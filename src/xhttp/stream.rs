use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use bytes::{Buf, Bytes};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, oneshot},
};
use tokio_util::{
    sync::{CancellationToken, PollSender},
    task::TaskTracker,
};

use crate::{
    async_stream::{AsyncPing, AsyncStream},
    resources::{Budget, BudgetPermit},
};

pub const CHUNK: usize = 16 * 1024;

#[derive(Clone, Debug)]
pub struct Memory {
    global: Arc<Budget>,
    session: Arc<Budget>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn partial_reads_explicit_eof_and_errors() {
        let memory = Memory::new(Arc::new(Budget::new(Some(128))), 128);
        let (mut writer, mut reader) = pipe(memory.clone());
        writer.write_all(b"abcdef").await.unwrap();
        writer.shutdown().await.unwrap();
        let mut result = Vec::new();
        let mut byte = [0];
        while reader.read(&mut byte).await.unwrap() != 0 {
            result.push(byte[0]);
        }
        assert_eq!(result, b"abcdef");
        let (mut writer, mut reader) = pipe(memory.clone());
        writer.fail(io::ErrorKind::ConnectionReset.into()).await;
        assert_eq!(
            reader.read(&mut byte).await.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
        let (writer, mut reader) = pipe(memory);
        drop(writer);
        assert_eq!(
            reader.read(&mut byte).await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn flush_waits_for_consumer_and_memory_is_returned() {
        let budget = Arc::new(Budget::new(Some(4)));
        let memory = Memory::new(budget.clone(), 4);
        let (mut writer, mut reader) = pipe(memory.clone());
        writer.write_all(b"data").await.unwrap();
        assert!(memory.copy(b"x").is_err());
        let mut flush = Box::pin(writer.flush());
        assert!(futures::poll!(&mut flush).is_pending());
        reader.read_exact(&mut [0; 4]).await.unwrap();
        let mut read = Box::pin(reader.read_u8());
        assert!(futures::poll!(&mut read).is_pending());
        flush.await.unwrap();
        assert!(memory.copy(b"more").is_ok());
    }
}

struct Allocation {
    data: Bytes,
    _global: BudgetPermit,
    _session: BudgetPermit,
}
impl AsRef<[u8]> for Allocation {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl Memory {
    pub fn concat(&self, chunks: &[Bytes]) -> io::Result<Bytes> {
        let size = chunks
            .iter()
            .try_fold(0usize, |n, b| n.checked_add(b.len()))
            .ok_or_else(crate::resources::exhausted)?;
        let global = self
            .global
            .acquire(size)
            .ok_or_else(crate::resources::exhausted)?;
        let session = self
            .session
            .acquire(size)
            .ok_or_else(crate::resources::exhausted)?;
        let mut data = Vec::with_capacity(size);
        for chunk in chunks {
            data.extend_from_slice(chunk);
        }
        Ok(Bytes::from_owner(Allocation {
            data: Bytes::from(data),
            _global: global,
            _session: session,
        }))
    }

    pub fn new(global: Arc<Budget>, session_limit: usize) -> Self {
        Self {
            global,
            session: Arc::new(Budget::new(Some(session_limit))),
        }
    }
    pub fn copy(&self, bytes: &[u8]) -> io::Result<Bytes> {
        let global = self
            .global
            .acquire(bytes.len())
            .ok_or_else(crate::resources::exhausted)?;
        let session = self
            .session
            .acquire(bytes.len())
            .ok_or_else(crate::resources::exhausted)?;
        Ok(Bytes::from_owner(Allocation {
            data: Bytes::copy_from_slice(bytes),
            _global: global,
            _session: session,
        }))
    }
}

#[derive(Debug)]
pub struct Tasks {
    pub cancel: CancellationToken,
    tracker: TaskTracker,
}
impl Tasks {
    pub fn new() -> Self {
        Self {
            cancel: CancellationToken::new(),
            tracker: TaskTracker::new(),
        }
    }
    pub fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) {
        let cancel = self.cancel.clone();
        self.tracker.spawn(async move {
            tokio::select! { biased; _ = cancel.cancelled() => {}, _ = future => {} }
        });
    }
}
impl Drop for Tasks {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.tracker.close();
    }
}

pub enum Event {
    Data(Bytes),
    Flush(oneshot::Sender<()>),
    Finish,
    Error(io::Error),
}

pub struct Reader {
    pub receiver: mpsc::Receiver<Event>,
    current: Bytes,
    ended: bool,
}

pub struct Writer {
    sender: parking_lot::Mutex<PollSender<Event>>,
    memory: Memory,
    flush: Option<oneshot::Receiver<()>>,
    finished: bool,
    pub flush_before_shutdown: bool,
}

pub fn pipe(memory: Memory) -> (Writer, Reader) {
    let (sender, receiver) = mpsc::channel(4);
    (
        Writer {
            sender: parking_lot::Mutex::new(PollSender::new(sender)),
            memory,
            flush: None,
            finished: false,
            flush_before_shutdown: false,
        },
        Reader {
            receiver,
            current: Bytes::new(),
            ended: false,
        },
    )
}

impl Writer {
    pub async fn forward(&mut self, mut data: Bytes) -> io::Result<()> {
        let sender = self
            .sender
            .lock()
            .get_ref()
            .cloned()
            .ok_or(io::ErrorKind::BrokenPipe)?;
        while !data.is_empty() {
            let len = data.len().min(CHUNK);
            sender
                .send(Event::Data(data.split_to(len)))
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        }
        Ok(())
    }

    pub async fn fail(&mut self, error: io::Error) {
        let sender = self.sender.lock().get_ref().cloned();
        if let Some(sender) = sender {
            let _ = sender.send(Event::Error(error)).await;
        }
        self.finished = true;
    }

    fn event(
        &mut self,
        cx: &mut Context<'_>,
        event: impl FnOnce() -> io::Result<Event>,
    ) -> Poll<io::Result<()>> {
        let mut sender = self.sender.lock();
        ready!(sender.poll_reserve(cx)).map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        sender
            .send_item(event()?)
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.finished {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if self.flush.is_some() {
            ready!(self.as_mut().poll_flush(cx))?;
        }
        let len = data.len().min(CHUNK);
        if len == 0 {
            return Poll::Ready(Ok(0));
        }
        let memory = self.memory.clone();
        ready!(self.event(cx, || Ok(Event::Data(memory.copy(&data[..len])?))))?;
        Poll::Ready(Ok(len))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.finished {
            return Poll::Ready(Ok(()));
        }
        if self.flush.is_none() {
            let (send, recv) = oneshot::channel();
            ready!(self.event(cx, || Ok(Event::Flush(send))))?;
            self.flush = Some(recv);
        }
        ready!(Pin::new(self.flush.as_mut().unwrap()).poll(cx))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        self.flush = None;
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.finished {
            if self.flush_before_shutdown {
                ready!(self.as_mut().poll_flush(cx))?;
                self.flush_before_shutdown = false;
            }
            ready!(self.event(cx, || Ok(Event::Finish)))?;
            self.finished = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.current.is_empty() {
                let len = self.current.len().min(buffer.remaining());
                buffer.put_slice(&self.current[..len]);
                self.current.advance(len);
                if self.current.is_empty() {
                    self.current = Bytes::new();
                }
                return Poll::Ready(Ok(()));
            }
            if self.ended {
                return Poll::Ready(Ok(()));
            }
            match ready!(self.receiver.poll_recv(cx)) {
                Some(Event::Data(data)) => self.current = data,
                Some(Event::Flush(ack)) => {
                    let _ = ack.send(());
                }
                Some(Event::Finish) => self.ended = true,
                Some(Event::Error(error)) => return Poll::Ready(Err(error)),
                None => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "XHTTP body terminated without FIN",
                    )));
                }
            }
        }
    }
}

pub struct Stream {
    pub read: Reader,
    pub write: Writer,
    pub _tasks: Arc<Tasks>,
}
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.read).poll_read(cx, buf)
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.write).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.write).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.write).poll_shutdown(cx)
    }
}
impl AsyncPing for Stream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncStream for Stream {}

pub enum Body {
    Empty,
    Full(Option<Bytes>),
    Stream {
        reader: Reader,
        _guard: Option<Box<dyn Send + Sync>>,
    },
}
impl Body {
    pub fn stream(reader: Reader) -> Self {
        Self::Stream {
            reader,
            _guard: None,
        }
    }
    pub fn with_guard(self, guard: impl Send + Sync + 'static) -> Self {
        match self {
            Self::Stream { reader, .. } => Self::Stream {
                reader,
                _guard: Some(Box::new(guard)),
            },
            other => other,
        }
    }
}
impl HttpBody for Body {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        match &mut *self {
            Self::Empty => Poll::Ready(None),
            Self::Full(data) => Poll::Ready(data.take().map(|data| Ok(Frame::data(data)))),
            Self::Stream { reader, .. } => {
                if reader.ended {
                    return Poll::Ready(None);
                }
                loop {
                    match ready!(reader.receiver.poll_recv(cx)) {
                        Some(Event::Data(data)) => return Poll::Ready(Some(Ok(Frame::data(data)))),
                        Some(Event::Flush(ack)) => {
                            let _ = ack.send(());
                        }
                        Some(Event::Finish) => {
                            reader.ended = true;
                            return Poll::Ready(None);
                        }
                        Some(Event::Error(error)) => {
                            reader.ended = true;
                            return Poll::Ready(Some(Err(error)));
                        }
                        None => {
                            reader.ended = true;
                            return Poll::Ready(Some(Err(io::ErrorKind::UnexpectedEof.into())));
                        }
                    }
                }
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        matches!(self, Self::Empty | Self::Full(None))
            || matches!(self, Self::Stream { reader, .. } if reader.ended)
    }
    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Empty | Self::Full(None) => SizeHint::with_exact(0),
            Self::Full(Some(data)) => SizeHint::with_exact(data.len() as u64),
            _ => SizeHint::default(),
        }
    }
}
