use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};

use bytes::{Buf, Bytes};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, oneshot},
    time::Instant,
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

#[derive(Debug)]
pub struct Activity(parking_lot::Mutex<Instant>);

impl Activity {
    pub fn new() -> Self {
        Self(parking_lot::Mutex::new(Instant::now()))
    }

    pub fn touch(&self) {
        *self.0.lock() = Instant::now();
    }

    pub async fn idle<T>(
        &self,
        since: Instant,
        timeout: Duration,
        work: impl Future<Output = T>,
    ) -> io::Result<T> {
        let expired = async {
            loop {
                let last = since.max(*self.0.lock());
                let Some(deadline) = last.checked_add(timeout) else {
                    return std::future::pending().await;
                };
                tokio::time::sleep_until(deadline).await;
                // Activity never wakes waiters; only real progress can extend their deadlines.
                if since.max(*self.0.lock()).checked_add(timeout) == Some(deadline) {
                    return;
                }
            }
        };
        tokio::select! {
            biased;
            result = work => Ok(result),
            _ = expired => Err(io::ErrorKind::TimedOut.into()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Memory {
    global: Arc<Budget>,
    session: Arc<Budget>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(start_paused = true)]
    async fn inactivity_tracks_progress_not_total_lifetime() {
        let activity = Activity::new();
        let mut wait = Box::pin(activity.idle(
            Instant::now(),
            Duration::from_secs(10),
            std::future::pending::<()>(),
        ));
        assert!(futures::poll!(&mut wait).is_pending());
        for _ in 0..10 {
            tokio::time::advance(Duration::from_secs(9)).await;
            activity.touch();
            assert!(futures::poll!(&mut wait).is_pending());
        }
        tokio::time::advance(Duration::from_millis(9999)).await;
        assert!(futures::poll!(&mut wait).is_pending());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(wait.await.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn inactivity_completion_and_progress_win_at_the_deadline() {
        let activity = Activity::new();
        let done = CancellationToken::new();
        let mut wait =
            Box::pin(activity.idle(Instant::now(), Duration::from_secs(10), done.cancelled()));
        assert!(futures::poll!(&mut wait).is_pending());
        tokio::time::advance(Duration::from_secs(10)).await;
        activity.touch();
        assert!(futures::poll!(&mut wait).is_pending());
        tokio::time::advance(Duration::from_secs(10)).await;
        done.cancel();
        wait.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn inactivity_has_a_phase_floor_and_accepts_unrepresentable_deadlines() {
        let activity = Activity::new();
        tokio::time::advance(Duration::from_secs(20)).await;
        let mut wait = Box::pin(activity.idle(
            Instant::now(),
            Duration::from_secs(10),
            std::future::pending::<()>(),
        ));
        assert!(futures::poll!(&mut wait).is_pending());
        tokio::time::advance(Duration::from_secs(9)).await;
        assert!(futures::poll!(&mut wait).is_pending());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(wait.await.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(
            futures::poll!(Box::pin(activity.idle(
                Instant::now(),
                Duration::MAX,
                std::future::pending::<()>(),
            )))
            .is_pending()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn tracked_h1_body_preserves_framing_and_only_finishes_on_handoff() {
        use http_body_util::BodyExt;

        let (upload, watch) = Upload::channel();
        let mut body = Body::Chunks([Bytes::from_static(b"a"), Bytes::from_static(b"bc")].into())
            .track_h1(upload);
        assert_eq!(body.size_hint().exact(), Some(3));
        assert!(!body.is_end_stream());
        let mut wait = Box::pin(watch.wait(Duration::from_secs(10)));
        assert!(futures::poll!(&mut wait).is_pending());
        tokio::time::advance(Duration::from_secs(9)).await;
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            "a"
        );
        assert_eq!(body.size_hint().exact(), Some(2));
        tokio::time::advance(Duration::from_secs(9)).await;
        assert!(futures::poll!(&mut wait).is_pending());
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            "bc"
        );
        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
        drop(body);
        wait.await.unwrap();

        let (upload, watch) = Upload::channel();
        let body = Body::Chunks([Bytes::from_static(b"unsent")].into()).track_h1(upload);
        drop(body);
        assert_eq!(
            watch
                .wait(Duration::from_secs(10))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        let (upload, watch) = Upload::channel();
        drop(Body::Empty.track_h1(upload));
        watch.wait(Duration::from_secs(10)).await.unwrap();
    }

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

    #[tokio::test]
    async fn dropped_barrier_ack_keeps_subsequent_operations_fallible() {
        for drain in [false, true] {
            let memory = Memory::new(Arc::new(Budget::new(Some(128))), 128);
            let (mut writer, reader) = pipe(memory);
            writer.drain_before_shutdown = drain;
            let mut barrier = Box::pin(async {
                if drain {
                    writer.shutdown().await
                } else {
                    writer.flush().await
                }
            });
            assert!(futures::poll!(&mut barrier).is_pending());
            drop(reader);
            assert_eq!(barrier.await.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
            assert_eq!(
                writer.flush().await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
            assert_eq!(
                writer.shutdown().await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
            assert_eq!(
                writer.write_all(b"x").await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
        }
    }

    #[tokio::test]
    async fn byte_budget_backpressures_other_sessions_and_wakes_on_release() {
        let budget = Arc::new(Budget::new(Some(8)));
        let (mut first, mut first_reader) = pipe(Memory::new(budget.clone(), 8));
        let (mut second, mut second_reader) = pipe(Memory::new(budget.clone(), 8));
        first.write_all(b"12345678").await.unwrap();
        let mut blocked = Box::pin(second.write_all(b"next"));
        assert!(futures::poll!(&mut blocked).is_pending());
        assert_eq!(budget.snapshot().active, 8);
        first_reader.read_exact(&mut [0; 8]).await.unwrap();
        blocked.await.unwrap();
        let mut bytes = [0; 4];
        second_reader.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"next");
        assert_eq!(budget.snapshot().active, 0);

        first.write_all(b"12345678").await.unwrap();
        let mut blocked = Box::pin(second.write_all(b"cancel"));
        assert!(futures::poll!(&mut blocked).is_pending());
        drop(second_reader);
        assert_eq!(blocked.await.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        drop(first_reader);
        assert_eq!(budget.snapshot().active, 0);
    }
}

struct Allocation {
    data: Bytes,
    _global: BudgetPermit,
    _session: BudgetPermit,
}
struct Retained {
    data: Bytes,
    _session: BudgetPermit,
}

pub struct PacketMemory {
    global: Arc<Budget>,
    session: BudgetPermit,
    remaining: usize,
}

impl PacketMemory {
    pub fn retain(&mut self, data: Bytes) -> io::Result<Bytes> {
        if data.len() > self.remaining {
            return Err(crate::resources::exhausted());
        }
        self.remaining -= data.len();
        Ok(Bytes::from_owner(Retained {
            _session: self.session.split(data.len()),
            data,
        }))
    }

    pub async fn copy(&mut self, bytes: &[u8]) -> io::Result<Bytes> {
        if bytes.len() > self.remaining {
            return Err(crate::resources::exhausted());
        }
        loop {
            let released = self.global.released();
            tokio::pin!(released);
            released.as_mut().enable();
            if let Some(global) = self.global.acquire(bytes.len()) {
                self.remaining -= bytes.len();
                return Ok(Bytes::from_owner(Allocation {
                    data: Bytes::copy_from_slice(bytes),
                    _global: global,
                    _session: self.session.split(bytes.len()),
                }));
            }
            released.await;
        }
    }
}
impl AsRef<[u8]> for Retained {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}
impl AsRef<[u8]> for Allocation {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl Memory {
    async fn reserve(&self, size: usize) -> io::Result<(BudgetPermit, BudgetPermit)> {
        if self.global.limit().is_some_and(|limit| size > limit)
            || self.session.limit().is_some_and(|limit| size > limit)
        {
            return Err(crate::resources::exhausted());
        }
        loop {
            let global_ready = self.global.released();
            tokio::pin!(global_ready);
            global_ready.as_mut().enable();
            let Some(global) = self.global.acquire(size) else {
                global_ready.await;
                continue;
            };
            let session_ready = self.session.released();
            tokio::pin!(session_ready);
            session_ready.as_mut().enable();
            if let Some(session) = self.session.acquire(size) {
                return Ok((global, session));
            }
            // Never hold the global budget while waiting for this session to drain.
            drop(global);
            session_ready.await;
        }
    }

    pub fn packet_space_released(&self) -> tokio::sync::futures::OwnedNotified {
        self.session.released()
    }

    pub fn reserve_packet(&self, size: usize, headroom: usize) -> Option<PacketMemory> {
        let mut permit = self.session.acquire(size.checked_add(headroom)?)?;
        Some(PacketMemory {
            global: self.global.clone(),
            session: permit.split(size),
            remaining: size,
        })
    }

    pub fn new(global: Arc<Budget>, session_limit: usize) -> Self {
        Self {
            global,
            session: Arc::new(Budget::new(Some(session_limit))),
        }
    }
    #[cfg(test)]
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
    pub async fn wait(&self) {
        self.tracker.close();
        self.tracker.wait().await;
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
    Drain(oneshot::Sender<()>),
    Finish,
    Error(io::Error),
}

pub struct Reader {
    pub receiver: mpsc::Receiver<Event>,
    current: Bytes,
    ended: bool,
    pub eof: CancellationToken,
    pub activity: Option<Arc<Activity>>,
}

pub struct Writer {
    sender: parking_lot::Mutex<PollSender<Event>>,
    memory: Memory,
    flush: Option<(bool, oneshot::Receiver<()>)>,
    finished: bool,
    allocation: parking_lot::Mutex<Option<(usize, Reservation)>>,
    pub drain_before_shutdown: bool,
}

type Reservation = Pin<Box<dyn Future<Output = io::Result<(BudgetPermit, BudgetPermit)>> + Send>>;

pub fn pipe(memory: Memory) -> (Writer, Reader) {
    let (sender, receiver) = mpsc::channel(4);
    (
        Writer {
            sender: parking_lot::Mutex::new(PollSender::new(sender)),
            memory,
            flush: None,
            finished: false,
            allocation: parking_lot::Mutex::new(None),
            drain_before_shutdown: false,
        },
        Reader {
            receiver,
            current: Bytes::new(),
            ended: false,
            eof: CancellationToken::new(),
            activity: None,
        },
    )
}

impl Writer {
    pub fn closed(&self) -> impl Future<Output = ()> + Send + 'static {
        let sender = self.sender.lock().get_ref().cloned();
        async move {
            if let Some(sender) = sender {
                sender.closed().await;
            }
        }
    }

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

    fn poll_barrier(&mut self, cx: &mut Context<'_>, drain: bool) -> Poll<io::Result<()>> {
        loop {
            if self.flush.is_none() {
                let (send, recv) = oneshot::channel();
                ready!(self.event(cx, || {
                    Ok(if drain {
                        Event::Drain(send)
                    } else {
                        Event::Flush(send)
                    })
                }))?;
                self.flush = Some((drain, recv));
            }
            let (was_drain, recv) = self.flush.as_mut().unwrap();
            let result = ready!(Pin::new(recv).poll(cx));
            let complete = !drain || *was_drain;
            self.flush = None;
            if result.is_err() {
                self.sender.get_mut().close();
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            if complete {
                return Poll::Ready(Ok(()));
            }
        }
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
        let len = data
            .len()
            .min(CHUNK)
            .min(self.memory.global.limit().unwrap_or(CHUNK))
            .min(self.memory.session.limit().unwrap_or(CHUNK));
        if len == 0 {
            return Poll::Ready(Ok(0));
        }
        let this = &mut *self;
        ready!(this.sender.get_mut().poll_reserve(cx))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        let allocation = this.allocation.get_mut();
        if allocation.as_ref().is_none_or(|(size, _)| *size != len) {
            let memory = this.memory.clone();
            let sender = this
                .sender
                .get_mut()
                .get_ref()
                .cloned()
                .ok_or(io::ErrorKind::BrokenPipe)?;
            *allocation = Some((
                len,
                Box::pin(async move {
                    tokio::select! {
                        result = memory.reserve(len) => result,
                        _ = sender.closed() => Err(io::ErrorKind::BrokenPipe.into()),
                    }
                }),
            ));
        }
        let result = ready!(allocation.as_mut().unwrap().1.as_mut().poll(cx));
        *allocation = None;
        let (global, session) = result?;
        let bytes = Bytes::from_owner(Allocation {
            data: Bytes::copy_from_slice(&data[..len]),
            _global: global,
            _session: session,
        });
        this.sender
            .get_mut()
            .send_item(Event::Data(bytes))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Poll::Ready(Ok(len))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.finished {
            return Poll::Ready(Ok(()));
        }
        self.poll_barrier(cx, false)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.finished {
            if self.drain_before_shutdown {
                ready!(self.poll_barrier(cx, true))?;
                self.drain_before_shutdown = false;
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
                if let Some(activity) = &self.activity {
                    activity.touch();
                }
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
                Some(Event::Flush(ack) | Event::Drain(ack)) => {
                    let _ = ack.send(());
                }
                Some(Event::Finish) => {
                    self.ended = true;
                    self.eof.cancel();
                }
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

pub struct Upload {
    pub activity: Arc<Activity>,
    done: Option<oneshot::Sender<()>>,
}

pub struct UploadWatch {
    activity: Arc<Activity>,
    done: oneshot::Receiver<()>,
}

impl Upload {
    pub fn channel() -> (Self, UploadWatch) {
        let activity = Arc::new(Activity::new());
        let (send, done) = oneshot::channel();
        (
            Self {
                activity: activity.clone(),
                done: Some(send),
            },
            UploadWatch { activity, done },
        )
    }

    pub fn finish(&mut self) {
        if let Some(done) = self.done.take() {
            let _ = done.send(());
        }
    }
}

impl UploadWatch {
    pub async fn wait(self, timeout: Duration) -> io::Result<()> {
        self.activity
            .idle(Instant::now(), timeout, async {
                self.done
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
            })
            .await?
    }
}

pub enum Body {
    Empty,
    Chunks(VecDeque<Bytes>),
    Packet {
        chunks: VecDeque<Bytes>,
        upload: Upload,
    },
    Stream {
        reader: Reader,
        _guard: Option<Box<dyn Send + Sync>>,
    },
}
impl Body {
    pub fn track_h1(self, mut upload: Upload) -> Self {
        let chunks = match self {
            Self::Chunks(chunks) => chunks,
            Self::Empty => VecDeque::new(),
            _ => unreachable!("only packet bodies have an upload watchdog"),
        };
        if chunks.is_empty() {
            upload.finish();
        }
        Self::Packet { chunks, upload }
    }

    pub fn stream(reader: Reader) -> Self {
        Self::Stream {
            reader,
            _guard: None,
        }
    }
    pub fn with_guard(self, guard: impl Send + Sync + 'static) -> Self {
        match self {
            Self::Stream { reader, _guard } => Self::Stream {
                reader,
                _guard: Some(Box::new((_guard, guard))),
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
            Self::Chunks(chunks) => {
                Poll::Ready(chunks.pop_front().map(|data| Ok(Frame::data(data))))
            }
            Self::Packet { chunks, upload } => {
                let data = chunks.pop_front();
                if data.as_ref().is_some_and(|data| !data.is_empty()) {
                    upload.activity.touch();
                }
                // Hyper may skip the EOF poll. H1 completion means bounded-buffer handoff.
                if chunks.is_empty() {
                    upload.finish();
                }
                Poll::Ready(data.map(|data| Ok(Frame::data(data))))
            }
            Self::Stream { reader, .. } => {
                if reader.ended {
                    return Poll::Ready(None);
                }
                loop {
                    match ready!(reader.receiver.poll_recv(cx)) {
                        Some(Event::Data(data)) => return Poll::Ready(Some(Ok(Frame::data(data)))),
                        Some(Event::Flush(ack) | Event::Drain(ack)) => {
                            let _ = ack.send(());
                        }
                        Some(Event::Finish) => {
                            reader.ended = true;
                            reader.eof.cancel();
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
        matches!(self, Self::Empty)
            || matches!(self, Self::Chunks(chunks) if chunks.is_empty())
            || matches!(self, Self::Packet { chunks, .. } if chunks.is_empty())
            || matches!(self, Self::Stream { reader, .. } if reader.ended)
    }
    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Empty => SizeHint::with_exact(0),
            Self::Chunks(chunks) => {
                SizeHint::with_exact(chunks.iter().map(|b| b.len() as u64).sum())
            }
            Self::Packet { chunks, .. } => {
                SizeHint::with_exact(chunks.iter().map(|b| b.len() as u64).sum())
            }
            _ => SizeHint::default(),
        }
    }
}
