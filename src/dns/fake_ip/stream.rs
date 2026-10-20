use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::task::JoinHandle;

use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};

use super::FakeDnsContext;

const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const FRAME_TIMEOUT: Duration = Duration::from_secs(30);
type Exchange = Pin<Box<dyn Future<Output = io::Result<Option<Vec<u8>>>> + Send>>;

pub(super) struct UdpDnsStream {
    context: Arc<FakeDnsContext>,
    exchange: Option<Exchange>,
    reader: Option<Waker>,
    writer: Option<Waker>,
    closed: bool,
}

impl UdpDnsStream {
    pub fn new(context: Arc<FakeDnsContext>) -> Self {
        Self {
            context,
            exchange: None,
            reader: None,
            writer: None,
            closed: false,
        }
    }
}

impl AsyncReadMessage for UdpDnsStream {
    fn read_message_eof_on_empty(&self) -> bool {
        false
    }

    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        self.reader = Some(cx.waker().clone());
        let Some(exchange) = &mut self.exchange else {
            return Poll::Pending;
        };
        let response = match exchange.as_mut().poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        self.exchange = None;
        if let Some(writer) = self.writer.take() {
            writer.wake();
        }
        match response {
            Ok(Some(bytes)) => {
                if bytes.len() > buf.remaining() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "DNS reply buffer too small",
                    )));
                }
                buf.put_slice(&bytes);
                Poll::Ready(Ok(()))
            }
            Ok(None) => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl AsyncWriteMessage for UdpDnsStream {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if self.exchange.is_some() {
            self.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        if bytes.len() > u16::MAX as usize {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS datagram too large",
            )));
        }
        let context = self.context.clone();
        let bytes = bytes.to_vec();
        self.exchange = Some(Box::pin(
            async move { context.exchange(bytes, false).await },
        ));
        if let Some(reader) = self.reader.take() {
            reader.wake();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for UdpDnsStream {
    fn poll_flush_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for UdpDnsStream {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.closed = true;
        self.exchange = None;
        if let Some(reader) = self.reader.take() {
            reader.wake();
        }
        if let Some(writer) = self.writer.take() {
            writer.wake();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for UdpDnsStream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncMessageStream for UdpDnsStream {}

pub(super) struct TcpDnsStream {
    stream: DuplexStream,
    task: JoinHandle<()>,
}

impl TcpDnsStream {
    pub fn new(context: Arc<FakeDnsContext>) -> Self {
        let (stream, mut peer) = tokio::io::duplex(16 * 1024);
        let task = tokio::spawn(async move {
            let _ = serve_tcp(&mut peer, context).await;
        });
        Self { stream, task }
    }
}

async fn serve_tcp(peer: &mut DuplexStream, context: Arc<FakeDnsContext>) -> io::Result<()> {
    loop {
        let length = tokio::time::timeout(IDLE_TIMEOUT, peer.read_u16()).await?? as usize;
        if length == 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut bytes = vec![0; length];
        tokio::time::timeout(FRAME_TIMEOUT, peer.read_exact(&mut bytes)).await??;
        let Some(response) = context.exchange(bytes, true).await? else {
            return Err(io::ErrorKind::InvalidData.into());
        };
        tokio::time::timeout(FRAME_TIMEOUT, async {
            peer.write_u16(response.len() as u16).await?;
            peer.write_all(&response).await?;
            peer.flush().await
        })
        .await??;
    }
}

impl Drop for TcpDnsStream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl AsyncRead for TcpDnsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpDnsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl AsyncPing for TcpDnsStream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for TcpDnsStream {}
