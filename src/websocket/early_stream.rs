use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::task::{ArcWake, AtomicWaker, waker_ref};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::websocket_handler::ClientHandshake;
use super::websocket_stream::WebsocketStream;
use crate::async_stream::{AsyncPing, AsyncStream};
use crate::config::WebsocketPingType;
use crate::control::flows::FlowEntry;

type Upgrade = Pin<Box<dyn Future<Output = io::Result<WebsocketStream>> + Send + Sync>>;

enum State {
    Idle(Box<dyn AsyncStream>),
    Upgrading(Upgrade),
    Open(WebsocketStream),
    Failed(io::ErrorKind, String),
}

#[derive(Default)]
struct UpgradeWake {
    reader: AtomicWaker,
    writer: AtomicWaker,
}

impl ArcWake for UpgradeWake {
    fn wake_by_ref(this: &Arc<Self>) {
        this.reader.wake();
        this.writer.wake();
    }
}

pub(super) struct EarlyWebsocketStream {
    state: State,
    handshake: Arc<ClientHandshake>,
    wake: Arc<UpgradeWake>,
    peer: Option<SocketAddr>,
    flow: Option<Arc<FlowEntry>>,
}

impl EarlyWebsocketStream {
    pub fn new(stream: Box<dyn AsyncStream>, handshake: Arc<ClientHandshake>) -> Self {
        Self {
            peer: stream.peer_addr(),
            flow: stream.flow().cloned(),
            state: State::Idle(stream),
            handshake,
            wake: Arc::default(),
        }
    }

    fn start(&mut self, prefix: &[u8]) {
        if !matches!(self.state, State::Idle(_)) {
            return;
        }
        let State::Idle(stream) = std::mem::replace(
            &mut self.state,
            State::Failed(io::ErrorKind::Other, "WebSocket upgrade interrupted".into()),
        ) else {
            unreachable!();
        };
        let handshake = self.handshake.clone();
        let prefix = prefix.to_vec();
        // Start the deadline when bytes are accepted, not when the next operation polls us.
        let deadline = tokio::time::Instant::now() + crate::util::STREAM_SETUP_TIMEOUT;
        self.state = State::Upgrading(Box::pin(async move {
            tokio::time::timeout_at(deadline, handshake.upgrade(stream, &prefix))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "WebSocket upgrade timed out")
                })?
        }));
    }

    fn poll_open(
        &mut self,
        cx: &mut Context<'_>,
        read: bool,
    ) -> Poll<io::Result<&mut WebsocketStream>> {
        self.start(&[]);
        if let State::Upgrading(future) = &mut self.state {
            if read {
                self.wake.reader.register(cx.waker());
            } else {
                self.wake.writer.register(cx.waker());
            }
            let waker = waker_ref(&self.wake);
            let mut handshake_cx = Context::from_waker(&waker);
            let result = std::task::ready!(future.as_mut().poll(&mut handshake_cx));
            self.state = match result {
                Ok(stream) => State::Open(stream),
                Err(error) => State::Failed(error.kind(), error.to_string()),
            };
            UpgradeWake::wake_by_ref(&self.wake);
        }
        match &mut self.state {
            State::Open(stream) => Poll::Ready(Ok(stream)),
            State::Failed(kind, message) => {
                Poll::Ready(Err(io::Error::new(*kind, message.clone())))
            }
            _ => unreachable!(),
        }
    }
}

impl AsyncRead for EarlyWebsocketStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let stream = std::task::ready!(self.get_mut().poll_open(cx, true))?;
        Pin::new(stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for EarlyWebsocketStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        if matches!(this.state, State::Idle(_)) {
            let accepted = buf.len().min(this.handshake.early_data.max);
            this.start(&buf[..accepted]);
            // Owned bytes must be acknowledged in this poll, even if the upgrade will fail.
            return Poll::Ready(Ok(accepted));
        }
        let stream = std::task::ready!(this.poll_open(cx, false))?;
        Pin::new(stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let stream = std::task::ready!(self.get_mut().poll_open(cx, false))?;
        Pin::new(stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let stream = std::task::ready!(self.get_mut().poll_open(cx, false))?;
        Pin::new(stream).poll_shutdown(cx)
    }
}

impl AsyncPing for EarlyWebsocketStream {
    fn supports_ping(&self) -> bool {
        self.handshake.ping_type != WebsocketPingType::Disabled
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        if !self.supports_ping() {
            return Poll::Ready(Ok(false));
        }
        let stream = std::task::ready!(self.get_mut().poll_open(cx, false))?;
        Pin::new(stream).poll_write_ping(cx)
    }
}

impl AsyncStream for EarlyWebsocketStream {
    fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer
    }

    fn flow(&self) -> Option<&Arc<FlowEntry>> {
        self.flow.as_ref()
    }
}
