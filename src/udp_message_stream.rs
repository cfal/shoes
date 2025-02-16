use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::ready;
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;

use crate::address::NetLocation;
use crate::async_stream::{
    AsyncFlushMessage, AsyncPing, AsyncReadSourcedMessage, AsyncShutdownMessage,
    AsyncSourcedMessageStream, AsyncWriteTargetedMessage,
};
use crate::resolver::{Resolver, ResolverCache};

/// A thin wrapper around a directly connecting UdpSocket to support hostname resolution.
pub struct UdpMessageStream {
    socket: UdpSocket,
    resolver_cache: ResolverCache,
}

impl UdpMessageStream {
    pub fn new(socket: UdpSocket, resolver: Arc<dyn Resolver>) -> Self {
        Self {
            socket,
            resolver_cache: ResolverCache::new(resolver),
        }
    }
}

impl AsyncReadSourcedMessage for UdpMessageStream {
    fn poll_read_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<SocketAddr>> {
        self.get_mut().socket.poll_recv_from(cx, buf)
    }
}

impl AsyncWriteTargetedMessage for UdpMessageStream {
    fn poll_write_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &NetLocation,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        let socket_addr = ready!(this.resolver_cache.poll_resolve_location(cx, target))?;

        // TODO: do we need to check usize result here?
        this.socket
            .poll_send_to(cx, buf, socket_addr)
            .map(|result| result.map(|_| ()))
    }
}

impl AsyncFlushMessage for UdpMessageStream {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for UdpMessageStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for UdpMessageStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        unimplemented!()
    }
}

impl AsyncSourcedMessageStream for UdpMessageStream {}
