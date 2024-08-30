use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::ReadBuf;
use tokio::net::UdpSocket;

use crate::address::NetLocation;
use crate::async_stream::{
    AsyncFlushMessage, AsyncPing, AsyncReadSourcedMessage, AsyncShutdownMessage,
    AsyncSourcedMessageStream, AsyncWriteTargetedMessage,
};
use crate::resolver::Resolver;

type ResolveFuture = Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>;

/// A thin wrapper around a directly connecting UdpSocket to support hostname resolution.
pub struct UdpDirectMessageStream {
    socket: UdpSocket,
    resolver: Arc<dyn Resolver>,
    location_cache: HashMap<NetLocation, SocketAddr>,
    resolving_locations: HashMap<NetLocation, ResolveFuture>,
}

impl UdpDirectMessageStream {
    pub fn new(socket: UdpSocket, resolver: Arc<dyn Resolver>) -> Self {
        Self {
            socket,
            resolver,
            // TODO: use a LRU cache
            location_cache: HashMap::new(),
            resolving_locations: HashMap::new(),
        }
    }
}

impl AsyncReadSourcedMessage for UdpDirectMessageStream {
    fn poll_read_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<SocketAddr>> {
        self.get_mut().socket.poll_recv_from(cx, buf)
    }
}

impl AsyncWriteTargetedMessage for UdpDirectMessageStream {
    fn poll_write_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &NetLocation,
    ) -> Poll<std::io::Result<()>> {
        // TODO: check if NetLocation is already an IP first?
        let this = self.get_mut();
        let socket_addr = match target.to_socket_addr_nonblocking() {
            Some(s) => s,
            None => {
                match this.location_cache.get(target) {
                    Some(s) => *s,
                    None => {
                        let resolve_results = match this.resolving_locations.get_mut(target) {
                            None => {
                                let mut resolve_future: Pin<
                                    Box<
                                        dyn Future<Output = std::io::Result<Vec<SocketAddr>>>
                                            + Send,
                                    >,
                                > = this.resolver.resolve_location(target);
                                match resolve_future.as_mut().poll(cx) {
                                    Poll::Pending => {
                                        this.resolving_locations
                                            .insert(target.clone(), resolve_future);
                                        return Poll::Pending;
                                    }
                                    Poll::Ready(result) => result,
                                }
                            }
                            Some(resolve_future) => match resolve_future.as_mut().poll(cx) {
                                Poll::Pending => {
                                    return Poll::Pending;
                                }
                                Poll::Ready(result) => {
                                    this.resolving_locations.remove(target);
                                    result
                                }
                            },
                        };
                        match resolve_results {
                            Err(e) => {
                                return Poll::Ready(Err(e));
                            }
                            Ok(socket_addrs) => {
                                if socket_addrs.is_empty() {
                                    return Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::Other,
                                        format!("Failed to resolve {}", target),
                                    )));
                                }
                                let socket_addr = socket_addrs.into_iter().next().unwrap();
                                // TODO: switch to using entry()
                                this.location_cache.insert(target.clone(), socket_addr);
                                socket_addr
                            }
                        }
                    }
                }
            }
        };
        // TODO: do we need to check usize result here?
        this.socket
            .poll_send_to(cx, buf, socket_addr)
            .map(|result| result.map(|_| ()))
    }
}

impl AsyncFlushMessage for UdpDirectMessageStream {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for UdpDirectMessageStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for UdpDirectMessageStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        unimplemented!()
    }
}

impl AsyncSourcedMessageStream for UdpDirectMessageStream {}
