use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::ready;
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{self, Receiver};
use tokio::task::JoinHandle;

use crate::address::NetLocation;
use crate::async_stream::{
    AsyncFlushMessage, AsyncPing, AsyncReadSourcedMessage, AsyncShutdownMessage,
    AsyncSourcedMessageStream, AsyncWriteTargetedMessage,
};
use crate::resolver::{Resolver, ResolverCache};

pub struct UdpMultiMessageStream {
    // We use a dedicated send socket so that tasks waiting for writable get
    // awoken correctly. In addition, when sending to the same destination
    // from multiple sockets, the underlying network stack (and NIC) is
    // typically the main throughput limiter. In many scenarios, since UDP
    // sending is non-blocking and efficient, rotating among sockets will
    // only provide marginal throughput improvements.
    send_socket: Arc<UdpSocket>,
    resolver_cache: ResolverCache,
    receiver: Receiver<(Box<[u8]>, SocketAddr)>,
    notify_shutdown: Arc<AtomicBool>,
    join_handles: Vec<JoinHandle<()>>,
}

// NOTE: With multiple UDP sockets bound using SO_REUSEPORT, the OS will
// distribute incoming packets based on a 4-tuple hash. If packets all come
// from the same remote address and port, they will likely always be routed
// to the same socket.
//
// tokio's mpsc channels require &mut self, while UdpSocket's poll_recv and
// poll_send only require &self. Since we only use this for multidirectional
// UDP, we implement the relevant traits directly instead.
impl UdpMultiMessageStream {
    pub fn new(sockets: Vec<Arc<UdpSocket>>, resolver: Arc<dyn Resolver>) -> Self {
        if sockets.is_empty() {
            panic!("at least one socket is required");
        }

        let send_socket = sockets.first().unwrap().clone();

        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel(40);
        let mut join_handles = Vec::new();

        for socket in sockets.into_iter() {
            let tx = tx.clone();
            let shutdown_flag = shutdown_flag.clone();
            let receiver_socket = socket;
            join_handles.push(tokio::spawn(async move {
                let mut buf = [0u8; 65535];
                'outer: loop {
                    if shutdown_flag.load(Ordering::Relaxed) {
                        break;
                    }

                    if receiver_socket.readable().await.is_err() {
                        break;
                    }

                    loop {
                        match receiver_socket.try_recv_from(&mut buf) {
                            Ok((n, from_addr)) => {
                                let message = Box::from(&buf[..n]);
                                match tx.try_send((message, from_addr)) {
                                    Ok(_) => {}
                                    Err(err) => match err {
                                        mpsc::error::TrySendError::Full(_) => {
                                            // Channel is full; the packet is dropped to maintain throughput.
                                        }
                                        mpsc::error::TrySendError::Closed(_) => {
                                            break;
                                        }
                                    },
                                }
                            }
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                continue 'outer;
                            }
                            Err(e) => {
                                eprintln!("UDP recv error: {:?}", e);
                                break;
                            }
                        }
                    }
                }
            }));
        }

        UdpMultiMessageStream {
            send_socket,
            resolver_cache: ResolverCache::new(resolver),
            receiver: rx,
            notify_shutdown: shutdown_flag,
            join_handles,
        }
    }
}

impl AsyncReadSourcedMessage for UdpMultiMessageStream {
    fn poll_read_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<SocketAddr>> {
        let this = self.get_mut();
        match Pin::new(&mut this.receiver).poll_recv(cx) {
            Poll::Ready(Some((message, from_addr))) => {
                if message.len() > buf.remaining() {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "buffer too small",
                    )));
                }
                buf.put_slice(&message);
                Poll::Ready(Ok(from_addr))
            }
            Poll::Ready(None) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "channel closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWriteTargetedMessage for UdpMultiMessageStream {
    fn poll_write_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &NetLocation,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let socket_addr = ready!(this.resolver_cache.poll_resolve_location(cx, target))?;
        this.send_socket
            .poll_send_to(cx, buf, socket_addr)
            .map(|result| result.map(|_| ()))
    }
}

impl AsyncFlushMessage for UdpMultiMessageStream {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for UdpMultiMessageStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.notify_shutdown.store(true, Ordering::Relaxed);
        for handle in this.join_handles.drain(..) {
            handle.abort();
        }
        this.join_handles.clear();
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for UdpMultiMessageStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        unimplemented!();
    }
}

impl AsyncSourcedMessageStream for UdpMultiMessageStream {}
