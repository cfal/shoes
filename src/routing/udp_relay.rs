use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use tokio::io::ReadBuf;
use tokio::sync::{Mutex, mpsc};
use tokio::time::Instant;

use crate::address::NetLocation;
use crate::async_stream::{
    AsyncFlushMessage, AsyncPing, AsyncReadTargetedMessage, AsyncShutdownMessage,
    AsyncTargetedMessageStream, AsyncWriteSourcedMessage,
};
use crate::client_proxy_selector::ClientProxySelector;
use crate::resolver::Resolver;

use super::{ServerStream, run_udp_routing};

const QUEUE_SIZE: usize = 4;
type Reply = (Vec<u8>, SocketAddr);

/// Channel transport for QUIC associations using the shared routing and proxy-chain machinery.
pub struct UdpRelay {
    _permit: crate::resources::BudgetPermit,
    tx: mpsc::Sender<(Vec<u8>, NetLocation)>,
    rx: Mutex<mpsc::Receiver<Reply>>,
    task: tokio::task::AbortHandle,
    last_activity: parking_lot::Mutex<Instant>,
}

impl UdpRelay {
    pub fn new(
        selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> io::Result<Self> {
        let permit = crate::resources::try_stream().ok_or_else(crate::resources::exhausted)?;
        let (tx, input) = mpsc::channel(QUEUE_SIZE);
        let (output, rx) = mpsc::channel(QUEUE_SIZE);
        let stream = ChannelStream { input, output };
        let task = tokio::spawn(async move {
            let _ = run_udp_routing(
                ServerStream::Targeted(Box::new(stream)),
                selector,
                resolver,
                false,
            )
            .await;
        })
        .abort_handle();
        Ok(Self {
            _permit: permit,
            tx,
            rx: Mutex::new(rx),
            task,
            last_activity: parking_lot::Mutex::new(Instant::now()),
        })
    }

    pub fn idle_for(&self) -> std::time::Duration {
        self.last_activity.lock().elapsed()
    }

    pub fn send_to(&self, data: &[u8], target: NetLocation) -> io::Result<()> {
        if data.len() > crate::udp_fragments::MAX_UDP_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP payload too large",
            ));
        }
        *self.last_activity.lock() = Instant::now();
        match self.tx.try_send((data.to_vec(), target)) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "UDP relay closed",
            )),
        }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (data, source) = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "UDP relay closed"))?;
        if data.len() > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP receive buffer too short",
            ));
        }
        buf[..data.len()].copy_from_slice(&data);
        *self.last_activity.lock() = Instant::now();
        Ok((data.len(), source))
    }
}

impl Drop for UdpRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct ChannelStream {
    input: mpsc::Receiver<(Vec<u8>, NetLocation)>,
    output: mpsc::Sender<Reply>,
}

impl AsyncReadTargetedMessage for ChannelStream {
    fn targeted_eof_on_empty(&self) -> bool {
        false
    }
    fn poll_read_targeted_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<NetLocation>> {
        match ready!(self.input.poll_recv(cx)) {
            Some((data, target)) => {
                if data.len() > buf.remaining() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "UDP read buffer too short",
                    )));
                }
                buf.put_slice(&data);
                Poll::Ready(Ok(target))
            }
            None => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "UDP association closed",
            ))),
        }
    }
}

impl AsyncWriteSourcedMessage for ChannelStream {
    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
        source: &SocketAddr,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(match self.output.try_send((data.to_vec(), *source)) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "UDP association closed",
            )),
        })
    }
}
impl AsyncFlushMessage for ChannelStream {
    fn poll_flush_message(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl AsyncShutdownMessage for ChannelStream {
    fn poll_shutdown_message(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl AsyncPing for ChannelStream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncTargetedMessageStream for ChannelStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_proxy_selector::{ConnectAction, ConnectRule};
    use std::future::Future;

    #[derive(Debug)]
    struct NoHostnameResolver;

    impl Resolver for NoHostnameResolver {
        fn resolve_location(
            &self,
            _: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
            Box::pin(async { Err(io::ErrorKind::NotFound.into()) })
        }
    }

    #[tokio::test]
    async fn relay_honors_route_override_and_empty_datagrams() {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let target = NetLocation::from_str(
            &format!("127.0.0.1:{}", socket.local_addr().unwrap().port()),
            None,
        )
        .unwrap();
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let selector = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
            vec![crate::address::NetLocationMask::from("0.0.0.0/0").unwrap()],
            ConnectAction::new_allow(
                Some(target),
                crate::tcp::chain_builder::build_direct_chain_group(resolver.clone()),
            ),
        )]));
        let relay = UdpRelay::new(selector, resolver).unwrap();
        let original = NetLocation::from_str("192.0.2.1:53", None).unwrap();
        for payload in [b"".as_slice(), b"query".as_slice()] {
            relay.send_to(payload, original.clone()).unwrap();
            let mut buf = [0; 64];
            let (n, peer) = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                socket.recv_from(&mut buf),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(&buf[..n], payload);
            socket.send_to(payload, peer).await.unwrap();
            let (n, source) =
                tokio::time::timeout(std::time::Duration::from_secs(1), relay.recv_from(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(&buf[..n], payload);
            assert_eq!(source, "192.0.2.1:53".parse().unwrap());
        }
        let task = relay.task.clone();
        drop(relay);
        tokio::task::yield_now().await;
        assert!(task.is_finished());
    }

    #[tokio::test]
    async fn relay_applies_override_before_resolving_original_hostname() {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let address = SocketAddr::from(([127, 0, 0, 1], socket.local_addr().unwrap().port()));
        let target = NetLocation::from_ip_addr(address.ip(), address.port());
        let resolver: Arc<dyn Resolver> = Arc::new(NoHostnameResolver);
        for mask in ["0.0.0.0/0", "unknown.invalid"] {
            let selector = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
                vec![crate::address::NetLocationMask::from(mask).unwrap()],
                ConnectAction::new_allow(
                    Some(target.clone()),
                    crate::tcp::chain_builder::build_direct_chain_group(resolver.clone()),
                ),
            )]));
            let relay = UdpRelay::new(selector, resolver.clone()).unwrap();
            relay
                .send_to(
                    b"query",
                    NetLocation::from_str("unknown.invalid:53", None).unwrap(),
                )
                .unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                let mut buf = [0; 64];
                let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], b"query");
                socket.send_to(b"answer", peer).await.unwrap();
                let (n, source) = relay.recv_from(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], b"answer");
                assert_eq!(source, address);
            })
            .await
            .expect("an overridden hostname must not require its own DNS record");
        }
    }
}
