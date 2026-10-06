use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
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
    tx: mpsc::Sender<(Bytes, NetLocation)>,
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

    pub fn send_to(&self, data: Bytes, target: NetLocation) -> io::Result<()> {
        if data.len() > crate::udp_fragments::MAX_UDP_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP payload too large",
            ));
        }
        *self.last_activity.lock() = Instant::now();
        match self.tx.try_send((data, target)) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "UDP relay closed",
            )),
        }
    }

    pub async fn recv(&self) -> io::Result<Reply> {
        let reply = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "UDP relay closed"))?;
        *self.last_activity.lock() = Instant::now();
        Ok(reply)
    }
}

impl Drop for UdpRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct ChannelStream {
    input: mpsc::Receiver<(Bytes, NetLocation)>,
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
        Poll::Ready(match self.output.try_reserve() {
            Ok(permit) => {
                permit.send((data.to_vec(), *source));
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
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
    async fn owned_input_preserves_allocation_and_queue_drop_policy() {
        let (tx, mut input) = mpsc::channel(QUEUE_SIZE);
        let (_output, rx) = mpsc::channel(QUEUE_SIZE);
        let relay = UdpRelay {
            _permit: crate::resources::try_stream().unwrap(),
            tx,
            rx: Mutex::new(rx),
            task: tokio::spawn(std::future::pending::<()>()).abort_handle(),
            last_activity: parking_lot::Mutex::new(Instant::now()),
        };
        let target = NetLocation::from_str("127.0.0.1:53", None).unwrap();
        let data = Bytes::from(vec![42; 128]);
        let pointer = data.as_ptr();
        relay.send_to(data, target.clone()).unwrap();
        let (received, received_target) = input.recv().await.unwrap();
        assert_eq!(received.as_ptr(), pointer);
        assert_eq!(received_target, target);
        for i in 0..=QUEUE_SIZE {
            relay
                .send_to(Bytes::from(vec![i as u8]), target.clone())
                .unwrap();
        }
        assert_eq!(input.len(), QUEUE_SIZE);
        for i in 0..QUEUE_SIZE {
            assert_eq!(input.recv().await.unwrap().0.as_ref(), &[i as u8]);
        }
        drop(input);
        assert_eq!(
            relay.send_to(Bytes::new(), target).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn replies_keep_full_queue_drops_and_closed_queue_errors() {
        let (_tx, input) = mpsc::channel(QUEUE_SIZE);
        let (output, mut rx) = mpsc::channel(QUEUE_SIZE);
        let mut stream = ChannelStream { input, output };
        let source = "[::1]:53".parse().unwrap();
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        for i in 0..=QUEUE_SIZE {
            assert!(matches!(
                Pin::new(&mut stream).poll_write_sourced_message(&mut cx, &[i as u8], &source),
                Poll::Ready(Ok(()))
            ));
        }
        assert_eq!(rx.len(), QUEUE_SIZE);
        for i in 0..QUEUE_SIZE {
            assert_eq!(rx.try_recv().unwrap(), (vec![i as u8], source));
        }
        drop(rx);
        assert!(matches!(
            Pin::new(&mut stream).poll_write_sourced_message(&mut cx, b"", &source),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe
        ));
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
            relay
                .send_to(Bytes::from_static(payload), original.clone())
                .unwrap();
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
            let (reply, source) =
                tokio::time::timeout(std::time::Duration::from_secs(1), relay.recv())
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(reply, payload);
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
                    Bytes::from_static(b"query"),
                    NetLocation::from_str("unknown.invalid:53", None).unwrap(),
                )
                .unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                let mut buf = [0; 64];
                let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], b"query");
                socket.send_to(b"answer", peer).await.unwrap();
                let (reply, source) = relay.recv().await.unwrap();
                assert_eq!(reply, b"answer");
                assert_eq!(source, address);
            })
            .await
            .expect("an overridden hostname must not require its own DNS record");
        }
    }
}
