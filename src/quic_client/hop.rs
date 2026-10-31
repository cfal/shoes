use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use futures::task::AtomicWaker;
use parking_lot::RwLock;
use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use rand::RngExt;
use tokio_util::task::AbortOnDropHandle;

use crate::config::quic_client::HoppingConfig;

pub(crate) type SocketFactory = Arc<dyn Fn() -> io::Result<Arc<dyn AsyncUdpSocket>> + Send + Sync>;

struct State {
    current: Arc<dyn AsyncUdpSocket>,
    poller: Pin<Box<dyn UdpPoller>>,
    previous: Option<Arc<dyn AsyncUdpSocket>>,
    destination: SocketAddr,
}

pub(crate) struct HoppingSocket {
    factory: SocketFactory,
    canonical: SocketAddr,
    ports: Vec<u16>,
    state: RwLock<State>,
    reader: AtomicWaker,
    writer: AtomicWaker,
    task: parking_lot::Mutex<Option<AbortOnDropHandle<()>>>,
}

impl std::fmt::Debug for HoppingSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HoppingSocket")
            .field("canonical", &self.canonical)
            .finish_non_exhaustive()
    }
}

impl HoppingSocket {
    pub fn new(
        factory: SocketFactory,
        canonical: SocketAddr,
        config: &HoppingConfig,
    ) -> io::Result<Arc<Self>> {
        let ports = config.parse_ports()?;
        let (min, max) = config.interval()?;
        let destination = SocketAddr::new(
            canonical.ip(),
            ports[rand::rng().random_range(0..ports.len())],
        );
        let current = factory()?;
        let poller = current.clone().create_io_poller();
        let socket = Arc::new(Self {
            state: RwLock::new(State {
                current,
                poller,
                previous: None,
                destination,
            }),
            factory,
            canonical,
            ports,
            reader: AtomicWaker::new(),
            writer: AtomicWaker::new(),
            task: parking_lot::Mutex::new(None),
        });
        let weak = Arc::downgrade(&socket);
        *socket.task.lock() = Some(AbortOnDropHandle::new(tokio::spawn(async move {
            loop {
                let seconds = rand::rng().random_range(min..=max);
                tokio::time::sleep(Duration::from_secs(seconds)).await;
                let Some(socket) = weak.upgrade() else { return };
                if let Err(error) = socket.hop() {
                    log::warn!("HY2 port hop failed; keeping current socket: {error}");
                }
            }
        })));
        Ok(socket)
    }

    fn hop(&self) -> io::Result<()> {
        let current = (self.factory)()?;
        let poller = current.clone().create_io_poller();
        let destination = SocketAddr::new(
            self.canonical.ip(),
            self.ports[rand::rng().random_range(0..self.ports.len())],
        );
        {
            let mut state = self.state.write();
            state.previous = Some(std::mem::replace(&mut state.current, current));
            state.destination = destination;
            state.poller = poller;
        }
        self.reader.wake();
        self.writer.wake();
        Ok(())
    }

    fn canonicalize(&self, meta: &mut [RecvMeta], count: usize) {
        for meta in &mut meta[..count] {
            meta.addr = self.canonical;
        }
    }
}

impl AsyncUdpSocket for HoppingSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        // Dedicated endpoints have one connection. Keeping its inner poller in
        // State retires the old socket immediately when a hop replaces it.
        Box::pin(HoppingPoller { socket: self })
    }
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let state = self.state.read();
        state.current.try_send(&Transmit {
            destination: state.destination,
            src_ip: None,
            ..*transmit
        })
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.reader.register(cx.waker());
        let state = self.state.read();
        if let Some(previous) = &state.previous
            && let Poll::Ready(Ok(count)) = previous.poll_recv(cx, bufs, meta)
        {
            self.canonicalize(meta, count);
            return Poll::Ready(Ok(count));
        }
        let count = std::task::ready!(state.current.poll_recv(cx, bufs, meta))?;
        self.canonicalize(meta, count);
        Poll::Ready(Ok(count))
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.state.read().current.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        self.state.read().current.max_transmit_segments()
    }
    fn max_receive_segments(&self) -> usize {
        self.state.read().current.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.state.read().current.may_fragment()
    }
}

#[derive(Debug)]
struct HoppingPoller {
    socket: Arc<HoppingSocket>,
}

impl UdpPoller for HoppingPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.socket.writer.register(cx.waker());
        this.socket.state.write().poller.as_mut().poll_writable(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::Runtime;

    #[tokio::test]
    async fn idle_poller_does_not_retain_old_sockets_and_failed_hops_keep_current() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let sockets = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let failed = Arc::new(AtomicBool::new(false));
        let factory: SocketFactory = {
            let sockets = sockets.clone();
            let failed = failed.clone();
            Arc::new(move || {
                if failed.load(Ordering::Relaxed) {
                    return Err(io::Error::other("test socket failure"));
                }
                let socket =
                    quinn::TokioRuntime.wrap_udp_socket(std::net::UdpSocket::bind("0.0.0.0:0")?)?;
                sockets.lock().push(Arc::downgrade(&socket));
                Ok(socket)
            })
        };
        let config = HoppingConfig {
            ports: "10000-10001".into(),
            interval_secs: None,
            min_interval_secs: None,
            max_interval_secs: None,
        };
        let socket =
            HoppingSocket::new(factory, "127.0.0.1:443".parse().unwrap(), &config).unwrap();
        let poller = socket.clone().create_io_poller();
        for _ in 0..10 {
            socket.hop().unwrap();
            assert_eq!(
                sockets
                    .lock()
                    .iter()
                    .filter(|socket| socket.strong_count() > 0)
                    .count(),
                2
            );
            assert!([10000, 10001].contains(&socket.state.read().destination.port()));
        }
        failed.store(true, Ordering::Relaxed);
        let address = socket.local_addr().unwrap();
        assert!(socket.hop().is_err());
        assert_eq!(socket.local_addr().unwrap(), address);
        drop((socket, poller));
        assert!(
            sockets
                .lock()
                .iter()
                .all(|socket| socket.strong_count() == 0)
        );
    }

    #[tokio::test]
    async fn hops_refresh_poller_and_drain_previous_socket() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let peer = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
            let address = SocketAddr::from(([127, 0, 0, 1], peer.local_addr().unwrap().port()));
            let factory: SocketFactory = Arc::new(|| {
                quinn::TokioRuntime.wrap_udp_socket(std::net::UdpSocket::bind("0.0.0.0:0")?)
            });
            let config = HoppingConfig {
                ports: address.port().to_string(),
                interval_secs: Some(30),
                min_interval_secs: None,
                max_interval_secs: None,
            };
            let socket = HoppingSocket::new(factory, address, &config).unwrap();
            let mut poller = socket.clone().create_io_poller();
            let mut peers = Vec::new();
            for _ in 0..3 {
                loop {
                    std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
                        .await
                        .unwrap();
                    match socket.try_send(&Transmit {
                        destination: address,
                        contents: b"hello",
                        ecn: None,
                        segment_size: None,
                        src_ip: None,
                    }) {
                        Ok(()) => break,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(error) => panic!("{error}"),
                    }
                }
                let mut buf = [0; 64];
                let (_, from) = peer.recv_from(&mut buf).await.unwrap();
                peers.push(from);
                socket.hop().unwrap();
                peer.send_to(b"old reply", from).await.unwrap();
                let mut meta = [RecvMeta::default()];
                std::future::poll_fn(|cx| {
                    socket.poll_recv(cx, &mut [IoSliceMut::new(&mut buf)], &mut meta)
                })
                .await
                .unwrap();
                assert_eq!(&buf[..meta[0].len], b"old reply");
                assert_eq!(meta[0].addr, address);
            }
            assert_ne!(peers[0], peers[1]);
            assert_ne!(peers[1], peers[2]);
        })
        .await
        .unwrap();
    }
}
