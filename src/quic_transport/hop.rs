//! A UDP socket that moves: Hysteria2 client port hopping.
//!
//! The mechanism is not a performance feature. Rotating the port changes the
//! connection's 4-tuple on a timer, so a middlebox tracking the flow loses it,
//! and a server published as a port range becomes reachable at all.
//!
//! Modelled on `extras/transport/udphop/conn.go` in the reference
//! implementation, including the parts that are counter-intuitive: a new
//! socket is bound on every hop rather than the destination being rewritten on
//! one, and two sockets stay live at a time.

use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::task::AtomicWaker;
use parking_lot::RwLock;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rand::RngExt;

use crate::address::parse_port_union;

/// The candidate ports a hopping socket draws from.
///
/// Upstream picks uniformly at random rather than cycling; a predictable cycle
/// would be a pattern, and hiding the pattern is the entire point.
#[derive(Debug, Clone)]
pub struct PortSet {
    ports: Vec<u16>,
}

impl PortSet {
    pub fn parse(s: &str) -> std::io::Result<Self> {
        Ok(Self {
            ports: parse_port_union(s)?,
        })
    }

    pub fn pick(&self) -> u16 {
        // parse_port_union rejects an empty union, so this cannot be empty.
        self.ports[rand::rng().random_range(0..self.ports.len())]
    }
}

/// How long to wait before the next hop.
#[derive(Debug, Clone, Copy)]
pub enum HopSchedule {
    Fixed(Duration),
    Range { min: Duration, max: Duration },
}

impl HopSchedule {
    pub fn next(&self) -> Duration {
        match *self {
            HopSchedule::Fixed(interval) => interval,
            HopSchedule::Range { min, max } => {
                if min >= max {
                    return min;
                }
                let span = (max - min).as_millis() as u64;
                min + Duration::from_millis(rand::rng().random_range(0..=span))
            }
        }
    }
}

/// Upstream's default interval (`extras/transport/udphop/conn.go`).
pub const DEFAULT_HOP_INTERVAL: Duration = Duration::from_secs(30);

/// Everything the outbound needs in order to hop, resolved from config.
#[derive(Debug, Clone)]
pub struct HopSettings {
    pub ports: PortSet,
    pub schedule: HopSchedule,
}

impl HopSettings {
    /// Build from the config's raw fields.
    ///
    /// Validation has already refused the impossible combinations, so this is
    /// the translation rather than a second check: a fixed interval and a
    /// range cannot both be present here.
    pub fn new(
        ports: &str,
        interval_ms: Option<u64>,
        min_interval_ms: Option<u64>,
        max_interval_ms: Option<u64>,
    ) -> std::io::Result<Self> {
        let schedule = match (interval_ms, min_interval_ms, max_interval_ms) {
            (_, Some(min), Some(max)) => HopSchedule::Range {
                min: Duration::from_millis(min),
                max: Duration::from_millis(max),
            },
            (Some(interval), _, _) => HopSchedule::Fixed(Duration::from_millis(interval)),
            _ => HopSchedule::Fixed(DEFAULT_HOP_INTERVAL),
        };
        Ok(Self {
            ports: PortSet::parse(ports)?,
            schedule,
        })
    }
}

/// Builds a fresh inner socket, already wrapped in whatever the outbound needs
/// and already protected from the VPN route.
///
/// Every socket in this module comes from here; there are no direct binds. A
/// socket is created on a timer for the life of a connection, and one that
/// skipped the protector would be routed back into the tunnel it carries.
pub type SocketFactory = Arc<dyn Fn() -> std::io::Result<Arc<dyn AsyncUdpSocket>> + Send + Sync>;

struct HopState {
    current: Arc<dyn AsyncUdpSocket>,
    /// The socket from the last hop. Kept because the server may already have
    /// sent to the old port; without it those datagrams vanish silently.
    previous: Option<Arc<dyn AsyncUdpSocket>>,
    destination: SocketAddr,
    generation: u64,
}

pub struct HoppingUdpSocket {
    factory: SocketFactory,
    /// The address quinn is told about, in both directions, for the whole
    /// connection. The real destination moves underneath it.
    canonical: SocketAddr,
    ports: PortSet,
    state: RwLock<HopState>,
    /// Woken on a hop, so a quinn task parked on the old socket learns about
    /// the new one instead of waiting for a datagram that may never come.
    waker: AtomicWaker,
}

impl std::fmt::Debug for HoppingUdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.read();
        f.debug_struct("HoppingUdpSocket")
            .field("canonical", &self.canonical)
            .field("destination", &state.destination)
            .field("generation", &state.generation)
            .finish_non_exhaustive()
    }
}

impl HoppingUdpSocket {
    pub fn new(
        factory: SocketFactory,
        canonical: SocketAddr,
        ports: PortSet,
    ) -> std::io::Result<Arc<Self>> {
        let current = factory()?;
        let destination = SocketAddr::new(canonical.ip(), ports.pick());
        Ok(Arc::new(Self {
            factory,
            canonical,
            ports,
            state: RwLock::new(HopState {
                current,
                previous: None,
                destination,
                generation: 0,
            }),
            waker: AtomicWaker::new(),
        }))
    }

    /// Bind a fresh socket, pick a fresh destination, and retire the oldest.
    ///
    /// The ordering mirrors upstream: the socket that was previous is dropped
    /// — which closes it — the current becomes previous, and the new one
    /// becomes current. Two sockets are therefore live between hops, and that
    /// is what covers the datagrams already in flight to the old port.
    ///
    /// A failure leaves everything as it was. Losing a working connection
    /// because a hop could not bind would turn an anti-blocking feature into
    /// an outage.
    pub fn hop(&self) -> std::io::Result<()> {
        let socket = (self.factory)()?;
        let destination = SocketAddr::new(self.canonical.ip(), self.ports.pick());

        {
            let mut state = self.state.write();
            state.previous = Some(std::mem::replace(&mut state.current, socket));
            state.destination = destination;
            state.generation += 1;
        }

        self.waker.wake();
        Ok(())
    }
}

/// Drive `socket` on `schedule` until it is dropped.
///
/// The task holds a `Weak`, so it ends when the endpoint does rather than
/// keeping a connection's sockets alive forever.
pub fn spawn_hop_task(socket: &Arc<HoppingUdpSocket>, schedule: HopSchedule) {
    let weak = Arc::downgrade(socket);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(schedule.next()).await;
            let Some(socket) = weak.upgrade() else {
                return;
            };
            if let Err(e) = socket.hop() {
                // Staying put beats dropping a working connection.
                log::warn!("port hop failed, keeping the current socket: {e}");
            }
        }
    });
}

/// Report every datagram in the batch as having come from `canonical`.
///
/// Upstream rewrites unconditionally rather than filtering by source, and so
/// do we. A stranger's datagram fails QUIC's own authentication and is
/// discarded a layer up, whereas filtering by address would break a
/// multi-homed server for no security gain.
fn canonicalise(meta: &mut [RecvMeta], count: usize, canonical: SocketAddr) {
    for entry in meta.iter_mut().take(count) {
        entry.addr = canonical;
    }
}

impl AsyncUdpSocket for HoppingUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        let (generation, current) = {
            let state = self.state.read();
            (state.generation, state.current.clone())
        };
        Box::pin(HoppingPoller {
            socket: self,
            generation,
            inner: current.create_io_poller(),
        })
    }

    fn try_send(&self, transmit: &Transmit) -> std::io::Result<()> {
        // max_transmit_segments() is 1, so quinn must never batch. If that
        // promise breaks, sending the batch as one datagram would put several
        // packets on the wire glued together.
        if transmit.segment_size.is_some() {
            return Err(std::io::Error::other(
                "hopping sockets cannot send segmented transmits",
            ));
        }

        let state = self.state.read();
        state.current.try_send(&Transmit {
            destination: state.destination,
            ecn: transmit.ecn,
            contents: transmit.contents,
            segment_size: None,
            // The socket quinn believes it is using is not the one carrying
            // this datagram, so its source hint is stale.
            src_ip: None,
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        self.waker.register(cx.waker());

        let state = self.state.read();
        match state.current.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(count)) => {
                canonicalise(meta, count, self.canonical);
                return Poll::Ready(Ok(count));
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => {}
        }

        if let Some(previous) = state.previous.as_ref() {
            match previous.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(count)) => {
                    canonicalise(meta, count, self.canonical);
                    return Poll::Ready(Ok(count));
                }
                // The previous socket is scheduled to die; its errors are
                // expected and must not take the connection with them.
                Poll::Ready(Err(_)) | Poll::Pending => {}
            }
        }

        Poll::Pending
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.state.read().current.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.state.read().current.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

/// quinn asks for a poller once and holds it for the connection's life, while
/// the socket underneath is replaced on every hop. This one notices.
struct HoppingPoller {
    socket: Arc<HoppingUdpSocket>,
    generation: u64,
    inner: Pin<Box<dyn UdpPoller>>,
}

impl std::fmt::Debug for HoppingPoller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HoppingPoller")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl UdpPoller for HoppingPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let (generation, current) = {
            let state = this.socket.state.read();
            (state.generation, state.current.clone())
        };
        if generation != this.generation {
            this.inner = current.create_io_poller();
            this.generation = generation;
        }
        this.inner.as_mut().poll_writable(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::{Runtime, TokioRuntime};
    use std::net::UdpSocket;

    /// A hopping socket whose port set contains exactly `peer`'s port, so a
    /// hop cannot change where it sends, and whose factory binds loopback.
    fn fixed_socket(peer: SocketAddr) -> Arc<HoppingUdpSocket> {
        let factory: SocketFactory = Arc::new(|| {
            let socket = UdpSocket::bind("127.0.0.1:0")?;
            TokioRuntime.wrap_udp_socket(socket)
        });
        HoppingUdpSocket::new(
            factory,
            peer,
            PortSet::parse(&peer.port().to_string()).unwrap(),
        )
        .unwrap()
    }

    /// Send one datagram, honouring quinn's contract: `try_send` may report
    /// WouldBlock until the socket says it is writable, and the poller is how
    /// that is asked. Going through it here also exercises the poller.
    async fn send(socket: &Arc<HoppingUdpSocket>, payload: &[u8]) {
        // The destination quinn asks for is deliberately wrong: the socket
        // must ignore it and use the one it chose.
        let bogus: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut poller = socket.clone().create_io_poller();
        loop {
            std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
                .await
                .unwrap();
            match socket.try_send(&Transmit {
                destination: bogus,
                ecn: None,
                contents: payload,
                segment_size: None,
                src_ip: None,
            }) {
                Ok(()) => return,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => panic!("send failed: {e}"),
            }
        }
    }

    async fn recv_one(socket: &HoppingUdpSocket, buf: &mut [u8]) -> (usize, SocketAddr) {
        let mut bufs = [IoSliceMut::new(buf)];
        let mut meta = [RecvMeta::default()];
        let count = std::future::poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta))
            .await
            .unwrap();
        assert_eq!(count, 1);
        (meta[0].len, meta[0].addr)
    }

    /// quinn is told where to send; the hopping socket overrules it. Honouring
    /// the requested destination would send every packet to the original port
    /// and the feature would do nothing.
    #[tokio::test]
    async fn test_a_send_goes_to_the_chosen_destination_not_the_requested_one() {
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let socket = fixed_socket(peer_addr);
        send(&socket, b"overruled").await;

        let mut buf = [0u8; 64];
        let (n, _) = peer.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"overruled");
    }

    /// Every datagram must be reported as coming from one constant address.
    /// Reporting the real source would show quinn a new peer on every hop,
    /// which it reads as a path change.
    #[tokio::test]
    async fn test_every_datagram_is_reported_from_the_canonical_address() {
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let socket = fixed_socket(peer_addr);

        send(&socket, b"ping").await;
        let mut buf = [0u8; 64];
        let (_, from) = peer.recv_from(&mut buf).unwrap();
        peer.send_to(b"pong", from).unwrap();

        let mut recv_buf = [0u8; 64];
        let (len, addr) = recv_one(&socket, &mut recv_buf).await;
        assert_eq!(&recv_buf[..len], b"pong");
        assert_eq!(
            addr, peer_addr,
            "the source must be canonicalised, not reported as it arrived"
        );
    }

    /// We report max_transmit_segments() == 1, so quinn must never hand us a
    /// batch. Sending one anyway would put several packets on the wire glued
    /// together.
    #[tokio::test]
    async fn test_a_segmented_transmit_is_refused() {
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let socket = fixed_socket(peer);
        let err = socket
            .try_send(&Transmit {
                destination: peer,
                ecn: None,
                contents: b"batched",
                segment_size: Some(4),
                src_ip: None,
            })
            .unwrap_err();
        assert!(err.to_string().contains("segmented"), "{err}");
    }

    /// A factory that counts its calls and fails once it has made `budget`
    /// sockets.
    fn counting_factory(budget: usize) -> SocketFactory {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        Arc::new(move || {
            if calls.fetch_add(1, Ordering::SeqCst) >= budget {
                return Err(std::io::Error::other("factory exhausted"));
            }
            let socket = UdpSocket::bind("127.0.0.1:0")?;
            TokioRuntime.wrap_udp_socket(socket)
        })
    }

    /// The point of the feature: the local port moves too. Rotating only the
    /// destination leaves the flow linkable by its unchanged source.
    #[tokio::test]
    async fn test_a_hop_binds_a_new_local_port() {
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let socket = fixed_socket(peer);

        let before = socket.local_addr().unwrap();
        socket.hop().unwrap();
        let after = socket.local_addr().unwrap();

        assert_ne!(before, after, "the local port did not move");
    }

    /// The server may already have sent to the old port. Without the overlap
    /// those datagrams are lost, and on a busy connection that is a stall.
    #[tokio::test]
    async fn test_the_previous_socket_still_receives_after_a_hop() {
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let socket = fixed_socket(peer_addr);

        // Let the peer learn the pre-hop local address.
        send(&socket, b"before").await;
        let mut buf = [0u8; 64];
        let (_, old_local) = peer.recv_from(&mut buf).unwrap();

        socket.hop().unwrap();

        // The server answers the address it knew about.
        peer.send_to(b"late reply", old_local).unwrap();

        let mut recv_buf = [0u8; 64];
        let (len, _) =
            tokio::time::timeout(Duration::from_secs(5), recv_one(&socket, &mut recv_buf))
                .await
                .expect("a datagram sent to the previous socket must still arrive");
        assert_eq!(&recv_buf[..len], b"late reply");
    }

    /// Two hops later the oldest socket is gone. Keeping every socket would
    /// leak a descriptor per hop for the life of the connection.
    #[tokio::test]
    async fn test_the_socket_from_two_hops_ago_is_closed() {
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let socket = fixed_socket(peer_addr);

        send(&socket, b"first").await;
        let mut buf = [0u8; 64];
        let (_, oldest_local) = peer.recv_from(&mut buf).unwrap();

        socket.hop().unwrap();
        socket.hop().unwrap();

        peer.send_to(b"too late", oldest_local).unwrap();

        let mut recv_buf = [0u8; 64];
        let outcome =
            tokio::time::timeout(Duration::from_millis(300), recv_one(&socket, &mut recv_buf))
                .await;
        assert!(
            outcome.is_err(),
            "a datagram to the socket from two hops ago must not arrive"
        );
    }

    /// A hop that cannot bind must not take the connection down. Turning an
    /// anti-blocking feature into an outage is worse than not having it.
    #[tokio::test]
    async fn test_a_failed_hop_leaves_the_current_socket_working() {
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let peer_addr = peer.local_addr().unwrap();

        // One socket for construction, nothing left for a hop.
        let socket = HoppingUdpSocket::new(
            counting_factory(1),
            peer_addr,
            PortSet::parse(&peer_addr.port().to_string()).unwrap(),
        )
        .unwrap();

        let before = socket.local_addr().unwrap();
        assert!(socket.hop().is_err(), "the factory was set to fail");
        assert_eq!(
            socket.local_addr().unwrap(),
            before,
            "a failed hop must leave the working socket in place"
        );

        send(&socket, b"still alive").await;
        let mut buf = [0u8; 64];
        let (n, _) = peer.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"still alive");
    }

    /// Without this wake, a task parked on the old socket waits for a datagram
    /// that may never come.
    #[tokio::test]
    async fn test_a_hop_wakes_a_parked_receiver() {
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let socket = fixed_socket(peer);
        let parked = socket.clone();

        let receiver = tokio::spawn(async move {
            let mut recv_buf = [0u8; 64];
            let mut bufs = [IoSliceMut::new(&mut recv_buf)];
            let mut meta = [RecvMeta::default()];
            let mut polls = 0u32;
            std::future::poll_fn(|cx| {
                polls += 1;
                if polls > 1 {
                    // Woken again, which is all this test is asking about.
                    return Poll::Ready(());
                }
                let _ = parked.poll_recv(cx, &mut bufs, &mut meta);
                Poll::Pending
            })
            .await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        socket.hop().unwrap();

        tokio::time::timeout(Duration::from_secs(5), receiver)
            .await
            .expect("the hop must wake a parked receiver")
            .unwrap();
    }

    #[test]
    fn test_port_set_only_yields_configured_ports() {
        let set = PortSet::parse("5000-5002,7044").unwrap();
        for _ in 0..200 {
            let port = set.pick();
            assert!(
                [5000, 5001, 5002, 7044].contains(&port),
                "picked {port}, which is not in the set"
            );
        }
    }

    /// A set of one is legal and must not loop forever or panic.
    #[test]
    fn test_a_single_port_set_is_constant() {
        let set = PortSet::parse("443").unwrap();
        assert_eq!(set.pick(), 443);
    }

    /// Every port has to be reachable, or a range is a lie: a picker that only
    /// ever returned the first port would pass a weaker test.
    #[test]
    fn test_every_port_is_reachable() {
        let set = PortSet::parse("100-103").unwrap();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..500 {
            seen.insert(set.pick());
        }
        assert_eq!(seen.len(), 4, "only saw {seen:?}");
    }

    #[test]
    fn test_a_fixed_schedule_returns_its_interval() {
        let schedule = HopSchedule::Fixed(Duration::from_millis(250));
        for _ in 0..10 {
            assert_eq!(schedule.next(), Duration::from_millis(250));
        }
    }

    #[test]
    fn test_a_ranged_schedule_stays_within_its_bounds() {
        let schedule = HopSchedule::Range {
            min: Duration::from_millis(100),
            max: Duration::from_millis(200),
        };
        for _ in 0..200 {
            let interval = schedule.next();
            assert!(
                interval >= Duration::from_millis(100) && interval <= Duration::from_millis(200),
                "{interval:?} is outside the configured range"
            );
        }
    }
}
