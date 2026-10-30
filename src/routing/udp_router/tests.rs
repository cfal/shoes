use super::*;
use bytes::{BufMut, BytesMut};
use futures::task::noop_waker;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::address::Address;
use crate::async_stream::AsyncStream;
use crate::resolver::NativeResolver;
use crate::xudp::XudpMessageStream;
use crate::xudp::frame::{FrameMetadata, FrameOption, SessionStatus, TargetNetwork};
use crate::xudp::message_stream::MAX_XUDP_ROUTES;

#[tokio::test]
async fn fake_unknown_and_blocked_routes_recover_without_poisoning_wire_cache() {
    use crate::client_proxy_selector::{ConnectAction, ConnectRule};
    use crate::dns::DnsContext;
    use crate::dns::fake_ip::FakeIpOptions;
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let context = Arc::new(
        DnsContext::new(
            FakeIpOptions {
                ipv4_range: Some("198.18.0.0/29".into()),
                max_entries: 1,
                ..Default::default()
            },
            resolver.clone(),
        )
        .unwrap(),
    );
    let selector = Arc::new(
        ClientProxySelector::new(vec![ConnectRule::new(
            vec![crate::address::NetLocationMask::from("allowed.example").unwrap()],
            ConnectAction::new_allow(
                Some(NetLocation::from_ip_addr(
                    "127.0.0.1".parse().unwrap(),
                    socket.local_addr().unwrap().port(),
                )),
                crate::tcp::chain_builder::build_direct_chain_group(resolver.clone()),
            ),
        )])
        .with_fake_dns_context(Some(context.clone()))
        .unwrap(),
    );
    let source = PacketSource::default();
    let mut server = ServerStream::Targeted(Box::new(source.clone()));
    let mut router = UdpRouter::new(&mut server, selector, resolver, false);
    let wire = NetLocation::from_ip_addr(context.allocate("old.example", false).unwrap(), 443);
    context.allocate("eviction.example", false).unwrap();
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    for name in [None, Some("blocked.example")] {
        if let Some(name) = name {
            for n in 0..3 {
                context
                    .allocate(&format!("before-block{n}.example"), false)
                    .unwrap();
            }
            assert_eq!(
                context.allocate(name, false).unwrap(),
                wire.to_socket_addr_nonblocking().unwrap().ip()
            );
        }
        router.start_session_creation(
            &mut cx,
            InboundPacket {
                destination: wire.clone(),
                session_id: 0,
            },
            b"blocked",
        );
        assert!(router.pending_creates.is_empty());
        assert!(router.sessions.is_empty());
        assert!(router.blocked.is_empty());
    }
    for n in 0..4 {
        context
            .allocate(&format!("unused{n}.example"), false)
            .unwrap();
    }
    assert_eq!(
        context.allocate("allowed.example", false).unwrap(),
        wire.to_socket_addr_nonblocking().unwrap().ip()
    );
    // Even a stale wire-keyed policy entry must not hide the new mapping.
    router.blocked.put(wire.clone(), ());
    router.start_session_creation(
        &mut cx,
        InboundPacket {
            destination: wire.clone(),
            session_id: 0,
        },
        b"first",
    );
    tokio::time::timeout(
        Duration::from_secs(1),
        futures::future::poll_fn(|cx| {
            router.poll_pending_creates(cx);
            if router.pending_creates.is_empty() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }),
    )
    .await
    .unwrap();
    assert_eq!(router.sessions.len(), 1);
    assert_eq!(router.sessions.first().unwrap().1.reply_identity, wire);
    context.allocate("replacement.example", false).unwrap();
    assert!(
        context
            .restore(wire.to_socket_addr_nonblocking().unwrap().ip())
            .is_err()
    );
    source
        .packets
        .lock()
        .unwrap()
        .push_back((wire, b"pinned".to_vec()));
    tokio::time::timeout(
        Duration::from_secs(1),
        futures::future::poll_fn(|cx| {
            router.poll_outbound(cx, false);
            if router.remote_write_queue.is_empty() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }),
    )
    .await
    .unwrap();
    for expected in [b"first".as_slice(), b"pinned".as_slice()] {
        let mut bytes = [0; 32];
        let (len, _) = tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes[..len], expected);
    }
}

#[tokio::test]
async fn empty_router_finishes_on_peer_eof() {
    let (stream, peer) = tokio::io::duplex(1024);
    drop(peer);
    let mut server =
        ServerStream::Targeted(Box::new(crate::uot::UotV1ServerStream::new_uot(stream)));
    let selector = Arc::new(ClientProxySelector::new(Vec::new()));
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    tokio::time::timeout(
        Duration::from_secs(1),
        UdpRouter::new(&mut server, selector, resolver, false),
    )
    .await
    .unwrap()
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn eof_drains_accepted_setup_but_not_forever() {
    let (stream, _peer) = tokio::io::duplex(1024);
    let mut server =
        ServerStream::Targeted(Box::new(crate::uot::UotV1ServerStream::new_uot(stream)));
    let selector = Arc::new(ClientProxySelector::new(Vec::new()));
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let mut router = UdpRouter::new(&mut server, selector, resolver, false);
    let destination = NetLocation::from_str("127.0.0.1:12345", None).unwrap();
    let state = Arc::new(RemoteState::default());
    let remote = RecordingRemote {
        state: Arc::clone(&state),
    };
    let SessionLookup::ByDestination(lookup) = &mut router.session_lookup else {
        unreachable!()
    };
    lookup.insert(destination.clone(), KeyState::Pending);
    let packet = router.retain_startup_packet(b"accepted").unwrap();
    router.pending_creates.push(PendingSessionCreate {
        cache_policy_failure: true,
        lookup_key: LookupKey::Destination(destination.clone()),
        destination,
        session_id: 0,
        packets: vec![packet],
        future: Box::pin(async move {
            Ok(SessionCreateResult {
                permit: crate::resources::try_stream().unwrap(),
                remote: Box::new(remote),
                reply_identity: NetLocation::from_str("127.0.0.1:12345", None).unwrap(),
            })
        }),
    });
    router.set_server_read_eof();
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(Pin::new(&mut router).poll(&mut cx).is_pending());
    assert_eq!(*state.writes.lock().unwrap(), vec![b"accepted".to_vec()]);
    tokio::time::advance(EOF_DRAIN_TIMEOUT).await;
    assert!(matches!(
        Pin::new(&mut router).poll(&mut cx),
        Poll::Ready(Ok(()))
    ));
}

#[tokio::test(start_paused = true)]
async fn cancelled_expired_session_drops_blocked_shutdown() {
    use crate::control::flows::{FlowContext, FlowRegistry};
    use crate::control::tracked_stream::TrackedMessageStream;
    let registry = Arc::new(FlowRegistry::default());
    let destination = NetLocation::from_str("192.0.2.1:53", None).unwrap();
    let guard = FlowContext {
        registry: registry.clone(),
        generation: 1,
        inbound: "test".into(),
        scope: "root".into(),
        protocol: "Socks5".into(),
    }
    .register(
        "udp",
        &destination.clone().into(),
        vec!["DIRECT".into()],
        "all",
        Default::default(),
    );
    let (stream, _peer) = tokio::io::duplex(1024);
    let mut server =
        ServerStream::Targeted(Box::new(crate::uot::UotV1ServerStream::new_uot(stream)));
    let mut router = UdpRouter::new(
        &mut server,
        Arc::new(ClientProxySelector::new(Vec::new())),
        Arc::new(NativeResolver::new()),
        false,
    );
    let state = Arc::new(RemoteState::default());
    let mut session = RoutingSession::new(
        destination.clone(),
        0,
        destination.clone(),
        LookupKey::Destination(destination.clone()),
        Box::new(TrackedMessageStream::new(
            Box::new(RecordingRemote {
                state: state.clone(),
            }),
            guard,
        )),
    );
    session.expiry_key = Some(router.expiry_queue.insert(0, Duration::from_secs(1)));
    router.sessions.insert(0, session);
    let SessionLookup::ByDestination(lookup) = &mut router.session_lookup else {
        unreachable!()
    };
    lookup.insert(destination, KeyState::Active(0));
    tokio::time::advance(Duration::from_secs(1)).await;
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    router.process_expired(&mut cx);
    router.drain_remote_shutdowns(&mut cx);
    assert_eq!(router.pending_shutdowns.len(), 1);
    assert_eq!(registry.snapshot(0).connections.len(), 1);
    assert!(state.shutdown_polls.load(Ordering::SeqCst) > 0);
    registry.cancel_all();
    router.drain_remote_shutdowns(&mut cx);
    assert!(router.pending_shutdowns.is_empty());
    assert!(registry.snapshot(0).connections.is_empty());
    assert_eq!(state.drops.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn new_session_cancellation_wakes_behind_a_blocked_sibling_response() {
    use crate::control::flows::{FlowContext, FlowRegistry};
    use crate::control::tracked_stream::TrackedMessageStream;

    #[derive(Default)]
    struct WakeFlag(AtomicBool);
    impl futures::task::ArcWake for WakeFlag {
        fn wake_by_ref(this: &Arc<Self>) {
            this.0.store(true, Ordering::SeqCst);
        }
    }

    for cancel_before_ready in [true, false] {
        let started = tokio::time::Instant::now();
        let source = PacketSource::default();
        source.block_writes.store(true, Ordering::SeqCst);
        let mut server = ServerStream::Targeted(Box::new(source));
        let mut router = test_router(&mut server);
        let sibling = NetLocation::from_str("127.0.0.1:53", None).unwrap();
        let sibling_state = Arc::new(RemoteState::default());
        seed_pending(
            &mut router,
            LookupKey::Destination(sibling.clone()),
            b"sibling",
        );
        finish_setup(&mut router, sibling_state.clone());
        router.sessions.get_mut(&0).unwrap().in_server_write_queue = 1;
        let mut response = router.server_write_pool.acquire().unwrap();
        response[..5].copy_from_slice(b"reply");
        router.server_write_queue.push_back(PendingResponse {
            id: 0,
            buf: response,
            len: 5,
            source: sibling,
            session_id: 0,
        });

        let destination = NetLocation::from_str("192.0.2.1:53", None).unwrap();
        let registry = Arc::new(FlowRegistry::default());
        let guard = FlowContext {
            registry: registry.clone(),
            generation: 1,
            inbound: "test".into(),
            scope: "root".into(),
            protocol: "Socks5".into(),
        }
        .register(
            "udp",
            &destination.clone().into(),
            vec!["DIRECT".into()],
            "all",
            Default::default(),
        );
        let state = Arc::new(RemoteState::default());
        let remote = TrackedMessageStream::new(
            Box::new(RecordingRemote {
                state: state.clone(),
            }),
            guard,
        );
        seed_pending(
            &mut router,
            LookupKey::Destination(destination.clone()),
            b"new",
        );
        let (ready, pending) = tokio::sync::oneshot::channel();
        router.pending_creates[0].future = Box::pin(async move { pending.await.unwrap() });
        let wake = Arc::new(WakeFlag::default());
        let waker = futures::task::waker(wake.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut router).poll(&mut cx).is_pending());
        wake.0.store(false, Ordering::SeqCst);
        if cancel_before_ready {
            registry.cancel_all();
        }
        assert!(
            ready
                .send(Ok(SessionCreateResult {
                    permit: crate::resources::try_stream().unwrap(),
                    remote: Box::new(remote),
                    reply_identity: destination.clone(),
                }))
                .is_ok()
        );
        assert!(wake.0.swap(false, Ordering::SeqCst));
        assert!(Pin::new(&mut router).poll(&mut cx).is_pending());
        if !cancel_before_ready {
            assert_eq!(router.sessions.len(), 2);
            registry.cancel_all();
        }
        for _ in 0..8 {
            if !wake.0.swap(false, Ordering::SeqCst) {
                break;
            }
            assert!(Pin::new(&mut router).poll(&mut cx).is_pending());
        }
        assert_eq!(
            router.sessions.len(),
            1,
            "cancel_before_ready={cancel_before_ready}"
        );
        assert!(registry.snapshot(0).connections.is_empty());
        assert_eq!(state.drops.load(Ordering::SeqCst), 1);
        assert_eq!(state.shutdown_polls.load(Ordering::SeqCst), 0);
        assert_eq!(sibling_state.drops.load(Ordering::SeqCst), 0);
        assert_eq!(router.expiry_queue.len(), 1);
        let SessionLookup::ByDestination(lookup) = &router.session_lookup else {
            panic!()
        };
        assert!(!lookup.contains_key(&destination));
        assert_eq!(router.startup_slots.snapshot().active, 0);
        assert_eq!(router.startup_bytes.snapshot().active, 0);
        assert_eq!(router.server_write_queue.len(), 1);
        assert_eq!(&router.server_write_queue[0].buf[..5], b"reply");
        assert_eq!(router.server_write_queue[0].id, 0);
        assert_eq!(tokio::time::Instant::now(), started);
    }
}

#[tokio::test(start_paused = true)]
async fn pending_shutdowns_are_bounded_and_expire() {
    let (stream, _peer) = tokio::io::duplex(1024);
    let mut server =
        ServerStream::Targeted(Box::new(crate::uot::UotV1ServerStream::new_uot(stream)));
    let selector = Arc::new(ClientProxySelector::new(Vec::new()));
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let mut router = UdpRouter::new(&mut server, selector, resolver, false);
    let state = Arc::new(RemoteState::default());
    for _ in 0..MAX_PENDING_SHUTDOWNS + 3 {
        router.queue_shutdown(
            Box::new(RecordingRemote {
                state: Arc::clone(&state),
            }),
            None,
        );
    }
    assert_eq!(router.pending_shutdowns.len(), MAX_PENDING_SHUTDOWNS);
    assert_eq!(state.drops.load(Ordering::SeqCst), 3);
    tokio::time::advance(SHUTDOWN_TIMEOUT).await;
    let waker = noop_waker();
    router.drain_remote_shutdowns(&mut Context::from_waker(&waker));
    assert!(router.pending_shutdowns.is_empty());
    assert_eq!(
        state.drops.load(Ordering::SeqCst),
        MAX_PENDING_SHUTDOWNS + 3
    );
}

struct PendingByteStream {
    input: Vec<u8>,
    offset: usize,
}

impl AsyncRead for PendingByteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset == self.input.len() {
            return Poll::Pending;
        }

        let end = (self.offset + buf.remaining()).min(self.input.len());
        buf.put_slice(&self.input[self.offset..end]);
        self.offset = end;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for PendingByteStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for PendingByteStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for PendingByteStream {}

#[derive(Debug)]
struct CountingFailingResolver {
    calls: Arc<AtomicUsize>,
}

impl Resolver for CountingFailingResolver {
    fn resolve_location(
        &self,
        _location: &NetLocation,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            tokio::task::yield_now().await;
            Err(io::Error::other("injected DNS failure"))
        })
    }
}

#[derive(Default)]
struct RemoteState {
    writes: Mutex<Vec<Vec<u8>>>,
    pending_write: Mutex<Option<Vec<u8>>>,
    blocked: AtomicBool,
    fail_write: AtomicBool,
    shutdown_polls: AtomicUsize,
    drops: AtomicUsize,
}

struct RecordingRemote {
    state: Arc<RemoteState>,
}

impl Drop for RecordingRemote {
    fn drop(&mut self) {
        self.state.drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl AsyncReadMessage for RecordingRemote {
    fn poll_read_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWriteMessage for RecordingRemote {
    fn poll_write_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<()>> {
        if self.state.fail_write.load(Ordering::SeqCst) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let mut pending = self.state.pending_write.lock().unwrap();
        if let Some(previous) = pending.as_ref() {
            assert_eq!(
                previous, buf,
                "a pending packet was replaced before completion"
            );
        }
        if self.state.blocked.load(Ordering::SeqCst) {
            *pending = Some(buf.to_vec());
            return Poll::Pending;
        }
        pending.take();
        self.state.writes.lock().unwrap().push(buf.to_vec());
        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for RecordingRemote {
    fn poll_flush_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for RecordingRemote {
    fn poll_shutdown_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.state.shutdown_polls.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
}

impl AsyncPing for RecordingRemote {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncMessageStream for RecordingRemote {}

type PacketQueue = Arc<Mutex<VecDeque<(NetLocation, Vec<u8>)>>>;

#[derive(Clone, Default)]
struct PacketSource {
    packets: PacketQueue,
    closed: Arc<Mutex<VecDeque<MessageSessionId>>>,
    block_writes: Arc<AtomicBool>,
}

impl AsyncReadTargetedMessage for PacketSource {
    fn targeted_eof_on_empty(&self) -> bool {
        false
    }
    fn poll_read_targeted_message(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<NetLocation>> {
        match self.packets.lock().unwrap().pop_front() {
            Some((destination, payload)) => {
                buf.put_slice(&payload);
                Poll::Ready(Ok(destination))
            }
            None => Poll::Pending,
        }
    }
}
impl AsyncReadSessionMessage for PacketSource {
    fn poll_read_session_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<(MessageSessionId, NetLocation)>> {
        self.poll_read_targeted_message(cx, buf)
            .map_ok(|location| (1, location))
    }
    fn take_closed_session(&mut self) -> Option<MessageSessionId> {
        self.closed.lock().unwrap().pop_front()
    }
}
impl AsyncWriteSourcedMessage for PacketSource {
    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[u8],
        _: &NetLocation,
    ) -> Poll<io::Result<()>> {
        if self.block_writes.load(Ordering::SeqCst) {
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWriteSessionMessage for PacketSource {
    fn poll_write_session_message(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: MessageSessionId,
        _: &[u8],
        _: &NetLocation,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl AsyncFlushMessage for PacketSource {
    fn poll_flush_message(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl AsyncShutdownMessage for PacketSource {
    fn poll_shutdown_message(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl AsyncPing for PacketSource {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncTargetedMessageStream for PacketSource {}
impl AsyncSessionMessageStream for PacketSource {}

fn test_router(server: &mut ServerStream) -> UdpRouter<'_> {
    UdpRouter::new(
        server,
        Arc::new(ClientProxySelector::new(Vec::new())),
        Arc::new(NativeResolver::new()),
        false,
    )
}

fn seed_pending(router: &mut UdpRouter<'_>, key: LookupKey, data: &[u8]) {
    let destination = NetLocation::from_str("127.0.0.1:53", None).unwrap();
    let packet = router.retain_startup_packet(data).unwrap();
    match (&mut router.session_lookup, &key) {
        (SessionLookup::ByDestination(map), LookupKey::Destination(destination)) => {
            map.insert(destination.clone(), KeyState::Pending);
        }
        (SessionLookup::BySessionId(map), LookupKey::SessionId(id)) => {
            map.insert(*id, KeyState::Pending);
        }
        _ => unreachable!(),
    }
    router.pending_creates.push(PendingSessionCreate {
        cache_policy_failure: true,
        lookup_key: key,
        destination,
        session_id: 1,
        packets: vec![packet],
        future: Box::pin(std::future::pending()),
    });
}

fn finish_setup(router: &mut UdpRouter<'_>, state: Arc<RemoteState>) {
    router.pending_creates[0].future = Box::pin(async move {
        Ok(SessionCreateResult {
            permit: crate::resources::try_stream().unwrap(),
            remote: Box::new(RecordingRemote { state }),
            reply_identity: NetLocation::from_str("127.0.0.1:53", None).unwrap(),
        })
    });
    assert!(
        router.poll_pending_create(&mut Context::from_waker(futures::task::noop_waker_ref()), 0)
    );
}

#[tokio::test]
async fn startup_burst_survives_pool_exhaustion_and_keeps_owned_and_pooled_order() {
    let source = PacketSource::default();
    let destination = NetLocation::from_str("127.0.0.1:53", None).unwrap();
    let mut server = ServerStream::Targeted(Box::new(source.clone()));
    let mut router = test_router(&mut server);
    seed_pending(
        &mut router,
        LookupKey::Destination(destination.clone()),
        b"",
    );
    for i in 1..=4 {
        source
            .packets
            .lock()
            .unwrap()
            .push_back((destination.clone(), vec![i]));
    }
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    router.poll_read_server(&mut cx);
    assert_eq!(router.pending_creates[0].packets.len(), 4);
    assert_eq!(router.startup_queue_drops, 1);
    assert_eq!(router.startup_slots.snapshot().active, 4);
    assert_eq!(router.startup_bytes.snapshot().active, 3);
    let pointers: Vec<_> = router.pending_creates[0]
        .packets
        .iter()
        .map(|packet| packet.data.as_ptr())
        .collect();

    let mut held = Vec::new();
    while let Some(buffer) = router.remote_write_pool.acquire() {
        held.push(buffer);
    }
    let state = Arc::new(RemoteState::default());
    state.blocked.store(true, Ordering::SeqCst);
    finish_setup(&mut router, state.clone());
    assert_eq!(router.startup_slots.snapshot().active, 4);
    assert!(!router.drain_remote_writes(&mut cx));
    assert_eq!(
        router
            .remote_write_queue
            .iter()
            .map(|packet| packet.buf.as_slice().as_ptr())
            .collect::<Vec<_>>(),
        pointers
    );
    assert!(!router.drain_remote_writes(&mut cx));

    router.remote_write_pool.release(held.pop().unwrap());
    source
        .packets
        .lock()
        .unwrap()
        .push_back((destination, vec![9]));
    router.poll_read_server(&mut cx);
    assert_eq!(router.remote_write_queue.len(), 5);
    assert!(!router.drain_remote_writes(&mut cx));
    state.blocked.store(false, Ordering::SeqCst);
    assert!(router.drain_remote_writes(&mut cx));
    assert_eq!(
        *state.writes.lock().unwrap(),
        vec![vec![], vec![1], vec![2], vec![3], vec![9]]
    );
    assert_eq!(router.startup_written, 4);
    assert_eq!(router.startup_slots.snapshot().active, 0);
    assert_eq!(router.startup_bytes.snapshot().active, 0);
    for buffer in held {
        router.remote_write_pool.release(buffer);
    }
    assert_eq!(
        router.remote_write_pool.buffers.len(),
        REMOTE_WRITE_POOL_SIZE
    );
    assert!(
        router
            .remote_write_pool
            .buffers
            .iter()
            .all(|buffer| buffer.len() == MAX_UDP_PACKET_SIZE)
    );
}

#[tokio::test]
async fn startup_packet_and_byte_budgets_cover_active_backlogs_and_drop() {
    let mut server = ServerStream::Targeted(Box::new(PacketSource::default()));
    let mut router = test_router(&mut server);
    let mut packets = Vec::new();
    for _ in 0..MAX_STARTUP_PACKETS {
        packets.push(router.retain_startup_packet(b"").unwrap());
    }
    assert!(router.retain_startup_packet(b"").is_none());
    assert_eq!(router.startup_slots.snapshot().rejected, 1);
    drop(packets);
    let packet = router
        .retain_startup_packet(&vec![0; MAX_STARTUP_BYTES])
        .unwrap();
    assert!(router.retain_startup_packet(b"x").is_none());
    assert_eq!(router.startup_slots.snapshot().active, 1);
    assert_eq!(router.startup_bytes.snapshot().rejected, 1);
    drop(packet);
    let destination = NetLocation::from_str("127.0.0.1:53", None).unwrap();
    seed_pending(&mut router, LookupKey::Destination(destination), b"owned");
    let bytes = router.startup_bytes.clone();
    let slots = router.startup_slots.clone();
    finish_setup(&mut router, Arc::new(RemoteState::default()));
    assert_eq!(bytes.snapshot().active, 5);
    drop(router);
    assert_eq!(bytes.snapshot().active, 0);
    assert_eq!(slots.snapshot().active, 0);
}

#[tokio::test]
async fn startup_setup_failure_write_error_and_session_close_release_owners() {
    for outcome in ["setup", "write", "close", "active_close"] {
        let source = PacketSource::default();
        let mut server = ServerStream::Session(Box::new(source.clone()));
        let mut router = test_router(&mut server);
        seed_pending(&mut router, LookupKey::SessionId(1), b"first");
        let second = router.retain_startup_packet(b"second").unwrap();
        router.pending_creates[0].packets.push(second);
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        match outcome {
            "setup" => {
                router.pending_creates[0].future =
                    Box::pin(async { Err(io::ErrorKind::ConnectionRefused.into()) });
                router.poll_pending_create(&mut cx, 0);
            }
            "write" => {
                let state = Arc::new(RemoteState::default());
                state.fail_write.store(true, Ordering::SeqCst);
                finish_setup(&mut router, state);
                router.drain_remote_writes(&mut cx);
                router.cancel_session(0);
            }
            "close" => {
                source.closed.lock().unwrap().push_back(1);
                router.drain_closed_server_sessions();
            }
            "active_close" => {
                finish_setup(&mut router, Arc::new(RemoteState::default()));
                source.closed.lock().unwrap().push_back(1);
                router.drain_closed_server_sessions();
            }
            _ => unreachable!(),
        }
        assert_eq!(router.startup_slots.snapshot().active, 0);
        assert_eq!(router.startup_bytes.snapshot().active, 0);
        assert_eq!(router.startup_written, 0);
        assert!(router.pending_creates.is_empty());
        assert!(router.remote_write_queue.is_empty());
        let SessionLookup::BySessionId(lookup) = &router.session_lookup else {
            unreachable!()
        };
        assert!(lookup.is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn startup_admission_precedes_setup_and_timeout_releases_the_burst() {
    use crate::client_proxy_selector::{ConnectAction, ConnectRule};
    #[derive(Debug)]
    struct StalledResolver;
    impl Resolver for StalledResolver {
        fn resolve_location(
            &self,
            _: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
            Box::pin(std::future::pending())
        }
    }
    let source = PacketSource::default();
    let mut server = ServerStream::Targeted(Box::new(source.clone()));
    let resolver: Arc<dyn Resolver> = Arc::new(StalledResolver);
    let selector = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
        vec![crate::address::NetLocationMask::from("0.0.0.0/0").unwrap()],
        ConnectAction::new_allow(
            None,
            crate::tcp::chain_builder::build_direct_chain_group(resolver.clone()),
        ),
    )]));
    let mut router = UdpRouter::new(&mut server, selector, resolver, false);
    let destination = NetLocation::from_str("delayed.invalid:53", None).unwrap();
    for i in 0..5 {
        source
            .packets
            .lock()
            .unwrap()
            .push_back((destination.clone(), vec![i]));
    }
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    router.poll_read_server(&mut cx);
    assert_eq!(router.pending_creates.len(), 1);
    assert_eq!(router.pending_creates[0].packets.len(), 4);
    assert_eq!(router.startup_queue_drops, 1);
    tokio::time::advance(SESSION_SETUP_TIMEOUT).await;
    router.poll_pending_creates(&mut cx);
    assert!(router.pending_creates.is_empty());
    assert_eq!(router.startup_slots.snapshot().active, 0);
    assert_eq!(router.startup_bytes.snapshot().active, 0);
    router.startup_bytes = Arc::new(crate::resources::Budget::new(Some(0)));
    router.start_session_creation(
        &mut cx,
        InboundPacket {
            destination,
            session_id: 0,
        },
        b"cannot fit",
    );
    assert!(router.pending_creates.is_empty());
    let SessionLookup::ByDestination(lookup) = &router.session_lookup else {
        unreachable!()
    };
    assert!(lookup.is_empty());
    assert_eq!(router.startup_slots.snapshot().active, 0);
}

#[tokio::test(start_paused = true)]
async fn session_expiry_releases_an_active_startup_backlog() {
    let mut server = ServerStream::Targeted(Box::new(PacketSource::default()));
    let mut router = test_router(&mut server);
    let destination = NetLocation::from_str("127.0.0.1:53", None).unwrap();
    seed_pending(
        &mut router,
        LookupKey::Destination(destination),
        b"retained",
    );
    finish_setup(&mut router, Arc::new(RemoteState::default()));
    tokio::time::advance(Duration::from_secs(SESSION_TIMEOUT_SECS)).await;
    router.process_expired(&mut Context::from_waker(futures::task::noop_waker_ref()));
    assert!(router.remote_write_queue.is_empty());
    assert_eq!(router.startup_slots.snapshot().active, 0);
    assert_eq!(router.startup_bytes.snapshot().active, 0);
}

#[tokio::test]
async fn pending_packets_keep_order_and_a_single_flow_burst_uses_bounded_backpressure() {
    let destination = NetLocation::from_str("127.0.0.1:53", None).unwrap();
    let mut input = BytesMut::new();
    let expected: Vec<Vec<u8>> = (0..20).map(|i| vec![i]).collect();
    for (index, payload) in expected.iter().enumerate() {
        append_xudp_frame(
            &mut input,
            10,
            if index == 0 {
                SessionStatus::New
            } else {
                SessionStatus::Keep
            },
            Some(destination.clone()),
            Some(payload),
        );
    }
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let xudp = XudpMessageStream::new(Box::new(PendingByteStream {
        input: input.to_vec(),
        offset: 0,
    }));
    let mut server = ServerStream::Session(Box::new(xudp));
    let mut router = UdpRouter::new(
        &mut server,
        Arc::new(ClientProxySelector::new(Vec::new())),
        resolver,
        false,
    );
    let state = Arc::new(RemoteState::default());
    state.blocked.store(true, Ordering::SeqCst);
    router.sessions.insert(
        0,
        RoutingSession::new(
            destination.clone(),
            1,
            destination.clone(),
            LookupKey::SessionId(1),
            Box::new(RecordingRemote {
                state: state.clone(),
            }),
        ),
    );
    let SessionLookup::BySessionId(lookup) = &mut router.session_lookup else {
        unreachable!()
    };
    lookup.insert(1, KeyState::Active(0));
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    router.poll_outbound(&mut cx, false);
    assert_eq!(router.remote_write_queue.len(), REMOTE_WRITE_POOL_SIZE);
    assert_eq!(
        router.remote_write_pool.created_count,
        REMOTE_WRITE_POOL_SIZE
    );
    state.blocked.store(false, Ordering::SeqCst);
    router.poll_outbound(&mut cx, false);
    assert_eq!(*state.writes.lock().unwrap(), expected);
    assert!(router.remote_write_queue.is_empty());
}

fn append_xudp_frame(
    output: &mut BytesMut,
    session_id: u16,
    status: SessionStatus,
    destination: Option<NetLocation>,
    payload: Option<&[u8]>,
) {
    FrameMetadata {
        session_id,
        status,
        option: if payload.is_some() {
            FrameOption::new().with_data()
        } else {
            FrameOption::new()
        },
        network: destination.as_ref().map(|_| TargetNetwork::Udp),
        target: destination,
    }
    .encode(output)
    .unwrap();
    if let Some(payload) = payload {
        output.put_u16(payload.len() as u16);
        output.extend_from_slice(payload);
    }
}

#[tokio::test]
async fn route_overflow_preserves_existing_route_and_end_cancels_remote() {
    let address = Address::Ipv4("127.0.0.1".parse().unwrap());
    let default_destination = NetLocation::new(address.clone(), 1);
    let mut input = BytesMut::new();
    append_xudp_frame(
        &mut input,
        10,
        SessionStatus::New,
        Some(default_destination.clone()),
        Some(b"before limit"),
    );
    for port in 2..=MAX_XUDP_ROUTES as u16 {
        append_xudp_frame(
            &mut input,
            10,
            SessionStatus::Keep,
            Some(NetLocation::new(address.clone(), port)),
            Some(b"fill"),
        );
    }
    let overflow_destination = NetLocation::new(
        Address::Hostname("cap-probe.invalid".to_string()),
        MAX_XUDP_ROUTES as u16 + 1,
    );
    for _ in 0..2 {
        append_xudp_frame(
            &mut input,
            10,
            SessionStatus::Keep,
            Some(overflow_destination.clone()),
            Some(b"overflow"),
        );
    }
    append_xudp_frame(
        &mut input,
        10,
        SessionStatus::Keep,
        None,
        Some(b"after limit"),
    );
    append_xudp_frame(&mut input, 10, SessionStatus::End, None, None);

    let inner = PendingByteStream {
        input: input.to_vec(),
        offset: 0,
    };
    let resolver_calls = Arc::new(AtomicUsize::new(0));
    let xudp = XudpMessageStream::new(Box::new(inner));
    let mut server = ServerStream::Session(Box::new(xudp));
    let selector = Arc::new(ClientProxySelector::new(Vec::new()));
    let resolver: Arc<dyn Resolver> = Arc::new(CountingFailingResolver {
        calls: Arc::clone(&resolver_calls),
    });
    let mut router = UdpRouter::new(&mut server, selector, resolver, false);

    let state = Arc::new(RemoteState::default());
    let resolved_destination = default_destination.clone();
    let mut session = RoutingSession::new(
        default_destination,
        1,
        resolved_destination,
        LookupKey::SessionId(1),
        Box::new(RecordingRemote {
            state: Arc::clone(&state),
        }),
    );
    session.expiry_key = Some(
        router
            .expiry_queue
            .insert(0, Duration::from_secs(SESSION_TIMEOUT_SECS)),
    );
    router.sessions.insert(0, session);
    let SessionLookup::BySessionId(lookup) = &mut router.session_lookup else {
        unreachable!()
    };
    lookup.insert(1, KeyState::Active(0));

    for index in 0..MAX_PENDING_CREATES {
        router.pending_creates.push(PendingSessionCreate {
            cache_policy_failure: true,
            lookup_key: LookupKey::SessionId(10_000 + index as u64),
            destination: NetLocation::new(
                Address::Ipv4("192.0.2.1".parse().unwrap()),
                index as u16 + 1,
            ),
            session_id: 10_000 + index as u64,
            packets: Vec::new(),
            future: Box::pin(std::future::pending()),
        });
    }

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert_eq!(router.poll_read_server(&mut cx), (true, true));
    assert!(!router.server_read_eof);
    assert!(router.sessions.is_empty());
    assert!(router.pending_shutdowns.is_empty());
    assert_eq!(
        *state.writes.lock().unwrap(),
        vec![b"before limit".to_vec(), b"after limit".to_vec()]
    );
    assert_eq!(state.shutdown_polls.load(Ordering::SeqCst), 0);
    assert_eq!(state.drops.load(Ordering::SeqCst), 1);
    assert_eq!(resolver_calls.load(Ordering::SeqCst), 0);
}
