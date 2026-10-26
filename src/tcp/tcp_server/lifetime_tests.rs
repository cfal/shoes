use super::*;
use async_trait::async_trait;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use tokio::io::ReadBuf;

use crate::address::NetLocation;
use crate::async_stream::{
    AsyncFlushMessage, AsyncPing, AsyncReadMessage, AsyncShutdownMessage, AsyncWriteMessage,
};
use crate::client_proxy_chain::{ClientChainGroup, ClientProxyChain, InitialHopEntry};
use crate::client_proxy_selector::{ClientProxySelector, ConnectAction, ConnectRule};
use crate::tcp::socket_connector::SocketConnector;

#[tokio::test]
async fn ephemeral_tcp_activation_does_not_cache_automatic_ports() {
    let mut sockets = TcpListeners::default();
    let first = sockets.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let second = sockets.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    assert_ne!(first.local_addr().unwrap(), second.local_addr().unwrap());
    assert!(sockets.sockets.is_empty());
    assert_eq!(sockets.automatic_sockets.len(), 2);
    drop((first, second));
    let _next = sockets.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    assert_eq!(sockets.automatic_sockets.len(), 1);
}

#[tokio::test]
async fn tcp_preparation_defers_reported_http_overlap_before_binding() {
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    let config = format!("- address: '{address}'\n  protocol: {{type: http}}\n");
    let configs =
        crate::config::create_server_configs(serde_yaml::from_str(&config).unwrap()).unwrap();
    drop(reservation);
    for retiring in [
        address,
        SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), address.port()),
    ] {
        let next =
            TcpListeners::prepare(&configs.configs, &TcpListeners::default(), &[retiring]).unwrap();
        assert!(next.sockets.is_empty(), "overlapping listener was prebound");
        std::net::TcpListener::bind(address).expect("preparation claimed a retiring address");
    }
}

#[tokio::test]
async fn tcp_preparation_defers_live_automatic_ports_without_retaining_them() {
    let mut previous = TcpListeners::default();
    let live = previous.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let address = live.local_addr().unwrap();
    let config = format!("- address: '{address}'\n  protocol: {{type: http}}\n");
    let configs =
        crate::config::create_server_configs(serde_yaml::from_str(&config).unwrap()).unwrap();
    let next = TcpListeners::prepare(&configs.configs, &previous, &[]).unwrap();
    assert!(
        next.sockets.is_empty(),
        "automatic port was prebound or reused"
    );
    drop(live);
    let next = TcpListeners::prepare(&configs.configs, &previous, &[]).unwrap();
    assert!(
        next.sockets.contains_key(&address),
        "retired port was still deferred"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn tcp_preparation_defers_ipv4_mapped_listener_transitions() {
    use tokio::io::AsyncReadExt;
    timeout(Duration::from_secs(5), async {
        for (old_ip, new_ip) in [
            ("127.0.0.1", "::ffff:127.0.0.1"),
            ("::ffff:127.0.0.1", "127.0.0.1"),
        ] {
            let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = reservation.local_addr().unwrap().port();
            drop(reservation);
            let mut previous = TcpListeners::default();
            let live = previous
                .bind(SocketAddr::new(old_ip.parse().unwrap(), port))
                .unwrap();
            let address = SocketAddr::new(new_ip.parse().unwrap(), port);
            let config = format!("- address: '{address}'\n  protocol: {{type: http}}\n");
            let configs =
                crate::config::create_server_configs(serde_yaml::from_str(&config).unwrap())
                    .unwrap();
            let mut next = TcpListeners::prepare(&configs.configs, &previous, &[]).unwrap();
            assert!(next.sockets.is_empty(), "mapped address was prebound");
            drop(live);
            previous.retain_shared(&next);
            let replacement = next.bind(address).unwrap();
            let mut peer = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let (mut accepted, _) = replacement.accept().await.unwrap();
            peer.write_all(b"live").await.unwrap();
            let mut bytes = [0; 4];
            accepted.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"live");
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn fake_dns_udp_modes() {
    use crate::routing::ingress::tests::{PacketMode, UdpCase, UdpFixture};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    timeout(Duration::from_secs(10), async {
        for fixed in [false, true] {
            for case in [UdpCase::Dns, UdpCase::Tls, UdpCase::Http] {
                let mut tasks = tokio::task::JoinSet::new();
                let fixture = UdpFixture::new(case, &mut tasks).await;
                let mode = if fixed {
                    PacketMode::Fixed
                } else {
                    PacketMode::Uot
                };
                let handler = Arc::new(crate::socks_handler::SocksTcpServerHandler::new(
                    None,
                    true,
                    "127.0.0.1".parse().unwrap(),
                    fixture.selector.clone(),
                    fixture.resolver.clone(),
                ));
                let (server, mut peer) = tokio::io::duplex(8192);
                let _server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(
                    process_stream(server, handler, fixture.resolver.clone()),
                ));
                peer.write_all(&[5, 1, 0]).await.unwrap();
                let mut auth = [0; 2];
                peer.read_exact(&mut auth).await.unwrap();
                assert_eq!(auth, [5, 0]);
                let magic =
                    NetLocation::from_str(crate::uot::UOT_V2_MAGIC_ADDRESS, Some(0)).unwrap();
                let mut request = vec![5, 1, 0];
                request.extend(crate::socks_handler::write_location_to_vec(&magic));
                peer.write_all(&request).await.unwrap();
                let mut status = [0; 3];
                peer.read_exact(&mut status).await.unwrap();
                assert_eq!(status, [5, 0, 0]);
                crate::socks_handler::read_location_direct(&mut peer)
                    .await
                    .unwrap();
                peer.write_all(&fixture.uot_header(fixed)).await.unwrap();
                peer.write_all(&fixture.request(mode)).await.unwrap();
                fixture.read_reply(&mut peer, mode).await;
                while let Some(result) = tasks.join_next().await {
                    result.unwrap();
                }
            }
        }
    })
    .await
    .unwrap();
}

#[derive(Debug)]
struct Handler(Arc<ClientProxySelector>);
#[async_trait]
impl TcpServerHandler for Handler {
    async fn setup_server_stream(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        Ok(TcpServerSetupResult::TcpForward {
            remote_location: NetLocation::from_str("127.0.0.1:80", None)?,
            stream,
            need_initial_flush: true,
            proxy_selector: self.0.clone(),
            connection_success_response: Some(b"response".to_vec().into_boxed_slice()),
            initial_remote_data: Some(b"request".to_vec().into_boxed_slice()),
        })
    }
}

#[derive(Debug)]
struct ReadyConnector(std::sync::Mutex<Option<FlushStream>>);

#[derive(Debug)]
struct FlushOnlyHandler(Arc<ClientProxySelector>);

#[async_trait]
impl TcpServerHandler for FlushOnlyHandler {
    async fn setup_server_stream(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        Ok(TcpServerSetupResult::TcpForward {
            remote_location: NetLocation::from_str(super::super::ingress::tests::TARGET, None)?,
            stream,
            need_initial_flush: true,
            proxy_selector: self.0.clone(),
            connection_success_response: None,
            initial_remote_data: None,
        })
    }
}

#[tokio::test]
async fn sniff_flushes_buffered_inbound_without_an_explicit_reply() {
    use tokio::io::AsyncReadExt;
    timeout(Duration::from_secs(5), async {
        let mut tasks = tokio::task::JoinSet::new();
        let hello = crate::sniff::tests::hello(&rustls::version::TLS13, true);
        let (selector, resolver) =
            super::super::ingress::tests::socks_target(hello.clone(), &mut tasks).await;
        let (server, mut peer) = tokio::io::duplex(8192);
        let flushes = Arc::new(AtomicUsize::new(0));
        let server = FlushStream {
            inner: server,
            stalled: false,
            flushes: flushes.clone(),
        };
        tasks.spawn(async move {
            process_stream(server, Arc::new(FlushOnlyHandler(selector)), resolver)
                .await
                .unwrap();
        });
        while flushes.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
        peer.write_all(&hello).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut reply = Vec::new();
        peer.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"greetinglater");
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
    })
    .await
    .unwrap();
}

#[derive(Debug)]
struct FlushStream {
    inner: tokio::io::DuplexStream,
    stalled: bool,
    flushes: Arc<AtomicUsize>,
}

impl tokio::io::AsyncRead for FlushStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for FlushStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flushes.fetch_add(1, Ordering::Relaxed);
        if self.stalled {
            Poll::Pending
        } else {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncPing for FlushStream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncStream for FlushStream {}

#[async_trait]
impl SocketConnector for ReadyConnector {
    async fn connect(
        &self,
        _: &Arc<dyn Resolver>,
        _: &crate::address::ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncStream>> {
        Ok(Box::new(self.0.lock().unwrap().take().unwrap()))
    }
    async fn connect_udp_bidirectional(
        &self,
        _: &Arc<dyn Resolver>,
        _: crate::address::ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        unreachable!()
    }
    fn bind_interface(&self) -> Option<&str> {
        None
    }
}

#[tokio::test(start_paused = true)]
async fn cancelled_flow_drops_a_blocked_initial_response() {
    use crate::control::catalog::RuleDescription;
    use crate::control::flows::{FlowContext, FlowRegistry};
    let registry = Arc::new(FlowRegistry::default());
    let (inbound, _peer) = tokio::io::duplex(1);
    let (outbound, _target) = tokio::io::duplex(64);
    let chain = ClientProxyChain::new(
        vec![InitialHopEntry::Direct(Arc::new(ReadyConnector(
            std::sync::Mutex::new(Some(FlushStream {
                inner: outbound,
                stalled: false,
                flushes: Arc::new(AtomicUsize::new(0)),
            })),
        )))],
        vec![],
    );
    let group =
        ClientChainGroup::new(vec![chain]).with_description(Some(Arc::new(RuleDescription {
            payload: "all".into(),
            proxy: "DIRECT".into(),
            context: Some(Arc::new(FlowContext {
                registry: registry.clone(),
                generation: 1,
                inbound: "test".into(),
                scope: "root".into(),
                protocol: "Socks5".into(),
            })),
        })));
    let selector = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
        vec![crate::address::NetLocationMask::ANY],
        ConnectAction::new_allow(None, group),
    )]));
    let relay = tokio::spawn(process_stream(
        inbound,
        Arc::new(Handler(selector)),
        Arc::new(PendingResolver),
    ));
    timeout(Duration::from_secs(1), async {
        while registry.snapshot(0).connections.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    registry.cancel_all();
    let error = timeout(Duration::from_secs(1), relay)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    assert!(registry.snapshot(0).connections.is_empty());
}

#[tokio::test]
async fn fixed_tcp_releases_setup_owners_before_relay_and_half_close() {
    use tokio::io::AsyncReadExt;
    timeout(Duration::from_secs(5), async {
        let (inbound, mut peer) = tokio::io::duplex(64);
        let (outbound, mut target) = tokio::io::duplex(64);
        let chain = ClientProxyChain::new(
            vec![InitialHopEntry::Direct(Arc::new(ReadyConnector(
                std::sync::Mutex::new(Some(FlushStream {
                    inner: outbound,
                    stalled: false,
                    flushes: Arc::new(AtomicUsize::new(0)),
                })),
            )))],
            vec![],
        );
        let selector = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
            vec![crate::address::NetLocationMask::ANY],
            ConnectAction::new_allow(None, ClientChainGroup::new(vec![chain])),
        )]));
        let resolver: Arc<dyn Resolver> = Arc::new(PendingResolver);
        let handler = Arc::new(Handler(selector.clone()));
        let weak_selector = Arc::downgrade(&selector);
        let weak_resolver = Arc::downgrade(&resolver);
        let weak_handler = Arc::downgrade(&handler);
        drop(selector);
        let relay = tokio::spawn(process_stream(inbound, handler, resolver));
        let mut response = [0; 8];
        peer.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
        let mut request = [0; 7];
        target.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");
        assert!(weak_selector.upgrade().is_none());
        assert!(weak_resolver.upgrade().is_none());
        assert!(weak_handler.upgrade().is_none());
        assert!(!relay.is_finished());

        peer.write_all(b"live request").await.unwrap();
        peer.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        target.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"live request");
        target.write_all(b"reply after FIN").await.unwrap();
        target.shutdown().await.unwrap();
        bytes.clear();
        peer.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"reply after FIN");
        relay.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn initial_writes_and_flushes_have_deadlines() {
    use tokio::io::AsyncReadExt;
    for (inbound_capacity, outbound_capacity, stall_response, stall_request) in [
        (1, 64, false, false),
        (64, 1, false, false),
        (64, 64, true, false),
        (64, 64, false, true),
    ] {
        let (inbound, mut peer) = tokio::io::duplex(inbound_capacity);
        let (outbound, mut target) = tokio::io::duplex(outbound_capacity);
        let response_flushes = Arc::new(AtomicUsize::new(0));
        let request_flushes = Arc::new(AtomicUsize::new(0));
        let inbound = FlushStream {
            inner: inbound,
            stalled: stall_response,
            flushes: response_flushes.clone(),
        };
        let outbound = FlushStream {
            inner: outbound,
            stalled: stall_request,
            flushes: request_flushes.clone(),
        };
        let chain = ClientProxyChain::new(
            vec![InitialHopEntry::Direct(Arc::new(ReadyConnector(
                std::sync::Mutex::new(Some(outbound)),
            )))],
            vec![],
        );
        let selector = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
            vec![crate::address::NetLocationMask::ANY],
            ConnectAction::new_allow(None, ClientChainGroup::new(vec![chain])),
        )]));
        let started = tokio::time::Instant::now();
        let error = timeout(
            Duration::from_secs(61),
            process_stream(
                inbound,
                Arc::new(Handler(selector)),
                Arc::new(PendingResolver),
            ),
        )
        .await
        .expect("initial writes retained the stream indefinitely")
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(started.elapsed(), Duration::from_secs(60));
        if stall_response {
            assert!(response_flushes.load(Ordering::Relaxed) > 0);
        }
        if stall_request {
            assert!(request_flushes.load(Ordering::Relaxed) > 0);
        }
        peer.read_to_end(&mut Vec::new()).await.unwrap();
        target.read_to_end(&mut Vec::new()).await.unwrap();
    }
}

#[tokio::test]
async fn protocol_response_precedes_chained_greeting() {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rule = serde_yaml::from_str(&format!(
        "masks: '0.0.0.0/0'\nclient_proxy:\n  address: '{}'\n  protocol: {{type: socks}}\n",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    let handler = Arc::new(Handler(Arc::new(
        super::super::tcp_client_handler_factory::create_test_selector(
            vec![rule],
            resolver.clone(),
        )
        .unwrap(),
    )));
    let (server, mut peer) = tokio::io::duplex(512);
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.read_exact(&mut [0; 3]).await.unwrap();
        socket.write_all(&[5, 0]).await.unwrap();
        socket.read_exact(&mut [0; 10]).await.unwrap();
        socket
            .write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00greeting")
            .await
            .unwrap();
        let mut request = [0; 7];
        socket.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");
        socket.write_all(b"later").await.unwrap();
    });
    tasks.spawn(async move {
        process_stream(server, handler, resolver).await.unwrap();
    });
    let mut response = [0; 21];
    timeout(Duration::from_secs(3), peer.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, b"responsegreetinglater");
    drop(peer);
    while let Some(result) = timeout(Duration::from_secs(3), tasks.join_next())
        .await
        .unwrap()
    {
        result.unwrap();
    }
}

#[tokio::test]
async fn reply_gated_socks_and_connect_sniff_route_and_preserve_proxy_ip() {
    use super::super::ingress::tests::{TARGET, socks_target};
    use tokio::io::AsyncReadExt;
    for socks in [true, false] {
        timeout(Duration::from_secs(5), async {
            let mut tasks = tokio::task::JoinSet::new();
            let hello = crate::sniff::tests::hello(&rustls::version::TLS13, true);
            let (selector, resolver) = socks_target(hello.clone(), &mut tasks).await;
            let handler: Arc<dyn TcpServerHandler> = if socks {
                Arc::new(crate::socks_handler::SocksTcpServerHandler::new(
                    None,
                    false,
                    "0.0.0.0".parse().unwrap(),
                    selector,
                    resolver.clone(),
                ))
            } else {
                Arc::new(crate::http_handler::HttpTcpServerHandler::new(
                    None,
                    selector,
                    resolver.clone(),
                ))
            };
            let (server, mut peer) = tokio::io::duplex(8192);
            tasks.spawn(async move {
                process_stream(server, handler, resolver).await.unwrap();
            });
            if socks {
                peer.write_all(&[5, 1, 0]).await.unwrap();
                let mut method = [0; 2];
                peer.read_exact(&mut method).await.unwrap();
                assert_eq!(method, [5, 0]);
                peer.write_all(&[5, 1, 0, 1, 203, 0, 113, 1, 1, 187])
                    .await
                    .unwrap();
                let mut reply = [0; 10];
                peer.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply[..4], &[5, 0, 0, 1]);
            } else {
                peer.write_all(
                    format!("CONNECT {TARGET} HTTP/1.1\r\nHost: {TARGET}\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
                let mut reply = Vec::new();
                while !reply.ends_with(b"\r\n\r\n") {
                    reply.push(peer.read_u8().await.unwrap());
                }
                assert!(reply.starts_with(b"HTTP/1.1 200"));
            }
            // No application bytes are sent until the actual protocol success.
            peer.write_all(&hello).await.unwrap();
            peer.shutdown().await.unwrap();
            let mut reply = Vec::new();
            peer.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"greetinglater");
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn coalesced_connect_dns_pipeline_drains_replies_during_prefix_replay() {
    use hickory_resolver::proto::op::{Message, Query};
    use hickory_resolver::proto::rr::{Name, RecordType};
    use tokio::io::AsyncReadExt;

    timeout(Duration::from_secs(5), async {
        let resolver: Arc<dyn Resolver> = Arc::new(PendingResolver);
        let context = Arc::new(
            crate::dns::fake_ip::FakeDnsContext::new(Default::default(), resolver.clone()).unwrap(),
        );
        let selector = Arc::new(
            ClientProxySelector::new(vec![])
                .with_fake_dns_context(Some(context))
                .unwrap(),
        );
        let handler = Arc::new(crate::http_handler::HttpTcpServerHandler::new(
            None,
            selector,
            resolver.clone(),
        ));
        let (server, mut peer) = tokio::io::duplex(65536);
        let mut prefix = b"CONNECT 192.0.2.1:53 HTTP/1.1\r\nHost: 192.0.2.1:53\r\n\r\n".to_vec();
        for id in 0..1200 {
            let mut query = Message::query();
            query.metadata.id = id;
            query.add_query(Query::query(
                Name::from_ascii("a.test").unwrap(),
                RecordType::A,
            ));
            let bytes = query.to_vec().unwrap();
            prefix.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            prefix.extend_from_slice(&bytes);
        }
        assert!(prefix.len() > 30 * 1024 && prefix.len() < 32 * 1024);
        peer.write_all(&prefix).await.unwrap();
        peer.shutdown().await.unwrap();
        let task = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(process_stream(
            server, handler, resolver,
        )));
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(peer.read_u8().await.unwrap());
        }
        assert!(header.starts_with(b"HTTP/1.1 200"));
        for id in 0..1200 {
            let length = peer.read_u16().await.unwrap() as usize;
            let mut bytes = vec![0; length];
            peer.read_exact(&mut bytes).await.unwrap();
            let answer = Message::from_vec(&bytes).unwrap();
            assert_eq!(answer.metadata.id, id);
            assert_eq!(answer.answers.len(), 1);
        }
        task.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn sniff_wait_does_not_consume_outbound_connect_budget() {
    use tokio::io::AsyncReadExt;
    #[derive(Debug)]
    struct DelayedConnector(std::sync::Mutex<Option<tokio::io::DuplexStream>>);
    #[async_trait]
    impl SocketConnector for DelayedConnector {
        async fn connect(
            &self,
            _: &Arc<dyn Resolver>,
            _: &crate::address::ResolvedLocation,
        ) -> io::Result<Box<dyn AsyncStream>> {
            tokio::time::sleep(Duration::from_millis(900)).await;
            Ok(Box::new(self.0.lock().unwrap().take().unwrap()))
        }
        async fn connect_udp_bidirectional(
            &self,
            _: &Arc<dyn Resolver>,
            _: crate::address::ResolvedLocation,
        ) -> io::Result<Box<dyn AsyncMessageStream>> {
            unreachable!()
        }
        fn bind_interface(&self) -> Option<&str> {
            None
        }
    }
    let (outbound, mut target) = tokio::io::duplex(64);
    target.write_all(b"ready").await.unwrap();
    target.shutdown().await.unwrap();
    let selector = Arc::new(
        ClientProxySelector::new(vec![ConnectRule::new(
            vec![
                crate::address::NetLocationMask::from("sniff.example").unwrap(),
                crate::address::NetLocationMask::ANY,
            ],
            ConnectAction::new_allow(
                None,
                ClientChainGroup::new(vec![ClientProxyChain::new(
                    vec![InitialHopEntry::Direct(Arc::new(DelayedConnector(
                        std::sync::Mutex::new(Some(outbound)),
                    )))],
                    vec![],
                )]),
            ),
        )])
        .with_sniff(true),
    );
    let (server, mut peer) = tokio::io::duplex(64);
    let started = tokio::time::Instant::now();
    let task = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(process_stream_with_permit(
        server,
        Arc::new(FlushOnlyHandler(selector)),
        Arc::new(PendingResolver),
        crate::resources::try_stream().unwrap(),
        Duration::from_secs(1),
    )));
    let mut bytes = [0; 5];
    peer.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"ready");
    assert!(started.elapsed() >= Duration::from_millis(1200));
    peer.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn sniff_failures_close_socks_and_connect_without_a_second_reply() {
    use super::super::ingress::tests::{TARGET, failure_selector};
    use tokio::io::AsyncReadExt;
    for socks in [true, false] {
        for blocked in [true, false] {
            timeout(Duration::from_secs(5), async {
                let selector = failure_selector(true, blocked);
                let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
                let handler: Arc<dyn TcpServerHandler> = if socks {
                    Arc::new(crate::socks_handler::SocksTcpServerHandler::new(
                        None,
                        false,
                        "0.0.0.0".parse().unwrap(),
                        selector,
                        resolver.clone(),
                    ))
                } else {
                    Arc::new(crate::http_handler::HttpTcpServerHandler::new(
                        None,
                        selector,
                        resolver.clone(),
                    ))
                };
                let (server, mut peer) = tokio::io::duplex(8192);
                let server = tokio::spawn(process_stream(server, handler, resolver));
                if socks {
                    peer.write_all(&[5, 1, 0]).await.unwrap();
                    let mut method = [0; 2];
                    peer.read_exact(&mut method).await.unwrap();
                    assert_eq!(method, [5, 0]);
                    peer.write_all(&[5, 1, 0, 1, 203, 0, 113, 1, 1, 187])
                        .await
                        .unwrap();
                    let mut reply = [0; 10];
                    peer.read_exact(&mut reply).await.unwrap();
                    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
                } else {
                    peer.write_all(
                        format!("CONNECT {TARGET} HTTP/1.1\r\nHost: {TARGET}\r\n\r\n").as_bytes(),
                    )
                    .await
                    .unwrap();
                    let mut reply = Vec::new();
                    while !reply.ends_with(b"\r\n\r\n") {
                        reply.push(peer.read_u8().await.unwrap());
                    }
                    assert!(reply.starts_with(b"HTTP/1.1 200"));
                }
                peer.write_all(&crate::sniff::tests::hello(&rustls::version::TLS13, true))
                    .await
                    .unwrap();
                let mut reply = Vec::new();
                peer.read_to_end(&mut reply).await.unwrap();
                assert!(reply.is_empty(), "second reply after optimistic success");
                let result = server.await.unwrap();
                if blocked {
                    result.unwrap();
                } else {
                    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionRefused);
                }
            })
            .await
            .unwrap();
        }
    }
}

#[tokio::test]
async fn direct_tcp_startup_rejects_duplicate_fixed_but_allows_automatic_ports() {
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    for port in [address.port(), 0] {
        let address = SocketAddr::new(address.ip(), port);
        let config = format!("- address: ['{address}', '{address}']\n  protocol: {{type: http}}\n");
        let configs =
            crate::config::create_server_configs(serde_yaml::from_str(&config).unwrap()).unwrap();
        let result = start_servers(
            configs.configs.into_iter().next().unwrap(),
            Arc::new(crate::resolver::NativeResolver::new()),
        )
        .await;
        if port == 0 {
            let handles = result.unwrap();
            assert_eq!(handles.len(), 2);
            for handle in &handles {
                handle.abort();
            }
            for handle in handles {
                assert!(handle.await.unwrap_err().is_cancelled());
            }
        } else {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::AddrInUse);
            std::net::TcpListener::bind(address).expect("duplicate bind leaked a listener");
        }
    }
}

#[tokio::test]
async fn tcp_bind_failure_releases_all_prepared_listeners() {
    let first = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let first_addr = first.local_addr().unwrap();
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let config = format!(
        "- address: ['{first_addr}', '{}']\n  protocol:\n    type: http\n",
        occupied.local_addr().unwrap()
    );
    let configs =
        crate::config::create_server_configs(serde_yaml::from_str(&config).unwrap()).unwrap();
    drop(first);
    let error = start_servers(
        configs.configs.into_iter().next().unwrap(),
        Arc::new(crate::resolver::NativeResolver::new()),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    std::net::TcpListener::bind(first_addr).expect("earlier bind leaked after startup failed");
}

#[derive(Debug)]
struct StalledMessageShutdown {
    _marker: Arc<()>,
    shutdowns: Arc<AtomicUsize>,
}

impl AsyncReadMessage for StalledMessageShutdown {
    fn poll_read_message(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
    }
}

impl AsyncWriteMessage for StalledMessageShutdown {
    fn poll_write_message(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for StalledMessageShutdown {
    fn poll_flush_message(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for StalledMessageShutdown {
    fn poll_shutdown_message(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdowns.fetch_add(1, Ordering::Relaxed);
        Poll::Pending
    }
}

impl AsyncPing for StalledMessageShutdown {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncMessageStream for StalledMessageShutdown {}

#[derive(Debug)]
struct UdpHandler {
    remote: NetLocation,
    selector: Arc<ClientProxySelector>,
    marker: Arc<()>,
    shutdowns: Arc<AtomicUsize>,
}

#[async_trait]
impl TcpServerHandler for UdpHandler {
    async fn setup_server_stream(
        &self,
        _: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        Ok(TcpServerSetupResult::BidirectionalUdp {
            remote_location: self.remote.clone(),
            stream: Box::new(StalledMessageShutdown {
                _marker: self.marker.clone(),
                shutdowns: self.shutdowns.clone(),
            }),
            need_initial_flush: false,
            proxy_selector: self.selector.clone(),
        })
    }
}

#[derive(Debug)]
struct PendingResolver;

impl Resolver for PendingResolver {
    fn resolve_location(
        &self,
        _: &NetLocation,
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
        Box::pin(std::future::pending())
    }
}

#[derive(Debug)]
struct PendingConnector;

#[async_trait]
impl SocketConnector for PendingConnector {
    async fn connect(
        &self,
        _: &Arc<dyn Resolver>,
        _: &crate::address::ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncStream>> {
        unreachable!()
    }
    async fn connect_udp_bidirectional(
        &self,
        _: &Arc<dyn Resolver>,
        _: crate::address::ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        std::future::pending().await
    }
    fn bind_interface(&self) -> Option<&str> {
        None
    }
}

#[tokio::test(start_paused = true)]
async fn fixed_udp_preserves_transport_permission_denials() {
    #[derive(Debug)]
    struct DeniedConnector;

    #[async_trait]
    impl SocketConnector for DeniedConnector {
        async fn connect(
            &self,
            _: &Arc<dyn Resolver>,
            _: &crate::address::ResolvedLocation,
        ) -> io::Result<Box<dyn AsyncStream>> {
            unreachable!()
        }

        async fn connect_udp_bidirectional(
            &self,
            _: &Arc<dyn Resolver>,
            _: crate::address::ResolvedLocation,
        ) -> io::Result<Box<dyn AsyncMessageStream>> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "transport denied",
            ))
        }

        fn bind_interface(&self) -> Option<&str> {
            None
        }
    }

    for blocked in [true, false] {
        let action = if blocked {
            ConnectAction::Block
        } else {
            ConnectAction::new_allow(
                None,
                ClientChainGroup::new(vec![ClientProxyChain::new(
                    vec![InitialHopEntry::Direct(Arc::new(DeniedConnector))],
                    vec![],
                )]),
            )
        };
        let handler = Arc::new(UdpHandler {
            remote: NetLocation::from_str("192.0.2.1:443", None).unwrap(),
            selector: Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
                vec![crate::address::NetLocationMask::ANY],
                action,
            )])),
            marker: Arc::new(()),
            shutdowns: Arc::new(AtomicUsize::new(0)),
        });
        let (stream, _peer) = tokio::io::duplex(64);
        let error = process_stream(stream, handler, Arc::new(PendingResolver))
            .await
            .unwrap_err();
        let (kind, message) = if blocked {
            (
                io::ErrorKind::ConnectionRefused,
                "Blocked bidirectional udp forward",
            )
        } else {
            (io::ErrorKind::PermissionDenied, "transport denied")
        };
        assert_eq!(error.kind(), kind);
        assert_eq!(error.to_string(), message);
    }
}

#[tokio::test(start_paused = true)]
async fn udp_setup_and_error_cleanup_have_deadlines() {
    for remote in ["pending.test:53", "192.0.2.1:53"] {
        let marker = Arc::new(());
        let shutdowns = Arc::new(AtomicUsize::new(0));
        let chain = ClientProxyChain::new(
            vec![InitialHopEntry::Direct(Arc::new(PendingConnector))],
            vec![],
        );
        let selector = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
            vec![crate::address::NetLocationMask::from("192.0.2.0/24").unwrap()],
            ConnectAction::new_allow(None, ClientChainGroup::new(vec![chain])),
        )]));
        let handler = Arc::new(UdpHandler {
            remote: NetLocation::from_str(remote, None).unwrap(),
            selector,
            marker: marker.clone(),
            shutdowns: shutdowns.clone(),
        });
        let (stream, _peer) = tokio::io::duplex(64);
        let started = tokio::time::Instant::now();
        let result = timeout(
            Duration::from_secs(66),
            process_stream(stream, handler, Arc::new(PendingResolver)),
        )
        .await
        .expect("UDP setup or cleanup retained the stream indefinitely");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(started.elapsed(), Duration::from_secs(65));
        assert!(shutdowns.load(Ordering::Relaxed) > 0);
        assert_eq!(Arc::strong_count(&marker), 1);
    }
}

#[tokio::test(start_paused = true)]
async fn udp_copy_error_cannot_stall_final_shutdown() {
    let marker = Arc::new(());
    let server_shutdowns = Arc::new(AtomicUsize::new(0));
    let client_shutdowns = Arc::new(AtomicUsize::new(0));
    let started = tokio::time::Instant::now();
    let result = timeout(
        Duration::from_secs(6),
        run_udp_copy(
            Box::new(StalledMessageShutdown {
                _marker: marker.clone(),
                shutdowns: server_shutdowns.clone(),
            }),
            Box::new(StalledMessageShutdown {
                _marker: marker.clone(),
                shutdowns: client_shutdowns.clone(),
            }),
            false,
            false,
        ),
    )
    .await
    .expect("final UDP shutdown retained streams indefinitely");
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(started.elapsed(), crate::util::SHUTDOWN_TIMEOUT);
    assert!(server_shutdowns.load(Ordering::Relaxed) > 0);
    assert!(client_shutdowns.load(Ordering::Relaxed) > 0);
    assert_eq!(Arc::strong_count(&marker), 1);
}

#[derive(Debug)]
struct SessionHandler(Arc<()>);

#[async_trait]
impl TcpServerHandler for SessionHandler {
    async fn setup_server_stream(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let owned = self.0.clone();
        Ok(TcpServerSetupResult::Session(Box::pin(async move {
            let _owned = owned;
            let _stream = stream;
            std::future::pending::<()>().await;
        })))
    }
}

#[tokio::test(start_paused = true)]
async fn session_outlives_setup_deadline_but_not_its_owner() {
    let marker = Arc::new(());
    let handler = Arc::new(SessionHandler(marker.clone()));
    let (stream, _peer) = tokio::io::duplex(64);
    let task = tokio::spawn(process_stream(
        stream,
        handler,
        Arc::new(crate::resolver::NativeResolver),
    ));
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(600)).await;
    assert!(!task.is_finished());
    assert_eq!(Arc::strong_count(&marker), 2);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(Arc::strong_count(&marker), 1);
}
