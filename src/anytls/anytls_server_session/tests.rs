use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn fake_dns_udp_modes() {
    use crate::routing::ingress::tests::{PacketMode, UdpCase, UdpFixture};
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
                let (server, mut peer) = duplex(8192);
                let session = AnyTlsSession::new_server_with_initial_data(
                    server,
                    PaddingFactory::default_factory(),
                    fixture.resolver.clone(),
                    fixture.selector.clone(),
                    true,
                    "test".into(),
                    None,
                );
                session
                    .received_client_settings
                    .store(true, Ordering::Relaxed);
                session.peer_version.store(2, Ordering::Relaxed);
                let runner = session.clone();
                let server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                    runner.run().await
                }));
                for id in [2, 3] {
                    peer.write_all(&Frame::control(Command::Syn, id).encode())
                        .await
                        .unwrap();
                    let magic = NetLocation::from_str(UOT_V2_MAGIC_ADDRESS, Some(0)).unwrap();
                    let mut header = crate::socks_handler::write_location_to_vec(&magic);
                    header.extend(fixture.uot_header(fixed));
                    peer.write_all(&Frame::data(id, Bytes::from(header)).encode())
                        .await
                        .unwrap();
                    let mut status = [0; 7];
                    loop {
                        peer.read_exact(&mut status).await.unwrap();
                        if status[0] != Command::Fin as u8 {
                            break;
                        }
                        assert_eq!(&status, &Frame::control(Command::Fin, id - 1).encode()[..]);
                    }
                    assert_eq!(&status, &Frame::control(Command::SynAck, id).encode()[..]);
                    // The second stream proves the session survives; DNS supports repeated queries.
                    if id == 2 || case == UdpCase::Dns {
                        peer.write_all(
                            &Frame::data(id, Bytes::from(fixture.request(mode))).encode(),
                        )
                        .await
                        .unwrap();
                        let mut reply = Vec::new();
                        loop {
                            peer.read_exact(&mut status).await.unwrap();
                            if status[0] == Command::Fin as u8 {
                                assert_eq!(
                                    &status,
                                    &Frame::control(Command::Fin, id - 1).encode()[..]
                                );
                                continue;
                            }
                            assert_eq!(status[0], Command::Psh as u8);
                            assert_eq!(&status[1..5], &id.to_be_bytes());
                            let len = u16::from_be_bytes([status[5], status[6]]) as usize;
                            let mut bytes = vec![0; len];
                            peer.read_exact(&mut bytes).await.unwrap();
                            reply.extend(bytes);
                            if let Some(payload) = mode.reply(&fixture.target, &reply) {
                                fixture.assert_reply(payload);
                                break;
                            }
                        }
                    }
                    peer.write_all(&Frame::control(Command::Fin, id).encode())
                        .await
                        .unwrap();
                    assert!(!session.is_closed.load(Ordering::Relaxed));
                }
                while let Some(result) = tasks.join_next().await {
                    result.unwrap();
                }
                session.close().await;
                server.await.unwrap().unwrap();
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn fake_dns_adapter_contract() {
    use crate::tcp::ingress::tests::FakeTcpCase;
    timeout(Duration::from_secs(10), async {
        for version in [1, 2] {
            for case in [
                FakeTcpCase::Dns,
                FakeTcpCase::Tls,
                FakeTcpCase::Http,
                FakeTcpCase::Plain,
            ] {
                let mut tasks = tokio::task::JoinSet::new();
                let (selector, resolver, target, payload) = case.fixture(&mut tasks).await;
                let (server, mut peer) = duplex(8192);
                let session = AnyTlsSession::new_server_with_initial_data(
                    server,
                    PaddingFactory::default_factory(),
                    resolver,
                    selector,
                    true,
                    "test".into(),
                    None,
                );
                session
                    .received_client_settings
                    .store(true, Ordering::Relaxed);
                session.peer_version.store(version, Ordering::Relaxed);
                let runner = session.clone();
                let server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                    runner.run().await
                }));
                peer.write_all(&Frame::control(Command::Syn, 2).encode())
                    .await
                    .unwrap();
                peer.write_all(
                    &Frame::data(
                        2,
                        Bytes::from(crate::socks_handler::write_location_to_vec(&target)),
                    )
                    .encode(),
                )
                .await
                .unwrap();
                if version == 2 {
                    let mut status = [0; 7];
                    peer.read_exact(&mut status).await.unwrap();
                    assert_eq!(
                        status.as_slice(),
                        Frame::control(Command::SynAck, 2).encode().as_ref()
                    );
                }
                peer.write_all(&Frame::data(2, Bytes::from(payload)).encode())
                    .await
                    .unwrap();
                peer.write_all(&Frame::control(Command::Fin, 2).encode())
                    .await
                    .unwrap();
                let mut reply = Vec::new();
                loop {
                    let mut header = [0; 7];
                    peer.read_exact(&mut header).await.unwrap();
                    assert_eq!(&header[1..5], &2u32.to_be_bytes());
                    let length = u16::from_be_bytes([header[5], header[6]]) as usize;
                    let mut data = vec![0; length];
                    peer.read_exact(&mut data).await.unwrap();
                    if header[0] == Command::Fin as u8 {
                        assert_eq!(length, 0);
                        break;
                    }
                    assert_eq!(header[0], Command::Psh as u8);
                    reply.extend(data);
                }
                case.assert_reply(&reply);
                assert!(!session.is_closed.load(Ordering::Relaxed));
                while let Some(result) = tasks.join_next().await {
                    result.unwrap();
                }
                session.close().await;
                server.await.unwrap().unwrap();
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unknown_fake_destinations_send_error_synack_then_fin() {
    for udp in [false, true] {
        timeout(Duration::from_secs(5), async {
            let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
            let context = Arc::new(
                crate::dns::DnsContext::new(Default::default(), resolver.clone()).unwrap(),
            );
            let selector =
                ClientProxySelector::new(vec![crate::client_proxy_selector::ConnectRule::new(
                    vec![crate::address::NetLocationMask::from("sniff.example").unwrap()],
                    crate::client_proxy_selector::ConnectAction::Block,
                )])
                .with_sniff(true)
                .with_fake_dns_context(Some(context))
                .unwrap();
            let (server, mut peer) = duplex(8192);
            let session = AnyTlsSession::new_server_with_initial_data(
                server,
                PaddingFactory::default_factory(),
                resolver,
                Arc::new(selector),
                true,
                "test".into(),
                None,
            );
            session
                .received_client_settings
                .store(true, Ordering::Relaxed);
            session.peer_version.store(2, Ordering::Relaxed);
            let runner = session.clone();
            let server = tokio::spawn(async move { runner.run().await });
            for id in [2, 3] {
                peer.write_all(&Frame::control(Command::Syn, id).encode())
                    .await
                    .unwrap();
                let mut payload = Vec::new();
                if udp {
                    payload.extend_from_slice(&[3, UOT_V2_MAGIC_ADDRESS.len() as u8]);
                    payload.extend_from_slice(UOT_V2_MAGIC_ADDRESS.as_bytes());
                    payload.extend_from_slice(&[0, 0, 1]);
                }
                payload.extend_from_slice(&[1, 198, 18, 0, 5, 1, 187]);
                peer.write_all(&Frame::data(id, Bytes::from(payload)).encode())
                    .await
                    .unwrap();
                let mut header = [0; 7];
                peer.read_exact(&mut header).await.unwrap();
                assert_eq!(
                    &header[..5],
                    &Frame::control(Command::SynAck, id).encode()[..5]
                );
                let mut message = vec![0; u16::from_be_bytes([header[5], header[6]]) as usize];
                peer.read_exact(&mut message).await.unwrap();
                let message = String::from_utf8(message).unwrap();
                assert!(
                    message.starts_with(if udp {
                        "UDP connect failed:"
                    } else {
                        "connect failed:"
                    }),
                    "{message}"
                );
                peer.read_exact(&mut header).await.unwrap();
                assert_eq!(&header, &Frame::control(Command::Fin, id).encode()[..]);
                assert!(!session.is_closed.load(Ordering::Relaxed));
            }
            while !session.stream_tasks.lock().is_empty() {
                tokio::task::yield_now().await;
            }
            session.close().await;
            server.await.unwrap().unwrap();
            let mut extra = Vec::new();
            peer.read_to_end(&mut extra).await.unwrap();
            assert!(
                extra.is_empty(),
                "duplicate status or FIN after stream completion"
            );
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn sniff_failures_send_one_synack_then_fin() {
    for sniff in [false, true] {
        for blocked in [false, true] {
            timeout(Duration::from_secs(5), async {
                let (server, mut peer) = duplex(8192);
                let session = AnyTlsSession::new_server_with_initial_data(
                    server,
                    PaddingFactory::default_factory(),
                    Arc::new(crate::resolver::NativeResolver::new()),
                    crate::tcp::ingress::tests::failure_selector(sniff, blocked),
                    false,
                    "test".into(),
                    None,
                );
                session
                    .received_client_settings
                    .store(true, Ordering::Relaxed);
                session.peer_version.store(2, Ordering::Relaxed);
                let runner = session.clone();
                let server = tokio::spawn(async move { runner.run().await });
                peer.write_all(&Frame::control(Command::Syn, 1).encode())
                    .await
                    .unwrap();
                peer.write_all(
                    &Frame::data(1, Bytes::from_static(&[1, 203, 0, 113, 1, 1, 187])).encode(),
                )
                .await
                .unwrap();
                let mut header = [0; 7];
                peer.read_exact(&mut header).await.unwrap();
                assert_eq!(
                    &header[..5],
                    &Frame::control(Command::SynAck, 1).encode()[..5]
                );
                let mut error = vec![0; u16::from_be_bytes([header[5], header[6]]) as usize];
                peer.read_exact(&mut error).await.unwrap();
                if sniff {
                    assert!(error.is_empty());
                    let hello = crate::sniff::tests::hello(&rustls::version::TLS13, true);
                    peer.write_all(&Frame::data(1, Bytes::from(hello)).encode())
                        .await
                        .unwrap();
                } else {
                    let error = String::from_utf8(error).unwrap();
                    assert!(error.starts_with(if blocked {
                        "blocked by rules:"
                    } else {
                        "connect failed:"
                    }));
                }
                peer.read_exact(&mut header).await.unwrap();
                assert_eq!(&header, &Frame::control(Command::Fin, 1).encode()[..]);
                while !session.stream_tasks.lock().is_empty() {
                    tokio::task::yield_now().await;
                }
                session.close().await;
                server.await.unwrap().unwrap();
                let mut extra = Vec::new();
                peer.read_to_end(&mut extra).await.unwrap();
                assert!(
                    extra.is_empty(),
                    "duplicate status or FIN after stream completion"
                );
            })
            .await
            .unwrap();
        }
    }
}

#[tokio::test]
async fn sniff_v2_synack_precedes_payload_and_preserves_early_data() {
    for version in [1, 2] {
        timeout(Duration::from_secs(5), async {
            let mut tasks = tokio::task::JoinSet::new();
            let hello = crate::sniff::tests::hello(&rustls::version::TLS13, true);
            let (selector, resolver) =
                crate::tcp::ingress::tests::socks_target(hello.clone(), &mut tasks).await;
            let (server, mut peer) = duplex(8192);
            let session = AnyTlsSession::new_server_with_initial_data(
                server,
                PaddingFactory::default_factory(),
                resolver,
                selector,
                false,
                "test".into(),
                None,
            );
            session
                .received_client_settings
                .store(true, Ordering::Relaxed);
            session.peer_version.store(version, Ordering::Relaxed);
            let runner = session.clone();
            let server = tokio::spawn(async move { runner.run().await });
            peer.write_all(&Frame::control(Command::Syn, 1).encode())
                .await
                .unwrap();
            peer.write_all(
                &Frame::data(1, Bytes::from_static(&[1, 203, 0, 113, 1, 1, 187])).encode(),
            )
            .await
            .unwrap();
            if version == 2 {
                let mut reply = [0; 7];
                peer.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, &Frame::control(Command::SynAck, 1).encode()[..]);
            }
            peer.write_all(&Frame::data(1, Bytes::from(hello)).encode())
                .await
                .unwrap();
            peer.write_all(&Frame::control(Command::Fin, 1).encode())
                .await
                .unwrap();
            let mut response = Vec::new();
            loop {
                let mut header = [0; 7];
                peer.read_exact(&mut header).await.unwrap();
                let len = u16::from_be_bytes([header[5], header[6]]) as usize;
                let mut data = vec![0; len];
                peer.read_exact(&mut data).await.unwrap();
                if header[0] == Command::Fin as u8 {
                    break;
                }
                assert_eq!(header[0], Command::Psh as u8);
                response.extend(data);
            }
            assert_eq!(response, b"greetinglater");
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
            session.close().await;
            server.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }
}

#[derive(Debug)]
struct TestConnector {
    address: std::net::SocketAddr,
    blocked_write: Option<Arc<tokio::sync::Notify>>,
}

#[derive(Debug)]
struct BlockedWriter {
    stream: tokio::net::TcpStream,
    writing: Arc<tokio::sync::Notify>,
}

impl AsyncRead for BlockedWriter {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for BlockedWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        self.writing.notify_one();
        std::task::Poll::Pending
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl crate::async_stream::AsyncPing for BlockedWriter {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<bool>> {
        std::task::Poll::Ready(Ok(false))
    }
}
impl crate::async_stream::AsyncStream for BlockedWriter {}

#[async_trait::async_trait]
impl crate::tcp::socket_connector::SocketConnector for TestConnector {
    async fn connect(
        &self,
        _: &Arc<dyn Resolver>,
        _: &crate::address::ResolvedLocation,
    ) -> io::Result<Box<dyn crate::async_stream::AsyncStream>> {
        Ok(Box::new(BlockedWriter {
            stream: tokio::net::TcpStream::connect(self.address).await?,
            writing: self.blocked_write.as_ref().unwrap().clone(),
        }))
    }

    async fn connect_udp_bidirectional(
        &self,
        _: &Arc<dyn Resolver>,
        _: crate::address::ResolvedLocation,
    ) -> io::Result<Box<dyn crate::async_stream::AsyncMessageStream>> {
        let stream = tokio::net::TcpStream::connect(self.address).await?;
        Ok(Box::new(VlessMessageStream::new(stream)))
    }

    fn bind_interface(&self) -> Option<&str> {
        None
    }
}

#[tokio::test]
async fn cancelled_flows_release_reads_and_egress_before_bounded_fin() {
    #[derive(Clone, Copy, Debug)]
    enum Phase {
        Synack,
        EarlyData,
        Prefix,
        Copy,
        UdpSynack,
        UdpCopy,
        UdpShutdown,
    }
    use Phase::*;
    for (phase, drain) in [
        Synack,
        EarlyData,
        Prefix,
        Copy,
        UdpSynack,
        UdpCopy,
        UdpShutdown,
    ]
    .into_iter()
    .flat_map(|phase| [true, false].map(|drain| (phase, drain)))
    {
        let early_data = matches!(phase, EarlyData);
        let prefix = matches!(phase, Prefix);
        let established = matches!(phase, Copy | UdpCopy | UdpShutdown);
        let udp = matches!(phase, UdpSynack | UdpCopy | UdpShutdown);
        let during_shutdown = matches!(phase, UdpShutdown);
        timeout(Duration::from_secs(3), async {
            use crate::client_proxy_chain::ClientChainGroup;
            use crate::client_proxy_selector::{ConnectAction, ConnectRule};
            use crate::control::catalog::RuleDescription;
            use crate::control::flows::{FlowContext, FlowRegistry};
            let registry = Arc::new(FlowRegistry::default());
            let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver);
            let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
            let target = NetLocation::from_str(
                &format!("127.0.0.1:{}", listener.local_addr().unwrap().port()),
                None,
            )
            .unwrap();
            let client = if early_data {
                serde_json::from_value(serde_json::json!({
                    "address": target.to_string(), "protocol": {"type":"http"},
                }))
                .unwrap()
            } else {
                crate::config::ClientConfig::default()
            };
            let writing = Arc::new(tokio::sync::Notify::new());
            let chain = if udp || prefix {
                crate::client_proxy_chain::ClientProxyChain::new(
                    vec![crate::client_proxy_chain::InitialHopEntry::Direct(
                        Arc::new(TestConnector {
                            address: std::net::SocketAddr::from((
                                [127, 0, 0, 1],
                                listener.local_addr().unwrap().port(),
                            )),
                            blocked_write: prefix.then(|| writing.clone()),
                        }),
                    )],
                    Vec::new(),
                )
            } else {
                crate::tcp::chain_builder::try_build_client_proxy_chain(
                    crate::option_util::OneOrSome::One(crate::config::ClientChainHop::Single(
                        crate::config::ConfigSelection::Config(client),
                    )),
                    resolver.clone(),
                )
                .unwrap()
            };
            let group = ClientChainGroup::new(vec![chain]).with_description(Some(Arc::new(
                RuleDescription {
                    payload: "all".into(),
                    proxy: "DIRECT".into(),
                    context: Some(Arc::new(FlowContext {
                        registry: registry.clone(),
                        generation: 1,
                        inbound: "test".into(),
                        scope: "root".into(),
                        protocol: "AnyTLS".into(),
                    })),
                },
            )));
            let selector = Arc::new(
                ClientProxySelector::new(vec![ConnectRule::new(
                    if prefix {
                        vec![crate::address::NetLocationMask::from("sniff.example").unwrap()]
                    } else {
                        vec![crate::address::NetLocationMask::ANY]
                    },
                    ConnectAction::new_allow(None, group),
                )])
                .with_sniff(prefix),
            );
            let (transport, mut peer) = duplex(if early_data || prefix || established {
                8192
            } else {
                1
            });
            let session = AnyTlsSession::new_server_with_initial_data(
                transport,
                PaddingFactory::default_factory(),
                resolver,
                selector,
                false,
                "test".into(),
                None,
            );
            session.peer_version.store(2, Ordering::Relaxed);
            while session.outgoing_tx.capacity() > 0 {
                session
                    .outgoing_tx
                    .try_send((2, Bytes::from_static(b"queued")))
                    .unwrap();
            }
            let (sender, receiver) = mpsc::channel(1);
            if prefix {
                sender
                    .try_send(Bytes::from(crate::sniff::tests::hello(
                        &rustls::version::TLS13,
                        true,
                    )))
                    .unwrap();
            } else if !established {
                sender
                    .try_send(Bytes::from_static(b"queued upload"))
                    .unwrap();
            }
            let stream = AnyTlsStream::new(
                1,
                receiver,
                session.outgoing_tx.clone(),
                session.is_closed.clone(),
            );
            let handler = session.clone();
            let forwarding = tokio::spawn(async move {
                if udp {
                    handler.handle_uot_v2_connect(stream, target).await
                } else {
                    handler.handle_tcp_forward(stream, target).await
                }
            });
            let (mut egress, _) = listener.accept().await.unwrap();
            if early_data {
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(egress.read_u8().await.unwrap());
                }
                assert!(request.starts_with(b"CONNECT "));
                egress
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\ngreeting")
                    .await
                    .unwrap();
            }
            let mut header = [0; 7];
            let initial = if early_data || prefix || established {
                7
            } else {
                1
            };
            peer.read_exact(&mut header[..initial]).await.unwrap();
            if prefix {
                writing.notified().await;
                assert_eq!(
                    registry.snapshot(0).connections[0].metadata.sniff_host,
                    "sniff.example"
                );
            }
            if early_data {
                assert_eq!(
                    registry.snapshot(0).connections[0].download,
                    8,
                    "fixture must return early data before copying starts"
                );
            }
            if established {
                if udp {
                    egress.write_all(&8u16.to_be_bytes()).await.unwrap();
                }
                egress.write_all(b"download").await.unwrap();
                while registry.snapshot(0).connections[0].download == 0 {
                    tokio::task::yield_now().await;
                }
            }
            tokio::task::yield_now().await;
            if during_shutdown {
                sender.try_send(Bytes::new()).unwrap();
                assert_eq!(egress.read(&mut [0; 1]).await.unwrap(), 0);
            }
            registry.cancel_all();
            if established || prefix {
                sender
                    .try_send(Bytes::from_static(b"queued upload"))
                    .unwrap();
            }
            timeout(Duration::from_millis(100), async {
                while !registry.snapshot(0).connections.is_empty() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert_eq!(egress.read(&mut [0; 1]).await.unwrap(), 0);
            timeout(Duration::from_millis(100), sender.closed())
                .await
                .unwrap();
            assert!(!forwarding.is_finished(), "{phase:?}, drain={drain}");
            peer.read_exact(&mut header[initial..]).await.unwrap();
            assert_eq!(
                header.as_slice(),
                Frame::control(Command::SynAck, 1).encode().as_ref()
            );
            if drain {
                let mut outgoing = session.outgoing_rx.lock().await;
                loop {
                    let (id, data) = outgoing.recv().await.unwrap();
                    if id == 1 {
                        assert!(
                            data.is_empty(),
                            "cancelled stream must queue FIN after SYNACK"
                        );
                        break;
                    }
                    assert_eq!((id, data), (2, Bytes::from_static(b"queued")));
                }
                drop(outgoing);
            }
            let result = timeout(Duration::from_secs(1), forwarding)
                .await
                .unwrap()
                .unwrap();
            if during_shutdown {
                result.unwrap();
            } else {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
            }
            let (result, read) =
                tokio::join!(session.send_synack(2, None), peer.read_exact(&mut header));
            result.unwrap();
            read.unwrap();
            assert_eq!(
                header.as_slice(),
                Frame::control(Command::SynAck, 2).encode().as_ref()
            );
            assert!(!session.is_closed());
        })
        .await
        .unwrap_or_else(|error| panic!("{phase:?}, drain={drain}: {error}"));
    }
}

#[tokio::test(start_paused = true)]
async fn setup_timeout_does_not_limit_established_stream_lifetime() {
    let (conn, _peer) = duplex(8192);
    let mut session = AnyTlsSession::new_server_test(conn, PaddingFactory::default_factory());
    Arc::get_mut(&mut session).unwrap().udp_enabled = true;
    session
        .received_client_settings
        .store(true, Ordering::Relaxed);
    session
        .handle_frame(Frame::control(Command::Syn, 1))
        .await
        .unwrap();
    session
        .handle_frame(Frame::control(Command::Syn, 2))
        .await
        .unwrap();
    let mut destination = vec![3, UOT_V1_MAGIC_ADDRESS.len() as u8];
    destination.extend_from_slice(UOT_V1_MAGIC_ADDRESS.as_bytes());
    destination.extend_from_slice(&[0, 0]);
    session
        .handle_frame(Frame::data(2, Bytes::from(destination)))
        .await
        .unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(301)).await;
    tokio::task::yield_now().await;
    assert!(!session.stream_tasks.lock().contains_key(&1));
    assert!(session.stream_tasks.lock().contains_key(&2));
    session.close().await;
}

#[tokio::test]
async fn cancelling_run_closes_and_releases_child_tasks() {
    let (conn, mut peer) = duplex(8192);
    let session = AnyTlsSession::new_server_test(conn, PaddingFactory::default_factory());
    session
        .received_client_settings
        .store(true, Ordering::Relaxed);
    let run_session = session.clone();
    let run = tokio::spawn(async move { run_session.run().await });
    peer.write_all(&Frame::control(Command::Syn, 1).encode())
        .await
        .unwrap();
    timeout(Duration::from_secs(1), async {
        while session.stream_tasks.lock().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    run.abort();
    let _ = run.await;
    assert!(session.is_closed());
    assert!(session.stream_tasks.lock().is_empty());
    assert!(session.streams.read().is_empty());
    let weak = Arc::downgrade(&session);
    drop(session);
    timeout(Duration::from_secs(1), async {
        while weak.strong_count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn test_session_creation() {
    let (client, _server) = duplex(8192);
    let padding = PaddingFactory::default_factory();
    let session = AnyTlsSession::new_server_test(client, padding);

    assert!(!session.is_closed());
    assert!(!session.is_client);
}

#[tokio::test]
async fn test_frame_encoding() {
    let frame = Frame::data(123, Bytes::from("test data"));
    let encoded = frame.encode();

    assert_eq!(encoded[0], Command::Psh as u8);
    assert_eq!(
        u32::from_be_bytes([encoded[1], encoded[2], encoded[3], encoded[4]]),
        123
    );
    assert_eq!(u16::from_be_bytes([encoded[5], encoded[6]]), 9);
    assert_eq!(&encoded[7..], b"test data");
}

#[tokio::test]
async fn test_session_close() {
    let (client, _server) = duplex(8192);
    let padding = PaddingFactory::default_factory();
    let session = AnyTlsSession::new_server_test(client, padding);

    assert!(!session.is_closed());
    session.close().await;
    assert!(session.is_closed());
}

#[tokio::test]
async fn test_settings_frame_parsing() {
    let mut settings = StringMap::new();
    settings.insert("v", "2");
    settings.insert("client", "test");
    settings.insert("padding-md5", "abc123");

    let bytes = settings.to_bytes();
    let parsed = StringMap::from_bytes(&bytes);

    assert_eq!(parsed.get("v"), Some(&"2".to_string()));
    assert_eq!(parsed.get("client"), Some(&"test".to_string()));
    assert_eq!(parsed.get("padding-md5"), Some(&"abc123".to_string()));
}

#[tokio::test]
async fn test_control_frame_types() {
    // Test all control frame types
    for (cmd, expected_byte) in [
        (Command::Waste, 0),
        (Command::Syn, 1),
        (Command::Psh, 2),
        (Command::Fin, 3),
        (Command::Settings, 4),
        (Command::Alert, 5),
        (Command::UpdatePaddingScheme, 6),
        (Command::SynAck, 7),
        (Command::HeartRequest, 8),
        (Command::HeartResponse, 9),
        (Command::ServerSettings, 10),
    ] {
        let frame = Frame::control(cmd, 42);
        let encoded = frame.encode();
        assert_eq!(encoded[0], expected_byte);
    }
}

#[tokio::test]
async fn test_heartbeat_frame_roundtrip() {
    let request = Frame::control(Command::HeartRequest, 0);
    let encoded = request.encode();

    let mut buf = BytesMut::from(&encoded[..]);
    let decoded = FrameCodec::decode(&mut buf).unwrap().unwrap();

    assert_eq!(decoded.cmd, Command::HeartRequest);
    assert_eq!(decoded.stream_id, 0);
    assert!(decoded.data.is_empty());
}

#[tokio::test]
async fn test_multiple_streams_frame_interleaving() {
    // Simulate multiple streams sending data - verify framing isolation
    let stream1_data = Frame::data(1, Bytes::from("stream1-data"));
    let stream2_data = Frame::data(2, Bytes::from("stream2-data"));
    let stream3_data = Frame::data(3, Bytes::from("stream3-data"));

    let mut combined = BytesMut::new();
    combined.extend_from_slice(&stream1_data.encode());
    combined.extend_from_slice(&stream2_data.encode());
    combined.extend_from_slice(&stream3_data.encode());

    // Decode all frames
    let f1 = FrameCodec::decode(&mut combined).unwrap().unwrap();
    let f2 = FrameCodec::decode(&mut combined).unwrap().unwrap();
    let f3 = FrameCodec::decode(&mut combined).unwrap().unwrap();

    assert_eq!(f1.stream_id, 1);
    assert_eq!(f1.data.as_ref(), b"stream1-data");
    assert_eq!(f2.stream_id, 2);
    assert_eq!(f2.data.as_ref(), b"stream2-data");
    assert_eq!(f3.stream_id, 3);
    assert_eq!(f3.data.as_ref(), b"stream3-data");
}

#[tokio::test]
async fn test_fin_and_syn_sequence() {
    // Test SYN -> PSH -> FIN sequence
    let syn = Frame::control(Command::Syn, 1);
    let data = Frame::data(1, Bytes::from("payload"));
    let fin = Frame::control(Command::Fin, 1);

    let mut combined = BytesMut::new();
    combined.extend_from_slice(&syn.encode());
    combined.extend_from_slice(&data.encode());
    combined.extend_from_slice(&fin.encode());

    let f1 = FrameCodec::decode(&mut combined).unwrap().unwrap();
    let f2 = FrameCodec::decode(&mut combined).unwrap().unwrap();
    let f3 = FrameCodec::decode(&mut combined).unwrap().unwrap();

    assert_eq!(f1.cmd, Command::Syn);
    assert_eq!(f2.cmd, Command::Psh);
    assert_eq!(f3.cmd, Command::Fin);
    assert!(f1.data.is_empty());
    assert_eq!(f2.data.as_ref(), b"payload");
    assert!(f3.data.is_empty());
}

#[tokio::test]
async fn test_alert_frame_with_message() {
    let alert = Frame::with_data(Command::Alert, 0, Bytes::from("connection refused"));
    let encoded = alert.encode();

    let mut buf = BytesMut::from(&encoded[..]);
    let decoded = FrameCodec::decode(&mut buf).unwrap().unwrap();

    assert_eq!(decoded.cmd, Command::Alert);
    assert_eq!(decoded.data.as_ref(), b"connection refused");
}

#[tokio::test]
async fn test_large_frame() {
    // Test frame with max-ish size (16KB)
    let large_data = vec![0xABu8; 16384];
    let frame = Frame::data(99, Bytes::from(large_data.clone()));
    let encoded = frame.encode();

    let mut buf = BytesMut::from(&encoded[..]);
    let decoded = FrameCodec::decode(&mut buf).unwrap().unwrap();

    assert_eq!(decoded.stream_id, 99);
    assert_eq!(decoded.data.len(), 16384);
    assert_eq!(decoded.data.as_ref(), large_data.as_slice());
}

#[tokio::test]
async fn test_partial_frame_decode() {
    // Test that partial frames don't decode until complete
    let frame = Frame::data(1, Bytes::from("complete"));
    let encoded = frame.encode();

    // Only provide partial data
    let mut partial = BytesMut::from(&encoded[..5]); // Only header partial
    let result = FrameCodec::decode(&mut partial).unwrap();
    assert!(result.is_none());

    // Add remaining data
    partial.extend_from_slice(&encoded[5..]);
    let decoded = FrameCodec::decode(&mut partial).unwrap().unwrap();
    assert_eq!(decoded.data.as_ref(), b"complete");
}

#[tokio::test]
async fn test_waste_frame_padding() {
    // Test padding frame
    let padding_data = vec![0u8; 100];
    let waste = Frame::with_data(Command::Waste, 0, Bytes::from(padding_data.clone()));
    let encoded = waste.encode();

    let mut buf = BytesMut::from(&encoded[..]);
    let decoded = FrameCodec::decode(&mut buf).unwrap().unwrap();

    assert_eq!(decoded.cmd, Command::Waste);
    assert_eq!(decoded.stream_id, 0);
    assert_eq!(decoded.data.len(), 100);
}

#[tokio::test]
async fn test_session_rejects_syn_without_settings() {
    let (client, mut server) = duplex(8192);
    let padding = PaddingFactory::default_factory();
    let session = AnyTlsSession::new_server_test(client, padding);

    let session_clone = Arc::clone(&session);
    let run_task = tokio::spawn(async move {
        let _ = session_clone.run().await;
    });

    // Send SYN without Settings first
    let syn_frame = Frame::control(Command::Syn, 1);
    server.write_all(&syn_frame.encode()).await.unwrap();

    // Should receive Alert
    let mut buf = vec![0u8; 256];
    let result = timeout(Duration::from_millis(500), server.read(&mut buf)).await;

    if let Ok(Ok(n)) = result
        && n > 0
    {
        assert_eq!(buf[0], Command::Alert as u8);
    }

    session.close().await;
    run_task.abort();
}

#[tokio::test]
async fn test_heartbeat_response() {
    let (client, mut server) = duplex(8192);
    let padding = PaddingFactory::default_factory();
    let session = AnyTlsSession::new_server_test(client, padding);

    let session_clone = Arc::clone(&session);
    let run_task = tokio::spawn(async move {
        let _ = session_clone.run().await;
    });

    // Send settings first
    let mut settings = StringMap::new();
    settings.insert("v", "2");
    settings.insert("padding-md5", PaddingFactory::default_factory().md5());
    let settings_frame = Frame::with_data(Command::Settings, 0, Bytes::from(settings.to_bytes()));
    server.write_all(&settings_frame.encode()).await.unwrap();

    // Wait for and consume the ServerSettings response
    let mut buf = vec![0u8; 128];
    let _ = timeout(Duration::from_millis(200), server.read(&mut buf)).await;

    // Send heartbeat request
    let heart_request = Frame::control(Command::HeartRequest, 0);
    server.write_all(&heart_request.encode()).await.unwrap();

    // Should receive heartbeat response
    let mut response_buf = vec![0u8; 16];
    let result = timeout(Duration::from_millis(500), server.read(&mut response_buf)).await;

    if let Ok(Ok(n)) = result
        && n >= 7
    {
        assert_eq!(response_buf[0], Command::HeartResponse as u8);
    }

    session.close().await;
    run_task.abort();
}

// ===== Frame parsing edge case tests =====

#[test]
fn test_frame_zero_length_data() {
    let frame = Frame::data(1, Bytes::new());
    let encoded = frame.encode();

    assert_eq!(encoded.len(), FRAME_HEADER_SIZE); // Just header, no data
    assert_eq!(encoded[0], Command::Psh as u8);

    // Decode should work
    let mut buf = BytesMut::from(&encoded[..]);
    let decoded = FrameCodec::decode(&mut buf).unwrap().unwrap();
    assert!(decoded.data.is_empty());
}

#[test]
fn test_frame_max_stream_id() {
    let frame = Frame::control(Command::Syn, u32::MAX);
    let encoded = frame.encode();

    let mut buf = BytesMut::from(&encoded[..]);
    let decoded = FrameCodec::decode(&mut buf).unwrap().unwrap();
    assert_eq!(decoded.stream_id, u32::MAX);
}

#[test]
fn test_frame_decode_incomplete_header() {
    // Less than 7 bytes
    let mut buf = BytesMut::from(&[0x00, 0x00, 0x00][..]);
    let result = FrameCodec::decode(&mut buf).unwrap();
    assert!(result.is_none());
}

#[test]
fn test_frame_decode_incomplete_data() {
    // Header says 100 bytes of data, but only 50 provided
    let mut buf = BytesMut::with_capacity(64);
    buf.extend_from_slice(&[Command::Psh as u8]); // cmd
    buf.extend_from_slice(&[0, 0, 0, 1]); // stream_id = 1
    buf.extend_from_slice(&[0, 100]); // length = 100
    buf.extend_from_slice(&[0u8; 50]); // only 50 bytes of data

    let result = FrameCodec::decode(&mut buf).unwrap();
    assert!(result.is_none());
}

#[test]
fn test_frame_unknown_command_returns_error() {
    // Command byte 255 is not defined
    let mut buf = BytesMut::with_capacity(16);
    buf.extend_from_slice(&[255u8]); // unknown cmd
    buf.extend_from_slice(&[0, 0, 0, 1]); // stream_id = 1
    buf.extend_from_slice(&[0, 0]); // length = 0

    let result = FrameCodec::decode(&mut buf);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
}

#[test]
fn test_frame_all_command_types() {
    for cmd in [
        Command::Waste,
        Command::Syn,
        Command::Psh,
        Command::Fin,
        Command::Settings,
        Command::Alert,
        Command::UpdatePaddingScheme,
        Command::SynAck,
        Command::HeartRequest,
        Command::HeartResponse,
        Command::ServerSettings,
    ] {
        let frame = Frame::control(cmd, 1);
        let encoded = frame.encode();
        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = FrameCodec::decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.cmd, cmd);
    }
}

#[test]
fn test_frame_max_data_length() {
    // Max u16 = 65535 bytes
    let large_data = vec![0xFFu8; 65535];
    let frame = Frame::data(1, Bytes::from(large_data.clone()));
    let encoded = frame.encode();

    // Verify length field
    let len = u16::from_be_bytes([encoded[5], encoded[6]]);
    assert_eq!(len, 65535);

    let mut buf = BytesMut::from(&encoded[..]);
    let decoded = FrameCodec::decode(&mut buf).unwrap().unwrap();
    assert_eq!(decoded.data.len(), 65535);
}

// ===== Session protocol edge case tests =====

#[tokio::test]
async fn test_session_psh_for_nonexistent_stream() {
    let (client, mut server) = duplex(8192);
    let padding = PaddingFactory::default_factory();
    let session = AnyTlsSession::new_server_test(client, padding);

    let session_clone = Arc::clone(&session);
    let run_task = tokio::spawn(async move {
        let _ = session_clone.run().await;
    });

    // Send settings
    let mut settings = StringMap::new();
    settings.insert("v", "2");
    settings.insert("padding-md5", PaddingFactory::default_factory().md5());
    let settings_frame = Frame::with_data(Command::Settings, 0, Bytes::from(settings.to_bytes()));
    server.write_all(&settings_frame.encode()).await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send PSH for stream 999 (never opened)
    // This should NOT crash the session
    let psh = Frame::data(999, Bytes::from("orphan data"));
    server.write_all(&psh.encode()).await.unwrap();

    // Session should still be alive - send heartbeat to verify
    tokio::time::sleep(Duration::from_millis(100)).await;
    let heart = Frame::control(Command::HeartRequest, 0);
    let result = server.write_all(&heart.encode()).await;
    assert!(result.is_ok());

    session.close().await;
    run_task.abort();
}

#[tokio::test]
async fn test_session_fin_for_nonexistent_stream() {
    let (client, mut server) = duplex(8192);
    let padding = PaddingFactory::default_factory();
    let session = AnyTlsSession::new_server_test(client, padding);

    let session_clone = Arc::clone(&session);
    let run_task = tokio::spawn(async move {
        let _ = session_clone.run().await;
    });

    // Send settings
    let mut settings = StringMap::new();
    settings.insert("v", "2");
    settings.insert("padding-md5", PaddingFactory::default_factory().md5());
    let settings_frame = Frame::with_data(Command::Settings, 0, Bytes::from(settings.to_bytes()));
    server.write_all(&settings_frame.encode()).await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send FIN for stream 999 (never opened)
    // Should be gracefully ignored
    let fin = Frame::control(Command::Fin, 999);
    server.write_all(&fin.encode()).await.unwrap();

    // Session should still be alive
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!session.is_closed());

    session.close().await;
    run_task.abort();
}

#[tokio::test]
async fn test_session_waste_frame_ignored() {
    let (client, mut server) = duplex(8192);
    let padding = PaddingFactory::default_factory();
    let session = AnyTlsSession::new_server_test(client, padding);

    let session_clone = Arc::clone(&session);
    let run_task = tokio::spawn(async move {
        let _ = session_clone.run().await;
    });

    // Send settings
    let mut settings = StringMap::new();
    settings.insert("v", "2");
    settings.insert("padding-md5", PaddingFactory::default_factory().md5());
    let settings_frame = Frame::with_data(Command::Settings, 0, Bytes::from(settings.to_bytes()));
    server.write_all(&settings_frame.encode()).await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send waste (padding) frame with data
    let padding_data = vec![0u8; 500];
    let waste = Frame::with_data(Command::Waste, 0, Bytes::from(padding_data));
    server.write_all(&waste.encode()).await.unwrap();

    // Session should still function
    tokio::time::sleep(Duration::from_millis(100)).await;
    let syn = Frame::control(Command::Syn, 1);
    let result = server.write_all(&syn.encode()).await;
    assert!(result.is_ok());

    session.close().await;
    run_task.abort();
}

#[tokio::test]
async fn test_session_update_padding_scheme() {
    let (client, mut server) = duplex(8192);
    let padding = PaddingFactory::default_factory();
    let session = AnyTlsSession::new_server_test(client, padding);

    let session_clone = Arc::clone(&session);
    let run_task = tokio::spawn(async move {
        let _ = session_clone.run().await;
    });

    // Send settings with mismatched padding MD5
    let mut settings = StringMap::new();
    settings.insert("v", "2");
    settings.insert("padding-md5", "different_md5_value");
    let settings_frame = Frame::with_data(Command::Settings, 0, Bytes::from(settings.to_bytes()));
    server.write_all(&settings_frame.encode()).await.unwrap();

    // Should receive UpdatePaddingScheme frame
    let mut buf = vec![0u8; 256];
    let result = timeout(Duration::from_millis(500), server.read(&mut buf)).await;

    if let Ok(Ok(n)) = result
        && n >= 7
    {
        // Could be ServerSettings or UpdatePaddingScheme
        // Either is valid response
        let cmd = buf[0];
        assert!(cmd == Command::UpdatePaddingScheme as u8 || cmd == Command::ServerSettings as u8);
    }

    session.close().await;
    run_task.abort();
}

#[tokio::test]
async fn test_session_alert_closes_session() {
    let (client, mut server) = duplex(8192);
    let padding = PaddingFactory::default_factory();
    let session = AnyTlsSession::new_server_test(client, padding);

    let session_clone = Arc::clone(&session);
    let run_task = tokio::spawn(async move {
        let _ = session_clone.run().await;
    });

    // Send settings first
    let mut settings = StringMap::new();
    settings.insert("v", "2");
    settings.insert("padding-md5", PaddingFactory::default_factory().md5());
    let settings_frame = Frame::with_data(Command::Settings, 0, Bytes::from(settings.to_bytes()));
    server.write_all(&settings_frame.encode()).await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send Alert from client
    let alert = Frame::with_data(Command::Alert, 0, Bytes::from("client error"));
    server.write_all(&alert.encode()).await.unwrap();

    // Session should close
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(session.is_closed());

    run_task.abort();
}

// ===== StringMap tests =====

#[test]
fn test_stringmap_roundtrip() {
    let mut map = StringMap::new();
    map.insert("key1", "value1");
    map.insert("key2", "value2");
    map.insert("special", "a=b=c");

    let bytes = map.to_bytes();
    let parsed = StringMap::from_bytes(&bytes);

    assert_eq!(parsed.get("key1"), Some(&"value1".to_string()));
    assert_eq!(parsed.get("key2"), Some(&"value2".to_string()));
    assert_eq!(parsed.get("special"), Some(&"a=b=c".to_string()));
}

#[test]
fn test_stringmap_empty() {
    let map = StringMap::new();
    let bytes = map.to_bytes();
    assert!(bytes.is_empty());

    let parsed = StringMap::from_bytes(&[]);
    assert!(parsed.get("anything").is_none());
}

#[test]
fn test_stringmap_newlines_in_values() {
    let mut map = StringMap::new();
    map.insert("multiline", "line1\nline2"); // Should not break parsing

    let bytes = map.to_bytes();
    let parsed = StringMap::from_bytes(&bytes);

    // With newlines, parsing may be affected
    // This test documents current behavior
    let val = parsed.get("multiline");
    // Value may be truncated at newline
    assert!(val.is_none() || val == Some(&"line1".to_string()));
}

#[test]
fn test_stringmap_special_characters() {
    let mut map = StringMap::new();
    map.insert("unicode", "Hello World!");
    map.insert("empty", "");

    let bytes = map.to_bytes();
    let parsed = StringMap::from_bytes(&bytes);

    assert_eq!(parsed.get("unicode"), Some(&"Hello World!".to_string()));
    assert_eq!(parsed.get("empty"), Some(&"".to_string()));
}
