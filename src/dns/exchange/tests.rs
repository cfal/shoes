use super::*;
use hickory_resolver::proto::op::{Query, ResponseCode};
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType, rdata};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn endpoint_pairing_requires_equal_ip_port_and_bind_address() {
    let upstream = |ip, config| Upstream {
        server_index: 0,
        ip,
        config,
        connection: Mutex::new(None),
    };
    let mut udp = upstream("192.0.2.1".parse().unwrap(), ConnectionConfig::udp());
    let mut tcp = upstream(udp.ip, ConnectionConfig::tcp());
    assert!(udp.same_endpoint(&tcp));
    assert!(tcp.same_endpoint(&udp));

    tcp.ip = "192.0.2.2".parse().unwrap();
    assert!(!udp.same_endpoint(&tcp));
    tcp.ip = udp.ip;
    tcp.config.port = udp.config.port + 1;
    assert!(!udp.same_endpoint(&tcp));
    tcp.config.port = udp.config.port;
    tcp.config.bind_addr = Some("127.0.0.1:0".parse().unwrap());
    assert!(!udp.same_endpoint(&tcp));
    udp.config.bind_addr = tcp.config.bind_addr;
    assert!(udp.same_endpoint(&tcp));
    tcp.config.bind_addr = Some("127.0.0.2:0".parse().unwrap());
    assert!(!udp.same_endpoint(&tcp));
}

fn exchange(addr: std::net::SocketAddr, tcp: bool) -> RawDnsExchange {
    let resolver = Arc::new(crate::resolver::NativeResolver::new());
    let provider = ProxyRuntimeProvider::with_bootstrap(
        Arc::new(crate::tcp::chain_builder::build_direct_chain_group(
            resolver.clone(),
        )),
        resolver,
        Duration::from_secs(1),
    );
    let mut config = if tcp {
        ConnectionConfig::tcp()
    } else {
        ConnectionConfig::udp()
    };
    config.port = addr.port();
    let mut options = ResolverOpts::default();
    options.timeout = Duration::from_secs(1);
    options.attempts = 1;
    RawDnsExchange::new(
        vec![NameServerConfig::new(addr.ip(), true, vec![config])],
        provider,
        options,
    )
}

fn request() -> Message {
    let mut message = Message::query();
    message.metadata.id = 17;
    message.metadata.checking_disabled = true;
    message.metadata.recursion_desired = false;
    message.add_query(Query::query(
        Name::from_ascii("Case.Example.").unwrap(),
        RecordType::TXT,
    ));
    message
}

#[tokio::test]
async fn fake_dns_raw_forwarding_over_verified_tls_preserves_and_guards_answers() {
    use crate::resolver::{DnsExchangeFuture, ResolveFuture, Resolver};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct Encrypted(Arc<RawDnsExchange>);
    impl Resolver for Encrypted {
        fn resolve_location(&self, _: &crate::address::NetLocation) -> ResolveFuture {
            panic!("Fake DNS forwarding must use raw exchange, not lookup")
        }
        fn exchange(&self, bytes: Vec<u8>) -> DnsExchangeFuture {
            let raw = self.0.clone();
            Box::pin(async move { raw.exchange(bytes).await })
        }
        fn exchange_with_deadline(
            &self,
            bytes: Vec<u8>,
            deadline: tokio::time::Instant,
        ) -> DnsExchangeFuture {
            let raw = self.0.clone();
            Box::pin(async move { raw.exchange_with_deadline(bytes, deadline).await })
        }
    }

    tokio::time::timeout(Duration::from_secs(10), async {
        let cert = rcgen::generate_simple_self_signed(vec!["dns.example".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
                    .into(),
            )
            .unwrap();
        server_tls.alpn_protocols = vec![b"dot".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address =
            std::net::SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
        let mut raw = exchange(address, true);
        let mut config = ConnectionConfig::tls("dns.example".into());
        config.port = address.port();
        raw.upstreams[0].config = config;
        raw.context = PoolContext::new(
            ResolverOpts::default(),
            TlsConfig {
                config: rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            },
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let exchanges = calls.clone();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(tcp).await.unwrap();
            for _ in 0..6 {
                let len = stream.read_u16().await.unwrap();
                let mut bytes = vec![0; len as usize];
                stream.read_exact(&mut bytes).await.unwrap();
                let query = Message::from_vec(&bytes).unwrap();
                assert_eq!(query.queries[0].query_type, RecordType::TXT);
                let name = query.queries[0].name().clone();
                let mut reply = query.into_response();
                match name.to_ascii().as_str() {
                    "text.example." => {
                        reply.add_answer(Record::from_rdata(
                            name,
                            30,
                            RData::TXT(rdata::TXT::new(vec!["encrypted answer".into()])),
                        ));
                    }
                    "missing.example." => reply.metadata.response_code = ResponseCode::NXDomain,
                    "poison.example." => {
                        reply.add_additional(Record::from_rdata(
                            name,
                            30,
                            RData::A(rdata::A::new(198, 18, 0, 9)),
                        ));
                    }
                    name => panic!("unexpected forwarded name {name}"),
                }
                exchanges.fetch_add(1, Ordering::SeqCst);
                let bytes = reply.to_vec().unwrap();
                stream.write_u16(bytes.len() as u16).await.unwrap();
                stream.write_all(&bytes).await.unwrap();
                stream.flush().await.unwrap();
            }
            stopped.await.unwrap();
        }));
        let context = crate::dns::fake_ip::FakeDnsContext::new(
            Default::default(),
            Arc::new(Encrypted(Arc::new(raw))),
        )
        .unwrap();
        for tcp in [false, true] {
            for (index, (name, kind, expected)) in [
                ("synth.example.", RecordType::A, ResponseCode::NoError),
                ("text.example.", RecordType::TXT, ResponseCode::NoError),
                ("missing.example.", RecordType::TXT, ResponseCode::NXDomain),
                ("poison.example.", RecordType::TXT, ResponseCode::ServFail),
            ]
            .into_iter()
            .enumerate()
            {
                let before = calls.load(Ordering::SeqCst);
                let mut request = Message::query();
                request.metadata.id = 90 + index as u16;
                request.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
                let bytes = context
                    .exchange(request.to_vec().unwrap(), tcp)
                    .await
                    .unwrap()
                    .unwrap();
                let reply = Message::from_vec(&bytes).unwrap();
                assert_eq!(reply.metadata.id, request.metadata.id);
                assert_eq!(reply.queries, request.queries);
                assert_eq!(reply.metadata.response_code, expected);
                assert_eq!(
                    calls.load(Ordering::SeqCst),
                    before + usize::from(kind != RecordType::A)
                );
                if kind == RecordType::A {
                    let RData::A(ip) = reply.answers[0].data else {
                        panic!("missing synthetic A")
                    };
                    assert!(context.contains(ip.0.into()));
                } else if expected == ResponseCode::NoError {
                    assert_eq!(
                        reply.answers[0].data,
                        RData::TXT(rdata::TXT::new(vec!["encrypted answer".into()]))
                    );
                } else {
                    assert!(reply.answers.is_empty());
                    assert!(reply.additionals.is_empty());
                }
            }
        }
        stop.send(()).unwrap();
        server.await.unwrap();
    })
    .await
    .unwrap();
}

async fn read_tcp(stream: &mut tokio::net::TcpStream) -> Message {
    let len = stream.read_u16().await.unwrap();
    let mut bytes = vec![0; len as usize];
    stream.read_exact(&mut bytes).await.unwrap();
    Message::from_vec(&bytes).unwrap()
}

async fn write_tcp(stream: &mut tokio::net::TcpStream, message: Message) {
    let bytes = message.to_vec().unwrap();
    stream.write_u16(bytes.len() as u16).await.unwrap();
    stream.write_all(&bytes).await.unwrap();
}

#[tokio::test]
async fn concurrent_tcp_ids_and_negative_replies_stay_independent() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let raw = exchange(listener.local_addr().unwrap(), true);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let first = read_tcp(&mut stream).await;
        let second = read_tcp(&mut stream).await;
        assert_ne!(first.metadata.id, second.metadata.id);
        for query in [second, first] {
            let mut answer = query.into_response();
            answer.metadata.response_code = if answer.queries[0].query_type == RecordType::TXT {
                ResponseCode::Refused
            } else {
                ResponseCode::ServFail
            };
            write_tcp(&mut stream, answer).await;
        }
    });
    let first = request();
    let mut second = request();
    second.queries[0].query_type = RecordType::HTTPS;
    let (a, b) = tokio::join!(
        raw.exchange(first.to_vec().unwrap()),
        raw.exchange(second.to_vec().unwrap())
    );
    let a = Message::from_vec(&a.unwrap()).unwrap();
    let b = Message::from_vec(&b.unwrap()).unwrap();
    assert_eq!(a.metadata.id, 17);
    assert_eq!(b.metadata.id, 17);
    assert_eq!(a.queries, first.queries);
    assert_eq!(b.queries, second.queries);
    assert_eq!(a.metadata.response_code, ResponseCode::Refused);
    assert_eq!(b.metadata.response_code, ResponseCode::ServFail);
    server.await.unwrap();
}

#[tokio::test]
async fn rejects_tcp_question_mismatch() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let raw = exchange(listener.local_addr().unwrap(), true);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut reply = read_tcp(&mut stream).await.into_response();
        reply.queries[0].query_type = RecordType::MX;
        write_tcp(&mut stream, reply).await;
    });
    assert_eq!(
        raw.exchange(request().to_vec().unwrap())
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    server.await.unwrap();
}

#[tokio::test]
async fn dead_tcp_handle_reconnects_without_spinning() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let raw = exchange(listener.local_addr().unwrap(), true);
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let reply = read_tcp(&mut stream).await.into_response();
            write_tcp(&mut stream, reply).await;
            stream.shutdown().await.unwrap();
        }
    });
    for _ in 0..2 {
        tokio::time::timeout(
            Duration::from_secs(3),
            raw.exchange(request().to_vec().unwrap()),
        )
        .await
        .unwrap()
        .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    server.await.unwrap();
}

#[tokio::test]
async fn udp_only_configuration_returns_truncation_without_new_transport() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let raw = exchange(socket.local_addr().unwrap(), false);
    let server = tokio::spawn(async move {
        let mut bytes = [0; 2048];
        let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
        let mut reply = Message::from_vec(&bytes[..len]).unwrap().into_response();
        reply.metadata.truncation = true;
        socket
            .send_to(&reply.to_vec().unwrap(), peer)
            .await
            .unwrap();
    });
    let reply = raw.exchange(request().to_vec().unwrap()).await.unwrap();
    assert!(Message::from_vec(&reply).unwrap().metadata.truncation);
    server.await.unwrap();
}

#[tokio::test]
async fn separately_configured_tcp_remains_a_primary_when_udp_is_silent() {
    for system_pair in [true, false] {
        let (tcp, udp) = crate::dns::bind_tcp_and_udp().await;
        let address = udp.local_addr().unwrap();
        let mut udp_config = ConnectionConfig::udp();
        udp_config.port = address.port();
        let mut tcp_config = ConnectionConfig::tcp();
        tcp_config.port = address.port();
        let servers = if system_pair {
            vec![NameServerConfig::new(
                address.ip(),
                true,
                vec![udp_config, tcp_config],
            )]
        } else {
            vec![
                NameServerConfig::new(address.ip(), true, vec![udp_config]),
                NameServerConfig::new(address.ip(), true, vec![tcp_config]),
            ]
        };
        let mut options = ResolverOpts::default();
        options.timeout = Duration::from_millis(100);
        options.attempts = 1;
        let raw = RawDnsExchange::new(servers, exchange(address, false).provider, options);
        if system_pair {
            assert_eq!(
                raw.exchange(request().to_vec().unwrap())
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::TimedOut
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(20), tcp.accept())
                    .await
                    .is_err()
            );
        } else {
            let server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                let (mut stream, _) = tcp.accept().await.unwrap();
                let answer = read_tcp(&mut stream).await.into_response();
                write_tcp(&mut stream, answer).await;
            }));
            let answer = raw.exchange(request().to_vec().unwrap()).await.unwrap();
            assert_eq!(Message::from_vec(&answer).unwrap().metadata.id, 17);
            server.await.unwrap();
        }
    }
}

#[tokio::test]
async fn silent_first_server_does_not_starve_healthy_second_server() {
    for (system_pair, extra_silent) in [(false, false), (true, false), (true, true)] {
        let silent = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let second_silent = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let healthy = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let mut raw = exchange(silent.local_addr().unwrap(), false);
        raw.context.options.timeout = Duration::from_millis(200);
        if system_pair {
            let mut config = ConnectionConfig::tcp();
            config.port = silent.local_addr().unwrap().port();
            raw.upstreams.push(Upstream {
                server_index: 0,
                ip: "127.0.0.1".parse().unwrap(),
                config,
                connection: Mutex::new(None),
            });
        }
        raw.upstreams[0].ip = "127.0.0.1".parse().unwrap();
        if extra_silent {
            let mut config = ConnectionConfig::udp();
            config.port = second_silent.local_addr().unwrap().port();
            raw.upstreams.push(Upstream {
                server_index: 1,
                ip: "127.0.0.1".parse().unwrap(),
                config,
                connection: Mutex::new(None),
            });
        }
        let mut config = ConnectionConfig::udp();
        config.port = healthy.local_addr().unwrap().port();
        raw.upstreams.push(Upstream {
            server_index: 2,
            ip: "127.0.0.1".parse().unwrap(),
            config,
            connection: Mutex::new(None),
        });
        let server = tokio::spawn(async move {
            let mut bytes = [0; 2048];
            let (len, peer) = healthy.recv_from(&mut bytes).await.unwrap();
            let reply = Message::from_vec(&bytes[..len]).unwrap().into_response();
            healthy
                .send_to(&reply.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        let answer = raw.exchange(request().to_vec().unwrap()).await.unwrap();
        assert_eq!(Message::from_vec(&answer).unwrap().metadata.id, 17);
        server.await.unwrap();
    }
}

#[tokio::test]
async fn unused_tcp_fallback_does_not_mark_udp_timeout_as_setup_pending() {
    for completed in [false, true] {
        let silent = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let mut address = silent.local_addr().unwrap();
        address.set_ip("127.0.0.1".parse().unwrap());
        let mut raw = exchange(address, false);
        raw.context.options.timeout = Duration::from_millis(30);
        let mut config = ConnectionConfig::tcp();
        config.port = address.port();
        let (finished, done) = tokio::sync::oneshot::channel();
        let setup = connection_setup(
            Box::pin(async move {
                if !completed {
                    futures::future::pending::<()>().await;
                }
                let _ = finished.send(());
                Err(NetError::Timeout)
            }),
            tokio::time::Instant::now() + Duration::from_secs(1),
        );
        if completed {
            done.await.unwrap();
        }
        assert!(setup.peek().is_none());
        raw.upstreams.push(Upstream {
            server_index: 0,
            ip: address.ip(),
            config,
            connection: Mutex::new(Some(setup)),
        });
        let error = raw.exchange(request().to_vec().unwrap()).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(!crate::resolver::dns_setup_pending(&error));
    }
}

#[tokio::test]
async fn slow_connection_setup_survives_refreshing_resolver_timeout() {
    assert_slow_setup_survives(false, false).await;
}

#[tokio::test]
async fn concurrent_query_completing_setup_preserves_canceled_wait_retry() {
    assert_slow_setup_survives(true, false).await;
}

#[tokio::test]
async fn later_bind_failure_preserves_canceled_setup_retry() {
    assert_slow_setup_survives(false, true).await;
}

async fn assert_slow_setup_survives(concurrent: bool, fail_last: bool) {
    use crate::resolver::{
        DnsExchangeFuture, RefreshPolicy, RefreshingResolver, ResolveFuture, Resolver,
        ResolverFactory,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[derive(Debug)]
    struct RawResolver(Arc<RawDnsExchange>);
    impl Resolver for RawResolver {
        fn resolve_location(&self, _: &crate::address::NetLocation) -> ResolveFuture {
            unreachable!()
        }
        fn exchange(&self, request: Vec<u8>) -> DnsExchangeFuture {
            let raw = self.0.clone();
            Box::pin(async move { raw.exchange(request).await })
        }
    }
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let mut address = listener.local_addr().unwrap();
    address.set_ip("127.0.0.1".parse().unwrap());
    let mut raw = exchange(address, true);
    raw.context.options.timeout = Duration::from_millis(300);
    raw.context.options.num_concurrent_reqs = 1;
    let future = raw
        .provider
        .new_connection(address.ip(), &raw.upstreams[0].config, &raw.context)
        .unwrap();
    *raw.upstreams[0].connection.lock().await = Some(connection_setup(
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            future.await
        }),
        tokio::time::Instant::now() + Duration::from_millis(300),
    ));
    let silent = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
    for index in 0..2 {
        let mut config = ConnectionConfig::udp();
        config.port = silent.local_addr().unwrap().port();
        if fail_last && index == 1 {
            config.bind_addr = Some(silent.local_addr().unwrap());
        }
        raw.upstreams.push(Upstream {
            server_index: raw.upstreams.len(),
            ip: address.ip(),
            config,
            connection: Mutex::new(None),
        });
    }
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        for _ in 0..3 + usize::from(concurrent) {
            let answer = read_tcp(&mut stream).await.into_response();
            write_tcp(&mut stream, answer).await;
        }
    });
    let raw = Arc::new(raw);
    let builds = Arc::new(AtomicUsize::new(0));
    let factory: ResolverFactory = {
        let builds = builds.clone();
        Arc::new(move || {
            builds.fetch_add(1, Ordering::SeqCst);
            let resolver: Arc<dyn Resolver> = Arc::new(RawResolver(raw.clone()));
            Box::pin(async { Ok(resolver) })
        })
    };
    let resolver = RefreshingResolver::new(
        factory,
        RefreshPolicy {
            max_idle: Duration::from_secs(60),
            retry_once_after_refresh: true,
        },
        "slow multi-upstream setup".into(),
    )
    .await
    .unwrap();
    let requests = async {
        for _ in 0..3 {
            resolver
                .exchange(request().to_vec().unwrap())
                .await
                .unwrap();
        }
    };
    if concurrent {
        let second = async {
            // Wait until the first query has canceled its TCP setup wait.
            silent.recv_from(&mut [0; 2048]).await.unwrap();
            resolver
                .exchange(request().to_vec().unwrap())
                .await
                .unwrap();
        };
        tokio::join!(requests, second);
    } else {
        requests.await;
    }
    assert_eq!(builds.load(Ordering::SeqCst), 1);
    server.await.unwrap();
}

#[tokio::test]
async fn dropping_connection_cache_cancels_pending_setup() {
    let marker = Arc::new(());
    let owned = marker.clone();
    let setup = connection_setup(
        Box::pin(async move {
            let _owned = owned;
            futures::future::pending().await
        }),
        tokio::time::Instant::now() + Duration::from_secs(30),
    );
    tokio::task::yield_now().await;
    assert_eq!(Arc::strong_count(&marker), 2);
    drop(setup);
    tokio::task::yield_now().await;
    assert_eq!(Arc::strong_count(&marker), 1);
}

#[tokio::test]
async fn stalled_tcp_exchange_has_a_complete_deadline() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut raw = exchange(listener.local_addr().unwrap(), true);
    raw.context.options.timeout = Duration::from_millis(50);
    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        raw.exchange(request().to_vec().unwrap()),
    )
    .await
    .unwrap();
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn udp_preserves_negative_sections_and_flags() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let raw = exchange(socket.local_addr().unwrap(), false);
    let server = tokio::spawn(async move {
        let mut bytes = [0; 2048];
        let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
        let query = Message::from_vec(&bytes[..len]).unwrap();
        assert!(query.metadata.checking_disabled);
        assert!(!query.metadata.recursion_desired);
        let mut response = query.into_response();
        response.metadata.response_code = ResponseCode::NXDomain;
        response.add_authority(Record::from_rdata(
            Name::from_ascii("example.").unwrap(),
            60,
            RData::TXT(rdata::TXT::new(vec!["negative metadata".into()])),
        ));
        socket
            .send_to(&response.to_vec().unwrap(), peer)
            .await
            .unwrap();
    });
    let response =
        Message::from_vec(&raw.exchange(request().to_vec().unwrap()).await.unwrap()).unwrap();
    assert_eq!(response.metadata.id, 17);
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(response.queries[0].name.to_ascii(), "Case.Example.");
    assert_eq!(response.authorities.len(), 1);
    server.await.unwrap();
}

#[tokio::test]
async fn truncated_udp_survives_failed_or_timed_out_tcp_fallback() {
    use crate::dns::hickory_resolver::{HickoryResolver, HickoryResolverOptions};
    use crate::resolver::Resolver;

    for silent in [false, true] {
        for caller_deadline in [false, true] {
            for synthetic in [false, true] {
                let (tcp, udp) = crate::dns::bind_tcp_and_udp().await;
                let addr = udp.local_addr().unwrap();
                let tcp = if silent {
                    Some(tcp)
                } else {
                    drop(tcp);
                    None
                };
                let server = tokio::spawn(async move {
                    let mut bytes = [0; 2048];
                    let (len, peer) = udp.recv_from(&mut bytes).await.unwrap();
                    let mut response = Message::from_vec(&bytes[..len]).unwrap().into_response();
                    response.metadata.truncation = true;
                    response.add_answer(Record::from_rdata(
                        response.queries[0].name.clone(),
                        42,
                        RData::TXT(rdata::TXT::new(vec!["partial".into()])),
                    ));
                    if synthetic {
                        response.add_additional(Record::from_rdata(
                            response.queries[0].name.clone(),
                            42,
                            RData::A(rdata::A("198.18.0.5".parse().unwrap())),
                        ));
                    }
                    udp.send_to(&response.to_vec().unwrap(), peer)
                        .await
                        .unwrap();
                    if let Some(tcp) = tcp {
                        let (mut stream, _) = tcp.accept().await.unwrap();
                        read_tcp(&mut stream).await;
                        std::future::pending::<()>().await;
                    }
                });
                let bootstrap: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
                let mut udp_config = ConnectionConfig::udp();
                udp_config.port = addr.port();
                let mut tcp_config = ConnectionConfig::tcp();
                tcp_config.port = addr.port();
                let resolver = HickoryResolver::build_pooled(
                    vec![(addr.ip(), udp_config), (addr.ip(), tcp_config)],
                    Arc::new(crate::tcp::chain_builder::build_direct_chain_group(
                        bootstrap.clone(),
                    )),
                    bootstrap,
                    HickoryResolverOptions {
                        request_timeout: Some(Duration::from_millis(300)),
                        attempts: 1,
                        ..Default::default()
                    },
                    "partial reply test".into(),
                )
                .unwrap();
                let resolver = super::super::guard::real_only(
                    Arc::new(resolver),
                    vec!["198.18.0.0/15".parse().unwrap()].into(),
                );
                let query = request();
                let start = tokio::time::Instant::now();
                let result = if caller_deadline {
                    resolver.exchange_with_deadline(
                        query.to_vec().unwrap(),
                        start + Duration::from_millis(150),
                    )
                } else {
                    resolver.exchange(query.to_vec().unwrap())
                };
                let result = tokio::time::timeout(Duration::from_secs(2), result)
                    .await
                    .unwrap();
                if synthetic {
                    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
                } else {
                    let response = Message::from_vec(&result.unwrap()).unwrap();
                    assert!(response.metadata.truncation);
                    assert_eq!(response.metadata.id, query.metadata.id);
                    assert_eq!(response.queries, query.queries);
                    assert_eq!(response.answers.len(), 1);
                }
                assert!(
                    start.elapsed()
                        < Duration::from_millis(if caller_deadline { 250 } else { 600 })
                );
                server.abort();
                let _ = server.await;
            }
        }
    }
}

#[tokio::test]
async fn udp_truncation_retries_the_same_configured_server_over_tcp() {
    let (tcp, udp) = crate::dns::bind_tcp_and_udp().await;
    let addr = udp.local_addr().unwrap();
    let mut raw = exchange(addr, false);
    let mut config = ConnectionConfig::tcp();
    config.port = addr.port();
    raw.upstreams.push(Upstream {
        server_index: 0,
        ip: addr.ip(),
        config,
        connection: Mutex::new(None),
    });
    let server = tokio::spawn(async move {
        let mut bytes = [0; 2048];
        let (len, peer) = udp.recv_from(&mut bytes).await.unwrap();
        let mut response = Message::from_vec(&bytes[..len]).unwrap().into_response();
        response.metadata.truncation = true;
        udp.send_to(&response.to_vec().unwrap(), peer)
            .await
            .unwrap();
        let (mut stream, _) = tcp.accept().await.unwrap();
        let len = stream.read_u16().await.unwrap() as usize;
        let mut bytes = vec![0; len];
        stream.read_exact(&mut bytes).await.unwrap();
        let mut response = Message::from_vec(&bytes).unwrap().into_response();
        response.add_answer(Record::from_rdata(
            response.queries[0].name.clone(),
            42,
            RData::TXT(rdata::TXT::new(vec!["complete".into()])),
        ));
        let bytes = response.to_vec().unwrap();
        stream.write_u16(bytes.len() as u16).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
    });
    let response =
        Message::from_vec(&raw.exchange(request().to_vec().unwrap()).await.unwrap()).unwrap();
    assert!(!response.metadata.truncation);
    assert_eq!(response.answers.len(), 1);
    server.await.unwrap();
}
