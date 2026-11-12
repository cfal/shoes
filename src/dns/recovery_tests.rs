use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
};
use std::time::Duration;

use bytes::Bytes;
use hickory_resolver::proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RData, Record, RecordType, rdata::A},
};
use tokio_util::task::AbortOnDropHandle;

use super::hickory_resolver::{HickoryResolver, HickoryResolverOptions};
use crate::address::NetLocation;
use crate::resolver::{NativeResolver, Resolver};

#[derive(Clone, Copy)]
#[repr(u8)]
enum Reply {
    Answer,
    Close,
    Reset,
    GoAway,
    HttpError,
    NxDomain,
    NoData,
    ServFail,
    Slow,
    BadH2,
    Refused,
    GoAwaySlow,
}

struct DohFixture {
    address: SocketAddr,
    roots: rustls::RootCertStore,
    stall: Arc<AtomicBool>,
    connections: Arc<AtomicUsize>,
    live: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
    builds: Arc<AtomicUsize>,
    reply: Arc<AtomicU8>,
    _server: AbortOnDropHandle<()>,
}

impl DohFixture {
    async fn start() -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
                    .into(),
            )
            .unwrap();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
        let stall = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(AtomicUsize::new(0));
        let live = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let reply = Arc::new(AtomicU8::new(Reply::Answer as u8));
        let state = (stall.clone(), connections.clone(), live.clone());
        let responses = (requests.clone(), reply.clone());
        let server = AbortOnDropHandle::new(tokio::spawn(async move {
            let (stall, connections, live) = state;
            let (requests, reply) = responses;
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (tcp, _) = accepted.unwrap();
                        connections.fetch_add(1, Ordering::SeqCst);
                        let live = live.clone();
                        let stall = stall.clone();
                        let acceptor = acceptor.clone();
                        let requests = requests.clone();
                        let reply = reply.clone();
                        tasks.spawn(async move {
                            struct Active(Arc<AtomicUsize>);
                            impl Drop for Active {
                                fn drop(&mut self) { self.0.fetch_sub(1, Ordering::SeqCst); }
                            }
                            live.fetch_add(1, Ordering::SeqCst);
                            let _active = Active(live);
                            let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                            if reply.load(Ordering::SeqCst) == Reply::BadH2 as u8 {
                                use tokio::io::AsyncWriteExt;
                                let _ = tls.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
                                let _ = tls.shutdown().await;
                                return;
                            }
                            let Ok(mut h2) = h2::server::handshake(tls).await else { return };
                            let mut replies = tokio::task::JoinSet::new();
                            let mut poisoned = false;
                            while let Some(Ok((request, mut respond))) = h2.accept().await {
                                requests.fetch_add(1, Ordering::SeqCst);
                                let mode = reply.load(Ordering::SeqCst);
                                if mode == Reply::Close as u8 {
                                    return;
                                }
                                if mode == Reply::Reset as u8 {
                                    respond.send_reset(h2::Reason::CANCEL);
                                    continue;
                                }
                                if mode == Reply::Refused as u8 {
                                    reply.store(Reply::Answer as u8, Ordering::SeqCst);
                                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                                    continue;
                                }
                                if mode == Reply::GoAway as u8 || mode == Reply::GoAwaySlow as u8 {
                                    h2.graceful_shutdown();
                                }
                                poisoned |= stall.load(Ordering::SeqCst);
                                let stalled = poisoned;
                                replies.spawn(async move {
                                    let mut body = request.into_body();
                                    let mut bytes = Vec::new();
                                    while let Some(Ok(data)) = body.data().await {
                                        bytes.extend_from_slice(&data);
                                        body.flow_control().release_capacity(data.len()).unwrap();
                                    }
                                    let mut reply = Message::from_vec(&bytes).unwrap().into_response();
                                    if mode == Reply::NxDomain as u8 {
                                        reply.metadata.response_code = ResponseCode::NXDomain;
                                    } else if mode == Reply::ServFail as u8 {
                                        reply.metadata.response_code = ResponseCode::ServFail;
                                    } else if mode != Reply::NoData as u8 {
                                        reply.add_answer(Record::from_rdata(
                                            reply.queries[0].name.clone(), 0, RData::A(A::new(192, 0, 2, 42)),
                                        ));
                                    }
                                    if mode == Reply::Slow as u8 || mode == Reply::GoAwaySlow as u8 {
                                        tokio::time::sleep(Duration::from_millis(80)).await;
                                    }
                                    let bytes = reply.to_vec().unwrap();
                                    let response = http::Response::builder()
                                        .status(if mode == Reply::HttpError as u8 { 503 } else { 200 })
                                        .header("content-type", "application/dns-message")
                                        .header("content-length", bytes.len()).body(()).unwrap();
                                    let Ok(mut send) = respond.send_response(response, false) else { return };
                                    if stalled {
                                        let _ = futures::future::poll_fn(|cx| send.poll_reset(cx)).await;
                                    } else {
                                        let _ = send.send_data(Bytes::from(bytes), true);
                                    }
                                });
                            }
                        });
                    }
                    _ = tasks.join_next(), if !tasks.is_empty() => {}
                }
            }
        }));
        Self {
            address,
            roots,
            stall,
            connections,
            live,
            requests,
            builds: Arc::new(AtomicUsize::new(0)),
            reply,
            _server: server,
        }
    }

    fn resolver(&self) -> HickoryResolver {
        self.resolver_with_attempts(1)
    }

    fn resolver_with_attempts(&self, attempts: usize) -> HickoryResolver {
        let bootstrap: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let chain = Arc::new(crate::tcp::chain_builder::build_direct_chain_group(
            bootstrap.clone(),
        ));
        self.resolver_with_options(chain, bootstrap, true, attempts)
    }

    fn resolver_via(
        &self,
        chain: Arc<crate::client_proxy_chain::ClientChainGroup>,
        bootstrap: Arc<dyn Resolver>,
        trusted: bool,
    ) -> HickoryResolver {
        self.resolver_with_options(chain, bootstrap, trusted, 1)
    }

    fn resolver_with_options(
        &self,
        chain: Arc<crate::client_proxy_chain::ClientChainGroup>,
        bootstrap: Arc<dyn Resolver>,
        trusted: bool,
        attempts: usize,
    ) -> HickoryResolver {
        let roots = if trusted {
            self.roots.clone()
        } else {
            rustls::RootCertStore::empty()
        };
        doh_resolver(self.address, roots, chain, bootstrap, attempts)
    }

    async fn wait_closed(&self) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while self.live.load(Ordering::SeqCst) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retired DoH socket remained live");
    }

    async fn refreshing(&self) -> crate::resolver::RefreshingResolver {
        let bootstrap: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let chain = Arc::new(crate::tcp::chain_builder::build_direct_chain_group(
            bootstrap.clone(),
        ));
        self.refreshing_via(chain, bootstrap).await
    }

    async fn refreshing_via(
        &self,
        chain: Arc<crate::client_proxy_chain::ClientChainGroup>,
        bootstrap: Arc<dyn Resolver>,
    ) -> crate::resolver::RefreshingResolver {
        let address = self.address;
        let roots = self.roots.clone();
        let builds = self.builds.clone();
        let factory: crate::resolver::ResolverFactory = Arc::new(move || {
            builds.fetch_add(1, Ordering::SeqCst);
            let resolver =
                doh_resolver(address, roots.clone(), chain.clone(), bootstrap.clone(), 1);
            Box::pin(async move { Ok(Arc::new(resolver) as Arc<dyn Resolver>) })
        });
        crate::resolver::RefreshingResolver::new(
            factory,
            crate::resolver::RefreshPolicy {
                max_idle: Duration::from_secs(60),
            },
            "local DoH".into(),
        )
        .await
        .unwrap()
    }
}

fn doh_resolver(
    address: SocketAddr,
    roots: rustls::RootCertStore,
    chain: Arc<crate::client_proxy_chain::ClientChainGroup>,
    bootstrap: Arc<dyn Resolver>,
    attempts: usize,
) -> HickoryResolver {
    crate::rustls_config_util::with_test_roots(roots, || {
        HickoryResolver::https(
            address,
            "localhost".into(),
            "/dns-query".into(),
            chain,
            bootstrap,
            HickoryResolverOptions {
                ip_strategy: super::IpStrategy::Ipv4Only,
                request_timeout: Some(Duration::from_millis(150)),
                connect_timeout: Duration::from_secs(1),
                attempts,
                ..Default::default()
            },
        )
        .unwrap()
    })
}

fn query(sequence: usize) -> Vec<u8> {
    let mut message = Message::query();
    message.add_query(Query::query(
        Name::from_ascii(format!("query{sequence}.example.")).unwrap(),
        RecordType::A,
    ));
    message.to_vec().unwrap()
}

#[tokio::test]
async fn doh_composite_short_deadline_preserves_healthy_transports() {
    let fixture = DohFixture::start().await;
    let first = Arc::new(fixture.resolver());
    let second = Arc::new(fixture.resolver());
    first.exchange(query(0)).await.unwrap();
    second.exchange(query(1)).await.unwrap();
    let composite = Arc::new(super::composite_resolver::CompositeResolver::new(vec![
        first.clone(),
        second.clone(),
    ]));
    let resolver = crate::resolver::RefreshingResolver::new(
        Arc::new(move || {
            let composite = composite.clone();
            Box::pin(async move { Ok(composite as Arc<dyn Resolver>) })
        }),
        crate::resolver::RefreshPolicy {
            max_idle: Duration::from_secs(60),
        },
        "composite DoH".into(),
    )
    .await
    .unwrap();
    fixture.reply.store(Reply::Slow as u8, Ordering::SeqCst);
    for duration in [Duration::from_millis(10), Duration::ZERO] {
        let error = resolver
            .exchange_with_deadline(query(2), tokio::time::Instant::now() + duration)
            .await
            .unwrap_err();
        assert!(crate::resolver::dns_caller_deadline(&error), "{error:?}");
    }
    fixture.reply.store(Reply::Answer as u8, Ordering::SeqCst);
    first.exchange(query(3)).await.unwrap();
    second.exchange(query(4)).await.unwrap();
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn doh_refused_stream_is_retried_but_cancel_remains_stream_local() {
    for lookup in [false, true] {
        let fixture = DohFixture::start().await;
        let resolver = fixture.refreshing().await;
        resolver.exchange(query(0)).await.unwrap();
        fixture.reply.store(Reply::Refused as u8, Ordering::SeqCst);
        if lookup {
            resolver
                .resolve_location(&NetLocation::from_str("refused.example:80", None).unwrap())
                .await
                .unwrap();
        } else {
            resolver.exchange(query(1)).await.unwrap();
        }
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 3);
        fixture.reply.store(Reply::Reset as u8, Ordering::SeqCst);
        let connections = fixture.connections.load(Ordering::SeqCst);
        if lookup {
            assert!(
                resolver
                    .resolve_location(&NetLocation::from_str("cancel.example:80", None).unwrap())
                    .await
                    .is_err()
            );
        } else {
            assert!(resolver.exchange(query(2)).await.is_err());
        }
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 4);
        assert_eq!(fixture.connections.load(Ordering::SeqCst), connections);
        fixture.reply.store(Reply::Answer as u8, Ordering::SeqCst);
        if lookup {
            resolver
                .resolve_location(&NetLocation::from_str("after-cancel.example:80", None).unwrap())
                .await
                .unwrap();
        } else {
            resolver.exchange(query(3)).await.unwrap();
        }
        assert_eq!(fixture.connections.load(Ordering::SeqCst), connections);
    }
}

#[tokio::test]
async fn doh_pooled_lookup_keeps_terminal_response_errors_and_reuses_the_connection() {
    use hickory_resolver::config::{
        ConnectionConfig, NameServerConfig, ResolverConfig, ServerOrderingStrategy,
    };
    for mode in [Reply::Reset, Reply::HttpError] {
        let first = DohFixture::start().await;
        let second = DohFixture::start().await;
        let servers = [first.address, second.address]
            .into_iter()
            .map(|address| {
                let mut connection =
                    ConnectionConfig::https("localhost".into(), Some("/dns-query".into()));
                connection.port = address.port();
                NameServerConfig::new(address.ip(), true, vec![connection])
            })
            .collect();
        let bootstrap: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let provider = super::proxy_runtime::ProxyRuntimeProvider::with_bootstrap(
            Arc::new(crate::tcp::chain_builder::build_direct_chain_group(
                bootstrap.clone(),
            )),
            bootstrap,
            Duration::from_secs(1),
        );
        let mut roots = first.roots.clone();
        roots.roots.extend(second.roots.roots.clone());
        let resolver = crate::rustls_config_util::with_test_roots(roots, || {
            let mut builder = hickory_resolver::Resolver::builder_with_config(
                ResolverConfig::from_parts(None, vec![], servers),
                provider.clone(),
            );
            let options = builder.options_mut();
            options.ip_strategy = super::IpStrategy::Ipv4Only.to_hickory();
            options.num_concurrent_reqs = 1;
            options.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
            options.attempts = 2;
            builder
                .with_tls_config(crate::rustls_config_util::create_dns_client_config())
                .build()
                .unwrap()
        });
        resolver.lookup_ip("warm.example.").await.unwrap();
        first.reply.store(mode as u8, Ordering::SeqCst);
        let error = resolver.lookup_ip("terminal.example.").await.unwrap_err();
        assert!(!error.to_string().contains("no connections available"));
        assert_eq!(first.requests.load(Ordering::SeqCst), 2);
        assert_eq!(second.requests.load(Ordering::SeqCst), 0);
        first.reply.store(Reply::Answer as u8, Ordering::SeqCst);
        resolver.lookup_ip("after-terminal.example.").await.unwrap();
        assert_eq!(first.connections.load(Ordering::SeqCst), 1);
        provider.retire();
        first.wait_closed().await;
    }
}

#[tokio::test]
async fn doh_lookup_retirement_reaches_the_driver_after_goaway() {
    let fixture = DohFixture::start().await;
    let resolver = Arc::new(fixture.resolver());
    resolver
        .resolve_location(&NetLocation::from_str("warm.example:80", None).unwrap())
        .await
        .unwrap();
    fixture.reply.store(Reply::GoAway as u8, Ordering::SeqCst);
    fixture.stall.store(true, Ordering::SeqCst);
    let active = resolver.clone();
    let query = tokio::spawn(async move {
        active
            .resolve_location(&NetLocation::from_str("drain.example:80", None).unwrap())
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while fixture.requests.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    resolver.retire();
    tokio::time::timeout(Duration::from_millis(50), async {
        fixture.wait_closed().await;
        assert!(query.await.unwrap().is_err());
    })
    .await
    .expect("post-GOAWAY lookup driver survived explicit retirement");
}

#[tokio::test]
async fn doh_concurrent_failures_rebuild_only_for_subsequent_queries() {
    let fixture = DohFixture::start().await;
    let resolver = Arc::new(fixture.refreshing().await);
    resolver.exchange(query(0)).await.unwrap();
    fixture.stall.store(true, Ordering::SeqCst);
    let mut queries = tokio::task::JoinSet::new();
    let first = resolver.clone();
    queries.spawn(async move { first.exchange(query(1)).await.map(|_| ()) });
    tokio::time::sleep(Duration::from_millis(50)).await;
    for index in 2..8 {
        let resolver = resolver.clone();
        queries.spawn(async move {
            match index % 3 {
                0 => resolver
                    .resolve_location(
                        &NetLocation::from_str(&format!("concurrent{index}.example:80"), None)
                            .unwrap(),
                    )
                    .await
                    .map(|_| ()),
                1 => resolver.exchange(query(index)).await.map(|_| ()),
                _ => resolver
                    .exchange_with_deadline(
                        query(index),
                        tokio::time::Instant::now() + Duration::from_secs(1),
                    )
                    .await
                    .map(|_| ()),
            }
        });
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(result) = queries.join_next().await {
            assert!(result.unwrap().is_err());
        }
    })
    .await
    .unwrap();
    assert_eq!(fixture.builds.load(Ordering::SeqCst), 1);
    fixture.wait_closed().await;
    fixture.stall.store(false, Ordering::SeqCst);
    let mut queries = tokio::task::JoinSet::new();
    for index in 8..16 {
        let resolver = resolver.clone();
        queries.spawn(async move { resolver.exchange(query(index)).await });
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(result) = queries.join_next().await {
            result.unwrap().unwrap();
        }
    })
    .await
    .unwrap();
    assert_eq!(
        fixture.builds.load(Ordering::SeqCst),
        2,
        "connections: {}",
        fixture.connections.load(Ordering::SeqCst)
    );
}

#[tokio::test]
async fn doh_explicit_retirement_cancels_a_shared_tls_handshake() {
    use tokio::io::AsyncReadExt;
    let mut fixture = DohFixture::start().await;
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    fixture.address = ([127, 0, 0, 1], listener.local_addr().unwrap().port()).into();
    let resolver = Arc::new(fixture.resolver());
    let query_resolver = resolver.clone();
    let query = tokio::spawn(async move { query_resolver.exchange(query(0)).await });
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut buffer = [0; 4096];
    assert_ne!(socket.read(&mut buffer).await.unwrap(), 0);
    resolver.retire();
    tokio::time::timeout(Duration::from_millis(50), async {
        while socket.read(&mut buffer).await.unwrap() != 0 {}
        assert_eq!(
            query.await.unwrap().unwrap_err().kind(),
            std::io::ErrorKind::ConnectionAborted
        );
    })
    .await
    .expect("retired TLS setup retained its socket or waiter");
}

#[tokio::test]
async fn doh_stalled_body_retires_active_socket_and_recovers_without_network_change() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let fixture = DohFixture::start().await;
        let resolver = fixture.resolver();
        resolver.exchange(query(0)).await.unwrap();
        assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
        fixture.stall.store(true, Ordering::SeqCst);
        let error = resolver.exchange(query(1)).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        tokio::time::timeout(Duration::from_millis(500), async {
            while fixture.live.load(Ordering::SeqCst) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("failed DoH connection retained an active socket");
        fixture.stall.store(false, Ordering::SeqCst);
        resolver.exchange(query(2)).await.unwrap();
        assert_eq!(fixture.connections.load(Ordering::SeqCst), 2);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn doh_fresh_setup_receives_a_full_exchange_timeout_and_retires_on_stall() {
    let fixture = DohFixture::start().await;
    let resolver = fixture.resolver();
    fixture.stall.store(true, Ordering::SeqCst);
    let error = resolver.exchange(query(0)).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(!crate::resolver::dns_caller_deadline(&error));
    fixture.wait_closed().await;
    fixture.stall.store(false, Ordering::SeqCst);
    resolver.exchange(query(1)).await.unwrap();
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn doh_zero_attempts_still_retires_cold_and_reused_stalled_connections() {
    for warm in [false, true] {
        let fixture = DohFixture::start().await;
        let resolver = fixture.resolver_with_attempts(0);
        if warm {
            resolver.exchange(query(0)).await.unwrap();
        }
        fixture.stall.store(true, Ordering::SeqCst);
        let error = resolver.exchange(query(1)).await.unwrap_err();
        assert!(
            crate::resolver::RefreshingResolver::should_refresh_for_error(&error),
            "{error:?}"
        );
        fixture.wait_closed().await;
        fixture.stall.store(false, Ordering::SeqCst);
        resolver.exchange(query(2)).await.unwrap();
        assert_eq!(fixture.connections.load(Ordering::SeqCst), 2);
        assert_eq!(resolver.request_timeout(), Some(Duration::from_millis(300)));
    }
}

#[tokio::test]
async fn doh_raw_goaway_eviction_does_not_abort_an_accepted_response() {
    let fixture = DohFixture::start().await;
    let resolver = Arc::new(fixture.resolver());
    resolver.exchange(query(0)).await.unwrap();
    fixture
        .reply
        .store(Reply::GoAwaySlow as u8, Ordering::SeqCst);
    let active = resolver.clone();
    let draining = tokio::spawn(async move { active.exchange(query(1)).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while fixture.requests.load(Ordering::SeqCst) != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // Let the peer's GOAWAY reach the client while its accepted response remains pending.
    tokio::time::sleep(Duration::from_millis(10)).await;
    fixture.reply.store(Reply::Answer as u8, Ordering::SeqCst);
    resolver.exchange(query(2)).await.unwrap();
    draining.await.unwrap().unwrap();
    assert_eq!(
        fixture.requests.load(Ordering::SeqCst),
        3,
        "accepted query was replayed"
    );
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 2);
    resolver.retire();
    fixture.wait_closed().await;
}

#[tokio::test]
async fn doh_lookup_preserves_connection_refused_instead_of_no_connections() {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let address = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
    drop(listener);
    let bootstrap: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let chain = Arc::new(crate::tcp::chain_builder::build_direct_chain_group(
        bootstrap.clone(),
    ));
    let resolver = HickoryResolver::https(
        address,
        "localhost".into(),
        "/dns-query".into(),
        chain,
        bootstrap,
        HickoryResolverOptions {
            attempts: 1,
            ..Default::default()
        },
    )
    .unwrap();
    let error = resolver
        .resolve_location(&NetLocation::from_str("refused.example.:443", None).unwrap())
        .await
        .unwrap_err();
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::ConnectionRefused,
        "{error:?}"
    );
}

#[tokio::test]
async fn doh_lookup_and_deadline_exchange_recover_after_repeated_stalls() {
    tokio::time::timeout(Duration::from_secs(8), async {
        for lookup in [false, true] {
            let fixture = DohFixture::start().await;
            let resolver = fixture.refreshing().await;
            for cycle in 0..3 {
                let perform = |index| {
                    let resolver = &resolver;
                    async move {
                        if lookup {
                            resolver
                                .resolve_location(
                                    &NetLocation::from_str(
                                        &format!("query{index}.example.:443"),
                                        None,
                                    )
                                    .unwrap(),
                                )
                                .await
                                .map(|_| ())
                        } else {
                            resolver
                                .exchange_with_deadline(
                                    query(index),
                                    tokio::time::Instant::now() + Duration::from_secs(1),
                                )
                                .await
                                .map(|_| ())
                        }
                    }
                };
                perform(cycle * 2).await.unwrap();
                let builds = fixture.builds.load(Ordering::SeqCst);
                fixture.stall.store(true, Ordering::SeqCst);
                let error = perform(cycle * 2 + 1).await.unwrap_err();
                assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
                assert_eq!(fixture.builds.load(Ordering::SeqCst), builds);
                if crate::resolver::dns_caller_deadline(&error) {
                    // A caller clip does not retire a healthy transport generation.
                    tokio::time::timeout(Duration::from_secs(1), async {
                        while fixture.live.load(Ordering::SeqCst) > 1 {
                            tokio::task::yield_now().await;
                        }
                    })
                    .await
                    .unwrap();
                } else {
                    assert!(crate::resolver::RefreshingResolver::should_refresh_for_error(&error));
                    fixture.wait_closed().await;
                }
                fixture.stall.store(false, Ordering::SeqCst);
            }
            assert!(
                fixture.connections.load(Ordering::SeqCst) <= 9,
                "unbounded reconnect attempts"
            );
            drop(resolver);
            fixture.wait_closed().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn doh_caller_deadline_and_cancellation_preserve_healthy_shared_connection() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let fixture = DohFixture::start().await;
        let resolver = fixture.refreshing().await;
        resolver.exchange(query(0)).await.unwrap();
        fixture.reply.store(Reply::Slow as u8, Ordering::SeqCst);
        let mut abandoned = resolver.exchange(query(1));
        assert!(futures::poll!(&mut abandoned).is_pending());
        let healthy = resolver.exchange(query(2));
        let short = resolver.exchange_with_deadline(
            query(3),
            tokio::time::Instant::now() + Duration::from_millis(20),
        );
        drop(abandoned);
        let (healthy, short) = tokio::join!(healthy, short);
        healthy.unwrap();
        assert_eq!(short.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        resolver.exchange(query(4)).await.unwrap();
        assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.live.load(Ordering::SeqCst), 1);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn doh_negative_answers_http_failures_and_stream_resets_do_not_evict_transport() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let fixture = DohFixture::start().await;
        let resolver = fixture.refreshing().await;
        resolver.exchange(query(0)).await.unwrap();
        for (index, (mode, code)) in [
            (Reply::NxDomain, Some(ResponseCode::NXDomain)),
            (Reply::NoData, Some(ResponseCode::NoError)),
            (Reply::ServFail, Some(ResponseCode::ServFail)),
            (Reply::HttpError, None),
            (Reply::Reset, None),
        ]
        .into_iter()
        .enumerate()
        {
            fixture.reply.store(mode as u8, Ordering::SeqCst);
            let before = fixture.requests.load(Ordering::SeqCst);
            let result = resolver.exchange(query(index + 1)).await;
            if let Some(code) = code {
                let response = Message::from_vec(&result.unwrap()).unwrap();
                assert_eq!(response.metadata.response_code, code);
                assert!(response.answers.is_empty());
            } else {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), std::io::ErrorKind::Other, "{error:?}");
                assert!(!error.to_string().contains("no connections available"));
            }
            assert_eq!(
                fixture.requests.load(Ordering::SeqCst),
                before + 1,
                "non-transport failure retried"
            );
            assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
        }
        fixture.reply.store(Reply::Answer as u8, Ordering::SeqCst);
        resolver.exchange(query(20)).await.unwrap();
        assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn doh_close_and_goaway_allow_new_connections() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for mode in [Reply::Close, Reply::GoAway] {
            let fixture = DohFixture::start().await;
            let resolver = fixture.resolver();
            resolver.exchange(query(0)).await.unwrap();
            fixture.reply.store(mode as u8, Ordering::SeqCst);
            let result = resolver.exchange(query(1)).await;
            if matches!(mode, Reply::Close) {
                let error = result.unwrap_err();
                assert!(
                    crate::resolver::RefreshingResolver::should_refresh_for_error(&error),
                    "{error:?}"
                );
                assert!(!error.to_string().contains("no connections available"));
            } else {
                result.unwrap();
            }
            fixture.reply.store(Reply::Answer as u8, Ordering::SeqCst);
            resolver.exchange(query(2)).await.unwrap();
            assert!(fixture.connections.load(Ordering::SeqCst) >= 2);
            resolver.retire();
            fixture.wait_closed().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn doh_untrusted_certificate_preserves_cause_without_hidden_retries() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let fixture = DohFixture::start().await;
        let bootstrap: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let chain = Arc::new(crate::tcp::chain_builder::build_direct_chain_group(
            bootstrap.clone(),
        ));
        let resolver = fixture.resolver_via(chain, bootstrap, false);
        for lookup in [false, true] {
            let before = fixture.connections.load(Ordering::SeqCst);
            let error = if lookup {
                resolver
                    .resolve_location(
                        &NetLocation::from_str("untrusted.example.:443", None).unwrap(),
                    )
                    .await
                    .unwrap_err()
            } else {
                resolver.exchange(query(0)).await.unwrap_err()
            };
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData, "{error:?}");
            assert!(error.to_string().contains("DoH TLS handshake"), "{error}");
            assert!(!crate::resolver::RefreshingResolver::should_refresh_for_error(&error));
            assert_eq!(fixture.connections.load(Ordering::SeqCst), before + 1);
            fixture.wait_closed().await;
        }
    })
    .await
    .unwrap();
}

mod proxy;

#[tokio::test]
async fn doh_h2_setup_failure_has_context_and_releases_its_socket() {
    let fixture = DohFixture::start().await;
    fixture.reply.store(Reply::BadH2 as u8, Ordering::SeqCst);
    let resolver = fixture.resolver();
    let error = resolver.exchange(query(0)).await.unwrap_err();
    assert!(error.to_string().contains("DoH"), "{error:?}");
    assert!(!error.to_string().contains("no connections available"));
    fixture.wait_closed().await;
    fixture.reply.store(Reply::Answer as u8, Ordering::SeqCst);
    resolver.exchange(query(1)).await.unwrap();
}

#[tokio::test]
async fn retiring_one_doh_resolver_does_not_stop_another() {
    let fixture = DohFixture::start().await;
    let retired = fixture.resolver();
    let healthy = fixture.resolver();
    retired.exchange(query(0)).await.unwrap();
    healthy.exchange(query(1)).await.unwrap();
    retired.retire();
    tokio::time::timeout(Duration::from_secs(1), async {
        while fixture.live.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    healthy.exchange(query(2)).await.unwrap();
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 2);
    assert_eq!(
        retired.exchange(query(3)).await.unwrap_err().kind(),
        std::io::ErrorKind::ConnectionAborted
    );
    healthy.retire();
    fixture.wait_closed().await;
}
