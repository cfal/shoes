use super::*;
use crate::http2::client::H2ClientSession;
use crate::resolver::NativeResolver;
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Peer {
    session: H2ClientSession,
    server: tokio::task::JoinHandle<()>,
}

#[tokio::test]
async fn fake_dns_adapter_contract() {
    use crate::tcp::ingress::tests::FakeTcpCase;
    tokio::time::timeout(Duration::from_secs(10), async {
        for case in [
            FakeTcpCase::Dns,
            FakeTcpCase::Tls,
            FakeTcpCase::Plain,
            FakeTcpCase::Unknown,
        ] {
            let mut tasks = JoinSet::new();
            let (selector, resolver, target, payload) = case.fixture(&mut tasks).await;
            let (client, transport) = tokio::io::duplex(8192);
            let _server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(serve(
                Box::new(transport),
                None,
                selector,
                resolver,
            )));
            let mut session = H2ClientSession::new(Box::new(client)).await.unwrap();
            let (response, mut stream) = session.open(connect(&target.to_string())).await.unwrap();
            if case == FakeTcpCase::Unknown {
                assert_eq!(response.status, StatusCode::BAD_GATEWAY);
                let payload = FakeTcpCase::Dns.fixture(&mut tasks).await.3;
                let (response, mut next) = session.open(connect("198.18.0.1:53")).await.unwrap();
                assert_eq!(response.status, StatusCode::OK);
                next.write_all(&payload).await.unwrap();
                next.shutdown().await.unwrap();
                let mut reply = Vec::new();
                next.read_to_end(&mut reply).await.unwrap();
                FakeTcpCase::Dns.assert_reply(&reply);
            } else {
                assert_eq!(response.status, StatusCode::OK);
                stream.write_all(&payload).await.unwrap();
                stream.shutdown().await.unwrap();
                let mut reply = Vec::new();
                stream.read_to_end(&mut reply).await.unwrap();
                case.assert_reply(&reply);
            }
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn reply_gated_sniff_routes_and_replays_after_early_data() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut tasks = JoinSet::new();
        let hello = crate::sniff::tests::hello(&rustls::version::TLS13, true);
        let (selector, resolver) =
            crate::tcp::ingress::tests::socks_target(hello.clone(), &mut tasks).await;
        let (client, transport) = tokio::io::duplex(8192);
        let server = tokio::spawn(serve(Box::new(transport), None, selector, resolver));
        let mut session = H2ClientSession::new(Box::new(client)).await.unwrap();
        let (response, mut stream) = session
            .open(connect(crate::tcp::ingress::tests::TARGET))
            .await
            .unwrap();
        assert_eq!(response.status, StatusCode::OK);
        stream.write_all(&hello).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"greetinglater");
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        server.abort();
        let _ = server.await;
    })
    .await
    .unwrap();
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.server.abort();
    }
}

#[tokio::test]
async fn sniff_failures_reset_after_success_without_a_second_response() {
    for sniff in [false, true] {
        for blocked in [false, true] {
            tokio::time::timeout(Duration::from_secs(5), async {
                let (client, transport) = tokio::io::duplex(8192);
                let server = tokio::spawn(serve(
                    Box::new(transport),
                    None,
                    crate::tcp::ingress::tests::failure_selector(sniff, blocked),
                    Arc::new(NativeResolver::new()),
                ));
                let mut session = H2ClientSession::new(Box::new(client)).await.unwrap();
                let (response, mut stream) = session
                    .open(connect(crate::tcp::ingress::tests::TARGET))
                    .await
                    .unwrap();
                let mut reply = Vec::new();
                if sniff {
                    assert_eq!(response.status, StatusCode::OK);
                    stream
                        .write_all(&crate::sniff::tests::hello(&rustls::version::TLS13, true))
                        .await
                        .unwrap();
                    let error = stream.read_to_end(&mut reply).await.unwrap_err();
                    let reset = error
                        .get_ref()
                        .unwrap()
                        .downcast_ref::<h2::Error>()
                        .unwrap();
                    assert_eq!(reset.reason(), Some(h2::Reason::CANCEL));
                } else {
                    assert_eq!(
                        response.status,
                        if blocked {
                            StatusCode::FORBIDDEN
                        } else {
                            StatusCode::BAD_GATEWAY
                        }
                    );
                    stream.read_to_end(&mut reply).await.unwrap();
                }
                assert!(reply.is_empty());
                server.abort();
                let _ = server.await;
            })
            .await
            .unwrap();
        }
    }
}

async fn peer(auth: bool, mixed: bool, resolver: Arc<dyn Resolver>, blocked: bool) -> Peer {
    let selector = Arc::new(if blocked {
        ClientProxySelector::new(vec![])
    } else {
        create_tcp_client_proxy_selector(
            vec![crate::config::RuleConfig::default()],
            resolver.clone(),
        )
        .unwrap()
    });
    let credentials = auth.then(|| ("user".into(), "pass".into()));
    let handler: Box<dyn TcpServerHandler> = if mixed {
        Box::new(crate::mixed_handler::MixedTcpServerHandler::new(
            credentials,
            false,
            "0.0.0.0".parse().unwrap(),
            selector,
            resolver,
        ))
    } else {
        Box::new(crate::http_handler::HttpTcpServerHandler::new(
            credentials,
            selector,
            resolver,
        ))
    };
    // A tiny transport fragments both the preface and HEADERS.
    let (client, server) = tokio::io::duplex(7);
    let server = tokio::spawn(async move {
        let TcpServerSetupResult::Session(session) =
            handler.setup_server_stream(Box::new(server)).await.unwrap()
        else {
            panic!("H2 preface was dispatched as H1");
        };
        session.await;
    });
    Peer {
        session: H2ClientSession::new(Box::new(client)).await.unwrap(),
        server,
    }
}

fn connect(target: &str) -> Request<()> {
    Request::builder()
        .method(Method::CONNECT)
        .uri(target)
        .body(())
        .unwrap()
}

fn raw_frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(9 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    frame.extend_from_slice(&[kind, flags]);
    frame.extend_from_slice(&stream.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

async fn read_raw_frame(client: &mut tokio::io::DuplexStream) -> (u8, u8, u32, Vec<u8>) {
    let mut header = [0; 9];
    client.read_exact(&mut header).await.unwrap();
    let len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    let mut payload = vec![0; len];
    client.read_exact(&mut payload).await.unwrap();
    (
        header[3],
        header[4],
        u32::from_be_bytes(header[5..9].try_into().unwrap()),
        payload,
    )
}

fn connect_block(target: &str, auth: Option<&[u8]>) -> Vec<u8> {
    let mut headers = b"\x02\x07CONNECT\x01".to_vec();
    headers.push(target.len() as u8);
    headers.extend_from_slice(target.as_bytes());
    if let Some(auth) = auth {
        headers.extend_from_slice(b"\x0f\x22"); // Literal proxy-authorization (static index 49).
        headers.push(auth.len() as u8);
        headers.extend_from_slice(auth);
    }
    headers
}

async fn accepted_tunnel_survives_graceful_shutdown(auth: bool) {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let target = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (mut read, mut write) = stream.split();
        tokio::io::copy(&mut read, &mut write).await.unwrap();
    });
    let (mut client, transport) = tokio::io::duplex(8192);
    let resolver = Arc::new(NativeResolver::new());
    let selector = Arc::new(
        create_tcp_client_proxy_selector(
            vec![crate::config::RuleConfig::default()],
            resolver.clone(),
        )
        .unwrap(),
    );
    let server = tokio::spawn(serve(
        Box::new(transport),
        auth.then(|| "dXNlcjpwYXNz".into()),
        selector,
        resolver,
    ));
    client
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    client.write_all(&raw_frame(4, 0, 0, &[])).await.unwrap();
    loop {
        let (kind, flags, _, _) = read_raw_frame(&mut client).await;
        if kind == 4 && flags & 1 == 0 {
            client.write_all(&raw_frame(4, 1, 0, &[])).await.unwrap();
            break;
        }
    }
    if auth {
        client
            .write_all(&raw_frame(
                1,
                4,
                1,
                &connect_block(&target, Some(b"Basic dXNlcjpwYXNz")),
            ))
            .await
            .unwrap();
    } else {
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::time::resume();
    }
    let mut connected = false;
    let mut final_goaway = false;
    while !connected || !final_goaway {
        let (kind, flags, stream, payload) = read_raw_frame(&mut client).await;
        match kind {
            1 if stream == 1 => {
                assert_eq!(payload[0], 0x88); // Static HPACK :status 200.
                connected = true;
                if auth {
                    client
                        .write_all(&raw_frame(
                            1,
                            4,
                            3,
                            &connect_block(&target, Some(b"Basic wrong")),
                        ))
                        .await
                        .unwrap();
                }
            }
            6 if flags & 1 == 0 => {
                if !auth {
                    // This in-flight CONNECT precedes the shutdown PING ACK.
                    client
                        .write_all(&raw_frame(1, 4, 1, &connect_block(&target, None)))
                        .await
                        .unwrap();
                }
                client
                    .write_all(&raw_frame(6, 1, 0, &payload))
                    .await
                    .unwrap();
            }
            7 => {
                let last = u32::from_be_bytes(payload[..4].try_into().unwrap());
                if last != 0x7fffffff {
                    assert!(last >= 1);
                    final_goaway = true;
                }
            }
            3 if stream == 1 => panic!("accepted tunnel was reset"),
            _ => {}
        }
    }
    tokio::time::pause();
    tokio::time::advance(crate::util::SHUTDOWN_TIMEOUT + Duration::from_secs(1)).await;
    tokio::time::resume();
    client
        .write_all(&raw_frame(0, 0, 1, b"after"))
        .await
        .unwrap();
    loop {
        let (kind, _, stream, payload) = read_raw_frame(&mut client).await;
        if kind == 0 && stream == 1 {
            assert_eq!(payload, b"after");
            break;
        }
    }
    assert!(!server.is_finished());
    client
        .write_all(&raw_frame(0, 1, 1, b"tail"))
        .await
        .unwrap();
    let mut tail = Vec::new();
    loop {
        let (kind, flags, stream, payload) = read_raw_frame(&mut client).await;
        if kind == 0 && stream == 1 {
            tail.extend(payload);
            if flags & 1 != 0 {
                break;
            }
        }
    }
    assert_eq!(tail, b"tail");
    upstream.await.unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn connect_racing_idle_goaway_is_not_cut_off_by_the_shutdown_deadline() {
    tokio::time::timeout(
        Duration::from_secs(70),
        accepted_tunnel_survives_graceful_shutdown(false),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn authenticated_tunnel_survives_another_streams_wrong_credentials() {
    tokio::time::timeout(
        Duration::from_secs(10),
        accepted_tunnel_survives_graceful_shutdown(true),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn final_upload_data_survives_graceful_goaway() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let target = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.shutdown().await.unwrap();
            let mut data = Vec::new();
            stream.read_to_end(&mut data).await.unwrap();
            data
        });
        let (mut client, transport) = tokio::io::duplex(8192);
        let resolver = Arc::new(NativeResolver::new());
        let selector = Arc::new(
            create_tcp_client_proxy_selector(
                vec![crate::config::RuleConfig::default()],
                resolver.clone(),
            )
            .unwrap(),
        );
        let server = tokio::spawn(serve(Box::new(transport), None, selector, resolver));
        // Literal HPACK :method CONNECT and :authority, followed by END_HEADERS.
        let mut headers = b"\x02\x07CONNECT\x01".to_vec();
        headers.push(target.len() as u8);
        headers.extend_from_slice(target.as_bytes());
        client
            .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .unwrap();
        client.write_all(&raw_frame(4, 0, 0, &[])).await.unwrap();
        client
            .write_all(&raw_frame(1, 4, 1, &headers))
            .await
            .unwrap();
        loop {
            let mut header = [0; 9];
            client.read_exact(&mut header).await.unwrap();
            let len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
            let mut payload = vec![0; len];
            client.read_exact(&mut payload).await.unwrap();
            if header[3] == 4 && header[4] & 1 == 0 {
                client.write_all(&raw_frame(4, 1, 0, &[])).await.unwrap();
            }
            if matches!(header[3], 0 | 1) && header[4] & 1 != 0 {
                break;
            }
        }
        let mut end = raw_frame(0, 1, 1, b"tail");
        end.extend(raw_frame(7, 0, 0, &[0; 8]));
        client.write_all(&end).await.unwrap();
        assert_eq!(upstream.await.unwrap(), b"tail");
        server.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn reset_cancels_a_relay_blocked_on_upstream() {
    let (client, transport) = tokio::io::duplex(8192);
    let (tx, rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(transport).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        let send = respond.send_response(Response::new(()), false).unwrap();
        tx.send(H2MultiStream::new(send, request.into_body()))
            .ok()
            .unwrap();
        while connection.accept().await.is_some() {}
    });
    let mut session = H2ClientSession::new(Box::new(client)).await.unwrap();
    let (_, mut client) = session.open(connect("example.com:443")).await.unwrap();
    let (upstream, _stalled) = tokio::io::duplex(1);
    let relay = tokio::spawn(relay(
        rx.await.unwrap(),
        crate::tcp::tcp_handler::TcpClientSetupResult {
            client_stream: Box::new(upstream),
            early_data: None,
        },
        Vec::new(),
    ));
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            client.write_all(&vec![0; 1024 * 1024])
        )
        .await
        .is_err()
    );
    drop(client);
    tokio::time::timeout(Duration::from_secs(1), relay)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(session.is_ready());
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn unread_upload_does_not_exhaust_connection_credit() {
    let resolver = Arc::new(PendingResolver {
        started: Arc::new(tokio::sync::Notify::new()),
        dropped: Arc::new(tokio::sync::Notify::new()),
    });
    let selector = Arc::new(
        create_tcp_client_proxy_selector(
            vec![crate::config::RuleConfig::default()],
            resolver.clone(),
        )
        .unwrap(),
    );
    let (client, transport) = tokio::io::duplex(8192);
    let server = tokio::spawn(serve(Box::new(transport), None, selector, resolver.clone()));
    let (mut sender, connection) = h2::client::handshake(client).await.unwrap();
    let driver = tokio::spawn(connection);
    let (first_response, first_send) = sender
        .send_request(connect("pending.test:443"), false)
        .unwrap();
    resolver.started.notified().await;
    // Consume one full stream window without reading it on the server.
    async fn write(send: &mut h2::SendStream<Bytes>, mut bytes: usize) {
        while bytes > 0 {
            send.reserve_capacity(bytes);
            let count = std::future::poll_fn(|cx| send.poll_capacity(cx))
                .await
                .unwrap()
                .unwrap()
                .min(bytes);
            send.send_data(Bytes::from(vec![0; count]), false).unwrap();
            bytes -= count;
        }
    }
    let mut first_send = first_send;
    tokio::time::timeout(
        Duration::from_secs(1),
        write(&mut first_send, super::super::STREAM_WINDOW as usize),
    )
    .await
    .unwrap();
    sender = sender.ready().await.unwrap();
    let (second_response, mut second_send) = sender
        .send_request(connect("pending.test:443"), false)
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), write(&mut second_send, 1))
        .await
        .unwrap();
    drop((first_response, first_send, second_response, second_send));
    server.abort();
    driver.abort();
    let _ = tokio::join!(server, driver);
}

#[tokio::test]
async fn h1_method_sharing_preface_prefix_remains_h1() {
    let (mut client, server) = tokio::io::duplex(256);
    client
        .write_all(b"PRI http://a.ab:80/ HTTP/1.1\r\n\r\nbody")
        .await
        .unwrap();
    let handler = crate::http_handler::HttpTcpServerHandler::new(
        None,
        Arc::new(ClientProxySelector::new(vec![])),
        Arc::new(NativeResolver::new()),
    );
    let result = handler.setup_server_stream(Box::new(server)).await.unwrap();
    let TcpServerSetupResult::TcpForward {
        initial_remote_data,
        ..
    } = result
    else {
        panic!("H1 method dispatched as H2")
    };
    let data = initial_remote_data.unwrap();
    assert!(data.starts_with(b"PRI / HTTP/1.1\r\n"));
    assert!(data.ends_with(b"body"));
}

#[tokio::test]
async fn missing_auth_can_be_retried_but_every_stream_must_authenticate() {
    let mut peer = peer(true, false, Arc::new(NativeResolver::new()), true).await;
    let (response, _) = peer.session.open(connect("example.com:443")).await.unwrap();
    assert_eq!(response.status, StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    assert!(response.headers.contains_key(header::PROXY_AUTHENTICATE));
    let mut request = connect("example.com:443");
    request.headers_mut().insert(
        header::PROXY_AUTHORIZATION,
        "bAsIc dXNlcjpwYXNz".parse().unwrap(),
    );
    let (response, _) = peer.session.open(request).await.unwrap();
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    let (response, _) = peer.session.open(connect("example.com:443")).await.unwrap();
    assert_eq!(response.status, StatusCode::PROXY_AUTHENTICATION_REQUIRED);
}

#[tokio::test]
async fn wrong_or_duplicate_credentials_close_the_carrier() {
    for headers in [
        vec!["Basic wrong"],
        vec!["Basic dXNlcjpwYXNz", "Basic dXNlcjpwYXNz"],
    ] {
        let mut peer = peer(true, false, Arc::new(NativeResolver::new()), true).await;
        let mut request = connect("example.com:443");
        for value in headers {
            request
                .headers_mut()
                .append(header::PROXY_AUTHORIZATION, value.parse().unwrap());
        }
        let (response, stream) = peer.session.open(request).await.unwrap();
        assert_eq!(response.status, StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        drop(stream);
        let mut request = connect("example.com:443");
        request.headers_mut().insert(
            header::PROXY_AUTHORIZATION,
            "Basic dXNlcjpwYXNz".parse().unwrap(),
        );
        if let Ok((response, stream)) = peer.session.open(request).await {
            assert_eq!(response.status, StatusCode::PROXY_AUTHENTICATION_REQUIRED);
            drop(stream);
        }
        tokio::time::timeout(Duration::from_secs(1), &mut peer.server)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn idle_timeout_ignores_pings_and_rejected_requests() {
    let mut peer = peer(true, false, Arc::new(NativeResolver::new()), true).await;
    // Complete SETTINGS and establish the idle clock.
    drop(peer.session.open(connect("example.com:443")).await.unwrap());
    let start = tokio::time::Instant::now();
    tokio::time::sleep(Duration::from_secs(59)).await;
    drop(peer.session.open(connect("example.com:443")).await.unwrap());
    // The shared client sends PINGs at 30 s, which must not keep this carrier alive.
    tokio::time::timeout(Duration::from_secs(7), &mut peer.server)
        .await
        .unwrap()
        .unwrap();
    assert!(start.elapsed() >= Duration::from_secs(60));
    assert!(start.elapsed() <= Duration::from_secs(65));
}

#[test]
fn connect_authority_and_method_validation() {
    for target in [
        "example.com",
        "example.com:0",
        "example.com:+443",
        "user@example.com:443",
        "[localhost]:443",
    ] {
        assert_eq!(
            validate(&connect(target), None),
            Err(StatusCode::BAD_REQUEST),
            "{target}"
        );
    }
    for target in ["localhost:443", "127.0.0.1:443", "[::1]:443"] {
        assert!(validate(&connect(target), None).is_ok(), "{target}");
    }
    let get = Request::builder()
        .uri("https://example.com/")
        .body(())
        .unwrap();
    assert_eq!(validate(&get, None), Err(StatusCode::METHOD_NOT_ALLOWED));
    let mut extended = connect("example.com:443");
    extended
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static("websocket"));
    assert_eq!(validate(&extended, None), Err(StatusCode::BAD_REQUEST));
}

#[tokio::test]
async fn admission_permits_are_released_on_reset_and_owner_drop() {
    const CHILD: &str = "SHOES_HTTP2_ADMISSION_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "http2::server::tests::admission_permits_are_released_on_reset_and_owner_drop",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    resources::configure(crate::config::GlobalLimits {
        max_streams: Some(1),
        max_streams_per_connection: Some(2),
        ..Default::default()
    })
    .unwrap();
    let resolver = Arc::new(PendingResolver {
        started: Arc::new(tokio::sync::Notify::new()),
        dropped: Arc::new(tokio::sync::Notify::new()),
    });
    let mut peer = peer(false, false, resolver.clone(), false).await;
    let mut other = peer.session.clone();
    {
        let first = peer.session.open(connect("pending.test:443"));
        tokio::pin!(first);
        tokio::select! {
            _ = resolver.started.notified() => {},
            _ = &mut first => panic!("unexpected completion"),
        }
        assert_eq!(resources::snapshot().streams.active, 1);
        assert!(other.open(connect("pending.test:443")).await.is_err());
        assert_eq!(resources::snapshot().streams.active, 1);
    }
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while resources::snapshot().streams.active != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    {
        let next = other.open(connect("pending.test:443"));
        tokio::pin!(next);
        tokio::select! {
            _ = resolver.started.notified() => {},
            _ = &mut next => panic!("permit was not returned"),
        }
        peer.server.abort();
    }
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while resources::snapshot().streams.active != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn non_connect_and_failed_dial_do_not_receive_success() {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let target = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    drop(listener);
    let mut peer = peer(false, true, Arc::new(NativeResolver::new()), false).await;
    let request = Request::builder()
        .uri("https://example.com/")
        .body(())
        .unwrap();
    let (response, _) = peer.session.open(request).await.unwrap();
    assert_eq!(response.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers[header::ALLOW], "CONNECT");
    let (response, _) = peer.session.open(connect(&target)).await.unwrap();
    assert_eq!(response.status, StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn concurrent_tunnels_preserve_banners_half_close_and_reset_isolation() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let target = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let server = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().await.unwrap();
                tasks.spawn(async move {
                    stream.write_all(b"banner").await.unwrap();
                    let mut data = Vec::new();
                    if stream.read_to_end(&mut data).await.is_ok() {
                        let _ = stream.write_all(&data).await;
                        let _ = stream.shutdown().await;
                    }
                });
            }
            while tasks.join_next().await.is_some() {}
        });
        let mut peer = peer(false, true, Arc::new(NativeResolver::new()), false).await;
        let (_, abandoned) = peer.session.open(connect(&target)).await.unwrap();
        drop(abandoned);
        let mut session = peer.session.clone();
        let (a, b) = tokio::join!(
            peer.session.open(connect(&target)),
            session.open(connect(&target))
        );
        let (a, mut first) = a.unwrap();
        let (b, mut second) = b.unwrap();
        assert_eq!(a.status, StatusCode::OK);
        assert_eq!(b.status, StatusCode::OK);
        async fn exchange(stream: &mut H2MultiStream, data: &[u8]) {
            let mut banner = [0; 6];
            stream.read_exact(&mut banner).await.unwrap();
            assert_eq!(&banner, b"banner");
            stream.write_all(data).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut echoed = Vec::new();
            stream.read_to_end(&mut echoed).await.unwrap();
            assert_eq!(echoed, data);
        }
        tokio::join!(
            exchange(&mut first, b"first"),
            exchange(&mut second, b"second")
        );
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[derive(Debug)]
struct PendingResolver {
    started: Arc<tokio::sync::Notify>,
    dropped: Arc<tokio::sync::Notify>,
}

impl Resolver for PendingResolver {
    fn resolve_location(
        &self,
        _: &NetLocation,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = io::Result<Vec<std::net::SocketAddr>>> + Send>,
    > {
        struct Guard(Arc<tokio::sync::Notify>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.notify_one();
            }
        }
        let guard = Guard(self.dropped.clone());
        self.started.notify_one();
        Box::pin(async move {
            let _guard = guard;
            std::future::pending().await
        })
    }
}

#[tokio::test(start_paused = true)]
async fn stalled_setup_times_out_without_premature_success() {
    let resolver = Arc::new(PendingResolver {
        started: Arc::new(tokio::sync::Notify::new()),
        dropped: Arc::new(tokio::sync::Notify::new()),
    });
    let mut peer = peer(false, false, resolver.clone(), false).await;
    let start = tokio::time::Instant::now();
    let (response, _) = peer
        .session
        .open(connect("pending.test:443"))
        .await
        .unwrap();
    assert_eq!(response.status, StatusCode::GATEWAY_TIMEOUT);
    assert!(start.elapsed() >= std::time::Duration::from_secs(60));
    resolver.dropped.notified().await;
}

#[tokio::test]
async fn reset_and_connection_teardown_cancel_pending_setup() {
    for close_connection in [false, true] {
        let resolver = Arc::new(PendingResolver {
            started: Arc::new(tokio::sync::Notify::new()),
            dropped: Arc::new(tokio::sync::Notify::new()),
        });
        let mut peer = peer(false, false, resolver.clone(), false).await;
        {
            let opening = peer.session.open(connect("pending.test:443"));
            tokio::pin!(opening);
            tokio::select! {
                _ = resolver.started.notified() => {},
                _ = &mut opening => panic!("CONNECT completed before upstream setup"),
            }
            if close_connection {
                peer.server.abort();
            }
        }
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            resolver.dropped.notified(),
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn reset_cancels_both_sniff_probe_and_post_sniff_dial() {
    for during_dial in [false, true] {
        tokio::time::timeout(Duration::from_secs(3), async {
            let resolver = Arc::new(PendingResolver {
                started: Arc::new(tokio::sync::Notify::new()),
                dropped: Arc::new(tokio::sync::Notify::new()),
            });
            let rule = serde_yaml::from_str(
                "masks: sniff.example\naction: allow\noverride_address: pending.test:443",
            )
            .unwrap();
            let selector = Arc::new(
                create_tcp_client_proxy_selector(vec![rule], resolver.clone())
                    .unwrap()
                    .with_sniff(true),
            );
            let (client, transport) = tokio::io::duplex(8192);
            let (done, finished) = tokio::sync::oneshot::channel();
            let resolver_clone = resolver.clone();
            let mut drivers = JoinSet::new();
            drivers.spawn(async move {
                let mut connection = h2::server::handshake(transport).await.unwrap();
                let (request, respond) = connection.accept().await.unwrap().unwrap();
                let mut tunnels = JoinSet::new();
                tunnels.spawn(async move {
                    tunnel(
                        request,
                        respond,
                        NetLocation::from_str(crate::tcp::ingress::tests::TARGET, None).unwrap(),
                        selector,
                        resolver_clone,
                    )
                    .await
                    .unwrap();
                    done.send(()).unwrap();
                });
                while connection.accept().await.is_some() {}
            });
            let mut session = H2ClientSession::new(Box::new(client)).await.unwrap();
            let (response, mut stream) = session
                .open(connect(crate::tcp::ingress::tests::TARGET))
                .await
                .unwrap();
            assert_eq!(response.status, StatusCode::OK);
            if during_dial {
                stream
                    .write_all(&crate::sniff::tests::hello(&rustls::version::TLS13, true))
                    .await
                    .unwrap();
                resolver.started.notified().await;
            }
            drop(stream);
            tokio::time::timeout(Duration::from_millis(100), finished)
                .await
                .unwrap()
                .unwrap();
            if during_dial {
                resolver.dropped.notified().await;
            }
            assert!(session.is_ready());
            drivers.shutdown().await;
        })
        .await
        .unwrap();
    }
}
