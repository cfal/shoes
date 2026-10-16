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

impl Drop for Peer {
    fn drop(&mut self) {
        self.server.abort();
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
async fn authentication_is_checked_on_every_stream_and_errors_are_isolated() {
    let mut peer = peer(true, false, Arc::new(NativeResolver::new()), true).await;
    for headers in [
        vec![],
        vec!["Basic wrong"],
        vec!["Basic dXNlcjpwYXNz", "Basic dXNlcjpwYXNz"],
    ] {
        let mut request = connect("example.com:443");
        for value in headers {
            request
                .headers_mut()
                .append(header::PROXY_AUTHORIZATION, value.parse().unwrap());
        }
        let (response, _) = peer.session.open(request).await.unwrap();
        assert_eq!(response.status, StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        assert!(response.headers.contains_key(header::PROXY_AUTHENTICATE));
    }
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
