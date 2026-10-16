use super::*;
use std::time::Duration;
use tokio::io::AsyncReadExt;

#[test]
fn version_defaults_and_alpn_are_explicit() {
    for (json, expected) in [
        (r#"{"type":"http"}"#, HttpVersion::H1),
        (r#"{"type":"http","http_version":"h1"}"#, HttpVersion::H1),
        (r#"{"type":"http","http_version":"h2"}"#, HttpVersion::H2),
    ] {
        let crate::config::ClientProxyConfig::Http { http_version, .. } =
            serde_json::from_str(json).unwrap()
        else {
            panic!()
        };
        assert_eq!(http_version, expected);
    }
    assert!(
        serde_json::from_str::<crate::config::ClientProxyConfig>(
            r#"{"type":"http","http_version":"h3"}"#
        )
        .is_err()
    );
    for version in [HttpVersion::H1, HttpVersion::H2] {
        let handler = HttpTcpClientHandler::new(None, None, version);
        for alpn in [
            None,
            Some(&b"http/1.1"[..]),
            Some(&b"h2"[..]),
            Some(&b"h3"[..]),
        ] {
            assert_eq!(
                handler.validate_alpn(alpn).is_ok(),
                match version {
                    HttpVersion::H1 => true,
                    HttpVersion::H2 => alpn == Some(b"h2"),
                }
            );
        }
    }
}

#[tokio::test]
async fn warm_reuse_miss_never_waits_for_cold_handshake() {
    let handler = HttpTcpClientHandler::new(None, None, HttpVersion::H2);
    let target: ResolvedLocation = NetLocation::from_str("example.com:443", None)
        .unwrap()
        .into();
    let (client, _stalled) = tokio::io::duplex(1);
    let cold = handler.setup_client_tcp_stream(Box::new(client), target.clone());
    tokio::pin!(cold);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut cold)
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(
            Duration::from_secs(1),
            handler.try_reuse_tcp_stream(&target)
        )
        .await
        .unwrap()
        .unwrap()
        .is_none()
    );
}

#[tokio::test]
async fn warm_tunnels_share_a_carrier_and_rejection_does_not_replay_or_truncate() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (client, peer) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(peer).await.unwrap();
            let mut tasks = tokio::task::JoinSet::new();
            let mut count = 0;
            loop {
                tokio::select! {
                    incoming = connection.accept() => {
                        let Some(Ok((request, mut respond))) = incoming else { break };
                        count += 1;
                        assert_eq!(request.headers()["proxy-authorization"], "Basic dXNlcjpwYXNz");
                        if request.uri().authority().unwrap() == "reject.test:443" {
                            respond.send_response(http::Response::builder().status(403).body(()).unwrap(), true).unwrap();
                            continue;
                        }
                        assert_eq!(request.uri().authority().unwrap(), "example.com:443");
                        let send = respond.send_response(http::Response::new(()), false).unwrap();
                        tasks.spawn(async move {
                            let mut stream = crate::http2::stream::H2MultiStream::new(send, request.into_body());
                            let mut data = Vec::new();
                            stream.read_to_end(&mut data).await.unwrap();
                            stream.write_all(&data).await.unwrap();
                            stream.shutdown().await.unwrap();
                        });
                    }
                    _ = tasks.join_next(), if !tasks.is_empty() => {}
                }
            }
            count
        });
        let handler = HttpTcpClientHandler::new(Some(("user".into(), "pass".into())), None, HttpVersion::H2);
        let target: ResolvedLocation = NetLocation::from_str("example.com:443", None).unwrap().into();
        assert!(handler.try_reuse_tcp_stream(&target).await.unwrap().is_none());
        let mut first = handler.setup_client_tcp_stream(Box::new(client), target.clone()).await.unwrap().client_stream;
        let mut second = handler.try_reuse_tcp_stream(&target).await.unwrap().unwrap().client_stream;
        let rejected = NetLocation::from_str("reject.test:443", None).unwrap().into();
        assert!(handler.try_reuse_tcp_stream(&rejected).await.err().unwrap().to_string().contains("403"));
        drop(handler);
        for stream in [&mut first, &mut second] {
            stream.write_all(b"tail").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"tail");
        }
        drop((first, second));
        assert_eq!(server.await.unwrap(), 3);
    }).await.unwrap();
}

#[tokio::test]
async fn hostname_resolution_is_shared_by_cold_and_warm_opens() {
    #[derive(Debug)]
    struct Resolver;
    impl crate::resolver::Resolver for Resolver {
        fn resolve_location(
            &self,
            _: &NetLocation,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = std::io::Result<Vec<std::net::SocketAddr>>> + Send,
            >,
        > {
            Box::pin(async { Ok(vec!["127.0.0.1:8443".parse().unwrap()]) })
        }
    }
    let handler = HttpTcpClientHandler::new(None, Some(Arc::new(Resolver)), HttpVersion::H2);
    let location = NetLocation::from_str("example.com:8443", None).unwrap();
    assert_eq!(
        handler
            .connect_location(location.into())
            .await
            .unwrap()
            .to_string(),
        "127.0.0.1:8443"
    );
}

fn marker_carrier(
    limit: u32,
    marker: u8,
    goaway: bool,
) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<()>) {
    let (client, peer) = tokio::io::duplex(8192);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::Builder::new()
            .max_concurrent_streams(limit)
            .handshake(peer)
            .await
            .unwrap();
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                incoming = connection.accept() => {
                    let Some(Ok((request, mut respond))) = incoming else { break };
                    if request.uri().authority().unwrap() == "reset.test:443" {
                        respond.send_reset(h2::Reason::REFUSED_STREAM);
                        continue;
                    }
                    let status = match request.uri().host().unwrap() {
                        "created.test" => 201,
                        "no-content.test" => 204,
                        "other-success.test" => 299,
                        _ => 200,
                    };
                    let send = respond.send_response(http::Response::builder().status(status).body(()).unwrap(), false).unwrap();
                    tasks.spawn(async move {
                        let mut stream = crate::http2::stream::H2MultiStream::new(send, request.into_body());
                        stream.write_all(&[marker]).await.unwrap();
                        let _ = stream.read_to_end(&mut Vec::new()).await;
                        let _ = stream.shutdown().await;
                    });
                    if goaway { connection.graceful_shutdown(); }
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    });
    (client, server)
}

#[tokio::test]
async fn cold_opens_always_use_the_supplied_route() {
    let handler = HttpTcpClientHandler::new(None, None, HttpVersion::H2);
    let target: ResolvedLocation = NetLocation::from_str("example.com:443", None)
        .unwrap()
        .into();
    let mut streams = Vec::new();
    let mut servers = Vec::new();
    for marker in b"ABAB" {
        let (client, server) = marker_carrier(10, *marker, false);
        let mut stream = handler
            .setup_client_tcp_stream(Box::new(client), target.clone())
            .await
            .unwrap()
            .client_stream;
        assert_eq!(stream.read_u8().await.unwrap(), *marker);
        streams.push(stream);
        servers.push(server);
    }
    for server in servers {
        server.abort();
        let _ = server.await;
    }
}

#[tokio::test]
async fn cold_only_handler_releases_the_carrier_after_its_tunnel() {
    let handler = HttpTcpClientHandler::new(None, None, HttpVersion::H2);
    let target = NetLocation::from_str("example.com:443", None)
        .unwrap()
        .into();
    let (client, server) = marker_carrier(10, b'A', false);
    let mut stream = handler
        .setup_client_tcp_stream(Box::new(client), target)
        .await
        .unwrap()
        .client_stream;
    assert_eq!(stream.read_u8().await.unwrap(), b'A');
    stream.shutdown().await.unwrap();
    assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
    drop(stream);
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .expect("a non-reusable carrier must not retain its prefix tunnel")
        .unwrap();
    drop(handler);
}

#[tokio::test]
async fn every_success_status_establishes_cold_and_warm_connect_tunnels() {
    for host in ["created.test", "no-content.test", "other-success.test"] {
        let (client, server) = marker_carrier(10, b'A', false);
        let handler = HttpTcpClientHandler::new(None, None, HttpVersion::H2);
        let target: ResolvedLocation = NetLocation::from_str(&format!("{host}:443"), None)
            .unwrap()
            .into();
        assert!(
            handler
                .try_reuse_tcp_stream(&target)
                .await
                .unwrap()
                .is_none()
        );
        let mut cold = handler
            .setup_client_tcp_stream(Box::new(client), target.clone())
            .await
            .unwrap()
            .client_stream;
        let mut warm = handler
            .try_reuse_tcp_stream(&target)
            .await
            .unwrap()
            .unwrap()
            .client_stream;
        for stream in [&mut cold, &mut warm] {
            assert_eq!(stream.read_u8().await.unwrap(), b'A');
            stream.shutdown().await.unwrap();
            assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
        }
        server.abort();
        let _ = server.await;
    }
}

#[tokio::test]
async fn refused_stream_does_not_retire_or_replay_the_carrier() {
    let (client, server) = marker_carrier(10, b'A', false);
    let handler = HttpTcpClientHandler::new(None, None, HttpVersion::H2);
    let target: ResolvedLocation = NetLocation::from_str("example.com:443", None)
        .unwrap()
        .into();
    assert!(
        handler
            .try_reuse_tcp_stream(&target)
            .await
            .unwrap()
            .is_none()
    );
    let first = handler
        .setup_client_tcp_stream(Box::new(client), target.clone())
        .await
        .unwrap();
    let generation = handler.session.lock().clone().unwrap();
    let rejected = NetLocation::from_str("reset.test:443", None)
        .unwrap()
        .into();
    assert!(handler.try_reuse_tcp_stream(&rejected).await.is_err());
    assert!(
        handler
            .session
            .lock()
            .as_ref()
            .unwrap()
            .same_generation(&generation)
    );
    let mut second = handler
        .try_reuse_tcp_stream(&target)
        .await
        .unwrap()
        .unwrap()
        .client_stream;
    assert_eq!(second.read_u8().await.unwrap(), b'A');
    drop((first, second));
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn a_carrier_failure_before_submission_is_a_warm_miss() {
    let (client, server) = marker_carrier(10, b'A', false);
    let handler = HttpTcpClientHandler::new(None, None, HttpVersion::H2);
    let target: ResolvedLocation = NetLocation::from_str("example.com:443", None)
        .unwrap()
        .into();
    assert!(
        handler
            .try_reuse_tcp_stream(&target)
            .await
            .unwrap()
            .is_none()
    );
    let first = handler
        .setup_client_tcp_stream(Box::new(client), target.clone())
        .await
        .unwrap();
    let generation = handler.session.lock().clone().unwrap();
    let reservation = generation.try_reserve().unwrap();
    server.abort();
    let _ = server.await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while generation.is_ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        handler
            .open_h2(generation, reservation, target, true)
            .await
            .unwrap()
            .is_none()
    );
    assert!(handler.session.lock().is_none());
    drop(first);
}

#[tokio::test]
async fn full_and_draining_carriers_are_warm_misses_without_breaking_existing_tunnels() {
    for goaway in [false, true] {
        let (client, server) = marker_carrier(if goaway { 10 } else { 1 }, b'A', goaway);
        let handler = HttpTcpClientHandler::new(None, None, HttpVersion::H2);
        let target: ResolvedLocation = NetLocation::from_str("example.com:443", None)
            .unwrap()
            .into();
        assert!(
            handler
                .try_reuse_tcp_stream(&target)
                .await
                .unwrap()
                .is_none()
        );
        let mut first = handler
            .setup_client_tcp_stream(Box::new(client), target.clone())
            .await
            .unwrap()
            .client_stream;
        if goaway {
            tokio::time::timeout(Duration::from_secs(1), async {
                while handler.session.lock().as_ref().unwrap().is_ready() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
        assert!(
            tokio::time::timeout(
                Duration::from_secs(1),
                handler.try_reuse_tcp_stream(&target)
            )
            .await
            .unwrap()
            .unwrap()
            .is_none()
        );
        let (replacement, other_server) = marker_carrier(10, b'B', false);
        let mut second = handler
            .setup_client_tcp_stream(Box::new(replacement), target)
            .await
            .unwrap()
            .client_stream;
        assert_eq!(second.read_u8().await.unwrap(), b'B');
        assert_eq!(first.read_u8().await.unwrap(), b'A');
        first.shutdown().await.unwrap();
        assert_eq!(first.read(&mut [0]).await.unwrap(), 0);
        server.abort();
        other_server.abort();
        let _ = tokio::join!(server, other_server);
    }
}
