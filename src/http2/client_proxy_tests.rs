use super::*;
use std::time::Duration;
use tokio::io::AsyncReadExt;

#[test]
fn version_defaults_and_alpn_are_explicit() {
    for (json, expected) in [
        (r#"{"type":"http"}"#, HttpVersion::H1),
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
                    HttpVersion::H1 => alpn.is_none() || alpn == Some(b"http/1.1"),
                    HttpVersion::H2 => alpn == Some(b"h2"),
                }
            );
        }
    }
}

#[tokio::test]
async fn warm_reuse_miss_never_waits_for_cold_handshake() {
    let handler = HttpTcpClientHandler::new(None, None, HttpVersion::H2);
    let _locked = handler.session.lock().await;
    let target = NetLocation::from_str("example.com:443", None)
        .unwrap()
        .into();
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
