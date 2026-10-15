use std::{
    collections::{BTreeMap, HashMap},
    io,
    net::IpAddr,
    sync::{Arc, Weak},
    time::Duration,
};

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Notify,
};
use tokio_util::sync::CancellationToken;

use super::{
    carrier,
    stream::{Activity, Body, Event, Memory, Reader, Stream, Tasks, Writer, pipe},
    wire::{self, Kind, Path},
};
use crate::{
    async_stream::AsyncStream,
    client_proxy_selector::ClientProxySelector,
    config::xhttp::{XhttpServerConfig, XhttpVersion},
    resolver::Resolver,
    resources::{Budget, BudgetPermit},
    tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
};

#[derive(Clone, Debug)]
pub struct XhttpServer {
    state: Arc<State>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[derive(Debug)]
    struct Echo;
    #[async_trait]
    impl TcpServerHandler for Echo {
        async fn setup_server_stream(
            &self,
            mut stream: Box<dyn AsyncStream>,
        ) -> io::Result<TcpServerSetupResult> {
            Ok(TcpServerSetupResult::Session(Box::pin(async move {
                let mut buffer = [0; 1024];
                while let Ok(size) = stream.read(&mut buffer).await {
                    if size == 0 {
                        let _ = stream.shutdown().await;
                        break;
                    }
                    if stream.write_all(&buffer[..size]).await.is_err() {
                        break;
                    }
                }
            })))
        }
    }

    fn service() -> Arc<State> {
        let config: XhttpServerConfig = serde_json::from_value(json!({"path":"/t", "sc_max_buffered_posts":2, "sc_max_each_post_bytes":16, "limits":{"max_sessions":2,"max_pending_sessions":2},"protocol":{"type":"socks"}})).unwrap();
        Arc::new(State {
            path: Path::new(&config.path).unwrap(),
            inner: Arc::new(Echo),
            resolver: Arc::new(crate::resolver::NativeResolver::new()),
            memory: Arc::new(Budget::new(Some(1024))),
            admission: Arc::new(Budget::new(Some(2))),
            sessions: parking_lot::Mutex::new(HashMap::new()),
            tasks: Tasks::new(),
            config,
        })
    }

    #[derive(Debug)]
    struct CloseDownload {
        keep_upload: bool,
    }
    #[async_trait]
    impl TcpServerHandler for CloseDownload {
        async fn setup_server_stream(
            &self,
            mut stream: Box<dyn AsyncStream>,
        ) -> io::Result<TcpServerSetupResult> {
            let keep_upload = self.keep_upload;
            Ok(TcpServerSetupResult::Session(Box::pin(async move {
                if keep_upload {
                    stream.write_all(b"bye").await.unwrap();
                }
                stream.shutdown().await.unwrap();
                if keep_upload {
                    let _ = stream.read_to_end(&mut Vec::new()).await;
                }
            })))
        }
    }

    #[tokio::test]
    async fn packet_download_eof_releases_the_session() {
        let mut state = service();
        Arc::get_mut(&mut state).unwrap().inner = Arc::new(CloseDownload { keep_upload: true });
        for id in ["a", "b", "c"] {
            assert_eq!(
                request(&state, "POST", &format!("{id}/0"), b"hello")
                    .await
                    .status(),
                StatusCode::OK
            );
            let response = request(&state, "GET", id, b"").await;
            let data = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(data, b"bye".as_slice());
            drop(data);
            tokio::task::yield_now().await;
            assert_eq!(state.admission.snapshot().active, 0);
            assert_eq!(state.memory.snapshot().active, 0);
        }
    }

    async fn streaming_carrier(
        state: Arc<State>,
        version: XhttpVersion,
    ) -> (Arc<carrier::Carrier>, Tasks, Option<quinn::Endpoint>) {
        let tasks = Tasks::new();
        if version == XhttpVersion::H2 {
            let (client, server) = tokio::io::duplex(8192);
            tasks.spawn(async move {
                let _ = state
                    .serve_h2(
                        Box::new(server),
                        tokio::time::Instant::now() + Duration::from_secs(4),
                    )
                    .await;
            });
            let carrier = carrier::Carrier::tcp(Box::new(client), version, 8192)
                .await
                .unwrap();
            return (carrier, tasks, None);
        }
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let mut config = quinn::ServerConfig::with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
        Arc::get_mut(&mut config.transport)
            .unwrap()
            .max_concurrent_bidi_streams(1u32.into());
        let server = quinn::Endpoint::server(config, "0.0.0.0:0".parse().unwrap()).unwrap();
        let mut client = crate::quic_endpoint::QuicEndpoint::new(
            None,
            std::net::UdpSocket::bind("0.0.0.0:0").unwrap(),
            0,
        )
        .unwrap();
        client.set_default_client_config(
            quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap(),
        );
        let client = Arc::new(client);
        let address = ([127, 0, 0, 1], server.local_addr().unwrap().port()).into();
        let (outgoing, incoming) =
            tokio::join!(client.connect(address, "localhost").unwrap(), async {
                server.accept().await.unwrap().await.unwrap()
            });
        tasks.spawn(async move {
            let _ = XhttpServer { state }.serve_h3(incoming).await;
        });
        let carrier = carrier::Carrier::quic(
            crate::tcp::carrier_dialer::QuicCarrier {
                connection: outgoing.unwrap(),
                _endpoint: client,
            },
            8192,
        )
        .await
        .unwrap();
        (carrier, tasks, Some(server))
    }

    #[tokio::test]
    async fn h3_idle_probes_preserve_stream_one_in_both_directions() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let (carrier, _server, _endpoint) =
                streaming_carrier(service(), XhttpVersion::H3).await;
            let memory = Memory::new(Arc::new(Budget::new(Some(1024))), 1024);
            let (mut writer, reader) = pipe(memory.clone());
            let tasks = Tasks::new();
            let request = Request::post("https://localhost/t/")
                .header("referer", format!("/?x_padding={}", "X".repeat(100)))
                .body(Body::stream(reader))
                .unwrap();
            let mut response = carrier
                .request(request, memory, &tasks, Duration::from_secs(1))
                .await
                .unwrap()
                .into_body();
            writer.write_all(b"head").await.unwrap();
            let mut echoed = [0; 4];
            response.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"head");
            tokio::time::sleep(Duration::from_secs(11)).await;
            writer.write_all(b"tail").await.unwrap();
            response.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"tail");
            writer.shutdown().await.unwrap();
            assert_eq!(response.read(&mut echoed).await.unwrap(), 0);
            assert!(!carrier.closed());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn ended_streaming_sessions_release_idle_request_bodies() {
        for version in [XhttpVersion::H2, XhttpVersion::H3] {
            for suffix in ["", "idle"] {
                let mut state = service();
                let inner = Arc::get_mut(&mut state).unwrap();
                inner.inner = Arc::new(CloseDownload { keep_upload: false });
                inner.config.limits.max_requests_per_connection = 1;
                inner.config.sc_stream_up_server_secs =
                    crate::config::xhttp::XhttpRange::Number(-1);
                let (carrier, _server, _endpoint) = streaming_carrier(state.clone(), version).await;
                let memory = Memory::new(Arc::new(Budget::new(Some(1024))), 1024);
                let (_writer, reader) = pipe(memory.clone());
                let upload = Tasks::new();
                let request = Request::post(format!("https://localhost/t/{suffix}"))
                    .header("referer", format!("/?x_padding={}", "X".repeat(100)))
                    .body(Body::stream(reader))
                    .unwrap();
                let mut response = carrier
                    .request(request, memory.clone(), &upload, Duration::from_secs(1))
                    .await
                    .unwrap()
                    .into_body();
                if !suffix.is_empty() {
                    state.close(suffix);
                }
                let mut data = Vec::new();
                let _ =
                    tokio::time::timeout(Duration::from_secs(1), response.read_to_end(&mut data))
                        .await
                        .unwrap();
                assert!(data.is_empty());
                // H3's idle sender observes STOP_SENDING on its ten-second probe.
                tokio::time::timeout(Duration::from_secs(12), upload.cancel.cancelled())
                    .await
                    .unwrap();
                let next = Tasks::new();
                let response = tokio::time::timeout(
                    Duration::from_secs(2),
                    carrier.request(
                        Request::builder()
                            .method("OPTIONS")
                            .uri("https://localhost/t/")
                            .body(Body::Empty)
                            .unwrap(),
                        memory,
                        &next,
                        Duration::from_secs(1),
                    ),
                )
                .await
                .unwrap()
                .unwrap_or_else(|error| panic!("{version:?} {suffix}: {error}"));
                assert_eq!(response.status(), StatusCode::OK, "{version:?} {suffix}");
            }
        }
    }

    async fn request(
        state: &Arc<State>,
        method: &str,
        suffix: &str,
        data: &[u8],
    ) -> Response<Body> {
        let request = Request::builder()
            .method(method)
            .uri(format!("http://localhost/t/{suffix}"))
            .header(
                "referer",
                format!("https://localhost/t/?x_padding={}", "X".repeat(100)),
            )
            .header("content-length", data.len())
            .body(())
            .unwrap();
        let (mut writer, body) = pipe(Memory::new(state.memory.clone(), 1024));
        writer.write_all(data).await.unwrap();
        writer.shutdown().await.unwrap();
        state.handle(request, body).await
    }

    fn inactivity_service(budget: usize) -> Arc<State> {
        let mut state = service();
        let config = &mut Arc::get_mut(&mut state).unwrap().config;
        config.limits.packet_timeout_secs = 10;
        config.limits.max_session_buffered_bytes = budget;
        config.sc_max_buffered_posts = 8;
        state
    }

    fn attached_reader(state: &Arc<State>, id: &str) -> Reader {
        let session = state.session(id).unwrap();
        let mut session = session.state.lock();
        session.downloaded = true;
        session.reader.take().unwrap()
    }

    fn open_post(
        state: &Arc<State>,
        suffix: &str,
    ) -> (Writer, tokio::task::JoinHandle<StatusCode>) {
        let post = Request::post(format!("http://localhost/t/{suffix}"))
            .header("referer", format!("/?x_padding={}", "X".repeat(100)))
            .body(())
            .unwrap();
        let (writer, body) = pipe(Memory::new(state.memory.clone(), 1024));
        let state = state.clone();
        (
            writer,
            tokio::spawn(async move { state.handle(post, body).await.status() }),
        )
    }

    #[tokio::test(start_paused = true)]
    async fn packet_body_timeout_measures_its_own_nonempty_bytes() {
        for finish in [false, true] {
            let state = inactivity_service(64);
            let mut reader = attached_reader(&state, "a");
            let session = state.session("a").unwrap();
            let (mut writer, post) = open_post(&state, "a/0");
            for _ in 0..5 {
                writer.write_all(b"a").await.unwrap();
                writer.flush().await.unwrap();
                tokio::time::advance(Duration::from_secs(9)).await;
                assert!(!post.is_finished());
            }
            if finish {
                writer.shutdown().await.unwrap();
                let mut data = [0; 5];
                reader.read_exact(&mut data).await.unwrap();
                assert_eq!(&data, b"aaaaa");
                assert_eq!(post.await.unwrap(), StatusCode::OK);
            } else {
                // Neither session activity nor barriers rescue an individually stalled body.
                session.activity.touch();
                writer.flush().await.unwrap();
                tokio::time::advance(Duration::from_millis(999)).await;
                assert!(!post.is_finished());
                tokio::time::advance(Duration::from_millis(1)).await;
                assert_eq!(post.await.unwrap(), StatusCode::REQUEST_TIMEOUT);
                assert!(session.cancel.is_cancelled());
                assert_eq!(state.admission.snapshot().active, 0);
                assert!(session.state.lock().reserved.is_empty());
                assert!(session.memory.reserve_packet(64, 0).is_some());
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn packet_admission_survives_a_trickling_predecessor() {
        let state = inactivity_service(16);
        let mut reader = attached_reader(&state, "a");
        let (mut first, first_post) = open_post(&state, "a/0");
        first.flush().await.unwrap();
        let (mut second, second_post) = open_post(&state, "a/1");
        second.write_all(b"b").await.unwrap();
        second.shutdown().await.unwrap();
        for _ in 0..5 {
            first.write_all(b"a").await.unwrap();
            first.flush().await.unwrap();
            tokio::time::advance(Duration::from_secs(9)).await;
            assert!(!second_post.is_finished());
        }
        first.shutdown().await.unwrap();
        let mut data = [0; 6];
        reader.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"aaaaab");
        assert_eq!(first_post.await.unwrap(), StatusCode::OK);
        assert_eq!(second_post.await.unwrap(), StatusCode::OK);
    }

    #[tokio::test(start_paused = true)]
    async fn forwarding_wait_tracks_consumption_not_packet_handoffs() {
        let state = inactivity_service(64);
        let mut reader = attached_reader(&state, "a");
        for sequence in 0..4 {
            assert_eq!(
                request(&state, "POST", &format!("a/{sequence}"), b"12345678")
                    .await
                    .status(),
                StatusCode::OK
            );
        }
        let (mut fifth, fifth_post) = open_post(&state, "a/4");
        fifth.write_all(b"fifth").await.unwrap();
        fifth.shutdown().await.unwrap();
        let (mut sixth, sixth_post) = open_post(&state, "a/5");
        sixth.write_all(b"sixth").await.unwrap();
        sixth.shutdown().await.unwrap();
        tokio::task::yield_now().await;
        for _ in 0..8 {
            tokio::time::advance(Duration::from_secs(9)).await;
            reader.read_u8().await.unwrap();
            tokio::task::yield_now().await;
            assert!(!sixth_post.is_finished());
        }
        assert_eq!(fifth_post.await.unwrap(), StatusCode::OK);
        tokio::time::advance(Duration::from_millis(9999)).await;
        assert!(!sixth_post.is_finished());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(sixth_post.await.unwrap(), StatusCode::REQUEST_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn duplicate_receivers_and_unrelated_activity_do_not_extend_admission() {
        let state = inactivity_service(64);
        let _reader = attached_reader(&state, "a");
        let mut other = attached_reader(&state, "b");
        let session = state.session("a").unwrap();
        let (mut original, original_post) = open_post(&state, "a/0");
        original.flush().await.unwrap();
        let (mut duplicate, duplicate_post) = open_post(&state, "a/0");
        duplicate.flush().await.unwrap();
        // Cancelling the original does not promote an already-running duplicate.
        original_post.abort();
        assert!(original_post.await.is_err());
        let held = session.memory.reserve_packet(48, 0).unwrap();
        let (mut later, later_post) = open_post(&state, "a/1");
        later.write_all(b"later").await.unwrap();
        later.shutdown().await.unwrap();
        tokio::task::yield_now().await;
        for sequence in 0..3 {
            tokio::time::advance(Duration::from_secs(3)).await;
            duplicate.write_all(b"d").await.unwrap();
            duplicate.flush().await.unwrap();
            session.progress.notify_waiters();
            assert_eq!(
                request(&state, "POST", &format!("b/{sequence}"), b"b")
                    .await
                    .status(),
                StatusCode::OK
            );
            other.read_u8().await.unwrap();
            assert!(!later_post.is_finished());
        }
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(later_post.await.unwrap(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(
            duplicate_post.await.unwrap(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        drop(held);
        assert!(session.memory.reserve_packet(64, 0).is_some());
    }

    #[tokio::test]
    async fn unmatched_requests_do_not_disclose_xhttp_headers() {
        let mut state = service();
        Arc::get_mut(&mut state).unwrap().config.host = Some("front.test".into());
        for uri in ["http://front.test/wrong", "http://wrong.test/t/session"] {
            let request = Request::builder()
                .method("OPTIONS")
                .uri(uri)
                .header("origin", "https://probe.test")
                .body(())
                .unwrap();
            let (_, body) = pipe(Memory::new(state.memory.clone(), 1024));
            let response = state.handle(request, body).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert!(response.headers().is_empty());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn h1_slow_packet_body_outlives_its_inactivity_interval() {
        let state = inactivity_service(64);
        let mut reader = attached_reader(&state, "a");
        let (mut client, server) = tokio::io::duplex(8192);
        let tasks = Tasks::new();
        tasks.spawn(async move {
            state
                .serve_h1(
                    Box::new(server),
                    tokio::time::Instant::now() + Duration::from_secs(4),
                )
                .await
                .unwrap();
        });
        tasks.spawn(async move {
            reader.read_exact(&mut [0; 5]).await.unwrap();
        });
        client.write_all(format!("POST /t/a/0 HTTP/1.1\r\nHost: localhost\r\nReferer: /?x_padding={}\r\nContent-Length: 5\r\n\r\n", "X".repeat(100)).as_bytes()).await.unwrap();
        for _ in 0..5 {
            client.write_all(b"x").await.unwrap();
            tokio::time::sleep(Duration::from_secs(9)).await;
        }
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            response.push(client.read_u8().await.unwrap());
        }
        assert!(
            String::from_utf8(response)
                .unwrap()
                .starts_with("HTTP/1.1 200")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn h2_slow_packet_body_and_empty_data_inactivity() {
        for stalled in [false, true] {
            let state = inactivity_service(64);
            let mut reader = attached_reader(&state, "a");
            let (client, server) = tokio::io::duplex(8192);
            let tasks = Tasks::new();
            tasks.spawn(async move {
                state
                    .serve_h2(
                        Box::new(server),
                        tokio::time::Instant::now() + Duration::from_secs(4),
                    )
                    .await
                    .unwrap();
            });
            if !stalled {
                tasks.spawn(async move {
                    reader.read_exact(&mut [0; 5]).await.unwrap();
                });
            }
            let (mut sender, connection) = h2::client::handshake(client).await.unwrap();
            tasks.spawn(async move {
                connection.await.unwrap();
            });
            let post = Request::post("https://localhost/t/a/0")
                .header("referer", format!("/?x_padding={}", "X".repeat(100)))
                .body(())
                .unwrap();
            let (response, mut send) = sender.send_request(post, false).unwrap();
            let mut response = Box::pin(response);
            send.send_data(Bytes::from_static(b"x"), false).unwrap();
            for _ in 0..4 {
                tokio::time::sleep(Duration::from_secs(if stalled { 2 } else { 9 })).await;
                assert!(futures::poll!(&mut response).is_pending());
                send.send_data(
                    if stalled {
                        Bytes::new()
                    } else {
                        Bytes::from_static(b"x")
                    },
                    false,
                )
                .unwrap();
            }
            if stalled {
                tokio::time::sleep(Duration::from_millis(1999)).await;
                assert!(futures::poll!(&mut response).is_pending());
                tokio::time::sleep(Duration::from_millis(1)).await;
                assert_eq!(
                    response.await.unwrap().status(),
                    StatusCode::REQUEST_TIMEOUT
                );
            } else {
                send.send_data(Bytes::new(), true).unwrap();
                assert_eq!(response.await.unwrap().status(), StatusCode::OK);
            }
        }
    }

    #[tokio::test]
    async fn h1_incomplete_rejected_bodies_close_the_connection() {
        for (method, path, expected) in [
            ("POST", "/t/id/0", "408"),
            ("POST", "/wrong", "404"),
            ("OPTIONS", "/t/", "200"),
        ] {
            let mut state = service();
            Arc::get_mut(&mut state)
                .unwrap()
                .config
                .limits
                .packet_timeout_secs = 1;
            let (mut client, server) = tokio::io::duplex(8192);
            let task = tokio::spawn(state.serve_h1(
                Box::new(server),
                tokio::time::Instant::now() + Duration::from_secs(4),
            ));
            client.write_all(format!(
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\nReferer: /?x_padding={}\r\nContent-Length: 10\r\n\r\nx",
                "X".repeat(100),
            ).as_bytes()).await.unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert!(
                String::from_utf8_lossy(&response).starts_with(&format!("HTTP/1.1 {expected}"))
            );
            task.await.unwrap().unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn h1_packet_connection_survives_idle_between_requests() {
        let (mut client, server) = tokio::io::duplex(8192);
        let task = tokio::spawn(service().serve_h1(
            Box::new(server),
            tokio::time::Instant::now() + Duration::from_secs(4),
        ));
        for sequence in 0..2 {
            client
                .write_all(
                    format!(
                        "POST /t/a/{sequence} HTTP/1.1\r\nHost: localhost\r\nReferer: /?x_padding={}\r\nContent-Length: 1\r\n\r\nx",
                        "X".repeat(100),
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let response = tokio::time::timeout(Duration::from_secs(1), async {
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    header.push(client.read_u8().await.unwrap());
                }
                String::from_utf8(header).unwrap()
            })
            .await
            .unwrap();
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            assert!(response.to_ascii_lowercase().contains("content-length: 0"));
            if sequence == 0 {
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
        drop(client);
        task.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_header_deadline_includes_preface_detection() {
        for prefix in [b"GET", b"PRI"] {
            let server = XhttpServer { state: service() };
            let (mut client, stream) = tokio::io::duplex(8192);
            let setup = server.setup_server_stream(Box::new(stream));
            tokio::pin!(setup);
            assert!(futures::poll!(&mut setup).is_pending());
            tokio::time::advance(Duration::from_secs(3)).await;
            client.write_all(prefix).await.unwrap();
            let TcpServerSetupResult::Session(run) = setup.await.unwrap() else {
                panic!("expected HTTP session");
            };
            tokio::pin!(run);
            assert!(futures::poll!(&mut run).is_pending());
            tokio::time::advance(Duration::from_secs(1)).await;
            run.await;
            client.read_to_end(&mut Vec::new()).await.unwrap();
        }
    }

    #[tokio::test]
    async fn completed_h2_requests_do_not_consume_stream_admission() {
        let mut state = service();
        Arc::get_mut(&mut state)
            .unwrap()
            .config
            .limits
            .max_requests_per_connection = 1;
        let (client, server) = tokio::io::duplex(8192);
        let tasks = Tasks::new();
        tasks.spawn(async move {
            let _ = state
                .serve_h2(
                    Box::new(server),
                    tokio::time::Instant::now() + Duration::from_secs(4),
                )
                .await;
        });
        let (mut sender, connection) = h2::client::handshake(client).await.unwrap();
        tasks.spawn(async move {
            let _ = connection.await;
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            for _ in 0..128 {
                sender = sender.ready().await.unwrap();
                let request = Request::builder()
                    .method("OPTIONS")
                    .uri("http://localhost/t/")
                    .body(())
                    .unwrap();
                let (response, _) = sender.send_request(request, true).unwrap();
                let response = response.await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let mut body = response.into_body();
                while let Some(data) = body.data().await {
                    assert!(data.unwrap().is_empty());
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn packet_reordering_duplicates_and_download_ownership() {
        let state = service();
        assert_eq!(
            request(&state, "POST", "a/1", b"second").await.status(),
            StatusCode::OK
        );
        assert_eq!(
            request(&state, "POST", "a/1", b"second").await.status(),
            StatusCode::OK
        );
        assert_eq!(
            request(&state, "POST", "a/1", b"different").await.status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            request(&state, "POST", "a/0", b"first").await.status(),
            StatusCode::OK
        );
        let response = request(&state, "GET", "a", b"").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            request(&state, "GET", "a", b"").await.status(),
            StatusCode::CONFLICT
        );
        let mut body = response.into_body();
        let mut data = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), async {
            while data.len() < 11 {
                data.extend(body.frame().await.unwrap().unwrap().into_data().unwrap());
            }
        })
        .await
        .unwrap();
        assert_eq!(data, b"firstsecond");
        assert_eq!(
            request(&state, "POST", "a/2", b"").await.status(),
            StatusCode::OK
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(10), body.frame())
                .await
                .is_err()
        );
        drop(body);
        assert_eq!(
            request(&state, "GET", "a", b"").await.status(),
            StatusCode::CONFLICT
        );
        state.close("a");
        assert_eq!(
            request(&state, "GET", "a", b"").await.status(),
            StatusCode::CONFLICT
        );
    }

    #[tokio::test(start_paused = true)]
    async fn orphan_expiry_and_tombstones_release_admission() {
        let state = service();
        assert_eq!(
            request(&state, "POST", "a/1", b"queued").await.status(),
            StatusCode::OK
        );
        assert_eq!(
            request(&state, "POST", "b/1", b"queued").await.status(),
            StatusCode::OK
        );
        assert_eq!(
            request(&state, "GET", "c", b"").await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        tokio::time::advance(Duration::from_secs(31)).await;
        state.reap();
        tokio::task::yield_now().await;
        assert_eq!(state.sessions.lock().len(), 2);
        assert_eq!(
            request(&state, "POST", "a/0", b"late").await.status(),
            StatusCode::CONFLICT
        );
        assert_eq!(state.admission.snapshot().active, 0);
        assert_eq!(
            request(&state, "GET", "c", b"").await.status(),
            StatusCode::OK
        );
        tokio::time::advance(Duration::from_secs(31)).await;
        state.reap();
        tokio::task::yield_now().await;
        assert!(state.sessions.lock().is_empty());
    }

    #[tokio::test]
    async fn closed_sessions_do_not_consume_live_admission() {
        let state = service();
        for index in 0..10 {
            let response = request(&state, "GET", &format!("session-{index}"), b"").await;
            assert_eq!(response.status(), StatusCode::OK);
            drop(response);
            tokio::task::yield_now().await;
            assert_eq!(state.admission.snapshot().active, 0);
            assert!(state.sessions.lock().len() <= state.config.limits.max_sessions);
        }
        assert_eq!(
            request(&state, "GET", "session-9", b"").await.status(),
            StatusCode::CONFLICT
        );
    }

    #[tokio::test]
    async fn queue_exhaustion_oversize_and_stream_conflicts_are_bounded() {
        let state = service();
        assert_eq!(
            request(&state, "POST", "a/1", b"x").await.status(),
            StatusCode::OK
        );
        assert_eq!(
            request(&state, "POST", "a/2", b"x").await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            request(&state, "GET", "a", b"").await.status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            request(&state, "POST", "b/0", &[0; 17]).await.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            request(&state, "GET", "b", b"").await.status(),
            StatusCode::CONFLICT
        );
        let state = service();
        let response = request(&state, "POST", "a", b"payload").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            request(&state, "POST", "a", b"").await.status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            request(&state, "POST", "a/0", b"x").await.status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            request(&state, "POST", "a/0", &[0; 17]).await.status(),
            StatusCode::CONFLICT
        );
        assert!(!state.session("a").unwrap().cancel.is_cancelled());
    }

    #[tokio::test]
    async fn packet_length_is_rejected_before_reading_the_body() {
        let state = service();
        let request = Request::post("http://localhost/t/a/0")
            .header("referer", format!("/?x_padding={}", "X".repeat(100)))
            .header("content-length", "17")
            .body(())
            .unwrap();
        let (_writer, reader) = pipe(Memory::new(state.memory.clone(), 1024));
        let response =
            tokio::time::timeout(Duration::from_millis(100), state.handle(request, reader))
                .await
                .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn packet_memory_pressure_waits_for_the_inner_reader() {
        let mut state = service();
        Arc::get_mut(&mut state)
            .unwrap()
            .config
            .limits
            .max_session_buffered_bytes = 32;
        let session = state.session("a").unwrap();
        let mut reader = {
            let mut session = session.state.lock();
            session.downloaded = true;
            session.reader.take().unwrap()
        };
        for sequence in 0..4 {
            assert_eq!(
                request(&state, "POST", &format!("a/{sequence}"), b"12345678")
                    .await
                    .status(),
                StatusCode::OK
            );
        }
        let mut blocked = Box::pin(request(&state, "POST", "a/4", b"abcdefgh"));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut blocked)
                .await
                .is_err()
        );
        reader.read_exact(&mut [0; 8]).await.unwrap();
        assert_eq!(blocked.await.status(), StatusCode::OK);
        assert!(!session.cancel.is_cancelled());
    }

    #[tokio::test]
    async fn reordered_packets_leave_memory_for_the_missing_predecessor() {
        let mut state = service();
        Arc::get_mut(&mut state)
            .unwrap()
            .config
            .limits
            .max_session_buffered_bytes = 32;
        let session = state.session("a").unwrap();
        let mut reader = {
            let mut session = session.state.lock();
            session.downloaded = true;
            session.reader.take().unwrap()
        };
        for sequence in 0..4 {
            assert_eq!(
                request(&state, "POST", &format!("a/{sequence}"), b"12345678")
                    .await
                    .status(),
                StatusCode::OK
            );
        }
        let mut later = Box::pin(request(&state, "POST", "a/5", b"abcdefgh"));
        assert!(futures::poll!(&mut later).is_pending());
        let mut next = Box::pin(request(&state, "POST", "a/4", b"ABCDEFGH"));
        assert!(futures::poll!(&mut next).is_pending());
        let mut received = [0; 48];
        tokio::time::timeout(Duration::from_secs(1), async {
            let (later, next, read) = tokio::join!(later, next, reader.read_exact(&mut received));
            read.unwrap();
            assert_eq!(later.status(), StatusCode::OK);
            assert_eq!(next.status(), StatusCode::OK);
        })
        .await
        .unwrap();
        assert_eq!(&received[32..], b"ABCDEFGHabcdefgh");
    }

    #[tokio::test]
    async fn contiguous_packets_wait_when_the_post_queue_is_full() {
        let state = service();
        let session = state.session("a").unwrap();
        let mut reader = {
            let mut session = session.state.lock();
            session.downloaded = true;
            session.reader.take().unwrap()
        };
        for sequence in 0..4 {
            assert_eq!(
                request(&state, "POST", &format!("a/{sequence}"), b"12345678")
                    .await
                    .status(),
                StatusCode::OK
            );
        }
        let mut requests = tokio::task::JoinSet::new();
        for sequence in 4..11 {
            let state = state.clone();
            requests.spawn(async move {
                request(&state, "POST", &format!("a/{sequence}"), b"abcdefgh")
                    .await
                    .status()
            });
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(
            requests.try_join_next().is_none(),
            "full queues must backpressure, not reject"
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            reader.read_exact(&mut [0; 88]).await.unwrap();
            while let Some(response) = requests.join_next().await {
                assert_eq!(response.unwrap(), StatusCode::OK);
            }
        })
        .await
        .unwrap();
    }

    async fn reserved_predecessors(attach_late: bool) {
        let mut state = service();
        {
            let state = Arc::get_mut(&mut state).unwrap();
            state.config.sc_max_buffered_posts = 4;
            state.config.limits.max_session_buffered_bytes = 64;
        }
        let session = state.session("a").unwrap();
        let mut reader = None;
        if !attach_late {
            let mut session = session.state.lock();
            session.downloaded = true;
            reader = session.reader.take();
        }
        let mut writers = Vec::new();
        let mut posts = tokio::task::JoinSet::new();
        for sequence in 0..4 {
            let post = Request::post(format!("http://localhost/t/a/{sequence}"))
                .header("referer", format!("/?x_padding={}", "X".repeat(100)))
                .header("content-length", "16")
                .body(())
                .unwrap();
            let (writer, body) = pipe(Memory::new(state.memory.clone(), 1024));
            writers.push(writer);
            let state = state.clone();
            posts.spawn(async move { state.handle(post, body).await.status() });
            tokio::task::yield_now().await;
        }
        let mut last = writers.pop().unwrap();
        last.write_all(&[3; 16]).await.unwrap();
        let download = {
            let mut admitted = Box::pin(last.flush());
            let download = if attach_late {
                assert!(
                    tokio::time::timeout(Duration::from_millis(50), &mut admitted)
                        .await
                        .is_err(),
                    "detached sessions keep predecessor headroom"
                );
                Some(request(&state, "GET", "a", b"").await)
            } else {
                None
            };
            tokio::time::timeout(Duration::from_secs(1), admitted)
                .await
                .expect("reserved predecessors must not hold back the successor body")
                .unwrap();
            download
        };
        for (sequence, writer) in writers.iter_mut().enumerate() {
            writer.write_all(&[sequence as u8; 16]).await.unwrap();
            writer.shutdown().await.unwrap();
        }
        last.shutdown().await.unwrap();
        let mut data = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), async {
            if let Some(reader) = reader.as_mut() {
                data.resize(64, 0);
                reader.read_exact(&mut data).await.unwrap();
            } else {
                let mut body = download.unwrap().into_body();
                while data.len() < 64 {
                    data.extend(body.frame().await.unwrap().unwrap().into_data().unwrap());
                }
            }
            while let Some(status) = posts.join_next().await {
                assert_eq!(status.unwrap(), StatusCode::OK);
            }
        })
        .await
        .unwrap();
        assert_eq!(data, [[0u8; 16], [1; 16], [2; 16], [3; 16]].concat());
    }

    #[tokio::test]
    async fn reserved_predecessors_admit_successor_bodies() {
        reserved_predecessors(false).await;
    }

    #[tokio::test]
    async fn download_attachment_wakes_reserved_predecessor_waiters() {
        reserved_predecessors(true).await;
    }

    #[tokio::test]
    async fn new_packet_reservations_wake_admission_waiters() {
        let mut state = service();
        {
            let state = Arc::get_mut(&mut state).unwrap();
            state.config.sc_max_buffered_posts = 4;
            state.config.limits.max_session_buffered_bytes = 24;
        }
        let session = state.session("a").unwrap();
        session.state.lock().downloaded = true;
        let mut posts = tokio::task::JoinSet::new();
        let mut writers = Vec::new();
        for sequence in [1, 2, 0] {
            let post = Request::post(format!("http://localhost/t/a/{sequence}"))
                .header("referer", format!("/?x_padding={}", "X".repeat(100)))
                .header("content-length", "8")
                .body(())
                .unwrap();
            let (mut writer, body) = pipe(Memory::new(state.memory.clone(), 1024));
            let state = state.clone();
            posts.spawn(async move { state.handle(post, body).await.status() });
            if sequence == 2 {
                assert!(
                    tokio::time::timeout(Duration::from_millis(10), writer.flush())
                        .await
                        .is_err()
                );
            } else {
                tokio::time::timeout(Duration::from_secs(1), writer.flush())
                    .await
                    .unwrap()
                    .unwrap();
            }
            writers.push(writer);
        }
        tokio::time::timeout(Duration::from_secs(1), writers[1].flush())
            .await
            .expect("reserving the missing predecessor must wake admission")
            .unwrap();
        assert_eq!(session.state.lock().reserved.len(), 3);
        posts.abort_all();
        while posts.join_next().await.is_some() {}
        assert!(session.state.lock().reserved.is_empty());
        assert!(session.memory.reserve_packet(24, 0).is_some());
    }

    #[tokio::test]
    async fn duplicate_packet_reservations_are_released_on_cancellation() {
        for close_session in [false, true] {
            let mut state = service();
            Arc::get_mut(&mut state)
                .unwrap()
                .config
                .limits
                .max_session_buffered_bytes = 64;
            let session = state.session("a").unwrap();
            let mut posts = Vec::new();
            let mut writers = Vec::new();
            for _ in 0..2 {
                let post = Request::post("http://localhost/t/a/0")
                    .header("referer", format!("/?x_padding={}", "X".repeat(100)))
                    .header("content-length", "16")
                    .body(())
                    .unwrap();
                let (mut writer, body) = pipe(Memory::new(state.memory.clone(), 1024));
                let state = state.clone();
                posts.push(tokio::spawn(async move {
                    state.handle(post, body).await.status()
                }));
                tokio::time::timeout(Duration::from_secs(1), writer.flush())
                    .await
                    .unwrap()
                    .unwrap();
                writers.push(writer);
            }
            assert_eq!(session.state.lock().reserved.get(&0), Some(&2));
            let first = posts.pop().unwrap();
            first.abort();
            assert!(first.await.is_err());
            assert_eq!(session.state.lock().reserved.get(&0), Some(&1));
            assert_eq!(session.state.lock().receiving.get(&0), Some(&1));
            assert!(session.memory.reserve_packet(48, 0).is_some());
            let second = posts.pop().unwrap();
            if close_session {
                state.close("a");
                assert_eq!(second.await.unwrap(), StatusCode::SERVICE_UNAVAILABLE);
            } else {
                second.abort();
                assert!(second.await.is_err());
            }
            assert!(session.state.lock().reserved.is_empty());
            assert!(session.state.lock().receiving.is_empty());
            assert!(session.memory.reserve_packet(64, 0).is_some());
        }
    }

    #[tokio::test]
    async fn cancellation_removes_reservation_markers_before_releasing_bytes() {
        use std::{
            future::Future,
            sync::atomic::{AtomicUsize, Ordering},
            task::Context,
        };

        struct ReleaseObserver {
            session: Arc<Session>,
            reserved: AtomicUsize,
        }
        impl futures::task::ArcWake for ReleaseObserver {
            fn wake_by_ref(observer: &Arc<Self>) {
                observer.reserved.store(
                    observer
                        .session
                        .state
                        .lock()
                        .reserved
                        .get(&0)
                        .copied()
                        .unwrap_or(0),
                    Ordering::SeqCst,
                );
            }
        }

        for buffered in [false, true] {
            let state = service();
            let session = state.session("a").unwrap();
            let post = Request::post("http://localhost/t/a/0")
                .header("referer", format!("/?x_padding={}", "X".repeat(100)))
                .header("content-length", "16")
                .body(())
                .unwrap();
            let (mut writer, body) = pipe(Memory::new(state.memory.clone(), 1024));
            let post = tokio::spawn(async move { state.handle(post, body).await.status() });
            if buffered {
                writer.write_all(b"partial").await.unwrap();
            }
            tokio::time::timeout(Duration::from_secs(1), writer.flush())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(session.state.lock().reserved.get(&0), Some(&1));
            let observer = Arc::new(ReleaseObserver {
                session: session.clone(),
                reserved: AtomicUsize::new(usize::MAX),
            });
            let mut released = Box::pin(session.memory.packet_space_released());
            {
                // Inspect state synchronously inside the byte-release wakeup.
                let waker = futures::task::waker_ref(&observer);
                let mut cx = Context::from_waker(&waker);
                assert!(released.as_mut().poll(&mut cx).is_pending());
            }
            post.abort();
            assert!(post.await.is_err());
            assert_eq!(observer.reserved.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn attached_duplicate_packets_wait_for_forwarding() {
        let state = service();
        let session = state.session("a").unwrap();
        let mut reader = {
            let mut state = session.state.lock();
            state.downloaded = true;
            state.reader.take().unwrap()
        };
        for sequence in 0..4 {
            assert_eq!(
                request(&state, "POST", &format!("a/{sequence}"), b"12345678")
                    .await
                    .status(),
                StatusCode::OK
            );
        }
        let mut later = Box::pin(request(&state, "POST", "a/5", b"BBBBBBBB"));
        assert!(futures::poll!(&mut later).is_pending());
        let mut duplicate_later = Box::pin(request(&state, "POST", "a/5", b"BBBBBBBB"));
        assert!(futures::poll!(&mut duplicate_later).is_pending());
        let mut next = Box::pin(request(&state, "POST", "a/4", b"AAAAAAAA"));
        assert!(futures::poll!(&mut next).is_pending());
        tokio::task::yield_now().await;
        let mut duplicate_next = Box::pin(request(&state, "POST", "a/4", b"AAAAAAAA"));
        assert!(futures::poll!(&mut duplicate_next).is_pending());
        let mut bytes = [0; 48];
        tokio::time::timeout(Duration::from_secs(1), async {
            let (later, duplicate_later, next, duplicate_next, read) = tokio::join!(
                later,
                duplicate_later,
                next,
                duplicate_next,
                reader.read_exact(&mut bytes)
            );
            read.unwrap();
            for response in [later, duplicate_later, next, duplicate_next] {
                assert_eq!(response.status(), StatusCode::OK);
            }
        })
        .await
        .unwrap();
        assert_eq!(&bytes[32..], b"AAAAAAAABBBBBBBB");
    }

    #[tokio::test]
    async fn closing_an_idle_h1_download_releases_its_session() {
        let state = service();
        let (mut client, server) = tokio::io::duplex(8192);
        let task = tokio::spawn(state.clone().serve_h1(
            Box::new(server),
            tokio::time::Instant::now() + Duration::from_secs(4),
        ));
        client
            .write_all(
                format!(
                    "GET /t/a HTTP/1.1\r\nHost: localhost\r\nReferer: /?x_padding={}\r\n\r\n",
                    "X".repeat(100),
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut header = [0; 4096];
        assert!(client.read(&mut header).await.unwrap() > 0);
        assert_eq!(state.admission.snapshot().active, 1);
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.admission.snapshot().active, 0);
    }

    #[tokio::test]
    async fn stream_one_admission_and_service_drop_release_resources() {
        let state = service();
        let first = request(&state, "POST", "", b"first").await;
        let second = request(&state, "POST", "", b"second").await;
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(
            request(&state, "POST", "", b"third").await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        drop(first);
        tokio::task::yield_now().await;
        assert_eq!(
            request(&state, "POST", "", b"third").await.status(),
            StatusCode::OK
        );
        drop(second);
        let memory = state.memory.clone();
        let weak = Arc::downgrade(&state);
        let upload = request(&state, "POST", "orphan", b"queued").await;
        drop(upload);
        drop(state);
        tokio::task::yield_now().await;
        assert!(weak.upgrade().is_none());
        assert_eq!(memory.snapshot().active, 0);
    }
}

struct State {
    config: XhttpServerConfig,
    path: Path,
    inner: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    memory: Arc<Budget>,
    admission: Arc<Budget>,
    sessions: parking_lot::Mutex<HashMap<String, Entry>>,
    tasks: Tasks,
}
impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XhttpService").finish_non_exhaustive()
    }
}

enum Entry {
    Live(Arc<Session>),
    Closed { when: tokio::time::Instant },
}
#[derive(Default, PartialEq)]
enum Upload {
    #[default]
    Unclaimed,
    Packet,
    Stream,
}
struct SessionState {
    upload: Upload,
    writer: Option<Writer>,
    reader: Option<Reader>,
    pending: BTreeMap<u64, Packet>,
    receiving: BTreeMap<u64, usize>,
    reserved: BTreeMap<u64, usize>,
    forwarding: Option<(u64, CancellationToken)>,
    next: u64,
    downloaded: bool,
    permit: Option<BudgetPermit>,
}
impl SessionState {
    fn acknowledgement(&self, sequence: u64) -> Option<CancellationToken> {
        if !self.downloaded {
            return None;
        }
        self.forwarding
            .as_ref()
            .filter(|(number, _)| *number == sequence)
            .map(|(_, forwarded)| forwarded.clone())
            .or_else(|| {
                self.pending
                    .get(&sequence)
                    .map(|packet| packet.forwarded.clone())
            })
    }
}
struct Packet {
    chunks: Vec<Bytes>,
    forwarded: CancellationToken,
}
struct Session {
    state: parking_lot::Mutex<SessionState>,
    memory: Memory,
    ready: Notify,
    cancel: CancellationToken,
    created: tokio::time::Instant,
    admission: parking_lot::Mutex<Option<BudgetPermit>>,
    progress: Notify,
    activity: Arc<Activity>,
}

struct PacketRequest {
    session: Arc<Session>,
    sequence: u64,
    reserved: bool,
    primary: bool,
}

impl PacketRequest {
    fn new(session: Arc<Session>, sequence: u64) -> Self {
        let primary = {
            let mut state = session.state.lock();
            let count = state.receiving.entry(sequence).or_default();
            *count += 1;
            *count == 1
        };
        Self {
            session,
            sequence,
            reserved: false,
            primary,
        }
    }

    fn touch(&self) {
        if self.primary {
            let state = self.session.state.lock();
            // Only the original receiver of the missing head packet can sustain other POSTs.
            if self.sequence == state.next && !state.pending.contains_key(&self.sequence) {
                self.session.activity.touch();
            }
        }
    }

    fn decrement(counts: &mut BTreeMap<u64, usize>, sequence: u64) {
        let count = counts.get_mut(&sequence).unwrap();
        *count -= 1;
        if *count == 0 {
            counts.remove(&sequence);
        }
    }
}

impl Drop for PacketRequest {
    fn drop(&mut self) {
        let mut state = self.session.state.lock();
        Self::decrement(&mut state.receiving, self.sequence);
        if self.reserved {
            Self::decrement(&mut state.reserved, self.sequence);
        }
        self.session.progress.notify_waiters();
    }
}

struct DownloadGuard {
    state: Weak<State>,
    session: Option<Weak<Session>>,
    id: String,
    cancel: CancellationToken,
    eof: CancellationToken,
}
impl Drop for DownloadGuard {
    fn drop(&mut self) {
        if self.eof.is_cancelled()
            && self.session.as_ref().is_none_or(|session| {
                session
                    .upgrade()
                    .is_some_and(|session| session.state.lock().upload == Upload::Stream)
            })
        {
            return;
        }
        self.cancel.cancel();
        if let Some(state) = self.state.upgrade() {
            state.close(&self.id);
        }
    }
}

impl XhttpServer {
    pub fn new(
        config: XhttpServerConfig,
        selector: &Arc<ClientProxySelector>,
        resolver: &Arc<dyn Resolver>,
        bind_ip: Option<IpAddr>,
    ) -> io::Result<Self> {
        config.validate()?;
        let inner = crate::tcp::tcp_server_handler_factory::create_tcp_server_handler(
            *config.protocol.clone(),
            selector,
            resolver,
            bind_ip,
        )?
        .into();
        let state = Arc::new(State {
            path: Path::new(&config.path)?,
            inner,
            resolver: resolver.clone(),
            memory: Arc::new(Budget::new(Some(config.limits.max_buffered_bytes))),
            admission: Arc::new(Budget::new(Some(config.limits.max_sessions))),
            sessions: parking_lot::Mutex::new(HashMap::new()),
            tasks: Tasks::new(),
            config,
        });
        let weak = Arc::downgrade(&state);
        state.tasks.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let Some(state) = weak.upgrade() else {
                    break;
                };
                state.reap();
            }
        });
        Ok(Self { state })
    }

    pub async fn serve_h3(&self, connection: quinn::Connection) -> io::Result<()> {
        let mut driver = h3::server::builder()
            .max_field_section_size(self.state.config.header_limit() as u64)
            .build(super::h3::Connection::new(connection))
            .await
            .map_err(io::Error::other)?;
        let mut requests = tokio::task::JoinSet::new();
        loop {
            let resolver = tokio::select! {
                result = driver.accept() => result.map_err(io::Error::other)?,
                _ = requests.join_next(), if !requests.is_empty() => continue,
            };
            let Some(resolver) = resolver else {
                return Ok(());
            };
            while requests.try_join_next().is_some() {}
            if requests.len() >= self.state.config.limits.request_limit() {
                drop(resolver);
                continue;
            }
            let state = self.state.clone();
            requests.spawn(async move {
                let Ok(Ok((request, stream))) = tokio::time::timeout(
                    Duration::from_secs(state.config.limits.setup_timeout_secs),
                    resolver.resolve_request(),
                )
                .await
                else {
                    return;
                };
                let (mut send, mut receive) = stream.split();
                let workers = Tasks::new();
                let memory = Memory::new(
                    state.memory.clone(),
                    state.config.limits.max_session_buffered_bytes,
                );
                let (mut writer, reader) = pipe(memory);
                let upload_closed = writer.closed();
                workers.spawn(async move {
                    let result: io::Result<()> = async {
                        while let Some(mut data) =
                            receive.recv_data().await.map_err(io::Error::other)?
                        {
                            while data.has_remaining() {
                                writer.write_all(data.chunk()).await?;
                                let len = data.chunk().len();
                                data.advance(len);
                            }
                        }
                        writer.shutdown().await
                    }
                    .await;
                    if let Err(error) = result {
                        receive.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
                        writer.fail(error).await;
                    }
                });
                let streaming_upload = matches!(
                    wire::classify(&state.config, &state.path, &request),
                    Ok(Kind::One | Kind::Upload(_))
                );
                let response = state.handle(request, reader).await;
                let keep_upload = streaming_upload && response.status() == StatusCode::OK;
                let (parts, mut body) = response.into_parts();
                let result: io::Result<()> = async {
                    send.send_response(Response::from_parts(parts, ()))
                        .await
                        .map_err(io::Error::other)?;
                    loop {
                        // h3 0.0.8 has no send-side cancellation waiter. An empty
                        // DATA frame detects STOP_SENDING without changing the
                        // inner byte stream or closing a shared QUIC connection.
                        let frame =
                            match tokio::time::timeout(Duration::from_secs(10), body.frame()).await
                            {
                                Ok(frame) => frame,
                                Err(_) => {
                                    send.send_data(Bytes::new())
                                        .await
                                        .map_err(io::Error::other)?;
                                    continue;
                                }
                            };
                        let Some(frame) = frame else {
                            break;
                        };
                        if let Ok(data) = frame?.into_data() {
                            send.send_data(data).await.map_err(io::Error::other)?;
                        }
                    }
                    send.finish().await.map_err(io::Error::other)
                }
                .await;
                if result.is_err() {
                    send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                } else if keep_upload {
                    tokio::select! {
                        _ = workers.wait() => {},
                        _ = upload_closed => {},
                    }
                }
            });
        }
    }
}

#[async_trait]
impl TcpServerHandler for XhttpServer {
    async fn setup_server_stream(
        &self,
        mut stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        let state = self.state.clone();
        let version = state.config.http_version;
        if version == XhttpVersion::H3 {
            return Err(io::Error::other("H3 requires a QUIC listener"));
        }
        let mut prefix = [0; 3];
        let deadline = tokio::time::Instant::now()
            + Duration::from_secs(state.config.limits.setup_timeout_secs.min(4));
        tokio::time::timeout_at(deadline, stream.read_exact(&mut prefix)).await??;
        let h2 = &prefix == b"PRI";
        if (version == XhttpVersion::H1 && h2) || (version == XhttpVersion::H2 && !h2) {
            return Err(io::Error::other("unexpected XHTTP version"));
        }
        let stream = crate::prepend_stream::PrependStream::new(stream, Some(Box::new(prefix)));
        Ok(TcpServerSetupResult::Session(Box::pin(async move {
            let result = if h2 {
                state.serve_h2(Box::new(stream), deadline).await
            } else {
                state.serve_h1(Box::new(stream), deadline).await
            };
            if let Err(error) = result {
                log::debug!("XHTTP carrier ended: {error}");
            }
        })))
    }
}

impl State {
    fn close(&self, id: &str) {
        let mut sessions = self.sessions.lock();
        self.close_entry(&mut sessions, id);
    }

    fn close_entry(&self, sessions: &mut HashMap<String, Entry>, id: &str) {
        if !matches!(sessions.get(id), Some(Entry::Live(_))) {
            return;
        }
        if let Some(Entry::Live(session)) = sessions.remove(id) {
            session.cancel.cancel();
            session.admission.lock().take();
            {
                let mut state = session.state.lock();
                state.pending.clear();
                state.permit.take();
                state.writer.take();
                state.reader.take();
            }
            let closed = sessions
                .values()
                .filter(|entry| matches!(entry, Entry::Closed { .. }))
                .count();
            if closed >= self.config.limits.max_sessions {
                let oldest = sessions
                    .iter()
                    .filter_map(|(id, entry)| match entry {
                        Entry::Closed { when } => Some((id, when)),
                        Entry::Live(_) => None,
                    })
                    .min_by_key(|(_, when)| *when)
                    .map(|(id, _)| id.clone());
                if let Some(oldest) = oldest {
                    sessions.remove(&oldest);
                }
            }
            sessions.insert(
                id.into(),
                Entry::Closed {
                    when: tokio::time::Instant::now(),
                },
            );
        }
    }

    fn reap(&self) {
        let mut sessions = self.sessions.lock();
        sessions.retain(|_, entry| match entry {
            Entry::Closed { when } => when.elapsed() < Duration::from_secs(30),
            Entry::Live(_) => true,
        });
        let expired: Vec<_> = sessions
            .iter()
            .filter_map(|(id, entry)| match entry {
                Entry::Live(session)
                    if !session.state.lock().downloaded
                        && session.created.elapsed() >= Duration::from_secs(30) =>
                {
                    Some(id.clone())
                }
                _ => None,
            })
            .collect();
        for id in expired {
            self.close_entry(&mut sessions, &id);
        }
    }

    fn session(&self, id: &str) -> Result<Arc<Session>, StatusCode> {
        let mut sessions = self.sessions.lock();
        if let Some(entry) = sessions.get(id) {
            return match entry {
                Entry::Live(s) if !s.cancel.is_cancelled() => Ok(s.clone()),
                Entry::Live(_) => Err(StatusCode::CONFLICT),
                Entry::Closed { .. } => Err(StatusCode::CONFLICT),
            };
        }
        if sessions
            .values()
            .filter(|entry| matches!(entry, Entry::Live(_)))
            .count()
            >= self.config.limits.max_sessions
            || sessions
                .values()
                .filter(|entry| matches!(entry, Entry::Live(s) if !s.state.lock().downloaded))
                .count()
                >= self.config.limits.max_pending_sessions
        {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        let permit = crate::resources::try_stream().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let admission = self
            .admission
            .acquire(1)
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let memory = Memory::new(
            self.memory.clone(),
            self.config.limits.max_session_buffered_bytes,
        );
        let (writer, mut reader) = pipe(memory.clone());
        let activity = Arc::new(Activity::new());
        reader.activity = Some(activity.clone());
        let session = Arc::new(Session {
            state: parking_lot::Mutex::new(SessionState {
                upload: Upload::Unclaimed,
                writer: Some(writer),
                reader: Some(reader),
                pending: BTreeMap::new(),
                receiving: BTreeMap::new(),
                reserved: BTreeMap::new(),
                forwarding: None,
                next: 0,
                downloaded: false,
                permit: Some(permit),
            }),
            memory,
            ready: Notify::new(),
            cancel: CancellationToken::new(),
            created: tokio::time::Instant::now(),
            admission: parking_lot::Mutex::new(Some(admission)),
            activity,
            progress: Notify::new(),
        });
        sessions.insert(id.into(), Entry::Live(session.clone()));
        Ok(session)
    }

    fn response(&self, status: StatusCode, body: Body, downstream: bool) -> Response<Body> {
        let mut response = Response::builder()
            .status(status)
            .header("cache-control", "no-store")
            .header("x-accel-buffering", "no")
            .header("access-control-allow-origin", "*")
            .header(
                "x-padding",
                "X".repeat(wire::sample(
                    self.config
                        .x_padding_bytes
                        .bounds((100, 1000), false)
                        .unwrap(),
                ) as usize),
            );
        if downstream && !self.config.no_sse_header {
            response = response.header("content-type", "text/event-stream");
        }
        response.body(body).unwrap()
    }

    fn spawn_inner_session(
        &self,
        stream: Stream,
        permit: BudgetPermit,
        cancel: CancellationToken,
        finished: impl FnOnce() + Send + 'static,
    ) {
        let inner = self.inner.clone();
        let resolver = self.resolver.clone();
        let timeout = Duration::from_secs(self.config.limits.setup_timeout_secs);
        self.tasks.spawn(async move {
            tokio::select! {
                _ = cancel.cancelled() => {},
                result = crate::tcp::tcp_server::process_stream_with_permit(
                    stream, inner, resolver, permit, timeout,
                ) => {
                    if let Err(error) = result {
                        log::debug!("XHTTP inner session failed: {error}");
                    }
                }
            }
            finished();
        });
    }

    async fn dispatch(
        self: &Arc<Self>,
        request: &Request<()>,
        mut body: Reader,
    ) -> Result<(Body, bool), StatusCode> {
        match wire::classify(&self.config, &self.path, request)? {
            Kind::Options => Ok((Body::Empty, false)),
            Kind::One => {
                let admission = self
                    .admission
                    .acquire(1)
                    .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
                let permit =
                    crate::resources::try_stream().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
                let memory = Memory::new(
                    self.memory.clone(),
                    self.config.limits.max_session_buffered_bytes,
                );
                let (writer, reader) = pipe(memory);
                let tasks = Arc::new(Tasks::new());
                let stream = Stream {
                    read: body,
                    write: writer,
                    _tasks: tasks.clone(),
                };
                self.spawn_inner_session(stream, permit, tasks.cancel.clone(), move || {
                    drop(admission);
                });
                let guard = DownloadGuard {
                    state: Weak::new(),
                    session: None,
                    id: String::new(),
                    cancel: tasks.cancel.clone(),
                    eof: reader.eof.clone(),
                };
                Ok((Body::stream(reader).with_guard(guard), true))
            }
            Kind::Download(id) => {
                let session = self.session(&id)?;
                let (reader, permit) = {
                    let mut state = session.state.lock();
                    if state.downloaded {
                        return Err(StatusCode::CONFLICT);
                    }
                    state.downloaded = true;
                    (state.reader.take().unwrap(), state.permit.take().unwrap())
                };
                session.progress.notify_waiters();
                let (writer, output) = pipe(session.memory.clone());
                let tasks = Arc::new(Tasks::new());
                let stream = Stream {
                    read: reader,
                    write: writer,
                    _tasks: tasks,
                };
                let state = Arc::downgrade(self);
                let session_id = id.clone();
                self.spawn_inner_session(stream, permit, session.cancel.clone(), move || {
                    if let Some(state) = state.upgrade() {
                        state.close(&session_id);
                    }
                });
                let guard = DownloadGuard {
                    state: Arc::downgrade(self),
                    session: Some(Arc::downgrade(&session)),
                    id,
                    cancel: session.cancel.clone(),
                    eof: output.eof.clone(),
                };
                Ok((Body::stream(output).with_guard(guard), true))
            }
            Kind::Upload(id) => {
                let session = self.session(&id)?;
                let mut writer = {
                    let mut state = session.state.lock();
                    if state.upload != Upload::Unclaimed {
                        return Err(StatusCode::CONFLICT);
                    }
                    state.upload = Upload::Stream;
                    state.writer.take().unwrap()
                };
                let (mut padding_writer, padding_reader) = pipe(session.memory.clone());
                let interval = if request
                    .headers()
                    .get("referer")
                    .is_some_and(|v| !v.is_empty())
                {
                    self.config
                        .sc_stream_up_server_secs
                        .bounds((20, 80), true)
                        .unwrap()
                } else {
                    (0, 0)
                };
                let padding = self
                    .config
                    .x_padding_bytes
                    .bounds((100, 1000), false)
                    .unwrap();
                let cancel = session.cancel.clone();
                self.tasks.spawn(async move {
                    let upload = async {
                        tokio::io::copy(&mut body, &mut writer).await?;
                        writer.shutdown().await
                    };
                    let padding = async {
                        if interval.1 == 0 {
                            std::future::pending::<()>().await;
                        }
                        loop {
                            padding_writer
                                .write_all(&vec![b'X'; wire::sample(padding) as usize])
                                .await?;
                            tokio::time::sleep(Duration::from_secs(wire::sample(interval) as u64))
                                .await;
                        }
                        #[allow(unreachable_code)]
                        Ok::<_, io::Error>(())
                    };
                    tokio::select! {
                        _ = cancel.cancelled() => {},
                        result = upload => {
                            if result.is_err() {
                                cancel.cancel();
                            }
                        },
                        _ = padding => { cancel.cancel(); }
                    }
                    let _ = padding_writer.shutdown().await;
                });
                Ok((Body::stream(padding_reader), false))
            }
            Kind::Packet(id, sequence) => {
                use std::ops::ControlFlow;

                let session = self.session(&id)?;
                {
                    let state = session.state.lock();
                    if state.upload == Upload::Stream {
                        return Err(StatusCode::CONFLICT);
                    }
                }
                let max = self
                    .config
                    .sc_max_each_post_bytes
                    .bounds((1_000_000, 1_000_000), false)
                    .unwrap()
                    .1 as usize;
                let initial =
                    wire::header_payload(request.headers()).map_err(|_| StatusCode::BAD_REQUEST)?;
                let mut size = initial.len();
                let mut reservation = max.min(self.config.limits.max_session_buffered_bytes);
                if let Some(length) = request.headers().get(http::header::CONTENT_LENGTH) {
                    let length = length
                        .to_str()
                        .ok()
                        .and_then(|v| v.parse::<u64>().ok())
                        .ok_or(StatusCode::BAD_REQUEST)?;
                    if length > max.saturating_sub(size) as u64 {
                        return Err(StatusCode::PAYLOAD_TOO_LARGE);
                    }
                    reservation = size + length as usize;
                }
                if size > max {
                    return Err(StatusCode::PAYLOAD_TOO_LARGE);
                }
                if reservation > self.config.limits.max_session_buffered_bytes {
                    return Err(StatusCode::SERVICE_UNAVAILABLE);
                }
                let arrived = tokio::time::Instant::now();
                let timeout = Duration::from_secs(self.config.limits.packet_timeout_secs);
                let ingest = async {
                    let mut packet_request = PacketRequest::new(session.clone(), sequence);
                    let admission = async {
                        loop {
                            let released = session.memory.packet_space_released();
                            let progress = session.progress.notified();
                            tokio::pin!(released, progress);
                            released.as_mut().enable();
                            progress.as_mut().enable();
                            {
                                let mut state = session.state.lock();
                                if state.upload == Upload::Stream {
                                    return Err(StatusCode::CONFLICT);
                                }
                                state.upload = Upload::Packet;
                                if sequence < state.next {
                                    return Ok(ControlFlow::Break(state.acknowledgement(sequence)));
                                }
                                let contiguous = state.downloaded
                                    && (state.next..sequence).all(|number| {
                                        state.pending.contains_key(&number)
                                            || state.reserved.contains_key(&number)
                                    });
                                if sequence.saturating_sub(state.next)
                                    >= self.config.buffered_posts() as u64
                                {
                                    if !state.downloaded
                                        || !(state.next..sequence).all(|number| {
                                            state.pending.contains_key(&number)
                                                || state.receiving.contains_key(&number)
                                        })
                                    {
                                        return Err(StatusCode::SERVICE_UNAVAILABLE);
                                    }
                                } else {
                                    // Out-of-order packets must leave space for their missing predecessor.
                                    let headroom = if contiguous || sequence == state.next {
                                        0
                                    } else {
                                        max.min(self.config.limits.max_session_buffered_bytes)
                                    };
                                    if let Some(memory) =
                                        session.memory.reserve_packet(reservation, headroom)
                                    {
                                        *state.reserved.entry(sequence).or_default() += 1;
                                        packet_request.reserved = true;
                                        session.progress.notify_waiters();
                                        break Ok(ControlFlow::Continue(memory));
                                    }
                                }
                            }
                            tokio::select! {
                                _ = released => {},
                                _ = progress => {},
                            }
                        }
                    };
                    let mut memory = match session
                        .activity
                        .idle(arrived, timeout, admission)
                        .await
                        .map_err(|_| StatusCode::REQUEST_TIMEOUT)??
                    {
                        ControlFlow::Break(ack) => return Ok(ack),
                        ControlFlow::Continue(memory) => memory,
                    };
                    let mut chunks = Vec::new();
                    // On cancellation, remove admission markers before releasing byte permits.
                    let body_request = packet_request;
                    let body_activity = Activity::new();
                    let intake = async {
                        if !initial.is_empty() {
                            chunks.push(
                                memory
                                    .copy(&initial)
                                    .await
                                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
                            );
                            body_activity.touch();
                            body_request.touch();
                        }
                        loop {
                            let data = match body.receiver.recv().await {
                                Some(Event::Data(data)) => data,
                                Some(Event::Flush(ack) | Event::Drain(ack)) => {
                                    let _ = ack.send(());
                                    continue;
                                }
                                Some(Event::Finish) => break,
                                Some(Event::Error(_)) | None => {
                                    return Err(StatusCode::BAD_REQUEST);
                                }
                            };
                            size = size
                                .checked_add(data.len())
                                .ok_or(StatusCode::PAYLOAD_TOO_LARGE)?;
                            if size > max {
                                return Err(StatusCode::PAYLOAD_TOO_LARGE);
                            }
                            if data.is_empty() {
                                continue;
                            }
                            chunks.push(
                                memory
                                    .retain(data)
                                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
                            );
                            body_activity.touch();
                            body_request.touch();
                        }
                        Ok::<_, StatusCode>(())
                    };
                    body_activity
                        .idle(tokio::time::Instant::now(), timeout, intake)
                        .await
                        .map_err(|_| StatusCode::REQUEST_TIMEOUT)??;
                    let forwarded = CancellationToken::new();
                    let writer = {
                        let mut state = session.state.lock();
                        if sequence < state.next {
                            return Ok(state.acknowledgement(sequence));
                        }
                        if let Some(previous) = state.pending.get(&sequence) {
                            if previous
                                .chunks
                                .iter()
                                .flat_map(|b| b.iter())
                                .eq(chunks.iter().flat_map(|b| b.iter()))
                            {
                                return Ok(state.acknowledgement(sequence));
                            }
                            return Err(StatusCode::CONFLICT);
                        }
                        if state.pending.len() >= self.config.buffered_posts() {
                            session.cancel.cancel();
                            return Err(StatusCode::SERVICE_UNAVAILABLE);
                        }
                        state.pending.insert(
                            sequence,
                            Packet {
                                chunks,
                                forwarded: forwarded.clone(),
                            },
                        );
                        state.writer.take()
                    };
                    drop(memory);
                    if let Some(mut writer) = writer {
                        let session = session.clone();
                        self.tasks.spawn(async move {
                            let work = async {
                                loop {
                                    let chunks = {
                                        let mut state = session.state.lock();
                                        let next = state.next;
                                        let chunks = state.pending.remove(&next);
                                        if let Some(packet) = &chunks {
                                            state.forwarding =
                                                Some((next, packet.forwarded.clone()));
                                            state.next = next.checked_add(1).ok_or_else(|| {
                                                io::Error::other("sequence exhausted")
                                            })?;
                                            session.progress.notify_waiters();
                                        }
                                        chunks
                                    };
                                    match chunks {
                                        Some(packet) => {
                                            for chunk in packet.chunks {
                                                writer.forward(chunk).await?;
                                            }
                                            session.state.lock().forwarding = None;
                                            packet.forwarded.cancel();
                                        }
                                        None => session.ready.notified().await,
                                    }
                                }
                                #[allow(unreachable_code)]
                                Ok::<_, io::Error>(())
                            };
                            tokio::select! {
                                _ = session.cancel.cancelled() => {},
                                _ = work => { session.cancel.cancel(); }
                            }
                        });
                    }
                    session.ready.notify_one();
                    let downloaded = session.state.lock().downloaded;
                    Ok(downloaded.then_some(forwarded))
                };
                let work = async {
                    if let Some(forwarded) = ingest.await? {
                        session
                            .activity
                            .idle(tokio::time::Instant::now(), timeout, forwarded.cancelled())
                            .await
                            .map_err(|_| StatusCode::REQUEST_TIMEOUT)?;
                    }
                    Ok((Body::Empty, false))
                };
                tokio::select! {
                    result = work => result,
                    _ = session.cancel.cancelled() => Err(StatusCode::SERVICE_UNAVAILABLE),
                }
            }
        }
    }

    async fn handle(self: &Arc<Self>, request: Request<()>, body: Reader) -> Response<Body> {
        let result = self.dispatch(&request, body).await;
        let mut response = match result {
            Ok((body, downstream)) => self.response(StatusCode::OK, body, downstream),
            Err(StatusCode::NOT_FOUND) => {
                return Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::Empty)
                    .unwrap();
            }
            Err(status) => {
                log::debug!("XHTTP request {} rejected: {status}", request.uri().path());
                if status != StatusCode::CONFLICT
                    && let Ok(Kind::Packet(id, _)) =
                        wire::classify(&self.config, &self.path, &request)
                {
                    self.close(&id);
                }
                self.response(status, Body::Empty, false)
            }
        };
        if let Some(origin) = request
            .headers()
            .get("origin")
            .filter(|value| !value.is_empty())
        {
            response
                .headers_mut()
                .insert("access-control-allow-origin", origin.clone());
        }
        if request.method() == http::Method::OPTIONS {
            for (requested, allowed) in [
                (
                    "access-control-request-method",
                    "access-control-allow-methods",
                ),
                (
                    "access-control-request-headers",
                    "access-control-allow-headers",
                ),
            ] {
                response.headers_mut().insert(
                    allowed,
                    request
                        .headers()
                        .get(requested)
                        .filter(|value| !value.is_empty())
                        .cloned()
                        .unwrap_or(http::HeaderValue::from_static("*")),
                );
            }
        }
        response
    }

    async fn serve_h1(
        self: Arc<Self>,
        stream: Box<dyn AsyncStream>,
        deadline: tokio::time::Instant,
    ) -> io::Result<()> {
        let header_limit = self.config.header_limit();
        let first_header = Arc::new(Notify::new());
        let received_header = first_header.clone();
        let service = hyper::service::service_fn(move |request: Request<hyper::body::Incoming>| {
            received_header.notify_one();
            let state = self.clone();
            async move {
                let (parts, body) = request.into_parts();
                let request = Request::from_parts(parts, ());
                let streaming_upload = matches!(
                    wire::classify(&state.config, &state.path, &request),
                    Ok(Kind::One | Kind::Upload(_))
                );
                let (writer, reader) = pipe(Memory::new(
                    state.memory.clone(),
                    state.config.limits.max_session_buffered_bytes,
                ));
                let tasks = Arc::new(Tasks::new());
                let eof = CancellationToken::new();
                tasks.spawn(carrier::receive_hyper(body, writer, Some(eof.clone())));
                let response = state.handle(request, reader).await;
                if streaming_upload && response.status() == StatusCode::OK {
                    return Ok::<_, io::Error>(response.map(|body| body.with_guard(tasks)));
                }
                let mut response = response;
                if !eof.is_cancelled() {
                    response
                        .headers_mut()
                        .insert("connection", http::HeaderValue::from_static("close"));
                }
                Ok(response)
            }
        });
        let mut builder = hyper::server::conn::http1::Builder::new();
        builder
            .max_buf_size(header_limit.max(8192))
            .timer(hyper_util::rt::TokioTimer::new())
            // Hyper starts this timer while idle, not at the first header byte.
            .header_read_timeout(None);
        let connection = builder.serve_connection(hyper_util::rt::TokioIo::new(stream), service);
        tokio::pin!(connection);
        tokio::select! {
            result = &mut connection => return result.map_err(io::Error::other),
            result = tokio::time::timeout_at(deadline, first_header.notified()) => { result?; }
        }
        connection.await.map_err(io::Error::other)
    }

    async fn serve_h2(
        self: Arc<Self>,
        stream: Box<dyn AsyncStream>,
        deadline: tokio::time::Instant,
    ) -> io::Result<()> {
        let mut connection = tokio::time::timeout_at(
            deadline,
            h2::server::Builder::new()
                .max_header_list_size(self.config.header_limit().min(u32::MAX as usize) as u32)
                .max_concurrent_streams(self.config.limits.request_limit() as u32)
                .initial_window_size(256 * 1024)
                .initial_connection_window_size(256 * 1024)
                .handshake(stream),
        )
        .await?
        .map_err(io::Error::other)?;
        let mut requests = tokio::task::JoinSet::new();
        loop {
            let request = tokio::select! {
                request = connection.accept() => request,
                _ = requests.join_next(), if !requests.is_empty() => continue,
            };
            let Some(request) = request else {
                return Ok(());
            };
            let (request, mut respond) = request.map_err(io::Error::other)?;
            while requests.try_join_next().is_some() {}
            if requests.len() >= self.config.limits.request_limit() {
                respond.send_reset(h2::Reason::REFUSED_STREAM);
                continue;
            }
            let state = self.clone();
            requests.spawn(async move {
                let (parts, body) = request.into_parts();
                let request = Request::from_parts(parts, ());
                let streaming_upload = matches!(
                    wire::classify(&state.config, &state.path, &request),
                    Ok(Kind::One | Kind::Upload(_))
                );
                let (writer, reader) = pipe(Memory::new(
                    state.memory.clone(),
                    state.config.limits.max_session_buffered_bytes,
                ));
                let tasks = Tasks::new();
                let upload_closed = writer.closed();
                tasks.spawn(carrier::receive_h2(body, writer));
                let response = state.handle(request, reader).await;
                let keep_upload = streaming_upload && response.status() == StatusCode::OK;
                let (parts, body) = response.into_parts();
                if let Ok(send) = respond.send_response(Response::from_parts(parts, ()), false)
                    && carrier::send_h2(body, send).await.is_ok()
                    && keep_upload
                {
                    tokio::select! {
                        _ = tasks.wait() => {},
                        _ = upload_closed => {},
                    }
                }
            });
        }
    }
}
