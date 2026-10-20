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
    use crate::config::xhttp::XhttpLimits;
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
        service_with_limits(XhttpLimits {
            max_sessions: Some(2),
            max_pending_sessions: Some(2),
            max_requests: Some(4096),
            max_buffered_bytes: Some(1024),
            ..XhttpLimits::default()
        })
    }

    fn service_with_limits(limits: XhttpLimits) -> Arc<State> {
        let config: XhttpServerConfig = serde_json::from_value(json!({
            "path": "/t", "sc_max_buffered_posts": 2, "sc_max_each_post_bytes": 16,
            "limits": limits, "protocol": {"type": "socks"}
        }))
        .unwrap();
        Arc::new(State {
            path: Path::new(&config.path).unwrap(),
            inner: Arc::new(Echo),
            resolver: Arc::new(crate::resolver::NativeResolver::new()),
            memory: Arc::new(Budget::new(config.limits.max_buffered_bytes)),
            admission: Arc::new(Budget::new(config.limits.max_sessions)),
            pending: Arc::new(Budget::new(config.limits.max_pending_sessions)),
            requests: Arc::new(Budget::new(config.limits.max_requests)),
            sessions: parking_lot::Mutex::new(HashMap::new()),
            tasks: Tasks::new(),
            config,
        })
    }

    #[tokio::test(start_paused = true)]
    async fn unlimited_defaults_admit_past_old_caps_and_reap_orphans() {
        let state = service_with_limits(XhttpLimits::default());
        for id in 0..1025 {
            state.session(&id.to_string()).unwrap();
        }
        assert_eq!(state.admission.snapshot().active, 1025);
        assert_eq!(state.pending.snapshot().active, 1025);
        let requests = state.requests.acquire(4097).unwrap();
        let bytes = state.memory.acquire(64 * 1024 * 1024 + 1).unwrap();
        let session = state.session("0").unwrap();
        let session_bytes = session
            .memory
            .reserve_packet(4 * 1024 * 1024 + 1, 0)
            .unwrap();
        let packets: Vec<_> = (0..129)
            .map(|_| PacketRequest::new(session.clone(), 1).unwrap())
            .collect();
        assert_eq!(session.packet_requests.snapshot().active, 129);
        drop((requests, bytes, session_bytes, packets));
        assert_eq!(state.requests.snapshot().active, 0);
        assert_eq!(state.memory.snapshot().active, 0);
        assert_eq!(session.packet_requests.snapshot().active, 0);
        tokio::time::advance(Duration::from_secs(31)).await;
        state.reap();
        assert_eq!(state.admission.snapshot().active, 0);
        assert_eq!(state.pending.snapshot().active, 0);
        tokio::time::advance(Duration::from_secs(31)).await;
        state.reap();
        assert!(state.sessions.lock().is_empty());
    }

    #[tokio::test]
    async fn explicit_session_caps_remain_independent() {
        for pending in [false, true] {
            let state = service_with_limits(XhttpLimits {
                max_sessions: (!pending).then_some(2),
                max_pending_sessions: pending.then_some(2),
                ..XhttpLimits::default()
            });
            let first = state.session("a").unwrap();
            state.session("b").unwrap();
            assert!(matches!(
                state.session("c"),
                Err(StatusCode::SERVICE_UNAVAILABLE)
            ));
            let (_reader, _permit) = first.claim_download().unwrap();
            if pending {
                state.session("c").unwrap();
            } else {
                assert!(matches!(
                    state.session("c"),
                    Err(StatusCode::SERVICE_UNAVAILABLE)
                ));
                state.close("a");
                state.session("c").unwrap();
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn pending_session_permits_follow_attachment_rejection_and_expiry() {
        let state = service_with_limits(XhttpLimits {
            max_sessions: Some(2),
            max_pending_sessions: Some(1),
            ..XhttpLimits::default()
        });
        let first = state.session("a").unwrap();
        assert!(state.session("b").is_err());
        assert_eq!(state.pending.snapshot().active, 1);
        assert_eq!(state.admission.snapshot().active, 1);
        let (_reader, _permit) = first.claim_download().unwrap();
        assert_eq!(state.pending.snapshot().active, 0);
        assert!(first.claim_download().is_err());
        let second = state.session("b").unwrap();
        assert!(state.session("c").is_err());
        assert_eq!(state.pending.snapshot().active, 1);
        state.close("a");
        assert_eq!(state.pending.snapshot().active, 1);
        state.close("b");
        assert!(second.claim_download().is_err());
        assert_eq!(state.pending.snapshot().active, 0);
        state.session("c").unwrap();
        tokio::time::advance(Duration::from_secs(31)).await;
        state.reap();
        assert_eq!(state.pending.snapshot().active, 0);
        assert_eq!(state.admission.snapshot().active, 0);
        state.session("d").unwrap();
    }

    #[tokio::test]
    async fn global_request_cap_derives_per_session_admission() {
        let state = service_with_limits(XhttpLimits {
            max_requests: Some(4096),
            ..XhttpLimits::default()
        });
        let session = state.session("a").unwrap();
        let mut packets = Vec::new();
        for _ in 0..127 {
            packets.push(PacketRequest::new(session.clone(), 1).unwrap());
        }
        assert!(matches!(
            PacketRequest::new(session.clone(), 1),
            Err(Rejection::Full)
        ));
        packets.push(PacketRequest::new(session.clone(), 0).unwrap());
        let other = state.session("b").unwrap();
        let _other_packet = PacketRequest::new(other, 0).unwrap();
        drop(packets);
        assert_eq!(session.packet_requests.snapshot().active, 0);
        assert_eq!(session.head_request.snapshot().active, 0);
    }

    async fn deferred_packet(state: Arc<State>, sequence: u64, data: Vec<u8>) -> StatusCode {
        let request = Request::post(format!("http://localhost/t/a/{sequence}"))
            .header("referer", format!("/?x_padding={}", "X".repeat(100)))
            .header("content-length", data.len())
            .body(())
            .unwrap();
        let (mut writer, mut reader) = pipe(state.new_memory());
        let ready = reader.defer();
        let pump = tokio::spawn(async move {
            if ready.await.is_ok() {
                let _ = writer.write_all(&data).await;
                let _ = writer.shutdown().await;
            }
        });
        let status = state.handle(request, reader).await.status();
        pump.abort();
        status
    }

    #[tokio::test]
    async fn global_only_byte_cap_preserves_reordered_headroom() {
        let mut state = service_with_limits(XhttpLimits {
            max_buffered_bytes: Some(48),
            ..XhttpLimits::default()
        });
        Arc::get_mut(&mut state)
            .unwrap()
            .config
            .sc_max_buffered_posts = 4;
        let session = state.session("a").unwrap();
        let (mut reader, _permit) = session.claim_download().unwrap();
        let mut posts = tokio::task::JoinSet::new();
        for sequence in [1, 2, 3] {
            posts.spawn(deferred_packet(
                state.clone(),
                sequence,
                vec![sequence as u8; 16],
            ));
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    {
                        let state = session.state.lock();
                        if state.receiving.contains_key(&sequence)
                            || state.pending.contains_key(&sequence)
                        {
                            break;
                        }
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
        posts.spawn(deferred_packet(state.clone(), 0, vec![0; 16]));
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut data = [0; 64];
            reader.read_exact(&mut data).await.unwrap();
            for (sequence, packet) in data.chunks(16).enumerate() {
                assert_eq!(packet, [sequence as u8; 16]);
            }
            while let Some(status) = posts.join_next().await {
                assert_eq!(status.unwrap(), StatusCode::OK);
            }
        })
        .await
        .expect("reordered uploads must progress under a global-only byte cap");
        state.close("a");
        drop(reader);
        assert_eq!(state.memory.snapshot().active, 0);
    }

    #[tokio::test]
    async fn global_only_byte_cap_recovers_after_destination_stall() {
        let mut state = service_with_limits(XhttpLimits {
            max_buffered_bytes: Some(8 * 1024 * 1024),
            ..XhttpLimits::default()
        });
        let config = &mut Arc::get_mut(&mut state).unwrap().config;
        config.sc_max_each_post_bytes = crate::config::xhttp::XhttpRange::Number(1_000_000);
        config.sc_max_buffered_posts = 30;
        let session = state.session("a").unwrap();
        let (mut reader, _permit) = session.claim_download().unwrap();
        let mut posts = tokio::task::JoinSet::new();
        for sequence in 0..38 {
            posts.spawn(deferred_packet(
                state.clone(),
                sequence,
                vec![sequence as u8; 1_000_000],
            ));
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut data = vec![0; 1_000_000];
            for sequence in 0..38 {
                reader.read_exact(&mut data).await.unwrap();
                assert!(data.iter().all(|byte| *byte == sequence));
            }
            while let Some(status) = posts.join_next().await {
                assert_eq!(status.unwrap(), StatusCode::OK);
            }
        })
        .await
        .expect("uploads must resume under a global-only byte cap");
        state.close("a");
        drop(reader);
        assert_eq!(state.memory.snapshot().active, 0);
    }

    #[tokio::test]
    async fn default_h2_connection_admits_250_live_requests() {
        let state = service_with_limits(XhttpLimits::default());
        let (client, server) = tokio::io::duplex(65536);
        let tasks = Tasks::new();
        let server_state = state.clone();
        tasks.spawn(async move {
            server_state
                .serve_h2(
                    Box::new(server),
                    tokio::time::Instant::now() + Duration::from_secs(4),
                )
                .await
                .unwrap();
        });
        let (mut sender, connection) = h2::client::handshake(client).await.unwrap();
        tasks.spawn(async move {
            connection.await.unwrap();
        });
        let mut downloads = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), async {
            for id in 0..250 {
                sender = sender.clone().ready().await.unwrap();
                let request = Request::get(format!("https://localhost/t/{id}"))
                    .header("referer", format!("/?x_padding={}", "X".repeat(100)))
                    .body(())
                    .unwrap();
                let (response, send) = sender.send_request(request, true).unwrap();
                let response = response.await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                downloads.push((send, response.into_body()));
            }
        })
        .await
        .unwrap();
        assert_eq!(sender.current_max_send_streams(), 250);
        assert_eq!(state.requests.snapshot().active, 250);
        assert_eq!(state.admission.snapshot().active, 250);
        for (mut send, _) in downloads {
            send.send_reset(h2::Reason::CANCEL);
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while state.requests.snapshot().active != 0 || state.admission.snapshot().active != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
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

    #[tokio::test]
    async fn download_pipe_can_write_before_reading_a_full_packet() {
        let mut state = inactivity_service(16);
        Arc::get_mut(&mut state).unwrap().inner = Arc::new(CloseDownload { keep_upload: true });
        assert_eq!(
            request(&state, "POST", "a/0", b"0123456789abcdef")
                .await
                .status(),
            StatusCode::OK
        );
        let response = request(&state, "GET", "a", b"").await;
        let data = tokio::time::timeout(Duration::from_secs(1), response.into_body().collect())
            .await
            .expect("download must not wait for packet memory")
            .unwrap()
            .to_bytes();
        assert_eq!(data, b"bye".as_slice());
        drop(data);
        tokio::task::yield_now().await;
        assert_eq!(state.admission.snapshot().active, 0);
        assert_eq!(state.memory.snapshot().active, 0);
    }

    #[derive(Debug)]
    struct DrainUpload;

    #[async_trait]
    impl TcpServerHandler for DrainUpload {
        async fn setup_server_stream(
            &self,
            mut stream: Box<dyn AsyncStream>,
        ) -> io::Result<TcpServerSetupResult> {
            Ok(TcpServerSetupResult::Session(Box::pin(async move {
                let mut data = Vec::new();
                stream.read_to_end(&mut data).await.unwrap();
                assert_eq!(data, vec![42; 16384]);
                stream.write_all(b"ok").await.unwrap();
                stream.shutdown().await.unwrap();
            })))
        }
    }

    #[tokio::test]
    async fn stream_upload_forwards_without_reserving_global_bytes_twice() {
        let mut state = inactivity_service(16384);
        let inner = Arc::get_mut(&mut state).unwrap();
        inner.inner = Arc::new(DrainUpload);
        inner.memory = Arc::new(Budget::new(Some(16384)));
        inner.config.limits.max_buffered_bytes = Some(16384);
        inner.config.sc_stream_up_server_secs = crate::config::xhttp::XhttpRange::Number(-1);
        let (mut writer, body) = pipe(state.new_memory());
        writer.write_all(&[42; 16384]).await.unwrap();
        writer.shutdown().await.unwrap();
        assert_eq!(state.memory.snapshot().active, 16384);
        let upload = Request::post("http://localhost/t/a")
            .header("referer", format!("/?x_padding={}", "X".repeat(100)))
            .body(())
            .unwrap();
        let upload = state.handle(upload, body).await;
        assert_eq!(upload.status(), StatusCode::OK);
        let download = request(&state, "GET", "a", b"").await;
        let data = tokio::time::timeout(Duration::from_secs(1), download.into_body().collect())
            .await
            .expect("stream upload must transfer its existing byte permits")
            .unwrap()
            .to_bytes();
        assert_eq!(data, b"ok".as_slice());
        drop(data);
        upload.into_body().collect().await.unwrap();
        tokio::task::yield_now().await;
        assert_eq!(state.admission.snapshot().active, 0);
        assert_eq!(state.memory.snapshot().active, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn download_eof_allows_bounded_late_stream_upload_attachment() {
        use crate::config::xhttp::{XhttpMode, XhttpRange};

        for mode in [XhttpMode::Auto, XhttpMode::StreamUp] {
            for attach in [false, true] {
                let mut state = service();
                let inner = Arc::get_mut(&mut state).unwrap();
                inner.inner = Arc::new(CloseDownload { keep_upload: true });
                inner.config.mode = mode;
                inner.config.sc_stream_up_server_secs = XhttpRange::Number(-1);
                let session = state.session("a").unwrap();
                let response = request(&state, "GET", "a", b"").await;
                let data = response.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(data, b"bye".as_slice());
                drop(data);
                assert!(!session.cancel.is_cancelled());
                assert_eq!(state.admission.snapshot().active, 1);
                assert_eq!(
                    request(&state, "POST", "a/0", b"").await.status(),
                    if mode == XhttpMode::Auto {
                        StatusCode::CONFLICT
                    } else {
                        StatusCode::BAD_REQUEST
                    }
                );
                tokio::time::advance(Duration::from_secs(29)).await;
                state.reap();
                assert!(!session.cancel.is_cancelled());
                if attach {
                    let response = request(&state, "POST", "a", b"tail").await;
                    assert_eq!(response.status(), StatusCode::OK);
                    response.into_body().collect().await.unwrap();
                    tokio::task::yield_now().await;
                } else {
                    tokio::time::advance(Duration::from_secs(1)).await;
                    assert!(matches!(
                        session.claim_stream_upload(),
                        Err(StatusCode::CONFLICT)
                    ));
                    state.reap();
                }
                assert!(session.cancel.is_cancelled());
                assert_eq!(state.admission.snapshot().active, 0);
                assert_eq!(state.memory.snapshot().active, 0);
            }
        }
    }

    async fn streaming_carrier(
        state: Arc<State>,
        version: XhttpVersion,
    ) -> (Arc<carrier::Carrier>, Tasks, Option<quinn::Endpoint>) {
        streaming_carrier_with_h3_limit(state, version, 1).await
    }

    async fn streaming_carrier_with_h3_limit(
        state: Arc<State>,
        version: XhttpVersion,
        h3_limit: u32,
    ) -> (Arc<carrier::Carrier>, Tasks, Option<quinn::Endpoint>) {
        let tasks = Tasks::new();
        if version != XhttpVersion::H3 {
            let (client, server) = tokio::io::duplex(8192);
            tasks.spawn(async move {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
                let _ = if version == XhttpVersion::H1 {
                    state.serve_h1(Box::new(server), deadline).await
                } else {
                    state.serve_h2(Box::new(server), deadline).await
                };
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
            .max_concurrent_bidi_streams(h3_limit.into());
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
            let memory = Memory::new(Arc::new(Budget::new(Some(1024))), Some(1024));
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
                let memory = Memory::new(Arc::new(Budget::new(Some(1024))), Some(1024));
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
                let result =
                    tokio::time::timeout(Duration::from_secs(1), response.read_to_end(&mut data))
                        .await
                        .unwrap();
                assert!(data.is_empty());
                if version == XhttpVersion::H2 {
                    result.unwrap();
                    tokio::time::timeout(Duration::from_secs(1), upload.wait())
                        .await
                        .unwrap();
                    assert!(!upload.cancel.is_cancelled());
                } else {
                    // H3's idle sender observes STOP_SENDING on its ten-second probe.
                    tokio::time::timeout(Duration::from_secs(12), upload.cancel.cancelled())
                        .await
                        .unwrap();
                }
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
        let (mut writer, body) = pipe(Memory::new(state.memory.clone(), Some(1024)));
        writer.write_all(data).await.unwrap();
        writer.shutdown().await.unwrap();
        state.handle(request, body).await
    }

    fn inactivity_service(budget: usize) -> Arc<State> {
        let mut state = service();
        let config = &mut Arc::get_mut(&mut state).unwrap().config;
        config.limits.packet_timeout_secs = 10;
        config.limits.max_session_buffered_bytes = Some(budget);
        config.sc_max_buffered_posts = 8;
        state
    }

    fn attached_reader(state: &Arc<State>, id: &str) -> Reader {
        let session = state.session(id).unwrap();
        session.claim_download().unwrap().0
    }

    fn open_post(
        state: &Arc<State>,
        suffix: &str,
    ) -> (Writer, tokio::task::JoinHandle<StatusCode>) {
        let post = Request::post(format!("http://localhost/t/{suffix}"))
            .header("referer", format!("/?x_padding={}", "X".repeat(100)))
            .body(())
            .unwrap();
        let (writer, body) = pipe(Memory::new(state.memory.clone(), Some(1024)));
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
    async fn queued_packets_ack_before_forwarding_and_full_queue_waits_for_consumption() {
        let state = inactivity_service(64);
        let mut reader = attached_reader(&state, "a");
        for sequence in 0..8 {
            assert_eq!(
                request(&state, "POST", &format!("a/{sequence}"), b"12345678")
                    .await
                    .status(),
                StatusCode::OK
            );
        }
        let (mut fifth, fifth_post) = open_post(&state, "a/8");
        fifth.write_all(b"fifth").await.unwrap();
        fifth.shutdown().await.unwrap();
        let (mut sixth, sixth_post) = open_post(&state, "a/9");
        sixth.write_all(b"sixth").await.unwrap();
        sixth.shutdown().await.unwrap();
        tokio::task::yield_now().await;
        for _ in 0..16 {
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
    async fn unknown_paths_close_only_http1_carriers() {
        tokio::time::timeout(Duration::from_secs(10), async {
            for version in [XhttpVersion::H1, XhttpVersion::H2, XhttpVersion::H3] {
                for method in ["OPTIONS", "GET", "POST"] {
                    for path in ["/wrong", "/%FF/t/"] {
                        let mut state = service();
                        let config = &mut Arc::get_mut(&mut state).unwrap().config;
                        config.close_on_http1_error = true;
                        config.matching_headers = [("X-Token".into(), "secret".into())].into();
                        let (carrier, server, _endpoint) =
                            streaming_carrier_with_h3_limit(state.clone(), version, 2).await;
                        let memory = Memory::new(Arc::new(Budget::new(Some(1024))), Some(1024));
                        let tasks = Tasks::new();
                        let valid = || {
                            Request::builder()
                                .method("OPTIONS")
                                .uri("https://localhost/t/")
                                .header("x-token", "secret")
                                .body(Body::Empty)
                                .unwrap()
                        };
                        let response = carrier
                            .request(valid(), memory.clone(), &tasks, Duration::from_secs(1))
                            .await
                            .unwrap();
                        assert_eq!(response.status(), StatusCode::OK);
                        response
                            .into_body()
                            .read_to_end(&mut Vec::new())
                            .await
                            .unwrap();

                        let mut invalid = Request::builder()
                            .method(method)
                            .uri(format!("https://localhost{path}"))
                            .header("x-token", "secret")
                            .header("referer", format!("/?x_padding={}", "X".repeat(100)));
                        let (_writer, body) = pipe(memory.clone());
                        let body = if method == "POST" {
                            invalid = invalid.header("content-length", "16");
                            Body::stream(body)
                        } else {
                            Body::Empty
                        };
                        let result = carrier
                            .request(
                                invalid.body(body).unwrap(),
                                memory.clone(),
                                &tasks,
                                Duration::from_secs(1),
                            )
                            .await;
                        if version == XhttpVersion::H1 {
                            match result {
                                Ok(response) => panic!(
                                    "{version:?} {method}: unexpected HTTP {}",
                                    response.status()
                                ),
                                Err(error) => assert_ne!(error.kind(), io::ErrorKind::TimedOut),
                            }
                            while !carrier.closed() || state.requests.snapshot().active != 0 {
                                tokio::task::yield_now().await;
                            }
                            server.wait().await;
                        } else {
                            let response = result.unwrap();
                            assert_eq!(response.status(), StatusCode::NOT_FOUND);
                            assert!(!response.headers().contains_key("x-padding"));
                            assert!(
                                !response
                                    .headers()
                                    .contains_key("access-control-allow-origin")
                            );
                            assert_eq!(
                                response
                                    .into_body()
                                    .read_to_end(&mut Vec::new())
                                    .await
                                    .unwrap(),
                                0
                            );
                            assert!(!carrier.closed());
                            let next = Tasks::new();
                            let response = carrier
                                .request(valid(), memory, &next, Duration::from_secs(1))
                                .await
                                .unwrap();
                            assert_eq!(response.status(), StatusCode::OK);
                        }
                        assert!(state.sessions.lock().is_empty());
                        assert_eq!(state.admission.snapshot().peak, 0);
                        assert_eq!(state.memory.snapshot().peak, 0);
                    }
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn header_rejections_are_silent_only_on_http1_when_enabled() {
        tokio::time::timeout(Duration::from_secs(15), async {
            for version in [XhttpVersion::H1, XhttpVersion::H2, XhttpVersion::H3] {
                for close_on_http1_error in [false, true] {
                    let silently_closes = version == XhttpVersion::H1 && close_on_http1_error;
                    for method in ["OPTIONS", "GET", "POST"] {
                        for values in [vec![], vec!["wrong"], vec!["secret", "secret"]] {
                            let mut state = service();
                            let config = &mut Arc::get_mut(&mut state).unwrap().config;
                            config.close_on_http1_error = close_on_http1_error;
                            config.matching_headers = [("x-token".into(), "secret".into())].into();
                            // The unfinished rejected upload still occupies a QUIC stream
                            // until the client observes STOP_SENDING on its idle probe.
                            let (carrier, _server, _endpoint) =
                                streaming_carrier_with_h3_limit(state.clone(), version, 2).await;
                            let memory = Memory::new(Arc::new(Budget::new(Some(1024))), Some(1024));
                            let tasks = Tasks::new();
                            let mut request = Request::builder()
                                .method(method)
                                .uri("https://localhost/t/session/0")
                                .header("origin", "https://probe.test");
                            for value in values {
                                request = request.header("x-token", value);
                            }
                            let (_writer, body) = pipe(memory.clone());
                            let body = if method == "POST" {
                                request = request.header("content-length", "16");
                                Body::stream(body)
                            } else {
                                Body::Empty
                            };
                            let result = carrier
                                .request(
                                    request.body(body).unwrap(),
                                    memory.clone(),
                                    &tasks,
                                    Duration::from_secs(1),
                                )
                                .await;
                            if silently_closes {
                                match result {
                                    Ok(response) => panic!("unexpected HTTP {}", response.status()),
                                    Err(error) => assert_ne!(error.kind(), io::ErrorKind::TimedOut),
                                }
                                while !carrier.closed() || state.requests.snapshot().active != 0 {
                                    tokio::task::yield_now().await;
                                }
                            } else {
                                let response = result.unwrap();
                                assert_eq!(response.status(), StatusCode::NOT_FOUND);
                                for name in [
                                    "access-control-allow-origin",
                                    "access-control-allow-methods",
                                    "access-control-allow-headers",
                                    "content-type",
                                    "x-padding",
                                    "x-accel-buffering",
                                    "cache-control",
                                ] {
                                    assert!(!response.headers().contains_key(name), "{name}");
                                }
                                assert_eq!(
                                    response
                                        .into_body()
                                        .read_to_end(&mut Vec::new())
                                        .await
                                        .unwrap(),
                                    0
                                );
                            }
                            assert!(state.sessions.lock().is_empty());
                            assert_eq!(state.admission.snapshot().peak, 0);
                            assert_eq!(state.memory.snapshot().peak, 0);
                            if !silently_closes && (version != XhttpVersion::H1 || method != "POST")
                            {
                                let next = Tasks::new();
                                let valid = Request::builder()
                                    .method("OPTIONS")
                                    .uri("https://localhost/t/")
                                    .header("x-token", "secret")
                                    .body(Body::Empty)
                                    .unwrap();
                                let response = carrier
                                    .request(valid, memory, &next, Duration::from_secs(1))
                                    .await
                                    .unwrap();
                                assert_eq!(response.status(), StatusCode::OK);
                            }
                        }
                    }
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn header_rejection_precedes_body_polling_and_session_admission() {
        let mut state = service();
        Arc::get_mut(&mut state).unwrap().config.matching_headers =
            [("x-token".into(), "secret".into())].into();
        let _admission = state.admission.acquire(2).unwrap();
        for values in [vec![], vec!["wrong"], vec!["secret", "secret"]] {
            let mut request = Request::post("https://localhost/t/session/0")
                .header("referer", format!("/?x_padding={}", "X".repeat(100)))
                .header("content-length", "16");
            for value in values {
                request = request.header("x-token", value);
            }
            let (_writer, mut body) = pipe(state.new_memory());
            let started = body.defer();
            let response = tokio::time::timeout(
                Duration::from_secs(1),
                state.handle(request.body(()).unwrap(), body),
            )
            .await
            .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert!(response.headers().is_empty());
            assert!(started.await.is_err());
            assert!(state.sessions.lock().is_empty());
            assert_eq!(state.admission.snapshot().active, 2);
            assert_eq!(state.memory.snapshot().peak, 0);
        }
    }

    #[tokio::test]
    async fn rejected_requests_preserve_h2_h3_sibling_downloads() {
        enum Case {
            MissingHeader,
            WrongHeader,
            DuplicateHeader,
            MalformedSuffix,
            UnmatchedPath,
        }

        tokio::time::timeout(Duration::from_secs(10), async {
            for version in [XhttpVersion::H2, XhttpVersion::H3] {
                for case in [
                    Case::MissingHeader,
                    Case::WrongHeader,
                    Case::DuplicateHeader,
                    Case::MalformedSuffix,
                    Case::UnmatchedPath,
                ] {
                    let mut state = service();
                    let service = Arc::get_mut(&mut state).unwrap();
                    service.config.close_on_http1_error = true;
                    service.config.matching_headers = [("x-token".into(), "secret".into())].into();
                    service.config.limits.max_requests_per_session = Some(2);
                    let (carrier, _server, _endpoint) =
                        streaming_carrier_with_h3_limit(state.clone(), version, 2).await;
                    let memory = Memory::new(Arc::new(Budget::new(Some(1024))), Some(1024));
                    let tasks = Tasks::new();
                    let make = |method: &str, path: &str| {
                        Request::builder()
                            .method(method)
                            .uri(format!("https://localhost{path}"))
                            .header("x-token", "secret")
                            .header("referer", format!("/?x_padding={}", "X".repeat(100)))
                    };
                    let packet = make("POST", "/t/session/1")
                        .header("content-length", "4")
                        .body(Body::Chunks([Bytes::from_static(b"held")].into()))
                        .unwrap();
                    let response = carrier
                        .request(packet, memory.clone(), &tasks, Duration::from_secs(1))
                        .await
                        .unwrap();
                    assert_eq!(response.status(), StatusCode::OK);
                    response
                        .into_body()
                        .read_to_end(&mut Vec::new())
                        .await
                        .unwrap();
                    let response = carrier
                        .request(
                            make("GET", "/t/session").body(Body::Empty).unwrap(),
                            memory.clone(),
                            &tasks,
                            Duration::from_secs(1),
                        )
                        .await
                        .unwrap();
                    assert_eq!(response.status(), StatusCode::OK);
                    let mut download = response.into_body();
                    assert_eq!(state.requests.snapshot().active, 1);
                    assert_eq!(state.admission.snapshot().active, 1);
                    assert_eq!(state.memory.snapshot().active, 4);

                    let invalid = match case {
                        Case::MissingHeader => Request::get("https://localhost/t/session/0"),
                        Case::WrongHeader => {
                            Request::get("https://localhost/t/session/0").header("x-token", "wrong")
                        }
                        Case::DuplicateHeader => {
                            make("GET", "/t/session/0").header("x-token", "secret")
                        }
                        Case::MalformedSuffix => make("GET", "/t/%FF"),
                        Case::UnmatchedPath => make("GET", "/wrong"),
                    };
                    let response = carrier
                        .request(
                            invalid.body(Body::Empty).unwrap(),
                            memory.clone(),
                            &tasks,
                            Duration::from_secs(1),
                        )
                        .await
                        .unwrap();
                    assert_eq!(response.status(), StatusCode::NOT_FOUND);
                    assert!(
                        !response
                            .headers()
                            .contains_key("access-control-allow-origin")
                    );
                    response
                        .into_body()
                        .read_to_end(&mut Vec::new())
                        .await
                        .unwrap();
                    let response = carrier
                        .request(
                            make("POST", "/t/session/0")
                                .body(Body::Chunks([Bytes::from_static(b"live")].into()))
                                .unwrap(),
                            memory,
                            &tasks,
                            Duration::from_secs(1),
                        )
                        .await
                        .unwrap();
                    assert_eq!(response.status(), StatusCode::OK);
                    response
                        .into_body()
                        .read_to_end(&mut Vec::new())
                        .await
                        .unwrap();
                    let mut echoed = [0; 8];
                    download.read_exact(&mut echoed).await.unwrap();
                    assert_eq!(&echoed, b"liveheld");
                    assert!(!carrier.closed());
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn session_teardown_errors_preserve_sibling_downloads_on_another_carrier() {
        tokio::time::timeout(Duration::from_secs(10), async {
            for version in [XhttpVersion::H2, XhttpVersion::H3] {
                let mut state = service();
                let config = &mut Arc::get_mut(&mut state).unwrap().config;
                config.close_on_http1_error = true;
                config.matching_headers = [("x-token".into(), "secret".into())].into();
                let (original_carrier, _original_server, _original_endpoint) =
                    streaming_carrier(state.clone(), version).await;
                let (shared_carrier, _shared_server, _shared_endpoint) =
                    streaming_carrier_with_h3_limit(state.clone(), version, 2).await;
                let memory = Memory::new(Arc::new(Budget::new(Some(1024))), Some(1024));
                let tasks = Tasks::new();
                let request = |method: &str, path: &str, data: &'static [u8]| {
                    Request::builder()
                        .method(method)
                        .uri(format!("https://localhost/t/{path}"))
                        .header("x-token", "secret")
                        .header("referer", format!("/?x_padding={}", "X".repeat(100)))
                        .body(if data.is_empty() {
                            Body::Empty
                        } else {
                            Body::Chunks([Bytes::from_static(data)].into())
                        })
                        .unwrap()
                };
                let retired = original_carrier
                    .request(
                        request("GET", "retired", b""),
                        memory.clone(),
                        &tasks,
                        Duration::from_secs(2),
                    )
                    .await
                    .unwrap();
                assert_eq!(retired.status(), StatusCode::OK);
                let healthy = shared_carrier
                    .request(
                        request("GET", "healthy", b""),
                        memory.clone(),
                        &tasks,
                        Duration::from_secs(2),
                    )
                    .await
                    .unwrap();
                assert_eq!(healthy.status(), StatusCode::OK);
                let mut download = healthy.into_body();

                let session = state.session("retired").unwrap();
                let parked = shared_carrier.request(
                    request("POST", "retired/100", b""),
                    memory.clone(),
                    &tasks,
                    Duration::from_secs(2),
                );
                tokio::pin!(parked);
                tokio::select! {
                    _ = &mut parked => panic!("far packet should wait for admission"),
                    _ = async {
                        while session.packet_requests.snapshot().active == 0 {
                            tokio::task::yield_now().await;
                        }
                    } => {},
                }
                state.close("retired");
                let response = parked.await.unwrap();
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                response
                    .into_body()
                    .read_to_end(&mut Vec::new())
                    .await
                    .unwrap();
                drop(retired);

                let late = shared_carrier
                    .request(
                        request("POST", "retired/0", b"late"),
                        memory.clone(),
                        &tasks,
                        Duration::from_secs(2),
                    )
                    .await
                    .unwrap();
                assert_eq!(late.status(), StatusCode::CONFLICT);
                late.into_body().read_to_end(&mut Vec::new()).await.unwrap();
                let response = shared_carrier
                    .request(
                        request("POST", "healthy/0", b"alive"),
                        memory.clone(),
                        &tasks,
                        Duration::from_secs(2),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                response
                    .into_body()
                    .read_to_end(&mut Vec::new())
                    .await
                    .unwrap();
                let mut echoed = [0; 5];
                download.read_exact(&mut echoed).await.unwrap();
                assert_eq!(&echoed, b"alive");
                assert!(!shared_carrier.closed());
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn default_bad_requests_and_path_misses_return_plain_http_errors() {
        tokio::time::timeout(Duration::from_secs(10), async {
            for version in [XhttpVersion::H1, XhttpVersion::H2, XhttpVersion::H3] {
                for (path, status) in [
                    ("/wrong", StatusCode::NOT_FOUND),
                    ("/t/session", StatusCode::BAD_REQUEST),
                ] {
                    let (carrier, _server, _endpoint) = streaming_carrier(service(), version).await;
                    let memory = Memory::new(Arc::new(Budget::new(Some(1024))), Some(1024));
                    let tasks = Tasks::new();
                    let request = Request::get(format!("https://localhost{path}"))
                        .header("origin", "https://probe.test")
                        .body(Body::Empty)
                        .unwrap();
                    let response = carrier
                        .request(request, memory.clone(), &tasks, Duration::from_secs(1))
                        .await
                        .unwrap();
                    assert_eq!(response.status(), status);
                    for header in [
                        "x-padding",
                        "x-accel-buffering",
                        "access-control-allow-origin",
                        "access-control-allow-methods",
                        "access-control-allow-headers",
                        "cache-control",
                        "content-type",
                    ] {
                        assert!(
                            !response.headers().contains_key(header),
                            "{version:?}: {header}"
                        );
                    }
                    let mut body = Vec::new();
                    response.into_body().read_to_end(&mut body).await.unwrap();
                    assert!(body.is_empty());
                    let response = carrier
                        .request(
                            Request::builder()
                                .method("OPTIONS")
                                .uri("https://localhost/t/")
                                .body(Body::Empty)
                                .unwrap(),
                            memory,
                            &tasks,
                            Duration::from_secs(1),
                        )
                        .await
                        .unwrap();
                    assert_eq!(response.status(), StatusCode::OK);
                    assert!(response.headers().contains_key("x-padding"));
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn known_path_errors_return_http_responses_even_when_close_on_http1_error_is_enabled() {
        tokio::time::timeout(Duration::from_secs(30), async {
            for version in [XhttpVersion::H1, XhttpVersion::H2, XhttpVersion::H3] {
                for close in [false, true] {
                    for status in [
                        StatusCode::BAD_REQUEST,
                        StatusCode::NOT_FOUND,
                        StatusCode::METHOD_NOT_ALLOWED,
                        StatusCode::REQUEST_TIMEOUT,
                        StatusCode::CONFLICT,
                        StatusCode::PAYLOAD_TOO_LARGE,
                        StatusCode::SERVICE_UNAVAILABLE,
                    ] {
                        let mut state = service();
                        let config = &mut Arc::get_mut(&mut state).unwrap().config;
                        config.close_on_http1_error = close;
                        config.host = Some("localhost".into());
                        config.limits.packet_timeout_secs = 1;
                        let admission = if status == StatusCode::SERVICE_UNAVAILABLE {
                            Some(state.admission.acquire(2).unwrap())
                        } else {
                            None
                        };
                        if status == StatusCode::CONFLICT {
                            state.session("session").unwrap();
                            state.close("session");
                        }
                        let _reader = if status == StatusCode::REQUEST_TIMEOUT {
                            Some(attached_reader(&state, "session"))
                        } else {
                            None
                        };
                        let (carrier, _server, _endpoint) =
                            streaming_carrier(state.clone(), version).await;
                        let memory = Memory::new(Arc::new(Budget::new(Some(1024))), Some(1024));
                        let tasks = Tasks::new();
                        let mut request = Request::post("https://localhost/t/session/0")
                            .header("referer", format!("/?x_padding={}", "X".repeat(100)));
                        let body = match status {
                            StatusCode::BAD_REQUEST => {
                                request = request.header("x-data-0", "!");
                                Body::Empty
                            }
                            StatusCode::NOT_FOUND => {
                                request = request.uri("https://wrong.test/t/session/0");
                                Body::Empty
                            }
                            StatusCode::METHOD_NOT_ALLOWED => {
                                request = request.method("PUT");
                                Body::Empty
                            }
                            StatusCode::REQUEST_TIMEOUT => {
                                request = request
                                    .uri("https://localhost/t/session/100")
                                    .header("content-length", "0");
                                Body::Empty
                            }
                            StatusCode::PAYLOAD_TOO_LARGE => {
                                request = request.header("content-length", "17");
                                Body::Chunks([Bytes::from_static(b"01234567890123456")].into())
                            }
                            _ => Body::Empty,
                        };
                        let response = carrier
                            .request(
                                request.body(body).unwrap(),
                                memory,
                                &tasks,
                                Duration::from_secs(3),
                            )
                            .await
                            .unwrap();
                        assert_eq!(response.status(), status, "{version:?}, close={close}");
                        response
                            .into_body()
                            .read_to_end(&mut Vec::new())
                            .await
                            .unwrap();
                        if version != XhttpVersion::H1 {
                            assert!(!carrier.closed());
                        }
                        drop(admission);
                        while state.requests.snapshot().active != 0 {
                            tokio::task::yield_now().await;
                        }
                        assert_eq!(state.admission.snapshot().active, 0);
                        assert_eq!(state.memory.snapshot().active, 0);
                    }
                }
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn http1_path_filter_preserves_known_prefixes() {
        let mut state = service();
        for close in [false, true] {
            Arc::get_mut(&mut state)
                .unwrap()
                .config
                .close_on_http1_error = close;
            for (path, known) in [
                ("/t/", true),
                ("/t/session/0", true),
                ("/%74/session/0?query=ignored", true),
                ("/t%2Fsession/0", true),
                ("/t/session/not-a-number", true),
                ("/t/%FF", true),
                ("/%74/%FF", true),
                ("/wrong", false),
                ("/t", false),
                ("/test/session", false),
                ("/%FF/t/", false),
            ] {
                let request = Request::get(format!("https://localhost{path}"))
                    .body(())
                    .unwrap();
                assert_eq!(
                    state.check_http1_request(&request).is_err(),
                    close && !known,
                    "{path}, close={close}"
                );
            }
        }
    }

    #[tokio::test]
    async fn aggregate_overflow_does_not_silently_close_known_paths() {
        tokio::time::timeout(Duration::from_secs(10), async {
            for version in [XhttpVersion::H1, XhttpVersion::H2, XhttpVersion::H3] {
                let mut state = service();
                Arc::get_mut(&mut state)
                    .unwrap()
                    .config
                    .close_on_http1_error = true;
                let held = state
                    .requests
                    .acquire(state.config.limits.max_requests.unwrap())
                    .unwrap();
                let (carrier, _server, _endpoint) = streaming_carrier(state.clone(), version).await;
                let memory = Memory::new(Arc::new(Budget::new(Some(1024))), Some(1024));
                let tasks = Tasks::new();
                let request = Request::builder()
                    .method("OPTIONS")
                    .uri("https://localhost/t/")
                    .body(Body::Empty)
                    .unwrap();
                match carrier
                    .request(request, memory.clone(), &tasks, Duration::from_secs(1))
                    .await
                {
                    Ok(response) => {
                        assert_eq!(version, XhttpVersion::H1);
                        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                    }
                    Err(error) => {
                        assert_ne!(version, XhttpVersion::H1);
                        assert_ne!(error.kind(), io::ErrorKind::TimedOut);
                    }
                }
                drop(held);
                assert!(state.sessions.lock().is_empty());
                assert_eq!(state.requests.snapshot().active, 0);
                assert_eq!(state.admission.snapshot().peak, 0);
                assert_eq!(state.memory.snapshot().peak, 0);
                if version != XhttpVersion::H1 {
                    assert!(!carrier.closed());
                    let probe = Request::builder()
                        .method("OPTIONS")
                        .uri("https://localhost/t/")
                        .body(Body::Empty)
                        .unwrap();
                    let response = carrier
                        .request(probe, memory, &tasks, Duration::from_secs(1))
                        .await
                        .unwrap();
                    assert_eq!(response.status(), StatusCode::OK);
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn h3_required_headers_preserve_carrier_when_admission_is_full() {
        tokio::time::timeout(Duration::from_secs(10), async {
            for connection_limit in [false, true] {
                for matching in [false, true] {
                    let mut state = service();
                    let service = Arc::get_mut(&mut state).unwrap();
                    service.config.matching_headers = [("x-token".into(), "secret".into())].into();
                    if connection_limit {
                        service.config.limits.max_requests_per_connection = 1;
                    } else {
                        service.requests = Arc::new(Budget::new(Some(1)));
                    }
                    assert!(!service.config.close_on_http1_error);
                    let (carrier, _server, _endpoint) =
                        streaming_carrier_with_h3_limit(state.clone(), XhttpVersion::H3, 2).await;
                    let memory = Memory::new(Arc::new(Budget::new(Some(1024))), Some(1024));
                    let tasks = Tasks::new();
                    let download = Request::get("https://localhost/t/session")
                        .header("x-token", "secret")
                        .header("referer", format!("/?x_padding={}", "X".repeat(100)))
                        .body(Body::Empty)
                        .unwrap();
                    let mut download = carrier
                        .request(download, memory.clone(), &tasks, Duration::from_secs(2))
                        .await
                        .unwrap()
                        .into_body();
                    let mut probe = Request::builder()
                        .method("OPTIONS")
                        .uri("https://localhost/t/");
                    if matching {
                        probe = probe.header("x-token", "secret");
                    }
                    assert!(
                        carrier
                            .request(
                                probe.body(Body::Empty).unwrap(),
                                memory.clone(),
                                &tasks,
                                Duration::from_secs(2)
                            )
                            .await
                            .is_err()
                    );
                    assert!(!carrier.closed());
                    assert_eq!(state.requests.snapshot().active, 1);
                    assert_eq!(state.admission.snapshot().active, 1);
                    let session = state.session("session").unwrap();
                    let mut writer = session.state.lock().writer.take().unwrap();
                    writer.write_all(b"alive").await.unwrap();
                    let mut echoed = [0; 5];
                    download.read_exact(&mut echoed).await.unwrap();
                    assert_eq!(&echoed, b"alive");
                    // Explicit teardown avoids waiting for the idle H3 cancellation probe.
                    state.close("session");
                    assert!(download.read_to_end(&mut Vec::new()).await.is_err());
                    while state.requests.snapshot().active != 0 {
                        tokio::task::yield_now().await;
                    }
                    let response = carrier
                        .request(
                            Request::builder()
                                .method("OPTIONS")
                                .uri("https://localhost/t/")
                                .header("x-token", "secret")
                                .body(Body::Empty)
                                .unwrap(),
                            memory,
                            &tasks,
                            Duration::from_secs(2),
                        )
                        .await
                        .unwrap();
                    assert_eq!(response.status(), StatusCode::OK);
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn h1_rejection_never_reads_the_body_or_discloses_xhttp_headers() {
        tokio::time::timeout(Duration::from_secs(2), async {
            for close_on_http1_error in [false, true] {
                for request_limit_reached in [false, true] {
                    for (path, token_header) in
                        [("/t/session/0", ""), ("/wrong", "X-Token: secret\r\n")]
                    {
                        let mut state = service();
                        let config = &mut Arc::get_mut(&mut state).unwrap().config;
                        config.close_on_http1_error = close_on_http1_error;
                        config.matching_headers = [("x-token".into(), "secret".into())].into();
                        let held = if request_limit_reached {
                            Some(
                                state
                                    .requests
                                    .acquire(state.config.limits.max_requests.unwrap())
                                    .unwrap(),
                            )
                        } else {
                            None
                        };
                        let (mut client, server) = tokio::io::duplex(8192);
                        let serving = state.clone().serve_h1(
                            Box::new(server),
                            tokio::time::Instant::now() + Duration::from_secs(1),
                        );
                        let probe = async {
                            let request = format!(
                                "POST {path} HTTP/1.1\r\n\
                                 Host: localhost\r\n\
                                 {token_header}Content-Length: 16\r\n\
                                 Expect: 100-continue\r\n\r\n"
                            );
                            client.write_all(request.as_bytes()).await.unwrap();
                            let mut response = Vec::new();
                            client.read_to_end(&mut response).await.unwrap();
                            if close_on_http1_error {
                                assert!(response.is_empty());
                            } else if request_limit_reached {
                                assert!(
                                    response.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n")
                                );
                            } else {
                                assert!(response.starts_with(b"HTTP/1.1 404 Not Found\r\n"));
                            }
                            let response =
                                String::from_utf8(response).unwrap().to_ascii_lowercase();
                            for forbidden in [
                                "100 continue",
                                "x-padding:",
                                "access-control-",
                                "cache-control:",
                                "x-accel-buffering:",
                            ] {
                                assert!(!response.contains(forbidden), "{forbidden}");
                            }
                        };
                        let (result, ()) = tokio::join!(serving, probe);
                        assert_eq!(result.is_err(), close_on_http1_error);
                        drop(held);
                        assert!(state.sessions.lock().is_empty());
                        assert_eq!(state.requests.snapshot().active, 0);
                        assert_eq!(state.memory.snapshot().peak, 0);
                    }
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn unmatched_requests_do_not_disclose_xhttp_headers() {
        let mut state = service();
        Arc::get_mut(&mut state).unwrap().config.host = Some("front.test".into());
        Arc::get_mut(&mut state)
            .unwrap()
            .config
            .server_max_header_bytes = 256;
        for uri in [
            "http://front.test/wrong",
            "http://wrong.test/t/session",
            "http://front.test/wrong/%FF",
            "http://front.test/%FF",
        ] {
            for oversized in [false, true] {
                let request = Request::builder()
                    .method("OPTIONS")
                    .uri(uri)
                    .header("origin", "https://probe.test")
                    .header("x-extra", "X".repeat(if oversized { 512 } else { 1 }))
                    .body(())
                    .unwrap();
                let (_, body) = pipe(Memory::new(state.memory.clone(), Some(1024)));
                let response = state.handle(request, body).await;
                assert_eq!(
                    response.status(),
                    StatusCode::NOT_FOUND,
                    "{uri}, {oversized}"
                );
                assert!(response.headers().is_empty());
            }
        }
        let request = Request::builder()
            .method("OPTIONS")
            .uri("http://front.test/t/session")
            .header("x-extra", "X".repeat(512))
            .body(())
            .unwrap();
        let (_, body) = pipe(state.new_memory());
        assert_eq!(
            state.handle(request, body).await.status(),
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );
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
    async fn h1_bodiless_requests_keep_the_connection_alive() {
        let (client, server) = tokio::io::duplex(8192);
        let tasks = Tasks::new();
        tasks.spawn(async move {
            service()
                .serve_h1(
                    Box::new(server),
                    tokio::time::Instant::now() + Duration::from_secs(4),
                )
                .await
                .unwrap();
        });
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(client))
                .await
                .unwrap();
        tasks.spawn(async move { connection.await.unwrap() });
        for method in ["OPTIONS", "GET"] {
            let request = Request::builder()
                .method(method)
                .uri("/wrong")
                .header("host", "localhost")
                .body(Body::Empty)
                .unwrap();
            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert!(!response.headers().contains_key("connection"));
            response.into_body().collect().await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
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
    async fn reset_parked_h2_packet_releases_admission_without_closing_session() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let state = service();
            let _reader = attached_reader(&state, "a");
            let session = state.session("a").unwrap();
            let (client, server) = tokio::io::duplex(8192);
            let tasks = Tasks::new();
            let serving = state.clone();
            tasks.spawn(async move {
                let _ = serving
                    .serve_h2(
                        Box::new(server),
                        tokio::time::Instant::now() + Duration::from_secs(4),
                    )
                    .await;
            });
            let (sender, connection) = h2::client::handshake(client).await.unwrap();
            tasks.spawn(async move {
                let _ = connection.await;
            });
            let mut sender = sender.ready().await.unwrap();
            let packet = Request::post("http://localhost/t/a/100")
                .header("referer", format!("/?x_padding={}", "X".repeat(100)))
                .header("content-length", 8)
                .body(())
                .unwrap();
            let (_response, mut body) = sender.send_request(packet, false).unwrap();
            body.send_data(Bytes::from_static(b"buffered"), false)
                .unwrap();
            while session.packet_requests.snapshot().active == 0 {
                tokio::task::yield_now().await;
            }
            assert_eq!(state.memory.snapshot().active, 0);
            body.send_reset(h2::Reason::CANCEL);
            while state.requests.snapshot().active != 0 {
                tokio::task::yield_now().await;
            }
            assert_eq!(session.packet_requests.snapshot().active, 0);
            assert!(session.state.lock().receiving.is_empty());
            assert!(!session.cancel.is_cancelled());
            assert_eq!(
                request(&state, "POST", "a/0", b"head").await.status(),
                StatusCode::OK
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn h3_reset_upload_keeps_strict_carrier_usable() {
        reset_upload_keeps_strict_carrier_usable(XhttpVersion::H3).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn h2_reset_upload_keeps_strict_carrier_usable() {
        reset_upload_keeps_strict_carrier_usable(XhttpVersion::H2).await;
    }

    async fn reset_upload_keeps_strict_carrier_usable(version: XhttpVersion) {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut state = service();
            Arc::get_mut(&mut state)
                .unwrap()
                .config
                .close_on_http1_error = true;
            let (carrier, _server, _endpoint) = streaming_carrier(state.clone(), version).await;
            let memory = Memory::new(Arc::new(Budget::new(Some(1024))), Some(1024));
            for sequence in 0..32 {
                let tasks = Tasks::new();
                let (mut writer, reader) = pipe(memory.clone());
                writer.write_all(b"partial").await.unwrap();
                let packet = Request::post(format!("https://localhost/t/session{sequence}/0"))
                    .header("referer", format!("/?x_padding={}", "X".repeat(100)))
                    .header("content-length", "16")
                    .body(Body::stream(reader))
                    .unwrap();
                let request =
                    carrier.request(packet, memory.clone(), &tasks, Duration::from_secs(2));
                tokio::pin!(request);
                tokio::select! {
                    _ = &mut request => panic!("partial packet completed before cancellation"),
                    _ = async {
                        while state.memory.snapshot().active == 0 {
                            tokio::task::yield_now().await;
                        }
                    } => {},
                }
                tasks.cancel.cancel();
                assert!(request.await.is_err());
                while state.requests.snapshot().active != 0 {
                    tokio::task::yield_now().await;
                }
                let tasks = Tasks::new();
                let probe = Request::builder()
                    .method("OPTIONS")
                    .uri("https://localhost/t/")
                    .body(Body::Empty)
                    .unwrap();
                let response = carrier
                    .request(probe, memory.clone(), &tasks, Duration::from_secs(2))
                    .await
                    .unwrap_or_else(|error| panic!("{version:?} reset {sequence}: {error}"));
                assert_eq!(response.status(), StatusCode::OK);
                response
                    .into_body()
                    .read_to_end(&mut Vec::new())
                    .await
                    .unwrap();
                assert_eq!(state.admission.snapshot().active, 0);
                assert_eq!(state.memory.snapshot().active, 0);
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn h2_library_body_resets_remain_stream_local_in_strict_mode() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut state = service();
            Arc::get_mut(&mut state)
                .unwrap()
                .config
                .close_on_http1_error = true;
            let (client, server) = tokio::io::duplex(8192);
            let tasks = Tasks::new();
            let serving = state.clone();
            tasks.spawn(async move {
                let _ = serving
                    .serve_h2(
                        Box::new(server),
                        tokio::time::Instant::now() + Duration::from_secs(4),
                    )
                    .await;
            });
            let (sender, connection) = h2::client::handshake(client).await.unwrap();
            tasks.spawn(async move {
                let _ = connection.await;
            });
            let mut sender = sender.ready().await.unwrap();
            let packet = Request::post("http://localhost/t/session/0")
                .header("referer", format!("/?x_padding={}", "X".repeat(100)))
                .header("content-length", "16")
                .body(())
                .unwrap();
            let (response, mut body) = sender.send_request(packet, false).unwrap();
            body.send_data(Bytes::from_static(b"partial"), false)
                .unwrap();
            while state.memory.snapshot().active == 0 {
                tokio::task::yield_now().await;
            }
            body.send_data(Bytes::new(), true).unwrap();
            let error = response.await.unwrap_err();
            assert_eq!(error.reason(), Some(h2::Reason::PROTOCOL_ERROR));
            while state.requests.snapshot().active != 0 {
                tokio::task::yield_now().await;
            }
            sender = sender.ready().await.unwrap();
            let probe = Request::builder()
                .method("OPTIONS")
                .uri("http://localhost/t/")
                .body(())
                .unwrap();
            let (response, _) = sender.send_request(probe, true).unwrap();
            assert_eq!(response.await.unwrap().status(), StatusCode::OK);
            assert_eq!(state.admission.snapshot().active, 0);
            assert_eq!(state.memory.snapshot().active, 0);
        })
        .await
        .unwrap();
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
    async fn fragmented_packets_retain_bounded_chunks_and_release_on_close() {
        let mut state = service();
        let size = super::super::stream::CHUNK + 7;
        let inner = Arc::get_mut(&mut state).unwrap();
        inner.config.sc_max_each_post_bytes = crate::config::xhttp::XhttpRange::Number(size as i64);
        inner.config.limits.max_buffered_bytes = Some(size);
        inner.config.limits.max_session_buffered_bytes = Some(2 * size);
        inner.memory = Arc::new(Budget::new(Some(size)));
        inner.config.validate().unwrap();
        let session = state.session("a").unwrap();
        let (mut writer, post) = open_post(&state, "a/1");
        for index in 0..size {
            writer.write_all(&[(index % 251) as u8]).await.unwrap();
        }
        writer.shutdown().await.unwrap();
        assert_eq!(post.await.unwrap(), StatusCode::OK);
        {
            let inner = session.state.lock();
            let packet = inner.pending.get(&1).unwrap();
            assert_eq!(packet.len(), 2);
            assert!(
                packet
                    .iter()
                    .flat_map(|chunk| chunk.iter())
                    .copied()
                    .eq((0..size).map(|index| (index % 251) as u8))
            );
            assert!(inner.receiving.is_empty());
            assert!(inner.reserved.is_empty());
        }
        assert_eq!(state.memory.snapshot().active, size);
        state.close("a");
        assert_eq!(state.memory.snapshot().active, 0);
        assert_eq!(session.packet_requests.snapshot().active, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn attached_default_window_waits_for_late_predecessors() {
        let mut state = service();
        Arc::get_mut(&mut state)
            .unwrap()
            .config
            .sc_max_buffered_posts = 0;
        let mut reader = attached_reader(&state, "a");
        let mut posts = Vec::new();
        for sequence in (0..=30).rev() {
            let state = state.clone();
            posts.push(tokio::spawn(async move {
                request(&state, "POST", &format!("a/{sequence}"), &[sequence])
                    .await
                    .status()
            }));
            tokio::task::yield_now().await;
            if sequence == 30 {
                assert!(!posts[0].is_finished());
            }
        }
        let mut data = [0; 31];
        tokio::time::timeout(Duration::from_secs(1), reader.read_exact(&mut data))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(data, std::array::from_fn(|index| index as u8));
        for post in posts {
            assert_eq!(post.await.unwrap(), StatusCode::OK);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn far_packet_waiters_expire_without_reserving_bytes() {
        let state = inactivity_service(64);
        let _reader = attached_reader(&state, "a");
        let session = state.session("a").unwrap();
        let mut post = Box::pin(request(&state, "POST", "a/18446744073709551615", b""));
        assert!(futures::poll!(&mut post).is_pending());
        assert!(session.state.lock().reserved.is_empty());
        assert!(session.memory.reserve_packet(64, 0).is_some());
        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(post.await.status(), StatusCode::REQUEST_TIMEOUT);
        assert!(session.state.lock().receiving.is_empty());
        assert_eq!(session.packet_requests.snapshot().active, 0);
    }

    #[tokio::test]
    async fn duplicate_receivers_keep_request_permits_and_leave_head_capacity() {
        let mut state = service();
        Arc::get_mut(&mut state)
            .unwrap()
            .config
            .limits
            .max_requests_per_session = Some(4);
        let _reader = attached_reader(&state, "a");
        let session = state.session("a").unwrap();
        let mut duplicates = Vec::new();
        for _ in 0..3 {
            duplicates.push(PacketRequest::new(session.clone(), 100).unwrap());
        }
        assert_eq!(session.state.lock().receiving[&100], 3);
        assert_eq!(session.packet_requests.snapshot().active, 3);
        assert!(matches!(
            PacketRequest::new(session.clone(), 1),
            Err(Rejection::Full)
        ));
        assert!(matches!(
            PacketRequest::new(session.clone(), 100),
            Err(Rejection::Full)
        ));
        let head = PacketRequest::new(session.clone(), 0).unwrap();
        assert_eq!(session.head_request.snapshot().active, 1);
        drop(head);
        drop(duplicates);
        assert_eq!(session.packet_requests.snapshot().active, 0);
        assert_eq!(session.head_request.snapshot().active, 0);
    }

    #[tokio::test]
    async fn aggregate_request_limit_refuses_before_creating_another_session() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut state = service();
            Arc::get_mut(&mut state).unwrap().requests = Arc::new(Budget::new(Some(1)));
            let (carrier, _server, _endpoint) =
                streaming_carrier(state.clone(), XhttpVersion::H2).await;
            let tasks = Tasks::new();
            let memory = Memory::new(Arc::new(Budget::new(Some(1024))), Some(1024));
            let make = |path: &str| {
                Request::get(format!("https://localhost/t/{path}"))
                    .header("referer", format!("/?x_padding={}", "X".repeat(100)))
                    .body(Body::Empty)
                    .unwrap()
            };
            let first = carrier
                .request(make("a"), memory.clone(), &tasks, Duration::from_secs(2))
                .await
                .unwrap();
            assert_eq!(first.status(), StatusCode::OK);
            assert_eq!(state.requests.snapshot().active, 1);
            let error = carrier
                .request(make("b"), memory.clone(), &tasks, Duration::from_secs(2))
                .await
                .err()
                .unwrap();
            assert_eq!(
                error
                    .get_ref()
                    .and_then(|error| error.downcast_ref::<h2::Error>())
                    .unwrap()
                    .reason(),
                Some(h2::Reason::REFUSED_STREAM)
            );
            assert!(!state.sessions.lock().contains_key("b"));
            assert!(!state.session("a").unwrap().cancel.is_cancelled());
            state.close("a");
            while state.requests.snapshot().active != 0 {
                tokio::task::yield_now().await;
            }
            let second = carrier
                .request(make("b"), memory, &tasks, Duration::from_secs(2))
                .await
                .unwrap();
            assert_eq!(second.status(), StatusCode::OK);
            assert_eq!(state.requests.snapshot().peak, 1);
            state.close("b");
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn packet_admission_precedes_body_buffering_and_cancellation_releases_waiters() {
        let state = inactivity_service(64);
        let _inner = attached_reader(&state, "a");
        let session = state.session("a").unwrap();
        let held = session.memory.reserve_packet(64, 0).unwrap();
        let (mut writer, mut reader) = pipe(state.new_memory());
        let ready = reader.defer();
        let pumping = tokio::spawn(async move {
            if ready.await.is_ok() {
                writer.write_all(b"not admitted").await.unwrap();
                true
            } else {
                false
            }
        });
        let req = Request::post("http://localhost/t/a/0")
            .header("referer", format!("/?x_padding={}", "X".repeat(100)))
            .header("content-length", 12)
            .body(())
            .unwrap();
        let mut post = Box::pin(state.handle(req, reader));
        assert!(futures::poll!(&mut post).is_pending());
        tokio::task::yield_now().await;
        assert!(!pumping.is_finished());
        assert_eq!(state.memory.snapshot().active, 0);
        assert_eq!(session.packet_requests.snapshot().active, 1);
        drop(post);
        assert!(!pumping.await.unwrap());
        assert_eq!(session.packet_requests.snapshot().active, 0);
        assert!(session.state.lock().receiving.is_empty());
        drop(held);
    }

    #[tokio::test]
    async fn live_packet_request_limit_applies_across_carriers() {
        for version in [XhttpVersion::H1, XhttpVersion::H2, XhttpVersion::H3] {
            tokio::time::timeout(Duration::from_secs(5), async {
                let mut state = service();
                Arc::get_mut(&mut state)
                    .unwrap()
                    .config
                    .limits
                    .max_requests_per_session = Some(4);
                let _reader = attached_reader(&state, "a");
                let session = state.session("a").unwrap();
                let mut servers = Vec::new();
                let mut posts = Vec::new();
                for count in 1..=4 {
                    let (carrier, tasks, endpoint) =
                        streaming_carrier(state.clone(), version).await;
                    servers.push((tasks, endpoint));
                    posts.push(tokio::spawn(async move {
                        let tasks = Tasks::new();
                        let request = Request::post("https://localhost/t/a/100")
                            .header("referer", format!("/?x_padding={}", "X".repeat(100)))
                            .header("content-length", 0)
                            .body(Body::Empty)
                            .unwrap();
                        carrier
                            .request(
                                request,
                                Memory::new(Arc::new(Budget::new(Some(1024))), Some(1024)),
                                &tasks,
                                Duration::from_secs(4),
                            )
                            .await
                            .map(|response| response.status())
                    }));
                    if count < 4 {
                        while session.packet_requests.snapshot().active != count {
                            tokio::task::yield_now().await;
                        }
                    }
                }
                let rejected = posts.pop().unwrap().await.unwrap();
                if version == XhttpVersion::H2 {
                    let error = rejected.unwrap_err();
                    assert_eq!(
                        error
                            .get_ref()
                            .and_then(|error| error.downcast_ref::<h2::Error>())
                            .unwrap()
                            .reason(),
                        Some(h2::Reason::REFUSED_STREAM)
                    );
                    assert!(!session.cancel.is_cancelled());
                    assert!(posts.iter().all(|post| !post.is_finished()));
                    state.close("a");
                } else {
                    assert_eq!(rejected.unwrap(), StatusCode::SERVICE_UNAVAILABLE);
                }
                for post in posts {
                    assert_eq!(
                        post.await.unwrap().unwrap(),
                        StatusCode::SERVICE_UNAVAILABLE
                    );
                }
                assert_eq!(session.packet_requests.snapshot().active, 0);
                assert_eq!(session.head_request.snapshot().active, 0);
                assert!(session.state.lock().receiving.is_empty());
                assert!(session.state.lock().reserved.is_empty());
                assert_eq!(state.memory.snapshot().active, 0);
                assert_eq!(state.admission.snapshot().active, 0);
            })
            .await
            .unwrap_or_else(|error| panic!("{version:?}: {error}"));
        }
    }

    #[tokio::test]
    async fn far_packet_timeout_releases_a_single_stream_carrier() {
        for version in [XhttpVersion::H1, XhttpVersion::H2, XhttpVersion::H3] {
            tokio::time::timeout(Duration::from_secs(5), async {
                let mut state = service();
                let limits = &mut Arc::get_mut(&mut state).unwrap().config.limits;
                limits.packet_timeout_secs = 1;
                limits.max_requests_per_connection = 1;
                let _reader = attached_reader(&state, "a");
                let (carrier, _server, _endpoint) = streaming_carrier(state, version).await;
                let tasks = Tasks::new();
                for (suffix, status) in [
                    ("a/30", StatusCode::REQUEST_TIMEOUT),
                    ("b/0", StatusCode::OK),
                ] {
                    let request = Request::post(format!("https://localhost/t/{suffix}"))
                        .header("referer", format!("/?x_padding={}", "X".repeat(100)))
                        .header("content-length", 0)
                        .body(Body::Empty)
                        .unwrap();
                    let response = carrier
                        .request(
                            request,
                            Memory::new(Arc::new(Budget::new(Some(1024))), Some(1024)),
                            &tasks,
                            Duration::from_secs(3),
                        )
                        .await
                        .unwrap();
                    assert_eq!(response.status(), status);
                    assert_eq!(response.into_body().read(&mut [0]).await.unwrap(), 0);
                }
            })
            .await
            .unwrap_or_else(|error| panic!("{version:?}: {error}"));
        }
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
            assert!(state.sessions.lock().len() <= state.config.limits.max_sessions.unwrap());
        }
        assert_eq!(
            request(&state, "GET", "session-9", b"").await.status(),
            StatusCode::CONFLICT
        );
    }

    #[tokio::test]
    async fn session_close_between_lookup_and_claim_rejects_both_stream_handles() {
        for close in [false, true] {
            let state = service();
            let session = state.session("a").unwrap();
            if close {
                state.close("a");
            } else {
                session.cancel.cancel();
            }

            assert!(matches!(
                session.claim_download(),
                Err(StatusCode::CONFLICT)
            ));
            assert!(matches!(
                session.claim_stream_upload(),
                Err(StatusCode::CONFLICT)
            ));
            let inner = session.state.lock();
            assert!(!inner.downloaded);
            assert!(inner.upload == Upload::Unclaimed);
            assert_eq!(inner.reader.is_some(), !close);
            assert_eq!(inner.writer.is_some(), !close);
            assert_eq!(inner.permit.is_some(), !close);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn old_download_guard_does_not_close_a_replacement_session() {
        for expire in [false, true] {
            let state = service();
            let response = request(&state, "GET", "a", b"").await;
            assert_eq!(response.status(), StatusCode::OK);
            state.close("a");
            if expire {
                tokio::time::advance(Duration::from_secs(31)).await;
                state.reap();
            } else {
                for id in ["b", "c"] {
                    tokio::time::advance(Duration::from_secs(1)).await;
                    state.session(id).unwrap();
                    state.close(id);
                }
            }
            let replacement = state.session("a").unwrap();
            drop(response);
            tokio::task::yield_now().await;
            assert!(!replacement.cancel.is_cancelled());
            assert!(Arc::ptr_eq(&state.session("a").unwrap(), &replacement));
            assert_eq!(state.admission.snapshot().active, 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn closed_packet_cannot_commit_or_close_a_replacement_session() {
        let state = service();
        let old = state.session("a").unwrap();
        let request = Request::post("http://localhost/t/a/1").body(()).unwrap();
        let (mut writer, mut reader) = pipe(state.new_memory());
        writer.write_all(b"partial").await.unwrap();
        let admission = PacketRequest::new(old.clone(), 1).unwrap();
        let mut packet = Box::pin(state.packet_body(&request, &mut reader, &old, 1, admission));
        assert!(futures::poll!(&mut packet).is_pending());
        state.close("a");
        writer.shutdown().await.unwrap();
        assert!(matches!(packet.await, Err(StatusCode::SERVICE_UNAVAILABLE)));
        assert!(old.state.lock().pending.is_empty());
        assert!(old.state.lock().receiving.is_empty());
        assert!(old.state.lock().reserved.is_empty());
        assert_eq!(old.packet_requests.snapshot().active, 0);
        for id in ["b", "c"] {
            tokio::time::advance(Duration::from_secs(1)).await;
            state.session(id).unwrap();
            state.close(id);
        }
        let replacement = state.session("a").unwrap();
        state.close_session("a", &old);
        assert!(!replacement.cancel.is_cancelled());
        assert!(Arc::ptr_eq(&state.session("a").unwrap(), &replacement));
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
        let (_writer, reader) = pipe(Memory::new(state.memory.clone(), Some(1024)));
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
            .max_session_buffered_bytes = Some(32);
        let session = state.session("a").unwrap();
        let (mut reader, _permit) = session.claim_download().unwrap();
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
            .max_session_buffered_bytes = Some(32);
        let session = state.session("a").unwrap();
        let (mut reader, _permit) = session.claim_download().unwrap();
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
        let (mut reader, _permit) = session.claim_download().unwrap();
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
        while let Some(result) = requests.try_join_next() {
            assert_eq!(result.unwrap(), StatusCode::OK);
        }
        assert!(
            !requests.is_empty(),
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
            state.config.limits.max_session_buffered_bytes = Some(64);
        }
        let session = state.session("a").unwrap();
        let mut reader = None;
        if !attach_late {
            reader = Some(session.claim_download().unwrap().0);
        }
        let mut writers = Vec::new();
        let mut posts = tokio::task::JoinSet::new();
        for sequence in 0..4 {
            let post = Request::post(format!("http://localhost/t/a/{sequence}"))
                .header("referer", format!("/?x_padding={}", "X".repeat(100)))
                .header("content-length", "16")
                .body(())
                .unwrap();
            let (writer, body) = pipe(Memory::new(state.memory.clone(), Some(1024)));
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
            state.config.limits.max_session_buffered_bytes = Some(24);
        }
        let session = state.session("a").unwrap();
        let (_reader, _permit) = session.claim_download().unwrap();
        let mut posts = tokio::task::JoinSet::new();
        let mut writers = Vec::new();
        for sequence in [1, 2, 0] {
            let post = Request::post(format!("http://localhost/t/a/{sequence}"))
                .header("referer", format!("/?x_padding={}", "X".repeat(100)))
                .header("content-length", "8")
                .body(())
                .unwrap();
            let (mut writer, body) = pipe(Memory::new(state.memory.clone(), Some(1024)));
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
                .max_session_buffered_bytes = Some(64);
            let session = state.session("a").unwrap();
            let mut posts = Vec::new();
            let mut writers = Vec::new();
            for _ in 0..2 {
                let post = Request::post("http://localhost/t/a/0")
                    .header("referer", format!("/?x_padding={}", "X".repeat(100)))
                    .header("content-length", "16")
                    .body(())
                    .unwrap();
                let (mut writer, body) = pipe(Memory::new(state.memory.clone(), Some(1024)));
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
            let (mut writer, body) = pipe(Memory::new(state.memory.clone(), Some(1024)));
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
    async fn attached_duplicate_packets_are_queued_only_once() {
        let state = service();
        let session = state.session("a").unwrap();
        let (mut reader, _permit) = session.claim_download().unwrap();
        for sequence in 0..4 {
            assert_eq!(
                request(&state, "POST", &format!("a/{sequence}"), b"12345678")
                    .await
                    .status(),
                StatusCode::OK
            );
        }
        let later = request(&state, "POST", "a/5", b"BBBBBBBB");
        let duplicate_later = request(&state, "POST", "a/5", b"BBBBBBBB");
        let next = request(&state, "POST", "a/4", b"AAAAAAAA");
        tokio::task::yield_now().await;
        let duplicate_next = request(&state, "POST", "a/4", b"AAAAAAAA");
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
    pending: Arc<Budget>,
    requests: Arc<Budget>,
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
    pending: BTreeMap<u64, Vec<Bytes>>,
    receiving: BTreeMap<u64, usize>,
    reserved: BTreeMap<u64, usize>,
    next: u64,
    downloaded: bool,
    upload_deadline: Option<tokio::time::Instant>,
    permit: Option<BudgetPermit>,
    pending_permit: Option<BudgetPermit>,
}
impl SessionState {
    fn predecessors_available(&self, sequence: u64, in_progress: &BTreeMap<u64, usize>) -> bool {
        self.downloaded
            && (self.next..sequence).all(|number| {
                self.pending.contains_key(&number) || in_progress.contains_key(&number)
            })
    }
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
    packet_requests: Arc<Budget>,
    head_request: Arc<Budget>,
}

impl Session {
    fn claim_download(&self) -> Result<(Reader, BudgetPermit), StatusCode> {
        let mut state = self.state.lock();
        // close_entry cancels before taking this lock and removing the handles.
        if self.cancel.is_cancelled() || state.downloaded {
            return Err(StatusCode::CONFLICT);
        }
        state.downloaded = true;
        state.pending_permit.take();
        Ok((state.reader.take().unwrap(), state.permit.take().unwrap()))
    }

    fn claim_stream_upload(&self) -> Result<Writer, StatusCode> {
        let mut state = self.state.lock();
        if self.cancel.is_cancelled()
            || state.upload != Upload::Unclaimed
            || state
                .upload_deadline
                .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
        {
            return Err(StatusCode::CONFLICT);
        }
        state.upload = Upload::Stream;
        state.upload_deadline = None;
        Ok(state.writer.take().unwrap())
    }
}

struct PacketRequest {
    session: Arc<Session>,
    sequence: u64,
    reserved: bool,
    primary: bool,
}

#[derive(Debug, PartialEq)]
enum Rejection {
    Status(StatusCode),
    Full,
}

impl From<StatusCode> for Rejection {
    fn from(status: StatusCode) -> Self {
        Self::Status(status)
    }
}

#[derive(Clone)]
struct Refused;

#[derive(Clone)]
struct RequestReset(CancellationToken);

impl PacketRequest {
    fn new(session: Arc<Session>, sequence: u64) -> Result<(Self, BudgetPermit), Rejection> {
        let (primary, permit) = {
            let mut state = session.state.lock();
            if session.cancel.is_cancelled() {
                return Err(StatusCode::SERVICE_UNAVAILABLE.into());
            }
            if state.upload == Upload::Stream || state.upload_deadline.is_some() {
                return Err(StatusCode::CONFLICT.into());
            }
            let permit = session
                .packet_requests
                .acquire(1)
                .or_else(|| {
                    // Far requests and duplicates cannot consume the missing head's last slot.
                    if sequence == state.next && !state.receiving.contains_key(&sequence) {
                        session.head_request.acquire(1)
                    } else {
                        None
                    }
                })
                .ok_or(Rejection::Full)?;
            let count = state.receiving.entry(sequence).or_default();
            *count += 1;
            (*count == 1, permit)
        };
        Ok((
            Self {
                session,
                sequence,
                reserved: false,
                primary,
            },
            permit,
        ))
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
        if self.eof.is_cancelled() {
            let Some(session) = &self.session else {
                return;
            };
            if let Some(session) = session.upgrade() {
                let mut state = session.state.lock();
                if state.upload == Upload::Stream {
                    return;
                }
                if !session.cancel.is_cancelled()
                    && state.upload == Upload::Unclaimed
                    && state.receiving.is_empty()
                    && self.state.upgrade().is_some_and(|service| {
                        matches!(
                            service.config.mode,
                            crate::config::xhttp::XhttpMode::Auto
                                | crate::config::xhttp::XhttpMode::StreamUp
                        )
                    })
                {
                    state.upload_deadline =
                        Some(tokio::time::Instant::now() + Duration::from_secs(30));
                    return;
                }
            }
        }
        self.cancel.cancel();
        if let Some(state) = self.state.upgrade()
            && let Some(session) = self.session.as_ref().and_then(Weak::upgrade)
        {
            state.close_session(&self.id, &session);
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
            memory: Arc::new(Budget::new(config.limits.max_buffered_bytes)),
            admission: Arc::new(Budget::new(config.limits.max_sessions)),
            pending: Arc::new(Budget::new(config.limits.max_pending_sessions)),
            requests: Arc::new(Budget::new(config.limits.max_requests)),
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
                log::debug!(
                    "XHTTP server resources: requests={:?} bytes={:?}",
                    state.requests.snapshot(),
                    state.memory.snapshot()
                );
            }
        });
        Ok(Self { state })
    }

    pub async fn serve_h3(&self, connection: quinn::Connection) -> io::Result<()> {
        let mut driver = h3::server::builder()
            .max_field_section_size(self.state.config.header_limit() as u64)
            .build(super::h3::Connection::new(connection.clone()))
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
            let request_permit = if requests.len() < self.state.config.limits.request_limit() {
                self.state.requests.acquire(1)
            } else {
                None
            };
            let Some(request_permit) = request_permit else {
                drop(resolver);
                continue;
            };
            let state = self.state.clone();
            requests.spawn(async move {
                let _request_permit = request_permit;
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
                let memory = state.new_memory();
                let (mut writer, mut reader) = pipe(memory);
                let ready = reader.defer();
                let upload_closed = writer.closed();
                let peer_reset = CancellationToken::new();
                let receive_reset = peer_reset.clone();
                workers.spawn(async move {
                    if ready.await.is_err() {
                        return;
                    }
                    let result: io::Result<()> = async {
                        while let Some(mut data) = receive.recv_data().await.map_err(|error| {
                            if matches!(error, h3::error::StreamError::RemoteTerminate { .. }) {
                                receive_reset.cancel();
                            }
                            io::Error::other(error)
                        })? {
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
                if peer_reset.is_cancelled() {
                    send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                    return;
                }
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
    fn new_memory(&self) -> Memory {
        Memory::new(self.memory.clone(), self.config.limits.session_byte_limit())
    }

    #[cfg(test)]
    fn close(&self, id: &str) {
        let mut sessions = self.sessions.lock();
        self.close_entry(&mut sessions, id);
    }

    fn close_session(&self, id: &str, session: &Arc<Session>) {
        let mut sessions = self.sessions.lock();
        if matches!(sessions.get(id), Some(Entry::Live(current)) if Arc::ptr_eq(current, session)) {
            self.close_entry(&mut sessions, id);
        }
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
                state.pending_permit.take();
                state.writer.take();
                state.reader.take();
            }
            if self.config.limits.max_sessions.is_some_and(|limit| {
                sessions
                    .values()
                    .filter(|entry| matches!(entry, Entry::Closed { .. }))
                    .count()
                    >= limit
            }) {
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
                Entry::Live(session) => {
                    let state = session.state.lock();
                    ((!state.downloaded && session.created.elapsed() >= Duration::from_secs(30))
                        || state
                            .upload_deadline
                            .is_some_and(|deadline| tokio::time::Instant::now() >= deadline))
                    .then(|| id.clone())
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
        let permit = crate::resources::try_stream().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let admission = self
            .admission
            .acquire(1)
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let pending_permit = self
            .pending
            .acquire(1)
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let memory = self.new_memory();
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
                next: 0,
                downloaded: false,
                upload_deadline: None,
                permit: Some(permit),
                pending_permit: Some(pending_permit),
            }),
            memory,
            ready: Notify::new(),
            cancel: CancellationToken::new(),
            created: tokio::time::Instant::now(),
            admission: parking_lot::Mutex::new(Some(admission)),
            activity,
            progress: Notify::new(),
            packet_requests: Arc::new(Budget::new(
                self.config
                    .limits
                    .session_request_limit()
                    .map(|limit| limit - 1),
            )),
            head_request: Arc::new(Budget::new(Some(1))),
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
        body: Reader,
    ) -> Result<(Body, bool), Rejection> {
        wire::check_matching_headers(&self.config, request.headers())
            .inspect_err(|error| log::debug!("XHTTP request rejected: {error}"))
            .map_err(|_| StatusCode::NOT_FOUND)?;
        match wire::classify(&self.config, &self.path, request)? {
            Kind::Options => Ok((Body::Empty, false)),
            Kind::One => self.stream_one(body).map_err(Into::into),
            Kind::Download(id) => self.download(id).map_err(Into::into),
            Kind::Upload(id) => self.stream_upload(request, body, id).map_err(Into::into),
            Kind::Packet(id, sequence) => self.packet(request, body, id, sequence).await,
        }
    }

    fn stream_one(self: &Arc<Self>, body: Reader) -> Result<(Body, bool), StatusCode> {
        let admission = self
            .admission
            .acquire(1)
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let permit = crate::resources::try_stream().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let memory = self.new_memory();
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

    fn download(self: &Arc<Self>, id: String) -> Result<(Body, bool), StatusCode> {
        let session = self.session(&id)?;
        let (reader, permit) = session.claim_download()?;
        session.progress.notify_waiters();
        let (writer, output) = pipe(self.new_memory());
        let tasks = Arc::new(Tasks::new());
        let stream = Stream {
            read: reader,
            write: writer,
            _tasks: tasks,
        };
        let state = Arc::downgrade(self);
        let session_id = id.clone();
        let completed = Arc::downgrade(&session);
        self.spawn_inner_session(stream, permit, session.cancel.clone(), move || {
            if let Some(state) = state.upgrade()
                && let Some(session) = completed.upgrade()
            {
                state.close_session(&session_id, &session);
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

    fn stream_upload(
        self: &Arc<Self>,
        request: &Request<()>,
        mut body: Reader,
        id: String,
    ) -> Result<(Body, bool), StatusCode> {
        let session = self.session(&id)?;
        let mut writer = session.claim_stream_upload()?;
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
                body.forward_to(&mut writer).await?;
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
                    tokio::time::sleep(Duration::from_secs(wire::sample(interval) as u64)).await;
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

    async fn packet(
        self: &Arc<Self>,
        request: &Request<()>,
        mut body: Reader,
        id: String,
        sequence: u64,
    ) -> Result<(Body, bool), Rejection> {
        let session = self.session(&id)?;
        let admission = match PacketRequest::new(session.clone(), sequence) {
            Ok(admission) => admission,
            Err(Rejection::Full) if request.version() == http::Version::HTTP_2 => {
                log::debug!(
                    "XHTTP session {id} request limit reached; refusing unaccepted packet {sequence}"
                );
                return Err(Rejection::Full);
            }
            Err(error) => {
                if error != Rejection::Status(StatusCode::CONFLICT) {
                    self.close_session(&id, &session);
                }
                return Err(match error {
                    Rejection::Full => StatusCode::SERVICE_UNAVAILABLE.into(),
                    error => error,
                });
            }
        };
        let result = self
            .packet_body(request, &mut body, &session, sequence, admission)
            .await;
        if matches!(result, Err(status) if status != StatusCode::CONFLICT) {
            self.close_session(&id, &session);
        }
        result.map_err(Into::into)
    }

    async fn packet_body(
        self: &Arc<Self>,
        request: &Request<()>,
        body: &mut Reader,
        session: &Arc<Session>,
        sequence: u64,
        (mut packet_request, _request_permit): (PacketRequest, BudgetPermit),
    ) -> Result<(Body, bool), StatusCode> {
        use std::ops::ControlFlow;

        {
            let state = session.state.lock();
            if session.cancel.is_cancelled() {
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
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
        let session_limit = self
            .config
            .limits
            .session_byte_limit()
            .unwrap_or(usize::MAX);
        let mut reservation = max.min(session_limit);
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
        if reservation > session_limit {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        let arrived = tokio::time::Instant::now();
        let timeout = Duration::from_secs(self.config.limits.packet_timeout_secs);
        let ingest = async {
            let admission = async {
                loop {
                    let released = session.memory.packet_space_released();
                    let progress = session.progress.notified();
                    tokio::pin!(released, progress);
                    released.as_mut().enable();
                    progress.as_mut().enable();
                    {
                        let mut state = session.state.lock();
                        if session.cancel.is_cancelled() {
                            return Err(StatusCode::SERVICE_UNAVAILABLE);
                        }
                        if state.upload == Upload::Stream {
                            return Err(StatusCode::CONFLICT);
                        }
                        state.upload = Upload::Packet;
                        if sequence < state.next {
                            return Ok(ControlFlow::Break(()));
                        }
                        if sequence.saturating_sub(state.next)
                            >= self.config.buffered_posts() as u64
                        {
                            if !state.downloaded {
                                return Err(StatusCode::SERVICE_UNAVAILABLE);
                            }
                        } else {
                            let contiguous =
                                state.predecessors_available(sequence, &state.reserved);
                            // Out-of-order packets must leave space for their missing predecessor.
                            let headroom = if contiguous || sequence == state.next {
                                0
                            } else {
                                max.min(session_limit)
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
            let cancelled = async {
                match request.extensions().get::<RequestReset>() {
                    Some(reset) => reset.0.cancelled().await,
                    None => std::future::pending().await,
                }
            };
            let admitted = tokio::select! {
                biased;
                // A reset before body admission withdraws only this request, not the session.
                _ = cancelled => return Err(StatusCode::CONFLICT),
                result = session.activity.idle(arrived, timeout, admission) => {
                    result.map_err(|_| StatusCode::REQUEST_TIMEOUT)??
                }
            };
            let mut memory = match admitted {
                ControlFlow::Break(()) => return Ok(()),
                ControlFlow::Continue(memory) => memory,
            };
            body.start();
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
                        Some(Event::Allocated(data)) => data,
                        Some(Event::Flush(ack) | Event::Drain(ack)) => {
                            let _ = ack.send(());
                            continue;
                        }
                        Some(Event::Finish) => break,
                        Some(Event::Data(_) | Event::Error(_)) | None => {
                            return Err(StatusCode::BAD_REQUEST);
                        }
                    };
                    size = size
                        .checked_add(data.len())
                        .ok_or(StatusCode::PAYLOAD_TOO_LARGE)?;
                    if size > max {
                        return Err(StatusCode::PAYLOAD_TOO_LARGE);
                    }
                    if data.len() == 0 {
                        continue;
                    }
                    memory
                        .retain(data, &mut chunks)
                        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                    body_activity.touch();
                    body_request.touch();
                }
                Ok::<_, StatusCode>(())
            };
            body_activity
                .idle(tokio::time::Instant::now(), timeout, intake)
                .await
                .map_err(|_| StatusCode::REQUEST_TIMEOUT)??;
            let writer = {
                let mut state = session.state.lock();
                if session.cancel.is_cancelled() {
                    return Err(StatusCode::SERVICE_UNAVAILABLE);
                }
                if sequence < state.next {
                    return Ok(());
                }
                if let Some(previous) = state.pending.get(&sequence) {
                    if previous
                        .iter()
                        .flat_map(|b| b.iter())
                        .eq(chunks.iter().flat_map(|b| b.as_ref().iter()))
                    {
                        return Ok(());
                    }
                    return Err(StatusCode::CONFLICT);
                }
                if state.pending.len() >= self.config.buffered_posts() {
                    session.cancel.cancel();
                    return Err(StatusCode::SERVICE_UNAVAILABLE);
                }
                state.pending.insert(
                    sequence,
                    chunks.into_iter().map(|chunk| chunk.into_bytes()).collect(),
                );
                state.writer.take()
            };
            drop(memory);
            if let Some(writer) = writer {
                self.spawn_packet_forwarder(session.clone(), writer);
            }
            session.ready.notify_one();
            Ok(())
        };
        let work = async {
            ingest.await?;
            if session.cancel.is_cancelled() {
                Err(StatusCode::SERVICE_UNAVAILABLE)
            } else {
                Ok((Body::Empty, false))
            }
        };
        tokio::select! {
            result = work => result,
            _ = session.cancel.cancelled() => Err(StatusCode::SERVICE_UNAVAILABLE),
        }
    }

    fn spawn_packet_forwarder(&self, session: Arc<Session>, mut writer: Writer) {
        self.tasks.spawn(async move {
            let work = async {
                loop {
                    let packet = {
                        let mut state = session.state.lock();
                        let next = state.next;
                        let packet = state.pending.remove(&next);
                        if packet.is_some() {
                            state.next = next
                                .checked_add(1)
                                .ok_or_else(|| io::Error::other("sequence exhausted"))?;
                            session.progress.notify_waiters();
                        }
                        packet
                    };
                    match packet {
                        Some(packet) => {
                            for chunk in packet {
                                writer.forward(chunk).await?;
                            }
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

    async fn handle(self: &Arc<Self>, request: Request<()>, body: Reader) -> Response<Body> {
        let result = self.dispatch(&request, body).await;
        let mut response = match result {
            Ok((body, downstream)) => self.response(StatusCode::OK, body, downstream),
            Err(Rejection::Full) => {
                let mut response =
                    self.response(StatusCode::SERVICE_UNAVAILABLE, Body::Empty, false);
                response.extensions_mut().insert(Refused);
                return response;
            }
            Err(Rejection::Status(status)) => {
                if status != StatusCode::NOT_FOUND {
                    log::debug!("XHTTP request {} rejected: {status}", request.uri().path());
                }
                if matches!(status, StatusCode::NOT_FOUND | StatusCode::BAD_REQUEST) {
                    return Response::builder()
                        .status(status)
                        .body(Body::Empty)
                        .unwrap();
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

    fn check_http1_request<B>(&self, request: &Request<B>) -> io::Result<()> {
        if !self.config.close_on_http1_error {
            return Ok(());
        }
        wire::check_matching_headers(&self.config, request.headers())?;
        if !percent_encoding::percent_decode_str(request.uri().path())
            .take(self.path.base.len())
            .eq(self.path.base.bytes())
        {
            return Err(io::Error::other("XHTTP request path does not match"));
        }
        Ok(())
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
                state
                    .check_http1_request(&request)
                    .inspect_err(|error| log::debug!("XHTTP request rejected: {error}"))?;
                let Some(request_permit) = state.requests.acquire(1) else {
                    return Ok::<_, io::Error>(
                        Response::builder()
                            .status(StatusCode::SERVICE_UNAVAILABLE)
                            .header("connection", "close")
                            .body(Body::Empty)
                            .unwrap(),
                    );
                };
                let (parts, body) = request.into_parts();
                let request = Request::from_parts(parts, ());
                let streaming_upload = matches!(
                    wire::classify(&state.config, &state.path, &request),
                    Ok(Kind::One | Kind::Upload(_))
                );
                let (writer, mut reader) = pipe(state.new_memory());
                let ready = reader.defer();
                let tasks = Arc::new(Tasks::new());
                let eof = CancellationToken::new();
                if hyper::body::Body::is_end_stream(&body) {
                    eof.cancel();
                }
                let received = eof.clone();
                tasks.spawn(async move {
                    if ready.await.is_ok() {
                        carrier::receive_hyper(body, writer, Some(received)).await;
                    }
                });
                let mut response = state
                    .handle(request, reader)
                    .await
                    .map(|body| body.with_guard(request_permit));
                if streaming_upload && response.status() == StatusCode::OK {
                    return Ok::<_, io::Error>(response.map(|body| body.with_guard(tasks)));
                }
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
        let (stream_window, connection_window) = self.config.limits.h2_windows();
        let mut connection = tokio::time::timeout_at(
            deadline,
            h2::server::Builder::new()
                .max_header_list_size(self.config.header_limit().min(u32::MAX as usize) as u32)
                .max_concurrent_streams(self.config.limits.request_limit() as u32)
                .initial_window_size(stream_window)
                .initial_connection_window_size(connection_window)
                .handshake(stream),
        )
        .await?
        .map_err(io::Error::other)?;
        let mut requests = tokio::task::JoinSet::new();
        loop {
            let request = tokio::select! {
                biased;
                request = connection.accept() => request,
                _ = requests.join_next(), if !requests.is_empty() => continue,
            };
            let Some(request) = request else {
                return Ok(());
            };
            let (request, mut respond) = request.map_err(io::Error::other)?;
            while requests.try_join_next().is_some() {}
            let request_permit = if requests.len() < self.config.limits.request_limit() {
                self.requests.acquire(1)
            } else {
                None
            };
            let Some(request_permit) = request_permit else {
                respond.send_reset(h2::Reason::REFUSED_STREAM);
                continue;
            };
            let state = self.clone();
            requests.spawn(async move {
                let _request_permit = request_permit;
                let (parts, body) = request.into_parts();
                let mut request = Request::from_parts(parts, ());
                let reset = CancellationToken::new();
                request.extensions_mut().insert(RequestReset(reset.clone()));
                let streaming_upload = matches!(
                    wire::classify(&state.config, &state.path, &request),
                    Ok(Kind::One | Kind::Upload(_))
                );
                let (writer, mut reader) = pipe(state.new_memory());
                let ready = reader.defer();
                let tasks = Tasks::new();
                let upload_closed = writer.closed();
                tasks.spawn(async move {
                    if ready.await.is_ok() {
                        carrier::receive_h2(body, writer).await;
                    }
                });
                let handle = state.handle(request, reader);
                tokio::pin!(handle);
                let response = tokio::select! {
                    biased;
                    _ = futures::future::poll_fn(|cx| respond.poll_reset(cx)) => {
                        reset.cancel();
                        let _ = handle.await;
                        return;
                    },
                    response = &mut handle => response,
                };
                // A reset can arrive after select polls it but before handle completes.
                if futures::poll!(futures::future::poll_fn(|cx| respond.poll_reset(cx))).is_ready()
                {
                    return;
                }
                if response.extensions().get::<Refused>().is_some() {
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                    return;
                }
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
