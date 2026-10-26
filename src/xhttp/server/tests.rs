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
    let (outgoing, incoming) = tokio::join!(client.connect(address, "localhost").unwrap(), async {
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
        let (carrier, _server, _endpoint) = streaming_carrier(service(), XhttpVersion::H3).await;
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
            inner.config.sc_stream_up_server_secs = crate::config::xhttp::XhttpRange::Number(-1);
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

async fn request(state: &Arc<State>, method: &str, suffix: &str, data: &[u8]) -> Response<Body> {
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

fn open_post(state: &Arc<State>, suffix: &str) -> (Writer, tokio::task::JoinHandle<StatusCode>) {
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

const XHTTP_SUCCESS_HEADERS: [&str; 7] = [
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "cache-control",
    "content-type",
    "x-accel-buffering",
    "x-padding",
];

#[tokio::test]
async fn header_and_path_mismatches_return_plain_404s_on_every_version() {
    tokio::time::timeout(Duration::from_secs(20), async {
        for version in [XhttpVersion::H1, XhttpVersion::H2, XhttpVersion::H3] {
            for method in ["OPTIONS", "GET", "POST"] {
                for (path, tokens) in [
                    ("/t/session/0", vec![]),
                    ("/t/session/0", vec!["wrong"]),
                    ("/t/session/0", vec!["secret", "secret"]),
                    ("/wrong", vec!["secret"]),
                    ("/%FF/t/", vec!["secret"]),
                ] {
                    let mut state = service();
                    Arc::get_mut(&mut state).unwrap().config.matching_headers =
                        [("x-token".into(), "secret".into())].into();
                    // The unfinished rejected upload still occupies a QUIC stream
                    // until the client observes STOP_SENDING on its idle probe.
                    let (carrier, _server, _endpoint) =
                        streaming_carrier_with_h3_limit(state.clone(), version, 2).await;
                    let memory = Memory::new(Arc::new(Budget::new(Some(1024))), Some(1024));
                    let tasks = Tasks::new();
                    let mut request = Request::builder()
                        .method(method)
                        .uri(format!("https://localhost{path}"))
                        .header("origin", "https://probe.test")
                        .header("referer", format!("/?x_padding={}", "X".repeat(100)));
                    for token in tokens {
                        request = request.header("x-token", token);
                    }
                    let (_writer, body) = pipe(memory.clone());
                    let body = if method == "POST" {
                        request = request.header("content-length", "16");
                        Body::stream(body)
                    } else {
                        Body::Empty
                    };
                    let response = carrier
                        .request(
                            request.body(body).unwrap(),
                            memory.clone(),
                            &tasks,
                            Duration::from_secs(1),
                        )
                        .await
                        .unwrap();
                    assert_eq!(
                        response.status(),
                        StatusCode::NOT_FOUND,
                        "{version:?} {method} {path}"
                    );
                    for name in XHTTP_SUCCESS_HEADERS {
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
                    assert!(state.sessions.lock().is_empty());
                    assert_eq!(state.admission.snapshot().peak, 0);
                    assert_eq!(state.memory.snapshot().peak, 0);
                    // H1 closes a connection whose request body was left unread.
                    if version == XhttpVersion::H1 && method == "POST" {
                        continue;
                    }
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
async fn errors_are_plain_while_successes_keep_xhttp_headers() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for version in [XhttpVersion::H1, XhttpVersion::H2, XhttpVersion::H3] {
            for (method, path, status) in [
                ("GET", "/wrong".to_owned(), StatusCode::NOT_FOUND),
                ("GET", "/t/session".to_owned(), StatusCode::BAD_REQUEST),
                (
                    "PUT",
                    format!("/t/session/0?x_padding={}", "X".repeat(100)),
                    StatusCode::METHOD_NOT_ALLOWED,
                ),
            ] {
                let (carrier, _server, _endpoint) = streaming_carrier(service(), version).await;
                let memory = Memory::new(Arc::new(Budget::new(Some(1024))), Some(1024));
                let tasks = Tasks::new();
                let request = Request::builder()
                    .method(method)
                    .uri(format!("https://localhost{path}"))
                    .header("origin", "https://probe.test")
                    .body(Body::Empty)
                    .unwrap();
                let response = carrier
                    .request(request, memory.clone(), &tasks, Duration::from_secs(1))
                    .await
                    .unwrap();
                assert_eq!(response.status(), status, "{version:?} {method} {path}");
                for header in XHTTP_SUCCESS_HEADERS {
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
                            .header("origin", "https://probe.test")
                            .header("access-control-request-method", "POST")
                            .body(Body::Empty)
                            .unwrap(),
                        memory,
                        &tasks,
                        Duration::from_secs(1),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let headers = response.headers();
                assert!(headers.contains_key("x-padding"));
                assert_eq!(headers["cache-control"], "no-store");
                assert_eq!(headers["access-control-allow-origin"], "https://probe.test");
                assert_eq!(headers["access-control-allow-methods"], "POST");
                assert_eq!(headers["access-control-allow-headers"], "*");
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn known_path_errors_return_http_responses_and_release_resources() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for version in [XhttpVersion::H1, XhttpVersion::H2, XhttpVersion::H3] {
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
                let (carrier, _server, _endpoint) = streaming_carrier(state.clone(), version).await;
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
                assert_eq!(response.status(), status, "{version:?}");
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
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn aggregate_request_overflow_refuses_individual_requests() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for version in [XhttpVersion::H1, XhttpVersion::H2, XhttpVersion::H3] {
            let state = service();
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
        for request_limit_reached in [false, true] {
            for (path, token_header) in [("/t/session/0", ""), ("/wrong", "X-Token: secret\r\n")] {
                let mut state = service();
                Arc::get_mut(&mut state).unwrap().config.matching_headers =
                    [("x-token".into(), "secret".into())].into();
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
                    if request_limit_reached {
                        assert!(response.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
                    } else {
                        assert!(response.starts_with(b"HTTP/1.1 404 Not Found\r\n"));
                    }
                    let response = String::from_utf8(response).unwrap().to_ascii_lowercase();
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
                result.unwrap();
                drop(held);
                assert!(state.sessions.lock().is_empty());
                assert_eq!(state.requests.snapshot().active, 0);
                assert_eq!(state.memory.snapshot().peak, 0);
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
        .header("origin", "https://probe.test")
        .header("x-extra", "X".repeat(512))
        .body(())
        .unwrap();
    let (_, body) = pipe(state.new_memory());
    let response = state.handle(request, body).await;
    assert_eq!(
        response.status(),
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
    );
    assert!(response.headers().is_empty());
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
        assert!(String::from_utf8_lossy(&response).starts_with(&format!("HTTP/1.1 {expected}")));
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
async fn h3_reset_upload_releases_resources_and_keeps_carrier_usable() {
    reset_upload_releases_resources_and_keeps_carrier_usable(XhttpVersion::H3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_reset_upload_releases_resources_and_keeps_carrier_usable() {
    reset_upload_releases_resources_and_keeps_carrier_usable(XhttpVersion::H2).await;
}

async fn reset_upload_releases_resources_and_keeps_carrier_usable(version: XhttpVersion) {
    tokio::time::timeout(Duration::from_secs(10), async {
        let state = service();
        let (carrier, _server, _endpoint) = streaming_carrier(state.clone(), version).await;
        let memory = Memory::new(Arc::new(Budget::new(Some(1024))), Some(1024));
        for sequence in 0..2 {
            let tasks = Tasks::new();
            let (mut writer, reader) = pipe(memory.clone());
            writer.write_all(b"partial").await.unwrap();
            let packet = Request::post(format!("https://localhost/t/session{sequence}/0"))
                .header("referer", format!("/?x_padding={}", "X".repeat(100)))
                .header("content-length", "16")
                .body(Body::stream(reader))
                .unwrap();
            let request = carrier.request(packet, memory.clone(), &tasks, Duration::from_secs(2));
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
async fn h3_upload_only_reset_releases_request_without_response_read() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let state = service();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let mut config = quinn::ServerConfig::with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
        // Without idle timeouts, a regression holds the request until the deadline
        // instead of being released when the connection idles out.
        Arc::get_mut(&mut config.transport)
            .unwrap()
            .max_idle_timeout(None);
        let server = quinn::Endpoint::server(config, "0.0.0.0:0".parse().unwrap()).unwrap();
        let mut client = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        let mut config = quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
        let mut transport = quinn::TransportConfig::default();
        transport
            .stream_receive_window(1u32.into())
            .max_idle_timeout(None);
        config.transport_config(Arc::new(transport));
        client.set_default_client_config(config);
        let address = ([127, 0, 0, 1], server.local_addr().unwrap().port()).into();
        let (outgoing, incoming) =
            tokio::join!(client.connect(address, "localhost").unwrap(), async {
                server.accept().await.unwrap().await.unwrap()
            });
        let tasks = Tasks::new();
        let serving = state.clone();
        tasks.spawn(async move {
            let _ = XhttpServer { state: serving }.serve_h3(incoming).await;
        });
        let (mut driver, mut sender) =
            h3::client::new(h3_quinn::Connection::new(outgoing.unwrap()))
                .await
                .unwrap();
        tasks.spawn(async move {
            let _ = futures::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let packet = Request::post("https://localhost/t/session/0")
            .header("referer", format!("/?x_padding={}", "X".repeat(100)))
            .header("content-length", "16")
            .body(())
            .unwrap();
        // Keep the unread receive half: dropping it would send STOP_SENDING.
        let (mut send, _receive) = sender.send_request(packet).await.unwrap().split();
        send.send_data(Bytes::from_static(b"partial"))
            .await
            .unwrap();
        while state.memory.snapshot().active == 0 {
            tokio::task::yield_now().await;
        }
        send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        while state.requests.snapshot().active != 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(state.admission.snapshot().active, 0);
        assert_eq!(state.memory.snapshot().active, 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn h2_library_body_resets_remain_stream_local() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let state = service();
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
                let (carrier, tasks, endpoint) = streaming_carrier(state.clone(), version).await;
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
    let response = tokio::time::timeout(Duration::from_millis(100), state.handle(request, reader))
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

#[tokio::test]
async fn matching_headers_accept_any_configured_value() {
    let mut state = service();
    Arc::get_mut(&mut state).unwrap().config.matching_headers = [(
        "x-token".into(),
        crate::option_util::OneOrSome::Some(vec!["old".into(), "new".into()]),
    )]
    .into();
    for (value, status) in [
        ("old", StatusCode::OK),
        ("new", StatusCode::OK),
        ("other", StatusCode::NOT_FOUND),
    ] {
        let request = Request::options("http://localhost/t/")
            .header("x-token", value)
            .body(())
            .unwrap();
        let (_writer, body) = pipe(state.new_memory());
        assert_eq!(state.handle(request, body).await.status(), status);
    }
}
