//! Bounded local ACME fixture, not a claim of interoperability with a public CA.
//! Checks JWS signatures/nonces, performs challenges over real sockets, verifies
//! CSRs, and signs leaf certificates with a private test CA.
use super::*;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

thread_local! {
    pub(super) static FAIL_STATE_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[test]
fn retry_after_parsing_preserves_supported_and_ignored_headers() {
    let mut headers = http::HeaderMap::new();
    assert!(parse_retry_after(&headers).unwrap().is_none());
    for value in [
        http::HeaderValue::from_static("invalid"),
        http::HeaderValue::from_static("-1"),
        http::HeaderValue::from_static("Sat, 01 Jan 2000 00:00:00 GMT"),
        http::HeaderValue::from_bytes(b"\xff").unwrap(),
    ] {
        headers.insert(http::header::RETRY_AFTER, value);
        assert!(parse_retry_after(&headers).unwrap().is_none());
    }
    for (value, seconds) in [("0", 0), (" 120\t", 120)] {
        headers.insert(http::header::RETRY_AFTER, value.parse().unwrap());
        let before = Instant::now();
        let deadline = parse_retry_after(&headers).unwrap().unwrap();
        let after = Instant::now();
        let delay = Duration::from_secs(seconds);
        assert!((before + delay..=after + delay).contains(&deadline));
    }
    let date = httpdate::fmt_http_date(SystemTime::now() + Duration::from_secs(3600));
    headers.insert(http::header::RETRY_AFTER, date.parse().unwrap());
    let remaining = parse_retry_after(&headers)
        .unwrap()
        .unwrap()
        .duration_since(Instant::now());
    assert!((3598..=3600).contains(&remaining.as_secs()));
    for seconds in [MAX_RETRY_AFTER.as_secs() + 1, u64::MAX] {
        headers.insert(
            http::header::RETRY_AFTER,
            seconds.to_string().parse().unwrap(),
        );
        let error = parse_retry_after(&headers).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            error.to_string(),
            "ACME Retry-After exceeds supported range"
        );
    }
}

#[test]
fn directory_nonce_metadata_requires_an_absolute_request_url() {
    for directory in [
        json!({}),
        json!({"newNonce": null}),
        json!({"newNonce": 123}),
        json!({"newNonce": ""}),
        json!({"newNonce": "/nonce"}),
        json!({"newNonce": "https://ca.test/non ce"}),
        json!({"newNonce": format!("https://ca.test/{}", "n".repeat(65536))}),
    ] {
        let error = validate_directory(
            http::StatusCode::OK,
            &serde_json::to_vec(&directory).unwrap(),
            None,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "invalid ACME directory");
    }
    validate_directory(
        http::StatusCode::OK,
        br#"{"newNonce":"https://ca.test/nonce"}"#,
        None,
    )
    .unwrap();
}

// Protocol/persistence tests skip short poll waits, but still enter the worker's
// due-selection path. Scheduling tests use turn() or run() without this shortcut.
async fn drive(
    source: &Arc<Source>,
    config: &AcmeConfig,
    client: HttpClient,
) -> Result<Turn, instant_acme::Error> {
    let mut scheduler = Scheduler::new();
    scheduler.client = Some(client);
    for _ in 0..10 {
        let turn = scheduler.turn(source, config).await;
        match turn.outcome {
            Err(error) => return Err(error),
            Ok(Progress::Pending) if turn.wake_at <= now() + POLL_INTERVAL.as_secs() as i64 + 3 => {
                expire_retry(config);
            }
            Ok(Progress::Idle) if turn.wake_at <= now() => {}
            _ => return Ok(turn),
        }
    }
    panic!("fixture did not finish within ten worker turns");
}

fn expire_retry(config: &AcmeConfig) {
    let mut state = load(config).unwrap().unwrap();
    state.retry_at = 0;
    persist(config, &state).unwrap();
}

struct Order {
    status: &'static str,
    challenge_status: &'static str,
    token: String,
    certificate: Option<String>,
}

struct CaState {
    base: String,
    nonce_url: Option<String>,
    kind: &'static str,
    challenge_address: SocketAddr,
    issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
    jwk: Option<Value>,
    accounts: usize,
    orders: Vec<Order>,
    nonces: HashSet<String>,
    ari_window: Option<(i64, i64)>,
    ari_requests: usize,
    ari_failure: bool,
    ari_stall: bool,
    ari_retry_after: u64,
    break_state: Option<std::path::PathBuf>,
    order_retry_after: Option<u64>,
    new_order_retry_after: Option<u64>,
    finalize_retry_after: Option<u64>,
    authorization_retry_after: Option<u64>,
    challenge_retry_after: Option<u64>,
    challenge_stall: bool,
    order_requests: usize,
    defer_validation: bool,
    missing_order_status: Option<u16>,
    invalidate_on_poll: bool,
    invalid_authorization: bool,
    challenge_requests: usize,
    failure_retry_after: Option<u64>,
    nonce_failure: bool,
    bad_nonces: usize,
    fail_state_sync_on: Option<&'static str>,
}

struct Fixture {
    state: Arc<Mutex<CaState>>,
    fail: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    tasks: JoinSet<()>,
    ca_pem: String,
}

impl Fixture {
    async fn new(challenge_address: SocketAddr, tls_alpn: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("https://{}", listener.local_addr().unwrap());
        let tls = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let tls_config = crate::rustls_config_util::try_create_server_config(
            tls.cert.pem().as_bytes(),
            tls.signing_key.serialize_pem().as_bytes(),
            vec![],
            &[],
            &[],
            &Default::default(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Shoes local ACME fixture");
        let issuer =
            rcgen::CertifiedIssuer::self_signed(params, rcgen::KeyPair::generate().unwrap())
                .unwrap();
        let state = Arc::new(Mutex::new(CaState {
            base,
            nonce_url: None,
            kind: if tls_alpn { "tls-alpn-01" } else { "http-01" },
            challenge_address,
            issuer,
            jwk: None,
            accounts: 0,
            orders: vec![],
            nonces: HashSet::new(),
            ari_window: None,
            ari_requests: 0,
            ari_failure: false,
            ari_stall: false,
            ari_retry_after: 3600,
            break_state: None,
            order_retry_after: None,
            new_order_retry_after: None,
            finalize_retry_after: None,
            authorization_retry_after: None,
            challenge_retry_after: None,
            challenge_stall: false,
            order_requests: 0,
            defer_validation: false,
            missing_order_status: None,
            invalidate_on_poll: false,
            invalid_authorization: false,
            challenge_requests: 0,
            failure_retry_after: Some(120),
            nonce_failure: false,
            bad_nonces: 0,
            fail_state_sync_on: None,
        }));
        let fail = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let mut tasks = JoinSet::new();
        let server_state = state.clone();
        let failing = fail.clone();
        let count = requests.clone();
        tasks.spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        assert!(connections.len() < 32);
                        let acceptor = acceptor.clone();
                        let state = server_state.clone();
                        let fail = failing.clone();
                        let count = count.clone();
                        connections.spawn(async move {
                            let connection = async {
                                let stream = acceptor.accept(stream).await?;
                                let service = hyper::service::service_fn(move |request| {
                                    assert!(count.fetch_add(1, Ordering::SeqCst) < 1000);
                                    handle(request, state.clone(), fail.clone())
                                });
                                hyper::server::conn::http1::Builder::new().max_buf_size(32 * 1024)
                                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service).await.map_err(io::Error::other)
                            };
                            let _ = tokio::time::timeout(Duration::from_secs(15), connection).await;
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        Self {
            state,
            fail,
            requests,
            tasks,
            ca_pem: tls.cert.pem(),
        }
    }

    fn config(&self, directory: &Path, tls_alpn: bool) -> AcmeConfig {
        let ca = directory.join("ca.crt");
        std::fs::write(&ca, &self.ca_pem).unwrap();
        let state = self.state.lock();
        AcmeConfig {
            domains: vec!["proxy.test".into()],
            directory_url: format!("{}/directory", state.base),
            state_dir: directory.join("state"),
            terms_of_service: Some("https://ca.test/terms".into()),
            contacts: vec!["mailto:test@example.invalid".into()],
            ca_cert: Some(ca),
            challenge: if tls_alpn {
                ChallengeConfig::TlsAlpn01
            } else {
                ChallengeConfig::Http01 {
                    listen: vec![state.challenge_address],
                }
            },
        }
    }
}

fn response(
    state: &mut CaState,
    status: u16,
    body: impl Into<Bytes>,
    location: Option<String>,
) -> http::Response<Full<Bytes>> {
    let nonce = B64.encode(rand::random::<[u8; 24]>());
    state.nonces.insert(nonce.clone());
    let mut response = http::Response::builder()
        .status(status)
        .header("replay-nonce", nonce)
        .header("content-type", "application/json");
    if let Some(location) = location {
        response = response.header("location", location);
    }
    response.body(Full::new(body.into())).unwrap()
}

fn order_json(state: &CaState, id: usize) -> Value {
    let order = &state.orders[id];
    json!({"status": order.status, "identifiers": [{"type":"dns", "value":"proxy.test"}],
        "authorizations":[format!("{}/auth/{id}", state.base)], "finalize":format!("{}/finalize/{id}", state.base),
        "certificate": order.certificate.as_ref().map(|_| format!("{}/certificate/{id}", state.base))})
}

fn thumbprint(jwk: &Value) -> String {
    let canonical = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        jwk["x"].as_str().unwrap(),
        jwk["y"].as_str().unwrap()
    );
    B64.encode(aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA256,
        canonical.as_bytes(),
    ))
}

async fn handle(
    request: http::Request<hyper::body::Incoming>,
    state: Arc<Mutex<CaState>>,
    fail: Arc<AtomicBool>,
) -> Result<http::Response<Full<Bytes>>, io::Error> {
    let path = request.uri().path().to_owned();
    if fail.load(Ordering::SeqCst) {
        let mut state = state.lock();
        let mut response = response(&mut state, 503, json!({"type":"urn:ietf:params:acme:error:serverInternal", "status":503, "detail":"fixture failure"}).to_string(), None);
        if let Some(delay) = state.failure_retry_after {
            response
                .headers_mut()
                .insert("retry-after", delay.to_string().parse().unwrap());
        }
        return Ok(response);
    }
    if path == "/directory" {
        let mut state = state.lock();
        let nonce_url = state
            .nonce_url
            .clone()
            .unwrap_or_else(|| format!("{}/nonce", state.base));
        let value = json!({"newNonce":nonce_url, "newAccount":format!("{}/account", state.base),
            "renewalInfo": state.ari_window.map(|_| format!("{}/renewal", state.base)),
            "newOrder":format!("{}/new-order", state.base), "meta":{"termsOfService":"https://ca.test/terms"}});
        return Ok(response(&mut state, 200, value.to_string(), None));
    }
    if path == "/nonce" {
        let mut state = state.lock();
        let status = if state.nonce_failure { 404 } else { 200 };
        return Ok(response(&mut state, status, Bytes::new(), None));
    }
    if path.starts_with("/renewal/") {
        assert_eq!(request.method(), http::Method::GET);
        let stalled = {
            let mut state = state.lock();
            state.ari_requests += 1;
            state.ari_stall
        };
        if stalled {
            std::future::pending::<()>().await;
        }
        let mut state = state.lock();
        let (status, value) = if state.ari_failure {
            (
                503,
                json!({"type":"urn:ietf:params:acme:error:serverInternal", "status":503}),
            )
        } else {
            let (start, end) = state.ari_window.unwrap();
            (
                200,
                json!({"suggestedWindow": {
                    "start": chrono::DateTime::from_timestamp(start, 0).unwrap().to_rfc3339(),
                    "end": chrono::DateTime::from_timestamp(end, 0).unwrap().to_rfc3339()
                }}),
            )
        };
        let mut response = response(&mut state, status, value.to_string(), None);
        response.headers_mut().insert(
            "retry-after",
            state.ari_retry_after.to_string().parse().unwrap(),
        );
        return Ok(response);
    }
    assert_eq!(request.method(), http::Method::POST);
    let bytes = Limited::new(request.into_body(), 64 * 1024)
        .collect()
        .await
        .map_err(io::Error::other)?
        .to_bytes();
    let jws: Value = serde_json::from_slice(&bytes).unwrap();
    let protected: Value =
        serde_json::from_slice(&B64.decode(jws["protected"].as_str().unwrap()).unwrap()).unwrap();
    let payload = B64.decode(jws["payload"].as_str().unwrap()).unwrap();
    let payload: Value = if payload.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&payload).unwrap()
    };
    {
        let mut state = state.lock();
        assert_eq!(protected["url"], format!("{}{path}", state.base));
        assert_eq!(protected["alg"], "ES256");
        assert!(
            state.nonces.remove(protected["nonce"].as_str().unwrap()),
            "nonce replay"
        );
        let jwk = protected.get("jwk").or(state.jwk.as_ref()).unwrap();
        let mut key = vec![4];
        key.extend(B64.decode(jwk["x"].as_str().unwrap()).unwrap());
        key.extend(B64.decode(jwk["y"].as_str().unwrap()).unwrap());
        let signature = B64.decode(jws["signature"].as_str().unwrap()).unwrap();
        aws_lc_rs::signature::UnparsedPublicKey::new(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED,
            key,
        )
        .verify(
            format!(
                "{}.{}",
                jws["protected"].as_str().unwrap(),
                jws["payload"].as_str().unwrap()
            )
            .as_bytes(),
            &signature,
        )
        .unwrap();
        if path == "/account" {
            if protected.get("jwk").is_some() {
                assert_eq!(payload["termsOfServiceAgreed"], true);
                if state.jwk.is_none() {
                    state.accounts += 1;
                }
                state.jwk = Some(protected["jwk"].clone());
            }
            let location = format!("{}/account", state.base);
            return Ok(response(
                &mut state,
                200,
                json!({"status":"valid"}).to_string(),
                Some(location),
            ));
        }
        assert_eq!(protected["kid"], format!("{}/account", state.base));
        if state.fail_state_sync_on == Some(path.as_str()) {
            state.fail_state_sync_on = None;
            FAIL_STATE_SYNC.set(true);
        }
        if state.bad_nonces > 0 {
            state.bad_nonces -= 1;
            let mut response = response(
                &mut state,
                400,
                json!({"type":"urn:ietf:params:acme:error:badNonce"}).to_string(),
                None,
            );
            response
                .headers_mut()
                .insert("retry-after", "900".parse().unwrap());
            return Ok(response);
        }
        if path == "/new-order" {
            assert_eq!(
                payload["identifiers"],
                json!([{"type":"dns", "value":"proxy.test"}])
            );
            let id = state.orders.len();
            state.orders.push(Order {
                status: "pending",
                challenge_status: "pending",
                token: B64.encode(rand::random::<[u8; 24]>()),
                certificate: None,
            });
            let order = order_json(&state, id).to_string();
            let location = format!("{}/order/{id}", state.base);
            let mut response = response(&mut state, 201, order, Some(location));
            if let Some(delay) = state.new_order_retry_after {
                response
                    .headers_mut()
                    .insert("retry-after", delay.to_string().parse().unwrap());
            }
            return Ok(response);
        }
    }
    let (operation, id) = path.trim_start_matches('/').split_once('/').unwrap();
    let id: usize = id.parse().unwrap();
    if operation == "challenge" {
        let (deferred, stalled) = {
            let mut state = state.lock();
            assert_eq!(
                state.orders[id].challenge_status, "pending",
                "processing challenges must not be resubmitted"
            );
            state.orders[id].challenge_status = "processing";
            state.challenge_requests += 1;
            (state.defer_validation, state.challenge_stall)
        };
        if stalled {
            std::future::pending::<()>().await;
        }
        if !deferred {
            validate_challenge(&state, id).await?;
        }
        let mut state = state.lock();
        let value = json!({"type":state.kind, "url":format!("{}/challenge/{id}", state.base),
            "token":state.orders[id].token, "status":if deferred {"processing"} else {"valid"}});
        let mut response = response(&mut state, 200, value.to_string(), None);
        if let Some(delay) = state.challenge_retry_after {
            response
                .headers_mut()
                .insert("retry-after", delay.to_string().parse().unwrap());
        }
        return Ok(response);
    }
    let mut state = state.lock();
    let value = match operation {
        "order" => {
            state.order_requests += 1;
            if let Some(status) = state.missing_order_status {
                let mut response = response(
                    &mut state,
                    status,
                    json!({"type":"urn:ietf:params:acme:error:malformed", "detail":"order absent"})
                        .to_string(),
                    None,
                );
                if let Some(delay) = state.order_retry_after {
                    response
                        .headers_mut()
                        .insert("retry-after", delay.to_string().parse().unwrap());
                }
                return Ok(response);
            }
            if state.invalidate_on_poll {
                state.orders[id].status = "invalid";
                state.orders[id].challenge_status = "invalid";
            }
            order_json(&state, id)
        }
        "auth" => json!({"identifier":{"type":"dns", "value":"proxy.test"},
            "status": if state.invalid_authorization || state.orders[id].status == "invalid" {"invalid"} else if state.orders[id].status == "pending" {"pending"} else {"valid"},
            "challenges":[{"type":state.kind, "url":format!("{}/challenge/{id}", state.base),
                "token":state.orders[id].token, "status":state.orders[id].challenge_status,
                "error": if state.invalid_authorization || state.orders[id].challenge_status == "invalid" {
                    Some(json!({"type":"urn:ietf:params:acme:error:connection", "detail":"PRIVATE VALIDATION DATA"}))
                } else { None }}]}),
        "finalize" => {
            assert_eq!(state.orders[id].status, "ready");
            let csr = B64.decode(payload["csr"].as_str().unwrap()).unwrap();
            let mut csr = rcgen::CertificateSigningRequestParams::from_der(&csr.into()).unwrap();
            assert_eq!(
                csr.params.subject_alt_names,
                [rcgen::SanType::DnsName("proxy.test".try_into().unwrap())]
            );
            csr.params.serial_number = Some((id as u64 + 1).into());
            csr.params.use_authority_key_identifier_extension = true;
            let cert = csr.signed_by(&state.issuer).unwrap();
            state.orders[id].certificate = Some(format!("{}{}", cert.pem(), state.issuer.pem()));
            state.orders[id].status =
                if state.order_retry_after.is_some() || state.finalize_retry_after.is_some() {
                    "processing"
                } else {
                    "valid"
                };
            if let Some(directory) = state.break_state.take() {
                std::fs::rename(directory.join("state.json"), directory.join("state.before"))
                    .unwrap();
                std::fs::create_dir(directory.join("state.json")).unwrap();
            }
            order_json(&state, id)
        }
        "certificate" => {
            let cert = state.orders[id].certificate.clone().unwrap();
            return Ok(response(&mut state, 200, cert, None));
        }
        _ => panic!("unexpected fixture path: {path}"),
    };
    let mut response = response(&mut state, 200, value.to_string(), None);
    let retry_after = match operation {
        "order" => state.order_retry_after,
        "finalize" => state.finalize_retry_after,
        "auth" => state.authorization_retry_after,
        _ => None,
    };
    if let Some(delay) = retry_after {
        response
            .headers_mut()
            .insert("retry-after", delay.to_string().parse().unwrap());
    }
    Ok(response)
}

async fn validate_challenge(state: &Arc<Mutex<CaState>>, id: usize) -> io::Result<()> {
    let (address, kind, token, authorization) = {
        let state = state.lock();
        let token = state.orders[id].token.clone();
        (
            state.challenge_address,
            state.kind,
            token.clone(),
            format!("{token}.{}", thumbprint(state.jwk.as_ref().unwrap())),
        )
    };
    if kind == "http-01" {
        let mut stream = TcpStream::connect(address).await?;
        stream
            .write_all(
                format!(
                    "GET /.well-known/acme-challenge/{token} HTTP/1.1\r\nHost: proxy.test\r\n\r\n"
                )
                .as_bytes(),
            )
            .await?;
        let mut bytes = Vec::new();
        stream.take(8192).read_to_end(&mut bytes).await?;
        let bytes = String::from_utf8(bytes).unwrap();
        assert!(bytes.starts_with("HTTP/1.1 200 "));
        assert_eq!(bytes.split_once("\r\n\r\n").unwrap().1, authorization);
    } else {
        validate_tls_challenge(address, &authorization).await;
    }
    state.lock().orders[id].status = "ready";
    state.lock().orders[id].challenge_status = "valid";
    Ok(())
}

#[derive(Debug)]
struct ChallengeVerifier(Vec<u8>);

impl rustls::client::danger::ServerCertVerifier for ChallengeVerifier {
    fn verify_server_cert(
        &self,
        end: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        name: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        assert!(intermediates.is_empty());
        assert_eq!(name.to_str(), "proxy.test");
        let (_, parsed) = x509_parser::parse_x509_certificate(end).unwrap();
        parsed.verify_signature(None).unwrap();
        assert!(parsed.validity().is_valid());
        assert!(parsed.validity().not_after.timestamp() <= now() + 600);
        let san = parsed.subject_alternative_name().unwrap().unwrap();
        assert_eq!(
            san.value.general_names,
            [x509_parser::extensions::GeneralName::DNSName("proxy.test")]
        );
        let extension = parsed
            .extensions()
            .iter()
            .find(|extension| extension.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
            .unwrap();
        assert!(extension.critical);
        assert_eq!(&extension.value[..2], &[4, 32]);
        assert_eq!(&extension.value[2..], self.0);
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.verify_tls13_signature(message, cert, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let (_, cert) = x509_parser::parse_x509_certificate(cert).unwrap();
        assert_eq!(
            signature.scheme,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256
        );
        aws_lc_rs::signature::UnparsedPublicKey::new(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
            cert.public_key().subject_public_key.data.as_ref(),
        )
        .verify(message, signature.signature())
        .unwrap();
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

async fn validate_tls_challenge(address: SocketAddr, authorization: &str) {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, authorization.as_bytes());
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(ChallengeVerifier(digest.as_ref().to_vec())))
    .with_no_client_auth();
    config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let mut stream = connector
        .connect(
            "proxy.test".try_into().unwrap(),
            TcpStream::connect(address).await.unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        Some(b"acme-tls/1".as_slice())
    );
    assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
}

#[derive(Debug)]
struct CountProxy(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl crate::tcp::tcp_handler::TcpServerHandler for CountProxy {
    async fn setup_server_stream(
        &self,
        _: Box<dyn crate::async_stream::AsyncStream>,
    ) -> io::Result<crate::tcp::tcp_handler::TcpServerSetupResult> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::other("test proxy reached"))
    }
}

fn tls_handler(
    source: Arc<Source>,
    count: Arc<AtomicUsize>,
) -> crate::tls_server_handler::TlsServerHandler {
    let config = crate::rustls_config_util::try_create_server_config_with_source(
        &[],
        &[],
        vec![],
        &["normal".into()],
        &[],
        &Default::default(),
        Some(&source),
    )
    .unwrap();
    let target = crate::tls_server_handler::TlsServerTarget::Tls {
        certificate_source: Some(source),
        server_config: Arc::new(config),
        effective_selector: Arc::new(crate::client_proxy_selector::ClientProxySelector::new(
            vec![],
        )),
        inner_protocol: crate::tls_server_handler::InnerProtocol::Normal(Box::new(CountProxy(
            count,
        ))),
    };
    crate::tls_server_handler::TlsServerHandler::new(
        [("proxy.test".to_owned(), target)].into_iter().collect(),
        None,
        None,
        Arc::new(crate::resolver::NativeResolver::new()),
    )
}

fn serve_challenges(
    listener: TcpListener,
    source: Arc<Source>,
    tls_alpn: bool,
    count: Arc<AtomicUsize>,
) -> JoinSet<()> {
    let mut serving = JoinSet::new();
    if tls_alpn {
        use crate::tcp::tcp_handler::TcpServerHandler;
        let handler = Arc::new(tls_handler(source.clone(), count.clone()));
        serving.spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        let handler = handler.clone();
                        connections.spawn(async move { handler.setup_server_stream(Box::new(stream)).await });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
    } else {
        serving.spawn(async move {
            challenge::serve(vec![Arc::new(listener)], source)
                .await
                .unwrap();
        });
    }
    serving
}

async fn issuance_roundtrip(tls_alpn: bool) {
    let directory = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut fixture = Fixture::new(listener.local_addr().unwrap(), tls_alpn).await;
    let config = fixture.config(directory.path(), tls_alpn);
    let source = Source::new("fixture".into(), super::super::Spec::Acme(config.clone())).unwrap();
    assert!(source.current().is_none());
    let lock = lock_state(&config).unwrap();
    assert!(lock_state(&config).is_err(), "storage must have one owner");
    let count = Arc::new(AtomicUsize::new(0));
    let mut serving = serve_challenges(listener, source.clone(), tls_alpn, count.clone());
    let client = HttpClient::new(client_tls(config.ca_cert.as_deref()).unwrap(), &config);
    drive(&source, &config, client.clone()).await.unwrap();
    let first = source.current().unwrap().cert[0].clone();
    assert!(source.challenges.read().is_empty());
    assert_eq!(fixture.state.lock().accounts, 1);
    assert_eq!(fixture.state.lock().orders.len(), 1);
    assert_eq!(count.load(Ordering::SeqCst), 0);
    let resumed = Source::new("fixture".into(), super::super::Spec::Acme(config.clone())).unwrap();
    load_cached(&resumed, &config).unwrap();
    assert_eq!(resumed.current().unwrap().cert[0], first);
    drive(&resumed, &config, client.clone()).await.unwrap();
    assert_eq!(fixture.state.lock().accounts, 1);
    assert_eq!(fixture.state.lock().orders.len(), 1);
    {
        let mut material = source.material.write();
        let material = material.as_mut().unwrap();
        material.not_before = now() - 600;
        material.not_after = now() + 30;
    }
    drive(&source, &config, client.clone()).await.unwrap();
    assert_ne!(source.current().unwrap().cert[0], first);
    assert_eq!(fixture.state.lock().orders.len(), 2);
    assert_eq!(fixture.state.lock().accounts, 1);
    let durable = source.current().unwrap().cert[0].clone();
    {
        let mut material = source.material.write();
        let material = material.as_mut().unwrap();
        material.not_before = now() - 600;
        material.not_after = now() + 30;
    }
    fixture.state.lock().break_state = Some(config.state_dir.clone());
    assert!(drive(&source, &config, client.clone()).await.is_err());
    assert_eq!(
        source.current().unwrap().cert[0],
        durable,
        "failed persistence must not publish"
    );
    std::fs::remove_dir(config.state_dir.join("state.json")).unwrap();
    std::fs::rename(
        config.state_dir.join("state.before"),
        config.state_dir.join("state.json"),
    )
    .unwrap();
    drive(&source, &config, client.clone()).await.unwrap();
    assert_ne!(source.current().unwrap().cert[0], durable);
    assert_eq!(
        fixture.state.lock().orders.len(),
        3,
        "resume the persisted order instead of issuing another"
    );
    fixture.fail.store(true, Ordering::SeqCst);
    let before = source.current().unwrap().cert[0].clone();
    drive(&resumed, &config, client.clone()).await.unwrap();
    assert_eq!(
        resumed.current().unwrap().cert[0],
        before,
        "recover a durable pair not yet published, even while the CA is unavailable"
    );
    assert_eq!(fixture.state.lock().orders.len(), 3);
    {
        let mut material = source.material.write();
        let material = material.as_mut().unwrap();
        material.not_before = now() - 600;
        material.not_after = now() + 30;
    }
    let error = drive(&source, &config, client).await.unwrap_err();
    assert!(failure_message(&error).contains("HTTP 503"));
    assert!(!failure_message(&error).contains("terms_of_service"));
    assert_eq!(source.current().unwrap().cert[0], before);
    let restarted =
        Source::new("fixture".into(), super::super::Spec::Acme(config.clone())).unwrap();
    load_cached(&restarted, &config).unwrap();
    assert!(
        restarted.current().is_some(),
        "cached certificate must not depend on CA availability"
    );
    let mut renewal = JoinSet::new();
    let worker_source = source.clone();
    let worker_config = config.clone();
    renewal.spawn(async move { run(worker_source, &worker_config).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if load(&config)
                .unwrap()
                .is_some_and(|state| state.retry_at >= now() + 100)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let requests = fixture.requests.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(fixture.requests.load(Ordering::SeqCst), requests);
    renewal.shutdown().await;
    serving.shutdown().await;
    fixture.tasks.shutdown().await;
    drop(lock);
    assert!(lock_state(&config).is_ok());
}

#[tokio::test]
async fn http01_issuance_renewal_restart_and_outage() {
    tokio::time::timeout(Duration::from_secs(30), issuance_roundtrip(false))
        .await
        .unwrap();
}

#[tokio::test]
async fn tls_alpn01_issuance_renewal_restart_and_outage() {
    tokio::time::timeout(Duration::from_secs(30), issuance_roundtrip(true))
        .await
        .unwrap();
}

#[tokio::test]
async fn ari_window_and_retry_after_survive_restart() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let directory = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut fixture = Fixture::new(listener.local_addr().unwrap(), false).await;
        fixture.state.lock().ari_window = Some((now() + 1000, now() + 2000));
        let config = fixture.config(directory.path(), false);
        let _lock = lock_state(&config).unwrap();
        let source =
            Source::new("fixture".into(), super::super::Spec::Acme(config.clone())).unwrap();
        let mut serving = JoinSet::new();
        let serving_source = source.clone();
        serving
            .spawn(async move { challenge::serve(vec![Arc::new(listener)], serving_source).await });
        let client = HttpClient::new(client_tls(config.ca_cert.as_deref()).unwrap(), &config);
        drive(&source, &config, client.clone()).await.unwrap();
        let turn = drive(&source, &config, client.clone()).await.unwrap();
        assert!(matches!(turn.outcome, Ok(Progress::Idle)));
        assert!((990..=2000).contains(&(turn.wake_at - now())));
        assert_eq!(fixture.state.lock().ari_requests, 1);
        let reloaded =
            Source::new("fixture".into(), super::super::Spec::Acme(config.clone())).unwrap();
        load_cached(&reloaded, &config).unwrap();
        drive(&reloaded, &config, client.clone()).await.unwrap();
        assert_eq!(fixture.state.lock().ari_requests, 1);

        let mut state = load(&config).unwrap().unwrap();
        state.ari_retry_at = 0;
        persist(&config, &state).unwrap();
        fixture.state.lock().ari_failure = true;
        fixture.state.lock().ari_retry_after = 24 * 3600;
        drive(&source, &config, client.clone()).await.unwrap();
        let failed = load(&config).unwrap().unwrap();
        assert!(failed.ari_retry_at >= now() + 24 * 3600);
        assert_eq!(
            failed.retry_at, 0,
            "ARI must not set an order retry deadline"
        );
        assert_eq!(fixture.state.lock().ari_requests, 2);
        let restarted_client = HttpClient {
            last: Arc::new(Mutex::new(None)),
            ..client.clone()
        };
        drive(&reloaded, &config, restarted_client).await.unwrap();
        assert_eq!(fixture.state.lock().ari_requests, 2);
        assert_eq!(
            load(&config).unwrap().unwrap().ari_retry_at,
            failed.ari_retry_at
        );

        let mut state = load(&config).unwrap().unwrap();
        state.ari_retry_at = 0;
        persist(&config, &state).unwrap();
        fixture.state.lock().ari_failure = false;
        fixture.state.lock().ari_retry_after = 3600;
        fixture.state.lock().ari_window = Some((now() - 200, now() - 100));
        drive(&source, &config, client).await.unwrap();
        assert_eq!(fixture.state.lock().ari_requests, 3);
        assert_eq!(fixture.state.lock().orders.len(), 2);
        serving.shutdown().await;
        fixture.tasks.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn malformed_directory_nonce_url_backs_off_and_recovers() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let directory = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut fixture = Fixture::new(listener.local_addr().unwrap(), false).await;
        fixture.state.lock().nonce_url = Some("https://ca.test/non ce-PRIVATE-DATA".into());
        let config = fixture.config(directory.path(), false);
        let _lock = lock_state(&config).unwrap();
        let source =
            Source::new("fixture".into(), super::super::Spec::Acme(config.clone())).unwrap();
        let mut serving = serve_challenges(
            listener,
            source.clone(),
            false,
            Arc::new(AtomicUsize::new(0)),
        );
        let mut scheduler = Scheduler::new();
        let failed = scheduler.turn(&source, &config).await;
        assert_eq!(
            failure_message(&failed.outcome.unwrap_err()),
            "invalid ACME directory"
        );
        assert!(failed.wake_at >= now() + 60);
        assert_eq!(load(&config).unwrap().unwrap().retry_at, failed.wake_at);
        assert_eq!(scheduler.backoff, 120);
        assert_eq!(fixture.state.lock().accounts, 0);
        assert!(fixture.state.lock().orders.is_empty());

        fixture.state.lock().nonce_url = None;
        let requests = fixture.requests.load(Ordering::SeqCst);
        let deferred = scheduler.turn(&source, &config).await;
        assert_eq!(deferred.outcome.unwrap(), Progress::Deferred);
        assert_eq!(fixture.requests.load(Ordering::SeqCst), requests);
        for expected in [Progress::Pending, Progress::Installed] {
            expire_retry(&config);
            let turn = scheduler.turn(&source, &config).await;
            assert_eq!(turn.outcome.unwrap(), expected);
        }
        assert!(source.current().is_some());
        assert_eq!(fixture.state.lock().accounts, 1);
        assert_eq!(fixture.state.lock().orders.len(), 1);
        serving.shutdown().await;
        fixture.tasks.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn worker_renews_despite_failed_ari_deadline_with_and_without_restart() {
    for restart in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut fixture = Fixture::new(listener.local_addr().unwrap(), false).await;
        fixture.state.lock().ari_window = Some((now() + 1000, now() + 2000));
        fixture.state.lock().ari_failure = true;
        fixture.state.lock().ari_retry_after = 24 * 3600;
        let config = fixture.config(directory.path(), false);
        let _lock = lock_state(&config).unwrap();
        let source =
            Source::new("fixture".into(), super::super::Spec::Acme(config.clone())).unwrap();
        let mut serving = serve_challenges(
            listener,
            source.clone(),
            false,
            Arc::new(AtomicUsize::new(0)),
        );
        let client = HttpClient::new(client_tls(config.ca_cert.as_deref()).unwrap(), &config);
        drive(&source, &config, client).await.unwrap();
        let mut workers = JoinSet::new();
        let worker_source = source.clone();
        let worker_config = config.clone();
        workers.spawn(async move { run(worker_source, &worker_config).await });
        let mut state = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let state = load(&config).unwrap().unwrap();
                if state.ari_retry_at >= now() + 24 * 3600 {
                    break state;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(state.retry_at, 0);
        let ari_deadline = state.ari_retry_at;
        state.ari_renew_at = now() - 1;
        persist(&config, &state).unwrap();
        if restart {
            workers.shutdown().await;
            let worker_source = source.clone();
            let worker_config = config.clone();
            workers.spawn(async move { run(worker_source, &worker_config).await });
        } else {
            tokio::time::pause();
            tokio::time::advance(MAINTENANCE_INTERVAL).await;
            tokio::time::resume();
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let renewed = {
                    let state = fixture.state.lock();
                    state.orders.len() == 2 && state.challenge_requests == 2
                };
                if renewed {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(fixture.state.lock().ari_requests, 1);
        assert_eq!(load(&config).unwrap().unwrap().ari_retry_at, ari_deadline);
        assert!(load(&config).unwrap().unwrap().retry_at < now() + 30);
        workers.shutdown().await;
        serving.shutdown().await;
        fixture.tasks.shutdown().await;
    }
}

#[tokio::test]
async fn optional_ari_setup_timeout_and_unsupported_leave_mandatory_policy_untouched() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for mode in ["setup-failure", "timeout", "unsupported", "contacts"] {
            let directory = tempfile::tempdir().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut fixture = Fixture::new(listener.local_addr().unwrap(), false).await;
            if mode != "unsupported" {
                fixture.state.lock().ari_window = Some((now() + 1000, now() + 2000));
            }
            let mut config = fixture.config(directory.path(), false);
            let _lock = lock_state(&config).unwrap();
            let source =
                Source::new("fixture".into(), super::super::Spec::Acme(config.clone())).unwrap();
            let mut serving = serve_challenges(
                listener,
                source.clone(),
                false,
                Arc::new(AtomicUsize::new(0)),
            );
            let client = HttpClient::new(client_tls(config.ca_cert.as_deref()).unwrap(), &config);
            drive(&source, &config, client.clone()).await.unwrap();
            if mode == "contacts" {
                config
                    .contacts
                    .push("mailto:updated@example.invalid".into());
                let mut state = load(&config).unwrap().unwrap();
                state.ari_retry_at = now() + 24 * 3600;
                persist(&config, &state).unwrap();
            }
            let mut scheduler = Scheduler::new();
            scheduler.client = Some(client);
            scheduler.backoff = 240;
            fixture
                .fail
                .store(mode == "setup-failure", Ordering::SeqCst);
            fixture.state.lock().failure_retry_after = Some(24 * 3600);
            if mode == "timeout" {
                fixture.state.lock().ari_stall = true;
                let mut state = load(&config).unwrap().unwrap();
                state.ari_renew_at = now() + 2;
                persist(&config, &state).unwrap();
            }
            let started_at = now();
            let started = Instant::now();
            let turn = scheduler.turn(&source, &config).await;
            assert!(
                matches!(turn.outcome, Ok(Progress::Idle)),
                "{mode}: {turn:?}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(3),
                "optional work exceeded renewal deadline"
            );
            assert_eq!(scheduler.backoff, 240);
            let mut state = load(&config).unwrap().unwrap();
            assert_eq!(state.retry_at, 0, "{mode}");
            assert!(state.ari_retry_at >= started_at + 6 * 3600);
            if mode == "contacts" {
                assert_eq!(state.contacts, config.contacts);
                assert_eq!(
                    fixture.state.lock().ari_requests,
                    0,
                    "contact updates must not bypass an ARI deadline"
                );
            }
            if mode == "setup-failure" {
                assert!(state.ari_retry_at >= started_at + 24 * 3600);
            }
            if mode == "timeout" {
                assert_eq!(fixture.state.lock().ari_requests, 1);
            }
            fixture.fail.store(false, Ordering::SeqCst);
            fixture.state.lock().ari_stall = false;
            state.ari_renew_at = now() - 1;
            persist(&config, &state).unwrap();
            let turn = scheduler.turn(&source, &config).await;
            assert!(
                matches!(turn.outcome, Ok(Progress::Pending)),
                "{mode}: {turn:?}"
            );
            assert!(turn.wake_at < now() + 30);
            assert_eq!(
                scheduler.backoff, 240,
                "intermediate progress must not reset failures"
            );
            expire_retry(&config);
            assert!(matches!(
                scheduler.turn(&source, &config).await.outcome,
                Ok(Progress::Installed)
            ));
            assert_eq!(scheduler.backoff, 60);
            assert!(scheduler.account.is_none());
            assert_eq!(fixture.state.lock().orders.len(), 2);
            serving.shutdown().await;
            fixture.tasks.shutdown().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn order_metadata_is_operation_local_and_nonce_404_does_not_delete_order() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let directory = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut fixture = Fixture::new(listener.local_addr().unwrap(), false).await;
        fixture.state.lock().defer_validation = true;
        fixture.state.lock().bad_nonces = 1;
        let config = fixture.config(directory.path(), false);
        let _lock = lock_state(&config).unwrap();
        let source =
            Source::new("fixture".into(), super::super::Spec::Acme(config.clone())).unwrap();
        let mut serving = serve_challenges(
            listener,
            source.clone(),
            false,
            Arc::new(AtomicUsize::new(0)),
        );
        let mut scheduler = Scheduler::new();
        let turn = scheduler.turn(&source, &config).await;
        assert!(matches!(turn.outcome, Ok(Progress::Pending)));
        assert!(turn.wake_at < now() + 30, "recovered badNonce hint leaked");
        assert_eq!(fixture.state.lock().bad_nonces, 0);
        let order_url = load(&config).unwrap().unwrap().order_url;
        expire_retry(&config);
        fixture.state.lock().nonce_failure = true;
        let turn = scheduler.turn(&source, &config).await;
        assert!(turn.outcome.is_err());
        assert_eq!(load(&config).unwrap().unwrap().order_url, order_url);
        assert!(turn.wake_at < now() + 100);
        expire_retry(&config);
        fixture.state.lock().nonce_failure = false;
        fixture.state.lock().bad_nonces = 10;
        let turn = scheduler.turn(&source, &config).await;
        assert!(turn.outcome.is_err());
        assert!(turn.wake_at >= now() + 890, "terminal badNonce hint lost");
        assert_eq!(load(&config).unwrap().unwrap().order_url, order_url);
        expire_retry(&config);
        fixture.state.lock().bad_nonces = 0;
        let turn = scheduler.turn(&source, &config).await;
        assert!(matches!(turn.outcome, Ok(Progress::Pending)));
        assert!(turn.wake_at < now() + 30, "previous failure hint leaked");
        assert_eq!(fixture.state.lock().challenge_requests, 1);
        assert_eq!(scheduler.backoff, 240);
        validate_challenge(&fixture.state, 0).await.unwrap();
        expire_retry(&config);
        assert!(matches!(
            scheduler.turn(&source, &config).await.outcome,
            Ok(Progress::Installed)
        ));
        assert_eq!(scheduler.backoff, 60);
        serving.shutdown().await;
        fixture.tasks.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn pending_authorization_and_challenge_hints_survive_restart() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for (processing, authorization_hint, challenge_hint) in [
            (true, Some(900), None),
            (false, Some(900), None),
            (false, None, Some(900)),
            (false, Some(900), Some(300)),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut fixture = Fixture::new(listener.local_addr().unwrap(), false).await;
            fixture.state.lock().defer_validation = true;
            let config = fixture.config(directory.path(), false);
            let _lock = lock_state(&config).unwrap();
            let source =
                Source::new("fixture".into(), super::super::Spec::Acme(config.clone())).unwrap();
            let mut scheduler = Scheduler::new();
            if processing {
                assert_eq!(
                    scheduler.turn(&source, &config).await.outcome.unwrap(),
                    Progress::Pending
                );
                expire_retry(&config);
            }
            {
                let mut state = fixture.state.lock();
                state.authorization_retry_after = authorization_hint;
                state.challenge_retry_after = challenge_hint;
            }
            let turn = scheduler.turn(&source, &config).await;
            assert_eq!(turn.outcome.unwrap(), Progress::Pending);
            assert!(turn.wake_at >= now() + 890, "pending hint lost");
            assert_eq!(load(&config).unwrap().unwrap().retry_at, turn.wake_at);
            assert_eq!(scheduler.backoff, 60);
            assert_eq!(fixture.state.lock().challenge_requests, 1);
            assert_eq!(source.challenges.read().len(), 1);
            let requests = fixture.requests.load(Ordering::SeqCst);
            for scheduler in [&mut scheduler, &mut Scheduler::new()] {
                let deferred = scheduler.turn(&source, &config).await;
                assert_eq!(deferred.outcome.unwrap(), Progress::Deferred);
                assert_eq!(deferred.wake_at, turn.wake_at);
            }
            assert_eq!(fixture.requests.load(Ordering::SeqCst), requests);
            fixture.tasks.shutdown().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn authorization_hint_is_durable_before_challenge_submission_completes() {
    let directory = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut fixture = Fixture::new(listener.local_addr().unwrap(), false).await;
    {
        let mut state = fixture.state.lock();
        state.authorization_retry_after = Some(900);
        state.challenge_stall = true;
    }
    let config = fixture.config(directory.path(), false);
    let _lock = lock_state(&config).unwrap();
    let source = Source::new("fixture".into(), super::super::Spec::Acme(config.clone())).unwrap();
    let mut scheduler = Scheduler::new();
    let mut turn = Box::pin(scheduler.turn(&source, &config));
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                result = &mut turn => panic!("stalled submission completed: {result:?}"),
                _ = tokio::time::sleep(Duration::from_millis(10)) => {
                    if fixture.state.lock().challenge_requests == 1 {
                        break;
                    }
                }
            }
        }
    })
    .await
    .unwrap();
    // Cancellation must not depend on the final Pending or failure save.
    drop(turn);
    let state = load(&config).unwrap().unwrap();
    assert!(state.retry_at >= now() + 890);
    let requests = fixture.requests.load(Ordering::SeqCst);
    let deferred = Scheduler::new().turn(&source, &config).await;
    assert_eq!(deferred.outcome.unwrap(), Progress::Deferred);
    assert_eq!(deferred.wake_at, state.retry_at);
    assert_eq!(fixture.requests.load(Ordering::SeqCst), requests);
    fixture.tasks.shutdown().await;
}

#[tokio::test]
async fn order_hints_survive_persistence_and_challenge_preparation_failures() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for mode in [
            "create",
            "missing",
            "challenge",
            "authorization",
            "ready-response",
            "invalid-authorization-hint",
        ] {
            let directory = tempfile::tempdir().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut fixture = Fixture::new(listener.local_addr().unwrap(), false).await;
            fixture.state.lock().defer_validation = true;
            let config = fixture.config(directory.path(), false);
            let _lock = lock_state(&config).unwrap();
            let source =
                Source::new("fixture".into(), super::super::Spec::Acme(config.clone())).unwrap();
            let mut serving = serve_challenges(
                listener,
                source.clone(),
                false,
                Arc::new(AtomicUsize::new(0)),
            );
            let mut scheduler = Scheduler::new();
            if mode == "missing" {
                assert!(matches!(
                    scheduler.turn(&source, &config).await.outcome,
                    Ok(Progress::Pending)
                ));
                expire_retry(&config);
                let mut state = fixture.state.lock();
                state.missing_order_status = Some(404);
                state.order_retry_after = Some(900);
                state.fail_state_sync_on = Some("/order/0");
            } else {
                let mut state = fixture.state.lock();
                match mode {
                    "create" => {
                        state.new_order_retry_after = Some(900);
                        state.fail_state_sync_on = Some("/new-order");
                    }
                    "challenge" => {
                        state.new_order_retry_after = Some(900);
                        state.invalid_authorization = true;
                    }
                    "authorization" => {
                        state.authorization_retry_after = Some(900);
                        state.fail_state_sync_on = Some("/auth/0");
                    }
                    "ready-response" => {
                        state.challenge_retry_after = Some(900);
                        state.fail_state_sync_on = Some("/challenge/0");
                    }
                    "invalid-authorization-hint" => {
                        state.invalid_authorization = true;
                        state.authorization_retry_after = Some(900);
                    }
                    _ => unreachable!(),
                }
            }
            let turn = scheduler.turn(&source, &config).await;
            let error = turn.outcome.unwrap_err();
            assert!(!FAIL_STATE_SYNC.get());
            if !matches!(mode, "challenge" | "invalid-authorization-hint") {
                assert!(failure_message(&error).contains("fixture state sync failure"));
            }
            assert!(turn.wake_at >= now() + 890, "{mode}: response hint lost");
            let state = load(&config).unwrap().unwrap();
            assert_eq!(state.retry_at, turn.wake_at);
            let order_retained = matches!(mode, "create" | "authorization" | "ready-response");
            assert_eq!(state.order_url.is_some(), order_retained);
            assert_eq!(state.order_key.is_some(), order_retained);
            let requests = fixture.requests.load(Ordering::SeqCst);
            assert!(matches!(
                scheduler.turn(&source, &config).await.outcome,
                Ok(Progress::Deferred)
            ));
            assert!(matches!(
                Scheduler::new().turn(&source, &config).await.outcome,
                Ok(Progress::Deferred)
            ));
            assert_eq!(fixture.requests.load(Ordering::SeqCst), requests);
            assert_eq!(load(&config).unwrap().unwrap().retry_at, state.retry_at);
            serving.shutdown().await;
            fixture.tasks.shutdown().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn retry_after_overflow_does_not_stop_issuance_or_ari() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let directory = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut fixture = Fixture::new(listener.local_addr().unwrap(), false).await;
        fixture.state.lock().ari_window = Some((now() + 1000, now() + 2000));
        fixture.state.lock().order_retry_after = Some(u64::MAX);
        let config = fixture.config(directory.path(), false);
        let _lock = lock_state(&config).unwrap();
        let source =
            Source::new("fixture".into(), super::super::Spec::Acme(config.clone())).unwrap();
        let mut serving = serve_challenges(
            listener,
            source.clone(),
            false,
            Arc::new(AtomicUsize::new(0)),
        );
        let client = HttpClient::new(client_tls(config.ca_cert.as_deref()).unwrap(), &config);
        let error = drive(&source, &config, client.clone()).await.err().unwrap();
        assert!(failure_message(&error).contains("Retry-After exceeds supported range"));
        assert_eq!(fixture.state.lock().order_requests, 1);
        fixture.state.lock().order_retry_after = None;
        expire_retry(&config);
        drive(&source, &config, client.clone()).await.unwrap();
        assert!(source.current().is_some());

        fixture.state.lock().ari_retry_after = u64::MAX;
        drive(&source, &config, client.clone()).await.unwrap();
        assert_eq!(fixture.state.lock().ari_requests, 1);
        assert!(source.current().is_some());
        let mut state = load(&config).unwrap().unwrap();
        assert!(state.ari_retry_at >= now() + 6 * 3600 - 1);
        state.ari_retry_at = 0;
        persist(&config, &state).unwrap();
        fixture.state.lock().ari_retry_after = 3600;
        drive(&source, &config, client).await.unwrap();
        assert_eq!(fixture.state.lock().ari_requests, 2);
        assert_eq!(fixture.state.lock().orders.len(), 1);
        serving.shutdown().await;
        fixture.tasks.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn successful_order_retry_after_is_persisted_and_respected_on_restart() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let directory = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut fixture = Fixture::new(listener.local_addr().unwrap(), false).await;
        fixture.state.lock().new_order_retry_after = Some(900);
        fixture.state.lock().defer_validation = true;
        let config = fixture.config(directory.path(), false);
        let _lock = lock_state(&config).unwrap();
        let source =
            Source::new("fixture".into(), super::super::Spec::Acme(config.clone())).unwrap();
        let mut serving = JoinSet::new();
        let serving_source = source.clone();
        serving
            .spawn(async move { challenge::serve(vec![Arc::new(listener)], serving_source).await });
        let mut workers = JoinSet::new();
        let worker_config = config.clone();
        let worker_source = source.clone();
        workers.spawn(async move { run(worker_source, &worker_config).await });
        let retry_at = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if let Some(state) = load(&config).unwrap()
                    && state.retry_at >= now() + 890
                {
                    assert_eq!(fixture.state.lock().orders[0].status, "pending");
                    assert!(
                        state.retry_at >= now() + 890,
                        "lost successful order Retry-After"
                    );
                    break state.retry_at;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let requests = fixture.requests.load(Ordering::SeqCst);
        assert_eq!(
            fixture.state.lock().challenge_requests,
            1,
            "a new order's polling hint must not postpone challenge preparation"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(fixture.requests.load(Ordering::SeqCst), requests);
        workers.shutdown().await;
        let resumed =
            Source::new("restarted".into(), super::super::Spec::Acme(config.clone())).unwrap();
        let client = HttpClient::new(client_tls(config.ca_cert.as_deref()).unwrap(), &config);
        let turn = drive(&resumed, &config, client).await.unwrap();
        assert!(matches!(turn.outcome, Ok(Progress::Deferred)));
        assert!(turn.wake_at >= now() + 890);
        assert_eq!(fixture.requests.load(Ordering::SeqCst), requests);
        assert_eq!(load(&config).unwrap().unwrap().retry_at, retry_at);
        assert!(source.current().is_none());
        assert!(source.challenges.read().is_empty());
        serving.shutdown().await;
        fixture.tasks.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn finalize_and_restored_order_retry_after_prevent_early_polls() {
    tokio::time::timeout(Duration::from_secs(12), async {
        let directory = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut fixture = Fixture::new(listener.local_addr().unwrap(), false).await;
        fixture.state.lock().finalize_retry_after = Some(900);
        let config = fixture.config(directory.path(), false);
        let _lock = lock_state(&config).unwrap();
        let source =
            Source::new("fixture".into(), super::super::Spec::Acme(config.clone())).unwrap();
        let mut serving = serve_challenges(
            listener,
            source.clone(),
            false,
            Arc::new(AtomicUsize::new(0)),
        );
        let client = HttpClient::new(client_tls(config.ca_cert.as_deref()).unwrap(), &config);
        let outcome = drive(&source, &config, client.clone()).await.unwrap();
        assert!(matches!(outcome.outcome, Ok(Progress::Pending)));
        assert!(outcome.wake_at >= now() + 890);
        assert_eq!(
            fixture.state.lock().order_requests,
            1,
            "must not poll after finalize"
        );
        assert!(load(&config).unwrap().unwrap().retry_at >= now() + 890);
        assert!(source.challenges.read().is_empty());

        // Simulate the first deadline passing, then a resumed processing response
        // that requests a new delay. No subsequent status response has been read.
        expire_retry(&config);
        fixture.state.lock().finalize_retry_after = None;
        fixture.state.lock().order_retry_after = Some(900);
        let restarted =
            Source::new("restarted".into(), super::super::Spec::Acme(config.clone())).unwrap();
        let outcome = drive(&restarted, &config, client.clone()).await.unwrap();
        assert!(matches!(outcome.outcome, Ok(Progress::Pending)));
        assert!(outcome.wake_at >= now() + 890);
        assert_eq!(
            fixture.state.lock().order_requests,
            2,
            "must not poll after restoration"
        );
        assert!(load(&config).unwrap().unwrap().retry_at >= now() + 890);
        let requests = fixture.requests.load(Ordering::SeqCst);
        let outcome = drive(&restarted, &config, client.clone()).await.unwrap();
        assert!(matches!(outcome.outcome, Ok(Progress::Deferred)));
        assert!(outcome.wake_at >= now() + 890);
        assert_eq!(fixture.requests.load(Ordering::SeqCst), requests);

        expire_retry(&config);
        fixture.state.lock().orders[0].status = "valid";
        fixture.state.lock().order_retry_after = None;
        drive(&restarted, &config, client).await.unwrap();
        assert!(restarted.current().is_some());
        serving.shutdown().await;
        fixture.tasks.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn pending_order_deferral_keeps_challenges_until_cancelled() {
    tokio::time::timeout(Duration::from_secs(20), async {
        for tls_alpn in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut fixture = Fixture::new(listener.local_addr().unwrap(), tls_alpn).await;
            fixture.state.lock().new_order_retry_after = Some(900);
            fixture.state.lock().defer_validation = true;
            let config = fixture.config(directory.path(), tls_alpn);
            let _lock = lock_state(&config).unwrap();
            let source =
                Source::new("fixture".into(), super::super::Spec::Acme(config.clone())).unwrap();
            let count = Arc::new(AtomicUsize::new(0));
            let mut serving = serve_challenges(listener, source.clone(), tls_alpn, count.clone());
            let mut workers = JoinSet::new();
            let worker_source = source.clone();
            let worker_config = config.clone();
            workers.spawn(async move { run(worker_source, &worker_config).await });
            loop {
                if load(&config)
                    .unwrap()
                    .is_some_and(|state| state.retry_at >= now() + 890)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            let requests = fixture.requests.load(Ordering::SeqCst);
            assert_eq!(source.challenges.read().len(), 1);
            validate_challenge(&fixture.state, 0).await.unwrap();
            assert_eq!(fixture.requests.load(Ordering::SeqCst), requests);
            assert_eq!(count.load(Ordering::SeqCst), 0);
            workers.shutdown().await;
            assert!(
                source.challenges.read().is_empty(),
                "cancellation must end the challenge lease"
            );
            serving.shutdown().await;
            fixture.tasks.shutdown().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn missing_orders_and_invalid_authorizations_recover_without_an_extra_failure_cycle() {
    tokio::time::timeout(Duration::from_secs(25), async {
        for mode in ["404", "410", "invalid-order", "invalid-authorization"] {
            let directory = tempfile::tempdir().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut fixture = Fixture::new(listener.local_addr().unwrap(), false).await;
            let config = fixture.config(directory.path(), false);
            let _lock = lock_state(&config).unwrap();
            let source =
                Source::new("fixture".into(), super::super::Spec::Acme(config.clone())).unwrap();
            let mut serving = serve_challenges(
                listener,
                source.clone(),
                false,
                Arc::new(AtomicUsize::new(0)),
            );
            let client = HttpClient::new(client_tls(config.ca_cert.as_deref()).unwrap(), &config);
            if let Ok(status) = mode.parse::<u16>() {
                fixture.state.lock().finalize_retry_after = Some(900);
                assert!(matches!(
                    drive(&source, &config, client.clone())
                        .await
                        .unwrap()
                        .outcome,
                    Ok(Progress::Pending)
                ));
                expire_retry(&config);
                fixture.state.lock().finalize_retry_after = None;
                fixture.state.lock().missing_order_status = Some(status);
            } else {
                fixture.state.lock().defer_validation = true;
                fixture.state.lock().invalidate_on_poll = mode == "invalid-order";
                fixture.state.lock().invalid_authorization = mode == "invalid-authorization";
                if mode == "invalid-order" {
                    assert_eq!(
                        Scheduler::new()
                            .turn(&source, &config)
                            .await
                            .outcome
                            .unwrap(),
                        Progress::Pending
                    );
                    expire_retry(&config);
                    // Only the terminal diagnostic fetch carries this hint.
                    fixture.state.lock().authorization_retry_after = Some(900);
                }
            }
            let error = drive(&source, &config, client.clone()).await.unwrap_err();
            if mode.starts_with("invalid-") {
                let message = failure_message(&error);
                assert!(message.contains("connection"), "{message}");
                assert!(!message.contains("PRIVATE VALIDATION DATA"));
            } else {
                assert!(
                    matches!(error, instant_acme::Error::Api(problem) if problem.status.is_none())
                );
            }
            let state = load(&config).unwrap().unwrap();
            assert!(
                state.order_url.is_none() && state.order_key.is_none(),
                "{mode}"
            );
            assert!(source.challenges.read().is_empty());
            if mode == "invalid-order" {
                assert!(
                    state.retry_at < now() + 100,
                    "diagnostic response hint leaked"
                );
            }
            {
                let mut state = fixture.state.lock();
                state.missing_order_status = None;
                state.invalidate_on_poll = false;
                state.invalid_authorization = false;
                state.defer_validation = false;
                state.authorization_retry_after = None;
            }
            expire_retry(&config);
            drive(&source, &config, client).await.unwrap();
            assert!(source.current().is_some(), "{mode}");
            assert_eq!(fixture.state.lock().orders.len(), 2);
            serving.shutdown().await;
            fixture.tasks.shutdown().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn resumed_processing_challenges_are_served_without_resubmission() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let directory = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut fixture = Fixture::new(listener.local_addr().unwrap(), false).await;
        fixture.state.lock().defer_validation = true;
        fixture.state.lock().order_retry_after = Some(900);
        let config = fixture.config(directory.path(), false);
        let _lock = lock_state(&config).unwrap();
        let source =
            Source::new("fixture".into(), super::super::Spec::Acme(config.clone())).unwrap();
        let mut serving = serve_challenges(
            listener,
            source.clone(),
            false,
            Arc::new(AtomicUsize::new(0)),
        );
        let client = HttpClient::new(client_tls(config.ca_cert.as_deref()).unwrap(), &config);
        assert!(matches!(
            drive(&source, &config, client.clone())
                .await
                .unwrap()
                .outcome,
            Ok(Progress::Pending)
        ));
        source.challenges.write().clear();
        expire_retry(&config);
        assert!(matches!(
            drive(&source, &config, client.clone())
                .await
                .unwrap()
                .outcome,
            Ok(Progress::Pending)
        ));
        assert_eq!(fixture.state.lock().challenge_requests, 1);
        validate_challenge(&fixture.state, 0).await.unwrap();
        expire_retry(&config);
        fixture.state.lock().order_retry_after = None;
        drive(&source, &config, client).await.unwrap();
        assert!(source.current().is_some());
        serving.shutdown().await;
        fixture.tasks.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn untrusted_ca_and_unaccepted_terms_never_register() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let directory = tempfile::tempdir().unwrap();
        let mut fixture = Fixture::new("127.0.0.1:9".parse().unwrap(), false).await;
        let config = fixture.config(directory.path(), false);
        let _lock = lock_state(&config).unwrap();
        let source =
            Source::new("fixture".into(), super::super::Spec::Acme(config.clone())).unwrap();
        for (trusted, terms) in [
            (false, config.terms_of_service.clone()),
            (true, None),
            (true, Some("https://ca.test/different-terms".into())),
        ] {
            let client = HttpClient {
                tls: client_tls(if trusted {
                    config.ca_cert.as_deref()
                } else {
                    None
                })
                .unwrap(),
                directory: config.directory_url.clone(),
                terms,
                last: Arc::new(Mutex::new(None)),
            };
            let error = drive(&source, &config, client).await.unwrap_err();
            if trusted {
                assert!(failure_message(&error).contains("terms_of_service"));
            }
            assert_eq!(fixture.state.lock().accounts, 0);
            assert!(source.current().is_none());
            expire_retry(&config);
        }
        fixture.tasks.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn deferred_retries_do_not_reset_failure_backoff() {
    let directory = tempfile::tempdir().unwrap();
    let mut fixture = Fixture::new("127.0.0.1:9".parse().unwrap(), false).await;
    fixture.state.lock().failure_retry_after = None;
    fixture.fail.store(true, Ordering::SeqCst);
    let config = fixture.config(directory.path(), false);
    let _lock = lock_state(&config).unwrap();
    let source = Source::new("backoff".into(), super::super::Spec::Acme(config.clone())).unwrap();
    let mut workers = JoinSet::new();
    let worker_config = config.clone();
    workers.spawn(async move { run(source, &worker_config).await });
    for (attempt, backoff) in [60, 120, 240].into_iter().enumerate() {
        let mut state = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(state) = load(&config).unwrap()
                    && state.retry_at != 0
                    && fixture.requests.load(Ordering::SeqCst) == attempt + 1
                {
                    break state;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let delay = state.retry_at - now();
        assert!(
            (backoff..=backoff * 5 / 4 + 3).contains(&delay),
            "attempt {attempt}: retry in {delay} seconds"
        );

        // Advance only the worker's timer, leaving the persisted wall-clock deadline
        // in the future to exercise the deferred path between consecutive failures.
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(400)).await;
        tokio::time::resume();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(fixture.requests.load(Ordering::SeqCst), attempt + 1);
        assert_eq!(load(&config).unwrap().unwrap().retry_at, state.retry_at);
        state.retry_at = 0;
        persist(&config, &state).unwrap();
        if attempt != 2 {
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(400)).await;
            tokio::time::resume();
        }
    }
    workers.shutdown().await;
    fixture.tasks.shutdown().await;
}

#[tokio::test]
async fn tls_challenge_selection_never_dispatches_or_changes_normal_certificate() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let config = AcmeConfig {
            domains: vec!["proxy.test".into()],
            directory_url: "http://127.0.0.1:9/directory".into(),
            state_dir: "unused".into(),
            terms_of_service: None,
            contacts: vec![],
            challenge: ChallengeConfig::TlsAlpn01,
            ca_cert: None,
        };
        let source = Source::new("selection".into(), super::super::Spec::Acme(config)).unwrap();
        let authorization = "configured-token.account-thumbprint";
        let digest =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, authorization.as_bytes());
        source.challenges.write().push(challenge::Pending {
            domain: "proxy.test".into(),
            token: "configured-token".into(),
            authorization: authorization.into(),
            expires: Instant::now() + Duration::from_secs(60),
            tls: Some(challenge::tls_config("proxy.test", digest.as_ref()).unwrap()),
        });
        let count = Arc::new(AtomicUsize::new(0));
        let mut serving = serve_challenges(listener, source.clone(), true, count.clone());
        let normal = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(normal.cert.der().clone()).unwrap();
        let mut normal_client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        normal_client.alpn_protocols = vec![b"normal".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(normal_client.clone()));
        assert!(
            connector
                .connect(
                    "proxy.test".try_into().unwrap(),
                    TcpStream::connect(address).await.unwrap()
                )
                .await
                .is_err()
        );
        validate_tls_challenge(address, authorization).await;
        assert_eq!(count.load(Ordering::SeqCst), 0);
        source.publish(
            Material::parse(
                &normal.cert.pem(),
                &normal.signing_key.serialize_pem(),
                &["proxy.test".into()],
            )
            .unwrap(),
        );
        let mut connection = connector
            .connect(
                "proxy.test".try_into().unwrap(),
                TcpStream::connect(address).await.unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            connection.get_ref().1.peer_certificates().unwrap()[0],
            *normal.cert.der()
        );
        let _ = connection.read(&mut [0]).await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
        validate_tls_challenge(address, authorization).await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
        for (sni, enable_sni, alpn) in [
            ("other.test", true, vec![b"acme-tls/1".to_vec()]),
            ("proxy.test", false, vec![b"acme-tls/1".to_vec()]),
        ] {
            let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ChallengeVerifier(digest.as_ref().to_vec())))
            .with_no_client_auth();
            config.alpn_protocols = alpn;
            config.enable_sni = enable_sni;
            assert!(
                tokio_rustls::TlsConnector::from(Arc::new(config))
                    .connect(
                        sni.to_owned().try_into().unwrap(),
                        TcpStream::connect(address).await.unwrap()
                    )
                    .await
                    .is_err()
            );
        }
        normal_client.alpn_protocols = vec![b"acme-tls/1".to_vec(), b"normal".to_vec()];
        let mut mixed = tokio_rustls::TlsConnector::from(Arc::new(normal_client))
            .connect(
                "proxy.test".try_into().unwrap(),
                TcpStream::connect(address).await.unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            mixed.get_ref().1.peer_certificates().unwrap()[0],
            *normal.cert.der()
        );
        assert_eq!(
            mixed.get_ref().1.alpn_protocol(),
            Some(b"normal".as_slice())
        );
        let _ = mixed.read(&mut [0]).await;
        assert_eq!(count.load(Ordering::SeqCst), 2);
        source.challenges.write()[0].expires = Instant::now();
        assert!(source.challenge_config(Some("proxy.test")).is_none());
        assert_eq!(source.current().unwrap().cert[0], *normal.cert.der());
        serving.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn ca_http_client_bounds_response_size_headers_and_time() {
    for mode in ["body", "headers", "retry-after", "stall"] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let mut serving = JoinSet::new();
        let (ready, received) = tokio::sync::oneshot::channel();
        serving.spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 8192];
            let _ = stream.read(&mut request).await;
            ready.send(()).unwrap();
            match mode {
                "body" => {
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nRetry-After: 900\r\nContent-Length: {}\r\n\r\n",
                        MAX_RESPONSE + 1
                    );
                    let _ = stream.write_all(header.as_bytes()).await;
                    let _ = stream.write_all(&vec![b'x'; MAX_RESPONSE + 1]).await;
                }
                "headers" => {
                    let _ = stream
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nX-Large: {}\r\nContent-Length: 0\r\n\r\n",
                                "x".repeat(40 * 1024)
                            )
                            .as_bytes(),
                        )
                        .await;
                }
                "retry-after" => {
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nRetry-After: \t18446744073709551615 \t\r\nContent-Length: 0\r\n\r\n",
                    ).await;
                }
                _ => std::future::pending::<()>().await,
            }
        });
        let client = HttpClient {
            tls: client_tls(None).unwrap(),
            directory: format!("{base}/directory"),
            terms: None,
            last: Arc::new(Mutex::new(None)),
        };
        let request = http::Request::get(format!("{base}/response"))
            .body(instant_acme::BodyWrapper::default())
            .unwrap();
        let (result, ()) = tokio::join!(
            client.perform(
                tokio::time::Instant::now() + ORDER_TIMEOUT,
                instant_acme::HttpClient::request(&client, request)
            ),
            async {
                tokio::time::timeout(Duration::from_secs(5), received)
                    .await
                    .unwrap()
                    .unwrap();
                if mode == "stall" {
                    tokio::time::pause();
                    tokio::time::advance(REQUEST_TIMEOUT).await;
                }
            }
        );
        let failure = result.err().expect("bounded response must fail");
        if mode == "body" {
            assert!(
                response_deadline(&failure.response) >= now() + 890,
                "headers must survive a failed body"
            );
        }
        let error = *failure.error;
        if mode == "retry-after" {
            assert!(failure_message(&error).contains("Retry-After exceeds supported range"));
        }
        assert_eq!(
            matches!(error, instant_acme::Error::Timeout(_)),
            mode == "stall"
        );
        serving.shutdown().await;
        // A no-request operation and a connection failure must not inherit headers.
        *client.last.lock() = failure.response;
        let failure = client
            .perform(tokio::time::Instant::now() + ORDER_TIMEOUT, async {
                Err::<(), _>(instant_acme::Error::Unsupported("fixture"))
            })
            .await
            .unwrap_err();
        assert!(failure.response.is_none());
        let request = http::Request::get(format!("{base}/response"))
            .body(instant_acme::BodyWrapper::default())
            .unwrap();
        let failure = client
            .perform(
                tokio::time::Instant::now() + ORDER_TIMEOUT,
                instant_acme::HttpClient::request(&client, request),
            )
            .await
            .err()
            .unwrap();
        assert!(failure.response.is_none());
    }
}

#[test]
fn durable_state_errors_do_not_disclose_keys() {
    let directory = tempfile::tempdir().unwrap();
    let config = AcmeConfig {
        domains: vec!["proxy.test".into()],
        directory_url: "http://127.0.0.1:9/directory".into(),
        state_dir: directory.path().join("state"),
        terms_of_service: None,
        contacts: vec![],
        challenge: ChallengeConfig::TlsAlpn01,
        ca_cert: None,
    };
    let _lock = lock_state(&config).unwrap();
    initial_state(&config).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&config.state_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(config.state_dir.join("state.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let secret = "PRIVATE KEY MUST NOT APPEAR";
    std::fs::write(
        config.state_dir.join("state.json"),
        format!("{{broken:{secret}"),
    )
    .unwrap();
    let error = load(&config).err().unwrap().to_string();
    assert!(error.contains("invalid ACME durable state"));
    assert!(!error.contains(secret));
}

#[test]
fn cached_identity_validation_is_read_only() {
    let directory = tempfile::tempdir().unwrap();
    let config = AcmeConfig {
        domains: vec!["proxy.test".into()],
        directory_url: "http://127.0.0.1:9/directory".into(),
        state_dir: directory.path().join("state"),
        terms_of_service: None,
        contacts: vec![],
        challenge: ChallengeConfig::Http01 {
            listen: vec!["127.0.0.1:18080".parse().unwrap()],
        },
        ca_cert: None,
    };
    let _lock = lock_state(&config).unwrap();
    initial_state(&config).unwrap();
    let before = std::fs::read(config.state_dir.join("state.json")).unwrap();
    for changed in [false, true] {
        let mut candidate = config.clone();
        if changed {
            candidate.domains = vec!["other.test".into()];
        }
        let configs = serde_yaml::from_value(
            serde_yaml::to_value(vec![crate::config::Config::CertificateSource(
                super::super::NamedSource {
                    certificate_source: "managed".into(),
                    source: super::super::SourceConfig::Acme(candidate),
                },
            )])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            crate::config::create_server_configs(configs).is_err(),
            changed
        );
    }
    let mut candidate = config.clone();
    candidate.directory_url = "http://127.0.0.1:8/directory".into();
    assert!(
        validate_state(&candidate)
            .unwrap_err()
            .to_string()
            .contains("identity differs")
    );
    assert_eq!(
        std::fs::read(config.state_dir.join("state.json")).unwrap(),
        before
    );
}

#[cfg(unix)]
#[test]
#[ignore = "requires root to create state owned by the service user"]
fn root_config_check_accepts_service_owned_state_without_relaxing_runtime_checks() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let directory = tempfile::tempdir().unwrap();
    let config = AcmeConfig {
        domains: vec!["proxy.test".into()],
        directory_url: "http://127.0.0.1:9/directory".into(),
        state_dir: directory.path().join("state"),
        terms_of_service: None,
        contacts: vec![],
        challenge: ChallengeConfig::Http01 {
            listen: vec!["127.0.0.1:18080".parse().unwrap()],
        },
        ca_cert: None,
    };
    let lock = lock_state(&config).unwrap();
    initial_state(&config).unwrap();
    drop(lock);
    let state_path = config.state_dir.join("state.json");
    let before = std::fs::read(&state_path).unwrap();
    std::os::unix::fs::chown(&state_path, Some(65534), None).unwrap();
    std::os::unix::fs::chown(&config.state_dir, Some(65534), None).unwrap();
    let configs = vec![crate::config::Config::CertificateSource(
        super::super::NamedSource {
            certificate_source: "managed".into(),
            source: super::super::SourceConfig::Acme(config.clone()),
        },
    )];
    crate::config::create_server_configs(configs).unwrap();
    assert!(load(&config).is_err());
    assert!(lock_state(&config).is_err());
    assert_eq!(std::fs::read(&state_path).unwrap(), before);
}

#[test]
fn acme_diagnostics_omit_remote_details_and_json_values() {
    let secret = "PRIVATE KEY MUST NOT APPEAR";
    let problem = instant_acme::Problem {
        r#type: Some("urn:ietf:params:acme:error:rateLimited".into()),
        detail: Some(secret.into()),
        status: Some(429),
        subproblems: vec![],
    };
    let message = failure_message(&instant_acme::Error::Api(problem));
    assert!(message.contains("rateLimited") && message.contains("429"));
    assert!(!message.contains(secret));
    let error = serde_json::from_str::<u64>(&format!("\"{secret}\"")).unwrap_err();
    assert!(!failure_message(&instant_acme::Error::Json(error)).contains(secret));
}
