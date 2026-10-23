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

struct Order {
    status: &'static str,
    token: String,
    certificate: Option<String>,
}

struct CaState {
    base: String,
    kind: &'static str,
    challenge_address: SocketAddr,
    issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
    jwk: Option<Value>,
    accounts: usize,
    orders: Vec<Order>,
    nonces: HashSet<String>,
    ari_window: Option<(i64, i64)>,
    ari_requests: usize,
    break_state: Option<std::path::PathBuf>,
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
            kind: if tls_alpn { "tls-alpn-01" } else { "http-01" },
            challenge_address,
            issuer,
            jwk: None,
            accounts: 0,
            orders: vec![],
            nonces: HashSet::new(),
            ari_window: None,
            ari_requests: 0,
            break_state: None,
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
        let mut response = response(&mut state.lock(), 503, json!({"type":"urn:ietf:params:acme:error:serverInternal", "status":503, "detail":"fixture failure"}).to_string(), None);
        response
            .headers_mut()
            .insert("retry-after", http::HeaderValue::from_static("120"));
        return Ok(response);
    }
    if path == "/directory" {
        let mut state = state.lock();
        let value = json!({"newNonce":format!("{}/nonce", state.base), "newAccount":format!("{}/account", state.base),
            "renewalInfo": state.ari_window.map(|_| format!("{}/renewal", state.base)),
            "newOrder":format!("{}/new-order", state.base), "meta":{"termsOfService":"https://ca.test/terms"}});
        return Ok(response(&mut state, 200, value.to_string(), None));
    }
    if path == "/nonce" {
        return Ok(response(&mut state.lock(), 200, Bytes::new(), None));
    }
    if path.starts_with("/renewal/") {
        assert_eq!(request.method(), http::Method::GET);
        let mut state = state.lock();
        state.ari_requests += 1;
        let (start, end) = state.ari_window.unwrap();
        let value = json!({"suggestedWindow": {
            "start": chrono::DateTime::from_timestamp(start, 0).unwrap().to_rfc3339(),
            "end": chrono::DateTime::from_timestamp(end, 0).unwrap().to_rfc3339()
        }});
        let mut response = response(&mut state, 200, value.to_string(), None);
        response
            .headers_mut()
            .insert("retry-after", http::HeaderValue::from_static("3600"));
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
        if path == "/new-order" {
            assert_eq!(
                payload["identifiers"],
                json!([{"type":"dns", "value":"proxy.test"}])
            );
            let id = state.orders.len();
            state.orders.push(Order {
                status: "pending",
                token: B64.encode(rand::random::<[u8; 24]>()),
                certificate: None,
            });
            let order = order_json(&state, id).to_string();
            let location = format!("{}/order/{id}", state.base);
            return Ok(response(&mut state, 201, order, Some(location)));
        }
    }
    let (operation, id) = path.trim_start_matches('/').split_once('/').unwrap();
    let id: usize = id.parse().unwrap();
    if operation == "challenge" {
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
            stream.write_all(format!("GET /.well-known/acme-challenge/{token} HTTP/1.1\r\nHost: proxy.test\r\n\r\n").as_bytes()).await?;
            let mut bytes = Vec::new();
            stream.take(8192).read_to_end(&mut bytes).await?;
            let bytes = String::from_utf8(bytes).unwrap();
            assert!(bytes.starts_with("HTTP/1.1 200 "));
            assert_eq!(bytes.split_once("\r\n\r\n").unwrap().1, authorization);
        } else {
            validate_tls_challenge(address, &authorization).await;
        }
        let mut state = state.lock();
        state.orders[id].status = "ready";
        let value = json!({"type":kind, "url":format!("{}/challenge/{id}", state.base), "token":token, "status":"valid"});
        return Ok(response(&mut state, 200, value.to_string(), None));
    }
    let mut state = state.lock();
    let value = match operation {
        "order" => order_json(&state, id),
        "auth" => json!({"identifier":{"type":"dns", "value":"proxy.test"},
            "status": if state.orders[id].status == "pending" {"pending"} else {"valid"},
            "challenges":[{"type":state.kind, "url":format!("{}/challenge/{id}", state.base),
                "token":state.orders[id].token, "status":"pending"}]}),
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
            state.orders[id].status = "valid";
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
    Ok(response(&mut state, 200, value.to_string(), None))
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
        let source = source.clone();
        serving.spawn(async move {
            challenge::serve(vec![Arc::new(listener)], source)
                .await
                .unwrap();
        });
    }
    let client = HttpClient {
        tls: client_tls(config.ca_cert.as_deref()).unwrap(),
        directory: config.directory_url.clone(),
        terms: config.terms_of_service.clone(),
        retry_after: Arc::new(Mutex::new(Instant::now())),
    };
    cycle(&source, &config, client.clone()).await.unwrap();
    let first = source.current().unwrap().cert[0].clone();
    assert!(source.challenges.read().is_empty());
    assert_eq!(fixture.state.lock().accounts, 1);
    assert_eq!(fixture.state.lock().orders.len(), 1);
    assert_eq!(count.load(Ordering::SeqCst), 0);
    let resumed = Source::new("fixture".into(), super::super::Spec::Acme(config.clone())).unwrap();
    load_cached(&resumed, &config).unwrap();
    assert_eq!(resumed.current().unwrap().cert[0], first);
    cycle(&resumed, &config, client.clone()).await.unwrap();
    assert_eq!(fixture.state.lock().accounts, 1);
    assert_eq!(fixture.state.lock().orders.len(), 1);
    {
        let mut material = source.material.write();
        let material = material.as_mut().unwrap();
        material.not_before = now() - 600;
        material.not_after = now() + 30;
    }
    cycle(&source, &config, client.clone()).await.unwrap();
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
    assert!(cycle(&source, &config, client.clone()).await.is_err());
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
    cycle(&source, &config, client.clone()).await.unwrap();
    assert_ne!(source.current().unwrap().cert[0], durable);
    assert_eq!(
        fixture.state.lock().orders.len(),
        3,
        "resume the persisted order instead of issuing another"
    );
    fixture.fail.store(true, Ordering::SeqCst);
    let before = source.current().unwrap().cert[0].clone();
    assert!(cycle(&resumed, &config, client.clone()).await.is_err());
    assert_eq!(
        resumed.current().unwrap().cert[0],
        before,
        "recover a durable pair not yet published, even while the CA is unavailable"
    );
    assert_eq!(fixture.state.lock().orders.len(), 3);
    assert!(cycle(&source, &config, client).await.is_err());
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
        let client = HttpClient {
            tls: client_tls(config.ca_cert.as_deref()).unwrap(),
            directory: config.directory_url.clone(),
            terms: config.terms_of_service.clone(),
            retry_after: Arc::new(Mutex::new(Instant::now())),
        };
        cycle(&source, &config, client.clone()).await.unwrap();
        let delay = cycle(&source, &config, client.clone()).await.unwrap();
        assert!((990..=2000).contains(&delay.as_secs()));
        assert_eq!(fixture.state.lock().ari_requests, 1);
        let reloaded =
            Source::new("fixture".into(), super::super::Spec::Acme(config.clone())).unwrap();
        load_cached(&reloaded, &config).unwrap();
        cycle(&reloaded, &config, client.clone()).await.unwrap();
        assert_eq!(fixture.state.lock().ari_requests, 1);
        let mut state = load(&config).unwrap().unwrap();
        state.ari_retry_at = 0;
        persist(&config, &state).unwrap();
        fixture.state.lock().ari_window = Some((now() - 200, now() - 100));
        cycle(&source, &config, client).await.unwrap();
        assert_eq!(fixture.state.lock().ari_requests, 2);
        assert_eq!(fixture.state.lock().orders.len(), 2);
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
                retry_after: Arc::new(Mutex::new(Instant::now())),
            };
            assert!(cycle(&source, &config, client).await.is_err());
            assert_eq!(fixture.state.lock().accounts, 0);
            assert!(source.current().is_none());
        }
        fixture.tasks.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tls_challenge_selection_never_dispatches_or_changes_normal_certificate() {
    use crate::tcp::tcp_handler::TcpServerHandler;
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let config = AcmeConfig {
            domains: vec!["proxy.test".into()], directory_url: "http://127.0.0.1:9/directory".into(),
            state_dir: "unused".into(), terms_of_service: None, contacts: vec![],
            challenge: ChallengeConfig::TlsAlpn01, ca_cert: None,
        };
        let source = Source::new("selection".into(), super::super::Spec::Acme(config)).unwrap();
        let authorization = "configured-token.account-thumbprint";
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, authorization.as_bytes());
        source.challenges.write().push(challenge::Pending {
            domain: "proxy.test".into(), token: "configured-token".into(), authorization: authorization.into(),
            expires: Instant::now() + Duration::from_secs(60), tls: Some(challenge::tls_config("proxy.test", digest.as_ref()).unwrap()),
        });
        let count = Arc::new(AtomicUsize::new(0));
        let handler = Arc::new(tls_handler(source.clone(), count.clone()));
        let mut serving = JoinSet::new();
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
        let normal = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(normal.cert.der().clone()).unwrap();
        let mut normal_client = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions().unwrap().with_root_certificates(roots).with_no_client_auth();
        normal_client.alpn_protocols = vec![b"normal".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(normal_client));
        assert!(connector.connect("proxy.test".try_into().unwrap(), TcpStream::connect(address).await.unwrap()).await.is_err());
        validate_tls_challenge(address, authorization).await;
        assert_eq!(count.load(Ordering::SeqCst), 0);
        source.publish(Material::parse(&normal.cert.pem(), &normal.signing_key.serialize_pem(), &["proxy.test".into()]).unwrap());
        let mut connection = connector.connect("proxy.test".try_into().unwrap(), TcpStream::connect(address).await.unwrap()).await.unwrap();
        assert_eq!(connection.get_ref().1.peer_certificates().unwrap()[0], *normal.cert.der());
        let _ = connection.read(&mut [0]).await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
        validate_tls_challenge(address, authorization).await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
        for (sni, enable_sni, alpn) in [
            ("other.test", true, vec![b"acme-tls/1".to_vec()]),
            ("proxy.test", false, vec![b"acme-tls/1".to_vec()]),
            ("proxy.test", true, vec![b"acme-tls/1".to_vec(), b"normal".to_vec()]),
        ] {
            let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
                .with_safe_default_protocol_versions().unwrap().dangerous()
                .with_custom_certificate_verifier(Arc::new(ChallengeVerifier(digest.as_ref().to_vec()))).with_no_client_auth();
            config.alpn_protocols = alpn;
            config.enable_sni = enable_sni;
            assert!(tokio_rustls::TlsConnector::from(Arc::new(config)).connect(sni.to_owned().try_into().unwrap(), TcpStream::connect(address).await.unwrap()).await.is_err());
        }
        source.challenges.write()[0].expires = Instant::now();
        assert!(source.challenge_config(Some("proxy.test")).is_none());
        assert_eq!(source.current().unwrap().cert[0], *normal.cert.der());
        serving.shutdown().await;
    }).await.unwrap();
}

#[tokio::test]
async fn ca_http_client_bounds_response_size_headers_and_time() {
    for mode in ["body", "headers", "stall"] {
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
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
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
                _ => std::future::pending::<()>().await,
            }
        });
        let client = HttpClient {
            tls: client_tls(None).unwrap(),
            directory: format!("{base}/directory"),
            terms: None,
            retry_after: Arc::new(Mutex::new(Instant::now())),
        };
        let request = http::Request::get(format!("{base}/response"))
            .body(instant_acme::BodyWrapper::default())
            .unwrap();
        let (result, ()) =
            tokio::join!(instant_acme::HttpClient::request(&client, request), async {
                tokio::time::timeout(Duration::from_secs(5), received)
                    .await
                    .unwrap()
                    .unwrap();
                if mode == "stall" {
                    tokio::time::pause();
                    tokio::time::advance(REQUEST_TIMEOUT).await;
                }
            });
        let error = result.err().expect("bounded response must fail");
        assert_eq!(
            matches!(error, instant_acme::Error::Timeout(_)),
            mode == "stall"
        );
        serving.shutdown().await;
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
