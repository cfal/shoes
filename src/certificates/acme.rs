use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewOrder, OrderStatus, RetryPolicy,
};
use parking_lot::Mutex;
use rustls::pki_types::pem::PemObject;
use serde::{Deserialize, Serialize};

use super::{AcmeConfig, ChallengeConfig, Material, Source, challenge, invalid, now, read_text};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const ORDER_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_RESPONSE: usize = 1024 * 1024;

#[cfg(test)]
#[path = "acme_tests.rs"]
mod tests;

pub(super) fn validate_url(value: &str) -> io::Result<url::Url> {
    let url = url::Url::parse(value).map_err(|_| invalid("invalid ACME URL"))?;
    let loopback = url.host_str().is_some_and(|host| {
        host.trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    });
    if !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            "ACME requires HTTPS (HTTP is allowed only for a numeric loopback test CA), without credentials or fragments",
        ));
    }
    Ok(url)
}

pub(super) fn client_tls(ca: Option<&Path>) -> io::Result<Arc<rustls::ClientConfig>> {
    let mut config = crate::rustls_config_util::create_dns_client_config();
    if let Some(path) = ca {
        let pem = read_text(path)?;
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls::pki_types::CertificateDer::pem_slice_iter(pem.as_bytes()) {
            roots
                .add(cert.map_err(|_| invalid("invalid ACME CA certificate"))?)
                .map_err(|_| invalid("invalid ACME CA certificate"))?;
        }
        if roots.is_empty() {
            return Err(invalid("empty ACME CA certificate file"));
        }
        config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    }
    Ok(Arc::new(config))
}

#[derive(Clone)]
struct HttpClient {
    tls: Arc<rustls::ClientConfig>,
    directory: String,
    terms: Option<String>,
    retry_after: Arc<Mutex<Instant>>,
}

impl instant_acme::HttpClient for HttpClient {
    fn request(
        &self,
        mut request: http::Request<instant_acme::BodyWrapper<Bytes>>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<instant_acme::BytesResponse, instant_acme::Error>,
                > + Send,
        >,
    > {
        let client = self.clone();
        Box::pin(async move {
            let result = tokio::time::timeout(REQUEST_TIMEOUT, async {
                let url = validate_url(&request.uri().to_string())?;
                if url.scheme() == "http" && !client.directory.starts_with("http://") {
                    return Err(invalid(
                        "ACME HTTPS directory cannot downgrade to HTTP endpoints",
                    ));
                }
                let host = url
                    .host_str()
                    .ok_or_else(|| invalid("ACME URL has no host"))?
                    .trim_matches(['[', ']']);
                let addresses =
                    tokio::net::lookup_host((host, url.port_or_known_default().unwrap())).await?;
                let mut stream = None;
                for address in addresses.take(8) {
                    let socket = crate::socket_util::new_tcp_socket(None, address.is_ipv6())?;
                    if let Ok(Ok(connected)) =
                        tokio::time::timeout(Duration::from_secs(5), socket.connect(address)).await
                    {
                        stream = Some(connected);
                        break;
                    }
                }
                let stream = stream.ok_or_else(|| io::Error::other("ACME connection failed"))?;
                let stream: Box<dyn crate::async_stream::AsyncStream> = if url.scheme() == "https" {
                    let name = rustls::pki_types::ServerName::try_from(host.to_owned())
                        .map_err(|_| invalid("invalid ACME TLS hostname"))?;
                    let connection = rustls::ClientConnection::new(client.tls.clone(), name)
                        .map_err(io::Error::other)?;
                    Box::new(
                        crate::crypto::CryptoTlsStream::handshake(
                            stream,
                            crate::crypto::TlsConnection::new(connection),
                            crate::crypto::TlsReadMode::Stream,
                            &[],
                        )
                        .await?,
                    )
                } else {
                    Box::new(stream)
                };
                let authority = request
                    .uri()
                    .authority()
                    .ok_or_else(|| invalid("ACME URI has no authority"))?
                    .as_str()
                    .to_owned();
                let is_directory = request.uri()
                    == &client
                        .directory
                        .parse::<http::Uri>()
                        .map_err(|_| invalid("invalid ACME directory URI"))?;
                request.headers_mut().insert(
                    http::header::HOST,
                    authority
                        .parse()
                        .map_err(|_| invalid("invalid ACME host"))?,
                );
                request.headers_mut().insert(
                    http::header::CONNECTION,
                    http::HeaderValue::from_static("close"),
                );
                *request.uri_mut() = request
                    .uri()
                    .path_and_query()
                    .map_or("/", |path| path.as_str())
                    .parse()
                    .map_err(|_| invalid("invalid ACME path"))?;
                let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
                    .max_buf_size(32 * 1024)
                    .handshake(hyper_util::rt::TokioIo::new(stream))
                    .await
                    .map_err(io::Error::other)?;
                let response = async {
                    let response = sender
                        .send_request(request)
                        .await
                        .map_err(io::Error::other)?;
                    let (parts, body) = response.into_parts();
                    if parts
                        .headers
                        .iter()
                        .map(|(name, value)| name.as_str().len() + value.as_bytes().len() + 4)
                        .sum::<usize>()
                        > 32 * 1024
                    {
                        return Err(io::Error::other("ACME response headers exceed 32 KiB"));
                    }
                    if !parts.status.is_success()
                        && let Some(value) = parts
                            .headers
                            .get(http::header::RETRY_AFTER)
                            .and_then(|value| value.to_str().ok())
                    {
                        let delay =
                            value
                                .parse::<u64>()
                                .ok()
                                .map(Duration::from_secs)
                                .or_else(|| {
                                    httpdate::parse_http_date(value).ok().and_then(|date| {
                                        date.duration_since(SystemTime::now()).ok()
                                    })
                                });
                        if let Some(delay) = delay
                            && let Some(deadline) = Instant::now().checked_add(delay)
                        {
                            let mut current = client.retry_after.lock();
                            *current = (*current).max(deadline);
                        }
                    }
                    let bytes = Limited::new(body, MAX_RESPONSE)
                        .collect()
                        .await
                        .map_err(|_| io::Error::other("ACME response failed or exceeded 1 MiB"))?
                        .to_bytes();
                    if is_directory {
                        let directory: serde_json::Value = serde_json::from_slice(&bytes)
                            .map_err(|_| invalid("invalid ACME directory"))?;
                        let terms = match directory.pointer("/meta/termsOfService") {
                            Some(serde_json::Value::String(terms)) => Some(terms.as_str()),
                            None | Some(serde_json::Value::Null) => None,
                            _ => return Err(invalid("invalid ACME terms URL metadata")),
                        };
                        if terms != client.terms.as_deref() {
                            return Err(invalid(
                                "ACME terms URL differs from explicitly accepted terms_of_service",
                            ));
                        }
                    }
                    Ok::<_, io::Error>(instant_acme::BytesResponse::from(
                        http::Response::from_parts(parts, Full::new(bytes)),
                    ))
                };
                tokio::pin!(response, connection);
                tokio::select! {
                    result = &mut response => result,
                    result = &mut connection => {
                        result.map_err(io::Error::other)?;
                        response.await
                    }
                }
            })
            .await;
            result
                .map_err(|_| instant_acme::Error::Timeout(None))?
                .map_err(|error| instant_acme::Error::Other(Box::new(error)))
        })
    }
}

// Never derive Debug: this record includes account and certificate private keys.
#[derive(Deserialize, Serialize)]
struct State {
    directory_url: String,
    domains: Vec<String>,
    account_key: String,
    credentials: Option<instant_acme::AccountCredentials>,
    certificate: Option<String>,
    private_key: Option<String>,
    order_url: Option<String>,
    order_key: Option<String>,
    #[serde(default)]
    retry_at: i64,
    #[serde(default)]
    contacts: Vec<String>,
    #[serde(default)]
    ari_retry_at: i64,
    #[serde(default)]
    ari_renew_at: i64,
}

fn open_private(path: &Path, new: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if new {
        options.create_new(true);
    } else {
        options.create(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = file.metadata()?;
        if meta.mode() & 0o077 != 0 || meta.uid() != unsafe { libc::geteuid() } {
            return Err(invalid(
                "ACME state files must be owner-only and owned by the current user",
            ));
        }
    }
    Ok(file)
}

pub(super) fn lock_state(config: &AcmeConfig) -> io::Result<File> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&config.state_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(&config.state_dir)?;
        if meta.mode() & 0o077 != 0 || meta.uid() != unsafe { libc::geteuid() } {
            return Err(invalid(
                "ACME state_dir must be owner-only and owned by the current user",
            ));
        }
    }
    let lock = open_private(&config.state_dir.join("lock"), false)?;
    lock.try_lock().map_err(|_| {
        io::Error::other("ACME state_dir is already owned by another source or process")
    })?;
    Ok(lock)
}

fn load(config: &AcmeConfig) -> io::Result<Option<State>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = match options.open(config.state_dir.join("state.json")) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = file.metadata()?;
        if meta.mode() & 0o077 != 0 || meta.uid() != unsafe { libc::geteuid() } {
            return Err(invalid(
                "ACME state must be owner-only and owned by the current user",
            ));
        }
    }
    let mut text = String::new();
    file.take(super::MAX_PEM_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > super::MAX_PEM_BYTES {
        return Err(invalid("ACME state exceeds 1 MiB"));
    }
    let state: State =
        serde_json::from_str(&text).map_err(|_| invalid("invalid ACME durable state"))?;
    if state.directory_url != config.directory_url || state.domains != config.domains {
        return Err(invalid(
            "ACME state identity differs; use a distinct state_dir when changing CA or domains",
        ));
    }
    if state.certificate.is_some() != state.private_key.is_some()
        || state.order_url.is_some() != state.order_key.is_some()
    {
        return Err(invalid("incomplete ACME durable state"));
    }
    Ok(Some(state))
}

fn persist(config: &AcmeConfig, state: &State) -> io::Result<()> {
    let bytes =
        serde_json::to_vec(state).map_err(|_| io::Error::other("cannot encode ACME state"))?;
    if bytes.len() as u64 > super::MAX_PEM_BYTES {
        return Err(invalid("ACME state exceeds 1 MiB"));
    }
    let temporary = config
        .state_dir
        .join(format!(".state-{:016x}", rand::random::<u64>()));
    let result = (|| {
        let mut file = open_private(&temporary, true)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, config.state_dir.join("state.json"))?;
        #[cfg(unix)]
        File::open(&config.state_dir)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

pub(super) fn load_cached(source: &Source, config: &AcmeConfig) -> io::Result<()> {
    if let Some(state) = load(config)?
        && let (Some(cert), Some(key)) = (&state.certificate, &state.private_key)
    {
        match Material::parse(cert, key, &config.domains) {
            Ok(material) => {
                source.publish(material);
            }
            Err(_) => {
                log::warn!(
                    "Certificate source {} has no usable cached certificate; normal handshakes will fail until issuance succeeds",
                    source.name
                );
            }
        }
    }
    Ok(())
}

fn initial_state(config: &AcmeConfig) -> io::Result<State> {
    let key = rcgen::KeyPair::generate().map_err(io::Error::other)?;
    let state = State {
        directory_url: config.directory_url.clone(),
        domains: config.domains.clone(),
        account_key: key.serialize_pem(),
        credentials: None,
        certificate: None,
        private_key: None,
        order_url: None,
        order_key: None,
        retry_at: 0,
        contacts: Vec::new(),
        ari_retry_at: 0,
        ari_renew_at: 0,
    };
    // Persist the account key before registration, including across a failed response/write.
    persist(config, &state)?;
    Ok(state)
}

async fn account(
    config: &AcmeConfig,
    state: &mut State,
    client: HttpClient,
) -> Result<Account, instant_acme::Error> {
    let builder = Account::builder_with_http(Box::new(client));
    let account = if let Some(credentials) = state.credentials.take() {
        // from_credentials consumes its input; keep the serialized record for persistence.
        let bytes = serde_json::to_vec(&credentials)?;
        state.credentials = Some(serde_json::from_slice(&bytes)?);
        builder.from_credentials(credentials).await?
    } else {
        let key =
            rustls::pki_types::PrivatePkcs8KeyDer::from_pem_slice(state.account_key.as_bytes())
                .map_err(|_| instant_acme::Error::Str("invalid persisted account key"))?;
        let signing_key = instant_acme::Key::from_pkcs8_der(key.clone_key())?;
        let (account, credentials) = builder
            .create_from_key((signing_key, key.into()), config.directory_url.clone())
            .await?;
        state.credentials = Some(credentials);
        persist(config, state).map_err(|error| instant_acme::Error::Other(Box::new(error)))?;
        account
    };
    if config.contacts != state.contacts {
        account
            .update_contacts(
                &config
                    .contacts
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
            )
            .await?;
        state.contacts = config.contacts.clone();
        persist(config, state).map_err(|error| instant_acme::Error::Other(Box::new(error)))?;
    }
    Ok(account)
}

fn renewal_time(source: &Source) -> i64 {
    source.material.read().as_ref().map_or(0, |material| {
        material.not_after - ((material.not_after - material.not_before) / 3).max(60)
    })
}

async fn cycle(
    source: &Arc<Source>,
    config: &AcmeConfig,
    client: HttpClient,
) -> Result<Duration, instant_acme::Error> {
    let mut state = load(config)
        .and_then(|state| state.map_or_else(|| initial_state(config), Ok))
        .map_err(|error| instant_acme::Error::Other(Box::new(error)))?;
    // A rename may have succeeded before the directory sync failed. Retry durability
    // and publication of that pair, rather than creating another ACME order.
    if let (Some(cert), Some(key)) = (&state.certificate, &state.private_key)
        && let Ok(material) = Material::parse(cert, key, &config.domains)
    {
        let changed = source
            .material
            .read()
            .as_ref()
            .is_none_or(|current| current.digest != material.digest);
        if changed {
            persist(config, &state).map_err(|error| instant_acme::Error::Other(Box::new(error)))?;
            source.publish(material);
        }
    }
    if state.retry_at > now() {
        return Ok(Duration::from_secs((state.retry_at - now()) as u64));
    }
    let account = account(config, &mut state, client).await?;
    let mut renewal = renewal_time(source);
    let current = source.current();
    if let Some(current) = current
        && now() >= state.ari_retry_at
        && let Ok(id) = instant_acme::CertificateIdentifier::try_from(&current.cert[0])
    {
        state.ari_retry_at = now().saturating_add(6 * 3600);
        if let Ok((info, delay)) = account.renewal_info(&id).await {
            state.ari_retry_at =
                now().saturating_add(delay.as_secs().clamp(60, i64::MAX as u64) as i64);
            let start = info.suggested_window.start.unix_timestamp();
            let end = info.suggested_window.end.unix_timestamp();
            if end > start {
                // A stable choice inside ARI's window avoids rescheduling on every poll.
                let offset = u64::from_be_bytes(
                    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, current.cert[0].as_ref())
                        .as_ref()[..8]
                        .try_into()
                        .unwrap(),
                );
                state.ari_renew_at = start.saturating_add((offset % (end - start) as u64) as i64);
            }
        }
        persist(config, &state).map_err(|error| instant_acme::Error::Other(Box::new(error)))?;
    }
    if state.ari_renew_at != 0 {
        renewal = renewal.min(state.ari_renew_at);
    }
    if now() < renewal && state.order_url.is_none() {
        return Ok(Duration::from_secs((renewal - now()).min(6 * 3600) as u64));
    }
    let identifiers: Vec<_> = config
        .domains
        .iter()
        .cloned()
        .map(Identifier::Dns)
        .collect();
    let mut order = if let Some(url) = &state.order_url {
        match account.order(url.clone()).await {
            Ok(order) => order,
            Err(error) => {
                if matches!(&error, instant_acme::Error::Api(problem) if matches!(problem.status, Some(404 | 410)))
                {
                    state.order_url = None;
                    state.order_key = None;
                    persist(config, &state)
                        .map_err(|error| instant_acme::Error::Other(Box::new(error)))?;
                }
                return Err(error);
            }
        }
    } else {
        let order = account.new_order(&NewOrder::new(&identifiers)).await?;
        state.order_url = Some(order.url().to_owned());
        state.order_key = Some(
            rcgen::KeyPair::generate()
                .map_err(|_| instant_acme::Error::Crypto)?
                .serialize_pem(),
        );
        persist(config, &state).map_err(|error| instant_acme::Error::Other(Box::new(error)))?;
        order
    };
    if order.state().status == OrderStatus::Invalid {
        state.order_url = None;
        state.order_key = None;
        persist(config, &state).map_err(|error| instant_acme::Error::Other(Box::new(error)))?;
        return Err(instant_acme::Error::Str("order invalid"));
    }
    let _cleanup = challenge::Cleanup(source.clone());
    if order.state().status == OrderStatus::Pending {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authorization = result?;
            if authorization.status == AuthorizationStatus::Valid {
                continue;
            }
            if authorization.status != AuthorizationStatus::Pending {
                return Err("authorization not pending".into());
            }
            let kind = match config.challenge {
                ChallengeConfig::Http01 { .. } => ChallengeType::Http01,
                ChallengeConfig::TlsAlpn01 => ChallengeType::TlsAlpn01,
            };
            let mut challenge = authorization
                .challenge(kind.clone())
                .ok_or("CA did not offer configured challenge")?;
            let domain = challenge.identifier().to_string();
            if !config.domains.contains(&domain) {
                return Err("CA returned an unconfigured identifier".into());
            }
            let token = challenge.token.clone();
            if token.len() < 22
                || token.len() > 256
                || !token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            {
                return Err("CA returned invalid challenge token".into());
            }
            let authorization = challenge.key_authorization();
            let tls = if kind == ChallengeType::TlsAlpn01 {
                Some(
                    challenge::tls_config(&domain, authorization.digest().as_ref())
                        .map_err(|error| instant_acme::Error::Other(Box::new(error)))?,
                )
            } else {
                None
            };
            source.challenges.write().push(challenge::Pending {
                domain,
                token,
                authorization: authorization.as_str().to_owned(),
                expires: Instant::now() + ORDER_TIMEOUT,
                tls,
            });
            challenge.set_ready().await?;
        }
    }
    let policy = RetryPolicy::new()
        .initial_delay(Duration::from_secs(1))
        .timeout(Duration::from_secs(240));
    if order.state().status == OrderStatus::Pending {
        order.poll_ready(&policy).await?;
    }
    if order.state().status == OrderStatus::Ready {
        let key = rcgen::KeyPair::from_pem(state.order_key.as_ref().ok_or("missing order key")?)
            .map_err(|_| instant_acme::Error::Crypto)?;
        let mut params = rcgen::CertificateParams::new(config.domains.clone())
            .map_err(|_| instant_acme::Error::Crypto)?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        let csr = params
            .serialize_request(&key)
            .map_err(|_| instant_acme::Error::Crypto)?;
        order.finalize_csr(csr.der()).await?;
    }
    let cert = order.poll_certificate(&policy).await?;
    let key = state.order_key.take().ok_or("missing order key")?;
    let material = Material::parse(&cert, &key, &config.domains)
        .map_err(|error| instant_acme::Error::Other(Box::new(error)))?;
    state.certificate = Some(cert);
    state.private_key = Some(key);
    state.order_url = None;
    state.retry_at = 0;
    state.ari_retry_at = 0;
    state.ari_renew_at = 0;
    persist(config, &state).map_err(|error| instant_acme::Error::Other(Box::new(error)))?;
    source.publish(material);
    log::info!("Certificate source {} issued and persisted", source.name);
    Ok(Duration::from_secs(60))
}

pub(super) async fn run(source: Arc<Source>, config: &AcmeConfig) {
    let tls = loop {
        match client_tls(config.ca_cert.as_deref()) {
            Ok(tls) => break tls,
            Err(_) => {
                log::error!(
                    "Certificate source {} cannot load ACME trust roots; retry in 60 seconds",
                    source.name
                );
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        }
    };
    let client = HttpClient {
        tls,
        directory: config.directory_url.clone(),
        terms: config.terms_of_service.clone(),
        retry_after: Arc::new(Mutex::new(Instant::now())),
    };
    let mut backoff = 60u64;
    loop {
        let retry_delay = client
            .retry_after
            .lock()
            .saturating_duration_since(Instant::now());
        if !retry_delay.is_zero() {
            tokio::time::sleep(retry_delay.min(Duration::from_secs(6 * 3600))).await;
            continue;
        }
        let outcome =
            tokio::time::timeout(ORDER_TIMEOUT, cycle(&source, config, client.clone())).await;
        let delay = match outcome {
            Ok(Ok(delay)) => {
                backoff = 60;
                delay
            }
            _ => {
                source.challenges.write().clear();
                let jitter = rand::random::<u64>() % (backoff / 4 + 1);
                let backoff_delay = Duration::from_secs((backoff + jitter).min(6 * 3600));
                let retry_after = client
                    .retry_after
                    .lock()
                    .saturating_duration_since(Instant::now());
                let delay = backoff_delay.max(retry_after);
                log::warn!(
                    "Certificate source {} ACME attempt failed; retry in {} seconds; retaining last good certificate",
                    source.name,
                    delay.as_secs()
                );
                if let Ok(Some(mut state)) = load(config) {
                    state.retry_at =
                        now().saturating_add(delay.as_secs().min(i64::MAX as u64) as i64);
                    if persist(config, &state).is_err() {
                        log::error!(
                            "Certificate source {} could not persist retry state",
                            source.name
                        );
                    }
                }
                backoff = (backoff * 2).min(6 * 3600);
                delay
            }
        };
        tokio::time::sleep(delay.min(Duration::from_secs(6 * 3600))).await;
    }
}
