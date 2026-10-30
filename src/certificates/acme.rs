use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeStatus, ChallengeType, Identifier, NewOrder, OrderStatus,
};
use parking_lot::Mutex;
use rustls::pki_types::pem::PemObject;
use serde::{Deserialize, Serialize};

use super::{AcmeConfig, ChallengeConfig, Material, Source, challenge, invalid, now, read_text};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const ORDER_TIMEOUT: Duration = Duration::from_secs(600);
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(6 * 3600);
const MAX_RESPONSE: usize = 1024 * 1024;
// Keep instant-acme's unchecked deadline arithmetic far from clock limits.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(100 * 365 * 24 * 3600);

#[cfg(test)]
#[path = "acme_tests.rs"]
mod tests;

pub(super) fn validate_url(value: &str) -> io::Result<url::Url> {
    // instant-acme builds requests from the original string, not Url's normalized form.
    let uri: http::Uri = value.parse().map_err(|_| invalid("invalid ACME URL"))?;
    if uri.scheme().is_none() || uri.authority().is_none() {
        return Err(invalid("invalid ACME URL"));
    }
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
        let roots = (|| {
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
            Ok(roots)
        })()
        .map_err(|error: io::Error| {
            io::Error::new(
                error.kind(),
                format!("ACME ca_cert '{}': {error}", path.display()),
            )
        })?;
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
    last: Arc<Mutex<Option<ResponseMetadata>>>,
}

#[derive(Clone, Debug)]
struct ResponseMetadata {
    url: String,
    status: http::StatusCode,
    retry_after: Option<Instant>,
}

fn parse_retry_after(headers: &http::HeaderMap) -> io::Result<Option<Instant>> {
    let Some(value) = headers
        .get(http::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
    else {
        return Ok(None);
    };
    let delay = value
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
        .or_else(|| {
            httpdate::parse_http_date(value)
                .ok()
                .and_then(|date| date.duration_since(SystemTime::now()).ok())
        });
    let Some(delay) = delay else {
        return Ok(None);
    };
    if delay > MAX_RETRY_AFTER || SystemTime::now().checked_add(delay).is_none() {
        return Err(invalid("ACME Retry-After exceeds supported range"));
    }
    let deadline = Instant::now()
        .checked_add(delay)
        .ok_or_else(|| invalid("ACME Retry-After exceeds supported range"))?;
    Ok(Some(deadline))
}

fn validate_directory(
    status: http::StatusCode,
    body: &[u8],
    accepted_terms: Option<&str>,
) -> io::Result<()> {
    if !status.is_success() {
        return Err(io::Error::other(format!(
            "ACME directory returned HTTP {}",
            status.as_u16()
        )));
    }
    let directory: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| invalid("invalid ACME directory"))?;
    let terms = match directory.pointer("/meta/termsOfService") {
        Some(serde_json::Value::String(terms)) => Some(terms.as_str()),
        None | Some(serde_json::Value::Null) => None,
        _ => return Err(invalid("invalid ACME terms URL metadata")),
    };
    if terms != accepted_terms {
        return Err(invalid(
            "ACME terms URL differs from explicitly accepted terms_of_service",
        ));
    }
    // instant-acme's nonce request builder can panic before it reaches our HTTP adapter.
    let nonce_url = directory
        .get("newNonce")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid("invalid ACME directory"))?;
    validate_url(nonce_url).map_err(|_| invalid("invalid ACME directory"))?;
    Ok(())
}

#[derive(Debug)]
struct Failure {
    error: Box<instant_acme::Error>,
    response: Option<ResponseMetadata>,
}

impl From<instant_acme::Error> for Failure {
    fn from(error: instant_acme::Error) -> Self {
        Self {
            error: Box::new(error),
            response: None,
        }
    }
}

impl From<io::Error> for Failure {
    fn from(error: io::Error) -> Self {
        instant_acme::Error::Other(Box::new(error)).into()
    }
}

impl HttpClient {
    fn new(tls: Arc<rustls::ClientConfig>, config: &AcmeConfig) -> Self {
        Self {
            tls,
            directory: config.directory_url.clone(),
            terms: config.terms_of_service.clone(),
            last: Arc::new(Mutex::new(None)),
        }
    }

    async fn perform<T>(
        &self,
        deadline: tokio::time::Instant,
        operation: impl std::future::Future<Output = Result<T, instant_acme::Error>>,
    ) -> Result<(T, Option<ResponseMetadata>), Failure> {
        self.last.lock().take();
        if deadline <= tokio::time::Instant::now() {
            return Err(instant_acme::Error::Timeout(None).into());
        }
        let result = tokio::time::timeout_at(deadline, operation)
            .await
            .unwrap_or(Err(instant_acme::Error::Timeout(None)));
        let response = self.last.lock().take();
        match result {
            Ok(value) => Ok((value, response)),
            Err(error) => Err(Failure {
                error: Box::new(error),
                response,
            }),
        }
    }
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
            client.last.lock().take();
            let result = tokio::time::timeout(REQUEST_TIMEOUT, async {
                let request_url = request.uri().to_string();
                let url = validate_url(&request_url)?;
                if url.scheme() == "http" && !client.directory.starts_with("http://") {
                    return Err(invalid(
                        "ACME HTTPS directory cannot downgrade to HTTP endpoints",
                    ));
                }
                let host = url
                    .host_str()
                    .ok_or_else(|| invalid("ACME URL has no host"))?
                    .trim_matches(['[', ']']);
                let location = crate::address::NetLocation::new(
                    crate::address::Address::from(host)?,
                    url.port_or_known_default().unwrap(),
                );
                let addresses = crate::resolver::Resolver::resolve_location(
                    &crate::resolver::NativeResolver::new(),
                    &location,
                )
                .await?;
                let mut stream = None;
                for address in addresses.into_iter().take(8) {
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
                    let retry_after = parse_retry_after(&parts.headers)?;
                    *client.last.lock() = Some(ResponseMetadata {
                        url: request_url,
                        status: parts.status,
                        retry_after,
                    });
                    let bytes = Limited::new(body, MAX_RESPONSE)
                        .collect()
                        .await
                        .map_err(|_| io::Error::other("ACME response failed or exceeded 1 MiB"))?
                        .to_bytes();
                    if is_directory {
                        validate_directory(parts.status, &bytes, client.terms.as_deref())?;
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
    load_state(config, true)
}

#[cfg_attr(not(unix), allow(unused_variables))]
fn load_state(config: &AcmeConfig, check_owner: bool) -> io::Result<Option<State>> {
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
        if meta.mode() & 0o077 != 0 || (check_owner && meta.uid() != unsafe { libc::geteuid() }) {
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

pub(super) fn validate_state(config: &AcmeConfig) -> io::Result<()> {
    match load_state(config, false) {
        Ok(_) => Ok(()),
        // A nonprivileged config check may not have the runtime user's state access.
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => Ok(()),
        Err(error) => Err(state_error(config, error)),
    }
}

pub(super) fn state_error(config: &AcmeConfig, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("ACME state_dir '{}': {error}", config.state_dir.display()),
    )
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
        #[cfg(test)]
        if tests::FAIL_STATE_SYNC.replace(false) {
            return Err(io::Error::other("fixture state sync failure"));
        }
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
                log::error!(
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

fn retry_time(delay: Duration) -> i64 {
    // Both timestamps truncate fractional seconds; round up to avoid early polling.
    now()
        .saturating_add(delay.as_secs().min(i64::MAX as u64) as i64)
        .saturating_add(2)
}

fn clear_order(
    source: &Source,
    config: &AcmeConfig,
    state: &mut State,
) -> Result<(), instant_acme::Error> {
    source.challenges.write().clear();
    state.order_url = None;
    state.order_key = None;
    persist(config, state).map_err(|error| instant_acme::Error::Other(Box::new(error)))
}

async fn invalid_order(
    source: &Source,
    config: &AcmeConfig,
    state: &mut State,
    order: &mut instant_acme::Order,
) -> instant_acme::Error {
    // Forget the terminal order before fetching diagnostics, even if those requests fail.
    if let Err(error) = clear_order(source, config, state) {
        return error;
    }
    if let Some(problem) = &order.state().error {
        return instant_acme::Error::Api(problem.clone());
    }
    let mut authorizations = order.authorizations();
    while let Some(Ok(authorization)) = authorizations.next().await {
        if authorization.status == AuthorizationStatus::Valid {
            continue;
        }
        if let Some(problem) = authorization
            .challenges
            .iter()
            .find_map(|challenge| challenge.error.clone())
        {
            return instant_acme::Error::Api(problem);
        }
    }
    instant_acme::Error::Str("order invalid")
}

#[derive(Debug, PartialEq, Eq)]
enum Progress {
    Deferred,
    Idle,
    Pending,
    Installed,
}

#[derive(Debug)]
struct Turn {
    wake_at: i64,
    outcome: Result<Progress, instant_acme::Error>,
}

struct Scheduler {
    client: Option<HttpClient>,
    account: Option<(Account, Instant)>,
    backoff: u64,
}

fn defer(config: &AcmeConfig, state: &mut State, at: i64) -> io::Result<()> {
    state.retry_at = at;
    persist(config, state)
}

fn response_deadline(response: &Option<ResponseMetadata>) -> i64 {
    response
        .as_ref()
        .and_then(|response| response.retry_after)
        .map_or(0, |deadline| {
            retry_time(deadline.saturating_duration_since(Instant::now()))
        })
}

impl Scheduler {
    fn new() -> Self {
        Self {
            client: None,
            account: None,
            backoff: 60,
        }
    }

    fn defer_hint(
        config: &AcmeConfig,
        state: &mut State,
        response: Option<ResponseMetadata>,
    ) -> Result<(), Failure> {
        let hint = response_deadline(&response);
        if hint > now() && hint > state.retry_at {
            // Preserve each workflow hint before a later operation can fail or be cancelled.
            defer(config, state, hint).map_err(|error| Failure {
                response,
                ..Failure::from(error)
            })?;
        }
        Ok(())
    }

    fn failure(
        &mut self,
        source: &Source,
        config: &AcmeConfig,
        state: Option<&mut State>,
        failure: Failure,
    ) -> Turn {
        self.account = None;
        let jitter = rand::random::<u64>() % (self.backoff / 4 + 1);
        let delay = Duration::from_secs((self.backoff + jitter).min(6 * 3600));
        self.backoff = (self.backoff * 2).min(6 * 3600);
        let wake_at = retry_time(delay)
            .max(response_deadline(&failure.response))
            .max(state.as_ref().map_or(0, |state| state.retry_at));
        let reason = failure_message(&failure.error);
        log::error!(
            "Certificate source {} ACME attempt failed (state_dir '{}'): {reason}; retry in {} seconds; retaining last good certificate",
            source.name,
            config.state_dir.display(),
            wake_at.saturating_sub(now())
        );
        if let Some(state) = state
            && let Err(error) = defer(config, state, wake_at)
        {
            log::error!(
                "Certificate source {} could not persist retry state: {}",
                source.name,
                state_error(config, error)
            );
        }
        Turn {
            wake_at,
            outcome: Err(*failure.error),
        }
    }

    async fn ensure_account(
        &mut self,
        config: &AcmeConfig,
        state: &mut State,
        client: &HttpClient,
        deadline: tokio::time::Instant,
    ) -> Result<(), Failure> {
        if self
            .account
            .as_ref()
            .is_some_and(|(_, created)| created.elapsed() < ORDER_TIMEOUT)
        {
            return Ok(());
        }
        self.account = None;
        let (account, _) = client
            .perform(deadline, account(config, state, client.clone()))
            .await?;
        self.account = Some((account, Instant::now()));
        Ok(())
    }

    async fn turn(&mut self, source: &Arc<Source>, config: &AcmeConfig) -> Turn {
        source
            .challenges
            .write()
            .retain(|pending| pending.expires > Instant::now());
        let mut state =
            match load(config).and_then(|state| state.map_or_else(|| initial_state(config), Ok)) {
                Ok(state) => state,
                Err(error) => return self.failure(source, config, None, error.into()),
            };
        // Recover a rename that succeeded before its directory sync or publication failed.
        if let (Some(cert), Some(key)) = (&state.certificate, &state.private_key)
            && let Ok(material) = Material::parse(cert, key, &config.domains)
            && source
                .material
                .read()
                .as_ref()
                .is_none_or(|current| current.digest != material.digest)
        {
            if let Err(error) = persist(config, &state) {
                return self.failure(source, config, Some(&mut state), error.into());
            }
            source.publish(material);
        }
        if state.retry_at > now() {
            return Turn {
                wake_at: state.retry_at,
                outcome: Ok(Progress::Deferred),
            };
        }
        let renewal = if state.ari_renew_at == 0 {
            renewal_time(source)
        } else {
            renewal_time(source).min(state.ari_renew_at)
        };
        let mandatory = state.order_url.is_some() || source.current().is_none() || now() >= renewal;
        if !mandatory && now() < state.ari_retry_at && config.contacts == state.contacts {
            self.account = None;
            self.backoff = 60;
            return Turn {
                wake_at: renewal.min(state.ari_retry_at),
                outcome: Ok(Progress::Idle),
            };
        }
        if !mandatory {
            return self.ari(source, config, &mut state, renewal).await;
        }
        let result = self.mandatory(source, config, &mut state).await;
        match result {
            Ok(Progress::Installed) => {
                self.account = None;
                self.backoff = 60;
                Turn {
                    wake_at: now() + 60,
                    outcome: Ok(Progress::Installed),
                }
            }
            Ok(Progress::Pending) => {
                let wake_at = state.retry_at.max(retry_time(POLL_INTERVAL));
                if let Err(error) = defer(config, &mut state, wake_at) {
                    return self.failure(source, config, Some(&mut state), error.into());
                }
                Turn {
                    wake_at,
                    outcome: Ok(Progress::Pending),
                }
            }
            Ok(_) => unreachable!("mandatory work installs a certificate or awaits an order"),
            Err(failure) => self.failure(source, config, Some(&mut state), failure),
        }
    }

    fn client(&mut self, config: &AcmeConfig) -> io::Result<HttpClient> {
        if self.client.is_none() {
            self.client = Some(HttpClient::new(
                client_tls(config.ca_cert.as_deref())?,
                config,
            ));
        }
        Ok(self.client.as_ref().unwrap().clone())
    }

    async fn ari(
        &mut self,
        source: &Source,
        config: &AcmeConfig,
        state: &mut State,
        renewal: i64,
    ) -> Turn {
        let probe_due = now() >= state.ari_retry_at;
        if probe_due {
            state.ari_retry_at = now().saturating_add(MAINTENANCE_INTERVAL.as_secs() as i64);
        }
        let current = source.current();
        let result = async {
            persist(config, state)?;
            let current = current
                .as_ref()
                .ok_or(instant_acme::Error::Str("no current certificate"))?;
            let client = self.client(config)?;
            // Optional setup and ARI cannot run past the next mandatory renewal.
            let budget =
                Duration::from_secs(renewal.saturating_sub(now()).max(0) as u64).min(ORDER_TIMEOUT);
            let deadline = tokio::time::Instant::now() + budget;
            self.ensure_account(config, state, &client, deadline)
                .await?;
            if !probe_due {
                return Ok(None);
            }
            let id = instant_acme::CertificateIdentifier::try_from(&current.cert[0])
                .map_err(|_| instant_acme::Error::Unsupported("certificate renewal identifier"))?;
            let account = &self.account.as_ref().unwrap().0;
            client
                .perform(deadline, account.renewal_info(&id))
                .await
                .map(Some)
        }
        .await;
        self.account = None;
        match result {
            Ok(Some(((info, delay), response))) => {
                state.ari_retry_at = retry_time(delay.max(Duration::from_secs(60)))
                    .max(response_deadline(&response));
                let start = info.suggested_window.start.unix_timestamp();
                let end = info.suggested_window.end.unix_timestamp();
                if end > start
                    && let Some(current) = &current
                {
                    let offset = u64::from_be_bytes(
                        aws_lc_rs::digest::digest(
                            &aws_lc_rs::digest::SHA256,
                            current.cert[0].as_ref(),
                        )
                        .as_ref()[..8]
                            .try_into()
                            .unwrap(),
                    );
                    state.ari_renew_at =
                        start.saturating_add((offset % (end - start) as u64) as i64);
                }
            }
            Ok(None) => {}
            Err(failure) => {
                state.ari_retry_at = state.ari_retry_at.max(response_deadline(&failure.response));
                if !matches!(*failure.error, instant_acme::Error::Unsupported(_)) {
                    log::error!(
                        "Certificate source {} ARI check failed: {}; ordinary renewal remains scheduled",
                        source.name,
                        failure_message(&failure.error)
                    );
                }
            }
        }
        if let Err(error) = persist(config, state) {
            log::error!(
                "Certificate source {} could not persist ARI state: {}",
                source.name,
                state_error(config, error)
            );
        }
        let renewal = if state.ari_renew_at == 0 {
            renewal
        } else {
            renewal.min(state.ari_renew_at)
        };
        Turn {
            wake_at: renewal.min(state.ari_retry_at),
            outcome: Ok(Progress::Idle),
        }
    }

    async fn mandatory(
        &mut self,
        source: &Source,
        config: &AcmeConfig,
        state: &mut State,
    ) -> Result<Progress, Failure> {
        let client = self.client(config)?;
        let deadline = tokio::time::Instant::now() + ORDER_TIMEOUT;
        self.ensure_account(config, state, &client, deadline)
            .await?;
        let account = &self.account.as_ref().unwrap().0;
        let (mut order, mut response) = if let Some(url) = state.order_url.clone() {
            match client.perform(deadline, account.order(url.clone())).await {
                Ok(value) => value,
                Err(failure) => {
                    if failure.response.as_ref().is_some_and(|response| {
                        response.url == url && matches!(response.status.as_u16(), 404 | 410)
                    }) {
                        clear_order(source, config, state).map_err(|error| Failure {
                            response: failure.response.clone(),
                            ..Failure::from(error)
                        })?;
                    }
                    return Err(failure);
                }
            }
        } else {
            source.challenges.write().clear();
            let identifiers: Vec<_> = config
                .domains
                .iter()
                .cloned()
                .map(Identifier::Dns)
                .collect();
            let key = rcgen::KeyPair::generate()
                .map_err(|_| instant_acme::Error::Crypto)?
                .serialize_pem();
            let (order, response) = client
                .perform(deadline, account.new_order(&NewOrder::new(&identifiers)))
                .await?;
            state.order_url = Some(order.url().to_owned());
            state.order_key = Some(key);
            persist(config, state).map_err(|error| Failure {
                response: response.clone(),
                ..Failure::from(error)
            })?;
            (order, response)
        };
        if order.state().status == OrderStatus::Pending {
            Self::defer_hint(config, state, response)?;
            self.prepare_challenges(source, config, state, &mut order, deadline)
                .await?;
            return Ok(Progress::Pending);
        }
        source.challenges.write().clear();
        if order.state().status == OrderStatus::Ready {
            let key = rcgen::KeyPair::from_pem(
                state
                    .order_key
                    .as_ref()
                    .ok_or(instant_acme::Error::Str("missing order key"))?,
            )
            .map_err(|_| instant_acme::Error::Crypto)?;
            let mut params = rcgen::CertificateParams::new(config.domains.clone())
                .map_err(|_| instant_acme::Error::Crypto)?;
            params.distinguished_name = rcgen::DistinguishedName::new();
            let csr = params
                .serialize_request(&key)
                .map_err(|_| instant_acme::Error::Crypto)?;
            (_, response) = client
                .perform(deadline, order.finalize_csr(csr.der()))
                .await?;
        }
        match order.state().status {
            OrderStatus::Processing => {
                Self::defer_hint(config, state, response)?;
                Ok(Progress::Pending)
            }
            OrderStatus::Invalid => {
                // Preserve the primary response before best-effort diagnostic requests.
                let (error, _) = client
                    .perform(deadline, async {
                        Ok(invalid_order(source, config, state, &mut order).await)
                    })
                    .await
                    .unwrap_or_else(|failure| (*failure.error, None));
                Err(Failure {
                    error: Box::new(error),
                    response,
                })
            }
            OrderStatus::Valid => {
                let (cert, _) = client.perform(deadline, order.certificate()).await?;
                let cert = cert.ok_or(instant_acme::Error::Str("no certificate received"))?;
                let key = state
                    .order_key
                    .as_ref()
                    .ok_or(instant_acme::Error::Str("missing order key"))?;
                let material = Material::parse(&cert, key, &config.domains)?;
                state.certificate = Some(cert);
                state.private_key = state.order_key.take();
                state.order_url = None;
                state.ari_retry_at = 0;
                state.ari_renew_at = 0;
                defer(config, state, 0)?;
                source.publish(material);
                log::info!("Certificate source {} issued and persisted", source.name);
                Ok(Progress::Installed)
            }
            _ => Err(instant_acme::Error::Str("unexpected order state").into()),
        }
    }

    async fn prepare_challenges(
        &mut self,
        source: &Source,
        config: &AcmeConfig,
        state: &mut State,
        order: &mut instant_acme::Order,
        deadline: tokio::time::Instant,
    ) -> Result<(), Failure> {
        let client = self.client(config)?;
        let mut authorizations = order.authorizations();
        loop {
            let (authorization, response) = client
                .perform(deadline, async { authorizations.next().await.transpose() })
                .await?;
            let Some(mut authorization) = authorization else {
                break;
            };
            if authorization.status == AuthorizationStatus::Valid {
                continue;
            }
            if authorization.status != AuthorizationStatus::Pending {
                let error = clear_order(source, config, state).err().unwrap_or_else(|| {
                    authorization
                        .challenges
                        .iter()
                        .find_map(|challenge| challenge.error.clone())
                        .map_or(
                            instant_acme::Error::Str("authorization not pending"),
                            instant_acme::Error::Api,
                        )
                });
                return Err(Failure {
                    error: Box::new(error),
                    response,
                });
            }
            Self::defer_hint(config, state, response)?;
            let kind = match config.challenge {
                ChallengeConfig::Http01 { .. } => ChallengeType::Http01,
                ChallengeConfig::TlsAlpn01 => ChallengeType::TlsAlpn01,
            };
            let mut challenge =
                authorization
                    .challenge(kind.clone())
                    .ok_or(instant_acme::Error::Str(
                        "CA did not offer configured challenge",
                    ))?;
            if challenge.status == ChallengeStatus::Invalid {
                clear_order(source, config, state)?;
                return Err(challenge
                    .error
                    .clone()
                    .map_or(
                        instant_acme::Error::Str("challenge invalid"),
                        instant_acme::Error::Api,
                    )
                    .into());
            }
            if challenge.status == ChallengeStatus::Valid {
                continue;
            }
            let domain = challenge.identifier().to_string();
            if !config.domains.contains(&domain) {
                return Err(
                    instant_acme::Error::Str("CA returned an unconfigured identifier").into(),
                );
            }
            let token = challenge.token.clone();
            if token.len() < 22
                || token.len() > 256
                || !token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            {
                return Err(instant_acme::Error::Str("CA returned invalid challenge token").into());
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
            {
                let mut pending = source.challenges.write();
                pending.retain(|existing| existing.domain != domain);
                pending.push(challenge::Pending {
                    domain,
                    token,
                    authorization: authorization.as_str().to_owned(),
                    expires: Instant::now() + ORDER_TIMEOUT,
                    tls,
                });
            }
            if challenge.status == ChallengeStatus::Pending {
                let ((), response) = client.perform(deadline, challenge.set_ready()).await?;
                Self::defer_hint(config, state, response)?;
            }
        }
        Ok(())
    }
}

pub(super) async fn run(source: Arc<Source>, config: &AcmeConfig) {
    let _cleanup = challenge::Cleanup(source.clone());
    let mut scheduler = Scheduler::new();
    let mut first_turn = true;
    loop {
        let turn = scheduler.turn(&source, config).await;
        if first_turn && matches!(turn.outcome, Ok(Progress::Deferred)) {
            log::error!(
                "Certificate source {} ACME retry deferred until Unix time {} (state_dir '{}'); waiting {} seconds",
                source.name,
                turn.wake_at,
                config.state_dir.display(),
                turn.wake_at.saturating_sub(now())
            );
        }
        first_turn = false;
        let delay = Duration::from_secs(turn.wake_at.saturating_sub(now()).max(0) as u64);
        tokio::time::sleep(delay.min(MAINTENANCE_INTERVAL)).await;
    }
}

fn failure_message(error: &instant_acme::Error) -> String {
    use instant_acme::Error;
    match error {
        Error::Api(problem) => {
            // CA detail/subproblems and JSON errors can echo submitted data. Log only
            // recognized problem codes and numeric status, never remote free text.
            let code = problem
                .r#type
                .as_deref()
                .and_then(|kind| kind.strip_prefix("urn:ietf:params:acme:error:"))
                .filter(|code| {
                    matches!(
                        *code,
                        "accountDoesNotExist"
                            | "alreadyRevoked"
                            | "badCSR"
                            | "badNonce"
                            | "badPublicKey"
                            | "badRevocationReason"
                            | "badSignatureAlgorithm"
                            | "caa"
                            | "compound"
                            | "connection"
                            | "dns"
                            | "externalAccountRequired"
                            | "incorrectResponse"
                            | "invalidContact"
                            | "malformed"
                            | "orderNotReady"
                            | "rateLimited"
                            | "rejectedIdentifier"
                            | "serverInternal"
                            | "tls"
                            | "unauthorized"
                            | "unsupportedContact"
                            | "unsupportedIdentifier"
                            | "userActionRequired"
                    )
                })
                .unwrap_or("unrecognized problem");
            format!("CA rejected request: {code} (status {:?})", problem.status)
        }
        Error::Other(error) => match error.downcast_ref::<io::Error>() {
            Some(error) => error.to_string(),
            None => "ACME protocol operation failed".to_owned(),
        },
        Error::Json(_) => "invalid ACME JSON or account credentials".to_owned(),
        Error::Str(_)
        | Error::Unsupported(_)
        | Error::Timeout(_)
        | Error::Crypto
        | Error::KeyRejected
        | Error::Http(_)
        | Error::InvalidUri(_) => error.to_string(),
        _ => "ACME request failed".to_owned(),
    }
}
