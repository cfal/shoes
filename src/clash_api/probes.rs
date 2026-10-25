use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::StreamExt;
use http_body_util::Empty;
use indexmap::IndexMap;
use parking_lot::Mutex;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use crate::address::NetLocation;
use crate::client_proxy_chain::ClientChainGroup;
use crate::config::{ClientChainHop, ClientConfig, ConfigSelection};
use crate::control::catalog::{Catalog, CatalogNode, MemberOrigin};
use crate::control::runtime::{ControlRuntime, Generation};
use crate::option_util::OneOrSome;
use crate::resolver::Resolver;

const PROBE_CONCURRENCY: usize = 16;

#[derive(Default)]
struct History {
    history: Vec<Value>,
    alive: bool,
    urls: IndexMap<String, UrlHistory>,
}

struct UrlHistory {
    alive: bool,
    samples: Vec<Value>,
}

#[derive(Default)]
struct FullBudgetAttempts {
    configured: IndexMap<String, tokio::time::Instant>,
    unfiltered: IndexMap<String, tokio::time::Instant>,
    filtered: IndexMap<String, tokio::time::Instant>,
}

pub struct ProbeState {
    connectors: Mutex<HashMap<String, Arc<ClientChainGroup>>>,
    history: Mutex<HashMap<String, History>>,
    full_budget_attempts: Mutex<HashMap<String, FullBudgetAttempts>>,
    resolver: Arc<dyn Resolver>,
    forbidden: Vec<ipnetwork::IpNetwork>,
}

impl ProbeState {
    pub fn url_history(&self, name: &str, url: &str) -> Value {
        self.history
            .lock()
            .get(name)
            .and_then(|history| history.urls.get(url))
            .map(|history| json!(history.samples))
            .unwrap_or_else(|| json!([]))
    }

    pub fn new(resolver: Arc<dyn Resolver>, forbidden: Vec<ipnetwork::IpNetwork>) -> Self {
        Self {
            connectors: Mutex::new(HashMap::new()),
            history: Mutex::new(HashMap::new()),
            full_budget_attempts: Mutex::new(HashMap::new()),
            resolver,
            forbidden,
        }
    }

    pub fn decorate(&self, name: &str, object: &mut Value) {
        let histories = self.history.lock();
        let Some(history) = histories.get(name) else {
            object["alive"] = json!(true);
            object["history"] = json!([]);
            return;
        };
        object["alive"] = json!(history.alive);
        object["history"] = json!(history.history);
        let mut extra = serde_json::Map::new();
        for (url, history) in &history.urls {
            extra.insert(
                url.clone(),
                json!({"alive":history.alive,"history":history.samples}),
            );
        }
        object["extra"] = Value::Object(extra);
    }

    fn record(&self, name: &str, url: &str, delay: u16, satisfied: bool) {
        let mut histories = self.history.lock();
        let history = histories.entry(name.into()).or_default();
        let sample = json!({"time":chrono::Utc::now().to_rfc3339(),"delay":delay});
        history.alive = delay != 0;
        history.history.push(sample.clone());
        if history.history.len() > 10 {
            history.history.remove(0);
        }
        let mut samples = history
            .urls
            .shift_remove(url)
            .map(|history| history.samples)
            .unwrap_or_default();
        if history.urls.len() >= 8 {
            history.urls.shift_remove_index(0);
        }
        let mut url_sample = sample;
        if !satisfied {
            url_sample["delay"] = json!(0);
        }
        samples.push(url_sample);
        if samples.len() > 10 {
            samples.remove(0);
        }
        history.urls.insert(
            url.into(),
            UrlHistory {
                alive: satisfied,
                samples,
            },
        );
    }

    fn order_members(&self, indices: &mut [usize], members: &[String], query: &ProbeQuery) {
        let attempts = self.full_budget_attempts.lock();
        indices.sort_by_key(|&index| {
            attempts.get(&members[index]).and_then(|attempts| {
                let at = if query.expected.is_empty() {
                    attempts
                        .configured
                        .get(query.url.as_str())
                        .or_else(|| attempts.unfiltered.get(query.url.as_str()))
                } else {
                    attempts.filtered.get(query.url.as_str())
                };
                at.copied()
            })
        });
    }

    fn record_full_budget_attempt(
        &self,
        name: &str,
        query: &ProbeQuery,
        automatic: &crate::control::url_test::AutomaticGroups,
    ) {
        let configured = query.expected.is_empty()
            && automatic.0.values().any(|group| {
                group.config.url == query.url.as_str()
                    && group.members.iter().any(|member| member == name)
            });
        let mut attempts = self.full_budget_attempts.lock();
        let attempts = attempts.entry(name.into()).or_default();
        // Configured keys are bounded by the catalog, not arbitrary API URL eviction.
        let urls = if configured {
            &mut attempts.configured
        } else if !query.expected.is_empty() {
            &mut attempts.filtered
        } else {
            &mut attempts.unfiltered
        };
        urls.shift_remove(query.url.as_str());
        if !configured && urls.len() >= 8 {
            urls.shift_remove_index(0);
        }
        urls.insert(query.url.to_string(), tokio::time::Instant::now());
    }

    fn connector(&self, catalog: &Catalog, name: &str) -> io::Result<Arc<ClientChainGroup>> {
        if let Some(connector) = self.connectors.lock().get(name) {
            return Ok(connector.clone());
        }
        let mut clients = Vec::new();
        expand(catalog, name, &mut Vec::new(), &mut clients)?;
        let chain = crate::tcp::chain_builder::try_build_client_proxy_chain(
            OneOrSome::One(ClientChainHop::Pool(OneOrSome::Some(
                clients.into_iter().map(ConfigSelection::Config).collect(),
            ))),
            self.resolver.clone(),
        )?;
        let connector = Arc::new(ClientChainGroup::new(vec![chain]));
        Ok(self
            .connectors
            .lock()
            .entry(name.into())
            .or_insert(connector)
            .clone())
    }
}

fn expand(
    catalog: &Catalog,
    name: &str,
    path: &mut Vec<(String, String)>,
    clients: &mut Vec<ClientConfig>,
) -> io::Result<()> {
    if clients.len() >= 16_384 || path.len() >= 128 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "probe subject expansion exceeds limit",
        ));
    }
    match catalog.nodes.get(name) {
        Some(CatalogNode::Leaf(config)) => {
            let mut config = (**config).clone();
            config.control = Some(MemberOrigin {
                name: Arc::from(name),
                path: path.clone(),
                selection: catalog.selection.clone(),
            });
            clients.push(config);
        }
        Some(CatalogNode::Group { members, .. }) => {
            for member in members {
                path.push((name.into(), member.clone()));
                expand(catalog, member, path, clients)?;
                path.pop();
            }
        }
        Some(CatalogNode::Reject) => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "REJECT cannot carry a probe",
            ));
        }
        None => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "proxy does not exist",
            ));
        }
    }
    Ok(())
}

pub struct ProbeQuery {
    url: url::Url,
    timeout: Duration,
    expected: Vec<(u16, u16)>,
}

impl ProbeQuery {
    pub(crate) fn validate_automatic_target(&self) -> io::Result<()> {
        let denied = match self.url.host() {
            Some(url::Host::Ipv4(ip)) => forbidden(ip.into()),
            Some(url::Host::Ipv6(ip)) => forbidden(ip.into()),
            _ => false,
        };
        if denied {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "url-test URL is denied by probe destination policy",
            ));
        }
        Ok(())
    }

    pub fn parse(query: &HashMap<String, String>, group: bool) -> io::Result<Self> {
        let bad = || io::Error::new(io::ErrorKind::InvalidInput, "invalid delay test query");
        let raw = query.get("url").ok_or_else(bad)?;
        if raw.len() > 2048 {
            return Err(bad());
        }
        let url = url::Url::parse(raw).map_err(|_| bad())?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(bad());
        }
        let timeout: u64 = query
            .get("timeout")
            .ok_or_else(bad)?
            .parse()
            .map_err(|_| bad())?;
        if timeout == 0 || timeout > if group { 60_000 } else { 32_767 } {
            return Err(bad());
        }
        let mut expected = Vec::new();
        if let Some(value) = query
            .get("expected")
            .filter(|value| !value.trim().is_empty() && value.trim() != "*")
        {
            for part in value.split([',', '/']) {
                let (start, end) = part.split_once('-').unwrap_or((part, part));
                let start: u16 = start.trim().parse().map_err(|_| bad())?;
                let end: u16 = end.trim().parse().map_err(|_| bad())?;
                if start > end {
                    return Err(bad());
                }
                expected.push((start, end));
            }
        }
        Ok(Self {
            url,
            timeout: Duration::from_millis(timeout),
            expected,
        })
    }
}

pub async fn probe(
    runtime: &ControlRuntime,
    generation: &Generation,
    name: &str,
    query: &ProbeQuery,
) -> io::Result<u16> {
    if runtime
        .activating
        .load(std::sync::atomic::Ordering::Acquire)
    {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "generation is activating",
        ));
    }
    let epoch = runtime.with_probe_generation(generation.id, || runtime.probe_epoch())?;
    let _permit = runtime
        .probes
        .try_acquire()
        .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "probe limit reached"))?;
    probe_until(
        runtime,
        generation,
        name,
        query,
        tokio::time::Instant::now() + query.timeout,
        false,
        &epoch,
    )
    .await
}

pub async fn probe_group(
    runtime: &ControlRuntime,
    generation: &Generation,
    members: &[String],
    query: &ProbeQuery,
) -> io::Result<serde_json::Map<String, Value>> {
    let epoch = runtime
        .with_probe_generation(generation.id, || runtime.probe_epoch())
        .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "group probes unavailable"))?;
    let deadline = tokio::time::Instant::now() + query.timeout;
    let mut indices: Vec<_> = (0..members.len()).collect();
    generation
        .probes
        .order_members(&mut indices, members, query);
    let mut results =
        futures::stream::iter(indices.into_iter().enumerate().map(|(ordinal, member)| {
            let name = members[member].clone();
            let epoch = &epoch;
            async move {
                let activating = || {
                    runtime
                        .activating
                        .load(std::sync::atomic::Ordering::Acquire)
                };
                if activating() || tokio::time::Instant::now() >= deadline {
                    return (name, None);
                }
                let permit = tokio::select! {
                    biased;
                    _ = epoch.cancelled() => return (name, None),
                    _ = runtime.shutdown.cancelled() => return (name, None),
                    permit = acquire_probe(runtime, deadline) => permit,
                };
                let Ok((_permit, waited)) = permit else {
                    return (name, None);
                };
                if activating() || tokio::time::Instant::now() >= deadline {
                    return (name, None);
                }
                let result = probe_until(
                    runtime,
                    generation,
                    &name,
                    query,
                    deadline,
                    waited || ordinal >= PROBE_CONCURRENCY,
                    epoch,
                )
                .await;
                (name, Some(result))
            }
        }))
        .buffer_unordered(PROBE_CONCURRENCY);
    let mut started = false;
    let mut successes = serde_json::Map::new();
    while let Some((name, result)) = results.next().await {
        let Some(result) = result else {
            continue;
        };
        started = true;
        if let Ok(delay) = result {
            successes.insert(name, json!(delay));
        }
    }
    if !successes.is_empty() {
        Ok(successes)
    } else if started {
        Err(io::Error::new(io::ErrorKind::TimedOut, "Timeout"))
    } else {
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "group probes unavailable",
        ))
    }
}

async fn acquire_probe(
    runtime: &ControlRuntime,
    deadline: tokio::time::Instant,
) -> io::Result<(tokio::sync::SemaphorePermit<'_>, bool)> {
    if let Ok(permit) = runtime.probes.try_acquire() {
        return Ok((permit, false));
    }
    let permit = tokio::time::timeout_at(deadline, runtime.probes.acquire())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Timeout"))?
        .map_err(|_| io::Error::new(io::ErrorKind::Interrupted, "probes stopped"))?;
    Ok((permit, true))
}

fn generation_changed() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "probe generation changed")
}

fn with_probe_epoch<T>(
    runtime: &ControlRuntime,
    generation: &Generation,
    epoch: &CancellationToken,
    apply: impl FnOnce() -> T,
) -> io::Result<T> {
    runtime.with_probe_generation(generation.id, || {
        if epoch.is_cancelled() {
            return Err(generation_changed());
        }
        Ok(apply())
    })?
}

async fn probe_until(
    runtime: &ControlRuntime,
    generation: &Generation,
    name: &str,
    query: &ProbeQuery,
    deadline: tokio::time::Instant,
    queued: bool,
    epoch: &CancellationToken,
) -> io::Result<u16> {
    with_probe_epoch(runtime, generation, epoch, || {
        if !queued {
            generation.probes.record_full_budget_attempt(
                name,
                query,
                &generation.catalog.selection.automatic,
            );
        }
    })?;
    let probe_request =
        crate::control::url_test::BACKGROUND.scope((), request(generation, name, query));
    let result = tokio::select! {
        biased;
        _ = runtime.shutdown.cancelled() => {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "controller stopped"));
        }
        _ = epoch.cancelled() => {
            return Err(generation_changed());
        }
        result = tokio::time::timeout_at(deadline, probe_request) => {
            match result {
                Ok(result) => result,
                // Queue time shortened this attempt's budget; expiry is not evidence of remote failure.
                Err(_) if queued => return Err(io::Error::new(io::ErrorKind::TimedOut, "Timeout")),
                Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "Timeout")),
            }
        }
    };
    let (delay, satisfied) = result.as_ref().copied().unwrap_or((0, false));
    with_probe_epoch(runtime, generation, epoch, || {
        if let Err(error) = &result
            && local_failure(error)
        {
            return;
        }
        generation
            .probes
            .record(name, query.url.as_str(), delay, satisfied);
        if query.expected.is_empty() {
            generation.catalog.selection.automatic.record(
                name,
                query.url.as_str(),
                (satisfied && delay != 0).then_some(delay),
            );
        }
    })?;
    result.map(|(delay, _)| delay)
}

pub(crate) fn local_failure(error: &io::Error) -> bool {
    if crate::resources::is_exhausted(error) {
        return true;
    }
    let mut error: &(dyn std::error::Error + 'static) = error;
    loop {
        if error.is::<ProbePolicyDenied>() || error.is::<crate::dns::SyntheticDnsAnswer>() {
            return true;
        }
        let source = if let Some(error) = error.downcast_ref::<io::Error>() {
            if local_io_failure(error) {
                return true;
            }
            // io::Error::source can skip the wrapped error itself.
            error.get_ref().map(|inner| inner as &dyn std::error::Error)
        } else if let Some(error) = error.downcast_ref::<h2::Error>() {
            return error.get_io().is_some_and(local_failure);
        } else {
            error.source()
        };
        let Some(source) = source else { return false };
        error = source;
    }
}

fn local_io_failure(error: &io::Error) -> bool {
    #[cfg(unix)]
    if error.raw_os_error().is_some_and(|code| {
        matches!(
            code,
            libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM
        )
    }) {
        return true;
    }
    // Protocol handlers can use these same kinds for remote rejections.
    if error.raw_os_error().is_some()
        && matches!(
            error.kind(),
            io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidInput | io::ErrorKind::NotFound
        )
    {
        return true;
    }
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock
            | io::ErrorKind::Unsupported
            | io::ErrorKind::Interrupted
            | io::ErrorKind::AddrInUse
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::OutOfMemory
            | io::ErrorKind::ResourceBusy
    )
}

#[derive(Debug)]
struct ProbePolicyDenied;

impl std::fmt::Display for ProbePolicyDenied {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("probe destination is not allowed")
    }
}

impl std::error::Error for ProbePolicyDenied {}

pub(crate) async fn run_automatic(
    runtime: std::sync::Weak<ControlRuntime>,
    generation: Arc<Generation>,
    epoch: CancellationToken,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let groups: Vec<_> = generation
        .catalog
        .nodes
        .keys()
        .filter_map(|name| generation.catalog.selection.automatic.0.get(name))
        .collect();
    let mut rounds = futures::stream::FuturesUnordered::new();
    let mut checking = vec![false; groups.len()];
    loop {
        let Some(runtime) = runtime.upgrade() else {
            return;
        };
        tokio::select! {
            biased;
            _ = runtime.shutdown.cancelled() => return,
            _ = epoch.cancelled() => return,
            Some(index) = rounds.next(), if !rounds.is_empty() => {
                checking[index] = false;
                continue;
            }
            _ = ticker.tick() => {}
        }
        if runtime.with_probe_generation(generation.id, || ()).is_err() {
            return;
        }
        let now = tokio::time::Instant::now();
        let mut due: Vec<_> = groups
            .iter()
            .enumerate()
            .filter(|(index, _)| !checking[*index])
            .filter_map(|(index, group)| group.due_members(now).map(|members| (index, members)))
            .collect();
        // A busy, short-interval group must not reset a waiting group's priority.
        due.sort_by_key(|(index, _)| groups[*index].last_unqueued_admission());
        for (index, members) in due {
            let group = groups[index];
            checking[index] = true;
            let round = AutomaticRound {
                group,
                completed: false,
            };
            let runtime = runtime.clone();
            let generation = &generation;
            let epoch = &epoch;
            rounds.push(async move {
                run_automatic_round(round, &runtime, generation, members, now, epoch).await;
                index
            });
        }
    }
}

struct AutomaticRound<'a> {
    group: &'a crate::control::url_test::AutomaticGroup,
    completed: bool,
}

impl Drop for AutomaticRound<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.group.cancel_check();
        }
    }
}

async fn run_automatic_round(
    mut round: AutomaticRound<'_>,
    runtime: &ControlRuntime,
    generation: &Generation,
    mut members: Vec<usize>,
    started: tokio::time::Instant,
    epoch: &CancellationToken,
) {
    let group = round.group;
    let query = ProbeQuery {
        url: url::Url::parse(&group.config.url).expect("validated url-test URL"),
        timeout: Duration::from_millis(group.config.timeout),
        expected: Vec::new(),
    };
    let deadline = started + query.timeout;
    // Local failures do not change health, but must not monopolize full-budget slots.
    generation
        .probes
        .order_members(&mut members, &group.members, &query);
    let mut probes = futures::stream::iter(members.into_iter().enumerate())
        .map(|(ordinal, index)| {
            let query = &query;
            async move {
                let Ok((_permit, waited)) = acquire_probe(runtime, deadline).await else {
                    return;
                };
                if tokio::time::Instant::now() >= deadline {
                    return;
                }
                let queued = waited || ordinal >= PROBE_CONCURRENCY;
                if with_probe_epoch(runtime, generation, epoch, || group.admitted(index, queued))
                    .is_err()
                {
                    return;
                }
                let _ = probe_until(
                    runtime,
                    generation,
                    &group.members[index],
                    query,
                    deadline,
                    queued,
                    epoch,
                )
                .await;
            }
        })
        .buffer_unordered(PROBE_CONCURRENCY);
    while probes.next().await.is_some() {}
    round.completed = with_probe_epoch(runtime, generation, epoch, || ()).is_ok();
}

async fn request(
    generation: &Generation,
    name: &str,
    query: &ProbeQuery,
) -> io::Result<(u16, bool)> {
    request_with_tls_config(
        generation,
        name,
        query,
        crate::rustls_config_util::create_dns_client_config,
    )
    .await
}

async fn request_with_tls_config(
    generation: &Generation,
    name: &str,
    query: &ProbeQuery,
    tls_config: impl FnOnce() -> rustls::ClientConfig,
) -> io::Result<(u16, bool)> {
    let started = Instant::now();
    let host = query
        .url
        .host_str()
        .unwrap()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let port = query.url.port_or_known_default().unwrap();
    let target = NetLocation::new(crate::address::Address::from(host)?, port);
    let resolver = ProbeResolver {
        inner: generation.probes.resolver.clone(),
        target: target.clone(),
        forbidden_ranges: generation.probes.forbidden.clone(),
        denied: forbidden,
    };
    if let Some(address) = target.to_socket_addr_nonblocking() {
        resolver.check(&[address])?;
    }
    let resolver: Arc<dyn Resolver> = Arc::new(resolver);
    let chain = generation.probes.connector(&generation.catalog, name)?;
    let setup = chain.connect_tcp(target.into(), &resolver).await?;
    if setup
        .early_data
        .as_ref()
        .is_some_and(|bytes| !bytes.is_empty())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsolicited probe data",
        ));
    }
    let stream: Box<dyn crate::async_stream::AsyncStream> = if query.url.scheme() == "https" {
        let server =
            rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(io::Error::other)?;
        let connection = rustls::ClientConnection::new(Arc::new(tls_config()), server)
            .map_err(io::Error::other)?;
        Box::new(
            crate::crypto::CryptoTlsStream::handshake(
                setup.client_stream,
                crate::crypto::TlsConnection::new(connection),
                crate::crypto::TlsReadMode::Stream,
                &[],
            )
            .await?,
        )
    } else {
        setup.client_stream
    };
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(io::Error::other)?;
    let _driver = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let path = &query.url[url::Position::BeforePath..url::Position::AfterQuery];
    let authority = &query.url[url::Position::BeforeHost..url::Position::AfterPort];
    let request = hyper::Request::builder()
        .method("HEAD")
        .uri(if path.is_empty() { "/" } else { path })
        .header("Host", authority)
        .header("Connection", "close")
        .body(Empty::<Bytes>::new())
        .map_err(io::Error::other)?;
    let response = sender
        .send_request(request)
        .await
        .map_err(io::Error::other)?;
    let status = response.status().as_u16();
    let satisfied = query.expected.is_empty()
        || query
            .expected
            .iter()
            .any(|(start, end)| (*start..=*end).contains(&status));
    Ok((
        started.elapsed().as_millis().clamp(1, u16::MAX as u128) as u16,
        satisfied,
    ))
}

#[derive(Debug, Clone)]
struct ProbeResolver {
    inner: Arc<dyn Resolver>,
    target: NetLocation,
    forbidden_ranges: Vec<ipnetwork::IpNetwork>,
    denied: fn(IpAddr) -> bool,
}

impl ProbeResolver {
    fn check(&self, addresses: &[std::net::SocketAddr]) -> io::Result<()> {
        if addresses.is_empty()
            || addresses.iter().any(|address| {
                (self.denied)(address.ip())
                    || self
                        .forbidden_ranges
                        .iter()
                        .any(|range| range.contains(address.ip().to_canonical()))
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                ProbePolicyDenied,
            ));
        }
        Ok(())
    }
}

impl Resolver for ProbeResolver {
    fn resolve_location(&self, location: &NetLocation) -> crate::resolver::ResolveFuture {
        let resolve = self.inner.resolve_location(location);
        if location != &self.target {
            return resolve;
        }
        let policy = self.clone();
        Box::pin(async move {
            let addresses = resolve.await?;
            policy.check(&addresses)?;
            Ok(addresses)
        })
    }
}

fn forbidden(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
                || matches!(ip.octets(), [198, 18 | 19, _, _])
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unicast_link_local()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn publish_for_api_probes(runtime: &ControlRuntime, generation: &Arc<Generation>) {
        runtime.publish(generation.clone()).await.unwrap();
        // Resume would also start periodic probes.
        runtime
            .activating
            .store(false, std::sync::atomic::Ordering::Release);
    }

    #[tokio::test]
    async fn probe_epoch_fence_preserves_errors_and_skips_stale_writes() {
        let generation = Arc::new(generation(catalog(), Arc::new(Answers(Vec::new()))));
        let mut service = crate::control::runtime::ControlService::new(Default::default()).unwrap();
        let runtime = &service.runtime;
        publish_for_api_probes(runtime, &generation).await;
        let epoch = runtime.probe_epoch();
        assert_eq!(
            with_probe_epoch(runtime, &generation, &epoch, || 7).unwrap(),
            7
        );

        epoch.cancel();
        let error = with_probe_epoch(runtime, &generation, &epoch, || {
            panic!("cancelled epoch must not write")
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(error.to_string(), "probe generation changed");

        runtime
            .activating
            .store(true, std::sync::atomic::Ordering::Release);
        let error = with_probe_epoch(runtime, &generation, &epoch, || {
            panic!("inactive generation must not write")
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(error.to_string(), "probe generation is no longer active");
        service.shutdown().await;
    }

    #[test]
    fn url_test_remote_authentication_failures_are_not_local_policy_denials() {
        assert!(local_failure(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            ProbePolicyDenied,
        )));
        assert!(!local_failure(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
        )));
        assert!(!local_failure(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "remote authentication failed",
        )));
        assert!(!local_failure(&io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKS server rejected auth method",
        )));
        #[cfg(unix)]
        for code in [
            libc::EMFILE,
            libc::ENFILE,
            libc::ENOBUFS,
            libc::ENOMEM,
            libc::EACCES,
        ] {
            assert!(local_failure(&io::Error::from_raw_os_error(code)));
        }
    }

    fn automatic_generation(id: u64, count: usize, resolver: Arc<dyn Resolver>) -> Arc<Generation> {
        let members: Vec<_> = (0..count)
            .map(|index| json!({"name":format!("member-{index}"), "protocol":{"type":"direct"}}))
            .collect();
        let configs = serde_json::from_value(json!([
            {"client_group":"auto", "type":"url-test", "url":"http://probe.invalid/", "interval":10,
                "timeout":1000, "lazy":false, "client_proxies":members}
        ]))
        .unwrap();
        let validated = crate::config::create_server_configs(configs).unwrap();
        assert!(validated.control.listeners.is_empty());
        let mut generation = generation(validated.catalog.unwrap(), resolver);
        generation.id = id;
        Arc::new(generation)
    }

    #[derive(Debug, Default)]
    struct ScheduledAnswers {
        calls: Mutex<Vec<String>>,
        delays: HashMap<String, Duration>,
        local_failures: std::collections::HashSet<String>,
    }

    impl Resolver for ScheduledAnswers {
        fn resolve_location(&self, location: &NetLocation) -> crate::resolver::ResolveFuture {
            let host = location.address().hostname().unwrap().to_owned();
            self.calls.lock().push(host.clone());
            let delay = self.delays.get(&host).copied();
            let local_failure = self.local_failures.contains(&host);
            Box::pin(async move {
                if local_failure {
                    return Err(io::Error::other(ProbePolicyDenied));
                }
                if let Some(delay) = delay {
                    tokio::time::sleep(delay).await;
                    Err(io::ErrorKind::ConnectionRefused.into())
                } else {
                    std::future::pending().await
                }
            })
        }
    }

    fn scheduled_generation(
        groups: &[(&str, usize, u64, u64)],
        resolver: Arc<ScheduledAnswers>,
    ) -> Arc<Generation> {
        let configs: Vec<_> = groups
            .iter()
            .map(|&(name, count, interval, timeout)| {
                let members: Vec<_> = (0..count)
                    .map(|index| {
                        json!({
                            "name": format!("{name}-{index}"),
                            "address": format!("{name}-{index}.invalid:80"),
                            "protocol": {"type": "http"}
                        })
                    })
                    .collect();
                json!({
                    "client_group": name, "type": "url-test", "url": "http://probe.invalid/",
                    "interval": interval, "timeout": timeout, "lazy": false,
                    "client_proxies": members
                })
            })
            .collect();
        let catalog =
            crate::config::create_server_configs(serde_json::from_value(json!(configs)).unwrap())
                .unwrap()
                .catalog
                .unwrap();
        Arc::new(generation(catalog, resolver))
    }

    async fn advance_rounds(seconds: u64) {
        for _ in 0..seconds * 10 {
            tokio::time::advance(Duration::from_millis(100)).await;
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn url_test_filtered_api_attempts_do_not_defer_automatic_health_checks() {
        let resolver = Arc::new(ScheduledAnswers {
            local_failures: (1..17)
                .map(|index| format!("auto-{index}.invalid"))
                .collect(),
            ..Default::default()
        });
        let generation = scheduled_generation(&[("auto", 17, 10, 1000)], resolver);
        generation
            .catalog
            .selection
            .automatic
            .record("auto-0", "http://probe.invalid/", Some(5));
        let mut service = crate::control::runtime::ControlService::new(Default::default()).unwrap();
        publish_for_api_probes(&service.runtime, &generation).await;
        let mut filtered = query();
        filtered.expected = vec![(204, 204)];
        assert!(
            probe(&service.runtime, &generation, "auto-0", &filtered)
                .await
                .is_err()
        );
        assert_eq!(
            generation.catalog.selection.automatic.0["auto"].health("auto-0"),
            "healthy"
        );
        service.runtime.resume().await.unwrap();
        advance_rounds(2).await;
        assert_eq!(
            generation.catalog.selection.automatic.0["auto"].health("auto-0"),
            "dead"
        );
        service.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn url_test_other_url_eviction_does_not_change_admission() {
        for filtered in [true, false] {
            let mut service =
                crate::control::runtime::ControlService::new(Default::default()).unwrap();
            let occupied = service.runtime.probes.acquire_many(15).await.unwrap();
            let resolver = Arc::new(ScheduledAnswers {
                local_failures: ["auto-0.invalid".into()].into(),
                ..Default::default()
            });
            let generation = scheduled_generation(&[("auto", 2, 10, 1000)], resolver.clone());
            publish_for_api_probes(&service.runtime, &generation).await;
            assert!(
                probe(&service.runtime, &generation, "auto-0", &query())
                    .await
                    .is_err()
            );
            let mut other = query();
            if filtered {
                other.expected = vec![(204, 204)];
            }
            for index in 0..8 {
                other.url = url::Url::parse(&format!("http://other.invalid/{index}")).unwrap();
                assert!(
                    probe(&service.runtime, &generation, "auto-0", &other)
                        .await
                        .is_err()
                );
            }
            assert_eq!(resolver.calls.lock().len(), 9);
            resolver.calls.lock().clear();
            service.runtime.resume().await.unwrap();
            advance_rounds(2).await;
            assert_eq!(
                *resolver.calls.lock(),
                ["auto-1.invalid"],
                "filtered={filtered}"
            );
            let automatic = &generation.catalog.selection.automatic.0["auto"];
            assert_eq!(automatic.health("auto-0"), "unprobed");
            assert_eq!(automatic.health("auto-1"), "dead");
            drop(occupied);
            service.shutdown().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn url_test_expansion_limits_preserve_health_without_dialing() {
        for automatic in [false, true] {
            let mut configs: Vec<_> = (0..128)
                .map(|index| {
                    let member = if index == 127 {
                        "direct".into()
                    } else {
                        format!("deep-{}", index + 1)
                    };
                    json!({
                        "client_group": format!("deep-{index}"),
                        "client_proxies": [member]
                    })
                })
                .collect();
            configs.push(json!({
                "client_group":"auto", "type":"url-test", "url":"http://probe.invalid/",
                "interval":10, "timeout":1000, "lazy":false, "client_proxies":["deep-0"]
            }));
            let validated = crate::config::create_server_configs(
                serde_json::from_value(json!(configs)).unwrap(),
            )
            .unwrap();
            let resolver = Arc::new(TrackedAnswers::default());
            let generation = Arc::new(generation(validated.catalog.unwrap(), resolver.clone()));
            generation.catalog.selection.automatic.record(
                "deep-0",
                "http://probe.invalid/",
                Some(5),
            );
            generation
                .probes
                .record("deep-0", "http://probe.invalid/", 5, true);
            let history = generation
                .probes
                .url_history("deep-0", "http://probe.invalid/");
            let mut service =
                crate::control::runtime::ControlService::new(Default::default()).unwrap();
            service.runtime.publish(generation.clone()).await.unwrap();
            if automatic {
                service.runtime.resume().await.unwrap();
                advance_rounds(2).await;
            } else {
                service
                    .runtime
                    .activating
                    .store(false, std::sync::atomic::Ordering::Release);
                assert!(
                    probe_group(&service.runtime, &generation, &["deep-0".into()], &query())
                        .await
                        .is_err()
                );
            }
            assert_eq!(
                resolver.started.load(std::sync::atomic::Ordering::Relaxed),
                0
            );
            assert_eq!(
                generation.catalog.selection.automatic.0["auto"].health("deep-0"),
                "healthy",
                "automatic={automatic}"
            );
            assert_eq!(
                generation
                    .probes
                    .url_history("deep-0", "http://probe.invalid/"),
                history
            );
            service.shutdown().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn url_test_partial_capacity_eventually_admits_every_member() {
        let mut service = crate::control::runtime::ControlService::new(Default::default()).unwrap();
        let _occupied = service.runtime.probes.acquire_many(15).await.unwrap();
        let resolver = Arc::new(ScheduledAnswers::default());
        let generation = scheduled_generation(&[("auto", 32, 1, 1000)], resolver.clone());
        service.runtime.publish(generation.clone()).await.unwrap();
        service.runtime.resume().await.unwrap();
        advance_rounds(1).await;
        assert_eq!(generation.probes.history.lock().len(), 1);
        assert_eq!(
            generation.catalog.selection.automatic.0["auto"].health("auto-31"),
            "unprobed"
        );
        advance_rounds(35).await;
        let seen: std::collections::HashSet<_> = resolver.calls.lock().iter().cloned().collect();
        assert_eq!(seen.len(), 32, "admitted: {seen:?}");
        drop(_occupied);
        service.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn url_test_different_intervals_do_not_starve_a_due_group() {
        let mut service = crate::control::runtime::ControlService::new(Default::default()).unwrap();
        let resolver = Arc::new(ScheduledAnswers::default());
        let generation = scheduled_generation(
            &[("a", 16, 1, 1000), ("b", 16, 2, 1000), ("c", 16, 2, 1000)],
            resolver.clone(),
        );
        service.runtime.publish(generation).await.unwrap();
        service.runtime.resume().await.unwrap();
        advance_rounds(8).await;
        let seen: std::collections::HashSet<_> = resolver.calls.lock().iter().cloned().collect();
        assert_eq!(seen.len(), 48, "admitted: {seen:?}");
        service.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn url_test_unadmitted_round_does_not_skip_members_on_the_next_round() {
        let mut service = crate::control::runtime::ControlService::new(Default::default()).unwrap();
        let resolver = Arc::new(ScheduledAnswers::default());
        let generation =
            scheduled_generation(&[("a", 32, 1, 1000), ("b", 16, 1, 1000)], resolver.clone());
        service.runtime.publish(generation).await.unwrap();
        service.runtime.resume().await.unwrap();
        advance_rounds(6).await;
        let seen: std::collections::HashSet<_> = resolver.calls.lock().iter().cloned().collect();
        assert_eq!(seen.len(), 48, "admitted: {seen:?}");
        service.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn url_test_slow_group_does_not_block_short_intervals() {
        let mut service = crate::control::runtime::ControlService::new(Default::default()).unwrap();
        let resolver = Arc::new(ScheduledAnswers {
            delays: HashMap::from([("b-0.invalid".into(), Duration::ZERO)]),
            ..Default::default()
        });
        let generation =
            scheduled_generation(&[("a", 1, 60, 60000), ("b", 1, 1, 500)], resolver.clone());
        service.runtime.publish(generation).await.unwrap();
        service.runtime.resume().await.unwrap();
        advance_rounds(5).await;
        let checks = resolver
            .calls
            .lock()
            .iter()
            .filter(|host| *host == "b-0.invalid")
            .count();
        assert!(checks >= 4, "short-interval checks: {checks}");
        service.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn url_test_queued_group_gets_a_full_budget_on_a_later_round() {
        let mut service = crate::control::runtime::ControlService::new(Default::default()).unwrap();
        let resolver = Arc::new(ScheduledAnswers {
            delays: (0..16)
                .map(|index| (format!("a-{index}.invalid"), Duration::from_millis(10)))
                .collect(),
            ..Default::default()
        });
        let generation = scheduled_generation(&[("a", 16, 10, 1000), ("b", 2, 10, 1000)], resolver);
        generation
            .catalog
            .selection
            .automatic
            .record("b-0", "http://probe.invalid/", Some(5));
        service.runtime.publish(generation.clone()).await.unwrap();
        service.runtime.resume().await.unwrap();
        advance_rounds(2).await;
        assert_eq!(
            generation.catalog.selection.automatic.0["b"].health("b-0"),
            "healthy"
        );
        advance_rounds(10).await;
        assert_eq!(
            generation.catalog.selection.automatic.0["b"].health("b-0"),
            "dead"
        );
        service.shutdown().await;
    }

    #[tokio::test]
    async fn url_test_real_dns_policy_denial_preserves_health_and_history() {
        let resolver = crate::dns::real_only(
            Arc::new(Answers(vec!["198.18.0.2:80".parse().unwrap()])),
            vec!["198.18.0.0/15".parse().unwrap()].into(),
        );
        let generation = automatic_generation(1, 1, resolver);
        let mut service = crate::control::runtime::ControlService::new(Default::default()).unwrap();
        generation
            .catalog
            .selection
            .automatic
            .record("member-0", "http://probe.invalid/", Some(5));
        generation
            .probes
            .record("member-0", "http://probe.invalid/", 5, true);
        let history = generation
            .probes
            .url_history("member-0", "http://probe.invalid/");
        publish_for_api_probes(&service.runtime, &generation).await;
        let error = probe(&service.runtime, &generation, "member-0", &query())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            generation.catalog.selection.automatic.0["auto"].health("member-0"),
            "healthy"
        );
        assert_eq!(
            generation
                .probes
                .url_history("member-0", "http://probe.invalid/"),
            history
        );
        assert!(!local_failure(&io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid TLS record"
        )));
        service.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn url_test_unchecked_groups_use_catalog_order_for_admission_ties() {
        let mut service = crate::control::runtime::ControlService::new(Default::default()).unwrap();
        let resolver = Arc::new(ScheduledAnswers::default());
        let generation = scheduled_generation(
            &[("z-first", 16, 10, 1000), ("a-second", 16, 10, 1000)],
            resolver.clone(),
        );
        service.runtime.publish(generation).await.unwrap();
        service.runtime.resume().await.unwrap();
        advance_rounds(1).await;
        assert!(
            resolver
                .calls
                .lock()
                .iter()
                .all(|host| host.starts_with("z-first-"))
        );
        assert_eq!(resolver.calls.lock().len(), 16);
        service.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn url_test_buffered_timeouts_get_a_full_budget_on_a_later_round() {
        for (automatic, local_failures) in
            [(false, true), (true, true), (false, false), (true, false)]
        {
            let mut service =
                crate::control::runtime::ControlService::new(Default::default()).unwrap();
            let resolver = Arc::new(ScheduledAnswers {
                delays: (0..16)
                    .map(|index| (format!("auto-{index}.invalid"), Duration::ZERO))
                    .collect(),
                local_failures: if local_failures {
                    (0..16)
                        .map(|index| format!("auto-{index}.invalid"))
                        .collect()
                } else {
                    Default::default()
                },
                ..Default::default()
            });
            let generation = scheduled_generation(&[("auto", 17, 10, 1000)], resolver);
            let automatic_groups = &generation.catalog.selection.automatic;
            automatic_groups.record("auto-16", "http://probe.invalid/", Some(5));
            generation
                .probes
                .record("auto-16", "http://probe.invalid/", 5, true);
            tokio::time::advance(Duration::from_millis(1)).await;
            service.runtime.publish(generation.clone()).await.unwrap();
            if automatic {
                service.runtime.resume().await.unwrap();
                advance_rounds(12).await;
            } else {
                service
                    .runtime
                    .activating
                    .store(false, std::sync::atomic::Ordering::Release);
                for _ in 0..2 {
                    assert!(
                        probe_group(
                            &service.runtime,
                            &generation,
                            &automatic_groups.0["auto"].members,
                            &query()
                        )
                        .await
                        .is_err()
                    );
                }
            }
            assert_eq!(
                automatic_groups.0["auto"].health("auto-16"),
                "dead",
                "automatic={automatic}, local_failures={local_failures}"
            );
            if local_failures {
                assert_eq!(automatic_groups.0["auto"].health("auto-0"), "unprobed");
                assert!(
                    generation
                        .probes
                        .url_history("auto-0", "http://probe.invalid/")
                        .as_array()
                        .unwrap()
                        .is_empty()
                );
            }
            assert_eq!(
                generation
                    .probes
                    .url_history("auto-16", "http://probe.invalid/")
                    .as_array()
                    .unwrap()
                    .last()
                    .unwrap()["delay"],
                0
            );
            service.shutdown().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn url_test_canceled_api_group_cannot_adopt_a_resumed_epoch() {
        let mut service = crate::control::runtime::ControlService::new(Default::default()).unwrap();
        let resolver = Arc::new(PendingAnswers::default());
        let generation = Arc::new(generation(catalog(), resolver.clone()));
        service.runtime.publish(generation.clone()).await.unwrap();
        service.runtime.resume().await.unwrap();
        let members = vec!["DIRECT".into()];
        let query = query();
        for _ in 0..32 {
            let occupied = service.runtime.probes.acquire_many(16).await.unwrap();
            let mut probes = Box::pin(probe_group(&service.runtime, &generation, &members, &query));
            assert!(futures::poll!(&mut probes).is_pending());
            service.runtime.begin_activation(&generation).await.unwrap();
            service.runtime.resume().await.unwrap();
            drop(occupied);
            let _ = futures::poll!(&mut probes);
            assert_eq!(resolver.0.load(std::sync::atomic::Ordering::Relaxed), 0);
            assert!(generation.probes.history.lock().is_empty());
        }
        service.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn url_test_canceled_round_cannot_finish_or_advance_admission() {
        let mut service = crate::control::runtime::ControlService::new(Default::default()).unwrap();
        let generation = automatic_generation(1, 16, Arc::new(PendingAnswers::default()));
        publish_for_api_probes(&service.runtime, &generation).await;
        let group = &generation.catalog.selection.automatic.0["auto"];
        let now = tokio::time::Instant::now();
        let members = group.due_members(now).unwrap();
        let occupied = service.runtime.probes.acquire_many(16).await.unwrap();
        let epoch = service.runtime.probe_epoch();
        let mut round = Box::pin(run_automatic_round(
            AutomaticRound {
                group,
                completed: false,
            },
            &service.runtime,
            &generation,
            members,
            now,
            &epoch,
        ));
        assert!(futures::poll!(&mut round).is_pending());
        service.runtime.begin_activation(&generation).await.unwrap();
        drop(occupied);
        round.await;
        assert!(group.last_unqueued_admission().is_none());
        assert!(group.due_members(tokio::time::Instant::now()).is_some());
        service.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn url_test_late_admission_timeout_does_not_overwrite_health() {
        for automatic in [false, true] {
            let mut service =
                crate::control::runtime::ControlService::new(Default::default()).unwrap();
            let resolver = Arc::new(ScheduledAnswers {
                delays: (0..16)
                    .map(|index| (format!("auto-{index}.invalid"), Duration::from_millis(900)))
                    .collect(),
                ..Default::default()
            });
            let generation = scheduled_generation(&[("auto", 17, 10, 1000)], resolver.clone());
            generation.catalog.selection.automatic.record(
                "auto-16",
                "http://probe.invalid/",
                Some(5),
            );
            service.runtime.publish(generation.clone()).await.unwrap();
            if automatic {
                service.runtime.resume().await.unwrap();
                advance_rounds(2).await;
            } else {
                service
                    .runtime
                    .activating
                    .store(false, std::sync::atomic::Ordering::Release);
                let query = query();
                let members = &generation.catalog.selection.automatic.0["auto"].members;
                assert!(
                    probe_group(&service.runtime, &generation, members, &query)
                        .await
                        .is_err()
                );
            }
            assert!(
                resolver
                    .calls
                    .lock()
                    .iter()
                    .any(|host| host == "auto-16.invalid")
            );
            assert_eq!(
                generation.catalog.selection.automatic.0["auto"].health("auto-16"),
                "healthy"
            );
            assert!(!generation.probes.history.lock().contains_key("auto-16"));
            service.shutdown().await;
        }
    }

    #[test]
    fn url_test_quic_budget_rejection_preserves_health_in_a_fresh_process() {
        const CHILD: &str = "SHOES_URL_TEST_QUIC_BUDGET_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "clash_api::probes::tests::url_test_quic_budget_rejection_preserves_health_in_a_fresh_process", "--nocapture"])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            crate::resources::configure(crate::config::GlobalLimits {
                quic_memory_bytes: Some(1),
                ..Default::default()
            })
            .unwrap();
            let configs = serde_json::from_value(json!([
                {"client_group":"auto", "type":"url-test", "url":"http://probe.invalid/", "client_proxies":[
                    {"name":"quic", "address":"127.0.0.1:443", "transport":"quic", "quic_settings":{"verify":false}, "protocol":{"type":"socks"}}
                ]}
            ])).unwrap();
            let catalog = crate::config::create_server_configs(configs)
                .unwrap()
                .catalog
                .unwrap();
            let generation = Arc::new(generation(catalog, Arc::new(Answers(Vec::new()))));
            let mut service =
                crate::control::runtime::ControlService::new(Default::default()).unwrap();
            generation.catalog.selection.automatic.record(
                "quic", "http://probe.invalid/", Some(5),
            );
            publish_for_api_probes(&service.runtime, &generation).await;
            let error = probe(&service.runtime, &generation, "quic", &query())
                .await
                .unwrap_err();
            assert!(error.to_string().contains("QUIC memory budget exhausted"), "{error}");
            assert_eq!(
                generation.catalog.selection.automatic.0["auto"].health("quic"), "healthy"
            );
            assert!(generation.probes.history.lock().is_empty());
            assert!(!crate::control::url_test::remote_failure(&crate::resources::exhausted()));
            service.shutdown().await;
        });
    }

    #[tokio::test]
    async fn url_test_hyper_wrapped_errors_preserve_local_remote_classification() {
        probe_wrapped_errors(false).await;
    }

    #[tokio::test]
    async fn url_test_h2_wrapped_errors_preserve_local_remote_classification() {
        probe_wrapped_errors(true).await;
    }

    async fn probe_wrapped_errors(h2_proxy: bool) {
        use crate::{
            address::ResolvedLocation,
            async_stream::{AsyncMessageStream, AsyncPing, AsyncStream},
            client_proxy_chain::{ClientProxyChain, InitialHopEntry},
            tcp::socket_connector::SocketConnector,
        };
        use std::{
            pin::Pin,
            task::{Context, Poll},
        };

        type ErrorFactory = fn() -> io::Error;

        struct FailingStream {
            error: ErrorFactory,
            written: bool,
        }

        impl tokio::io::AsyncRead for FailingStream {
            fn poll_read(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                if self.written {
                    Poll::Ready(Err((self.error)()))
                } else {
                    Poll::Pending
                }
            }
        }

        impl tokio::io::AsyncWrite for FailingStream {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.written = true;
                cx.waker().wake_by_ref();
                Poll::Ready(Ok(bytes.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        impl AsyncPing for FailingStream {
            fn supports_ping(&self) -> bool {
                false
            }
            fn poll_write_ping(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<io::Result<bool>> {
                Poll::Ready(Ok(false))
            }
        }
        impl AsyncStream for FailingStream {}

        #[derive(Debug)]
        struct Socket(ErrorFactory);

        #[async_trait::async_trait]
        impl SocketConnector for Socket {
            async fn connect(
                &self,
                _: &Arc<dyn Resolver>,
                _: &ResolvedLocation,
            ) -> io::Result<Box<dyn AsyncStream>> {
                Ok(Box::new(FailingStream {
                    error: self.0,
                    written: false,
                }))
            }
            async fn connect_udp_bidirectional(
                &self,
                _: &Arc<dyn Resolver>,
                _: ResolvedLocation,
            ) -> io::Result<Box<dyn AsyncMessageStream>> {
                unreachable!()
            }
            fn bind_interface(&self) -> Option<&str> {
                None
            }
        }

        let cases: &[(ErrorFactory, bool)] = &[
            (|| io::ErrorKind::ConnectionReset.into(), false),
            (
                || io::Error::new(io::ErrorKind::InvalidInput, "remote protocol rejection"),
                false,
            ),
            (
                || {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "remote authentication rejection",
                    )
                },
                false,
            ),
            (|| io::ErrorKind::OutOfMemory.into(), true),
            #[cfg(unix)]
            (|| io::Error::from_raw_os_error(libc::EMFILE), true),
            (|| io::ErrorKind::Unsupported.into(), true),
            (|| io::Error::other(ProbePolicyDenied), true),
            (|| io::Error::other(crate::dns::SyntheticDnsAnswer), true),
            (crate::resources::exhausted, true),
        ];
        for &(make_error, local) in cases {
            let generation = automatic_generation(1, 1, Arc::new(Answers(Vec::new())));
            let socket = Arc::new(Socket(make_error));
            let entry = if h2_proxy {
                let config = serde_json::from_value(json!({
                    "address":"proxy.invalid:80", "protocol":{"type":"http", "http_version":"h2"}
                }))
                .unwrap();
                InitialHopEntry::Proxy {
                    socket,
                    proxy: Box::new(
                        crate::tcp::proxy_connector_impl::ProxyConnectorImpl::from_config(
                            config,
                            generation.probes.resolver.clone(),
                        )
                        .unwrap()
                        .unwrap(),
                    ),
                }
            } else {
                InitialHopEntry::Direct(socket)
            };
            let chain = ClientProxyChain::new(vec![entry], vec![]);
            generation.probes.connectors.lock().insert(
                "member-0".into(),
                Arc::new(ClientChainGroup::new(vec![chain])),
            );
            generation.catalog.selection.automatic.record(
                "member-0",
                "http://probe.invalid/",
                Some(5),
            );
            generation
                .probes
                .record("member-0", "http://probe.invalid/", 5, true);
            let history = generation
                .probes
                .url_history("member-0", "http://probe.invalid/");
            let mut service =
                crate::control::runtime::ControlService::new(Default::default()).unwrap();
            publish_for_api_probes(&service.runtime, &generation).await;
            let error = probe(&service.runtime, &generation, "member-0", &query())
                .await
                .unwrap_err();
            if h2_proxy {
                let recovered = error
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<crate::http2::transport::RecoveredError>()
                    .expect("H2 transport cause was not restored");
                assert!(recovered.error.is_io(), "{error:?}");
            } else {
                assert!(error.get_ref().unwrap().is::<hyper::Error>(), "{error:?}");
            }
            assert_eq!(
                generation.catalog.selection.automatic.0["auto"].health("member-0"),
                if local { "healthy" } else { "dead" },
                "{error:?}"
            );
            let recorded = generation
                .probes
                .url_history("member-0", "http://probe.invalid/");
            if local {
                assert_eq!(recorded, history);
            } else {
                assert_eq!(recorded.as_array().unwrap().len(), 2);
                assert_eq!(recorded[1]["delay"], 0);
            }
            service.shutdown().await;
        }
    }

    #[tokio::test]
    async fn url_test_xhttp_session_budget_rejection_preserves_health() {
        let configs = serde_json::from_value(json!([
            {"client_group":"auto", "type":"url-test", "url":"http://probe.invalid/", "client_proxies":[
                {"name":"xhttp", "address":"proxy.invalid:80", "protocol":{
                    "type":"xhttp", "limits":{"max_sessions":1}, "protocol":{"type":"socks"}
                }}
            ]}
        ])).unwrap();
        let catalog = crate::config::create_server_configs(configs)
            .unwrap()
            .catalog
            .unwrap();
        let generation = Arc::new(generation(catalog, Arc::new(ScheduledAnswers::default())));
        let mut service = crate::control::runtime::ControlService::new(Default::default()).unwrap();
        publish_for_api_probes(&service.runtime, &generation).await;
        let query = query();
        let mut occupied = Box::pin(request(&generation, "xhttp", &query));
        assert!(futures::poll!(&mut occupied).is_pending());
        generation
            .catalog
            .selection
            .automatic
            .record("xhttp", "http://probe.invalid/", Some(5));
        let error = probe(&service.runtime, &generation, "xhttp", &query)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "process resource budget exhausted");
        assert!(crate::resources::is_exhausted(&error));
        assert!(!crate::control::url_test::remote_failure(&error));
        assert_eq!(
            generation.catalog.selection.automatic.0["auto"].health("xhttp"),
            "healthy"
        );
        assert!(generation.probes.history.lock().is_empty());
        drop(occupied);
        service.shutdown().await;
    }

    #[derive(Debug, Default)]
    struct TrackedAnswers {
        started: Arc<std::sync::atomic::AtomicUsize>,
        active: Arc<std::sync::atomic::AtomicUsize>,
        changed: Arc<tokio::sync::Notify>,
    }

    impl TrackedAnswers {
        async fn wait(&self, started: usize, active: usize) {
            use std::sync::atomic::Ordering::Relaxed;
            tokio::time::timeout(Duration::from_secs(2), async {
                while self.started.load(Relaxed) != started || self.active.load(Relaxed) != active {
                    self.changed.notified().await;
                }
            })
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "expected started={started}, active={active}; got {}, {}",
                    self.started.load(Relaxed),
                    self.active.load(Relaxed)
                )
            });
        }
    }

    impl Resolver for TrackedAnswers {
        fn resolve_location(&self, _: &NetLocation) -> crate::resolver::ResolveFuture {
            let started = self.started.clone();
            let active = self.active.clone();
            let changed = self.changed.clone();
            Box::pin(async move {
                use std::sync::atomic::Ordering::Relaxed;
                struct Guard(
                    Arc<std::sync::atomic::AtomicUsize>,
                    Arc<tokio::sync::Notify>,
                );
                impl Drop for Guard {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, Relaxed);
                        self.1.notify_one();
                    }
                }
                active.fetch_add(1, Relaxed);
                let _guard = Guard(active, changed.clone());
                started.fetch_add(1, Relaxed);
                changed.notify_one();
                std::future::pending().await
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn url_test_automatic_deadline_bounds_concurrency_and_does_not_poison_queued_members() {
        let mut service = crate::control::runtime::ControlService::new(Default::default()).unwrap();
        let resolver = Arc::new(TrackedAnswers::default());
        let generation = automatic_generation(1, 32, resolver.clone());
        service.runtime.publish(generation.clone()).await.unwrap();
        service.runtime.resume().await.unwrap();
        resolver.wait(16, 16).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        resolver.wait(16, 0).await;
        assert_eq!(generation.probes.history.lock().len(), 16);
        let group = &generation.catalog.selection.automatic.0["auto"];
        assert_eq!(group.health("member-0"), "dead");
        assert_eq!(group.health("member-31"), "unprobed");
        assert_eq!(service.runtime.probes.available_permits(), 16);
        tokio::time::advance(Duration::from_secs(9)).await;
        resolver.wait(32, 16).await;
        service.shutdown().await;
        resolver.wait(32, 0).await;
        assert_eq!(group.health("member-31"), "unprobed");
        assert_eq!(service.runtime.probes.available_permits(), 16);
    }

    #[tokio::test(start_paused = true)]
    async fn url_test_automatic_capacity_exhaustion_is_not_remote_failure() {
        let mut service = crate::control::runtime::ControlService::new(Default::default()).unwrap();
        let permits = service
            .runtime
            .probes
            .clone()
            .acquire_many_owned(16)
            .await
            .unwrap();
        let resolver = Arc::new(TrackedAnswers::default());
        let generation = automatic_generation(1, 32, resolver.clone());
        service.runtime.publish(generation.clone()).await.unwrap();
        service.runtime.resume().await.unwrap();
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(generation.probes.history.lock().is_empty());
        assert_eq!(
            generation.catalog.selection.automatic.0["auto"].health("member-0"),
            "unprobed"
        );
        assert_eq!(
            resolver.started.load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        drop(permits);
        service.shutdown().await;
    }

    #[tokio::test]
    async fn url_test_automatic_connector_errors_distinguish_local_and_remote_failures() {
        #[derive(Debug)]
        struct ErrorAnswers(io::ErrorKind);
        impl Resolver for ErrorAnswers {
            fn resolve_location(&self, _: &NetLocation) -> crate::resolver::ResolveFuture {
                let kind = self.0;
                Box::pin(async move { Err(io::Error::from(kind)) })
            }
        }
        for (kind, local) in [
            (io::ErrorKind::WouldBlock, true),
            (io::ErrorKind::Unsupported, true),
            (io::ErrorKind::OutOfMemory, true),
            (io::ErrorKind::PermissionDenied, false),
            (io::ErrorKind::InvalidInput, false),
        ] {
            let mut service =
                crate::control::runtime::ControlService::new(Default::default()).unwrap();
            let generation = automatic_generation(1, 1, Arc::new(ErrorAnswers(kind)));
            let automatic = &generation.catalog.selection.automatic;
            automatic.record("member-0", "http://probe.invalid/", Some(5));
            publish_for_api_probes(&service.runtime, &generation).await;
            assert_eq!(
                probe(&service.runtime, &generation, "member-0", &query())
                    .await
                    .unwrap_err()
                    .kind(),
                kind
            );
            assert_eq!(
                automatic.0["auto"].health("member-0"),
                if local { "healthy" } else { "dead" }
            );
            assert_eq!(generation.probes.history.lock().is_empty(), local);
            service.shutdown().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn url_test_automatic_generation_commit_removal_and_shutdown_cancel_every_probe() {
        let mut service = crate::control::runtime::ControlService::new(Default::default()).unwrap();
        let runtime = &service.runtime;
        let resolver = Arc::new(TrackedAnswers::default());
        let first = automatic_generation(1, 32, resolver.clone());
        let second = automatic_generation(2, 16, resolver.clone());
        runtime.publish(first.clone()).await.unwrap();
        runtime.resume().await.unwrap();
        resolver.wait(16, 16).await;
        assert_eq!(
            resolver.started.load(std::sync::atomic::Ordering::Relaxed),
            16
        );
        runtime.begin_activation(&second).await.unwrap();
        resolver.wait(16, 0).await;
        assert!(first.probes.history.lock().is_empty());
        runtime.publish(second.clone()).await.unwrap();
        assert_eq!(
            resolver.started.load(std::sync::atomic::Ordering::Relaxed),
            16
        );
        runtime.resume().await.unwrap();
        resolver.wait(32, 16).await;
        assert_eq!(
            probe(runtime, &first, "member-0", &query())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        assert!(first.probes.history.lock().is_empty());
        let old = Arc::downgrade(&first);
        drop(first);
        assert!(old.upgrade().is_none());

        let mut removed = crate::config::create_server_configs(Vec::new()).unwrap();
        assert!(removed.catalog.is_none());
        runtime.prepare(&mut removed).await.unwrap();
        let mut removed = generation(removed.catalog.unwrap(), resolver.clone());
        removed.id = 3;
        let removed = Arc::new(removed);
        runtime.begin_activation(&removed).await.unwrap();
        resolver.wait(32, 0).await;
        runtime.publish(removed).await.unwrap();
        runtime.resume().await.unwrap();
        let old = Arc::downgrade(&second);
        drop(second);
        assert!(old.upgrade().is_none());
        tokio::time::advance(Duration::from_secs(30)).await;
        assert_eq!(
            resolver.started.load(std::sync::atomic::Ordering::Relaxed),
            32
        );
        service.shutdown().await;
        assert_eq!(service.runtime.probes.available_permits(), 16);
    }

    #[tokio::test(start_paused = true)]
    async fn url_test_automatic_resume_after_abandoned_activation_uses_committed_generation() {
        let mut service = crate::control::runtime::ControlService::new(Default::default()).unwrap();
        let resolver = Arc::new(TrackedAnswers::default());
        let first = automatic_generation(1, 16, resolver.clone());
        let candidate = automatic_generation(2, 16, resolver.clone());
        service.runtime.publish(first.clone()).await.unwrap();
        service.runtime.resume().await.unwrap();
        resolver.wait(16, 16).await;
        service.runtime.begin_activation(&candidate).await.unwrap();
        resolver.wait(16, 0).await;
        service.runtime.resume().await.unwrap();
        resolver.wait(32, 16).await;
        assert_eq!(service.runtime.generation().unwrap().id, 1);
        assert!(candidate.probes.history.lock().is_empty());
        service.shutdown().await;
        resolver.wait(32, 0).await;
        assert!(first.probes.history.lock().is_empty());
    }

    #[tokio::test]
    async fn url_test_automatic_real_proxy_probes_select_fast_sticky_recovered_member_without_listener()
     {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
        async fn peer() -> (
            String,
            Arc<AtomicU64>,
            Arc<AtomicBool>,
            tokio_util::task::AbortOnDropHandle<()>,
        ) {
            let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
            let address = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
            let delay = Arc::new(AtomicU64::new(1));
            let fail = Arc::new(AtomicBool::new(false));
            let peer_delay = delay.clone();
            let peer_fail = fail.clone();
            let task = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") {
                        header.push(stream.read_u8().await.unwrap());
                    }
                    assert!(header.starts_with(b"CONNECT probe.invalid:80 HTTP/1.1\r\n"));
                    if peer_fail.load(Relaxed) {
                        continue;
                    }
                    stream
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await
                        .unwrap();
                    header.clear();
                    while !header.ends_with(b"\r\n\r\n") {
                        header.push(stream.read_u8().await.unwrap());
                    }
                    assert!(header.starts_with(b"HEAD /"));
                    tokio::time::sleep(Duration::from_millis(peer_delay.load(Relaxed))).await;
                    stream
                        .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                        .await
                        .unwrap();
                }
            }));
            (address, delay, fail, task)
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            let (a, a_delay, _, _a_task) = peer().await;
            let (b, b_delay, b_fail, _b_task) = peer().await;
            let configs = serde_json::from_value(json!([
                {
                    "client_group": "auto",
                    "type": "url-test",
                    "url": "http://probe.invalid/",
                    "tolerance": 100,
                    "client_proxies": [
                        {"name": "a", "address": a, "protocol": {"type": "http"}},
                        {"name": "b", "address": b, "protocol": {"type": "http"}}
                    ]
                }
            ]))
            .unwrap();
            let validated = crate::config::create_server_configs(configs).unwrap();
            let mut service =
                crate::control::runtime::ControlService::new(Default::default()).unwrap();
            let generation = Arc::new(generation(
                validated.catalog.unwrap(),
                Arc::new(Answers(Vec::new())),
            ));
            publish_for_api_probes(&service.runtime, &generation).await;
            let members = vec!["a".into(), "b".into()];
            let query = query();
            let selected_member =
                || super::super::dto::proxies(&generation)["proxies"]["auto"]["now"].clone();

            a_delay.store(250, Relaxed);
            probe_group(&service.runtime, &generation, &members, &query)
                .await
                .unwrap();
            assert_eq!(selected_member(), "b");

            a_delay.store(1, Relaxed);
            b_delay.store(30, Relaxed);
            probe_group(&service.runtime, &generation, &members, &query)
                .await
                .unwrap();
            assert_eq!(selected_member(), "b");

            b_fail.store(true, Relaxed);
            probe_group(&service.runtime, &generation, &members, &query)
                .await
                .unwrap();
            assert_eq!(selected_member(), "a");

            b_fail.store(false, Relaxed);
            b_delay.store(1, Relaxed);
            a_delay.store(250, Relaxed);
            probe_group(&service.runtime, &generation, &members, &query)
                .await
                .unwrap();
            assert_eq!(selected_member(), "b");

            let mut other = query;
            other.url.set_path("/different");
            a_delay.store(1, Relaxed);
            b_delay.store(250, Relaxed);
            probe_group(&service.runtime, &generation, &members, &other)
                .await
                .unwrap();
            assert_eq!(selected_member(), "b");
            let dto = &super::super::dto::proxies(&generation)["proxies"]["auto"];
            assert_eq!(dto["type"], "URLTest");
            assert_eq!(dto["health"], "healthy");
            assert_eq!(dto["alive"], true);
            assert_eq!(dto["udpNow"], Value::Null);

            let group = &generation.catalog.selection.automatic.0["auto"];
            let initial = tokio::time::Instant::now();
            assert!(group.due_members(initial).is_some());
            probe(&service.runtime, &generation, "auto", &other)
                .await
                .unwrap();
            assert!(
                group
                    .due_members(initial + Duration::from_secs(300))
                    .is_none()
            );
            request(&generation, "auto", &other).await.unwrap();
            assert!(
                group
                    .due_members(initial + Duration::from_secs(300))
                    .is_some()
            );
            assert!(
                service
                    .runtime
                    .select(1, "auto".into(), "a".into())
                    .await
                    .is_err()
            );
            service.shutdown().await;
        })
        .await
        .unwrap();
    }

    #[test]
    fn query_validation_preserves_url_timeout_and_status_boundaries() {
        let valid = HashMap::from([
            ("url".into(), "https://probe.invalid/".into()),
            ("timeout".into(), "1000".into()),
        ]);
        for missing in ["url", "timeout"] {
            let mut query = valid.clone();
            query.remove(missing);
            assert_eq!(
                ProbeQuery::parse(&query, false).err().unwrap().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        let prefix = "https://probe.invalid/";
        let longest = format!("{prefix}{}", "x".repeat(2048 - prefix.len()));
        for (url, accepted) in [
            ("http://probe.invalid/", true),
            ("https://[2001:db8::1]:8443/path?x=1", true),
            (longest.as_str(), true),
            (&format!("{longest}x"), false),
            ("not a URL", false),
            ("ftp://probe.invalid/", false),
            ("https://user@probe.invalid/", false),
            ("https://:password@probe.invalid/", false),
            ("https://probe.invalid/#fragment", false),
            ("https://", false),
        ] {
            let mut query = valid.clone();
            query.insert("url".into(), url.into());
            assert_eq!(ProbeQuery::parse(&query, false).is_ok(), accepted, "{url}");
        }
        for (timeout, single, group) in [
            ("0", false, false),
            ("1", true, true),
            ("32767", true, true),
            ("32768", false, true),
            ("60000", false, true),
            ("60001", false, false),
            ("-1", false, false),
            ("invalid", false, false),
        ] {
            let mut query = valid.clone();
            query.insert("timeout".into(), timeout.into());
            for (is_group, accepted) in [(false, single), (true, group)] {
                assert_eq!(
                    ProbeQuery::parse(&query, is_group).is_ok(),
                    accepted,
                    "timeout={timeout}, group={is_group}"
                );
            }
        }
        for (expected, ranges) in [
            ("", vec![]),
            (" * ", vec![]),
            ("200/204", vec![(200, 200), (204, 204)]),
            (" 200-299 , 304 ", vec![(200, 299), (304, 304)]),
        ] {
            let mut query = valid.clone();
            query.insert("expected".into(), expected.into());
            let parsed = ProbeQuery::parse(&query, false).unwrap();
            assert_eq!(parsed.expected, ranges, "{expected}");
            assert_eq!(parsed.timeout, Duration::from_secs(1));
        }
        for expected in ["204-200", "invalid", "200-", "65536"] {
            let mut query = valid.clone();
            query.insert("expected".into(), expected.into());
            assert_eq!(
                ProbeQuery::parse(&query, false).err().unwrap().kind(),
                io::ErrorKind::InvalidInput,
                "{expected}"
            );
        }
    }

    #[test]
    fn full_budget_order_is_url_scoped_bounded_and_independent_of_health() {
        let state = ProbeState::new(Arc::new(Answers(Vec::new())), Vec::new());
        let automatic = Default::default();
        let members = vec!["a".into(), "b".into()];
        let mut indices = vec![0, 1];
        let mut probe = query();
        probe.url = url::Url::parse("https://probe.invalid/0").unwrap();
        state.record_full_budget_attempt("a", &probe, &automatic);
        state.order_members(&mut indices, &members, &probe);
        assert_eq!(indices, [1, 0]);
        indices = vec![0, 1];
        probe.expected = vec![(204, 204)];
        state.order_members(&mut indices, &members, &probe);
        assert_eq!(indices, [0, 1]);
        state.record_full_budget_attempt("b", &probe, &automatic);
        indices = vec![1, 0];
        state.order_members(&mut indices, &members, &probe);
        assert_eq!(indices, [0, 1]);
        for index in 1..=8 {
            probe.url = url::Url::parse(&format!("https://filtered.invalid/{index}")).unwrap();
            state.record_full_budget_attempt("a", &probe, &automatic);
        }
        probe.expected.clear();
        probe.url = url::Url::parse("https://probe.invalid/0").unwrap();
        indices = vec![0, 1];
        state.order_members(&mut indices, &members, &probe);
        assert_eq!(indices, [1, 0]);
        indices = vec![0, 1];
        probe.url = url::Url::parse("https://probe.invalid/1").unwrap();
        state.order_members(&mut indices, &members, &probe);
        assert_eq!(indices, [0, 1]);
        for index in 1..=8 {
            probe.url = url::Url::parse(&format!("https://probe.invalid/{index}")).unwrap();
            state.record_full_budget_attempt("a", &probe, &automatic);
        }
        let attempts = state.full_budget_attempts.lock();
        assert!(attempts["a"].configured.is_empty());
        assert_eq!(attempts["a"].unfiltered.len(), 8);
        assert_eq!(attempts["a"].filtered.len(), 8);
        assert!(
            !attempts["a"]
                .unfiltered
                .contains_key("https://probe.invalid/0")
        );
        assert!(state.history.lock().is_empty());
    }

    #[test]
    fn configured_attempt_urls_survive_filtered_and_unfiltered_api_eviction() {
        let state = ProbeState::new(Arc::new(Answers(Vec::new())), Vec::new());
        let mut automatic = crate::control::url_test::AutomaticGroups::default();
        let mut probe = query();
        for index in 0..12 {
            probe.url = url::Url::parse(&format!("http://probe.invalid/{index}")).unwrap();
            automatic
                .insert(
                    format!("group-{index}"),
                    crate::config::UrlTestConfig {
                        url: probe.url.to_string(),
                        interval: 10,
                        timeout: 1000,
                        tolerance: 50,
                        lazy: false,
                    },
                    vec!["a".into(), "b".into()],
                )
                .unwrap();
            state.record_full_budget_attempt("a", &probe, &automatic);
        }
        for index in 0..12 {
            probe.url = url::Url::parse(&format!("http://other.invalid/{index}")).unwrap();
            probe.expected.clear();
            state.record_full_budget_attempt("a", &probe, &automatic);
            probe.url = url::Url::parse(&format!("http://probe.invalid/{index}")).unwrap();
            probe.expected = vec![(204, 204)];
            state.record_full_budget_attempt("a", &probe, &automatic);
        }
        probe.expected.clear();
        for index in 0..12 {
            probe.url = url::Url::parse(&format!("http://probe.invalid/{index}")).unwrap();
            let mut indices = [0, 1];
            state.order_members(&mut indices, &["a".into(), "b".into()], &probe);
            assert_eq!(indices, [1, 0]);
        }
        let attempts = state.full_budget_attempts.lock();
        assert_eq!(attempts["a"].configured.len(), 12);
        assert_eq!(attempts["a"].unfiltered.len(), 8);
        assert_eq!(attempts["a"].filtered.len(), 8);
    }

    #[test]
    fn history_bounds_samples_and_urls_without_conflating_reachability_with_status() {
        let state = ProbeState::new(Arc::new(Answers(Vec::new())), Vec::new());
        let mut value = json!({});
        state.decorate("proxy", &mut value);
        assert_eq!(value, json!({"alive":true, "history":[]}));
        for delay in 1..=12 {
            state.record("proxy", "https://probe.invalid/0", delay, true);
        }
        state.decorate("proxy", &mut value);
        let delays = |samples: &Value| {
            samples
                .as_array()
                .unwrap()
                .iter()
                .map(|sample| sample["delay"].as_u64().unwrap())
                .collect::<Vec<_>>()
        };
        assert_eq!(delays(&value["history"]), (3..=12).collect::<Vec<_>>());
        assert_eq!(
            value["extra"]["https://probe.invalid/0"]["history"],
            value["history"]
        );
        for index in 1..8 {
            state.record("proxy", &format!("https://probe.invalid/{index}"), 20, true);
        }
        state.record("proxy", "https://probe.invalid/0", 30, false);
        state.record("proxy", "https://probe.invalid/8", 40, true);
        state.decorate("proxy", &mut value);
        let extra = value["extra"].as_object().unwrap();
        assert_eq!(
            extra.keys().cloned().collect::<Vec<_>>(),
            [2, 3, 4, 5, 6, 7, 0, 8].map(|index| format!("https://probe.invalid/{index}"))
        );
        assert_eq!(
            delays(&extra["https://probe.invalid/0"]["history"]),
            (4..=12).chain([0]).collect::<Vec<_>>()
        );
        assert_eq!(extra["https://probe.invalid/0"]["alive"], false);
        state.record("proxy", "https://probe.invalid/8", 50, false);
        state.decorate("proxy", &mut value);
        assert_eq!(value["alive"], true);
        assert_eq!(value["history"].as_array().unwrap().len(), 10);
        assert_eq!(
            value["history"].as_array().unwrap().last().unwrap()["delay"],
            50
        );
        assert_eq!(value["extra"]["https://probe.invalid/8"]["alive"], false);
        assert_eq!(
            value["extra"]["https://probe.invalid/8"]["history"]
                .as_array()
                .unwrap()
                .last()
                .unwrap()["delay"],
            0
        );
        state.record("proxy", "https://probe.invalid/8", 0, false);
        state.decorate("proxy", &mut value);
        assert_eq!(value["alive"], false);
        let mut untouched = json!({});
        state.decorate("other", &mut untouched);
        assert_eq!(untouched, json!({"alive":true, "history":[]}));
    }

    #[test]
    fn destination_policy_preserves_ipv4_and_ipv6_boundaries() {
        for (address, denied) in [
            ("127.0.0.1", true),
            ("0.0.0.0", true),
            ("169.254.1.1", true),
            ("224.0.0.1", true),
            ("255.255.255.255", true),
            ("198.17.255.255", false),
            ("198.18.0.0", true),
            ("198.19.255.255", true),
            ("198.20.0.0", false),
            ("192.0.2.1", false),
            ("10.0.0.1", false),
            ("::", true),
            ("::1", true),
            ("fe80::1", true),
            ("ff02::1", true),
            ("2001:db8::1", false),
            ("fc00::1", false),
            ("::127.0.0.1", false),
            ("::ffff:127.0.0.1", true),
            ("::ffff:198.18.0.1", true),
            ("::ffff:192.0.2.1", false),
        ] {
            assert_eq!(forbidden(address.parse().unwrap()), denied, "{address}");
        }
    }

    #[derive(Debug)]
    struct Answers(Vec<SocketAddr>);
    impl Resolver for Answers {
        fn resolve_location(&self, _: &NetLocation) -> crate::resolver::ResolveFuture {
            let addresses = self.0.clone();
            Box::pin(async move { Ok(addresses) })
        }
    }

    fn generation(catalog: Catalog, resolver: Arc<dyn Resolver>) -> Generation {
        Generation {
            id: 1,
            catalog,
            rules: Vec::new(),
            probes: ProbeState::new(resolver, Vec::new()),
            leaf_udp_support: HashMap::new(),
        }
    }

    fn catalog() -> Catalog {
        Catalog {
            nodes: IndexMap::from([("DIRECT".into(), CatalogNode::Leaf(Box::default()))]),
            selection: Default::default(),
        }
    }

    fn query() -> ProbeQuery {
        ProbeQuery::parse(
            &HashMap::from([
                ("url".into(), "http://probe.invalid/".into()),
                ("timeout".into(), "1000".into()),
            ]),
            false,
        )
        .unwrap()
    }

    #[derive(Debug, Default)]
    struct PendingAnswers(std::sync::atomic::AtomicUsize);

    impl Resolver for PendingAnswers {
        fn resolve_location(&self, _: &NetLocation) -> crate::resolver::ResolveFuture {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn group_deadline_includes_members_waiting_for_capacity() {
        let service = crate::control::runtime::ControlService::new(Default::default()).unwrap();
        service
            .runtime
            .activating
            .store(false, std::sync::atomic::Ordering::Release);
        let resolver = Arc::new(PendingAnswers::default());
        let mut catalog = catalog();
        let members: Vec<_> = (0..32).map(|index| format!("direct-{index}")).collect();
        for name in &members {
            catalog
                .nodes
                .insert(name.clone(), CatalogNode::Leaf(Box::default()));
        }
        let generation = Arc::new(generation(catalog, resolver.clone()));
        service.runtime.publish(generation.clone()).await.unwrap();
        let start = tokio::time::Instant::now();
        let error = probe_group(&service.runtime, &generation, &members, &query())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(start.elapsed(), Duration::from_secs(1));
        assert_eq!(resolver.0.load(std::sync::atomic::Ordering::Relaxed), 16);
        assert_eq!(generation.probes.history.lock().len(), 16);
        assert_eq!(service.runtime.probes.available_permits(), 16);
    }

    #[tokio::test(start_paused = true)]
    async fn group_capacity_exhaustion_does_not_record_probe_failures() {
        let service = crate::control::runtime::ControlService::new(Default::default()).unwrap();
        service
            .runtime
            .activating
            .store(false, std::sync::atomic::Ordering::Release);
        let resolver = Arc::new(PendingAnswers::default());
        let generation = Arc::new(generation(catalog(), resolver.clone()));
        service.runtime.publish(generation.clone()).await.unwrap();
        let members = vec!["DIRECT".into(), "DIRECT".into()];
        let permits = service.runtime.probes.acquire_many(16).await.unwrap();
        let start = tokio::time::Instant::now();
        let error = probe_group(&service.runtime, &generation, &members, &query())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(start.elapsed(), Duration::from_secs(1));
        assert_eq!(resolver.0.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert!(generation.probes.history.lock().is_empty());
        drop(permits);
        service
            .runtime
            .activating
            .store(true, std::sync::atomic::Ordering::Release);
        let start = tokio::time::Instant::now();
        assert_eq!(
            probe_group(&service.runtime, &generation, &members, &query())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert!(generation.probes.history.lock().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn inactive_wireguard_member_only_fails_when_selected() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
            let proxy = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
            let peer = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
            let config = json!([
                crate::wireguard::test_support::client(peer.local_addr().unwrap().port()),
                {"client_group":"outbound","type":"selector","default":"http","client_proxies":[
                    "wg", {"name":"http","address":proxy,"protocol":{"type":"http"}}
                ]},
                {"address":"127.0.0.1:0","protocol":{"type":"socks"},"rules":"allow-all-direct"}
            ]);
            let mut validated =
                crate::config::create_server_configs(serde_json::from_value(config).unwrap())
                    .unwrap();
            assert!(validated.wireguard_endpoints.is_empty());
            let _prepared = crate::wireguard::Prepared::new(&mut validated)
                .await
                .unwrap();
            assert!(validated.wireguard_endpoints.is_empty());
            let generation = generation(
                validated.catalog.take().unwrap(),
                Arc::new(Answers(Vec::new())),
            );
            let mut owner = crate::control::selection::SelectionOwner::new(None).unwrap();
            owner
                .activate(generation.catalog.selection.clone())
                .unwrap();
            let server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                for _ in 0..2 {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") {
                        header.push(stream.read_u8().await.unwrap());
                    }
                    assert!(header.starts_with(b"CONNECT probe.invalid:80 HTTP/1.1\r\n"));
                    stream
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await
                        .unwrap();
                    header.clear();
                    while !header.ends_with(b"\r\n\r\n") {
                        header.push(stream.read_u8().await.unwrap());
                    }
                    assert!(header.starts_with(b"HEAD / HTTP/1.1\r\n"));
                    stream
                        .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                        .await
                        .unwrap();
                }
            }));
            assert!(request(&generation, "outbound", &query()).await.unwrap().0 > 0);
            owner.select("outbound", "wg").unwrap();
            let error = request(&generation, "outbound", &query())
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::NotConnected);
            assert!(error.to_string().contains("not active"));
            owner.select("outbound", "http").unwrap();
            assert!(request(&generation, "outbound", &query()).await.unwrap().0 > 0);
            server.await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(20), peer.recv(&mut [0; 2048]))
                    .await
                    .is_err()
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn trusted_https_probe_sends_head_and_checks_status_without_following_redirects() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
            let certificate =
                rcgen::generate_simple_self_signed(vec!["probe.invalid".into()]).unwrap();
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let mut roots = rustls::RootCertStore::empty();
            roots.add(certificate.cert.der().clone()).unwrap();
            let tls = rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let config = rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![certificate.cert.der().clone()],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(
                        certificate.signing_key.serialize_der(),
                    )
                    .into(),
                )
                .unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            let cases = [
                (204, "*", true),
                (204, "200", false),
                (204, "200-299", true),
                (302, "300-399", true),
            ];
            let server = async {
                for (status, _, _) in cases {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") {
                        header.push(stream.read_u8().await.unwrap());
                        assert!(header.len() < 4096);
                    }
                    assert!(header.starts_with(b"CONNECT probe.invalid:8443 HTTP/1.1\r\n"));
                    stream
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await
                        .unwrap();
                    let mut stream = acceptor.accept(stream).await.unwrap();
                    assert_eq!(stream.get_ref().1.server_name(), Some("probe.invalid"));
                    header.clear();
                    while !header.ends_with(b"\r\n\r\n") {
                        header.push(stream.read_u8().await.unwrap());
                        assert!(header.len() < 4096);
                    }
                    let mut headers = [httparse::EMPTY_HEADER; 16];
                    let mut request = httparse::Request::new(&mut headers);
                    assert!(request.parse(&header).unwrap().is_complete());
                    assert_eq!(request.method, Some("HEAD"));
                    assert_eq!(request.path, Some("/generate_204?x=1"));
                    assert_eq!(request.version, Some(1));
                    for (name, value) in [
                        ("host", b"probe.invalid:8443".as_slice()),
                        ("connection", b"close".as_slice()),
                    ] {
                        assert_eq!(
                            request
                                .headers
                                .iter()
                                .find(|header| header.name.eq_ignore_ascii_case(name))
                                .unwrap()
                                .value,
                            value
                        );
                    }
                    let response = format!(
                        "HTTP/1.1 {status} Test\r\n\
                        Location: https://redirect.invalid/\r\n\
                        Connection: close\r\nContent-Length: 0\r\n\r\n"
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                    stream.shutdown().await.unwrap();
                }
            };
            let mut catalog = catalog();
            catalog.nodes.insert(
                "http".into(),
                CatalogNode::Leaf(Box::new(
                    serde_json::from_value(json!({
                        "address":format!("127.0.0.1:{}", listener.local_addr().unwrap().port()),
                        "protocol":{"type":"http"}
                    }))
                    .unwrap(),
                )),
            );
            let generation = generation(catalog, Arc::new(Answers(Vec::new())));
            let client = async {
                for (_, expected, satisfied) in cases {
                    let query = ProbeQuery::parse(
                        &HashMap::from([
                            (
                                "url".into(),
                                "https://probe.invalid:8443/generate_204?x=1".into(),
                            ),
                            ("timeout".into(), "1000".into()),
                            ("expected".into(), expected.into()),
                        ]),
                        false,
                    )
                    .unwrap();
                    let (delay, actual) =
                        request_with_tls_config(&generation, "http", &query, || tls.clone())
                            .await
                            .unwrap();
                    assert!(delay > 0);
                    assert_eq!(actual, satisfied, "expected={expected}");
                }
            };
            tokio::join!(server, client);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn https_probe_rejects_untrusted_certificates_through_proxy() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
            let proxy = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
            let certificate =
                rcgen::generate_simple_self_signed(vec!["probe.invalid".into()]).unwrap();
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    certificate.signing_key.serialize_der(),
                )
                .into(),
            )
            .unwrap();
            let server = async {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    header.push(stream.read_u8().await.unwrap());
                }
                assert!(header.starts_with(b"CONNECT probe.invalid:443 HTTP/1.1\r\n"));
                stream
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .unwrap();
                let connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
                assert!(
                    crate::crypto::CryptoTlsStream::handshake(
                        stream,
                        crate::crypto::TlsConnection::new(connection),
                        crate::crypto::TlsReadMode::Stream,
                        &[],
                    )
                    .await
                    .is_err()
                );
            };
            let mut catalog = catalog();
            catalog.nodes.insert(
                "http".into(),
                CatalogNode::Leaf(Box::new(
                    serde_json::from_value(json!({
                        "address": proxy,
                        "protocol": {"type": "http"},
                    }))
                    .unwrap(),
                )),
            );
            let generation = generation(catalog, Arc::new(Answers(Vec::new())));
            let mut query = query();
            query.url = url::Url::parse("https://probe.invalid/").unwrap();
            let (result, ()) = tokio::join!(request(&generation, "http", &query), server);
            let error = result.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(
                error
                    .to_string()
                    .contains("InvalidCertificate(UnknownIssuer)"),
                "{error}"
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cached_connectors_reject_forbidden_hostname_candidates() {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let local = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
        let resolver: Arc<dyn Resolver> =
            Arc::new(Answers(vec!["192.0.2.1:80".parse().unwrap(), local]));
        let mut catalog = catalog();
        catalog.nodes.insert(
            "http".into(),
            CatalogNode::Leaf(Box::new(
                serde_json::from_value(json!({
                    "address":local.to_string(),
                    "protocol":{"type":"http","resolve_hostname":true},
                }))
                .unwrap(),
            )),
        );
        let generation = generation(catalog, resolver);
        for name in ["DIRECT", "http"] {
            let cached = generation
                .probes
                .connector(&generation.catalog, name)
                .unwrap();
            for _ in 0..2 {
                assert_eq!(
                    tokio::time::timeout(
                        Duration::from_secs(1),
                        request(&generation, name, &query())
                    )
                    .await
                    .unwrap()
                    .unwrap_err()
                    .kind(),
                    io::ErrorKind::PermissionDenied
                );
                assert!(Arc::ptr_eq(
                    &cached,
                    &generation
                        .probes
                        .connector(&generation.catalog, name)
                        .unwrap()
                ));
            }
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn carrier_probe_checks_http_hostname_before_connecting() {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let local = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
        let config = json!([
            {"client_group":"outbound","type":"selector","default":"http","client_proxies":[
                {"name":"http","address":local.to_string(),"protocol":{"type":"http","resolve_hostname":true}},
                {"name":"xhttp","address":local.to_string(),"protocol":{"type":"xhttp","protocol":{"type":"socks"}}}
            ]}
        ]);
        let mut validated =
            crate::config::create_server_configs(serde_json::from_value(config).unwrap()).unwrap();
        let generation = generation(
            validated.catalog.take().unwrap(),
            Arc::new(Answers(vec!["192.0.2.1:80".parse().unwrap(), local])),
        );
        let cached = generation
            .probes
            .connector(&generation.catalog, "outbound")
            .unwrap();
        for _ in 0..2 {
            assert_eq!(
                tokio::time::timeout(
                    Duration::from_secs(1),
                    request(&generation, "outbound", &query())
                )
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
                io::ErrorKind::PermissionDenied
            );
            assert!(Arc::ptr_eq(
                &cached,
                &generation
                    .probes
                    .connector(&generation.catalog, "outbound")
                    .unwrap()
            ));
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn cached_http2_reuse_checks_each_requests_resolver() {
        #[derive(Debug)]
        struct ChangingAnswers(Arc<Mutex<Vec<SocketAddr>>>);
        impl Resolver for ChangingAnswers {
            fn resolve_location(&self, _: &NetLocation) -> crate::resolver::ResolveFuture {
                let addresses = self.0.lock().clone();
                Box::pin(async move { Ok(addresses) })
            }
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
            let local = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
            let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let count = accepted.clone();
            let server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut connection = h2::server::handshake(stream).await.unwrap();
                let mut tasks = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        incoming = connection.accept() => {
                            let Some(Ok((request, mut respond))) = incoming else { break };
                            count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            assert_eq!(request.uri().authority().unwrap(), "192.0.2.1:80");
                            let send = respond.send_response(http::Response::new(()), false).unwrap();
                            tasks.spawn(async move {
                                let mut stream = crate::http2::stream::H2MultiStream::new(send, request.into_body());
                                let mut header = Vec::new();
                                while !header.ends_with(b"\r\n\r\n") { header.push(stream.read_u8().await.unwrap()); }
                                assert!(header.starts_with(b"HEAD / HTTP/1.1\r\n"));
                                stream.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await.unwrap();
                                stream.shutdown().await.unwrap();
                            });
                        }
                        _ = tasks.join_next(), if !tasks.is_empty() => {}
                    }
                }
            }));
            let answers = Arc::new(Mutex::new(vec!["192.0.2.1:80".parse().unwrap()]));
            let mut catalog = catalog();
            // Cleartext transport isolates HTTP/2 reuse from the TLS handshake in this fixture.
            catalog.nodes.insert("http".into(), CatalogNode::Leaf(Box::new(serde_json::from_value(json!({
                "address":local.to_string(),
                "protocol":{"type":"http","resolve_hostname":true,"http_version":"h2"},
            })).unwrap())));
            let generation = generation(catalog, Arc::new(ChangingAnswers(answers.clone())));
            for _ in 0..2 { assert!(request(&generation, "http", &query()).await.unwrap().0 > 0); }
            assert_eq!(accepted.load(std::sync::atomic::Ordering::Relaxed), 2);
            answers.lock().push("127.0.0.1:80".parse().unwrap());
            assert_eq!(request(&generation, "http", &query()).await.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(accepted.load(std::sync::atomic::Ordering::Relaxed), 2);
            server.abort();
        }).await.unwrap();
    }

    #[tokio::test]
    async fn guarded_direct_resolution_keeps_fallback_candidates() {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let live = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
        let closed = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let refused = SocketAddr::from(([127, 0, 0, 1], closed.local_addr().unwrap().port()));
        drop(closed);
        let target = NetLocation::from_str("probe.invalid:80", None).unwrap();
        let base: Arc<dyn Resolver> = Arc::new(Answers(vec![refused, live]));
        let resolver: Arc<dyn Resolver> = Arc::new(ProbeResolver {
            inner: base.clone(),
            target: target.clone(),
            forbidden_ranges: Vec::new(),
            denied: |_| false,
        });
        let chain = crate::tcp::chain_builder::try_build_client_proxy_chain(
            OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                ClientConfig::default(),
            ))),
            base,
        )
        .unwrap();
        let mut setup = tokio::time::timeout(
            Duration::from_secs(2),
            chain.connect_tcp(target.into(), &resolver),
        )
        .await
        .unwrap()
        .unwrap();
        let (mut accepted, _) = listener.accept().await.unwrap();
        setup.client_stream.write_all(b"ok").await.unwrap();
        let mut response = [0; 2];
        accepted.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ok");
    }

    #[tokio::test]
    async fn guarded_resolution_rejects_any_forbidden_candidate() {
        let target = NetLocation::from_str("probe.invalid:80", None).unwrap();
        let resolver = ProbeResolver {
            inner: Arc::new(Answers(vec![
                "192.0.2.1:80".parse().unwrap(),
                "127.0.0.1:80".parse().unwrap(),
            ])),
            target: target.clone(),
            forbidden_ranges: Vec::new(),
            denied: forbidden,
        };
        assert_eq!(
            resolver.resolve_location(&target).await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
