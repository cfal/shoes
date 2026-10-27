//! Shared bounded HTTP probes; controller history is independent of fallback health.
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

pub(crate) const PROBE_CONCURRENCY: usize = 16;

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
    pub(crate) fn forbidden_ranges(&self) -> Vec<ipnetwork::IpNetwork> {
        self.forbidden.clone()
    }

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
    pub(crate) timeout: Duration,
    expected: Vec<(u16, u16)>,
}

impl ProbeQuery {
    pub(crate) fn validate_automatic_target(&self, label: &str) -> io::Result<()> {
        let denied = match self.url.host() {
            Some(url::Host::Ipv4(ip)) => forbidden(ip.into()),
            Some(url::Host::Ipv6(ip)) => forbidden(ip.into()),
            _ => false,
        };
        if denied {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{label} is denied by probe destination policy"),
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
        if error.is::<ProbePolicyDenied>()
            || error.is::<crate::dns::SyntheticDnsAnswer>()
            || error.is::<super::health::HealthCapacity>()
        {
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
    let resolver = ProbeResolver::for_query(
        generation.probes.resolver.clone(),
        &generation.probes.forbidden,
        query,
    )?;
    let chain = generation.probes.connector(&generation.catalog, name)?;
    request_with_resolver(&chain, resolver, query, tls_config).await
}

pub(crate) async fn request_via(
    chain: &ClientChainGroup,
    resolver: Arc<dyn Resolver>,
    forbidden_ranges: &[ipnetwork::IpNetwork],
    query: &ProbeQuery,
    tls_config: impl FnOnce() -> rustls::ClientConfig,
) -> io::Result<(u16, bool)> {
    let resolver = ProbeResolver::for_query(resolver, forbidden_ranges, query)?;
    request_with_resolver(chain, resolver, query, tls_config).await
}

async fn request_with_resolver(
    chain: &ClientChainGroup,
    resolver: ProbeResolver,
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
    let target = resolver.target.clone();
    let resolver: Arc<dyn Resolver> = Arc::new(resolver);
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
    let path = &query.url[url::Position::BeforePath..url::Position::AfterQuery];
    let authority = &query.url[url::Position::BeforeHost..url::Position::AfterPort];
    let request = hyper::Request::builder()
        .method("HEAD")
        .uri(if path.is_empty() { "/" } else { path })
        .header("Host", authority)
        .header("Connection", "close")
        .body(Empty::<Bytes>::new())
        .map_err(io::Error::other)?;
    // Poll the transport inline so cancellation drops it before releasing admission.
    let response = sender.send_request(request);
    tokio::pin!(response);
    let response = tokio::select! {
        biased;
        response = &mut response => response,
        _ = connection => response.await,
    }
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
    fn for_query(
        inner: Arc<dyn Resolver>,
        forbidden_ranges: &[ipnetwork::IpNetwork],
        query: &ProbeQuery,
    ) -> io::Result<Self> {
        let host = query
            .url
            .host_str()
            .unwrap()
            .trim_start_matches('[')
            .trim_end_matches(']');
        let target = NetLocation::new(
            crate::address::Address::from(host)?,
            query.url.port_or_known_default().unwrap(),
        );
        let resolver = Self {
            inner,
            target,
            forbidden_ranges: forbidden_ranges.to_vec(),
            denied: forbidden,
        };
        if let Some(address) = resolver.target.to_socket_addr_nonblocking() {
            resolver.check(&[address])?;
        }
        Ok(resolver)
    }

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
mod tests;
