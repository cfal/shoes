use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::hash::Hash;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::future::FutureExt;
use log::debug;
use lru::LruCache;
use parking_lot::Mutex;
use tokio::sync::{Mutex as AsyncMutex, Semaphore, broadcast};

use crate::address::{Address, NetLocation, ResolvedLocation};

pub type ResolveFuture = Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>;
pub type DnsExchangeFuture = Pin<Box<dyn Future<Output = std::io::Result<Vec<u8>>> + Send>>;

fn dns_exchange_until(
    future: DnsExchangeFuture,
    deadline: tokio::time::Instant,
) -> DnsExchangeFuture {
    Box::pin(async move {
        tokio::time::timeout_at(deadline, future)
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS exchange timed out")
            })?
    })
}

#[derive(Debug)]
pub(crate) struct DnsSetupPending;

impl std::fmt::Display for DnsSetupPending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DNS exchange timed out with retained connection setup")
    }
}

impl std::error::Error for DnsSetupPending {}

pub(crate) fn dns_setup_pending(error: &std::io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|cause| cause.is::<DnsSetupPending>())
}

#[derive(Debug)]
pub(crate) struct DnsCallerDeadline;

impl std::fmt::Display for DnsCallerDeadline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DNS caller deadline exceeded")
    }
}

impl std::error::Error for DnsCallerDeadline {}

pub(crate) fn dns_caller_deadline(error: &std::io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|cause| cause.is::<DnsCallerDeadline>())
}

const CACHING_NATIVE_RESOLVER_CACHE_CAPACITY: usize = 10_000;
const CACHING_NATIVE_RESOLVER_MAX_PARTICIPANTS: usize = 1_024;
const RESOLVER_CACHE_CAPACITY: usize = 1_024;

/// Constructs a bounded LRU without eagerly reserving storage for every entry.
fn bounded_lru<K: Hash + Eq, V>(capacity: usize) -> LruCache<K, V> {
    let mut cache = LruCache::unbounded();
    cache.resize(NonZeroUsize::new(capacity).unwrap());
    cache
}

pub trait Resolver: Send + Sync + Debug {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture;

    /// Bounds a logical request, including transport attempts and lazy reconstruction.
    fn request_timeout(&self) -> Option<Duration> {
        None
    }

    /// Retires transport state without changing routes, DNS policy or fake-IP mappings.
    fn retire(&self) {}

    fn fake_dns_context(&self) -> Option<Arc<crate::dns::DnsContext>> {
        None
    }

    fn exchange(&self, _request: Vec<u8>) -> DnsExchangeFuture {
        Box::pin(async {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "resolver does not support DNS message exchange",
            ))
        })
    }

    /// Completes by the deadline; wrappers forward it so fallbacks can return a retained partial.
    fn exchange_with_deadline(
        &self,
        request: Vec<u8>,
        deadline: tokio::time::Instant,
    ) -> DnsExchangeFuture {
        dns_exchange_until(self.exchange(request), deadline)
    }
}

/// Resolver wrapper that enforces a timeout on DNS resolution.
/// Wraps any inner Resolver and fails with TimedOut if resolution takes too long.
pub struct TimeoutResolver<T> {
    inner: T,
    timeout: Duration,
}

impl<T: Resolver> TimeoutResolver<T> {
    #[allow(dead_code)]
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

    #[allow(dead_code)]
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            timeout: Self::DEFAULT_TIMEOUT,
        }
    }

    pub fn with_timeout(inner: T, timeout: Duration) -> Self {
        Self { inner, timeout }
    }
}

impl<T: Resolver> Debug for TimeoutResolver<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimeoutResolver")
            .field("inner", &self.inner)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl<T: Resolver> Resolver for TimeoutResolver<T> {
    fn fake_dns_context(&self) -> Option<Arc<crate::dns::DnsContext>> {
        self.inner.fake_dns_context()
    }

    fn exchange(&self, request: Vec<u8>) -> DnsExchangeFuture {
        let future = self.inner.exchange(request);
        let timeout = self.timeout;
        Box::pin(async move {
            tokio::time::timeout(timeout, future).await.map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS exchange timed out")
            })?
        })
    }

    fn exchange_with_deadline(
        &self,
        request: Vec<u8>,
        deadline: tokio::time::Instant,
    ) -> DnsExchangeFuture {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.timeout)
            .map_or(deadline, |configured| deadline.min(configured));
        self.inner.exchange_with_deadline(request, deadline)
    }

    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        // Fast path: if already an IP address, no resolution needed
        if location.to_socket_addr_nonblocking().is_some() {
            let loc = location.clone();
            return Box::pin(async move { Ok(vec![loc.to_socket_addr_nonblocking().unwrap()]) });
        }

        let inner_future = self.inner.resolve_location(location);
        let timeout_duration = self.timeout;
        let location_str = location.to_string();

        Box::pin(async move {
            match tokio::time::timeout(timeout_duration, inner_future).await {
                Ok(result) => result,
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "DNS resolution for {} timed out after {:?}",
                        location_str, timeout_duration
                    ),
                )),
            }
        })
    }
}

type ResolverFactoryFuture =
    Pin<Box<dyn Future<Output = std::io::Result<Arc<dyn Resolver>>> + Send>>;

pub type ResolverFactory = Arc<dyn Fn() -> ResolverFactoryFuture + Send + Sync>;

/// Policy controlling when a RefreshingResolver rebuilds its inner resolver.
#[derive(Debug, Clone, Copy)]
pub struct RefreshPolicy {
    /// Rebuild the inner resolver if it has been idle longer than this.
    pub max_idle: Duration,
}

/// Resolver wrapper that rebuilds its inner resolver on idle timeout or
/// connection-related errors. Targets stale pooled connection state in
/// hickory-backed resolvers.
#[derive(Clone)]
pub struct RefreshingResolver {
    factory: ResolverFactory,
    refresh_lock: Arc<AsyncMutex<()>>,
    refresh_state: Arc<Mutex<RefreshState>>,
    policy: RefreshPolicy,
    description: String,
}

struct RefreshState {
    current: Arc<dyn Resolver>,
    invalidated: bool,
    last_activity_at: Option<Instant>,
    generation: u64,
    recovering: bool,
    last_report_at: Option<Instant>,
}

impl Debug for RefreshingResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshingResolver")
            .field("description", &self.description)
            .field("max_idle", &self.policy.max_idle)
            .finish()
    }
}

impl RefreshingResolver {
    pub async fn new(
        factory: ResolverFactory,
        policy: RefreshPolicy,
        description: String,
    ) -> std::io::Result<Self> {
        let inner = factory().await?;
        Ok(Self {
            factory,
            refresh_lock: Arc::new(AsyncMutex::new(())),
            refresh_state: Arc::new(Mutex::new(RefreshState {
                current: inner,
                invalidated: false,
                last_activity_at: None,
                generation: 0,
                recovering: false,
                last_report_at: None,
            })),
            policy,
            description,
        })
    }

    pub(crate) fn should_refresh_for_error(err: &std::io::Error) -> bool {
        if crate::resources::is_exhausted(err) || dns_caller_deadline(err) {
            return false;
        }
        matches!(
            err.kind(),
            std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::NotConnected
        )
    }

    fn execute<T: Send + 'static>(
        &self,
        deadline: Option<tokio::time::Instant>,
        operation: impl FnOnce(
            Arc<dyn Resolver>,
            Option<tokio::time::Instant>,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<T>> + Send>>
        + Send
        + 'static,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<T>> + Send>> {
        let resolver = self.clone();

        Box::pin(async move {
            let configured_deadline = resolver
                .refresh_state
                .lock()
                .current
                .request_timeout()
                .and_then(|timeout| tokio::time::Instant::now().checked_add(timeout));
            let deadline = match (deadline, configured_deadline) {
                (Some(caller), Some(configured)) => Some(caller.min(configured)),
                (caller, configured) => caller.or(configured),
            };
            let current = resolver.current(deadline).await?;
            let result = operation(current.clone(), deadline).await;
            match &result {
                Ok(_) => resolver.record_success(&current),
                // A retained handshake owns its deadline and can serve a later query.
                Err(error)
                    if Self::should_refresh_for_error(error) && !dns_setup_pending(error) =>
                {
                    resolver.invalidate(&current, error);
                }
                Err(_) => {}
            }
            result
        })
    }

    fn invalidate(&self, current: &Arc<dyn Resolver>, error: &std::io::Error) {
        let (generation, report) = {
            let mut state = self.refresh_state.lock();
            if state.invalidated || !Arc::ptr_eq(&state.current, current) {
                return;
            }
            state.invalidated = true;
            state.recovering = true;
            let report = state
                .last_report_at
                .is_none_or(|last| last.elapsed() >= Duration::from_secs(30));
            if report {
                state.last_report_at = Some(Instant::now());
            }
            (state.generation, report)
        };
        if report {
            log::info!(
                "DNS resolver {} generation {generation}: transport retired after {error}",
                self.description
            );
        }
        current.retire();
    }

    fn record_success(&self, current: &Arc<dyn Resolver>) {
        let mut state = self.refresh_state.lock();
        if !state.invalidated && Arc::ptr_eq(&state.current, current) {
            state.last_activity_at = Some(Instant::now());
            if state.recovering {
                log::info!(
                    "DNS resolver {} generation {}: query recovered",
                    self.description,
                    state.generation
                );
                state.recovering = false;
            }
        }
    }

    async fn current(
        &self,
        deadline: Option<tokio::time::Instant>,
    ) -> std::io::Result<Arc<dyn Resolver>> {
        let needs_refresh = |state: &RefreshState| {
            state.invalidated
                || state
                    .last_activity_at
                    .is_some_and(|last| last.elapsed() > self.policy.max_idle)
        };
        {
            let state = self.refresh_state.lock();
            if !needs_refresh(&state) {
                return Ok(state.current.clone());
            }
        }
        let _guard = Self::refresh_wait(deadline, self.refresh_lock.lock()).await?;
        {
            let state = self.refresh_state.lock();
            if !needs_refresh(&state) {
                return Ok(state.current.clone());
            }
        }
        let fresh = match Self::refresh_wait(deadline, (self.factory)()).await? {
            Ok(fresh) => fresh,
            Err(error) => {
                let state = self.refresh_state.lock();
                if state.invalidated {
                    return Err(error);
                }
                log::debug!(
                    "DNS resolver {}: idle refresh failed: {error}",
                    self.description
                );
                return Ok(state.current.clone());
            }
        };
        let old = {
            let mut state = self.refresh_state.lock();
            let old = std::mem::replace(&mut state.current, fresh.clone());
            state.last_activity_at = if state.invalidated {
                None
            } else {
                Some(Instant::now())
            };
            state.invalidated = false;
            state.generation = state.generation.wrapping_add(1);
            log::debug!(
                "DNS resolver {}: installed generation {}: {fresh:?}",
                self.description,
                state.generation
            );
            old
        };
        // Idle eviction must not interrupt queries already using the previous generation.
        drop(old);
        Ok(fresh)
    }

    async fn refresh_wait<T>(
        deadline: Option<tokio::time::Instant>,
        future: impl Future<Output = T>,
    ) -> std::io::Result<T> {
        match deadline {
            Some(deadline) => tokio::select! {
                biased;
                _ = tokio::time::sleep_until(deadline) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut, DnsCallerDeadline,
                )),
                result = future => Ok(result),
            },
            None => Ok(future.await),
        }
    }
}

impl Resolver for RefreshingResolver {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        if let Some(socket_addr) = location.to_socket_addr_nonblocking() {
            return Box::pin(async move { Ok(vec![socket_addr]) });
        }
        let location = location.clone();
        self.execute(None, move |resolver, deadline| {
            let future = resolver.resolve_location(&location);
            Box::pin(async move { Self::refresh_wait(deadline, future).await? })
        })
    }

    fn exchange(&self, request: Vec<u8>) -> DnsExchangeFuture {
        self.execute(None, move |resolver, deadline| match deadline {
            Some(deadline) => resolver.exchange_with_deadline(request, deadline),
            None => resolver.exchange(request),
        })
    }

    fn exchange_with_deadline(
        &self,
        request: Vec<u8>,
        deadline: tokio::time::Instant,
    ) -> DnsExchangeFuture {
        // A second timer around the operation could beat its retained reply's timer wake.
        self.execute(Some(deadline), move |resolver, deadline| {
            resolver.exchange_with_deadline(request, deadline.unwrap())
        })
    }
}

#[derive(Debug, Default)]
pub struct NativeResolver;

impl NativeResolver {
    pub fn new() -> Self {
        NativeResolver {}
    }
}

impl Resolver for NativeResolver {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        if let Some(bootstrap) = crate::socket_policy::bootstrap() {
            return bootstrap.resolve_location(location);
        }
        let address = location.address().clone();
        let port = location.port();
        Box::pin(
            tokio::net::lookup_host((address.to_string(), port)).map(move |result| {
                let ret = result.map(|r| {
                    r.filter(|addr| !addr.ip().is_unspecified())
                        .collect::<Vec<_>>()
                });
                debug!("NativeResolver resolved {address}:{port} -> {ret:?}");
                ret
            }),
        )
    }
}

pub async fn resolve_single_address(
    resolver: &Arc<dyn Resolver>,
    location: &NetLocation,
) -> std::io::Result<SocketAddr> {
    if let Some(socket_addr) = location.to_socket_addr_nonblocking() {
        return Ok(socket_addr);
    }
    let resolve_results = resolver.resolve_location(location).await?;
    if resolve_results.is_empty() {
        return Err(std::io::Error::other(format!(
            "could not resolve location: {location}"
        )));
    }
    Ok(resolve_results[0])
}

/// Resolve all addresses for a location. Returns a single-element vec
/// for IP literals, or the full set from the resolver.
pub async fn resolve_addresses(
    resolver: &Arc<dyn Resolver>,
    location: &NetLocation,
) -> std::io::Result<Vec<SocketAddr>> {
    if let Some(socket_addr) = location.to_socket_addr_nonblocking() {
        return Ok(vec![socket_addr]);
    }

    let addrs = resolver.resolve_location(location).await?;
    if addrs.is_empty() {
        return Err(std::io::Error::other(format!(
            "could not resolve location: {location}"
        )));
    }
    Ok(addrs)
}

/// Resolve a ResolvedLocation lazily. If already resolved, returns the cached
/// address. Otherwise resolves, caches the result in the location, and returns it.
/// This is the key function for the lazy resolution pattern.
pub async fn resolve_location(
    location: &mut ResolvedLocation,
    resolver: &Arc<dyn Resolver>,
) -> std::io::Result<SocketAddr> {
    if let Some(addr) = location.resolved_addr() {
        return Ok(addr);
    }
    let addr = resolve_single_address(resolver, location.location()).await?;
    location.set_resolved(addr);
    Ok(addr)
}

/// Native resolver with application-level caching.
/// Used by implicit native resolution and opt-in caching on explicit `system` entries.
/// OS lookups expose no DNS TTL; successful results are reused for at most 60 seconds
/// by default, measured from lookup completion. Errors and empty results are never cached.
///
/// At most 1,024 callers participate in coalesced misses (owners plus subscribers).
/// Excess callers perform independent lookups, preserving existing failure
/// semantics without adding an unbounded admission queue or detached tasks.
/// Cancelling an owner makes surviving subscribers start a new lookup, which
/// may exceed their remaining deadlines. Already-running OS calls cannot be stopped.
pub struct CachingNativeResolver {
    state: Arc<Mutex<NativeResolverState>>,
    participants: Arc<Semaphore>,
    lookup: Arc<dyn Resolver>,
    result_timeout_secs: u64,
}

type NativeLookupResult = Result<Arc<[SocketAddr]>, Arc<std::io::Error>>;

struct NativeResolverState {
    cache: LruCache<Address, CachedResolveResult>,
    inflight: HashMap<Address, broadcast::Sender<NativeLookupResult>>,
}

struct CachedResolveResult {
    completed_at: tokio::time::Instant,
    addrs: Arc<[SocketAddr]>,
}

impl NativeResolverState {
    fn cached(&mut self, address: &Address, max_age: Duration) -> Option<Arc<[SocketAddr]>> {
        if max_age.is_zero() {
            return None;
        }
        if let Some(cached) = self.cache.get(address)
            && cached.completed_at.elapsed() < max_age
        {
            return Some(cached.addrs.clone());
        }
        self.cache.pop(address);
        None
    }
}

struct NativeLookupOwner {
    state: Arc<Mutex<NativeResolverState>>,
    address: Address,
    registered: bool,
}

enum NativeLookupRole {
    Owner(NativeLookupOwner),
    Subscriber(broadcast::Receiver<NativeLookupResult>),
}

impl NativeLookupOwner {
    fn publish(mut self, result: &NativeLookupResult, cache_enabled: bool) {
        let mut state = self.state.lock();
        if cache_enabled && let Ok(addrs) = result {
            state.cache.put(
                self.address.clone(),
                CachedResolveResult {
                    completed_at: tokio::time::Instant::now(),
                    addrs: addrs.clone(),
                },
            );
        }
        // Cache insertion and flight removal are atomic with subscription.
        if self.registered {
            let sender = state.inflight.remove(&self.address).unwrap();
            // A panicking waker must not let Drop remove a replacement flight.
            self.registered = false;
            drop(state);
            let _ = sender.send(result.clone());
        }
    }
}

impl Drop for NativeLookupOwner {
    fn drop(&mut self) {
        if self.registered {
            // Closing outside the lock wakes subscribers to elect a replacement owner.
            let sender = self.state.lock().inflight.remove(&self.address);
            drop(sender);
        }
    }
}

fn native_addrs_with_port(addrs: &[SocketAddr], port: u16) -> Vec<SocketAddr> {
    addrs
        .iter()
        .map(|addr| {
            let mut addr = *addr;
            addr.set_port(port);
            addr
        })
        .collect()
}

fn native_lookup_error(error: Arc<std::io::Error>) -> std::io::Error {
    match error.raw_os_error() {
        Some(errno) => std::io::Error::from_raw_os_error(errno),
        None => std::io::Error::new(error.kind(), error),
    }
}

impl std::fmt::Debug for CachingNativeResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachingNativeResolver")
            .field("result_timeout_secs", &self.result_timeout_secs)
            .finish()
    }
}

impl CachingNativeResolver {
    /// Conservative application result age, not an authoritative DNS record TTL.
    pub const DEFAULT_RESULT_TIMEOUT_SECS: u64 = 60;

    pub fn new() -> Self {
        Self::with_timeout(Self::DEFAULT_RESULT_TIMEOUT_SECS)
    }

    /// Sets the maximum successful result age, not a lookup deadline or DNS TTL.
    /// Zero disables completed-result caching but still coalesces concurrent misses.
    pub fn with_timeout(result_timeout_secs: u64) -> Self {
        Self::with_lookup(Arc::new(NativeResolver::new()), result_timeout_secs)
    }

    pub(crate) fn with_lookup(lookup: Arc<dyn Resolver>, result_timeout_secs: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(NativeResolverState {
                cache: bounded_lru(CACHING_NATIVE_RESOLVER_CACHE_CAPACITY),
                inflight: HashMap::new(),
            })),
            participants: Arc::new(Semaphore::new(CACHING_NATIVE_RESOLVER_MAX_PARTICIPANTS)),
            lookup,
            result_timeout_secs,
        }
    }
}

impl Default for CachingNativeResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolver for CachingNativeResolver {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        let max_age = Duration::from_secs(self.result_timeout_secs);
        let cache_enabled = self.result_timeout_secs > 0;
        let caller_port = location.port();
        if let Some(addrs) = self.state.lock().cached(location.address(), max_age) {
            let addrs = native_addrs_with_port(&addrs, caller_port);
            return Box::pin(async move { Ok(addrs) });
        }

        // Tokio's (host, u16) lookup delegates to std, which passes a null service
        // to getaddrinfo and sets ports afterward. Only the exact host is a key;
        // socket candidates retain order, duplicates, IPv6 scope IDs and flowinfo.
        let query_location = NetLocation::new(location.address().clone(), 0);
        let state = self.state.clone();
        let participants = self.participants.clone();
        let lookup = self.lookup.clone();

        Box::pin(async move {
            let permit = participants.try_acquire().ok();
            loop {
                let role = {
                    let mut locked = state.lock();
                    // Rechecks after future creation or cancellation of an owner.
                    if let Some(addrs) = locked.cached(query_location.address(), max_age) {
                        return Ok(native_addrs_with_port(&addrs, caller_port));
                    }
                    if let Some(sender) = locked.inflight.get(query_location.address())
                        && permit.is_some()
                    {
                        NativeLookupRole::Subscriber(sender.subscribe())
                    } else {
                        let registered = permit.is_some();
                        if registered {
                            let (sender, _) = broadcast::channel(1);
                            locked
                                .inflight
                                .insert(query_location.address().clone(), sender);
                        }
                        NativeLookupRole::Owner(NativeLookupOwner {
                            state: state.clone(),
                            address: query_location.address().clone(),
                            registered,
                        })
                    }
                };

                let result = match role {
                    NativeLookupRole::Subscriber(mut subscriber) => match subscriber.recv().await {
                        Ok(result) => result,
                        Err(_) => continue,
                    },
                    NativeLookupRole::Owner(owner) => {
                        let result = lookup
                            .resolve_location(&query_location)
                            .await
                            .and_then(|mut addrs| {
                                addrs.retain(|addr| !addr.ip().is_unspecified());
                                if addrs.is_empty() {
                                    Err(std::io::Error::other(format!(
                                        "DNS lookup returned no addresses for {}",
                                        query_location.address()
                                    )))
                                } else {
                                    Ok(Arc::from(addrs))
                                }
                            })
                            .map_err(Arc::new);
                        owner.publish(&result, cache_enabled);
                        result
                    }
                };
                let addrs = result.map_err(native_lookup_error)?;
                let addrs = native_addrs_with_port(&addrs, caller_port);
                debug!(
                    "CachingNativeResolver resolved {}:{caller_port} -> {addrs:?}",
                    query_location.address()
                );
                return Ok(addrs);
            }
        })
    }
}

#[cfg(test)]
mod native_tests;

/// Poll-based resolver cache for use in Future/Stream implementations.
/// Wraps any Resolver and provides poll_resolve_location for manual polling.
pub struct ResolverCache {
    resolver: Arc<dyn Resolver>,
    /// Completed resolution results with timestamps
    cache: LruCache<NetLocation, (Instant, SocketAddr)>,
    /// The latest poll-based lookup. A changed target cancels the abandoned lookup.
    pending: Option<(NetLocation, ResolveFuture)>,
    result_timeout_secs: u64,
}

impl ResolverCache {
    pub const DEFAULT_RESULT_TIMEOUT_SECS: u64 = 60 * 60;

    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        Self::new_with_timeout(resolver, Self::DEFAULT_RESULT_TIMEOUT_SECS)
    }

    pub fn new_with_timeout(resolver: Arc<dyn Resolver>, result_timeout_secs: u64) -> Self {
        Self {
            resolver,
            cache: bounded_lru(RESOLVER_CACHE_CAPACITY),
            pending: None,
            result_timeout_secs,
        }
    }

    /// Async resolve method for convenience.
    #[allow(
        dead_code,
        reason = "Public library API; the binary uses poll_resolve_location"
    )]
    pub async fn resolve_location(&mut self, target: &NetLocation) -> std::io::Result<SocketAddr> {
        self.pending = None;

        // Fast path: IP address
        if let Some(socket_addr) = target.to_socket_addr_nonblocking() {
            return Ok(socket_addr);
        }

        // Check cache
        if let Some((ts, addr)) = self.cache.get(target) {
            if Instant::now().duration_since(*ts) <= Duration::from_secs(self.result_timeout_secs) {
                return Ok(*addr);
            }
            self.cache.pop(target);
        }

        // Resolve
        let addrs = self.resolver.resolve_location(target).await?;
        if addrs.is_empty() {
            return Err(std::io::Error::other(format!(
                "DNS lookup returned no addresses for {target}"
            )));
        }
        let addr = addrs[0];
        self.cache.put(target.clone(), (Instant::now(), addr));
        Ok(addr)
    }

    /// Poll-based resolve for use in Future/Stream poll methods.
    pub fn poll_resolve_location(
        &mut self,
        cx: &mut Context<'_>,
        target: &NetLocation,
    ) -> Poll<std::io::Result<SocketAddr>> {
        if self
            .pending
            .as_ref()
            .is_some_and(|(pending_target, _)| pending_target != target)
        {
            self.pending = None;
        }

        // Fast path: IP address
        if let Some(socket_addr) = target.to_socket_addr_nonblocking() {
            return Poll::Ready(Ok(socket_addr));
        }

        // Check completed cache
        if let Some((ts, addr)) = self.cache.get(target) {
            if Instant::now().duration_since(*ts) <= Duration::from_secs(self.result_timeout_secs) {
                return Poll::Ready(Ok(*addr));
            }
            self.cache.pop(target);
        }

        if self.pending.is_none() {
            self.pending = Some((target.clone(), self.resolver.resolve_location(target)));
        }

        let result = self.pending.as_mut().unwrap().1.as_mut().poll(cx);
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(addrs)) => {
                self.pending = None;
                if addrs.is_empty() {
                    return Poll::Ready(Err(std::io::Error::other(format!(
                        "DNS lookup returned no addresses for {target}"
                    ))));
                }
                let addr = addrs[0];
                self.cache.put(target.clone(), (Instant::now(), addr));
                Poll::Ready(Ok(addr))
            }
            Poll::Ready(Err(e)) => {
                self.pending = None;
                Poll::Ready(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod tests;
