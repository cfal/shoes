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
use tokio::sync::{Mutex as AsyncMutex, RwLock, Semaphore, broadcast};

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

    /// Configuration dependencies for health rechecks, not DNS answer provenance.
    fn manual_selector_paths(&self) -> Vec<crate::control::selection::ManualSelectorPath> {
        Vec::new()
    }

    fn fake_dns_context(&self) -> Option<Arc<crate::dns::fake_ip::FakeDnsContext>> {
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
    fn manual_selector_paths(&self) -> Vec<crate::control::selection::ManualSelectorPath> {
        self.inner.manual_selector_paths()
    }

    fn fake_dns_context(&self) -> Option<Arc<crate::dns::fake_ip::FakeDnsContext>> {
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
    /// After a refreshable error, rebuild and retry the lookup once.
    pub retry_once_after_refresh: bool,
}

/// Resolver wrapper that rebuilds its inner resolver on idle timeout or
/// connection-related errors. Targets stale pooled connection state in
/// hickory-backed resolvers.
pub struct RefreshingResolver {
    factory: ResolverFactory,
    inner: Arc<RwLock<Arc<dyn Resolver>>>,
    refresh_lock: Arc<AsyncMutex<()>>,
    refresh_state: Arc<Mutex<RefreshState>>,
    policy: RefreshPolicy,
    description: String,
}

struct RefreshState {
    last_activity_at: Option<Instant>,
    generation: u64,
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
            inner: Arc::new(RwLock::new(inner)),
            refresh_lock: Arc::new(AsyncMutex::new(())),
            refresh_state: Arc::new(Mutex::new(RefreshState {
                last_activity_at: None,
                generation: 0,
            })),
            policy,
            description,
        })
    }

    fn should_refresh_for_error(err: &std::io::Error) -> bool {
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
        operation: impl Fn(
            Arc<dyn Resolver>,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<T>> + Send>>
        + Send
        + Sync
        + 'static,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<T>> + Send>> {
        let inner = self.inner.clone();
        let refresh_lock = self.refresh_lock.clone();
        let factory = self.factory.clone();
        let refresh_state = self.refresh_state.clone();
        let policy = self.policy;
        let description = self.description.clone();

        Box::pin(async move {
            // Refreshes if idle too long using double-checked locking.
            if matches!(refresh_state.lock().last_activity_at, Some(last) if last.elapsed() > policy.max_idle)
            {
                let _guard = Self::refresh_wait(deadline, refresh_lock.lock()).await?;
                if matches!(refresh_state.lock().last_activity_at, Some(last) if last.elapsed() > policy.max_idle)
                {
                    log::info!(
                        "RefreshingResolver ({}): rebuilding after idle timeout ({:?})",
                        description,
                        policy.max_idle
                    );
                    match Self::refresh_wait(deadline, factory()).await? {
                        Ok(fresh) => {
                            *Self::refresh_wait(deadline, inner.write()).await? = fresh;
                            let mut state = refresh_state.lock();
                            state.last_activity_at = Some(Instant::now());
                            state.generation = state.generation.wrapping_add(1);
                        }
                        Err(e) => {
                            log::warn!(
                                "RefreshingResolver ({}): idle refresh failed: {}",
                                description,
                                e
                            );
                        }
                    }
                }
            }

            let current_generation = refresh_state.lock().generation;
            let current = Self::refresh_wait(deadline, inner.read()).await?.clone();
            let mut result = operation(current.clone()).await;
            let retried_setup = policy.retry_once_after_refresh
                && result.as_ref().is_err_and(dns_setup_pending)
                && deadline.is_none_or(|limit| tokio::time::Instant::now() < limit);
            if retried_setup {
                result = operation(current).await;
            }
            let error = match result {
                Ok(value) => {
                    refresh_state.lock().last_activity_at = Some(Instant::now());
                    return Ok(value);
                }
                Err(error) => error,
            };
            if !policy.retry_once_after_refresh
                || !Self::should_refresh_for_error(&error)
                || deadline.is_some_and(|limit| tokio::time::Instant::now() >= limit)
            {
                return Err(error);
            }

            let _guard = Self::refresh_wait(deadline, refresh_lock.lock()).await?;
            let retry_resolver = if refresh_state.lock().generation != current_generation {
                if retried_setup {
                    return Err(error);
                }
                Self::refresh_wait(deadline, inner.read()).await?.clone()
            } else {
                log::info!(
                    "RefreshingResolver ({}): refresh-on-error ({})",
                    description,
                    error.kind()
                );
                let fresh = match Self::refresh_wait(deadline, factory()).await? {
                    Ok(fresh) => fresh,
                    Err(factory_err) => {
                        log::warn!(
                            "RefreshingResolver ({}): error-refresh factory failed: {}",
                            description,
                            factory_err
                        );
                        return Err(error);
                    }
                };
                *Self::refresh_wait(deadline, inner.write()).await? = fresh.clone();
                {
                    let mut state = refresh_state.lock();
                    state.generation = state.generation.wrapping_add(1);
                }
                // A retained setup gets one retry, then refreshes only for future calls.
                if retried_setup {
                    return Err(error);
                }
                fresh
            };
            let value = operation(retry_resolver).await?;
            refresh_state.lock().last_activity_at = Some(Instant::now());
            Ok(value)
        })
    }

    async fn refresh_wait<T>(
        deadline: Option<tokio::time::Instant>,
        future: impl Future<Output = T>,
    ) -> std::io::Result<T> {
        match deadline {
            Some(deadline) => tokio::time::timeout_at(deadline, future)
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS exchange timed out")
                }),
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
        self.execute(None, move |resolver| resolver.resolve_location(&location))
    }

    fn exchange(&self, request: Vec<u8>) -> DnsExchangeFuture {
        self.execute(None, move |resolver| resolver.exchange(request.clone()))
    }

    fn exchange_with_deadline(
        &self,
        request: Vec<u8>,
        deadline: tokio::time::Instant,
    ) -> DnsExchangeFuture {
        // A second timer around the operation could beat its retained reply's timer wake.
        self.execute(Some(deadline), move |resolver| {
            resolver.exchange_with_deadline(request.clone(), deadline)
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
