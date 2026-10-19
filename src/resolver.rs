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
use tokio::sync::{Mutex as AsyncMutex, RwLock};

use crate::address::{NetLocation, ResolvedLocation};

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
const RESOLVER_CACHE_CAPACITY: usize = 1_024;

/// Constructs a bounded LRU without eagerly reserving storage for every entry.
fn bounded_lru<K: Hash + Eq, V>(capacity: usize) -> LruCache<K, V> {
    let mut cache = LruCache::unbounded();
    cache.resize(NonZeroUsize::new(capacity).unwrap());
    cache
}

pub trait Resolver: Send + Sync + Debug {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture;

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
/// Uses tokio::net::lookup_host (OS resolver) with TTL-based cache.
/// This is used as the default resolver when no DNS config is specified.
pub struct CachingNativeResolver {
    cache: Arc<parking_lot::Mutex<LruCache<NetLocation, CachedResolveResult>>>,
    result_timeout_secs: u64,
}

struct CachedResolveResult {
    timestamp: Instant,
    addrs: Vec<SocketAddr>,
}

impl std::fmt::Debug for CachingNativeResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachingNativeResolver")
            .field("result_timeout_secs", &self.result_timeout_secs)
            .finish()
    }
}

impl CachingNativeResolver {
    pub const DEFAULT_RESULT_TIMEOUT_SECS: u64 = 60 * 60; // 1 hour

    pub fn new() -> Self {
        Self::with_timeout(Self::DEFAULT_RESULT_TIMEOUT_SECS)
    }

    pub fn with_timeout(result_timeout_secs: u64) -> Self {
        Self {
            cache: Arc::new(parking_lot::Mutex::new(bounded_lru(
                CACHING_NATIVE_RESOLVER_CACHE_CAPACITY,
            ))),
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
        // Check cache first
        {
            let mut cache = self.cache.lock();
            if let Some(cached) = cache.get(location)
                && Instant::now().duration_since(cached.timestamp)
                    <= Duration::from_secs(self.result_timeout_secs)
            {
                let addrs = cached.addrs.clone();
                return Box::pin(async move { Ok(addrs) });
            }
            cache.pop(location);
        }

        let location = location.clone();
        let cache = self.cache.clone();

        Box::pin(async move {
            let address = location.address().to_string();
            let port = location.port();

            let result = tokio::net::lookup_host((address.clone(), port)).await?;
            let addrs: Vec<SocketAddr> =
                result.filter(|addr| !addr.ip().is_unspecified()).collect();

            if addrs.is_empty() {
                return Err(std::io::Error::other(format!(
                    "DNS lookup returned no addresses for {address}"
                )));
            }

            cache.lock().put(
                location,
                CachedResolveResult {
                    timestamp: Instant::now(),
                    addrs: addrs.clone(),
                },
            );

            debug!("CachingNativeResolver resolved {address}:{port} -> {addrs:?}");
            Ok(addrs)
        })
    }
}

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
mod tests {
    use super::*;
    use crate::address::Address;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Barrier;

    /// A mock resolver that returns configurable results, tracking call count.
    #[derive(Debug)]
    struct MockResolver {
        addrs: Vec<SocketAddr>,
        call_count: AtomicUsize,
        error_kind: Option<std::io::ErrorKind>,
    }

    impl MockResolver {
        fn with_addrs(addrs: Vec<SocketAddr>) -> Self {
            Self {
                addrs,
                call_count: AtomicUsize::new(0),
                error_kind: None,
            }
        }

        fn with_error(kind: std::io::ErrorKind) -> Self {
            Self {
                addrs: vec![],
                call_count: AtomicUsize::new(0),
                error_kind: Some(kind),
            }
        }
    }

    impl Resolver for MockResolver {
        fn exchange(&self, request: Vec<u8>) -> DnsExchangeFuture {
            self.call_count.fetch_add(1, Ordering::Relaxed);
            let error = self.error_kind;
            Box::pin(async move {
                match error {
                    Some(kind) => Err(std::io::Error::new(kind, "mock exchange error")),
                    None => Ok(request),
                }
            })
        }

        fn resolve_location(&self, _location: &NetLocation) -> ResolveFuture {
            self.call_count.fetch_add(1, Ordering::Relaxed);
            let addrs = self.addrs.clone();
            let error_kind = self.error_kind;
            Box::pin(async move {
                if let Some(kind) = error_kind {
                    Err(std::io::Error::new(kind, "mock error"))
                } else {
                    Ok(addrs)
                }
            })
        }
    }

    #[derive(Debug, Default)]
    struct PendingResolver {
        active: Arc<AtomicUsize>,
        calls: AtomicUsize,
    }

    struct PendingFuture {
        active: Arc<AtomicUsize>,
    }

    impl Future for PendingFuture {
        type Output = std::io::Result<Vec<SocketAddr>>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl Drop for PendingFuture {
        fn drop(&mut self) {
            self.active.fetch_sub(1, Ordering::Relaxed);
        }
    }

    impl Resolver for PendingResolver {
        fn resolve_location(&self, _location: &NetLocation) -> ResolveFuture {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.active.fetch_add(1, Ordering::Relaxed);
            Box::pin(PendingFuture {
                active: self.active.clone(),
            })
        }
    }

    fn test_location() -> NetLocation {
        NetLocation::new(Address::Hostname("example.com".to_string()), 80)
    }

    #[tokio::test]
    async fn exchange_propagates_timeout_and_refreshes_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let builds = calls.clone();
        let factory: ResolverFactory = Arc::new(move || {
            let generation = builds.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move {
                let resolver = if generation == 0 {
                    MockResolver::with_error(std::io::ErrorKind::TimedOut)
                } else {
                    MockResolver::with_addrs(vec![])
                };
                Ok(Arc::new(resolver) as Arc<dyn Resolver>)
            })
        });
        let resolver = RefreshingResolver::new(
            factory,
            RefreshPolicy {
                max_idle: Duration::from_secs(60),
                retry_once_after_refresh: true,
            },
            "exchange".into(),
        )
        .await
        .unwrap();
        let resolver = TimeoutResolver::with_timeout(resolver, Duration::from_secs(1));
        assert_eq!(resolver.exchange(vec![1, 2]).await.unwrap(), vec![1, 2]);
        assert_eq!(resolver.exchange(vec![3]).await.unwrap(), vec![3]);
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert!(
            resolver
                .inner
                .refresh_state
                .lock()
                .last_activity_at
                .is_some()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn exchange_deadline_handles_an_unbounded_configured_timeout() {
        let resolver =
            TimeoutResolver::with_timeout(MockResolver::with_addrs(vec![]), Duration::MAX);
        assert_eq!(
            resolver
                .exchange_with_deadline(
                    vec![1],
                    tokio::time::Instant::now() + Duration::from_secs(1)
                )
                .await
                .unwrap(),
            vec![1]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn exchange_deadline_completion_is_not_raced_by_a_refresh_timer() {
        #[derive(Debug)]
        struct DeadlineReply(bool);
        impl Resolver for DeadlineReply {
            fn resolve_location(&self, _: &NetLocation) -> ResolveFuture {
                unreachable!()
            }
            fn exchange_with_deadline(
                &self,
                request: Vec<u8>,
                deadline: tokio::time::Instant,
            ) -> DnsExchangeFuture {
                let fail = self.0;
                Box::pin(async move {
                    tokio::time::sleep_until(deadline).await;
                    // Model a leaf timer wake delivered after an enclosing timer's wake batch.
                    tokio::task::yield_now().await;
                    if fail {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            DnsSetupPending,
                        ))
                    } else {
                        Ok(request)
                    }
                })
            }
        }
        for fail in [false, true] {
            let builds = Arc::new(AtomicUsize::new(0));
            let calls = builds.clone();
            let factory: ResolverFactory = Arc::new(move || {
                calls.fetch_add(1, Ordering::Relaxed);
                Box::pin(async move { Ok(Arc::new(DeadlineReply(fail)) as Arc<dyn Resolver>) })
            });
            let resolver = RefreshingResolver::new(
                factory,
                RefreshPolicy {
                    max_idle: Duration::from_secs(60),
                    retry_once_after_refresh: true,
                },
                "deadline completion".into(),
            )
            .await
            .unwrap();
            let reply = resolver
                .exchange_with_deadline(
                    vec![1],
                    tokio::time::Instant::now() + Duration::from_millis(10),
                )
                .await;
            if fail {
                assert!(dns_setup_pending(&reply.unwrap_err()));
            } else {
                assert_eq!(reply.unwrap(), vec![1]);
            }
            assert_eq!(builds.load(Ordering::Relaxed), 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn exchange_deadline_also_bounds_refresh_factory_and_lock_waits() {
        for hold_lock in [false, true] {
            let builds = Arc::new(AtomicUsize::new(0));
            let calls = builds.clone();
            let factory: ResolverFactory = Arc::new(move || {
                let generation = calls.fetch_add(1, Ordering::Relaxed);
                Box::pin(async move {
                    if generation > 0 {
                        std::future::pending::<()>().await;
                    }
                    Ok(Arc::new(MockResolver::with_error(
                        std::io::ErrorKind::ConnectionReset,
                    )) as Arc<dyn Resolver>)
                })
            });
            let resolver = RefreshingResolver::new(
                factory,
                RefreshPolicy {
                    max_idle: Duration::from_secs(60),
                    retry_once_after_refresh: true,
                },
                "deadline".into(),
            )
            .await
            .unwrap();
            let _guard = if hold_lock {
                Some(resolver.refresh_lock.lock().await)
            } else {
                None
            };
            let started = tokio::time::Instant::now();
            let error = resolver
                .exchange_with_deadline(vec![], started + Duration::from_secs(1))
                .await
                .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
            assert_eq!(started.elapsed(), Duration::from_secs(1));
            assert_eq!(
                builds.load(Ordering::Relaxed),
                if hold_lock { 1 } else { 2 }
            );
        }
    }

    fn test_addrs() -> Vec<SocketAddr> {
        vec!["127.0.0.1:80".parse().unwrap()]
    }

    #[tokio::test]
    async fn failed_setup_retry_refreshes_only_for_future_requests() {
        #[derive(Debug)]
        struct SetupFailureResolver {
            calls: AtomicUsize,
            second_error: Option<std::io::ErrorKind>,
        }
        impl Resolver for SetupFailureResolver {
            fn resolve_location(&self, _: &NetLocation) -> ResolveFuture {
                unreachable!()
            }

            fn exchange(&self, _: Vec<u8>) -> DnsExchangeFuture {
                let call = self.calls.fetch_add(1, Ordering::Relaxed);
                let second_error = self.second_error;
                Box::pin(async move {
                    if call > 0
                        && let Some(kind) = second_error
                    {
                        return Err(std::io::Error::new(kind, "retry failure"));
                    }
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        DnsSetupPending,
                    ))
                })
            }
        }

        for (second_error, factory_fails) in [
            (None, false),
            (Some(std::io::ErrorKind::TimedOut), false),
            (Some(std::io::ErrorKind::InvalidData), false),
            (None, true),
        ] {
            let initial = Arc::new(SetupFailureResolver {
                calls: AtomicUsize::new(0),
                second_error,
            });
            let builds = Arc::new(AtomicUsize::new(0));
            let factory: ResolverFactory = {
                let initial = initial.clone();
                let builds = builds.clone();
                Arc::new(move || {
                    let generation = builds.fetch_add(1, Ordering::Relaxed);
                    let initial = initial.clone();
                    Box::pin(async move {
                        if generation == 0 {
                            Ok(initial as Arc<dyn Resolver>)
                        } else if factory_fails {
                            Err(std::io::Error::other("factory failed"))
                        } else {
                            Ok(Arc::new(MockResolver::with_addrs(vec![])) as Arc<dyn Resolver>)
                        }
                    })
                })
            };
            let resolver = RefreshingResolver::new(
                factory,
                RefreshPolicy {
                    max_idle: Duration::from_secs(60),
                    retry_once_after_refresh: true,
                },
                "failed retained setup".into(),
            )
            .await
            .unwrap();
            let error = resolver.exchange(vec![]).await.unwrap_err();
            assert_eq!(initial.calls.load(Ordering::Relaxed), 2);
            assert!(resolver.refresh_state.lock().last_activity_at.is_none());
            assert_eq!(dns_setup_pending(&error), second_error.is_none());
            assert_eq!(
                error.kind(),
                second_error.unwrap_or(std::io::ErrorKind::TimedOut)
            );
            let refreshable = RefreshingResolver::should_refresh_for_error(&error);
            assert_eq!(builds.load(Ordering::Relaxed), 1 + usize::from(refreshable));
            if refreshable && !factory_fails {
                assert_eq!(resolver.exchange(vec![3]).await.unwrap(), vec![3]);
                assert_eq!(initial.calls.load(Ordering::Relaxed), 2);
                assert_eq!(builds.load(Ordering::Relaxed), 2);
            }
        }
    }

    fn unique_location(index: usize) -> NetLocation {
        NetLocation::new(Address::Hostname(format!("host-{index}.example")), 443)
    }

    #[tokio::test]
    async fn concurrent_setup_retries_do_not_attempt_again_after_generation_changes() {
        #[derive(Debug, Default)]
        struct SetupFailureResolver(AtomicUsize);
        impl Resolver for SetupFailureResolver {
            fn resolve_location(&self, _: &NetLocation) -> ResolveFuture {
                unreachable!()
            }

            fn exchange(&self, _: Vec<u8>) -> DnsExchangeFuture {
                self.0.fetch_add(1, Ordering::Relaxed);
                Box::pin(async {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        DnsSetupPending,
                    ))
                })
            }
        }
        let initial = Arc::new(SetupFailureResolver::default());
        let fresh = Arc::new(MockResolver::with_addrs(vec![]));
        let builds = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let factory: ResolverFactory = {
            let (initial, fresh, builds, gate) =
                (initial.clone(), fresh.clone(), builds.clone(), gate.clone());
            Arc::new(move || {
                let generation = builds.fetch_add(1, Ordering::Relaxed);
                let (initial, fresh, gate) = (initial.clone(), fresh.clone(), gate.clone());
                Box::pin(async move {
                    if generation == 0 {
                        Ok(initial as Arc<dyn Resolver>)
                    } else {
                        let _permit = gate.acquire().await.unwrap();
                        Ok(fresh as Arc<dyn Resolver>)
                    }
                })
            })
        };
        let resolver = RefreshingResolver::new(
            factory,
            RefreshPolicy {
                max_idle: Duration::from_secs(60),
                retry_once_after_refresh: true,
            },
            "concurrent retained setup retries".into(),
        )
        .await
        .unwrap();
        let mut first = resolver.exchange(vec![]);
        let mut second = resolver.exchange(vec![]);
        assert!(futures::poll!(&mut first).is_pending());
        assert!(futures::poll!(&mut second).is_pending());
        assert_eq!(initial.0.load(Ordering::Relaxed), 4);
        assert_eq!(builds.load(Ordering::Relaxed), 2);
        gate.add_permits(1);
        assert!(dns_setup_pending(&first.await.unwrap_err()));
        assert!(dns_setup_pending(&second.await.unwrap_err()));
        assert_eq!(initial.0.load(Ordering::Relaxed), 4);
        assert_eq!(fresh.call_count.load(Ordering::Relaxed), 0);
        assert_eq!(builds.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_caching_native_resolver_cache_is_bounded() {
        let resolver = CachingNativeResolver::new();
        let mut cache = resolver.cache.lock();

        for index in 0..CACHING_NATIVE_RESOLVER_CACHE_CAPACITY + 1 {
            cache.put(
                unique_location(index),
                CachedResolveResult {
                    timestamp: Instant::now(),
                    addrs: vec!["127.0.0.1:443".parse().unwrap()],
                },
            );
        }

        assert_eq!(cache.len(), CACHING_NATIVE_RESOLVER_CACHE_CAPACITY);
        assert!(cache.peek(&unique_location(0)).is_none());
    }

    #[tokio::test]
    async fn native_cache_preserves_all_candidates_and_order() {
        let resolver = CachingNativeResolver::new();
        let location = test_location();
        let addrs = vec![
            "[2001:db8::1]:80".parse().unwrap(),
            "192.0.2.1:80".parse().unwrap(),
            "192.0.2.2:80".parse().unwrap(),
        ];
        resolver.cache.lock().put(
            location.clone(),
            CachedResolveResult {
                timestamp: Instant::now(),
                addrs: addrs.clone(),
            },
        );
        let mut result = resolver.resolve_location(&location).await.unwrap();
        assert_eq!(result, addrs);
        result.clear();
        assert_eq!(resolver.resolve_location(&location).await.unwrap(), addrs);
    }

    #[tokio::test]
    async fn native_cache_expires_and_stores_the_complete_cold_result() {
        let resolver = CachingNativeResolver::with_timeout(1);
        let location = NetLocation::from_str("127.0.0.1:80", None).unwrap();
        resolver.cache.lock().put(
            location.clone(),
            CachedResolveResult {
                timestamp: Instant::now() - Duration::from_secs(2),
                addrs: vec!["192.0.2.1:80".parse().unwrap()],
            },
        );
        let cold = resolver.resolve_location(&location).await.unwrap();
        assert_eq!(cold, vec!["127.0.0.1:80".parse::<SocketAddr>().unwrap()]);
        assert_eq!(resolver.cache.lock().peek(&location).unwrap().addrs, cold);
        assert_eq!(resolver.resolve_location(&location).await.unwrap(), cold);
    }

    #[tokio::test]
    async fn test_resolver_cache_is_bounded() {
        let resolver: Arc<dyn Resolver> = Arc::new(MockResolver::with_addrs(test_addrs()));
        let mut cache = ResolverCache::new(resolver);

        for index in 0..RESOLVER_CACHE_CAPACITY + 1 {
            cache
                .resolve_location(&unique_location(index))
                .await
                .unwrap();
        }

        assert_eq!(cache.cache.len(), RESOLVER_CACHE_CAPACITY);
        assert!(cache.cache.peek(&unique_location(0)).is_none());
    }

    #[test]
    fn test_resolver_cache_cancels_abandoned_pending_result() {
        let resolver = Arc::new(PendingResolver::default());
        let mut cache = ResolverCache::new(resolver.clone());
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let first = unique_location(0);
        let second = unique_location(1);

        assert!(matches!(
            cache.poll_resolve_location(&mut cx, &first),
            Poll::Pending
        ));
        assert_eq!(resolver.active.load(Ordering::Relaxed), 1);

        assert!(matches!(
            cache.poll_resolve_location(&mut cx, &second),
            Poll::Pending
        ));
        assert_eq!(resolver.active.load(Ordering::Relaxed), 1);
        assert_eq!(resolver.calls.load(Ordering::Relaxed), 2);

        assert!(matches!(
            cache.poll_resolve_location(&mut cx, &second),
            Poll::Pending
        ));
        assert_eq!(resolver.calls.load(Ordering::Relaxed), 2);

        let literal = NetLocation::new(Address::Ipv4(std::net::Ipv4Addr::LOCALHOST), 443);
        assert!(matches!(
            cache.poll_resolve_location(&mut cx, &literal),
            Poll::Ready(Ok(_))
        ));
        assert_eq!(resolver.active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_refreshing_resolver_retries_after_timeout() {
        let success_addrs = test_addrs();
        let call_count = Arc::new(AtomicUsize::new(0));

        let call_count_clone = call_count.clone();
        let addrs = success_addrs.clone();
        let factory: ResolverFactory = Arc::new(move || {
            let n = call_count_clone.fetch_add(1, Ordering::Relaxed);
            let addrs = addrs.clone();
            Box::pin(async move {
                if n == 0 {
                    // First build: return a resolver that times out
                    Ok(
                        Arc::new(MockResolver::with_error(std::io::ErrorKind::TimedOut))
                            as Arc<dyn Resolver>,
                    )
                } else {
                    // Refresh build: return a resolver that succeeds
                    Ok(Arc::new(MockResolver::with_addrs(addrs)) as Arc<dyn Resolver>)
                }
            })
        });

        let policy = RefreshPolicy {
            max_idle: Duration::from_secs(60),
            retry_once_after_refresh: true,
        };

        let resolver = RefreshingResolver::new(factory, policy, "test".to_string())
            .await
            .unwrap();

        let result = resolver.resolve_location(&test_location()).await.unwrap();
        assert_eq!(result, success_addrs);
        // Factory called twice: initial build + refresh-on-error
        assert_eq!(call_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_refreshing_resolver_no_retry_on_non_refreshable_error() {
        let call_count = Arc::new(AtomicUsize::new(0));

        let call_count_clone = call_count.clone();
        let factory: ResolverFactory = Arc::new(move || {
            call_count_clone.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move {
                // Return a resolver that returns a non-refreshable error
                Ok(
                    Arc::new(MockResolver::with_error(std::io::ErrorKind::Other))
                        as Arc<dyn Resolver>,
                )
            })
        });

        let policy = RefreshPolicy {
            max_idle: Duration::from_secs(60),
            retry_once_after_refresh: true,
        };

        let resolver = RefreshingResolver::new(factory, policy, "test".to_string())
            .await
            .unwrap();

        let result = resolver.resolve_location(&test_location()).await;
        assert!(result.is_err());
        // Factory called only once (initial build, no refresh for non-refreshable errors)
        assert_eq!(call_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_refreshing_resolver_idle_refresh() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let addrs = test_addrs();

        let call_count_clone = call_count.clone();
        let addrs_clone = addrs.clone();
        let factory: ResolverFactory = Arc::new(move || {
            call_count_clone.fetch_add(1, Ordering::Relaxed);
            let addrs = addrs_clone.clone();
            Box::pin(
                async move { Ok(Arc::new(MockResolver::with_addrs(addrs)) as Arc<dyn Resolver>) },
            )
        });

        let policy = RefreshPolicy {
            max_idle: Duration::from_millis(50),
            retry_once_after_refresh: true,
        };

        let resolver = RefreshingResolver::new(factory, policy, "test".to_string())
            .await
            .unwrap();

        // First resolve records activity.
        let result = resolver.resolve_location(&test_location()).await.unwrap();
        assert_eq!(result, addrs);
        assert_eq!(call_count.load(Ordering::Relaxed), 1);

        // Wait for idle timeout
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Second resolve triggers idle refresh
        let result = resolver.resolve_location(&test_location()).await.unwrap();
        assert_eq!(result, addrs);
        // Factory called twice: initial + idle refresh
        assert_eq!(call_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_refreshing_resolver_coalesces_concurrent_idle_refresh() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let addrs = test_addrs();

        let call_count_clone = call_count.clone();
        let addrs_clone = addrs.clone();
        let factory: ResolverFactory = Arc::new(move || {
            call_count_clone.fetch_add(1, Ordering::Relaxed);
            let addrs = addrs_clone.clone();
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok(Arc::new(MockResolver::with_addrs(addrs)) as Arc<dyn Resolver>)
            })
        });

        let policy = RefreshPolicy {
            max_idle: Duration::from_millis(20),
            retry_once_after_refresh: true,
        };

        let resolver = Arc::new(
            RefreshingResolver::new(factory, policy, "test".to_string())
                .await
                .unwrap(),
        );

        let result = resolver.resolve_location(&test_location()).await.unwrap();
        assert_eq!(result, addrs);
        assert_eq!(call_count.load(Ordering::Relaxed), 1);

        tokio::time::sleep(Duration::from_millis(50)).await;

        let concurrency = 32;
        let barrier = Arc::new(Barrier::new(concurrency));
        let tasks = (0..concurrency).map(|_| {
            let resolver = resolver.clone();
            let barrier = barrier.clone();
            let location = test_location();
            tokio::spawn(async move {
                barrier.wait().await;
                resolver.resolve_location(&location).await
            })
        });

        for result in futures::future::join_all(tasks).await {
            assert_eq!(result.unwrap().unwrap(), addrs);
        }
        assert_eq!(call_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_resolve_addresses_returns_all() {
        let addrs: Vec<SocketAddr> = vec![
            "1.1.1.1:80".parse().unwrap(),
            "2.2.2.2:80".parse().unwrap(),
            "3.3.3.3:80".parse().unwrap(),
        ];
        let inner: Arc<dyn Resolver> = Arc::new(MockResolver::with_addrs(addrs.clone()));
        let loc = test_location();

        let result = resolve_addresses(&inner, &loc).await.unwrap();
        assert_eq!(result, addrs);
    }

    #[tokio::test]
    async fn test_resolve_addresses_ip_literal() {
        let inner: Arc<dyn Resolver> = Arc::new(MockResolver::with_addrs(vec![]));
        let loc = NetLocation::new(Address::Ipv4("1.2.3.4".parse().unwrap()), 443);

        let result = resolve_addresses(&inner, &loc).await.unwrap();
        assert_eq!(result, vec!["1.2.3.4:443".parse::<SocketAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn test_timeout_resolver_ip_bypass() {
        let inner = MockResolver::with_addrs(test_addrs());
        let resolver = TimeoutResolver::with_timeout(inner, Duration::from_millis(1));

        // IP literals should return immediately without timeout
        let loc = NetLocation::new(Address::Ipv4("1.2.3.4".parse().unwrap()), 80);
        let result = resolver.resolve_location(&loc).await.unwrap();
        assert_eq!(result[0], "1.2.3.4:80".parse::<SocketAddr>().unwrap());
    }
}
