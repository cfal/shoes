use std::fmt::Debug;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::future::{FutureExt, Shared};
use log::debug;
use rustc_hash::FxHashMap;

use crate::address::{NetLocation, ResolvedLocation};

type ResolveFuture = Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>;

pub trait Resolver: Send + Sync + Debug {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture;
}

#[derive(Debug)]
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
    cache: Arc<parking_lot::Mutex<FxHashMap<NetLocation, CachedResolveResult>>>,
    result_timeout_secs: u64,
}

struct CachedResolveResult {
    timestamp: Instant,
    addr: SocketAddr,
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
            cache: Arc::new(parking_lot::Mutex::new(FxHashMap::default())),
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
            let cache = self.cache.lock();
            if let Some(cached) = cache.get(location) {
                if Instant::now().duration_since(cached.timestamp)
                    <= Duration::from_secs(self.result_timeout_secs)
                {
                    let addr = cached.addr;
                    return Box::pin(async move { Ok(vec![addr]) });
                }
            }
        }

        let location = location.clone();
        let cache = self.cache.clone();

        Box::pin(async move {
            let address = location.address().to_string();
            let port = location.port();

            let result = tokio::net::lookup_host((address.clone(), port)).await?;
            let addrs: Vec<SocketAddr> = result
                .filter(|addr| !addr.ip().is_unspecified())
                .collect();

            if addrs.is_empty() {
                return Err(std::io::Error::other(format!(
                    "DNS lookup returned no addresses for {address}"
                )));
            }

            // Cache the first result
            cache.lock().insert(
                location,
                CachedResolveResult {
                    timestamp: Instant::now(),
                    addr: addrs[0],
                },
            );

            debug!("CachingNativeResolver resolved {address}:{port} -> {addrs:?}");
            Ok(addrs)
        })
    }
}

/// Shared future type for concurrent resolution deduplication.
/// Uses Arc<std::io::Error> because Shared requires Clone on the output type.
type SharedResolveFuture =
    Shared<Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, Arc<std::io::Error>>> + Send>>>;

/// Poll-based resolver cache for use in Future/Stream implementations.
/// Wraps any Resolver and provides poll_resolve_location for manual polling.
/// Uses Shared futures to correctly handle concurrent requests for the same target.
pub struct ResolverCache {
    resolver: Arc<dyn Resolver>,
    /// Completed resolution results with timestamps
    cache: FxHashMap<NetLocation, (Instant, SocketAddr)>,
    /// In-flight resolutions using Shared futures for proper waker handling
    pending: FxHashMap<NetLocation, SharedResolveFuture>,
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
            cache: FxHashMap::default(),
            pending: FxHashMap::default(),
            result_timeout_secs,
        }
    }

    /// Async resolve method for convenience.
    pub async fn resolve_location(
        &mut self,
        target: &NetLocation,
    ) -> std::io::Result<SocketAddr> {
        // Fast path: IP address
        if let Some(socket_addr) = target.to_socket_addr_nonblocking() {
            return Ok(socket_addr);
        }

        // Check cache
        if let Some((ts, addr)) = self.cache.get(target) {
            if Instant::now().duration_since(*ts) <= Duration::from_secs(self.result_timeout_secs) {
                return Ok(*addr);
            }
            self.cache.remove(target);
        }

        // Resolve
        let addrs = self.resolver.resolve_location(target).await?;
        if addrs.is_empty() {
            return Err(std::io::Error::other(format!(
                "DNS lookup returned no addresses for {target}"
            )));
        }
        let addr = addrs[0];
        self.cache.insert(target.clone(), (Instant::now(), addr));
        Ok(addr)
    }

    /// Poll-based resolve for use in Future/Stream poll methods.
    /// Uses Shared futures to correctly wake all tasks waiting on the same target.
    pub fn poll_resolve_location(
        &mut self,
        cx: &mut Context<'_>,
        target: &NetLocation,
    ) -> Poll<std::io::Result<SocketAddr>> {
        // Fast path: IP address
        if let Some(socket_addr) = target.to_socket_addr_nonblocking() {
            return Poll::Ready(Ok(socket_addr));
        }

        // Check completed cache
        if let Some((ts, addr)) = self.cache.get(target) {
            if Instant::now().duration_since(*ts) <= Duration::from_secs(self.result_timeout_secs) {
                return Poll::Ready(Ok(*addr));
            }
            self.cache.remove(target);
        }

        // Get or create shared future for this target
        let mut shared_fut = self
            .pending
            .entry(target.clone())
            .or_insert_with(|| {
                let fut = self.resolver.resolve_location(target);
                // Wrap error in Arc for Clone requirement, then make shared
                fut.map(|r| r.map_err(Arc::new)).boxed().shared()
            })
            .clone();

        // Poll the shared future
        match shared_fut.poll_unpin(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(addrs)) => {
                self.pending.remove(target);
                if addrs.is_empty() {
                    return Poll::Ready(Err(std::io::Error::other(format!(
                        "DNS lookup returned no addresses for {target}"
                    ))));
                }
                let addr = addrs[0];
                self.cache.insert(target.clone(), (Instant::now(), addr));
                Poll::Ready(Ok(addr))
            }
            Poll::Ready(Err(e)) => {
                self.pending.remove(target);
                // Convert Arc<Error> back to Error
                Poll::Ready(Err(std::io::Error::new(e.kind(), e.to_string())))
            }
        }
    }
}
