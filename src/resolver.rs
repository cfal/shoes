use std::fmt::Debug;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::future::FutureExt;
use log::debug;
use rustc_hash::FxHashMap;

use crate::address::NetLocation;

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

pub struct ResolverCache {
    resolver: Arc<dyn Resolver>,
    cache: FxHashMap<NetLocation, ResolveState>,
    result_timeout_secs: u64,
}

enum ResolveState {
    Resolving(ResolveFuture),
    Resolved(Instant, SocketAddr),
}

impl ResolverCache {
    pub const DEFAULT_RESULT_TIMEOUT_SECS: u64 = 60 * 60;

    pub fn new_with_timeout(resolver: Arc<dyn Resolver>, result_timeout_secs: u64) -> Self {
        Self {
            resolver,
            cache: FxHashMap::default(),
            result_timeout_secs,
        }
    }

    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        Self::new_with_timeout(resolver, Self::DEFAULT_RESULT_TIMEOUT_SECS)
    }

    pub fn resolve_location<'a, 'b>(
        &'a mut self,
        target: &'b NetLocation,
    ) -> ResolveLocation<'a, 'b> {
        ResolveLocation {
            resolver_cache: self,
            target,
        }
    }

    pub fn poll_resolve_location(
        &mut self,
        cx: &mut Context<'_>,
        target: &NetLocation,
    ) -> Poll<std::io::Result<SocketAddr>> {
        if let Some(socket_addr) = target.to_socket_addr_nonblocking() {
            return Poll::Ready(Ok(socket_addr));
        }

        if let Some(ResolveState::Resolved(ts, socket_addr)) = self.cache.get(target) {
            if Instant::now().duration_since(*ts) <= Duration::from_secs(self.result_timeout_secs) {
                return Poll::Ready(Ok(*socket_addr));
            } else {
                self.cache.remove(target);
            }
        }

        if let Some(ResolveState::Resolving(resolve_future)) = self.cache.get_mut(target) {
            match resolve_future.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => match result {
                    Ok(v) => {
                        if v.is_empty() {
                            return Poll::Ready(Err(std::io::Error::other(format!(
                                "Failed to resolve {target}, no results"
                            ))));
                        }
                        let socket_addr = v.into_iter().next().unwrap();
                        self.cache.insert(
                            target.clone(),
                            ResolveState::Resolved(Instant::now(), socket_addr),
                        );
                        return Poll::Ready(Ok(socket_addr));
                    }
                    Err(e) => return Poll::Ready(Err(e)),
                },
            }
        }

        let mut resolve_future = self.resolver.resolve_location(target);
        match resolve_future.as_mut().poll(cx) {
            Poll::Pending => {
                self.cache
                    .insert(target.clone(), ResolveState::Resolving(resolve_future));
                Poll::Pending
            }
            Poll::Ready(result) => match result {
                Ok(v) => {
                    if v.is_empty() {
                        return Poll::Ready(Err(std::io::Error::other(format!(
                            "Failed to resolve {target}, no results"
                        ))));
                    }
                    let socket_addr = v.into_iter().next().unwrap();
                    self.cache.insert(
                        target.clone(),
                        ResolveState::Resolved(Instant::now(), socket_addr),
                    );
                    Poll::Ready(Ok(socket_addr))
                }
                Err(e) => Poll::Ready(Err(e)),
            },
        }
    }
}

pub struct ResolveLocation<'a, 'b> {
    resolver_cache: &'a mut ResolverCache,
    target: &'b NetLocation,
}

impl Future for ResolveLocation<'_, '_> {
    type Output = std::io::Result<SocketAddr>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.resolver_cache.poll_resolve_location(cx, this.target)
    }
}
