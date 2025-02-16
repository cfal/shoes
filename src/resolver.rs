use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use log::debug;

use crate::address::NetLocation;

type ResolveFuture = Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>;

pub trait Resolver: Send + Sync {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture;
}

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
        use futures::future::FutureExt;
        Box::pin(
            tokio::net::lookup_host((address.to_string(), port)).map(move |result| {
                let ret = result.map(|r| {
                    r.filter(|addr| !addr.ip().is_unspecified())
                        .collect::<Vec<_>>()
                });
                debug!("NativeResolver resolved {}:{} -> {:?}", address, port, ret);
                ret
            }),
        )
    }
}

pub async fn resolve_single_address(
    resolver: &Arc<dyn Resolver>,
    location: &NetLocation,
) -> std::io::Result<SocketAddr> {
    let resolve_results = resolver.resolve_location(location).await?;
    if resolve_results.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("could not resolve location: {}", location),
        ));
    }
    Ok(resolve_results[0])
}

pub struct ResolverCache {
    resolver: Arc<dyn Resolver>,
    cache: HashMap<NetLocation, ResolveState>,
}

enum ResolveState {
    Resolving(ResolveFuture),
    Resolved(SocketAddr),
}

impl ResolverCache {
    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        Self {
            resolver,
            cache: HashMap::new(),
        }
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

        // TODO: switch to using entry()
        match self.cache.get_mut(target) {
            Some(ResolveState::Resolved(ref socket_addr)) => Poll::Ready(Ok(socket_addr.clone())),
            None => {
                let mut resolve_future: Pin<
                    Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>,
                > = self.resolver.resolve_location(target);
                match resolve_future.as_mut().poll(cx) {
                    Poll::Pending => {
                        self.cache
                            .insert(target.clone(), ResolveState::Resolving(resolve_future));
                        return Poll::Pending;
                    }
                    Poll::Ready(result) => match result {
                        Ok(v) => {
                            if v.is_empty() {
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    format!("Failed to resolve {}, no results", target),
                                )));
                            }
                            let socket_addr = v.into_iter().next().unwrap();
                            Poll::Ready(Ok(socket_addr))
                        }
                        Err(e) => Poll::Ready(Err(e)),
                    },
                }
            }
            Some(ResolveState::Resolving(ref mut resolve_future)) => {
                match resolve_future.as_mut().poll(cx) {
                    Poll::Pending => {
                        return Poll::Pending;
                    }
                    Poll::Ready(result) => {
                        let v = result?;
                        if v.is_empty() {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("Failed to resolve {}, no results", target),
                            )));
                        }
                        let socket_addr = v.into_iter().next().unwrap();
                        self.cache
                            .insert(target.clone(), ResolveState::Resolved(socket_addr));
                        Poll::Ready(Ok(socket_addr))
                    }
                }
            }
        }
    }
}

pub struct ResolveLocation<'a, 'b> {
    resolver_cache: &'a mut ResolverCache,
    target: &'b NetLocation,
}

impl<'a, 'b> Future for ResolveLocation<'a, 'b> {
    type Output = std::io::Result<SocketAddr>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.resolver_cache.poll_resolve_location(cx, this.target)
    }
}
