use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use log::debug;

use crate::address::NetLocation;

pub trait Resolver: Send + Sync {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>;
}

pub struct NativeResolver;

impl NativeResolver {
    pub fn new() -> Self {
        NativeResolver {}
    }
}

impl Resolver for NativeResolver {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> {
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
    let resolve_results = resolver.resolve_location(&location).await?;
    if resolve_results.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("could not resolve location: {}", location),
        ));
    }
    Ok(resolve_results[0])
}
