//! Resolver that tries multiple DNS servers in order until one succeeds.

use std::fmt::Debug;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use crate::address::NetLocation;
use crate::resolver::Resolver;

/// Resolver that tries multiple DNS servers in order until one succeeds.
pub struct CompositeResolver {
    resolvers: Vec<Arc<dyn Resolver>>,
}

impl Debug for CompositeResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeResolver")
            .field("count", &self.resolvers.len())
            .finish()
    }
}

impl CompositeResolver {
    pub fn new(resolvers: Vec<Arc<dyn Resolver>>) -> Self {
        Self { resolvers }
    }
}

impl Resolver for CompositeResolver {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> {
        let resolvers = self.resolvers.clone();
        let location = location.clone();

        Box::pin(async move {
            let mut last_error = None;

            for resolver in &resolvers {
                match resolver.resolve_location(&location).await {
                    Ok(addrs) if !addrs.is_empty() => return Ok(addrs),
                    Ok(_) => {
                        last_error = Some(std::io::Error::other("empty response"));
                    }
                    Err(e) => {
                        log::debug!("DNS resolver failed, trying next: {e}");
                        last_error = Some(e);
                    }
                }
            }

            Err(last_error.unwrap_or_else(|| std::io::Error::other("no DNS resolvers configured")))
        })
    }
}
