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

            for (i, resolver) in resolvers.iter().enumerate() {
                match resolver.resolve_location(&location).await {
                    Ok(addrs) if !addrs.is_empty() => {
                        if i > 0 {
                            log::info!(
                                "CompositeResolver: resolved {} via resolver #{} ({:?}) after {} failures",
                                location,
                                i,
                                resolver,
                                i
                            );
                        }
                        return Ok(addrs);
                    }
                    Ok(_) => {
                        log::debug!(
                            "CompositeResolver: resolver #{} ({:?}) returned empty for {}, trying next",
                            i,
                            resolver,
                            location
                        );
                        last_error = Some(std::io::Error::other("empty response"));
                    }
                    Err(e) => {
                        log::debug!(
                            "CompositeResolver: resolver #{} ({:?}) failed for {}: {}, trying next",
                            i,
                            resolver,
                            location,
                            e
                        );
                        last_error = Some(e);
                    }
                }
            }

            Err(last_error.unwrap_or_else(|| std::io::Error::other("no DNS resolvers configured")))
        })
    }
}
