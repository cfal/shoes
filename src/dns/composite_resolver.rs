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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, ErrorKind};
    use std::sync::Mutex;

    type Calls = Arc<Mutex<Vec<(usize, NetLocation)>>>;

    #[derive(Debug)]
    struct RecordingResolver {
        id: usize,
        calls: Calls,
        result: Result<Vec<SocketAddr>, ErrorKind>,
    }

    impl Resolver for RecordingResolver {
        fn resolve_location(
            &self,
            location: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
            self.calls.lock().unwrap().push((self.id, location.clone()));
            let result = self.result.clone();
            Box::pin(async move { result.map_err(|kind| io::Error::new(kind, "resolver failure")) })
        }
    }

    fn composite(results: Vec<Result<Vec<SocketAddr>, ErrorKind>>) -> (CompositeResolver, Calls) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let resolvers = results
            .into_iter()
            .enumerate()
            .map(|(id, result)| {
                Arc::new(RecordingResolver {
                    id,
                    calls: calls.clone(),
                    result,
                }) as Arc<dyn Resolver>
            })
            .collect();
        (CompositeResolver::new(resolvers), calls)
    }

    #[tokio::test]
    async fn fallback_is_ordered_and_stops_at_first_nonempty_result() {
        let location = NetLocation::from_str("example.com:8443", None).unwrap();
        let addresses = vec![
            "[::1]:8443".parse().unwrap(),
            "127.0.0.1:8443".parse().unwrap(),
        ];
        for prefix in [vec![], vec![Err(ErrorKind::TimedOut), Ok(vec![])]] {
            let called = prefix.len() + 1;
            let mut results = prefix;
            results.push(Ok(addresses.clone()));
            results.push(Err(ErrorKind::PermissionDenied));
            let (resolver, calls) = composite(results);
            assert_eq!(
                resolver.resolve_location(&location).await.unwrap(),
                addresses
            );
            assert_eq!(
                *calls.lock().unwrap(),
                (0..called)
                    .map(|id| (id, location.clone()))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[tokio::test]
    async fn exhaustion_reports_last_failure_including_empty_responses() {
        let location = NetLocation::from_str("example.com:53", None).unwrap();
        for (results, kind, message) in [
            (
                vec![
                    Err(ErrorKind::TimedOut),
                    Ok(vec![]),
                    Err(ErrorKind::PermissionDenied),
                ],
                ErrorKind::PermissionDenied,
                "resolver failure",
            ),
            (
                vec![Err(ErrorKind::TimedOut), Ok(vec![])],
                ErrorKind::Other,
                "empty response",
            ),
            (
                vec![Ok(vec![]), Ok(vec![])],
                ErrorKind::Other,
                "empty response",
            ),
            (vec![], ErrorKind::Other, "no DNS resolvers configured"),
        ] {
            let count = results.len();
            let (resolver, calls) = composite(results);
            let error = resolver.resolve_location(&location).await.unwrap_err();
            assert_eq!(error.kind(), kind);
            assert_eq!(error.to_string(), message);
            assert_eq!(
                *calls.lock().unwrap(),
                (0..count)
                    .map(|id| (id, location.clone()))
                    .collect::<Vec<_>>()
            );
        }
    }
}
