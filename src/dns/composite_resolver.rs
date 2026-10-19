//! Resolver that tries multiple DNS servers in order until one succeeds.

use std::fmt::Debug;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use hickory_resolver::proto::op::ResponseCode;

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

    fn exchange_inner(
        &self,
        request: Vec<u8>,
        deadline: Option<tokio::time::Instant>,
    ) -> crate::resolver::DnsExchangeFuture {
        let resolvers = self.resolvers.clone();
        Box::pin(async move {
            let mut last =
                std::io::Error::new(std::io::ErrorKind::NotFound, "no DNS resolvers configured");
            let mut retained_setup = false;
            let mut truncated = None;
            for resolver in resolvers {
                if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
                    last =
                        std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS exchange timed out");
                    break;
                }
                let exchange = match deadline {
                    Some(deadline) => resolver.exchange_with_deadline(request.clone(), deadline),
                    None => resolver.exchange(request.clone()),
                };
                match exchange.await {
                    Ok(response) => {
                        let message = super::message::decode(&response);
                        if message
                            .as_ref()
                            .is_ok_and(|message| message.metadata.truncation)
                        {
                            truncated.get_or_insert(response);
                        } else if truncated.is_none()
                            || message.is_ok_and(|message| {
                                matches!(
                                    message.metadata.response_code,
                                    ResponseCode::NoError | ResponseCode::NXDomain
                                )
                            })
                        {
                            return Ok(response);
                        }
                    }
                    Err(error) => {
                        retained_setup |= crate::resolver::dns_setup_pending(&error);
                        last = error;
                    }
                }
            }
            if let Some(response) = truncated {
                Ok(response)
            } else if retained_setup {
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    crate::resolver::DnsSetupPending,
                ))
            } else {
                Err(last)
            }
        })
    }
}

impl Resolver for CompositeResolver {
    fn exchange(&self, request: Vec<u8>) -> crate::resolver::DnsExchangeFuture {
        self.exchange_inner(request, None)
    }

    fn exchange_with_deadline(
        &self,
        request: Vec<u8>,
        deadline: tokio::time::Instant,
    ) -> crate::resolver::DnsExchangeFuture {
        self.exchange_inner(request, Some(deadline))
    }

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
        fn exchange(&self, _request: Vec<u8>) -> crate::resolver::DnsExchangeFuture {
            let result = self.result.clone();
            Box::pin(async move {
                result
                    .map(|_| vec![])
                    .map_err(|kind| io::Error::new(kind, "exchange failure"))
            })
        }

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
    async fn later_exchange_failure_preserves_retained_setup_retry() {
        #[derive(Debug)]
        struct PendingSetup;
        impl Resolver for PendingSetup {
            fn resolve_location(&self, _: &NetLocation) -> crate::resolver::ResolveFuture {
                unreachable!()
            }
            fn exchange(&self, _: Vec<u8>) -> crate::resolver::DnsExchangeFuture {
                Box::pin(async {
                    Err(io::Error::new(
                        ErrorKind::TimedOut,
                        crate::resolver::DnsSetupPending,
                    ))
                })
            }
        }
        let fallback = composite(vec![Err(ErrorKind::TimedOut)]).0;
        let resolver = CompositeResolver::new(vec![Arc::new(PendingSetup), Arc::new(fallback)]);
        assert!(crate::resolver::dns_setup_pending(
            &resolver.exchange(Vec::new()).await.unwrap_err()
        ));
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
    async fn exchange_stops_at_any_success_even_with_empty_answers() {
        let (resolver, _) = composite(vec![
            Err(ErrorKind::TimedOut),
            Ok(vec![]),
            Err(ErrorKind::PermissionDenied),
        ]);
        assert_eq!(resolver.exchange(vec![]).await.unwrap(), Vec::<u8>::new());
    }

    #[tokio::test]
    async fn truncated_exchange_tries_fallback_and_preserves_first_partial_answer() {
        use hickory_resolver::proto::op::{Message, ResponseCode};

        #[derive(Debug)]
        struct WireReply(Result<Vec<u8>, ErrorKind>);
        impl Resolver for WireReply {
            fn resolve_location(&self, _: &NetLocation) -> crate::resolver::ResolveFuture {
                unreachable!()
            }
            fn exchange(&self, _: Vec<u8>) -> crate::resolver::DnsExchangeFuture {
                let result = self.0.clone();
                Box::pin(async move { result.map_err(io::Error::from) })
            }
        }

        let mut response = Message::query().into_response();
        response.metadata.truncation = true;
        let first = response.to_vec().unwrap();
        response.metadata.id = 1;
        let second = response.to_vec().unwrap();
        response.metadata.truncation = false;
        let complete = response.to_vec().unwrap();
        let mut cases = vec![
            (Ok(complete.clone()), complete),
            (Ok(second), first.clone()),
            (Err(ErrorKind::TimedOut), first.clone()),
        ];
        for code in [
            ResponseCode::NXDomain,
            ResponseCode::ServFail,
            ResponseCode::Refused,
            ResponseCode::FormErr,
            ResponseCode::NotImp,
        ] {
            response.metadata.response_code = code;
            let fallback = response.to_vec().unwrap();
            let expected = if code == ResponseCode::NXDomain {
                fallback.clone()
            } else {
                first.clone()
            };
            cases.push((Ok(fallback), expected));
        }
        for (fallback, expected) in cases {
            let resolver = CompositeResolver::new(vec![
                Arc::new(WireReply(Ok(first.clone()))),
                Arc::new(WireReply(fallback)),
            ]);
            assert_eq!(resolver.exchange(vec![]).await.unwrap(), expected);
        }
        let resolver =
            CompositeResolver::new(vec![Arc::new(WireReply(Ok(response.to_vec().unwrap())))]);
        assert_eq!(
            resolver.exchange(vec![]).await.unwrap(),
            response.to_vec().unwrap()
        );
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
