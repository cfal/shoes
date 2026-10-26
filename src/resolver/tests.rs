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
    let resolver = TimeoutResolver::with_timeout(MockResolver::with_addrs(vec![]), Duration::MAX);
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
            Ok(Arc::new(MockResolver::with_error(std::io::ErrorKind::Other)) as Arc<dyn Resolver>)
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
        Box::pin(async move { Ok(Arc::new(MockResolver::with_addrs(addrs)) as Arc<dyn Resolver>) })
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
