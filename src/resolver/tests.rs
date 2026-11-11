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
async fn exchange_returns_original_error_and_rebuilds_on_next_query() {
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
        },
        "exchange".into(),
    )
    .await
    .unwrap();
    let resolver = TimeoutResolver::with_timeout(resolver, Duration::from_secs(1));
    let error = resolver.exchange(vec![0]).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(error.to_string(), "mock exchange error");
    assert_eq!(calls.load(Ordering::Relaxed), 1);
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
            },
            "deadline".into(),
        )
        .await
        .unwrap();
        assert_eq!(
            resolver.exchange(vec![]).await.unwrap_err().kind(),
            std::io::ErrorKind::ConnectionReset
        );
        assert_eq!(builds.load(Ordering::Relaxed), 1);
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
        assert!(dns_caller_deadline(&error));
        assert_eq!(
            builds.load(Ordering::Relaxed),
            if hold_lock { 1 } else { 2 }
        );
        assert!(resolver.refresh_state.lock().invalidated);
    }
}

fn test_addrs() -> Vec<SocketAddr> {
    vec!["127.0.0.1:80".parse().unwrap()]
}

#[tokio::test]
async fn retained_setup_is_reused_until_a_confirmed_transport_failure() {
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
                    return Err(std::io::Error::new(kind, "setup outcome"));
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
        (Some(std::io::ErrorKind::TimedOut), true),
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
            },
            "failed retained setup".into(),
        )
        .await
        .unwrap();
        let error = resolver.exchange(vec![]).await.unwrap_err();
        assert!(dns_setup_pending(&error));
        assert_eq!(initial.calls.load(Ordering::Relaxed), 1);
        assert_eq!(builds.load(Ordering::Relaxed), 1);
        assert!(!resolver.refresh_state.lock().invalidated);
        assert!(resolver.refresh_state.lock().last_activity_at.is_none());

        let error = resolver.exchange(vec![]).await.unwrap_err();
        assert_eq!(initial.calls.load(Ordering::Relaxed), 2);
        assert_eq!(dns_setup_pending(&error), second_error.is_none());
        assert_eq!(
            error.kind(),
            second_error.unwrap_or(std::io::ErrorKind::TimedOut)
        );
        let refreshable =
            RefreshingResolver::should_refresh_for_error(&error) && !dns_setup_pending(&error);
        assert_eq!(resolver.refresh_state.lock().invalidated, refreshable);
        assert_eq!(builds.load(Ordering::Relaxed), 1);
        if refreshable {
            if factory_fails {
                for expected_builds in 2..=3 {
                    let error = resolver.exchange(vec![3]).await.unwrap_err();
                    assert_eq!(error.to_string(), "factory failed");
                    assert!(resolver.refresh_state.lock().invalidated);
                    assert_eq!(builds.load(Ordering::Relaxed), expected_builds);
                }
            } else {
                assert_eq!(resolver.exchange(vec![3]).await.unwrap(), vec![3]);
                assert_eq!(builds.load(Ordering::Relaxed), 2);
            }
            assert_eq!(initial.calls.load(Ordering::Relaxed), 2);
        }
    }
}

fn unique_location(index: usize) -> NetLocation {
    NetLocation::new(Address::Hostname(format!("host-{index}.example")), 443)
}

#[tokio::test]
async fn each_failed_generation_is_retired_without_eager_reconstruction() {
    #[derive(Debug)]
    struct Failed(Arc<AtomicUsize>);
    impl Resolver for Failed {
        fn resolve_location(&self, _: &NetLocation) -> ResolveFuture {
            unreachable!()
        }
        fn exchange(&self, _: Vec<u8>) -> DnsExchangeFuture {
            Box::pin(async { Err(std::io::ErrorKind::BrokenPipe.into()) })
        }
        fn retire(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let builds = Arc::new(AtomicUsize::new(0));
    let retirements = Arc::new(AtomicUsize::new(0));
    let factory: ResolverFactory = {
        let builds = builds.clone();
        let retirements = retirements.clone();
        Arc::new(move || {
            let generation = builds.fetch_add(1, Ordering::SeqCst);
            let retirements = retirements.clone();
            Box::pin(async move {
                Ok(if generation < 2 {
                    Arc::new(Failed(retirements)) as Arc<dyn Resolver>
                } else {
                    Arc::new(MockResolver::with_addrs(vec![]))
                })
            })
        })
    };
    let resolver = RefreshingResolver::new(
        factory,
        RefreshPolicy {
            max_idle: Duration::from_secs(60),
        },
        "final failure".into(),
    )
    .await
    .unwrap();
    for expected in 1..=2 {
        assert_eq!(
            resolver.exchange(vec![]).await.unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe
        );
        assert_eq!(builds.load(Ordering::SeqCst), expected);
        assert_eq!(retirements.load(Ordering::SeqCst), expected);
    }
    assert_eq!(resolver.exchange(vec![1]).await.unwrap(), vec![1]);
    assert_eq!(builds.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn concurrent_and_late_failures_only_retire_the_generation_they_used() {
    #[derive(Debug)]
    struct Gated {
        gates: Vec<Arc<tokio::sync::Semaphore>>,
        retired: Arc<AtomicUsize>,
    }
    impl Resolver for Gated {
        fn resolve_location(&self, _: &NetLocation) -> ResolveFuture {
            unreachable!()
        }
        fn exchange(&self, request: Vec<u8>) -> DnsExchangeFuture {
            let gate = self.gates[request[0] as usize].clone();
            Box::pin(async move {
                gate.acquire().await.unwrap().forget();
                if request[0] == 2 {
                    Ok(request)
                } else {
                    Err(std::io::ErrorKind::ConnectionReset.into())
                }
            })
        }
        fn retire(&self) {
            self.retired.fetch_add(1, Ordering::SeqCst);
        }
    }
    let gates: Vec<_> = (0..3)
        .map(|_| Arc::new(tokio::sync::Semaphore::new(0)))
        .collect();
    let retired = Arc::new(AtomicUsize::new(0));
    let initial: Arc<dyn Resolver> = Arc::new(Gated {
        gates: gates.clone(),
        retired: retired.clone(),
    });
    let builds = Arc::new(AtomicUsize::new(0));
    let factory: ResolverFactory = {
        let builds = builds.clone();
        Arc::new(move || {
            let generation = builds.fetch_add(1, Ordering::SeqCst);
            let initial = initial.clone();
            Box::pin(async move {
                Ok(if generation == 0 {
                    initial
                } else {
                    Arc::new(MockResolver::with_addrs(vec![]))
                })
            })
        })
    };
    let resolver = RefreshingResolver::new(
        factory,
        RefreshPolicy {
            max_idle: Duration::from_secs(60),
        },
        "concurrent failures".into(),
    )
    .await
    .unwrap();
    let mut calls: Vec<_> = (0..16).map(|_| resolver.exchange(vec![0])).collect();
    for call in &mut calls {
        assert!(futures::poll!(call).is_pending());
    }
    let mut late_error = resolver.exchange(vec![1]);
    let mut late_success = resolver.exchange(vec![2]);
    assert!(futures::poll!(&mut late_error).is_pending());
    assert!(futures::poll!(&mut late_success).is_pending());
    gates[0].add_permits(16);
    for call in calls {
        assert_eq!(
            call.await.unwrap_err().kind(),
            std::io::ErrorKind::ConnectionReset
        );
    }
    assert_eq!(builds.load(Ordering::SeqCst), 1);
    assert_eq!(resolver.exchange(vec![3]).await.unwrap(), vec![3]);
    assert_eq!(builds.load(Ordering::SeqCst), 2);
    assert_eq!(retired.load(Ordering::SeqCst), 1);
    resolver.refresh_state.lock().last_activity_at = None;
    gates[2].add_permits(1);
    assert_eq!(late_success.await.unwrap(), vec![2]);
    assert!(resolver.refresh_state.lock().last_activity_at.is_none());
    gates[1].add_permits(1);
    assert_eq!(
        late_error.await.unwrap_err().kind(),
        std::io::ErrorKind::ConnectionReset
    );
    assert_eq!(builds.load(Ordering::SeqCst), 2);
    assert_eq!(retired.load(Ordering::SeqCst), 1);
    assert!(!resolver.refresh_state.lock().invalidated);
}

#[tokio::test(start_paused = true)]
async fn logical_deadline_never_promotes_a_clipped_leaf_to_transport_failure() {
    #[derive(Debug)]
    struct Clipped {
        fail: bool,
        retired: Arc<AtomicUsize>,
    }
    impl Resolver for Clipped {
        fn resolve_location(&self, _: &NetLocation) -> ResolveFuture {
            unreachable!()
        }
        fn request_timeout(&self) -> Option<Duration> {
            Some(Duration::from_millis(200))
        }
        fn retire(&self) {
            self.retired.fetch_add(1, Ordering::SeqCst);
        }
        fn exchange_with_deadline(
            &self,
            _: Vec<u8>,
            deadline: tokio::time::Instant,
        ) -> DnsExchangeFuture {
            let fail = self.fail;
            Box::pin(async move {
                if fail {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    Err(std::io::ErrorKind::BrokenPipe.into())
                } else {
                    tokio::time::sleep_until(deadline).await;
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        DnsCallerDeadline,
                    ))
                }
            })
        }
    }
    for fail in [false, true] {
        let builds = Arc::new(AtomicUsize::new(0));
        let retired = Arc::new(AtomicUsize::new(0));
        let factory: ResolverFactory = {
            let builds = builds.clone();
            let retired = retired.clone();
            Arc::new(move || {
                let generation = builds.fetch_add(1, Ordering::SeqCst);
                let retired = retired.clone();
                Box::pin(async move {
                    if generation != 0 {
                        tokio::time::sleep(Duration::from_millis(60)).await;
                    }
                    Ok(Arc::new(Clipped {
                        fail: fail && generation == 0,
                        retired,
                    }) as Arc<dyn Resolver>)
                })
            })
        };
        let resolver = RefreshingResolver::new(
            factory,
            RefreshPolicy {
                max_idle: Duration::from_secs(60),
            },
            "clipped request".into(),
        )
        .await
        .unwrap();
        if fail {
            assert_eq!(
                resolver.exchange(vec![]).await.unwrap_err().kind(),
                std::io::ErrorKind::BrokenPipe
            );
            assert_eq!(builds.load(Ordering::SeqCst), 1);
        }
        let started = tokio::time::Instant::now();
        assert!(dns_caller_deadline(
            &resolver.exchange(vec![]).await.unwrap_err()
        ));
        assert_eq!(started.elapsed(), Duration::from_millis(200));
        assert_eq!(builds.load(Ordering::SeqCst), 1 + usize::from(fail));
        assert_eq!(retired.load(Ordering::SeqCst), usize::from(fail));
        assert!(!resolver.refresh_state.lock().invalidated);
    }
}

#[tokio::test(start_paused = true)]
async fn clipped_lookup_does_not_retire_a_healthy_replacement() {
    #[derive(Debug)]
    struct SlowLookup {
        fail: bool,
        retired: Arc<AtomicUsize>,
    }
    impl Resolver for SlowLookup {
        fn request_timeout(&self) -> Option<Duration> {
            Some(Duration::from_millis(200))
        }
        fn retire(&self) {
            self.retired.fetch_add(1, Ordering::SeqCst);
        }
        fn resolve_location(&self, _: &NetLocation) -> ResolveFuture {
            let fail = self.fail;
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(if fail { 100 } else { 60 })).await;
                if fail {
                    Err(std::io::ErrorKind::BrokenPipe.into())
                } else {
                    Ok(vec!["192.0.2.1:80".parse().unwrap()])
                }
            })
        }
    }
    let builds = Arc::new(AtomicUsize::new(0));
    let retired = Arc::new(AtomicUsize::new(0));
    let factory: ResolverFactory = {
        let builds = builds.clone();
        let retired = retired.clone();
        Arc::new(move || {
            let generation = builds.fetch_add(1, Ordering::SeqCst);
            let retired = retired.clone();
            Box::pin(async move {
                if generation != 0 {
                    tokio::time::sleep(Duration::from_millis(160)).await;
                }
                Ok(Arc::new(SlowLookup {
                    fail: generation == 0,
                    retired,
                }) as Arc<dyn Resolver>)
            })
        })
    };
    let resolver = RefreshingResolver::new(
        factory,
        RefreshPolicy {
            max_idle: Duration::from_secs(60),
        },
        "clipped lookup".into(),
    )
    .await
    .unwrap();
    assert_eq!(
        resolver
            .resolve_location(&test_location())
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::BrokenPipe
    );
    assert_eq!(builds.load(Ordering::SeqCst), 1);
    let mut clipped = resolver.resolve_location(&test_location());
    assert!(futures::poll!(&mut clipped).is_pending());
    tokio::time::advance(Duration::from_millis(160)).await;
    assert!(futures::poll!(&mut clipped).is_pending());
    let healthy = resolver.resolve_location(&test_location());
    let (clipped, healthy) = tokio::join!(clipped, healthy);
    assert!(dns_caller_deadline(&clipped.unwrap_err()));
    assert_eq!(
        healthy.unwrap(),
        vec!["192.0.2.1:80".parse::<SocketAddr>().unwrap()]
    );
    assert_eq!(builds.load(Ordering::SeqCst), 2);
    assert_eq!(retired.load(Ordering::SeqCst), 1);
    assert!(!resolver.refresh_state.lock().invalidated);
}

#[tokio::test(start_paused = true)]
async fn refresh_wait_prioritizes_expired_deadlines_but_preserves_inner_errors() {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let (send, receive) = tokio::sync::oneshot::channel();
    let mut wait = Box::pin(RefreshingResolver::refresh_wait(Some(deadline), receive));
    assert!(futures::poll!(&mut wait).is_pending());
    send.send(42).unwrap();
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(dns_caller_deadline(&wait.await.unwrap_err()));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let error = RefreshingResolver::refresh_wait(Some(deadline), async {
        Err::<(), _>(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "factory timeout",
        ))
    })
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(error.to_string(), "factory timeout");
    assert!(!dns_caller_deadline(&error));
}

#[tokio::test]
async fn concurrent_queries_coalesce_lazy_reconstruction_after_failure() {
    for cancel_owner in [false, true] {
        let initial = Arc::new(MockResolver::with_error(
            std::io::ErrorKind::ConnectionReset,
        ));
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
            },
            "concurrent lazy reconstruction".into(),
        )
        .await
        .unwrap();
        assert_eq!(
            resolver.exchange(vec![]).await.unwrap_err().kind(),
            std::io::ErrorKind::ConnectionReset
        );
        assert_eq!(builds.load(Ordering::Relaxed), 1);
        let mut first = resolver.exchange(vec![]);
        let mut second = resolver.exchange(vec![]);
        assert!(futures::poll!(&mut first).is_pending());
        assert!(futures::poll!(&mut second).is_pending());
        assert_eq!(initial.call_count.load(Ordering::Relaxed), 1);
        assert_eq!(builds.load(Ordering::Relaxed), 2);
        gate.add_permits(1);
        if cancel_owner {
            drop(first);
        } else {
            assert_eq!(first.await.unwrap(), Vec::<u8>::new());
        }
        let reply = tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .expect("coalesced waiter stranded after rebuild owner cancellation")
            .unwrap();
        assert_eq!(reply, Vec::<u8>::new());
        assert_eq!(initial.call_count.load(Ordering::Relaxed), 1);
        assert_eq!(
            fresh.call_count.load(Ordering::Relaxed),
            if cancel_owner { 1 } else { 2 }
        );
        assert_eq!(
            builds.load(Ordering::Relaxed),
            if cancel_owner { 3 } else { 2 }
        );
        assert!(!resolver.refresh_state.lock().invalidated);
    }
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
async fn test_refreshing_resolver_rebuilds_on_next_lookup_after_timeout() {
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
    };

    let resolver = RefreshingResolver::new(factory, policy, "test".to_string())
        .await
        .unwrap();

    assert_eq!(
        resolver
            .resolve_location(&test_location())
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
    assert_eq!(call_count.load(Ordering::Relaxed), 1);
    let result = resolver.resolve_location(&test_location()).await.unwrap();
    assert_eq!(result, success_addrs);
    // Factory called twice: initial build + refresh-on-error
    assert_eq!(call_count.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn non_refreshable_errors_preserve_the_generation_for_subsequent_queries() {
    for kind in [
        std::io::ErrorKind::Other,
        std::io::ErrorKind::InvalidData,
        std::io::ErrorKind::ConnectionRefused,
        std::io::ErrorKind::WouldBlock,
    ] {
        let initial = Arc::new(MockResolver::with_error(kind));
        let builds = Arc::new(AtomicUsize::new(0));
        let factory: ResolverFactory = {
            let initial = initial.clone();
            let builds = builds.clone();
            Arc::new(move || {
                builds.fetch_add(1, Ordering::Relaxed);
                let initial = initial.clone();
                Box::pin(async move { Ok(initial as Arc<dyn Resolver>) })
            })
        };
        let resolver = RefreshingResolver::new(
            factory,
            RefreshPolicy {
                max_idle: Duration::from_secs(60),
            },
            "non-refreshable error".into(),
        )
        .await
        .unwrap();

        assert_eq!(
            resolver
                .resolve_location(&test_location())
                .await
                .unwrap_err()
                .kind(),
            kind
        );
        assert_eq!(resolver.exchange(vec![]).await.unwrap_err().kind(), kind);
        assert_eq!(initial.call_count.load(Ordering::Relaxed), 2);
        assert_eq!(builds.load(Ordering::Relaxed), 1, "{kind:?}");
    }
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
async fn idle_refresh_failure_keeps_serving_the_healthy_generation() {
    let initial = Arc::new(MockResolver::with_addrs(test_addrs()));
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
                } else {
                    Err(std::io::Error::other("idle reconstruction failed"))
                }
            })
        })
    };
    let resolver = RefreshingResolver::new(
        factory,
        RefreshPolicy {
            max_idle: Duration::from_secs(60),
        },
        "idle reconstruction failure".into(),
    )
    .await
    .unwrap();
    assert_eq!(resolver.exchange(vec![1]).await.unwrap(), vec![1]);
    resolver.refresh_state.lock().last_activity_at = Some(Instant::now() - Duration::from_secs(61));
    assert_eq!(resolver.exchange(vec![2]).await.unwrap(), vec![2]);
    assert_eq!(resolver.exchange(vec![3]).await.unwrap(), vec![3]);
    assert_eq!(initial.call_count.load(Ordering::Relaxed), 3);
    assert_eq!(builds.load(Ordering::Relaxed), 2);
    let state = resolver.refresh_state.lock();
    assert!(!state.invalidated);
    assert!(Arc::ptr_eq(&state.current, &(initial as Arc<dyn Resolver>)));
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
