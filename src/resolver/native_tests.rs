use super::*;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::oneshot;

type LookupReply = std::io::Result<Vec<SocketAddr>>;

#[derive(Debug, Default)]
struct FakeLookup {
    calls: Mutex<Vec<NetLocation>>,
    replies: Mutex<VecDeque<oneshot::Sender<LookupReply>>>,
    active: Arc<AtomicUsize>,
}

struct ActiveLookup(Arc<AtomicUsize>);

impl Drop for ActiveLookup {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Resolver for FakeLookup {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        self.calls.lock().push(location.clone());
        self.active.fetch_add(1, Ordering::Relaxed);
        let active = ActiveLookup(self.active.clone());
        let (sender, receiver) = oneshot::channel();
        self.replies.lock().push_back(sender);
        Box::pin(async move {
            let _active = active;
            receiver.await.expect("fake lookup sender dropped")
        })
    }
}

impl FakeLookup {
    fn reply(&self, result: LookupReply) {
        self.replies
            .lock()
            .pop_front()
            .unwrap()
            .send(result)
            .unwrap();
    }

    fn calls(&self) -> usize {
        self.calls.lock().len()
    }

    fn discard_cancelled(&self) {
        assert!(self.replies.lock().pop_front().unwrap().is_closed());
    }
}

fn fixture(max_age_secs: u64) -> (CachingNativeResolver, Arc<FakeLookup>) {
    let lookup = Arc::new(FakeLookup::default());
    let mut resolver = CachingNativeResolver::with_timeout(max_age_secs);
    resolver.lookup = lookup.clone();
    (resolver, lookup)
}

fn location(port: u16) -> NetLocation {
    NetLocation::new(Address::Hostname("example.test".into()), port)
}

fn candidates() -> Vec<SocketAddr> {
    vec![
        "[2001:db8::1]:0".parse().unwrap(),
        "192.0.2.1:0".parse().unwrap(),
        SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            0,
            123,
            4,
        )),
        "192.0.2.1:0".parse().unwrap(),
        "[2001:db8::2]:0".parse().unwrap(),
    ]
}

fn assert_idle(resolver: &CachingNativeResolver, lookup: &FakeLookup) {
    assert!(resolver.state.lock().inflight.is_empty());
    assert_eq!(
        resolver.participants.available_permits(),
        CACHING_NATIVE_RESOLVER_MAX_PARTICIPANTS
    );
    assert_eq!(lookup.active.load(Ordering::Relaxed), 0);
}

async fn complete_lookup(resolver: &CachingNativeResolver, lookup: &FakeLookup, port: u16) {
    let mut future = resolver.resolve_location(&location(port));
    assert!(futures::poll!(&mut future).is_pending());
    lookup.reply(Ok(candidates()));
    assert_eq!(
        future.await.unwrap(),
        native_addrs_with_port(&candidates(), port)
    );
}

#[tokio::test]
async fn cold_misses_coalesce_across_ports_and_preserve_complete_candidates() {
    let (resolver, lookup) = fixture(60);
    let ports: Vec<u16> = (0..128).chain([443, u16::MAX]).collect();
    let mut futures: Vec<_> = ports
        .iter()
        .map(|&port| resolver.resolve_location(&location(port)))
        .collect();
    for future in &mut futures {
        assert!(futures::poll!(future).is_pending());
    }
    assert_eq!(lookup.calls(), 1);
    assert_eq!(lookup.calls.lock()[0], location(0));
    let mut addrs = candidates();
    addrs.insert(1, "0.0.0.0:0".parse().unwrap());
    addrs.push("[::]:0".parse().unwrap());
    lookup.reply(Ok(addrs));

    let owner = futures.remove(0);
    assert_eq!(owner.await.unwrap(), candidates());
    assert!(resolver.state.lock().inflight.is_empty());
    assert_eq!(
        resolver
            .state
            .lock()
            .cache
            .peek(location(0).address())
            .unwrap()
            .addrs
            .as_ref(),
        candidates()
    );
    // A new caller sees the cache even before subscribers consume the publication.
    let mut hit = resolver.resolve_location(&location(8080)).await.unwrap();
    assert_eq!(hit, native_addrs_with_port(&candidates(), 8080));
    hit.clear();
    for (future, &port) in futures.into_iter().zip(&ports[1..]) {
        assert_eq!(
            future.await.unwrap(),
            native_addrs_with_port(&candidates(), port)
        );
    }
    assert_eq!(lookup.calls(), 1);
    assert_eq!(resolver.state.lock().cache.len(), 1);
    assert_idle(&resolver, &lookup);
}

#[tokio::test]
async fn unpolled_miss_rechecks_cache_and_allocates_no_inflight_state() {
    let (resolver, lookup) = fixture(60);
    let unpolled = resolver.resolve_location(&location(80));
    assert_idle(&resolver, &lookup);
    complete_lookup(&resolver, &lookup, 443).await;
    assert_eq!(
        unpolled.await.unwrap(),
        native_addrs_with_port(&candidates(), 80)
    );
    assert_eq!(lookup.calls(), 1);
    assert_idle(&resolver, &lookup);
}

#[tokio::test]
async fn publisher_cancellation_reelects_exactly_one_subscriber() {
    let (resolver, lookup) = fixture(60);
    let mut owner = resolver.resolve_location(&location(80));
    assert!(futures::poll!(&mut owner).is_pending());
    let mut waiters: Vec<_> = (0..32)
        .map(|port| resolver.resolve_location(&location(port)))
        .collect();
    for waiter in &mut waiters {
        assert!(futures::poll!(waiter).is_pending());
    }
    drop(owner);
    lookup.discard_cancelled();
    assert!(resolver.state.lock().inflight.is_empty());
    for waiter in &mut waiters {
        assert!(futures::poll!(waiter).is_pending());
    }
    assert_eq!(lookup.calls(), 2);
    assert_eq!(resolver.state.lock().inflight.len(), 1);
    lookup.reply(Ok(candidates()));
    for (port, waiter) in waiters.into_iter().enumerate() {
        assert_eq!(
            waiter.await.unwrap(),
            native_addrs_with_port(&candidates(), port as u16)
        );
    }
    assert_idle(&resolver, &lookup);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_subscribers_wake_after_publisher_cancellation() {
    #[derive(Debug, Default)]
    struct RetryLookup(AtomicUsize);

    impl Resolver for RetryLookup {
        fn resolve_location(&self, _: &NetLocation) -> ResolveFuture {
            let call = self.0.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move {
                if call == 0 {
                    std::future::pending::<()>().await;
                }
                Ok(candidates())
            })
        }
    }

    let lookup = Arc::new(RetryLookup::default());
    let mut resolver = CachingNativeResolver::new();
    resolver.lookup = lookup.clone();
    let resolver = Arc::new(resolver);
    let mut owner = resolver.resolve_location(&location(80));
    assert!(futures::poll!(&mut owner).is_pending());

    let barrier = Arc::new(tokio::sync::Barrier::new(129));
    let mut tasks = Vec::new();
    for port in 0..128 {
        let resolver = resolver.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            let mut future = resolver.resolve_location(&location(port));
            assert!(futures::poll!(&mut future).is_pending());
            barrier.wait().await;
            assert_eq!(
                future.await.unwrap(),
                native_addrs_with_port(&candidates(), port)
            );
        }));
    }
    barrier.wait().await;
    assert_eq!(lookup.0.load(Ordering::Relaxed), 1);
    drop(owner);
    tokio::time::timeout(Duration::from_secs(5), async {
        for task in tasks {
            task.await.unwrap();
        }
    })
    .await
    .expect("subscribers remained stuck after cancellation");
    assert_eq!(lookup.0.load(Ordering::Relaxed), 2);
    assert!(resolver.state.lock().inflight.is_empty());
    assert_eq!(
        resolver.participants.available_permits(),
        CACHING_NATIVE_RESOLVER_MAX_PARTICIPANTS
    );
}

#[tokio::test]
async fn waiter_cancellation_and_all_callers_cancelling_release_state() {
    let (resolver, lookup) = fixture(60);
    let mut owner = resolver.resolve_location(&location(80));
    let mut waiter = resolver.resolve_location(&location(443));
    assert!(futures::poll!(&mut owner).is_pending());
    assert!(futures::poll!(&mut waiter).is_pending());
    drop(waiter);
    assert_eq!(
        resolver.participants.available_permits(),
        CACHING_NATIVE_RESOLVER_MAX_PARTICIPANTS - 1
    );
    assert_eq!(
        resolver
            .state
            .lock()
            .inflight
            .get(location(80).address())
            .unwrap()
            .receiver_count(),
        0
    );
    assert_eq!(lookup.active.load(Ordering::Relaxed), 1);
    lookup.reply(Ok(candidates()));
    owner.await.unwrap();
    assert_idle(&resolver, &lookup);

    resolver.state.lock().cache.clear();
    let mut owner = resolver.resolve_location(&location(80));
    let mut waiter = resolver.resolve_location(&location(443));
    assert!(futures::poll!(&mut owner).is_pending());
    assert!(futures::poll!(&mut waiter).is_pending());
    drop(owner);
    drop(waiter);
    lookup.discard_cancelled();
    assert_idle(&resolver, &lookup);
    complete_lookup(&resolver, &lookup, 443).await;
    assert_eq!(lookup.calls(), 3);
    assert_idle(&resolver, &lookup);
}

#[tokio::test]
async fn publisher_panic_closes_flight_and_allows_retry() {
    let (resolver, lookup) = fixture(60);
    let mut owner = resolver.resolve_location(&location(80));
    let mut waiter = resolver.resolve_location(&location(443));
    assert!(futures::poll!(&mut owner).is_pending());
    assert!(futures::poll!(&mut waiter).is_pending());
    drop(lookup.replies.lock().pop_front().unwrap());
    assert!(
        std::panic::AssertUnwindSafe(owner)
            .catch_unwind()
            .await
            .is_err()
    );
    assert!(resolver.state.lock().inflight.is_empty());
    assert!(futures::poll!(&mut waiter).is_pending());
    lookup.reply(Ok(candidates()));
    waiter.await.unwrap();
    assert_eq!(lookup.calls(), 2);
    assert_idle(&resolver, &lookup);
}

#[tokio::test(start_paused = true)]
async fn caller_deadlines_cancel_only_their_own_participation() {
    for owner_expires_first in [true, false] {
        let (resolver, lookup) = fixture(60);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let mut owner = resolver.resolve_location(&location(80));
        let mut waiter = resolver.resolve_location(&location(443));
        assert!(futures::poll!(&mut owner).is_pending());
        assert!(futures::poll!(&mut waiter).is_pending());
        let (expires, mut survivor) = if owner_expires_first {
            (owner, waiter)
        } else {
            (waiter, owner)
        };
        assert!(tokio::time::timeout_at(deadline, expires).await.is_err());
        assert!(futures::poll!(&mut survivor).is_pending());
        if owner_expires_first {
            lookup.discard_cancelled();
        }
        assert_eq!(lookup.calls(), if owner_expires_first { 2 } else { 1 });
        lookup.reply(Ok(candidates()));
        survivor.await.unwrap();
        assert_idle(&resolver, &lookup);
    }
}

#[tokio::test(start_paused = true)]
async fn timeout_wrapper_releases_owner_and_permit_before_subsequent_retry() {
    let (resolver, lookup) = fixture(60);
    let wrapper = TimeoutResolver::with_timeout(resolver, Duration::from_secs(1));
    assert_eq!(
        wrapper
            .resolve_location(&location(443))
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
    lookup.discard_cancelled();
    assert_idle(&wrapper.inner, &lookup);
    complete_lookup(&wrapper.inner, &lookup, 443).await;
    assert_idle(&wrapper.inner, &lookup);
}

#[tokio::test]
async fn failures_share_errno_kind_and_message_without_negative_caching() {
    for failure in [
        Err(std::io::Error::from_raw_os_error(libc::EMFILE)),
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "fake name not found",
        )),
        Ok(vec![]),
        Ok(vec![
            "0.0.0.0:0".parse().unwrap(),
            "[::]:0".parse().unwrap(),
        ]),
    ] {
        let (resolver, lookup) = fixture(60);
        let (kind, errno, message) = match &failure {
            Err(error) => (error.kind(), error.raw_os_error(), error.to_string()),
            Ok(_) => (
                std::io::ErrorKind::Other,
                None,
                "DNS lookup returned no addresses for example.test".into(),
            ),
        };
        let mut owner = resolver.resolve_location(&location(80));
        let mut waiter = resolver.resolve_location(&location(443));
        assert!(futures::poll!(&mut owner).is_pending());
        assert!(futures::poll!(&mut waiter).is_pending());
        lookup.reply(failure);
        let first_error = owner.await.unwrap_err();
        // A new flight can start before an old subscriber consumes its error.
        complete_lookup(&resolver, &lookup, 8080).await;
        let second_error = waiter.await.unwrap_err();
        for error in [first_error, second_error] {
            assert_eq!(error.kind(), kind);
            assert_eq!(error.raw_os_error(), errno);
            assert_eq!(error.to_string(), message);
        }
        assert_eq!(lookup.calls(), 2);
        assert_idle(&resolver, &lookup);
    }
}

#[tokio::test(start_paused = true)]
async fn result_age_starts_at_completion_hits_do_not_extend_it_and_zero_disables_reuse() {
    assert_eq!(CachingNativeResolver::DEFAULT_RESULT_TIMEOUT_SECS, 60);
    let (resolver, lookup) = fixture(60);
    let mut first = resolver.resolve_location(&location(80));
    assert!(futures::poll!(&mut first).is_pending());
    tokio::time::advance(Duration::from_secs(120)).await;
    lookup.reply(Ok(candidates()));
    first.await.unwrap();
    tokio::time::advance(Duration::from_secs(59)).await;
    assert_eq!(
        resolver.resolve_location(&location(443)).await.unwrap(),
        native_addrs_with_port(&candidates(), 443)
    );
    assert_eq!(lookup.calls(), 1);
    tokio::time::advance(Duration::from_secs(1)).await;
    let mut refreshed = resolver.resolve_location(&location(443));
    assert!(futures::poll!(&mut refreshed).is_pending());
    assert!(resolver.state.lock().cache.is_empty());
    lookup.reply(Ok(vec!["192.0.2.99:0".parse().unwrap()]));
    assert_eq!(
        refreshed.await.unwrap(),
        vec!["192.0.2.99:443".parse::<SocketAddr>().unwrap()]
    );
    assert_eq!(lookup.calls(), 2);
    assert_idle(&resolver, &lookup);

    let (resolver, lookup) = fixture(0);
    let mut first = resolver.resolve_location(&location(80));
    let mut second = resolver.resolve_location(&location(443));
    assert!(futures::poll!(&mut first).is_pending());
    assert!(futures::poll!(&mut second).is_pending());
    lookup.reply(Ok(candidates()));
    first.await.unwrap();
    second.await.unwrap();
    assert_eq!(lookup.calls(), 1);
    complete_lookup(&resolver, &lookup, 80).await;
    assert_eq!(lookup.calls(), 2);
    assert_idle(&resolver, &lookup);
}

#[tokio::test]
async fn cache_evicts_least_recent_host_and_keeps_exact_host_identity() {
    let (resolver, lookup) = fixture(60);
    resolver
        .state
        .lock()
        .cache
        .resize(NonZeroUsize::new(2).unwrap());
    for host in [
        "example.test",
        "EXAMPLE.test",
        "example.test",
        "example.test.",
    ] {
        let target = NetLocation::new(Address::Hostname(host.into()), 443);
        let mut future = resolver.resolve_location(&target);
        if host == "example.test" && lookup.calls() == 2 {
            future.await.unwrap();
            continue;
        }
        assert!(futures::poll!(&mut future).is_pending());
        lookup.reply(Ok(candidates()));
        future.await.unwrap();
    }
    let state = resolver.state.lock();
    assert_eq!(state.cache.len(), 2);
    assert!(
        state
            .cache
            .peek(&Address::Hostname("example.test".into()))
            .is_some()
    );
    assert!(
        state
            .cache
            .peek(&Address::Hostname("EXAMPLE.test".into()))
            .is_none()
    );
    assert!(
        state
            .cache
            .peek(&Address::Hostname("example.test.".into()))
            .is_some()
    );
    drop(state);
    assert_eq!(lookup.calls(), 3);
    let evicted = NetLocation::new(Address::Hostname("EXAMPLE.test".into()), 443);
    let mut retry = resolver.resolve_location(&evicted);
    assert!(futures::poll!(&mut retry).is_pending());
    lookup.reply(Ok(candidates()));
    retry.await.unwrap();
    assert_eq!(lookup.calls(), 4);
    assert_idle(&resolver, &lookup);
}

#[test]
fn default_cache_capacity_is_bounded() {
    let resolver = CachingNativeResolver::new();
    let mut state = resolver.state.lock();
    for index in 0..=CACHING_NATIVE_RESOLVER_CACHE_CAPACITY {
        state.cache.put(
            Address::Hostname(format!("{index}.test")),
            CachedResolveResult {
                timestamp: tokio::time::Instant::now(),
                addrs: Arc::from(candidates()),
            },
        );
    }
    assert_eq!(state.cache.len(), CACHING_NATIVE_RESOLVER_CACHE_CAPACITY);
    assert!(
        state
            .cache
            .peek(&Address::Hostname("0.test".into()))
            .is_none()
    );
}

#[tokio::test]
async fn participants_and_inflight_are_bounded_without_new_overload_errors() {
    for same_host in [true, false] {
        let (resolver, lookup) = fixture(60);
        let mut futures = Vec::new();
        for index in 0..CACHING_NATIVE_RESOLVER_MAX_PARTICIPANTS {
            let target = if same_host {
                location(index as u16)
            } else {
                NetLocation::new(Address::Hostname(format!("{index}.test")), 443)
            };
            let mut future = resolver.resolve_location(&target);
            assert!(futures::poll!(&mut future).is_pending());
            futures.push(future);
        }
        let expected = if same_host {
            1
        } else {
            CACHING_NATIVE_RESOLVER_MAX_PARTICIPANTS
        };
        assert_eq!(resolver.participants.available_permits(), 0);
        assert_eq!(resolver.state.lock().inflight.len(), expected);
        assert_eq!(lookup.calls(), expected);
        let mut overflow = resolver.resolve_location(&location(8443));
        assert!(futures::poll!(&mut overflow).is_pending());
        assert_eq!(lookup.calls(), expected + 1);
        assert_eq!(resolver.state.lock().inflight.len(), expected);
        lookup
            .replies
            .lock()
            .pop_back()
            .unwrap()
            .send(Ok(candidates()))
            .unwrap();
        assert_eq!(
            overflow.await.unwrap(),
            native_addrs_with_port(&candidates(), 8443)
        );
        // Overflow completion must not remove another caller's flight.
        assert_eq!(resolver.state.lock().inflight.len(), expected);
        assert_eq!(
            resolver.resolve_location(&location(80)).await.unwrap(),
            native_addrs_with_port(&candidates(), 80)
        );
        assert_eq!(resolver.participants.available_permits(), 0);
        drop(futures);
        for _ in 0..expected {
            lookup.discard_cancelled();
        }
        assert_idle(&resolver, &lookup);
        resolver.state.lock().cache.clear();
        complete_lookup(&resolver, &lookup, 443).await;
        assert_idle(&resolver, &lookup);
    }
}

#[tokio::test]
async fn numeric_literals_preserve_native_filtering_and_ports() {
    let resolver = CachingNativeResolver::new();
    for host in ["127.0.0.1", "::1"] {
        for port in [0, 80, u16::MAX] {
            let address = Address::from(host).unwrap();
            let target = NetLocation::new(address, port);
            assert_eq!(
                resolver.resolve_location(&target).await.unwrap(),
                vec![target.to_socket_addr_nonblocking().unwrap()]
            );
        }
    }
    for host in ["0.0.0.0", "::"] {
        let target = NetLocation::new(Address::from(host).unwrap(), 80);
        assert_eq!(
            resolver.resolve_location(&target).await.unwrap_err().kind(),
            std::io::ErrorKind::Other
        );
    }
    assert!(resolver.state.lock().inflight.is_empty());
    assert_eq!(
        resolver.participants.available_permits(),
        CACHING_NATIVE_RESOLVER_MAX_PARTICIPANTS
    );
}

#[tokio::test]
#[ignore = "manual native-cache microbenchmark; run under the shared heavy.lock"]
async fn benchmark_native_cache_hits_and_cold_miss_suppression() {
    let (resolver, lookup) = fixture(60);
    const CONCURRENCY: usize = 512;
    const ROUNDS: usize = 100;
    const HITS: usize = 100_000;
    let started = Instant::now();
    for _ in 0..ROUNDS {
        resolver.state.lock().cache.clear();
        let mut futures: Vec<_> = (0..CONCURRENCY)
            .map(|port| resolver.resolve_location(&location(port as u16)))
            .collect();
        for future in &mut futures {
            assert!(futures::poll!(future).is_pending());
        }
        lookup.reply(Ok(candidates()));
        for future in futures {
            std::hint::black_box(future.await.unwrap());
        }
    }
    let miss_elapsed = started.elapsed();
    assert_eq!(lookup.calls(), ROUNDS);
    let target = location(443);
    let started = Instant::now();
    for _ in 0..HITS {
        std::hint::black_box(
            resolver
                .resolve_location(std::hint::black_box(&target))
                .await
                .unwrap(),
        );
    }
    let hit_elapsed = started.elapsed();
    assert_eq!(lookup.calls(), ROUNDS);
    assert_idle(&resolver, &lookup);
    println!(
        "native-cache fixture: concurrency={CONCURRENCY}, rounds={ROUNDS}, cold_callers={}, lookup_calls={}, miss_elapsed_us={}, hits={HITS}, hit_elapsed_us={}, ns_per_hit={}",
        CONCURRENCY * ROUNDS,
        lookup.calls(),
        miss_elapsed.as_micros(),
        hit_elapsed.as_micros(),
        hit_elapsed.as_nanos() / HITS as u128
    );
}
