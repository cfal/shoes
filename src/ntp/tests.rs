use super::*;
use std::sync::atomic::AtomicUsize;

#[derive(Clone, Copy)]
enum Reply {
    Offset(i64),
    KissOfDeath([u8; 4]),
    Mutate(fn(&mut Vec<u8>)),
    Silent,
    WrongSource,
}

struct FakeServer {
    address: SocketAddr,
    reply: Arc<Mutex<Reply>>,
    requests: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl FakeServer {
    async fn new(reply: Reply) -> Self {
        Self::bind("127.0.0.1:0", reply).await
    }

    async fn bind(address: &str, reply: Reply) -> Self {
        let socket = UdpSocket::bind(address).await.unwrap();
        let address = socket.local_addr().unwrap();
        let state = Arc::new(Mutex::new(reply));
        let requests = Arc::new(AtomicUsize::new(0));
        let task = {
            let state = state.clone();
            let requests = requests.clone();
            tokio::spawn(async move {
                let mut request = [0; 48];
                loop {
                    let (count, peer) = socket.recv_from(&mut request).await.unwrap();
                    assert_eq!(count, 48);
                    requests.fetch_add(1, Ordering::Relaxed);
                    let mode = *state.lock();
                    if matches!(mode, Reply::Silent) {
                        continue;
                    }
                    let mut reply = vec![0; 48];
                    reply[0] = 0x24;
                    reply[1] = 1;
                    reply[3] = (-20i8) as u8;
                    reply[24..32].copy_from_slice(&request[40..48]);
                    let offset = match mode {
                        Reply::Offset(seconds) => seconds,
                        _ => 0,
                    };
                    // Independent server time makes corrected-client feedback observable.
                    let raw = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap();
                    let seconds = (raw.as_secs() as i64 + 2_208_988_800 + offset) as u32;
                    let fraction = (u64::from(raw.subsec_nanos()) << 32) / 1_000_000_000;
                    let stamp = ((u64::from(seconds) << 32) | fraction).to_be_bytes();
                    reply[32..40].copy_from_slice(&stamp);
                    reply[40..48].copy_from_slice(&stamp);
                    if let Reply::Mutate(mutate) = mode {
                        mutate(&mut reply);
                    }
                    if let Reply::KissOfDeath(code) = mode {
                        reply[0] = 0xe4;
                        reply[1] = 0;
                        reply[12..16].copy_from_slice(&code);
                        reply[32..48].fill(0);
                    }
                    if matches!(mode, Reply::WrongSource) {
                        let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                        other.send_to(&reply, peer).await.unwrap();
                    } else {
                        socket.send_to(&reply, peer).await.unwrap();
                    }
                }
            })
        };
        Self {
            address,
            reply: state,
            requests,
            task,
        }
    }

    fn config(&self) -> NtpConfig {
        NtpConfig {
            server: crate::address::NetLocation::from_ip_addr(
                self.address.ip(),
                self.address.port(),
            ),
            interval_secs: 60,
            timeout_secs: 1,
        }
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::Relaxed)
    }
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn positive_and_negative_offsets_use_raw_time_on_each_exchange() {
    for seconds in [600, -600] {
        let server = FakeServer::new(Reply::Offset(seconds)).await;
        for _ in 0..2 {
            let offset = query(&server.config(), Arc::from([])).await.unwrap();
            assert!(offset.abs_diff(seconds * 1_000_000) < 250_000, "{offset}");
        }
        assert_eq!(server.requests(), 2);
    }
}

#[tokio::test]
async fn ntp_exchange_supports_ipv6() {
    let server = FakeServer::bind("[::1]:0", Reply::Offset(600)).await;
    let offset = query(&server.config(), Arc::from([])).await.unwrap();
    assert!(offset.abs_diff(600_000_000) < 250_000, "{offset}");
}

#[tokio::test]
async fn malformed_responses_never_produce_offsets() {
    let cases: &[fn(&mut Vec<u8>)] = &[
        |p| {
            p.truncate(47);
        },
        |p| p.resize(49, 0),
        |p| p.resize(2048, 0),
        |p| p[24] ^= 1,
        |p| p[0] = 0x23,
        |p| p[0] = 4,
        |p| p[0] = (5 << 3) | 4,
        |p| p[0] |= 0xc0,
        |p| p[1] = 16,
        |p| p[32..40].fill(0),
        |p| p[40..48].fill(0),
        |p| p[8..12].copy_from_slice(&(16u32 << 16).to_be_bytes()),
        |p| {
            let transmit = u64::from_be_bytes(p[40..48].try_into().unwrap());
            p[16..24].copy_from_slice(&transmit.wrapping_add(1 << 32).to_be_bytes());
        },
    ];
    for (index, mutate) in cases.iter().enumerate() {
        let server = FakeServer::new(Reply::Mutate(*mutate)).await;
        assert!(
            query(&server.config(), Arc::from([])).await.is_err(),
            "case {index}"
        );
    }
}

#[tokio::test]
async fn timeout_wrong_source_and_resolved_range_guards() {
    for reply in [Reply::Silent, Reply::WrongSource] {
        let server = FakeServer::new(reply).await;
        let result = query(&server.config(), Arc::from([])).await;
        assert!(
            matches!(result, Err(QueryError::Io(error)) if error.kind() == io::ErrorKind::TimedOut)
        );
    }
    let server = FakeServer::new(Reply::Offset(600)).await;
    let ranges: Arc<[IpNetwork]> =
        vec!["127.0.0.0/8".parse().unwrap(), "::1/128".parse().unwrap()].into();
    assert!(query(&server.config(), ranges.clone()).await.is_err());
    let mut config = server.config();
    config.server = crate::address::NetLocation::from_str(
        &format!("localhost:{}", server.address.port()),
        None,
    )
    .unwrap();
    assert!(query(&config, ranges).await.is_err());
    assert_eq!(server.requests(), 0);
}

#[test]
fn raw_timestamp_failure_is_latched_across_generator_copies() {
    let invalid = AtomicBool::new(false);
    let mut clock = RawClock {
        sample: Duration::ZERO,
        invalid: &invalid,
    };
    clock.capture(SystemTime::UNIX_EPOCH + Duration::new(123, 456_000));
    assert_eq!(clock.timestamp_sec(), 123);
    assert_eq!(clock.timestamp_subsec_micros(), 456);
    let mut copy = clock;
    copy.capture(SystemTime::UNIX_EPOCH - Duration::from_secs(1));
    clock.capture(SystemTime::now());
    assert!(invalid.load(Ordering::Relaxed));
}

#[tokio::test]
async fn lifecycle_reuses_deadlines_retains_offsets_and_restores_publication() {
    const CHILD: &str = "SHOES_NTP_LIFECYCLE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        shoes_test_support::isolated::run_isolated(
            "ntp::tests::lifecycle_reuses_deadlines_retains_offsets_and_restores_publication",
            CHILD,
            "1",
        );
        return;
    }
    let raw = crate::clock::unix_seconds().unwrap();
    let server = FakeServer::new(Reply::Offset(600)).await;
    let prepared = Prepared::new(Some(server.config()), None);
    assert_eq!(server.requests(), 0);
    let mut running = prepared.start(Arc::from([])).await;
    let due = prepared.state.schedule.lock().next;
    assert!(crate::clock::unix_seconds().unwrap().abs_diff(raw + 600) <= 2);
    let offset = query(&server.config(), Arc::from([])).await.unwrap();
    assert!(
        offset.abs_diff(600_000_000) < 250_000,
        "corrected-clock feedback: {offset}"
    );
    running.stop().await;
    let same = Prepared::new(Some(server.config()), Some(&prepared));
    let mut replacement = same.start(Arc::from([])).await;
    drop(running);
    assert_eq!(server.requests(), 2);
    assert_eq!(same.state.schedule.lock().next, due);
    assert!(crate::clock::unix_seconds().unwrap().abs_diff(raw + 600) <= 2);
    *server.reply.lock() = Reply::Mutate(|p| p[24] ^= 1);
    refresh(&server.config(), &same.state, Arc::from([])).await;
    assert!(crate::clock::unix_seconds().unwrap().abs_diff(raw + 600) <= 2);
    replacement.stop().await;
    let next_server = FakeServer::new(Reply::Offset(1200)).await;
    let next = Prepared::new(Some(next_server.config()), Some(&same));
    let mut candidate = next.start(Arc::from([])).await;
    assert!(crate::clock::unix_seconds().unwrap().abs_diff(raw + 1200) <= 2);
    candidate.stop().await;
    let count = server.requests();
    let mut rollback = prepared.start(Arc::from([])).await;
    drop(candidate);
    drop(replacement);
    assert_eq!(server.requests(), count);
    assert!(crate::clock::unix_seconds().unwrap().abs_diff(raw + 600) <= 2);
    rollback.stop().await;
    let disabled = Prepared::new(None, Some(&prepared));
    let disabled_running = disabled.start(Arc::from([])).await;
    drop(rollback);
    prepared.state.clock.set_offset(3_600_000_000).unwrap();
    assert!(crate::clock::unix_seconds().unwrap().abs_diff(raw) <= 2);
    drop(disabled_running);
    assert!(crate::clock::unix_seconds().unwrap().abs_diff(raw) <= 2);
}

#[tokio::test]
async fn worker_refreshes_on_retained_deadline_and_stops_on_drop() {
    const CHILD: &str = "SHOES_NTP_WORKER_CHILD";
    if std::env::var_os(CHILD).is_none() {
        shoes_test_support::isolated::run_isolated(
            "ntp::tests::worker_refreshes_on_retained_deadline_and_stops_on_drop",
            CHILD,
            "1",
        );
        return;
    }
    let server = FakeServer::new(Reply::Offset(600)).await;
    let prepared = Prepared::new(Some(server.config()), None);
    let mut first = prepared.start(Arc::from([])).await;
    first.stop().await;
    *server.reply.lock() = Reply::Offset(-600);
    prepared.state.schedule.lock().next = Some(Instant::now() + Duration::from_millis(50));
    let same = Prepared::new(Some(server.config()), Some(&prepared));
    let mut running = same.start(Arc::from([])).await;
    drop(first);
    tokio::time::timeout(Duration::from_secs(2), async {
        while crate::clock::now().unwrap() > SystemTime::now() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(server.requests(), 2);
    running.stop().await;
    *server.reply.lock() = Reply::Silent;
    prepared.state.schedule.lock().next = Some(Instant::now());
    let running = same.start(Arc::from([])).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while server.requests() < 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    drop(running);
    assert!(
        crate::clock::unix_seconds().unwrap().abs_diff(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ) <= 1
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(server.requests(), 3);

    // Reusing the sample must not reuse the previous generation's resolver guards.
    prepared.state.schedule.lock().next = Some(Instant::now());
    let mut guarded = same
        .start(vec!["127.0.0.0/8".parse().unwrap()].into())
        .await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    guarded.stop().await;
    assert_eq!(server.requests(), 3);
}

#[cfg(all(unix, feature = "ffi"))]
#[tokio::test]
async fn ntp_protector_failure_sends_no_datagram() {
    const CHILD: &str = "SHOES_NTP_PROTECTOR_CHILD";
    if std::env::var_os(CHILD).is_none() {
        shoes_test_support::isolated::run_isolated(
            "ntp::tests::ntp_protector_failure_sends_no_datagram",
            CHILD,
            "1",
        );
        return;
    }
    let server = FakeServer::new(Reply::Offset(600)).await;
    crate::tun::set_global_socket_protector(Arc::new(crate::tun::FnSocketProtector::new(|_| {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "test protection failed",
        ))
    })));
    let result = query(&server.config(), Arc::from([])).await;
    assert!(
        matches!(result, Err(QueryError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied)
    );
    assert_eq!(server.requests(), 0);
}

#[tokio::test]
async fn clock_steps_reject_samples_but_cannot_mask_correlated_refusals() {
    let server = FakeServer::new(Reply::KissOfDeath(*b"DENY")).await;
    let start = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let elapsed = Duration::from_millis(10);
    for (invalid, end, message) in [
        (
            false,
            start + Duration::from_secs(2),
            "system clock changed",
        ),
        (
            false,
            start - Duration::from_secs(2),
            "system clock moved backward",
        ),
        (
            true,
            SystemTime::UNIX_EPOCH - Duration::from_secs(1),
            "before the Unix epoch",
        ),
    ] {
        let error = finish_exchange(Ok(600_000_000), invalid, start, end, elapsed).unwrap_err();
        assert!(error.to_string().contains(message), "{error}");
        let response = tokio::time::timeout(Duration::from_secs(1), exchange(server.address))
            .await
            .unwrap();
        let Err(QueryError::Protocol(refusal)) = response else {
            panic!("expected a correlated refusal");
        };
        assert!(matches!(
            finish_exchange(Err(refusal), invalid, start, end, elapsed),
            Err(QueryError::Protocol(sntpc::Error::KissOfDeath(
                sntpc::KissOfDeathCode::Deny
            )))
        ));
    }
    assert_eq!(
        finish_exchange(Ok(123), false, start, start + elapsed, elapsed).unwrap(),
        123
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn ntp_managed_resolution_failure_does_not_fall_back_to_native() {
    const CHILD: &str = "SHOES_NTP_BOOTSTRAP_CHILD";
    if std::env::var_os(CHILD).is_none() {
        shoes_test_support::isolated::run_isolated(
            "ntp::tests::ntp_managed_resolution_failure_does_not_fall_back_to_native",
            CHILD,
            "1",
        );
        return;
    }
    #[derive(Debug)]
    struct Unavailable;
    impl crate::resolver::Resolver for Unavailable {
        fn resolve_location(
            &self,
            _: &crate::address::NetLocation,
        ) -> crate::resolver::ResolveFuture {
            Box::pin(async { Err(io::Error::other("test bootstrap unavailable")) })
        }
    }
    let server = FakeServer::new(Reply::Offset(600)).await;
    let mut config = server.config();
    config.server = crate::address::NetLocation::from_str(
        &format!("localhost:{}", server.address.port()),
        None,
    )
    .unwrap();
    let _policy = crate::socket_policy::SocketPolicy::install(
        "test0".into(),
        0x40000000,
        0x60000000,
        vec![],
        Arc::new(Unavailable),
        vec![],
    )
    .unwrap();
    let error = query(&config, Arc::from([])).await.unwrap_err();
    assert!(
        error.to_string().contains("test bootstrap unavailable"),
        "{error}"
    );
    assert_eq!(server.requests(), 0);
}

#[tokio::test]
async fn kiss_of_death_with_zero_timestamps_stops_polling_across_reload() {
    const CHILD: &str = "SHOES_NTP_KOD_CHILD";
    if std::env::var_os(CHILD).is_none() {
        shoes_test_support::isolated::run_isolated(
            "ntp::tests::kiss_of_death_with_zero_timestamps_stops_polling_across_reload",
            CHILD,
            "1",
        );
        return;
    }
    for code in [*b"DENY", *b"RATE", *b"RSTR"] {
        let server = FakeServer::new(Reply::KissOfDeath(code)).await;
        let config = server.config();
        let prepared = Prepared::new(Some(config.clone()), None);
        prepared.state.clock.set_offset(600_000_000).unwrap();
        let mut running = prepared.start(Arc::from([])).await;
        assert!(prepared.state.schedule.lock().initialized);
        assert!(prepared.state.schedule.lock().next.is_none());
        let same = Prepared::new(Some(server.config()), Some(&prepared));
        assert!(Arc::ptr_eq(&same.state, &prepared.state));
        running.stop().await;
        let mut replacement = same.start(Arc::from([])).await;
        drop(running);
        tokio::task::yield_now().await;
        assert_eq!(server.requests(), 1);
        assert!(same.state.schedule.lock().next.is_none());
        assert!(crate::clock::now().unwrap() > SystemTime::now() + Duration::from_secs(599));
        replacement.stop().await;
    }
}
