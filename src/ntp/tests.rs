use super::*;
use std::sync::atomic::AtomicUsize;

type PacketMutation = fn(&mut Vec<u8>);

#[derive(Clone, Copy)]
enum Reply {
    Offset(i64),
    DelayedOffset(i64, Duration),
    KissOfDeath([u8; 4]),
    Mutate(PacketMutation),
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
                        Reply::Offset(seconds) | Reply::DelayedOffset(seconds, _) => seconds,
                        _ => 0,
                    };
                    let stamp = server_timestamp(offset);
                    reply[32..40].copy_from_slice(&stamp);
                    let transmit = if let Reply::DelayedOffset(_, delay) = mode {
                        tokio::time::sleep(delay).await;
                        server_timestamp(offset)
                    } else {
                        stamp
                    };
                    reply[40..48].copy_from_slice(&transmit);
                    if let Reply::Mutate(mutate) = mode {
                        mutate(&mut reply);
                    }
                    if let Reply::KissOfDeath(code) = mode {
                        refusal(&mut reply, code);
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

fn server_timestamp(offset: i64) -> [u8; 8] {
    // Independent server time makes corrected-client feedback observable.
    let raw = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let seconds = (raw.as_secs() as i64 + 2_208_988_800 + offset) as u32;
    let fraction = (u64::from(raw.subsec_nanos()) << 32) / 1_000_000_000;
    ((u64::from(seconds) << 32) | fraction).to_be_bytes()
}

fn refusal(packet: &mut [u8], code: [u8; 4]) {
    packet[0] = 0xe4;
    packet[1] = 0;
    packet[12..16].copy_from_slice(&code);
    packet[32..48].fill(0);
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[test]
fn ntp_error_messages_distinguish_network_failures_from_invalid_responses() {
    assert_eq!(
        QueryError::Protocol(sntpc::Error::Network).to_string(),
        "NTP socket send/receive failed"
    );
    assert_eq!(
        QueryError::Protocol(sntpc::Error::IncorrectPayload).to_string(),
        "invalid NTP response: IncorrectPayload"
    );
    assert_eq!(
        QueryError::Io(io::Error::other("socket creation failed")).to_string(),
        "socket creation failed"
    );
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
async fn server_processing_time_does_not_bias_the_offset() {
    for seconds in [600, -600] {
        let delay = Duration::from_secs(1);
        let server = FakeServer::new(Reply::DelayedOffset(seconds, delay)).await;
        let mut config = server.config();
        config.timeout_secs = 3;
        let started = Instant::now();
        let offset = query(&config, Arc::from([])).await.unwrap();
        assert!(started.elapsed() >= delay);
        assert!(offset.abs_diff(seconds * 1_000_000) < 250_000, "{offset}");
        assert_eq!(server.requests(), 1);
    }
}

#[tokio::test]
async fn silent_addresses_share_the_deadline_without_starving_failover() {
    for reply in [Reply::Offset(600), Reply::Silent] {
        let first = FakeServer::new(Reply::Silent).await;
        let second = FakeServer::new(reply).await;
        let deadline = Instant::now() + Duration::from_secs(1);
        let result = timeout_at(
            deadline + Duration::from_millis(500),
            query_addresses(&[first.address, second.address], deadline),
        )
        .await
        .expect("address attempts exceeded the shared deadline");
        if matches!(reply, Reply::Silent) {
            assert!(
                matches!(result, Err(QueryError::Io(error)) if error.kind() == io::ErrorKind::TimedOut)
            );
        } else {
            assert!(result.unwrap().abs_diff(600_000_000) < 250_000);
        }
        assert_eq!(first.requests(), 1);
        assert_eq!(second.requests(), 1);
    }
}

#[tokio::test]
async fn ntp_exchange_supports_ipv6() {
    let server = FakeServer::bind("[::1]:0", Reply::Offset(600)).await;
    let offset = query(&server.config(), Arc::from([])).await.unwrap();
    assert!(offset.abs_diff(600_000_000) < 250_000, "{offset}");
}

#[tokio::test]
async fn ntp_exchange_accepts_legacy_response_versions() {
    let versions: &[PacketMutation] = &[
        |packet| packet[0] = (1 << 3) | 4,
        |packet| packet[0] = (2 << 3) | 4,
        |packet| packet[0] = (3 << 3) | 4,
    ];
    for (index, mutate) in versions.iter().enumerate() {
        let server = FakeServer::new(Reply::Mutate(*mutate)).await;
        let offset = query(&server.config(), Arc::from([]))
            .await
            .unwrap_or_else(|error| panic!("NTPv{}: {error}", index + 1));
        assert!(offset.abs_diff(0) < 250_000, "{offset}");
        assert_eq!(server.requests(), 1);
    }
}

#[tokio::test]
async fn malformed_responses_never_produce_offsets() {
    use sntpc::Error::*;
    let cases: &[(PacketMutation, sntpc::Error)] = &[
        (|p| p.truncate(47), IncorrectPayload),
        (|p| p.resize(49, 0), IncorrectPayload),
        (|p| p.resize(2048, 0), IncorrectPayload),
        (|p| p[24] ^= 1, IncorrectOriginTimestamp),
        (|p| p[0] = 0x23, IncorrectMode),
        (|p| p[0] = 4, IncorrectResponseVersion),
        (|p| p[0] = (5 << 3) | 4, IncorrectResponseVersion),
        (|p| p[0] |= 0xc0, UnsynchronizedClock),
        (|p| p[1] = 16, IncorrectStratumHeaders),
        (|p| p[32..40].fill(0), InvalidTimestamp),
        (|p| p[40..48].fill(0), InvalidTimestamp),
        (
            |p| p[8..12].copy_from_slice(&(16u32 << 16).to_be_bytes()),
            ExcessiveRootDistance,
        ),
        (
            |p| {
                let transmit = u64::from_be_bytes(p[40..48].try_into().unwrap());
                p[16..24].copy_from_slice(&transmit.wrapping_add(1 << 32).to_be_bytes());
            },
            BackwardReferenceTimestamp,
        ),
    ];
    for (index, (mutate, expected)) in cases.iter().enumerate() {
        let server = FakeServer::new(Reply::Mutate(*mutate)).await;
        let error = query(&server.config(), Arc::from([])).await.unwrap_err();
        assert!(
            matches!(error, QueryError::Protocol(actual) if actual == *expected),
            "case {index}: expected {expected:?}, got {error:?}"
        );
    }
}

#[tokio::test]
async fn malformed_refusals_allow_failover_and_keep_polling() {
    use sntpc::Error::*;
    let cases: &[(PacketMutation, sntpc::Error)] = &[
        (
            |p| {
                refusal(p, *b"DENY");
                p[0] = 0xc4;
            },
            IncorrectResponseVersion,
        ),
        (
            |p| {
                refusal(p, *b"DENY");
                p[0] = 0xec;
            },
            IncorrectResponseVersion,
        ),
        (
            |p| {
                refusal(p, *b"DENY");
                p[0] = 0xe3;
            },
            IncorrectMode,
        ),
        (
            |p| {
                refusal(p, *b"DENY");
                p[24] ^= 1;
            },
            IncorrectOriginTimestamp,
        ),
        (
            |p| {
                refusal(p, *b"DENY");
                p.resize(49, 0);
            },
            IncorrectPayload,
        ),
    ];
    for (index, (mutate, expected)) in cases.iter().enumerate() {
        let first = FakeServer::new(Reply::Mutate(*mutate)).await;
        let second = FakeServer::new(Reply::Offset(600)).await;
        let config = first.config();
        let error = query(&config, Arc::from([])).await.unwrap_err();
        assert!(
            matches!(error, QueryError::Protocol(actual) if actual == *expected),
            "case {index}: expected {expected:?}, got {error:?}"
        );
        let prepared = Prepared::new(Some(config.clone()), None);
        let started = Instant::now();
        refresh(&config, &prepared.state, Arc::from([])).await;
        let interval = Duration::from_secs(config.interval_secs);
        let due = prepared.state.schedule.lock().next.unwrap();
        assert!(
            (started + interval..=Instant::now() + interval).contains(&due),
            "case {index}"
        );
        let deadline = Instant::now() + Duration::from_secs(1);
        let offset = timeout_at(
            deadline,
            query_addresses(&[first.address, second.address], deadline),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            offset.abs_diff(600_000_000) < 250_000,
            "case {index}: {offset}"
        );
        assert_eq!(first.requests(), 3);
        assert_eq!(second.requests(), 1);
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
    let unspecified = SocketAddr::from(([0, 0, 0, 0], server.address.port()));
    let error = query_addresses(&[unspecified], Instant::now() + Duration::from_secs(1))
        .await
        .unwrap_err();
    assert!(
        matches!(&error, QueryError::Io(error) if error.kind() == io::ErrorKind::InvalidInput),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .contains("server must be a unicast address")
    );
    assert_eq!(server.requests(), 0);
    let offset = query_addresses(
        &[unspecified, server.address],
        Instant::now() + Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert!(offset.abs_diff(600_000_000) < 250_000, "{offset}");
    assert_eq!(server.requests(), 1);
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
    let started = Instant::now();
    let mut running = prepared.start(Arc::from([])).await;
    let due = prepared.state.schedule.lock().next;
    let interval = Duration::from_secs(server.config().interval_secs);
    assert!((started + interval..=Instant::now() + interval).contains(&due.unwrap()));
    assert!(crate::clock::unix_seconds().unwrap().abs_diff(raw + 600) <= 2);
    let offset = query(&server.config(), Arc::from([])).await.unwrap();
    assert!(
        offset.abs_diff(600_000_000) < 250_000,
        "corrected-clock feedback: {offset}"
    );
    running.stop().await;
    assert!(crate::clock::unix_seconds().unwrap().abs_diff(raw + 600) <= 2);
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
    let has_negative_offset = || {
        let raw = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        crate::clock::unix_seconds().unwrap().abs_diff(raw - 600) <= 2
    };
    tokio::time::timeout(Duration::from_secs(2), async {
        while !has_negative_offset() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(server.requests(), 2);
    running.stop().await;
    *server.reply.lock() = Reply::Silent;
    for (index, stop) in [false, true].into_iter().enumerate() {
        let due = Some(Instant::now());
        prepared.state.schedule.lock().next = due;
        let mut running = same.start(Arc::from([])).await;
        let expected_requests = index + 3;
        tokio::time::timeout(Duration::from_secs(2), async {
            while server.requests() < expected_requests {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let worker = running.task.as_ref().unwrap().abort_handle();
        if stop {
            tokio::time::timeout(Duration::from_secs(2), running.stop())
                .await
                .expect("stopping the worker did not cancel its in-flight exchange");
            assert!(
                worker.is_finished(),
                "stop returned before the worker exited"
            );
            assert!(has_negative_offset());
        }
        drop(running);
        assert!(
            crate::clock::unix_seconds().unwrap().abs_diff(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            ) <= 1
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while !worker.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropping the worker did not cancel its in-flight exchange");
        assert_eq!(prepared.state.schedule.lock().next, due);
        assert_eq!(server.requests(), expected_requests);
    }

    // Reusing the sample must not reuse the previous generation's resolver guards.
    let forced = Instant::now();
    prepared.state.schedule.lock().next = Some(forced);
    let mut guarded = same
        .start(vec!["127.0.0.0/8".parse().unwrap()].into())
        .await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while prepared.state.schedule.lock().next == Some(forced) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("guarded worker never completed its refresh");
    guarded.stop().await;
    assert_eq!(server.requests(), 4);
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

#[cfg(target_os = "linux")]
#[tokio::test(start_paused = true)]
async fn ntp_deadline_cancels_pending_dns_resolution() {
    const CHILD: &str = "SHOES_NTP_DNS_DEADLINE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        shoes_test_support::isolated::run_isolated(
            "ntp::tests::ntp_deadline_cancels_pending_dns_resolution",
            CHILD,
            "1",
        );
        return;
    }
    #[derive(Debug)]
    struct PendingResolver {
        calls: AtomicUsize,
        cancelled: Arc<AtomicBool>,
    }
    struct Cancelled(Arc<AtomicBool>);
    impl Drop for Cancelled {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }
    impl crate::resolver::Resolver for PendingResolver {
        fn resolve_location(
            &self,
            _: &crate::address::NetLocation,
        ) -> crate::resolver::ResolveFuture {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let cancelled = Cancelled(self.cancelled.clone());
            Box::pin(async move {
                let _cancelled = cancelled;
                std::future::pending().await
            })
        }
    }
    let resolver = Arc::new(PendingResolver {
        calls: AtomicUsize::new(0),
        cancelled: Arc::new(AtomicBool::new(false)),
    });
    let _policy = crate::socket_policy::SocketPolicy::install(
        "test0".into(),
        0x40000000,
        0x60000000,
        vec![],
        resolver.clone(),
        vec![],
    )
    .unwrap();
    let config = NtpConfig {
        server: crate::address::NetLocation::from_str("localhost:123", None).unwrap(),
        interval_secs: 60,
        timeout_secs: 1,
    };
    let started = Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(2), query(&config, Arc::from([])))
        .await
        .expect("DNS resolution escaped the synchronization deadline");
    assert!(
        matches!(result, Err(QueryError::Io(error)) if error.kind() == io::ErrorKind::TimedOut)
    );
    assert!((Duration::from_secs(1)..=Duration::from_millis(1005)).contains(&started.elapsed()));
    assert_eq!(resolver.calls.load(Ordering::Relaxed), 1);
    assert!(resolver.cancelled.load(Ordering::Relaxed));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn ntp_resolved_tun_subnet_is_rejected_before_socket_creation() {
    const CHILD: &str = "SHOES_NTP_TUN_GUARD_CHILD";
    if std::env::var_os(CHILD).is_none() {
        shoes_test_support::isolated::run_isolated(
            "ntp::tests::ntp_resolved_tun_subnet_is_rejected_before_socket_creation",
            CHILD,
            "1",
        );
        return;
    }
    #[derive(Debug)]
    struct Resolved(SocketAddr);
    impl crate::resolver::Resolver for Resolved {
        fn resolve_location(
            &self,
            _: &crate::address::NetLocation,
        ) -> crate::resolver::ResolveFuture {
            Box::pin(std::future::ready(Ok(vec![self.0])))
        }
    }
    let server = FakeServer::new(Reply::Offset(600)).await;
    let mut config = server.config();
    config.server = crate::address::NetLocation::from_str("ntp.invalid:123", None).unwrap();
    #[cfg(feature = "ffi")]
    let protected = Arc::new(AtomicUsize::new(0));
    #[cfg(feature = "ffi")]
    {
        let calls = protected.clone();
        crate::tun::set_global_socket_protector(Arc::new(crate::tun::FnSocketProtector::new(
            move |_| {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            },
        )));
    }
    let _policy = crate::socket_policy::SocketPolicy::install(
        "test0".into(),
        0x40000000,
        0x60000000,
        vec!["127.0.0.0/8".parse().unwrap()],
        Arc::new(Resolved(server.address)),
        vec![],
    )
    .unwrap();
    let error = query(&config, Arc::from([])).await.unwrap_err();
    assert!(error.to_string().contains("managed TUN subnet"), "{error}");
    assert_eq!(server.requests(), 0);
    #[cfg(feature = "ffi")]
    assert_eq!(protected.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn ntp_changed_settings_inherit_the_last_active_sample() {
    const CHILD: &str = "SHOES_NTP_INHERIT_CHILD";
    if std::env::var_os(CHILD).is_none() {
        shoes_test_support::isolated::run_isolated(
            "ntp::tests::ntp_changed_settings_inherit_the_last_active_sample",
            CHILD,
            "1",
        );
        return;
    }
    for reply in [Reply::KissOfDeath(*b"DENY"), Reply::Mutate(|p| p[24] ^= 1)] {
        let server = FakeServer::new(Reply::Offset(600)).await;
        let previous = Prepared::new(Some(server.config()), None);
        let mut old = previous.start(Arc::from([])).await;
        let changed = FakeServer::new(reply).await;
        let candidate = Prepared::new(Some(changed.config()), Some(&previous));
        assert!(!Arc::ptr_eq(&candidate.state.clock, &previous.state.clock));
        *server.reply.lock() = Reply::Offset(1200);
        refresh(&server.config(), &previous.state, Arc::from([])).await;
        old.stop().await;
        let raw = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut running = candidate.start(Arc::from([])).await;
        assert!(crate::clock::unix_seconds().unwrap().abs_diff(raw + 1200) <= 2);
        running.stop().await;
        candidate.state.clock.set_offset(1_800_000_000).unwrap();
        let mut retry = candidate.start(Arc::from([])).await;
        drop(running);
        assert!(crate::clock::unix_seconds().unwrap().abs_diff(raw + 1800) <= 2);
        assert_eq!(changed.requests(), 1, "bind retry repeated synchronization");
        retry.stop().await;
        let mut rollback = previous.start(Arc::from([])).await;
        drop(retry);
        assert!(crate::clock::unix_seconds().unwrap().abs_diff(raw + 1200) <= 2);
        assert_eq!(server.requests(), 2, "rollback repeated synchronization");
        rollback.stop().await;
        drop(rollback);
        drop(old);
    }
}

#[tokio::test]
async fn ntp_status_codes_control_address_failover() {
    for (code, refused) in [
        (*b"DENY", true),
        (*b"RSTR", true),
        (*b"RATE", true),
        (*b"INIT", false),
        (*b"STEP", false),
        (*b"X123", false),
    ] {
        let first = FakeServer::new(Reply::KissOfDeath(code)).await;
        let second = FakeServer::new(Reply::Offset(600)).await;
        let deadline = Instant::now() + Duration::from_secs(1);
        let result = timeout_at(
            deadline,
            query_addresses(&[first.address, second.address], deadline),
        )
        .await
        .unwrap();
        assert_eq!(first.requests(), 1);
        if refused {
            assert!(matches!(
                result,
                Err(QueryError::Protocol(sntpc::Error::KissOfDeath(_)))
            ));
            assert_eq!(second.requests(), 0);
        } else {
            assert!(result.unwrap().abs_diff(600_000_000) < 250_000);
            assert_eq!(second.requests(), 1);
        }
    }
}

#[tokio::test]
async fn ntp_non_refusal_codes_retain_samples_and_retry_after_reload() {
    const CHILD: &str = "SHOES_NTP_STATUS_CHILD";
    if std::env::var_os(CHILD).is_none() {
        shoes_test_support::isolated::run_isolated(
            "ntp::tests::ntp_non_refusal_codes_retain_samples_and_retry_after_reload",
            CHILD,
            "1",
        );
        return;
    }
    for code in [*b"INIT", *b"STEP", *b"X123"] {
        let server = FakeServer::new(Reply::KissOfDeath(code)).await;
        let prepared = Prepared::new(Some(server.config()), None);
        prepared.state.clock.set_offset(600_000_000).unwrap();
        let mut running = prepared.start(Arc::from([])).await;
        assert!(prepared.state.schedule.lock().next.is_some());
        assert!(crate::clock::now().unwrap() > SystemTime::now() + Duration::from_secs(599));
        running.stop().await;
        *server.reply.lock() = Reply::Offset(1200);
        prepared.state.schedule.lock().next = Some(Instant::now());
        let same = Prepared::new(Some(server.config()), Some(&prepared));
        let mut replacement = same.start(Arc::from([])).await;
        drop(running);
        tokio::time::timeout(Duration::from_secs(2), async {
            while crate::clock::now().unwrap() < SystemTime::now() + Duration::from_secs(1199) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(server.requests(), 2);
        replacement.stop().await;
    }
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
        let prepared = Prepared::new(Some(server.config()), None);
        prepared.state.clock.set_offset(600_000_000).unwrap();
        let mut running = prepared.start(Arc::from([])).await;
        assert!(prepared.state.schedule.lock().initialized);
        assert!(prepared.state.schedule.lock().next.is_none());
        let same = Prepared::new(Some(server.config()), Some(&prepared));
        assert!(Arc::ptr_eq(&same.state, &prepared.state));
        running.stop().await;
        let mut replacement = same.start(Arc::from([])).await;
        drop(running);
        let worker = replacement.task.as_ref().unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !worker.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("refused worker did not stop after reload");
        assert_eq!(server.requests(), 1);
        assert!(same.state.schedule.lock().next.is_none());
        assert!(crate::clock::now().unwrap() > SystemTime::now() + Duration::from_secs(599));
        replacement.stop().await;
        *server.reply.lock() = Reply::Offset(1200);
        for (index, (interval_secs, timeout_secs)) in [(61, 1), (60, 2)].into_iter().enumerate() {
            let config = NtpConfig {
                interval_secs,
                timeout_secs,
                ..server.config()
            };
            let changed = Prepared::new(Some(config), Some(&same));
            assert!(!Arc::ptr_eq(&changed.state, &same.state));
            let mut restarted = changed.start(Arc::from([])).await;
            assert_eq!(server.requests(), index + 2);
            assert!(changed.state.schedule.lock().next.is_some());
            assert!(crate::clock::now().unwrap() > SystemTime::now() + Duration::from_secs(1199));
            restarted.stop().await;
        }
    }
}
