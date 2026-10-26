use super::*;
use crate::config::{ClientChainHop, ClientConfig, ConfigSelection};
use crate::control::catalog::Catalog;
use crate::control::runtime::{ControlService, Generation};
use crate::option_util::OneOrSome;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn options() -> HealthCheckConfig {
    HealthCheckConfig {
        url: "http://192.0.2.1/".into(),
        interval_secs: 1,
        timeout_ms: 1000,
        expected_status: 204,
    }
}

fn chain(proxy: String, resolver: Arc<dyn Resolver>) -> ClientProxyChain {
    let client: ClientConfig =
        serde_json::from_value(serde_json::json!({"address":proxy, "protocol":{"type":"http"}}))
            .unwrap();
    crate::tcp::chain_builder::try_build_client_proxy_chain(
        OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(client))),
        resolver,
    )
    .unwrap()
}

fn view() -> Arc<SelectionView> {
    let mut view = SelectionView::default();
    view.health.definitions.insert(
        "out".into(),
        FallbackDefinition {
            members: vec!["proxy".into()],
            check: options(),
        },
    );
    Arc::new(view)
}

fn register(
    view: &SelectionView,
    index: u32,
    proxy: &str,
    options: &HealthCheckConfig,
    resolver: Arc<dyn Resolver>,
) -> Arc<ProbeJob> {
    let mut key = [0; 32];
    key[..4].copy_from_slice(&index.to_be_bytes());
    view.health
        .register(
            key,
            options,
            resolver.clone(),
            Vec::new(),
            Vec::new(),
            || chain(proxy.into(), resolver),
        )
        .unwrap()
}

async fn header(stream: &mut TcpStream) -> Vec<u8> {
    let mut data = Vec::new();
    while !data.ends_with(b"\r\n\r\n") {
        data.push(stream.read_u8().await.unwrap());
        assert!(data.len() < 4096);
    }
    data
}

#[test]
fn health_review9_samples_release_unrelated_choice_snapshots() {
    let view = view();
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    for (index, dynamic) in [
        Vec::new(),
        vec![vec![
            ("carrier".into(), "a".into()),
            ("child".into(), "x".into()),
        ]],
    ]
    .into_iter()
    .enumerate()
    {
        let job = view
            .health
            .register(
                [index as u8; 32],
                &options(),
                resolver.clone(),
                Vec::new(),
                dynamic,
                || chain("127.0.0.1:1".into(), resolver.clone()),
            )
            .unwrap();
        let choices = Arc::new(Choices::from([
            ("carrier".into(), "a".into()),
            ("child".into(), "x".into()),
            ("unrelated".into(), "first".into()),
        ]));
        let obsolete = Arc::downgrade(&choices);
        let mut current = (*choices).clone();
        job.record(Ok((1, true)), choices, Instant::now());
        assert!(obsolete.upgrade().is_none());
        current.insert("unrelated".into(), "second".into());
        assert_eq!(job.health(&current, Instant::now()), Health::Healthy);
        current.insert("child".into(), "y".into());
        assert_eq!(
            job.health(&current, Instant::now()),
            if index == 0 {
                Health::Healthy
            } else {
                Health::Unknown
            }
        );
    }
}

#[tokio::test]
async fn health_review9_dns_specs_share_checks_only_with_equivalent_bootstraps() {
    use serde_json::json;
    let mut configs = vec![json!({"client_group":"out", "type":"fallback",
        "health_check":{"url":"http://192.0.2.1/", "interval_secs":30},
        "client_proxies":[{"name":"proxy", "address":"192.0.2.10:80", "protocol":{"type":"http"}}]})];
    for (index, bootstrap) in [
        None,
        None,
        Some("udp://192.0.2.54"),
        Some("udp://192.0.2.54"),
        Some("udp://192.0.2.55"),
    ]
    .into_iter()
    .enumerate()
    {
        let name = format!("dns-{index}");
        configs.push(json!({"dns_group":name, "dns_servers":[
            {"url":"tcp://192.0.2.53", "bootstrap_url":bootstrap, "client_chain":"out"},
            {"url":"tcp://192.0.2.56", "bootstrap_url":bootstrap, "client_chain":"out"}
        ]}));
        configs.push(
            json!({"address":"127.0.0.1:0", "protocol":{"type":"socks"}, "dns":{"servers":name}}),
        );
    }
    let validated =
        crate::config::create_server_configs(serde_json::from_value(json!(configs)).unwrap())
            .unwrap();
    let view = validated.catalog.unwrap().selection;
    let registry = crate::dns::build_dns_registry(validated.dns_groups)
        .await
        .unwrap();
    let jobs: Vec<_> = view
        .health
        .jobs
        .lock()
        .values()
        .filter_map(Weak::upgrade)
        .collect();
    assert_eq!(
        jobs.len(),
        3,
        "one native and two distinct URL bootstrap policies"
    );
    assert_eq!(
        view.health
            .jobs
            .lock()
            .keys()
            .map(|key| key.path)
            .collect::<HashSet<_>>()
            .len(),
        1
    );
    for (index, job) in jobs.iter().enumerate() {
        assert!(
            jobs[..index]
                .iter()
                .all(|other| !Arc::ptr_eq(&other.resolver, &job.resolver))
        );
    }
    drop(jobs);
    drop(registry);
    assert!(
        view.health
            .jobs
            .lock()
            .values()
            .all(|job| job.upgrade().is_none())
    );
}

#[derive(Debug)]
struct PendingResolver(tokio::sync::mpsc::UnboundedSender<String>);

impl Resolver for PendingResolver {
    fn resolve_location(
        &self,
        location: &crate::address::NetLocation,
    ) -> crate::resolver::ResolveFuture {
        self.0.send(location.to_string()).unwrap();
        Box::pin(std::future::pending())
    }
}

#[derive(Debug)]
struct SelectorResolver(PendingResolver);

impl Resolver for SelectorResolver {
    fn manual_selector_paths(&self) -> Vec<ManualSelectorPath> {
        vec![vec![("dns".into(), "primary".into())]]
    }

    fn resolve_location(
        &self,
        location: &crate::address::NetLocation,
    ) -> crate::resolver::ResolveFuture {
        self.0.resolve_location(location)
    }
}

#[tokio::test(start_paused = true)]
async fn health_review6_inactive_to_inactive_dependencies_preserve_attempts_and_due() {
    use crate::control::selection::{SelectionOwner, SelectorDefinition};
    let mut owner = SelectionOwner::new(None).unwrap();
    let view = owner
        .prepare(BTreeMap::from([(
            "dns".into(),
            SelectorDefinition {
                members: vec!["primary".into(), "secondary".into(), "third".into()],
                default: None,
            },
        )]))
        .unwrap();
    owner.activate(view.clone()).unwrap();
    owner.select("dns", "secondary").unwrap();
    let (started, _calls) = tokio::sync::mpsc::unbounded_channel();
    let job = register(
        &view,
        0,
        "192.0.2.10:80",
        &options(),
        Arc::new(SelectorResolver(PendingResolver(started))),
    );
    let due = Instant::now() + Duration::from_secs(30);
    job.state.lock().due = due;
    job.record(Ok((1, true)), view.snapshot(), Instant::now());
    let revision = job.state.lock().revision;
    owner.select("dns", "third").unwrap();
    assert_eq!(job.state.lock().revision, revision);
    assert_eq!(job.state.lock().due, due);
    job.record_if_current(Ok((1, false)), view.snapshot(), Instant::now(), revision);
    assert_eq!(job.health(&view.snapshot(), Instant::now()), Health::Failed);

    for (index, member) in ["primary", "secondary"].into_iter().enumerate() {
        job.state.lock().due = due;
        owner.select("dns", member).unwrap();
        assert_eq!(job.state.lock().revision, revision + index as u64 + 1);
        assert_eq!(job.state.lock().due, Instant::now());
        job.record_if_current(Ok((1, true)), view.snapshot(), Instant::now(), revision);
        assert_eq!(job.health(&view.snapshot(), Instant::now()), Health::Failed);
    }
}

#[cfg(unix)]
#[tokio::test(start_paused = true)]
async fn health_review6_dns_carrier_dependencies_keep_enclosing_selector_conditions() {
    use crate::control::selection::SelectionOwner;
    use serde_json::json;
    let mut wireguard = crate::wireguard::test_support::client(51820);
    wireguard["client_proxies"][0]["protocol"]["peer_client_chain"] = json!("carrier");
    let mut validated = crate::config::create_server_configs(serde_json::from_value(json!([
        wireguard,
        {"client_group":"carrier", "type":"selector", "client_proxies":["direct", {
            "name":"proxy", "address":"192.0.2.10:80", "protocol":crate::wireguard::test_support::vless_protocol()
        }]},
        {"client_group":"dns-route", "type":"selector", "client_proxies":["direct", "wg"]},
        {"dns_group":"resolver", "dns_servers":[{"url":"tcp://192.0.2.53", "client_chain":"dns-route"}]},
        {"address":"127.0.0.1:0", "protocol":{"type":"socks"}, "dns":{"servers":"resolver"}}
    ])).unwrap()).unwrap();
    let _prepared = crate::wireguard::Prepared::new(&mut validated)
        .await
        .unwrap();
    let view = validated.catalog.as_ref().unwrap().selection.clone();
    let mut owner = SelectionOwner::new(None).unwrap();
    owner.activate(view.clone()).unwrap();
    let registry = crate::dns::build_dns_registry(std::mem::take(&mut validated.dns_groups))
        .await
        .unwrap();
    let resolver = registry.get_by_name("resolver").unwrap();
    let job = register(&view, 0, "192.0.2.10:80", &options(), resolver);
    let due = Instant::now() + Duration::from_secs(30);
    job.state.lock().due = due;
    job.record(Ok((1, true)), view.snapshot(), Instant::now());
    let revision = job.state.lock().revision;
    owner.select("carrier", "proxy").unwrap();
    assert_eq!(
        job.state.lock().revision,
        revision,
        "an inactive WireGuard carrier must not fence a probe"
    );
    assert_eq!(job.state.lock().due, due);
    job.record_if_current(Ok((1, false)), view.snapshot(), Instant::now(), revision);
    assert_eq!(job.health(&view.snapshot(), Instant::now()), Health::Failed);
    owner.select("dns-route", "wg").unwrap();
    assert_eq!(job.state.lock().revision, revision + 1);
    assert_eq!(job.state.lock().due, Instant::now());
    job.state.lock().due = due;
    owner.select("carrier", "DIRECT").unwrap();
    assert_eq!(job.state.lock().revision, revision + 2);
    assert_eq!(job.state.lock().due, Instant::now());
    job.record_if_current(Ok((1, true)), view.snapshot(), Instant::now(), revision + 1);
    assert_eq!(job.health(&view.snapshot(), Instant::now()), Health::Failed);
}

#[tokio::test]
async fn health_review3_resolver_aba_discards_completion_but_unrelated_changes_do_not() {
    use crate::control::selection::{SelectionOwner, SelectorDefinition};
    #[derive(Debug)]
    struct GatedResolver(Mutex<Option<tokio::sync::oneshot::Receiver<()>>>);
    impl Resolver for GatedResolver {
        fn manual_selector_paths(&self) -> Vec<ManualSelectorPath> {
            vec![vec![("dns".into(), "a".into())]]
        }
        fn resolve_location(
            &self,
            _: &crate::address::NetLocation,
        ) -> crate::resolver::ResolveFuture {
            let gate = self.0.lock().take().unwrap();
            Box::pin(async move {
                gate.await.unwrap();
                Err(io::ErrorKind::ConnectionRefused.into())
            })
        }
    }
    for changed in ["dns", "unrelated"] {
        let mut owner = SelectionOwner::new(None).unwrap();
        let view = owner
            .prepare(
                ["dns", "unrelated"]
                    .into_iter()
                    .map(|name| {
                        (
                            name.into(),
                            SelectorDefinition {
                                members: vec!["a".into(), "b".into()],
                                default: None,
                            },
                        )
                    })
                    .collect(),
            )
            .unwrap();
        owner.activate(view.clone()).unwrap();
        let (release, gate) = tokio::sync::oneshot::channel();
        let job = register(
            &view,
            0,
            "proxy.invalid:80",
            &options(),
            Arc::new(GatedResolver(Mutex::new(Some(gate)))),
        );
        let at = Instant::now();
        job.record(Ok((1, true)), view.snapshot(), at);
        let mut attempt = Box::pin(check(
            job.clone(),
            view.clone(),
            Arc::new(Semaphore::new(1)),
            &[],
        ));
        assert!(futures::poll!(&mut attempt).is_pending());
        owner.select(changed, "b").unwrap();
        owner.select(changed, "a").unwrap();
        release.send(()).unwrap();
        attempt.await;
        let expected = if changed == "dns" {
            Health::Healthy
        } else {
            Health::Failed
        };
        assert_eq!(
            job.health(&view.snapshot(), Instant::now()),
            expected,
            "{changed}"
        );
        if changed == "dns" {
            assert_eq!(job.state.lock().sample.as_ref().unwrap().at, at);
        }
    }
}

#[tokio::test(start_paused = true)]
async fn health_review_reselected_paths_are_checked_without_waiting_an_interval() {
    use crate::control::selection::{SelectionOwner, SelectorDefinition};
    let mut owner = SelectionOwner::new(None).unwrap();
    let view = owner
        .prepare(BTreeMap::from([(
            "manual".into(),
            SelectorDefinition {
                members: vec!["out".into(), "other".into()],
                default: None,
            },
        )]))
        .unwrap();
    owner.activate(view.clone()).unwrap();
    let (started, mut calls) = tokio::sync::mpsc::unbounded_channel();
    let resolver: Arc<dyn Resolver> = Arc::new(PendingResolver(started));
    let options = HealthCheckConfig {
        interval_secs: 30,
        ..options()
    };
    let job = view
        .health
        .register(
            [0; 32],
            &options,
            resolver.clone(),
            vec![("manual".into(), "out".into())],
            Vec::new(),
            || chain("proxy.invalid:80".into(), resolver),
        )
        .unwrap();
    job.record(Ok((1, true)), view.snapshot(), Instant::now());
    owner.select("manual", "other").unwrap();
    tokio::time::advance(options.freshness()).await;
    check(job.clone(), view.clone(), Arc::new(Semaphore::new(1)), &[]).await;
    assert_eq!(job.health(&view.snapshot(), Instant::now()), Health::Stale);
    let service = HealthService::start(view.clone(), Arc::new(Semaphore::new(1)), Vec::new());
    tokio::task::yield_now().await;
    owner.select("manual", "out").unwrap();
    let result = tokio::time::timeout(Duration::from_millis(10), calls.recv()).await;
    service.shutdown().await;
    assert_eq!(result.unwrap().unwrap(), "proxy.invalid:80");
}

#[tokio::test(start_paused = true)]
async fn health_review_changed_dependencies_recheck_once_without_hot_looping() {
    use crate::control::selection::{SelectionOwner, SelectorDefinition};
    for resolver_dependency in [false, true] {
        let mut owner = SelectionOwner::new(None).unwrap();
        let view = owner
            .prepare(BTreeMap::from([(
                "dns".into(),
                SelectorDefinition {
                    members: vec!["primary".into(), "backup".into()],
                    default: None,
                },
            )]))
            .unwrap();
        owner.activate(view.clone()).unwrap();
        let (started, mut calls) = tokio::sync::mpsc::unbounded_channel();
        let resolver: Arc<dyn Resolver> = if resolver_dependency {
            Arc::new(SelectorResolver(PendingResolver(started)))
        } else {
            Arc::new(PendingResolver(started))
        };
        let options = HealthCheckConfig {
            interval_secs: 30,
            ..options()
        };
        let job = view
            .health
            .register(
                [0; 32],
                &options,
                resolver.clone(),
                Vec::new(),
                if resolver_dependency {
                    Vec::new()
                } else {
                    vec![vec![("dns".into(), "primary".into())]]
                },
                || chain("proxy.invalid:80".into(), resolver),
            )
            .unwrap();
        let budget = Arc::new(Semaphore::new(1));
        check(job.clone(), view.clone(), budget.clone(), &[]).await;
        assert_eq!(calls.try_recv().unwrap(), "proxy.invalid:80");
        let service = HealthService::start(view.clone(), budget.clone(), Vec::new());
        tokio::task::yield_now().await;
        job.record(Ok((1, true)), view.snapshot(), Instant::now());
        owner.select("dns", "backup").unwrap();
        assert_eq!(
            job.health(&view.snapshot(), Instant::now()),
            if resolver_dependency {
                Health::Healthy
            } else {
                Health::Unknown
            }
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(10), calls.recv())
                .await
                .unwrap()
                .unwrap(),
            "proxy.invalid:80"
        );
        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        assert!(
            tokio::time::timeout(Duration::from_millis(10), calls.recv())
                .await
                .is_err()
        );
        service.shutdown().await;
        assert_eq!(budget.available_permits(), 1);
    }
}

#[tokio::test(start_paused = true)]
async fn health_review_queued_expiry_preserves_sample_but_full_budget_expiry_fails() {
    let view = view();
    let (started, mut calls) = tokio::sync::mpsc::unbounded_channel();
    let job = register(
        &view,
        0,
        "proxy.invalid:80",
        &options(),
        Arc::new(PendingResolver(started)),
    );
    let now = Instant::now();
    job.record(Ok((1, true)), view.snapshot(), now);
    let budget = Arc::new(Semaphore::new(1));
    let held = budget.acquire().await.unwrap();
    let mut attempt = Box::pin(check(job.clone(), view.clone(), budget.clone(), &[]));
    assert!(futures::poll!(&mut attempt).is_pending());
    tokio::time::advance(Duration::from_millis(900)).await;
    drop(held);
    assert!(futures::poll!(&mut attempt).is_pending());
    assert_eq!(calls.try_recv().unwrap(), "proxy.invalid:80");
    attempt.await;
    assert!(Instant::now() - now < Duration::from_millis(1100));
    assert_eq!(
        job.health(&view.snapshot(), Instant::now()),
        Health::Healthy
    );
    assert_eq!(job.state.lock().sample.as_ref().unwrap().at, now);
    assert_eq!(budget.available_permits(), 1);

    check(job.clone(), view.clone(), budget.clone(), &[]).await;
    assert_eq!(job.health(&view.snapshot(), Instant::now()), Health::Failed);
    assert_eq!(budget.available_permits(), 1);
}

#[tokio::test(start_paused = true)]
async fn health_review_scheduler_serves_every_waiting_job_before_repeating() {
    tokio::time::timeout(Duration::from_secs(16), async {
        let view = view();
        let (started, mut calls) = tokio::sync::mpsc::unbounded_channel();
        let resolver = Arc::new(PendingResolver(started));
        let options = HealthCheckConfig {
            timeout_ms: 5000,
            ..options()
        };
        let jobs: Vec<_> = (0..48)
            .map(|i| {
                register(
                    &view,
                    i,
                    &format!("proxy-{i}.invalid:80"),
                    &options,
                    resolver.clone(),
                )
            })
            .collect();
        let budget = Arc::new(Semaphore::new(16));
        let service = HealthService::start(view, budget.clone(), Vec::new());
        let mut seen = HashSet::new();
        for _ in 0..48 {
            seen.insert(calls.recv().await.unwrap());
        }
        service.shutdown().await;
        assert_eq!(budget.available_permits(), 16);
        assert_eq!(
            seen.len(),
            jobs.len(),
            "waiting jobs must precede repeat checks"
        );
    })
    .await
    .unwrap();
}

#[test]
fn health_local_admission_errors_never_condemn_a_path() {
    let view = view();
    let resolver = Arc::new(crate::resolver::NativeResolver::new());
    let job = register(&view, 0, "127.0.0.1:1", &options(), resolver);
    let now = Instant::now();
    for error in [
        crate::resources::exhausted(),
        crate::resources::quic_memory_exhausted(1024),
        io::Error::from(io::ErrorKind::WouldBlock),
        #[cfg(unix)]
        io::Error::from_raw_os_error(libc::EMFILE),
        #[cfg(unix)]
        io::Error::from_raw_os_error(libc::ENOBUFS),
    ] {
        job.record(Err(error), view.snapshot(), now);
        assert_eq!(job.health(&view.snapshot(), now), Health::Unknown);
    }
    job.record(Ok((1, true)), view.snapshot(), now);
    job.record(Err(crate::resources::exhausted()), view.snapshot(), now);
    assert_eq!(job.health(&view.snapshot(), now), Health::Healthy);
    assert_eq!(
        job.health(&view.snapshot(), now + options().freshness()),
        Health::Stale
    );
    job.record(
        Err(io::ErrorKind::ConnectionRefused.into()),
        view.snapshot(),
        now,
    );
    assert_eq!(job.health(&view.snapshot(), now), Health::Failed);
}

#[tokio::test]
async fn health_status_deadline_and_recovery_use_the_proxy_probe_engine() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let view = view();
        let resolver = Arc::new(crate::resolver::NativeResolver::new());
        let mut options = options();
        options.timeout_ms = 100;
        let job = register(&view, 0, &format!("127.0.0.1:{}", listener.local_addr().unwrap().port()), &options, resolver);
        let budget = Arc::new(Semaphore::new(16));
        for (status, expected) in [(503, Health::Failed), (204, Health::Healthy), (0, Health::Failed)] {
            let serve = async {
                let (mut stream, _) = listener.accept().await.unwrap();
                assert!(header(&mut stream).await.starts_with(b"CONNECT 192.0.2.1:80 HTTP/1.1"));
                stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.unwrap();
                assert!(header(&mut stream).await.starts_with(b"HEAD / HTTP/1.1"));
                if status != 0 {
                    stream.write_all(format!("HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
                }
                assert_eq!(stream.read(&mut [0;1]).await.unwrap(), 0);
            };
            let before = Instant::now();
            tokio::join!(serve, check(job.clone(), view.clone(), budget.clone(), &[]));
            let after = Instant::now();
            let due = job.state.lock().due;
            assert!(due >= before + Duration::from_millis(900));
            assert!(due <= after + Duration::from_millis(1100));
            assert_eq!(job.health(&view.snapshot(), Instant::now()), expected);
            assert_eq!(budget.available_permits(), 16);
        }
    }).await.unwrap();
}

#[tokio::test]
async fn health_scheduler_shares_admission_and_joins_cancelled_transports() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let proxy = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let view = view();
        let resolver = Arc::new(crate::resolver::NativeResolver::new());
        let options = HealthCheckConfig {
            timeout_ms: 5000,
            ..options()
        };
        let jobs: Vec<_> = (0..20)
            .map(|i| register(&view, i, &proxy, &options, resolver.clone()))
            .collect();
        let budget = Arc::new(Semaphore::new(16));
        let api_permits = budget.acquire_many(3).await.unwrap();
        let service = HealthService::start(view.clone(), budget.clone(), Vec::new());
        let mut streams = Vec::new();
        for _ in 0..13 {
            let (mut stream, _) = listener.accept().await.unwrap();
            header(&mut stream).await;
            streams.push(stream);
        }
        assert_eq!(budget.available_permits(), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
        service.shutdown().await;
        assert_eq!(budget.available_permits(), 13);
        for mut stream in streams {
            assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        }
        for job in &jobs {
            assert_eq!(
                job.health(&view.snapshot(), Instant::now()),
                Health::Unknown
            );
        }
        drop(api_permits);
        assert_eq!(budget.available_permits(), 16);
        let weak = Arc::downgrade(&view);
        drop(view);
        assert!(
            weak.upgrade().is_none(),
            "probe ownership must not retain its generation"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn health_scheduler_caps_active_checks_independently_of_admission() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let proxy = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let view = view();
        let resolver = Arc::new(crate::resolver::NativeResolver::new());
        let options = HealthCheckConfig {
            interval_secs: 60,
            timeout_ms: 5000,
            ..options()
        };
        let jobs: Vec<_> = (0..20)
            .map(|i| register(&view, i, &proxy, &options, resolver.clone()))
            .collect();
        let budget = Arc::new(Semaphore::new(20));
        let service = HealthService::start(view, budget.clone(), Vec::new());
        let mut streams = Vec::new();
        for _ in 0..16 {
            let (mut stream, _) = listener.accept().await.unwrap();
            header(&mut stream).await;
            streams.push(stream);
        }
        assert_eq!(budget.available_permits(), 4);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );

        drop(streams.pop().unwrap());
        let (mut replacement, _) = listener.accept().await.unwrap();
        header(&mut replacement).await;
        streams.push(replacement);
        assert_eq!(budget.available_permits(), 4);

        service.shutdown().await;
        assert_eq!(budget.available_permits(), 20);
        for mut stream in streams {
            assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        }
        drop(jobs);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn health_service_drop_aborts_probes_and_releases_admission() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let proxy = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let view = view();
        let job = register(
            &view,
            0,
            &proxy,
            &HealthCheckConfig {
                timeout_ms: 5000,
                ..options()
            },
            Arc::new(crate::resolver::NativeResolver::new()),
        );
        let budget = Arc::new(Semaphore::new(1));
        let service = HealthService::start(view.clone(), budget.clone(), Vec::new());
        let (mut stream, _) = listener.accept().await.unwrap();
        header(&mut stream).await;
        assert_eq!(budget.available_permits(), 0);

        drop(service);
        let permit = budget.acquire().await.unwrap();
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        assert_eq!(
            job.health(&view.snapshot(), Instant::now()),
            Health::Unknown
        );
        drop(permit);
        assert_eq!(budget.available_permits(), 1);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn health_reload_during_probes_releases_each_generation_without_a_controller() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let proxy = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let mut service = ControlService::new(Default::default()).unwrap();
        let mut previous = None;
        for id in 1..=4 {
            let view = view();
            let resolver = Arc::new(crate::resolver::NativeResolver::new());
            let job = register(&view, 0, &proxy, &options(), resolver.clone());
            let generation = Arc::new(Generation {
                id,
                catalog: Catalog {
                    nodes: Default::default(),
                    selection: view.clone(),
                },
                rules: Vec::new(),
                probes: super::super::probes::ProbeState::new(resolver, Vec::new()),
                leaf_udp_support: Default::default(),
            });
            service.runtime.begin_activation(&generation).await.unwrap();
            if let Some((old, mut stream, old_job)) = previous.take() {
                let old: Weak<Generation> = old;
                let stream: &mut TcpStream = &mut stream;
                assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
                assert_eq!(service.runtime.probes.available_permits(), 16);
                service.runtime.publish(generation.clone()).await.unwrap();
                assert!(old.upgrade().is_none());
                drop(old_job);
            } else {
                service.runtime.publish(generation.clone()).await.unwrap();
            }
            service.runtime.resume().await.unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();
            header(&mut stream).await;
            assert_eq!(
                job.health(&view.snapshot(), Instant::now()),
                Health::Unknown
            );
            previous = Some((Arc::downgrade(&generation), stream, job));
        }
        service.shutdown().await;
        assert_eq!(service.runtime.probes.available_permits(), 16);
        let (_, mut stream, _) = previous.unwrap();
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
    })
    .await
    .unwrap();
}

#[test]
fn health_registry_is_bounded_and_reclaims_unreferenced_jobs() {
    let view = view();
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    let options = options();
    let jobs: Vec<_> = (0..MAX_CHECKS as u32)
        .map(|i| register(&view, i, "127.0.0.1:1", &options, resolver.clone()))
        .collect();
    let result = view.health.register(
        [255; 32],
        &options,
        resolver.clone(),
        Vec::new(),
        Vec::new(),
        || panic!("must reject before constructing transport"),
    );
    let error = result.err().expect("job capacity must be enforced");
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(
        error.to_string(),
        "fallback exceeds 1024 active path checks"
    );
    assert!(error.get_ref().unwrap().is::<HealthCapacity>());
    drop(jobs);
    let _job = register(&view, 5000, "127.0.0.1:1", &options, resolver);
    assert_eq!(view.health.jobs.lock().len(), 1);
}

#[tokio::test]
async fn health_and_url_test_share_admission_and_stop_at_activation() {
    use crate::config::{GroupType, UrlTestConfig};
    use crate::control::catalog::CatalogNode;

    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let proxy = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let resolver = Arc::new(crate::resolver::NativeResolver::new());
        let mut view = view();
        let config = UrlTestConfig {
            url: options().url,
            interval: 30,
            timeout: 5000,
            tolerance: 50,
            lazy: false,
        };
        Arc::get_mut(&mut view)
            .unwrap()
            .automatic
            .insert("auto".into(), config.clone(), vec!["url-proxy".into()])
            .unwrap();
        let job = register(
            &view,
            0,
            &proxy,
            &HealthCheckConfig {
                timeout_ms: 5000,
                ..options()
            },
            resolver.clone(),
        );
        let client = serde_json::from_value(serde_json::json!({
            "address":proxy, "protocol":{"type":"http"}}))
        .unwrap();
        let generation = Arc::new(Generation {
            id: 1,
            catalog: Catalog {
                nodes: indexmap::IndexMap::from([
                    (
                        "auto".into(),
                        CatalogNode::Group {
                            members: vec!["url-proxy".into()],
                            group_type: GroupType::UrlTest(config),
                        },
                    ),
                    ("url-proxy".into(), CatalogNode::Leaf(Box::new(client))),
                ]),
                selection: view.clone(),
            },
            rules: Vec::new(),
            probes: super::super::probes::ProbeState::new(resolver, Vec::new()),
            leaf_udp_support: Default::default(),
        });
        let mut service = ControlService::new(Default::default()).unwrap();
        service.runtime.publish(generation.clone()).await.unwrap();
        service.runtime.resume().await.unwrap();
        let mut streams = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            header(&mut stream).await;
            streams.push(stream);
        }
        assert_eq!(service.runtime.probes.available_permits(), 14);
        service.runtime.begin_activation(&generation).await.unwrap();
        assert_eq!(service.runtime.probes.available_permits(), 16);
        for mut stream in streams {
            assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        }
        assert_eq!(
            job.health(&view.snapshot(), Instant::now()),
            Health::Unknown
        );
        assert_eq!(view.automatic.0["auto"].health("url-proxy"), "unprobed");
        service.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn health_probes_obey_manual_choices_after_waiting_for_admission() {
    use crate::control::selection::{SelectionOwner, SelectorDefinition};
    let mut owner = SelectionOwner::new(None).unwrap();
    let view = owner
        .prepare(BTreeMap::from([(
            "manual".into(),
            SelectorDefinition {
                members: vec!["pinned".into(), "other".into()],
                default: None,
            },
        )]))
        .unwrap();
    owner.activate(view.clone()).unwrap();
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let proxy = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    let options = options();
    let job = view
        .health
        .register(
            [0; 32],
            &options,
            resolver.clone(),
            vec![("manual".into(), "pinned".into())],
            Vec::new(),
            || chain(proxy, resolver),
        )
        .unwrap();
    let budget = Arc::new(Semaphore::new(1));
    let held = budget.acquire().await.unwrap();
    let task = check(job.clone(), view.clone(), budget.clone(), &[]);
    tokio::pin!(task);
    assert!(futures::poll!(&mut task).is_pending());
    owner.select("manual", "other").unwrap();
    drop(held);
    task.await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
    assert_eq!(
        job.health(&view.snapshot(), Instant::now()),
        Health::Unknown
    );
    assert_eq!(budget.available_permits(), 1);
}

#[tokio::test]
async fn health_refused_proxy_and_admission_timeout_have_distinct_results() {
    let closed = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    let proxy = format!("127.0.0.1:{}", closed.local_addr().unwrap().port());
    drop(closed);
    let view = view();
    let options = HealthCheckConfig {
        timeout_ms: 20,
        ..options()
    };
    let job = register(
        &view,
        0,
        &proxy,
        &options,
        Arc::new(crate::resolver::NativeResolver::new()),
    );
    let budget = Arc::new(Semaphore::new(1));
    let permit = budget.acquire().await.unwrap();
    check(job.clone(), view.clone(), budget.clone(), &[]).await;
    assert_eq!(
        job.health(&view.snapshot(), Instant::now()),
        Health::Unknown
    );
    drop(permit);
    check(job.clone(), view.clone(), budget.clone(), &[]).await;
    assert_eq!(job.health(&view.snapshot(), Instant::now()), Health::Failed);
    assert_eq!(budget.available_permits(), 1);
}
