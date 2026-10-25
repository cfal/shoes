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
        .register(key, options, resolver.clone(), Vec::new(), || {
            chain(proxy.into(), resolver)
        })
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
fn health_local_admission_errors_never_condemn_a_path() {
    let view = view();
    let resolver = Arc::new(crate::resolver::NativeResolver::new());
    let job = register(&view, 0, "127.0.0.1:1", &options(), resolver);
    let now = Instant::now();
    for error in [
        crate::resources::exhausted(),
        crate::resources::quic_memory_exhausted(1024),
        io::Error::from(io::ErrorKind::WouldBlock),
        io::Error::from_raw_os_error(libc::EMFILE),
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
        let mut service = HealthService::start(view.clone(), budget.clone(), Vec::new());
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
    let result = view
        .health
        .register([255; 32], &options, resolver.clone(), Vec::new(), || {
            panic!("must reject before constructing transport")
        });
    assert!(result.is_err());
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
