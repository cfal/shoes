use super::*;
use crate::config::ExpandedDnsSpec;
use crate::dns::parsed::{IpStrategy, ParsedDnsServer};
use crate::resolver::NativeResolver;
use crate::tcp::chain_builder::build_direct_chain_group;

/// Helper to build a shared chain group and bootstrap resolver for tests.
fn shared_test_deps() -> (
    Arc<crate::client_proxy_chain::ClientChainGroup>,
    Arc<dyn Resolver>,
) {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let chain = Arc::new(build_direct_chain_group(resolver.clone()));
    (chain, resolver)
}

fn make_entry(
    server: ParsedDnsServer,
    chain: &Arc<crate::client_proxy_chain::ClientChainGroup>,
    bootstrap: &Arc<dyn Resolver>,
) -> ParsedDnsServerEntry {
    ParsedDnsServerEntry::new(
        server,
        chain.clone(),
        bootstrap.clone(),
        IpStrategy::default(),
        5,
        5,
        1,
    )
}

fn make_spec(url: &str) -> ExpandedDnsSpec {
    ExpandedDnsSpec {
        url: url.to_string(),
        server_name: None,
        client_chains: vec![],
        bootstrap_url: None,
        ip_strategy: IpStrategy::default(),
        timeout_secs: 5,
        connect_timeout_secs: 5,
        attempts: 1,
        native_cache_secs: 0,
    }
}

#[tokio::test]
async fn health_review_dns_fallback_probes_use_the_forwarding_bootstrap() {
    #[derive(Debug)]
    struct Bootstrap(tokio::sync::mpsc::UnboundedSender<String>);
    impl Resolver for Bootstrap {
        fn resolve_location(
            &self,
            location: &crate::address::NetLocation,
        ) -> crate::resolver::ResolveFuture {
            self.0.send(location.to_string()).unwrap();
            Box::pin(std::future::pending())
        }
    }
    let configs = serde_json::from_value(serde_json::json!([
        {
            "client_group": "out",
            "type": "fallback",
            "health_check": {"url": "http://192.0.2.1/", "interval_secs": 30},
            "client_proxies": [{
                "address": "private-proxy.invalid:80",
                "protocol": {"type": "http"}
            }]
        },
        {
            "dns_group": "dns",
            "dns_servers": [{
                "url": "tcp://192.0.2.53",
                "bootstrap_url": "system",
                "client_chain": "out"
            }]
        },
        {
            "address": "127.0.0.1:0",
            "protocol": {"type": "socks"},
            "dns": {"servers": "dns"}
        }
    ]))
    .unwrap();
    let mut validated = crate::config::create_server_configs(configs).unwrap();
    let (sent, mut calls) = tokio::sync::mpsc::unbounded_channel();
    let mut registry = DnsRegistry::new();
    registry.register("system".into(), Arc::new(Bootstrap(sent)));
    let spec = &validated
        .dns_groups
        .iter()
        .find(|group| group.name == "dns")
        .unwrap()
        .specs[0];
    let (_entry, _plan) = build_entry_and_plan(spec, &registry, &mut FxHashMap::default())
        .await
        .unwrap();
    let service = crate::control::health::HealthService::start(
        validated.catalog.take().unwrap().selection,
        Arc::new(tokio::sync::Semaphore::new(16)),
        Vec::new(),
    );
    let result = tokio::time::timeout(Duration::from_millis(200), calls.recv()).await;
    service.shutdown().await;
    assert_eq!(result.unwrap().unwrap(), "private-proxy.invalid:80");
}

fn fake_groups(enabled: bool) -> Vec<ExpandedDnsGroup> {
    vec![ExpandedDnsGroup {
        name: "fake".into(),
        specs: vec![make_spec("system")],
        fake_ip: enabled.then(FakeIpOptions::default),
        use_default_resolver: false,
    }]
}

#[tokio::test]
async fn native_cache_policy_distinguishes_implicit_and_explicit_system() {
    for (dns, window) in [
        ("", Some(60)),
        ("dns: {}", Some(60)),
        ("dns: {servers: []}", Some(60)),
        ("dns: {servers: system}", None),
        ("dns: {servers: {url: system}}", None),
        ("dns: {servers: {url: system, native_cache_secs: 0}}", None),
        (
            "dns: {servers: {url: system, native_cache_secs: 7}}",
            Some(7),
        ),
    ] {
        let yaml = format!("- address: '127.0.0.1:1080'\n  protocol: {{type: socks}}\n  {dns}\n");
        let configs =
            crate::config::create_server_configs(serde_yaml::from_str(&yaml).unwrap()).unwrap();
        let mut registry = build_dns_registry(configs.dns_groups).await.unwrap();
        let crate::config::Config::Server(server) = &configs.configs[0] else {
            panic!("expected server")
        };
        let resolver = registry.get_for_server(server.dns.as_ref());
        let debug = format!("{resolver:?}");
        assert!(debug.contains("SystemResolver"), "{debug}");
        match window {
            Some(seconds) => {
                let expected =
                    format!("CachingNativeResolver {{ result_timeout_secs: {seconds} }}");
                assert!(debug.contains(&expected), "{dns}: {debug}");
            }
            None => assert!(!debug.contains("CachingNativeResolver"), "{dns}: {debug}"),
        }
        let literal = crate::address::NetLocation::from_str("127.0.0.1:443", None).unwrap();
        assert_eq!(
            resolver.resolve_location(&literal).await.unwrap(),
            vec!["127.0.0.1:443".parse::<std::net::SocketAddr>().unwrap()]
        );
    }
}

#[tokio::test]
async fn omitted_servers_keeps_default_cache_and_retired_pools_freeze_on_shutdown() {
    let configs = crate::config::create_server_configs(
        serde_yaml::from_str(
            "- address: '0.0.0.0:1080'\n  protocol: {type: socks}\n  dns: {fake_ip: false}\n",
        )
        .unwrap(),
    )
    .unwrap();
    assert!(configs.dns_groups[0].use_default_resolver);
    let name = configs.dns_groups[0].name.clone();
    let mut registry = build_dns_registry(configs.dns_groups).await.unwrap();
    assert!(Arc::ptr_eq(
        &registry.get_by_name(&name).unwrap(),
        &registry.get_or_create_default()
    ));

    let initial = build_dns_registry(fake_groups(true)).await.unwrap();
    let old = initial
        .get_by_name("fake")
        .unwrap()
        .fake_dns_context()
        .unwrap();
    old.allocate("before.test", false).unwrap();
    let removed = build_dns_registry_reusing(Vec::new(), initial.limits, Some(&initial))
        .await
        .unwrap();
    assert_eq!(removed.pools.len(), 1);
    removed.shutdown_checkpoint().await.unwrap();
    assert_eq!(
        old.allocate("after.test", false).unwrap_err().kind(),
        std::io::ErrorKind::BrokenPipe
    );
}

#[tokio::test]
async fn failed_pool_checkpoint_does_not_skip_other_pools() {
    let directory = tempfile::tempdir().unwrap();
    let mut pools = Vec::new();
    for index in 0..2 {
        let options = FakeIpOptions {
            state_file: Some(directory.path().join(format!("{index}.json"))),
            ..Default::default()
        };
        pools.push(Arc::new(FakeIpPool::new(&options).unwrap()));
    }
    std::fs::create_dir(directory.path().join("0.json")).unwrap();
    assert!(checkpoint_pools(pools).is_err());
    assert!(directory.path().join("1.json").is_file());
}

#[test]
fn snapshot_task_needs_persistent_pools() {
    let mut registry = DnsRegistry::new();
    assert!(registry.snapshot_task().0.is_none());
    let options = FakeIpOptions::default();
    registry.pools.insert(
        "memory".into(),
        PoolState {
            pool: Arc::new(FakeIpPool::new(&options).unwrap()),
            options,
        },
    );
    assert!(registry.snapshot_task().0.is_none());
}

#[tokio::test]
async fn disabling_and_removing_contexts_retains_real_only_guards() {
    let mut groups = fake_groups(true);
    groups[0].specs = vec![make_spec("udp://192.0.2.53")];
    let initial = build_dns_registry_for_runtime(
        groups,
        crate::resources::limits(),
        None,
        &["10.99.0.1".parse().unwrap()],
    )
    .await
    .unwrap();
    let disabled = build_dns_registry_reusing(fake_groups(false), initial.limits, Some(&initial))
        .await
        .unwrap();
    let mut removed = build_dns_registry_reusing(Vec::new(), initial.limits, Some(&disabled))
        .await
        .unwrap();
    assert_eq!(initial.forbidden_ranges(), removed.forbidden_ranges());
    let resolver = removed.get_or_create_default();
    for address in ["198.18.0.5:443", "10.99.0.1:443"] {
        assert_eq!(
            resolver
                .resolve_location(&crate::address::NetLocation::from_str(address, None).unwrap())
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidData
        );
    }
    for endpoint in ["udp://198.18.0.5", "udp://10.99.0.1"] {
        let mut groups = fake_groups(false);
        groups[0].specs = vec![make_spec(endpoint)];
        assert_eq!(
            build_dns_registry_reusing(groups, initial.limits, Some(&removed))
                .await
                .err()
                .unwrap()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
    }
}

#[tokio::test]
async fn literal_upstreams_cannot_target_tun_endpoints_outside_the_pool() {
    for endpoint in ["10.99.0.1", "::ffff:10.99.0.1"] {
        let mut groups = fake_groups(true);
        groups[0].specs = vec![make_spec("udp://10.99.0.1:53")];
        let failure = build_dns_registry_for_runtime(
            groups,
            crate::resources::limits(),
            None,
            &[endpoint.parse().unwrap()],
        )
        .await
        .err()
        .unwrap();
        assert_eq!(failure.kind(), std::io::ErrorKind::InvalidInput);
    }
}

#[tokio::test]
async fn fake_context_reload_sharing_disable_and_reenable_keep_pool_identity() {
    let initial = build_dns_registry(fake_groups(true)).await.unwrap();
    let context = initial
        .get_by_name("fake")
        .unwrap()
        .fake_dns_context()
        .unwrap();
    let ip = context.allocate("stable.test", false).unwrap();
    assert!(Arc::ptr_eq(
        &context,
        &initial
            .get_by_name("fake")
            .unwrap()
            .fake_dns_context()
            .unwrap()
    ));
    let mut updated = fake_groups(true);
    updated[0]
        .fake_ip
        .as_mut()
        .unwrap()
        .bypass_domains
        .push("new.test".into());
    let next = build_dns_registry_reusing(updated, initial.limits, Some(&initial))
        .await
        .unwrap();
    assert_eq!(
        next.get_by_name("fake")
            .unwrap()
            .fake_dns_context()
            .unwrap()
            .restore(ip)
            .unwrap()
            .as_deref(),
        Some("stable.test")
    );
    let disabled = build_dns_registry_reusing(fake_groups(false), initial.limits, Some(&next))
        .await
        .unwrap();
    assert!(
        disabled
            .get_by_name("fake")
            .unwrap()
            .fake_dns_context()
            .is_none()
    );
    let enabled = build_dns_registry_reusing(fake_groups(true), initial.limits, Some(&disabled))
        .await
        .unwrap();
    assert_eq!(
        enabled
            .get_by_name("fake")
            .unwrap()
            .fake_dns_context()
            .unwrap()
            .restore(ip)
            .unwrap()
            .as_deref(),
        Some("stable.test")
    );
    let mut incompatible = fake_groups(true);
    incompatible[0].fake_ip.as_mut().unwrap().max_entries -= 1;
    assert!(
        build_dns_registry_reusing(incompatible, initial.limits, Some(&enabled))
            .await
            .is_err()
    );
    assert_eq!(context.restore(ip).unwrap().as_deref(), Some("stable.test"));
}

#[tokio::test]
async fn equivalent_pool_ranges_reuse_live_mappings_on_reload() {
    let mut groups = fake_groups(true);
    groups[0].specs = vec![make_spec("udp://127.0.0.1:9")];
    groups[0].fake_ip.as_mut().unwrap().ipv6_range = Some("fd00::/64".into());
    let initial = build_dns_registry(groups.clone()).await.unwrap();
    let context = initial
        .get_by_name("fake")
        .unwrap()
        .fake_dns_context()
        .unwrap();
    let v4 = context.allocate("stable.test", false).unwrap();
    let v6 = context.allocate("stable.test", true).unwrap();
    groups[0].fake_ip.as_mut().unwrap().ipv6_range = Some("FD00:0::/64".into());
    let next = build_dns_registry_reusing(groups.clone(), initial.limits, Some(&initial))
        .await
        .unwrap();
    assert!(Arc::ptr_eq(
        &initial.pools["fake"].pool,
        &next.pools["fake"].pool
    ));
    let next_context = next
        .get_by_name("fake")
        .unwrap()
        .fake_dns_context()
        .unwrap();
    for ip in [v4, v6] {
        assert_eq!(
            next_context.restore(ip).unwrap().as_deref(),
            Some("stable.test")
        );
    }
    let options = groups[0].fake_ip.as_ref().unwrap();
    for incompatible in [
        FakeIpOptions {
            ipv4_range: Some("198.19.0.0/16".into()),
            ..options.clone()
        },
        FakeIpOptions {
            ipv6_range: Some("fd01::/64".into()),
            ..options.clone()
        },
        FakeIpOptions {
            ipv6_range: None,
            ..options.clone()
        },
        FakeIpOptions {
            max_entries: 32,
            ..options.clone()
        },
    ] {
        let mut candidate = groups.clone();
        candidate[0].fake_ip = Some(incompatible);
        let error = build_dns_registry_reusing(candidate, next.limits, Some(&next))
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("explicit restart required"));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn equivalent_snapshot_parent_paths_reuse_the_open_store_on_reload() {
    let directory = tempfile::tempdir().unwrap();
    let parent = directory.path().join("parent");
    let alias = directory.path().join("alias");
    std::fs::create_dir(&parent).unwrap();
    std::os::unix::fs::symlink(&parent, &alias).unwrap();
    let path = parent.join("state.json");
    let mut groups = fake_groups(true);
    groups[0].specs = vec![make_spec("udp://127.0.0.1:9")];
    groups[0].fake_ip.as_mut().unwrap().state_file = Some(path.clone());
    let initial = build_dns_registry(groups.clone()).await.unwrap();
    let context = initial
        .get_by_name("fake")
        .unwrap()
        .fake_dns_context()
        .unwrap();
    let ip = context.allocate("stable.test", false).unwrap();
    groups[0].fake_ip.as_mut().unwrap().state_file = Some(alias.join("state.json"));
    let next = build_dns_registry_reusing(groups.clone(), initial.limits, Some(&initial))
        .await
        .unwrap();
    assert!(Arc::ptr_eq(
        &initial.pools["fake"].pool,
        &next.pools["fake"].pool
    ));

    let file_alias = parent.join("alias.json");
    std::os::unix::fs::symlink(&path, &file_alias).unwrap();
    for state_file in [None, Some(parent.join("different.json")), Some(file_alias)] {
        let mut candidate = groups.clone();
        candidate[0].fake_ip.as_mut().unwrap().state_file = state_file;
        let error = build_dns_registry_reusing(candidate, next.limits, Some(&next))
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("explicit restart required"));
    }

    let other = directory.path().join("other");
    std::fs::create_dir(&other).unwrap();
    std::fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink(&other, &alias).unwrap();
    assert!(
        build_dns_registry_reusing(groups, next.limits, Some(&next))
            .await
            .is_err()
    );
    assert_eq!(context.restore(ip).unwrap().as_deref(), Some("stable.test"));
    next.checkpoint().await.unwrap();
    assert!(path.is_file());
    assert!(!other.join("state.json").exists());
}

#[tokio::test]
async fn named_fake_dns_fallback_uses_configured_exchange_and_refresh_wrapper() {
    use hickory_resolver::proto::op::{Message, Query, ResponseCode};
    use hickory_resolver::proto::rr::{Name, RecordType};
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut groups = fake_groups(true);
    groups[0].specs = vec![make_spec(&format!(
        "udp://{}",
        socket.local_addr().unwrap()
    ))];
    let registry = build_dns_registry(groups).await.unwrap();
    let server = tokio::spawn(async move {
        let mut bytes = [0; 2048];
        let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
        let mut answer = Message::from_vec(&bytes[..len]).unwrap().into_response();
        assert_eq!(answer.queries[0].query_type, RecordType::MX);
        answer.metadata.response_code = ResponseCode::NXDomain;
        socket
            .send_to(&answer.to_vec().unwrap(), peer)
            .await
            .unwrap();
    });
    let context = registry
        .get_by_name("fake")
        .unwrap()
        .fake_dns_context()
        .unwrap();
    let mut request = Message::query();
    request.add_query(Query::query(
        Name::from_ascii("mail.test").unwrap(),
        RecordType::MX,
    ));
    let reply = context
        .exchange(request.to_vec().unwrap(), true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        Message::from_vec(&reply).unwrap().metadata.response_code,
        ResponseCode::NXDomain
    );
    server.await.unwrap();
}

#[tokio::test]
async fn heterogeneous_group_retries_truncated_udp_over_configured_tcp() {
    use hickory_resolver::proto::op::{Message, Query, ResponseCode};
    use hickory_resolver::proto::rr::{Name, RecordType};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (tcp, udp) = crate::dns::bind_tcp_and_udp().await;
    let address = udp.local_addr().unwrap();
    let mut groups = fake_groups(true);
    let mut tcp_spec = make_spec(&format!("tcp://{address}"));
    tcp_spec.attempts = 2;
    groups[0].specs = vec![make_spec(&format!("udp://{address}")), tcp_spec];
    let registry = build_dns_registry(groups).await.unwrap();
    let server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        let mut bytes = [0; 2048];
        let (length, peer) = udp.recv_from(&mut bytes).await.unwrap();
        let mut answer = Message::from_vec(&bytes[..length]).unwrap().into_response();
        answer.metadata.truncation = true;
        udp.send_to(&answer.to_vec().unwrap(), peer).await.unwrap();

        let (mut stream, _) = tcp.accept().await.unwrap();
        let length = stream.read_u16().await.unwrap() as usize;
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).await.unwrap();
        let mut answer = Message::from_vec(&bytes).unwrap().into_response();
        answer.metadata.response_code = ResponseCode::NXDomain;
        let bytes = answer.to_vec().unwrap();
        stream.write_u16(bytes.len() as u16).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
    }));
    let context = registry
        .get_by_name("fake")
        .unwrap()
        .fake_dns_context()
        .unwrap();
    let mut request = Message::query();
    request.add_query(Query::query(
        Name::from_ascii("mail.test").unwrap(),
        RecordType::MX,
    ));
    let bytes = context
        .exchange(request.to_vec().unwrap(), true)
        .await
        .unwrap()
        .unwrap();
    let response = Message::from_vec(&bytes).unwrap();
    assert!(!response.metadata.truncation);
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    server.await.unwrap();
}

#[tokio::test]
async fn dns_bootstrap_uses_live_quic_admission_before_activation() {
    if std::env::var_os("SHOES_DNS_ADMISSION_TEST_CHILD").is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "dns::builder::tests::dns_bootstrap_uses_live_quic_admission_before_activation",
            ])
            .env("SHOES_DNS_ADMISSION_TEST_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = blackhole.local_addr().unwrap();
    let live = GlobalLimits {
        quic_memory_bytes: Some(1),
        ..Default::default()
    };
    let candidate = GlobalLimits {
        quic_memory_bytes: Some(64 << 20),
        ..live
    };
    crate::resources::configure(live).unwrap();
    for server in [
        format!("url: h3://{address}/dns-query"),
        format!(
            "url: tcp://127.0.0.1\n      client_chain:\n        address: '{address}'\n        transport: quic\n        protocol: {{type: socks}}"
        ),
    ] {
        let config = format!(
            "- dns_group: bootstrap\n  dns_servers:\n    - {server}\n      timeout_secs: 1\n      attempts: 1\n- dns_group: candidate\n  dns_servers:\n    - url: https://candidate.test/dns-query\n      bootstrap_url: bootstrap\n"
        );
        let validated =
            crate::config::create_server_configs(serde_yaml::from_str(&config).unwrap()).unwrap();
        let rejected = crate::resources::snapshot().quic_buffer_bytes.rejected;
        assert!(
            tokio::time::timeout(
                Duration::from_secs(5),
                build_dns_registry_with_limits(validated.dns_groups, candidate)
            )
            .await
            .unwrap()
            .is_err()
        );
        assert!(crate::resources::snapshot().quic_buffer_bytes.rejected > rejected);
        assert_eq!(crate::resources::snapshot().quic_buffer_bytes.active, 0);
        assert_eq!(
            crate::resources::limits().quic_memory_bytes,
            live.quic_memory_bytes
        );
        assert!(blackhole.try_recv(&mut [0; 1500]).is_err());
    }
}

#[tokio::test]
async fn prepared_dns_chains_use_candidate_quic_windows() {
    if std::env::var_os("SHOES_DNS_CANDIDATE_TEST_CHILD").is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "dns::builder::tests::prepared_dns_chains_use_candidate_quic_windows",
            ])
            .env("SHOES_DNS_CANDIDATE_TEST_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let config = format!(
        "- dns_group: candidate\n  dns_servers:\n    - url: tcp://127.0.0.1\n      client_chain:\n        address: '{}'\n        transport: quic\n        protocol: {{type: socks}}\n",
        blackhole.local_addr().unwrap()
    );
    crate::resources::configure(GlobalLimits {
        quic_memory_bytes: Some(1 << 20),
        ..Default::default()
    })
    .unwrap();
    for window in [65536, 131072] {
        let previous = crate::resources::limits();
        let candidate = GlobalLimits {
            quic_receive_window: window,
            quic_send_window: window,
            quic_stream_window: 16384,
            ..previous
        };
        let configs =
            crate::config::create_server_configs(serde_yaml::from_str(&config).unwrap()).unwrap();
        let registry = build_dns_registry_with_limits(configs.dns_groups, candidate)
            .await
            .unwrap();
        assert_eq!(
            crate::resources::limits().quic_receive_window,
            previous.quic_receive_window
        );
        let resolver = registry.get_by_name("candidate").unwrap();
        {
            let target = crate::address::NetLocation::from_str("candidate.test:80", None).unwrap();
            let lookup = resolver.resolve_location(&target);
            tokio::pin!(lookup);
            let mut packet = [0; 1500];
            tokio::select! {
                result = &mut lookup => panic!("lookup completed before QUIC packet: {result:?}"),
                result = tokio::time::timeout(std::time::Duration::from_secs(2), blackhole.recv(&mut packet)) => { result.unwrap().unwrap(); }
            }
            assert_eq!(
                crate::resources::snapshot().quic_buffer_bytes.active,
                window * 2 + (512 << 10)
            );
        }
        drop((resolver, registry));
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while crate::resources::snapshot().quic_buffer_bytes.active != 0 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        crate::resources::configure(candidate).unwrap();
        while blackhole.try_recv(&mut [0; 1500]).is_ok() {}
    }
}

#[test]
fn test_compatible_servers_are_pooled() {
    let (chain, bootstrap) = shared_test_deps();
    let entries = vec![
        make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        ),
        make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.4.4:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        ),
    ];

    let resolver = build_resolver(entries).unwrap();
    let debug = format!("{:?}", resolver);
    assert!(
        debug.contains("pool["),
        "compatible entries should be pooled into one HickoryResolver, got: {}",
        debug
    );
    assert!(
        !debug.contains("CompositeResolver"),
        "compatible entries should NOT produce CompositeResolver, got: {}",
        debug
    );
}

#[test]
fn test_incompatible_timeout_prevents_pooling() {
    let (chain, bootstrap) = shared_test_deps();
    let mut entry_a = make_entry(
        ParsedDnsServer::Udp {
            addr: "8.8.8.8:53".parse().unwrap(),
        },
        &chain,
        &bootstrap,
    );
    entry_a.timeout_secs = 5;

    let mut entry_b = make_entry(
        ParsedDnsServer::Udp {
            addr: "8.8.4.4:53".parse().unwrap(),
        },
        &chain,
        &bootstrap,
    );
    entry_b.timeout_secs = 10;

    let resolver = build_resolver(vec![entry_a, entry_b]).unwrap();
    let debug = format!("{:?}", resolver);
    assert!(
        debug.contains("CompositeResolver"),
        "incompatible timeouts should fall back to CompositeResolver, got: {}",
        debug
    );
}

#[test]
fn test_incompatible_attempts_prevents_pooling() {
    let (chain, bootstrap) = shared_test_deps();
    let mut entry_a = make_entry(
        ParsedDnsServer::Udp {
            addr: "8.8.8.8:53".parse().unwrap(),
        },
        &chain,
        &bootstrap,
    );
    entry_a.attempts = 1;

    let mut entry_b = make_entry(
        ParsedDnsServer::Udp {
            addr: "8.8.4.4:53".parse().unwrap(),
        },
        &chain,
        &bootstrap,
    );
    entry_b.attempts = 3;

    let resolver = build_resolver(vec![entry_a, entry_b]).unwrap();
    let debug = format!("{:?}", resolver);
    assert!(
        debug.contains("CompositeResolver"),
        "incompatible attempts should fall back to CompositeResolver, got: {}",
        debug
    );
}

#[test]
fn test_incompatible_ip_strategy_prevents_pooling() {
    let (chain, bootstrap) = shared_test_deps();
    let mut entry_a = make_entry(
        ParsedDnsServer::Udp {
            addr: "8.8.8.8:53".parse().unwrap(),
        },
        &chain,
        &bootstrap,
    );
    entry_a.ip_strategy = IpStrategy::Ipv4Only;

    let mut entry_b = make_entry(
        ParsedDnsServer::Udp {
            addr: "8.8.4.4:53".parse().unwrap(),
        },
        &chain,
        &bootstrap,
    );
    entry_b.ip_strategy = IpStrategy::Ipv6Only;

    let resolver = build_resolver(vec![entry_a, entry_b]).unwrap();
    let debug = format!("{:?}", resolver);
    assert!(
        debug.contains("CompositeResolver"),
        "incompatible ip_strategy should fall back to CompositeResolver, got: {}",
        debug
    );
}

#[test]
fn test_different_chain_groups_prevent_pooling() {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let chain_a = Arc::new(build_direct_chain_group(resolver.clone()));
    let chain_b = Arc::new(build_direct_chain_group(resolver.clone()));

    let entry_a = make_entry(
        ParsedDnsServer::Udp {
            addr: "8.8.8.8:53".parse().unwrap(),
        },
        &chain_a,
        &resolver,
    );
    let entry_b = make_entry(
        ParsedDnsServer::Udp {
            addr: "8.8.4.4:53".parse().unwrap(),
        },
        &chain_b,
        &resolver,
    );

    let result = build_resolver(vec![entry_a, entry_b]).unwrap();
    let debug = format!("{:?}", result);
    assert!(
        debug.contains("CompositeResolver"),
        "different chain groups should fall back to CompositeResolver, got: {}",
        debug
    );
}

#[test]
fn test_different_bootstrap_resolvers_prevent_pooling() {
    let (chain, _) = shared_test_deps();
    let bootstrap_a: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let bootstrap_b: Arc<dyn Resolver> = Arc::new(NativeResolver::new());

    let entry_a = ParsedDnsServerEntry::new(
        ParsedDnsServer::Udp {
            addr: "8.8.8.8:53".parse().unwrap(),
        },
        chain.clone(),
        bootstrap_a,
        IpStrategy::default(),
        5,
        5,
        1,
    );
    let entry_b = ParsedDnsServerEntry::new(
        ParsedDnsServer::Udp {
            addr: "8.8.4.4:53".parse().unwrap(),
        },
        chain.clone(),
        bootstrap_b,
        IpStrategy::default(),
        5,
        5,
        1,
    );

    let result = build_resolver(vec![entry_a, entry_b]).unwrap();
    let debug = format!("{:?}", result);
    assert!(
        debug.contains("CompositeResolver"),
        "different bootstrap resolvers should fall back to CompositeResolver, got: {}",
        debug
    );
}

#[test]
fn test_system_resolver_prevents_pooling() {
    let (chain, bootstrap) = shared_test_deps();
    let entries = vec![
        make_entry(ParsedDnsServer::System, &chain, &bootstrap),
        make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        ),
    ];

    let resolver = build_resolver(entries).unwrap();
    let debug = format!("{:?}", resolver);
    assert!(
        !debug.contains("pool["),
        "system resolver entry should prevent pooling, got: {}",
        debug
    );
}

#[test]
fn test_single_entry_not_pooled() {
    let (chain, bootstrap) = shared_test_deps();
    let entries = vec![make_entry(
        ParsedDnsServer::Udp {
            addr: "8.8.8.8:53".parse().unwrap(),
        },
        &chain,
        &bootstrap,
    )];

    let resolver = build_resolver(entries).unwrap();
    let debug = format!("{:?}", resolver);
    // Single entry should not go through pooling (no benefit).
    assert!(
        !debug.contains("pool["),
        "single entry should not be pooled, got: {}",
        debug
    );
    assert!(
        !debug.contains("CompositeResolver"),
        "single entry should not be composited, got: {}",
        debug
    );
}

#[test]
fn test_three_compatible_servers_pooled() {
    let (chain, bootstrap) = shared_test_deps();
    let entries = vec![
        make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        ),
        make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.4.4:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        ),
        make_entry(
            ParsedDnsServer::Tcp {
                addr: "1.1.1.1:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        ),
    ];

    let resolver = build_resolver(entries).unwrap();
    let debug = format!("{:?}", resolver);
    assert!(
        debug.contains("pool["),
        "three compatible entries should be pooled, got: {}",
        debug
    );
}

#[test]
fn test_incompatible_connect_timeout_prevents_pooling() {
    let (chain, bootstrap) = shared_test_deps();
    let mut entry_a = make_entry(
        ParsedDnsServer::Udp {
            addr: "8.8.8.8:53".parse().unwrap(),
        },
        &chain,
        &bootstrap,
    );
    entry_a.connect_timeout_secs = 5;

    let mut entry_b = make_entry(
        ParsedDnsServer::Udp {
            addr: "8.8.4.4:53".parse().unwrap(),
        },
        &chain,
        &bootstrap,
    );
    entry_b.connect_timeout_secs = 2;

    let resolver = build_resolver(vec![entry_a, entry_b]).unwrap();
    let debug = format!("{:?}", resolver);
    assert!(
        debug.contains("CompositeResolver"),
        "incompatible connect_timeout should fall back to CompositeResolver, got: {}",
        debug
    );
}

#[tokio::test]
async fn test_plan_group_pools_equivalent_specs_with_distinct_runtime_objects() {
    let registry = DnsRegistry::new();
    let spec_a = make_spec("udp://8.8.8.8");
    let spec_b = make_spec("udp://8.8.4.4");

    let mut bootstraps = FxHashMap::default();
    let (_, plan_a) = build_entry_and_plan(&spec_a, &registry, &mut bootstraps)
        .await
        .unwrap();
    let (_, plan_b) = build_entry_and_plan(&spec_b, &registry, &mut bootstraps)
        .await
        .unwrap();
    let plans = vec![plan_a.unwrap(), plan_b.unwrap()];

    let resolver = build_hickory_resolver_group(&plans).await.unwrap();
    let debug = format!("{:?}", resolver);
    assert!(
        debug.contains("pool["),
        "equivalent specs should pool through the refresh builder path, got: {}",
        debug
    );
    assert!(
        !debug.contains("CompositeResolver"),
        "equivalent specs should not de-pool into CompositeResolver, got: {}",
        debug
    );
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
#[tokio::test]
async fn selector_identity_prevents_dns_pooling_of_identical_members() {
    let configs = serde_yaml::from_str(
        r#"
- client_group: east
  client_proxies: [{name: east-direct, protocol: {type: direct}, bind_interface: east}]
- client_group: west
  client_proxies: [{name: west-direct, protocol: {type: direct}, bind_interface: west}]
- client_group: first
  type: selector
  default: east
  client_proxies: [east, west]
- client_group: second
  type: selector
  default: west
  client_proxies: [east, west]
- dns_group: selected
  dns_servers:
    - {url: 'udp://192.0.2.1', client_chain: first}
    - {url: 'udp://192.0.2.2', client_chain: second}
"#,
    )
    .unwrap();
    let validated = crate::config::create_server_configs(configs).unwrap();
    let specs = &validated.dns_groups[0].specs;
    assert_eq!(
        serde_yaml::to_string(&specs[0].client_chains).unwrap(),
        serde_yaml::to_string(&specs[1].client_chains).unwrap()
    );
    let registry = DnsRegistry::new();
    let mut bootstraps = FxHashMap::default();
    let (_, first) = build_entry_and_plan(&specs[0], &registry, &mut bootstraps)
        .await
        .unwrap();
    let (_, second) = build_entry_and_plan(&specs[1], &registry, &mut bootstraps)
        .await
        .unwrap();
    let plans = [first.unwrap(), second.unwrap()];
    assert!(!plans[0].is_pool_compatible_with(&plans[1]));
    assert!(
        try_build_hickory_pool_from_plans(&plans)
            .await
            .unwrap()
            .is_none()
    );
    let resolver = build_hickory_resolver_group(&plans).await.unwrap();
    assert!(format!("{resolver:?}").contains("CompositeResolver"));
    assert_eq!(
        plans[0].chain_group.select_bind_interface().unwrap(),
        Some("east")
    );
    assert_eq!(
        plans[1].chain_group.select_bind_interface().unwrap(),
        Some("west")
    );
    let mut owner = crate::control::selection::SelectionOwner::new(None).unwrap();
    owner
        .activate(validated.catalog.unwrap().selection)
        .unwrap();
    owner.select("first", "west").unwrap();
    assert_eq!(
        plans[0].chain_group.select_bind_interface().unwrap(),
        Some("west")
    );
    assert_eq!(
        plans[1].chain_group.select_bind_interface().unwrap(),
        Some("west")
    );
    owner.select("second", "east").unwrap();
    assert_eq!(
        plans[0].chain_group.select_bind_interface().unwrap(),
        Some("west")
    );
    assert_eq!(
        plans[1].chain_group.select_bind_interface().unwrap(),
        Some("east")
    );
}

#[tokio::test]
async fn test_plan_group_falls_back_for_incompatible_specs() {
    let registry = DnsRegistry::new();
    let spec_a = make_spec("udp://8.8.8.8");
    let mut spec_b = make_spec("udp://8.8.4.4");
    spec_b.attempts = 3;

    let mut bootstraps = FxHashMap::default();
    let (_, plan_a) = build_entry_and_plan(&spec_a, &registry, &mut bootstraps)
        .await
        .unwrap();
    let (_, plan_b) = build_entry_and_plan(&spec_b, &registry, &mut bootstraps)
        .await
        .unwrap();
    let plans = vec![plan_a.unwrap(), plan_b.unwrap()];

    let resolver = build_hickory_resolver_group(&plans).await.unwrap();
    let debug = format!("{:?}", resolver);
    assert!(
        debug.contains("CompositeResolver"),
        "incompatible specs should fall back to CompositeResolver, got: {}",
        debug
    );
}
