use super::*;
use crate::config::{Config, ConfigSelection, RuleActionConfig};
use crate::control::catalog::Catalog;
use crate::control::health::Health;
use crate::control::selection::SelectionOwner;
use serde_json::{Value, json};
use tokio::time::Instant;

fn config() -> Value {
    json!([{
        "client_group": "out",
        "type": "fallback",
        "health_check": {
            "url": "http://192.0.2.1/",
            "interval_secs": 10,
            "timeout_ms": 5000,
            "expected_status": 204
        },
        "client_proxies": [
            {"name": "primary", "address": "192.0.2.10:80", "protocol": {"type": "http"}},
            {"name": "backup", "address": "192.0.2.11:80", "protocol": {"type": "http"}}
        ]
    }])
}

fn build(mut config: Value, chain: Value) -> (ClientProxyChain, Catalog) {
    config.as_array_mut().unwrap().push(json!({
        "address": "127.0.0.1:0",
        "protocol": {"type": "socks"},
        "rules": [{"mask": "0.0.0.0/0", "action": "allow", "client_chain": chain}]
    }));
    let mut validated =
        crate::config::create_server_configs(serde_json::from_value(config).unwrap()).unwrap();
    let Config::Server(server) = &validated.configs[0] else {
        panic!()
    };
    let ConfigSelection::Config(rule) = server.rules.iter().next().unwrap() else {
        panic!()
    };
    let RuleActionConfig::Allow { client_chains, .. } = &rule.action else {
        panic!()
    };
    let chain = crate::tcp::chain_builder::try_build_client_proxy_chain(
        client_chains.iter().next().unwrap().hops.clone(),
        Arc::new(crate::resolver::NativeResolver::new()),
    )
    .unwrap();
    (chain, validated.catalog.take().unwrap())
}

fn sample(chain: &ClientProxyChain, path: usize, healthy: bool, at: Instant) {
    let choices = chain.selection.as_ref().unwrap().snapshot();
    for check in &chain.health_paths[path].checks {
        check.record(Ok((1, healthy)), choices.clone(), at);
    }
}

#[test]
fn health_review_unrelated_manual_choice_does_not_reset_failed_paths() {
    let mut configs = config();
    configs.as_array_mut().unwrap().push(json!({
        "client_group": "unrelated", "type": "selector",
        "client_proxies": ["direct", {"name": "other", "address": "192.0.2.90:80", "protocol": {"type": "http"}}]
    }));
    let (chain, catalog) = build(configs, json!("out"));
    let mut owner = SelectionOwner::new(None).unwrap();
    owner.activate(catalog.selection.clone()).unwrap();
    sample(&chain, 0, false, Instant::now());
    sample(&chain, 1, true, Instant::now());
    assert_eq!(chain.select_indices(false).unwrap(), [1]);
    owner.select("unrelated", "other").unwrap();
    assert_eq!(chain.select_indices(false).unwrap(), [1]);
}

#[tokio::test(start_paused = true)]
async fn health_review_retired_generation_keeps_samples_for_draining_sessions() {
    let (chain, catalog) = build(config(), json!("out"));
    sample(&chain, 0, false, Instant::now());
    sample(&chain, 1, true, Instant::now());
    let service = crate::control::health::HealthService::start(
        catalog.selection.clone(),
        Arc::new(tokio::sync::Semaphore::new(0)),
        Vec::new(),
    );
    service.shutdown().await;
    tokio::time::advance(std::time::Duration::from_secs(300)).await;
    assert_eq!(chain.select_indices(false).unwrap(), [1]);

    let resumed = crate::control::health::HealthService::start(
        catalog.selection.clone(),
        Arc::new(tokio::sync::Semaphore::new(0)),
        Vec::new(),
    );
    assert!(
        chain.select_indices(false).is_err(),
        "resuming must restore freshness checks"
    );
    sample(&chain, 1, true, Instant::now());
    assert_eq!(chain.select_indices(false).unwrap(), [1]);
    resumed.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn health_review10_fixed_carrier_aliases_share_samples_but_policies_do_not() {
    let mut left = crate::wireguard::test_support::client(51820);
    left["client_group"] = json!("wg-left");
    left["client_proxies"][0]["name"] = json!("left");
    left["client_proxies"][0]["protocol"]["peer_client_chain"] = json!("alias-left");
    let mut right = left.clone();
    right["client_group"] = json!("wg-right");
    right["client_proxies"][0]["name"] = json!("right");
    right["client_proxies"][0]["protocol"]["peer_client_chain"] = json!("alias-right");
    let configs = json!([
        left, right,
        {"client_group":"alias-left", "client_proxies":["direct"]},
        {"client_group":"alias-right", "client_proxies":["direct"]},
        {"client_group":"policy-left", "type":"selector", "client_proxies":["direct"]},
        {"client_group":"policy-right", "type":"selector", "client_proxies":["direct"]},
        {"client_group":"out", "type":"fallback", "health_check":{"url":"http://192.0.2.1/", "interval_secs":30},
         "client_proxies":["wg-left", "wg-right"]},
        {"address":"127.0.0.1:0", "protocol":{"type":"socks"},
         "rules":[{"mask":"0.0.0.0/0", "action":"allow", "client_chain":"out"}]}
    ]);
    let mut validated =
        crate::config::create_server_configs(serde_json::from_value(configs).unwrap()).unwrap();
    let _prepared = crate::wireguard::Prepared::new(&mut validated)
        .await
        .unwrap();
    let Config::Server(server) = &validated.configs[0] else {
        panic!()
    };
    let ConfigSelection::Config(rule) = server.rules.iter().next().unwrap() else {
        panic!()
    };
    let RuleActionConfig::Allow { client_chains, .. } = &rule.action else {
        panic!()
    };
    let hops = client_chains.iter().next().unwrap().hops.clone();
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    let make = |hops| {
        crate::tcp::chain_builder::try_build_client_proxy_chain(hops, resolver.clone()).unwrap()
    };
    let chain = make(hops.clone());
    let (InitialHopEntry::Wireguard(left), InitialHopEntry::Wireguard(right)) =
        (chain.initial_hop[0].as_ref(), chain.initial_hop[1].as_ref())
    else {
        panic!()
    };
    assert!(Arc::ptr_eq(left, right));
    assert!(Arc::ptr_eq(
        &chain.health_paths[0].checks[0],
        &chain.health_paths[1].checks[0]
    ));
    sample(&chain, 0, false, Instant::now());
    assert_eq!(
        chain.health_paths[1].checks[0].health(
            &chain.selection.as_ref().unwrap().snapshot(),
            Instant::now()
        ),
        Health::Failed
    );
    assert!(chain.select_indices(false).is_err());

    // Keep the prepared connector fixed to isolate policy metadata in the health key.
    let policies: Vec<_> = ["policy-left", "policy-right"]
        .into_iter()
        .map(|policy| {
            let mut hops = hops.clone();
            for hop in hops.iter_mut() {
                crate::config::client_visit::visit_hop(hop, &mut |client| {
                    if client.protocol.is_direct() {
                        client.control.as_mut().unwrap().path =
                            vec![(policy.into(), "DIRECT".into())];
                    }
                    Ok(())
                })
                .unwrap();
            }
            make(hops)
        })
        .collect();
    for policy in &policies {
        assert!(!Arc::ptr_eq(
            &chain.health_paths[0].checks[0],
            &policy.health_paths[0].checks[0]
        ));
    }
    assert!(!Arc::ptr_eq(
        &policies[0].health_paths[0].checks[0],
        &policies[1].health_paths[0].checks[0]
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn health_review_static_nested_carrier_identity_and_manual_choice_scoping() {
    use crate::config::{ClientChainHop, ClientProxyConfig};
    let mut wireguard = crate::wireguard::test_support::client(51820);
    wireguard["client_proxies"][0]["protocol"]["peer_client_chain"] = json!("carrier");
    let configs = json!([
        wireguard,
        {"client_group": "carrier", "type": "selector", "client_proxies": [
            {"name": "fixed", "address": "127.0.0.1:1", "protocol": crate::wireguard::test_support::vless_protocol()}
        ]},
        {"client_group": "unrelated", "type": "selector", "client_proxies": ["carrier", "direct"]},
        {"client_group": "out", "type": "fallback",
         "health_check": {"url": "http://192.0.2.1/", "interval_secs": 10}, "client_proxies": ["wg"]},
        {"address": "127.0.0.1:0", "protocol": {"type": "socks"},
         "rules": [{"mask": "0.0.0.0/0", "action": "allow", "client_chain": "out"}]}
    ]);
    let mut validated =
        crate::config::create_server_configs(serde_json::from_value(configs).unwrap()).unwrap();
    let _prepared = crate::wireguard::Prepared::new(&mut validated)
        .await
        .unwrap();
    let Config::Server(server) = &validated.configs[0] else {
        panic!()
    };
    let ConfigSelection::Config(rule) = server.rules.iter().next().unwrap() else {
        panic!()
    };
    let RuleActionConfig::Allow { client_chains, .. } = &rule.action else {
        panic!()
    };
    let hops = client_chains.iter().next().unwrap().hops.clone();
    let selection = validated.catalog.as_ref().unwrap().selection.clone();
    let mut owner = SelectionOwner::new(None).unwrap();
    owner.activate(selection.clone()).unwrap();
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    let make = |hops| {
        crate::tcp::chain_builder::try_build_client_proxy_chain(hops, resolver.clone()).unwrap()
    };
    let chain = make(hops.clone());
    let equivalent = make(hops.clone());
    assert!(Arc::ptr_eq(
        &chain.health_paths[0].checks[0],
        &equivalent.health_paths[0].checks[0]
    ));

    // Hold the generation and transport constant to isolate the nested identity inputs.
    for change_policy in [false, true] {
        let mut changed = hops.clone();
        for hop in changed.iter_mut() {
            crate::config::client_visit::visit_hop(hop, &mut |client| {
                if !client.protocol.is_wireguard() && !client.protocol.is_direct() {
                    if change_policy {
                        client.control.as_mut().unwrap().path[0].0 = "other-carrier".into();
                    } else {
                        client.address =
                            crate::address::NetLocation::from_str("127.0.0.1:2", None).unwrap();
                    }
                }
                Ok(())
            })
            .unwrap();
        }
        let changed = make(changed);
        assert!(!Arc::ptr_eq(
            &chain.health_paths[0].checks[0],
            &changed.health_paths[0].checks[0]
        ));
    }

    let first = match hops.iter().next().unwrap() {
        ClientChainHop::Single(client) => client,
        ClientChainHop::Pool(pool) => pool.iter().next().unwrap(),
    };
    let ConfigSelection::Config(client) = first else {
        panic!()
    };
    let ClientProxyConfig::Wireguard(wireguard) = &client.protocol else {
        panic!()
    };
    let carrier = make(wireguard.peer_client_chain.as_ref().unwrap().hops.clone());
    assert_eq!(carrier.select_indices(true).unwrap(), [0]);
    sample(&chain, 0, true, Instant::now());
    owner.select("unrelated", "DIRECT").unwrap();
    assert_eq!(
        chain.health_paths[0].checks[0].health(&selection.snapshot(), Instant::now()),
        Health::Healthy
    );
    sample(&chain, 0, false, Instant::now());
    assert!(chain.select_indices(false).is_err());
    owner.select("unrelated", "carrier").unwrap();
    assert!(
        chain.select_indices(false).is_err(),
        "unrelated selectors must not revive failed paths"
    );
}

#[tokio::test]
async fn health_review3_dns_changes_preserve_samples_and_resolver_dependencies() {
    let mut configs = config();
    configs[0]["client_proxies"][0]["address"] = json!("private-proxy.invalid:80");
    configs.as_array_mut().unwrap().extend([
        json!({"client_group": "dns-child", "type": "selector", "client_proxies": [
            "direct", {"name": "dns-proxy", "address": "192.0.2.53:1080", "protocol": {"type": "socks"}}
        ]}),
        json!({"client_group": "dns-parent", "type": "selector", "client_proxies": ["direct", "dns-child"]}),
        json!({"client_group": "unrelated", "type": "selector", "client_proxies": ["direct", "dns-child"]}),
        json!({"dns_group": "resolver", "dns_servers": [{"url": "tcp://192.0.2.53", "client_chain": "dns-parent"}], "fake_ip": true}),
        json!({"address": "127.0.0.1:0", "protocol": {"type": "socks"}, "dns": {"servers": "resolver"},
            "rules": [{"mask": "0.0.0.0/0", "action": "allow", "client_chain": "out"}]}),
    ]);
    let mut validated =
        crate::config::create_server_configs(serde_json::from_value(configs).unwrap()).unwrap();
    let mut registry = crate::dns::build_dns_registry(std::mem::take(&mut validated.dns_groups))
        .await
        .unwrap();
    let Config::Server(server) = &validated.configs[0] else {
        panic!()
    };
    let ConfigSelection::Config(rule) = server.rules.iter().next().unwrap() else {
        panic!()
    };
    let RuleActionConfig::Allow { client_chains, .. } = &rule.action else {
        panic!()
    };
    let resolver = registry.get_for_server(server.dns.as_ref());
    assert!(resolver.fake_dns_context().is_some());
    let chain = crate::tcp::chain_builder::try_build_client_proxy_chain(
        client_chains.iter().next().unwrap().hops.clone(),
        resolver,
    )
    .unwrap();
    let selection = validated.catalog.take().unwrap().selection;
    let mut owner = SelectionOwner::new(None).unwrap();
    owner.activate(selection.clone()).unwrap();
    sample(&chain, 0, false, Instant::now());
    sample(&chain, 1, true, Instant::now());
    owner.select("unrelated", "dns-child").unwrap();
    owner.select("dns-child", "dns-proxy").unwrap();
    assert_eq!(
        chain.select_indices(false).unwrap(),
        [1],
        "inactive DNS selectors must not revive failed paths"
    );
    owner.select("dns-parent", "dns-child").unwrap();
    assert_eq!(chain.select_indices(false).unwrap(), [1]);
    assert_eq!(
        chain.health_paths[0].checks[0].health(&selection.snapshot(), Instant::now()),
        Health::Failed
    );
    sample(&chain, 0, false, Instant::now());
    owner.select("dns-child", "DIRECT").unwrap();
    assert_eq!(
        chain.health_paths[0].checks[0].health(&selection.snapshot(), Instant::now()),
        Health::Failed
    );
}

#[test]
fn health_ordered_dead_primary_recovery_all_down_unknown_stale_and_flapping() {
    let (chain, catalog) = build(config(), json!("out"));
    let now = Instant::now();
    assert_eq!(chain.select_indices(false).unwrap(), [0]);
    assert_eq!(
        chain.health_paths[0].checks[0].health(&catalog.selection.snapshot(), now),
        Health::Unknown
    );
    sample(&chain, 1, true, now);
    assert_eq!(chain.select_indices(false).unwrap(), [1]);
    sample(&chain, 0, false, now);
    assert_eq!(chain.select_indices(false).unwrap(), [1]);
    sample(&chain, 1, false, now);
    assert!(chain.select_indices(false).is_err());
    for healthy in [true, false, true, false, true] {
        sample(&chain, 1, true, now);
        sample(&chain, 0, healthy, now);
        assert_eq!(
            chain.select_indices(false).unwrap(),
            [usize::from(!healthy)]
        );
    }
    for path in 0..2 {
        sample(&chain, path, true, now - std::time::Duration::from_secs(36));
    }
    assert_eq!(
        chain.health_paths[0].checks[0].health(&catalog.selection.snapshot(), now),
        Health::Stale
    );
    assert!(chain.select_indices(false).is_err());
}

#[test]
fn health_prefers_healthy_paths_within_one_member_then_uses_unknown_after_failure() {
    let mut configs = config();
    configs[0]["type"] = json!("round-robin");
    configs[0].as_object_mut().unwrap().remove("health_check");
    configs.as_array_mut().unwrap().push(json!({
        "client_group": "outer",
        "type": "fallback",
        "health_check": {"url": "http://192.0.2.1/", "interval_secs": 10},
        "client_proxies": ["out", "direct"]
    }));
    let (chain, catalog) = build(configs, json!("outer"));
    let now = Instant::now();
    sample(&chain, 1, true, now);
    assert_eq!(
        chain.health_paths[0].checks[0].health(&catalog.selection.snapshot(), now),
        Health::Unknown
    );
    for _ in 0..4 {
        assert_eq!(chain.select_indices(false).unwrap(), [1]);
    }
    sample(&chain, 1, false, now);
    assert_eq!(chain.select_indices(false).unwrap(), [0]);
    sample(&chain, 2, true, now);
    assert_eq!(chain.select_indices(false).unwrap(), [2]);
}

#[test]
fn health_nested_manual_pin_is_not_bypassed_and_udp_filters_before_ordering() {
    let mut configs = config();
    configs[0]["client_proxies"][1]["protocol"] =
        json!({"type":"vless", "user_id":"b85798ef-e9dc-46a4-9a87-8da4499d36d0"});
    configs.as_array_mut().unwrap().push(
        json!({"client_group":"manual", "type":"selector", "client_proxies":["out","direct"]}),
    );
    let (chain, catalog) = build(configs, json!("manual"));
    let mut owner = SelectionOwner::new(None).unwrap();
    owner.activate(catalog.selection.clone()).unwrap();
    sample(&chain, 0, true, Instant::now());
    sample(&chain, 1, true, Instant::now());
    assert_eq!(chain.select_indices(false).unwrap(), [0]);
    assert_eq!(chain.select_indices(true).unwrap(), [1]);
    sample(&chain, 1, false, Instant::now());
    assert!(chain.select_indices(true).is_err());
    sample(&chain, 0, false, Instant::now());
    assert!(chain.select_indices(false).is_err());
    owner.select("manual", "DIRECT").unwrap();
    assert_eq!(chain.select_indices(true).unwrap(), [2]);
}

#[test]
fn health_review4_capability_rejection_is_distinct_from_all_down() {
    let mut configs = config();
    configs.as_array_mut().unwrap().push(json!({
        "client_group":"manual", "type":"selector", "client_proxies":["out", "direct"]
    }));
    let (chain, catalog) = build(configs, json!("manual"));
    let mut owner = SelectionOwner::new(None).unwrap();
    owner.activate(catalog.selection.clone()).unwrap();
    for path in 0..2 {
        sample(&chain, path, false, Instant::now());
    }
    let error = chain.select_indices(true).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    assert_eq!(error.to_string(), "selected branch cannot carry this flow");
    let error = chain.select_indices(false).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::NotConnected);
    assert_eq!(
        error.to_string(),
        "fallback has no healthy or unknown eligible path"
    );
    owner.select("manual", "DIRECT").unwrap();
    assert_eq!(chain.select_indices(true).unwrap(), [2]);
}

#[tokio::test(start_paused = true)]
async fn health_review4_reselection_preserves_stale_exclusion_until_a_sample_arrives() {
    let mut configs = config();
    configs.as_array_mut().unwrap().push(json!({
        "client_group":"manual", "type":"selector", "client_proxies":["out", "direct"]
    }));
    let (chain, catalog) = build(configs, json!("manual"));
    let mut owner = SelectionOwner::new(None).unwrap();
    owner.activate(catalog.selection.clone()).unwrap();
    sample(&chain, 0, true, Instant::now());
    sample(&chain, 1, false, Instant::now());
    owner.select("manual", "DIRECT").unwrap();
    tokio::time::advance(std::time::Duration::from_secs(100)).await;
    owner.select("manual", "out").unwrap();
    let service = crate::control::health::HealthService::start(
        catalog.selection.clone(),
        Arc::new(tokio::sync::Semaphore::new(0)),
        Vec::new(),
    );
    assert_eq!(
        chain.health_paths[0].checks[0].health(&catalog.selection.snapshot(), Instant::now()),
        Health::Stale
    );
    assert_eq!(
        chain.select_indices(false).unwrap_err().kind(),
        std::io::ErrorKind::NotConnected
    );
    sample(&chain, 1, true, Instant::now());
    assert_eq!(chain.select_indices(false).unwrap(), [1]);
    service.shutdown().await;
}

#[test]
fn health_fallback_preserves_nested_manual_pin_for_tcp_and_udp() {
    let mut configs = config();
    configs[0]["type"] = json!("selector");
    configs[0].as_object_mut().unwrap().remove("health_check");
    configs[0]["client_proxies"][1]["protocol"] =
        json!({"type":"vless", "user_id":"b85798ef-e9dc-46a4-9a87-8da4499d36d0"});
    configs.as_array_mut().unwrap().push(json!({
        "client_group": "manual",
        "type": "fallback",
        "health_check": {"url": "http://192.0.2.1/", "interval_secs": 10},
        "client_proxies": ["out", "direct"]
    }));
    let (chain, _) = build(configs, json!("manual"));
    sample(&chain, 0, false, Instant::now());
    sample(&chain, 1, true, Instant::now());
    sample(&chain, 2, false, Instant::now());
    assert!(
        chain.select_indices(false).is_err(),
        "must not bypass nested selector's dead primary"
    );
    assert!(
        chain.select_indices(true).is_err(),
        "nested TCP-only pin must not select its UDP sibling"
    );
}

#[test]
fn health_nested_fallback_respects_outer_then_inner_order() {
    let mut configs = config();
    configs.as_array_mut().unwrap().push(json!({
        "client_group": "outer",
        "type": "fallback",
        "health_check": {"url": "http://192.0.2.1/", "interval_secs": 10},
        "client_proxies": [
            "out",
            {"name": "last", "address": "192.0.2.12:80", "protocol": {"type": "http"}}
        ]
    }));
    let (chain, _) = build(configs, json!("outer"));
    sample(&chain, 0, false, Instant::now());
    sample(&chain, 1, true, Instant::now());
    sample(&chain, 2, true, Instant::now());
    assert_eq!(chain.select_indices(false).unwrap(), [1]);
    sample(&chain, 1, false, Instant::now());
    assert_eq!(chain.select_indices(false).unwrap(), [2]);
}

#[test]
fn health_composes_with_nested_url_test_selection_and_udp_eligibility() {
    let mut configs = config();
    configs[0]["type"] = json!("url-test");
    configs[0].as_object_mut().unwrap().remove("health_check");
    configs[0]["url"] = json!("http://192.0.2.2/");
    configs[0]["client_proxies"][1]["protocol"] =
        json!({"type":"vless", "user_id":"b85798ef-e9dc-46a4-9a87-8da4499d36d0"});
    configs.as_array_mut().unwrap().push(json!({"client_group":"outer", "type":"fallback",
        "health_check":{"url":"http://192.0.2.1/", "interval_secs":10}, "client_proxies":["out","direct"]}));
    let (chain, catalog) = build(configs, json!("outer"));
    for path in 0..3 {
        sample(&chain, path, true, Instant::now());
    }
    let automatic = &catalog.selection.automatic;
    automatic.record("primary", "http://192.0.2.2/", Some(10));
    automatic.record("backup", "http://192.0.2.2/", Some(100));
    assert_eq!(chain.select_indices(false).unwrap(), [0]);
    assert_eq!(chain.select_indices(true).unwrap(), [1]);
    automatic.record("backup", "http://192.0.2.2/", Some(1));
    automatic.record("primary", "http://192.0.2.2/", Some(100));
    assert_eq!(chain.select_indices(false).unwrap(), [1]);
    sample(&chain, 1, false, Instant::now());
    assert_eq!(chain.select_indices(false).unwrap(), [0]);
    assert_eq!(chain.select_indices(true).unwrap(), [2]);
}

#[test]
fn health_review3_mixed_url_test_candidates_keep_healthy_before_unknown() {
    for healthy in 0..2 {
        let mut configs = config();
        configs[0]["type"] = json!("url-test");
        configs[0].as_object_mut().unwrap().remove("health_check");
        configs[0]["url"] = json!("http://192.0.2.2/");
        configs.as_array_mut().unwrap().push(json!({"client_group":"outer", "type":"fallback",
            "health_check":{"url":"http://192.0.2.1/", "interval_secs":10}, "client_proxies":["out","direct"]}));
        let (chain, catalog) = build(configs, json!("outer"));
        sample(&chain, healthy, true, Instant::now());
        if healthy == 0 {
            catalog
                .selection
                .automatic
                .record("primary", "http://192.0.2.2/", Some(100));
            catalog
                .selection
                .automatic
                .record("backup", "http://192.0.2.2/", Some(1));
        }
        assert_eq!(chain.select_indices(false).unwrap(), [healthy]);
    }
}

#[test]
fn health_review3_healthy_prefix_precedes_unknown_without_overriding_unrelated_round_robin() {
    let (chain, _) = build(
        config(),
        json!([
            {"pool":[
                {"address":"192.0.2.50:80", "protocol":{"type":"http"}},
                {"address":"192.0.2.51:80", "protocol":{"type":"http"}}
            ]}, "out"
        ]),
    );
    sample(&chain, 2, true, Instant::now());
    assert_eq!(chain.select_indices(false).unwrap(), [1, 0]);

    let mut configs = config();
    configs
        .as_array_mut()
        .unwrap()
        .push(json!({"client_group":"outer", "client_proxies":["out", "direct"]}));
    let (chain, _) = build(configs, json!("outer"));
    assert_eq!(chain.select_indices(false).unwrap(), [0]);
    assert_eq!(chain.select_indices(false).unwrap(), [2]);
}

#[test]
fn health_nested_fallback_preserves_url_test_group_health() {
    let mut configs = config();
    configs
        .as_array_mut()
        .unwrap()
        .push(json!({"client_group":"outer", "type":"url-test",
        "url":"http://192.0.2.2/", "client_proxies":["out","direct"]}));
    let (chain, catalog) = build(configs, json!("outer"));
    for path in 0..2 {
        sample(&chain, path, true, Instant::now());
    }
    let automatic = &catalog.selection.automatic;
    automatic.record("out", "http://192.0.2.2/", Some(1));
    automatic.record("DIRECT", "http://192.0.2.2/", Some(100));
    assert_eq!(chain.select_indices(false).unwrap(), [0]);
    sample(&chain, 0, false, Instant::now());
    assert_eq!(chain.select_indices(false).unwrap(), [1]);
    sample(&chain, 1, false, Instant::now());
    assert_eq!(chain.select_indices(false).unwrap(), [2]);
    assert_eq!(automatic.0["outer"].health("out"), "healthy");
}

#[test]
fn health_identity_deduplicates_equivalent_paths_not_prefixes_endpoints_or_generations() {
    let mut configs = config();
    configs[0]["client_proxies"][1]["address"] = configs[0]["client_proxies"][0]["address"].clone();
    let (chain, _) = build(configs.clone(), json!("out"));
    assert!(Arc::ptr_eq(
        &chain.health_paths[0].checks[0],
        &chain.health_paths[1].checks[0]
    ));
    sample(&chain, 0, false, Instant::now());
    let (new, _) = build(configs.clone(), json!("out"));
    assert!(!Arc::ptr_eq(
        &chain.health_paths[0].checks[0],
        &new.health_paths[0].checks[0]
    ));
    assert_eq!(new.select_indices(false).unwrap(), [0]);
    configs[0]["client_proxies"][0]["address"] = json!("192.0.2.99:80");
    let (changed, _) = build(configs.clone(), json!("out"));
    assert!(!Arc::ptr_eq(
        &changed.health_paths[0].checks[0],
        &changed.health_paths[1].checks[0]
    ));
    assert_eq!(changed.select_indices(false).unwrap(), [0]);

    configs.as_array_mut().unwrap().push(json!({
        "client_group": "other",
        "type": "fallback",
        "health_check": {"url": "http://192.0.2.2/", "interval_secs": 10},
        "client_proxies": ["out"]
    }));
    let (different_endpoint, _) = build(configs, json!("other"));
    assert_eq!(different_endpoint.health_paths[0].checks.len(), 2);

    let (composed, _) = build(
        config(),
        json!([
            {"pool":[{"address":"192.0.2.50:80", "protocol":{"type":"http"}}, {"address":"192.0.2.51:80", "protocol":{"type":"http"}}]}, "out"
        ]),
    );
    assert_eq!(composed.health_paths.len(), 4);
    assert!(!Arc::ptr_eq(
        &composed.health_paths[0].checks[0],
        &composed.health_paths[2].checks[0]
    ));
    for path in 0..4 {
        sample(&composed, path, path == 3, Instant::now());
    }
    assert_eq!(composed.select_indices(false).unwrap(), [1, 1]);
}

#[test]
fn health_anonymous_members_keep_configuration_identity() {
    let mut configs = config();
    for client in configs[0]["client_proxies"].as_array_mut().unwrap() {
        client.as_object_mut().unwrap().remove("name");
    }
    let (chain, _) = build(configs, json!("out"));
    assert!(!Arc::ptr_eq(
        &chain.health_paths[0].checks[0],
        &chain.health_paths[1].checks[0]
    ));
    sample(&chain, 0, false, Instant::now());
    sample(&chain, 1, true, Instant::now());
    assert_eq!(chain.select_indices(false).unwrap(), [1]);
}

#[tokio::test]
async fn health_application_failure_does_not_replay_or_change_samples() {
    let backup = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let closed = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    let primary_port = closed.local_addr().unwrap().port();
    drop(closed);
    let mut configs = config();
    configs[0]["client_proxies"][0]["address"] = json!(format!("127.0.0.1:{primary_port}"));
    configs[0]["client_proxies"][1]["address"] =
        json!(format!("127.0.0.1:{}", backup.local_addr().unwrap().port()));
    let (chain, catalog) = build(configs, json!("out"));
    for path in 0..2 {
        sample(&chain, path, true, Instant::now());
    }
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    let target = crate::address::NetLocation::from_str("192.0.2.1:80", None).unwrap();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            chain.connect_tcp(target.into(), &resolver)
        )
        .await
        .unwrap()
        .is_err()
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), backup.accept())
            .await
            .is_err()
    );
    assert_eq!(
        chain.health_paths[0].checks[0].health(&catalog.selection.snapshot(), Instant::now()),
        Health::Healthy
    );
    assert_eq!(chain.select_indices(false).unwrap(), [0]);
}

#[test]
fn health_ffi_validation_preserves_rejection_order_and_errors() {
    let validate = |config| {
        crate::config::create_server_configs(serde_json::from_value(config).unwrap())
            .unwrap()
            .validate_ffi_support()
    };
    let fallback_error = "fallback groups require the CLI generation lifecycle";
    let error = validate(config()).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(error.to_string(), fallback_error);

    let mut selector = config();
    selector[0]["type"] = json!("selector");
    selector[0].as_object_mut().unwrap().remove("health_check");
    assert!(validate(selector).is_ok());

    let automatic = json!({
        "client_group": "auto",
        "type": "url-test",
        "url": "http://192.0.2.2/",
        "client_proxies": ["direct"]
    });
    let error = validate(json!([automatic.clone()])).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    assert_eq!(
        error.to_string(),
        "url-test groups require the process runtime and are not supported by FFI"
    );
    let mut mixed = config();
    mixed.as_array_mut().unwrap().push(automatic);
    let error = validate(mixed.clone()).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(error.to_string(), fallback_error);
    mixed.as_array_mut().unwrap().push(json!({
        "clash_api_address": "127.0.0.1:0",
        "secret": "test"
    }));
    let error = validate(mixed).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(
        error.to_string(),
        "Clash controller and cache configuration are not supported by the FFI lifecycle"
    );
}

#[test]
fn health_validation_rejects_invalid_fields_and_types() {
    for (pointer, value) in [
        ("/0/health_check/url", json!("ftp://bad/")),
        ("/0/health_check/url", json!("https://user:password@host/")),
        ("/0/health_check/url", json!("http://host/#fragment")),
        ("/0/health_check/url", json!("http://127.0.0.1/")),
        ("/0/health_check/url", json!("http://[::ffff:127.0.0.1]/")),
        ("/0/health_check/url", json!("http://198.18.0.1/")),
        ("/0/health_check/interval_secs", json!(0)),
        ("/0/health_check/interval_secs", json!(86401)),
        ("/0/health_check/timeout_ms", json!(0)),
        ("/0/health_check/timeout_ms", json!(32768)),
        ("/0/health_check/expected_status", json!(99)),
        ("/0/health_check/expected_status", json!(600)),
        ("/0/type", json!("round-robin")),
        ("/0/health_check", Value::Null),
    ] {
        let mut configs = config();
        *configs
            .pointer_mut(pointer)
            .unwrap_or_else(|| panic!("missing {pointer}")) = value;
        let parsed = serde_json::from_value(configs);
        assert!(
            parsed.is_err() || crate::config::create_server_configs(parsed.unwrap()).is_err(),
            "{pointer}"
        );
    }
    for field in ["all_down", "lazy", "tolerance", "strategy"] {
        let mut configs = config();
        configs[0][field] = json!("direct");
        assert!(serde_json::from_value::<Vec<Config>>(configs).is_err());
    }
}

#[test]
fn health_validation_bounds_path_expansion() {
    let mut configs = config();
    configs.as_array_mut().unwrap().push(
        json!({"address":"127.0.0.1:0", "protocol":{"type":"socks"}, "rules":[{
            "mask":"0.0.0.0/0", "action":"allow", "client_chain":vec!["out"; 9]
        }]}),
    );
    let error = crate::config::create_server_configs(serde_json::from_value(configs).unwrap())
        .err()
        .unwrap();
    assert!(error.to_string().contains("256 concrete chain paths"));
}
