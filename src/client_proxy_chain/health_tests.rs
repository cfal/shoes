use super::*;
use crate::config::{Config, ConfigSelection, RuleActionConfig};
use crate::control::catalog::Catalog;
use crate::control::health::Health;
use crate::control::selection::SelectionOwner;
use serde_json::{Value, json};
use tokio::time::Instant;

fn config() -> Value {
    json!([{"client_group":"out", "type":"fallback",
    "health_check":{"url":"http://192.0.2.1/", "interval_secs":10, "timeout_ms":5000, "expected_status":204},
    "client_proxies":[
        {"name":"primary", "address":"192.0.2.10:80", "protocol":{"type":"http"}},
        {"name":"backup", "address":"192.0.2.11:80", "protocol":{"type":"http"}}
    ]}])
}

fn build(mut config: Value, chain: Value) -> (ClientProxyChain, Catalog) {
    config
        .as_array_mut()
        .unwrap()
        .push(json!({"address":"127.0.0.1:0", "protocol":{"type":"socks"},
        "rules":[{"mask":"0.0.0.0/0", "action":"allow", "client_chain":chain}]}));
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
fn health_nested_manual_pin_is_not_bypassed_and_udp_filters_before_ordering() {
    let mut configs = config();
    configs[0]["client_proxies"][1]["protocol"] =
        json!({"type":"vless", "user_id":"b85798ef-e9dc-46a4-9a87-8da4499d36d0"});
    configs.as_array_mut().unwrap().push(
        json!({"client_group":"manual", "type":"selector", "client_proxies":["out","direct"]}),
    );
    let (chain, catalog) = build(configs.clone(), json!("manual"));
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

    configs[0]["type"] = json!("selector");
    configs[0].as_object_mut().unwrap().remove("health_check");
    configs[1] = json!({"client_group":"manual", "type":"fallback", "health_check":{"url":"http://192.0.2.1/", "interval_secs":10}, "client_proxies":["out","direct"]});
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
    configs.as_array_mut().unwrap().push(json!({"client_group":"outer", "type":"fallback", "health_check":{"url":"http://192.0.2.1/", "interval_secs":10}, "client_proxies":["out", {"name":"last", "address":"192.0.2.12:80", "protocol":{"type":"http"}}]}));
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

    configs.as_array_mut().unwrap().push(json!({"client_group":"other", "type":"fallback", "health_check":{"url":"http://192.0.2.2/", "interval_secs":10}, "client_proxies":["out"]}));
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
fn health_validation_is_strict_and_bounds_path_expansion() {
    let validated =
        crate::config::create_server_configs(serde_json::from_value(config()).unwrap()).unwrap();
    assert!(validated.reject_ffi_control().is_err());
    let mut selector = config();
    selector[0]["type"] = json!("selector");
    selector[0].as_object_mut().unwrap().remove("health_check");
    assert!(
        crate::config::create_server_configs(serde_json::from_value(selector).unwrap())
            .unwrap()
            .reject_ffi_control()
            .is_ok()
    );
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
