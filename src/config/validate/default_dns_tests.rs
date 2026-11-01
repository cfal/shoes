use super::*;
use serde_json::{Value, json};

fn validate(value: Value) -> std::io::Result<ValidatedConfigs> {
    create_server_configs(serde_json::from_value(value).unwrap())
}

fn listener(port: u16) -> Value {
    json!({"address": format!("127.0.0.1:{port}"), "protocol": {"type": "socks"}})
}

fn dns(config: &ResolvedConfig) -> Option<&ResolvedDnsConfig> {
    match config {
        ResolvedConfig::Server(server) => server.dns.as_ref(),
        ResolvedConfig::TunServer(tun) => tun.dns.as_ref(),
    }
}

#[test]
fn default_dns_is_order_independent_and_explicit_objects_override_it() {
    let mut null_dns = listener(1081);
    null_dns["dns"] = Value::Null;
    let mut entries = vec![
        json!({"global_settings": {"default_dns": {"servers": "selected"}}}),
        json!({"dns_group": "selected", "dns_servers": "tcp://192.0.2.53"}),
        listener(1080),
        null_dns,
        json!({"device_name": "tun0", "address": "10.0.0.1", "netmask": "255.255.255.0"}),
    ];
    for reversed in [false, true] {
        if reversed {
            entries.reverse();
        }
        let result = validate(json!(entries)).unwrap();
        for config in &result.configs {
            assert_eq!(dns(config).unwrap().resolved_group(), Some("selected"));
        }
    }
    for (explicit, has_group) in [
        (json!({}), false),
        (json!({"servers": null}), false),
        (json!({"servers": []}), false),
        (json!({"servers": "system"}), true),
        (json!({"fake_ip": false}), true),
    ] {
        let mut server = listener(1080);
        server["dns"] = explicit.clone();
        let result = validate(json!([
            {"global_settings": {"default_dns": {"servers": "tcp://192.0.2.53", "fake_ip": true}}},
            server
        ]))
        .unwrap();
        let group = dns(&result.configs[0]).unwrap().resolved_group();
        assert_eq!(group.is_some(), has_group, "{explicit}");
        if let Some(name) = group {
            let group = result
                .dns_groups
                .iter()
                .find(|group| group.name == name)
                .unwrap();
            assert_eq!(group.specs[0].url, "system", "{explicit}");
            assert!(group.fake_ip.is_none());
        }
    }
}

#[tokio::test]
async fn default_dns_inline_fake_pool_is_shared_and_system_never_inherits_itself() {
    for servers in [None, Some("udp://127.0.0.1:9")] {
        let mut default = json!({"fake_ip": {"max_entries": 16}});
        if let Some(servers) = servers {
            default["servers"] = json!(servers);
        }
        let result = validate(json!([
            {"global_settings": {"default_dns": default}}, listener(1080), listener(1081)
        ]))
        .unwrap();
        assert_eq!(result.dns_groups.len(), 1);
        assert_eq!(result.dns_groups[0].use_default_resolver, servers.is_none());
        let name = result.dns_groups[0].name.clone();
        assert_eq!(name, "__inline_fake_dns:global_settings");
        for config in &result.configs {
            assert_eq!(dns(config).unwrap().resolved_group(), Some(name.as_str()));
        }
        let mut registry = crate::dns::build_dns_registry(result.dns_groups)
            .await
            .unwrap();
        let first = registry.get_for_server(dns(&result.configs[0]));
        let second = registry.get_for_server(dns(&result.configs[1]));
        assert!(std::sync::Arc::ptr_eq(&first, &second));
        assert!(first.fake_dns_context().is_some());
        assert!(
            registry
                .get_or_create_default()
                .fake_dns_context()
                .is_none()
        );
    }
    for default in [Value::Null, json!({}), json!({"servers": null})] {
        let result = validate(json!([
            {"global_settings": {"default_dns": default}}, listener(1080)
        ]))
        .unwrap();
        assert!(result.dns_groups.is_empty());
        assert!(
            dns(&result.configs[0])
                .and_then(ResolvedDnsConfig::resolved_group)
                .is_none()
        );
    }
}

#[test]
fn default_dns_validates_even_when_no_listener_uses_it() {
    let error = validate(json!([{"global_settings": {"default_dns": {"servers": "missing"}}}]))
        .err()
        .unwrap();
    assert!(
        error.to_string().contains("global_settings.default_dns"),
        "{error}"
    );
    for default in [
        json!({"servers": [{"url": "tcp://192.0.2.53", "bootstrap_url": "missing"}]}),
        json!({"fake_ip": {"max_entries": 0}}),
    ] {
        assert!(validate(json!([{"global_settings": {"default_dns": default}}])).is_err());
    }
    for default in [
        json!("system"),
        json!({"unknown": true}),
        json!({"servers": {"url": "system", "unknown": 1}}),
    ] {
        assert!(
            serde_json::from_value::<Vec<Config>>(json!([
                {"global_settings": {"default_dns": default}}
            ]))
            .is_err()
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn default_dns_reserves_raw_bootstrap_ranges_and_state_paths() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");
    let default =
        json!({"fake_ip": {"ipv4_range": "198.18.0.0/24", "max_entries": 16, "state_file": state}});
    let configs: Vec<Config> = serde_json::from_value(json!([
        {"global_settings": {"default_dns": default}}
    ]))
    .unwrap();
    let registry =
        crate::dns::DnsRegistry::for_rule_bootstrap(&configs, &[], GlobalLimits::default())
            .unwrap();
    assert!(registry.rule_bootstrap("udp://198.18.0.5").await.is_err());
    assert!(registry.rule_bootstrap("udp://192.0.2.53").await.is_ok());
    assert!(!state.exists());
    let error = validate(json!([
        {"global_settings": {"default_dns": default, "rule_cache_dir": dir.path()}}
    ]))
    .err()
    .unwrap();
    assert!(error.to_string().contains("overlaps"), "{error}");
    let error = validate(json!([
        {"global_settings": {"default_dns": default}},
        {"dns_group": "other", "dns_servers": "system", "fake_ip": {"state_file": state}}
    ]))
    .err()
    .unwrap();
    assert!(error.to_string().contains("same state_file"), "{error}");
}

#[tokio::test]
async fn default_dns_clients_participate_in_pem_loading_and_client_visits() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.pem");
    let key_path = dir.path().join("client.key");
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = generated.cert.pem();
    std::fs::write(&path, &certificate).unwrap();
    std::fs::write(&key_path, generated.signing_key.serialize_pem()).unwrap();
    let mut configs: Vec<Config> = serde_json::from_value(json!([
        {"global_settings": {"default_dns": {"servers": {
            "url": "tcp://192.0.2.53", "client_chain": {
                "address": "127.0.0.1:443", "protocol": {
                    "type": "tls", "cert": path, "key": key_path, "protocol": {"type": "socks"}
                }
            }
        }}}}
    ]))
    .unwrap();
    let mut visits = 0;
    crate::config::client_visit::visit_source_configs(&mut configs, &mut |_| {
        visits += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(visits, 1);
    assert!(
        crate::config::pem_reload_dependencies(&mut configs)
            .unwrap()
            .contains(&path)
    );
    let (configs, loaded) = crate::config::convert_cert_paths(configs).await.unwrap();
    assert_eq!(loaded, 2);
    let validated = create_server_configs(configs).unwrap();
    let serialized =
        serde_json::to_string(&validated.dns_groups[0].specs[0].client_chains).unwrap();
    assert!(serialized.contains("BEGIN CERTIFICATE"));
    assert!(!serialized.contains(path.to_str().unwrap()));
}
