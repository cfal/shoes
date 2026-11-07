use super::*;
use serde_json::json;
use std::net::IpAddr;

fn validate(yaml: &str) -> std::io::Result<ValidatedConfigs> {
    create_server_configs(serde_yaml::from_str(yaml).map_err(std::io::Error::other)?)
}

fn address(group: &ExpandedDnsGroup, name: &str) -> IpAddr {
    group.hosts.lookup(name).unwrap()[0]
}

#[test]
fn hosts_compose_with_local_then_reference_order_precedence() {
    let validated = validate(
        r#"
- dns_group: first
  hosts: {same.test: 192.0.2.1, first.test: 192.0.2.10}
  dns_servers: system
- dns_group: second
  hosts: {same.test: 192.0.2.2, second.test: 192.0.2.20}
  dns_servers: udp://192.0.2.53
- dns_group: composed
  dns_servers: [first, second]
- dns_group: override
  hosts: {SAME.test.: 192.0.2.3}
  dns_servers: composed
- address: 127.0.0.1:1080
  protocol: {type: socks}
  dns:
    hosts: {same.test: 192.0.2.4}
    servers: override
"#,
    )
    .unwrap();
    for (name, expected) in [
        ("first", "192.0.2.1"),
        ("second", "192.0.2.2"),
        ("composed", "192.0.2.1"),
        ("override", "192.0.2.3"),
        ("__inline_dns_0", "192.0.2.4"),
    ] {
        let group = validated
            .dns_groups
            .iter()
            .find(|group| group.name == name)
            .unwrap();
        assert_eq!(
            address(group, "same.test"),
            expected.parse::<IpAddr>().unwrap()
        );
        if name == "composed" || name == "override" || name == "__inline_dns_0" {
            assert_eq!(group.specs.len(), 2);
            assert!(group.hosts.lookup("first.test").is_some());
            assert!(group.hosts.lookup("second.test").is_some());
        }
    }
}

#[test]
fn hosts_only_inline_defaults_and_explicit_dns_replacement() {
    let validated = validate(
        r#"
- global_settings:
    default_dns:
      hosts: {global.test: 192.0.2.1}
- address: 127.0.0.1:1080
  protocol: {type: socks}
- address: 127.0.0.1:1081
  protocol: {type: socks}
  dns:
    hosts: {local.test: 192.0.2.2}
- address: 127.0.0.1:1082
  protocol: {type: socks}
  dns: {}
- device_name: tun0
  address: 10.0.0.1
  netmask: 255.255.255.0
"#,
    )
    .unwrap();
    assert_eq!(validated.dns_groups.len(), 2);
    for group in &validated.dns_groups {
        assert!(group.use_default_resolver);
        assert_eq!(group.specs[0].url, "system");
        assert_ne!(
            group.hosts.lookup("global.test").is_some(),
            group.hosts.lookup("local.test").is_some()
        );
    }
    let bindings: Vec<_> = validated
        .configs
        .iter()
        .map(|config| match config {
            ResolvedConfig::Server(server) => server
                .dns
                .as_ref()
                .and_then(ResolvedDnsConfig::resolved_group),
            ResolvedConfig::TunServer(tun) => {
                tun.dns.as_ref().and_then(ResolvedDnsConfig::resolved_group)
            }
        })
        .collect();
    assert_eq!(bindings[0], bindings[3]);
    assert_ne!(bindings[0], bindings[1]);
    assert!(bindings[2].is_none());
}

#[test]
fn hosts_overlay_on_fake_group_requires_an_explicit_context_policy() {
    let mut config = json!([
        {"dns_group": "shared", "dns_servers": "system", "fake_ip": true},
        {"address": "0.0.0.0:1080", "protocol": {"type": "socks"},
         "dns": {"servers": "shared", "hosts": {"proxy.test": "192.0.2.1"}}}
    ]);
    let error = validate(&config.to_string()).err().unwrap();
    assert!(
        error
            .to_string()
            .contains("put hosts on the referenced group"),
        "{error}"
    );
    for policy in [false, true] {
        config[1]["dns"]["fake_ip"] = json!(policy);
        assert!(validate(&config.to_string()).is_ok());
    }
    let dns = config[1]["dns"].as_object_mut().unwrap();
    dns.remove("hosts");
    dns.remove("fake_ip");
    dns.insert("servers".into(), json!(["shared", "system"]));
    let error = validate(&config.to_string()).err().unwrap();
    assert!(
        error
            .to_string()
            .contains("reference the group directly to share its pool"),
        "{error}"
    );
    assert!(!error.to_string().contains("hosts"), "{error}");
}

#[test]
fn hosts_reject_protected_addresses_and_preserve_empty_serialization() {
    for ip in ["198.18.0.5", "::ffff:198.18.0.5", "2001:2::5"] {
        let config = json!([
            {"dns_group": "static", "hosts": {"proxy.test": ip}, "dns_servers": "system"},
            {"dns_group": "fake", "dns_servers": "system", "fake_ip": {"ipv6_range": "2001:2::/48"}}
        ]);
        let error = validate(&config.to_string()).err().unwrap();
        assert!(
            error.to_string().contains("static hosts address"),
            "{error}"
        );
    }
    let config: DnsConfig = serde_yaml::from_str("servers: system").unwrap();
    assert!(serde_json::to_value(config).unwrap().get("hosts").is_none());
    for hosts in ["null", "[]", "{example: []}", "{example: not-an-ip}"] {
        assert!(
            validate(&format!(
                "- address: 127.0.0.1:1080\n  protocol: {{type: socks}}\n  dns: {{hosts: {hosts}}}"
            ))
            .is_err(),
            "accepted hosts: {hosts}"
        );
    }
}
