use super::*;
use std::net::{IpAddr, Ipv4Addr};

fn create_test_rule_config() -> RuleConfig {
    RuleConfig {
        criteria: RuleCriteria {
            description: None,
            expression: Expression::Legacy(OneOrSome::Some(vec![
                NetLocationMask::from("192.168.0.0/16:80").unwrap(),
                NetLocationMask::from("10.0.0.0/8:443").unwrap(),
            ])),
            ..Default::default()
        },
        action: RuleActionConfig::Allow {
            override_address: Some(NetLocation::from_ip_addr(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                8080,
            )),
            client_chains: NoneOrSome::One(ClientChain {
                hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::GroupName(
                    "test-proxy-group".to_string(),
                ))),
            }),
        },
    }
}

#[test]
fn legacy_masks_keep_scalar_and_list_serialization() {
    for masks in [
        "example.com",
        "[example.com]",
        "[example.com, '192.0.2.0/24']",
    ] {
        let rule: RuleConfig = serde_yaml::from_str(&format!("masks: {masks}")).unwrap();
        let encoded = serde_yaml::to_value(&rule).unwrap();
        let expected: serde_yaml::Value = serde_yaml::from_str(masks).unwrap();
        assert_eq!(encoded["masks"], expected);
    }
    let default = serde_yaml::to_value(RuleConfig::default()).unwrap();
    assert_eq!(default["masks"], "0.0.0.0/0");
    let error = serde_yaml::from_str::<RuleConfig>("masks: []\naction: invalid")
        .unwrap_err()
        .to_string();
    assert!(error.contains("masks cannot be empty"), "{error}");
}

#[test]
fn mixed_masks_round_trip_without_reinterpreting_strings() {
    for masks in [
        "blocked",
        "[blocked, {domain: [exact.example]}, '192.0.2.0/24']",
        "{all: [blocked, {not: {destination_port: [80]}}]}",
    ] {
        let rule: RuleConfig = serde_yaml::from_str(&format!("masks: {masks}")).unwrap();
        assert!(matches!(rule.action, RuleActionConfig::Allow { .. }));
        let encoded = serde_yaml::to_string(&rule).unwrap();
        let mut rule: RuleConfig = serde_yaml::from_str(&encoded).unwrap();
        rule.compile(&mut crate::rules::Compiler::default())
            .unwrap();
        let predicate = rule.criteria.compiled.unwrap();
        assert_eq!(
            predicate.evaluate(Some("child.blocked"), None, 443),
            crate::rules::Outcome::Match
        );
        assert_ne!(
            predicate.evaluate(Some("other.example"), None, 443),
            crate::rules::Outcome::Match
        );
    }
}

#[test]
fn typed_rule_round_trip_and_validation() {
    let input = "masks: {all: [{domain: [Example.com]}, {destination_port: [443]}]}\nno_resolve: true\naction: block";
    let rule: RuleConfig = serde_yaml::from_str(input).unwrap();
    let encoded = serde_yaml::to_string(&rule).unwrap();
    let mut rule: RuleConfig = serde_yaml::from_str(&encoded).unwrap();
    rule.compile(&mut crate::rules::Compiler::default())
        .unwrap();
    assert_eq!(
        rule.criteria
            .compiled
            .as_ref()
            .unwrap()
            .evaluate(Some("example.com"), None, 443),
        crate::rules::Outcome::Match
    );
    assert!(serde_yaml::to_string(&rule).is_err());
    for input in [
        "match: {any_destination: true}\nmasks: example.com",
        "rule_sets: [old]",
        "masks: {unknown: true}",
        "masks: {domain: [a], ip_cidr: [\"::/0\"]}",
        "masks: {path: a.srs, rule_group: other}",
        "masks: {path: a.srs, fromat: srs}",
        "masks: {path: a.srs, action: block}",
        "masks: []",
        "masks: {all: []}",
        "masks: {any: []}",
    ] {
        assert!(
            serde_yaml::from_str::<RuleConfig>(input).is_err(),
            "{input}"
        );
    }
}

#[test]
fn test_rule_config_serialization() {
    let original = create_test_rule_config();
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    println!("Rule config YAML:\n{yaml_str}");
    let deserialized: RuleConfig = serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
    assert!(matches!(
        deserialized.action,
        RuleActionConfig::Allow { .. }
    ));
}

#[test]
fn test_rule_config_block() {
    let yaml = r#"
masks: 0.0.0.0/0
action: block
"#;
    let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok());
    assert!(matches!(result.unwrap().action, RuleActionConfig::Block));
}

#[test]
fn test_rule_config_allow() {
    let yaml = r#"
masks: 0.0.0.0/0
action: allow
"#;
    let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok());
    assert!(matches!(
        result.unwrap().action,
        RuleActionConfig::Allow { .. }
    ));
}

#[test]
fn test_rule_config_with_override() {
    let yaml = r#"
masks: 0.0.0.0/0
action: allow
override_address: "127.0.0.1:8080"
"#;
    let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok());
    if let RuleActionConfig::Allow {
        override_address, ..
    } = result.unwrap().action
    {
        assert!(override_address.is_some());
    } else {
        panic!("Expected Allow action");
    }
}

// =========================================================================
// ClientChain deserialization tests
// =========================================================================

#[test]
fn test_client_chain_from_array_of_hops() {
    // Array syntax: [hop1, hop2, ...]
    let yaml = r#"
- my-proxy-group
- exit-proxy
"#;
    let result: Result<ClientChain, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok());
    let chain = result.unwrap();
    assert_eq!(chain.hops.len(), 2);
}

#[test]
fn test_client_chain_from_object_with_chain_key() {
    // Object syntax: { chain: [...] }
    let yaml = r#"
chain:
  - my-proxy-group
  - exit-proxy
"#;
    let result: Result<ClientChain, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok());
    let chain = result.unwrap();
    assert_eq!(chain.hops.len(), 2);
}

#[test]
fn test_client_chain_from_single_string() {
    // Single string: "group-name"
    let yaml = r#"my-proxy-group"#;
    let result: Result<ClientChain, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok());
    let chain = result.unwrap();
    assert_eq!(chain.hops.len(), 1);
    assert!(matches!(
        chain.hops.iter().next().unwrap(),
        ClientChainHop::Single(ConfigSelection::GroupName(n)) if n == "my-proxy-group"
    ));
}

#[test]
fn test_client_chain_from_inline_config() {
    // Inline config object (without 'chain' key)
    let yaml = r#"
address: "127.0.0.1:1080"
protocol:
  type: socks
"#;
    let result: Result<ClientChain, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok());
    let chain = result.unwrap();
    assert_eq!(chain.hops.len(), 1);
    assert!(matches!(
        chain.hops.iter().next().unwrap(),
        ClientChainHop::Single(ConfigSelection::Config(_))
    ));
}

#[test]
fn test_client_chain_differentiates_chain_key_from_proxy_config() {
    // Object with 'chain' key should be parsed as chain syntax
    let yaml_chain = r#"
chain:
  - my-proxy
  - exit-proxy
"#;
    let result: Result<ClientChain, _> = serde_yaml::from_str(yaml_chain);
    assert!(result.is_ok());
    let chain = result.unwrap();
    assert_eq!(chain.hops.len(), 2); // Two hops from the chain array

    // Object without 'chain' key should be parsed as inline proxy config
    let yaml_proxy = r#"
address: "127.0.0.1:1080"
protocol:
  type: socks
"#;
    let result: Result<ClientChain, _> = serde_yaml::from_str(yaml_proxy);
    assert!(result.is_ok());
    let chain = result.unwrap();
    assert_eq!(chain.hops.len(), 1); // Single hop from inline config
    assert!(matches!(
        chain.hops.iter().next().unwrap(),
        ClientChainHop::Single(ConfigSelection::Config(_))
    ));
}

#[test]
fn test_client_chain_empty_array_rejected() {
    let yaml = r#"[]"#;
    let result: Result<ClientChain, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("empty"), "Error should mention empty: {err}");
}

#[test]
fn test_client_chain_empty_chain_key_rejected() {
    let yaml = r#"
chain: []
"#;
    let result: Result<ClientChain, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err());
}

// =========================================================================
// client_chains (plural) tests - multiple chains for round-robin
// =========================================================================

#[test]
fn test_rule_config_with_single_client_chain_backward_compat() {
    // Using singular 'client_chain' should still work
    let yaml = r#"
masks: 0.0.0.0/0
action: allow
client_chain:
  - my-proxy-group
"#;
    let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok());
    if let RuleActionConfig::Allow { client_chains, .. } = result.unwrap().action {
        assert_eq!(client_chains.len(), 1);
        let chain = client_chains.iter().next().unwrap();
        assert_eq!(chain.hops.len(), 1);
    } else {
        panic!("Expected Allow action");
    }
}

#[test]
fn test_rule_config_with_multiple_chains_object_syntax() {
    // Multiple chains using object syntax { chain: [...] }
    let yaml = r#"
masks: 0.0.0.0/0
action: allow
client_chains:
  - chain: [direct]
  - chain: [proxy1, proxy2, proxy3]
  - chain: [proxy4, proxy5]
"#;
    let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok(), "Parse error: {:?}", result.err());
    if let RuleActionConfig::Allow { client_chains, .. } = result.unwrap().action {
        assert_eq!(client_chains.len(), 3);
        let chains: Vec<_> = client_chains.iter().collect();
        assert_eq!(chains[0].hops.len(), 1); // direct
        assert_eq!(chains[1].hops.len(), 3); // proxy1, proxy2, proxy3
        assert_eq!(chains[2].hops.len(), 2); // proxy4, proxy5
    } else {
        panic!("Expected Allow action");
    }
}

#[test]
fn test_rule_config_with_multiple_chains_array_syntax() {
    // Multiple chains using bare array syntax [[...], [...]]
    let yaml = r#"
masks: 0.0.0.0/0
action: allow
client_chains:
  - [direct]
  - [proxy1, proxy2, proxy3]
  - [proxy4, proxy5]
"#;
    let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok(), "Parse error: {:?}", result.err());
    if let RuleActionConfig::Allow { client_chains, .. } = result.unwrap().action {
        assert_eq!(client_chains.len(), 3);
        let chains: Vec<_> = client_chains.iter().collect();
        assert_eq!(chains[0].hops.len(), 1);
        assert_eq!(chains[1].hops.len(), 3);
        assert_eq!(chains[2].hops.len(), 2);
    } else {
        panic!("Expected Allow action");
    }
}

#[test]
fn test_rule_config_with_mixed_chain_syntax() {
    // Mix of object and array syntax
    let yaml = r#"
masks: 0.0.0.0/0
action: allow
client_chains:
  - [direct]
  - chain: [proxy1, proxy2]
  - my-proxy-group
"#;
    let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok(), "Parse error: {:?}", result.err());
    if let RuleActionConfig::Allow { client_chains, .. } = result.unwrap().action {
        assert_eq!(client_chains.len(), 3);
        let chains: Vec<_> = client_chains.iter().collect();
        assert_eq!(chains[0].hops.len(), 1); // [direct]
        assert_eq!(chains[1].hops.len(), 2); // chain: [proxy1, proxy2]
        assert_eq!(chains[2].hops.len(), 1); // my-proxy-group (single string)
    } else {
        panic!("Expected Allow action");
    }
}

#[test]
fn test_rule_config_defaults_to_unspecified() {
    // When no client_chains is specified, defaults to Unspecified
    let yaml = r#"
masks: 0.0.0.0/0
action: allow
"#;
    let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok());
    if let RuleActionConfig::Allow { client_chains, .. } = result.unwrap().action {
        assert!(client_chains.is_unspecified());
    } else {
        panic!("Expected Allow action");
    }
}

#[test]
fn test_rule_config_chains_with_pools() {
    // Chains that contain pools at various hops
    let yaml = r#"
masks: 0.0.0.0/0
action: allow
client_chains:
  - chain:
      - pool: [entry-us, entry-eu]
      - exit-proxy
  - chain:
      - direct
"#;
    let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok(), "Parse error: {:?}", result.err());
    if let RuleActionConfig::Allow { client_chains, .. } = result.unwrap().action {
        assert_eq!(client_chains.len(), 2);
        let chains: Vec<_> = client_chains.iter().collect();
        // First chain has 2 hops, first hop is a pool
        assert_eq!(chains[0].hops.len(), 2);
        assert!(matches!(
            chains[0].hops.iter().next().unwrap(),
            ClientChainHop::Pool(_)
        ));
    } else {
        panic!("Expected Allow action");
    }
}

// =========================================================================
// ClientChainHop tests (unchanged from before)
// =========================================================================

#[test]
fn test_client_chain_hop_single_group_ref() {
    let yaml = r#"my-proxy-group"#;
    let result: Result<ClientChainHop, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok());
    assert!(matches!(
        result.unwrap(),
        ClientChainHop::Single(ConfigSelection::GroupName(_))
    ));
}

#[test]
fn test_client_chain_hop_single_inline_config() {
    let yaml = r#"
address: "127.0.0.1:1080"
protocol:
  type: socks
"#;
    let result: Result<ClientChainHop, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok());
    assert!(matches!(
        result.unwrap(),
        ClientChainHop::Single(ConfigSelection::Config(_))
    ));
}

#[test]
fn test_client_chain_hop_pool_group_refs() {
    let yaml = r#"
pool:
  - us-proxies
  - eu-proxies
"#;
    let result: Result<ClientChainHop, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok());
    if let ClientChainHop::Pool(selections) = result.unwrap() {
        let vec: Vec<_> = selections.into_vec();
        assert_eq!(vec.len(), 2);
        assert!(matches!(&vec[0], ConfigSelection::GroupName(n) if n == "us-proxies"));
        assert!(matches!(&vec[1], ConfigSelection::GroupName(n) if n == "eu-proxies"));
    } else {
        panic!("Expected Pool");
    }
}

#[test]
fn test_client_chain_hop_pool_mixed() {
    let yaml = r#"
pool:
  - my-proxy-group
  - address: "127.0.0.1:1080"
    protocol:
      type: socks
"#;
    let result: Result<ClientChainHop, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok());
    if let ClientChainHop::Pool(selections) = result.unwrap() {
        let vec: Vec<_> = selections.into_vec();
        assert_eq!(vec.len(), 2);
        assert!(matches!(&vec[0], ConfigSelection::GroupName(_)));
        assert!(matches!(&vec[1], ConfigSelection::Config(_)));
    } else {
        panic!("Expected Pool");
    }
}

#[test]
fn test_client_chain_hop_pool_cannot_be_empty() {
    let yaml = r#"
pool: []
"#;
    let result: Result<ClientChainHop, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("pool") || err.contains("empty"),
        "Error should mention pool or empty: {err}"
    );
}

#[test]
fn test_client_chain_hop_pool_single_item() {
    // OneOrSome allows a single item without array syntax
    let yaml = r#"
pool: my-proxy-group
"#;
    let result: Result<ClientChainHop, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok());
    if let ClientChainHop::Pool(selections) = result.unwrap() {
        let vec: Vec<_> = selections.into_vec();
        assert_eq!(vec.len(), 1);
        assert!(matches!(&vec[0], ConfigSelection::GroupName(n) if n == "my-proxy-group"));
    } else {
        panic!("Expected Pool");
    }
}

#[test]
fn test_rejects_both_client_proxies_and_client_chains() {
    let yaml = r#"
masks: 0.0.0.0/0
action: allow
client_proxies:
  - my-group
client_chains:
  - chain: [other-group]
"#;
    let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("cannot specify both"));
}

// =========================================================================
// Serialization tests
// =========================================================================

#[test]
fn test_chain_hop_serialization_roundtrip_single_group() {
    let original = ClientChainHop::Single(ConfigSelection::GroupName("my-group".to_string()));
    let yaml = serde_yaml::to_string(&original).unwrap();
    println!("Single group YAML: {yaml}");
    let deserialized: ClientChainHop = serde_yaml::from_str(&yaml).unwrap();
    assert!(matches!(
        deserialized,
        ClientChainHop::Single(ConfigSelection::GroupName(_))
    ));
}

#[test]
fn test_chain_hop_serialization_roundtrip_single_config() {
    let original = ClientChainHop::Single(ConfigSelection::Config(ClientConfig::default()));
    let yaml = serde_yaml::to_string(&original).unwrap();
    println!("Single config YAML: {yaml}");
    let deserialized: ClientChainHop = serde_yaml::from_str(&yaml).unwrap();
    assert!(matches!(
        deserialized,
        ClientChainHop::Single(ConfigSelection::Config(_))
    ));
}

#[test]
fn test_chain_hop_serialization_roundtrip_pool() {
    let original = ClientChainHop::Pool(OneOrSome::Some(vec![
        ConfigSelection::GroupName("group-a".to_string()),
        ConfigSelection::Config(ClientConfig::default()),
    ]));
    let yaml = serde_yaml::to_string(&original).unwrap();
    println!("Pool YAML: {yaml}");
    assert!(yaml.contains("pool:"));
    let deserialized: ClientChainHop = serde_yaml::from_str(&yaml).unwrap();
    assert!(matches!(deserialized, ClientChainHop::Pool(_)));
}

#[test]
fn test_client_chain_serialization_roundtrip() {
    let original = ClientChain {
        hops: OneOrSome::Some(vec![
            ClientChainHop::Single(ConfigSelection::GroupName("entry".to_string())),
            ClientChainHop::Single(ConfigSelection::GroupName("exit".to_string())),
        ]),
    };
    let yaml = serde_yaml::to_string(&original).unwrap();
    println!("ClientChain YAML:\n{yaml}");
    assert!(yaml.contains("chain:"));
    let deserialized: ClientChain = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(deserialized.hops.len(), 2);
}

#[test]
fn test_multi_hop_chain() {
    let yaml = r#"
masks: 0.0.0.0/0
action: allow
client_chain:
  - pool:
      - entry-proxies-us
      - entry-proxies-eu
  - exit-proxies
"#;
    let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok());
    if let RuleActionConfig::Allow { client_chains, .. } = result.unwrap().action {
        assert_eq!(client_chains.len(), 1);
        let chain = client_chains.iter().next().unwrap();
        assert_eq!(chain.hops.len(), 2);
        // First hop is a pool
        assert!(matches!(
            chain.hops.iter().next().unwrap(),
            ClientChainHop::Pool(_)
        ));
        // Second hop is a single group ref
        assert!(matches!(
            chain.hops.iter().nth(1).unwrap(),
            ClientChainHop::Single(ConfigSelection::GroupName(_))
        ));
    } else {
        panic!("Expected Allow action");
    }
}

// =========================================================================
// Complex multi-chain scenarios
// =========================================================================

#[test]
fn test_direct_with_proxy_fallback() {
    // Round-robin between direct and a proxy chain
    let yaml = r#"
masks: 0.0.0.0/0
action: allow
client_chains:
  - chain: [direct]
  - chain:
      - address: "proxy.example.com:1080"
        protocol:
          type: socks
"#;
    let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok(), "Parse error: {:?}", result.err());
    if let RuleActionConfig::Allow { client_chains, .. } = result.unwrap().action {
        assert_eq!(client_chains.len(), 2);
    } else {
        panic!("Expected Allow action");
    }
}

#[test]
fn test_geographic_load_balancing() {
    // Different paths for different regions
    let yaml = r#"
masks: 0.0.0.0/0
action: allow
client_chains:
  - chain: [us-entry, asia-exit]
  - chain: [eu-entry, asia-exit]
  - chain: [direct]
"#;
    let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok(), "Parse error: {:?}", result.err());
    if let RuleActionConfig::Allow { client_chains, .. } = result.unwrap().action {
        assert_eq!(client_chains.len(), 3);
        let chains: Vec<_> = client_chains.iter().collect();
        assert_eq!(chains[0].hops.len(), 2); // us-entry, asia-exit
        assert_eq!(chains[1].hops.len(), 2); // eu-entry, asia-exit
        assert_eq!(chains[2].hops.len(), 1); // direct
    } else {
        panic!("Expected Allow action");
    }
}

#[test]
fn test_complex_multi_hop_with_pools() {
    // Per-hop load balancing within multi-chain selection
    let yaml = r#"
masks: 0.0.0.0/0
action: allow
client_chains:
  - chain: [direct]
  - chain:
      - pool: [entry-us-1, entry-us-2, entry-eu-1]
      - pool: [middle-relay-a, middle-relay-b]
      - pool: [exit-asia, exit-europe]
  - chain:
      - fast-entry
      - fast-exit
"#;
    let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
    assert!(result.is_ok(), "Parse error: {:?}", result.err());
    if let RuleActionConfig::Allow { client_chains, .. } = result.unwrap().action {
        assert_eq!(client_chains.len(), 3);
        let chains: Vec<_> = client_chains.iter().collect();

        // Chain 1: direct (1 hop)
        assert_eq!(chains[0].hops.len(), 1);

        // Chain 2: 3 hops, all pools
        assert_eq!(chains[1].hops.len(), 3);
        for hop in chains[1].hops.iter() {
            assert!(matches!(hop, ClientChainHop::Pool(_)));
        }

        // Chain 3: 2 hops
        assert_eq!(chains[2].hops.len(), 2);
    } else {
        panic!("Expected Allow action");
    }
}
