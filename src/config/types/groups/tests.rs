use super::*;
use crate::address::{NetLocation, NetLocationMask};
use crate::config::types::client::ClientProxyConfig;
use crate::config::types::rules::ClientChain;
use crate::config::types::rules::{ClientChainHop, RuleActionConfig};
use crate::config::types::transport::Transport;
use crate::option_util::NoneOrSome;
use std::net::{IpAddr, Ipv4Addr};

fn create_test_client_config() -> ClientConfig {
    ClientConfig {
        name: None,
        control: None,
        bind_interface: crate::option_util::NoneOrOne::One("eth0".to_string()),
        address: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 1080),
        protocol: ClientProxyConfig::Socks {
            username: Some("client_user".to_string()),
            password: Some("client_pass".to_string()),
        },
        transport: Transport::Tcp,
        tcp_settings: None,
        quic_settings: None,
    }
}

fn create_test_rule_config() -> RuleConfig {
    RuleConfig {
        criteria: super::super::rules::RuleCriteria {
            description: None,
            expression: crate::rules::Expression::Legacy(OneOrSome::Some(vec![
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
fn test_client_config_group() {
    let original = vec![Config::ClientConfigGroup(ClientConfigGroup {
        group_type: Default::default(),
        default: None,
        client_group: "test-client-group".to_string(),
        client_proxies: OneOrSome::Some(vec![
            ConfigSelection::Config(create_test_client_config()),
            ConfigSelection::Config(ClientConfig {
                name: None,
                control: None,
                bind_interface: crate::option_util::NoneOrOne::None,
                address: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
                protocol: ClientProxyConfig::Http {
                    username: None,
                    password: None,
                    resolve_hostname: false,
                    http_version: Default::default(),
                },
                transport: Transport::Tcp,
                tcp_settings: None,
                quic_settings: None,
            }),
        ]),
    })];

    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    let deserialized: Vec<Config> = serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");

    assert_eq!(deserialized.len(), 1);
    let Config::ClientConfigGroup(group) = &deserialized[0] else {
        panic!("Expected client config group");
    };
    assert_eq!(group.client_group, "test-client-group");
    match &group.client_proxies {
        OneOrSome::Some(vec) => assert_eq!(vec.len(), 2),
        OneOrSome::One(_) => panic!("Expected Some(vec), got One"),
    }
}

#[test]
fn test_client_config_group_with_group_refs() {
    let yaml = r#"
client_group: all-proxies
client_proxies:
  - us-proxies
  - eu-proxies
"#;
    let group: ClientConfigGroup = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(group.client_group, "all-proxies");
    let proxies: Vec<_> = group.client_proxies.into_vec();
    assert_eq!(proxies.len(), 2);
    assert!(matches!(&proxies[0], ConfigSelection::GroupName(n) if n == "us-proxies"));
    assert!(matches!(&proxies[1], ConfigSelection::GroupName(n) if n == "eu-proxies"));
}

#[test]
fn test_client_config_group_mixed() {
    let yaml = r#"
client_group: mixed-group
client_proxies:
  - other-group
  - address: "127.0.0.1:1080"
    protocol:
      type: direct
"#;
    let group: ClientConfigGroup = serde_yaml::from_str(yaml).unwrap();
    let proxies: Vec<_> = group.client_proxies.into_vec();
    assert_eq!(proxies.len(), 2);
    assert!(matches!(&proxies[0], ConfigSelection::GroupName(_)));
    assert!(matches!(&proxies[1], ConfigSelection::Config(_)));
}

#[test]
fn rule_group_members_determine_kind_not_action_presence() {
    for yaml in [
        "rule_group: policies\nrules: [{masks: example.com}]",
        "rule_group: policies\nrule: {mask: example.com, action: block}",
    ] {
        let group: RuleConfigGroup = serde_yaml::from_str(yaml).unwrap();
        let RuleGroupRules::Policies(_) = group.rules else {
            panic!("expected policies")
        };
        let encoded = serde_yaml::to_string(&group).unwrap();
        let group: RuleConfigGroup = serde_yaml::from_str(&encoded).unwrap();
        assert!(matches!(group.rules, RuleGroupRules::Policies(_)));
    }
    for yaml in [
        "rule_group: files\nrules: [a.srs, {path: b, format: srs}]",
        "rule_group: files\nrule: a.srs",
        "rule_group: files\nrule: [a.srs, {path: b, format: srs}]",
        "rule_group: files\nrules: {path: a.txt, behavior: domain}",
    ] {
        let group: RuleConfigGroup = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(group.rules, RuleGroupRules::Sources(_)));
        let encoded = serde_yaml::to_string(&group).unwrap();
        let group: RuleConfigGroup = serde_yaml::from_str(&encoded).unwrap();
        assert!(matches!(group.rules, RuleGroupRules::Sources(_)));
    }
    for (rules, error) in [
        ("[]", "cannot be empty"),
        ("[a.srs, {masks: example.com}]", "cannot mix"),
        ("[{masks: example.com}, {path: a.srs}]", "cannot mix"),
        ("[{path: a.srs, action: block}]", "unknown field `action`"),
        ("[{path: a.srs, fromat: srs}]", "unknown field `fromat`"),
        ("[{rule_group: other}]", "unknown field `rule_group`"),
    ] {
        let result =
            serde_yaml::from_str::<RuleConfigGroup>(&format!("rule_group: x\nrules: {rules}"));
        assert!(result.unwrap_err().to_string().contains(error), "{rules}");
    }
    let error = serde_yaml::from_str::<Config>("rule_set: old\npath: a.srs").unwrap_err();
    assert!(error.to_string().contains("replaced by rule_group"));
}

#[test]
fn test_rule_config_group() {
    let original = vec![Config::RuleConfigGroup(RuleConfigGroup {
        rule_group: "test-rule-group".to_string(),
        rules: RuleGroupRules::Policies(Box::new(OneOrSome::Some(vec![
            create_test_rule_config(),
            RuleConfig {
                criteria: Default::default(),
                action: RuleActionConfig::Block,
            },
        ]))),
    })];

    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    let deserialized: Vec<Config> = serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");

    assert_eq!(deserialized.len(), 1);
    let Config::RuleConfigGroup(group) = &deserialized[0] else {
        panic!("Expected rule config group");
    };
    assert_eq!(group.rule_group, "test-rule-group");
    let RuleGroupRules::Policies(rules) = &group.rules else {
        panic!("Expected policies");
    };
    assert!(matches!(rules.as_ref(), OneOrSome::Some(values) if values.len() == 2));
}

#[test]
fn test_config_error_messages() {
    // Test invalid config with no recognized fields
    let invalid_yaml = r#"
        - foo: bar
          baz: qux
        "#;

    let result: Result<Vec<Config>, _> = serde_yaml::from_str(invalid_yaml);
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    println!("Error for invalid config: {error_msg}");
    assert!(error_msg.contains("Unable to determine config type"));
    assert!(error_msg.contains("Found fields: "));
    assert!(error_msg.contains("foo"));
    assert!(error_msg.contains("baz"));
}

#[test]
fn test_named_pem() {
    // Test with path
    let pem_with_path = NamedPem {
        pem: "my-server-pem".to_string(),
        source: PemSource::Path("/etc/certs/server.pem".to_string()),
    };

    let yaml = serde_yaml::to_string(&pem_with_path).unwrap();
    println!("NamedPem with path YAML:\n{yaml}");
    assert!(yaml.contains("pem: my-server-pem"));
    assert!(yaml.contains("path: /etc/certs/server.pem"));

    let deserialized: NamedPem = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(deserialized.pem, "my-server-pem");
    match deserialized.source {
        PemSource::Path(p) => assert_eq!(p, "/etc/certs/server.pem"),
        _ => panic!("Expected Path source"),
    }

    // Test with data (combined cert and key)
    let pem_with_data = NamedPem {
            pem: "inline-pem".to_string(),
            source: PemSource::Data(
                "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHHI...\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nMIIEvQ...\n-----END PRIVATE KEY-----".to_string(),
            ),
        };

    let yaml = serde_yaml::to_string(&pem_with_data).unwrap();
    println!("NamedPem with data YAML:\n{yaml}");
    assert!(yaml.contains("pem: inline-pem"));
    assert!(yaml.contains("data: "));
    assert!(yaml.contains("-----BEGIN CERTIFICATE-----"));
    assert!(yaml.contains("-----BEGIN PRIVATE KEY-----"));

    let deserialized: NamedPem = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(deserialized.pem, "inline-pem");
    match deserialized.source {
        PemSource::Data(d) => {
            assert!(d.contains("-----BEGIN CERTIFICATE-----"));
            assert!(d.contains("-----BEGIN PRIVATE KEY-----"));
        }
        _ => panic!("Expected Data source"),
    }
}

#[test]
fn test_named_pem_invalid_yaml() {
    // Missing pem field
    let yaml = r#"
        path: /etc/certs/server.pem
        "#;
    let result: Result<NamedPem, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("missing field `pem`")
    );

    // Missing source (no path or data)
    let yaml = r#"
        pem: my-pem
        "#;
    let result: Result<NamedPem, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("must have either 'path' or 'data'")
    );

    // Both path and data
    let yaml = r#"
        pem: my-pem
        path: /etc/certs/server.pem
        data: "-----BEGIN CERTIFICATE-----"
        "#;
    let result: Result<NamedPem, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("cannot have both 'path' and 'data'")
    );
}

#[test]
fn test_config_with_named_pems() {
    // Test NamedPem as Config with path
    let pem_config = Config::NamedPem(NamedPem {
        pem: "web-server-pem".to_string(),
        source: PemSource::Path("/etc/certs/web.pem".to_string()),
    });

    let yaml = serde_yaml::to_string(&pem_config).unwrap();
    println!("Config::NamedPem YAML:\n{yaml}");

    let deserialized: Config = serde_yaml::from_str(&yaml).unwrap();
    match deserialized {
        Config::NamedPem(pem) => {
            assert_eq!(pem.pem, "web-server-pem");
            match pem.source {
                PemSource::Path(p) => assert_eq!(p, "/etc/certs/web.pem"),
                _ => panic!("Expected Path source"),
            }
        }
        _ => panic!("Expected NamedPem config"),
    }

    // Test NamedPem as Config with data
    let pem_config_data = Config::NamedPem(NamedPem {
            pem: "web-server-pem-data".to_string(),
            source: PemSource::Data("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----".to_string()),
        });

    let yaml = serde_yaml::to_string(&pem_config_data).unwrap();
    println!("Config::NamedPem with data YAML:\n{yaml}");

    let deserialized: Config = serde_yaml::from_str(&yaml).unwrap();
    match deserialized {
        Config::NamedPem(pem) => {
            assert_eq!(pem.pem, "web-server-pem-data");
            match pem.source {
                PemSource::Data(d) => {
                    assert!(d.contains("-----BEGIN CERTIFICATE-----"));
                    assert!(d.contains("-----BEGIN PRIVATE KEY-----"));
                }
                _ => panic!("Expected Data source"),
            }
        }
        _ => panic!("Expected NamedPem config"),
    }
}

#[test]
fn test_server_config_with_addresses_alias() {
    let yaml = r#"
- addresses:
    - "127.0.0.1:22223"
    - "172.17.0.1:22223-22225"
  protocol:
    type: http
"#;

    let configs: Vec<Config> = serde_yaml::from_str(yaml).unwrap();
    let Config::Server(server) = &configs[0] else {
        panic!("expected server config");
    };
    assert_eq!(
        server.bind_location.to_string(),
        "127.0.0.1:22223, 172.17.0.1:22223-22225"
    );

    let serialized = serde_yaml::to_value(&configs[0]).unwrap();
    let mapping = serialized.as_mapping().unwrap();
    assert!(mapping.contains_key(serde_yaml::Value::String("address".to_string())));
    assert!(!mapping.contains_key(serde_yaml::Value::String("addresses".to_string())));
}

#[test]
fn test_rejects_unknown_field_in_client_config_group() {
    let yaml = r#"
- client_group: my-proxies
  client_proxies:
    - address: "127.0.0.1:9090"
      protocol:
        type: socks
  extra_field: "should fail"
"#;
    let result: Result<Vec<Config>, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown field `extra_field`"),
        "Error should mention unknown field: {err}"
    );
}

#[test]
fn test_rejects_unknown_field_in_rule_config_group() {
    let yaml = r#"
- rule_group: my-rules
  rules:
    - mask: 0.0.0.0/0
      action: allow
  bogus_field: 42
"#;
    let result: Result<Vec<Config>, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown field `bogus_field`"),
        "Error should mention unknown field: {err}"
    );
}

#[test]
fn test_example_files_load_and_validate() {
    use crate::thread_util;
    use std::path::{Path, PathBuf};

    // Initialize thread count for the test environment if not already set
    // set_num_threads will panic if NUM_THREADS is already set by another test
    let _ = std::panic::catch_unwind(|| {
        thread_util::set_num_threads(4);
    });

    // Get the examples directory relative to the project root
    let examples_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");

    // Read all YAML files in the examples directory
    let mut example_files: Vec<PathBuf> = std::fs::read_dir(&examples_dir)
        .expect("Failed to read examples directory")
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.extension()?.to_str()? == "yaml" {
                Some(path)
            } else {
                None
            }
        })
        .collect();

    // Sort files for consistent test output
    example_files.sort();

    assert!(!example_files.is_empty(), "No example YAML files found");
    println!("Found {} example files to test", example_files.len());

    let mut failures = Vec::new();

    // Test each example file
    for example_file in &example_files {
        let file_name = example_file.file_name().unwrap().to_str().unwrap();
        println!("\nTesting example file: {file_name}");

        // Read the file
        let content = match std::fs::read_to_string(example_file) {
            Ok(c) => c,
            Err(e) => {
                failures.push(format!("- {file_name}: Failed to read file: {e}"));
                continue;
            }
        };

        // Parse the YAML
        let mut configs: Vec<Config> = match serde_yaml::from_str(&content) {
            Ok(c) => c,
            Err(e) => {
                failures.push(format!("- {file_name}: Failed to parse YAML: {e}"));
                continue;
            }
        };

        let mut compiler = crate::rules::Compiler::default();
        let compiled = crate::rule_set::anchor(&mut configs, example_file)
            .and_then(|()| crate::rule_set::load(&mut configs, &mut compiler))
            .and_then(|()| crate::config::rule_visit::compile(&mut configs, &mut compiler));
        if let Err(error) = compiled {
            failures.push(format!("- {file_name}: invalid rules: {error}"));
            continue;
        }
        if file_name == "mixed.yaml" {
            let certificate =
                rcgen::generate_simple_self_signed(vec!["proxy.local".into()]).unwrap();
            for config in &mut configs {
                if let Config::Server(server) = config
                    && let crate::config::ServerProxyConfig::Tls { tls_targets, .. } =
                        &mut server.protocol
                {
                    for target in tls_targets.values_mut() {
                        target.cert = certificate.cert.pem();
                        target.key = certificate.signing_key.serialize_pem();
                    }
                }
            }
            crate::config::create_server_configs(configs.clone())
                .expect("mixed example must pass full validation");
        }
        // Other examples contain deployment-specific certificates and keys.
        println!("  ✓ Parsed successfully ({} configs)", configs.len());
    }

    if !failures.is_empty() {
        panic!(
            "Example config validation failed for {} files:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}
