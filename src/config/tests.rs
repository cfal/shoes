use super::{compile_configs, convert_cert_paths, load_configs, parse_config_yaml};

#[tokio::test]
async fn nested_parse_errors_include_source_and_field_context_without_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nested.yaml");
    let prefix = r#"- clash_api_address: '127.0.0.1:9090'
  secret: CONTROLLER_SECRET_SENTINEL
- pem: private
  data: |
    -----BEGIN PRIVATE KEY-----
    PEM_SECRET_SENTINEL
    -----END PRIVATE KEY-----
"#;
    for (entry, context) in [
        (
            r#"- rule_group: imported
  rules:
    - path: [VALUE_SECRET_SENTINEL]
"#,
            "rules[0]",
        ),
        (
            r#"- rule_group: imported
  rules:
    - first.srs
    - path: second.srs
      unsupported_policy: VALUE_SECRET_SENTINEL
"#,
            "rules[1]",
        ),
        (
            r#"- rule_group: policy
  rules:
    action: [VALUE_SECRET_SENTINEL]
"#,
            "rules:",
        ),
        (
            r#"- global_limits:
    unsupported_policy: VALUE_SECRET_SENTINEL
"#,
            "unknown field `unsupported_policy`",
        ),
        (
            r#"- address: '127.0.0.1:1080'
  protocol: {type: socks, password: PASSWORD_SECRET_SENTINEL}
  tcp_settings:
    no_delay: [VALUE_SECRET_SENTINEL]
"#,
            "tcp_settings",
        ),
        (
            r#"- address: '127.0.0.1:1080'
  protocol: {type: socks, password: PASSWORD_SECRET_SENTINEL}
  tcp_settings:
    unsupported_policy: VALUE_SECRET_SENTINEL
"#,
            "unknown field `unsupported_policy`",
        ),
    ] {
        std::fs::write(&path, format!("{prefix}{entry}")).unwrap();
        let Err(error) = load_configs(&vec![path.to_str().unwrap().into()]).await else {
            panic!("invalid configuration must reject");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        let diagnostic = error.to_string();
        assert!(diagnostic.contains(path.to_str().unwrap()), "{diagnostic}");
        assert!(diagnostic.contains(context), "{diagnostic}");
        assert!(diagnostic.contains("config[2]"), "{diagnostic}");
        assert!(!diagnostic.contains("SECRET_SENTINEL"), "{diagnostic}");
        assert!(!diagnostic.contains("BEGIN PRIVATE KEY"), "{diagnostic}");
    }
}

#[test]
fn loader_preserves_strict_document_structure() {
    for invalid in [
        r#"address: '127.0.0.1:1080'
protocol: {type: socks}"#,
        r#"[]
---
[]"#,
        "- 42",
        r#"- global_limits: {}
  global_limits: {}"#,
        r#"- pem: private
  data: SECRET_SENTINEL
  unsupported_policy: true"#,
        r#"- pem: private
  path: private.pem
  unsupported_policy: true"#,
    ] {
        let Err(error) = parse_config_yaml(invalid) else {
            panic!("invalid document must reject");
        };
        let error = error.to_string();
        assert!(!error.contains("SECRET_SENTINEL"), "{error}");
    }
    assert!(parse_config_yaml("[]").unwrap().is_empty());
}

#[test]
fn loader_preserves_yaml_error_locations() {
    for prefix in ["# lead\n", "---\n", "\n", ""] {
        for invalid in [
            "- address: '127.0.0.1:1080'\n  tcp_settings: [\n",
            "- global_limits: {}\n  global_limits: {}\n",
            "- global_limits: {}\n- global_limits: {}\n  global_limits: {}\n",
        ] {
            let yaml = format!("{prefix}{invalid}");
            let Err(expected) = serde_yaml::from_str::<Vec<super::Config>>(&yaml) else {
                panic!("invalid YAML must reject");
            };
            let Err(error) = parse_config_yaml(&yaml) else {
                panic!("invalid YAML must reject");
            };
            assert_eq!(error.to_string(), expected.to_string());
            let expected = expected.location().unwrap();
            let actual = error.location().unwrap();
            assert_eq!(actual.line(), expected.line());
            assert_eq!(actual.column(), expected.column());
        }
    }
}

#[test]
fn loader_reports_first_invalid_entry_before_decoding_later_entries() {
    let yaml = r#"- global_limits: {unsupported_policy: true}
- global_limits: {}
  global_limits: {}
"#;
    let Err(error) = parse_config_yaml(yaml) else {
        panic!("invalid configuration must reject");
    };
    let diagnostic = error.to_string();
    assert!(diagnostic.contains("config[0]"), "{diagnostic}");
    assert!(
        diagnostic.contains("unknown field `unsupported_policy`"),
        "{diagnostic}"
    );
}

#[test]
fn tcp_settings_reject_unknown_fields_for_servers_and_clients() {
    for yaml in [
        r#"- address: '127.0.0.1:1080'
  protocol: {type: socks}
  tcp_settings: {unsupported_policy: true}"#,
        r#"- client_group: proxy
  client_proxies:
    address: '127.0.0.1:1080'
    protocol: {type: socks}
    tcp_settings: {unsupported_policy: true}"#,
    ] {
        assert!(parse_config_yaml(yaml).is_err());
        assert!(parse_config_yaml(&yaml.replace("unsupported_policy", "no_delay")).is_ok());
    }
}

#[tokio::test]
async fn representative_examples_pass_native_validation() {
    for example in [
        "socks_basic.yaml",
        "http_through_socks.yaml",
        "multi_hop_chain.yaml",
        "clash_api.yaml",
        "rule_sources.yaml",
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples")
            .join(example);
        let configs = load_configs(&vec![path.to_str().unwrap().into()])
            .await
            .unwrap_or_else(|error| panic!("{example}: {error}"));
        let (configs, _) = convert_cert_paths(configs)
            .await
            .unwrap_or_else(|error| panic!("{example}: {error}"));
        let validated = compile_configs(configs)
            .await
            .unwrap_or_else(|error| panic!("{example}: {error}"));
        if validated.catalog.is_some() {
            crate::control::validation::validate_resources(&validated)
                .unwrap_or_else(|error| panic!("{example}: {error}"));
        }
        assert!(!validated.configs.is_empty(), "{example}");
    }
}
