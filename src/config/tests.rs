use super::{compile_configs, convert_cert_paths, load_configs};

#[tokio::test]
async fn nested_parse_errors_include_source_and_field_context_without_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nested.yaml");
    let prefix = "- clash_api_address: '127.0.0.1:9090'\n  secret: CONTROLLER_SECRET_SENTINEL\n\
                  - pem: private\n  data: |\n    -----BEGIN PRIVATE KEY-----\n    PEM_SECRET_SENTINEL\n    -----END PRIVATE KEY-----\n";
    for (entry, context) in [
        (
            "- rule_group: imported\n  rules:\n    - path: [VALUE_SECRET_SENTINEL]\n",
            "rules[0]",
        ),
        (
            "- rule_group: imported\n  rules:\n    - first.srs\n    - path: second.srs\n      unsupported_policy: VALUE_SECRET_SENTINEL\n",
            "rules[1]",
        ),
        (
            "- rule_group: policy\n  rules:\n    action: [VALUE_SECRET_SENTINEL]\n",
            "rules:",
        ),
        (
            "- global_limits:\n    unsupported_policy: VALUE_SECRET_SENTINEL\n",
            "unknown field `unsupported_policy`",
        ),
        (
            "- address: '127.0.0.1:1080'\n  protocol: {type: socks, password: PASSWORD_SECRET_SENTINEL}\n  tcp_settings:\n    no_delay: [VALUE_SECRET_SENTINEL]\n",
            "tcp_settings",
        ),
        (
            "- address: '127.0.0.1:1080'\n  protocol: {type: socks, password: PASSWORD_SECRET_SENTINEL}\n  tcp_settings:\n    unsupported_policy: VALUE_SECRET_SENTINEL\n",
            "unknown field `unsupported_policy`",
        ),
    ] {
        std::fs::write(&path, format!("{prefix}{entry}")).unwrap();
        let error = load_configs(&vec![path.to_str().unwrap().into()])
            .await
            .err()
            .expect("invalid configuration must reject");
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
        "address: '127.0.0.1:1080'\nprotocol: {type: socks}",
        "[]\n---\n[]",
        "- 42",
        "- global_limits: {}\n  global_limits: {}",
        "- pem: private\n  data: SECRET_SENTINEL\n  unsupported_policy: true",
        "- pem: private\n  path: private.pem\n  unsupported_policy: true",
    ] {
        let error = super::parse_config_yaml(invalid)
            .err()
            .expect("invalid document must reject")
            .to_string();
        assert!(!error.contains("SECRET_SENTINEL"), "{error}");
    }
    assert!(super::parse_config_yaml("[]").unwrap().is_empty());
}

#[test]
fn tcp_settings_reject_unknown_fields_for_servers_and_clients() {
    for yaml in [
        "- address: '127.0.0.1:1080'\n  protocol: {type: socks}\n  tcp_settings: {unsupported_policy: true}",
        "- client_group: proxy\n  client_proxies:\n    address: '127.0.0.1:1080'\n    protocol: {type: socks}\n    tcp_settings: {unsupported_policy: true}",
    ] {
        assert!(super::parse_config_yaml(yaml).is_err());
        assert!(super::parse_config_yaml(&yaml.replace("unsupported_policy", "no_delay")).is_ok());
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
