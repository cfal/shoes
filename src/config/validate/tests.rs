use super::*;
use crate::config::pem::convert_cert_paths;
use crate::dns::IpStrategy;

#[tokio::test]
async fn sudoku_mask_walkers_reach_certificates_rules_clients_and_fake_dns_targets() {
    use serde_json::json;
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let cert = directory.path().join("client.crt");
    let key = directory.path().join("client.key");
    std::fs::write(&cert, certificate.cert.pem()).unwrap();
    std::fs::write(&key, certificate.signing_key.serialize_pem()).unwrap();
    let mut configs: Vec<Config> = serde_json::from_value(json!([{
        "address":"0.0.0.0:1080", "rules":"block-all",
        "protocol":{"type":"sudoku_mask","protocol":{"type":"tls","default_target":{
            "cert":cert, "key":key,
            "protocol":{"type":"socks"},
            "override_rules":[{"masks":"0.0.0.0/0","action":"allow",
                "override_address":"198.18.0.2:443",
                "client_chain":{"address":"proxy.example:443","protocol":{
                    "type":"sudoku_mask","protocol":{"type":"tls","cert":cert,"key":key,
                        "protocol":{"type":"socks"}}
                }}
            }]
        }}}
    }]))
    .unwrap();
    let dependencies = crate::config::pem::pem_reload_dependencies(&mut configs).unwrap();
    assert!(dependencies.contains(&cert));
    assert!(dependencies.contains(&key));
    let sources = crate::certificates::configure(&mut configs).unwrap();
    assert_eq!(sources.len(), 1);
    let (configs, loaded) = convert_cert_paths(configs).await.unwrap();
    assert_eq!(loaded, 2);
    let mut validated = create_server_configs(configs).unwrap();
    let mut clients = 0;
    validated
        .visit_clients(&mut |client| {
            clients += 1;
            let ClientProxyConfig::SudokuMask(mask) = &client.protocol else {
                panic!("mask lost")
            };
            let ClientProxyConfig::Tls(tls) = mask.protocol.as_ref() else {
                panic!("TLS lost")
            };
            assert!(tls.cert.as_ref().unwrap().contains("BEGIN CERTIFICATE"));
            assert!(tls.key.as_ref().unwrap().contains("BEGIN PRIVATE KEY"));
            Ok(())
        })
        .unwrap();
    assert_eq!(clients, 1);
    let mut overrides = 0;
    crate::config::rule_visit::visit(
        &mut validated.configs,
        &mut |rule| {
            assert!(rule.criteria.compiled.is_some());
            if matches!(
                &rule.action,
                RuleActionConfig::Allow {
                    override_address: Some(_),
                    ..
                }
            ) {
                overrides += 1;
            }
            Ok(())
        },
        &mut |_| panic!("unexpanded group"),
    )
    .unwrap();
    assert_eq!(overrides, 1);
    let error = validated
        .validate_network_endpoints(&["198.18.0.0/15".parse().unwrap()])
        .unwrap_err();
    assert!(
        error.to_string().contains("rule override overlaps"),
        "{error}"
    );
}

#[test]
fn sudoku_mask_round_trip_preserves_tag_options_and_protocol() {
    let value = serde_json::json!({"type":"sudoku_mask","password":"never-log-me","paddingMax":300,
        "protocol":{"type":"socks"}});
    let client: ClientProxyConfig = serde_json::from_value(value.clone()).unwrap();
    let server: ServerProxyConfig = serde_json::from_value(value).unwrap();
    for (export, debug) in [
        (
            serde_json::to_value(&client).unwrap(),
            format!("{client:?}"),
        ),
        (
            serde_json::to_value(&server).unwrap(),
            format!("{server:?}"),
        ),
    ] {
        assert_eq!(export["type"], "sudoku_mask");
        assert_eq!(export["padding_max"], 300);
        assert_eq!(export["protocol"]["type"], "socks");
        assert!(!debug.contains("never-log-me"));
    }
}

#[test]
fn sudoku_mask_rejects_non_tcp_transports_even_inside_xhttp() {
    use serde_json::json;
    let mask = json!({"type":"sudoku_mask","protocol":{"type":"socks"}});
    let clients = [
        mask.clone(),
        json!({"type":"tls","protocol":mask}),
        json!({"type":"websocket","protocol":mask}),
        json!({"type":"xhttp","protocol":mask}),
    ];
    for protocol in clients {
        for transport in ["quic", "udp"] {
            let mut config: ClientConfig = serde_json::from_value(
                json!({"address":"localhost:1234","transport":transport,"protocol":protocol}),
            )
            .unwrap();
            let error =
                validate_client_config(&mut config, &HashMap::new(), GlobalLimits::default())
                    .unwrap_err();
            assert!(
                error.to_string().contains("sudoku_mask requires TCP"),
                "{error}"
            );
        }
    }
    let servers = [
        mask.clone(),
        json!({"type":"xhttp","protocol":mask}),
        json!({"type":"tls","default_target":{"cert":"unused","key":"unused","protocol":mask}}),
        json!({"type":"websocket","targets":[{"protocol":mask}]}),
    ];
    for protocol in servers {
        for transport in ["quic", "udp"] {
            let mut config: ServerConfig = serde_json::from_value(
                json!({"address":"0.0.0.0:1234","transport":transport,"protocol":protocol}),
            )
            .unwrap();
            let error = validate_server_config(
                &mut config,
                &HashMap::new(),
                &HashMap::new(),
                &HashMap::new(),
                GlobalLimits::default(),
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("sudoku_mask requires TCP"),
                "{error}"
            );
        }
    }
}

#[test]
fn sudoku_mask_preserves_sni_and_existing_immediate_child_constraints() {
    use serde_json::json;
    let mask = |protocol| json!({"type":"sudoku_mask","protocol":protocol});
    let mut reality: ClientProxyConfig = serde_json::from_value(mask(json!({"type":"reality",
        "public_key":"CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","protocol":{"type":"socks"}})))
    .unwrap();
    validate_client_proxy_config(&mut reality, &HashMap::new(), Some("origin.example")).unwrap();
    let resolver = std::sync::Arc::new(crate::resolver::NativeResolver::new());
    crate::tcp::tcp_client_handler_factory::create_tcp_client_handler(
        reality,
        Some("origin.example".into()),
        resolver,
    )
    .unwrap();
    let vless = json!({"type":"vless","user_id":"550e8400-e29b-41d4-a716-446655440000"});
    for (protocol, valid) in [
        (
            mask(json!({"type":"tls","vision":true,"protocol":vless})),
            true,
        ),
        (
            json!({"type":"tls","vision":true,"protocol":mask(vless)}),
            false,
        ),
        (mask(json!({"type":"direct"})), false),
    ] {
        let protocol = serde_json::from_value(protocol).unwrap();
        assert_eq!(validate_client_proxy_structure(&protocol).is_ok(), valid);
    }
    let naive = json!({"type":"naive","users":[{"username":"user","password":"secret"}]});
    let mut protocol = serde_json::from_value(mask(naive.clone())).unwrap();
    let error = validate_server_proxy_config(
        &mut protocol,
        &HashMap::new(),
        &HashMap::new(),
        &HashMap::new(),
        ServerProtocolContext::Tls,
        GlobalLimits::default(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("NaiveProxy must be used inside"));
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let configs = serde_json::from_value(json!([{
        "address": "0.0.0.0:1234",
        "protocol": mask(json!({
            "type": "tls",
            "default_target": {
                "cert": cert.cert.pem(),
                "key": cert.signing_key.serialize_pem(),
                "protocol": naive
            }
        }))
    }]))
    .unwrap();
    assert!(create_server_configs(configs).is_ok());
}

#[test]
fn sudoku_mask_rejects_inner_client_placements() {
    use serde_json::json;
    let mask = |protocol| json!({"type":"sudoku_mask","protocol":protocol});
    let inner = mask(json!({"type":"socks"}));
    for protocol in [
        json!({"type":"tls","protocol":inner}),
        json!({"type":"reality","public_key":"unused","protocol":inner}),
        json!({"type":"shadowtls","password":"secret","protocol":inner}),
        json!({"type":"websocket","protocol":inner}),
        json!({"type":"xhttp","protocol":inner}),
        json!({"type":"tls","protocol":{"type":"xhttp","protocol":inner}}),
    ] {
        for protocol in [protocol.clone(), mask(mask(protocol))] {
            let mut config: ClientConfig = serde_json::from_value(json!({
                "address":"localhost:443", "protocol":protocol
            }))
            .unwrap();
            let error =
                validate_client_config(&mut config, &HashMap::new(), GlobalLimits::default())
                    .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert!(
                error.to_string().contains("outermost protocol layer"),
                "{error}"
            );
        }
    }
}

#[test]
fn sudoku_mask_rejects_inner_server_placements_in_every_target_branch() {
    use serde_json::json;
    let mask = |protocol| json!({"type":"sudoku_mask","protocol":protocol});
    let inner = mask(json!({"type":"socks"}));
    let tls_target = json!({"protocol":inner});
    for protocol in [
        json!({"type":"xhttp","protocol":inner}),
        json!({"type":"websocket","targets":[{"protocol":inner}]}),
        json!({"type":"tls","default_target":tls_target}),
        json!({"type":"tls","tls_targets":{"localhost":tls_target}}),
        json!({"type":"tls","shadowtls_targets":{"localhost":{
            "password":"secret","handshake":{"address":"localhost:443"},"protocol":inner
        }}}),
        json!({"type":"tls","reality_targets":{"localhost":{
            "private_key":"unused","dest":"localhost:443","protocol":inner
        }}}),
        json!({"type":"tls","default_target":{
            "protocol":{"type":"xhttp","protocol":inner}
        }}),
    ] {
        for protocol in [protocol.clone(), mask(mask(protocol))] {
            let mut config: ServerConfig = serde_json::from_value(json!({
                "address":"0.0.0.0:443", "protocol":protocol
            }))
            .unwrap();
            let error = validate_server_config(
                &mut config,
                &HashMap::new(),
                &HashMap::new(),
                &HashMap::new(),
                GlobalLimits::default(),
            )
            .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert!(
                error.to_string().contains("outermost protocol layer"),
                "{error}"
            );
        }
    }
}

#[test]
fn sudoku_mask_accepts_consecutive_outer_prefixes() {
    use serde_json::json;
    for depth in 1..=2 {
        let mut protocol = json!({"type":"socks"});
        for _ in 0..depth {
            protocol = json!({"type":"sudoku_mask","protocol":protocol});
        }
        let mut client: ClientConfig = serde_json::from_value(json!({
            "address":"localhost:1080","protocol":protocol
        }))
        .unwrap();
        validate_client_config(&mut client, &HashMap::new(), GlobalLimits::default()).unwrap();
        let configs = serde_json::from_value(json!([{
            "address":"0.0.0.0:1080","protocol":protocol
        }]))
        .unwrap();
        create_server_configs(configs).unwrap();
    }
}

#[test]
fn sudoku_mask_outer_prefix_preserves_tls_alpn_validation() {
    use serde_json::json;
    let xhttp = json!({"type":"xhttp","http_version":"h2","protocol":{"type":"socks"}});
    let mask = |protocol| json!({"type":"sudoku_mask","protocol":protocol});
    for (alpn, valid) in [(json!(["http/1.1"]), false), (json!(["h2"]), true)] {
        let tls = json!({"type":"tls","default_target":{
            "cert":"unused","key":"unused","alpn_protocols":alpn,"protocol":xhttp
        }});
        for protocol in [mask(tls.clone()), mask(mask(tls))] {
            let protocol = serde_json::from_value(protocol).unwrap();
            assert_eq!(
                crate::config::xhttp::validate_server_transport(&protocol, &Transport::Tcp).is_ok(),
                valid
            );
        }
    }
}

#[test]
fn native_vless_configuration_rejects_ambiguous_vision_and_secrets() {
    use serde_json::json;

    const KEY: &str = "CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let client = json!({
        "type": "vless", "user_id": "550e8400-e29b-41d4-a716-446655440000",
        "encryption": format!("mlkem768x25519plus.native.0rtt.{KEY}"), "vision": true,
    });
    let server = json!({
        "type": "vless", "user_id": "550e8400-e29b-41d4-a716-446655440000",
        "decryption": format!("mlkem768x25519plus.native.600s.{KEY}"), "vision": true,
    });
    let mut client_config = serde_json::from_value(client.clone()).unwrap();
    validate_client_proxy_config(&mut client_config, &HashMap::new(), None).unwrap();
    for outer in ["TLS", "REALITY"] {
        let error = validate_client_vision_protocol(true, &client_config, outer).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("outer TLS/REALITY vision: false")
        );
        assert!(!error.to_string().contains(KEY));
        validate_client_vision_protocol(false, &client_config, outer).unwrap();
    }
    let validate_server = |value: serde_json::Value| {
        let mut config = serde_json::from_value(value).unwrap();
        validate_server_proxy_config(
            &mut config,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            ServerProtocolContext::Stream,
            GlobalLimits::default(),
        )?;
        Ok::<_, std::io::Error>(config)
    };
    let server_config = validate_server(server.clone()).unwrap();
    assert!(
        validate_server_vision(true, &server_config)
            .unwrap_err()
            .to_string()
            .contains("outer TLS/REALITY vision: false")
    );
    validate_server_vision(false, &server_config).unwrap();
    for (key, value) in [
        ("encryption", json!("none")),
        ("encryption", json!("invalid-secret-do-not-log")),
        ("h2mux", json!({})),
    ] {
        let mut value_config = client.clone();
        value_config[key] = value;
        let mut config = serde_json::from_value(value_config).unwrap();
        let error = validate_client_proxy_config(&mut config, &HashMap::new(), None).unwrap_err();
        assert!(!error.to_string().contains("do-not-log"));
        assert!(!format!("{config:?}").contains("do-not-log"));
    }
    for (key, value) in [
        ("decryption", json!("none")),
        ("decryption", json!("invalid-secret-do-not-log")),
        ("fallback", json!("127.0.0.1:80")),
        ("encryption_limits", json!({"max_replays": 0})),
    ] {
        let mut config = server.clone();
        config[key] = value;
        let error = validate_server(config).unwrap_err();
        assert!(!error.to_string().contains("do-not-log"));
    }
    for disabled in ["", "none"] {
        let mut config = client.clone();
        config["encryption"] = json!(disabled);
        config["vision"] = json!(false);
        let mut config = serde_json::from_value(config).unwrap();
        validate_client_proxy_config(&mut config, &HashMap::new(), None).unwrap();
        validate_client_vision_protocol(true, &config, "TLS").unwrap();
        let mut config = server.clone();
        config["decryption"] = json!(disabled);
        config["vision"] = json!(false);
        validate_server_vision(true, &validate_server(config).unwrap()).unwrap();
    }
}

#[test]
fn server_secrets_must_be_nonempty() {
    use serde_json::json;
    for mut value in [
        json!({"type": "trojan", "password": ""}),
        json!({"type": "snell", "cipher": "aes-128-gcm", "password": ""}),
        json!({"type": "shadowsocks", "cipher": "aes-128-gcm", "password": ""}),
        json!({"type": "hysteria2", "password": ""}),
        json!({"type": "tuic", "uuid": "550e8400-e29b-41d4-a716-446655440000", "password": ""}),
    ] {
        for password in ["", "do-not-log-this-secret", " "] {
            value["password"] = json!(password);
            let protocol = serde_json::from_value(value.clone()).unwrap();
            let result = validate_server_auth(&protocol);
            assert_eq!(result.is_ok(), !password.is_empty());
            if let Err(error) = result {
                assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
                assert!(!error.to_string().contains("do-not-log-this-secret"));
            }
        }
    }
    for password in ["", "do-not-log-this-secret"] {
        let protocol = serde_json::from_value(json!({
            "type": "trojan", "password": "do-not-log-this-secret",
            "shadowsocks": {"cipher": "aes-128-gcm", "password": password}
        }))
        .unwrap();
        assert_eq!(
            validate_server_auth(&protocol).is_ok(),
            !password.is_empty()
        );
        for protocol_type in ["anytls", "naive"] {
            let mut user = json!({"password": password});
            if protocol_type == "naive" {
                user["username"] = json!("user");
            }
            let mut valid_user = user.clone();
            valid_user["password"] = json!("do-not-log-this-secret");
            for users in [user.clone(), json!([valid_user, user])] {
                let protocol = serde_json::from_value(json!({
                    "type": protocol_type, "users": users
                }))
                .unwrap();
                let result = validate_server_auth(&protocol);
                assert_eq!(result.is_ok(), !password.is_empty());
                if let Err(error) = result {
                    assert!(!error.to_string().contains("do-not-log-this-secret"));
                }
            }
        }
    }
    let protocol = ServerProxyConfig::Shadowsocks {
        config: ShadowsocksConfig::Aead2022 {
            cipher: "aes-128-gcm".try_into().unwrap(),
            key_bytes: vec![0; 1].into_boxed_slice(),
            identity_keys: Vec::new(),
        },
        udp_enabled: true,
    };
    assert!(validate_server_auth(&protocol).is_err());
}

#[test]
fn shadowsocks_identity_keys_validate_programmatic_clients_and_reject_servers() {
    for cipher in ["aes-128-gcm", "aes-256-gcm", "chacha20-poly1305"] {
        let cipher: crate::shadowsocks::ShadowsocksCipher = cipher.try_into().unwrap();
        let required = cipher.key_len();
        for (user_len, identity_len) in [
            (required, 0),
            (required, required),
            (required, required + 1),
            (0, required),
            (required + 1, required),
        ] {
            let config = ShadowsocksConfig::Aead2022 {
                key_bytes: vec![0x33; user_len].into_boxed_slice(),
                identity_keys: vec![vec![0x11; identity_len].into_boxed_slice()],
                cipher,
            };
            let mut client = ClientProxyConfig::Shadowsocks {
                config: config.clone(),
                udp_enabled: true,
            };
            assert_eq!(
                validate_client_proxy_config(&mut client, &HashMap::new(), None).is_ok(),
                user_len == required
                    && identity_len == required
                    && matches!(cipher.name(), "aes-128-gcm" | "aes-256-gcm")
            );
            assert!(
                validate_server_auth(&ServerProxyConfig::Shadowsocks {
                    config,
                    udp_enabled: true,
                })
                .is_err()
            );
        }
    }
}

#[test]
fn optional_server_auth_preserves_no_auth_and_http_empty_username() {
    use serde_json::json;
    for protocol_type in ["http", "socks", "mixed"] {
        for (username, password, http_valid, socks_valid) in [
            (None, None, true, true),
            (Some("user"), Some("secret"), true, true),
            (None, Some("secret"), true, false),
            (Some(""), Some("secret"), true, false),
            (Some("user"), None, false, false),
            (Some("user"), Some(""), false, false),
            (None, Some(""), false, false),
            (Some(""), None, false, false),
            (Some(""), Some(""), false, false),
        ] {
            let protocol = serde_json::from_value(json!({
                "type": protocol_type, "username": username, "password": password
            }))
            .unwrap();
            assert_eq!(
                validate_server_auth(&protocol).is_ok(),
                if protocol_type == "http" {
                    http_valid
                } else {
                    socks_valid
                },
                "{protocol_type}: {username:?}, {password:?}"
            );
        }
        for value in [
            "a".to_string(),
            "a".repeat(255),
            "a".repeat(256),
            format!("{}a", "\u{e9}".repeat(127)),
            "\u{e9}".repeat(128),
        ] {
            for field in ["username", "password"] {
                let mut protocol = json!({
                    "type": protocol_type, "username": "user", "password": "secret"
                });
                protocol[field] = json!(value);
                let protocol = serde_json::from_value(protocol).unwrap();
                assert_eq!(
                    validate_server_auth(&protocol).is_ok(),
                    protocol_type == "http" || value.len() <= 255,
                    "{protocol_type}: {field}, {} bytes",
                    value.len()
                );
            }
        }
    }
}

#[test]
fn server_protocol_context_enforces_transport_and_termination() {
    use serde_json::json;
    for (value, valid_context) in [
        (
            json!({"type": "hysteria2", "password": "secret"}),
            ServerProtocolContext::Quic,
        ),
        (
            json!({"type": "tuic", "uuid": "550e8400-e29b-41d4-a716-446655440000", "password": "secret"}),
            ServerProtocolContext::Quic,
        ),
        (
            json!({"type": "naive", "users": [{"username": "user", "password": "secret"}]}),
            ServerProtocolContext::Tls,
        ),
    ] {
        for context in [
            ServerProtocolContext::Stream,
            ServerProtocolContext::Tls,
            ServerProtocolContext::Quic,
        ] {
            let mut protocol = serde_json::from_value(value.clone()).unwrap();
            let result = validate_server_proxy_config(
                &mut protocol,
                &HashMap::new(),
                &HashMap::new(),
                &HashMap::new(),
                context,
                GlobalLimits::default(),
            );
            assert_eq!(result.is_ok(), context == valid_context);
            if let Err(error) = result {
                assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
                assert!(!error.to_string().contains("secret"));
            }
        }
    }
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    for protocol in [
        json!({"type": "hysteria2", "password": "secret"}),
        json!({"type": "tuic", "uuid": "550e8400-e29b-41d4-a716-446655440000", "password": "secret"}),
    ] {
        let configs = serde_json::from_value(json!([{
            "address": "127.0.0.1:9000", "transport": "quic", "protocol": protocol,
            "quic_settings": {"cert": cert.cert.pem(), "key": cert.signing_key.serialize_pem()}
        }]))
        .unwrap();
        assert!(create_server_configs(configs).is_ok());
    }
}

#[test]
fn nested_structure_errors_precede_protocol_field_errors() {
    let mut config = serde_json::from_value(serde_json::json!({
        "address": "example.com:443",
        "protocol": {
            "type": "reality", "public_key": "invalid",
            "protocol": {"type": "websocket", "protocol": {"type": "direct"}}
        }
    }))
    .unwrap();
    let error =
        validate_client_config(&mut config, &HashMap::new(), GlobalLimits::default()).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(
        error.to_string(),
        "direct cannot be used as an inner proxy protocol"
    );
}

#[test]
fn tls_sni_distinguishes_inheritance_disable_and_override() {
    for (sni, valid) in [
        (NoneOrOne::Unspecified, false),
        (NoneOrOne::None, true),
        (NoneOrOne::One("example.com".to_owned()), true),
        (NoneOrOne::One("invalid name".to_owned()), false),
    ] {
        let mut protocol = serde_json::from_value(serde_json::json!({
            "type": "tls", "protocol": {"type": "socks"}
        }))
        .unwrap();
        let ClientProxyConfig::Tls(ref mut tls) = protocol else {
            unreachable!()
        };
        tls.sni_hostname = sni;
        assert_eq!(
            validate_client_proxy_config(&mut protocol, &HashMap::new(), Some("invalid name"))
                .is_ok(),
            valid,
        );
    }
}

#[test]
fn reality_sni_defaults_only_at_the_outer_client_layer() {
    let protocol = serde_json::json!({
        "type": "reality", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "protocol": {"type": "socks"}
    });
    for (address, protocol, valid) in [
        ("example.com:443", protocol.clone(), true),
        ("127.0.0.1:443", protocol.clone(), false),
        (
            "example.com:443",
            serde_json::json!({"type": "websocket", "protocol": protocol}),
            false,
        ),
    ] {
        let mut config: ClientConfig = serde_json::from_value(serde_json::json!({
            "address": address, "protocol": protocol
        }))
        .unwrap();
        assert_eq!(
            validate_client_config(&mut config, &HashMap::new(), GlobalLimits::default()).is_ok(),
            valid
        );
    }
}

#[test]
fn reality_mldsa_client_key_validation() {
    let (_, valid) = crate::reality::generate_mldsa65_keypair().unwrap();
    for (key, expected) in [
        (None, true),
        (Some(valid.as_str()), true),
        (Some(""), false),
        (Some("AA"), false),
        (Some("invalid!"), false),
    ] {
        let mut value = serde_json::json!({
            "address": "cover.test:443", "protocol": {
                "type": "reality", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "protocol": {"type": "socks"}
            }
        });
        if let Some(key) = key {
            value["protocol"]["mldsa65_verify"] = key.into();
        }
        let mut config: ClientConfig = serde_json::from_value(value).unwrap();
        assert_eq!(
            validate_client_config(&mut config, &HashMap::new(), GlobalLimits::default()).is_ok(),
            expected
        );
    }
}

#[tokio::test]
async fn reality_mldsa_server_seed_validation() {
    let (valid, _) = crate::reality::generate_mldsa65_keypair().unwrap();
    for (seed, expected) in [
        (None, true),
        (Some(valid.as_str()), true),
        (Some(""), false),
        (Some("AA"), false),
        (Some("invalid!"), false),
    ] {
        let mut value = serde_json::json!({
            "address": "0.0.0.0:4443", "protocol": {"type": "tls", "reality_targets": {
                "cover.test": {"private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "dest": "cover.test:443", "protocol": {"type": "socks"}}
            }}
        });
        if let Some(seed) = seed {
            value["protocol"]["reality_targets"]["cover.test"]["mldsa65_seed"] = seed.into();
        }
        let result = validate_configs_test(vec![serde_json::from_value(value).unwrap()]).await;
        assert_eq!(result.is_ok(), expected, "{result:?}");
    }
}

async fn validate_configs_test(configs: Vec<Config>) -> std::io::Result<Vec<Config>> {
    let (converted_configs, _) = convert_cert_paths(configs).await?;
    let validated = create_server_configs(converted_configs)?;
    Ok(validated.configs)
}

#[test]
fn xhttp_split_capacity_uses_candidate_global_stream_limit() {
    use serde_json::json;

    for version in ["h1", "h2", "h3"] {
        for mode in ["auto", "packet-up", "stream-up", "stream-one"] {
            for connections in [1, 2] {
                for stream_limit in [None, Some(1), Some(2)] {
                    let client = json!({
                        "address": "127.0.0.1:443",
                        "transport": if version == "h3" { "quic" } else { "tcp" },
                        "protocol": {
                            "type": "xhttp", "http_version": version, "mode": mode,
                            "pool": {"max_connections": connections, "max_h1_connections": 2},
                            "limits": {"max_requests_per_connection": 2},
                            "protocol": {"type": "socks"}
                        }
                    });
                    let rules =
                        json!([{"masks": "0.0.0.0/0", "action": "allow", "client_chain": client}]);
                    let entries = [
                        json!({"client_group": "proxy", "client_proxies": client}),
                        json!({"address": "0.0.0.0:1080", "protocol": {"type": "socks"}, "rules": rules}),
                        json!({"dns_group": "dns", "dns_servers": [{"url": "https://1.1.1.1/dns-query", "client_chain": client}]}),
                        json!({"device_fd": 1, "rules": rules}),
                        json!({"address": "0.0.0.0:1080", "protocol": {"type": "websocket", "targets": [{"protocol": {"type": "socks"}, "override_rules": rules}]}}),
                    ];
                    for entry in entries {
                        let configs = serde_json::from_value(json!([
                            entry,
                            {"global_limits": {"max_streams_per_connection": stream_limit}}
                        ]))
                        .unwrap();
                        let result = create_server_configs(configs);
                        let valid = version == "h1"
                            || mode == "stream-one"
                            || connections == 2
                            || stream_limit != Some(1);
                        assert_eq!(
                            result.is_ok(),
                            valid,
                            "version={version}, mode={mode}, connections={connections}, stream_limit={stream_limit:?}, entry={entry}: {:?}",
                            result.as_ref().err()
                        );
                        if let Err(error) = result {
                            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
                            assert!(error.to_string().contains("at least two request lanes"));
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn hybrid_only_rejects_vision_and_tuic_early_handshakes() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let tls_target = serde_json::json!({
        "cert": cert.cert.pem(), "key": cert.signing_key.serialize_pem(),
        "key_exchange_groups": ["X25519MLKEM768"], "vision": true,
        "protocol": {"type": "vless", "user_id": "550e8400-e29b-41d4-a716-446655440000"}
    });
    for protocol in [
        serde_json::json!({"type": "tls", "tls_targets": {"localhost": tls_target}}),
        serde_json::json!({"type": "tls", "default_tls_target": tls_target}),
    ] {
        let mut server: ServerProxyConfig = serde_json::from_value(protocol).unwrap();
        let error = validate_server_proxy_config(
            &mut server,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            ServerProtocolContext::Stream,
            GlobalLimits::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("hybrid-only"), "{error}");
    }
    let client: ClientProxyConfig = serde_json::from_value(serde_json::json!({
        "type": "tls", "key_exchange_groups": ["SecP256r1MLKEM768"], "vision": true,
        "protocol": {"type": "vless", "user_id": "550e8400-e29b-41d4-a716-446655440000"}
    }))
    .unwrap();
    assert!(
        validate_client_proxy_structure(&client)
            .unwrap_err()
            .to_string()
            .contains("hybrid-only")
    );
    let mut server: ServerConfig = serde_json::from_value(serde_json::json!({
            "address": "0.0.0.0:443", "transport": "quic",
            "quic_settings": {"cert": cert.cert.pem(), "key": cert.signing_key.serialize_pem(), "key_exchange_groups": ["X25519MLKEM768"]},
            "protocol": {"type": "tuic", "uuid": "550e8400-e29b-41d4-a716-446655440000", "password": "test", "zero_rtt_handshake": true}
        })).unwrap();
    assert!(
        validate_server_config(
            &mut server,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            GlobalLimits::default(),
        )
        .unwrap_err()
        .to_string()
        .contains("zero_rtt_handshake")
    );
}

#[test]
fn quic_allowlists_cannot_be_ignored_by_direct_or_later_hops() {
    use serde_json::json;
    for groups in [
        None,
        Some(json!(["X25519MLKEM768"])),
        Some(json!(["X25519"])),
    ] {
        let mut settings = json!({});
        if let Some(ref groups) = groups {
            settings["key_exchange_groups"] = groups.clone();
        }
        let direct =
            json!({"protocol": {"type": "direct"}, "transport": "quic", "quic_settings": settings});
        let mut config: ClientConfig = serde_json::from_value(direct).unwrap();
        let result = validate_client_config(&mut config, &HashMap::new(), GlobalLimits::default());
        assert_eq!(result.is_err(), groups.is_some());

        let proxy = json!({"address": "127.0.0.1:443", "protocol": {"type": "socks"}, "transport": "quic", "quic_settings": settings});
        let group_configs = HashMap::from([(
            "proxy".into(),
            vec![serde_json::from_value::<ClientConfig>(proxy.clone()).unwrap()],
        )]);
        for hop in [
            proxy.clone(),
            json!("proxy"),
            json!({"pool": ["proxy", proxy.clone()]}),
        ] {
            let direct = json!({"protocol": {"type": "direct"}});
            for chain in [json!([hop]), json!([direct, hop])] {
                let later_hop = chain.as_array().unwrap().len() > 1;
                let mut parsed: super::super::types::ClientChain =
                    serde_json::from_value(chain.clone()).unwrap();
                let result = validate_client_chain(
                    &mut parsed.hops,
                    0,
                    &group_configs,
                    &HashMap::new(),
                    GlobalLimits::default(),
                );
                assert_eq!(result.is_err(), later_hop && groups.is_some(), "{chain}");
                if let Err(error) = result {
                    assert!(error.to_string().contains("QUIC key_exchange_groups"));
                }
                let spec: DnsServerSpec = serde_json::from_value(json!({
                    "url": "https://1.1.1.1/dns-query", "client_chain": {"chain": chain}
                }))
                .unwrap();
                let result = expand_dns_specs(
                    &[spec],
                    &group_configs,
                    &HashMap::new(),
                    &HashSet::new(),
                    GlobalLimits::default(),
                );
                assert_eq!(result.is_err(), later_hop && groups.is_some());
                if let Err(error) = result {
                    assert!(error.to_string().contains("QUIC key_exchange_groups"));
                }
            }
        }
    }
}

#[tokio::test]
async fn test_validate_config_success() {
    use crate::config::types::ClientConfigGroup;
    use crate::config::types::groups::RuleConfigGroup;

    let configs = vec![
        Config::RuleConfigGroup(RuleConfigGroup {
            rule_group: "test-rules".to_string(),
            rules: crate::config::RuleGroupRules::Policies(Box::new(OneOrSome::One(RuleConfig {
                criteria: Default::default(),
                action: RuleActionConfig::Allow {
                    override_address: None,
                    client_chains: NoneOrSome::One(ClientChain::default()),
                },
            }))),
        }),
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "test-group".to_string(),
            client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
        }),
    ];

    assert!(validate_configs_test(configs).await.is_ok());
}

#[tokio::test]
async fn test_topological_sort_simple() {
    use crate::config::types::ClientConfigGroup;

    // group-b has no dependencies, group-a references group-b
    let configs = vec![
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "group-a".to_string(),
            client_proxies: OneOrSome::One(ConfigSelection::GroupName("group-b".to_string())),
        }),
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "group-b".to_string(),
            client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
        }),
    ];

    assert!(validate_configs_test(configs).await.is_ok());
}

#[tokio::test]
async fn test_topological_sort_cycle_detected() {
    use crate::config::types::ClientConfigGroup;

    let configs = vec![
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "group-a".to_string(),
            client_proxies: OneOrSome::One(ConfigSelection::GroupName("group-b".to_string())),
        }),
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "group-b".to_string(),
            client_proxies: OneOrSome::One(ConfigSelection::GroupName("group-a".to_string())),
        }),
    ];

    let result = validate_configs_test(configs).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Circular dependency"),
        "Error should mention circular dependency: {err}"
    );
}

#[tokio::test]
async fn test_topological_sort_unknown_group() {
    use crate::config::types::ClientConfigGroup;

    let configs = vec![Config::ClientConfigGroup(ClientConfigGroup {
        group_type: Default::default(),
        default: None,
        client_group: "group-a".to_string(),
        client_proxies: OneOrSome::One(ConfigSelection::GroupName("nonexistent".to_string())),
    })];

    let result = validate_configs_test(configs).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown group") || err.contains("Unknown"),
        "Error should mention unknown group: {err}"
    );
}

#[tokio::test]
async fn test_topological_sort_diamond() {
    use crate::config::types::ClientConfigGroup;

    // Diamond: a -> b, a -> c, b -> d, c -> d
    let configs = vec![
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "group-d".to_string(),
            client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
        }),
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "group-c".to_string(),
            client_proxies: OneOrSome::One(ConfigSelection::GroupName("group-d".to_string())),
        }),
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "group-b".to_string(),
            client_proxies: OneOrSome::One(ConfigSelection::GroupName("group-d".to_string())),
        }),
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "group-a".to_string(),
            client_proxies: OneOrSome::Some(vec![
                ConfigSelection::GroupName("group-b".to_string()),
                ConfigSelection::GroupName("group-c".to_string()),
            ]),
        }),
    ];

    assert!(validate_configs_test(configs).await.is_ok());
}

#[tokio::test]
async fn test_nested_groups_resolve() {
    use crate::config::types::ClientConfigGroup;

    let configs = vec![
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "us-proxies".to_string(),
            client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
        }),
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "eu-proxies".to_string(),
            client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
        }),
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "all-proxies".to_string(),
            client_proxies: OneOrSome::Some(vec![
                ConfigSelection::GroupName("us-proxies".to_string()),
                ConfigSelection::GroupName("eu-proxies".to_string()),
            ]),
        }),
    ];

    assert!(validate_configs_test(configs).await.is_ok());
}

#[tokio::test]
async fn test_empty_config() {
    let original: Vec<Config> = vec![];
    let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
    let deserialized: Vec<Config> = serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");

    assert_eq!(deserialized.len(), 0);
    assert!(validate_configs_test(deserialized).await.is_ok());
}

#[tokio::test]
async fn test_named_pem_duplicate_names() {
    let configs = vec![
        Config::NamedPem(super::super::types::NamedPem {
            pem: "duplicate-name".to_string(),
            source: PemSource::Data("pem1".to_string()),
        }),
        Config::NamedPem(super::super::types::NamedPem {
            pem: "duplicate-name".to_string(),
            source: PemSource::Data("pem2".to_string()),
        }),
    ];

    let result = validate_configs_test(configs).await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("named pem already exists: duplicate-name")
    );
}

#[tokio::test]
async fn test_recursive_certificate_embedding() {
    crate::thread_util::set_num_threads(1);

    let test_dir = tempfile::tempdir().unwrap();
    let cert_dir = test_dir.path().join("certs");
    tokio::fs::create_dir_all(&cert_dir).await.unwrap();

    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = certificate.cert.pem();
    let key_pem = certificate.signing_key.serialize_pem();
    let test_cert = cert_pem.as_str();
    let test_key = key_pem.as_str();

    let cert_files = vec![
        ("quic.crt", test_cert),
        ("quic.key", test_key),
        ("server.crt", test_cert),
        ("server.key", test_key),
        ("ca.crt", test_cert),
        ("shadow.crt", test_cert),
        ("shadow.key", test_key),
        ("client-quic.crt", test_cert),
        ("client-quic.key", test_key),
        ("client.crt", test_cert),
        ("client.key", test_key),
    ];

    for (filename, content) in cert_files {
        let path = cert_dir.join(filename);
        tokio::fs::write(&path, content).await.unwrap();
    }

    let config_yaml = format!(
        r#"
- address: "0.0.0.0:443"
  transport: quic
  quic_settings:
    cert: "{}/quic.crt"
    key: "{}/quic.key"
  protocol:
    type: tls
    sni_targets:
      "example.com":
        cert: "{}/server.crt"
        key: "{}/server.key"
        client_ca_certs:
          - "{}/ca.crt"
        protocol:
          type: websocket
          targets:
            - matching_path: "/ws"
              protocol:
                type: vmess
                cipher: any
                user_id: "123e4567-e89b-42d3-a456-426614174000"
    shadowtls_targets:
      "shadow.com":
        password: "shadowpass"
        handshake:
          cert: "{}/shadow.crt"
          key: "{}/shadow.key"
        protocol:
          type: socks
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - address: "proxy.example.com:443"
          transport: quic
          quic_settings:
            cert: "{}/client-quic.crt"
            key: "{}/client-quic.key"
          protocol:
            type: tls
            cert: "{}/client.crt"
            key: "{}/client.key"
            protocol:
              type: http
"#,
        cert_dir.display(),
        cert_dir.display(),
        cert_dir.display(),
        cert_dir.display(),
        cert_dir.display(),
        cert_dir.display(),
        cert_dir.display(),
        cert_dir.display(),
        cert_dir.display(),
        cert_dir.display(),
        cert_dir.display()
    );

    let configs: Vec<Config> = serde_yaml::from_str(&config_yaml).unwrap();
    let (converted_configs, load_count) = convert_cert_paths(configs).await.unwrap();

    assert_eq!(load_count, 11);

    let validated = create_server_configs(converted_configs).unwrap();
    let Config::Server(server_config) = &validated.configs[0] else {
        panic!("expected Config::Server");
    };

    let quic_settings = server_config.quic_settings.as_ref().unwrap();
    assert!(quic_settings.cert.contains("BEGIN CERTIFICATE"));
    assert!(quic_settings.key.contains("BEGIN PRIVATE KEY"));

    if let ServerProxyConfig::Tls {
        tls_targets,
        shadowtls_targets,
        ..
    } = &server_config.protocol
    {
        let tls_config = tls_targets.get("example.com").unwrap();
        assert!(tls_config.cert.contains("BEGIN CERTIFICATE"));
        assert!(tls_config.key.contains("BEGIN PRIVATE KEY"));

        let shadow_config = shadowtls_targets.get("shadow.com").unwrap();
        if let ShadowTlsServerHandshakeConfig::Local(handshake) = &shadow_config.handshake {
            assert!(handshake.cert.contains("BEGIN CERTIFICATE"));
            assert!(handshake.key.contains("BEGIN PRIVATE KEY"));
        }
    }
}

#[test]
fn test_direct_connector_at_hop_0_allowed() {
    // Single direct connector at hop 0 should be allowed
    let hops = OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
        ClientConfig::default(), // default is direct
    )));

    assert!(validate_connector_positions(&hops, 0).is_ok());
}

fn http_proxy_config() -> ClientProxyConfig {
    ClientProxyConfig::Http {
        username: None,
        password: None,
        resolve_hostname: false,
        http_version: Default::default(),
    }
}

fn socks_proxy_config() -> ClientProxyConfig {
    ClientProxyConfig::Socks {
        username: None,
        password: None,
    }
}

#[test]
fn test_direct_then_proxy_allowed() {
    // Direct at hop 0, proxy at hop 1 - should be allowed
    let hops = OneOrSome::Some(vec![
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig::default())),
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
            protocol: http_proxy_config(),
            ..Default::default()
        })),
    ]);

    assert!(validate_connector_positions(&hops, 0).is_ok());
}

#[test]
fn test_proxy_then_proxy_allowed() {
    // Proxy at hop 0, proxy at hop 1 - should be allowed
    let hops = OneOrSome::Some(vec![
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
            protocol: http_proxy_config(),
            ..Default::default()
        })),
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
            protocol: socks_proxy_config(),
            ..Default::default()
        })),
    ]);

    assert!(validate_connector_positions(&hops, 0).is_ok());
}

#[test]
fn test_direct_at_hop_1_rejected() {
    // Direct at hop 1 should be rejected
    let hops = OneOrSome::Some(vec![
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
            protocol: http_proxy_config(),
            ..Default::default()
        })),
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig::default())), // direct
    ]);

    let result = validate_connector_positions(&hops, 0);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("hop 1"));
}

#[test]
fn test_direct_in_middle_of_chain_rejected() {
    // Direct in the middle of a 3-hop chain should be rejected
    let hops = OneOrSome::Some(vec![
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
            protocol: http_proxy_config(),
            ..Default::default()
        })),
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig::default())), // direct
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
            protocol: socks_proxy_config(),
            ..Default::default()
        })),
    ]);

    let result = validate_connector_positions(&hops, 0);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("hop 1"));
}

#[test]
fn test_direct_in_pool_at_hop_0_allowed() {
    // Mixed pool at hop 0 with direct - should be allowed
    let hops = OneOrSome::One(ClientChainHop::Pool(OneOrSome::Some(vec![
        ConfigSelection::Config(ClientConfig::default()), // direct
        ConfigSelection::Config(ClientConfig {
            protocol: http_proxy_config(),
            ..Default::default()
        }),
    ])));

    assert!(validate_connector_positions(&hops, 0).is_ok());
}

#[test]
fn test_direct_in_pool_at_hop_1_rejected() {
    // Mixed pool at hop 1 with direct - should be rejected
    let hops = OneOrSome::Some(vec![
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
            protocol: http_proxy_config(),
            ..Default::default()
        })),
        ClientChainHop::Pool(OneOrSome::Some(vec![
            ConfigSelection::Config(ClientConfig::default()), // direct
            ConfigSelection::Config(ClientConfig {
                protocol: socks_proxy_config(),
                ..Default::default()
            }),
        ])),
    ]);

    let result = validate_connector_positions(&hops, 0);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("hop 1"));
}

#[test]
fn test_three_hop_direct_first_then_proxies_allowed() {
    // Direct at hop 0, two proxies following - should be allowed
    let hops = OneOrSome::Some(vec![
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig::default())), // direct
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
            protocol: http_proxy_config(),
            ..Default::default()
        })),
        ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
            protocol: socks_proxy_config(),
            ..Default::default()
        })),
    ]);

    assert!(validate_connector_positions(&hops, 0).is_ok());
}

#[tokio::test]
async fn test_tun_config_parsing() {
    let yaml = r#"
- device_name: "tun0"
  address: "10.0.0.1"
  netmask: "255.255.255.0"
  mtu: 1400
  tcp_enabled: true
  udp_enabled: true
  icmp_enabled: false
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - protocol:
            type: direct
"#;
    let configs: Vec<Config> = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(configs.len(), 1);

    match &configs[0] {
        Config::TunServer(tun) => {
            assert_eq!(tun.device_name, Some("tun0".to_string()));
            assert_eq!(tun.address, Some("10.0.0.1".parse().unwrap()));
            assert_eq!(tun.netmask, Some("255.255.255.0".parse().unwrap()));
            assert_eq!(tun.mtu, 1400);
            assert!(tun.tcp_enabled);
            assert!(tun.udp_enabled);
            assert!(!tun.icmp_enabled);
        }
        _ => panic!("Expected TunServer config"),
    }

    // Validate the config
    let result = validate_configs_test(configs).await;
    assert!(result.is_ok(), "TUN config validation failed: {:?}", result);
}

#[test]
fn tun_dns_interception_override_roundtrips() {
    for value in [None, Some(false), Some(true)] {
        let mut yaml = serde_json::json!({"device_fd":42});
        if let Some(value) = value {
            yaml["dns_hijack"] = value.into();
        }
        let tun: TunConfig = serde_json::from_value(yaml).unwrap();
        assert_eq!(tun.dns_hijack, value);
        let restored: TunConfig =
            serde_yaml::from_str(&serde_yaml::to_string(&tun).unwrap()).unwrap();
        assert_eq!(restored.dns_hijack, value);
    }
}

#[test]
fn tun_managed_options_distinguish_absent_and_disabled_settings() {
    let manual = serde_json::json!({
        "device_fd": 42,
        "auto_route": false,
        "auto_redirect": false,
        "dns_hijack": true,
    });
    let tun: TunConfig = serde_json::from_value(manual.clone()).unwrap();
    assert!(!tun.has_managed_options());
    for (field, value) in [
        ("auto_route", serde_json::json!(true)),
        ("auto_redirect", serde_json::json!(true)),
        ("auto_dns", serde_json::json!(false)),
        ("linux", serde_json::json!({})),
        ("addresses", serde_json::json!(["10.233.0.1/30"])),
        ("bootstrap_dns", serde_json::json!(["192.0.2.53:53"])),
        ("route_address", serde_json::json!(["0.0.0.0/0"])),
        ("route_exclude_address", serde_json::json!(["192.0.2.0/24"])),
    ] {
        let mut config = manual.clone();
        config[field] = value;
        let tun: TunConfig = serde_json::from_value(config).unwrap();
        assert!(tun.has_managed_options(), "{field}");
    }
}

#[test]
fn tun_adjacent_dns_addresses_preserve_family_and_check_overflow() {
    for (address, next) in [
        ("10.233.0.1", Some("10.233.0.2")),
        ("fd73::1", Some("fd73::2")),
        ("255.255.255.255", None),
        ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", None),
    ] {
        assert_eq!(
            crate::config::tun::next_ip_address(address.parse().unwrap()),
            next.map(|address| address.parse().unwrap()),
        );
    }
}

#[tokio::test]
async fn test_tun_config_with_device_fd() {
    let yaml = r#"
- device_fd: 42
  mtu: 1500
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - protocol:
            type: direct
"#;
    let configs: Vec<Config> = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(configs.len(), 1);

    match &configs[0] {
        Config::TunServer(tun) => {
            assert_eq!(tun.device_fd, Some(42));
            assert_eq!(tun.device_name, None);
            assert_eq!(tun.mtu, 1500);
        }
        _ => panic!("Expected TunServer config"),
    }
}

#[tokio::test]
async fn test_tun_config_defaults() {
    let yaml = r#"
- device_name: "tun0"
  address: "10.0.0.1"
"#;
    let configs: Vec<Config> = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(configs.len(), 1);

    match &configs[0] {
        Config::TunServer(tun) => {
            // Check defaults
            assert_eq!(tun.mtu, 1500); // default
            assert!(tun.tcp_enabled); // default true
            assert!(tun.udp_enabled); // default true
            assert!(tun.icmp_enabled); // default true
        }
        _ => panic!("Expected TunServer config"),
    }
}

#[tokio::test]
async fn test_tun_icmp_requires_tcp() {
    // ICMP requires TCP to be enabled
    let tun_config = TunConfig {
        auto_route: false,
        auto_redirect: false,
        auto_dns: None,
        addresses: Vec::new(),
        route_address: Vec::new(),
        route_exclude_address: Vec::new(),
        bootstrap_dns: Vec::new(),
        linux: None,
        dns_hijack: None,
        name: None,
        sniff: false,
        segmentation_offload: None,
        resource_limits: Default::default(),
        packet_information: None,
        device_name: Some("tun0".to_string()),
        device_fd: None,
        address: Some("10.0.0.1".parse().unwrap()),
        netmask: None,
        destination: None,
        mtu: 1500,
        tcp_enabled: false, // TCP disabled
        udp_enabled: true,
        icmp_enabled: true, // but ICMP enabled - should fail
        rules: NoneOrSome::Unspecified,
        dns: None,
    };

    let configs = vec![Config::TunServer(tun_config)];
    let result = validate_configs_test(configs).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("TCP must be enabled for ICMP"),
        "Expected ICMP/TCP error, got: {err}"
    );
}

#[tokio::test]
async fn test_dns_system_with_client_chain_rejected() {
    let configs = vec![Config::DnsConfigGroup(DnsConfigGroup {
        fake_ip: None,
        dns_group: "test-dns".to_string(),
        dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
            url: "system".to_string(),
            client_chain: NoneOrSome::One(ConfigSelection::Config(ClientChain::default())),
            bootstrap_url: None,
            server_name: None,
            ip_strategy: IpStrategy::default(),
            timeout_secs: 10,
            connect_timeout_secs: 5,
            attempts: 1,
            native_cache_secs: None,
        }),
    })];

    let result = validate_configs_test(configs).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("client_chain is not supported for system DNS"),
        "Expected system DNS client_chain error, got: {err}"
    );
}

#[test]
fn test_dns_native_cache_only_accepts_system_specs() {
    for url in [
        "system",
        "udp://192.0.2.1",
        "tcp://192.0.2.1",
        "tls://192.0.2.1",
        "https://192.0.2.1/dns-query",
        "h3://192.0.2.1/dns-query",
    ] {
        for seconds in [0, 7] {
            let yaml = format!(
                "- dns_group: native\n  dns_servers: [{{url: '{url}', native_cache_secs: {seconds}}}]\n- dns_group: composed\n  dns_servers: native\n"
            );
            let result = create_server_configs(serde_yaml::from_str(&yaml).unwrap());
            if url == "system" {
                let config = result.unwrap();
                assert_eq!(config.dns_groups.len(), 2);
                for group in config.dns_groups {
                    assert_eq!(group.specs[0].native_cache_secs, seconds);
                }
            } else {
                let error = result.err().expect("non-system cache option must fail");
                assert!(
                    error
                        .to_string()
                        .contains("native_cache_secs is only supported for system")
                );
            }
        }
    }
}

#[test]
fn test_dns_tuning_example_validates() {
    create_server_configs(
        serde_yaml::from_str(include_str!("../../../examples/dns_tuning.yaml")).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn test_dns_udp_with_proxy_chain_rejected() {
    use crate::config::types::{ClientConfigGroup, ClientProxyConfig};

    // Create a non-direct (socks5) chain - should be rejected for UDP.
    let socks_config = ClientConfig {
        protocol: ClientProxyConfig::Socks {
            username: None,
            password: None,
        },
        ..Default::default()
    };

    let configs = vec![
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "test-proxy".to_string(),
            client_proxies: OneOrSome::One(ConfigSelection::Config(socks_config)),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            fake_ip: None,
            dns_group: "test-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                url: "udp://8.8.8.8".to_string(),
                client_chain: NoneOrSome::One(ConfigSelection::GroupName("test-proxy".to_string())),
                bootstrap_url: None,
                server_name: None,
                ip_strategy: IpStrategy::default(),
                timeout_secs: 10,
                connect_timeout_secs: 5,
                attempts: 1,
                native_cache_secs: None,
            }),
        }),
    ];

    let result = validate_configs_test(configs).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("UDP DNS only supports direct client_chain"),
        "Expected UDP DNS client_chain error, got: {err}"
    );
}

#[tokio::test]
async fn test_dns_udp_with_direct_chain_allowed() {
    use crate::config::types::ClientConfigGroup;

    // Create a direct chain - should be allowed for UDP (for bind_interface).
    let configs = vec![
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "direct-chain".to_string(),
            client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            fake_ip: None,
            dns_group: "test-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                url: "udp://8.8.8.8".to_string(),
                client_chain: NoneOrSome::One(ConfigSelection::GroupName(
                    "direct-chain".to_string(),
                )),
                bootstrap_url: None,
                server_name: None,
                ip_strategy: IpStrategy::default(),
                timeout_secs: 10,
                connect_timeout_secs: 5,
                attempts: 1,
                native_cache_secs: None,
            }),
        }),
    ];

    assert!(validate_configs_test(configs).await.is_ok());
}

#[tokio::test]
async fn test_dns_h3_with_proxy_chain_rejected() {
    use crate::config::types::{ClientConfigGroup, ClientProxyConfig};

    // Create a non-direct (socks5) chain - should be rejected for H3.
    let socks_config = ClientConfig {
        protocol: ClientProxyConfig::Socks {
            username: None,
            password: None,
        },
        ..Default::default()
    };

    let configs = vec![
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "test-proxy".to_string(),
            client_proxies: OneOrSome::One(ConfigSelection::Config(socks_config)),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            fake_ip: None,
            dns_group: "test-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                url: "h3://1.1.1.1/dns-query".to_string(),
                client_chain: NoneOrSome::One(ConfigSelection::GroupName("test-proxy".to_string())),
                bootstrap_url: None,
                server_name: None,
                ip_strategy: IpStrategy::default(),
                timeout_secs: 10,
                connect_timeout_secs: 5,
                attempts: 1,
                native_cache_secs: None,
            }),
        }),
    ];

    let result = validate_configs_test(configs).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("H3 DNS only supports direct client_chain"),
        "Expected H3 DNS client_chain error, got: {err}"
    );
}

#[tokio::test]
async fn test_dns_h3_with_direct_chain_allowed() {
    use crate::config::types::ClientConfigGroup;

    // Create a direct chain - should be allowed for H3 (for bind_interface).
    let configs = vec![
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "direct-chain".to_string(),
            client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            fake_ip: None,
            dns_group: "test-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                url: "h3://1.1.1.1/dns-query".to_string(),
                client_chain: NoneOrSome::One(ConfigSelection::GroupName(
                    "direct-chain".to_string(),
                )),
                bootstrap_url: None,
                server_name: None,
                ip_strategy: IpStrategy::default(),
                timeout_secs: 10,
                connect_timeout_secs: 5,
                attempts: 1,
                native_cache_secs: None,
            }),
        }),
    ];

    assert!(validate_configs_test(configs).await.is_ok());
}

#[tokio::test]
async fn test_dns_tcp_with_client_chain_allowed() {
    use crate::config::types::ClientConfigGroup;

    let configs = vec![
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "test-proxy".to_string(),
            client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            fake_ip: None,
            dns_group: "test-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                url: "tcp://8.8.8.8".to_string(),
                client_chain: NoneOrSome::One(ConfigSelection::GroupName("test-proxy".to_string())),
                bootstrap_url: None,
                server_name: None,
                ip_strategy: IpStrategy::default(),
                timeout_secs: 10,
                connect_timeout_secs: 5,
                attempts: 1,
                native_cache_secs: None,
            }),
        }),
    ];

    // TCP with client_chain should be allowed
    assert!(validate_configs_test(configs).await.is_ok());
}

#[tokio::test]
async fn test_dns_tls_with_client_chain_allowed() {
    use crate::config::types::ClientConfigGroup;

    let configs = vec![
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "test-proxy".to_string(),
            client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            fake_ip: None,
            dns_group: "test-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                url: "tls://1.1.1.1".to_string(),
                client_chain: NoneOrSome::One(ConfigSelection::GroupName("test-proxy".to_string())),
                bootstrap_url: None,
                server_name: None,
                ip_strategy: IpStrategy::default(),
                timeout_secs: 10,
                connect_timeout_secs: 5,
                attempts: 1,
                native_cache_secs: None,
            }),
        }),
    ];

    // TLS with client_chain should be allowed
    assert!(validate_configs_test(configs).await.is_ok());
}

#[tokio::test]
async fn test_dns_https_with_client_chain_allowed() {
    use crate::config::types::ClientConfigGroup;

    let configs = vec![
        Config::ClientConfigGroup(ClientConfigGroup {
            group_type: Default::default(),
            default: None,
            client_group: "test-proxy".to_string(),
            client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            fake_ip: None,
            dns_group: "test-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                url: "https://1.1.1.1/dns-query".to_string(),
                client_chain: NoneOrSome::One(ConfigSelection::GroupName("test-proxy".to_string())),
                bootstrap_url: None,
                server_name: None,
                ip_strategy: IpStrategy::default(),
                timeout_secs: 10,
                connect_timeout_secs: 5,
                attempts: 1,
                native_cache_secs: None,
            }),
        }),
    ];

    // HTTPS with client_chain should be allowed
    assert!(validate_configs_test(configs).await.is_ok());
}

#[tokio::test]
async fn test_dns_group_composition_basic() {
    // Group full-dns includes base-dns
    let configs = vec![
        Config::DnsConfigGroup(DnsConfigGroup {
            fake_ip: None,
            dns_group: "base-dns".to_string(),
            dns_servers: NoneOrSome::Some(vec![
                DnsServerSpec::Simple("udp://8.8.8.8".to_string()),
                DnsServerSpec::Simple("udp://8.8.4.4".to_string()),
            ]),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            fake_ip: None,
            dns_group: "full-dns".to_string(),
            dns_servers: NoneOrSome::Some(vec![
                DnsServerSpec::Simple("base-dns".to_string()), // Group reference
                DnsServerSpec::Simple("tls://1.1.1.1".to_string()),
            ]),
        }),
    ];

    let result = validate_configs_test(configs).await;
    assert!(
        result.is_ok(),
        "composition should work: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_dns_group_composition_multi_level() {
    // C includes B, B includes A
    let configs = vec![
        Config::DnsConfigGroup(DnsConfigGroup {
            fake_ip: None,
            dns_group: "level-a".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            fake_ip: None,
            dns_group: "level-b".to_string(),
            dns_servers: NoneOrSome::Some(vec![
                DnsServerSpec::Simple("level-a".to_string()),
                DnsServerSpec::Simple("udp://1.1.1.1".to_string()),
            ]),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            fake_ip: None,
            dns_group: "level-c".to_string(),
            dns_servers: NoneOrSome::Some(vec![
                DnsServerSpec::Simple("level-b".to_string()),
                DnsServerSpec::Simple("system".to_string()),
            ]),
        }),
    ];

    let result = validate_configs_test(configs).await;
    assert!(
        result.is_ok(),
        "multi-level composition should work: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_dns_group_composition_cycle_detected() {
    // A includes B, B includes A - cycle!
    let configs = vec![
        Config::DnsConfigGroup(DnsConfigGroup {
            fake_ip: None,
            dns_group: "group-a".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::Simple("group-b".to_string())),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            fake_ip: None,
            dns_group: "group-b".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::Simple("group-a".to_string())),
        }),
    ];

    let result = validate_configs_test(configs).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Circular dependency") || err.contains("cycle"),
        "Expected cycle error, got: {err}"
    );
}

#[tokio::test]
async fn test_dns_group_composition_unknown_ref() {
    // Reference to non-existent group
    let configs = vec![Config::DnsConfigGroup(DnsConfigGroup {
        fake_ip: None,
        dns_group: "my-dns".to_string(),
        dns_servers: NoneOrSome::One(DnsServerSpec::Simple("nonexistent".to_string())),
    })];

    let result = validate_configs_test(configs).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown group") || err.contains("nonexistent"),
        "Expected unknown group error, got: {err}"
    );
}

#[tokio::test]
async fn test_dns_group_composition_with_bootstrap() {
    // Composition and bootstrap work together
    // Note: Using IP-based URLs to avoid network calls during tests
    let configs = vec![
        Config::DnsConfigGroup(DnsConfigGroup {
            fake_ip: None,
            dns_group: "bootstrap-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            fake_ip: None,
            dns_group: "base-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::Simple("tls://1.1.1.1".to_string())),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            fake_ip: None,
            dns_group: "full-dns".to_string(),
            dns_servers: NoneOrSome::Some(vec![
                DnsServerSpec::Simple("base-dns".to_string()), // Composition reference
                DnsServerSpec::WithOptions {
                    url: "tls://8.8.4.4".to_string(), // IP-based, no resolution needed
                    client_chain: NoneOrSome::None,
                    bootstrap_url: Some("bootstrap-dns".to_string()), // Bootstrap reference (not used since URL is IP)
                    server_name: Some("dns.google".to_string()),      // SNI override
                    ip_strategy: IpStrategy::default(),
                    timeout_secs: 10,
                    connect_timeout_secs: 5,
                    attempts: 1,
                    native_cache_secs: None,
                },
            ]),
        }),
    ];

    let result = validate_configs_test(configs).await;
    assert!(
        result.is_ok(),
        "composition with bootstrap should work: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_empty_dns_lists_use_default_resolver() {
    use serde_json::json;

    let configs = serde_json::from_value(json!([
        {"address": "127.0.0.1:1080", "protocol": {"type": "socks"}, "dns": {"servers": []}},
        {"device_fd": 42, "dns": {"servers": []}},
    ]))
    .unwrap();
    let configs = validate_configs_test(configs).await.unwrap();
    assert_eq!(configs.len(), 2);
    for config in configs {
        let dns = match config {
            Config::Server(server) => server.dns.unwrap(),
            Config::TunServer(tun) => tun.dns.unwrap(),
            _ => unreachable!(),
        };
        assert!(matches!(dns.servers, NoneOrSome::None));
        assert_eq!(dns.resolved_group(), None);
    }
}

#[tokio::test]
async fn test_server_dns_with_group_ref() {
    use crate::address::NetLocationPortRange;
    use crate::config::types::dns::DnsConfig;
    use crate::config::types::transport::BindLocation;

    // Server config references an existing dns_group
    let configs = vec![
        Config::DnsConfigGroup(DnsConfigGroup {
            fake_ip: None,
            dns_group: "my-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
        }),
        Config::Server(ServerConfig {
            name: None,
            sniff: false,
            bind_location: BindLocation::Address(OneOrSome::One(
                NetLocationPortRange::new(
                    crate::address::Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                    vec![1234],
                )
                .unwrap(),
            )),
            protocol: ServerProxyConfig::Http {
                username: None,
                password: None,
            },
            transport: Transport::Tcp,
            tcp_settings: None,
            quic_settings: None,
            rules: direct_allow_rule(),
            dns: Some(DnsConfig {
                fake_ip: None,
                servers: NoneOrSome::One(DnsServerSpec::Simple("my-dns".to_string())),
            }),
        }),
    ];

    let result = validate_configs_test(configs).await;
    assert!(
        result.is_ok(),
        "server with dns group ref should work: {:?}",
        result.err()
    );

    // Verify servers is still the group name (not expanded)
    let validated = result.unwrap();
    if let Config::Server(s) = &validated[0] {
        assert_eq!(s.dns.as_ref().unwrap().resolved_group(), Some("my-dns"));
    }
}

#[tokio::test]
async fn test_server_dns_with_mixed_group_and_url() {
    use crate::address::NetLocationPortRange;
    use crate::config::types::dns::DnsConfig;
    use crate::config::types::transport::BindLocation;

    // Server config with both group ref and URL in servers
    let configs = vec![
        Config::DnsConfigGroup(DnsConfigGroup {
            fake_ip: None,
            dns_group: "base-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
        }),
        Config::Server(ServerConfig {
            name: None,
            sniff: false,
            bind_location: BindLocation::Address(OneOrSome::One(
                NetLocationPortRange::new(
                    crate::address::Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                    vec![1234],
                )
                .unwrap(),
            )),
            protocol: ServerProxyConfig::Http {
                username: None,
                password: None,
            },
            transport: Transport::Tcp,
            tcp_settings: None,
            quic_settings: None,
            rules: direct_allow_rule(),
            dns: Some(DnsConfig {
                fake_ip: None,
                servers: NoneOrSome::Some(vec![
                    DnsServerSpec::Simple("base-dns".to_string()), // group ref
                    DnsServerSpec::Simple("udp://1.1.1.1".to_string()), // URL
                ]),
            }),
        }),
    ];

    let result = validate_configs_test(configs).await;
    assert!(
        result.is_ok(),
        "server with mixed dns should work: {:?}",
        result.err()
    );

    // Verify servers was expanded to an inline group name
    let validated = result.unwrap();
    if let Config::Server(s) = &validated[0] {
        let group = s.dns.as_ref().unwrap().resolved_group().unwrap();
        assert!(
            group.starts_with("__inline_dns_"),
            "should be inline group: {}",
            group
        );
    }
}

#[tokio::test]
async fn test_server_dns_with_multiple_group_refs() {
    use crate::address::NetLocationPortRange;
    use crate::config::types::dns::DnsConfig;
    use crate::config::types::transport::BindLocation;

    // Server config with multiple group refs that need expansion
    let configs = vec![
        Config::DnsConfigGroup(DnsConfigGroup {
            fake_ip: None,
            dns_group: "fast-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
        }),
        Config::DnsConfigGroup(DnsConfigGroup {
            fake_ip: None,
            dns_group: "secure-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::Simple("tcp://1.1.1.1".to_string())),
        }),
        Config::Server(ServerConfig {
            name: None,
            sniff: false,
            bind_location: BindLocation::Address(OneOrSome::One(
                NetLocationPortRange::new(
                    crate::address::Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                    vec![1234],
                )
                .unwrap(),
            )),
            protocol: ServerProxyConfig::Http {
                username: None,
                password: None,
            },
            transport: Transport::Tcp,
            tcp_settings: None,
            quic_settings: None,
            rules: direct_allow_rule(),
            dns: Some(DnsConfig {
                fake_ip: None,
                servers: NoneOrSome::Some(vec![
                    DnsServerSpec::Simple("fast-dns".to_string()),
                    DnsServerSpec::Simple("secure-dns".to_string()),
                ]),
            }),
        }),
    ];

    let result = validate_configs_test(configs).await;
    assert!(
        result.is_ok(),
        "server with multiple group refs should work: {:?}",
        result.err()
    );

    // Verify servers was expanded to an inline group name
    let validated = result.unwrap();
    if let Config::Server(s) = &validated[0] {
        let group = s.dns.as_ref().unwrap().resolved_group().unwrap();
        assert!(
            group.starts_with("__inline_dns_"),
            "should be inline group: {}",
            group
        );
    }
}

#[tokio::test]
async fn test_server_dns_unknown_group_ref() {
    use crate::address::NetLocationPortRange;
    use crate::config::types::dns::DnsConfig;
    use crate::config::types::transport::BindLocation;

    // Server config references non-existent dns_group
    let configs = vec![Config::Server(ServerConfig {
        name: None,
        sniff: false,
        bind_location: BindLocation::Address(OneOrSome::One(
            NetLocationPortRange::new(
                crate::address::Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                vec![1234],
            )
            .unwrap(),
        )),
        protocol: ServerProxyConfig::Http {
            username: None,
            password: None,
        },
        transport: Transport::Tcp,
        tcp_settings: None,
        quic_settings: None,
        rules: direct_allow_rule(),
        dns: Some(DnsConfig {
            fake_ip: None,
            servers: NoneOrSome::One(DnsServerSpec::Simple("nonexistent-dns".to_string())),
        }),
    })];

    let result = validate_configs_test(configs).await;
    assert!(result.is_err(), "unknown dns group should fail");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("nonexistent-dns"),
        "error should mention group name: {}",
        err
    );
}
