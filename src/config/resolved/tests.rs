use super::*;
use crate::config::{
    ClientChain, ClientChainHop, ClientConfigGroup, ValidatedConfigs, create_server_configs,
};
use crate::control::catalog::CatalogNode;
use serde_json::{Value, json};

fn compile(configs: Value) -> std::io::Result<ValidatedConfigs> {
    create_server_configs(serde_json::from_value(configs).unwrap())
}

#[test]
fn resolved_routes_preserve_identity_serialization_shape() {
    let source = super::super::ClientChain::default();
    let resolved = ResolvedClientChain::default();
    assert_eq!(
        serde_json::to_value(source).unwrap(),
        serde_json::to_value(&resolved).unwrap()
    );
    let choice = HopPlan::Choice(Box::new(ChoicePlan {
        name: "out".into(),
        group_type: GroupType::RoundRobin,
        labels: vec!["direct".into()],
        members: vec![resolved],
    }));
    let value = serde_json::to_value(choice).unwrap();
    assert_eq!(value["name"], "out");
    assert_eq!(value["labels"], serde_json::json!(["direct"]));
    assert_eq!(value["members"][0]["chain"]["protocol"]["type"], "direct");
    assert!(value.get("Choice").is_none());
}

#[test]
fn resolved_client_protocol_serialization_matches_source_bytes() {
    use crate::config::test_support::Inline;

    for protocol in [
        json!({"type":"direct"}),
        json!({"type":"http"}),
        json!({"type":"socks5","username":"user","password":"secret"}),
        json!({"type":"ss","cipher":"aes-128-gcm","password":"secret"}),
        json!({"type":"snell","cipher":"aes-128-gcm","password":"secret","udp_enabled":false}),
        json!({"type":"vless","user_id":"test","vision":true,"udp_enabled":false,"h2mux":{}}),
        json!({"type":"trojan","password":"secret"}),
        json!({"type":"reality","public_key":"test","protocol":{"type":"socks"}}),
        json!({"type":"shadowtls","password":"secret","protocol":{"type":"socks"}}),
        json!({"type":"tls","protocol":{"type":"socks"}}),
        json!({"type":"vmess","cipher":"aes-128-gcm","user_id":"test"}),
        json!({"type":"ws","protocol":{"type":"socks"}}),
        json!({"type":"splithttp","protocol":{"type":"socks"}}),
        json!({"type":"sudoku_mask","protocol":{"type":"socks"}}),
        json!({"type":"noop"}),
        json!({"type":"anytls","password":"secret","udp_enabled":false}),
        json!({"type":"naive","username":"user","password":"secret","padding":false}),
    ] {
        let source: crate::config::ClientProxyConfig = serde_json::from_value(protocol).unwrap();
        let resolved = ResolvedClientProxyConfig::inline(source.clone());
        assert_eq!(
            serde_yaml::to_string(&source).unwrap(),
            serde_yaml::to_string(&resolved).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&source).unwrap(),
            serde_json::to_string(&resolved).unwrap()
        );
    }
}

#[test]
fn resolved_server_protocol_serialization_matches_source_bytes() {
    use crate::config::test_support::Inline;

    for protocol in [
        json!({"type":"http"}),
        json!({"type":"socks5","udp_enabled":false}),
        json!({"type":"ss","cipher":"aes-128-gcm","password":"secret"}),
        json!({"type":"snell","cipher":"aes-128-gcm","password":"secret"}),
        json!({"type":"vless","user_id":"test","vision":true}),
        json!({"type":"trojan","password":"secret"}),
        json!({"type":"tls"}),
        json!({"type":"vmess","cipher":"aes-128-gcm","user_id":"test"}),
        json!({"type":"anytls","user":{"password":"secret"}}),
        json!({"type":"ws","target":{"protocol":{"type":"socks"}}}),
        json!({"type":"splithttp","protocol":{"type":"socks"}}),
        json!({"type":"sudoku_mask","protocol":{"type":"socks"}}),
        json!({"type":"forward","target":"127.0.0.1:443"}),
        json!({"type":"hysteria2","password":"secret"}),
        json!({"type":"tuic","uuid":"test","password":"secret"}),
        json!({"type":"http+socks"}),
        json!({"type":"naive","user":{"username":"user","password":"secret"}}),
    ] {
        let source: crate::config::ServerProxyConfig = serde_json::from_value(protocol).unwrap();
        let resolved = ResolvedServerProxyConfig::inline(source.clone());
        assert_eq!(
            serde_yaml::to_string(&source).unwrap(),
            serde_yaml::to_string(&resolved).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&source).unwrap(),
            serde_json::to_string(&resolved).unwrap()
        );
    }
}

#[test]
fn resolved_choice_payloads_are_not_source_syntax() {
    let choice = json!({"name":"out","group_type":"round-robin","labels":["direct"],
        "members":[{"chain":{"protocol":{"type":"direct"}}}]});
    assert!(serde_json::from_value::<ClientChainHop>(choice.clone()).is_err());
    assert!(serde_json::from_value::<ClientChain>(json!({"chain":[choice]})).is_err());
    assert!(
        serde_json::from_value::<ClientConfigGroup>(
            json!({"client_group":"out","client_chains":[{"chain":[choice]}]})
        )
        .is_err()
    );
}

#[test]
fn lowering_preserves_defined_validation_precedence() {
    let invalid_client = json!({"address":"192.0.2.1:443",
        "protocol":{"type":"tls","protocol":{"type":"direct"}}});
    let server = |chain: Value| {
        json!({"address":"127.0.0.1:0","protocol":{"type":"socks"},
        "rules":[{"masks":"0.0.0.0/0","action":"allow","client_chain":chain}]})
    };
    for (configs, expected) in [
        (
            json!([server(json!([invalid_client, "missing"]))]),
            "direct cannot be used as an inner",
        ),
        (
            json!([server(json!(["missing", invalid_client]))]),
            "Unknown client group: missing",
        ),
        (
            json!([server(json!([{"pool":[invalid_client, "missing"]}]))]),
            "direct cannot be used as an inner",
        ),
        (
            json!([{"address":"127.0.0.1:0","protocol":{"type":"snell","cipher":"invalid","password":"secret"},
            "rules":[{"masks":"0.0.0.0/0","action":"allow","client_chain":"missing"}]}]),
            "Unknown client group: missing",
        ),
        (
            json!([
                {"clash_api_address":"127.0.0.1:0","secret":"test"},
                {"rule_group":"unused","rules":[{"masks":"0.0.0.0/0","action":"allow","client_chain":invalid_client}]},
                {"address":"127.0.0.1:0","protocol":{"type":"socks"},"dns":{"fake_ip":true},
                 "rules":[{"masks":"0.0.0.0/0","action":"allow","override_address":"198.18.0.2:443"}]}
            ]),
            "rule override overlaps",
        ),
    ] {
        let error = compile(configs).err().unwrap();
        assert!(
            error.to_string().contains(expected),
            "{error}, expected {expected}"
        );
    }
    let mut groups = vec![json!({"client_group":"g0","client_chains":invalid_client})];
    for index in 1..15 {
        let previous = format!("g{}", index - 1);
        groups.push(json!({"client_group":format!("g{index}"),
            "client_chains":[{"chain":[previous]},{"chain":[previous]}]}));
    }
    let error = compile(json!(groups)).err().unwrap();
    assert!(error.to_string().contains("16384 nodes"), "{error}");
}

#[cfg(unix)]
fn wireguard() -> Value {
    use base64::Engine;
    let public = gotatun::x25519::PublicKey::from(&gotatun::x25519::StaticSecret::from([41; 32]));
    json!({"name":"vpn","address":"192.0.2.99:51820","protocol":{
        "type":"wireguard",
        "private_key":base64::engine::general_purpose::STANDARD.encode([42; 32]),
        "public_key":base64::engine::general_purpose::STANDARD.encode(public.as_bytes()),
        "addresses":["10.77.0.2/32"],"mtu":1280,"peer_client_chain":"carrier"
    }})
}

#[cfg(unix)]
#[test]
fn catalog_only_carriers_obey_complete_client_node_and_depth_limits() {
    for depth_limit in [false, true] {
        for over_limit in [false, true] {
            let mut configs = vec![
                json!({"clash_api_address":"127.0.0.1:0","secret":"test"}),
                json!({"client_group":"g0","client_chain":"direct"}),
            ];
            let levels = if depth_limit {
                63 + usize::from(over_limit)
            } else {
                13
            };
            for index in 1..=levels {
                let previous = format!("g{}", index - 1);
                configs.push(if depth_limit {
                    json!({"client_group":format!("g{index}"),"type":"selector","client_chain":previous})
                } else {
                    json!({"client_group":format!("g{index}"),"client_chains":[
                        {"chain":[previous]},{"chain":[previous]}
                    ]})
                });
            }
            let mut carrier = vec![json!(format!("g{levels}"))];
            if !depth_limit && over_limit {
                carrier.push(json!({"address":"192.0.2.1:443","protocol":{
                    "type":"vless","user_id":"550e8400-e29b-41d4-a716-446655440000"
                }}));
            }
            let mut client = wireguard();
            client["protocol"]["peer_client_chain"] = json!(carrier);
            configs.push(json!({"rule_group":"unused","rules":[{
                "masks":"0.0.0.0/0","client_chain":client
            }]}));
            let result = compile(json!(configs));
            if over_limit {
                let error = result
                    .err()
                    .expect("catalog leaf exceeds the complete route limit");
                let expected = if depth_limit {
                    "64 levels"
                } else {
                    "16384 nodes"
                };
                assert!(error.to_string().contains(expected), "{error}");
            } else {
                let validated = result.unwrap();
                assert!(validated.wireguard_endpoints.is_empty());
                let route = validated.catalog.unwrap().route("vpn").unwrap();
                crate::config::composition::validate(&route.hops).unwrap();
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn recursive_carriers_are_resolved_at_every_consumer_and_in_unused_catalog_leaves() {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let client = wireguard();
    let rule = json!({"masks":"0.0.0.0/0","action":"allow","client_chain":client});
    let dns = json!({"url":"tcp://192.0.2.53","client_chain":client});
    let mut sources = vec![
        json!({"client_group":"out","client_chain":client}),
        json!({"client_group":"out","client_chain":{"name":"relay","chain":[client]}}),
        json!({"client_group":"out","client_chain":{"name":"relay","chain":[{"pool":[client]}]}}),
        json!({"rule_group":"unused","rules":[rule]}),
        json!({"dns_group":"dns","dns_servers":[dns]}),
        json!({"address":"127.0.0.1:0","protocol":{"type":"socks"},"rules":[rule]}),
        json!({"address":"127.0.0.1:0","protocol":{"type":"socks"},"dns":{"servers":[dns]}}),
        json!({"device_fd":42,"rules":[rule]}),
        json!({"device_fd":42,"dns":{"servers":[dns]}}),
    ];
    let target = json!({"cert":certificate.cert.pem(),"key":certificate.signing_key.serialize_pem(),
        "protocol":{"type":"socks"},"override_rules":[rule]});
    for protocol in [
        json!({"type":"tls","default_target":target}),
        json!({"type":"tls","tls_targets":{"localhost":target}}),
        json!({"type":"tls","shadowtls_targets":{"localhost":{
            "password":"secret","protocol":{"type":"socks"},
            "handshake":{"address":"localhost:443","client_chain":[client]}
        }}}),
        json!({"type":"tls","reality_targets":{"localhost":{
            "private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","dest":"localhost:443",
            "protocol":{"type":"socks"},"dest_client_chain":[client]
        }}}),
        json!({"type":"websocket","targets":[{"protocol":{"type":"socks"},"override_rules":[rule]}]}),
        json!({"type":"sudoku_mask","protocol":{"type":"websocket",
            "targets":[{"protocol":{"type":"socks"},"override_rules":[rule]}]}}),
        json!({"type":"xhttp","protocol":{"type":"websocket",
            "targets":[{"protocol":{"type":"socks"},"override_rules":[rule]}]}}),
    ] {
        sources.push(json!({"address":"127.0.0.1:0","protocol":protocol}));
    }
    for source in sources {
        let mut validated = compile(json!([
            {"clash_api_address":"127.0.0.1:0","secret":"test"},
            {"client_group":"carrier","type":"selector","client_chains":["direct"]},
            source
        ]))
        .unwrap_or_else(|error| panic!("{source}: {error}"));
        let catalog = validated.catalog.as_ref().unwrap();
        let CatalogNode::Leaf(client) = &catalog.nodes["vpn"] else {
            panic!("expected leaf")
        };
        let ResolvedClientProxyConfig::Wireguard(wg) = &client.protocol else {
            panic!("expected WireGuard")
        };
        let chain = wg.peer_client_chain.as_ref().unwrap();
        let HopPlan::Choice(choice) = chain.hops.iter().next().unwrap() else {
            panic!("policy boundary lost")
        };
        assert_eq!(choice.name, "carrier");
        assert_eq!(choice.labels, ["DIRECT"]);
        assert!(wg.connector.is_none());
        assert!(catalog.route("vpn").is_ok());
        let mut found = 0;
        validated
            .visit_clients(&mut |client| {
                if let ResolvedClientProxyConfig::Wireguard(wg) = &client.protocol {
                    assert!(wg.peer_client_chain.is_some());
                    found += 1;
                }
                Ok(())
            })
            .unwrap();
        if validated.configs.is_empty() {
            assert!(
                validated.wireguard_endpoints.is_empty(),
                "unused leaf activated a device"
            );
        } else {
            assert!(found > 0, "runtime traversal missed {source}");
        }
    }
}

#[cfg(unix)]
#[test]
fn invalid_wireguard_placement_and_settings_precede_hidden_references() {
    let client = wireguard();
    let mut invalid = client.clone();
    invalid["protocol"]["peer_client_chain"] = json!("missing");
    let invalid_inline = json!({"address":"192.0.2.1:443",
        "protocol":{"type":"tls","protocol":{"type":"direct"}}});
    let error = compile(json!([{"address":"127.0.0.1:0","protocol":{"type":"socks"},
    "rules":[{"masks":"0.0.0.0/0","action":"allow","client_chain":[
        {"pool":[invalid_inline, invalid]}
    ]}]}]))
    .err()
    .unwrap();
    assert!(
        error.to_string().contains("Unknown client group: missing"),
        "{error}"
    );
    let wrapped = json!({"address":"192.0.2.1:443","protocol":{
        "type":"tls","protocol":invalid["protocol"]
    }});
    let error = compile(json!([{"address":"127.0.0.1:0","protocol":{"type":"socks"},
        "rules":[{"masks":"0.0.0.0/0","action":"allow","client_chain":wrapped}]}]))
    .err()
    .unwrap();
    assert!(
        error
            .to_string()
            .contains("WireGuard cannot be used as an inner"),
        "{error}"
    );

    let mut server = json!({"protocol":{"type":"wireguard",
        "private_key":client["protocol"]["private_key"],"addresses":["10.77.0.1/32"],"mtu":1200,
        "peer_client_chain":"missing","peers":[{"public_key":client["protocol"]["public_key"],
        "endpoint":"192.0.2.1:51820","allowed_ips":["10.77.0.2/32"],"persistent_keepalive":25}]},
        "rules":"block-all"});
    let error = compile(json!([server])).err().unwrap();
    assert!(error.to_string().contains("MTU must be"), "{error}");
    server["protocol"]["mtu"] = json!(1280);
    let error = compile(json!([server])).err().unwrap();
    assert!(
        error.to_string().contains("Unknown client group: missing"),
        "{error}"
    );
}

#[cfg(unix)]
#[test]
fn carrier_identity_serialization_is_flat_complete_and_ignores_runtime_handles() {
    let mut source = wireguard();
    source["protocol"]["peer_client_chain"] = json!([{"protocol":{"type":"direct"}}]);
    let source: crate::config::ClientConfig = serde_json::from_value(source).unwrap();
    let mut resolved = crate::config::test_support::client(source.clone());
    assert_eq!(
        serde_yaml::to_value(&source).unwrap(),
        serde_yaml::to_value(&resolved).unwrap()
    );
    let before = serde_yaml::to_value(&resolved).unwrap();
    let ResolvedClientProxyConfig::Wireguard(config) = &mut resolved.protocol else {
        panic!("expected WireGuard")
    };
    config.endpoint_id = "generation-local".into();
    assert_eq!(before, serde_yaml::to_value(&resolved).unwrap());
    let ResolvedClientProxyConfig::Wireguard(config) = &mut resolved.protocol else {
        panic!("expected WireGuard")
    };
    config.peer_client_chain = Some(ResolvedClientChain {
        hops: OneOrSome::One(HopPlan::Choice(Box::new(ChoicePlan {
            name: "carrier".into(),
            group_type: GroupType::RoundRobin,
            labels: vec!["0".into(), "1".into()],
            members: vec![
                ResolvedClientChain::default(),
                ResolvedClientChain::default(),
            ],
        }))),
    });
    assert_ne!(before, serde_yaml::to_value(&resolved).unwrap());
}
