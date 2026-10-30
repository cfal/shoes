use std::io;

use super::{ClientChainHop, ClientConfig, ClientProxyConfig, ConfigSelection};

pub(super) fn clients(hop: &ClientChainHop) -> impl Iterator<Item = &ClientConfig> {
    let selections: Box<dyn Iterator<Item = &ConfigSelection<ClientConfig>>> = match hop {
        ClientChainHop::Single(selection) => Box::new(std::iter::once(selection)),
        ClientChainHop::Pool(pool) => pool.iter(),
    };
    selections.map(|selection| match selection {
        ConfigSelection::Config(client) => client,
        ConfigSelection::GroupName(_) => unreachable!("health validation requires expanded groups"),
    })
}

pub(crate) fn validate_chain<'a>(
    hops: impl IntoIterator<Item = impl IntoIterator<Item = &'a ClientConfig>>,
) -> io::Result<()> {
    let hops: Vec<Vec<_>> = hops
        .into_iter()
        .map(|hop| hop.into_iter().collect())
        .collect();
    if !hops.iter().flatten().any(|client| {
        client
            .control
            .as_ref()
            .is_some_and(crate::control::catalog::MemberOrigin::has_fallback)
    }) {
        return Ok(());
    }

    // Shared retained transports cannot establish which concrete prefix a check used.
    let mut multiple_prefixes = false;
    for hop in hops {
        for client in &hop {
            if has_dynamic_carrier(client) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "fallback does not support WireGuard with multiple carrier paths",
                ));
            }
            if multiple_prefixes && contains_naive(&client.protocol) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "fallback does not support NaiveProxy with multiple chain prefixes",
                ));
            }
        }
        multiple_prefixes |= hop.len() > 1;
    }
    Ok(())
}

fn has_dynamic_carrier(client: &ClientConfig) -> bool {
    let ClientProxyConfig::Wireguard(config) = &client.protocol else {
        return false;
    };
    config.peer_client_chain.as_ref().is_some_and(|chain| {
        chain
            .hops
            .iter()
            .any(|hop| clients(hop).take(2).count() > 1 || clients(hop).any(has_dynamic_carrier))
    })
}

fn contains_naive(protocol: &ClientProxyConfig) -> bool {
    match protocol {
        ClientProxyConfig::Naiveproxy { .. } => true,
        ClientProxyConfig::Tls(config) => contains_naive(&config.protocol),
        ClientProxyConfig::Reality { protocol, .. }
        | ClientProxyConfig::ShadowTls { protocol, .. } => contains_naive(protocol),
        ClientProxyConfig::Websocket(config) => contains_naive(&config.protocol),
        ClientProxyConfig::SudokuMask(config) => contains_naive(&config.protocol),
        ClientProxyConfig::Xhttp(config) => contains_naive(&config.protocol),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{Config, ConfigSelection, RuleActionConfig, create_server_configs};
    use serde_json::{Value, json};

    const WIREGUARD: &str = "fallback does not support WireGuard with multiple carrier paths";
    const NAIVE: &str = "fallback does not support NaiveProxy with multiple chain prefixes";

    fn fallback(members: Value) -> Value {
        json!({"client_group":"out", "type":"fallback",
            "health_check":{"url":"http://192.0.2.1/", "interval_secs":30},
            "client_proxies":members})
    }

    fn proxy(name: &str) -> Value {
        json!({"name":name, "address":"192.0.2.10:80", "protocol":{"type":"http"}})
    }

    fn server(chain: Value) -> Value {
        json!({"address":"127.0.0.1:0", "protocol":{"type":"socks"},
            "rules":[{"mask":"0.0.0.0/0", "action":"allow", "client_chain":chain}]})
    }

    fn validate(values: Value) -> std::io::Result<crate::config::ValidatedConfigs> {
        create_server_configs(serde_json::from_value(values).unwrap())
    }

    fn rejects(values: Value, message: &str) {
        let error = validate(values)
            .err()
            .expect("unsupported fallback must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported, "{error}");
        assert_eq!(error.to_string(), message);
    }

    #[cfg(unix)]
    fn wireguard(carrier: Value) -> Value {
        let mut group = crate::wireguard::test_support::client(51820);
        group["client_proxies"][0]["protocol"]["peer_client_chain"] = carrier;
        group
    }

    #[cfg(unix)]
    #[test]
    fn health_review5_dynamic_wireguard_rejected_in_unused_groups_and_all_policies() {
        for kind in ["round-robin", "selector", "fallback", "url-test"] {
            let mut carrier = json!({"client_group":"carrier", "type":kind,
                "client_proxies":["direct", proxy("tcp-only")]});
            if kind == "fallback" {
                carrier["health_check"] = json!({"url":"http://192.0.2.1/", "interval_secs":30});
            } else if kind == "url-test" {
                carrier["url"] = json!("http://192.0.2.1/");
            }
            rejects(
                json!([
                    wireguard(json!("carrier")),
                    carrier,
                    fallback(json!(["wg"]))
                ]),
                WIREGUARD,
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn health_review5_wireguard_rejection_covers_recursive_and_separate_hops() {
        let carrier = json!({"client_group":"carrier", "type":"selector", "client_proxies":["direct", proxy("tcp-only")]});
        let mut inner = wireguard(json!("carrier"));
        inner["client_group"] = json!("inner");
        inner["client_proxies"][0]["name"] = json!("inner-wg");
        inner["client_proxies"][0]["address"] = json!("127.0.0.1:51821");
        inner["client_proxies"][0]["protocol"]["private_key"] =
            json!(crate::wireguard::test_support::key(44));
        inner["client_proxies"][0]["protocol"]["public_key"] =
            json!(crate::wireguard::test_support::public(45));
        inner["client_proxies"][0]["protocol"]["addresses"] = json!(["10.78.0.2/32"]);
        let mut outer = wireguard(json!("inner"));
        outer["client_proxies"][0]["protocol"]["mtu"] = json!(1280);
        validate(json!([
            inner.clone(), carrier.clone(), outer.clone(),
            {"client_group":"out", "client_proxies":["wg"]}
        ]))
        .unwrap();
        rejects(
            json!([inner, carrier.clone(), outer, fallback(json!(["wg"]))]),
            WIREGUARD,
        );

        for dns in [false, true] {
            let chain = json!(["wg", "out"]);
            let consumer = if dns {
                json!({"dns_group":"dns", "dns_servers":[{"url":"tcp://192.0.2.53", "client_chain":{"chain":chain}}]})
            } else {
                server(chain)
            };
            rejects(
                json!([
                    wireguard(json!("carrier")),
                    carrier.clone(),
                    fallback(json!([proxy("end")])),
                    consumer
                ]),
                WIREGUARD,
            );
        }
        // A group can combine a fallback branch and a dynamic WireGuard sibling.
        rejects(
            json!([wireguard(json!("carrier")), carrier, fallback(json!(["direct"])),
            {"client_group":"mixed", "client_proxies":["out", "wg"]}]),
            WIREGUARD,
        );
    }

    #[test]
    fn health_review5_naive_rejection_covers_prefixes_wrappers_and_dns() {
        let naive = json!({"type":"naive", "username":"user", "password":"secret"});
        for protocol in [
            naive.clone(),
            json!({"type":"sudoku_mask", "protocol":{"type":"tls", "verify":false, "protocol":naive.clone()}}),
            json!({"type":"tls", "verify":false, "protocol":naive.clone()}),
            json!({"type":"ws", "protocol":naive.clone()}),
            json!({"type":"shadowtls", "password":"secret", "protocol":naive.clone()}),
            json!({"type":"reality", "public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "sni_hostname":"example.com", "protocol":naive.clone()}),
            json!({"type":"xhttp", "mode":"stream-one", "protocol":naive}),
        ] {
            let hop = json!({"address":"192.0.2.20:443", "protocol":protocol});
            rejects(
                json!([
                    fallback(json!([proxy("a"), proxy("b")])),
                    server(json!(["out", hop.clone()]))
                ]),
                NAIVE,
            );
            rejects(
                json!([
                    fallback(json!([hop.clone()])),
                    server(json!([{"pool":[proxy("a"), proxy("b")]}, "out"]))
                ]),
                NAIVE,
            );
            rejects(
                json!([fallback(json!([proxy("a"), proxy("b")])),
                {"dns_group":"dns", "dns_servers":[{"url":"tcp://192.0.2.53", "client_chain":{"chain":["out", hop]}}]}]),
                NAIVE,
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn health_review5_inline_carriers_are_expanded_before_rejection() {
        let mut inner = wireguard(json!("carrier"))["client_proxies"][0].clone();
        inner["address"] = json!("127.0.0.1:51821");
        inner["protocol"]["private_key"] = json!(crate::wireguard::test_support::key(44));
        inner["protocol"]["public_key"] = json!(crate::wireguard::test_support::public(45));
        inner["protocol"]["addresses"] = json!(["10.78.0.2/32"]);
        let mut outer = wireguard(json!({"chain":[{"pool":["out", inner]}]}));
        outer["client_proxies"][0]["protocol"]["mtu"] = json!(1280);
        let carrier = json!({"client_group":"carrier", "type":"selector", "client_proxies":["direct", proxy("tcp-only")]});
        validate(json!([outer.clone(), carrier.clone(), {"client_group":"out", "client_proxies":["direct"]}])).unwrap();
        rejects(
            json!([outer, carrier, fallback(json!(["direct"]))]),
            WIREGUARD,
        );
    }

    #[cfg(unix)]
    #[test]
    fn health_review7_peer_chains_reject_dynamic_carriers_during_config_validation() {
        let carrier = json!({"client_group":"carrier", "type":"selector",
            "client_proxies":["direct", proxy("tcp-only")]});
        let mut inner = wireguard(json!("carrier"));
        inner["client_group"] = json!("inner");
        inner["client_proxies"][0]["name"] = json!("inner-wg");
        inner["client_proxies"][0]["address"] = json!("127.0.0.1:51821");
        inner["client_proxies"][0]["protocol"]["private_key"] =
            json!(crate::wireguard::test_support::key(44));
        inner["client_proxies"][0]["protocol"]["public_key"] =
            json!(crate::wireguard::test_support::public(45));
        inner["client_proxies"][0]["protocol"]["addresses"] = json!(["10.78.0.2/32"]);
        let members = json!([{"name":"end", "address":"192.0.2.10:80",
            "protocol":crate::wireguard::test_support::vless_protocol()}]);

        for chain in [
            json!({"chain":["inner", "out"]}),
            json!({"chain":[{"pool":["out", "inner"]}]}),
        ] {
            let mut outer = wireguard(chain);
            outer["client_proxies"][0]["protocol"]["mtu"] = json!(1280);
            for used in [false, true] {
                let mut configs = vec![inner.clone(), carrier.clone(), outer.clone()];
                if used {
                    configs.push(server(json!("wg")));
                }
                let mut ordinary = configs.clone();
                ordinary.push(json!({"client_group":"out", "client_proxies":members}));
                validate(json!(ordinary)).unwrap();

                configs.push(fallback(members.clone()));
                rejects(json!(configs), WIREGUARD);
            }
        }
    }

    #[test]
    fn health_review5_single_prefix_naive_and_nonfallback_chains_remain_supported() {
        let naive = json!({"name":"naive", "address":"192.0.2.20:443",
            "protocol":{"type":"naive", "username":"user", "password":"secret"}});
        validate(json!([
            fallback(json!([proxy("a")])),
            server(json!(["out", naive.clone()]))
        ]))
        .unwrap();
        validate(json!([
            fallback(json!([naive.clone(), proxy("a")])),
            server(json!("out"))
        ]))
        .unwrap();
        validate(json!([
            fallback(json!([proxy("a"), proxy("b")])),
            server(json!([naive.clone(), "out"]))
        ]))
        .unwrap();
        validate(json!([server(
            json!([{"pool":[proxy("a"), proxy("b")]}, naive])
        )]))
        .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn health_review5_static_wireguard_and_resolver_only_dynamics_remain_supported() {
        validate(json!([
            wireguard(json!("direct")),
            fallback(json!(["wg"])),
            server(json!("out"))
        ]))
        .unwrap();
        let carrier = json!({"client_group":"carrier", "type":"selector", "client_proxies":["direct", proxy("tcp-only")]});
        validate(
            json!([wireguard(json!("carrier")), carrier, fallback(json!([proxy("a")])),
            {"dns_group":"dns", "dns_servers":[{"url":"tcp://192.0.2.53", "client_chain":"wg"}]},
            {"address":"127.0.0.1:0", "protocol":{"type":"socks"}, "dns":{"servers":"dns"},
                "rules":[{"mask":"0.0.0.0/0", "action":"allow", "client_chain":"out"}]}]),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn health_review8_path_cap_precedes_transport_construction() {
        use crate::config::{ClientChainHop, ClientQuicConfig, Transport};
        use crate::option_util::OneOrSome;
        use crate::tcp::chain_builder::try_build_client_proxy_chain;

        let validated =
            validate(json!([fallback(json!([proxy("a")])), server(json!("out"))])).unwrap();
        let Config::Server(server) = &validated.configs[0] else {
            panic!()
        };
        let ConfigSelection::Config(rule) = server.rules.iter().next().unwrap() else {
            panic!()
        };
        let RuleActionConfig::Allow { client_chains, .. } = &rule.action else {
            panic!()
        };
        let client = super::clients(
            client_chains
                .iter()
                .next()
                .unwrap()
                .hops
                .iter()
                .next()
                .unwrap(),
        )
        .next()
        .unwrap();
        let resolver = std::sync::Arc::new(crate::resolver::NativeResolver::new());
        let mut invalid_transport = client.clone();
        invalid_transport.transport = Transport::Quic;
        invalid_transport.quic_settings = Some(ClientQuicConfig {
            verify: false,
            key: Some("not a PEM key".into()),
            cert: Some("not a PEM certificate".into()),
            ..Default::default()
        });
        let error = try_build_client_proxy_chain(
            OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                invalid_transport.clone(),
            ))),
            resolver.clone(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Other, "{error}");

        for sizes in [vec![257], vec![17, 16], vec![2; usize::BITS as usize]] {
            let mut hops: Vec<_> = sizes
                .iter()
                .map(|size| {
                    ClientChainHop::Pool(OneOrSome::Some(vec![
                        ConfigSelection::Config(
                            client.clone()
                        );
                        *size
                    ]))
                })
                .collect();
            let ClientChainHop::Pool(first) = &mut hops[0] else {
                panic!()
            };
            *first.iter_mut().next().unwrap() = ConfigSelection::Config(invalid_transport.clone());
            let error =
                try_build_client_proxy_chain(OneOrSome::Some(hops), resolver.clone()).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{error}");
            assert_eq!(
                error.to_string(),
                "fallback exceeds 256 concrete chain paths"
            );
            assert!(
                error
                    .get_ref()
                    .unwrap()
                    .is::<crate::control::health::HealthCapacity>()
            );
        }

        for (count, fallback) in [(256, true), (257, false)] {
            let mut client = client.clone();
            if !fallback {
                client.control = None;
            }
            try_build_client_proxy_chain(
                OneOrSome::One(ClientChainHop::Pool(OneOrSome::Some(vec![
                    ConfigSelection::Config(client);
                    count
                ]))),
                resolver.clone(),
            )
            .unwrap();
        }
    }

    #[tokio::test]
    async fn health_review5_runtime_builder_rejects_before_constructing_transports() {
        let validated = validate(json!([
            fallback(json!([proxy("a"), proxy("b")])),
            server(json!("out"))
        ]))
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
        let mut hops = client_chains.iter().next().unwrap().hops.clone().into_vec();
        hops.push(
            serde_json::from_value(json!({"address":"192.0.2.20:443", "transport":"quic",
            "protocol":{"type":"xhttp", "protocol":{"type":"naive", "username":"user", "password":"secret"}}}))
            .unwrap(),
        );
        let mut ordinary = hops.clone();
        for hop in &mut ordinary {
            crate::config::client_visit::visit_hop(hop, &mut |client| {
                client.control = None;
                Ok(())
            })
            .unwrap();
        }
        let error = crate::tcp::chain_builder::try_build_client_proxy_chain(
            crate::option_util::OneOrSome::Some(ordinary),
            std::sync::Arc::new(crate::resolver::NativeResolver::new()),
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "XHTTP H3 is only supported at hop 0");
        let error = crate::tcp::chain_builder::try_build_client_proxy_chain(
            crate::option_util::OneOrSome::Some(hops),
            std::sync::Arc::new(crate::resolver::NativeResolver::new()),
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(error.to_string(), NAIVE);
    }
}
