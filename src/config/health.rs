use std::io;

use super::resolved::{
    ResolvedClientConfig as ClientConfig, ResolvedClientProxyConfig as ClientProxyConfig,
};

pub(super) fn validate_client(client: &ClientConfig, multiple_prefixes: bool) -> io::Result<()> {
    if multiple_prefixes && contains_naive(&client.protocol) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NaiveProxy does not support multiple chain prefixes",
        ));
    }
    Ok(())
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

pub(super) fn validate_source_client(
    client: &super::ClientConfig,
    multiple_prefixes: bool,
) -> io::Result<()> {
    if multiple_prefixes && source_contains_naive(&client.protocol) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NaiveProxy does not support multiple chain prefixes",
        ));
    }
    Ok(())
}

fn source_contains_naive(protocol: &super::ClientProxyConfig) -> bool {
    match protocol {
        super::ClientProxyConfig::Naiveproxy { .. } => true,
        super::ClientProxyConfig::Tls(config) => source_contains_naive(&config.protocol),
        super::ClientProxyConfig::Reality { protocol, .. }
        | super::ClientProxyConfig::ShadowTls { protocol, .. } => source_contains_naive(protocol),
        super::ClientProxyConfig::Websocket(config) => source_contains_naive(&config.protocol),
        super::ClientProxyConfig::SudokuMask(config) => source_contains_naive(&config.protocol),
        super::ClientProxyConfig::Xhttp(config) => source_contains_naive(&config.protocol),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::config::create_server_configs;
    use serde_json::{Value, json};

    const NAIVE: &str = "NaiveProxy does not support multiple chain prefixes";

    fn fallback(members: Value) -> Value {
        let members: Vec<_> = members
            .as_array()
            .unwrap()
            .iter()
            .map(|member| {
                if member.get("chain").is_some() {
                    member.clone()
                } else {
                    json!({"chain":[member]})
                }
            })
            .collect();
        json!({"client_group":"out", "type":"fallback",
            "health_check":{"url":"http://192.0.2.1/", "interval_secs":30},
            "client_chains":members})
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

    #[test]
    fn composition_validation_preserves_fixed_and_variable_prefixes() {
        use crate::config::{ResolvedClientChain, ResolvedClientHop, composition};
        use crate::option_util::OneOrSome;

        let validate = |pools: Vec<Vec<super::ClientConfig>>| {
            let hops = pools
                .into_iter()
                .map(|clients| {
                    composition::pool_choice(
                        clients
                            .into_iter()
                            .map(|client| ResolvedClientChain {
                                hops: OneOrSome::One(ResolvedClientHop::Single(client)),
                            })
                            .collect(),
                    )
                })
                .collect();
            composition::validate(&OneOrSome::Some(hops))
        };
        let proxy: super::ClientConfig =
            crate::config::test_support::from_json(proxy("proxy")).unwrap();
        let protocol = json!({"type":"naive", "username":"user", "password":"secret"});
        for protocol in [protocol.clone(), json!({"type":"tls", "protocol":protocol})] {
            let naive: super::ClientConfig = crate::config::test_support::from_json(json!({
                "address":"192.0.2.20:443", "protocol":protocol
            }))
            .unwrap();
            validate(vec![vec![proxy.clone()], vec![naive.clone()]]).unwrap();
            validate(vec![
                vec![naive.clone(), proxy.clone()],
                vec![proxy.clone()],
            ])
            .unwrap();
            for hops in [
                vec![vec![proxy.clone(), proxy.clone()], vec![naive.clone()]],
                vec![
                    vec![proxy.clone(), proxy.clone()],
                    vec![proxy.clone()],
                    vec![naive],
                ],
            ] {
                let error = validate(hops).unwrap_err();
                assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
                assert_eq!(error.to_string(), NAIVE);
            }
        }
    }

    #[cfg(unix)]
    fn wireguard(carrier: Value) -> Value {
        let mut group = crate::wireguard::test_support::client(51820);
        group["client_chains"][0]["protocol"]["peer_client_chain"] = carrier;
        group
    }

    #[test]
    fn naive_choice_entries_are_fixed_but_shared_suffixes_are_variable() {
        let naive = json!({"address":"192.0.2.20:443",
            "protocol":{"type":"naive", "username":"user", "password":"secret"}});
        let groups = vec![
            json!({"client_group":"inner", "client_chains":[
                {"chain":[naive]}, {"chain":[proxy("prefix"), naive]}
            ]}),
            json!({"client_group":"outer", "client_chains":[
                {"chain":["inner"]}, {"chain":[proxy("other")]}
            ]}),
        ];
        for (route, valid) in [
            (json!("outer"), true),
            (json!(["outer", naive]), false),
            (json!([{"pool":[proxy("a"), proxy("b")]}, "outer"]), false),
        ] {
            let mut configs = groups.clone();
            configs.push(server(route));
            if valid {
                validate(json!(configs)).unwrap();
            } else {
                rejects(json!(configs), NAIVE);
            }
        }
        rejects(
            json!([{"client_group":"out", "client_chains":[
                {"chain":[proxy("fixed")]},
                {"chain":[{"pool":[proxy("a"), proxy("b")]}, naive]}
            ]}]),
            NAIVE,
        );
    }

    #[cfg(unix)]
    #[test]
    fn health_review5_dynamic_wireguard_allowed_in_unused_groups_and_all_policies() {
        for kind in ["round-robin", "selector", "fallback", "url-test"] {
            let mut carrier = json!({"client_group":"carrier", "type":kind,
                "client_chains":[{"chain": ["direct"]}, {"chain": [proxy("tcp-only")]}]});
            if kind == "fallback" {
                carrier["health_check"] = json!({"url":"http://192.0.2.1/", "interval_secs":30});
            } else if kind == "url-test" {
                carrier["url"] = json!("http://192.0.2.1/");
            }
            validate(json!([
                wireguard(json!("carrier")),
                carrier,
                fallback(json!(["wg"]))
            ]))
            .unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn health_review5_wireguard_health_covers_recursive_and_separate_hops() {
        let carrier = json!({"client_group":"carrier", "type":"selector", "client_chains":[{"chain": ["direct"]}, {"chain": [proxy("tcp-only")]}]});
        let mut inner = wireguard(json!("carrier"));
        inner["client_group"] = json!("inner");
        inner["client_chains"][0]["name"] = json!("inner-wg");
        inner["client_chains"][0]["address"] = json!("127.0.0.1:51821");
        inner["client_chains"][0]["protocol"]["private_key"] =
            json!(crate::wireguard::test_support::key(44));
        inner["client_chains"][0]["protocol"]["public_key"] =
            json!(crate::wireguard::test_support::public(45));
        inner["client_chains"][0]["protocol"]["addresses"] = json!(["10.78.0.2/32"]);
        let mut outer = wireguard(json!("inner"));
        outer["client_chains"][0]["protocol"]["mtu"] = json!(1280);
        validate(json!([
            inner.clone(), carrier.clone(), outer.clone(),
            {"client_group":"out", "client_chains":["wg"]}
        ]))
        .unwrap();
        validate(json!([
            inner,
            carrier.clone(),
            outer,
            fallback(json!(["wg"]))
        ]))
        .unwrap();

        for dns in [false, true] {
            let chain = json!(["wg", "out"]);
            let consumer = if dns {
                json!({"dns_group":"dns", "dns_servers":[{"url":"tcp://192.0.2.53", "client_chain":{"chain":chain}}]})
            } else {
                server(chain)
            };
            validate(json!([
                wireguard(json!("carrier")),
                carrier.clone(),
                fallback(json!([proxy("end")])),
                consumer
            ]))
            .unwrap();
        }
        // A group can combine a fallback branch and a dynamic WireGuard sibling.
        validate(
            json!([wireguard(json!("carrier")), carrier, fallback(json!(["direct"])),
            {"client_group":"mixed", "client_chains":[{"chain": ["out"]}, {"chain": ["wg"]}]}]),
        )
        .unwrap();
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
    fn health_review5_inline_carriers_are_expanded_without_route_health_restrictions() {
        let mut inner = wireguard(json!("carrier"))["client_chains"][0].clone();
        inner["address"] = json!("127.0.0.1:51821");
        inner["protocol"]["private_key"] = json!(crate::wireguard::test_support::key(44));
        inner["protocol"]["public_key"] = json!(crate::wireguard::test_support::public(45));
        inner["protocol"]["addresses"] = json!(["10.78.0.2/32"]);
        let mut outer = wireguard(json!({"chain":[{"pool":["out", inner]}]}));
        outer["client_chains"][0]["protocol"]["mtu"] = json!(1280);
        let carrier = json!({"client_group":"carrier", "type":"selector", "client_chains":[{"chain": ["direct"]}, {"chain": [proxy("tcp-only")]}]});
        validate(json!([outer.clone(), carrier.clone(), {"client_group":"out", "client_chains":["direct"]}])).unwrap();
        validate(json!([outer, carrier, fallback(json!(["direct"]))])).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn health_review7_peer_chains_accept_dynamic_carriers_with_group_health() {
        let carrier = json!({"client_group":"carrier", "type":"selector",
            "client_chains":[{"chain": ["direct"]}, {"chain": [proxy("tcp-only")]}]});
        let mut inner = wireguard(json!("carrier"));
        inner["client_group"] = json!("inner");
        inner["client_chains"][0]["name"] = json!("inner-wg");
        inner["client_chains"][0]["address"] = json!("127.0.0.1:51821");
        inner["client_chains"][0]["protocol"]["private_key"] =
            json!(crate::wireguard::test_support::key(44));
        inner["client_chains"][0]["protocol"]["public_key"] =
            json!(crate::wireguard::test_support::public(45));
        inner["client_chains"][0]["protocol"]["addresses"] = json!(["10.78.0.2/32"]);
        let members = json!([{"name":"end", "address":"192.0.2.10:80",
            "protocol":crate::wireguard::test_support::vless_protocol()}]);

        for chain in [
            json!({"chain":["inner", "out"]}),
            json!({"chain":[{"pool":["out", "inner"]}]}),
        ] {
            let mut outer = wireguard(chain);
            outer["client_chains"][0]["protocol"]["mtu"] = json!(1280);
            for used in [false, true] {
                let mut configs = vec![inner.clone(), carrier.clone(), outer.clone()];
                if used {
                    configs.push(server(json!("wg")));
                }
                let mut ordinary = configs.clone();
                ordinary.push(json!({"client_group":"out", "client_chains":members}));
                validate(json!(ordinary)).unwrap();

                configs.push(fallback(members.clone()));
                validate(json!(configs)).unwrap();
            }
        }
    }

    #[test]
    fn naive_allows_fixed_prefixes_but_rejects_shared_variable_prefixes() {
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
        rejects(
            json!([server(json!([{"pool":[proxy("a"), proxy("b")]}, naive]))]),
            "NaiveProxy does not support multiple chain prefixes",
        );
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
        let carrier = json!({"client_group":"carrier", "type":"selector", "client_chains":[{"chain": ["direct"]}, {"chain": [proxy("tcp-only")]}]});
        validate(
            json!([wireguard(json!("carrier")), carrier, fallback(json!([proxy("a")])),
            {"dns_group":"dns", "dns_servers":[{"url":"tcp://192.0.2.53", "client_chain":"wg"}]},
            {"address":"127.0.0.1:0", "protocol":{"type":"socks"}, "dns":{"servers":"dns"},
                "rules":[{"mask":"0.0.0.0/0", "action":"allow", "client_chain":"out"}]}]),
        )
        .unwrap();
    }

    #[test]
    fn fallback_routes_do_not_enumerate_pool_products() {
        validate(json!([
            fallback(json!([proxy("a"), proxy("b")])),
            server(json!(vec!["out"; 12]))
        ]))
        .unwrap();
    }
}
