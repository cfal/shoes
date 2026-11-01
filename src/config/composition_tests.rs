use crate::config::create_server_configs;
use serde_json::{Value, json};

use crate::config::ResolvedClientConfig as ClientConfig;

fn selector(members: Value) -> Value {
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
    json!({"client_group":"out", "type":"selector",
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

#[test]
fn composition_validation_preserves_fixed_and_variable_prefixes() {
    use crate::config::{ResolvedClientChain, ResolvedClientHop, composition};
    use crate::option_util::OneOrSome;

    let validate = |pools: Vec<Vec<ClientConfig>>| {
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
    let proxy: ClientConfig = crate::config::test_support::from_json(proxy("proxy")).unwrap();
    let protocol = json!({"type":"naive", "username":"user", "password":"secret"});
    for protocol in [protocol.clone(), json!({"type":"tls", "protocol":protocol})] {
        let naive: ClientConfig = crate::config::test_support::from_json(json!({
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
            validate(hops).unwrap();
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
fn naive_choice_entries_and_shared_variable_suffixes_are_supported() {
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
    for route in [
        json!("outer"),
        json!(["outer", naive]),
        json!([{"pool":[proxy("a"), proxy("b")]}, "outer"]),
    ] {
        let mut configs = groups.clone();
        configs.push(server(route));
        validate(json!(configs)).unwrap();
    }
    validate(json!([{"client_group":"out", "client_chains":[
        {"chain":[proxy("fixed")]},
        {"chain":[{"pool":[proxy("a"), proxy("b")]}, naive]}
    ]}]))
    .unwrap();
}

#[cfg(unix)]
#[test]
fn health_review5_dynamic_wireguard_allowed_in_unused_groups_and_all_policies() {
    for kind in ["round-robin", "selector", "url-test"] {
        let mut carrier = json!({"client_group":"carrier", "type":kind,
            "client_chains":[{"chain": ["direct"]}, {"chain": [proxy("tcp-only")]}]});
        if kind == "url-test" {
            carrier["url"] = json!("http://192.0.2.1/");
        }
        validate(json!([
            wireguard(json!("carrier")),
            carrier,
            selector(json!(["wg"]))
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
        selector(json!(["wg"]))
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
            selector(json!([proxy("end")])),
            consumer
        ]))
        .unwrap();
    }
    // A group can combine a selector branch and a dynamic WireGuard sibling.
    validate(
        json!([wireguard(json!("carrier")), carrier, selector(json!(["direct"])),
        {"client_group":"mixed", "client_chains":[{"chain": ["out"]}, {"chain": ["wg"]}]}]),
    )
    .unwrap();
}

#[test]
fn naive_acceptance_covers_prefixes_wrappers_and_dns() {
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
        let hop = json!({"name":"naive", "address":"192.0.2.20:443", "protocol":protocol});
        let connector = crate::tcp::proxy_connector_impl::create_proxy_connector(
            crate::config::test_support::from_json(hop.clone()).unwrap(),
            std::sync::Arc::new(crate::resolver::NativeResolver::new()),
        )
        .unwrap()
        .unwrap();
        assert!(connector.needs_carrier_dialer());
        validate(json!([
            selector(json!([proxy("a"), proxy("b")])),
            server(json!(["out", hop.clone()]))
        ]))
        .unwrap();
        validate(json!([
            selector(json!([hop.clone()])),
            server(json!([{"pool":[proxy("a"), proxy("b")]}, "out"]))
        ]))
        .unwrap();
        validate(
            json!([selector(json!([proxy("a"), proxy("b")])),
            {"dns_group":"dns", "dns_servers":[{"url":"tcp://192.0.2.53", "client_chain":{"chain":["out", hop]}}]}])
        ).unwrap();
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
    validate(
        json!([outer.clone(), carrier.clone(), {"client_group":"out", "client_chains":["direct"]}]),
    )
    .unwrap();
    validate(json!([outer, carrier, selector(json!(["direct"]))])).unwrap();
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

            configs.push(selector(members.clone()));
            validate(json!(configs)).unwrap();
        }
    }
}

#[test]
fn naive_allows_fixed_and_shared_variable_prefixes() {
    let naive = json!({"name":"naive", "address":"192.0.2.20:443",
        "protocol":{"type":"naive", "username":"user", "password":"secret"}});
    validate(json!([
        selector(json!([proxy("a")])),
        server(json!(["out", naive.clone()]))
    ]))
    .unwrap();
    validate(json!([
        selector(json!([naive.clone(), proxy("a")])),
        server(json!("out"))
    ]))
    .unwrap();
    validate(json!([
        selector(json!([proxy("a"), proxy("b")])),
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
        selector(json!(["wg"])),
        server(json!("out"))
    ]))
    .unwrap();
    let carrier = json!({"client_group":"carrier", "type":"selector", "client_chains":[{"chain": ["direct"]}, {"chain": [proxy("tcp-only")]}]});
    validate(
        json!([wireguard(json!("carrier")), carrier, selector(json!([proxy("a")])),
        {"dns_group":"dns", "dns_servers":[{"url":"tcp://192.0.2.53", "client_chain":"wg"}]},
        {"address":"127.0.0.1:0", "protocol":{"type":"socks"}, "dns":{"servers":"dns"},
            "rules":[{"mask":"0.0.0.0/0", "action":"allow", "client_chain":"out"}]}]),
    )
    .unwrap();
}

#[test]
fn selector_routes_do_not_enumerate_pool_products() {
    validate(json!([
        selector(json!([proxy("a"), proxy("b")])),
        server(json!(vec!["out"; 12]))
    ]))
    .unwrap();
}
