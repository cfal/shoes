use std::io;

#[cfg(test)]
use super::resolved::ResolvedClientChain as ClientChain;
use super::resolved::{
    ResolvedClientConfig as ClientConfig, ResolvedClientHop as ClientChainHop,
    ResolvedClientProxyConfig as ClientProxyConfig,
};
use crate::option_util::OneOrSome;

pub(crate) const MAX_NODES: usize = 16_384;
pub(crate) const MAX_DEPTH: usize = 64;
pub(crate) const MAX_HOPS: usize = 64;

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

pub(crate) fn clients(hop: &ClientChainHop) -> Box<dyn Iterator<Item = &ClientConfig> + '_> {
    super::plan_ops::clients(hop)
}

#[cfg(test)]
pub(crate) fn pool_choice(members: Vec<ClientChain>) -> ClientChainHop {
    super::plan_ops::pool_choice(members)
}

pub(crate) fn measure(hop: &ClientChainHop, depth: usize) -> io::Result<(usize, usize)> {
    super::plan_ops::measure(hop, depth, client_nodes)
}

pub(crate) fn client_nodes(client: &ClientConfig, depth: usize) -> io::Result<usize> {
    let mut nodes = 1usize;
    if let ClientProxyConfig::Wireguard(config) = &client.protocol
        && let Some(chain) = &config.peer_client_chain
    {
        for hop in chain.hops.iter() {
            nodes = nodes.saturating_add(measure(hop, depth + 1)?.0);
        }
    }
    if nodes > MAX_NODES {
        return Err(invalid("client composition exceeds 16384 nodes"));
    }
    Ok(nodes)
}

pub(crate) fn validate(hops: &OneOrSome<ClientChainHop>) -> io::Result<()> {
    super::plan_ops::validate(
        hops,
        client_nodes,
        super::health::validate_client,
        validate_position,
    )
}

pub(super) fn validate_position(client: &ClientConfig, offset: usize) -> io::Result<()> {
    client.validate_quic_key_exchange(offset == 0)?;
    crate::quic_client::validate_resolved(client, offset == 0)?;
    validate_position_flags(
        client.protocol.is_direct(),
        client.protocol.is_wireguard(),
        client.transport == super::Transport::Quic
            && crate::xhttp::connector::contains(&client.protocol),
        offset,
    )
}

pub(super) fn validate_position_flags(
    direct: bool,
    wireguard: bool,
    xhttp_h3: bool,
    offset: usize,
) -> io::Result<()> {
    if offset != 0 {
        if direct {
            return Err(invalid(format!(
                "Direct connectors can only be used at hop 0, not hop {offset}"
            )));
        }
        if wireguard {
            return Err(invalid("WireGuard is only supported at hop 0"));
        }
        if xhttp_h3 {
            return Err(invalid("XHTTP H3 is only supported at hop 0"));
        }
    }
    Ok(())
}

pub(crate) fn direct_only(hops: &OneOrSome<ClientChainHop>) -> bool {
    if hops.iter().count() != 1 {
        return false;
    }
    match hops.iter().next().unwrap() {
        ClientChainHop::Choice(choice) => {
            choice.members.iter().all(|chain| direct_only(&chain.hops))
        }
        hop => clients(hop).all(|client| client.protocol.is_direct()),
    }
}

pub(crate) fn final_clients(
    hops: &OneOrSome<ClientChainHop>,
) -> Box<dyn Iterator<Item = &ClientConfig> + '_> {
    match hops.iter().last() {
        Some(ClientChainHop::Choice(choice)) => Box::new(
            choice
                .members
                .iter()
                .flat_map(|chain| final_clients(&chain.hops)),
        ),
        Some(hop) => clients(hop),
        None => Box::new(std::iter::empty()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ResolvedConfig as Config, ResolvedRuleActionConfig as RuleActionConfig, ValidatedConfigs,
        create_server_configs,
    };
    use serde_json::{Value, json};

    fn proxy(name: &str) -> Value {
        json!({"name":name,"address":"192.0.2.1:443","protocol":{"type":"http"}})
    }

    fn validate(value: Value) -> io::Result<ValidatedConfigs> {
        create_server_configs(serde_json::from_value(value).map_err(io::Error::other)?)
    }

    fn route(value: &ValidatedConfigs) -> &ClientChain {
        let Config::Server(server) = &value.configs[0] else {
            panic!()
        };
        let rule = server.rules.iter().next().unwrap();
        let RuleActionConfig::Allow { client_chains, .. } = &rule.action else {
            panic!()
        };
        client_chains.iter().next().unwrap()
    }

    #[test]
    fn group_wrappers_are_alternatives_and_bare_lists_are_sequences() {
        let base = json!([
            {"client_group":"a", "client_chains":[proxy("a-leaf")]},
            {"client_group":"b", "client_chains":[proxy("b-leaf")]},
            {"client_group":"out", "client_chains":[{"chain": ["a"]},{"chain": ["b"]}]},
            {"address":"127.0.0.1:0","protocol":{"type":"socks"},
             "rules":[{"mask":"0.0.0.0/0","action":"allow","client_chain":"out"}]}
        ]);
        let choices = validate(base.clone()).unwrap();
        let hop = route(&choices).hops.iter().next().unwrap();
        let ClientChainHop::Choice(group) = hop else {
            panic!("group alternatives must remain a choice")
        };
        assert_eq!(group.members.len(), 2);
        assert!(
            group
                .members
                .iter()
                .all(|member| member.hops.iter().count() == 1)
        );
        assert_eq!(measure(hop, 0).unwrap().1, 1);
        let mut sequential = base;
        sequential[2]["client_chains"] = json!(["a", "b"]);
        let sequential = validate(sequential).unwrap();
        let hop = route(&sequential).hops.iter().next().unwrap();
        let ClientChainHop::Choice(group) = hop else {
            panic!("multi-hop members must retain their choice boundary")
        };
        assert_eq!(group.members.len(), 1);
        assert_eq!(group.members[0].hops.iter().count(), 2);
        assert_eq!(measure(hop, 0).unwrap().1, 2);
    }

    #[test]
    fn named_groups_compose_different_length_paths_without_crossing_branches() {
        let validated = validate(json!([
            {"client_group":"a1-selected","type":"selector","client_chains":[proxy("a1")]},
            {"client_group":"nl-hop","client_chains":[proxy("nl")]},
            {"client_group":"a1-selected-nl","client_chains":[{"chain":["a1-selected","nl-hop"]}]},
            {"client_group":"geo-reddit-selected","type":"selector","default":"a1-selected-nl",
             "client_chains":[{"chain": ["a1-selected"]},{"chain": ["a1-selected-nl"]},{"chain": ["direct"]}]},
            {"address":"127.0.0.1:0","protocol":{"type":"socks"},
             "rules":[{"mask":"0.0.0.0/0","action":"allow","client_chain":"geo-reddit-selected"}]}
        ]))
        .unwrap();
        let ClientChainHop::Choice(group) = route(&validated).hops.iter().next().unwrap() else {
            panic!()
        };
        assert_eq!(group.labels, ["a1-selected", "a1-selected-nl", "DIRECT"]);
        assert_eq!(
            group
                .members
                .iter()
                .map(|chain| measure(chain.hops.iter().next().unwrap(), 0).unwrap().1)
                .collect::<Vec<_>>(),
            [1, 2, 1]
        );
        let catalog = validated.catalog.unwrap();
        assert_eq!(
            catalog.selection.snapshot()["geo-reddit-selected"],
            "a1-selected-nl"
        );
        let named = catalog.route("a1-selected-nl").unwrap();
        assert_eq!(measure(named.hops.iter().next().unwrap(), 0).unwrap().1, 2);
    }

    #[test]
    fn group_pool_stages_are_available_to_forwarding_and_probe_routes() {
        for field in ["client_chain", "client_chains"] {
            let validated = validate(json!([
                {"client_group":"a", "client_chain":proxy("a-leaf")},
                {"client_group":"b", "client_chain":proxy("b-leaf")},
                {"client_group":"exit", "client_chain":proxy("exit-leaf")},
                {"client_group":"out", "type":"selector", "default":"pooled",
                 field:{"name":"pooled", "chain":[{"pool":["a", "b"]}, "exit"]}},
                {"address":"127.0.0.1:0", "protocol":{"type":"socks"},
                 "rules":[{"mask":"0.0.0.0/0", "client_chain":"out"}]}
            ]))
            .unwrap();
            let probe = validated.catalog.as_ref().unwrap().route("out").unwrap();
            for chain in [route(&validated), &probe] {
                let ClientChainHop::Choice(group) = chain.hops.iter().next().unwrap() else {
                    panic!()
                };
                assert_eq!(group.labels, ["pooled"]);
                let hops: Vec<_> = group.members[0].hops.iter().collect();
                assert_eq!(hops.len(), 2);
                let ClientChainHop::Choice(pool) = hops[0] else {
                    panic!()
                };
                assert_eq!(pool.members.len(), 2);
                assert_eq!(
                    clients(hops[0])
                        .map(|client| client.name.as_deref().unwrap())
                        .collect::<Vec<_>>(),
                    ["a-leaf", "b-leaf"]
                );
                assert_eq!(
                    clients(hops[1]).next().unwrap().name.as_deref(),
                    Some("exit-leaf")
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn group_origins_do_not_enter_wireguard_carriers_or_include_builtin_direct() {
        let mut wireguard = crate::wireguard::test_support::client(51820);
        wireguard["client_chains"][0]["name"] = json!("tunnel");
        wireguard["client_chains"][0]["protocol"]["peer_client_chain"] = json!("carrier");
        let validated = validate(json!([
            {"client_group":"carrier","type":"selector","client_chains":["direct"]},
            wireguard,
            {"client_group":"out","type":"selector","client_chains":[{"chain": ["wg"]},{"chain": ["direct"]}]},
            {"address":"127.0.0.1:0","protocol":{"type":"socks"},
             "rules":[{"mask":"0.0.0.0/0","action":"allow","client_chain":"out"}]}
        ]))
        .unwrap();
        let hop = route(&validated).hops.iter().next().unwrap();
        let leaves: Vec<_> = clients(hop).collect();
        assert_eq!(
            leaves[0].control.as_ref().unwrap().path,
            [("out".into(), "wg".into()), ("wg".into(), "tunnel".into())]
        );
        assert_eq!(
            leaves[1].control.as_ref().unwrap().path,
            [("out".into(), "DIRECT".into())]
        );
        let super::super::ResolvedClientProxyConfig::Wireguard(config) = &leaves[0].protocol else {
            panic!()
        };
        let carrier = config.peer_client_chain.as_ref().unwrap();
        let leaf = clients(carrier.hops.iter().next().unwrap()).next().unwrap();
        assert_eq!(
            leaf.control.as_ref().unwrap().path,
            [("carrier".into(), "DIRECT".into())]
        );
    }

    #[test]
    fn group_chain_wrappers_are_strict_and_selector_labels_are_explicit() {
        for members in [
            json!([]),
            json!([{"chain":[]}]),
            json!([{"chain":["direct"],"typo":true}]),
            json!([{"chain":["direct"],"protocol":{"type":"direct"}}]),
            json!([{"chain":[{"chain":["direct"]}]}]),
        ] {
            assert!(
                validate(json!([{"client_group":"out","client_chains":members}])).is_err(),
                "{members}"
            );
        }
        assert!(validate(json!([{"client_group":"out","type":"selector","client_chains":[{"chain":["direct", proxy("exit")]}]}])).is_err());
        validate(json!([{"client_group":"out","type":"selector","client_chains":[{"name":"local","chain":["direct"]}]}])).unwrap();
        assert!(
            validate(json!([
                {"client_group":"out","client_chains":[{"name":"local","chain":["direct"]}]},
                {"client_group":"bad","client_chains":["local"]}
            ]))
            .is_err(),
            "choice labels must not create a routing namespace"
        );
    }

    #[test]
    fn chain_references_participate_in_cycle_detection() {
        for members in [json!([{"chain":["a"]}]), json!([{"chain":["b"]}])] {
            assert!(
                validate(json!([
                    {"client_group":"a","client_chains":members},
                    {"client_group":"b","client_chains":["a"]}
                ]))
                .err()
                .unwrap()
                .to_string()
                .to_ascii_lowercase()
                .contains("circular dependency")
            );
        }
    }

    #[test]
    fn unused_groups_and_nested_choices_obey_physical_hop_restrictions() {
        for members in [
            json!([{"chain":[proxy("first"),"direct"]}]),
            json!([{"chain":[proxy("first"),"tail"]}]),
        ] {
            let error = validate(json!([
                {"client_group":"tail","client_chains":[{"chain": ["direct"]},{"chain": [proxy("last")]}]},
                {"client_group":"out","client_chains":members}
            ]))
            .err()
            .unwrap();
            assert!(error.to_string().contains("hop 0"), "{error}");
        }
    }

    #[test]
    fn expansion_is_bounded_before_exponential_materialization() {
        let mut groups = vec![json!({"client_group":"g0","client_chains":["direct"]})];
        for index in 1..20 {
            let previous = format!("g{}", index - 1);
            groups.push(
                json!({"client_group":format!("g{index}"),"client_chains":[{"chain": [previous]},{"chain": [previous]}]}),
            );
        }
        let error = validate(json!(groups)).err().unwrap();
        assert!(error.to_string().contains("16384 nodes"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn expansion_budget_includes_nested_wireguard_carriers() {
        let mut groups = vec![json!({"client_group":"g0","client_chains":["direct"]})];
        for index in 1..20 {
            let mut group = crate::wireguard::test_support::client(51820);
            group["client_group"] = json!(format!("g{index}"));
            let previous = format!("g{}", index - 1);
            group["client_chains"][0]["protocol"]["peer_client_chain"] =
                json!([{"pool":[previous,previous]}]);
            groups.push(group);
        }
        let error = validate(json!(groups)).err().unwrap();
        assert!(error.to_string().contains("16384 nodes"), "{error}");
    }

    #[test]
    fn fixed_aliases_have_the_same_depth_in_forwarding_and_probe_routes() {
        for explicit_chain in [false, true] {
            let mut groups =
                vec![json!({"client_group":"g0","type":"selector","client_chains":["direct"]})];
            for index in 1..256 {
                let previous = format!("g{}", index - 1);
                let member = if explicit_chain {
                    json!({"chain":[previous]})
                } else {
                    json!(previous)
                };
                groups.push(json!({"client_group":format!("g{index}"),"client_chains":[member]}));
            }
            let validated = validate(json!(groups)).unwrap();
            let chain = validated.catalog.unwrap().route("g255").unwrap();
            super::validate(&chain.hops).unwrap();
            assert!(direct_only(&chain.hops));
        }
    }

    #[test]
    fn probe_node_budget_counts_normalized_routes_not_fixed_alias_visits() {
        let mut groups = vec![json!({"client_group":"g0","client_chains":[proxy("leaf")]})];
        for index in 1..=16 {
            groups.push(json!({"client_group":format!("g{index}"),"client_chains":[format!("g{}",index-1)]}));
        }
        groups.extend([
            json!({"client_group":"wide","client_chains":vec![json!({"chain":["g16"]});1024]}),
            json!({"client_group":"out","type":"selector",
                "client_chains":["wide"]}),
        ]);
        let validated = validate(json!(groups)).unwrap();
        let catalog = validated.catalog.unwrap();
        for (name, nodes) in [("wide", 1025), ("out", 1026)] {
            let chain = catalog.route(name).unwrap();
            assert_eq!(
                measure(chain.hops.iter().next().unwrap(), 0).unwrap().0,
                nodes
            );
            super::validate(&chain.hops).unwrap();
        }
    }

    #[test]
    fn repeated_automatic_occurrences_do_not_allocate_health_contexts() {
        let members = vec![json!({"chain":["auto"]}); 2048];
        validate(json!([
            {"client_group":"auto","type":"url-test","url":"http://probe.invalid/","client_chains":["direct"]},
            {"client_group":"wide","client_chains":members}
        ])).unwrap();
    }
}
