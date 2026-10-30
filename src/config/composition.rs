use std::collections::HashMap;
use std::io;

use super::{ClientChain, ClientChainHop, ClientConfig, ConfigSelection, GroupType};
use crate::option_util::OneOrSome;

pub(crate) type Groups = HashMap<String, ClientChainHop>;
pub(crate) const MAX_NODES: usize = 16_384;
pub(crate) const MAX_DEPTH: usize = 64;
pub(crate) const MAX_HOPS: usize = 64;

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

pub(crate) fn clients(hop: &ClientChainHop) -> Box<dyn Iterator<Item = &ClientConfig> + '_> {
    fn client(selection: &ConfigSelection<ClientConfig>) -> &ClientConfig {
        match selection {
            ConfigSelection::Config(client) => client,
            ConfigSelection::GroupName(_) => panic!("client groups must be resolved"),
        }
    }
    match hop {
        ClientChainHop::Single(selection) => Box::new(std::iter::once(client(selection))),
        ClientChainHop::Pool(pool) => Box::new(pool.iter().map(client)),
        ClientChainHop::Choice(choice) => Box::new(
            choice
                .members
                .iter()
                .flat_map(|chain| chain.hops.iter().flat_map(clients)),
        ),
    }
}

pub(crate) fn expand(hops: &mut OneOrSome<ClientChainHop>, groups: &Groups) -> io::Result<()> {
    fn member(
        selection: &ConfigSelection<ClientConfig>,
        groups: &Groups,
    ) -> io::Result<ClientChainHop> {
        match selection {
            ConfigSelection::Config(_) => Ok(ClientChainHop::Single(selection.clone())),
            ConfigSelection::GroupName(name) => groups
                .get(name)
                .cloned()
                .ok_or_else(|| invalid(format!("Unknown client group: {name}"))),
        }
    }
    // Charge referenced trees before cloning them into this occurrence.
    let mut nodes = 0usize;
    for hop in hops.iter() {
        let selections: Vec<_> = match hop {
            ClientChainHop::Single(selection) => vec![selection],
            ClientChainHop::Pool(pool) => pool.iter().collect(),
            ClientChainHop::Choice(_) => {
                nodes = nodes.saturating_add(measure(hop, 0)?.0);
                if nodes > MAX_NODES {
                    return Err(invalid("client composition exceeds 16384 nodes"));
                }
                continue;
            }
        };
        for selection in selections {
            nodes = nodes.saturating_add(match selection {
                ConfigSelection::Config(client) => client_nodes(client, 0)?,
                ConfigSelection::GroupName(name) => {
                    measure(
                        groups
                            .get(name)
                            .ok_or_else(|| invalid(format!("Unknown client group: {name}")))?,
                        0,
                    )?
                    .0
                }
            });
            if nodes > MAX_NODES {
                return Err(invalid("client composition exceeds 16384 nodes"));
            }
        }
    }
    for hop in hops.iter_mut() {
        *hop = match hop {
            ClientChainHop::Single(selection) => member(selection, groups)?,
            ClientChainHop::Pool(pool) => {
                let mut members = Vec::new();
                for selection in pool.iter() {
                    members.push(ClientChain {
                        hops: OneOrSome::One(member(selection, groups)?),
                    });
                }
                ClientChainHop::Choice(Box::new(super::ClientChoice {
                    name: String::new(),
                    group_type: GroupType::RoundRobin,
                    labels: (0..members.len()).map(|index| index.to_string()).collect(),
                    members,
                }))
            }
            ClientChainHop::Choice(_) => continue,
        };
    }
    validate(hops)
}

// Returns expanded node count, maximum physical hop count, and concrete path count.
pub(crate) fn measure(hop: &ClientChainHop, depth: usize) -> io::Result<(usize, usize, usize)> {
    if depth > MAX_DEPTH {
        return Err(invalid("client composition exceeds 64 levels"));
    }
    match hop {
        ClientChainHop::Single(ConfigSelection::GroupName(name)) => {
            Err(invalid(format!("unresolved client group: {name}")))
        }
        ClientChainHop::Single(ConfigSelection::Config(client)) => {
            Ok((client_nodes(client, depth)?, 1, 1))
        }
        ClientChainHop::Pool(pool) => {
            if pool.iter().count() == 0 {
                return Err(invalid("pool cannot be empty"));
            }
            let mut nodes = 0usize;
            for selection in pool.iter() {
                let ConfigSelection::Config(client) = selection else {
                    return Err(invalid("unresolved client group in pool"));
                };
                nodes = nodes.saturating_add(client_nodes(client, depth)?);
            }
            Ok((nodes, 1, pool.iter().count()))
        }
        ClientChainHop::Choice(choice) => {
            if choice.members.is_empty() || choice.members.len() != choice.labels.len() {
                return Err(invalid("choice requires nonempty, labeled members"));
            }
            let mut nodes = 1usize;
            let mut longest = 0usize;
            let mut paths = 0usize;
            for member in &choice.members {
                if member.hops.iter().count() == 0 {
                    return Err(invalid("chain cannot be empty"));
                }
                let mut length = 0usize;
                let mut product = 1usize;
                for hop in member.hops.iter() {
                    let (count, hops, branches) = measure(hop, depth + 1)?;
                    nodes = nodes.saturating_add(count);
                    length = length.saturating_add(hops);
                    product = product.saturating_mul(branches);
                }
                longest = longest.max(length);
                paths = paths.saturating_add(product);
            }
            if nodes > MAX_NODES || longest > MAX_HOPS {
                return Err(invalid("client composition exceeds 16384 nodes or 64 hops"));
            }
            Ok((nodes, longest, paths))
        }
    }
}

fn client_nodes(client: &ClientConfig, depth: usize) -> io::Result<usize> {
    let mut nodes = 1usize;
    if let super::ClientProxyConfig::Wireguard(config) = &client.protocol
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
    if hops.iter().count() == 0 {
        return Err(invalid("chain cannot be empty"));
    }
    fn walk(hops: &OneOrSome<ClientChainHop>, mut offset: usize) -> io::Result<usize> {
        for hop in hops.iter() {
            let initial = offset == 0;
            if let ClientChainHop::Choice(choice) = hop {
                let mut end = offset;
                for member in &choice.members {
                    end = end.max(walk(&member.hops, offset)?);
                }
                offset = end;
            } else {
                for client in clients(hop) {
                    client.validate_quic_key_exchange(initial)?;
                    crate::quic_client::validate(client, initial)?;
                    if !initial {
                        if client.protocol.is_direct() {
                            return Err(invalid(format!(
                                "Direct connectors can only be used at hop 0, not hop {offset}"
                            )));
                        }
                        if client.protocol.is_wireguard() {
                            return Err(invalid("WireGuard is only supported at hop 0"));
                        }
                        if client.transport == super::Transport::Quic
                            && crate::xhttp::connector::contains(&client.protocol)
                        {
                            return Err(invalid("XHTTP H3 is only supported at hop 0"));
                        }
                    }
                }
                offset += 1;
            }
        }
        Ok(offset)
    }
    let mut nodes = 0usize;
    let mut longest = 0usize;
    let mut paths = 1usize;
    for hop in hops.iter() {
        let (count, length, branches) = measure(hop, 0)?;
        nodes = nodes.saturating_add(count);
        longest = longest.saturating_add(length);
        paths = paths.saturating_mul(branches);
    }
    if nodes > MAX_NODES || longest > MAX_HOPS {
        return Err(invalid("client composition exceeds 16384 nodes or 64 hops"));
    }
    fn automatic_count(hop: &ClientChainHop) -> usize {
        match hop {
            ClientChainHop::Choice(choice) => {
                usize::from(matches!(choice.group_type, GroupType::UrlTest(_)))
                    + choice
                        .members
                        .iter()
                        .flat_map(|chain| chain.hops.iter())
                        .map(automatic_count)
                        .sum::<usize>()
            }
            _ => 0,
        }
    }
    if hops.iter().map(automatic_count).sum::<usize>()
        > crate::control::url_test::context::MAX_CONTEXTS
    {
        return Err(crate::control::health::capacity_error(
            "URL-test exceeds 1024 route contexts".into(),
        ));
    }
    if hops.iter().flat_map(clients).any(|client| {
        client
            .control
            .as_ref()
            .is_some_and(crate::control::catalog::MemberOrigin::has_fallback)
    }) && paths > crate::control::health::MAX_PATHS
    {
        return Err(crate::control::health::capacity_error(
            "fallback exceeds 256 concrete chain paths".into(),
        ));
    }
    super::health::validate_composition(hops)?;
    walk(hops, 0).map(|_| ())
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
    use crate::config::{Config, RuleActionConfig, ValidatedConfigs, create_server_configs};
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
        let ConfigSelection::Config(rule) = server.rules.iter().next().unwrap() else {
            panic!()
        };
        let RuleActionConfig::Allow { client_chains, .. } = &rule.action else {
            panic!()
        };
        client_chains.iter().next().unwrap()
    }

    #[test]
    fn group_members_are_alternatives_not_an_implicit_sequence() {
        let base = json!([
            {"client_group":"a", "client_chains":[proxy("a-leaf")]},
            {"client_group":"b", "client_chains":[proxy("b-leaf")]},
            {"client_group":"out", "client_chains":["a","b"]},
            {"address":"127.0.0.1:0","protocol":{"type":"socks"},
             "rules":[{"mask":"0.0.0.0/0","action":"allow","client_chain":"out"}]}
        ]);
        let choices = validate(base.clone()).unwrap();
        let (_, hops, paths) = measure(route(&choices).hops.iter().next().unwrap(), 0).unwrap();
        assert_eq!((hops, paths), (1, 2));
        let mut sequential = base;
        sequential[2]["client_chains"] = json!([{"chain":["a","b"]}]);
        let sequential = validate(sequential).unwrap();
        let (_, hops, paths) = measure(route(&sequential).hops.iter().next().unwrap(), 0).unwrap();
        assert_eq!((hops, paths), (2, 1));
    }

    #[test]
    fn named_groups_compose_different_length_paths_without_crossing_branches() {
        let validated = validate(json!([
            {"client_group":"a1-selected","type":"selector","client_chains":[proxy("a1")]},
            {"client_group":"nl-hop","client_chains":[proxy("nl")]},
            {"client_group":"a1-selected-nl","client_chains":[{"chain":["a1-selected","nl-hop"]}]},
            {"client_group":"geo-reddit-selected","type":"selector","default":"a1-selected-nl",
             "client_chains":["a1-selected","a1-selected-nl","direct"]},
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
    fn group_chain_wrappers_are_strict_and_selector_labels_are_explicit() {
        for members in [
            json!([]),
            json!([["direct"]]),
            json!([{"chain":[]}]),
            json!([{"chain":["direct"],"typo":true}]),
            json!([{"chain":["direct"],"protocol":{"type":"direct"}}]),
            json!([{"chain":[{"pool":["direct"]}]}]),
            json!([{"chain":[{"chain":["direct"]}]}]),
        ] {
            assert!(
                validate(json!([{"client_group":"out","client_chains":members}])).is_err(),
                "{members}"
            );
        }
        assert!(validate(json!([{"client_group":"out","type":"selector","client_chains":[{"chain":["direct"]}]}])).is_err());
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
                {"client_group":"tail","client_chains":["direct",proxy("last")]},
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
                json!({"client_group":format!("g{index}"),"client_chains":[previous,previous]}),
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
        let mut groups =
            vec![json!({"client_group":"g0","type":"selector","client_chains":["direct"]})];
        for index in 1..80 {
            groups.push(json!({"client_group":format!("g{index}"),"client_chains":[format!("g{}",index-1)]}));
        }
        let validated = validate(json!(groups)).unwrap();
        let chain = validated.catalog.unwrap().route("g79").unwrap();
        super::validate(&chain.hops).unwrap();
        assert!(direct_only(&chain.hops));
    }

    #[test]
    fn automatic_occurrence_budget_is_checked_before_building_transports() {
        let members = vec!["auto"; crate::control::url_test::context::MAX_CONTEXTS + 1];
        let error = validate(json!([
            {"client_group":"auto","type":"url-test","url":"http://probe.invalid/","client_chains":["direct"]},
            {"client_group":"wide","client_chains":members}
        ])).err().unwrap();
        assert!(error.to_string().contains("1024 route contexts"), "{error}");
    }
}
