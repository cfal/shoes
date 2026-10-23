use serde_json::{Value, json};
use std::collections::HashMap;
use std::io;

use crate::config::{ClientChain, ClientChainHop, ConfigSelection, GroupStrategy};
use crate::control::catalog::{Catalog, CatalogNode, protocol_type};
use crate::control::runtime::Generation;
use crate::control::selection::Choices;
use crate::option_util::OneOrSome;

pub fn leaf_udp_support(catalog: &Catalog) -> io::Result<HashMap<String, bool>> {
    let mut support = HashMap::new();
    for (name, node) in &catalog.nodes {
        let CatalogNode::Leaf(client) = node else {
            continue;
        };
        let chain = ClientChain {
            hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                (**client).clone(),
            ))),
        };
        let udp = crate::tcp::chain_builder::supports_udp_offline(&chain)?;
        support.insert(name.clone(), udp);
    }
    Ok(support)
}

pub fn proxy(generation: &Generation, choices: &Choices, name: &str) -> Option<Value> {
    let node = generation.catalog.nodes.get(name)?;
    let udp = supports_udp(generation, choices, name, 0);
    let mut value = match node {
        CatalogNode::Leaf(client) => {
            json!({"name":name,"type":protocol_type(&client.protocol),"udp":udp})
        }
        CatalogNode::Reject => json!({"name":name,"type":"Reject","udp":false}),
        CatalogNode::Group { members, strategy } => {
            let proxy_type = match strategy {
                GroupStrategy::Selector => "Selector",
                GroupStrategy::RoundRobin => "LoadBalance",
            };
            let mut value = json!({
                "name": name,
                "type": proxy_type,
                "all": members,
                "udp": udp,
            });
            if let Some(selected) = choices.get(name) {
                value["now"] = json!(selected);
            }
            value
        }
    };
    generation.probes.decorate(name, &mut value);
    Some(value)
}

fn supports_udp(generation: &Generation, choices: &Choices, name: &str, depth: usize) -> bool {
    if depth > 128 {
        return false;
    }
    match generation.catalog.nodes.get(name) {
        Some(CatalogNode::Group { members, strategy }) => {
            if *strategy == GroupStrategy::Selector {
                choices
                    .get(name)
                    .is_some_and(|name| supports_udp(generation, choices, name, depth + 1))
            } else {
                members
                    .iter()
                    .any(|name| supports_udp(generation, choices, name, depth + 1))
            }
        }
        _ => generation
            .leaf_udp_support
            .get(name)
            .copied()
            .unwrap_or(false),
    }
}

pub fn proxies(generation: &Generation) -> Value {
    let choices = generation.catalog.selection.snapshot();
    let nodes: serde_json::Map<_, _> = generation
        .catalog
        .nodes
        .keys()
        .map(|name| (name.clone(), proxy(generation, &choices, name).unwrap()))
        .collect();
    json!({"proxies":nodes})
}

pub fn groups(generation: &Generation) -> Value {
    let choices = generation.catalog.selection.snapshot();
    let groups: Vec<_> = generation
        .catalog
        .nodes
        .iter()
        .filter(|(_, node)| matches!(node, CatalogNode::Group { .. }))
        .map(|(name, _)| proxy(generation, &choices, name).unwrap())
        .collect();
    json!({"proxies": groups})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::selection::SelectionOwner;
    use std::sync::Arc;

    #[test]
    fn catalog_dtos_preserve_group_types_members_and_selected_udp_support() {
        let configs = serde_json::from_value(json!([
            {"client_group":"child", "client_proxies":[
                {"name":"east", "address":"east.invalid:1080", "protocol":{"type":"socks"}},
                "direct"
            ]},
            {"client_group":"outbound", "strategy":"selector", "default":"child", "client_proxies":[
                "child",
                {"name":"west", "address":"west.invalid:1080", "protocol":{"type":"socks"}}
            ]}
        ]))
        .unwrap();
        let catalog = crate::config::create_server_configs(configs)
            .unwrap()
            .catalog
            .unwrap();
        let generation = Generation {
            id: 1,
            leaf_udp_support: leaf_udp_support(&catalog).unwrap(),
            catalog,
            rules: Vec::new(),
            probes: super::super::probes::ProbeState::new(
                Arc::new(crate::resolver::NativeResolver::new()),
                Vec::new(),
            ),
        };
        let mut owner = SelectionOwner::new(None).unwrap();
        owner
            .activate(generation.catalog.selection.clone())
            .unwrap();
        let nodes = proxies(&generation);
        for (name, kind, udp) in [
            ("DIRECT", "Direct", true),
            ("REJECT", "Reject", false),
            ("east", "Socks5", false),
            ("west", "Socks5", false),
        ] {
            assert_eq!(
                nodes["proxies"][name],
                json!({"name":name, "type":kind, "udp":udp, "alive":true, "history":[]})
            );
        }
        assert_eq!(
            nodes["proxies"]["child"],
            json!({"name":"child", "type":"LoadBalance", "all":["east","DIRECT"], "udp":true, "alive":true, "history":[]})
        );
        assert_eq!(
            nodes["proxies"]["outbound"],
            json!({"name":"outbound", "type":"Selector", "all":["child","west"], "now":"child", "udp":true, "alive":true, "history":[]})
        );
        assert_eq!(
            groups(&generation),
            json!({"proxies":[nodes["proxies"]["child"], nodes["proxies"]["outbound"]]})
        );
        assert!(
            proxy(
                &generation,
                &generation.catalog.selection.snapshot(),
                "missing"
            )
            .is_none()
        );
        owner.select("outbound", "west").unwrap();
        let selected = proxies(&generation);
        assert_eq!(selected["proxies"]["outbound"]["now"], "west");
        assert_eq!(selected["proxies"]["outbound"]["udp"], false);
        assert_eq!(selected["proxies"]["child"], nodes["proxies"]["child"]);
        assert_eq!(
            groups(&generation)["proxies"][1],
            selected["proxies"]["outbound"]
        );
    }
}
