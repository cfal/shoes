use serde_json::{Value, json};
use std::collections::HashMap;
use std::io;

use crate::config::{ClientChain, ClientChainHop, ConfigSelection, GroupStrategy};
use crate::control::catalog::{Catalog, CatalogNode, protocol_type};
use crate::control::runtime::Generation;
use crate::control::selection::Choices;
use crate::option_util::OneOrSome;

pub fn capabilities(catalog: &Catalog) -> io::Result<HashMap<String, bool>> {
    let mut capabilities = HashMap::new();
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
        capabilities.insert(name.clone(), udp);
    }
    Ok(capabilities)
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
        _ => generation.udp.get(name).copied().unwrap_or(false),
    }
}

pub fn proxies(generation: &Generation, groups_only: bool) -> Value {
    let choices = generation.catalog.selection.snapshot();
    if groups_only {
        let groups: Vec<_> = generation
            .catalog
            .nodes
            .iter()
            .filter(|(_, node)| matches!(node, CatalogNode::Group { .. }))
            .map(|(name, _)| proxy(generation, &choices, name).unwrap())
            .collect();
        json!({"proxies": groups})
    } else {
        let nodes: serde_json::Map<_, _> = generation
            .catalog
            .nodes
            .keys()
            .map(|name| (name.clone(), proxy(generation, &choices, name).unwrap()))
            .collect();
        json!({"proxies":nodes})
    }
}
