use serde_json::{Value, json};
use std::collections::HashMap;
use std::io;

use crate::config::{ClientChain, ClientChainHop, ConfigSelection, GroupStrategy};
use crate::control::catalog::{Catalog, CatalogNode, protocol_type};
use crate::control::runtime::Generation;
use crate::control::selection::Choices;
use crate::option_util::OneOrSome;

pub fn capabilities(catalog: &Catalog) -> io::Result<HashMap<String, bool>> {
    catalog
        .nodes
        .iter()
        .filter_map(|(name, node)| {
            if let CatalogNode::Leaf(client) = node {
                Some(
                    crate::tcp::chain_builder::supports_udp_offline(&ClientChain {
                        hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                            (**client).clone(),
                        ))),
                    })
                    .map(|udp| (name.clone(), udp)),
                )
            } else {
                None
            }
        })
        .collect()
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
            let mut value = json!({"name":name,"type":if *strategy == GroupStrategy::Selector { "Selector" } else { "LoadBalance" },"all":members,"udp":udp});
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
        json!({"proxies":generation.catalog.nodes.iter().filter(|(_,node)| matches!(node,CatalogNode::Group { .. })).map(|(name,_)| proxy(generation,&choices,name).unwrap()).collect::<Vec<_>>()})
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
