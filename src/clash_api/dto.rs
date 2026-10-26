use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::io;

use crate::config::{ClientChain, ClientChainHop, ConfigSelection, GroupType};
use crate::control::catalog::{Catalog, CatalogNode, protocol_type};
use crate::control::runtime::Generation;
use crate::control::selection::Choices;
use crate::control::url_test::AutomaticGroup;
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
    let udp = supports_udp(generation, choices, name);
    let mut value = match node {
        CatalogNode::Leaf(client) => {
            json!({"name":name,"type":protocol_type(&client.protocol),"udp":udp})
        }
        CatalogNode::Reject => json!({"name":name,"type":"Reject","udp":false}),
        CatalogNode::Group {
            members,
            group_type,
        } => {
            let proxy_type = match group_type {
                GroupType::Selector => "Selector",
                GroupType::RoundRobin => "LoadBalance",
                GroupType::UrlTest(_) => "URLTest",
                GroupType::Fallback { .. } => "Fallback",
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
    if let Some(group) = generation.catalog.selection.automatic.0.get(name) {
        let selected = automatic_member(generation, choices, group, false)?;
        let health = group.health(&selected);
        value["now"] = json!(selected);
        value["udpNow"] = json!(automatic_member(generation, choices, group, true));
        value["testUrl"] = json!(group.config.url);
        value["health"] = json!(health);
        value["alive"] = json!(health == "healthy");
        value["history"] = generation.probes.url_history(&selected, &group.config.url);
    }
    Some(value)
}

fn automatic_member(
    generation: &Generation,
    choices: &Choices,
    group: &AutomaticGroup,
    udp: bool,
) -> Option<String> {
    let eligible = group
        .members
        .iter()
        .filter(|name| !udp || supports_udp(generation, choices, name))
        .map(String::as_str)
        .collect();
    group.choose(&eligible, udp)
}

fn supports_udp(generation: &Generation, choices: &Choices, name: &str) -> bool {
    let mut pending = vec![name];
    let mut visited = HashSet::new();
    while let Some(name) = pending.pop() {
        if !visited.insert(name) {
            continue;
        }
        match generation.catalog.nodes.get(name) {
            Some(CatalogNode::Group {
                members,
                group_type,
            }) => {
                if *group_type == GroupType::Selector {
                    if let Some(selected) = choices.get(name) {
                        pending.push(selected);
                    }
                } else {
                    pending.extend(members.iter().map(String::as_str));
                }
            }
            _ if generation
                .leaf_udp_support
                .get(name)
                .copied()
                .unwrap_or(false) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
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
    fn health_review9_fallback_dto_is_not_a_manual_selector() {
        let configs = serde_json::from_value(json!([
            {"client_group":"out", "type":"fallback", "health_check":{"url":"http://probe.invalid/", "interval_secs":30},
             "client_proxies":[{"name":"tcp", "address":"proxy.invalid:80", "protocol":{"type":"http"}}, "direct"]}
        ])).unwrap();
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
        let before = proxies(&generation)["proxies"]["out"].clone();
        assert_eq!(before["type"], "Fallback");
        assert_eq!(before["all"], json!(["tcp", "DIRECT"]));
        assert_eq!(before["udp"], true);
        assert!(before.get("now").is_none());
        assert!(owner.select("out", "DIRECT").is_err());
        assert_eq!(proxies(&generation)["proxies"]["out"], before);
    }

    #[test]
    fn url_test_dto_reports_transport_eligible_members_and_url_health() {
        let configs = serde_json::from_value(json!([
            {"client_group":"manual", "type":"selector", "default":"tcp", "client_proxies":[
                "direct", {"name":"tcp", "address":"proxy.invalid:80", "protocol":{"type":"http"}}
            ]},
            {"client_group":"auto", "type":"url-test", "url":"http://probe.invalid/", "client_proxies":[
                "manual", {"name":"udp", "protocol":{"type":"direct"}}
            ]}
        ])).unwrap();
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
        let node = proxies(&generation)["proxies"]["auto"].clone();
        assert_eq!(node["now"], "manual");
        assert_eq!(node["udpNow"], "udp");
        assert_eq!(node["health"], "unprobed");
        assert_eq!(node["alive"], false);
        let automatic = &generation.catalog.selection.automatic;
        automatic.record("manual", "http://probe.invalid/", Some(5));
        automatic.record("udp", "http://probe.invalid/", Some(100));
        let node = proxies(&generation)["proxies"]["auto"].clone();
        assert_eq!(node["type"], "URLTest");
        assert_eq!(node["now"], "manual");
        assert_eq!(node["udpNow"], "udp");
        assert_eq!(node["udp"], true);
        assert_eq!(node["health"], "healthy");
        owner.select("manual", "DIRECT").unwrap();
        assert_eq!(proxies(&generation)["proxies"]["auto"]["udpNow"], "manual");
    }

    #[test]
    fn catalog_dtos_preserve_group_types_members_and_selected_udp_support() {
        let configs = serde_json::from_value(json!([
            {"client_group":"child", "client_proxies":[
                {"name":"east", "address":"east.invalid:1080", "protocol":{"type":"socks"}},
                "direct"
            ]},
            {"client_group":"outbound", "type":"selector", "default":"child", "client_proxies":[
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
