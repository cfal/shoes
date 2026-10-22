use std::io;
use std::sync::Arc;

use indexmap::IndexMap;

use super::selection::{
    Choices, SelectionOwner, SelectionView, SelectorDefinition, SelectorDefinitions,
};
use super::store::valid_name;
use crate::config::{
    ClientChainHop, ClientConfig, ClientProxyConfig, Config, ConfigSelection, GroupStrategy,
    RuleActionConfig,
};

#[derive(Debug, Clone)]
pub struct MemberOrigin {
    pub name: Arc<str>,
    pub path: Vec<(String, String)>,
    pub selection: Arc<SelectionView>,
}

impl MemberOrigin {
    pub fn selector_path(&self) -> Vec<(String, String)> {
        self.path
            .iter()
            .filter(|(group, _)| self.selection.definitions().contains_key(group))
            .cloned()
            .collect()
    }
    pub fn allowed(&self, choices: &Choices) -> bool {
        self.path
            .iter()
            .all(|(group, member)| choices.get(group).is_none_or(|selected| selected == member))
    }

    pub fn chains(&self) -> impl Iterator<Item = String> + '_ {
        std::iter::once(self.name.to_string())
            .chain(self.path.iter().rev().map(|(group, _)| group.clone()))
    }
}

pub fn chain_selection_key(
    chains: &[crate::config::ClientChain],
) -> io::Result<Vec<Vec<(String, String)>>> {
    let mut key = Vec::new();
    for chain in chains {
        for mut hop in chain.hops.iter().cloned() {
            crate::config::client_visit::visit_hop(&mut hop, &mut |client| {
                key.push(
                    client
                        .control
                        .as_ref()
                        .map(MemberOrigin::selector_path)
                        .unwrap_or_default(),
                );
                Ok(())
            })?;
        }
    }
    Ok(key)
}

#[derive(Debug, Clone)]
pub struct RuleDescription {
    pub payload: String,
    pub proxy: String,
    pub context: Option<Arc<super::flows::FlowContext>>,
}

#[derive(Debug, Clone)]
pub enum CatalogNode {
    Group {
        members: Vec<String>,
        strategy: GroupStrategy,
    },
    Leaf(Box<ClientConfig>),
    Reject,
}

#[derive(Debug)]
pub struct Catalog {
    pub nodes: IndexMap<String, CatalogNode>,
    pub selection: Arc<SelectionView>,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

pub fn api_group(name: &str) -> &str {
    if name == "direct" { "DIRECT" } else { name }
}

fn member_name(member: &ConfigSelection<ClientConfig>) -> String {
    match member {
        ConfigSelection::GroupName(name) => api_group(name).to_owned(),
        ConfigSelection::Config(client) => client
            .control
            .as_ref()
            .map(|c| c.name.to_string())
            .unwrap_or_else(|| "DIRECT".into()),
    }
}

pub fn bounded(mut value: String) -> String {
    if value.len() > 4096 {
        let mut end = 4093;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
        value.push_str("...");
    }
    value
}

fn rule_target(action: &RuleActionConfig) -> String {
    let RuleActionConfig::Allow { client_chains, .. } = action else {
        return "REJECT".into();
    };
    if client_chains.is_empty() {
        return "DIRECT".into();
    }
    let chains: Vec<_> = client_chains
        .iter()
        .map(|chain| {
            let hops: Vec<_> = chain
                .hops
                .iter()
                .map(|hop| match hop {
                    ClientChainHop::Single(member) => member_name(member),
                    ClientChainHop::Pool(members) => format!(
                        "pool[{}]",
                        members
                            .iter()
                            .map(member_name)
                            .collect::<Vec<_>>()
                            .join(" | ")
                    ),
                })
                .collect();
            if hops.len() == 1 {
                hops[0].clone()
            } else {
                format!("chain[{}]", hops.join(" -> "))
            }
        })
        .collect();
    bounded(if chains.len() == 1 {
        chains[0].clone()
    } else {
        format!("routes[{}]", chains.join(" | "))
    })
}

impl Catalog {
    pub fn capture(configs: &mut [Config]) -> io::Result<Option<Self>> {
        for config in configs.iter() {
            if let Config::ClientConfigGroup(group) = config
                && group.strategy != GroupStrategy::Selector
                && group.default.is_some()
            {
                return Err(invalid("default is only valid for selector groups"));
            }
        }
        let enabled = configs.iter().any(|config| matches!(config, Config::ClashApi(_) | Config::CacheFile(_)) || matches!(config, Config::ClientConfigGroup(g) if g.strategy == GroupStrategy::Selector));
        if !enabled {
            return Ok(None);
        }
        let empty = SelectionOwner::new(None)?.prepare(SelectorDefinitions::new())?;
        let mut nodes = IndexMap::new();
        nodes.insert("DIRECT".into(), CatalogNode::Leaf(Box::default()));
        nodes.insert("REJECT".into(), CatalogNode::Reject);
        let mut names = std::collections::HashSet::from([
            "DIRECT".to_owned(),
            "REJECT".to_owned(),
            "GLOBAL".to_owned(),
        ]);
        let mut claim = |name: &str| -> io::Result<()> {
            if !valid_name(name) || !names.insert(name.to_owned()) {
                return Err(invalid(format!(
                    "invalid or duplicate control name: {name}"
                )));
            }
            Ok(())
        };
        for (index, config) in configs.iter_mut().enumerate() {
            match config {
                Config::ClientConfigGroup(group) => {
                    claim(&group.client_group)?;
                    nodes.insert(
                        group.client_group.clone(),
                        CatalogNode::Group {
                            members: Vec::new(),
                            strategy: group.strategy,
                        },
                    );
                }
                Config::Server(server) => {
                    let name = server
                        .name
                        .get_or_insert_with(|| format!("inbound-{}", index + 1));
                    claim(name)?;
                }
                Config::TunServer(tun) => {
                    let name = tun.name.get_or_insert_with(|| format!("tun-{}", index + 1));
                    claim(name)?;
                }
                _ => {}
            }
            let mut ordinal = 0;
            crate::config::client_visit::visit_configs(
                std::slice::from_mut(config),
                &mut |client| {
                    ordinal += 1;
                    let name = client.name.clone().unwrap_or_else(|| {
                        if client.protocol.is_direct()
                            && client.address.is_unspecified()
                            && client.bind_interface.is_unspecified()
                        {
                            "DIRECT".into()
                        } else {
                            format!("client-{}-{ordinal}", index + 1)
                        }
                    });
                    if name != "DIRECT" || client.name.is_some() {
                        claim(&name)?;
                    }
                    client.control = Some(MemberOrigin {
                        name: Arc::from(name.as_str()),
                        path: Vec::new(),
                        selection: empty.clone(),
                    });
                    if name != "DIRECT" {
                        nodes.insert(name, CatalogNode::Leaf(Box::new(client.clone())));
                    }
                    Ok(())
                },
            )?;
        }
        let mut definitions = SelectorDefinitions::new();
        for config in configs.iter() {
            if let Config::ClientConfigGroup(group) = config {
                let members: Vec<_> = group.client_proxies.iter().map(member_name).collect();
                if group.strategy == GroupStrategy::Selector {
                    if group.client_proxies.iter().any(|member| matches!(member, ConfigSelection::Config(client) if client.name.is_none())) {
                        return Err(invalid("inline selector members require explicit names"));
                    }
                    definitions.insert(
                        group.client_group.clone(),
                        SelectorDefinition {
                            members: members.clone(),
                            default: group.default.clone(),
                        },
                    );
                } else if group.default.is_some() {
                    return Err(invalid("default is only valid for selector groups"));
                }
                nodes.insert(
                    group.client_group.clone(),
                    CatalogNode::Group {
                        members,
                        strategy: group.strategy,
                    },
                );
            }
        }
        let selection = SelectionOwner::new(None)?.prepare(definitions)?;
        crate::config::client_visit::visit_configs(configs, &mut |client| {
            if let Some(origin) = &mut client.control {
                origin.selection = selection.clone();
            }
            Ok(())
        })?;
        crate::config::rule_visit::visit(
            configs,
            &mut |rule| {
                let payload = bounded(
                    serde_json::to_string(&rule.criteria.expression).map_err(io::Error::other)?,
                );
                rule.criteria.description = Some(Arc::new(RuleDescription {
                    payload,
                    proxy: rule_target(&rule.action),
                    context: None,
                }));
                Ok(())
            },
            &mut |_| Ok(()),
        )?;
        if nodes.len() > 16_384 {
            return Err(invalid("control catalog exceeds 16384 nodes"));
        }
        Ok(Some(Self { nodes, selection }))
    }

    pub fn update_client(&mut self, client: &ClientConfig) {
        if let Some(origin) = &client.control
            && let Some(CatalogNode::Leaf(config)) = self.nodes.get_mut(origin.name.as_ref())
        {
            **config = client.clone();
            if let Some(origin) = &mut config.control {
                origin.path.clear();
            }
        }
    }
}

pub fn protocol_type(protocol: &ClientProxyConfig) -> &str {
    match protocol {
        ClientProxyConfig::Tls(config) => protocol_type(&config.protocol),
        ClientProxyConfig::Reality { protocol, .. }
        | ClientProxyConfig::ShadowTls { protocol, .. } => protocol_type(protocol),
        ClientProxyConfig::Websocket(config) => protocol_type(&config.protocol),
        ClientProxyConfig::Xhttp(config) => protocol_type(&config.protocol),
        ClientProxyConfig::Socks { .. } => "Socks5",
        ClientProxyConfig::Vless { .. } => "VLESS",
        ClientProxyConfig::Vmess { .. } => "Vmess",
        other => other.protocol_name(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = "
- client_group: child
  client_proxies:
    - name: east
      address: east.example:1080
      protocol: {type: socks}
    - name: west
      address: west.example:1080
      protocol: {type: socks}
- client_group: outbound
  strategy: selector
  default: child
  client_proxies: [child, direct]
- address: 127.0.0.1:1080
  name: inbound
  protocol: {type: socks}
  rules: [{mask: 0.0.0.0/0, action: allow, client_chain: outbound}]
";

    #[test]
    fn flattening_retains_definition_identity_and_every_group_branch() {
        let validated =
            crate::config::create_server_configs(serde_yaml::from_str(CONFIG).unwrap()).unwrap();
        let catalog = validated.catalog.as_ref().unwrap();
        let Config::Server(server) = &validated.configs[0] else {
            panic!()
        };
        let ConfigSelection::Config(rule) = server.rules.iter().next().unwrap() else {
            panic!()
        };
        assert_eq!(
            rule.criteria.description.as_ref().unwrap().proxy,
            "outbound"
        );
        let RuleActionConfig::Allow { client_chains, .. } = &rule.action else {
            panic!()
        };
        let ClientChainHop::Pool(pool) = client_chains
            .iter()
            .next()
            .unwrap()
            .hops
            .iter()
            .next()
            .unwrap()
        else {
            panic!()
        };
        let origins: Vec<_> = pool
            .iter()
            .map(|member| {
                let ConfigSelection::Config(client) = member else {
                    panic!()
                };
                client.control.as_ref().unwrap()
            })
            .collect();
        assert_eq!(
            origins.iter().map(|o| o.name.as_ref()).collect::<Vec<_>>(),
            ["east", "west", "DIRECT"]
        );
        assert_eq!(
            origins[0].path,
            [
                ("outbound".into(), "child".into()),
                ("child".into(), "east".into())
            ]
        );
        assert!(origins[0].allowed(&catalog.selection.snapshot()));
        assert!(!origins[2].allowed(&catalog.selection.snapshot()));
        let mut owner = SelectionOwner::new(None).unwrap();
        owner.activate(catalog.selection.clone()).unwrap();
        owner.select("outbound", "DIRECT").unwrap();
        assert!(!origins[0].allowed(&catalog.selection.snapshot()));
        assert!(origins[2].allowed(&catalog.selection.snapshot()));
    }

    #[test]
    fn names_are_not_connector_identity_and_anonymous_ids_are_repeatable() {
        let mut client: ClientConfig =
            serde_yaml::from_str("name: east\naddress: host:1080\nprotocol: {type: socks}")
                .unwrap();
        let before = serde_yaml::to_string(&client).unwrap();
        client.name = Some("west".into());
        assert_eq!(serde_yaml::to_string(&client).unwrap(), before);
        let yaml = CONFIG.replace("name: east", "").replace("name: west", "");
        let capture = || {
            crate::config::create_server_configs(serde_yaml::from_str(&yaml).unwrap())
                .unwrap()
                .catalog
                .unwrap()
                .nodes
                .keys()
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(capture(), capture());
    }

    #[test]
    fn rejects_ambiguous_selectors_and_reserved_or_duplicate_names() {
        for yaml in [
            CONFIG.replace("default: child", "default: missing"),
            CONFIG.replace("[child, direct]", "[child, child]"),
            CONFIG.replace("name: west", "name: east"),
            CONFIG.replace("name: west", "name: GLOBAL"),
            CONFIG.replace("strategy: selector", "strategy: round-robin"),
            CONFIG.replace("[child, direct]", "[{protocol: {type: direct}}]"),
        ] {
            assert!(
                crate::config::create_server_configs(serde_yaml::from_str(&yaml).unwrap()).is_err()
            );
        }
    }
}
