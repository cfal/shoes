use std::io;
use std::sync::Arc;

use indexmap::IndexMap;

use super::selection::{
    Choices, SelectionOwner, SelectionView, SelectorDefinition, SelectorDefinitions,
};
use super::store::valid_name;
use crate::config::{
    ClientChainHop, ClientConfig, ClientProxyConfig, Config, ConfigSelection, GroupType,
    RuleActionConfig,
};

#[derive(Debug, Clone)]
pub struct MemberOrigin {
    pub name: Arc<str>,
    pub path: Vec<(String, String)>,
    pub selection: Arc<SelectionView>,
}

impl MemberOrigin {
    fn manages(&self, group: &str) -> bool {
        self.selection.definitions().contains_key(group)
            || self.selection.automatic.0.contains_key(group)
    }

    pub fn has_selector(&self) -> bool {
        self.path.iter().any(|(group, _)| self.manages(group))
    }

    pub fn selector_path(&self) -> Vec<(String, String)> {
        self.path
            .iter()
            .filter(|(group, _)| self.manages(group))
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
        group_type: GroupType,
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
        value.truncate(value.floor_char_boundary(4093));
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
                && group.group_type != GroupType::Selector
                && group.default.is_some()
            {
                return Err(invalid("default is only valid for selector groups"));
            }
        }
        let enabled = configs.iter().any(|config| match config {
            Config::ClashApi(_) | Config::CacheFile(_) => true,
            Config::ClientConfigGroup(group) => group.group_type != GroupType::RoundRobin,
            _ => false,
        });
        if !enabled {
            return Ok(None);
        }
        let empty = Arc::<SelectionView>::default();
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
                    // Reserve source order before populating members in the second pass.
                    nodes.insert(
                        group.client_group.clone(),
                        CatalogNode::Group {
                            members: Vec::new(),
                            group_type: group.group_type.clone(),
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
        let mut automatic = super::url_test::AutomaticGroups::default();
        for config in configs.iter() {
            if let Config::ClientConfigGroup(group) = config {
                let members: Vec<_> = group.client_proxies.iter().map(member_name).collect();
                if group.group_type == GroupType::Selector {
                    let has_unnamed_member = group.client_proxies.iter().any(|member| {
                        matches!(member, ConfigSelection::Config(client) if client.name.is_none())
                    });
                    if has_unnamed_member {
                        return Err(invalid("inline selector members require explicit names"));
                    }
                    definitions.insert(
                        group.client_group.clone(),
                        SelectorDefinition {
                            members: members.clone(),
                            default: group.default.as_ref().map(|name| {
                                if members.contains(name) {
                                    name.clone()
                                } else {
                                    api_group(name).to_owned()
                                }
                            }),
                        },
                    );
                }
                if let GroupType::UrlTest(config) = &group.group_type {
                    automatic.insert(
                        group.client_group.clone(),
                        config.clone(),
                        members.clone(),
                    )?;
                }
                nodes.insert(
                    group.client_group.clone(),
                    CatalogNode::Group {
                        members,
                        group_type: group.group_type.clone(),
                    },
                );
            }
        }
        let mut selection = SelectionOwner::new(None)?.prepare(definitions)?;
        Arc::get_mut(&mut selection).unwrap().automatic = automatic;
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

    #[cfg(unix)]
    #[test]
    fn unused_catalog_leaves_are_normalized_without_activating_wireguard() {
        use base64::Engine;
        use serde_json::json;

        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = certificate.cert.pem();
        let key = certificate.signing_key.serialize_pem();
        for nested in [false, true] {
            for named_pems in [false, true] {
                let mut client = json!({
                    "name":"unused-tls", "address":"localhost:443",
                    "protocol":{"type":"tls", "server_fingerprints":"any",
                        "protocol":{"type":"vless", "user_id":"b85798ef-e9dc-46a4-9a87-8da4499d36d0"}}
                });
                if named_pems {
                    client["protocol"]["cert"] = json!("client-cert");
                    client["protocol"]["key"] = json!("client-key");
                }
                let definition = if nested {
                    json!({"client_group":"unused", "client_proxies":{
                        "name":"unused-wireguard", "address":"192.0.2.1:51820",
                        "protocol":{"type":"wireguard",
                            "private_key":base64::engine::general_purpose::STANDARD.encode([42;32]),
                            "public_key":base64::engine::general_purpose::STANDARD.encode([43;32]),
                            "addresses":["10.77.0.2/32"], "peer_client_chain":[client]}
                    }})
                } else {
                    json!({"rule_group":"unused", "rules":[{
                        "mask":"0.0.0.0/0", "action":"allow", "client_chain":[client]
                    }]})
                };
                let configs = serde_yaml::from_str(
                    &json!([
                        {"clash_api_address":"127.0.0.1:0", "secret":"test"},
                        {"pem":"client-cert", "data":cert},
                        {"pem":"client-key", "data":key},
                        definition
                    ])
                    .to_string(),
                )
                .unwrap();
                let validated = crate::config::create_server_configs(configs).unwrap();
                assert!(validated.wireguard_endpoints.is_empty());
                let catalog = validated.catalog.unwrap();
                crate::clash_api::dto::leaf_udp_support(&catalog).unwrap_or_else(|error| {
                    panic!("nested={nested}, named_pems={named_pems}: {error}")
                });
                let CatalogNode::Leaf(client) = &catalog.nodes["unused-tls"] else {
                    panic!()
                };
                let ClientProxyConfig::Tls(tls) = &client.protocol else {
                    panic!()
                };
                assert!(tls.server_fingerprints.is_unspecified());
                if named_pems {
                    assert_eq!(tls.cert.as_deref(), Some(cert.as_str()));
                    assert_eq!(tls.key.as_deref(), Some(key.as_str()));
                }
            }
        }
    }

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
  type: selector
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
    fn selector_default_uses_declared_direct_name() {
        let yaml = CONFIG.replace("default: child", "default: direct");
        for (yaml, expected) in [
            (yaml.clone(), "DIRECT"),
            (
                yaml.replace(
                    "[child, direct]",
                    "[child, {name: direct, protocol: {type: direct}}]",
                ),
                "direct",
            ),
        ] {
            let validated =
                crate::config::create_server_configs(serde_yaml::from_str(&yaml).unwrap()).unwrap();
            assert_eq!(
                validated.catalog.unwrap().selection.snapshot()["outbound"],
                expected
            );
        }
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
            CONFIG.replace("type: selector", "type: round-robin"),
            CONFIG.replace("[child, direct]", "[{protocol: {type: direct}}]"),
        ] {
            let configs = serde_yaml::from_str(&yaml);
            assert!(
                configs.is_err() || crate::config::create_server_configs(configs.unwrap()).is_err()
            );
        }
    }
}
