use std::io;
use std::sync::Arc;

use super::catalog::RuleDescription;
use super::flows::{FlowContext, FlowRegistry};
use crate::config::client_visit::sorted_targets;
use crate::config::{Config, ConfigSelection, RuleConfig, ServerProxyConfig, ValidatedConfigs};
use crate::option_util::NoneOrSome;

struct Builder {
    registry: Option<Arc<FlowRegistry>>,
    generation: u64,
    rules: Vec<serde_json::Value>,
}

impl Builder {
    fn project_rules(
        &mut self,
        rules: &mut NoneOrSome<ConfigSelection<RuleConfig>>,
        inbound: &str,
        scope: &str,
        protocol: &str,
    ) {
        for selected in rules.iter_mut() {
            let ConfigSelection::Config(rule) = selected else {
                continue;
            };
            let mut description = rule
                .criteria
                .description
                .as_deref()
                .cloned()
                .unwrap_or_else(|| RuleDescription {
                    payload: "match all".into(),
                    proxy: if matches!(rule.action, crate::config::RuleActionConfig::Block) {
                        "REJECT"
                    } else {
                        "DIRECT"
                    }
                    .into(),
                    context: None,
                });
            if let Some(registry) = &self.registry {
                description.context = Some(Arc::new(FlowContext {
                    registry: registry.clone(),
                    generation: self.generation,
                    inbound: inbound.into(),
                    scope: scope.into(),
                    protocol: protocol.into(),
                }));
            }
            self.rules.push(serde_json::json!({
                "index": self.rules.len(),
                "type": "Shoes",
                "payload": format!("{inbound} ({scope}): {}", description.payload),
                "proxy": description.proxy,
                "size": -1,
                "shoes": {"inbound": inbound, "scope": scope},
            }));
            rule.criteria.description = Some(Arc::new(description));
        }
    }

    fn project_target(
        &mut self,
        rules: &mut NoneOrSome<ConfigSelection<RuleConfig>>,
        protocol: &mut ServerProxyConfig,
        inherited: &NoneOrSome<ConfigSelection<RuleConfig>>,
        inbound: &str,
        scope: &str,
    ) {
        if rules.is_empty() {
            // Project inherited contexts without rebuilding shared routing pools or counters.
            let mut effective = inherited.clone();
            let first = self.rules.len();
            self.project_rules(&mut effective, inbound, scope, inbound_type(protocol));
            for rule in &mut self.rules[first..] {
                rule["shoes"]["inherited"] = serde_json::json!(true);
            }
            self.project_protocol(protocol, inbound, scope, &effective);
        } else {
            self.project_rules(rules, inbound, scope, inbound_type(protocol));
            self.project_protocol(protocol, inbound, scope, rules);
        }
    }

    fn project_protocol(
        &mut self,
        protocol: &mut ServerProxyConfig,
        inbound: &str,
        scope: &str,
        inherited: &NoneOrSome<ConfigSelection<RuleConfig>>,
    ) {
        match protocol {
            ServerProxyConfig::Tls {
                tls_targets,
                default_tls_target,
                shadowtls_targets,
                reality_targets,
                ..
            } => {
                for (key, target) in sorted_targets(tls_targets) {
                    let scope = format!("{scope}/tls/{key}");
                    self.project_target(
                        &mut target.override_rules,
                        &mut target.protocol,
                        inherited,
                        inbound,
                        &scope,
                    );
                }
                if let Some(target) = default_tls_target {
                    let scope = format!("{scope}/tls/default");
                    self.project_target(
                        &mut target.override_rules,
                        &mut target.protocol,
                        inherited,
                        inbound,
                        &scope,
                    );
                }
                for (key, target) in sorted_targets(shadowtls_targets) {
                    let scope = format!("{scope}/shadowtls/{key}");
                    self.project_target(
                        &mut target.override_rules,
                        &mut target.protocol,
                        inherited,
                        inbound,
                        &scope,
                    );
                }
                for (key, target) in sorted_targets(reality_targets) {
                    let scope = format!("{scope}/reality/{key}");
                    self.project_target(
                        &mut target.override_rules,
                        &mut target.protocol,
                        inherited,
                        inbound,
                        &scope,
                    );
                }
            }
            ServerProxyConfig::Websocket { targets } => {
                for (index, target) in targets.iter_mut().enumerate() {
                    let scope = format!("{scope}/websocket/{index}");
                    self.project_target(
                        &mut target.override_rules,
                        &mut target.protocol,
                        inherited,
                        inbound,
                        &scope,
                    );
                }
            }
            ServerProxyConfig::Xhttp(config) => self.project_target(
                &mut NoneOrSome::None,
                &mut config.protocol,
                inherited,
                inbound,
                &format!("{scope}/xhttp"),
            ),
            _ => {}
        }
    }
}

pub fn inbound_type(protocol: &ServerProxyConfig) -> &'static str {
    match protocol {
        ServerProxyConfig::Socks { .. } => "Socks5",
        ServerProxyConfig::Http { .. } => "HTTP",
        ServerProxyConfig::Vless { .. } => "VLESS",
        ServerProxyConfig::Vmess { .. } => "Vmess",
        ServerProxyConfig::Shadowsocks { .. } => "Shadowsocks",
        ServerProxyConfig::Snell { .. } => "Snell",
        ServerProxyConfig::Trojan { .. } => "Trojan",
        ServerProxyConfig::Anytls { .. } => "AnyTLS",
        ServerProxyConfig::Wireguard(_) => "WireGuard",
        ServerProxyConfig::Tls { .. } => "TLS",
        ServerProxyConfig::Websocket { .. } => "WebSocket",
        ServerProxyConfig::Xhttp(_) => "XHTTP",
        _ => "Shoes",
    }
}

pub fn attach(
    validated: &mut ValidatedConfigs,
    generation: u64,
    registry: Option<Arc<FlowRegistry>>,
) -> io::Result<Vec<serde_json::Value>> {
    let mut builder = Builder {
        registry,
        generation,
        rules: Vec::new(),
    };
    for (index, config) in validated.configs.iter_mut().enumerate() {
        match config {
            Config::Server(server) => {
                let inbound = server
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("inbound-{index}"));
                builder.project_rules(
                    &mut server.rules,
                    &inbound,
                    "root",
                    inbound_type(&server.protocol),
                );
                builder.project_protocol(&mut server.protocol, &inbound, "root", &server.rules);
            }
            Config::TunServer(tun) => {
                let inbound = tun.name.clone().unwrap_or_else(|| format!("tun-{index}"));
                builder.project_rules(&mut tun.rules, &inbound, "root", "Tun");
            }
            _ => {}
        }
    }
    for endpoint in &mut validated.wireguard_endpoints {
        if let Some(inbound) = &mut endpoint.inbound {
            builder.project_rules(
                &mut inbound.rules,
                inbound.name.as_deref().unwrap_or(&endpoint.id),
                "wireguard",
                "WireGuard",
            );
        }
    }
    if serde_json::to_vec(&builder.rules)
        .map_err(io::Error::other)?
        .len()
        > 32 * 1024 * 1024
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "rule catalog exceeds 32 MiB",
        ));
    }
    Ok(builder.rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_projection_without_tracking_leaves_flow_context_absent() {
        let configs = serde_yaml::from_str(
            "- address: '127.0.0.1:1080'\n  protocol: {type: socks}\n  rules: allow-all-direct",
        )
        .unwrap();
        let mut validated = crate::config::create_server_configs(configs).unwrap();
        let rules = attach(&mut validated, 1, None).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["proxy"], "DIRECT");
        let Config::Server(server) = &validated.configs[0] else {
            panic!()
        };
        let ConfigSelection::Config(rule) = server.rules.iter().next().unwrap() else {
            panic!()
        };
        assert!(
            rule.criteria
                .description
                .as_ref()
                .unwrap()
                .context
                .is_none()
        );
    }

    #[test]
    fn inherited_protocol_rules_are_projected_without_materializing_overrides() {
        let configs = serde_yaml::from_str(
            &serde_json::json!([
                {"clash_api_address":"127.0.0.1:9090","secret":"test"},
                {"name":"entry","address":"127.0.0.1:1080","rules":"allow-all-direct",
                 "protocol":{"type":"websocket","targets":[
                     {"protocol":{"type":"socks"}},
                     {"protocol":{"type":"socks"},"override_rules":"block-all"}
                 ]}}
            ])
            .to_string(),
        )
        .unwrap();
        let mut validated = crate::config::create_server_configs(configs).unwrap();
        let rules = attach(&mut validated, 1, Some(Arc::new(FlowRegistry::default()))).unwrap();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[1]["shoes"]["scope"], "root/websocket/0");
        assert_eq!(rules[1]["shoes"]["inherited"], true);
        assert_eq!(rules[1]["proxy"], "DIRECT");
        assert_eq!(rules[2]["proxy"], "REJECT");
        let Config::Server(server) = &validated.configs[0] else {
            panic!()
        };
        let ServerProxyConfig::Websocket { targets } = &server.protocol else {
            panic!()
        };
        assert!(targets.iter().next().unwrap().override_rules.is_empty());
    }
}
