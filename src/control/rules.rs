use std::io;
use std::sync::Arc;

use super::catalog::RuleDescription;
use super::flows::{FlowContext, FlowRegistry};
use crate::config::{Config, ConfigSelection, RuleConfig, ServerProxyConfig, ValidatedConfigs};
use crate::option_util::NoneOrSome;

struct Builder {
    registry: Arc<FlowRegistry>,
    generation: u64,
    enabled: bool,
    rules: Vec<serde_json::Value>,
}

impl Builder {
    fn rules(
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
            if self.enabled {
                description.context = Some(Arc::new(FlowContext {
                    registry: self.registry.clone(),
                    generation: self.generation,
                    inbound: inbound.into(),
                    scope: scope.into(),
                    protocol: protocol.into(),
                }));
            }
            self.rules.push(serde_json::json!({"index":self.rules.len(),"type":"Shoes","payload":format!("{inbound} ({scope}): {}",description.payload),"proxy":description.proxy,"size":-1,"shoes":{"inbound":inbound,"scope":scope}}));
            rule.criteria.description = Some(Arc::new(description));
        }
    }

    fn protocol(&mut self, protocol: &mut ServerProxyConfig, inbound: &str, scope: &str) {
        match protocol {
            ServerProxyConfig::Tls {
                tls_targets,
                default_tls_target,
                shadowtls_targets,
                reality_targets,
                ..
            } => {
                let mut keys: Vec<_> = tls_targets.keys().cloned().collect();
                keys.sort();
                for key in keys {
                    let target = tls_targets.get_mut(&key).unwrap();
                    let scope = format!("{scope}/tls/{key}");
                    self.rules(
                        &mut target.override_rules,
                        inbound,
                        &scope,
                        inbound_type(&target.protocol),
                    );
                    self.protocol(&mut target.protocol, inbound, &scope);
                }
                if let Some(target) = default_tls_target {
                    let scope = format!("{scope}/tls/default");
                    self.rules(
                        &mut target.override_rules,
                        inbound,
                        &scope,
                        inbound_type(&target.protocol),
                    );
                    self.protocol(&mut target.protocol, inbound, &scope);
                }
                let mut keys: Vec<_> = shadowtls_targets.keys().cloned().collect();
                keys.sort();
                for key in keys {
                    let target = shadowtls_targets.get_mut(&key).unwrap();
                    let scope = format!("{scope}/shadowtls/{key}");
                    self.rules(
                        &mut target.override_rules,
                        inbound,
                        &scope,
                        inbound_type(&target.protocol),
                    );
                    self.protocol(&mut target.protocol, inbound, &scope);
                }
                let mut keys: Vec<_> = reality_targets.keys().cloned().collect();
                keys.sort();
                for key in keys {
                    let target = reality_targets.get_mut(&key).unwrap();
                    let scope = format!("{scope}/reality/{key}");
                    self.rules(
                        &mut target.override_rules,
                        inbound,
                        &scope,
                        inbound_type(&target.protocol),
                    );
                    self.protocol(&mut target.protocol, inbound, &scope);
                }
            }
            ServerProxyConfig::Websocket { targets } => {
                for (index, target) in targets.iter_mut().enumerate() {
                    let scope = format!("{scope}/websocket/{index}");
                    self.rules(
                        &mut target.override_rules,
                        inbound,
                        &scope,
                        inbound_type(&target.protocol),
                    );
                    self.protocol(&mut target.protocol, inbound, &scope);
                }
            }
            ServerProxyConfig::Xhttp(config) => {
                self.protocol(&mut config.protocol, inbound, &format!("{scope}/xhttp"))
            }
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
    registry: Arc<FlowRegistry>,
    generation: u64,
    enabled: bool,
) -> io::Result<Vec<serde_json::Value>> {
    let mut builder = Builder {
        registry,
        generation,
        enabled,
        rules: Vec::new(),
    };
    for (index, config) in validated.configs.iter_mut().enumerate() {
        match config {
            Config::Server(server) => {
                let inbound = server
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("inbound-{index}"));
                builder.rules(
                    &mut server.rules,
                    &inbound,
                    "root",
                    inbound_type(&server.protocol),
                );
                builder.protocol(&mut server.protocol, &inbound, "root");
            }
            Config::TunServer(tun) => {
                let inbound = tun.name.clone().unwrap_or_else(|| format!("tun-{index}"));
                builder.rules(&mut tun.rules, &inbound, "root", "Tun");
            }
            _ => {}
        }
    }
    for endpoint in &mut validated.wireguard_endpoints {
        if let Some(inbound) = &mut endpoint.inbound {
            builder.rules(&mut inbound.rules, &endpoint.id, "wireguard", "WireGuard");
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
