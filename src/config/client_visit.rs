use std::collections::HashMap;
use std::io;

use super::{
    ClientChain, ClientChainHop, ClientConfig, ClientProxyConfig, Config, ConfigSelection,
    RuleActionConfig, RuleConfig, ServerProxyConfig, ShadowTlsServerHandshakeConfig,
};
use crate::option_util::NoneOrSome;

type Visitor<'a> = dyn FnMut(&mut ClientConfig) -> io::Result<()> + 'a;

// Generated client identities and projected rule order depend on lexical target order.
pub(crate) fn sorted_targets<T>(targets: &mut HashMap<String, T>) -> Vec<(&String, &mut T)> {
    let mut targets: Vec<_> = targets.iter_mut().collect();
    targets.sort_unstable_by_key(|(key, _)| *key);
    targets
}

fn visit_chain(chain: &mut ClientChain, visitor: &mut Visitor<'_>) -> io::Result<()> {
    for hop in chain.hops.iter_mut() {
        visit_source_hop(hop, visitor)?;
    }
    Ok(())
}

fn visit_source_hop(hop: &mut ClientChainHop, visitor: &mut Visitor<'_>) -> io::Result<()> {
    match hop {
        ClientChainHop::Single(selection) => visit_selection(selection, visitor),
        ClientChainHop::Pool(selections) => {
            for selection in selections.iter_mut() {
                visit_selection(selection, visitor)?;
            }
            Ok(())
        }
    }
}

fn visit_selection(
    selection: &mut ConfigSelection<ClientConfig>,
    visitor: &mut Visitor<'_>,
) -> io::Result<()> {
    if let ConfigSelection::Config(client) = selection {
        visit_source_client(client, visitor)?;
    }
    Ok(())
}

pub(crate) fn visit_source_client(
    client: &mut ClientConfig,
    visitor: &mut Visitor<'_>,
) -> io::Result<()> {
    if let ClientProxyConfig::Wireguard(config) = &mut client.protocol
        && let Some(chain) = &mut config.peer_client_chain
    {
        visit_chain(chain, visitor)?;
    }
    visitor(client)
}

fn visit_action(action: &mut RuleActionConfig, visitor: &mut Visitor<'_>) -> io::Result<()> {
    if let RuleActionConfig::Allow { client_chains, .. } = action {
        for chain in client_chains.iter_mut() {
            visit_chain(chain, visitor)?;
        }
    }
    Ok(())
}

fn visit_rules(
    rules: &mut NoneOrSome<ConfigSelection<RuleConfig>>,
    visitor: &mut Visitor<'_>,
) -> io::Result<()> {
    for rule in rules.iter_mut() {
        if let ConfigSelection::Config(rule) = rule {
            visit_action(&mut rule.action, visitor)?;
        }
    }
    Ok(())
}

fn visit_dns(
    specs: &mut NoneOrSome<super::DnsServerSpec>,
    visitor: &mut Visitor<'_>,
) -> io::Result<()> {
    for spec in specs.iter_mut() {
        if let super::DnsServerSpec::WithOptions { client_chain, .. } = spec {
            for chain in client_chain.iter_mut() {
                visit_chain(chain, visitor)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn visit_source_configs(
    configs: &mut [Config],
    visitor: &mut Visitor<'_>,
) -> io::Result<()> {
    for config in configs.iter_mut() {
        match config {
            Config::ClientConfigGroup(group) => {
                for member in group.client_chains.iter_mut() {
                    match member {
                        super::ClientGroupMember::Client(client) => {
                            visit_selection(client, visitor)?
                        }
                        super::ClientGroupMember::Chain { chain, .. } => {
                            visit_chain(chain, visitor)?
                        }
                    }
                }
            }
            Config::RuleConfigGroup(group) => {
                for rule in group.rules.iter_mut() {
                    visit_action(&mut rule.action, visitor)?;
                }
            }
            Config::Server(server) => {
                visit_rules(&mut server.rules, visitor)?;
                visit_protocol(&mut server.protocol, visitor)?;
                if let Some(dns) = &mut server.dns {
                    visit_dns(&mut dns.servers, visitor)?;
                }
            }
            Config::TunServer(tun) => {
                visit_rules(&mut tun.rules, visitor)?;
                if let Some(dns) = &mut tun.dns {
                    visit_dns(&mut dns.servers, visitor)?;
                }
            }
            Config::DnsConfigGroup(group) => visit_dns(&mut group.dns_servers, visitor)?,
            _ => {}
        }
    }
    crate::rule_set::visit_sources(configs, &mut |rule_source| {
        if let Some(download) = &mut rule_source.download {
            visit_chain(&mut download.client_chain, visitor)?;
        }
        Ok(())
    })
}

fn visit_protocol(protocol: &mut ServerProxyConfig, visitor: &mut Visitor<'_>) -> io::Result<()> {
    match protocol {
        ServerProxyConfig::Wireguard(config) => {
            if let Some(chain) = &mut config.peer_client_chain {
                visit_chain(chain, visitor)?;
            }
        }
        ServerProxyConfig::Tls {
            tls_targets,
            default_tls_target,
            shadowtls_targets,
            reality_targets,
            ..
        } => {
            for (_, target) in sorted_targets(tls_targets) {
                visit_rules(&mut target.override_rules, visitor)?;
                visit_protocol(&mut target.protocol, visitor)?;
            }
            if let Some(target) = default_tls_target {
                visit_rules(&mut target.override_rules, visitor)?;
                visit_protocol(&mut target.protocol, visitor)?;
            }
            for (_, target) in sorted_targets(shadowtls_targets) {
                visit_rules(&mut target.override_rules, visitor)?;
                visit_protocol(&mut target.protocol, visitor)?;
                if let ShadowTlsServerHandshakeConfig::Remote(remote) = &mut target.handshake {
                    for hop in remote.client_chain.iter_mut() {
                        visit_source_hop(hop, visitor)?;
                    }
                }
            }
            for (_, target) in sorted_targets(reality_targets) {
                visit_rules(&mut target.override_rules, visitor)?;
                visit_protocol(&mut target.protocol, visitor)?;
                for hop in target.dest_client_chain.iter_mut() {
                    visit_source_hop(hop, visitor)?;
                }
            }
        }
        ServerProxyConfig::Websocket { targets } => {
            for target in targets.iter_mut() {
                visit_rules(&mut target.override_rules, visitor)?;
                visit_protocol(&mut target.protocol, visitor)?;
            }
        }
        ServerProxyConfig::SudokuMask(config) => {
            visit_protocol(&mut config.protocol, visitor)?;
        }
        ServerProxyConfig::Xhttp(config) => visit_protocol(&mut config.protocol, visitor)?,
        _ => {}
    }
    Ok(())
}
