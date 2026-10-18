use std::io;

use super::{
    ClientChainHop, ClientConfig, ClientProxyConfig, Config, ConfigSelection, RuleActionConfig,
    RuleConfig, ServerProxyConfig, ShadowTlsServerHandshakeConfig, ValidatedConfigs,
};
use crate::option_util::NoneOrSome;

type Visitor<'a> = dyn FnMut(&mut ClientConfig) -> io::Result<()> + 'a;

pub(crate) fn visit_hop(hop: &mut ClientChainHop, visitor: &mut Visitor<'_>) -> io::Result<()> {
    match hop {
        ClientChainHop::Single(selection) => visit_client(selection.unwrap_config_mut(), visitor),
        ClientChainHop::Pool(selections) => {
            for selection in selections.iter_mut() {
                visit_client(selection.unwrap_config_mut(), visitor)?;
            }
            Ok(())
        }
    }
}

pub(crate) fn visit_client(client: &mut ClientConfig, visitor: &mut Visitor<'_>) -> io::Result<()> {
    if let ClientProxyConfig::Wireguard(config) = &mut client.protocol
        && let Some(chain) = &mut config.peer_client_chain
    {
        for hop in chain.hops.iter_mut() {
            visit_hop(hop, visitor)?;
        }
    }
    visitor(client)
}

fn visit_rules(
    rules: &mut NoneOrSome<ConfigSelection<RuleConfig>>,
    visitor: &mut Visitor<'_>,
) -> io::Result<()> {
    for rule in rules.iter_mut() {
        if let RuleActionConfig::Allow { client_chains, .. } = &mut rule.unwrap_config_mut().action
        {
            for chain in client_chains.iter_mut() {
                for hop in chain.hops.iter_mut() {
                    visit_hop(hop, visitor)?;
                }
            }
        }
    }
    Ok(())
}

fn visit_protocol(protocol: &mut ServerProxyConfig, visitor: &mut Visitor<'_>) -> io::Result<()> {
    match protocol {
        ServerProxyConfig::Wireguard(config) => {
            if let Some(chain) = &mut config.peer_client_chain {
                for hop in chain.hops.iter_mut() {
                    visit_hop(hop, visitor)?;
                }
            }
        }
        ServerProxyConfig::Tls {
            tls_targets,
            default_tls_target,
            shadowtls_targets,
            reality_targets,
            ..
        } => {
            for target in tls_targets
                .values_mut()
                .chain(default_tls_target.iter_mut().map(|target| target.as_mut()))
            {
                visit_rules(&mut target.override_rules, visitor)?;
                visit_protocol(&mut target.protocol, visitor)?;
            }
            for target in shadowtls_targets.values_mut() {
                visit_rules(&mut target.override_rules, visitor)?;
                visit_protocol(&mut target.protocol, visitor)?;
                if let ShadowTlsServerHandshakeConfig::Remote(remote) = &mut target.handshake {
                    for hop in remote.client_chain.iter_mut() {
                        visit_hop(hop, visitor)?;
                    }
                }
            }
            for target in reality_targets.values_mut() {
                visit_rules(&mut target.override_rules, visitor)?;
                visit_protocol(&mut target.protocol, visitor)?;
                for hop in target.dest_client_chain.iter_mut() {
                    visit_hop(hop, visitor)?;
                }
            }
        }
        ServerProxyConfig::Websocket { targets } => {
            for target in targets.iter_mut() {
                visit_rules(&mut target.override_rules, visitor)?;
                visit_protocol(&mut target.protocol, visitor)?;
            }
        }
        ServerProxyConfig::Xhttp(config) => visit_protocol(&mut config.protocol, visitor)?,
        _ => {}
    }
    Ok(())
}

impl ValidatedConfigs {
    pub(crate) fn visit_clients(&mut self, visitor: &mut Visitor<'_>) -> io::Result<()> {
        for config in &mut self.configs {
            match config {
                Config::Server(server) => {
                    visit_rules(&mut server.rules, visitor)?;
                    visit_protocol(&mut server.protocol, visitor)?;
                }
                Config::TunServer(tun) => visit_rules(&mut tun.rules, visitor)?,
                _ => {}
            }
        }
        for endpoint in &mut self.wireguard_endpoints {
            if let Some(chain) = &mut endpoint.peer_client_chain {
                for hop in chain.hops.iter_mut() {
                    visit_hop(hop, visitor)?;
                }
            }
            if let Some(inbound) = &mut endpoint.inbound {
                visit_rules(&mut inbound.rules, visitor)?;
            }
        }
        for group in &mut self.dns_groups {
            for spec in &mut group.specs {
                for chain in &mut spec.client_chains {
                    for hop in chain.hops.iter_mut() {
                        visit_hop(hop, visitor)?;
                    }
                }
            }
        }
        Ok(())
    }
}
