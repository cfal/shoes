use std::io;

use super::{
    ClientChainHop, ClientConfig, Config, ConfigSelection, RuleActionConfig, RuleConfig,
    ServerProxyConfig, ShadowTlsServerHandshakeConfig, ValidatedConfigs,
};
use crate::option_util::NoneOrSome;

type Visitor<'a> = dyn FnMut(&mut ClientConfig) -> io::Result<()> + 'a;

pub(crate) fn visit_hop(hop: &mut ClientChainHop, visitor: &mut Visitor<'_>) -> io::Result<()> {
    match hop {
        ClientChainHop::Single(selection) => visitor(selection.unwrap_config_mut()),
        ClientChainHop::Pool(selections) => {
            for selection in selections.iter_mut() {
                visitor(selection.unwrap_config_mut())?;
            }
            Ok(())
        }
    }
}

fn rules(
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

fn protocol(protocol: &mut ServerProxyConfig, visitor: &mut Visitor<'_>) -> io::Result<()> {
    match protocol {
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
                rules(&mut target.override_rules, visitor)?;
                self::protocol(&mut target.protocol, visitor)?;
            }
            for target in shadowtls_targets.values_mut() {
                rules(&mut target.override_rules, visitor)?;
                self::protocol(&mut target.protocol, visitor)?;
                if let ShadowTlsServerHandshakeConfig::Remote(remote) = &mut target.handshake {
                    for hop in remote.client_chain.iter_mut() {
                        visit_hop(hop, visitor)?;
                    }
                }
            }
            for target in reality_targets.values_mut() {
                rules(&mut target.override_rules, visitor)?;
                self::protocol(&mut target.protocol, visitor)?;
                for hop in target.dest_client_chain.iter_mut() {
                    visit_hop(hop, visitor)?;
                }
            }
        }
        ServerProxyConfig::Websocket { targets } => {
            for target in targets.iter_mut() {
                rules(&mut target.override_rules, visitor)?;
                self::protocol(&mut target.protocol, visitor)?;
            }
        }
        ServerProxyConfig::Xhttp(config) => self::protocol(&mut config.protocol, visitor)?,
        _ => {}
    }
    Ok(())
}

impl ValidatedConfigs {
    pub(crate) fn visit_clients(&mut self, visitor: &mut Visitor<'_>) -> io::Result<()> {
        for config in &mut self.configs {
            match config {
                Config::Server(server) => {
                    rules(&mut server.rules, visitor)?;
                    protocol(&mut server.protocol, visitor)?;
                }
                Config::TunServer(tun) => rules(&mut tun.rules, visitor)?,
                _ => {}
            }
        }
        for endpoint in &mut self.wireguard_endpoints {
            if let Some(inbound) = &mut endpoint.inbound {
                rules(&mut inbound.rules, visitor)?;
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
