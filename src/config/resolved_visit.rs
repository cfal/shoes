use std::io;

use super::ValidatedConfigs;
use super::client_visit::sorted_targets;
use super::resolved::{
    ResolvedClientChain as ClientChain, ResolvedClientConfig as ClientConfig,
    ResolvedClientHop as ClientChainHop, ResolvedClientProxyConfig as ClientProxyConfig,
    ResolvedConfig as Config, ResolvedRuleActionConfig as RuleActionConfig,
    ResolvedRuleConfig as RuleConfig, ResolvedServerProxyConfig as ServerProxyConfig,
    ResolvedShadowTlsServerHandshakeConfig as ShadowTlsServerHandshakeConfig,
};
use crate::option_util::NoneOrSome;

type Visitor<'a> = dyn FnMut(&mut ClientConfig) -> io::Result<()> + 'a;

pub(crate) fn visit_chain(chain: &mut ClientChain, visitor: &mut Visitor<'_>) -> io::Result<()> {
    for hop in chain.hops.iter_mut() {
        visit_hop(hop, visitor)?;
    }
    Ok(())
}

pub(crate) fn visit_hop(hop: &mut ClientChainHop, visitor: &mut Visitor<'_>) -> io::Result<()> {
    super::plan_ops::visit_leaves(hop, &mut |client| visit_client(client, visitor))
}

pub(crate) fn visit_client(client: &mut ClientConfig, visitor: &mut Visitor<'_>) -> io::Result<()> {
    if let ClientProxyConfig::Wireguard(config) = &mut client.protocol
        && let Some(chain) = &mut config.peer_client_chain
    {
        visit_chain(chain, visitor)?;
    }
    visitor(client)
}

pub(crate) fn client_tree(client: &ClientConfig) -> Box<dyn Iterator<Item = &ClientConfig> + '_> {
    let carrier: Box<dyn Iterator<Item = &ClientConfig>> = match &client.protocol {
        ClientProxyConfig::Wireguard(config) => Box::new(
            config
                .peer_client_chain
                .iter()
                .flat_map(|chain| chain.hops.iter().flat_map(super::composition::clients))
                .flat_map(client_tree),
        ),
        _ => Box::new(std::iter::empty()),
    };
    Box::new(carrier.chain(std::iter::once(client)))
}

fn visit_rules(rules: &mut NoneOrSome<RuleConfig>, visitor: &mut Visitor<'_>) -> io::Result<()> {
    for rule in rules.iter_mut() {
        if let RuleActionConfig::Allow { client_chains, .. } = &mut rule.action {
            for chain in client_chains.iter_mut() {
                visit_chain(chain, visitor)?;
            }
        }
    }
    Ok(())
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
                        visit_hop(hop, visitor)?;
                    }
                }
            }
            for (_, target) in sorted_targets(reality_targets) {
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
        ServerProxyConfig::SudokuMask(config) => {
            visit_protocol(&mut config.protocol, visitor)?;
        }
        ServerProxyConfig::Xhttp(config) => visit_protocol(&mut config.protocol, visitor)?,
        _ => {}
    }
    Ok(())
}

impl ValidatedConfigs {
    pub(crate) fn refresh_catalog(&mut self) -> io::Result<()> {
        if let Some(mut catalog) = self.catalog.take() {
            self.visit_clients(&mut |client| {
                catalog.update_client(client);
                Ok(())
            })?;
            self.catalog = Some(catalog);
        }
        Ok(())
    }

    pub(crate) fn visit_clients(&mut self, visitor: &mut Visitor<'_>) -> io::Result<()> {
        for config in &mut self.configs {
            match config {
                Config::Server(server) => {
                    visit_rules(&mut server.rules, visitor)?;
                    visit_protocol(&mut server.protocol, visitor)?;
                }
                Config::TunServer(tun) => visit_rules(&mut tun.rules, visitor)?,
            }
        }
        for endpoint in &mut self.wireguard_endpoints {
            if let Some(chain) = &mut endpoint.peer_client_chain {
                visit_chain(chain, visitor)?;
            }
            if let Some(inbound) = &mut endpoint.inbound {
                visit_rules(&mut inbound.rules, visitor)?;
            }
        }
        for group in &mut self.dns_groups {
            for spec in &mut group.specs {
                for chain in &mut spec.client_chains {
                    visit_chain(chain, visitor)?;
                }
            }
        }
        Ok(())
    }
}
