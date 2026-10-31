use std::collections::HashMap;
use std::io;

use super::{
    ClientChain, ClientChainHop, ClientConfig, ClientProxyConfig, Config, ConfigSelection,
    RuleActionConfig, RuleConfig, ServerProxyConfig, ShadowTlsServerHandshakeConfig,
    ValidatedConfigs,
};
use crate::option_util::NoneOrSome;

type Visitor<'a> = dyn FnMut(&mut ClientConfig) -> io::Result<()> + 'a;

// Generated client identities and projected rule order depend on lexical target order.
pub(crate) fn sorted_targets<T>(targets: &mut HashMap<String, T>) -> Vec<(&String, &mut T)> {
    let mut targets: Vec<_> = targets.iter_mut().collect();
    targets.sort_unstable_by_key(|(key, _)| *key);
    targets
}

fn visit_chain(chain: &mut ClientChain, visitor: &mut Visitor<'_>, source: bool) -> io::Result<()> {
    for hop in chain.hops.iter_mut() {
        visit_hop_inner(hop, visitor, source)?;
    }
    Ok(())
}

pub(crate) fn visit_hop(hop: &mut ClientChainHop, visitor: &mut Visitor<'_>) -> io::Result<()> {
    visit_hop_inner(hop, visitor, false)
}

fn visit_hop_inner(
    hop: &mut ClientChainHop,
    visitor: &mut Visitor<'_>,
    source: bool,
) -> io::Result<()> {
    if source && matches!(hop, ClientChainHop::Choice(_)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "resolved client choices cannot be used in source configuration; use group references or pools",
        ));
    }
    visit_hop_clients(hop, &mut |client| {
        visit_client_inner(client, visitor, source)
    })
}

// Visits composition leaves; the callback owns traversal into WireGuard carriers.
pub(crate) fn visit_hop_clients(
    hop: &mut ClientChainHop,
    visitor: &mut Visitor<'_>,
) -> io::Result<()> {
    match hop {
        ClientChainHop::Choice(choice) => {
            for chain in &mut choice.members {
                for hop in chain.hops.iter_mut() {
                    visit_hop_clients(hop, visitor)?;
                }
            }
            Ok(())
        }
        ClientChainHop::Single(selection) => {
            if let ConfigSelection::Config(client) = selection {
                visitor(client)?;
            }
            Ok(())
        }
        ClientChainHop::Pool(selections) => {
            for selection in selections.iter_mut() {
                if let ConfigSelection::Config(client) = selection {
                    visitor(client)?;
                }
            }
            Ok(())
        }
    }
}

fn visit_selection(
    selection: &mut ConfigSelection<ClientConfig>,
    visitor: &mut Visitor<'_>,
    source: bool,
) -> io::Result<()> {
    if let ConfigSelection::Config(client) = selection {
        visit_client_inner(client, visitor, source)?;
    }
    Ok(())
}

pub(crate) fn visit_client(client: &mut ClientConfig, visitor: &mut Visitor<'_>) -> io::Result<()> {
    visit_client_inner(client, visitor, false)
}

fn visit_client_inner(
    client: &mut ClientConfig,
    visitor: &mut Visitor<'_>,
    source: bool,
) -> io::Result<()> {
    if let ClientProxyConfig::Wireguard(config) = &mut client.protocol
        && let Some(chain) = &mut config.peer_client_chain
    {
        visit_chain(chain, visitor, source)?;
    }
    visitor(client)
}

fn visit_action(
    action: &mut RuleActionConfig,
    visitor: &mut Visitor<'_>,
    source: bool,
) -> io::Result<()> {
    if let RuleActionConfig::Allow { client_chains, .. } = action {
        for chain in client_chains.iter_mut() {
            visit_chain(chain, visitor, source)?;
        }
    }
    Ok(())
}

fn visit_rules(
    rules: &mut NoneOrSome<ConfigSelection<RuleConfig>>,
    visitor: &mut Visitor<'_>,
    source: bool,
) -> io::Result<()> {
    for rule in rules.iter_mut() {
        if let ConfigSelection::Config(rule) = rule {
            visit_action(&mut rule.action, visitor, source)?;
        }
    }
    Ok(())
}

fn visit_dns(
    specs: &mut NoneOrSome<super::DnsServerSpec>,
    visitor: &mut Visitor<'_>,
    source: bool,
) -> io::Result<()> {
    for spec in specs.iter_mut() {
        if let super::DnsServerSpec::WithOptions { client_chain, .. } = spec {
            for chain in client_chain.iter_mut() {
                visit_chain(chain, visitor, source)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn visit_configs(configs: &mut [Config], visitor: &mut Visitor<'_>) -> io::Result<()> {
    visit_configs_inner(configs, visitor, false)
}

pub(crate) fn validate_source_configs(configs: &mut [Config]) -> io::Result<()> {
    visit_configs_inner(configs, &mut |_| Ok(()), true)
}

fn visit_configs_inner(
    configs: &mut [Config],
    visitor: &mut Visitor<'_>,
    source: bool,
) -> io::Result<()> {
    for config in configs.iter_mut() {
        match config {
            Config::ClientConfigGroup(group) => {
                for member in group.client_chains.iter_mut() {
                    match member {
                        super::ClientGroupMember::Client(client) => {
                            visit_selection(client, visitor, source)?
                        }
                        super::ClientGroupMember::Chain { chain, .. } => {
                            visit_chain(chain, visitor, source)?
                        }
                    }
                }
            }
            Config::RuleConfigGroup(group) => {
                for rule in group.rules.iter_mut() {
                    visit_action(&mut rule.action, visitor, source)?;
                }
            }
            Config::Server(server) => {
                visit_rules(&mut server.rules, visitor, source)?;
                visit_protocol(&mut server.protocol, visitor, source)?;
                if let Some(dns) = &mut server.dns {
                    visit_dns(&mut dns.servers, visitor, source)?;
                }
            }
            Config::TunServer(tun) => {
                visit_rules(&mut tun.rules, visitor, source)?;
                if let Some(dns) = &mut tun.dns {
                    visit_dns(&mut dns.servers, visitor, source)?;
                }
            }
            Config::DnsConfigGroup(group) => visit_dns(&mut group.dns_servers, visitor, source)?,
            _ => {}
        }
    }
    crate::rule_set::visit_sources(configs, &mut |rule_source| {
        if let Some(download) = &mut rule_source.download {
            visit_chain(&mut download.client_chain, visitor, source)?;
        }
        Ok(())
    })
}

fn visit_protocol(
    protocol: &mut ServerProxyConfig,
    visitor: &mut Visitor<'_>,
    source: bool,
) -> io::Result<()> {
    match protocol {
        ServerProxyConfig::Wireguard(config) => {
            if let Some(chain) = &mut config.peer_client_chain {
                visit_chain(chain, visitor, source)?;
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
                visit_rules(&mut target.override_rules, visitor, source)?;
                visit_protocol(&mut target.protocol, visitor, source)?;
            }
            if let Some(target) = default_tls_target {
                visit_rules(&mut target.override_rules, visitor, source)?;
                visit_protocol(&mut target.protocol, visitor, source)?;
            }
            for (_, target) in sorted_targets(shadowtls_targets) {
                visit_rules(&mut target.override_rules, visitor, source)?;
                visit_protocol(&mut target.protocol, visitor, source)?;
                if let ShadowTlsServerHandshakeConfig::Remote(remote) = &mut target.handshake {
                    for hop in remote.client_chain.iter_mut() {
                        visit_hop_inner(hop, visitor, source)?;
                    }
                }
            }
            for (_, target) in sorted_targets(reality_targets) {
                visit_rules(&mut target.override_rules, visitor, source)?;
                visit_protocol(&mut target.protocol, visitor, source)?;
                for hop in target.dest_client_chain.iter_mut() {
                    visit_hop_inner(hop, visitor, source)?;
                }
            }
        }
        ServerProxyConfig::Websocket { targets } => {
            for target in targets.iter_mut() {
                visit_rules(&mut target.override_rules, visitor, source)?;
                visit_protocol(&mut target.protocol, visitor, source)?;
            }
        }
        ServerProxyConfig::SudokuMask(config) => {
            visit_protocol(&mut config.protocol, visitor, source)?;
        }
        ServerProxyConfig::Xhttp(config) => visit_protocol(&mut config.protocol, visitor, source)?,
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
        for source in &mut self.remote_rules {
            if let Some(download) = &mut source.download {
                visit_chain(&mut download.client_chain, visitor)?;
            }
        }
        for config in &mut self.configs {
            match config {
                Config::Server(server) => {
                    visit_rules(&mut server.rules, visitor, false)?;
                    visit_protocol(&mut server.protocol, visitor, false)?;
                }
                Config::TunServer(tun) => visit_rules(&mut tun.rules, visitor, false)?,
                _ => {}
            }
        }
        for endpoint in &mut self.wireguard_endpoints {
            if let Some(chain) = &mut endpoint.peer_client_chain {
                visit_chain(chain, visitor, false)?;
            }
            if let Some(inbound) = &mut endpoint.inbound {
                visit_rules(&mut inbound.rules, visitor, false)?;
            }
        }
        for group in &mut self.dns_groups {
            for spec in &mut group.specs {
                for chain in &mut spec.client_chains {
                    visit_chain(chain, visitor, false)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ClientConfigGroup, ClientGroupMember, GroupType, create_server_configs,
        wireguard::WireguardClientConfig,
    };
    use crate::option_util::OneOrSome;
    use serde_json::json;

    fn choice() -> ClientChainHop {
        super::super::composition::pool_choice(vec![ClientChain::default(), ClientChain::default()])
    }

    fn rejects(config: Config) {
        let error = create_server_configs(vec![config])
            .err()
            .expect("resolved choices must fail source validation");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            error.to_string(),
            "resolved client choices cannot be used in source configuration; use group references or pools"
        );
    }

    #[test]
    fn source_choices_are_rejected_with_and_without_control() {
        for group_type in [GroupType::RoundRobin, GroupType::Selector] {
            rejects(Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "out".into(),
                group_type,
                default: None,
                client_chains: OneOrSome::One(ClientGroupMember::Chain {
                    name: Some("relay".into()),
                    chain: ClientChain {
                        hops: OneOrSome::One(choice()),
                    },
                }),
            }));
        }
    }

    #[test]
    fn source_choices_are_rejected_in_rules_and_dns() {
        let mut server: super::super::ServerConfig = serde_json::from_value(json!({
            "address":"0.0.0.0:0", "protocol":{"type":"socks"}
        }))
        .unwrap();
        server.rules = NoneOrSome::One(ConfigSelection::Config(RuleConfig {
            action: RuleActionConfig::Allow {
                override_address: None,
                client_chains: NoneOrSome::One(ClientChain {
                    hops: OneOrSome::One(choice()),
                }),
            },
            ..RuleConfig::default()
        }));
        rejects(Config::Server(server));

        let mut config: Config = serde_json::from_value(json!({
            "dns_group":"dns", "dns_servers":[{"url":"tcp://192.0.2.1"}]
        }))
        .unwrap();
        let Config::DnsConfigGroup(group) = &mut config else {
            panic!()
        };
        let super::super::DnsServerSpec::WithOptions { client_chain, .. } =
            group.dns_servers.iter_mut().next().unwrap()
        else {
            panic!()
        };
        *client_chain = NoneOrSome::One(ClientChain {
            hops: OneOrSome::One(choice()),
        });
        rejects(config);
    }

    #[test]
    fn source_choices_are_rejected_inside_carriers_at_each_consumer() {
        use base64::Engine;

        let mut wireguard: WireguardClientConfig = serde_json::from_value(json!({
            "private_key":base64::engine::general_purpose::STANDARD.encode([42; 32]),
            "public_key":base64::engine::general_purpose::STANDARD.encode([43; 32]),
            "addresses":["10.77.0.2/32"]
        }))
        .unwrap();
        wireguard.peer_client_chain = Some(ClientChain {
            hops: OneOrSome::One(choice()),
        });
        let client = json!({"name":"inject", "protocol":{"type":"direct"}});
        let rule = json!({"mask":"0.0.0.0/0", "client_chain":client});
        let dns = json!({"url":"tcp://192.0.2.1", "client_chain":client});
        let mut sources = vec![
            json!({"client_group":"out", "client_chain":client}),
            json!({"client_group":"out", "client_chain":{"chain":[client]}}),
            json!({"client_group":"out", "client_chain":{"chain":[{"pool":[client]}]}}),
            json!({"rule_group":"rules", "rules":[rule]}),
            json!({"dns_group":"dns", "dns_servers":[dns]}),
            json!({"address":"0.0.0.0:0", "protocol":{"type":"socks"}, "rules":[rule]}),
            json!({"address":"0.0.0.0:0", "protocol":{"type":"socks"}, "dns":{"servers":[dns]}}),
            json!({"device_name":"tun0", "rules":[rule]}),
            json!({"device_name":"tun0", "dns":{"servers":[dns]}}),
        ];
        for protocol in [
            json!({"type":"wireguard", "private_key":wireguard.private_key,
                "addresses":["10.77.0.1/24"], "peers":[], "peer_client_chain":client}),
            json!({"type":"tls", "default_target":{"protocol":{"type":"socks"}, "override_rules":[rule]}}),
            json!({"type":"tls", "tls_targets":{"example.com":{"protocol":{"type":"socks"}, "override_rules":[rule]}}}),
            json!({"type":"tls", "shadowtls_targets":{"example.com":{
                "password":"test", "protocol":{"type":"socks"},
                "handshake":{"address":"example.com:443", "client_chain":[client]}
            }}}),
            json!({"type":"tls", "reality_targets":{"example.com":{
                "private_key":"unused", "dest":"example.com:443", "protocol":{"type":"socks"},
                "dest_client_chain":[client]
            }}}),
            json!({"type":"websocket", "targets":[{"protocol":{"type":"socks"}, "override_rules":[rule]}]}),
            json!({"type":"sudoku_mask", "protocol":{"type":"websocket", "targets":[{
                "protocol":{"type":"socks"}, "override_rules":[rule]
            }]}}),
            json!({"type":"xhttp", "protocol":{"type":"websocket", "targets":[{
                "protocol":{"type":"socks"}, "override_rules":[rule]
            }]}}),
        ] {
            sources.push(json!({"address":"0.0.0.0:0", "protocol":protocol}));
        }
        for source in sources {
            let mut config: Config = serde_json::from_value(source).unwrap();
            let mut injected = 0;
            visit_configs(std::slice::from_mut(&mut config), &mut |client| {
                if client.name.as_deref() == Some("inject") {
                    client.protocol = ClientProxyConfig::Wireguard(Box::new(wireguard.clone()));
                    injected += 1;
                }
                Ok(())
            })
            .unwrap();
            assert_eq!(injected, 1);
            rejects(config);
        }
    }
}
