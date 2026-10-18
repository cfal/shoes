use std::collections::HashMap;
use std::io;
use std::net::IpAddr;

use ipnetwork::IpNetwork;

use super::{
    Config, ConfigSelection, DnsConfig, RuleActionConfig, RuleConfig, ServerProxyConfig,
    ShadowTlsServerHandshakeConfig, ValidatedConfigs,
};
use crate::address::NetLocation;
use crate::option_util::NoneOrSome;

fn reject(ranges: &[IpNetwork], ip: IpAddr, label: &str) -> io::Result<()> {
    if ranges
        .iter()
        .any(|range| range.contains(ip) || range.contains(ip.to_canonical()))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} overlaps an active fake IP range: {ip}"),
        ));
    }
    Ok(())
}

fn target(ranges: &[IpNetwork], location: &NetLocation, label: &str) -> io::Result<()> {
    if let Some(address) = location.to_socket_addr_nonblocking() {
        reject(ranges, address.ip(), label)?;
    }
    Ok(())
}

fn rules(ranges: &[IpNetwork], rules: &NoneOrSome<ConfigSelection<RuleConfig>>) -> io::Result<()> {
    for rule in rules.iter() {
        let ConfigSelection::Config(rule) = rule else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unexpanded fake DNS routing rules",
            ));
        };
        if let RuleActionConfig::Allow {
            override_address: Some(address),
            ..
        } = &rule.action
        {
            target(ranges, address, "rule override")?;
        }
    }
    Ok(())
}

fn protocol(ranges: &[IpNetwork], config: &ServerProxyConfig) -> io::Result<()> {
    match config {
        ServerProxyConfig::Tls {
            tls_targets,
            default_tls_target,
            shadowtls_targets,
            reality_targets,
            ..
        } => {
            for target in tls_targets
                .values()
                .chain(default_tls_target.iter().map(|target| target.as_ref()))
            {
                rules(ranges, &target.override_rules)?;
                protocol(ranges, &target.protocol)?;
            }
            for server in shadowtls_targets.values() {
                if let ShadowTlsServerHandshakeConfig::Remote(handshake) = &server.handshake {
                    target(
                        ranges,
                        &handshake.address,
                        "ShadowTLS handshake destination",
                    )?;
                }
                rules(ranges, &server.override_rules)?;
                protocol(ranges, &server.protocol)?;
            }
            for server in reality_targets.values() {
                target(ranges, &server.dest, "Reality fallback destination")?;
                rules(ranges, &server.override_rules)?;
                protocol(ranges, &server.protocol)?;
            }
        }
        ServerProxyConfig::Vless { fallback, .. } | ServerProxyConfig::Anytls { fallback, .. } => {
            if let Some(address) = fallback {
                target(ranges, address, "authentication fallback destination")?;
            }
        }
        ServerProxyConfig::PortForward { targets } => {
            for address in targets.iter() {
                target(ranges, address, "port-forward destination")?;
            }
        }
        ServerProxyConfig::Websocket { targets } => {
            for target in targets.iter() {
                rules(ranges, &target.override_rules)?;
                protocol(ranges, &target.protocol)?;
            }
        }
        ServerProxyConfig::Xhttp(config) => protocol(ranges, &config.protocol)?,
        _ => {}
    }
    Ok(())
}

pub(super) fn validate(config: &mut ValidatedConfigs) -> io::Result<()> {
    let mut contexts = HashMap::new();
    for group in &config.dns_groups {
        if let Some(options) = &group.fake_ip {
            let ranges: Result<Vec<IpNetwork>, _> = options
                .ipv4_range
                .iter()
                .chain(options.ipv6_range.iter())
                .map(|range| range.parse())
                .collect();
            contexts.insert(group.name.clone(), ranges.map_err(io::Error::other)?);
        }
    }
    if contexts.is_empty() {
        return Ok(());
    }
    let mut all: Vec<IpNetwork> = contexts.values().flatten().copied().collect();
    for server in &config.configs {
        if let Config::TunServer(tun) = server {
            all.extend(
                [tun.address, tun.destination]
                    .into_iter()
                    .flatten()
                    .map(IpNetwork::from),
            );
        }
    }
    let effective = |dns: &Option<DnsConfig>| -> &[IpNetwork] {
        dns.as_ref()
            .and_then(DnsConfig::resolved_group)
            .and_then(|name| contexts.get(name))
            .map_or(&[], Vec::as_slice)
    };
    for server in &config.configs {
        match server {
            Config::Server(server) => {
                let ranges = effective(&server.dns);
                rules(ranges, &server.rules)?;
                protocol(ranges, &server.protocol)?;
            }
            Config::TunServer(tun) => {
                let ranges = effective(&tun.dns);
                rules(ranges, &tun.rules)?;
                for ip in [tun.address, tun.destination].into_iter().flatten() {
                    // The conventional virtual endpoint is already reserved by the allocator.
                    if !ranges.iter().any(|range| match (range.network(), ip) {
                        (IpAddr::V4(base), IpAddr::V4(ip)) => {
                            u32::from(ip) == u32::from(base).saturating_add(1)
                        }
                        (IpAddr::V6(base), IpAddr::V6(ip)) => {
                            u128::from(ip) == u128::from(base).saturating_add(1)
                        }
                        _ => false,
                    }) {
                        reject(ranges, ip, "TUN interface/gateway")?;
                    }
                }
            }
            _ => {}
        }
    }
    for endpoint in &config.wireguard_endpoints {
        if let Some(inbound) = &endpoint.inbound {
            rules(effective(&inbound.dns), &inbound.rules)?;
        }
    }
    config.validate_network_endpoints(&all)
}

impl ValidatedConfigs {
    pub(crate) fn validate_network_endpoints(&mut self, ranges: &[IpNetwork]) -> io::Result<()> {
        for group in &self.dns_groups {
            for spec in &group.specs {
                for value in std::iter::once(spec.url.as_str()).chain(spec.bootstrap_url.as_deref())
                {
                    if let Ok(url) = url::Url::parse(value) {
                        let ip = match url.host() {
                            Some(url::Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
                            Some(url::Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
                            Some(url::Host::Domain(host)) => host.parse::<IpAddr>().ok(),
                            _ => None,
                        };
                        if let Some(ip) = ip {
                            reject(ranges, ip, "DNS/bootstrap endpoint")?;
                        }
                    }
                }
            }
        }
        for endpoint in &self.wireguard_endpoints {
            for peer in &endpoint.peers {
                if let Some(address) = &peer.endpoint {
                    if let Ok(address) = address.parse::<std::net::SocketAddr>() {
                        reject(ranges, address.ip(), "WireGuard endpoint")?;
                    }
                }
            }
        }
        self.visit_clients(&mut |client| target(ranges, &client.address, "proxy endpoint"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validate_yaml(yaml: &str) -> io::Result<ValidatedConfigs> {
        super::super::create_server_configs(serde_yaml::from_str(yaml).map_err(io::Error::other)?)
    }

    #[test]
    fn inline_policy_is_opt_in_private_and_defaults_to_system() {
        let configs = validate_yaml("- address: 127.0.0.1:1080\n  protocol: {type: socks}\n  dns: {fake_ip: true}\n- address: 127.0.0.1:1081\n  protocol: {type: socks}\n  dns: {fake_ip: true}\n").unwrap();
        assert_eq!(configs.dns_groups.len(), 2);
        assert_ne!(configs.dns_groups[0].name, configs.dns_groups[1].name);
        assert!(
            configs
                .dns_groups
                .iter()
                .all(|group| group.fake_ip.is_some() && group.specs[0].url == "system")
        );
        let config =
            validate_yaml("- address: 127.0.0.1:1080\n  protocol: {type: socks}\n").unwrap();
        assert!(config.dns_groups.is_empty());
    }

    #[test]
    fn group_reference_shares_but_override_derives() {
        let configs = validate_yaml("- dns_group: shared\n  dns_servers: system\n  fake_ip: true\n- address: 127.0.0.1:1080\n  protocol: {type: socks}\n  dns: {servers: shared}\n- address: 127.0.0.1:1081\n  protocol: {type: socks}\n  dns: {servers: shared, fake_ip: false}\n").unwrap();
        assert_eq!(configs.dns_groups.len(), 2);
        let Config::Server(first) = &configs.configs[0] else {
            panic!()
        };
        let Config::Server(second) = &configs.configs[1] else {
            panic!()
        };
        assert_eq!(first.dns.as_ref().unwrap().resolved_group(), Some("shared"));
        assert_ne!(
            second.dns.as_ref().unwrap().resolved_group(),
            Some("shared")
        );
        assert!(
            configs
                .dns_groups
                .iter()
                .find(|group| group.name != "shared")
                .unwrap()
                .fake_ip
                .is_none()
        );
    }

    #[test]
    fn fake_literal_overrides_and_upstreams_are_rejected() {
        for dns in [
            "{fake_ip: true, servers: 'udp://198.18.0.1'}",
            "{fake_ip: {max_entries: 0}}",
        ] {
            assert!(
                validate_yaml(&format!(
                    "- address: 127.0.0.1:1080\n  protocol: {{type: socks}}\n  dns: {dns}\n"
                ))
                .is_err()
            );
        }
        for address in ["198.18.0.5:443", "[::ffff:198.18.0.5]:443"] {
            let yaml = format!(
                "- address: 127.0.0.1:1080\n  protocol: {{type: socks}}\n  dns: {{fake_ip: true}}\n  rules:\n    - masks: '0.0.0.0/0'\n      action: allow\n      override_address: '{address}'\n"
            );
            assert!(validate_yaml(&yaml).is_err());
        }
    }

    #[test]
    fn policy_roundtrip_and_unknown_options() {
        for text in [
            "{}",
            "{fake_ip: false}",
            "{fake_ip: true}",
            "{fake_ip: {ipv6_range: '2001:2::/48'}}",
        ] {
            let config: DnsConfig = serde_yaml::from_str(text).unwrap();
            let decoded: DnsConfig =
                serde_yaml::from_str(&serde_yaml::to_string(&config).unwrap()).unwrap();
            assert_eq!(config.fake_ip, decoded.fake_ip);
        }
        assert!(serde_yaml::from_str::<DnsConfig>("{fake_ip: {surprise: true}}").is_err());
    }

    #[test]
    fn server_owned_destinations_follow_effective_fake_ranges() {
        use serde_json::json;
        for address in [
            "198.18.0.5:443",
            "[::ffff:198.18.0.5]:443",
            "[2001:2::5]:443",
        ] {
            let protocols = [
                json!({"type":"forward", "targets":["192.0.2.1:443", address]}),
                json!({"type":"vless", "user_id":"b85798ef-e9dc-46a4-9a87-8da4499d36d0", "fallback":address}),
                json!({"type":"anytls", "users":[{"password":"test"}], "fallback":address}),
                json!({"type":"tls", "reality_targets":{"cover.example":{
                    "private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "dest":address, "protocol":{"type":"socks"}
                }}}),
                json!({"type":"tls", "shadowtls_targets":{"cover.example":{
                    "password":"test", "handshake":{"address":address}, "protocol":{"type":"socks"}
                }}}),
            ];
            for protocol in protocols {
                for nested in [false, true] {
                    let protocol = if nested {
                        json!({"type":"websocket", "targets":[{"protocol":protocol}]})
                    } else {
                        protocol.clone()
                    };
                    let mut config = json!([
                        {"dns_group":"fake", "dns_servers":"system", "fake_ip":{"ipv6_range":"2001:2::/48"}},
                        {"address":"0.0.0.0:1080", "protocol":protocol, "dns":{"servers":"fake"}},
                    ]);
                    let error = validate_yaml(&config.to_string()).err().unwrap();
                    assert!(
                        error
                            .to_string()
                            .contains("overlaps an active fake IP range"),
                        "{error}"
                    );
                    config[1]["dns"]["fake_ip"] = false.into();
                    validate_yaml(&config.to_string()).unwrap();
                    config[1]["dns"] = json!({"servers":"system"});
                    validate_yaml(&config.to_string()).unwrap();
                }
            }
        }
    }
}
