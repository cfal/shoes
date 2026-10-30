use std::io;
use std::net::IpAddr;

use ipnetwork::IpNetwork;

use super::{
    Config, ConfigSelection, RuleActionConfig, RuleConfig, ServerProxyConfig,
    ShadowTlsServerHandshakeConfig, ValidatedConfigs,
};
use crate::address::NetLocation;
use crate::option_util::NoneOrSome;

pub(crate) fn tun_endpoint_ips(configs: &[Config]) -> impl Iterator<Item = IpAddr> + '_ {
    configs
        .iter()
        .filter_map(|config| match config {
            Config::TunServer(tun) => Some(tun),
            _ => None,
        })
        .flat_map(|tun| {
            [tun.address, tun.destination]
                .into_iter()
                .flatten()
                .chain(tun.addresses.iter().map(IpNetwork::ip))
                .chain(tun.virtual_dns_addresses())
        })
}

pub(crate) fn validate_tun_endpoints(
    endpoints: impl IntoIterator<Item = IpAddr>,
    pool_ranges: &[IpNetwork],
) -> io::Result<()> {
    for ip in endpoints {
        let ip = ip.to_canonical();
        for range in pool_ranges.iter().filter(|range| range.contains(ip)) {
            // base+1 must be reserved in every overlapping pool, not just one.
            let reserved = match (range.network(), ip) {
                (IpAddr::V4(base), IpAddr::V4(ip)) => {
                    u32::from(base).checked_add(1) == Some(u32::from(ip))
                }
                (IpAddr::V6(base), IpAddr::V6(ip)) => {
                    u128::from(base).checked_add(1) == Some(u128::from(ip))
                }
                _ => false,
            };
            if !reserved {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "TUN interface/gateway overlaps an active or retained fake IP pool: {ip}"
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn reject(ranges: &[IpNetwork], ip: IpAddr, label: &str) -> io::Result<()> {
    if ranges
        .iter()
        .any(|range| range.contains(ip) || range.contains(ip.to_canonical()))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} overlaps an active fake IP range or TUN endpoint: {ip}"),
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
        ServerProxyConfig::SudokuMask(config) => protocol(ranges, &config.protocol)?,
        ServerProxyConfig::Xhttp(config) => protocol(ranges, &config.protocol)?,
        _ => {}
    }
    Ok(())
}

pub(super) fn validate(config: &mut ValidatedConfigs) -> io::Result<()> {
    let pool_ranges: Result<Vec<IpNetwork>, _> = config
        .dns_groups
        .iter()
        .filter_map(|group| group.fake_ip.as_ref())
        .flat_map(|options| options.ipv4_range.iter().chain(options.ipv6_range.iter()))
        .map(|range| range.parse())
        .collect();
    let pool_ranges = pool_ranges.map_err(io::Error::other)?;
    if pool_ranges.is_empty() {
        return Ok(());
    }
    validate_tun_endpoints(tun_endpoint_ips(&config.configs), &pool_ranges)?;

    let mut forbidden = pool_ranges;
    forbidden
        .extend(tun_endpoint_ips(&config.configs).map(|ip| IpNetwork::from(ip.to_canonical())));
    config.validate_network_endpoints(&forbidden)
}

impl ValidatedConfigs {
    pub(crate) fn validate_network_endpoints(&mut self, ranges: &[IpNetwork]) -> io::Result<()> {
        if let Some(catalog) = &self.catalog {
            let urls = catalog
                .selection
                .automatic
                .0
                .values()
                .map(|group| (group.config.url.as_str(), "url-test URL"))
                .chain(
                    catalog
                        .selection
                        .health
                        .definitions
                        .values()
                        .map(|group| (group.check.url.as_str(), "fallback URL")),
                );
            for (url, label) in urls {
                let url = url::Url::parse(url).map_err(io::Error::other)?;
                let ip = match url.host() {
                    Some(url::Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
                    Some(url::Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
                    _ => None,
                };
                if let Some(ip) = ip {
                    reject(ranges, ip, label)?;
                }
            }
        }
        for config in &self.configs {
            match config {
                Config::Server(server) => {
                    rules(ranges, &server.rules)?;
                    protocol(ranges, &server.protocol)?;
                }
                Config::TunServer(tun) => {
                    rules(ranges, &tun.rules)?;
                    for endpoint in &tun.bootstrap_dns {
                        reject(ranges, endpoint.ip(), "managed bootstrap endpoint")?;
                    }
                }
                _ => {}
            }
        }
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
            if let Some(inbound) = &endpoint.inbound {
                rules(ranges, &inbound.rules)?;
            }
            for peer in &endpoint.peers {
                if let Some(address) = &peer.endpoint {
                    let address = NetLocation::from_str(address, None)?;
                    target(ranges, &address, "WireGuard endpoint")?;
                }
            }
        }
        self.visit_clients(&mut |client| target(ranges, &client.address, "proxy endpoint"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DnsConfig;

    fn validate_yaml(yaml: &str) -> io::Result<ValidatedConfigs> {
        super::super::create_server_configs(serde_yaml::from_str(yaml).map_err(io::Error::other)?)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn managed_bootstrap_rejects_active_and_retained_fake_ranges() {
        use serde_json::json;

        let ranges = [
            "198.18.0.0/15".parse().unwrap(),
            "2001:2::/48".parse().unwrap(),
        ];
        for endpoint in ["198.18.0.1:53", "198.18.0.5:53", "[2001:2::5]:53"] {
            let mut configs = json!([
                {"dns_group":"fake", "dns_servers":"system", "fake_ip":{"ipv6_range":"2001:2::/48"}},
                {"device_name":"shoes0", "auto_route":true, "auto_dns":false,
                 "addresses":["10.233.0.1/30", "fd73::1/126"], "bootstrap_dns":[endpoint]}
            ]);
            let error = validate_yaml(&configs.to_string()).err().unwrap();
            assert!(
                error.to_string().contains("managed bootstrap endpoint"),
                "{error}"
            );
            configs[0]["fake_ip"] = false.into();
            let mut validated = validate_yaml(&configs.to_string()).unwrap();
            let error = validated.validate_network_endpoints(&ranges).unwrap_err();
            assert!(
                error.to_string().contains("managed bootstrap endpoint"),
                "{error}"
            );
            validated
                .validate_network_endpoints(&["192.0.2.0/24".parse().unwrap()])
                .unwrap();
        }
    }

    #[test]
    fn automatic_probe_literals_reject_active_and_retained_custom_fake_ranges() {
        use serde_json::json;

        for kind in ["url-test", "fallback"] {
            for url in [
                "http://100.64.0.2/",
                "http://[::ffff:100.64.0.2]/",
                "http://[fd00::2]/",
            ] {
                let mut configs = json!([
                    {"dns_group":"fake", "dns_servers":"system", "fake_ip":{"ipv4_range":"100.64.0.0/10", "ipv6_range":"fd00::/64"}},
                    {"client_group":"auto", "type":"url-test", "url":url, "client_proxies":["direct"]}
                ]);
                if kind == "fallback" {
                    configs[1] = json!({"client_group":"auto", "type":"fallback",
                    "health_check":{"url":url, "interval_secs":30}, "client_proxies":["direct"]});
                }
                let label = format!("{kind} URL");
                let error = validate_yaml(&configs.to_string())
                    .err()
                    .expect("active probe range must be rejected");
                assert!(error.to_string().contains(&label), "{error}");
                configs[0]["fake_ip"] = false.into();
                let mut validated = validate_yaml(&configs.to_string()).unwrap();
                let error = validated
                    .validate_network_endpoints(&[
                        "100.64.0.0/10".parse().unwrap(),
                        "fd00::/64".parse().unwrap(),
                    ])
                    .unwrap_err();
                assert!(error.to_string().contains(&label), "{error}");
                validated
                    .validate_network_endpoints(&["192.0.2.0/24".parse().unwrap()])
                    .unwrap();
            }
        }
    }

    #[test]
    fn tun_endpoint_iteration_preserves_order_duplicates_and_address_form() {
        let configs = serde_yaml::from_str::<Vec<Config>>(
            r#"
- device_name: first
  address: '::ffff:198.18.0.1'
  destination: '198.18.0.2'
- address: '127.0.0.1:1080'
  protocol: {type: socks}
- device_name: second
  destination: '198.18.0.2'
- device_name: third
  address: '2001:db8::1'
"#,
        )
        .unwrap();
        let expected: Vec<IpAddr> = [
            "::ffff:198.18.0.1",
            "198.18.0.2",
            "198.18.0.2",
            "2001:db8::1",
        ]
        .into_iter()
        .map(|ip| ip.parse().unwrap())
        .collect();
        assert_eq!(tun_endpoint_ips(&configs).collect::<Vec<_>>(), expected);
    }

    #[test]
    fn tun_endpoints_reject_every_active_pool_regardless_of_selected_context() {
        use serde_json::json;

        for field in ["address", "destination"] {
            for (ip, allowed) in [
                ("198.18.0.5", false),
                ("::ffff:198.18.0.5", false),
                ("2001:2::5", false),
                ("198.18.0.1", true),
                ("::ffff:198.18.0.1", true),
                ("2001:2::1", true),
                ("10.99.0.1", true),
            ] {
                for dns in [None, Some("fake"), Some("other")] {
                    let mut tun = json!({"device_name":"tun0", "device_fd":42});
                    tun[field] = ip.into();
                    if let Some(dns) = dns {
                        tun["dns"] = json!({"servers":dns});
                    }
                    let configs = json!([
                        {"dns_group":"fake", "dns_servers":"udp://127.0.0.1:9", "fake_ip":{
                            "ipv4_range":"198.18.0.0/29", "ipv6_range":"2001:2::/125", "max_entries":5
                        }},
                        {"dns_group":"other", "dns_servers":"udp://127.0.0.1:9", "fake_ip":{
                            "ipv4_range":"198.19.0.0/29", "max_entries":5
                        }},
                        tun,
                    ]);
                    let result = validate_yaml(&configs.to_string());
                    if allowed {
                        result.unwrap();
                    } else {
                        let error = result.err().expect("allocatable TUN endpoint accepted");
                        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
                        assert!(
                            error.to_string().contains("TUN interface/gateway"),
                            "{error}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn tun_reserved_endpoint_must_be_reserved_in_every_overlapping_pool() {
        for (wide, narrow, ip) in [
            ("198.18.0.0/28", "198.18.0.8/29", "198.18.0.9"),
            ("2001:2::/124", "2001:2::8/125", "2001:2::9"),
        ] {
            let field = if ip.contains(':') {
                "ipv6_range"
            } else {
                "ipv4_range"
            };
            let configs = serde_json::json!([
                {"dns_group":"wide", "dns_servers":"udp://127.0.0.1:9", "fake_ip":{field:wide, "max_entries":5}},
                {"dns_group":"narrow", "dns_servers":"udp://127.0.0.1:9", "fake_ip":{field:narrow, "max_entries":5}},
                {"device_name":"tun0", "device_fd":42, "address":ip, "dns":{"servers":"narrow"}},
            ]);
            let error = validate_yaml(&configs.to_string()).err().unwrap();
            assert!(
                error.to_string().contains("TUN interface/gateway"),
                "{error}"
            );
        }
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
    fn private_identities_remain_group_references_with_url_like_paths_and_names() {
        let mut names = std::collections::HashSet::new();
        for fake_ip in [true, false] {
            for path in [
                "//tmp/shoes.sock",
                "/tmp/region://shoes.sock",
                "/tmp/%2F.sock",
            ] {
                let configs = validate_yaml(&format!(
                    "- path: '{path}'\n  protocol: {{type: http}}\n  dns: {{fake_ip: {fake_ip}}}\n"
                ))
                .unwrap();
                let Config::Server(server) = &configs.configs[0] else {
                    panic!()
                };
                let group = server.dns.as_ref().unwrap().resolved_group().unwrap();
                assert_eq!(group, configs.dns_groups[0].name);
                if fake_ip {
                    assert!(names.insert(group.to_owned()));
                } else {
                    assert!(names.contains(group));
                }
            }
            let configs = validate_yaml(&format!(
                "- device_name: 'tun://edge'\n  device_fd: 42\n  dns: {{fake_ip: {fake_ip}}}\n"
            ))
            .unwrap();
            let Config::TunServer(tun) = &configs.configs[0] else {
                panic!()
            };
            let group = tun.dns.as_ref().unwrap().resolved_group().unwrap();
            assert_eq!(group, configs.dns_groups[0].name);
            if fake_ip {
                assert!(names.insert(group.to_owned()));
            } else {
                assert!(names.contains(group));
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_socket_identities_preserve_non_utf8_path_bytes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let mut configs: Vec<Config> = serde_yaml::from_str(
            "- path: /tmp/first.sock\n  protocol: {type: http}\n  dns: {fake_ip: true}\n\
             - path: /tmp/second.sock\n  protocol: {type: http}\n  dns: {fake_ip: true}\n",
        )
        .unwrap();
        for (config, byte) in configs.iter_mut().zip([0xfe, 0xff]) {
            let Config::Server(server) = config else {
                panic!()
            };
            let mut path = b"/tmp/shoes-".to_vec();
            path.push(byte);
            server.bind_location =
                super::super::BindLocation::Path(OsString::from_vec(path).into());
        }
        let configs = super::super::create_server_configs(configs).unwrap();
        assert_eq!(configs.dns_groups.len(), 2);
        assert_ne!(configs.dns_groups[0].name, configs.dns_groups[1].name);
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
    fn server_owned_destinations_reject_all_active_fake_ranges() {
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
                    assert!(validate_yaml(&config.to_string()).is_err());
                    config[1]["dns"] = json!({"servers":"system"});
                    assert!(validate_yaml(&config.to_string()).is_err());
                    config[1].as_object_mut().unwrap().remove("dns");
                    assert!(validate_yaml(&config.to_string()).is_err());
                    config[0]["fake_ip"] = false.into();
                    validate_yaml(&config.to_string()).unwrap();
                }
            }
        }
    }

    #[test]
    fn rule_overrides_reject_all_active_and_retained_fake_ranges() {
        use serde_json::json;

        for address in [
            "198.18.0.5:443",
            "[::ffff:198.18.0.5]:443",
            "[2001:2::5]:443",
        ] {
            let rules =
                json!([{"masks":"0.0.0.0/0", "action":"allow", "override_address":address}]);
            for inbound in [
                json!({"address":"127.0.0.1:1080", "protocol":{"type":"socks"}, "rules":rules}),
                json!({"device_name":"tun0", "device_fd":42, "rules":rules}),
                json!({"address":"127.0.0.1:1080", "protocol":{"type":"websocket", "targets":[{
                    "protocol":{"type":"socks"}, "override_rules":rules
                }]}}),
            ] {
                let mut configs = json!([
                    {"dns_group":"fake", "dns_servers":"system", "fake_ip":{"ipv6_range":"2001:2::/48"}},
                    inbound,
                ]);
                let error = validate_yaml(&configs.to_string()).err().unwrap();
                assert!(error.to_string().contains("rule override"), "{error}");
                configs[0]["fake_ip"] = false.into();
                let mut validated = validate_yaml(&configs.to_string()).unwrap();
                let error = validated
                    .validate_network_endpoints(&[
                        "198.18.0.0/15".parse().unwrap(),
                        "2001:2::/48".parse().unwrap(),
                    ])
                    .unwrap_err();
                assert!(error.to_string().contains("rule override"), "{error}");
            }
        }
    }
}
