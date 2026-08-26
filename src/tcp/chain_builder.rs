//! Builder functions for creating ClientProxyChain from config.

use std::sync::Arc;

use crate::client_proxy_chain::{ClientChainGroup, ClientProxyChain, InitialHopEntry};
use crate::config::ConfigSelection;
use crate::config::{ClientChainHop, ClientConfig, ClientProxyConfig};
use crate::quic_transport::build_obfuscator;
use crate::resolver::Resolver;
use crate::tcp::proxy_connector::ProxyConnector;
use crate::tcp::proxy_connector_impl::ProxyConnectorImpl;
use crate::tcp::socket_connector::SocketConnector;
use crate::tcp::socket_connector_impl::SocketConnectorImpl;
use crate::tcp::terminal_connector::TerminalConnector;

/// Build a ClientProxyChain from a client_chain configuration.
///
/// Creates InitialHopEntry (socket + optional proxy paired) from hop 0.
/// Creates ProxyConnectors for subsequent hops (1+).
/// `protocol: direct` at hop 0 creates InitialHopEntry::Direct.
pub fn build_client_proxy_chain(
    client_chain: crate::option_util::OneOrSome<ClientChainHop>,
    resolver: Arc<dyn Resolver>,
) -> ClientProxyChain {
    let hops: Vec<Vec<ClientConfig>> = client_chain
        .into_vec()
        .into_iter()
        .map(|hop| match hop {
            ClientChainHop::Single(selection) => match selection {
                ConfigSelection::Config(config) => vec![config],
                ConfigSelection::GroupName(group_name) => {
                    panic!(
                        "Group reference '{}' was not resolved during config validation.",
                        group_name
                    );
                }
            },
            ClientChainHop::Pool(selections) => selections
                .into_vec()
                .into_iter()
                .flat_map(|selection| match selection {
                    ConfigSelection::Config(config) => vec![config],
                    ConfigSelection::GroupName(group_name) => {
                        panic!(
                            "Group reference '{}' was not resolved during config validation.",
                            group_name
                        );
                    }
                })
                .collect(),
        })
        .collect();

    if hops.is_empty() {
        panic!("Client chain must have at least one hop");
    }

    // Same shape as `hops`, so a pool index selects the same member in both.
    // register() only fails on what validation already rejected -- a blank
    // name, or one name on two addresses -- so a failure here is a bug.
    #[cfg(feature = "control-stats")]
    let hop_counters: Vec<Vec<Arc<crate::outbound_stats::OutboundCounters>>> = hops
        .iter()
        .map(|pool| {
            pool.iter()
                .map(|config| {
                    crate::outbound_stats::register(
                        &config.stats_key().expect("validated config"),
                        &config.address.to_string(),
                    )
                    .expect("validated config")
                })
                .collect()
        })
        .collect();

    // Protocols that own their transport (WireGuard/AmneziaWG) cannot be
    // wrapped by another proxy, so they must be the only hop. Validation
    // enforces that, and that a pool at that hop is homogeneous.
    if hops.len() == 1 && hops[0].iter().all(|c| c.protocol.owns_transport()) {
        let connectors = hops
            .into_iter()
            .next()
            .unwrap()
            .into_iter()
            .map(build_terminal_connector)
            .collect();
        let chain = ClientProxyChain::new_terminal(connectors);
        #[cfg(feature = "control-stats")]
        let chain =
            chain.with_terminal_counters(hop_counters.into_iter().next().expect("one hop"));
        return chain;
    }

    // Build initial hop entries from hop 0.
    // Each entry pairs socket + optional proxy together to ensure atomic selection.
    let initial_hop: Vec<InitialHopEntry> = hops[0]
        .iter()
        .map(|config| {
            // Find the first proxy address for QUIC socket configuration
            let target_address = find_first_proxy_address(&hops, config);

            let socket = SocketConnectorImpl::from_config(config, target_address)
                .map(|s| Box::new(s) as Box<dyn SocketConnector>)
                .expect("Failed to create SocketConnector");

            if config.protocol.is_direct() {
                // Direct: socket only, no proxy
                InitialHopEntry::Direct(socket)
            } else {
                // Proxy: socket + proxy paired
                let proxy = ProxyConnectorImpl::from_config(config.clone(), resolver.clone())
                    .map(|p| Box::new(p) as Box<dyn ProxyConnector>)
                    .expect("Failed to create ProxyConnector for non-direct config");
                InitialHopEntry::Proxy { socket, proxy }
            }
        })
        .collect();

    // Build proxy connectors for subsequent hops (1+)
    let subsequent_hops: Vec<Vec<Box<dyn ProxyConnector>>> = hops
        .into_iter()
        .skip(1) // Skip hop 0, already processed as initial_hop
        .enumerate()
        .map(|(hop_offset, hop_configs)| {
            let hop_index = hop_offset + 1; // Actual hop index for error messages
            hop_configs
                .into_iter()
                .map(|config| {
                    // Subsequent hops MUST NOT have direct protocol
                    if config.protocol.is_direct() {
                        panic!(
                            "protocol: direct is only valid at hop 0. Found direct at hop {} with address {}",
                            hop_index,
                            config.address
                        );
                    }

                    ProxyConnectorImpl::from_config(config, resolver.clone())
                        .map(|p| Box::new(p) as Box<dyn ProxyConnector>)
                        .expect("Failed to create ProxyConnector for subsequent hop")
                })
                .collect()
        })
        .collect();

    let chain = ClientProxyChain::new(initial_hop, subsequent_hops);
    #[cfg(feature = "control-stats")]
    let chain = {
        let mut counters = hop_counters.into_iter();
        let initial = counters.next().expect("at least one hop");
        chain.with_counters(initial, counters.collect())
    };
    chain
}

/// Build a connector for a protocol that owns its transport.
///
/// Every variant here is one `owns_transport` reports, and config validation
/// has already rejected the settings that do not apply to it.
fn build_terminal_connector(config: ClientConfig) -> Arc<dyn TerminalConnector> {
    match config.protocol {
        ClientProxyConfig::Hysteria2(hysteria2) => {
            let obfs = build_obfuscator(hysteria2.obfs.as_ref())
                .expect("obfuscation settings were validated during config load");
            let port_hopping = hysteria2.port_hopping.as_ref().map(|hopping| {
                crate::quic_transport::hop::HopSettings::new(
                    &hopping.ports,
                    hopping.interval_ms,
                    hopping.min_interval_ms,
                    hopping.max_interval_ms,
                )
                .expect("port hopping settings were validated during config load")
            });
            Arc::new(crate::hysteria2::Hysteria2Connector::new(
                config.address,
                hysteria2.password.into_inner(),
                hysteria2.udp_enabled,
                config.quic_settings.unwrap_or_default(),
                config.bind_interface.into_option(),
                obfs,
                port_hopping,
            ))
        }
        ClientProxyConfig::Tuic(tuic) => Arc::new(
            crate::tuic::TuicConnector::new(
                config.address,
                &tuic.uuid,
                tuic.password.into_inner(),
                tuic.udp_enabled,
                tuic.udp_relay_mode,
                std::time::Duration::from_millis(tuic.heartbeat_ms),
                config.quic_settings.unwrap_or_default(),
                config.bind_interface.into_option(),
            )
            .expect("the uuid was validated during config load"),
        ),
        protocol => {
            let connector =
                crate::amneziawg::AmneziaWgConnector::from_client_config(protocol, config.address)
                    .expect("config validation should have ensured a tunnel variant");
            Arc::new(connector)
        }
    }
}

/// Find the first proxy address in the chain (for socket connector target).
fn find_first_proxy_address<'a>(
    hops: &'a [Vec<ClientConfig>],
    current_config: &'a ClientConfig,
) -> Option<&'a crate::address::NetLocation> {
    // If current config is a proxy, use its address
    if !current_config.protocol.is_direct() {
        return Some(&current_config.address);
    }

    // Otherwise, look at subsequent hops
    for hop in hops.iter().skip(1) {
        for config in hop {
            if !config.protocol.is_direct() {
                return Some(&config.address);
            }
        }
    }

    None
}

/// Build a "direct" ClientChainGroup (no proxy, just socket connection).
/// Uses the same pattern as build_client_chain_group with no chains configured.
pub fn build_direct_chain_group(resolver: Arc<dyn Resolver>) -> ClientChainGroup {
    build_client_chain_group(crate::option_util::NoneOrSome::None, resolver)
}

/// Build a ClientChainGroup from config chains.
pub fn build_client_chain_group(
    client_chains: crate::option_util::NoneOrSome<crate::config::ClientChain>,
    resolver: Arc<dyn Resolver>,
) -> ClientChainGroup {
    let chains: Vec<ClientProxyChain> = if client_chains.is_empty() {
        vec![build_client_proxy_chain(
            crate::option_util::OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                ClientConfig::default(),
            ))),
            resolver,
        )]
    } else {
        client_chains
            .into_vec()
            .into_iter()
            .map(|chain| build_client_proxy_chain(chain.hops, resolver.clone()))
            .collect()
    };

    ClientChainGroup::new(chains)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::NetLocation;
    use crate::config::{ClientChain, ClientProxyConfig};
    use crate::option_util::{NoneOrSome, OneOrSome};
    use crate::resolver::NativeResolver;
    use std::net::{IpAddr, Ipv4Addr};

    fn mock_resolver() -> Arc<dyn Resolver> {
        Arc::new(NativeResolver::new())
    }

    fn socks_config(port: u16) -> ClientConfig {
        ClientConfig {
            address: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
            protocol: ClientProxyConfig::Socks {
                username: None,
                password: None,
            },
            ..Default::default()
        }
    }

    fn direct_config() -> ClientConfig {
        ClientConfig::default()
    }

    #[test]
    fn test_build_single_direct_hop() {
        let chain = build_client_proxy_chain(
            OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                direct_config(),
            ))),
            mock_resolver(),
        );

        // Direct creates 1 socket connector, 0 proxy connectors
        assert_eq!(chain.num_hops(), 1);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_build_single_proxy_hop() {
        let chain = build_client_proxy_chain(
            OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                socks_config(1080),
            ))),
            mock_resolver(),
        );

        // Single proxy creates 1 socket connector, 1 proxy connector
        assert_eq!(chain.num_hops(), 1);
    }

    #[test]
    fn test_build_direct_then_proxy_chain() {
        let chain = build_client_proxy_chain(
            OneOrSome::Some(vec![
                ClientChainHop::Single(ConfigSelection::Config(direct_config())),
                ClientChainHop::Single(ConfigSelection::Config(socks_config(1080))),
            ]),
            mock_resolver(),
        );

        // direct (hop 0) -> socks (hop 1)
        // InitialHopEntry::Direct + 1 subsequent hop = 2 hops total
        assert_eq!(chain.num_hops(), 2);
    }

    #[test]
    fn test_build_two_proxy_hops() {
        let chain = build_client_proxy_chain(
            OneOrSome::Some(vec![
                ClientChainHop::Single(ConfigSelection::Config(socks_config(1080))),
                ClientChainHop::Single(ConfigSelection::Config(socks_config(1081))),
            ]),
            mock_resolver(),
        );

        // socks1 (hop 0) -> socks2 (hop 1)
        assert_eq!(chain.num_hops(), 2);
    }

    #[test]
    fn test_build_pool_at_hop0() {
        let chain = build_client_proxy_chain(
            OneOrSome::One(ClientChainHop::Pool(OneOrSome::Some(vec![
                ConfigSelection::Config(socks_config(1080)),
                ConfigSelection::Config(socks_config(1081)),
            ]))),
            mock_resolver(),
        );

        // Pool of 2 proxies at hop 0
        assert_eq!(chain.num_hops(), 1);
    }

    #[test]
    fn test_build_empty_client_chains_creates_default() {
        let group = build_client_chain_group(NoneOrSome::None, mock_resolver());
        // Default is a single direct chain
        assert!(group.supports_udp());
    }

    #[test]
    fn test_build_client_chain_group_with_chains() {
        let chains = NoneOrSome::Some(vec![
            ClientChain {
                hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                    socks_config(1080),
                ))),
            },
            ClientChain {
                hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                    direct_config(),
                ))),
            },
        ]);
        let group = build_client_chain_group(chains, mock_resolver());
        // 2 chains in group
        assert!(group.supports_udp()); // direct chain supports UDP
    }

    #[test]
    #[should_panic(expected = "protocol: direct is only valid at hop 0")]
    fn test_direct_at_hop1_panics() {
        build_client_proxy_chain(
            OneOrSome::Some(vec![
                ClientChainHop::Single(ConfigSelection::Config(socks_config(1080))),
                ClientChainHop::Single(ConfigSelection::Config(direct_config())),
            ]),
            mock_resolver(),
        );
    }

    #[test]
    #[should_panic(expected = "protocol: direct is only valid at hop 0")]
    fn test_direct_in_pool_at_hop1_panics() {
        build_client_proxy_chain(
            OneOrSome::Some(vec![
                ClientChainHop::Single(ConfigSelection::Config(socks_config(1080))),
                ClientChainHop::Pool(OneOrSome::Some(vec![
                    ConfigSelection::Config(socks_config(1081)),
                    ConfigSelection::Config(direct_config()),
                ])),
            ]),
            mock_resolver(),
        );
    }

    #[test]
    #[should_panic(expected = "was not resolved during config validation")]
    fn test_unresolved_group_reference_panics() {
        build_client_proxy_chain(
            OneOrSome::One(ClientChainHop::Single(ConfigSelection::GroupName(
                "unresolved_group".to_string(),
            ))),
            mock_resolver(),
        );
    }

    #[test]
    fn test_find_first_proxy_address_direct_only() {
        let direct = direct_config();
        let hops = vec![vec![direct.clone()]];
        assert!(find_first_proxy_address(&hops, &direct).is_none());
    }

    #[test]
    fn test_find_first_proxy_address_proxy_at_hop0() {
        let proxy = socks_config(1080);
        let hops = vec![vec![proxy.clone()]];
        let addr = find_first_proxy_address(&hops, &proxy);
        assert!(addr.is_some());
        assert_eq!(addr.unwrap().port(), 1080);
    }

    #[test]
    fn test_find_first_proxy_address_proxy_at_hop1() {
        let direct = direct_config();
        let proxy = socks_config(1080);
        let hops = vec![vec![direct.clone()], vec![proxy.clone()]];
        let addr = find_first_proxy_address(&hops, &direct);
        assert!(addr.is_some());
        assert_eq!(addr.unwrap().port(), 1080);
    }

    fn wireguard_config(port: u16) -> ClientConfig {
        use crate::config::WireGuardClientConfig;
        ClientConfig {
            address: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
            protocol: ClientProxyConfig::Wireguard(Box::new(WireGuardClientConfig {
                private_key: "cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MTI=".into(),
                peer_public_key: "cHVibGlja2V5cHVibGlja2V5cHVibGlja2V5MTIzNDU=".to_string(),
                preshared_key: None,
                local_addresses: OneOrSome::One("10.0.0.2/32".to_string()),
                allowed_ips: OneOrSome::One("0.0.0.0/0".to_string()),
                persistent_keepalive: None,
                mtu: 1280,
            })),
            ..Default::default()
        }
    }

    #[test]
    fn test_build_pool_of_tunnels_does_not_panic() {
        let chain = build_client_proxy_chain(
            OneOrSome::One(ClientChainHop::Pool(OneOrSome::Some(vec![
                ConfigSelection::Config(wireguard_config(51820)),
                ConfigSelection::Config(wireguard_config(51821)),
            ]))),
            mock_resolver(),
        );
        assert_eq!(chain.num_hops(), 1);
        assert!(chain.supports_udp());
    }

    #[cfg(feature = "control-stats")]
    #[test]
    fn the_built_chain_registers_the_configured_names() {
        let _guard = crate::outbound_stats::REGISTRY_TEST_LOCK.lock().unwrap();
        crate::outbound_stats::reset_for_test();

        let mut relay = socks_config(1080);
        relay.name = Some("relay".to_string());
        let mut exit = socks_config(1081);
        exit.name = Some("exit".to_string());

        let _chain = build_client_proxy_chain(
            OneOrSome::Some(vec![
                ClientChainHop::Single(ConfigSelection::Config(relay)),
                ClientChainHop::Single(ConfigSelection::Config(exit)),
            ]),
            mock_resolver(),
        );

        let names: Vec<String> = crate::outbound_stats::snapshot_all()
            .into_iter()
            .map(|o| o.name)
            .collect();
        assert!(names.contains(&"relay".to_string()), "got {names:?}");
        assert!(names.contains(&"exit".to_string()), "got {names:?}");
    }
}
