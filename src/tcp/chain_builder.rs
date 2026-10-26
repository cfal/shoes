//! Builder functions for creating ClientProxyChain from config.

use std::sync::Arc;

use crate::client_proxy_chain::{ClientChainGroup, ClientProxyChain, InitialHopEntry};
use crate::config::ConfigSelection;
use crate::config::{ClientChainHop, ClientConfig};
use crate::resolver::Resolver;
use crate::tcp::proxy_connector::ProxyConnector;
use crate::tcp::proxy_connector_impl::ProxyConnectorImpl;
use crate::tcp::socket_connector::SocketConnector;
use crate::tcp::socket_connector_impl::SocketConnectorImpl;

/// Checks the final hop without creating sockets or resolving addresses.
pub(crate) fn supports_udp_offline(chain: &crate::config::ClientChain) -> std::io::Result<bool> {
    let Some(hop) = chain.hops.iter().last() else {
        return Ok(false);
    };
    let selections: Box<dyn Iterator<Item = &ConfigSelection<ClientConfig>>> = match hop {
        ClientChainHop::Single(selection) => Box::new(std::iter::once(selection)),
        ClientChainHop::Pool(selections) => selections.iter(),
    };
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    let mut supports_udp = false;
    for selection in selections {
        let ConfigSelection::Config(config) = selection else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Client chain groups must be expanded before checking UDP capability",
            ));
        };
        supports_udp |= config.protocol.is_direct()
            || config.protocol.is_wireguard()
            || ProxyConnectorImpl::from_config(config.clone(), resolver.clone())?
                .is_some_and(|proxy| proxy.supports_udp_over_tcp());
    }
    Ok(supports_udp)
}

/// Build a ClientProxyChain from a client_chain configuration.
///
/// Creates InitialHopEntry (socket + optional proxy paired) from hop 0.
/// Creates ProxyConnectors for subsequent hops (1+).
/// `protocol: direct` at hop 0 creates InitialHopEntry::Direct.
#[cfg(test)]
pub fn build_client_proxy_chain(
    client_chain: crate::option_util::OneOrSome<ClientChainHop>,
    resolver: Arc<dyn Resolver>,
) -> ClientProxyChain {
    try_build_client_proxy_chain(client_chain, resolver).expect("Failed to create client chain")
}

pub fn try_build_client_proxy_chain(
    client_chain: crate::option_util::OneOrSome<ClientChainHop>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<ClientProxyChain> {
    build_client_proxy_chain_with_limits(client_chain, resolver, crate::resources::limits())
}

pub(crate) fn build_client_proxy_chain_with_limits(
    client_chain: crate::option_util::OneOrSome<ClientChainHop>,
    resolver: Arc<dyn Resolver>,
    limits: crate::config::GlobalLimits,
) -> std::io::Result<ClientProxyChain> {
    let hops: Vec<Vec<ClientConfig>> = client_chain
        .into_vec()
        .into_iter()
        .map(|hop| {
            let selections = match hop {
                ClientChainHop::Single(selection) => vec![selection],
                ClientChainHop::Pool(selections) => selections.into_vec(),
            };
            selections
                .into_iter()
                .map(|selection| match selection {
                    ConfigSelection::Config(config) => Ok(config),
                    ConfigSelection::GroupName(group_name) => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "Group reference '{group_name}' was not resolved during config validation."
                        ),
                    )),
                })
                .collect::<std::io::Result<_>>()
        })
        .collect::<std::io::Result<_>>()?;

    if hops.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Client chain must have at least one hop",
        ));
    }

    for (index, configs) in hops.iter().enumerate() {
        for config in configs {
            config.validate_quic_key_exchange(index == 0)?;
        }
    }
    crate::config::health::validate_chain(hops.iter().map(|hop| hop.iter()))?;
    let health_hops = if hops.iter().flatten().any(|client| {
        client
            .control
            .as_ref()
            .is_some_and(crate::control::catalog::MemberOrigin::has_fallback)
    }) {
        use crate::control::health::MAX_PATHS;
        // Administrative targets can bypass config-time chain expansion limits.
        let size = hops
            .iter()
            .try_fold(1usize, |size, pool| size.checked_mul(pool.len()))
            .filter(|size| *size <= MAX_PATHS)
            .ok_or_else(|| {
                crate::control::health::capacity_error(format!(
                    "fallback exceeds {MAX_PATHS} concrete chain paths"
                ))
            })?;
        Some((hops.clone(), size))
    } else {
        None
    };

    // Build initial hop entries from hop 0.
    // Each entry pairs socket + optional proxy together to ensure atomic selection.
    let initial_hop: Vec<InitialHopEntry> = hops[0]
        .iter()
        .map(|config| {
            if let crate::config::ClientProxyConfig::Wireguard(reference) = &config.protocol {
                let connector = reference.connector.clone().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotConnected,
                        "WireGuard endpoint registry has not been prepared",
                    )
                })?;
                return Ok(InitialHopEntry::Wireguard(connector));
            }
            // Find the first proxy address for QUIC socket configuration
            let target_address = find_first_proxy_address(&hops, config);

            let socket =
                SocketConnectorImpl::from_config_with_limits(config, target_address, limits)
                    .map(|s| Arc::new(s) as Arc<dyn SocketConnector>)?;

            if config.protocol.is_direct() {
                // Direct: socket only, no proxy
                Ok(InitialHopEntry::Direct(socket))
            } else {
                // Proxy: socket + proxy paired
                let proxy = ProxyConnectorImpl::from_config(config.clone(), resolver.clone())?
                    .map(|p| Box::new(p) as Box<dyn ProxyConnector>)
                    .ok_or_else(|| {
                        std::io::Error::other(
                            "Missing proxy connector for non-direct configuration",
                        )
                    })?;
                Ok(InitialHopEntry::Proxy { socket, proxy })
            }
        })
        .collect::<std::io::Result<_>>()?;

    // Build proxy connectors for subsequent hops (1+)
    let origins = hops
        .iter()
        .map(|pool| pool.iter().map(|client| client.control.clone()).collect())
        .collect();
    let subsequent_hops: Vec<Vec<Box<dyn ProxyConnector>>> = hops
        .into_iter()
        .skip(1) // Skip hop 0, already processed as initial_hop
        .enumerate()
        .map(|(hop_offset, hop_configs)| {
            let hop_index = hop_offset + 1; // Actual hop index for error messages
            hop_configs
                .into_iter()
                .map(|config| {
                    if config.transport == crate::config::Transport::Quic && crate::xhttp::connector::contains(&config.protocol) {
                        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "XHTTP H3 is only supported at hop 0"));
                    }
                    // Subsequent hops MUST NOT have direct protocol
                    if config.protocol.is_direct() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "protocol: direct is only valid at hop 0. Found direct at hop {} with address {}",
                                hop_index, config.address
                            ),
                        ));
                    }

                    ProxyConnectorImpl::from_config(config, resolver.clone())?
                        .map(|p| Box::new(p) as Box<dyn ProxyConnector>)
                        .ok_or_else(|| std::io::Error::other("Missing proxy connector for subsequent hop"))
                })
                .collect::<std::io::Result<_>>()
        })
        .collect::<std::io::Result<_>>()?;

    let chain = ClientProxyChain::new(initial_hop, subsequent_hops).with_origins(origins);
    match health_hops {
        Some((hops, size)) => chain.with_health(&hops, size, resolver),
        None => Ok(chain),
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
    try_build_client_chain_group(client_chains, resolver)
        .expect("Failed to create client chain group")
}

pub fn try_build_client_chain_group(
    client_chains: crate::option_util::NoneOrSome<crate::config::ClientChain>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<ClientChainGroup> {
    build_client_chain_group_with_limits(client_chains, resolver, crate::resources::limits())
}

pub fn build_client_chain_group_with_limits(
    client_chains: crate::option_util::NoneOrSome<crate::config::ClientChain>,
    resolver: Arc<dyn Resolver>,
    limits: crate::config::GlobalLimits,
) -> std::io::Result<ClientChainGroup> {
    let chains: Vec<ClientProxyChain> = if client_chains.is_empty() {
        vec![build_client_proxy_chain_with_limits(
            crate::option_util::OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                ClientConfig::default(),
            ))),
            resolver,
            limits,
        )?]
    } else {
        client_chains
            .into_vec()
            .into_iter()
            .map(|chain| build_client_proxy_chain_with_limits(chain.hops, resolver.clone(), limits))
            .collect::<std::io::Result<_>>()?
    };

    Ok(ClientChainGroup::new(chains))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::NetLocation;
    use crate::config::{ClientChain, ClientProxyConfig};
    use crate::option_util::{NoneOrSome, OneOrSome};
    use crate::resolver::NativeResolver;
    use std::net::{IpAddr, Ipv4Addr};

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn socket_initialization_failure_is_returned() {
        let config: ClientConfig = serde_yaml::from_str("address: '127.0.0.1:443'\ntransport: quic\nbind_interface: shoes-missing-interface\nprotocol: {type: socks}\n").unwrap();
        let result = try_build_client_proxy_chain(
            OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(config))),
            mock_resolver(),
        );
        assert!(result.is_err());
    }

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
    fn offline_udp_capability_matches_wrappers_pools_and_runtime_handlers() {
        for (protocol, expected) in [
            ("{type: direct}", true),
            ("{type: socks}", false),
            ("{type: trojan, password: test}", false),
            ("{type: trojan, password: test, h2mux: {}}", true),
            (
                "{type: vless, user_id: b85798ef-e9dc-46a4-9a87-8da4499d36d0, udp_enabled: false}",
                false,
            ),
            (
                "{type: websocket, protocol: {type: vless, user_id: b85798ef-e9dc-46a4-9a87-8da4499d36d0}}",
                true,
            ),
        ] {
            let config: ClientConfig = serde_yaml::from_str(&format!(
                "{{address: 'unresolvable.invalid:443', protocol: {protocol}}}"
            ))
            .unwrap();
            let chain = ClientChain {
                hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                    config.clone(),
                ))),
            };
            assert_eq!(supports_udp_offline(&chain).unwrap(), expected);
            let runtime =
                try_build_client_proxy_chain(chain.hops.clone(), mock_resolver()).unwrap();
            assert_eq!(runtime.supports_udp(), expected);
            let pool = ClientChain {
                hops: OneOrSome::One(ClientChainHop::Pool(OneOrSome::Some(vec![
                    ConfigSelection::Config(socks_config(1080)),
                    ConfigSelection::Config(config),
                ]))),
            };
            assert_eq!(supports_udp_offline(&pool).unwrap(), expected);
        }
    }

    #[test]
    fn quic_allowlists_fail_before_ignored_transport_construction() {
        for groups in [None, Some("X25519MLKEM768"), Some("X25519")] {
            let field = groups
                .map(|g| format!("key_exchange_groups: [{g}]"))
                .unwrap_or_default();
            let direct: ClientConfig = serde_yaml::from_str(&format!(
                "protocol: {{type: direct}}\ntransport: quic\nquic_settings: {{{field}}}\n"
            ))
            .unwrap();
            assert_eq!(
                SocketConnectorImpl::from_config(&direct, None).is_err(),
                groups.is_some()
            );
            let direct_chain =
                OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(direct)));
            assert_eq!(
                try_build_client_proxy_chain(direct_chain, mock_resolver()).is_err(),
                groups.is_some()
            );

            let proxy: ClientConfig = serde_yaml::from_str(&format!(
                "address: '127.0.0.1:443'\nprotocol: {{type: socks}}\ntransport: quic\nquic_settings: {{{field}}}\n"
            )).unwrap();
            for hop in [
                ClientChainHop::Single(ConfigSelection::Config(proxy.clone())),
                ClientChainHop::Pool(OneOrSome::Some(vec![
                    ConfigSelection::Config(socks_config(1080)),
                    ConfigSelection::Config(proxy),
                ])),
            ] {
                let chain = OneOrSome::Some(vec![
                    ClientChainHop::Single(ConfigSelection::Config(direct_config())),
                    hop,
                ]);
                let result = try_build_client_proxy_chain(chain, mock_resolver());
                assert_eq!(result.is_err(), groups.is_some());
                if let Err(error) = result {
                    assert!(error.to_string().contains("QUIC key_exchange_groups"));
                }
            }
        }
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
    fn test_direct_at_hop1_returns_error() {
        let result = try_build_client_proxy_chain(
            OneOrSome::Some(vec![
                ClientChainHop::Single(ConfigSelection::Config(socks_config(1080))),
                ClientChainHop::Single(ConfigSelection::Config(direct_config())),
            ]),
            mock_resolver(),
        );
        assert_eq!(
            result.err().unwrap().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn test_direct_in_pool_at_hop1_returns_error() {
        let result = try_build_client_proxy_chain(
            OneOrSome::Some(vec![
                ClientChainHop::Single(ConfigSelection::Config(socks_config(1080))),
                ClientChainHop::Pool(OneOrSome::Some(vec![
                    ConfigSelection::Config(socks_config(1081)),
                    ConfigSelection::Config(direct_config()),
                ])),
            ]),
            mock_resolver(),
        );
        assert_eq!(
            result.err().unwrap().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn test_empty_chain_returns_error() {
        let result = try_build_client_proxy_chain(OneOrSome::Some(vec![]), mock_resolver());
        assert_eq!(
            result.err().unwrap().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn test_unresolved_group_reference_returns_error() {
        let selection = ConfigSelection::GroupName("unresolved_group".to_string());
        for hop in [
            ClientChainHop::Single(selection.clone()),
            ClientChainHop::Pool(OneOrSome::One(selection)),
        ] {
            let result = try_build_client_proxy_chain(OneOrSome::One(hop), mock_resolver());
            assert_eq!(
                result.err().unwrap().kind(),
                std::io::ErrorKind::InvalidInput
            );
        }
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
}
