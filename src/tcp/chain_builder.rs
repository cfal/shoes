//! Builder functions for creating ClientProxyChain from config.

use crate::client_proxy_chain::{ClientChainGroup, ClientProxyChain, InitialHopEntry};
use crate::config::ConfigSelection;
use crate::config::{ClientChainHop, ClientConfig};
use crate::tcp::proxy_connector::ProxyConnector;
use crate::tcp::proxy_connector_impl::ProxyConnectorImpl;
use crate::tcp::socket_connector::SocketConnector;
use crate::tcp::socket_connector_impl::SocketConnectorImpl;

/// Build a ClientProxyChain from a client_chain configuration.
///
/// Creates InitialHopEntry (socket + optional proxy paired) from hop 0.
/// Creates ProxyConnectors for subsequent hops (1+).
/// `protocol: direct` at hop 0 creates InitialHopEntry::Direct.
pub fn build_client_proxy_chain(
    client_chain: crate::option_util::OneOrSome<ClientChainHop>,
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
                let proxy = ProxyConnectorImpl::from_config(config.clone())
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

                    ProxyConnectorImpl::from_config(config)
                        .map(|p| Box::new(p) as Box<dyn ProxyConnector>)
                        .expect("Failed to create ProxyConnector for subsequent hop")
                })
                .collect()
        })
        .collect();

    ClientProxyChain::new(initial_hop, subsequent_hops)
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

/// Build a ClientChainGroup from config chains.
pub fn build_client_chain_group(
    client_chains: crate::option_util::NoneOrSome<crate::config::ClientChain>,
) -> ClientChainGroup {
    let chains: Vec<ClientProxyChain> = if client_chains.is_empty() {
        vec![build_client_proxy_chain(
            crate::option_util::OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                ClientConfig::default(),
            ))),
        )]
    } else {
        client_chains
            .into_vec()
            .into_iter()
            .map(|chain| build_client_proxy_chain(chain.hops))
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
    use std::net::{IpAddr, Ipv4Addr};

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
        let chain = build_client_proxy_chain(OneOrSome::One(ClientChainHop::Single(
            ConfigSelection::Config(direct_config()),
        )));

        // Direct creates 1 socket connector, 0 proxy connectors
        assert_eq!(chain.num_hops(), 1);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_build_single_proxy_hop() {
        let chain = build_client_proxy_chain(OneOrSome::One(ClientChainHop::Single(
            ConfigSelection::Config(socks_config(1080)),
        )));

        // Single proxy creates 1 socket connector, 1 proxy connector
        assert_eq!(chain.num_hops(), 1);
    }

    #[test]
    fn test_build_direct_then_proxy_chain() {
        let chain = build_client_proxy_chain(OneOrSome::Some(vec![
            ClientChainHop::Single(ConfigSelection::Config(direct_config())),
            ClientChainHop::Single(ConfigSelection::Config(socks_config(1080))),
        ]));

        // direct (hop 0) -> socks (hop 1)
        // InitialHopEntry::Direct + 1 subsequent hop = 2 hops total
        assert_eq!(chain.num_hops(), 2);
    }

    #[test]
    fn test_build_two_proxy_hops() {
        let chain = build_client_proxy_chain(OneOrSome::Some(vec![
            ClientChainHop::Single(ConfigSelection::Config(socks_config(1080))),
            ClientChainHop::Single(ConfigSelection::Config(socks_config(1081))),
        ]));

        // socks1 (hop 0) -> socks2 (hop 1)
        assert_eq!(chain.num_hops(), 2);
    }

    #[test]
    fn test_build_pool_at_hop0() {
        let chain =
            build_client_proxy_chain(OneOrSome::One(ClientChainHop::Pool(OneOrSome::Some(vec![
                ConfigSelection::Config(socks_config(1080)),
                ConfigSelection::Config(socks_config(1081)),
            ]))));

        // Pool of 2 proxies at hop 0
        assert_eq!(chain.num_hops(), 1);
    }

    #[test]
    fn test_build_empty_client_chains_creates_default() {
        let group = build_client_chain_group(NoneOrSome::None);
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
        let group = build_client_chain_group(chains);
        // 2 chains in group
        assert!(group.supports_udp()); // direct chain supports UDP
    }

    #[test]
    #[should_panic(expected = "protocol: direct is only valid at hop 0")]
    fn test_direct_at_hop1_panics() {
        build_client_proxy_chain(OneOrSome::Some(vec![
            ClientChainHop::Single(ConfigSelection::Config(socks_config(1080))),
            ClientChainHop::Single(ConfigSelection::Config(direct_config())),
        ]));
    }

    #[test]
    #[should_panic(expected = "protocol: direct is only valid at hop 0")]
    fn test_direct_in_pool_at_hop1_panics() {
        build_client_proxy_chain(OneOrSome::Some(vec![
            ClientChainHop::Single(ConfigSelection::Config(socks_config(1080))),
            ClientChainHop::Pool(OneOrSome::Some(vec![
                ConfigSelection::Config(socks_config(1081)),
                ConfigSelection::Config(direct_config()),
            ])),
        ]));
    }

    #[test]
    #[should_panic(expected = "was not resolved during config validation")]
    fn test_unresolved_group_reference_panics() {
        build_client_proxy_chain(OneOrSome::One(ClientChainHop::Single(
            ConfigSelection::GroupName("unresolved_group".to_string()),
        )));
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
