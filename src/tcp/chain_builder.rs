//! Builder functions for creating ClientProxyChain from config.

use std::sync::Arc;

use crate::client_proxy_chain::{ClientChainGroup, ClientProxyChain, InitialHopEntry};
use crate::config::{ResolvedClientConfig, ResolvedClientHop};
use crate::resolver::Resolver;
use crate::tcp::proxy_connector_impl::create_proxy_connector;
use crate::tcp::socket_connector::SocketConnector;
use crate::tcp::socket_connector_impl::SocketConnectorImpl;

/// Checks the final hop without creating sockets or resolving addresses.
pub(crate) fn supports_udp_offline(
    chain: &crate::config::ResolvedClientChain,
) -> std::io::Result<bool> {
    crate::config::composition::validate(&chain.hops)?;
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    let mut supported = false;
    for config in crate::config::composition::final_clients(&chain.hops) {
        supported |= config.protocol.is_direct()
            || config.protocol.is_wireguard()
            || create_proxy_connector(config.clone(), resolver.clone())?
                .is_some_and(|proxy| proxy.supports_udp());
    }
    Ok(supported)
}

/// Build a ClientProxyChain from a client_chain configuration.
///
/// Creates InitialHopEntry (socket + optional proxy paired) from hop 0.
/// Creates ProxyConnectors for subsequent hops (1+).
/// `protocol: direct` at hop 0 creates InitialHopEntry::Direct.
#[cfg(test)]
pub fn build_client_proxy_chain(
    client_chain: crate::option_util::OneOrSome<ResolvedClientHop>,
    resolver: Arc<dyn Resolver>,
) -> ClientProxyChain {
    try_build_client_proxy_chain(client_chain, resolver).expect("Failed to create client chain")
}

pub fn try_build_client_proxy_chain(
    client_chain: crate::option_util::OneOrSome<ResolvedClientHop>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<ClientProxyChain> {
    build_client_proxy_chain_with_limits(client_chain, resolver, crate::resources::limits())
}

pub(crate) fn build_client_proxy_chain_with_limits(
    client_chain: crate::option_util::OneOrSome<ResolvedClientHop>,
    resolver: Arc<dyn Resolver>,
    limits: crate::config::GlobalLimits,
) -> std::io::Result<ClientProxyChain> {
    if client_chain
        .iter()
        .any(|hop| matches!(hop, ResolvedClientHop::Choice(_)))
    {
        return ClientProxyChain::composed(client_chain, resolver, limits);
    }
    let hops: Vec<ResolvedClientConfig> = client_chain
        .into_vec()
        .into_iter()
        .map(|hop| match hop {
            ResolvedClientHop::Single(client) => client,
            ResolvedClientHop::Choice(_) => unreachable!("composition handled above"),
        })
        .collect();

    if hops.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Client chain must have at least one hop",
        ));
    }

    for (index, config) in hops.iter().enumerate() {
        crate::sudoku_mask::validate_resolved_client(&config.protocol, &config.transport)?;
        config.validate_quic_key_exchange(index == 0)?;
        crate::quic_client::validate_resolved(config, index == 0)?;
    }
    let config = &hops[0];
    let initial_hop = if let crate::config::ResolvedClientProxyConfig::Wireguard(reference) =
        &config.protocol
    {
        let connector = reference.connector.clone().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "WireGuard endpoint registry has not been prepared",
            )
        })?;
        InitialHopEntry::Wireguard(connector)
    } else {
        let socket = SocketConnectorImpl::from_config_with_limits(
            config,
            find_first_proxy_address(&hops),
            limits,
        )
        .map(|s| Arc::new(s) as Arc<dyn SocketConnector>)?;

        if config.protocol.is_direct() {
            InitialHopEntry::Direct(socket)
        } else {
            let proxy =
                create_proxy_connector(config.clone(), resolver.clone())?.ok_or_else(|| {
                    std::io::Error::other("Missing proxy connector for non-direct configuration")
                })?;
            InitialHopEntry::Proxy { socket, proxy }
        }
    };

    let origins = hops
        .iter()
        .map(|client| vec![client.control.clone()])
        .collect();
    let mut subsequent_hops = Vec::new();
    for (hop_index, config) in hops.into_iter().enumerate().skip(1) {
        if config.transport == crate::config::Transport::Quic
            && crate::xhttp::connector::contains(&config.protocol)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "XHTTP H3 is only supported at hop 0",
            ));
        }
        if config.protocol.is_direct() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "protocol: direct is only valid at hop 0. Found direct at hop {} with address {}",
                    hop_index, config.address
                ),
            ));
        }
        let proxy = create_proxy_connector(config, resolver.clone())?
            .ok_or_else(|| std::io::Error::other("Missing proxy connector for subsequent hop"))?;
        subsequent_hops.push(vec![proxy]);
    }

    Ok(ClientProxyChain::new(vec![initial_hop], subsequent_hops).with_origins(origins))
}

/// Find the first proxy address in the chain (for socket connector target).
fn find_first_proxy_address(hops: &[ResolvedClientConfig]) -> Option<&crate::address::NetLocation> {
    hops.iter()
        .find(|config| !config.protocol.is_direct())
        .map(|config| &config.address)
}

/// Build a "direct" ClientChainGroup (no proxy, just socket connection).
/// Uses the same pattern as build_client_chain_group with no chains configured.
pub fn build_direct_chain_group(resolver: Arc<dyn Resolver>) -> ClientChainGroup {
    build_client_chain_group(crate::option_util::NoneOrSome::None, resolver)
}

/// Build a ClientChainGroup from config chains.
pub fn build_client_chain_group(
    client_chains: crate::option_util::NoneOrSome<crate::config::ResolvedClientChain>,
    resolver: Arc<dyn Resolver>,
) -> ClientChainGroup {
    try_build_client_chain_group(client_chains, resolver)
        .expect("Failed to create client chain group")
}

pub fn try_build_client_chain_group(
    client_chains: crate::option_util::NoneOrSome<crate::config::ResolvedClientChain>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<ClientChainGroup> {
    build_client_chain_group_with_limits(client_chains, resolver, crate::resources::limits())
}

pub fn build_client_chain_group_with_limits(
    client_chains: crate::option_util::NoneOrSome<crate::config::ResolvedClientChain>,
    resolver: Arc<dyn Resolver>,
    limits: crate::config::GlobalLimits,
) -> std::io::Result<ClientChainGroup> {
    let chains: Vec<ClientProxyChain> = if client_chains.is_empty() {
        vec![build_client_proxy_chain_with_limits(
            crate::option_util::OneOrSome::One(ResolvedClientHop::Single(
                ResolvedClientConfig::default(),
            )),
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
    use crate::config::{ResolvedClientChain, ResolvedClientProxyConfig};
    use crate::option_util::{NoneOrSome, OneOrSome};
    use crate::resolver::NativeResolver;
    use std::net::{IpAddr, Ipv4Addr};

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn socket_initialization_failure_is_returned() {
        let config: ResolvedClientConfig = crate::config::test_support::from_yaml("address: '127.0.0.1:443'\ntransport: quic\nbind_interface: shoes-missing-interface\nprotocol: {type: socks}\n").unwrap();
        let result = try_build_client_proxy_chain(
            OneOrSome::One(ResolvedClientHop::Single(config)),
            mock_resolver(),
        );
        assert!(result.is_err());
    }

    fn pool(clients: Vec<ResolvedClientConfig>) -> ResolvedClientHop {
        crate::config::composition::pool_choice(
            clients
                .into_iter()
                .map(|client| ResolvedClientChain {
                    hops: OneOrSome::One(ResolvedClientHop::Single(client)),
                })
                .collect(),
        )
    }

    fn mock_resolver() -> Arc<dyn Resolver> {
        Arc::new(NativeResolver::new())
    }

    fn socks_config(port: u16) -> ResolvedClientConfig {
        ResolvedClientConfig {
            address: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
            protocol: ResolvedClientProxyConfig::Socks {
                username: None,
                password: None,
            },
            ..Default::default()
        }
    }

    fn direct_config() -> ResolvedClientConfig {
        ResolvedClientConfig::default()
    }

    #[test]
    fn sudoku_mask_placement_is_checked_in_every_chain_hop_and_pool() {
        use serde_json::json;
        let mask = json!({"type":"sudoku_mask","protocol":{"type":"socks"}});
        for (protocol, valid) in [
            (mask.clone(), true),
            (json!({"type":"tls","protocol":mask}), false),
        ] {
            let config: ResolvedClientConfig = crate::config::test_support::from_json(json!({
                "address":"localhost:1080","protocol":protocol
            }))
            .unwrap();
            for hop in [
                ResolvedClientHop::Single(config.clone()),
                pool(vec![socks_config(1081), config]),
            ] {
                for index in 0..=1 {
                    let mut hops = Vec::new();
                    if index == 1 {
                        hops.push(ResolvedClientHop::Single(direct_config()));
                    }
                    hops.push(hop.clone());
                    let result =
                        try_build_client_proxy_chain(OneOrSome::Some(hops), mock_resolver());
                    assert_eq!(result.is_ok(), valid);
                    if let Err(error) = result {
                        assert!(
                            error.to_string().contains("outermost protocol layer"),
                            "{error}"
                        );
                    }
                }
            }
        }
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
            let config: ResolvedClientConfig = crate::config::test_support::from_yaml(&format!(
                "{{address: 'unresolvable.invalid:443', protocol: {protocol}}}"
            ))
            .unwrap();
            let chain = ResolvedClientChain {
                hops: OneOrSome::One(ResolvedClientHop::Single(config.clone())),
            };
            assert_eq!(supports_udp_offline(&chain).unwrap(), expected);
            let runtime =
                try_build_client_proxy_chain(chain.hops.clone(), mock_resolver()).unwrap();
            assert_eq!(runtime.supports_udp(), expected);
            let pool = ResolvedClientChain {
                hops: OneOrSome::One(pool(vec![socks_config(1080), config])),
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
            let direct: ResolvedClientConfig = crate::config::test_support::from_yaml(&format!(
                "protocol: {{type: direct}}\ntransport: quic\nquic_settings: {{{field}}}\n"
            ))
            .unwrap();
            assert_eq!(
                SocketConnectorImpl::from_config(&direct, None).is_err(),
                groups.is_some()
            );
            let direct_chain = OneOrSome::One(ResolvedClientHop::Single(direct));
            assert_eq!(
                try_build_client_proxy_chain(direct_chain, mock_resolver()).is_err(),
                groups.is_some()
            );

            let proxy: ResolvedClientConfig = crate::config::test_support::from_yaml(&format!(
                "address: '127.0.0.1:443'\nprotocol: {{type: socks}}\ntransport: quic\nquic_settings: {{{field}}}\n"
            )).unwrap();
            for hop in [
                ResolvedClientHop::Single(proxy.clone()),
                pool(vec![socks_config(1080), proxy]),
            ] {
                let chain = OneOrSome::Some(vec![ResolvedClientHop::Single(direct_config()), hop]);
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
            OneOrSome::One(ResolvedClientHop::Single(direct_config())),
            mock_resolver(),
        );

        // Direct creates 1 socket connector, 0 proxy connectors
        assert_eq!(chain.num_hops(), 1);
        assert!(chain.supports_udp());
    }

    #[test]
    fn flat_chain_preflight_validates_later_hops_before_creating_connectors() {
        let invalid_proxy = crate::config::test_support::from_yaml(
            "address: '127.0.0.1:443'\nprotocol: {type: vless, user_id: invalid}\n",
        )
        .unwrap();
        let invalid_transport = crate::config::test_support::from_yaml(
            "address: '127.0.0.1:443'\nprotocol: {type: socks}\ntransport: quic\nquic_settings: {key_exchange_groups: [X25519]}\n",
        )
        .unwrap();
        let error = try_build_client_proxy_chain(
            OneOrSome::Some(vec![
                ResolvedClientHop::Single(invalid_proxy),
                ResolvedClientHop::Single(invalid_transport),
            ]),
            mock_resolver(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(
            error.to_string(),
            "QUIC key_exchange_groups requires a non-direct client at chain hop 0 with transport: quic"
        );
    }

    #[test]
    fn test_build_single_proxy_hop() {
        let chain = build_client_proxy_chain(
            OneOrSome::One(ResolvedClientHop::Single(socks_config(1080))),
            mock_resolver(),
        );

        // Single proxy creates 1 socket connector, 1 proxy connector
        assert_eq!(chain.num_hops(), 1);
    }

    #[test]
    fn test_build_direct_then_proxy_chain() {
        let chain = build_client_proxy_chain(
            OneOrSome::Some(vec![
                ResolvedClientHop::Single(direct_config()),
                ResolvedClientHop::Single(socks_config(1080)),
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
                ResolvedClientHop::Single(socks_config(1080)),
                ResolvedClientHop::Single(socks_config(1081)),
            ]),
            mock_resolver(),
        );

        // socks1 (hop 0) -> socks2 (hop 1)
        assert_eq!(chain.num_hops(), 2);
    }

    #[test]
    fn test_build_pool_at_hop0() {
        let chain = build_client_proxy_chain(
            OneOrSome::One(pool(vec![socks_config(1080), socks_config(1081)])),
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
            ResolvedClientChain {
                hops: OneOrSome::One(ResolvedClientHop::Single(socks_config(1080))),
            },
            ResolvedClientChain {
                hops: OneOrSome::One(ResolvedClientHop::Single(direct_config())),
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
                ResolvedClientHop::Single(socks_config(1080)),
                ResolvedClientHop::Single(direct_config()),
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
                ResolvedClientHop::Single(socks_config(1080)),
                pool(vec![socks_config(1081), direct_config()]),
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
    fn test_find_first_proxy_address_direct_only() {
        let direct = direct_config();
        let hops = vec![direct];
        assert!(find_first_proxy_address(&hops).is_none());
    }

    #[test]
    fn test_find_first_proxy_address_proxy_at_hop0() {
        let proxy = socks_config(1080);
        let hops = vec![proxy];
        let addr = find_first_proxy_address(&hops);
        assert!(addr.is_some());
        assert_eq!(addr.unwrap().port(), 1080);
    }

    #[test]
    fn test_find_first_proxy_address_proxy_at_hop1() {
        let direct = direct_config();
        let proxy = socks_config(1080);
        let hops = vec![direct, proxy];
        let addr = find_first_proxy_address(&hops);
        assert!(addr.is_some());
        assert_eq!(addr.unwrap().port(), 1080);
    }
}
