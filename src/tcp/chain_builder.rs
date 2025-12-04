//! Builder functions for creating ClientProxyChain from config.

use crate::client_proxy_chain::{ClientChainGroup, ClientProxyChain, InitialHopEntry};
use crate::config::ConfigSelection;
use crate::config::{ClientChainHop, ClientConfig, ClientProxyConfig, ClientQuicConfig};
use crate::tcp::proxy_connector::ProxyConnector;
use crate::tcp::proxy_connector_impl::ProxyConnectorImpl;
use crate::tcp::socket_connector::SocketConnector;
use crate::tcp::socket_connector_impl::SocketConnectorImpl;
use crate::hysteria2_client::Hysteria2SocketConnector;

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
            // Check if this is a Hysteria2 configuration
            // Hysteria2 uses its own socket connector that handles QUIC + HTTP/3 auth
            if matches!(config.protocol, ClientProxyConfig::Hysteria2 { .. }) {
                // For Hysteria2, we need to extract the password and create a special socket connector
                let (password, udp_enabled, fast_open, bandwidth) = match &config.protocol {
                    ClientProxyConfig::Hysteria2 { password, udp_enabled, fast_open, bandwidth } => {
                        (password.clone(), *udp_enabled, *fast_open, bandwidth.clone())
                    }
                    _ => unreachable!(),
                };

                // Parse bandwidth configuration
                use crate::config::resolve_hysteria2_bandwidth;
                let (max_tx, max_rx) = match resolve_hysteria2_bandwidth(&bandwidth) {
                    Ok((tx, rx)) => {
                        eprintln!("DEBUG: Parsed bandwidth: up={} bytes/s ({} MB/s), down={} bytes/s ({} MB/s)",
                            tx, tx / 1024 / 1024, rx, rx / 1024 / 1024);
                        (tx, rx)
                    }
                    Err(e) => {
                        eprintln!("DEBUG: Failed to parse bandwidth: {}, using 0", e);
                        (0, 0)
                    }
                };

                // Build Hysteria2 socket connector
                let target_address = find_first_proxy_address(&hops, config)
                    .expect("Hysteria2 requires a target address");

                let bind_interface = config.bind_interface.clone().into_option();

                // Get SNI hostname from quic_settings or use target address
                let sni_hostname = config
                    .quic_settings
                    .as_ref()
                    .and_then(|q| q.sni_hostname.clone().into_option())
                    .or_else(|| target_address.address().hostname().map(|h| h.to_string()));

                // Create QUIC endpoint for Hysteria2
                let default_sni_hostname =
                    target_address.address().hostname().map(ToString::to_string);

                let effective_sni = sni_hostname.as_ref().or(default_sni_hostname.as_ref());

                let ClientQuicConfig {
                    verify,
                    server_fingerprints,
                    alpn_protocols,
                    sni_hostname: _,
                    key,
                    cert,
                } = config.quic_settings.clone().unwrap_or_default();

                let tls13_suite =
                    match rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256 {
                        rustls::SupportedCipherSuite::Tls13(t) => t,
                        _ => {
                            panic!("Could not retrieve Tls13CipherSuite");
                        }
                    };

                let key_and_cert_bytes = key.zip(cert).map(|(key, cert)| {
                    let cert_bytes = cert.as_bytes().to_vec();
                    let key_bytes = key.as_bytes().to_vec();
                    (key_bytes, cert_bytes)
                });

                use crate::rustls_config_util::create_client_config;
                let rustls_client_config = create_client_config(
                    verify,
                    server_fingerprints.into_vec(),
                    alpn_protocols.into_vec(),
                    effective_sni.is_some(),
                    key_and_cert_bytes,
                    true, // tls13_only - Hysteria2 requires TLS 1.3
                );

                let quic_client_config = quinn::crypto::rustls::QuicClientConfig::with_initial(
                    std::sync::Arc::new(rustls_client_config),
                    tls13_suite.quic_suite().unwrap(),
                )
                .unwrap();

                let mut quinn_client_config =
                    quinn::ClientConfig::new(std::sync::Arc::new(quic_client_config));

                let mut transport_config = quinn::TransportConfig::default();
                transport_config
                    .max_concurrent_bidi_streams(256_u32.into())
                    .max_concurrent_uni_streams(255_u8.into())
                    .keep_alive_interval(Some(std::time::Duration::from_secs(15)))
                    .max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into().unwrap()));

                quinn_client_config.transport_config(std::sync::Arc::new(transport_config));

                let udp_socket = match crate::socket_util::new_udp_socket(
                    target_address.address().is_ipv6(),
                    bind_interface,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        panic!("Failed to bind UDP socket for Hysteria2: {e}");
                    }
                };
                let udp_socket = udp_socket.into_std().unwrap();

                let mut endpoint = quinn::Endpoint::new(
                    quinn::EndpointConfig::default(),
                    None,
                    udp_socket,
                    std::sync::Arc::new(quinn::TokioRuntime),
                )
                .unwrap();
                endpoint.set_default_client_config(quinn_client_config);

                let socket = Box::new(Hysteria2SocketConnector::new(
                    std::sync::Arc::new(endpoint),
                    target_address.clone(),
                    effective_sni.cloned(),
                    password,
                    udp_enabled,
                    fast_open,
                    max_tx,
                    max_rx,
                )) as Box<dyn SocketConnector>;

                // Hysteria2 is a direct protocol from the proxy chain perspective
                // (no additional ProxyConnector needed)
                return InitialHopEntry::Direct(socket);
            }

            // Standard path: create SocketConnector from config
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
