//! Factory functions for creating TCP server handlers from config.

use std::net::IpAddr;
use std::sync::Arc;

use rustc_hash::FxHashMap;

use crate::anytls::{AnyTlsServerHandler, PaddingFactory};
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::{ClientChainHop, ClientConfig};
use crate::config::{
    ConfigSelection, RealityServerConfig, ServerProxyConfig, ShadowTlsServerConfig,
    ShadowTlsServerHandshakeConfig, ShadowsocksConfig, TlsServerConfig, WebsocketServerConfig,
};
use crate::http_handler::HttpTcpServerHandler;
use crate::mixed_handler::MixedTcpServerHandler;
use crate::naiveproxy::UserLookup;
use crate::option_util::OneOrSome;
use crate::port_forward_handler::PortForwardServerHandler;
use crate::reality::RealityServerTarget;
use crate::resolver::Resolver;
use crate::rustls_config_util::create_server_config;
use crate::shadow_tls::{ShadowTlsServerTarget, ShadowTlsServerTargetHandshake};
use crate::shadowsocks::ShadowsocksTcpHandler;
use crate::snell::snell_handler::SnellServerHandler;
use crate::socks_handler::SocksTcpServerHandler;
use crate::tcp::chain_builder::build_client_proxy_chain;
use crate::tcp::tcp_handler::TcpServerHandler;
use crate::tls_server_handler::NaiveConfig;
use crate::tls_server_handler::{
    InnerProtocol, TlsServerHandler, TlsServerTarget, VisionVlessConfig,
};
use crate::trojan_handler::TrojanTcpHandler;
use crate::uuid_util::parse_uuid;
use crate::vless::vless_server_handler::VlessTcpServerHandler;
use crate::vmess::VmessTcpServerHandler;
use crate::websocket::{WebsocketServerTarget, WebsocketTcpServerHandler};

use super::tcp_client_handler_factory::create_tcp_client_proxy_selector;

fn create_auth_credentials(
    username: Option<String>,
    password: Option<String>,
) -> Option<(String, String)> {
    match (&username, &password) {
        (None, None) => None,
        _ => Some((username.unwrap_or_default(), password.unwrap_or_default())),
    }
}

/// Create a TCP server handler from config.
///
/// # Arguments
/// * `server_proxy_config` - The protocol configuration
/// * `client_proxy_selector` - Selector for outbound proxy routing
/// * `resolver` - DNS resolver
/// * `bind_ip` - Optional bind IP for handlers that need it (e.g., Socks5 UDP, Mixed)
///
/// The `bind_ip` is required for:
/// - `Socks` with `udp_enabled: true` (for UDP ASSOCIATE)
/// - `Mixed` with `udp_enabled: true` (for UDP ASSOCIATE)
pub fn create_tcp_server_handler(
    server_proxy_config: ServerProxyConfig,
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    bind_ip: Option<IpAddr>,
) -> Box<dyn TcpServerHandler> {
    match server_proxy_config {
        ServerProxyConfig::Http { username, password } => Box::new(HttpTcpServerHandler::new(
            create_auth_credentials(username, password),
            client_proxy_selector.clone(),
        )),
        ServerProxyConfig::Socks {
            username,
            password,
            udp_enabled,
        } => {
            // Use 0.0.0.0 as default if bind_ip not provided
            let ip = bind_ip.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            Box::new(SocksTcpServerHandler::new(
                create_auth_credentials(username, password),
                udp_enabled,
                ip,
                client_proxy_selector.clone(),
                resolver.clone(),
            ))
        }
        ServerProxyConfig::Mixed {
            username,
            password,
            udp_enabled,
        } => {
            // Use 0.0.0.0 as default if bind_ip not provided
            let ip = bind_ip.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            Box::new(MixedTcpServerHandler::new(
                create_auth_credentials(username, password),
                udp_enabled,
                ip,
                client_proxy_selector.clone(),
                resolver.clone(),
            ))
        }
        ServerProxyConfig::Shadowsocks {
            config,
            udp_enabled,
        } => match config {
            ShadowsocksConfig::Legacy { cipher, password } => {
                Box::new(ShadowsocksTcpHandler::new_server(
                    cipher,
                    &password,
                    udp_enabled,
                    client_proxy_selector.clone(),
                ))
            }
            ShadowsocksConfig::Aead2022 { cipher, key_bytes } => {
                Box::new(ShadowsocksTcpHandler::new_aead2022_server(
                    cipher,
                    &key_bytes,
                    udp_enabled,
                    client_proxy_selector.clone(),
                ))
            }
        },
        ServerProxyConfig::Snell {
            cipher,
            password,
            udp_enabled,
        } => Box::new(SnellServerHandler::new(
            cipher.as_str().try_into().unwrap(),
            &password,
            udp_enabled,
            client_proxy_selector.clone(),
        )),
        ServerProxyConfig::Vless {
            user_id,
            udp_enabled,
            fallback,
        } => Box::new(VlessTcpServerHandler::new(
            &user_id,
            udp_enabled,
            client_proxy_selector.clone(),
            resolver.clone(),
            fallback,
        )),
        ServerProxyConfig::Trojan {
            password,
            shadowsocks,
        } => Box::new(TrojanTcpHandler::new_server(
            &password,
            &shadowsocks,
            client_proxy_selector.clone(),
        )),
        ServerProxyConfig::Tls {
            tls_targets,
            default_tls_target,
            shadowtls_targets,
            reality_targets,
            tls_buffer_size,
        } => {
            let mut all_targets = tls_targets
                .into_iter()
                .map(|(sni, config)| {
                    (
                        sni,
                        create_tls_server_target(config, client_proxy_selector, resolver, bind_ip),
                    )
                })
                .collect::<FxHashMap<String, TlsServerTarget>>();
            let default_tls_target = default_tls_target.map(|config| {
                create_tls_server_target(*config, client_proxy_selector, resolver, bind_ip)
            });
            let shadowtls_targets = shadowtls_targets
                .into_iter()
                .map(|(sni, config)| {
                    (
                        sni,
                        create_shadow_tls_server_target(
                            config,
                            client_proxy_selector,
                            resolver,
                            bind_ip,
                        ),
                    )
                })
                .collect::<FxHashMap<String, TlsServerTarget>>();
            all_targets.extend(shadowtls_targets);
            let reality_server_targets = reality_targets
                .into_iter()
                .map(|(sni, config)| {
                    (
                        sni,
                        create_reality_server_target(
                            config,
                            client_proxy_selector,
                            resolver,
                            bind_ip,
                        ),
                    )
                })
                .collect::<FxHashMap<String, TlsServerTarget>>();
            all_targets.extend(reality_server_targets);
            Box::new(TlsServerHandler::new(
                all_targets,
                default_tls_target,
                tls_buffer_size,
                resolver.clone(),
            ))
        }
        ServerProxyConfig::Vmess {
            cipher,
            user_id,
            udp_enabled,
        } => Box::new(VmessTcpServerHandler::new(
            &cipher,
            &user_id,
            udp_enabled,
            client_proxy_selector.clone(),
        )),
        ServerProxyConfig::Websocket { targets } => {
            let server_targets: Vec<WebsocketServerTarget> = targets
                .into_vec()
                .into_iter()
                .map(|config| {
                    create_websocket_server_target(config, client_proxy_selector, resolver, bind_ip)
                })
                .collect::<Vec<_>>();
            Box::new(WebsocketTcpServerHandler::new(server_targets))
        }
        ServerProxyConfig::PortForward { targets } => {
            let targets = targets.into_vec();
            Box::new(PortForwardServerHandler::new(
                targets,
                client_proxy_selector.clone(),
            ))
        }
        ServerProxyConfig::Anytls {
            users,
            padding_scheme,
            udp_enabled,
            fallback,
        } => {
            let users: Vec<(String, String)> = users
                .into_vec()
                .into_iter()
                .map(|u| (u.name, u.password))
                .collect();

            let padding = if let Some(scheme_lines) = padding_scheme {
                let scheme_str = scheme_lines.join("\n");
                Arc::new(
                    PaddingFactory::new(scheme_str.as_bytes())
                        .expect("Invalid padding scheme (should be validated during config load)"),
                )
            } else {
                PaddingFactory::default_factory()
            };

            // AnyTLS spawns its own task and returns AlreadyHandled, so it needs the proxy
            // provider directly (it won't inherit from outer handler through TcpForward)
            Box::new(AnyTlsServerHandler::new(
                users,
                padding,
                resolver.clone(),
                Arc::clone(client_proxy_selector),
                udp_enabled,
                fallback,
            ))
        }
        ServerProxyConfig::Naiveproxy { .. } => {
            // This should be caught at config validation time
            unreachable!(
                "NaiveProxy must be used inside a TLS or Reality protocol - \
                 config validation should have rejected this"
            )
        }
        unknown_config => {
            panic!("Unsupported TCP proxy config: {unknown_config:?}")
        }
    }
}

fn create_tls_server_target(
    tls_server_config: TlsServerConfig,
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    bind_ip: Option<IpAddr>,
) -> TlsServerTarget {
    let TlsServerConfig {
        cert,
        key,
        alpn_protocols,
        client_ca_certs,
        client_fingerprints,
        vision,
        protocol,
        override_rules,
    } = tls_server_config;

    // Certificates are already embedded as PEM data during config validation
    let cert_bytes = cert.as_bytes().to_vec();
    let key_bytes = key.as_bytes().to_vec();

    let client_ca_certs = client_ca_certs
        .into_iter()
        .map(|cert| cert.as_bytes().to_vec())
        .collect();

    // For NaiveProxy, hardcode ALPN to h2 and http/1.1
    let is_naive = matches!(protocol, ServerProxyConfig::Naiveproxy { .. });
    let effective_alpn: Vec<String> = if is_naive {
        let naive_alpn = vec!["h2".to_string(), "http/1.1".to_string()];
        let user_alpn = alpn_protocols.into_vec();
        if user_alpn != naive_alpn {
            log::warn!(
                "NaiveProxy requires ALPN [\"h2\", \"http/1.1\"], ignoring user-specified {:?}",
                user_alpn
            );
        }
        naive_alpn
    } else {
        alpn_protocols.into_vec()
    };

    let server_config = Arc::new(create_server_config(
        &cert_bytes,
        &key_bytes,
        client_ca_certs,
        &effective_alpn,
        &client_fingerprints.into_vec(),
    ));

    // Compute effective selector: if override_rules exist, create new selector; otherwise use parent's
    let effective_selector = if !override_rules.is_empty() {
        let rules = override_rules
            .map(ConfigSelection::unwrap_config)
            .into_vec();
        Arc::new(create_tcp_client_proxy_selector(rules, resolver.clone()))
    } else {
        client_proxy_selector.clone()
    };

    // Create inner_protocol based on protocol type
    let inner_protocol = if let ServerProxyConfig::Naiveproxy {
        users,
        padding,
        fallback,
        udp_enabled,
    } = protocol
    {
        // NaiveProxy uses hyper-based handler
        let users_vec: Vec<(String, String, String)> = users
            .into_vec()
            .into_iter()
            .map(|u| (u.name, u.username, u.password))
            .collect();

        InnerProtocol::Naive(NaiveConfig {
            users: Arc::new(UserLookup::new(users_vec)),
            fallback_path: fallback.map(|f| f.0),
            udp_enabled,
            padding_enabled: padding,
        })
    } else if vision {
        // Vision requires VLESS protocol (validated in config/mod.rs)
        if let ServerProxyConfig::Vless {
            user_id,
            udp_enabled,
            fallback,
        } = &protocol
        {
            let user_id_bytes = parse_uuid(user_id)
                .expect("Invalid user_id UUID")
                .into_boxed_slice();
            InnerProtocol::VisionVless(VisionVlessConfig {
                user_id: user_id_bytes,
                udp_enabled: *udp_enabled,
                fallback: fallback.clone(),
            })
        } else {
            unreachable!("Vision requires VLESS (should be validated during config load)")
        }
    } else {
        let handler = create_tcp_server_handler(protocol, &effective_selector, resolver, bind_ip);
        InnerProtocol::Normal(handler)
    };

    TlsServerTarget::Tls {
        server_config,
        effective_selector,
        inner_protocol,
    }
}

fn create_shadow_tls_server_target(
    shadow_tls_server_config: ShadowTlsServerConfig,
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    bind_ip: Option<IpAddr>,
) -> TlsServerTarget {
    let ShadowTlsServerConfig {
        password,
        handshake,
        protocol,
        override_rules,
    } = shadow_tls_server_config;

    let target_handshake = match handshake {
        ShadowTlsServerHandshakeConfig::Local(handshake) => {
            // Certificates are already embedded as PEM data during config validation
            let cert_bytes = handshake.cert.as_bytes().to_vec();
            let key_bytes = handshake.key.as_bytes().to_vec();

            let client_ca_certs = handshake
                .client_ca_certs
                .into_iter()
                .map(|cert| cert.as_bytes().to_vec())
                .collect();

            let server_config = Arc::new(create_server_config(
                &cert_bytes,
                &key_bytes,
                client_ca_certs,
                &handshake.alpn_protocols.into_vec(),
                &handshake.client_fingerprints.into_vec(),
            ));

            ShadowTlsServerTargetHandshake::new_local(server_config)
        }
        ShadowTlsServerHandshakeConfig::Remote(handshake) => {
            // Build ClientProxyChain from client_chain
            // client_chain is guaranteed to be non-empty (defaults to direct hop)
            let client_chain =
                build_client_proxy_chain(handshake.client_chain, resolver.clone());
            ShadowTlsServerTargetHandshake::new_remote(handshake.address, client_chain)
        }
    };

    // Compute effective selector: if override_rules exist, create new selector; otherwise use parent's
    let effective_selector = if !override_rules.is_empty() {
        let rules = override_rules
            .map(ConfigSelection::unwrap_config)
            .into_vec();
        Arc::new(create_tcp_client_proxy_selector(rules, resolver.clone()))
    } else {
        client_proxy_selector.clone()
    };

    let handler = create_tcp_server_handler(protocol, &effective_selector, resolver, bind_ip);

    TlsServerTarget::ShadowTls(ShadowTlsServerTarget::new(
        password,
        target_handshake,
        handler,
    ))
}

fn create_reality_server_target(
    reality_server_config: RealityServerConfig,
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    bind_ip: Option<IpAddr>,
) -> TlsServerTarget {
    let RealityServerConfig {
        private_key,
        short_ids,
        dest,
        max_time_diff,
        min_client_version,
        max_client_version,
        cipher_suites,
        vision,
        protocol,
        dest_client_chain,
        override_rules,
    } = reality_server_config;

    // Decode private key from base64url (validated during config load)
    let private_key_bytes = crate::reality::decode_private_key(&private_key)
        .expect("Invalid REALITY private key (should be validated during config load)");

    // Decode short IDs from hex strings (validated during config load)
    // OneOrSome ensures at least one short_id is always present (default is all zeros)
    let short_id_bytes: Vec<[u8; 8]> = short_ids
        .into_vec()
        .into_iter()
        .map(|s| {
            crate::reality::decode_short_id(&s)
                .expect("Invalid REALITY short_id (should be validated during config load)")
        })
        .collect();

    // Compute effective selector: if override_rules exist, create new selector; otherwise use parent's
    let effective_selector = if !override_rules.is_empty() {
        let rules = override_rules
            .map(ConfigSelection::unwrap_config)
            .into_vec();
        Arc::new(create_tcp_client_proxy_selector(rules, resolver.clone()))
    } else {
        client_proxy_selector.clone()
    };

    // Create inner_protocol based on protocol type
    let inner_protocol = if let ServerProxyConfig::Naiveproxy {
        users,
        padding,
        fallback,
        udp_enabled,
    } = protocol
    {
        // NaiveProxy uses hyper-based handler
        let users_vec: Vec<(String, String, String)> = users
            .into_vec()
            .into_iter()
            .map(|u| (u.name, u.username, u.password))
            .collect();

        InnerProtocol::Naive(NaiveConfig {
            users: Arc::new(UserLookup::new(users_vec)),
            fallback_path: fallback.map(|f| f.0),
            udp_enabled,
            padding_enabled: padding,
        })
    } else if vision {
        // Vision requires VLESS protocol (validated in config/mod.rs)
        if let ServerProxyConfig::Vless {
            user_id,
            udp_enabled,
            fallback,
        } = &protocol
        {
            let user_id_bytes = parse_uuid(user_id)
                .expect("Invalid user_id UUID")
                .into_boxed_slice();
            InnerProtocol::VisionVless(VisionVlessConfig {
                user_id: user_id_bytes,
                udp_enabled: *udp_enabled,
                fallback: fallback.clone(),
            })
        } else {
            unreachable!("Vision requires VLESS (should be validated during config load)")
        }
    } else {
        let handler = create_tcp_server_handler(protocol, &effective_selector, resolver, bind_ip);
        InnerProtocol::Normal(handler)
    };

    // Build dest client chain: if specified use it, otherwise default to direct
    let dest_client_chain = {
        let hops = dest_client_chain.into_vec();
        if hops.is_empty() {
            // Default to direct connection
            build_client_proxy_chain(
                OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                    ClientConfig::default(),
                ))),
                resolver.clone(),
            )
        } else if hops.len() == 1 {
            build_client_proxy_chain(
                OneOrSome::One(hops.into_iter().next().unwrap()),
                resolver.clone(),
            )
        } else {
            build_client_proxy_chain(OneOrSome::Some(hops), resolver.clone())
        }
    };

    TlsServerTarget::Reality(RealityServerTarget {
        private_key: private_key_bytes,
        short_ids: short_id_bytes,
        dest,
        max_time_diff,
        min_client_version,
        max_client_version,
        cipher_suites: cipher_suites.into_vec(),
        effective_selector,
        inner_protocol,
        dest_client_chain,
    })
}

fn create_websocket_server_target(
    websocket_server_config: WebsocketServerConfig,
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    bind_ip: Option<IpAddr>,
) -> WebsocketServerTarget {
    let WebsocketServerConfig {
        matching_path,
        matching_headers,
        ping_type,
        protocol,
        override_rules,
    } = websocket_server_config;

    let matching_headers = matching_headers.map(|h| {
        h.into_iter()
            .map(|(mut key, val)| {
                key.make_ascii_lowercase();
                (key, val)
            })
            .collect::<FxHashMap<_, _>>()
    });

    // Compute effective selector: if override_rules exist, create new selector; otherwise use parent's
    let effective_selector = if !override_rules.is_empty() {
        let rules = override_rules
            .map(ConfigSelection::unwrap_config)
            .into_vec();
        Arc::new(create_tcp_client_proxy_selector(rules, resolver.clone()))
    } else {
        client_proxy_selector.clone()
    };

    let handler = create_tcp_server_handler(protocol, &effective_selector, resolver, bind_ip);

    WebsocketServerTarget {
        matching_path,
        matching_headers,
        ping_type,
        handler,
    }
}
