//! Factory functions for creating TCP server handlers from config.

use std::sync::Arc;

use rustc_hash::FxHashMap;

use crate::config::{
    ConfigSelection, RealityServerConfig, RuleConfig, ServerProxyConfig, ShadowTlsServerConfig,
    ShadowTlsServerHandshakeConfig, ShadowsocksConfig, TlsServerConfig, WebsocketServerConfig,
};
use crate::http_handler::HttpTcpServerHandler;
use crate::option_util::NoneOrOne;
use crate::port_forward_handler::PortForwardServerHandler;
use crate::rustls_config_util::create_server_config;
use crate::shadow_tls::{ShadowTlsServerTarget, ShadowTlsServerTargetHandshake};
use crate::shadowsocks::ShadowsocksTcpHandler;
use crate::snell::snell_handler::SnellServerHandler;
use crate::socks_handler::SocksTcpServerHandler;
use crate::tcp::chain_builder::build_client_proxy_chain;
use crate::tcp_handler::TcpServerHandler;
use crate::tls_server_handler::{
    RealityServerTarget, TlsServerHandler, TlsServerTarget, VisionConfig,
};
use crate::trojan_handler::TrojanTcpHandler;
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

pub fn create_tcp_server_handler(
    server_proxy_config: ServerProxyConfig,
    rules_stack: &mut Vec<Vec<RuleConfig>>,
) -> Box<dyn TcpServerHandler> {
    match server_proxy_config {
        ServerProxyConfig::Http { username, password } => Box::new(HttpTcpServerHandler::new(
            create_auth_credentials(username, password),
        )),
        ServerProxyConfig::Socks { username, password } => Box::new(SocksTcpServerHandler::new(
            create_auth_credentials(username, password),
        )),
        ServerProxyConfig::Shadowsocks(ShadowsocksConfig::Legacy { cipher, password }) => {
            Box::new(ShadowsocksTcpHandler::new(cipher, &password))
        }
        ServerProxyConfig::Shadowsocks(ShadowsocksConfig::Aead2022 { cipher, key_bytes }) => {
            Box::new(ShadowsocksTcpHandler::new_aead2022(cipher, &key_bytes))
        }
        ServerProxyConfig::Snell {
            cipher,
            password,
            udp_enabled,
        } => Box::new(SnellServerHandler::new(
            cipher.as_str().try_into().unwrap(),
            &password,
            udp_enabled,
        )),
        ServerProxyConfig::Vless {
            user_id,
            udp_enabled,
        } => Box::new(VlessTcpServerHandler::new(&user_id, udp_enabled)),
        ServerProxyConfig::Trojan {
            password,
            shadowsocks,
        } => Box::new(TrojanTcpHandler::new(&password, &shadowsocks)),
        ServerProxyConfig::Tls {
            tls_targets,
            default_tls_target,
            shadowtls_targets,
            reality_targets,
            tls_buffer_size,
        } => {
            let mut all_targets = tls_targets
                .into_iter()
                .map(|(sni, config)| (sni, create_tls_server_target(config, rules_stack)))
                .collect::<FxHashMap<String, TlsServerTarget>>();
            let default_tls_target =
                default_tls_target.map(|config| create_tls_server_target(*config, rules_stack));
            let shadowtls_targets = shadowtls_targets
                .into_iter()
                .map(|(sni, config)| (sni, create_shadow_tls_server_target(config, rules_stack)))
                .collect::<FxHashMap<String, TlsServerTarget>>();
            all_targets.extend(shadowtls_targets);
            let reality_server_targets = reality_targets
                .into_iter()
                .map(|(sni, config)| (sni, create_reality_server_target(config, rules_stack)))
                .collect::<FxHashMap<String, TlsServerTarget>>();
            all_targets.extend(reality_server_targets);
            Box::new(TlsServerHandler::new(
                all_targets,
                default_tls_target,
                tls_buffer_size,
            ))
        }
        ServerProxyConfig::Vmess {
            cipher,
            user_id,
            udp_enabled,
        } => Box::new(VmessTcpServerHandler::new(&cipher, &user_id, udp_enabled)),
        ServerProxyConfig::Websocket { targets } => {
            let server_targets: Vec<WebsocketServerTarget> = targets
                .into_vec()
                .into_iter()
                .map(|config| create_websocket_server_target(config, rules_stack))
                .collect::<Vec<_>>();
            Box::new(WebsocketTcpServerHandler::new(server_targets))
        }
        ServerProxyConfig::PortForward { targets } => {
            let targets = targets.into_vec();
            Box::new(PortForwardServerHandler::new(targets))
        }
        unknown_config => {
            panic!("Unsupported TCP proxy config: {unknown_config:?}")
        }
    }
}

fn create_tls_server_target(
    tls_server_config: TlsServerConfig,
    rules_stack: &mut Vec<Vec<RuleConfig>>,
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

    let server_config = Arc::new(create_server_config(
        &cert_bytes,
        &key_bytes,
        client_ca_certs,
        &alpn_protocols.into_vec(),
        &client_fingerprints.into_vec(),
    ));

    let pushed_rules = !override_rules.is_empty();
    if pushed_rules {
        rules_stack.push(
            override_rules
                .clone()
                .map(ConfigSelection::unwrap_config)
                .into_vec(),
        );
    }

    // Create vision_config if vision is enabled
    let vision_config = if vision {
        // Vision requires VLESS protocol (validated in config/mod.rs)
        if let ServerProxyConfig::Vless {
            user_id,
            udp_enabled,
        } = &protocol
        {
            let user_id_bytes = crate::util::parse_uuid(user_id)
                .expect("Invalid user_id UUID")
                .into_boxed_slice();
            Some(VisionConfig {
                user_id: user_id_bytes,
                udp_enabled: *udp_enabled,
            })
        } else {
            unreachable!("Vision requires VLESS (should be validated during config load)")
        }
    } else {
        None
    };

    let handler = create_tcp_server_handler(protocol, rules_stack);

    let override_proxy_provider = if override_rules.is_empty() {
        NoneOrOne::None
    } else {
        let rules = rules_stack.last().unwrap().clone();
        NoneOrOne::One(Arc::new(create_tcp_client_proxy_selector(rules)))
    };

    if pushed_rules {
        rules_stack.pop().unwrap();
    }

    TlsServerTarget::Tls {
        server_config,
        handler,
        override_proxy_provider,
        vision_config,
    }
}

fn create_shadow_tls_server_target(
    shadow_tls_server_config: ShadowTlsServerConfig,
    rules_stack: &mut Vec<Vec<RuleConfig>>,
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
            let client_chain = build_client_proxy_chain(handshake.client_chain);
            ShadowTlsServerTargetHandshake::new_remote(handshake.address, client_chain)
        }
    };

    let pushed_rules = !override_rules.is_empty();
    if pushed_rules {
        rules_stack.push(
            override_rules
                .clone()
                .map(ConfigSelection::unwrap_config)
                .into_vec(),
        );
    }

    let handler = create_tcp_server_handler(protocol, rules_stack);

    let override_proxy_provider = if override_rules.is_empty() {
        NoneOrOne::None
    } else {
        let rules = rules_stack.last().unwrap().clone();
        NoneOrOne::One(Arc::new(create_tcp_client_proxy_selector(rules)))
    };

    if pushed_rules {
        rules_stack.pop().unwrap();
    }

    TlsServerTarget::ShadowTls(ShadowTlsServerTarget::new(
        password,
        target_handshake,
        handler,
        override_proxy_provider,
    ))
}

fn create_reality_server_target(
    reality_server_config: RealityServerConfig,
    rules_stack: &mut Vec<Vec<RuleConfig>>,
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

    // Create vision_config if vision is enabled
    let vision_config = if vision {
        // Vision requires VLESS protocol (validated in config/mod.rs)
        if let ServerProxyConfig::Vless {
            user_id,
            udp_enabled,
        } = &protocol
        {
            let user_id_bytes = crate::util::parse_uuid(user_id)
                .expect("Invalid user_id UUID")
                .into_boxed_slice();
            Some(VisionConfig {
                user_id: user_id_bytes,
                udp_enabled: *udp_enabled,
            })
        } else {
            unreachable!("Vision requires VLESS (should be validated during config load)")
        }
    } else {
        None
    };

    // Create inner handler
    let handler = create_tcp_server_handler(protocol, rules_stack);

    let override_proxy_provider = if override_rules.is_empty() {
        NoneOrOne::None
    } else {
        rules_stack.push(
            override_rules
                .clone()
                .map(ConfigSelection::unwrap_config)
                .into_vec(),
        );
        let rules = rules_stack.last().unwrap().clone();
        let provider = NoneOrOne::One(Arc::new(create_tcp_client_proxy_selector(rules)));
        rules_stack.pop().unwrap();
        provider
    };

    TlsServerTarget::Reality(RealityServerTarget {
        private_key: private_key_bytes,
        short_ids: short_id_bytes,
        dest,
        max_time_diff,
        min_client_version,
        max_client_version,
        cipher_suites: cipher_suites.into_vec(),
        handler,
        override_proxy_provider,
        vision_config,
    })
}

fn create_websocket_server_target(
    websocket_server_config: WebsocketServerConfig,
    rules_stack: &mut Vec<Vec<RuleConfig>>,
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

    let pushed_rules = !override_rules.is_empty();
    if pushed_rules {
        rules_stack.push(
            override_rules
                .clone()
                .map(ConfigSelection::unwrap_config)
                .into_vec(),
        );
    }

    let handler = create_tcp_server_handler(protocol, rules_stack);

    let override_proxy_provider = if override_rules.is_empty() {
        NoneOrOne::None
    } else {
        let rules = rules_stack.last().unwrap().clone();
        NoneOrOne::One(Arc::new(create_tcp_client_proxy_selector(rules)))
    };

    if pushed_rules {
        rules_stack.pop().unwrap();
    }

    WebsocketServerTarget {
        matching_path,
        matching_headers,
        ping_type,
        handler,
        override_proxy_provider,
    }
}
