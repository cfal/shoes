use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use log::debug;
use rustc_hash::FxHashMap;

use crate::client_proxy_selector::{ClientProxySelector, ConnectAction, ConnectRule};
use crate::config::{
    ClientConfig, ClientProxyConfig, ConfigSelection, RealityServerConfig, RuleActionConfig,
    RuleConfig, ServerProxyConfig, ShadowTlsServerConfig, ShadowTlsServerHandshakeConfig,
    ShadowsocksConfig, TlsClientConfig, TlsServerConfig, WebsocketClientConfig,
    WebsocketServerConfig,
};
use crate::http_handler::{HttpTcpClientHandler, HttpTcpServerHandler};
use crate::option_util::NoneOrOne;
use crate::port_forward_handler::{PortForwardClientHandler, PortForwardServerHandler};
use crate::rustls_config_util::{create_client_config, create_server_config};
use crate::shadow_tls::{
    ShadowTlsClientHandler, ShadowTlsServerTarget, ShadowTlsServerTargetHandshake,
};
use crate::shadowsocks::ShadowsocksTcpHandler;
use crate::snell::snell_handler::{SnellClientHandler, SnellServerHandler};
use crate::socks_handler::{SocksTcpClientHandler, SocksTcpServerHandler};
use crate::tcp_client_connector::TcpClientConnector;
use crate::tcp_handler::{TcpClientHandler, TcpServerHandler};
use crate::tls_client_handler::TlsClientHandler;
use crate::tls_server_handler::{
    RealityServerTarget, TlsServerHandler, TlsServerTarget, VisionConfig,
};
use crate::trojan_handler::TrojanTcpHandler;
use crate::vless::vless_client_handler::VlessTcpClientHandler;
use crate::vless::vless_server_handler::VlessTcpServerHandler;
use crate::vmess::{VmessTcpClientHandler, VmessTcpServerHandler};
use crate::websocket::{
    WebsocketServerTarget, WebsocketTcpClientHandler, WebsocketTcpServerHandler,
};

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
        ServerProxyConfig::Shadowsocks(ShadowsocksConfig { cipher, password }) => {
            if let Some(stripped) = cipher.strip_prefix("2022-blake3-") {
                let key_bytes = BASE64
                    .decode(password)
                    .expect("could not base64 decode password");
                Box::new(ShadowsocksTcpHandler::new_aead2022(stripped, &key_bytes))
            } else {
                Box::new(ShadowsocksTcpHandler::new(&cipher, &password))
            }
        }
        ServerProxyConfig::Snell {
            cipher,
            password,
            udp_enabled,
            udp_num_sockets,
        } => Box::new(SnellServerHandler::new(
            &cipher,
            &password,
            udp_enabled,
            udp_num_sockets,
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
            let mut client_proxies: Vec<TcpClientConnector> = handshake
                .client_proxies
                .into_iter()
                .map(ConfigSelection::unwrap_config)
                .map(TcpClientConnector::try_from)
                .map(Option::unwrap)
                .collect();
            if client_proxies.is_empty() {
                client_proxies.push(TcpClientConnector::try_from(ClientConfig::default()).unwrap());
            }
            ShadowTlsServerTargetHandshake::new_remote(handshake.address, client_proxies)
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

pub fn create_tcp_client_handler(
    client_proxy_config: ClientProxyConfig,
    default_sni_hostname: Option<String>,
) -> Box<dyn TcpClientHandler> {
    match client_proxy_config {
        ClientProxyConfig::Direct => {
            panic!("Tried to create a direct tcp client handler");
        }
        ClientProxyConfig::Http { username, password } => Box::new(HttpTcpClientHandler::new(
            create_auth_credentials(username, password),
        )),
        ClientProxyConfig::Socks { username, password } => Box::new(SocksTcpClientHandler::new(
            create_auth_credentials(username, password),
        )),
        ClientProxyConfig::Shadowsocks(ShadowsocksConfig { cipher, password }) => {
            if let Some(stripped) = cipher.strip_prefix("2022-blake3-") {
                let key_bytes = BASE64
                    .decode(password)
                    .expect("could not base64 decode password");
                Box::new(ShadowsocksTcpHandler::new_aead2022(stripped, &key_bytes))
            } else {
                Box::new(ShadowsocksTcpHandler::new(&cipher, &password))
            }
        }
        ClientProxyConfig::Snell(ShadowsocksConfig { cipher, password }) => {
            Box::new(SnellClientHandler::new(&cipher, &password))
        }
        ClientProxyConfig::Vless { user_id } => {
            // Plain VLESS without TLS
            Box::new(VlessTcpClientHandler::new(&user_id))
        }
        ClientProxyConfig::Trojan {
            password,
            shadowsocks,
        } => Box::new(TrojanTcpHandler::new(&password, &shadowsocks)),
        ClientProxyConfig::Tls(tls_client_config) => {
            let TlsClientConfig {
                verify,
                server_fingerprints,
                sni_hostname,
                alpn_protocols,
                tls_buffer_size,
                protocol,
                key,
                cert,
                vision,
            } = tls_client_config;

            let sni_hostname = if sni_hostname.is_unspecified() {
                if default_sni_hostname.is_some() {
                    debug!(
                        "Using default sni hostname for TLS client connection: {}",
                        default_sni_hostname.as_ref().unwrap()
                    );
                }
                default_sni_hostname
            } else {
                sni_hostname.into_option()
            };

            let key_and_cert_bytes = key.zip(cert).map(|(key, cert)| {
                // Certificates are already embedded as PEM data during config validation
                let cert_bytes = cert.as_bytes().to_vec();
                let key_bytes = key.as_bytes().to_vec();

                (key_bytes, cert_bytes)
            });

            let client_config = Arc::new(create_client_config(
                verify,
                server_fingerprints.into_vec(),
                alpn_protocols.into_vec(),
                sni_hostname.is_some(),
                key_and_cert_bytes,
            ));

            let server_name = match sni_hostname {
                Some(s) => rustls::pki_types::ServerName::try_from(s).unwrap(),
                // This is unused, since enable_sni is false, but connect_with still requires a
                // parameter.
                None => "example.com".try_into().unwrap(),
            };

            if vision {
                let ClientProxyConfig::Vless { user_id } = protocol.as_ref() else {
                    // Validated when loading config
                    unreachable!();
                };
                let user_id_bytes = crate::util::parse_uuid(user_id)
                    .expect("Invalid user_id UUID")
                    .into_boxed_slice();
                Box::new(TlsClientHandler::new_vision_vless(
                    client_config,
                    tls_buffer_size,
                    server_name,
                    user_id_bytes,
                ))
            } else {
                let handler = create_tcp_client_handler(*protocol, None);

                Box::new(TlsClientHandler::new(
                    client_config,
                    tls_buffer_size,
                    server_name,
                    handler,
                ))
            }
        }
        ClientProxyConfig::Reality {
            public_key,
            short_id,
            sni_hostname,
            vision,
            protocol,
        } => {
            eprintln!("========== CREATING REALITY CLIENT HANDLER ==========");

            // Decode public key from base64url
            let public_key_bytes =
                crate::reality::decode_public_key(&public_key).expect("Invalid REALITY public key");

            // Decode short ID from hex string
            let short_id_bytes =
                crate::reality::decode_short_id(&short_id).expect("Invalid REALITY short_id");

            // Determine SNI hostname
            let sni_hostname = sni_hostname.or(default_sni_hostname.clone());
            let server_name = match sni_hostname {
                Some(s) => rustls::pki_types::ServerName::try_from(s)
                    .unwrap()
                    .to_owned(),
                None => {
                    panic!("REALITY client requires sni_hostname to be specified");
                }
            };

            if vision {
                let ClientProxyConfig::Vless { user_id } = protocol.as_ref() else {
                    unreachable!("Vision requires VLESS (should be validated during config load)")
                };
                let user_id_bytes = crate::util::parse_uuid(user_id)
                    .expect("Invalid user_id UUID")
                    .into_boxed_slice();
                Box::new(
                    crate::reality_client_handler::RealityClientHandler::new_vision_vless(
                        public_key_bytes,
                        short_id_bytes,
                        server_name,
                        user_id_bytes,
                    ),
                )
            } else {
                let inner_handler = create_tcp_client_handler(*protocol, None);
                Box::new(crate::reality_client_handler::RealityClientHandler::new(
                    public_key_bytes,
                    short_id_bytes,
                    server_name,
                    inner_handler,
                ))
            }
        }
        ClientProxyConfig::ShadowTls {
            password,
            sni_hostname,
            protocol,
        } => {
            // ShadowTLS client handler
            let sni_hostname = sni_hostname.or(default_sni_hostname);
            let enable_sni = sni_hostname.is_some();

            let server_name = match sni_hostname {
                Some(s) => rustls::pki_types::ServerName::try_from(s).unwrap(),
                None => "example.com".try_into().unwrap(), // Fallback
            };

            // Create TLS config for ShadowTLS
            // TODO: Ensure client_config is suitable for TLS 1.3.
            // Rustls ClientConfig by default supports TLS 1.3 if server does.
            // The server handler enforces TLS 1.3 from client and for negotiation.
            let client_config = Arc::new(create_client_config(
                false,      // No WebPKI verification needed for ShadowTLS
                Vec::new(), // No fingerprints
                Vec::new(), // No ALPN
                enable_sni, // Enable SNI if hostname provided
                None,       // No client cert
            ));

            let handler = create_tcp_client_handler(*protocol, None);

            Box::new(ShadowTlsClientHandler::new(
                password,
                client_config,
                server_name,
                handler,
            ))
        }
        ClientProxyConfig::Vmess { cipher, user_id } => {
            Box::new(VmessTcpClientHandler::new(&cipher, &user_id))
        }
        ClientProxyConfig::Websocket(websocket_client_config) => {
            let WebsocketClientConfig {
                matching_path,
                matching_headers,
                ping_type,
                protocol,
            } = websocket_client_config;

            let handler = create_tcp_client_handler(*protocol, None);

            Box::new(WebsocketTcpClientHandler::new(
                matching_path,
                matching_headers.map(|h| h.into_iter().collect()),
                ping_type,
                handler,
            ))
        }
        ClientProxyConfig::PortForward => Box::new(PortForwardClientHandler),
    }
}

pub fn create_tcp_client_proxy_selector(
    rules: Vec<RuleConfig>,
) -> ClientProxySelector<TcpClientConnector> {
    let rules = rules
        .into_iter()
        .map(|rule_config| {
            let RuleConfig { masks, action } = rule_config;
            let connect_action = match action {
                RuleActionConfig::Allow {
                    override_address,
                    client_proxies,
                } => ConnectAction::new_allow(
                    override_address,
                    client_proxies
                        .map(ConfigSelection::unwrap_config)
                        .map(TcpClientConnector::try_from)
                        // .filter(Option::is_some)
                        .map(Option::unwrap),
                ),
                RuleActionConfig::Block => ConnectAction::new_block(),
            };
            ConnectRule::new(masks.into_vec(), connect_action)
        })
        .collect::<Vec<_>>();
    ClientProxySelector::new(rules)
}
