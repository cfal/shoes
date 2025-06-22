use std::io::Read;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use log::debug;
use rustc_hash::FxHashMap;

use crate::client_proxy_selector::{ClientProxySelector, ConnectAction, ConnectRule};
use crate::config::{
    ClientConfig, ClientProxyConfig, ConfigSelection, RuleActionConfig, RuleConfig,
    ServerProxyConfig, ShadowTlsServerConfig, ShadowTlsServerHandshakeConfig, ShadowsocksConfig,
    TlsClientConfig, TlsServerConfig, WebsocketClientConfig, WebsocketServerConfig,
};
use crate::http_handler::{HttpTcpClientHandler, HttpTcpServerHandler};
use crate::option_util::NoneOrOne;
use crate::port_forward_handler::PortForwardServerHandler;
use crate::rustls_util::{create_client_config, create_server_config};
use crate::shadow_tls::{
    ShadowTlsClientHandler, ShadowTlsServerTarget, ShadowTlsServerTargetHandshake,
};
use crate::shadowsocks::ShadowsocksTcpHandler;
use crate::snell::snell_handler::{SnellClientHandler, SnellServerHandler};
use crate::socks_handler::{SocksTcpClientHandler, SocksTcpServerHandler};
use crate::tcp_client_connector::TcpClientConnector;
use crate::tcp_handler::{TcpClientHandler, TcpServerHandler};
use crate::tls_handler::{TlsClientHandler, TlsServerHandler, TlsServerTarget};
use crate::trojan_handler::TrojanTcpHandler;
use crate::vless_handler::{VlessTcpClientHandler, VlessTcpServerHandler};
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
            Box::new(TlsServerHandler::new(
                all_targets,
                default_tls_target,
                tls_buffer_size,
            ))
        }
        ServerProxyConfig::Vmess {
            cipher,
            user_id,
            force_aead,
            udp_enabled,
        } => Box::new(VmessTcpServerHandler::new(
            &cipher,
            &user_id,
            force_aead,
            udp_enabled,
        )),
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
            panic!("Unsupported TCP proxy config: {:?}", unknown_config)
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
        protocol,
        override_rules,
    } = tls_server_config;

    // TODO: do this asynchronously
    let mut cert_file = std::fs::File::open(&cert).unwrap();
    let mut cert_bytes = vec![];
    cert_file.read_to_end(&mut cert_bytes).unwrap();

    let mut key_file = std::fs::File::open(&key).unwrap();
    let mut key_bytes = vec![];
    key_file.read_to_end(&mut key_bytes).unwrap();

    let client_ca_certs = client_ca_certs
        .into_iter()
        .map(|cert| {
            let mut cert_file = std::fs::File::open(cert).unwrap();
            let mut cert_bytes = vec![];
            cert_file.read_to_end(&mut cert_bytes).unwrap();
            cert_bytes
        })
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
            // TODO: do this asynchronously
            let mut cert_file = std::fs::File::open(&handshake.cert).unwrap();
            let mut cert_bytes = vec![];
            cert_file.read_to_end(&mut cert_bytes).unwrap();

            let mut key_file = std::fs::File::open(&handshake.key).unwrap();
            let mut key_bytes = vec![];
            key_file.read_to_end(&mut key_bytes).unwrap();

            let client_ca_certs = handshake
                .client_ca_certs
                .into_iter()
                .map(|cert| {
                    let mut cert_file = std::fs::File::open(cert).unwrap();
                    let mut cert_bytes = vec![];
                    cert_file.read_to_end(&mut cert_bytes).unwrap();
                    cert_bytes
                })
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
        ClientProxyConfig::Vless { user_id } => Box::new(VlessTcpClientHandler::new(&user_id)),
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
                shadowtls_password,
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
                // TODO: do this asynchronously
                let mut cert_file = std::fs::File::open(&cert).unwrap();
                let mut cert_bytes = vec![];
                cert_file.read_to_end(&mut cert_bytes).unwrap();

                let mut key_file = std::fs::File::open(&key).unwrap();
                let mut key_bytes = vec![];
                key_file.read_to_end(&mut key_bytes).unwrap();

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

            let handler = create_tcp_client_handler(*protocol, None);

            match shadowtls_password {
                None => Box::new(TlsClientHandler::new(
                    client_config,
                    tls_buffer_size,
                    server_name,
                    handler,
                )),
                Some(password) => {
                    // TODO: Ensure client_config is suitable for TLS 1.3.
                    // Rustls ClientConfig by default supports TLS 1.3 if server does.
                    // The server handler enforces TLS 1.3 from client and for negotiation.
                    Box::new(ShadowTlsClientHandler::new(
                        password,
                        client_config,
                        server_name,
                        handler,
                    ))
                }
            }
        }
        ClientProxyConfig::Vmess {
            cipher,
            user_id,
            aead,
        } => Box::new(VmessTcpClientHandler::new(&cipher, &user_id, aead)),
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
