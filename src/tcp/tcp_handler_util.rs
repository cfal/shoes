use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use log::debug;

use crate::client_proxy_selector::{ClientProxySelector, ConnectAction, ConnectRule};
use crate::config::{
    ClientProxyConfig, ConfigSelection, RuleActionConfig, RuleConfig, ServerProxyConfig,
    ShadowsocksConfig, TlsClientConfig, TlsServerConfig, WebsocketClientConfig,
    WebsocketServerConfig,
};
use crate::http_handler::{HttpTcpClientHandler, HttpTcpServerHandler};
use crate::option_util::NoneOrOne;
use crate::port_forward_handler::PortForwardServerHandler;
use crate::rustls_util::{create_client_config, create_server_config};
use crate::shadowsocks::ShadowsocksTcpHandler;
use crate::snell::snell_handler::SnellTcpHandler;
use crate::socks_handler::{SocksTcpClientHandler, SocksTcpServerHandler};
use crate::tcp_client_connector::TcpClientConnector;
use crate::tcp_handler::{TcpClientHandler, TcpServerHandler};
use crate::tls_handler::{TlsClientHandler, TlsServerHandler, TlsServerTarget};
use crate::trojan_handler::TrojanTcpHandler;
use crate::vless_handler::VlessTcpHandler;
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
        ServerProxyConfig::Snell(ShadowsocksConfig { cipher, password }) => {
            Box::new(SnellTcpHandler::new(&cipher, &password))
        }
        ServerProxyConfig::Vless { user_id } => Box::new(VlessTcpHandler::new(&user_id)),
        ServerProxyConfig::Trojan {
            password,
            shadowsocks,
        } => Box::new(TrojanTcpHandler::new(&password, &shadowsocks)),
        ServerProxyConfig::Tls {
            sni_targets,
            default_target,
        } => {
            let sni_targets = sni_targets
                .into_iter()
                .map(|(sni, config)| (sni, create_tls_server_target(config, rules_stack)))
                .collect::<HashMap<String, TlsServerTarget>>();
            let default_target =
                default_target.map(|config| create_tls_server_target(*config, rules_stack));
            Box::new(TlsServerHandler::new(sni_targets, default_target))
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

    let server_config = Arc::new(create_server_config(
        &cert_bytes,
        &key_bytes,
        &alpn_protocols.into_vec(),
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

    TlsServerTarget {
        server_config,
        handler,
        override_proxy_provider,
    }
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
            .collect::<HashMap<_, _>>()
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
            Box::new(SnellTcpHandler::new(&cipher, &password))
        }
        ClientProxyConfig::Vless { user_id } => Box::new(VlessTcpHandler::new(&user_id)),
        ClientProxyConfig::Trojan {
            password,
            shadowsocks,
        } => Box::new(TrojanTcpHandler::new(&password, &shadowsocks)),
        ClientProxyConfig::Tls(tls_client_config) => {
            let TlsClientConfig {
                verify,
                sni_hostname,
                alpn_protocols,
                protocol,
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

            let client_config = Arc::new(create_client_config(
                verify,
                &alpn_protocols.into_vec(),
                sni_hostname.is_some(),
            ));

            let server_name = match sni_hostname {
                Some(s) => s.as_str().try_into().unwrap(),
                // This is unused, since enable_sni is false, but connect_with still requires a
                // parameter.
                None => "example.com".try_into().unwrap(),
            };

            let handler = create_tcp_client_handler(*protocol, None);

            Box::new(TlsClientHandler::new(client_config, server_name, handler))
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
                matching_headers,
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
