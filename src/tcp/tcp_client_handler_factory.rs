//! Factory functions for creating TCP client handlers from config.

use std::sync::Arc;

use log::debug;

use crate::client_proxy_selector::{ClientProxySelector, ConnectAction, ConnectRule};
use crate::config::{
    ClientProxyConfig, RuleActionConfig, RuleConfig, ShadowsocksConfig, TlsClientConfig,
    WebsocketClientConfig,
};
use crate::http_handler::HttpTcpClientHandler;
use crate::port_forward_handler::PortForwardClientHandler;
use crate::rustls_config_util::create_client_config;
use crate::shadow_tls::ShadowTlsClientHandler;
use crate::shadowsocks::ShadowsocksTcpHandler;
use crate::snell::snell_handler::SnellClientHandler;
use crate::socks_handler::SocksTcpClientHandler;
use crate::tcp::chain_builder::build_client_chain_group;
use crate::tcp_handler::TcpClientHandler;
use crate::tls_client_handler::TlsClientHandler;
use crate::trojan_handler::TrojanTcpHandler;
use crate::vless::vless_client_handler::VlessTcpClientHandler;
use crate::vmess::VmessTcpClientHandler;
use crate::websocket::WebsocketTcpClientHandler;

fn create_auth_credentials(
    username: Option<String>,
    password: Option<String>,
) -> Option<(String, String)> {
    match (&username, &password) {
        (None, None) => None,
        _ => Some((username.unwrap_or_default(), password.unwrap_or_default())),
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
        ClientProxyConfig::Shadowsocks(ShadowsocksConfig::Legacy { cipher, password }) => {
            Box::new(ShadowsocksTcpHandler::new(cipher, &password))
        }
        ClientProxyConfig::Shadowsocks(ShadowsocksConfig::Aead2022 { cipher, key_bytes }) => {
            Box::new(ShadowsocksTcpHandler::new_aead2022(cipher, &key_bytes))
        }
        ClientProxyConfig::Snell(ShadowsocksConfig::Legacy { cipher, password }) => {
            Box::new(SnellClientHandler::new(cipher, &password))
        }
        ClientProxyConfig::Snell(ShadowsocksConfig::Aead2022 { .. }) => {
            panic!(
                "Snell does not support shadowsocks 2022 ciphers (checked during config validation)"
            )
        }
        ClientProxyConfig::Vless {
            user_id,
            udp_enabled,
        } => {
            // Plain VLESS without TLS
            Box::new(VlessTcpClientHandler::new(&user_id, udp_enabled))
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
                let ClientProxyConfig::Vless {
                    user_id,
                    udp_enabled,
                } = protocol.as_ref()
                else {
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
                    *udp_enabled,
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
            cipher_suites,
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

            let cipher_suites = cipher_suites.into_vec();

            if vision {
                let ClientProxyConfig::Vless {
                    user_id,
                    udp_enabled,
                } = protocol.as_ref()
                else {
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
                        cipher_suites,
                        user_id_bytes,
                        *udp_enabled,
                    ),
                )
            } else {
                let inner_handler = create_tcp_client_handler(*protocol, None);
                Box::new(crate::reality_client_handler::RealityClientHandler::new(
                    public_key_bytes,
                    short_id_bytes,
                    server_name,
                    cipher_suites,
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
        ClientProxyConfig::Vmess {
            cipher,
            user_id,
            udp_enabled,
        } => Box::new(VmessTcpClientHandler::new(&cipher, &user_id, udp_enabled)),
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
        ClientProxyConfig::Hysteria2 { .. } => {
            panic!("Hysteria2 is a QUIC protocol and should be handled by the socket connector, not as a TCP client handler. Ensure Hysteria2 configs use transport: quic.")
        }
    }
}

pub fn create_tcp_client_proxy_selector(rules: Vec<RuleConfig>) -> ClientProxySelector {
    let rules = rules
        .into_iter()
        .map(|rule_config| {
            let RuleConfig { masks, action } = rule_config;
            let connect_action = match action {
                RuleActionConfig::Allow {
                    override_address,
                    client_chains,
                } => {
                    let chain_group = build_client_chain_group(client_chains);
                    ConnectAction::new_allow(override_address, chain_group)
                }
                RuleActionConfig::Block => ConnectAction::new_block(),
            };
            ConnectRule::new(masks.into_vec(), connect_action)
        })
        .collect::<Vec<_>>();
    ClientProxySelector::new(rules)
}
