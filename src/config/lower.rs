//! Structural lowering after source settings validation.

use super::resolved::*;
use super::{ClientConfig, ClientProxyConfig};

pub(super) fn client(
    source: ClientConfig,
    carrier: Option<ResolvedClientChain>,
) -> ResolvedClientConfig {
    ResolvedClientConfig {
        name: source.name,
        control: source.control,
        bind_interface: source.bind_interface,
        address: source.address,
        protocol: client_protocol(source.protocol, carrier),
        transport: source.transport,
        tcp_settings: source.tcp_settings,
        quic_settings: source.quic_settings,
    }
}

fn client_protocol(
    source: ClientProxyConfig,
    carrier: Option<ResolvedClientChain>,
) -> ResolvedClientProxyConfig {
    match source {
        ClientProxyConfig::SudokuMask(config) => {
            ResolvedClientProxyConfig::SudokuMask(crate::sudoku_mask::SudokuMaskConfig {
                password: config.password,
                ascii: config.ascii,
                custom_table: config.custom_table,
                custom_tables: config.custom_tables,
                padding_min: config.padding_min,
                padding_max: config.padding_max,
                protocol: Box::new(client_protocol(*config.protocol, None)),
            })
        }
        ClientProxyConfig::Direct => ResolvedClientProxyConfig::Direct,
        ClientProxyConfig::Wireguard(config) => {
            ResolvedClientProxyConfig::Wireguard(Box::new(ResolvedWireguardClientConfig {
                settings: super::types::wireguard::WireguardClientRecord {
                    private_key: config.private_key,
                    public_key: config.public_key,
                    pre_shared_key: config.pre_shared_key,
                    addresses: config.addresses,
                    allowed_ips: config.allowed_ips,
                    persistent_keepalive: config.persistent_keepalive,
                    mtu: config.mtu,
                    resource_limits: config.resource_limits,
                    peer_client_chain: carrier,
                },
                endpoint_id: String::new(),
                connector: None,
            }))
        }
        ClientProxyConfig::Http {
            username,
            password,
            resolve_hostname,
            http_version,
        } => ResolvedClientProxyConfig::Http {
            username,
            password,
            resolve_hostname,
            http_version,
        },
        ClientProxyConfig::Socks { username, password } => {
            ResolvedClientProxyConfig::Socks { username, password }
        }
        ClientProxyConfig::Shadowsocks {
            config,
            udp_enabled,
        } => ResolvedClientProxyConfig::Shadowsocks {
            config,
            udp_enabled,
        },
        ClientProxyConfig::Snell {
            config,
            udp_enabled,
        } => ResolvedClientProxyConfig::Snell {
            config,
            udp_enabled,
        },
        ClientProxyConfig::Vless {
            user_id,
            encryption,
            _invalid_decryption,
            vision,
            udp_enabled,
            h2mux,
        } => ResolvedClientProxyConfig::Vless {
            user_id,
            encryption,
            _invalid_decryption,
            vision,
            udp_enabled,
            h2mux,
        },
        ClientProxyConfig::Trojan {
            password,
            shadowsocks,
            h2mux,
        } => ResolvedClientProxyConfig::Trojan {
            password,
            shadowsocks,
            h2mux,
        },
        ClientProxyConfig::Reality {
            mldsa65_verify,
            public_key,
            short_id,
            sni_hostname,
            cipher_suites,
            vision,
            protocol,
        } => ResolvedClientProxyConfig::Reality {
            mldsa65_verify,
            public_key,
            short_id,
            sni_hostname,
            cipher_suites,
            vision,
            protocol: Box::new(client_protocol(*protocol, None)),
        },
        ClientProxyConfig::ShadowTls {
            password,
            sni_hostname,
            protocol,
        } => ResolvedClientProxyConfig::ShadowTls {
            password,
            sni_hostname,
            protocol: Box::new(client_protocol(*protocol, None)),
        },
        ClientProxyConfig::Tls(config) => ResolvedClientProxyConfig::Tls(ResolvedTlsClientConfig {
            key_exchange_groups: config.key_exchange_groups,
            verify: config.verify,
            server_fingerprints: config.server_fingerprints,
            sni_hostname: config.sni_hostname,
            alpn_protocols: config.alpn_protocols,
            tls_buffer_size: config.tls_buffer_size,
            key: config.key,
            cert: config.cert,
            vision: config.vision,
            protocol: Box::new(client_protocol(*config.protocol, None)),
        }),
        ClientProxyConfig::Vmess {
            cipher,
            user_id,
            udp_enabled,
            h2mux,
        } => ResolvedClientProxyConfig::Vmess {
            cipher,
            user_id,
            udp_enabled,
            h2mux,
        },
        ClientProxyConfig::Websocket(config) => {
            ResolvedClientProxyConfig::Websocket(ResolvedWebsocketClientConfig {
                matching_path: config.matching_path,
                matching_headers: config.matching_headers,
                ping_type: config.ping_type,
                protocol: Box::new(client_protocol(*config.protocol, None)),
            })
        }
        ClientProxyConfig::Xhttp(config) => {
            ResolvedClientProxyConfig::Xhttp(ResolvedXhttpClientConfig {
                path: config.path,
                host: config.host,
                mode: config.mode,
                http_version: config.http_version,
                x_padding_bytes: config.x_padding_bytes,
                sc_max_each_post_bytes: config.sc_max_each_post_bytes,
                sc_min_posts_interval_ms: config.sc_min_posts_interval_ms,
                no_grpc_header: config.no_grpc_header,
                download_idle_timeout_secs: config.download_idle_timeout_secs,
                packet_pipeline_depth: config.packet_pipeline_depth,
                headers: config.headers,
                limits: config.limits,
                pool: config.pool,
                protocol: Box::new(client_protocol(*config.protocol, None)),
            })
        }
        ClientProxyConfig::PortForward => ResolvedClientProxyConfig::PortForward,
        ClientProxyConfig::Anytls {
            password,
            udp_enabled,
            padding_scheme,
        } => ResolvedClientProxyConfig::Anytls {
            password,
            udp_enabled,
            padding_scheme,
        },
        ClientProxyConfig::Naiveproxy {
            username,
            password,
            padding,
        } => ResolvedClientProxyConfig::Naiveproxy {
            username,
            password,
            padding,
        },
    }
}
