//! Server configuration types.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::address::NetLocation;
use crate::option_util::{NoneOrSome, OneOrSome};

use super::common::{default_reality_server_short_ids, default_reality_time_diff, default_true};
use super::rules::{ClientChainHop, RuleConfig};
use super::selection::ConfigSelection;
use super::shadowsocks::ShadowsocksConfig;
use super::transport::{BindLocation, ServerQuicConfig, TcpConfig, Transport};

// Forward declarations for client types (used in ShadowTlsRemoteHandshake)
use super::client::ClientConfig;

/// Custom deserializer for ServerProxyConfig::Vmess that validates legacy force_aead field
fn deserialize_vmess_server<'de, D>(deserializer: D) -> Result<(String, String, bool), D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct VmessServerTemp {
        cipher: String,
        user_id: String,
        #[serde(default = "default_true")]
        udp_enabled: bool,
        #[serde(default)]
        force_aead: Option<bool>,
    }

    let temp = VmessServerTemp::deserialize(deserializer)?;

    // Check if force_aead was explicitly set
    if let Some(force_aead_value) = temp.force_aead {
        if !force_aead_value {
            return Err(Error::custom(
                "Non-AEAD VMess mode (force_aead=false) is no longer supported. \
                 Please remove the force_aead field from your configuration, or set it to true.",
            ));
        }
        // Warn about deprecated field
        log::warn!(
            "The 'force_aead' field in VMess server configuration is deprecated and will be removed in a future version. \
             AEAD mode is now always enabled. Please remove this field from your configuration."
        );
    }

    Ok((temp.cipher, temp.user_id, temp.udp_enabled))
}

pub fn direct_allow_rule() -> NoneOrSome<ConfigSelection<RuleConfig>> {
    NoneOrSome::One(ConfigSelection::Config(RuleConfig::default()))
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerConfig {
    #[serde(flatten)]
    pub bind_location: BindLocation,
    pub protocol: ServerProxyConfig,
    #[serde(alias = "transport", default)]
    pub transport: Transport,
    #[serde(default)]
    pub tcp_settings: Option<TcpConfig>,
    #[serde(default)]
    pub quic_settings: Option<ServerQuicConfig>,
    #[serde(alias = "rule", default = "direct_allow_rule")]
    pub rules: NoneOrSome<ConfigSelection<RuleConfig>>,
}

impl<'de> serde::de::Deserialize<'de> for ServerConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use serde::de::Error;

        let value = serde_yaml::Value::deserialize(deserializer)?;
        let map = value
            .as_mapping()
            .ok_or_else(|| Error::custom("ServerConfig must be a YAML mapping"))?;

        // Valid fields: address/path (bind_location), protocol, transport, tcp_settings, quic_settings, rules/rule
        const VALID_FIELDS: &[&str] = &[
            "address",
            "path", // BindLocation (flattened)
            "protocol",
            "transport",
            "tcp_settings",
            "quic_settings",
            "rules",
            "rule",
        ];

        // Check for unknown fields
        for key in map.keys() {
            if let Some(key_str) = key.as_str()
                && !VALID_FIELDS.contains(&key_str)
            {
                return Err(Error::custom(format!(
                    "unknown field `{}` in server config. Expected one of: {}",
                    key_str,
                    VALID_FIELDS.join(", ")
                )));
            }
        }

        // Parse bind_location (flattened - either address or path)
        let bind_location = if let Some(v) = map.get("address") {
            serde_yaml::from_value(v.clone())
                .map(BindLocation::Address)
                .map_err(|e| Error::custom(format!("invalid address: {e}")))?
        } else if let Some(v) = map.get("path") {
            serde_yaml::from_value(v.clone())
                .map(BindLocation::Path)
                .map_err(|e| Error::custom(format!("invalid path: {e}")))?
        } else {
            return Err(Error::custom(
                "server config must have either 'address' or 'path' field",
            ));
        };

        // Parse protocol (required)
        let protocol: ServerProxyConfig = map
            .get("protocol")
            .ok_or_else(|| Error::custom("missing 'protocol' field in server config"))
            .and_then(|v| {
                serde_yaml::from_value(v.clone())
                    .map_err(|e| Error::custom(format!("invalid protocol: {e}")))
            })?;

        // Parse transport (optional, default)
        let transport: Transport = map
            .get("transport")
            .map(|v| serde_yaml::from_value(v.clone()))
            .transpose()
            .map_err(|e| Error::custom(format!("invalid transport: {e}")))?
            .unwrap_or_default();

        // Parse tcp_settings (optional, skip if null)
        let tcp_settings: Option<TcpConfig> = map
            .get("tcp_settings")
            .filter(|v| !v.is_null())
            .map(|v| serde_yaml::from_value(v.clone()))
            .transpose()
            .map_err(|e| Error::custom(format!("invalid tcp_settings: {e}")))?;

        // Parse quic_settings (optional, skip if null)
        let quic_settings: Option<ServerQuicConfig> = map
            .get("quic_settings")
            .filter(|v| !v.is_null())
            .map(|v| serde_yaml::from_value(v.clone()))
            .transpose()
            .map_err(|e| Error::custom(format!("invalid quic_settings: {e}")))?;

        // Parse rules (optional, with alias "rule", default to direct_allow_rule, skip if null)
        let rules: NoneOrSome<ConfigSelection<RuleConfig>> = map
            .get("rules")
            .or_else(|| map.get("rule"))
            .filter(|v| !v.is_null())
            .map(|v| serde_yaml::from_value(v.clone()))
            .transpose()
            .map_err(|e| Error::custom(format!("invalid rules: {e}")))?
            .unwrap_or_else(direct_allow_rule);

        Ok(ServerConfig {
            bind_location,
            protocol,
            transport,
            tcp_settings,
            quic_settings,
            rules,
        })
    }
}

// REALITY Protocol Configuration

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RealityServerConfig {
    /// X25519 private key (32 bytes, base64url encoded)
    pub private_key: String,

    /// List of valid short IDs (hex strings, 0-16 chars each)
    #[serde(alias = "short_id", default = "default_reality_server_short_ids")]
    pub short_ids: OneOrSome<String>,

    /// Fallback destination (e.g., "example.com:443")
    pub dest: NetLocation,

    /// Maximum timestamp difference in milliseconds (optional)
    #[serde(default = "default_reality_time_diff")]
    pub max_time_diff: Option<u64>,

    /// Minimum client version [major, minor, patch] (optional)
    #[serde(default)]
    pub min_client_version: Option<[u8; 3]>,

    /// Maximum client version [major, minor, patch] (optional)
    #[serde(default)]
    pub max_client_version: Option<[u8; 3]>,

    /// TLS 1.3 cipher suites to support (optional)
    /// Valid values: "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"
    /// If empty or not specified, the default set is used.
    #[serde(alias = "cipher_suite", default)]
    pub cipher_suites: NoneOrSome<crate::reality::CipherSuite>,

    /// Enable XTLS-Vision protocol for TLS-in-TLS optimization.
    /// When enabled, the inner protocol MUST be VLESS.
    /// Vision detects TLS-in-TLS scenarios and switches to Direct mode for zero-copy performance.
    /// Reality provides censorship resistance while Vision provides performance optimization.
    #[serde(default)]
    pub vision: bool,
    /// Inner protocol (VLESS, Trojan, etc.)
    pub protocol: ServerProxyConfig,

    /// Override rules
    #[serde(alias = "override_rule", default)]
    pub override_rules: NoneOrSome<ConfigSelection<RuleConfig>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsServerConfig {
    pub cert: String,
    pub key: String,
    #[serde(alias = "alpn_protocol", default)]
    pub alpn_protocols: NoneOrSome<String>,

    // trusted CA certs that client certs must chain to.
    // note that if a client cert chains back to a cert in this field,
    // it is validated even if the leaf certificate is not in `client_fingerprints`
    // below.
    #[serde(alias = "client_ca_cert", default)]
    pub client_ca_certs: NoneOrSome<String>,

    // sha256 fingerprint of allowed client certificates
    //
    // To generate a new ECDSA client certificate:
    // 1. Generate private key with P-256 curve:
    //    openssl ecparam -genkey -name prime256v1 -out client.key
    // 2. Create self-signed certificate:
    //    openssl req -new -x509 -nodes -key client.key -out client.crt -days 365 -subj "/CN=Client"
    //
    // Get the certificate's SHA256 fingerprint:
    //    openssl x509 -in client.crt -noout -fingerprint -sha256
    //
    // Each generated key pair will be unique. Multiple fingerprints can be specified
    // to allow multiple client certificates.
    #[serde(alias = "client_fingerprint", default)]
    pub client_fingerprints: NoneOrSome<String>,

    /// Enable XTLS-Vision protocol for TLS-in-TLS optimization.
    /// When enabled, the inner protocol MUST be VLESS.
    /// Vision detects TLS-in-TLS scenarios and switches to Direct mode for zero-copy performance.
    /// Requires TLS 1.3.
    #[serde(default)]
    pub vision: bool,
    pub protocol: ServerProxyConfig,

    #[serde(alias = "override_rule", default)]
    pub override_rules: NoneOrSome<ConfigSelection<RuleConfig>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ShadowTlsServerConfig {
    pub password: String,
    pub handshake: ShadowTlsServerHandshakeConfig,
    pub protocol: ServerProxyConfig,
    #[serde(alias = "override_rule", default)]
    pub override_rules: NoneOrSome<ConfigSelection<RuleConfig>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowTlsLocalHandshake {
    pub cert: String,
    pub key: String,
    #[serde(
        alias = "alpn_protocol",
        default,
        skip_serializing_if = "NoneOrSome::is_unspecified"
    )]
    pub alpn_protocols: NoneOrSome<String>,
    #[serde(
        alias = "client_ca_cert",
        default,
        skip_serializing_if = "NoneOrSome::is_unspecified"
    )]
    pub client_ca_certs: NoneOrSome<String>,
    #[serde(
        alias = "client_fingerprint",
        default,
        skip_serializing_if = "NoneOrSome::is_unspecified"
    )]
    pub client_fingerprints: NoneOrSome<String>,
}

#[derive(Debug, Clone)]
pub struct ShadowTlsRemoteHandshake {
    pub address: NetLocation,
    /// Ordered chain of proxy hops for reaching the remote handshake server.
    /// Guaranteed to be non-empty - if not specified, defaults to a single direct hop.
    pub client_chain: OneOrSome<ClientChainHop>,
}

impl<'de> Deserialize<'de> for ShadowTlsRemoteHandshake {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ShadowTlsRemoteHandshakeTemp {
            address: NetLocation,
            /// Legacy field - will be converted to client_chain
            #[serde(alias = "client_proxy", default)]
            client_proxies: NoneOrSome<ConfigSelection<ClientConfig>>,
            /// New field
            #[serde(default)]
            client_chain: NoneOrSome<ClientChainHop>,
        }

        let temp = ShadowTlsRemoteHandshakeTemp::deserialize(deserializer)?;

        // Check for conflicting fields
        let has_client_proxies = !temp.client_proxies.is_empty();
        let has_client_chain = !temp.client_chain.is_empty();

        if has_client_proxies && has_client_chain {
            return Err(D::Error::custom(
                "cannot specify both 'client_proxies' and 'client_chain' in ShadowTLS remote handshake. \
                 'client_proxies' is deprecated - please use 'client_chain' instead.",
            ));
        }

        // Convert client_proxies to client_chain if present
        let client_chain: OneOrSome<ClientChainHop> = if has_client_proxies {
            log::warn!(
                "The 'client_proxies' field in ShadowTLS remote handshake is deprecated and will be removed in a future version. \
                 Please use 'client_chain' instead. Your config will continue to work, but consider updating it."
            );

            // Convert to client_chain format:
            // - Single proxy -> Single hop
            // - Multiple proxies -> Pool hop
            let proxy_list = temp.client_proxies.into_vec();
            if proxy_list.len() == 1 {
                let selection = proxy_list.into_iter().next().unwrap();
                OneOrSome::One(ClientChainHop::Single(selection))
            } else {
                // Multiple client_proxies entries mean a pool
                let selections: Vec<ConfigSelection<ClientConfig>> = proxy_list;
                OneOrSome::One(ClientChainHop::Pool(OneOrSome::Some(selections)))
            }
        } else if has_client_chain {
            // client_chain specified - convert NoneOrSome to OneOrSome
            let hops = temp.client_chain.into_vec();
            if hops.len() == 1 {
                OneOrSome::One(hops.into_iter().next().unwrap())
            } else {
                OneOrSome::Some(hops)
            }
        } else {
            // Default: single direct hop
            OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                ClientConfig::default(),
            )))
        };

        Ok(ShadowTlsRemoteHandshake {
            address: temp.address,
            client_chain,
        })
    }
}

impl Serialize for ShadowTlsRemoteHandshake {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("address", &self.address)?;
        map.serialize_entry("client_chain", &self.client_chain)?;
        map.end()
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ShadowTlsServerHandshakeConfig {
    // Do the handshake locally with the provided TLS config.
    // This does not require a remote server, but for most clients,
    // the provided certificate must be signed by a trusted CA.
    Local(ShadowTlsLocalHandshake),
    Remote(ShadowTlsRemoteHandshake),
}

impl<'de> serde::de::Deserialize<'de> for ShadowTlsServerHandshakeConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use serde::de::Error;
        use serde_yaml::Value;

        // First deserialize to a generic Value to inspect the structure
        let value = Value::deserialize(deserializer)?;

        // Check if it's a mapping (as it should be)
        let map = value.as_mapping().ok_or_else(|| {
            Error::custom("Expected a YAML mapping for ShadowTLS handshake config")
        })?;

        // Look for discriminating fields
        let has_cert = map.contains_key(Value::String("cert".to_string()));
        let has_key = map.contains_key(Value::String("key".to_string()));
        let has_address = map.contains_key(Value::String("address".to_string()));

        if has_cert || has_key {
            // This is a Local handshake config
            let handshake: ShadowTlsLocalHandshake =
                serde_yaml::from_value(value).map_err(|e| {
                    Error::custom(format!(
                        "Failed to parse local ShadowTLS handshake config: {e}. \
                    Local handshake requires 'cert' and 'key' fields, with optional \
                    'alpn_protocols', 'client_ca_certs', and 'client_fingerprints'"
                    ))
                })?;

            Ok(ShadowTlsServerHandshakeConfig::Local(handshake))
        } else if has_address {
            // This is a Remote handshake config
            let handshake: ShadowTlsRemoteHandshake =
                serde_yaml::from_value(value).map_err(|e| {
                    Error::custom(format!(
                        "Failed to parse remote ShadowTLS handshake config: {e}. \
                    Remote handshake requires 'address' field, with optional 'client_chain'"
                    ))
                })?;

            Ok(ShadowTlsServerHandshakeConfig::Remote(handshake))
        } else {
            // Provide a helpful error message
            let found_fields: Vec<String> = map
                .keys()
                .filter_map(|k| k.as_str().map(|s| s.to_string()))
                .collect();

            Err(Error::custom(format!(
                "Unable to determine ShadowTLS handshake type. Found fields: {found_fields:?}. Expected one of:\n\
                - Local handshake: must have 'cert' and 'key' fields\n\
                - Remote handshake: must have 'address' field"
            )))
        }
    }
}

impl serde::ser::Serialize for ShadowTlsServerHandshakeConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        match self {
            ShadowTlsServerHandshakeConfig::Local(handshake) => handshake.serialize(serializer),
            ShadowTlsServerHandshakeConfig::Remote(handshake) => handshake.serialize(serializer),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebsocketServerConfig {
    #[serde(default)]
    pub matching_path: Option<String>,
    #[serde(default)]
    pub matching_headers: Option<HashMap<String, String>>,
    pub protocol: ServerProxyConfig,
    #[serde(default)]
    pub ping_type: WebsocketPingType,

    #[serde(alias = "override_rule", default)]
    pub override_rules: NoneOrSome<ConfigSelection<RuleConfig>>,
}

#[derive(Default, Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum WebsocketPingType {
    Disabled,
    // Ping frames are better if the websocket (or a proxy) requires it to stop from timing
    // out because it causes the remote end to write a pong, which could prevent the connection
    // from timing out.
    // However, some clients (e.g. Quantumult-X) can't handle ping frames and disconnects when
    // one is received, so empty frames can be better for compatibility.
    #[serde(alias = "ping", alias = "ping-frame")]
    #[default]
    PingFrame,
    #[serde(alias = "empty", alias = "empty-frame")]
    EmptyFrame,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ServerProxyConfig {
    Http {
        username: Option<String>,
        password: Option<String>,
    },
    #[serde(alias = "socks5")]
    Socks {
        username: Option<String>,
        password: Option<String>,
    },
    #[serde(alias = "ss")]
    Shadowsocks(ShadowsocksConfig),
    Snell {
        cipher: String,
        password: String,
        #[serde(default = "default_true")]
        udp_enabled: bool,
    },
    Vless {
        user_id: String,
        #[serde(default = "default_true")]
        udp_enabled: bool,
    },
    Trojan {
        password: String,
        #[serde(default)]
        shadowsocks: Option<ShadowsocksConfig>,
    },
    Tls {
        // sni_targets is the previous field name
        #[serde(default, alias = "sni_targets", alias = "targets")]
        tls_targets: HashMap<String, TlsServerConfig>,
        // default_target is the previous field name
        #[serde(default, alias = "default_target")]
        default_tls_target: Option<Box<TlsServerConfig>>,
        #[serde(default)]
        shadowtls_targets: HashMap<String, ShadowTlsServerConfig>,
        #[serde(default)]
        reality_targets: HashMap<String, RealityServerConfig>,

        #[serde(default)]
        tls_buffer_size: Option<usize>,
    },
    #[serde(deserialize_with = "deserialize_vmess_server")]
    Vmess {
        cipher: String,
        user_id: String,
        #[serde(default = "default_true")]
        udp_enabled: bool,
    },
    #[serde(alias = "ws")]
    Websocket {
        #[serde(alias = "target")]
        targets: Box<OneOrSome<WebsocketServerConfig>>,
    },
    #[serde(alias = "forward")]
    PortForward {
        #[serde(alias = "target")]
        targets: OneOrSome<NetLocation>,
    },
    Hysteria2 {
        password: String,
        #[serde(default = "default_true")]
        udp_enabled: bool,
    },
    #[serde(alias = "tuic")]
    TuicV5 {
        uuid: String,
        password: String,
        /// Enable 0-RTT (0.5-RTT for server) handshake for faster connection establishment.
        /// Default is false for security - 0-RTT data is vulnerable to replay attacks.
        /// See: https://blog.cloudflare.com/even-faster-connection-establishment-with-quic-0-rtt-resumption/
        #[serde(default)]
        zero_rtt_handshake: bool,
    },
}

impl std::fmt::Display for ServerProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http { .. } => write!(f, "HTTP"),
            Self::Socks { .. } => write!(f, "SOCKS"),
            Self::Shadowsocks { .. } => write!(f, "Shadowsocks"),
            Self::Snell { .. } => write!(f, "Snell"),
            Self::Vless { .. } => write!(f, "Vless"),
            Self::Trojan { .. } => write!(f, "Trojan"),
            Self::Tls {
                tls_targets,
                default_tls_target,
                shadowtls_targets,
                reality_targets,
                ..
            } => {
                let mut parts = vec![];

                if !tls_targets.is_empty() {
                    parts.push("TLS");
                }

                if !reality_targets.is_empty() {
                    parts.push("REALITY");
                }
                if !shadowtls_targets.is_empty() {
                    parts.push("ShadowTLSv3");
                }
                if tls_targets.values().any(|cfg| cfg.vision)
                    || default_tls_target.as_ref().is_some_and(|cfg| cfg.vision)
                    || reality_targets.values().any(|cfg| cfg.vision)
                {
                    parts.push("Vision");
                }

                write!(f, "{}", parts.join("+"))
            }
            Self::Vmess { .. } => write!(f, "Vmess"),
            Self::Websocket { .. } => write!(f, "Websocket"),
            Self::PortForward { .. } => write!(f, "Portforward"),
            Self::Hysteria2 { .. } => write!(f, "Hysteria2"),
            Self::TuicV5 { .. } => write!(f, "TuicV5"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;

    fn create_test_server_config_http() -> ServerConfig {
        ServerConfig {
            bind_location: BindLocation::Address(
                NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080).into(),
            ),
            protocol: ServerProxyConfig::Http {
                username: Some("user".to_string()),
                password: Some("pass".to_string()),
            },
            transport: Transport::Tcp,
            tcp_settings: Some(TcpConfig { no_delay: true }),
            quic_settings: None,
            rules: NoneOrSome::None,
        }
    }

    fn create_test_server_config_socks() -> ServerConfig {
        ServerConfig {
            bind_location: BindLocation::Address(
                NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1080).into(),
            ),
            protocol: ServerProxyConfig::Socks {
                username: None,
                password: None,
            },
            transport: Transport::Tcp,
            tcp_settings: None,
            quic_settings: None,
            rules: NoneOrSome::None,
        }
    }

    fn create_test_server_config_shadowsocks() -> ServerConfig {
        ServerConfig {
            bind_location: BindLocation::Path(PathBuf::from("/tmp/ss.sock")),
            protocol: ServerProxyConfig::Shadowsocks(ShadowsocksConfig::Legacy {
                cipher: "aes-256-gcm".try_into().unwrap(),
                password: "secret123".to_string(),
            }),
            transport: Transport::Tcp,
            tcp_settings: None,
            quic_settings: None,
            rules: NoneOrSome::None,
        }
    }

    fn create_test_server_config_vless() -> ServerConfig {
        ServerConfig {
            bind_location: BindLocation::Address(
                NetLocation::from_ip_addr(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 443)
                    .into(),
            ),
            protocol: ServerProxyConfig::Vless {
                user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                udp_enabled: true,
            },
            transport: Transport::Quic,
            tcp_settings: None,
            quic_settings: Some(ServerQuicConfig {
                cert: "server.crt".to_string(),
                key: "server.key".to_string(),
                alpn_protocols: NoneOrSome::Some(vec!["h3".to_string()]),
                client_ca_certs: NoneOrSome::None,
                client_fingerprints: NoneOrSome::None,
                num_endpoints: 1,
            }),
            rules: NoneOrSome::None,
        }
    }

    fn create_test_server_config_trojan() -> ServerConfig {
        ServerConfig {
            bind_location: BindLocation::Address(
                NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 443).into(),
            ),
            protocol: ServerProxyConfig::Trojan {
                password: "trojan_password".to_string(),
                shadowsocks: Some(ShadowsocksConfig::Legacy {
                    cipher: "chacha20-poly1305".try_into().unwrap(),
                    password: "ss_password".to_string(),
                }),
            },
            transport: Transport::Tcp,
            tcp_settings: None,
            quic_settings: None,
            rules: NoneOrSome::None,
        }
    }

    fn create_test_server_config_tls() -> ServerConfig {
        let mut tls_targets = HashMap::new();
        tls_targets.insert(
            "example.com".to_string(),
            TlsServerConfig {
                cert: "example.crt".to_string(),
                key: "example.key".to_string(),
                alpn_protocols: NoneOrSome::Some(vec!["h2".to_string(), "http/1.1".to_string()]),
                client_ca_certs: NoneOrSome::One("ca.crt".to_string()),
                client_fingerprints: NoneOrSome::One("abc123".to_string()),
                vision: false,
                protocol: ServerProxyConfig::Http {
                    username: None,
                    password: None,
                },
                override_rules: NoneOrSome::None,
            },
        );

        ServerConfig {
            bind_location: BindLocation::Address(
                NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8443).into(),
            ),
            protocol: ServerProxyConfig::Tls {
                tls_targets,
                default_tls_target: Some(Box::new(TlsServerConfig {
                    cert: "default.crt".to_string(),
                    key: "default.key".to_string(),
                    alpn_protocols: NoneOrSome::None,
                    client_ca_certs: NoneOrSome::None,
                    client_fingerprints: NoneOrSome::None,
                    vision: false,
                    protocol: ServerProxyConfig::Http {
                        username: None,
                        password: None,
                    },
                    override_rules: NoneOrSome::None,
                })),
                shadowtls_targets: HashMap::new(),
                reality_targets: HashMap::new(),
                tls_buffer_size: Some(8192),
            },
            transport: Transport::Tcp,
            tcp_settings: None,
            quic_settings: None,
            rules: NoneOrSome::None,
        }
    }

    fn create_test_server_config_vmess() -> ServerConfig {
        ServerConfig {
            bind_location: BindLocation::Address(
                NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 10086).into(),
            ),
            protocol: ServerProxyConfig::Vmess {
                cipher: "aes-128-gcm".to_string(),
                user_id: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
                udp_enabled: false,
            },
            transport: Transport::Tcp,
            tcp_settings: None,
            quic_settings: None,
            rules: NoneOrSome::None,
        }
    }

    fn create_test_server_config_websocket() -> ServerConfig {
        ServerConfig {
            bind_location: BindLocation::Address(
                NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080).into(),
            ),
            protocol: ServerProxyConfig::Websocket {
                targets: Box::new(OneOrSome::One(WebsocketServerConfig {
                    matching_path: Some("/ws".to_string()),
                    matching_headers: None,
                    protocol: ServerProxyConfig::Http {
                        username: None,
                        password: None,
                    },
                    ping_type: WebsocketPingType::PingFrame,
                    override_rules: NoneOrSome::None,
                })),
            },
            transport: Transport::Tcp,
            tcp_settings: None,
            quic_settings: None,
            rules: NoneOrSome::None,
        }
    }

    fn create_test_server_config_port_forward() -> ServerConfig {
        ServerConfig {
            bind_location: BindLocation::Address(
                NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9090).into(),
            ),
            protocol: ServerProxyConfig::PortForward {
                targets: OneOrSome::Some(vec![
                    NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80),
                    NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
                ]),
            },
            transport: Transport::Tcp,
            tcp_settings: None,
            quic_settings: None,
            rules: NoneOrSome::None,
        }
    }

    fn create_test_server_config_hysteria2() -> ServerConfig {
        ServerConfig {
            bind_location: BindLocation::Address(
                NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443).into(),
            ),
            protocol: ServerProxyConfig::Hysteria2 {
                password: "hysteria_pass".to_string(),
                udp_enabled: true,
            },
            transport: Transport::Quic,
            tcp_settings: None,
            quic_settings: Some(ServerQuicConfig {
                cert: "hysteria.crt".to_string(),
                key: "hysteria.key".to_string(),
                alpn_protocols: NoneOrSome::One("hysteria".to_string()),
                client_ca_certs: NoneOrSome::None,
                client_fingerprints: NoneOrSome::None,
                num_endpoints: 1,
            }),
            rules: NoneOrSome::None,
        }
    }

    fn create_test_server_config_tuic() -> ServerConfig {
        ServerConfig {
            bind_location: BindLocation::Address(
                NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8443).into(),
            ),
            protocol: ServerProxyConfig::TuicV5 {
                uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                password: "tuic_password".to_string(),
                zero_rtt_handshake: false,
            },
            transport: Transport::Quic,
            tcp_settings: None,
            quic_settings: Some(ServerQuicConfig {
                cert: "tuic.crt".to_string(),
                key: "tuic.key".to_string(),
                alpn_protocols: NoneOrSome::None,
                client_ca_certs: NoneOrSome::None,
                client_fingerprints: NoneOrSome::None,
                num_endpoints: 1,
            }),
            rules: NoneOrSome::None,
        }
    }

    // Test individual server config variants
    #[test]
    fn test_server_config_http() {
        let original = create_test_server_config_http();
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        println!("HTTP config YAML:\n{yaml_str}");
        let deserialized: ServerConfig =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
        assert!(matches!(
            deserialized.protocol,
            ServerProxyConfig::Http { .. }
        ));
    }

    #[test]
    fn test_server_config_socks() {
        let original = create_test_server_config_socks();
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: ServerConfig =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
        assert!(matches!(
            deserialized.protocol,
            ServerProxyConfig::Socks { .. }
        ));
    }

    #[test]
    fn test_server_config_shadowsocks() {
        let original = create_test_server_config_shadowsocks();
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        println!("Shadowsocks YAML: {yaml_str}");
        let deserialized: ServerConfig =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
        assert!(matches!(
            deserialized.protocol,
            ServerProxyConfig::Shadowsocks(_)
        ));
    }

    #[test]
    fn test_server_config_vless() {
        let original = create_test_server_config_vless();
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: ServerConfig =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
        assert!(matches!(
            deserialized.protocol,
            ServerProxyConfig::Vless { .. }
        ));
    }

    #[test]
    fn test_server_config_trojan() {
        let original = create_test_server_config_trojan();
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: ServerConfig =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
        assert!(matches!(
            deserialized.protocol,
            ServerProxyConfig::Trojan { .. }
        ));
    }

    #[test]
    fn test_server_config_tls() {
        let original = create_test_server_config_tls();
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: ServerConfig =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
        assert!(matches!(
            deserialized.protocol,
            ServerProxyConfig::Tls { .. }
        ));
    }

    #[test]
    fn test_server_config_vmess() {
        let original = create_test_server_config_vmess();
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: ServerConfig =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
        assert!(matches!(
            deserialized.protocol,
            ServerProxyConfig::Vmess { .. }
        ));
    }

    #[test]
    fn test_server_config_websocket() {
        let original = create_test_server_config_websocket();
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: ServerConfig =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
        assert!(matches!(
            deserialized.protocol,
            ServerProxyConfig::Websocket { .. }
        ));
    }

    #[test]
    fn test_server_config_port_forward() {
        let original = create_test_server_config_port_forward();
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: ServerConfig =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
        assert!(matches!(
            deserialized.protocol,
            ServerProxyConfig::PortForward { .. }
        ));
    }

    #[test]
    fn test_server_config_hysteria2() {
        let original = create_test_server_config_hysteria2();
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: ServerConfig =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
        assert!(matches!(
            deserialized.protocol,
            ServerProxyConfig::Hysteria2 { .. }
        ));
    }

    #[test]
    fn test_server_config_tuic() {
        let original = create_test_server_config_tuic();
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: ServerConfig =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
        assert!(matches!(
            deserialized.protocol,
            ServerProxyConfig::TuicV5 { .. }
        ));
    }

    #[test]
    fn test_rejects_invalid_upstream_field() {
        let yaml = r#"
address: "127.0.0.1:8080"
protocol:
  type: http
upstream:
  address: "127.0.0.1:443"
  protocol:
    type: vless
    user_id: "test-uuid"
"#;

        let result: Result<ServerConfig, _> = serde_yaml::from_str(yaml);
        assert!(
            result.is_err(),
            "Should reject config with invalid 'upstream' field"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") && err.contains("upstream"),
            "Error should mention 'upstream' as unknown field, got: {err}"
        );
    }

    #[test]
    fn test_rejects_typo_in_field_name() {
        let yaml = r#"
address: "127.0.0.1:8080"
protocl:
  type: http
"#;

        let result: Result<ServerConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "Should reject config with typo 'protocl'");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field") && err.contains("protocl"),
            "Error should mention 'protocl' as unknown field, got: {err}"
        );
    }

    #[test]
    fn test_accepts_valid_server_config() {
        let yaml = r#"
address: "127.0.0.1:8080"
protocol:
  type: http
rules:
  - mask: 0.0.0.0/0
    action: allow
"#;

        let result: Result<ServerConfig, _> = serde_yaml::from_str(yaml);
        assert!(
            result.is_ok(),
            "Should accept valid server config: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_accepts_valid_server_config_with_all_fields() {
        let yaml = r#"
address: "127.0.0.1:8080"
protocol:
  type: http
transport: tcp
tcp_settings:
  no_delay: true
rules:
  - mask: 0.0.0.0/0
    action: allow
"#;

        let result: Result<ServerConfig, _> = serde_yaml::from_str(yaml);
        assert!(
            result.is_ok(),
            "Should accept valid server config with all fields: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_rejects_unknown_field_in_vmess_server() {
        let yaml = r#"
address: "127.0.0.1:8080"
protocol:
  type: vmess
  cipher: aes-128-gcm
  user_id: "b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4"
  typo_field: "should fail"
"#;
        let result: Result<ServerConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field `typo_field`"),
            "Error should mention unknown field: {err}"
        );
    }

    #[test]
    fn test_rejects_unknown_field_in_shadowsocks() {
        let yaml = r#"
address: "127.0.0.1:8080"
protocol:
  type: shadowsocks
  cipher: aes-256-gcm
  password: "secret"
  invalid_field: 123
"#;
        let result: Result<ServerConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field `invalid_field`"),
            "Error should mention unknown field: {err}"
        );
    }

    #[test]
    fn test_shadowtls_handshake_serialization() {
        // Test local handshake with minimal fields
        let local = ShadowTlsLocalHandshake {
            cert: "server.crt".to_string(),
            key: "server.key".to_string(),
            alpn_protocols: NoneOrSome::Unspecified,
            client_ca_certs: NoneOrSome::Unspecified,
            client_fingerprints: NoneOrSome::Unspecified,
        };

        let yaml = serde_yaml::to_string(&local).unwrap();
        println!("Local handshake (minimal):\n{yaml}");

        // Should only contain cert and key
        assert!(yaml.contains("cert:"));
        assert!(yaml.contains("key:"));
        assert!(!yaml.contains("alpn_protocols:"));
        assert!(!yaml.contains("client_ca_certs:"));
        assert!(!yaml.contains("client_fingerprints:"));

        // Test remote handshake
        let remote = ShadowTlsRemoteHandshake {
            address: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443),
            client_chain: OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                super::super::client::ClientConfig::default(),
            ))),
        };

        let yaml = serde_yaml::to_string(&remote).unwrap();
        println!("Remote handshake (minimal):\n{yaml}");

        // Should contain address and client_chain
        assert!(yaml.contains("address:"));
        assert!(yaml.contains("client_chain:"));
    }

    #[test]
    fn test_shadowtls_handshake_error_messages() {
        // Test invalid handshake config with cert but missing key
        let invalid_missing_key = r#"
cert: "server.crt"
"#;

        let result: Result<ShadowTlsServerHandshakeConfig, _> =
            serde_yaml::from_str(invalid_missing_key);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        println!("Error for missing key: {error_msg}");
        assert!(error_msg.contains("Failed to parse local ShadowTLS handshake config"));
        assert!(error_msg.contains("missing field `key`"));
        assert!(error_msg.contains("Local handshake requires 'cert' and 'key' fields"));

        // Test invalid handshake config with mixed fields (cert + address)
        let invalid_mixed = r#"
cert: "server.crt"
address: "example.com:443"
"#;

        let result: Result<ShadowTlsServerHandshakeConfig, _> = serde_yaml::from_str(invalid_mixed);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        println!("Error for mixed handshake fields: {error_msg}");
        // Since it has cert, it will try to parse as Local and reject the unknown 'address' field
        assert!(error_msg.contains("Failed to parse local ShadowTLS handshake config"));
        assert!(error_msg.contains("unknown field `address`"));

        // Test invalid handshake with unknown fields only
        let invalid_unknown = r#"
unknown_field: "value"
another_field: 123
"#;

        let result: Result<ShadowTlsServerHandshakeConfig, _> =
            serde_yaml::from_str(invalid_unknown);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        println!("Error for unknown handshake fields: {error_msg}");
        assert!(error_msg.contains("Unable to determine ShadowTLS handshake type"));
        assert!(error_msg.contains("Found fields:"));
        assert!(error_msg.contains("unknown_field"));
        assert!(error_msg.contains("another_field"));

        // Test valid local handshake
        let valid_local = r#"
cert: "server.crt"
key: "server.key"
"#;

        let result: Result<ShadowTlsServerHandshakeConfig, _> = serde_yaml::from_str(valid_local);
        assert!(result.is_ok());
        assert!(matches!(
            result.unwrap(),
            ShadowTlsServerHandshakeConfig::Local(_)
        ));

        // Test valid remote handshake
        let valid_remote = r#"
address: "example.com:443"
"#;

        let result: Result<ShadowTlsServerHandshakeConfig, _> = serde_yaml::from_str(valid_remote);
        assert!(result.is_ok());
        assert!(matches!(
            result.unwrap(),
            ShadowTlsServerHandshakeConfig::Remote(_)
        ));

        // Test invalid remote with missing address value
        let invalid_remote_syntax = r#"
address:
"#;

        let result: Result<ShadowTlsServerHandshakeConfig, _> =
            serde_yaml::from_str(invalid_remote_syntax);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        println!("Error for invalid remote syntax: {error_msg}");
        // This will generate a parse error for NetLocation
        assert!(error_msg.contains("Failed to parse remote ShadowTLS handshake config"));
    }

    #[test]
    fn test_rejects_unknown_field_in_shadowtls_local_handshake() {
        // Test ShadowTlsServerHandshakeConfig directly
        let yaml = r#"
cert: "server.crt"
key: "server.key"
bad_option: "value"
"#;
        let result: Result<ShadowTlsServerHandshakeConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field `bad_option`"),
            "Error should mention unknown field: {err}"
        );
    }

    #[test]
    fn test_rejects_unknown_field_in_shadowtls_remote_handshake() {
        // Test ShadowTlsServerHandshakeConfig directly
        let yaml = r#"
address: "example.com:443"
misspelled: true
"#;
        let result: Result<ShadowTlsServerHandshakeConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field `misspelled`"),
            "Error should mention unknown field: {err}"
        );
    }

    #[test]
    fn test_shadowtls_remote_handshake_defaults_to_direct() {
        // When no client_chain or client_proxies is specified, should default to direct
        let yaml = r#"
address: "example.com:443"
"#;
        let result: Result<ShadowTlsRemoteHandshake, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok(), "Should parse: {:?}", result.err());
        let handshake = result.unwrap();
        assert_eq!(handshake.client_chain.len(), 1);
        // Check it's a direct config
        if let super::super::rules::ClientChainHop::Single(
            super::super::selection::ConfigSelection::Config(config),
        ) = handshake.client_chain.iter().next().unwrap()
        {
            assert!(config.protocol.is_direct());
        } else {
            panic!("Expected Single hop with direct Config");
        }
    }

    #[test]
    fn test_shadowtls_remote_handshake_with_client_chain() {
        let yaml = r#"
address: "example.com:443"
client_chain:
  - address: "proxy.example.com:1080"
    protocol:
      type: socks
"#;
        let result: Result<ShadowTlsRemoteHandshake, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok(), "Should parse: {:?}", result.err());
        let handshake = result.unwrap();
        assert_eq!(handshake.client_chain.len(), 1);
    }

    #[test]
    fn test_shadowtls_remote_handshake_with_deprecated_client_proxies() {
        // Should still work with deprecated client_proxies field
        let yaml = r#"
address: "example.com:443"
client_proxies:
  - address: "proxy.example.com:1080"
    protocol:
      type: socks
"#;
        let result: Result<ShadowTlsRemoteHandshake, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok(), "Should parse: {:?}", result.err());
        let handshake = result.unwrap();
        assert_eq!(handshake.client_chain.len(), 1);
    }

    #[test]
    fn test_shadowtls_remote_handshake_rejects_both_client_proxies_and_chain() {
        let yaml = r#"
address: "example.com:443"
client_proxies:
  - address: "proxy1.example.com:1080"
    protocol:
      type: socks
client_chain:
  - address: "proxy2.example.com:1080"
    protocol:
      type: socks
"#;
        let result: Result<ShadowTlsRemoteHandshake, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("cannot specify both"),
            "Error should mention cannot specify both: {err}"
        );
    }

    #[test]
    fn test_shadowtls_remote_handshake_serialization_roundtrip() {
        let yaml = r#"
address: "example.com:443"
client_chain:
  - address: "proxy.example.com:1080"
    protocol:
      type: socks
"#;
        let original: ShadowTlsRemoteHandshake = serde_yaml::from_str(yaml).unwrap();
        let serialized = serde_yaml::to_string(&original).unwrap();
        println!("Serialized:\n{serialized}");
        let deserialized: ShadowTlsRemoteHandshake = serde_yaml::from_str(&serialized).unwrap();
        assert_eq!(deserialized.client_chain.len(), original.client_chain.len());
    }
}
