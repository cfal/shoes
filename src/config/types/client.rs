//! Client configuration types.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::address::NetLocation;
use crate::option_util::{NoneOrOne, NoneOrSome};

use super::common::{
    default_reality_client_short_id, default_true, is_false, is_true, unspecified_address,
};
use super::server::WebsocketPingType;
use super::shadowsocks::ShadowsocksConfig;
use super::transport::{ClientQuicConfig, TcpConfig, Transport};

/// Custom deserializer for ClientProxyConfig::Shadowsocks
fn deserialize_shadowsocks_client<'de, D>(
    deserializer: D,
) -> Result<(ShadowsocksConfig, bool), D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ShadowsocksClientTemp {
        cipher: String,
        password: String,
        #[serde(default = "default_true")]
        udp_enabled: bool,
    }

    let temp = ShadowsocksClientTemp::deserialize(deserializer)?;
    let config =
        ShadowsocksConfig::from_fields(&temp.cipher, &temp.password).map_err(Error::custom)?;

    Ok((config, temp.udp_enabled))
}

/// Custom serializer for ClientProxyConfig::Shadowsocks - flattens config fields
fn serialize_shadowsocks_client<S>(
    config: &ShadowsocksConfig,
    udp_enabled: &bool,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeStruct;

    // Only serialize udp_enabled if it's not the default (true)
    let field_count = if *udp_enabled { 2 } else { 3 };
    let mut state = serializer.serialize_struct("Shadowsocks", field_count)?;
    config.serialize_fields(&mut state)?;
    if !*udp_enabled {
        state.serialize_field("udp_enabled", udp_enabled)?;
    }
    state.end()
}

/// Custom deserializer for ClientProxyConfig::Snell - flattens config fields
fn deserialize_snell_client<'de, D>(deserializer: D) -> Result<(ShadowsocksConfig, bool), D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SnellClientTemp {
        cipher: String,
        password: String,
        #[serde(default = "default_true")]
        udp_enabled: bool,
    }

    let temp = SnellClientTemp::deserialize(deserializer)?;
    let config =
        ShadowsocksConfig::from_fields(&temp.cipher, &temp.password).map_err(Error::custom)?;

    Ok((config, temp.udp_enabled))
}

/// Custom serializer for ClientProxyConfig::Snell - flattens config fields
fn serialize_snell_client<S>(
    config: &ShadowsocksConfig,
    udp_enabled: &bool,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeStruct;

    // Only serialize udp_enabled if it's not the default (true)
    let field_count = if *udp_enabled { 2 } else { 3 };
    let mut state = serializer.serialize_struct("Snell", field_count)?;
    config.serialize_fields(&mut state)?;
    if !*udp_enabled {
        state.serialize_field("udp_enabled", udp_enabled)?;
    }
    state.end()
}

/// Custom deserializer for ClientProxyConfig::Vmess that validates legacy aead field
fn deserialize_vmess_client<'de, D>(deserializer: D) -> Result<(String, String, bool), D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct VmessClientTemp {
        cipher: String,
        user_id: String,
        #[serde(default, alias = "force_aead")]
        aead: Option<bool>,
        #[serde(default = "default_true")]
        udp_enabled: bool,
    }

    let temp = VmessClientTemp::deserialize(deserializer)?;

    // Check if aead/force_aead was explicitly set
    if let Some(aead_value) = temp.aead {
        if !aead_value {
            return Err(Error::custom(
                "Non-AEAD VMess mode (aead=false or force_aead=false) is no longer supported. \
                 Please remove the aead/force_aead field from your configuration, or set it to true.",
            ));
        }
        // Warn about deprecated field
        log::warn!(
            "The 'aead'/'force_aead' field in VMess client configuration is deprecated and will be removed in a future version. \
             AEAD mode is now always enabled. Please remove this field from your configuration."
        );
    }

    Ok((temp.cipher, temp.user_id, temp.udp_enabled))
}

/// Custom deserializer for TlsClientConfig that handles deprecated shadowtls_password field
fn deserialize_tls_client_config<'de, D>(deserializer: D) -> Result<TlsClientConfig, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TlsClientConfigTemp {
        #[serde(default = "default_true")]
        verify: bool,
        #[serde(alias = "server_fingerprint", default)]
        server_fingerprints: NoneOrSome<String>,
        #[serde(default)]
        sni_hostname: NoneOrOne<String>,
        #[serde(alias = "alpn_protocol", default)]
        alpn_protocols: NoneOrSome<String>,
        #[serde(default)]
        tls_buffer_size: Option<usize>,
        #[serde(default)]
        key: Option<String>,
        #[serde(default)]
        cert: Option<String>,
        #[serde(default)]
        shadowtls_password: Option<String>,
        #[serde(default)]
        vision: bool,
        protocol: Box<ClientProxyConfig>,
    }

    let temp = TlsClientConfigTemp::deserialize(deserializer)?;

    // Check for mutually exclusive fields
    if temp.vision && temp.shadowtls_password.is_some() {
        return Err(Error::custom(
            "TLS client config cannot have both vision=true and shadowtls_password set. \
             Vision and ShadowTLS are incompatible. \
             Use either 'vision: true' with regular TLS, or 'type: shadowtls' for ShadowTLS.",
        ));
    }

    // Check if deprecated shadowtls_password was used
    if let Some(password) = temp.shadowtls_password {
        log::warn!(
            "The 'shadowtls_password' field in TLS client configuration is deprecated. \
             Please use 'type: shadowtls' with 'password' field instead. \
             This field will be removed in a future version."
        );

        // Transform to ShadowTLS variant internally by wrapping protocol
        return Ok(TlsClientConfig {
            verify: temp.verify,
            server_fingerprints: temp.server_fingerprints,
            sni_hostname: temp.sni_hostname.clone(),
            alpn_protocols: temp.alpn_protocols,
            tls_buffer_size: temp.tls_buffer_size,
            key: temp.key,
            cert: temp.cert,
            vision: false,
            protocol: Box::new(ClientProxyConfig::ShadowTls {
                password,
                sni_hostname: temp.sni_hostname.into_option(),
                protocol: temp.protocol,
            }),
        });
    }

    // Normal case - no shadowtls_password
    Ok(TlsClientConfig {
        verify: temp.verify,
        server_fingerprints: temp.server_fingerprints,
        sni_hostname: temp.sni_hostname,
        alpn_protocols: temp.alpn_protocols,
        tls_buffer_size: temp.tls_buffer_size,
        key: temp.key,
        cert: temp.cert,
        vision: temp.vision,
        protocol: temp.protocol,
    })
}

/// Variant deserializer for Tls in ClientProxyConfig enum
fn deserialize_tls_variant<'de, D>(deserializer: D) -> Result<TlsClientConfig, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_tls_client_config(deserializer)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    #[serde(default, skip_serializing_if = "NoneOrOne::is_unspecified")]
    pub bind_interface: NoneOrOne<String>,
    #[serde(
        default = "unspecified_address",
        skip_serializing_if = "NetLocation::is_unspecified"
    )]
    pub address: NetLocation,
    pub protocol: ClientProxyConfig,
    #[serde(default, skip_serializing_if = "Transport::is_default")]
    pub transport: Transport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_settings: Option<TcpConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic_settings: Option<ClientQuicConfig>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            bind_interface: NoneOrOne::None,
            address: unspecified_address(),
            protocol: ClientProxyConfig::Direct,
            transport: Transport::default(),
            tcp_settings: None,
            quic_settings: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ClientProxyConfig {
    Direct,
    Http {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        /// When true, resolve hostnames to IP addresses before passing to HTTP CONNECT.
        /// Used when the upstream proxy blocks by hostname.
        #[serde(default, skip_serializing_if = "is_false")]
        resolve_hostname: bool,
    },
    #[serde(alias = "socks5")]
    Socks {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
    },
    #[serde(
        alias = "ss",
        deserialize_with = "deserialize_shadowsocks_client",
        serialize_with = "serialize_shadowsocks_client"
    )]
    Shadowsocks {
        config: ShadowsocksConfig,
        udp_enabled: bool,
    },
    #[serde(
        deserialize_with = "deserialize_snell_client",
        serialize_with = "serialize_snell_client"
    )]
    Snell {
        config: ShadowsocksConfig,
        udp_enabled: bool,
    },
    Vless {
        user_id: String,
        #[serde(default = "default_true", skip_serializing_if = "is_true")]
        udp_enabled: bool,
    },
    Trojan {
        password: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        shadowsocks: Option<ShadowsocksConfig>,
    },
    Reality {
        public_key: String,
        #[serde(default = "default_reality_client_short_id")]
        short_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sni_hostname: Option<String>,

        /// TLS 1.3 cipher suites to use (optional)
        /// Valid values: "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"
        /// If empty or not specified, all three cipher suites are offered.
        #[serde(
            alias = "cipher_suite",
            default,
            skip_serializing_if = "NoneOrSome::is_unspecified"
        )]
        cipher_suites: NoneOrSome<crate::reality::CipherSuite>,

        /// Enable XTLS-Vision protocol for TLS-in-TLS optimization.
        /// When enabled, the inner protocol MUST be VLESS.
        #[serde(default, skip_serializing_if = "is_false")]
        vision: bool,

        protocol: Box<ClientProxyConfig>,
    },
    #[serde(alias = "shadowtls")]
    ShadowTls {
        /// ShadowTLS password for authentication
        password: String,

        /// Optional SNI hostname override
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sni_hostname: Option<String>,

        /// Inner protocol (typically VLESS, Trojan, etc.)
        protocol: Box<ClientProxyConfig>,
    },
    #[serde(deserialize_with = "deserialize_tls_variant")]
    Tls(TlsClientConfig),
    #[serde(deserialize_with = "deserialize_vmess_client")]
    Vmess {
        cipher: String,
        user_id: String,
        #[serde(default = "default_true", skip_serializing_if = "is_true")]
        udp_enabled: bool,
    },
    #[serde(alias = "ws")]
    Websocket(WebsocketClientConfig),
    #[serde(alias = "noop")]
    PortForward,
    /// AnyTLS outbound protocol
    Anytls {
        /// Authentication password
        password: String,
        /// UDP over TCP support (default: true)
        #[serde(default = "default_true", skip_serializing_if = "is_true")]
        udp_enabled: bool,
        /// Custom padding scheme (optional, uses default if not specified)
        /// Each line is a key=value pair like "stop=8" or "0=30-30"
        #[serde(default, skip_serializing_if = "Option::is_none")]
        padding_scheme: Option<Vec<String>>,
    },
    /// NaiveProxy client protocol (HTTP/2 CONNECT with padding)
    #[serde(alias = "naive")]
    Naiveproxy {
        /// Username for Basic Auth
        username: String,
        /// Password for Basic Auth
        password: String,
        /// Enable padding protocol (default: true)
        #[serde(default = "default_true", skip_serializing_if = "is_true")]
        padding: bool,
    },
    #[serde(alias = "hy2")]
    Hysteria2 {
        password: String,
        #[serde(default = "default_true")]
        udp_enabled: bool,
        #[serde(default)]
        fast_open: bool,
        /// Bandwidth configuration
        #[serde(default)]
        bandwidth: Option<Hysteria2Bandwidth>,
    },
}

/// Bandwidth configuration for Hysteria2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hysteria2Bandwidth {
    /// Upload bandwidth (e.g., "100 mbps", "1 gbps")
    pub up: Option<String>,
    /// Download bandwidth (e.g., "200 mbps", "1 gbps")
    pub down: Option<String>,
}

impl Hysteria2Bandwidth {
    /// Parse upload bandwidth to bytes per second
    pub fn parse_up(&self) -> std::io::Result<u64> {
        self.parse_bandwidth(&self.up, "up")
    }

    /// Parse download bandwidth to bytes per second
    pub fn parse_down(&self) -> std::io::Result<u64> {
        self.parse_bandwidth(&self.down, "down")
    }

    fn parse_bandwidth(&self, value: &Option<String>, field: &str) -> std::io::Result<u64> {
        let s = value.as_ref().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("bandwidth {} not specified", field))
        })?;

        let s = s.trim().to_lowercase();
        // Find first non-digit, non-dot, non-space character to separate number from unit
        let mut num_end = 0;
        for (i, c) in s.chars().enumerate() {
            if c.is_ascii_digit() || c == '.' {
                num_end = i + 1;
            } else if !c.is_whitespace() {
                break;
            }
        }

        let num_str = s[..num_end].trim();
        let unit = s[num_end..].trim();

        let num: f64 = num_str.parse().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("invalid bandwidth value: {}", s))
        })?;

        let multiplier = match unit {
            "bps" => 1.0,
            "kbps" | "k" => 1024.0,
            "mbps" | "m" => 1024.0 * 1024.0,
            "gbps" | "g" => 1024.0 * 1024.0 * 1024.0,
            "tbps" | "t" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
            "" => 1024.0 * 1024.0, // Default to mbps if no unit
            _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("unknown bandwidth unit: {}", unit))),
        };

        Ok((num * multiplier / 8.0) as u64) // Convert bits to bytes
    }
}

/// Resolve bandwidth config to actual bytes per second values
pub fn resolve_hysteria2_bandwidth(bandwidth: &Option<Hysteria2Bandwidth>) -> std::io::Result<(u64, u64)> {
    if let Some(bw) = bandwidth {
        let up = bw.parse_up().unwrap_or(0);
        let down = bw.parse_down().unwrap_or(0);
        Ok((up, down))
    } else {
        Ok((0, 0))
    }
}

impl ClientProxyConfig {
    pub fn is_direct(&self) -> bool {
        matches!(self, ClientProxyConfig::Direct)
    }

    /// Returns the protocol name for display/error messages
    pub fn protocol_name(&self) -> &str {
        match self {
            ClientProxyConfig::Direct => "Direct",
            ClientProxyConfig::Http { .. } => "HTTP",
            ClientProxyConfig::Socks { .. } => "SOCKS5",
            ClientProxyConfig::Shadowsocks { .. } => "Shadowsocks",
            ClientProxyConfig::Snell { .. } => "Snell",
            ClientProxyConfig::Vless { .. } => "VLESS",
            ClientProxyConfig::Trojan { .. } => "Trojan",
            ClientProxyConfig::Reality { .. } => "Reality",
            ClientProxyConfig::Tls(..) => "TLS",
            ClientProxyConfig::ShadowTls { .. } => "ShadowTLS",
            ClientProxyConfig::Vmess { .. } => "VMess",
            ClientProxyConfig::Websocket(..) => "WebSocket",
            ClientProxyConfig::PortForward => "PortForward",
            ClientProxyConfig::Anytls { .. } => "AnyTLS",
            ClientProxyConfig::Naiveproxy { .. } => "NaiveProxy",
            ClientProxyConfig::Hysteria2 { .. } => "Hysteria2",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsClientConfig {
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub verify: bool,
    #[serde(
        alias = "server_fingerprint",
        default,
        skip_serializing_if = "NoneOrSome::is_unspecified"
    )]
    pub server_fingerprints: NoneOrSome<String>,
    #[serde(default, skip_serializing_if = "NoneOrOne::is_unspecified")]
    pub sni_hostname: NoneOrOne<String>,
    #[serde(
        alias = "alpn_protocol",
        default,
        skip_serializing_if = "NoneOrSome::is_unspecified"
    )]
    pub alpn_protocols: NoneOrSome<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_buffer_size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,

    /// Enable XTLS-Vision protocol for TLS-in-TLS optimization.
    /// When enabled, the inner protocol MUST be VLESS.
    /// Requires TLS 1.3.
    #[serde(default, skip_serializing_if = "is_false")]
    pub vision: bool,

    pub protocol: Box<ClientProxyConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebsocketClientConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matching_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matching_headers: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "WebsocketPingType::is_default")]
    pub ping_type: WebsocketPingType,
    pub protocol: Box<ClientProxyConfig>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn create_test_client_config() -> ClientConfig {
        ClientConfig {
            bind_interface: NoneOrOne::One("eth0".to_string()),
            address: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 1080),
            protocol: ClientProxyConfig::Socks {
                username: Some("client_user".to_string()),
                password: Some("client_pass".to_string()),
            },
            transport: Transport::Tcp,
            tcp_settings: None,
            quic_settings: None,
        }
    }

    #[test]
    fn test_client_config_serialization() {
        let original = create_test_client_config();
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        println!("Client config YAML:\n{yaml_str}");
        let deserialized: ClientConfig =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
        assert!(matches!(
            deserialized.protocol,
            ClientProxyConfig::Socks { .. }
        ));
    }

    #[test]
    fn test_rejects_unknown_field_in_vmess_client() {
        // Test ClientProxyConfig::Vmess directly
        let yaml = r#"
type: vmess
cipher: aes-128-gcm
user_id: "b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4"
unknown_option: true
"#;
        let result: Result<ClientProxyConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field `unknown_option`"),
            "Error should mention unknown field: {err}"
        );
    }

    #[test]
    fn test_rejects_unknown_field_in_tls_client_config() {
        // Test ClientProxyConfig::Tls directly
        let yaml = r#"
type: tls
verify: true
wrong_field: "oops"
protocol:
  type: socks
"#;
        let result: Result<ClientProxyConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field `wrong_field`"),
            "Error should mention unknown field: {err}"
        );
    }

    #[test]
    fn test_rejects_unknown_field_in_client_config() {
        // Test ClientConfig directly
        let yaml = r#"
address: "127.0.0.1:9090"
protocol:
  type: socks
invalid_client_field: "bad"
"#;
        let result: Result<ClientConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field `invalid_client_field`"),
            "Error should mention unknown field: {err}"
        );
    }

    #[test]
    fn test_client_proxy_config_direct() {
        let yaml = r#"
type: direct
"#;
        let result: Result<ClientProxyConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        assert!(result.unwrap().is_direct());
    }

    #[test]
    fn test_client_proxy_config_socks() {
        let yaml = r#"
type: socks
username: "user"
password: "pass"
"#;
        let result: Result<ClientProxyConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ClientProxyConfig::Socks { .. }));
    }

    #[test]
    fn test_client_proxy_config_http() {
        let yaml = r#"
type: http
"#;
        let result: Result<ClientProxyConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ClientProxyConfig::Http { .. }));
    }

    #[test]
    fn test_websocket_client_config() {
        let yaml = r#"
type: websocket
matching_path: "/ws"
protocol:
  type: direct
"#;
        let result: Result<ClientProxyConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ClientProxyConfig::Websocket(_)));
    }
}
