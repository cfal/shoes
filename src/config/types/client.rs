//! Client configuration types.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::address::NetLocation;
use crate::option_util::{NoneOrOne, NoneOrSome};

use super::common::{default_reality_client_short_id, default_true, unspecified_address};
use super::server::WebsocketPingType;
use super::shadowsocks::ShadowsocksConfig;
use super::transport::{ClientQuicConfig, TcpConfig, Transport};

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
    #[serde(default)]
    pub bind_interface: NoneOrOne<String>,
    #[serde(default = "unspecified_address")]
    pub address: NetLocation,
    pub protocol: ClientProxyConfig,
    #[serde(default)]
    pub transport: Transport,
    #[serde(default)]
    pub tcp_settings: Option<TcpConfig>,
    #[serde(default)]
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
    Snell(ShadowsocksConfig),
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
    Reality {
        public_key: String,
        #[serde(default = "default_reality_client_short_id")]
        short_id: String,
        #[serde(default)]
        sni_hostname: Option<String>,

        /// TLS 1.3 cipher suites to use (optional)
        /// Valid values: "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"
        /// If empty or not specified, all three cipher suites are offered.
        #[serde(alias = "cipher_suite", default)]
        cipher_suites: NoneOrSome<crate::reality::CipherSuite>,

        /// Enable XTLS-Vision protocol for TLS-in-TLS optimization.
        /// When enabled, the inner protocol MUST be VLESS.
        #[serde(default)]
        vision: bool,

        protocol: Box<ClientProxyConfig>,
    },
    #[serde(alias = "shadowtls")]
    ShadowTls {
        /// ShadowTLS password for authentication
        password: String,

        /// Optional SNI hostname override
        #[serde(default)]
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
        #[serde(default = "default_true")]
        udp_enabled: bool,
    },
    #[serde(alias = "ws")]
    Websocket(WebsocketClientConfig),
    #[serde(alias = "noop")]
    PortForward,
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
            ClientProxyConfig::Shadowsocks(..) => "Shadowsocks",
            ClientProxyConfig::Snell(..) => "Snell",
            ClientProxyConfig::Vless { .. } => "VLESS",
            ClientProxyConfig::Trojan { .. } => "Trojan",
            ClientProxyConfig::Reality { .. } => "Reality",
            ClientProxyConfig::Tls(..) => "TLS",
            ClientProxyConfig::ShadowTls { .. } => "ShadowTLS",
            ClientProxyConfig::Vmess { .. } => "VMess",
            ClientProxyConfig::Websocket(..) => "WebSocket",
            ClientProxyConfig::PortForward => "PortForward",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsClientConfig {
    #[serde(default = "default_true")]
    pub verify: bool,
    #[serde(alias = "server_fingerprint", default)]
    pub server_fingerprints: NoneOrSome<String>,
    #[serde(default)]
    pub sni_hostname: NoneOrOne<String>,
    #[serde(alias = "alpn_protocol", default)]
    pub alpn_protocols: NoneOrSome<String>,
    #[serde(default)]
    pub tls_buffer_size: Option<usize>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub cert: Option<String>,

    /// Enable XTLS-Vision protocol for TLS-in-TLS optimization.
    /// When enabled, the inner protocol MUST be VLESS.
    /// Requires TLS 1.3.
    #[serde(default)]
    pub vision: bool,

    pub protocol: Box<ClientProxyConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebsocketClientConfig {
    #[serde(default)]
    pub matching_path: Option<String>,
    #[serde(default)]
    pub matching_headers: Option<HashMap<String, String>>,
    #[serde(default)]
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
