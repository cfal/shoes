use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::address::{NetLocation, NetLocationMask, NetLocationPortRange};
use crate::option_util::{NoneOrOne, NoneOrSome, OneOrSome};

fn default_true() -> bool {
    true
}

fn default_snell_udp_num_sockets() -> usize {
    1
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BindLocation {
    Address(NetLocationPortRange),
    Path(PathBuf),
}

impl std::fmt::Display for BindLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindLocation::Address(n) => write!(f, "{n}"),
            BindLocation::Path(p) => write!(f, "{}", p.display()),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Quic,
    Udp,
}

impl Default for Transport {
    fn default() -> Self {
        Self::Tcp
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TcpConfig {
    #[serde(default = "default_true")]
    pub no_delay: bool,
}

impl Default for TcpConfig {
    fn default() -> Self {
        TcpConfig { no_delay: true }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerQuicConfig {
    pub cert: String,
    pub key: String,
    #[serde(alias = "alpn_protocol", default)]
    pub alpn_protocols: NoneOrSome<String>,
    #[serde(alias = "client_ca_cert", default)]
    pub client_ca_certs: NoneOrSome<String>,
    #[serde(alias = "client_fingerprint", default)]
    pub client_fingerprints: NoneOrSome<String>,
    // num_endpoints of 0 will use the number of threads as the default value.
    #[serde(default)]
    pub num_endpoints: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientConfigGroup {
    pub client_group: String,
    // TODO: do a topological sort and allow this to be OneOrSome<ConfigSelection>
    #[serde(alias = "client_proxy")]
    pub client_proxies: OneOrSome<ClientConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleConfigGroup {
    pub rule_group: String,
    #[serde(alias = "rule")]
    pub rules: OneOrSome<RuleConfig>,
}

#[derive(Debug, Clone)]
pub struct NamedPem {
    pub pem: String, // The name identifier
    pub source: PemSource,
}

#[derive(Debug, Clone)]
pub enum PemSource {
    Path(String),
    Data(String),
}

impl<'de> Deserialize<'de> for NamedPem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use serde::de::{Error, MapAccess, Visitor};
        use std::fmt;

        struct NamedPemVisitor;

        impl<'de> Visitor<'de> for NamedPemVisitor {
            type Value = NamedPem;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a NamedPem with 'pem' and either 'path' or 'data' fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut pem_name: Option<String> = None;
                let mut path: Option<String> = None;
                let mut data: Option<String> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "pem" => {
                            if pem_name.is_some() {
                                return Err(Error::duplicate_field("pem"));
                            }
                            pem_name = Some(map.next_value()?);
                        }
                        "path" => {
                            if path.is_some() {
                                return Err(Error::duplicate_field("path"));
                            }
                            path = Some(map.next_value()?);
                        }
                        "data" => {
                            if data.is_some() {
                                return Err(Error::duplicate_field("data"));
                            }
                            data = Some(map.next_value()?);
                        }
                        _ => {
                            // Ignore unknown fields
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }

                let pem_name = pem_name.ok_or_else(|| Error::missing_field("pem"))?;

                let source = match (path, data) {
                    (Some(p), None) => PemSource::Path(p),
                    (None, Some(d)) => PemSource::Data(d),
                    (Some(_), Some(_)) => {
                        return Err(Error::custom(
                            "NamedPem cannot have both 'path' and 'data' fields",
                        ));
                    }
                    (None, None) => {
                        return Err(Error::custom(
                            "NamedPem must have either 'path' or 'data' field",
                        ));
                    }
                };

                Ok(NamedPem {
                    pem: pem_name,
                    source,
                })
            }
        }

        deserializer.deserialize_map(NamedPemVisitor)
    }
}

impl Serialize for NamedPem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("pem", &self.pem)?;

        match &self.source {
            PemSource::Path(path) => {
                map.serialize_entry("path", path)?;
            }
            PemSource::Data(data) => {
                map.serialize_entry("data", data)?;
            }
        }

        map.end()
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Config {
    Server(ServerConfig),
    ClientConfigGroup(ClientConfigGroup),
    RuleConfigGroup(RuleConfigGroup),
    NamedPem(NamedPem),
}

impl<'de> serde::de::Deserialize<'de> for Config {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use serde::de::Error;
        use serde_yaml::Value;

        // First deserialize to a generic Value to inspect the structure
        let value = Value::deserialize(deserializer)?;

        // Check if it's a mapping (as all our configs should be)
        let map = value.as_mapping().ok_or_else(|| {
            Error::custom("Expected a YAML mapping for Config, but found a different type")
        })?;

        // Look for discriminating fields
        let has_client_group = map.contains_key(Value::String("client_group".to_string()));
        let has_rule_group = map.contains_key(Value::String("rule_group".to_string()));
        let has_address = map.contains_key(Value::String("address".to_string()));
        let has_path_field = map.contains_key(Value::String("path".to_string()));
        let has_pem = map.contains_key(Value::String("pem".to_string()));

        // Try to determine which variant based on fields
        if has_pem {
            // This is a NamedPem (pem field is unique to NamedPem)
            let pem: NamedPem = serde_yaml::from_value(value)
                .map_err(|e| Error::custom(format!(
                    "Failed to parse named PEM: {e}. Expected fields: 'pem' and either 'path' or 'data'"
                )))?;

            Ok(Config::NamedPem(pem))
        } else if has_client_group {
            // This is a ClientConfigGroup
            let group: ClientConfigGroup = serde_yaml::from_value(value)
                .map_err(|e| Error::custom(format!(
                    "Failed to parse client config group: {e}. Expected fields: 'client_group' and 'client_proxies' (or 'client_proxy')"
                )))?;

            Ok(Config::ClientConfigGroup(group))
        } else if has_rule_group {
            // This is a RuleConfigGroup
            let group: RuleConfigGroup = serde_yaml::from_value(value)
                .map_err(|e| Error::custom(format!(
                    "Failed to parse rule config group: {e}. Expected fields: 'rule_group' and 'rules' (or 'rule')"
                )))?;

            Ok(Config::RuleConfigGroup(group))
        } else if has_address || has_path_field {
            // This is a Server config
            let server: ServerConfig = serde_yaml::from_value(value)
                .map_err(|e| Error::custom(format!(
                    "Failed to parse server config: {e}. Server configs must have either 'address' or 'path' field, plus 'protocol' and optional fields"
                )))?;

            Ok(Config::Server(server))
        } else {
            // Provide a helpful error message listing what fields we found
            let found_fields: Vec<String> = map
                .keys()
                .filter_map(|k| k.as_str().map(|s| s.to_string()))
                .collect();

            Err(Error::custom(format!(
                "Unable to determine config type. Found fields: {found_fields:?}. Expected one of:\n\
                - Server config: must have 'address' or 'path' field\n\
                - Client config group: must have 'client_group' field\n\
                - Rule config group: must have 'rule_group' field"
            )))
        }
    }
}

impl serde::ser::Serialize for Config {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        match self {
            Config::Server(server) => server.serialize(serializer),
            Config::ClientConfigGroup(group) => group.serialize(serializer),
            Config::RuleConfigGroup(group) => group.serialize(serializer),
            Config::NamedPem(pem) => pem.serialize(serializer),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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

pub fn direct_allow_rule() -> NoneOrSome<ConfigSelection<RuleConfig>> {
    NoneOrSome::One(ConfigSelection::Config(RuleConfig::default()))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ShadowsocksConfig {
    pub cipher: String,
    pub password: String,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ShadowTlsRemoteHandshake {
    pub address: NetLocation,
    #[serde(
        alias = "client_proxy",
        default,
        skip_serializing_if = "NoneOrSome::is_unspecified"
    )]
    pub client_proxies: NoneOrSome<ConfigSelection<ClientConfig>>,
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
                    Remote handshake requires 'address' field, with optional 'client_proxies'"
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
        // number of socket for each UDP session
        #[serde(default = "default_snell_udp_num_sockets")]
        udp_num_sockets: usize,
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
        tls_buffer_size: Option<usize>,
    },
    Vmess {
        cipher: String,
        user_id: String,
        #[serde(default = "default_true")]
        force_aead: bool,
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
    TuicV5 { uuid: String, password: String },
}

impl std::fmt::Display for ServerProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Http { .. } => "HTTP",
                Self::Socks { .. } => "SOCKS",
                Self::Shadowsocks { .. } => "Shadowsocks",
                Self::Snell { .. } => "Snell",
                Self::Vless { .. } => "Vless",
                Self::Trojan { .. } => "Trojan",
                Self::Tls {
                    tls_targets,
                    default_tls_target,
                    shadowtls_targets,
                    ..
                } => {
                    let has_tls = !tls_targets.is_empty() || !default_tls_target.is_none();
                    let has_shadowtls = !shadowtls_targets.is_empty();
                    if has_tls && has_shadowtls {
                        "TLS+ShadowTLSv3"
                    } else if has_shadowtls {
                        "ShadowTLSv3"
                    } else {
                        "TLS"
                    }
                }
                Self::Vmess { .. } => "Vmess",
                Self::Websocket { .. } => "Websocket",
                Self::PortForward { .. } => "Portforward",
                Self::Hysteria2 { .. } => "Hysteria2",
                Self::TuicV5 { .. } => "TuicV5",
            }
        )
    }
}

#[derive(Debug, Clone)]
pub enum ConfigSelection<T> {
    Config(T),
    GroupName(String),
}

impl<T> ConfigSelection<T> {
    pub fn unwrap_config(self) -> T {
        match self {
            ConfigSelection::Config(config) => config,
            ConfigSelection::GroupName(_) => {
                panic!("Tried to unwrap a ConfigSelection::GroupName");
            }
        }
    }

    pub fn unwrap_config_mut(&mut self) -> &mut T {
        match self {
            ConfigSelection::Config(ref mut config) => config,
            ConfigSelection::GroupName(_) => {
                panic!("Tried to unwrap a ConfigSelection::GroupName");
            }
        }
    }

    fn replace<'a, U>(
        iter: impl Iterator<Item = &'a ConfigSelection<U>>,
        client_groups: &HashMap<String, Vec<U>>,
    ) -> std::io::Result<Vec<ConfigSelection<U>>>
    where
        U: Clone + 'a,
    {
        let mut ret = vec![];
        for selection in iter {
            match selection {
                ConfigSelection::Config(client_config) => {
                    ret.push(ConfigSelection::Config(client_config.clone()));
                }
                ConfigSelection::GroupName(client_group) => {
                    match client_groups.get(client_group.as_str()) {
                        Some(client_configs) => {
                            ret.extend(client_configs.iter().cloned().map(ConfigSelection::Config));
                        }
                        None => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                format!("No such client group: {client_group}"),
                            ));
                        }
                    }
                }
            }
        }
        Ok(ret)
    }

    pub fn replace_none_or_some_groups(
        selections: &mut NoneOrSome<ConfigSelection<T>>,
        client_groups: &HashMap<String, Vec<T>>,
    ) -> std::io::Result<()>
    where
        T: Clone + Sync,
    {
        if selections.is_empty() {
            return Ok(());
        }

        let ret = Self::replace(selections.iter(), client_groups)?;
        let _ = std::mem::replace(selections, NoneOrSome::Some(ret));
        Ok(())
    }

    pub fn replace_one_or_some_groups(
        selections: &mut OneOrSome<ConfigSelection<T>>,
        client_groups: &HashMap<String, Vec<T>>,
    ) -> std::io::Result<()>
    where
        T: Clone + Sync,
    {
        let ret = Self::replace(selections.iter(), client_groups)?;
        let _ = std::mem::replace(selections, OneOrSome::Some(ret));
        Ok(())
    }
}

impl<'de, T> serde::de::Deserialize<'de> for ConfigSelection<T>
where
    T: serde::de::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use serde::de::{Error, Visitor};
        use std::fmt;
        use std::marker::PhantomData;

        struct ConfigSelectionVisitor<T>(PhantomData<T>);

        impl<'de, T> Visitor<'de> for ConfigSelectionVisitor<T>
        where
            T: serde::de::Deserialize<'de>,
        {
            type Value = ConfigSelection<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(
                    "either a string (group name reference) or an inline configuration object",
                )
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(ConfigSelection::GroupName(value.to_string()))
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let config = T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
                    .map_err(|e| Error::custom(format!(
                        "Failed to parse inline configuration: {e}. \
                        Expected either a string referencing a named group or a valid configuration object"
                    )))?;
                Ok(ConfigSelection::Config(config))
            }
        }

        deserializer.deserialize_any(ConfigSelectionVisitor(PhantomData))
    }
}

impl<T> serde::ser::Serialize for ConfigSelection<T>
where
    T: serde::ser::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        match self {
            ConfigSelection::Config(config) => config.serialize(serializer),
            ConfigSelection::GroupName(name) => serializer.serialize_str(name),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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

fn unspecified_address() -> NetLocation {
    NetLocation::UNSPECIFIED
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
pub struct ClientQuicConfig {
    #[serde(default = "default_true")]
    pub verify: bool,
    #[serde(alias = "server_fingerprint", default)]
    pub server_fingerprints: NoneOrSome<String>,
    #[serde(default)]
    pub sni_hostname: NoneOrOne<String>,
    #[serde(alias = "alpn_protocol", default)]
    pub alpn_protocols: NoneOrSome<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub cert: Option<String>,
}

impl Default for ClientQuicConfig {
    fn default() -> Self {
        Self {
            verify: true,
            server_fingerprints: NoneOrSome::Unspecified,
            sni_hostname: NoneOrOne::Unspecified,
            alpn_protocols: NoneOrSome::Unspecified,
            key: None,
            cert: None,
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
    },
    Trojan {
        password: String,
        #[serde(default)]
        shadowsocks: Option<ShadowsocksConfig>,
    },
    Tls(TlsClientConfig),
    Vmess {
        cipher: String,
        user_id: String,
        #[serde(default = "default_true")]
        aead: bool,
    },
    #[serde(alias = "ws")]
    Websocket(WebsocketClientConfig),
}

impl ClientProxyConfig {
    pub fn is_direct(&self) -> bool {
        matches!(self, ClientProxyConfig::Direct)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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
    #[serde(default)]
    pub shadowtls_password: Option<String>,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleConfig {
    #[serde(alias = "mask")]
    pub masks: OneOrSome<NetLocationMask>,
    #[serde(flatten)]
    pub action: RuleActionConfig,
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            masks: OneOrSome::One(NetLocationMask::ANY),
            action: RuleActionConfig::Allow {
                override_address: None,
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            },
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "lowercase")]
#[allow(clippy::large_enum_variant)]
pub enum RuleActionConfig {
    Allow {
        #[serde(default, deserialize_with = "deserialize_override_address")]
        override_address: Option<NetLocation>,
        #[serde(alias = "client_proxy")]
        client_proxies: OneOrSome<ConfigSelection<ClientConfig>>,
    },
    Block,
}

fn deserialize_net_location<'de, D>(
    deserializer: D,
    default_port: Option<u16>,
) -> Result<NetLocation, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let net_location = NetLocation::from_str(&value, default_port).map_err(|_| {
        serde::de::Error::invalid_value(
            serde::de::Unexpected::Other("invalid net location"),
            &"invalid net location",
        )
    })?;

    Ok(net_location)
}

impl<'de> serde::de::Deserialize<'de> for NetLocation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        deserialize_net_location(deserializer, None)
    }
}

fn deserialize_override_address<'de, D>(deserializer: D) -> Result<Option<NetLocation>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    Ok(Some(deserialize_net_location(deserializer, Some(0))?))
}

impl<'de> serde::de::Deserialize<'de> for NetLocationMask {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let net_location_mask = NetLocationMask::from(&value).map_err(|_| {
            serde::de::Error::invalid_value(
                serde::de::Unexpected::Other("invalid net location mask"),
                &"invalid net location mask",
            )
        })?;

        Ok(net_location_mask)
    }
}

impl<'de> serde::de::Deserialize<'de> for NetLocationPortRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let net_location_port_range = NetLocationPortRange::from_str(&value).map_err(|e| {
            serde::de::Error::invalid_value(
                serde::de::Unexpected::Other(&format!("invalid net location port range: {e}")),
                &"valid net location port range (address:port[-port][,port])",
            )
        })?;

        Ok(net_location_port_range)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::*;
    use crate::config::{convert_cert_paths, create_server_configs};
    use crate::option_util::*;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;

    async fn validate_configs_test(configs: Vec<Config>) -> std::io::Result<Vec<ServerConfig>> {
        let (converted_configs, _) = convert_cert_paths(configs).await?;
        create_server_configs(converted_configs).await
    }

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
            rules: NoneOrSome::One(ConfigSelection::GroupName("test-rules".to_string())),
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
            protocol: ServerProxyConfig::Shadowsocks(ShadowsocksConfig {
                cipher: "aes-256-gcm".to_string(),
                password: "secret123".to_string(),
            }),
            transport: Transport::Tcp,
            tcp_settings: None,
            quic_settings: None,
            rules: NoneOrSome::One(ConfigSelection::GroupName("test-rules".to_string())),
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
                shadowsocks: Some(ShadowsocksConfig {
                    cipher: "chacha20-poly1305".to_string(),
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
                    protocol: ServerProxyConfig::Http {
                        username: None,
                        password: None,
                    },
                    override_rules: NoneOrSome::None,
                })),
                shadowtls_targets: HashMap::new(),
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
                force_aead: true,
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

    fn create_test_rule_config() -> RuleConfig {
        RuleConfig {
            masks: OneOrSome::Some(vec![
                NetLocationMask::from("192.168.0.0/16:80").unwrap(),
                NetLocationMask::from("10.0.0.0/8:443").unwrap(),
            ]),
            action: RuleActionConfig::Allow {
                override_address: Some(NetLocation::from_ip_addr(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    8080,
                )),
                client_proxies: OneOrSome::One(ConfigSelection::GroupName(
                    "test-proxy-group".to_string(),
                )),
            },
        }
    }

    // Test individual server config variants
    #[test]
    fn test_server_config_http() {
        let original = vec![Config::Server(create_test_server_config_http())];
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        println!("HTTP config YAML:\n{yaml_str}");
        let deserialized: Vec<Config> =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");

        // We can't do direct equality comparison due to some fields, so let's check structure
        assert_eq!(deserialized.len(), 1);
        if let Config::Server(server) = &deserialized[0] {
            assert!(matches!(server.protocol, ServerProxyConfig::Http { .. }));
        } else {
            panic!("Expected server config");
        }
    }

    #[test]
    fn test_server_config_socks() {
        let original = vec![Config::Server(create_test_server_config_socks())];
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: Vec<Config> =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");

        assert_eq!(deserialized.len(), 1);
        if let Config::Server(server) = &deserialized[0] {
            assert!(matches!(server.protocol, ServerProxyConfig::Socks { .. }));
        } else {
            panic!("Expected server config");
        }
    }

    #[test]
    fn test_server_config_shadowsocks() {
        let original = vec![Config::Server(create_test_server_config_shadowsocks())];
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        println!("Shadowsocks YAML: {yaml_str}");
        let deserialized: Vec<Config> =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");

        assert_eq!(deserialized.len(), 1);
        if let Config::Server(server) = &deserialized[0] {
            assert!(matches!(server.protocol, ServerProxyConfig::Shadowsocks(_)));
        } else {
            panic!("Expected server config");
        }
    }

    #[test]
    fn test_server_config_vless() {
        let original = vec![Config::Server(create_test_server_config_vless())];
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: Vec<Config> =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");

        assert_eq!(deserialized.len(), 1);
        if let Config::Server(server) = &deserialized[0] {
            assert!(matches!(server.protocol, ServerProxyConfig::Vless { .. }));
        } else {
            panic!("Expected server config");
        }
    }

    #[test]
    fn test_server_config_trojan() {
        let original = vec![Config::Server(create_test_server_config_trojan())];
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: Vec<Config> =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");

        assert_eq!(deserialized.len(), 1);
        if let Config::Server(server) = &deserialized[0] {
            assert!(matches!(server.protocol, ServerProxyConfig::Trojan { .. }));
        } else {
            panic!("Expected server config");
        }
    }

    #[test]
    fn test_server_config_tls() {
        let original = vec![Config::Server(create_test_server_config_tls())];
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: Vec<Config> =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");

        assert_eq!(deserialized.len(), 1);
        if let Config::Server(server) = &deserialized[0] {
            assert!(matches!(server.protocol, ServerProxyConfig::Tls { .. }));
        } else {
            panic!("Expected server config");
        }
    }

    #[test]
    fn test_server_config_vmess() {
        let original = vec![Config::Server(create_test_server_config_vmess())];
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: Vec<Config> =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");

        assert_eq!(deserialized.len(), 1);
        if let Config::Server(server) = &deserialized[0] {
            assert!(matches!(server.protocol, ServerProxyConfig::Vmess { .. }));
        } else {
            panic!("Expected server config");
        }
    }

    #[test]
    fn test_server_config_websocket() {
        let original = vec![Config::Server(create_test_server_config_websocket())];
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: Vec<Config> =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");

        assert_eq!(deserialized.len(), 1);
        if let Config::Server(server) = &deserialized[0] {
            assert!(matches!(
                server.protocol,
                ServerProxyConfig::Websocket { .. }
            ));
        } else {
            panic!("Expected server config");
        }
    }

    #[test]
    fn test_server_config_port_forward() {
        let original = vec![Config::Server(create_test_server_config_port_forward())];
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: Vec<Config> =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");

        assert_eq!(deserialized.len(), 1);
        if let Config::Server(server) = &deserialized[0] {
            assert!(matches!(
                server.protocol,
                ServerProxyConfig::PortForward { .. }
            ));
        } else {
            panic!("Expected server config");
        }
    }

    #[test]
    fn test_server_config_hysteria2() {
        let original = vec![Config::Server(create_test_server_config_hysteria2())];
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: Vec<Config> =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");

        assert_eq!(deserialized.len(), 1);
        if let Config::Server(server) = &deserialized[0] {
            assert!(matches!(
                server.protocol,
                ServerProxyConfig::Hysteria2 { .. }
            ));
        } else {
            panic!("Expected server config");
        }
    }

    #[test]
    fn test_server_config_tuic() {
        let original = vec![Config::Server(create_test_server_config_tuic())];
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: Vec<Config> =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");

        assert_eq!(deserialized.len(), 1);
        if let Config::Server(server) = &deserialized[0] {
            assert!(matches!(server.protocol, ServerProxyConfig::TuicV5 { .. }));
        } else {
            panic!("Expected server config");
        }
    }

    #[test]
    fn test_client_config_group() {
        let original = vec![Config::ClientConfigGroup(ClientConfigGroup {
            client_group: "test-client-group".to_string(),
            client_proxies: OneOrSome::Some(vec![
                create_test_client_config(),
                ClientConfig {
                    bind_interface: NoneOrOne::None,
                    address: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
                    protocol: ClientProxyConfig::Http {
                        username: None,
                        password: None,
                    },
                    transport: Transport::Tcp,
                    tcp_settings: None,
                    quic_settings: None,
                },
            ]),
        })];

        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: Vec<Config> =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");

        assert_eq!(deserialized.len(), 1);
        if let Config::ClientConfigGroup(group) = &deserialized[0] {
            assert_eq!(group.client_group, "test-client-group");
            // Check that we have the correct number of proxies by converting to vec
            match &group.client_proxies {
                OneOrSome::Some(vec) => assert_eq!(vec.len(), 2),
                OneOrSome::One(_) => panic!("Expected Some(vec), got One"),
            }
        } else {
            panic!("Expected client config group");
        }
    }

    #[test]
    fn test_rule_config_group() {
        let original = vec![Config::RuleConfigGroup(RuleConfigGroup {
            rule_group: "test-rule-group".to_string(),
            rules: OneOrSome::Some(vec![
                create_test_rule_config(),
                RuleConfig {
                    masks: OneOrSome::One(NetLocationMask::ANY),
                    action: RuleActionConfig::Block,
                },
            ]),
        })];

        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: Vec<Config> =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");

        assert_eq!(deserialized.len(), 1);
        if let Config::RuleConfigGroup(group) = &deserialized[0] {
            assert_eq!(group.rule_group, "test-rule-group");
            // Check that we have the correct number of rules by pattern matching
            match &group.rules {
                OneOrSome::Some(vec) => assert_eq!(vec.len(), 2),
                OneOrSome::One(_) => panic!("Expected Some(vec), got One"),
            }
        } else {
            panic!("Expected rule config group");
        }
    }

    #[test]
    fn test_mixed_config() {
        let original = vec![
            Config::Server(create_test_server_config_http()),
            Config::Server(create_test_server_config_shadowsocks()),
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "mixed-client-group".to_string(),
                client_proxies: OneOrSome::One(create_test_client_config()),
            }),
            Config::RuleConfigGroup(RuleConfigGroup {
                rule_group: "mixed-rule-group".to_string(),
                rules: OneOrSome::One(create_test_rule_config()),
            }),
        ];

        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: Vec<Config> =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");

        assert_eq!(deserialized.len(), 4);
        assert!(matches!(deserialized[0], Config::Server(_)));
        assert!(matches!(deserialized[1], Config::Server(_)));
        assert!(matches!(deserialized[2], Config::ClientConfigGroup(_)));
        assert!(matches!(deserialized[3], Config::RuleConfigGroup(_)));
    }

    #[tokio::test]
    async fn test_validate_config_success() {
        let configs = vec![
            Config::RuleConfigGroup(RuleConfigGroup {
                rule_group: "test-rules".to_string(),
                rules: OneOrSome::One(RuleConfig {
                    masks: OneOrSome::One(NetLocationMask::ANY),
                    action: RuleActionConfig::Allow {
                        override_address: None,
                        client_proxies: OneOrSome::One(ConfigSelection::Config(
                            ClientConfig::default(),
                        )),
                    },
                }),
            }),
            Config::Server(create_test_server_config_http()),
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "test-group".to_string(),
                client_proxies: OneOrSome::One(create_test_client_config()),
            }),
        ];

        assert!(validate_configs_test(configs).await.is_ok());
    }

    #[tokio::test]
    async fn test_empty_config() {
        let original: Vec<Config> = vec![];
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: Vec<Config> =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");

        assert_eq!(deserialized.len(), 0);
        assert!(validate_configs_test(deserialized).await.is_ok());
    }

    #[tokio::test]
    async fn test_named_pem_validation() {
        let configs = vec![
            Config::NamedPem(NamedPem {
                pem: "my-server-pem".to_string(),
                source: PemSource::Data(
                    "-----BEGIN CERTIFICATE-----\ntest cert data\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\ntest key data\n-----END PRIVATE KEY-----"
                        .to_string(),
                ),
            }),
            Config::Server(ServerConfig {
                bind_location: BindLocation::Address(
                    NetLocationPortRange::from_str("0.0.0.0:443").unwrap(),
                ),
                protocol: ServerProxyConfig::Tls {
                    tls_targets: vec![(
                        "example.com".to_string(),
                        TlsServerConfig {
                            cert: "my-server-pem".to_string(), // Reference to named pem
                            key: "my-server-pem".to_string(),   // Reference to named pem
                            client_ca_certs: NoneOrSome::None,
                            client_fingerprints: NoneOrSome::Unspecified,
                            alpn_protocols: NoneOrSome::Unspecified,
                            protocol: ServerProxyConfig::Http {
                                username: None,
                                password: None,
                            },
                            override_rules: NoneOrSome::None,
                        },
                    )]
                    .into_iter()
                    .collect(),
                    default_tls_target: None,
                    shadowtls_targets: HashMap::new(),
                    tls_buffer_size: None,
                },
                transport: Transport::Tcp,
                tcp_settings: None,
                quic_settings: None,
                rules: NoneOrSome::One(ConfigSelection::GroupName("allow-all-direct".to_string())),
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(result.is_ok());

        let server_configs = result.unwrap();
        assert_eq!(server_configs.len(), 1);

        // Check that the named cert/key were resolved to the actual data
        if let ServerProxyConfig::Tls {
            ref tls_targets, ..
        } = server_configs[0].protocol
        {
            let tls_config = &tls_targets["example.com"];
            // Both cert and key fields should contain the full PEM data
            // The actual parsing/extraction happens when the data is used
            assert_eq!(
                tls_config.cert,
                "-----BEGIN CERTIFICATE-----\ntest cert data\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\ntest key data\n-----END PRIVATE KEY-----"
            );
            assert_eq!(
                tls_config.key,
                "-----BEGIN CERTIFICATE-----\ntest cert data\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\ntest key data\n-----END PRIVATE KEY-----"
            );
        } else {
            panic!("Expected TLS protocol");
        }
    }

    #[tokio::test]
    async fn test_named_pem_json_serialization() {
        // Test that NamedPem can be serialized to JSON (for API responses)
        let pem1 = NamedPem {
            pem: "test-cert".to_string(),
            source: PemSource::Data(
                "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
            ),
        };

        let json = serde_yaml::to_string(&pem1).expect("Failed to serialize NamedPem to YAML");
        assert!(json.contains("pem: test-cert"));
        assert!(json.contains("data: |"));
        assert!(json.contains("-----BEGIN CERTIFICATE-----"));

        // Test with path source
        let pem2 = NamedPem {
            pem: "test-cert-2".to_string(),
            source: PemSource::Path("/etc/certs/test.pem".to_string()),
        };

        let yaml2 =
            serde_yaml::to_string(&pem2).expect("Failed to serialize NamedPem with path to YAML");
        assert!(yaml2.contains("pem: test-cert-2"));
        assert!(yaml2.contains("path: /etc/certs/test.pem"));

        // Test round-trip serialization
        let yaml_str = "pem: test-cert\ndata: |\n  -----BEGIN CERTIFICATE-----\n  test\n  -----END CERTIFICATE-----";
        let deserialized: NamedPem =
            serde_yaml::from_str(yaml_str).expect("Failed to deserialize NamedPem from YAML");
        assert_eq!(deserialized.pem, "test-cert");
        match deserialized.source {
            PemSource::Data(data) => assert!(data.contains("-----BEGIN CERTIFICATE-----")),
            _ => panic!("Expected Data source"),
        }
    }

    #[test]
    fn test_example_files_load_and_validate() {
        use crate::thread_util;
        use std::path::{Path, PathBuf};

        // Initialize thread count for the test environment if not already set
        // set_num_threads will panic if NUM_THREADS is already set by another test
        let _ = std::panic::catch_unwind(|| {
            thread_util::set_num_threads(4);
        });

        // Get the examples directory relative to the project root
        let examples_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");

        // Read all YAML files in the examples directory
        let mut example_files: Vec<PathBuf> = std::fs::read_dir(&examples_dir)
            .expect("Failed to read examples directory")
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();
                if path.extension()?.to_str()? == "yaml" {
                    Some(path)
                } else {
                    None
                }
            })
            .collect();

        // Sort files for consistent test output
        example_files.sort();

        assert!(!example_files.is_empty(), "No example YAML files found");
        println!("Found {} example files to test", example_files.len());

        let mut failures = Vec::new();

        // Test each example file
        for example_file in &example_files {
            let file_name = example_file.file_name().unwrap().to_str().unwrap();
            println!("\nTesting example file: {file_name}");

            // Read the file
            let content = match std::fs::read_to_string(example_file) {
                Ok(c) => c,
                Err(e) => {
                    failures.push(format!("- {file_name}: Failed to read file: {e}"));
                    continue;
                }
            };

            // Parse the YAML
            let configs: Vec<Config> = match serde_yaml::from_str(&content) {
                Ok(c) => c,
                Err(e) => {
                    failures.push(format!("- {file_name}: Failed to parse YAML: {e}"));
                    continue;
                }
            };

            // Just test parsing, not full validation with file reads
            // since certificate files don't exist in test environment
            println!("  ✓ Parsed successfully ({} configs)", configs.len());
        }

        if !failures.is_empty() {
            panic!(
                "Example config validation failed for {} files:\n{}",
                failures.len(),
                failures.join("\n")
            );
        }
    }

    #[test]
    fn test_config_error_messages() {
        // Test invalid config with no recognized fields
        let invalid_yaml = r#"
        - foo: bar
          baz: qux
        "#;

        let result: Result<Vec<Config>, _> = serde_yaml::from_str(invalid_yaml);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        println!("Error for invalid config: {error_msg}");
        assert!(error_msg.contains("Unable to determine config type"));
        assert!(error_msg.contains("Found fields: "));
        assert!(error_msg.contains("foo"));
        assert!(error_msg.contains("baz"));

        // Test invalid server config
        let invalid_server_yaml = r#"
        - address: 127.0.0.1:8080
          invalid_field: test
        "#;

        let result: Result<Vec<Config>, _> = serde_yaml::from_str(invalid_server_yaml);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        println!("Error for invalid server: {error_msg}");
        assert!(error_msg.contains("Failed to parse server config"));

        // Test invalid client group
        let invalid_client_yaml = r#"
        - client_group: test
          invalid_field: test
        "#;

        let result: Result<Vec<Config>, _> = serde_yaml::from_str(invalid_client_yaml);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        println!("Error for invalid client group: {error_msg}");
        assert!(error_msg.contains("Failed to parse client config group"));
    }

    #[test]
    fn test_shadowtls_handshake_serialization() {
        use crate::config::{ShadowTlsLocalHandshake, ShadowTlsRemoteHandshake};

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
            client_proxies: NoneOrSome::Unspecified,
        };

        let yaml = serde_yaml::to_string(&remote).unwrap();
        println!("Remote handshake (minimal):\n{yaml}");

        // Should only contain address
        assert!(yaml.contains("address:"));
        assert!(!yaml.contains("client_proxies:"));
    }

    #[test]
    fn test_shadowtls_handshake_error_messages() {
        use crate::config::ShadowTlsServerHandshakeConfig;

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
        // Since it has cert, it will try to parse as Local and fail due to missing key
        assert!(error_msg.contains("Failed to parse local ShadowTLS handshake config"));
        assert!(error_msg.contains("missing field `key`"));

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
    fn test_named_pem() {
        // Test with path
        let pem_with_path = NamedPem {
            pem: "my-server-pem".to_string(),
            source: PemSource::Path("/etc/certs/server.pem".to_string()),
        };

        let yaml = serde_yaml::to_string(&pem_with_path).unwrap();
        println!("NamedPem with path YAML:\n{yaml}");
        assert!(yaml.contains("pem: my-server-pem"));
        assert!(yaml.contains("path: /etc/certs/server.pem"));

        let deserialized: NamedPem = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(deserialized.pem, "my-server-pem");
        match deserialized.source {
            PemSource::Path(p) => assert_eq!(p, "/etc/certs/server.pem"),
            _ => panic!("Expected Path source"),
        }

        // Test with data (combined cert and key)
        let pem_with_data = NamedPem {
            pem: "inline-pem".to_string(),
            source: PemSource::Data(
                "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHHI...\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nMIIEvQ...\n-----END PRIVATE KEY-----".to_string(),
            ),
        };

        let yaml = serde_yaml::to_string(&pem_with_data).unwrap();
        println!("NamedPem with data YAML:\n{yaml}");
        assert!(yaml.contains("pem: inline-pem"));
        assert!(yaml.contains("data: "));
        assert!(yaml.contains("-----BEGIN CERTIFICATE-----"));
        assert!(yaml.contains("-----BEGIN PRIVATE KEY-----"));

        let deserialized: NamedPem = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(deserialized.pem, "inline-pem");
        match deserialized.source {
            PemSource::Data(d) => {
                assert!(d.contains("-----BEGIN CERTIFICATE-----"));
                assert!(d.contains("-----BEGIN PRIVATE KEY-----"));
            }
            _ => panic!("Expected Data source"),
        }
    }

    #[test]
    fn test_named_pem_invalid_yaml() {
        // Missing pem field
        let yaml = r#"
        path: /etc/certs/server.pem
        "#;
        let result: Result<NamedPem, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("missing field `pem`"));

        // Missing source (no path or data)
        let yaml = r#"
        pem: my-pem
        "#;
        let result: Result<NamedPem, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must have either 'path' or 'data'"));

        // Both path and data
        let yaml = r#"
        pem: my-pem
        path: /etc/certs/server.pem
        data: "-----BEGIN CERTIFICATE-----"
        "#;
        let result: Result<NamedPem, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("cannot have both 'path' and 'data'"));
    }

    #[tokio::test]
    async fn test_quic_with_named_pems() {
        // Test QUIC server with named PEM
        let configs = vec![
            Config::NamedPem(NamedPem {
                pem: "quic-pem".to_string(),
                source: PemSource::Data(
                    "-----BEGIN CERTIFICATE-----\nquic cert data\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nquic key data\n-----END PRIVATE KEY-----"
                        .to_string(),
                ),
            }),
            Config::Server(ServerConfig {
                bind_location: BindLocation::Address(
                    NetLocationPortRange::from_str("0.0.0.0:443").unwrap(),
                ),
                protocol: ServerProxyConfig::Hysteria2 {
                    password: "test-password".to_string(),
                    udp_enabled: true,
                },
                transport: Transport::Quic,
                tcp_settings: None,
                quic_settings: Some(ServerQuicConfig {
                    cert: "quic-pem".to_string(), // Reference to named pem
                    key: "quic-pem".to_string(),   // Reference to named pem
                    alpn_protocols: NoneOrSome::Some(vec!["h3".to_string()]),
                    client_ca_certs: NoneOrSome::None,
                    client_fingerprints: NoneOrSome::None,
                    num_endpoints: 1,
                }),
                rules: NoneOrSome::One(ConfigSelection::GroupName("allow-all-direct".to_string())),
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(result.is_ok());

        let server_configs = result.unwrap();
        assert_eq!(server_configs.len(), 1);

        let quic_settings = server_configs[0].quic_settings.as_ref().unwrap();
        assert_eq!(
            quic_settings.cert,
            "-----BEGIN CERTIFICATE-----\nquic cert data\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nquic key data\n-----END PRIVATE KEY-----"
        );
        assert_eq!(
            quic_settings.key,
            "-----BEGIN CERTIFICATE-----\nquic cert data\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nquic key data\n-----END PRIVATE KEY-----"
        );
    }

    #[tokio::test]
    async fn test_shadowtls_with_named_pems() {
        // Test ShadowTLS with named PEM
        let configs = vec![
            Config::NamedPem(NamedPem {
                pem: "shadow-pem".to_string(),
                source: PemSource::Data(
                    "-----BEGIN CERTIFICATE-----\nshadow cert\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nshadow key\n-----END PRIVATE KEY-----"
                        .to_string(),
                ),
            }),
            Config::Server(ServerConfig {
                bind_location: BindLocation::Address(
                    NetLocationPortRange::from_str("0.0.0.0:443").unwrap(),
                ),
                protocol: ServerProxyConfig::Tls {
                    tls_targets: HashMap::new(),
                    default_tls_target: None,
                    shadowtls_targets: vec![(
                        "shadow.example.com".to_string(),
                        ShadowTlsServerConfig {
                            password: "shadow-password".to_string(),
                            handshake: ShadowTlsServerHandshakeConfig::Local(
                                ShadowTlsLocalHandshake {
                                    cert: "shadow-pem".to_string(),
                                    key: "shadow-pem".to_string(),
                                    alpn_protocols: NoneOrSome::Unspecified,
                                    client_ca_certs: NoneOrSome::Unspecified,
                                    client_fingerprints: NoneOrSome::Unspecified,
                                },
                            ),
                            protocol: ServerProxyConfig::Http {
                                username: None,
                                password: None,
                            },
                            override_rules: NoneOrSome::None,
                        },
                    )]
                    .into_iter()
                    .collect(),
                    tls_buffer_size: None,
                },
                transport: Transport::Tcp,
                tcp_settings: None,
                quic_settings: None,
                rules: NoneOrSome::One(ConfigSelection::GroupName("allow-all-direct".to_string())),
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(result.is_ok());

        let server_configs = result.unwrap();
        if let ServerProxyConfig::Tls {
            ref shadowtls_targets,
            ..
        } = server_configs[0].protocol
        {
            let shadow_config = &shadowtls_targets["shadow.example.com"];
            if let ShadowTlsServerHandshakeConfig::Local(ref handshake) = shadow_config.handshake {
                // Both cert and key fields should contain the full PEM data
                assert_eq!(
                    handshake.cert,
                    "-----BEGIN CERTIFICATE-----\nshadow cert\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nshadow key\n-----END PRIVATE KEY-----"
                );
                assert_eq!(
                    handshake.key,
                    "-----BEGIN CERTIFICATE-----\nshadow cert\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nshadow key\n-----END PRIVATE KEY-----"
                );
            } else {
                panic!("Expected Local handshake");
            }
        }
    }

    #[tokio::test]
    async fn test_named_pem_duplicate_names() {
        // Test that duplicate named PEM names are rejected
        let configs = vec![
            Config::NamedPem(NamedPem {
                pem: "duplicate-name".to_string(),
                source: PemSource::Data("pem1".to_string()),
            }),
            Config::NamedPem(NamedPem {
                pem: "duplicate-name".to_string(),
                source: PemSource::Data("pem2".to_string()),
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("named pem already exists: duplicate-name"));
    }

    #[tokio::test]
    async fn test_client_ca_certs_with_named_refs() {
        // Test that client CA certs can use named PEM references
        let configs = vec![
            Config::NamedPem(NamedPem {
                pem: "ca-pem-1".to_string(),
                source: PemSource::Data(
                    "-----BEGIN CERTIFICATE-----\nCA1\n-----END CERTIFICATE-----".to_string(),
                ),
            }),
            Config::NamedPem(NamedPem {
                pem: "ca-pem-2".to_string(),
                source: PemSource::Data(
                    "-----BEGIN CERTIFICATE-----\nCA2\n-----END CERTIFICATE-----".to_string(),
                ),
            }),
            Config::Server(ServerConfig {
                bind_location: BindLocation::Address(
                    NetLocationPortRange::from_str("0.0.0.0:443").unwrap(),
                ),
                protocol: ServerProxyConfig::Tls {
                    tls_targets: vec![(
                        "example.com".to_string(),
                        TlsServerConfig {
                            cert: "-----BEGIN CERTIFICATE-----\nserver\n-----END CERTIFICATE-----"
                                .to_string(),
                            key: "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----"
                                .to_string(),
                            client_ca_certs: NoneOrSome::Some(vec![
                                "ca-pem-1".to_string(),
                                "ca-pem-2".to_string(),
                                "-----BEGIN CERTIFICATE-----\nCA3\n-----END CERTIFICATE-----"
                                    .to_string(),
                            ]),
                            client_fingerprints: NoneOrSome::Unspecified,
                            alpn_protocols: NoneOrSome::Unspecified,
                            protocol: ServerProxyConfig::Http {
                                username: None,
                                password: None,
                            },
                            override_rules: NoneOrSome::None,
                        },
                    )]
                    .into_iter()
                    .collect(),
                    default_tls_target: None,
                    shadowtls_targets: HashMap::new(),
                    tls_buffer_size: None,
                },
                transport: Transport::Tcp,
                tcp_settings: None,
                quic_settings: None,
                rules: NoneOrSome::One(ConfigSelection::GroupName("allow-all-direct".to_string())),
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(result.is_ok());

        let server_configs = result.unwrap();
        if let ServerProxyConfig::Tls {
            ref tls_targets, ..
        } = server_configs[0].protocol
        {
            let tls_config = &tls_targets["example.com"];
            let ca_certs = &tls_config.client_ca_certs;
            assert_eq!(ca_certs.len(), 3);
            let ca_vec = ca_certs.clone().into_vec();
            assert_eq!(
                ca_vec[0],
                "-----BEGIN CERTIFICATE-----\nCA1\n-----END CERTIFICATE-----"
            );
            assert_eq!(
                ca_vec[1],
                "-----BEGIN CERTIFICATE-----\nCA2\n-----END CERTIFICATE-----"
            );
            assert_eq!(
                ca_vec[2],
                "-----BEGIN CERTIFICATE-----\nCA3\n-----END CERTIFICATE-----"
            );
        }
    }

    #[test]
    fn test_config_with_named_pems() {
        // Test NamedPem as Config with path
        let pem_config = Config::NamedPem(NamedPem {
            pem: "web-server-pem".to_string(),
            source: PemSource::Path("/etc/certs/web.pem".to_string()),
        });

        let yaml = serde_yaml::to_string(&pem_config).unwrap();
        println!("Config::NamedPem YAML:\n{yaml}");

        let deserialized: Config = serde_yaml::from_str(&yaml).unwrap();
        match deserialized {
            Config::NamedPem(pem) => {
                assert_eq!(pem.pem, "web-server-pem");
                match pem.source {
                    PemSource::Path(p) => assert_eq!(p, "/etc/certs/web.pem"),
                    _ => panic!("Expected Path source"),
                }
            }
            _ => panic!("Expected NamedPem config"),
        }

        // Test NamedPem as Config with data
        let pem_config_data = Config::NamedPem(NamedPem {
            pem: "web-server-pem-data".to_string(),
            source: PemSource::Data("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----".to_string()),
        });

        let yaml = serde_yaml::to_string(&pem_config_data).unwrap();
        println!("Config::NamedPem with data YAML:\n{yaml}");

        let deserialized: Config = serde_yaml::from_str(&yaml).unwrap();
        match deserialized {
            Config::NamedPem(pem) => {
                assert_eq!(pem.pem, "web-server-pem-data");
                match pem.source {
                    PemSource::Data(d) => {
                        assert!(d.contains("-----BEGIN CERTIFICATE-----"));
                        assert!(d.contains("-----BEGIN PRIVATE KEY-----"));
                    }
                    _ => panic!("Expected Data source"),
                }
            }
            _ => panic!("Expected NamedPem config"),
        }
    }
}
