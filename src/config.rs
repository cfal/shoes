use std::collections::HashMap;
use std::path::PathBuf;

use serde::Deserialize;

use crate::address::{NetLocation, NetLocationMask, NetLocationPortRange};
use crate::option_util::{NoneOrOne, NoneOrSome, OneOrSome};
use crate::thread_util::get_num_threads;
use crate::util::parse_uuid;

fn default_true() -> bool {
    true
}

fn default_snell_udp_num_sockets() -> usize {
    1
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BindLocation {
    Address(NetLocationPortRange),
    Path(PathBuf),
}

impl std::fmt::Display for BindLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindLocation::Address(n) => write!(f, "{}", n),
            BindLocation::Path(p) => write!(f, "{}", p.display()),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct TcpConfig {
    #[serde(default = "default_true")]
    pub no_delay: bool,
}

impl Default for TcpConfig {
    fn default() -> Self {
        TcpConfig { no_delay: true }
    }
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Config {
    Server(ServerConfig),
    ClientConfigGroup {
        client_group: String,
        // TODO: do a topological sort and allow this to be OneOrSome<ConfigSelection>
        #[serde(alias = "client_proxy")]
        client_proxies: OneOrSome<ClientConfig>,
    },
    RuleConfigGroup {
        rule_group: String,
        #[serde(alias = "rule")]
        rules: OneOrSome<RuleConfig>,
    },
}

#[derive(Debug, Clone, Deserialize)]
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

fn direct_allow_rule() -> NoneOrSome<ConfigSelection<RuleConfig>> {
    NoneOrSome::One(ConfigSelection::Config(RuleConfig::default()))
}

#[derive(Debug, Clone, Deserialize)]
pub struct ShadowsocksConfig {
    pub cipher: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct ShadowTlsServerConfig {
    pub password: String,
    pub handshake: ShadowTlsServerHandshakeConfig,
    pub protocol: ServerProxyConfig,
    #[serde(alias = "override_rule", default)]
    pub override_rules: NoneOrSome<ConfigSelection<RuleConfig>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ShadowTlsServerHandshakeConfig {
    // Do the handshake locally with the provided TLS config.
    // This does not require a remote server, but for most clients,
    // the provided certificate must be signed by a trusted CA.
    Local {
        cert: String,
        key: String,
        #[serde(alias = "alpn_protocol", default)]
        alpn_protocols: NoneOrSome<String>,
        #[serde(alias = "client_ca_cert", default)]
        client_ca_certs: NoneOrSome<String>,
        #[serde(alias = "client_fingerprint", default)]
        client_fingerprints: NoneOrSome<String>,
    },
    Remote {
        address: NetLocation,
        #[serde(alias = "client_proxy", default)]
        client_proxies: NoneOrSome<ConfigSelection<ClientConfig>>,
    },
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Default, Debug, Clone, Deserialize, PartialEq)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
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
                                format!("No such client group: {}", client_group),
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
        T: Clone,
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
        T: Clone,
    {
        let ret = Self::replace(selections.iter(), client_groups)?;
        let _ = std::mem::replace(selections, OneOrSome::Some(ret));
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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
    pub key: Option<String>,
    #[serde(default)]
    pub cert: Option<String>,
    pub protocol: Box<ClientProxyConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebsocketClientConfig {
    #[serde(default)]
    pub matching_path: Option<String>,
    #[serde(default)]
    pub matching_headers: Option<HashMap<String, String>>,
    #[serde(default)]
    pub ping_type: WebsocketPingType,
    pub protocol: Box<ClientProxyConfig>,
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "action", rename_all = "lowercase")]
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
                serde::de::Unexpected::Other(&format!("invalid net location port range: {}", e)),
                &"valid net location port range (address:port[-port][,port])",
            )
        })?;

        Ok(net_location_port_range)
    }
}

pub async fn load_configs(args: &Vec<String>) -> std::io::Result<Vec<ServerConfig>> {
    let mut all_configs = vec![];
    for config_filename in args {
        let config_bytes = match tokio::fs::read(config_filename).await {
            Ok(b) => b,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Could not read config file {}: {}", config_filename, e),
                ));
            }
        };

        let config_str = match String::from_utf8(config_bytes) {
            Ok(s) => s,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "Could not parse config file {} as UTF8: {}",
                        config_filename, e
                    ),
                ));
            }
        };

        let mut configs = match serde_yaml::from_str::<Vec<Config>>(&config_str) {
            Ok(c) => c,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "Could not parse config file {} as config YAML: {}",
                        config_filename, e
                    ),
                ));
            }
        };
        all_configs.append(&mut configs)
    }

    let mut client_groups: HashMap<String, Vec<ClientConfig>> = HashMap::new();
    client_groups.insert(String::from("direct"), vec![ClientConfig::default()]);

    let mut rule_groups: HashMap<String, Vec<RuleConfig>> = HashMap::new();
    rule_groups.insert(
        String::from("allow-all-direct"),
        vec![RuleConfig {
            masks: OneOrSome::One(NetLocationMask::ANY),
            action: RuleActionConfig::Allow {
                override_address: None,
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            },
        }],
    );
    rule_groups.insert(
        String::from("block-all"),
        vec![RuleConfig {
            masks: OneOrSome::One(NetLocationMask::ANY),
            action: RuleActionConfig::Block,
        }],
    );

    let mut server_configs: Vec<ServerConfig> = vec![];

    for config in all_configs.into_iter() {
        match config {
            Config::ClientConfigGroup {
                client_group,
                client_proxies,
            } => {
                if client_groups
                    .insert(client_group.clone(), client_proxies.into_vec())
                    .is_some()
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("client group already exists: {}", client_group),
                    ));
                }
            }
            Config::RuleConfigGroup { rule_group, rules } => {
                if rule_groups
                    .insert(rule_group.clone(), rules.into_vec())
                    .is_some()
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("rule group already exists: {}", rule_group),
                    ));
                }
            }
            Config::Server(server_config) => {
                server_configs.push(server_config);
            }
        }
    }

    for config in server_configs.iter_mut() {
        validate_server_config(config, &client_groups, &rule_groups)?;
    }

    Ok(server_configs)
}

fn validate_server_config(
    server_config: &mut ServerConfig,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    rule_groups: &HashMap<String, Vec<RuleConfig>>,
) -> std::io::Result<()> {
    if server_config.transport != Transport::Tcp && server_config.tcp_settings.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TCP transport is not selected but TCP settings specified",
        ));
    }

    if server_config.transport == Transport::Quic {
        match server_config.quic_settings {
            Some(ServerQuicConfig {
                ref mut client_fingerprints,
                ref mut num_endpoints,
                ..
            }) => {
                validate_client_fingerprints(client_fingerprints)?;

                if *num_endpoints == 0 {
                    *num_endpoints = get_num_threads();
                }
            }
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "QUIC transport is selected but QUIC settings not specified",
                ));
            }
        }
    } else if server_config.quic_settings.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "QUIC transport is not selected but QUIC settings specified",
        ));
    }

    if let BindLocation::Path(_) = server_config.bind_location {
        if server_config.transport != Transport::Tcp {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unix domain socket support only available for TCP transport",
            ));
        }
    }

    ConfigSelection::replace_none_or_some_groups(&mut server_config.rules, rule_groups)?;

    if server_config.rules.is_empty() {
        server_config.rules = direct_allow_rule();
    }

    for rule_config_selection in server_config.rules.iter_mut() {
        validate_rule_config(rule_config_selection.unwrap_config_mut(), client_groups)?;
    }

    validate_server_proxy_config(&mut server_config.protocol, client_groups, rule_groups)?;

    Ok(())
}

fn validate_client_fingerprints(
    client_fingerprints: &mut NoneOrSome<String>,
) -> std::io::Result<()> {
    if !client_fingerprints.is_unspecified() && client_fingerprints.is_empty() {
        println!("WARNING: Client fingerprints provided but empty, defaulting to 'any'");
    }

    if client_fingerprints.iter().any(|fp| fp == "any") {
        let _ = std::mem::replace(client_fingerprints, NoneOrSome::Unspecified);
    } else {
        let _ = crate::rustls_util::process_fingerprints(&client_fingerprints.clone().into_vec())?;
    }

    Ok(())
}

fn validate_client_config(client_config: &mut ClientConfig) -> std::io::Result<()> {
    if client_config.transport != Transport::Tcp && client_config.tcp_settings.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TCP transport is not selected but TCP settings specified",
        ));
    }

    if let Some(ref mut quic_config) = client_config.quic_settings {
        if client_config.transport != Transport::Quic {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "QUIC transport is not selected but QUIC settings specified",
            ));
        }

        let ClientQuicConfig {
            cert,
            key,
            server_fingerprints,
            ..
        } = quic_config;
        if cert.is_none() != key.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Both client cert and key have to be specified, or both have to be omitted",
            ));
        }
        validate_server_fingerprints(server_fingerprints)?;
    }

    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    if client_config.bind_interface.is_one() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "bind_interface is only available on Android, Fuchsia, or Linux.",
        ));
    }

    validate_client_proxy_config(&mut client_config.protocol)?;

    Ok(())
}

fn validate_server_fingerprints(
    server_fingerprints: &mut NoneOrSome<String>,
) -> std::io::Result<()> {
    if !server_fingerprints.is_unspecified() && server_fingerprints.is_empty() {
        println!("WARNING: Server fingerprints provided but empty, defaulting to 'any'");
    }

    if server_fingerprints.iter().any(|fp| fp == "any") {
        let _ = std::mem::replace(server_fingerprints, NoneOrSome::Unspecified);
    } else {
        let _ = crate::rustls_util::process_fingerprints(&server_fingerprints.clone().into_vec())?;
    }

    Ok(())
}

fn validate_client_proxy_config(
    client_proxy_config: &mut ClientProxyConfig,
) -> std::io::Result<()> {
    if let ClientProxyConfig::Tls(TlsClientConfig {
        cert,
        key,
        server_fingerprints,
        ..
    }) = client_proxy_config
    {
        if cert.is_none() != key.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Both client cert and key have to be specified, or both have to be omitted",
            ));
        }
        validate_server_fingerprints(server_fingerprints)?;
    }
    Ok(())
}

fn validate_server_proxy_config(
    server_proxy_config: &mut ServerProxyConfig,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    rule_groups: &HashMap<String, Vec<RuleConfig>>,
) -> std::io::Result<()> {
    match server_proxy_config {
        ServerProxyConfig::Vless { user_id, .. } => {
            parse_uuid(user_id)?;
        }
        ServerProxyConfig::Vmess { user_id, .. } => {
            parse_uuid(user_id)?;
        }
        ServerProxyConfig::Tls {
            tls_targets,
            default_tls_target,
            shadowtls_targets,
        } => {
            for (_, tls_server_config) in tls_targets.iter_mut() {
                let TlsServerConfig {
                    ref mut protocol,
                    ref mut override_rules,
                    ref mut client_fingerprints,
                    ..
                } = *tls_server_config;

                validate_client_fingerprints(client_fingerprints)?;

                validate_server_proxy_config(protocol, client_groups, rule_groups)?;

                ConfigSelection::replace_none_or_some_groups(override_rules, rule_groups)?;

                for rule_config_selection in override_rules.iter_mut() {
                    validate_rule_config(rule_config_selection.unwrap_config_mut(), client_groups)?;
                }
            }
            if let Some(tls_server_config) = default_tls_target {
                let TlsServerConfig {
                    ref mut protocol,
                    ref mut override_rules,
                    ..
                } = **tls_server_config;
                validate_server_proxy_config(protocol, client_groups, rule_groups)?;

                ConfigSelection::replace_none_or_some_groups(override_rules, rule_groups)?;

                for rule_config_selection in override_rules.iter_mut() {
                    validate_rule_config(rule_config_selection.unwrap_config_mut(), client_groups)?;
                }
            }
            for (sni_hostname, tls_server_config) in shadowtls_targets.iter_mut() {
                if tls_targets.contains_key(sni_hostname) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "duplicated SNI hostname between TLS and ShadowTLS targets: {}",
                            sni_hostname
                        ),
                    ));
                }
                let ShadowTlsServerConfig {
                    ref mut protocol,
                    ref mut override_rules,
                    ref mut handshake,
                    ..
                } = *tls_server_config;

                if let ShadowTlsServerHandshakeConfig::Local {
                    ref mut client_fingerprints,
                    ..
                } = handshake
                {
                    validate_client_fingerprints(client_fingerprints)?;
                }

                validate_server_proxy_config(protocol, client_groups, rule_groups)?;

                ConfigSelection::replace_none_or_some_groups(override_rules, rule_groups)?;

                for rule_config_selection in override_rules.iter_mut() {
                    validate_rule_config(rule_config_selection.unwrap_config_mut(), client_groups)?;
                }
            }
        }
        ServerProxyConfig::Websocket { targets } => {
            for websocket_server_config in targets.iter_mut() {
                let WebsocketServerConfig {
                    ref mut protocol,
                    ref mut override_rules,
                    ..
                } = websocket_server_config;
                validate_server_proxy_config(protocol, client_groups, rule_groups)?;

                ConfigSelection::replace_none_or_some_groups(override_rules, rule_groups)?;

                for rule_config_selection in override_rules.iter_mut() {
                    validate_rule_config(rule_config_selection.unwrap_config_mut(), client_groups)?;
                }
            }
        }
        ServerProxyConfig::TuicV5 { uuid, .. } => {
            parse_uuid(uuid)?;
        }
        _ => (),
    }
    Ok(())
}

fn validate_rule_config(
    rule_config: &mut RuleConfig,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
) -> std::io::Result<()> {
    if let RuleActionConfig::Allow {
        ref mut client_proxies,
        ..
    } = rule_config.action
    {
        ConfigSelection::replace_one_or_some_groups(client_proxies, client_groups)?;
        for client_config_selection in client_proxies.iter_mut() {
            validate_client_config(client_config_selection.unwrap_config_mut())?
        }
    }

    Ok(())
}
