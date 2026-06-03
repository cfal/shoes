//! Transport-related configuration types.

use std::{fmt, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::address::{NetLocation, NetLocationPortRange};
use crate::option_util::{NoneOrOne, NoneOrSome};

use super::common::default_true;

const REDACTED: &str = "<redacted>";

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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    #[default]
    Tcp,
    Quic,
    Udp,
}

impl Transport {
    /// Returns true if this is the default transport (TCP)
    pub fn is_default(&self) -> bool {
        matches!(self, Transport::Tcp)
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

#[derive(Clone, Deserialize, Serialize)]
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

impl fmt::Debug for ServerQuicConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerQuicConfig")
            .field("cert", &"<present>")
            .field("key", &REDACTED)
            .field("alpn_protocols", &self.alpn_protocols)
            .field("client_ca_certs", &self.client_ca_certs)
            .field("client_fingerprints", &self.client_fingerprints)
            .field("num_endpoints", &self.num_endpoints)
            .finish()
    }
}

#[derive(Clone, Deserialize, Serialize)]
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

impl fmt::Debug for ClientQuicConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientQuicConfig")
            .field("verify", &self.verify)
            .field("server_fingerprints", &self.server_fingerprints)
            .field("sni_hostname", &self.sni_hostname)
            .field("alpn_protocols", &self.alpn_protocols)
            .field("key", &self.key.as_ref().map(|_| REDACTED))
            .field("cert", &self.cert.as_ref().map(|_| "<present>"))
            .finish()
    }
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

impl From<NetLocation> for BindLocation {
    fn from(loc: NetLocation) -> Self {
        BindLocation::Address(loc.into())
    }
}
