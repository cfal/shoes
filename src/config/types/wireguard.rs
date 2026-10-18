#[cfg(unix)]
use std::collections::HashSet;
use std::{fmt, io, net::SocketAddr};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use super::{
    ClientChain, DnsConfig, RuleConfig, selection::ConfigSelection, tun::TunResourceLimits,
};
use crate::option_util::NoneOrSome;

#[derive(Clone)]
pub struct WireguardKey(pub [u8; 32]);

impl fmt::Debug for WireguardKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl Serialize for WireguardKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(self.0))
    }
}

impl<'de> Deserialize<'de> for WireguardKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Parses through Value to keep rejected key material out of deserialization errors.
        let value = serde_yaml::Value::deserialize(deserializer)?;
        let bytes = value.as_str().and_then(|text| STANDARD.decode(text).ok());
        bytes
            .and_then(|bytes| bytes.try_into().ok())
            .map(Self)
            .ok_or_else(|| {
                serde::de::Error::custom("WireGuard key must be a base64-encoded 32-byte value")
            })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireguardPeer {
    pub public_key: WireguardKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_shared_key: Option<WireguardKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub persistent_keepalive: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct WireguardInbound {
    pub rules: NoneOrSome<ConfigSelection<RuleConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsConfig>,
}

/// A validated device, private to one configuration generation.
#[derive(Debug, Clone, Serialize)]
pub struct WireguardDeviceConfig {
    pub id: String,
    pub private_key: WireguardKey,
    pub addresses: Vec<String>,
    pub peers: Vec<WireguardPeer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<SocketAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_interface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_client_chain: Option<ClientChain>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound: Option<WireguardInbound>,
    #[serde(default)]
    pub resource_limits: TunResourceLimits,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireguardClientConfig {
    pub private_key: WireguardKey,
    pub public_key: WireguardKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_shared_key: Option<WireguardKey>,
    pub addresses: Vec<String>,
    #[serde(default = "default_allowed_ips")]
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub persistent_keepalive: u16,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    #[serde(default)]
    pub resource_limits: TunResourceLimits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_client_chain: Option<ClientChain>,
    #[serde(skip)]
    pub(crate) endpoint_id: String,
    #[serde(skip)]
    pub(crate) connector: Option<std::sync::Arc<dyn crate::tcp::socket_connector::SocketConnector>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireguardServerConfig {
    pub private_key: WireguardKey,
    pub addresses: Vec<String>,
    pub peers: Vec<WireguardPeer>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    #[serde(default)]
    pub resource_limits: TunResourceLimits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_interface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_client_chain: Option<ClientChain>,
}

fn default_allowed_ips() -> Vec<String> {
    vec!["0.0.0.0/0".into(), "::/0".into()]
}

impl WireguardClientConfig {
    pub(crate) fn device(
        &self,
        address: &crate::address::NetLocation,
        bind_interface: Option<String>,
    ) -> WireguardDeviceConfig {
        WireguardDeviceConfig {
            id: self.endpoint_id.clone(),
            private_key: self.private_key.clone(),
            addresses: self.addresses.clone(),
            peers: vec![WireguardPeer {
                public_key: self.public_key.clone(),
                pre_shared_key: self.pre_shared_key.clone(),
                endpoint: Some(address.to_string()),
                allowed_ips: self.allowed_ips.clone(),
                persistent_keepalive: self.persistent_keepalive,
            }],
            listen: None,
            bind_interface,
            peer_client_chain: self.peer_client_chain.clone(),
            mtu: self.mtu,
            inbound: None,
            resource_limits: self.resource_limits.clone(),
        }
    }
}

impl WireguardServerConfig {
    pub(crate) fn device(&self, server: &super::ServerConfig) -> io::Result<WireguardDeviceConfig> {
        let listen = match &server.bind_location {
            super::BindLocation::Unspecified {} if self.peer_client_chain.is_some() => None,
            super::BindLocation::Address(addresses) if addresses.iter().count() == 1 => {
                let address = addresses.iter().next().unwrap();
                let listen = address
                    .literal_socket_addr()
                    .filter(|address| address.port() != 0)
                    .ok_or_else(|| {
                        invalid("WireGuard server requires one nonzero literal UDP listen address")
                    })?;
                Some(listen)
            }
            _ => {
                return Err(invalid(
                    "WireGuard server requires one literal UDP listen address, or peer_client_chain without an address",
                ));
            }
        };
        if self.peer_client_chain.is_some()
            && self.peers.iter().any(|peer| peer.persistent_keepalive == 0)
        {
            return Err(invalid(
                "WireGuard server peer_client_chain requires persistent_keepalive for every peer",
            ));
        }
        Ok(WireguardDeviceConfig {
            id: String::new(),
            private_key: self.private_key.clone(),
            addresses: self.addresses.clone(),
            peers: self.peers.clone(),
            listen,
            bind_interface: self.bind_interface.clone(),
            peer_client_chain: self.peer_client_chain.clone(),
            mtu: self.mtu,
            inbound: Some(WireguardInbound {
                rules: server.rules.clone(),
                dns: server.dns.clone(),
            }),
            resource_limits: self.resource_limits.clone(),
        })
    }
}

fn default_mtu() -> u16 {
    1408
}

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

impl WireguardDeviceConfig {
    #[cfg(unix)]
    pub(crate) fn can_reach_endpoint(&self, endpoint: SocketAddr) -> bool {
        self.listen.is_none_or(|listen| {
            let listen_ip = listen.ip().to_canonical();
            let endpoint_ip = endpoint.ip().to_canonical();
            listen_ip.is_ipv4() == endpoint_ip.is_ipv4()
                || listen_ip.is_ipv6() && listen_ip.is_unspecified()
        })
    }

    pub fn limits(&self) -> TunResourceLimits {
        let mut limits = self.resource_limits.clone();
        limits.tcp_memory_bytes.get_or_insert(32 * 1024 * 1024);
        limits.max_tcp_connections.get_or_insert(256);
        limits.max_udp_sessions.get_or_insert(1024);
        limits.max_udp_destinations.get_or_insert(4096);
        limits.max_udp_destinations_per_session.get_or_insert(64);
        limits.max_udp_queued_bytes.get_or_insert(8 * 1024 * 1024);
        limits
    }

    pub fn validate(&self) -> io::Result<()> {
        if !cfg!(unix) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "WireGuard requires Unix",
            ));
        }
        if self.peers.is_empty() || self.addresses.is_empty() {
            return Err(invalid("WireGuard requires local addresses and peers"));
        }
        if !(1280..=1420).contains(&self.mtu) {
            return Err(invalid("WireGuard MTU must be between 1280 and 1420"));
        }
        self.limits().validate()?;
        if self.peer_client_chain.is_some() {
            if self.listen.is_some() || self.bind_interface.is_some() {
                return Err(invalid(
                    "WireGuard peer_client_chain conflicts with listen and bind_interface",
                ));
            }
            if self.peers.iter().any(|peer| peer.endpoint.is_none()) {
                return Err(invalid(
                    "WireGuard peer_client_chain requires an endpoint for every peer",
                ));
            }
        }
        if self
            .inbound
            .as_ref()
            .is_some_and(|inbound| inbound.rules.is_empty())
        {
            return Err(invalid("WireGuard server requires nonempty explicit rules"));
        }
        #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "fuchsia")))]
        if self.bind_interface.is_some() {
            return Err(invalid(
                "WireGuard bind_interface is unsupported on this platform",
            ));
        }
        #[cfg(unix)]
        {
            use gotatun::x25519::{PublicKey, StaticSecret};
            use ipnetwork::IpNetwork;
            let mut families = HashSet::new();
            for address in &self.addresses {
                let network: IpNetwork = address
                    .parse()
                    .map_err(|_| invalid("invalid WireGuard local CIDR"))?;
                if network.ip().to_canonical() != network.ip() {
                    return Err(invalid(
                        "WireGuard local addresses must not be IPv4-mapped IPv6",
                    ));
                }
                if !families.insert(network.is_ipv4())
                    || !smoltcp::wire::IpAddress::from(network.ip()).is_unicast()
                {
                    return Err(invalid(
                        "WireGuard requires at most one unicast local address per family",
                    ));
                }
            }
            let secret = StaticSecret::from(self.private_key.0);
            let own_key = PublicKey::from(&secret);
            let mut keys = HashSet::new();
            let mut ranges: Vec<(usize, IpNetwork)> = Vec::new();
            for (index, peer) in self.peers.iter().enumerate() {
                if !secret
                    .diffie_hellman(&PublicKey::from(peer.public_key.0))
                    .was_contributory()
                {
                    return Err(invalid("WireGuard peer key is non-contributory"));
                }
                if peer.public_key.0 == *own_key.as_bytes() || !keys.insert(peer.public_key.0) {
                    return Err(invalid(
                        "WireGuard peer key is duplicated or equals the local public key",
                    ));
                }
                if peer.allowed_ips.is_empty() {
                    return Err(invalid("WireGuard peer requires allowed_ips"));
                }
                if let Some(endpoint) = &peer.endpoint {
                    let location = crate::address::NetLocation::from_str(endpoint, None)
                        .map_err(|_| invalid("invalid WireGuard peer endpoint"))?;
                    if location.port() == 0 {
                        return Err(invalid("WireGuard peer endpoint requires a nonzero port"));
                    }
                    if location
                        .to_socket_addr_nonblocking()
                        .is_some_and(|address| !self.can_reach_endpoint(address))
                    {
                        return Err(invalid(
                            "WireGuard peer endpoint is incompatible with the listen address",
                        ));
                    }
                }
                for prefix in &peer.allowed_ips {
                    let network: IpNetwork = prefix
                        .parse()
                        .map_err(|_| invalid("invalid WireGuard allowed_ips CIDR"))?;
                    if ranges.iter().any(|(other, range)| {
                        *other != index
                            && (range.contains(network.network())
                                || network.contains(range.network()))
                    }) {
                        return Err(invalid("WireGuard allowed_ips overlap between peers"));
                    }
                    ranges.push((index, network));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_roundtrip_without_debug_or_error_disclosure() {
        let secret = STANDARD.encode([7; 32]);
        let key: WireguardKey = serde_yaml::from_str(&secret).unwrap();
        assert!(!format!("{key:?}").contains(&secret));
        let restored: WireguardKey =
            serde_yaml::from_str(&serde_yaml::to_string(&key).unwrap()).unwrap();
        assert_eq!(key.0, restored.0);
        for value in ["secret-value", "12345", "[secret-value]", "''"] {
            let error = serde_yaml::from_str::<WireguardKey>(value)
                .unwrap_err()
                .to_string();
            assert!(!error.contains("secret-value"));
        }
    }
}
