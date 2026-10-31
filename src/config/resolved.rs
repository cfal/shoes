//! Routing output of configuration compilation. These types are not input syntax.
//!
//! Source and resolved records are distinct despite sharing their settings layout.
//! ```compile_fail
//! use shoes::config::{ClientConfig, resolved::ResolvedClientConfig};
//! let source: ClientConfig = ResolvedClientConfig::default();
//! ```
//!
//! Resolved output cannot be parsed as configuration.
//! ```compile_fail
//! use shoes::config::resolved::ResolvedClientConfig;
//! let _: ResolvedClientConfig = serde_yaml::from_str("{}").unwrap();
//! ```
//!
//! Carrier routes cannot reintroduce source syntax through a resolved client.
//! ```compile_fail
//! use shoes::config::{ClientChain, resolved::ResolvedWireguardClientConfig};
//! fn replace_carrier(client: &mut ResolvedWireguardClientConfig, source: ClientChain) {
//!     client.peer_client_chain = Some(source);
//! }
//! ```

use serde::Serialize;

use super::GroupType;
use super::types::{client, rules, server, tun, wireguard, xhttp};
use crate::option_util::OneOrSome;

pub use client::ResolvedClientProxyConfig;
pub use server::ResolvedServerProxyConfig;

pub type ResolvedClientConfig = client::ClientRecord<ResolvedClientProxyConfig>;
pub type ResolvedTlsClientConfig = client::TlsClientRecord<ResolvedClientProxyConfig>;
pub type ResolvedWebsocketClientConfig = client::WebsocketClientRecord<ResolvedClientProxyConfig>;
pub type ResolvedXhttpClientConfig = xhttp::XhttpClientRecord<ResolvedClientProxyConfig>;
pub type ResolvedXhttpServerConfig = xhttp::XhttpServerRecord<ResolvedServerProxyConfig>;
pub type ResolvedWireguardClientConfig = wireguard::WireguardClientRecord<ResolvedClientChain>;
pub type ResolvedWireguardServerConfig = wireguard::WireguardServerRecord<ResolvedClientChain>;

pub type ResolvedRuleConfig = rules::RuleRecord<ResolvedClientChain>;
pub type ResolvedRuleActionConfig = rules::RuleActionRecord<ResolvedClientChain>;
pub type ResolvedServerConfig =
    server::ServerRecord<ResolvedServerProxyConfig, ResolvedRuleConfig, ResolvedDnsConfig>;
pub type ResolvedTunConfig = tun::TunRecord<ResolvedRuleConfig, ResolvedDnsConfig>;
pub type ResolvedTlsServerConfig =
    server::TlsServerRecord<ResolvedServerProxyConfig, ResolvedRuleConfig>;
pub type ResolvedWebsocketServerConfig =
    server::WebsocketServerRecord<ResolvedServerProxyConfig, ResolvedRuleConfig>;
pub type ResolvedRealityServerConfig =
    server::RealityServerRecord<ResolvedServerProxyConfig, ResolvedRuleConfig, ResolvedClientHop>;
pub type ResolvedShadowTlsServerConfig = server::ShadowTlsServerRecord<
    ResolvedServerProxyConfig,
    ResolvedRuleConfig,
    ResolvedShadowTlsServerHandshakeConfig,
>;
pub type ResolvedShadowTlsRemoteHandshake =
    server::ShadowTlsRemoteHandshakeRecord<ResolvedClientHop>;

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum ResolvedShadowTlsServerHandshakeConfig {
    Local(server::ShadowTlsLocalHandshake),
    Remote(ResolvedShadowTlsRemoteHandshake),
}

#[derive(Debug, Clone)]
pub enum ResolvedConfig {
    Server(ResolvedServerConfig),
    TunServer(ResolvedTunConfig),
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedDnsConfig {
    pub group: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChainPlan<C> {
    #[serde(rename = "chain")]
    pub(crate) hops: OneOrSome<HopPlan<C>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum HopPlan<C> {
    Single(C),
    Choice(Box<ChoicePlan<C>>),
}

#[derive(Debug, Clone, Serialize)]
pub struct ChoicePlan<C> {
    pub(crate) name: String,
    pub(crate) group_type: GroupType,
    pub(crate) labels: Vec<String>,
    pub(crate) members: Vec<ChainPlan<C>>,
}

pub type ResolvedClientChain = ChainPlan<ResolvedClientConfig>;
pub type ResolvedClientHop = HopPlan<ResolvedClientConfig>;
pub type ResolvedClientChoice = ChoicePlan<ResolvedClientConfig>;

impl Default for ResolvedClientConfig {
    fn default() -> Self {
        Self {
            name: None,
            control: None,
            bind_interface: crate::option_util::NoneOrOne::None,
            address: super::types::common::unspecified_address(),
            protocol: ResolvedClientProxyConfig::Direct,
            transport: super::Transport::default(),
            tcp_settings: None,
            quic_settings: None,
        }
    }
}

impl Default for ResolvedClientChain {
    fn default() -> Self {
        Self {
            hops: OneOrSome::One(HopPlan::Single(ResolvedClientConfig::default())),
        }
    }
}

impl ResolvedDnsConfig {
    pub fn resolved_group(&self) -> Option<&str> {
        self.group.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolved_routes_preserve_identity_serialization_shape() {
        let source = super::super::ClientChain::default();
        let resolved = ResolvedClientChain::default();
        assert_eq!(
            serde_json::to_value(source).unwrap(),
            serde_json::to_value(&resolved).unwrap()
        );
        let choice = HopPlan::Choice(Box::new(ChoicePlan {
            name: "out".into(),
            group_type: GroupType::RoundRobin,
            labels: vec!["direct".into()],
            members: vec![resolved],
        }));
        let value = serde_json::to_value(choice).unwrap();
        assert_eq!(value["name"], "out");
        assert_eq!(value["labels"], serde_json::json!(["direct"]));
        assert_eq!(value["members"][0]["chain"]["protocol"]["type"], "direct");
        assert!(value.get("Choice").is_none());
    }
}

impl ResolvedClientConfig {
    pub fn validate_quic_key_exchange(&self, initial_hop: bool) -> std::io::Result<()> {
        let explicit_groups = self
            .quic_settings
            .as_ref()
            .is_some_and(|settings| !settings.key_exchange_groups.is_default());
        if explicit_groups
            && (!initial_hop
                || self.protocol.is_direct()
                || self.transport != super::Transport::Quic)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "QUIC key_exchange_groups requires a non-direct client at chain hop 0 with transport: quic",
            ));
        }
        Ok(())
    }
}
