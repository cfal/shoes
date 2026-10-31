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

//! Source routes cannot contain resolved choices.
//! ```compile_fail
//! use shoes::config::{ClientChainHop, resolved::ResolvedClientChoice};
//! fn source(choice: ResolvedClientChoice) -> ClientChainHop {
//!     ClientChainHop::Choice(Box::new(choice))
//! }
//! ```
//!
//! Executable routes cannot contain source chains.
//! ```compile_fail
//! use shoes::config::{ClientChain, resolved::ResolvedClientChain};
//! fn execute(_: ResolvedClientChain) {}
//! execute(ClientChain::default());
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
#[derive(Debug, Clone, Serialize)]
pub struct ResolvedWireguardClientConfig {
    #[serde(flatten)]
    pub(crate) settings: wireguard::WireguardClientRecord<ResolvedClientChain>,
    #[serde(skip)]
    pub(crate) endpoint_id: String,
    #[serde(skip)]
    pub(crate) connector: Option<std::sync::Arc<dyn crate::tcp::socket_connector::SocketConnector>>,
}

impl std::ops::Deref for ResolvedWireguardClientConfig {
    type Target = wireguard::WireguardClientRecord<ResolvedClientChain>;
    fn deref(&self) -> &Self::Target {
        &self.settings
    }
}

impl std::ops::DerefMut for ResolvedWireguardClientConfig {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.settings
    }
}
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
#[allow(clippy::large_enum_variant)]
pub enum ResolvedShadowTlsServerHandshakeConfig {
    Local(server::ShadowTlsLocalHandshake),
    Remote(ResolvedShadowTlsRemoteHandshake),
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
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

impl Default for ResolvedRuleConfig {
    fn default() -> Self {
        Self {
            criteria: super::rules::RuleCriteria::default(),
            action: ResolvedRuleActionConfig::Allow {
                override_address: None,
                client_chains: crate::option_util::NoneOrSome::One(ResolvedClientChain::default()),
            },
        }
    }
}

impl ResolvedDnsConfig {
    pub fn resolved_group(&self) -> Option<&str> {
        self.group.as_deref()
    }
}

#[cfg(test)]
mod tests;
