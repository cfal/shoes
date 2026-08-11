//! Configuration types for the proxy server.
//!
//! This module contains all the configuration types used by the proxy server,
//! organized into submodules by functionality:
//!
//! - [`common`]: Shared helpers and constants
//! - [`transport`]: Transport layer types (TCP, QUIC, UDP)
//! - [`shadowsocks`]: Shadowsocks protocol configuration
//! - [`selection`]: ConfigSelection for referencing groups or inline configs
//! - [`server`]: Server-side protocol configurations
//! - [`client`]: Client-side protocol configurations
//! - [`rules`]: Rule configurations for traffic routing
//! - [`groups`]: Top-level configuration groups and the Config enum
//! - [`dns`]: DNS server configuration

pub mod client;
pub mod common;
pub mod dns;
pub mod groups;
pub mod obfs;
pub mod redacted;
pub mod rule_set;
pub mod rules;
pub mod selection;
pub mod server;
pub mod shadowsocks;
pub mod sniff;
pub mod transport;
pub mod tun;

// Re-export all public types for convenience
#[allow(unused_imports)]
pub use client::{
    AmneziaWgClientConfig, AmneziaWgParams, ClientConfig, ClientProxyConfig, H2MuxConfig,
    Hysteria2ClientConfig, TlsClientConfig, TuicClientConfig, TuicUdpRelayMode,
    WebsocketClientConfig, WireGuardClientConfig,
};
pub use common::DEFAULT_REALITY_SHORT_ID;
pub use dns::{DnsConfig, DnsConfigGroup, DnsServerSpec, ExpandedDnsGroup, ExpandedDnsSpec};
pub use groups::{ClientConfigGroup, Config, NamedPem, PemSource};
// Part of the public config surface; the protocol configs that carry it name
// the module type directly, so the binary does not yet reach for this alias.
#[allow(unused_imports)]
pub use obfs::ObfsConfig;
pub use redacted::Redacted;
// Part of the public config surface; the binary itself matches on
// Config::RuleSet rather than naming the type.
#[allow(unused_imports)]
pub use rule_set::RuleSetConfig;
pub use rules::{ClientChain, ClientChainHop, RuleActionConfig, RuleConfig};
pub use selection::ConfigSelection;
pub use server::{
    RealityServerConfig, ServerConfig, ServerProxyConfig, ShadowTlsServerConfig,
    ShadowTlsServerHandshakeConfig, TlsServerConfig, WebsocketPingType, WebsocketServerConfig,
    direct_allow_rule,
};
pub use shadowsocks::ShadowsocksConfig;
// Part of the public config surface; the binary names only SniffConfig.
#[allow(unused_imports)]
pub use sniff::{SniffConfig, SniffProtocolConfig};
pub use transport::{BindLocation, ClientQuicConfig, ServerQuicConfig, TcpConfig, Transport};
pub use tun::{FakeIpConfig, TunConfig};
