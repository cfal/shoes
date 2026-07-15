//! DNS resolver module with configurable DNS servers.
//!
//! Supports:
//! - System resolver (NativeResolver)
//! - UDP DNS
//! - TCP DNS
//! - DNS-over-TLS (DoT) - requires `hickory-tls` feature
//! - DNS-over-HTTPS (DoH) - requires `hickory-https` feature
//!
//! TCP-based protocols (tcp://, tls://, https://) support routing through
//! proxy chains via the ProxyRuntimeProvider.

mod builder;
mod composite_resolver;
pub mod fake_ip;
pub mod fake_ip_server;
mod hickory_resolver;
mod parsed;
mod proxy_runtime;

pub use builder::build_dns_registry;
pub use fake_ip::FakeIpManager;
pub use parsed::{IpStrategy, ParsedDnsUrl};
