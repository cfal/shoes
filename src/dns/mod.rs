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
mod exchange;
pub mod fake_ip;
mod guard;
mod hickory_resolver;
mod message;
mod parsed;
mod proxy_runtime;
mod system;

pub(crate) use guard::real_only;

#[allow(unused_imports)]
pub use builder::{
    DnsRegistry, DnsSnapshotTask, build_dns_registry, build_dns_registry_for_runtime,
    build_dns_registry_reusing, build_dns_registry_with_limits,
};
pub use parsed::{IpStrategy, ParsedDnsUrl};
#[cfg(all(test, unix))]
pub(crate) use proxy_runtime::ProxyRuntimeProvider;
