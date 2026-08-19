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
mod hickory_resolver;
mod parsed;
mod proxy_runtime;

pub use builder::build_dns_registry;
// Named in the mobile FFI's PreparedService, which is not compiled on desktop.
#[allow(unused_imports)]
pub use builder::DnsRegistry;
pub use parsed::{IpStrategy, ParsedDnsUrl};
