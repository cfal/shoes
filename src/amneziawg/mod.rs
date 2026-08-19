//! AmneziaWG client outbound module.
//!
//! Implements a virtual network tunnel using the AmneziaWG protocol, backed by
//! the boringtun fork with AmneziaWG 2.0 and 3.0 support. Plain WireGuard is
//! the same code path with every obfuscation parameter left at its default.

mod config;
mod connector;
mod endpoint;
mod netstack;
mod tunnel;

pub use config::convert_amnezia_config;
// Used by the mobile FFI, which is compiled only for Android and iOS; nothing
// on a desktop target calls it.
pub use connector::AmneziaWgConnector;
#[allow(unused_imports)]
pub use endpoint::notify_network_change;
