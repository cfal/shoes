//! AmneziaWG client outbound module.
//!
//! Implements a virtual network tunnel using the AmneziaWG protocol, backed by
//! the boringtun fork with AmneziaWG 2.0 and 3.0 support. Plain WireGuard is
//! the same code path with every obfuscation parameter left at its default.

mod config;
mod connector;
mod netstack;
mod tunnel;

pub use config::convert_amnezia_config;
pub use connector::AmneziaWgConnector;
