//! AmneziaWG 2.0 client outbound module.
//!
//! Implements a virtual network tunnel using the AmneziaWG protocol,
//! backed by the boringtun fork with AmneziaWG 2.0 support.

mod config;
mod connector;
mod netstack;
mod tunnel;

pub use connector::AmneziaWgConnector;
