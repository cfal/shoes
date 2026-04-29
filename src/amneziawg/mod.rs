//! AmneziaWG 2.0 client outbound module.
//!
//! Implements a virtual network tunnel using the AmneziaWG protocol,
//! backed by the boringtun fork with AmneziaWG 2.0 support.

mod connector;

pub use connector::AmneziaWgConnector;
