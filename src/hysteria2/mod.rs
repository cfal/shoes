//! Hysteria2: server, client and the frame codec they share.

// The client half of the codec has no caller in the binary until the chain
// builder starts constructing Hysteria2 connectors, and the binary declares
// this module privately, so its lint would fire on code that is merely early.
// Scoped to the codec so the server next door stays under the lint. Remove when
// the connector lands.
pub mod auth;
pub mod client;
pub mod frame;
pub mod server;
pub mod udp;

pub use client::Hysteria2Connector;
pub use server::start_hysteria2_server;
