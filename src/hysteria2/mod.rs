//! Hysteria2: server, client and the frame codec they share.

// The client half of the codec has no caller in the binary until the chain
// builder starts constructing Hysteria2 connectors, and the binary declares
// this module privately, so its lint would fire on code that is merely early.
// Scoped to the codec so the server next door stays under the lint. Remove when
// the connector lands.
#[allow(dead_code)]
pub mod auth;
#[allow(dead_code)]
pub mod frame;
pub mod server;

pub use server::start_hysteria2_server;
