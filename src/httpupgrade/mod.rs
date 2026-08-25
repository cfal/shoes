//! HTTPUpgrade: WebSocket's HTTP handshake without WebSocket's framing.
//!
//! Compatible with sing-box's `v2ray-http-upgrade` (`transport/v2rayhttpupgrade`
//! at `0f17638`). The client sends a `GET` carrying `Connection: Upgrade` and
//! `Upgrade: websocket`, the server answers `101`, and both sides then write
//! raw bytes -- no masking, no frame headers, no pings.
//!
//! The distinguishing rule, and the one an implementation gets wrong silently:
//! a real WebSocket handshake must be *refused*. sing-box answers `404` to any
//! request carrying `Sec-WebSocket-Key`, so this client never sends one and
//! this server rejects one.

mod client;
mod server;

#[cfg(test)]
mod tests;

pub use client::HttpUpgradeTcpClientHandler;
pub use server::{HttpUpgradeServerTarget, HttpUpgradeTcpServerHandler};
