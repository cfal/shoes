//! ProxyConnector trait - Wraps protocols on existing streams.
//!
//! This trait handles protocol setup for proxy connections. It is responsible for:
//! - Setting up proxy protocols (VLESS, VMess, SOCKS5, etc.) on existing streams
//! - UDP-over-TCP tunneling through proxy protocols
//!
//! ## Design
//!
//! Every `ClientConfig` with a non-direct protocol implicitly defines a `ProxyConnector`
//! through its `protocol` and `address` fields.
//!
//! When a config is used:
//! - **As hop 0**: The ProxyConnector wraps the stream from SocketConnector
//! - **As hop 1+**: The ProxyConnector wraps the stream from the previous hop
//!
//! `protocol: direct` does NOT create a ProxyConnector - it only creates a SocketConnector.

use async_trait::async_trait;
use std::fmt::Debug;

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::tcp_handler::{TcpClientSetupResult, TcpClientUdpSetupResult, UdpStreamRequest};

/// Trait for proxy protocol connectors.
///
/// Used to wrap protocols on existing streams. The stream may come from:
/// - A SocketConnector (at hop 0)
/// - A previous ProxyConnector (at hop 1+)
///
/// ## Implementations
///
/// - `TcpClientConnector`: For all proxy protocols (SOCKS5, HTTP, VMess, VLESS, etc.)
#[async_trait]
pub trait ProxyConnector: Send + Sync + Debug {
    /// Returns the proxy server address.
    ///
    /// This is used to determine where the SocketConnector should connect to
    /// when this is the first ProxyConnector in the chain.
    fn proxy_location(&self) -> &NetLocation;

    /// Check if this connector supports UDP-over-TCP tunneling.
    fn supports_udp_over_tcp(&self) -> bool;

    /// Setup protocol on existing stream.
    ///
    /// # Arguments
    /// * `stream` - Existing transport stream
    /// * `target` - Where traffic should reach through this hop
    ///              (either the next proxy, or the final destination)
    async fn setup_tcp_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        target: &NetLocation,
    ) -> std::io::Result<TcpClientSetupResult>;

    /// Setup UDP-over-TCP on existing stream.
    ///
    /// # Arguments
    /// * `stream` - Existing transport stream
    /// * `request` - The type of UDP stream requested
    async fn setup_udp_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        request: UdpStreamRequest,
    ) -> std::io::Result<TcpClientUdpSetupResult>;
}
