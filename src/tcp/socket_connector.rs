//! SocketConnector trait - Creates socket connections (TCP or QUIC).
//!
//! This trait handles the socket-level connection at hop 0 of a chain.
//! It is responsible for:
//! - Creating TCP sockets with bind_interface
//! - Creating and caching QUIC endpoints
//! - UDP socket creation for direct connections
//!
//! ## Design
//!
//! Every `ClientConfig` implicitly defines a `SocketConnector` through its
//! socket-related fields: `bind_interface`, `transport`, `tcp_settings`, `quic_settings`.
//!
//! When a config is used:
//! - **As hop 0**: The SocketConnector is used to create the connection
//! - **As hop 1+**: The SocketConnector config is ignored (connection comes from previous hop)

use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;

use crate::async_stream::AsyncStream;
use crate::resolver::Resolver;
use crate::tcp_handler::{TcpClientUdpSetupResult, UdpStreamRequest};

use crate::address::NetLocation;

/// Trait for creating socket connections at hop 0.
///
/// Only used at the first hop of a chain. Handles TCP and QUIC transports
/// with optional bind_interface.
#[async_trait]
pub trait SocketConnector: Send + Sync + Debug {
    /// Create a TCP/QUIC connection to the given address.
    ///
    /// # Arguments
    /// * `resolver` - DNS resolver for address resolution
    /// * `address` - Target address to connect to
    async fn connect(
        &self,
        resolver: &Arc<dyn Resolver>,
        address: &NetLocation,
    ) -> std::io::Result<Box<dyn AsyncStream>>;

    /// Create UDP socket(s) for the given request type.
    ///
    /// Returns matched server/client stream pair ready for copying.
    ///
    /// # Arguments
    /// * `resolver` - DNS resolver for address resolution
    /// * `request` - The type of UDP stream requested
    async fn connect_udp(
        &self,
        resolver: &Arc<dyn Resolver>,
        request: UdpStreamRequest,
    ) -> std::io::Result<TcpClientUdpSetupResult>;
}
