use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;

use crate::address::NetLocation;
use crate::async_stream::{AsyncMessageStream, AsyncStream, AsyncTargetedMessageStream};
use crate::client_proxy_selector::ClientProxySelector;

pub enum TcpServerSetupResult {
    TcpForward {
        remote_location: NetLocation,
        stream: Box<dyn AsyncStream>,
        need_initial_flush: bool,
        /// Response to write to the server stream after connection to remote location succeeds
        connection_success_response: Option<Box<[u8]>>,
        /// Initial data to send to the remote location
        initial_remote_data: Option<Box<[u8]>>,
        /// The proxy selector to use for routing this connection
        proxy_selector: Arc<ClientProxySelector>,
    },
    BidirectionalUdp {
        need_initial_flush: bool,
        remote_location: NetLocation,
        stream: Box<dyn AsyncMessageStream>,
        /// The proxy selector to use for routing this connection
        proxy_selector: Arc<ClientProxySelector>,
    },
    MultiDirectionalUdp {
        need_initial_flush: bool,
        stream: Box<dyn AsyncTargetedMessageStream>,
        /// The proxy selector to use for routing this connection
        proxy_selector: Arc<ClientProxySelector>,
    },
    SessionBasedUdp {
        need_initial_flush: bool,
        stream: Box<dyn crate::async_stream::AsyncSessionMessageStream>,
        /// The proxy selector to use for routing this connection
        proxy_selector: Arc<ClientProxySelector>,
    },
    /// Connection has been fully handled (e.g., spawned as a background task).
    /// No further processing needed by the caller.
    AlreadyHandled,
}

impl TcpServerSetupResult {
    pub fn set_need_initial_flush(&mut self, need_initial_flush: bool) {
        match self {
            TcpServerSetupResult::TcpForward {
                need_initial_flush: flush,
                ..
            }
            | TcpServerSetupResult::BidirectionalUdp {
                need_initial_flush: flush,
                ..
            }
            | TcpServerSetupResult::MultiDirectionalUdp {
                need_initial_flush: flush,
                ..
            }
            | TcpServerSetupResult::SessionBasedUdp {
                need_initial_flush: flush,
                ..
            } => {
                *flush = need_initial_flush;
            }
            TcpServerSetupResult::AlreadyHandled => {}
        }
    }
}

#[async_trait]
pub trait TcpServerHandler: Send + Sync + Debug {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult>;
}

pub struct TcpClientSetupResult {
    pub client_stream: Box<dyn AsyncStream>,
    /// Early application data that was buffered during protocol handshake.
    /// Only expected from the final destination - intermediate hops should not
    /// return early data (all proxy protocols are client-initiated).
    pub early_data: Option<Vec<u8>>,
}

#[async_trait]
pub trait TcpClientHandler: Send + Sync + Debug {
    /// Setup a client connection through this proxy.
    ///
    /// # Arguments
    /// * `client_stream` - The transport stream to the proxy server
    /// * `remote_location` - The destination to connect to through the proxy
    ///
    /// # Returns
    /// * `client_stream` - The wrapped stream ready for application data
    /// * `early_data` - Any application data received during handshake (from final destination)
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: NetLocation,
    ) -> std::io::Result<TcpClientSetupResult>;

    /// Returns true if this handler supports UDP-over-TCP tunneling.
    fn supports_udp_over_tcp(&self) -> bool {
        false
    }

    /// Setup a bidirectional UDP message stream over a TCP connection.
    /// Only called if `supports_udp_over_tcp()` returns true.
    ///
    /// # Arguments
    /// * `client_stream` - The transport stream to the proxy server
    /// * `target` - The destination for UDP packets
    ///
    /// # Returns
    /// A message stream for sending/receiving UDP packets to the target.
    async fn setup_client_udp_bidirectional(
        &self,
        _client_stream: Box<dyn AsyncStream>,
        _target: NetLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "UDP-over-TCP not supported by this protocol",
        ))
    }
}
