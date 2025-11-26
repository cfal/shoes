use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;

use crate::address::NetLocation;
use crate::async_stream::{
    AsyncMessageStream, AsyncSessionMessageStream, AsyncSourcedMessageStream, AsyncStream,
    AsyncTargetedMessageStream,
};
use crate::client_proxy_selector::ClientProxySelector;
use crate::option_util::NoneOrOne;

pub enum TcpServerSetupResult {
    TcpForward {
        remote_location: NetLocation,
        stream: Box<dyn AsyncStream>,
        need_initial_flush: bool,
        // the response to write to the server stream after a connection to the remote location is
        // successful
        connection_success_response: Option<Box<[u8]>>,
        // initial data to send to the remote location.
        initial_remote_data: Option<Box<[u8]>>,
        override_proxy_provider: NoneOrOne<Arc<ClientProxySelector>>,
    },
    // TODO: support udp client proxy selector
    BidirectionalUdp {
        need_initial_flush: bool,
        remote_location: NetLocation,
        stream: Box<dyn AsyncMessageStream>,
        override_proxy_provider: NoneOrOne<Arc<ClientProxySelector>>,
    },
    MultiDirectionalUdp {
        need_initial_flush: bool,
        stream: Box<dyn AsyncTargetedMessageStream>,
        override_proxy_provider: NoneOrOne<Arc<ClientProxySelector>>,
    },
    SessionBasedUdp {
        need_initial_flush: bool,
        stream: Box<dyn crate::async_stream::AsyncSessionMessageStream>,
        override_proxy_provider: NoneOrOne<Arc<ClientProxySelector>>,
    },
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
        }
    }
    pub fn override_proxy_provider_unspecified(&self) -> bool {
        match self {
            TcpServerSetupResult::TcpForward {
                override_proxy_provider,
                ..
            }
            | TcpServerSetupResult::BidirectionalUdp {
                override_proxy_provider,
                ..
            }
            | TcpServerSetupResult::MultiDirectionalUdp {
                override_proxy_provider,
                ..
            }
            | TcpServerSetupResult::SessionBasedUdp {
                override_proxy_provider,
                ..
            } => override_proxy_provider.is_unspecified(),
        }
    }

    pub fn set_override_proxy_provider(
        &mut self,
        override_proxy_provider: NoneOrOne<Arc<ClientProxySelector>>,
    ) {
        match self {
            TcpServerSetupResult::TcpForward {
                override_proxy_provider: provider,
                ..
            }
            | TcpServerSetupResult::BidirectionalUdp {
                override_proxy_provider: provider,
                ..
            }
            | TcpServerSetupResult::MultiDirectionalUdp {
                override_proxy_provider: provider,
                ..
            }
            | TcpServerSetupResult::SessionBasedUdp {
                override_proxy_provider: provider,
                ..
            } => {
                *provider = override_proxy_provider;
            }
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

/// Request type for UDP connections through the chain.
/// Contains the server stream so the handler can decide optimal pairing.
/// The handler receives the server stream, decides the optimal client setup,
/// and returns a matched pair ready for copying.
pub enum UdpStreamRequest {
    /// Single fixed destination - server provides AsyncMessageStream.
    /// Target is required: all packets go to this one destination.
    Bidirectional {
        server_stream: Box<dyn AsyncMessageStream>,
        target: NetLocation,
    },

    /// Multiple destinations with address per packet - server provides AsyncTargetedMessageStream.
    /// No target needed: each packet specifies its own destination.
    MultiDirectional {
        server_stream: Box<dyn AsyncTargetedMessageStream>,
    },

    /// Session-based multiplexing (XUDP) - server provides AsyncSessionMessageStream.
    /// No target needed: destinations come in XUDP frames.
    SessionBased {
        server_stream: Box<dyn AsyncSessionMessageStream>,
    },
}

impl std::fmt::Debug for UdpStreamRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UdpStreamRequest::Bidirectional { target, .. } => f
                .debug_struct("Bidirectional")
                .field("target", target)
                .finish_non_exhaustive(),
            UdpStreamRequest::MultiDirectional { .. } => {
                f.debug_struct("MultiDirectional").finish_non_exhaustive()
            }
            UdpStreamRequest::SessionBased { .. } => {
                f.debug_struct("SessionBased").finish_non_exhaustive()
            }
        }
    }
}

impl std::fmt::Display for UdpStreamRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UdpStreamRequest::Bidirectional { target, .. } => {
                write!(f, "Bidirectional(target={})", target)
            }
            UdpStreamRequest::MultiDirectional { .. } => {
                write!(f, "MultiDirectional")
            }
            UdpStreamRequest::SessionBased { .. } => {
                write!(f, "SessionBased")
            }
        }
    }
}

/// Result type for UDP client setup.
/// Contains both server and client streams, ready for copying.
/// The handler has already performed any necessary wrapping to ensure
/// the stream types are compatible for copying.
pub enum TcpClientUdpSetupResult {
    /// Both sides are Bidirectional (AsyncMessageStream).
    /// Simple single-target UDP - used for protocols like Trojan UDP.
    Bidirectional {
        server_stream: Box<dyn AsyncMessageStream>,
        client_stream: Box<dyn AsyncMessageStream>,
    },

    /// Both sides are MultiDirectional.
    /// Server: AsyncTargetedMessageStream (read gives source, write takes target)
    /// Client: AsyncSourcedMessageStream (read gives source, write takes target)
    /// Used for multi-target UDP like native UDP sockets.
    MultiDirectional {
        server_stream: Box<dyn AsyncTargetedMessageStream>,
        client_stream: Box<dyn AsyncSourcedMessageStream>,
    },

    /// Both sides are SessionBased (AsyncSessionMessageStream).
    /// Used by VLESS and VMess with session ID tracking for multiplexed streams.
    SessionBased {
        server_stream: Box<dyn AsyncSessionMessageStream>,
        client_stream: Box<dyn AsyncSessionMessageStream>,
    },
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

    /// Setup a UDP message stream over a TCP connection.
    /// Only called if `supports_udp_over_tcp()` returns true.
    ///
    /// # Arguments
    /// * `client_stream` - The transport stream to the proxy server
    /// * `request` - The type of UDP stream requested. Target is embedded in `Bidirectional` variant.
    ///   The handler MUST return a result matching this request type, or return an error if it
    ///   cannot support that type.
    ///
    /// # Returns
    /// A TcpClientUdpSetupResult matching the requested type.
    async fn setup_client_udp_stream(
        &self,
        _client_stream: Box<dyn AsyncStream>,
        _request: UdpStreamRequest,
    ) -> std::io::Result<TcpClientUdpSetupResult> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "UDP-over-TCP not supported by this protocol",
        ))
    }
}
