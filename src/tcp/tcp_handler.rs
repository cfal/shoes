use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream, AsyncTargetedMessageStream};
use crate::client_proxy_selector::ClientProxySelector;

pub enum TcpServerSetupResult {
    TcpForward {
        remote_location: NetLocation,
        stream: Box<dyn AsyncStream>,
        need_initial_flush: bool,
        /// Response to write to the server stream after connection to remote location succeeds
        connection_success_response: Option<Box<[u8]>>,
        connection_failure_response: Option<fn(std::io::ErrorKind) -> Vec<u8>>,
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
    /// Long-lived work, polled outside the setup deadline and cancelled with its owner.
    /// The producer/session owns output flushing; `need_initial_flush` does not apply.
    Session(Pin<Box<dyn Future<Output = ()> + Send>>),
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
            TcpServerSetupResult::Session(_) => {}
        }
    }
}

#[async_trait]
#[allow(
    clippy::double_must_use,
    reason = "async-trait adds must_use to boxed futures"
)]
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

/// A selected route whose transport is acquired only on a pool miss. Wrappers
/// transform the future, keeping warm reuse ahead of every transport handshake.
pub struct ClientTransport<'a> {
    pub route: Arc<dyn super::carrier_dialer::CarrierDialer>,
    pub open: futures::future::BoxFuture<'a, std::io::Result<Box<dyn AsyncStream>>>,
}

impl<'a> ClientTransport<'a> {
    pub fn wrap<F, Fut, S>(self, wrap: F) -> Self
    where
        F: FnOnce(Box<dyn AsyncStream>) -> Fut + Send + 'a,
        Fut: Future<Output = std::io::Result<S>> + Send + 'a,
        S: AsyncStream + 'static,
    {
        Self {
            route: self.route,
            open: Box::pin(async move {
                let stream = wrap(self.open.await?).await?;
                Ok(Box::new(stream) as Box<dyn AsyncStream>)
            }),
        }
    }
}

#[async_trait]
#[allow(
    clippy::double_must_use,
    reason = "async-trait adds must_use to boxed futures"
)]
pub trait TcpClientHandler: Send + Sync + Debug {
    fn has_session_pool(&self) -> bool {
        false
    }

    async fn connect_client_tcp(
        &self,
        transport: ClientTransport<'_>,
        target: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        self.setup_client_tcp_stream(transport.open.await?, target)
            .await
    }

    async fn connect_client_udp(
        &self,
        transport: ClientTransport<'_>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        self.setup_client_udp_bidirectional(transport.open.await?, target)
            .await
    }

    /// Resolve protocol-local targets with the current dial's resolver, including on reuse.
    async fn prepare_target(
        &self,
        target: ResolvedLocation,
        _resolver: &Arc<dyn crate::resolver::Resolver>,
    ) -> std::io::Result<ResolvedLocation> {
        Ok(target)
    }

    /// Validates the immediately enclosing TLS layer before any protocol bytes are sent.
    fn validate_alpn(&self, _alpn: Option<&[u8]>) -> std::io::Result<()> {
        Ok(())
    }

    /// Opens a logical stream on an existing session without acquiring a new transport.
    /// Only a miss permits cold setup; an open error must not retry the request.
    async fn try_reuse_tcp_stream(
        &self,
        _target: &ResolvedLocation,
    ) -> std::io::Result<Option<TcpClientSetupResult>> {
        Ok(None)
    }

    /// Setup a client connection through this proxy.
    ///
    /// # Arguments
    /// * `client_stream` - The transport stream to the proxy server
    /// * `remote_location` - The destination to connect to through the proxy.
    ///                       May include pre-resolved address to avoid duplicate DNS lookups.
    ///
    /// # Returns
    /// * `client_stream` - The wrapped stream ready for application data
    /// * `early_data` - Any application data received during handshake (from final destination)
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
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
    /// * `target` - The destination for UDP packets.
    ///              May include pre-resolved address to avoid duplicate DNS lookups.
    ///
    /// # Returns
    /// A message stream for sending/receiving UDP packets to the target.
    async fn setup_client_udp_bidirectional(
        &self,
        _client_stream: Box<dyn AsyncStream>,
        _target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "UDP-over-TCP not supported by this protocol",
        ))
    }
}
