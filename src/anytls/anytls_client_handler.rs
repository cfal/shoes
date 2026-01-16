//! AnyTLS Client Handler
//!
//! Implements TcpClientHandler for AnyTLS protocol outbound connections.
//!
//! TODO: Implement session pooling to enable real multiplexing.
//! Currently each request creates a new TLS connection + AnyTLS session with a single stream.
//! To benefit from AnyTLS multiplexing:
//! - Pool/reuse AnyTlsClientSession instances across multiple client requests
//! - Open multiple streams on the same session for different destinations
//! - Add config options like idle_session_timeout, min_idle_session (similar to sing-box)

use async_trait::async_trait;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::anytls::anytls_client_session::AnyTlsClientSession;
use crate::anytls::anytls_padding::PaddingFactory;
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::AsyncStream;
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};
use crate::uot::UOT_V2_MAGIC_ADDRESS;
use crate::vless::VlessMessageStream;

/// AnyTLS client handler implementing TcpClientHandler.
///
/// Creates an AnyTLS session on the provided transport (expected to be TLS-wrapped),
/// opens multiplexed streams to destinations, and supports UDP-over-TCP via UoT magic addresses.
#[derive(Clone)]
pub struct AnyTlsClientHandler {
    /// Authentication password
    password: String,
    /// Padding factory for traffic obfuscation
    padding: Arc<PaddingFactory>,
    /// UDP enabled
    udp_enabled: bool,
}

impl std::fmt::Debug for AnyTlsClientHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsClientHandler")
            .field("udp_enabled", &self.udp_enabled)
            .finish()
    }
}

impl AnyTlsClientHandler {
    /// Create a new AnyTLS client handler
    pub fn new(password: String, padding: Arc<PaddingFactory>, udp_enabled: bool) -> Self {
        Self {
            password,
            padding,
            udp_enabled,
        }
    }
}

#[async_trait]
impl TcpClientHandler for AnyTlsClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let session =
            AnyTlsClientSession::new(client_stream, &self.password, Arc::clone(&self.padding))
                .await?;

        let stream = session.open_stream(remote_location.into_location()).await?;

        Ok(TcpClientSetupResult {
            client_stream: Box::new(stream),
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.udp_enabled
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if !self.udp_enabled {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "UDP not enabled for AnyTLS client",
            ));
        }

        let session =
            AnyTlsClientSession::new(client_stream, &self.password, Arc::clone(&self.padding))
                .await?;

        // UoT V2 Connect Mode: single destination via magic address
        let uot_dest = NetLocation::new(Address::Hostname(UOT_V2_MAGIC_ADDRESS.to_string()), 0);
        let mut stream = session.open_stream(uot_dest).await?;

        // UoT V2 header: isConnect(1) + destination
        stream.write_u8(1).await?;
        stream.write_all(&encode_socks_address(target.location())).await?;
        stream.flush().await?;

        let message_stream = VlessMessageStream::new(stream);

        Ok(Box::new(message_stream))
    }
}

/// Encode a NetLocation to SOCKS address format
fn encode_socks_address(location: &NetLocation) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);

    match location.address() {
        Address::Ipv4(ip) => {
            buf.push(0x01); // IPv4
            buf.extend_from_slice(&ip.octets());
        }
        Address::Ipv6(ip) => {
            buf.push(0x04); // IPv6
            buf.extend_from_slice(&ip.octets());
        }
        Address::Hostname(host) => {
            buf.push(0x03); // Domain
            buf.push(host.len() as u8);
            buf.extend_from_slice(host.as_bytes());
        }
    }

    buf.extend_from_slice(&location.port().to_be_bytes());
    buf
}
