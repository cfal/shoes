//! AnyTLS Client Handler
//!
//! Implements TcpClientHandler for AnyTLS protocol outbound connections.
//!
//! Uses session pooling to multiplex multiple streams over a single TLS
//! connection. Each incoming request either reuses an existing session
//! (if one is available and under the stream limit) or creates a new
//! session from the provided transport.

use async_trait::async_trait;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::anytls::anytls_client_session::AnyTlsClientSession;
use crate::anytls::anytls_padding::PaddingFactory;
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::AsyncStream;
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};
use crate::uot::UOT_V2_MAGIC_ADDRESS;
use crate::vless::VlessMessageStream;

/// Maximum number of concurrent streams per session before creating a new one.
/// Keep this small to limit head-of-line blocking on a single TLS connection.
const MAX_STREAMS_PER_SESSION: u32 = 8;

/// AnyTLS client handler implementing TcpClientHandler.
///
/// Maintains a pool of AnyTLS sessions for connection multiplexing.
/// Each session wraps a single TLS connection and supports multiple
/// concurrent streams (up to MAX_STREAMS_PER_SESSION).
#[derive(Clone)]
pub struct AnyTlsClientHandler {
    /// Authentication password
    password: String,
    /// Padding factory for traffic obfuscation
    padding: Arc<PaddingFactory>,
    /// UDP enabled
    udp_enabled: bool,
    /// Pool of active sessions available for stream multiplexing
    session_pool: Arc<Mutex<Vec<Arc<AnyTlsClientSession>>>>,
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
            session_pool: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Get or create a session for opening a new stream.
    ///
    /// Strategy:
    /// 1. Remove dead sessions from the pool
    /// 2. Try to reuse the session with the fewest active streams (if under limit)
    /// 3. If no reusable session, create a new one from the provided transport
    ///
    /// The provided `transport` is ONLY consumed when a new session is needed.
    /// If an existing session is reused, the transport is dropped (unused).
    async fn get_or_create_session(
        &self,
        transport: Box<dyn AsyncStream>,
    ) -> std::io::Result<Arc<AnyTlsClientSession>> {
        let mut pool = self.session_pool.lock().await;

        // Remove dead sessions
        pool.retain(|s| s.is_usable());

        // Find the session with the fewest streams that's under the limit
        let mut best: Option<(usize, u32)> = None;
        for (i, session) in pool.iter().enumerate() {
            let count = session.active_stream_count();
            if count < MAX_STREAMS_PER_SESSION {
                match best {
                    None => best = Some((i, count)),
                    Some((_, best_count)) if count < best_count => {
                        best = Some((i, count));
                    }
                    _ => {}
                }
            }
        }

        if let Some((idx, count)) = best {
            let session = Arc::clone(&pool[idx]);
            log::debug!(
                "AnyTLS: reusing session (streams={}, pool={})",
                count,
                pool.len()
            );
            return Ok(session);
        }

        // No reusable session — create a new one
        // Release lock before the potentially slow TLS handshake
        drop(pool);

        log::debug!("AnyTLS: creating new session");
        let session =
            AnyTlsClientSession::new(transport, &self.password, Arc::clone(&self.padding)).await?;

        // Add to pool
        let mut pool = self.session_pool.lock().await;
        pool.push(Arc::clone(&session));
        log::debug!("AnyTLS: pool size = {}", pool.len());

        Ok(session)
    }
}

#[async_trait]
impl TcpClientHandler for AnyTlsClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let session = self.get_or_create_session(client_stream).await?;

        let stream = session
            .open_stream(remote_location.into_location())
            .await?;

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

        let session = self.get_or_create_session(client_stream).await?;

        // UoT V2 Connect Mode: single destination via magic address
        let uot_dest = NetLocation::new(Address::Hostname(UOT_V2_MAGIC_ADDRESS.to_string()), 0);
        let mut stream = session.open_stream(uot_dest).await?;

        // UoT V2 header: isConnect(1) + destination
        stream.write_u8(1).await?;
        stream
            .write_all(&encode_socks_address(target.location()))
            .await?;
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
