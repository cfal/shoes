//! NaiveProxy client session for HTTP/2 multiplexing.
//!
//! This module manages a persistent H2 connection that can handle multiple
//! concurrent CONNECT streams, enabling true HTTP/2 multiplexing on the client side.
//!
//! ## Design
//!
//! `NaiveClientSession` is cheaply cloneable - it wraps h2's `SendRequest` which
//! internally uses `Arc<Mutex<...>>` for shared state. This follows the same pattern
//! as the h2 crate's own examples and benchmarks.
//!
//! The handler maintains `Arc<Mutex<Option<NaiveClientSession>>>` only for:
//! - Lazy initialization (session created on first request)
//! - Reconnection (recreate session if connection dies)
//!
//! Once a session is obtained, it's cloned and used directly without holding locks.

use std::io;
use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request, Version};
use log::debug;
use rand::Rng;

use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncStream;

use super::h2_multi_stream::H2MultiStream;
use super::naive_padding_stream::{
    NaivePaddingStream, PaddingDirection, PaddingType, generate_padding_header,
};

/// A client session managing a single H2 connection with multiplexing support.
///
/// This session maintains a persistent HTTP/2 connection to a NaiveProxy server
/// and can create multiple CONNECT streams over the same connection.
///
/// `NaiveClientSession` is cheaply cloneable - cloning shares the underlying
/// H2 connection (via h2's internal `Arc<Mutex<...>>`).
pub struct NaiveClientSession {
    /// The SendRequest handle - has internal Arc, cheap to clone
    send_request: h2::client::SendRequest<Bytes>,
    /// Handle to abort the connection driver on drop (shared across clones)
    driver_handle: Arc<DriverHandle>,
}

/// Wrapper to abort the driver when all session clones are dropped.
struct DriverHandle(tokio::task::AbortHandle);

impl Drop for DriverHandle {
    fn drop(&mut self) {
        debug!("NaiveClientSession: all clones dropped, aborting connection driver");
        self.0.abort();
    }
}

impl Clone for NaiveClientSession {
    fn clone(&self) -> Self {
        Self {
            send_request: self.send_request.clone(),
            driver_handle: Arc::clone(&self.driver_handle),
        }
    }
}

impl NaiveClientSession {
    /// Create a new client session from an established TLS stream.
    ///
    /// Performs H2 handshake and spawns the connection driver.
    pub async fn new(stream: Box<dyn AsyncStream>) -> io::Result<Self> {
        // H2 settings tuned for reasonable throughput without excessive memory
        // Reference naiveproxy uses ~64KB default, we use 256 KB for better throughput
        const WINDOW_SIZE: u32 = 256 * 1024; // 256 KB (was 16 MB)
        const MAX_FRAME_SIZE: u32 = (1 << 24) - 1; // ~16 MB (max allowed by HTTP/2)

        let (send_request, connection) = h2::client::Builder::new()
            .initial_window_size(WINDOW_SIZE)
            .initial_connection_window_size(WINDOW_SIZE)
            .max_frame_size(MAX_FRAME_SIZE)
            .max_concurrent_streams(1024)
            .handshake(stream)
            .await
            .map_err(|e| io::Error::other(format!("H2 client handshake failed: {}", e)))?;

        let abort_handle = tokio::spawn(async move {
            if let Err(e) = connection.await {
                debug!("NaiveProxy client H2 connection ended: {}", e);
            }
        })
        .abort_handle();

        debug!("NaiveClientSession: H2 handshake complete, session ready for multiplexing");

        Ok(Self {
            send_request,
            driver_handle: Arc::new(DriverHandle(abort_handle)),
        })
    }

    /// Check if this session is still usable for new streams.
    pub fn is_ready(&self) -> bool {
        // SendRequest::poll_ready would be more accurate, but this is a good heuristic
        // The actual check happens when we try to send a request
        true // Optimistic - let send_request fail if not ready
    }

    /// Open a new CONNECT stream to the specified target.
    ///
    /// Returns a stream wrapped with padding if enabled.
    pub async fn open_stream(
        &mut self,
        target: &NetLocation,
        auth_header: &str,
        padding_enabled: bool,
    ) -> io::Result<Box<dyn AsyncStream>> {
        let authority = format_authority(target);

        let mut request = Request::builder()
            .method(Method::CONNECT)
            .uri(&authority)
            .version(Version::HTTP_2)
            .header("proxy-authorization", auth_header);

        if padding_enabled {
            let padding_len = rand::rng().random_range(16..=32);
            request = request.header("padding", generate_padding_header(padding_len));
            request = request.header("padding-type-request", "1, 0");
        }

        let request = request
            .body(())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        // No ready() call needed - matches h2 benchmarks pattern
        let (response_future, send_stream) = self
            .send_request
            .send_request(request, false)
            .map_err(|e| io::Error::other(format!("Failed to send CONNECT: {}", e)))?;

        let response = response_future
            .await
            .map_err(|e| io::Error::other(format!("CONNECT response error: {}", e)))?;

        debug!(
            "NaiveClientSession: CONNECT response: status={}, headers={:?}",
            response.status(),
            response.headers()
        );

        if response.status() != http::StatusCode::OK {
            return Err(io::Error::other(format!(
                "CONNECT failed with status: {}",
                response.status()
            )));
        }

        let padding_type = if padding_enabled {
            if let Some(reply) = response.headers().get("padding-type-reply") {
                let reply_str = reply.to_str().unwrap_or("1");
                reply_str
                    .trim()
                    .parse::<u8>()
                    .ok()
                    .and_then(PaddingType::from_u8)
                    .unwrap_or(PaddingType::Variant1)
            } else if response.headers().contains_key("padding") {
                // Backward compat: padding header without type means Variant1
                PaddingType::Variant1
            } else {
                PaddingType::None
            }
        } else {
            PaddingType::None
        };

        let recv_stream = response.into_body();
        let h2_stream = H2MultiStream::new(send_stream, recv_stream);

        let client_stream: Box<dyn AsyncStream> = if padding_type != PaddingType::None {
            Box::new(NaivePaddingStream::new(
                h2_stream,
                PaddingDirection::Client,
                padding_type,
            ))
        } else {
            Box::new(h2_stream)
        };

        debug!("NaiveClientSession: opened stream to {}", target);

        Ok(client_stream)
    }
}

/// Format authority for CONNECT request
fn format_authority(location: &NetLocation) -> String {
    match location.address() {
        Address::Ipv6(addr) => format!("[{}]:{}", addr, location.port()),
        Address::Ipv4(addr) => format!("{}:{}", addr, location.port()),
        Address::Hostname(host) => format!("{}:{}", host, location.port()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_authority_ipv4() {
        use std::net::Ipv4Addr;
        let loc = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        assert_eq!(format_authority(&loc), "192.168.1.1:8080");
    }

    #[test]
    fn test_format_authority_ipv6() {
        use std::net::Ipv6Addr;
        let loc = NetLocation::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 443);
        assert_eq!(format_authority(&loc), "[::1]:443");
    }

    #[test]
    fn test_format_authority_hostname() {
        let loc = NetLocation::new(Address::Hostname("example.com".to_string()), 443);
        assert_eq!(format_authority(&loc), "example.com:443");
    }
}
