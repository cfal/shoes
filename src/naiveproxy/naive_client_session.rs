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
use rand::RngExt;
use tokio::sync::oneshot;

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
#[derive(Clone)]
pub struct NaiveClientSession {
    /// The SendRequest handle - has internal Arc, cheap to clone
    send_request: h2::client::SendRequest<Bytes>,
    driver_handle: Arc<DriverHandle>,
}

struct DriverHandle {
    driver: tokio::task::AbortHandle,
    _drain: oneshot::Sender<()>,
}

impl NaiveClientSession {
    /// Create a new client session from an established TLS stream.
    ///
    /// Performs H2 handshake and spawns the connection driver.
    pub async fn new(stream: Box<dyn AsyncStream>) -> io::Result<Self> {
        // H2 settings tuned for reasonable throughput without excessive memory
        // Reference naiveproxy uses ~64KB default, we use 256 KB for better throughput
        const WINDOW_SIZE: u32 = 256 * 1024; // 256 KB (was 16 MB)
        const MAX_FRAME_SIZE: u32 = 16 * 1024;

        let (send_request, mut connection) = h2::client::Builder::new()
            .initial_window_size(WINDOW_SIZE)
            .initial_connection_window_size(WINDOW_SIZE)
            .max_frame_size(MAX_FRAME_SIZE)
            .max_concurrent_streams(1024)
            .handshake(stream)
            .await
            .map_err(|e| io::Error::other(format!("H2 client handshake failed: {}", e)))?;

        let (drain_tx, drain_rx) = oneshot::channel();
        let abort_handle = tokio::spawn(async move {
            // Retired sessions must flush queued DATA and END_STREAM before teardown.
            let result = tokio::select! {
                result = &mut connection => Some(result),
                _ = drain_rx => tokio::time::timeout(crate::util::SHUTDOWN_TIMEOUT, connection).await.ok(),
            };
            if let Some(Err(e)) = result {
                debug!("NaiveProxy client H2 connection ended: {}", e);
            }
        })
        .abort_handle();

        debug!("NaiveClientSession: H2 handshake complete, session ready for multiplexing");

        Ok(Self {
            send_request,
            driver_handle: Arc::new(DriverHandle {
                driver: abort_handle,
                _drain: drain_tx,
            }),
        })
    }

    /// Check if this session is still usable for new streams.
    pub fn is_ready(&self) -> bool {
        !self.driver_handle.driver.is_finished()
    }

    pub fn same_generation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.driver_handle, &other.driver_handle)
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

        std::future::poll_fn(|cx| self.send_request.poll_ready(cx))
            .await
            .map_err(|e| io::Error::other(format!("H2 session closed: {e}")))?;
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
        let mut h2_stream = H2MultiStream::new(send_stream, recv_stream);
        h2_stream.set_session_owner(self.clone());

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

    #[tokio::test(start_paused = true)]
    async fn last_owner_drain_is_bounded_when_peer_stalls() {
        let (client, _peer) = tokio::io::duplex(64);
        let mut session = NaiveClientSession::new(Box::new(client)).await.unwrap();
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri("example.com:443")
            .body(())
            .unwrap();
        drop(session.send_request.send_request(request, false).unwrap());
        let driver = session.driver_handle.driver.clone();
        drop(session);
        tokio::task::yield_now().await;
        assert!(!driver.is_finished());
        tokio::time::sleep(crate::util::SHUTDOWN_TIMEOUT + std::time::Duration::from_millis(1))
            .await;
        assert!(driver.is_finished());
    }

    #[tokio::test]
    async fn active_stream_keeps_driver_after_session_slot_is_dropped() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, peer) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            let mut conn = h2::server::handshake(peer).await.unwrap();
            let (req, mut respond) = conn.accept().await.unwrap().unwrap();
            let send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let mut stream = H2MultiStream::new(send, req.into_body());
            let echo = async {
                let mut data = [0; 4];
                stream.read_exact(&mut data).await.unwrap();
                stream.write_all(&data).await.unwrap();
                stream.shutdown().await.unwrap();
            };
            tokio::select! { _ = echo => {}, _ = conn.accept() => {} }
            let _ =
                tokio::time::timeout(std::time::Duration::from_millis(100), conn.accept()).await;
        });
        let mut session = NaiveClientSession::new(Box::new(client)).await.unwrap();
        let weak = Arc::downgrade(&session.driver_handle);
        let mut stream = session
            .open_stream(
                &NetLocation::from_str("example.com:443", None).unwrap(),
                "Basic dTpw",
                false,
            )
            .await
            .unwrap();
        drop(session);
        assert!(weak.upgrade().is_some());
        stream.write_all(b"test").await.unwrap();
        let mut data = [0; 4];
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            stream.read_exact(&mut data),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&data, b"test");
        drop(stream);
        assert!(weak.upgrade().is_none());
        server.abort();
        let _ = server.await;
    }

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
