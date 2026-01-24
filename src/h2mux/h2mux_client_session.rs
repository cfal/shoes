//! H2MUX Client Session
//!
//! Manages a single HTTP/2 connection for multiplexing multiple streams.
//! Matches sing-mux behavior: uses PING keepalive to detect dead connections,
//! but has no application-level idle timeout (relies on session pool cleanup).

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use bytes::Bytes;
use h2::{Ping, PingPong};
use http::{Method, Request, Version};
use log::debug;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::interval;

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;

use super::H2MuxOptions;
use super::activity_tracker::{PING_INTERVAL, PING_TIMEOUT, STREAM_OPEN_TIMEOUT};
use super::h2mux_client_stream::H2MuxClientStream;
use super::h2mux_padding::H2MuxPaddingStream;
use super::h2mux_protocol::SessionRequest;

/// HTTP/2 window and frame size configuration.
const STREAM_WINDOW_SIZE: u32 = 256 * 1024; // 256 KB per stream
const CONNECTION_WINDOW_SIZE: u32 = 1 << 20; // 1 MB (matches Go's http2 default)
const MAX_FRAME_SIZE: u32 = (1 << 24) - 1; // ~16 MB (max allowed by HTTP/2)

/// Client session managing multiplexed streams over a single H2 connection.
///
/// Matches sing-mux behavior:
/// - PING keepalive (30s) - detects dead connections
/// - Stream open timeout (5s) - prevents hanging on unresponsive servers
/// - No application-level idle timeout (session pool handles cleanup)
pub struct H2MuxClientSession {
    send_request: h2::client::SendRequest<Bytes>,
    /// Handle to abort the connection driver on drop
    driver_handle: Arc<DriverHandle>,
    padding_enabled: bool,
    /// Approximate count of open streams. Only incremented, never decremented.
    /// TODO: For proper session pooling, wrap streams in a guard that decrements on drop.
    active_streams: AtomicU32,
    /// Closed flag - set by ping failure or connection error
    is_closed: Arc<AtomicBool>,
}

impl std::fmt::Debug for H2MuxClientSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2MuxClientSession")
            .field("padding_enabled", &self.padding_enabled)
            .field(
                "active_streams",
                &self.active_streams.load(Ordering::Relaxed),
            )
            .field("is_closed", &self.is_closed.load(Ordering::Relaxed))
            .finish()
    }
}

/// RAII wrapper to abort the driver when all session clones are dropped
struct DriverHandle(tokio::task::AbortHandle);

impl Drop for DriverHandle {
    fn drop(&mut self) {
        debug!("H2MuxClientSession: aborting connection driver");
        self.0.abort();
    }
}

impl Clone for H2MuxClientSession {
    fn clone(&self) -> Self {
        Self {
            send_request: self.send_request.clone(),
            driver_handle: Arc::clone(&self.driver_handle),
            padding_enabled: self.padding_enabled,
            active_streams: AtomicU32::new(self.active_streams.load(Ordering::Relaxed)),
            is_closed: Arc::clone(&self.is_closed),
        }
    }
}

impl H2MuxClientSession {
    /// Create a new client session from a raw connection.
    ///
    /// This performs:
    /// 1. Send session request header on RAW stream (unpadded)
    /// 2. Apply padding layer if enabled
    /// 3. Perform HTTP/2 handshake over (potentially padded) stream
    /// 4. Spawn connection driver, idle watchdog, and PING keepalive tasks
    pub async fn new<IO>(mut conn: IO, options: &H2MuxOptions) -> io::Result<Self>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Send session request header on RAW stream (before padding)
        let session_req = SessionRequest::new(options.protocol, options.padding);
        session_req.write(&mut conn).await?;

        // Apply padding and perform handshake
        if options.padding {
            let padded = H2MuxPaddingStream::new(conn);
            Self::handshake_and_spawn(padded, options.padding).await
        } else {
            Self::handshake_and_spawn(conn, options.padding).await
        }
    }

    /// Perform HTTP/2 handshake and spawn driver + timeout tasks.
    async fn handshake_and_spawn<IO>(conn: IO, padding_enabled: bool) -> io::Result<Self>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (send_request, mut connection) = h2::client::Builder::new()
            .initial_window_size(STREAM_WINDOW_SIZE)
            .initial_connection_window_size(CONNECTION_WINDOW_SIZE)
            .max_frame_size(MAX_FRAME_SIZE)
            .max_concurrent_streams(1024)
            .handshake(conn)
            .await
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("H2 client handshake failed: {}", e),
                )
            })?;

        // Take ping_pong handle before spawning - can only be called once
        let ping_pong = connection.ping_pong();

        let is_closed = Arc::new(AtomicBool::new(false));

        // Spawn connection driver
        let abort_handle = tokio::spawn(async move {
            if let Err(e) = connection.await {
                debug!("H2MUX client connection ended: {}", e);
            }
        })
        .abort_handle();

        // Spawn PING keepalive task to detect dead connections
        // (matches Go's http2.Transport.ReadIdleTimeout behavior)
        if let Some(pp) = ping_pong {
            Self::spawn_ping_task(pp, Arc::clone(&is_closed));
        }

        debug!("H2MuxClientSession: ready for multiplexing");

        Ok(Self {
            send_request,
            driver_handle: Arc::new(DriverHandle(abort_handle)),
            padding_enabled,
            active_streams: AtomicU32::new(0),
            is_closed,
        })
    }

    /// Spawn PING keepalive task to detect dead connections.
    ///
    /// Sends periodic PINGs to verify the server is still responsive.
    /// Matches Go's http2.Transport.ReadIdleTimeout behavior.
    fn spawn_ping_task(mut ping_pong: PingPong, is_closed: Arc<AtomicBool>) {
        tokio::spawn(async move {
            let mut timer = interval(PING_INTERVAL);
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Skip the first tick which returns immediately
            timer.tick().await;

            loop {
                timer.tick().await;

                if is_closed.load(Ordering::Relaxed) {
                    break;
                }

                // Send PING and wait for PONG
                match tokio::time::timeout(PING_TIMEOUT, ping_pong.ping(Ping::opaque())).await {
                    Ok(Ok(_pong)) => {
                        debug!("H2MUX client: PING/PONG successful");
                    }
                    Ok(Err(e)) => {
                        debug!("H2MUX client: PING failed: {}", e);
                        is_closed.store(true, Ordering::Relaxed);
                        break;
                    }
                    Err(_) => {
                        debug!("H2MUX client: PING timeout");
                        is_closed.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
        });
    }

    /// Check if the session is still usable.
    pub fn is_ready(&self) -> bool {
        !self.is_closed.load(Ordering::Relaxed)
    }

    /// Get the number of active streams.
    #[allow(dead_code)]
    pub fn active_streams(&self) -> u32 {
        self.active_streams.load(Ordering::Relaxed)
    }

    /// Open a new TCP stream to the specified destination.
    pub async fn open_tcp(
        &mut self,
        destination: &NetLocation,
    ) -> io::Result<Box<dyn AsyncStream>> {
        self.open_stream_with_timeout(destination, true).await
    }

    /// Open a new UDP stream to the specified destination.
    pub async fn open_udp(
        &mut self,
        destination: &NetLocation,
        _packet_addr: bool,
    ) -> io::Result<Box<dyn AsyncStream>> {
        self.open_stream_with_timeout(destination, false).await
    }

    /// Open stream with timeout wrapper.
    async fn open_stream_with_timeout(
        &mut self,
        destination: &NetLocation,
        is_tcp: bool,
    ) -> io::Result<Box<dyn AsyncStream>> {
        if self.is_closed.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "H2MUX session is closed",
            ));
        }

        tokio::time::timeout(STREAM_OPEN_TIMEOUT, self.open_stream(destination, is_tcp))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("H2MUX stream open timeout to {}", destination),
                )
            })?
    }

    /// Open a new stream with the given destination.
    ///
    /// Uses lazy stream pattern matching sing-mux's behavior:
    /// - Returns immediately after sending CONNECT request
    /// - Response is resolved asynchronously on first read
    /// - StreamRequest is prepended to first write
    /// - Status response is read on first read
    async fn open_stream(
        &mut self,
        destination: &NetLocation,
        is_tcp: bool,
    ) -> io::Result<Box<dyn AsyncStream>> {
        // Create CONNECT request - h2 crate handles proper pseudo-header encoding
        let http_request = Request::builder()
            .method(Method::CONNECT)
            .uri("https://localhost")
            .version(Version::HTTP_2)
            .body(())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        // Send CONNECT request
        let (response_future, send_stream) = self
            .send_request
            .send_request(http_request, false)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to send CONNECT: {}", e),
                )
            })?;

        // Create unified client stream with lazy response resolution
        let client_stream =
            H2MuxClientStream::new(send_stream, response_future, destination.clone(), is_tcp)?;

        self.active_streams.fetch_add(1, Ordering::Relaxed);

        debug!("H2MuxClientSession: opened stream to {}", destination);

        Ok(Box::new(client_stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_clone() {
        fn assert_clone<T: Clone>() {}
        assert_clone::<H2MuxClientSession>();
    }
}
