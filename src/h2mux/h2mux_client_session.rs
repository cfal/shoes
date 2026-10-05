//! H2MUX Client Session
//!
//! Manages a single HTTP/2 connection for multiplexing multiple streams.
//! Matches sing-mux behavior: uses PING keepalive to detect dead connections,
//! Streams keep their driver alive; the last owner starts a bounded drain.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use bytes::Bytes;
use h2::{Ping, PingPong};
use http::{Method, Request, Version};
use log::debug;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;
use tokio::time::interval;

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;

use super::H2MuxOptions;
use super::activity_tracker::{
    PING_INTERVAL, PING_TIMEOUT, SHUTDOWN_DRAIN_TIMEOUT, STREAM_OPEN_TIMEOUT,
};
use super::h2mux_client_stream::H2MuxClientStream;
use super::h2mux_padding::H2MuxPaddingStream;
use super::h2mux_protocol::SessionRequest;

/// HTTP/2 window and frame size configuration.
const STREAM_WINDOW_SIZE: u32 = 256 * 1024; // 256 KB per stream
const CONNECTION_WINDOW_SIZE: u32 = 1 << 20; // 1 MB (matches Go's http2 default)
const MAX_FRAME_SIZE: u32 = 16 * 1024;

/// Client session managing multiplexed streams over a single H2 connection.
///
/// Matches sing-mux behavior:
/// - PING keepalive (30s) - detects dead connections
/// - Stream open timeout (5s) - prevents hanging on unresponsive servers
/// - Driver ownership shared by sessions and active streams
#[derive(Clone)]
pub struct H2MuxClientSession {
    send_request: h2::client::SendRequest<Bytes>,
    _driver_handle: Arc<DriverHandle>,
    padding_enabled: bool,
    active_streams: Arc<AtomicU32>,
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

struct DriverHandle {
    _drain: oneshot::Sender<()>,
    ping: Option<tokio::task::AbortHandle>,
}

impl Drop for DriverHandle {
    fn drop(&mut self) {
        if let Some(ping) = &self.ping {
            ping.abort();
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
    /// 4. Spawn connection driver and PING keepalive tasks
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
            .map_err(|e| io::Error::other(format!("H2 client handshake failed: {}", e)))?;

        // Take ping_pong handle before spawning - can only be called once
        let ping_pong = connection.ping_pong();

        let is_closed = Arc::new(AtomicBool::new(false));
        let driver_closed = Arc::clone(&is_closed);
        let (drain_tx, drain_rx) = oneshot::channel();

        // Spawn connection driver
        let abort_handle = tokio::spawn(async move {
            // Dropping the last owner must still flush queued DATA and END_STREAM.
            let result = tokio::select! {
                result = &mut connection => Some(result),
                _ = drain_rx => tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, connection).await.ok(),
            };
            if let Some(Err(e)) = result {
                debug!("H2MUX client connection ended: {}", e);
            }
            driver_closed.store(true, Ordering::Relaxed);
        })
        .abort_handle();

        // Spawn PING keepalive task to detect dead connections
        // (matches Go's http2.Transport.ReadIdleTimeout behavior)
        let ping = ping_pong
            .map(|pp| Self::spawn_ping_task(pp, Arc::clone(&is_closed), abort_handle.clone()));

        debug!("H2MuxClientSession: ready for multiplexing");

        Ok(Self {
            send_request,
            _driver_handle: Arc::new(DriverHandle {
                _drain: drain_tx,
                ping,
            }),
            padding_enabled,
            active_streams: Arc::new(AtomicU32::new(0)),
            is_closed,
        })
    }

    /// Spawn PING keepalive task to detect dead connections.
    ///
    /// Sends periodic PINGs to verify the server is still responsive.
    /// Matches Go's http2.Transport.ReadIdleTimeout behavior.
    fn spawn_ping_task(
        mut ping_pong: PingPong,
        is_closed: Arc<AtomicBool>,
        driver: tokio::task::AbortHandle,
    ) -> tokio::task::AbortHandle {
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
            driver.abort();
        })
        .abort_handle()
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

    pub(super) fn release_stream(&self) {
        self.active_streams.fetch_sub(1, Ordering::Relaxed);
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
        if !self.is_ready() {
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
            .map_err(|e| io::Error::other(format!("Failed to send CONNECT: {}", e)))?;

        // Create unified client stream with lazy response resolution
        let client_stream = H2MuxClientStream::new(
            send_stream,
            response_future,
            destination.clone(),
            is_tcp,
            self.clone(),
        )?;

        self.active_streams.fetch_add(1, Ordering::Relaxed);

        debug!("H2MuxClientSession: opened stream to {}", destination);

        Ok(Box::new(client_stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn streams_own_driver_until_last_stream_is_dropped() {
        for _ in 0..16 {
            let (client, peer) = tokio::io::duplex(65536);
            let peer = tokio::spawn(async move {
                let mut session = super::super::H2MuxServerSession::new(peer).await.unwrap();
                let mut inbound = session.accept().await.unwrap();
                let mut bytes = [0; 3];
                inbound.stream.read_exact(&mut bytes).await.unwrap();
                inbound.stream.write_all(&bytes).await.unwrap();
                inbound.stream.flush().await.unwrap();
                while session.accept().await.is_some() {}
            });
            let mut session = H2MuxClientSession::new(client, &H2MuxOptions::default())
                .await
                .unwrap();
            let owner = Arc::downgrade(&session._driver_handle);
            let closed = Arc::clone(&session.is_closed);
            let destination = NetLocation::from_str("example.com:443", None).unwrap();
            let mut stream = session.open_tcp(&destination).await.unwrap();
            assert_eq!(session.active_streams(), 1);
            drop(session);
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                stream.write_all(b"abc").await.unwrap();
                stream.flush().await.unwrap();
                let mut bytes = [0; 3];
                stream.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"abc");
            })
            .await
            .unwrap();
            drop(stream);
            assert!(owner.upgrade().is_none());
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                while !closed.load(Ordering::Relaxed) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            peer.abort();
            let _ = peer.await;
        }
    }

    #[tokio::test]
    async fn last_stream_drop_drains_tail_after_peer_half_close() {
        let (client, mut peer) = tokio::io::duplex(65536);
        let peer = tokio::spawn(async move {
            SessionRequest::decode(&mut peer).await.unwrap();
            let mut connection = h2::server::handshake(peer).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let mut receive = request.into_body();
            let read = async {
                let warmup = receive.data().await.unwrap().unwrap();
                assert!(warmup.ends_with(b"warmup"));
                receive
                    .flow_control()
                    .release_capacity(warmup.len())
                    .unwrap();
                send.send_data(Bytes::from_static(&[0]), true).unwrap();

                let mut tail = Vec::new();
                while let Some(data) = receive.data().await {
                    let data = data.unwrap();
                    receive.flow_control().release_capacity(data.len()).unwrap();
                    tail.extend_from_slice(&data);
                }
                tail
            };
            tokio::pin!(read);
            tokio::select! {
                tail = &mut read => tail,
                accepted = connection.accept() => {
                    assert!(!matches!(accepted, Some(Ok(_))));
                    read.await
                }
            }
        });
        let options = H2MuxOptions {
            padding: false,
            ..Default::default()
        };
        let mut session = H2MuxClientSession::new(client, &options).await.unwrap();
        let destination = NetLocation::from_str("example.com:443", None).unwrap();
        let mut stream = session.open_tcp(&destination).await.unwrap();
        drop(session);
        stream.write_all(b"warmup").await.unwrap();
        stream.read_to_end(&mut Vec::new()).await.unwrap();
        stream.write_all(b"FINAL-TAIL").await.unwrap();
        stream.flush().await.unwrap();
        stream.shutdown().await.unwrap();
        drop(stream);
        let tail = tokio::time::timeout(std::time::Duration::from_secs(1), peer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tail, b"FINAL-TAIL");
    }

    #[tokio::test(start_paused = true)]
    async fn last_owner_drain_is_bounded_when_peer_stalls() {
        let (client, _peer) = tokio::io::duplex(64);
        let mut session = H2MuxClientSession::new(client, &H2MuxOptions::default())
            .await
            .unwrap();
        let closed = Arc::clone(&session.is_closed);
        let destination = NetLocation::from_str("example.com:443", None).unwrap();
        let stream = session.open_tcp(&destination).await.unwrap();
        drop(session);
        drop(stream);
        tokio::task::yield_now().await;
        assert!(!closed.load(Ordering::Relaxed));
        tokio::time::sleep(SHUTDOWN_DRAIN_TIMEOUT + std::time::Duration::from_millis(1)).await;
        assert!(closed.load(Ordering::Relaxed));
    }

    #[test]
    fn test_session_clone() {
        fn assert_clone<T: Clone>() {}
        assert_clone::<H2MuxClientSession>();
    }
}
