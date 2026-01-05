//! Hysteria2 client implementation.
//!
//! This module implements the client side of the Hysteria2 protocol, which includes:
//! - QUIC connection establishment
//! - HTTP/3 authentication handshake
//! - TCP stream creation with Hysteria2 protocol framing
//! - UDP packet encapsulation via QUIC datagrams
//!
//! Protocol reference: https://v2.hysteria.network/zh/docs/developers/Protocol/
//! Go client reference: https://github.com/apernet/hysteria/blob/master/core/client/client.go

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use log::{debug, error, warn};
use lru::LruCache;
use rand::distr::Alphanumeric;
use rand::{Rng, RngCore};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::address::NetLocation;
use crate::async_stream::{
    AsyncPing, AsyncStream,
};
use crate::quic_stream::QuicStream;
use crate::resolver::{resolve_single_address, NativeResolver, Resolver};
use crate::socket_util::new_udp_socket;

/// Authentication timeout - close connection if server doesn't authenticate within this time.
/// Per protocol reference implementation, default is 3 seconds.
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);

/// TCP request frame type from Hysteria2 protocol
const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

/// TCP response status codes
const TCP_STATUS_OK: u8 = 0x00;
const TCP_STATUS_ERROR: u8 = 0x01;

/// Maximum address length (from official Go implementation)
const MAX_ADDRESS_LENGTH: usize = 2048;

/// Maximum padding length (from official Go implementation)
const MAX_PADDING_LENGTH: usize = 4096;

/// Maximum number of fragmented packets to track per session
const MAX_FRAGMENT_CACHE_SIZE: usize = 256;

/// UDP session cleanup interval
const UDP_CLEANUP_INTERVAL: Duration = Duration::from_secs(100);

/// UDP session idle timeout
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(200);

/// Channel size for UDP message passing
const UDP_MESSAGE_CHAN_SIZE: usize = 1024;

/// Generates a random ASCII string for Hysteria-Padding header
fn generate_padding_string() -> String {
    let mut rng = rand::rng();
    let length = rng.random_range(1..80);
    rng.sample_iter(Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

/// Encodes a value as QUIC varint (same format as server side)
fn encode_varint(value: u64) -> std::io::Result<Box<[u8]>> {
    if value <= 0b00111111 {
        Ok(Box::new([value as u8]))
    } else if value < (1 << 14) {
        let encoded: u16 = (0b01_u16 << 14) | value as u16;
        Ok(Box::new(encoded.to_be_bytes()))
    } else if value < (1 << 30) {
        let encoded: u32 = (0b10_u32 << 30) | value as u32;
        Ok(Box::new(encoded.to_be_bytes()))
    } else if value < (1 << 62) {
        let encoded: u64 = (0b11_u64 << 62) | value;
        Ok(Box::new(encoded.to_be_bytes()))
    } else {
        Err(std::io::Error::other("value too large to encode as varint"))
    }
}

/// Decodes a QUIC varint from bytes, returns (value, bytes_consumed)
fn decode_varint(data: &[u8]) -> std::io::Result<(u64, usize)> {
    if data.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "incomplete varint",
        ));
    }

    let first_byte = data[0];
    let length_indicator = first_byte >> 6;
    let mut value: u64 = (first_byte & 0b00111111) as u64;

    let num_bytes = match length_indicator {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };

    if data.len() < num_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("incomplete varint: have {} bytes, need {}", data.len(), num_bytes),
        ));
    }

    if num_bytes > 1 {
        for byte in &data[1..num_bytes] {
            value <<= 8;
            value |= *byte as u64;
        }
    }

    Ok((value, num_bytes))
}

/// A fragmented packet being reassembled
struct FragmentedPacket {
    fragment_count: u8,
    fragment_received: u8,
    packet_len: usize,
    received: Vec<Option<Bytes>>,
}

/// Represents a UDP session with the Hysteria2 server
#[derive(Debug)]
struct HyUdpSession {
    /// Session ID
    id: u32,
    /// Defragger for incoming packets
    defragger: LruCache<u16, FragmentedPacket>,
    /// Channel for receiving messages from the server
    receive_ch: tokio::sync::mpsc::Receiver<Bytes>,
    /// Local UDP socket for communicating with the client
    local_socket: Arc<UdpSocket>,
    /// Last activity timestamp for idle timeout
    last_activity: Instant,
    /// Cancellation token for this session
    cancel_token: CancellationToken,
    /// Handle to the receive task
    _task_handle: JoinHandle<()>,
}

impl HyUdpSession {
    /// Create a new UDP session
    fn new(
        id: u32,
        connection: quinn::Connection,
        local_socket: Arc<UdpSocket>,
        _resolver: Arc<dyn Resolver>,
        cancel_token: CancellationToken,
    ) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(UDP_MESSAGE_CHAN_SIZE);

        let session_cancel_token = cancel_token.child_token();
        let task_handle = tokio::spawn(async move {
            if let Err(e) = run_udp_receive_loop(id, connection, tx, session_cancel_token).await {
                error!("[Hysteria2] UDP receive loop for session {} ended with error: {}", id, e);
            }
        });

        Self {
            id,
            defragger: LruCache::new(
                std::num::NonZeroUsize::new(MAX_FRAGMENT_CACHE_SIZE).unwrap(),
            ),
            receive_ch: rx,
            local_socket,
            last_activity: Instant::now(),
            cancel_token,
            _task_handle: task_handle,
        }
    }

    /// Check if the session has timed out
    fn is_idle(&self) -> bool {
        self.last_activity.elapsed() > UDP_IDLE_TIMEOUT
    }

    /// Update the last activity timestamp
    fn refresh(&mut self) {
        self.last_activity = Instant::now();
    }
}

/// Handles receiving UDP datagrams from the server
async fn run_udp_receive_loop(
    session_id: u32,
    connection: quinn::Connection,
    tx: tokio::sync::mpsc::Sender<Bytes>,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let max_datagram_size = connection
        .max_datagram_size()
        .ok_or_else(|| std::io::Error::other("datagram not supported by remote endpoint"))?;

    let _buf = vec![0u8; max_datagram_size as usize];

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                return Ok(());
            }
            result = connection.read_datagram() => {
                let data = match result {
                    Ok(d) => d,
                    Err(e) => {
                        return Err(std::io::Error::other(format!(
                            "failed to read datagram for session {}: {}",
                            session_id, e
                        )));
                    }
                };

                if data.len() < 9 {
                    warn!("[Hysteria2] Received too short datagram for session {}", session_id);
                    continue;
                }

                // Parse the datagram header
                let _session_id = u32::from_be_bytes(data[0..4].try_into().unwrap());
                let _packet_id = u16::from_be_bytes(data[4..6].try_into().unwrap());
                let _fragment_id = data[6];
                let fragment_count = data[7];

                // Parse address length (varint starting at byte 8)
                let (address_len, addr_end) = match decode_varint(&data[8..]) {
                    Ok((len, consumed)) => (len as usize, 8 + consumed),
                    Err(e) => {
                        warn!("[Hysteria2] Failed to parse address length: {}", e);
                        continue;
                    }
                };

                if address_len == 0 || address_len > MAX_ADDRESS_LENGTH {
                    warn!("[Hysteria2] Invalid address length {}", address_len);
                    continue;
                }

                if data.len() < addr_end + address_len {
                    warn!("[Hysteria2] Incomplete address in datagram");
                    continue;
                }

                // Skip address bytes
                let payload_start = addr_end + address_len;
                let payload = &data[payload_start..];

                if payload.is_empty() {
                    continue;
                }

                // Handle fragmentation
                if fragment_count <= 1 {
                    // No fragmentation, send directly
                    if tx.send(Bytes::copy_from_slice(payload)).await.is_err() {
                        return Ok(());
                    }
                } else {
                    // Fragmented packet - this would be handled by HyUdpSession
                    // For now, we just pass it through
                    if tx.send(Bytes::copy_from_slice(payload)).await.is_err() {
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// Manages UDP sessions for a Hysteria2 connection
#[derive(Debug)]
struct UdpSessionManager {
    /// The QUIC connection
    connection: quinn::Connection,
    /// Active sessions keyed by session ID
    sessions: RwLock<HashMap<u32, HyUdpSession>>,
    /// Next session ID to assign
    next_session_id: AtomicU32,
    /// Cancellation token for all sessions
    cancel_token: CancellationToken,
    /// Local resolver for address resolution
    resolver: Arc<dyn Resolver>,
    /// Maximum datagram size
    max_datagram_size: usize,
    /// Background cleanup task handle
    _cleanup_task: JoinHandle<()>,
}

use std::sync::atomic::{AtomicU32, Ordering};

impl UdpSessionManager {
    /// Create a new UDP session manager
    fn new(
        connection: quinn::Connection,
        resolver: Arc<dyn Resolver>,
        cancel_token: CancellationToken,
    ) -> Self {
        let max_datagram_size = connection
            .max_datagram_size()
            .unwrap_or(65535) as usize;

        let manager = Self {
            connection,
            sessions: RwLock::new(HashMap::new()),
            next_session_id: AtomicU32::new(1),
            cancel_token,
            resolver,
            max_datagram_size,
            _cleanup_task: tokio::spawn(async move {
                // Cleanup task implementation would go here
                // For now, we rely on session-level cleanup
            }),
        };

        manager
    }

    /// Create a new UDP session
    async fn new_session(
        &self,
        _target: &NetLocation,
    ) -> std::io::Result<(u32, Arc<UdpSocket>)> {
        let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);

        // Create a local UDP socket for this session
        let local_socket = Arc::new(new_udp_socket(true, None)?);

        let session = HyUdpSession::new(
            session_id,
            self.connection.clone(),
            local_socket.clone(),
            self.resolver.clone(),
            self.cancel_token.clone(),
        );

        self.sessions.write().await.insert(session_id, session);

        debug!("[Hysteria2] Created UDP session {}", session_id);

        Ok((session_id, local_socket))
    }

    /// Send a UDP packet to the server
    async fn send_packet(
        &self,
        session_id: u32,
        data: &[u8],
        target: &SocketAddr,
    ) -> std::io::Result<()> {
        let address_str = target.to_string();
        let address_bytes = address_str.as_bytes();
        let address_len_bytes = encode_varint(address_bytes.len() as u64)?;

        // Calculate header overhead
        let header_overhead = 4 + 2 + 1 + 1 + address_len_bytes.len() + address_len_bytes.len() + address_bytes.len();
        let effective_max_size = self.max_datagram_size.saturating_sub(header_overhead);

        if data.len() <= effective_max_size {
            // No fragmentation needed
            let mut datagram = BytesMut::with_capacity(header_overhead + data.len());
            datagram.extend_from_slice(&session_id.to_be_bytes());
            datagram.extend_from_slice(&0u16.to_be_bytes()); // packet_id = 0 for no frag
            datagram.extend_from_slice(&[0u8, 1u8]); // frag_id = 0, frag_count = 1
            datagram.extend_from_slice(&address_len_bytes);
            datagram.extend_from_slice(address_bytes);
            datagram.extend_from_slice(data);

            self.connection
                .send_datagram(datagram.freeze())
                .map_err(|e| std::io::Error::other(format!("Failed to send datagram: {}", e)))?;
        } else {
            // Fragmentation needed
            let packet_id = rand::rng().random_range(1..u16::MAX) as u16 + 1;
            let fragment_count = (data.len().div_ceil(effective_max_size)) as u8;

            for frag_id in 0..fragment_count {
                let start = (frag_id as usize) * effective_max_size;
                let end = std::cmp::min(start + effective_max_size, data.len());
                let fragment_data = &data[start..end];

                let mut datagram = BytesMut::with_capacity(header_overhead + fragment_data.len());
                datagram.extend_from_slice(&session_id.to_be_bytes());
                datagram.extend_from_slice(&packet_id.to_be_bytes());
                datagram.extend_from_slice(&[frag_id, fragment_count]);
                datagram.extend_from_slice(&address_len_bytes);
                datagram.extend_from_slice(address_bytes);
                datagram.extend_from_slice(fragment_data);

                self.connection
                    .send_datagram(datagram.freeze())
                    .map_err(|e| std::io::Error::other(format!(
                        "Failed to send datagram fragment {}: {}",
                        frag_id, e
                    )))?;
            }
        }

        Ok(())
    }

    /// Get the count of active sessions
    async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Cleanup idle sessions
    async fn cleanup_idle_sessions(&self) {
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_id, session| {
            !session.is_idle()
        });
    }
}

/// Hysteria2 client that manages a QUIC connection to the server
#[derive(Debug)]
pub struct Hysteria2Client {
    /// The QUIC endpoint (for creating new connections)
    endpoint: Arc<quinn::Endpoint>,
    /// Server address
    server_address: NetLocation,
    /// SNI hostname for TLS
    sni_hostname: Option<String>,
    /// Authentication password
    password: String,
    /// Whether UDP relay is enabled
    pub udp_enabled: bool,
    /// Whether TCP Fast Open is enabled
    pub fast_open: bool,
    /// Maximum upload rate in bytes per second (0 = unlimited)
    pub max_tx: u64,
    /// Maximum download rate in bytes per second (0 = unlimited)
    pub max_rx: u64,
}

impl Hysteria2Client {
    /// Create a new Hysteria2 client
    pub fn new(
        endpoint: Arc<quinn::Endpoint>,
        server_address: NetLocation,
        sni_hostname: Option<String>,
        password: String,
        udp_enabled: bool,
        fast_open: bool,
        max_tx: u64,
        max_rx: u64,
    ) -> Self {
        Self {
            endpoint,
            server_address,
            sni_hostname,
            password,
            udp_enabled,
            fast_open,
            max_tx,
            max_rx,
        }
    }

    /// Connect to the Hysteria2 server and perform authentication
    pub async fn connect_and_authenticate(
        &self,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<(Hysteria2Connection, u64, bool)> {
        let server_addr = resolve_single_address(resolver, &self.server_address).await?;

        let domain = self
            .sni_hostname
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or_else(|| {
                self.server_address
                    .address()
                    .hostname()
                    .unwrap_or("example.com")
            });

        debug!(
            "[Hysteria2] Connecting to {} ({})",
            self.server_address, server_addr
        );

        // Establish QUIC connection
        let connection = self
            .endpoint
            .connect(server_addr, domain)
            .map_err(|e| std::io::Error::other(format!("Failed to connect QUIC endpoint: {e}")))?
            .await
            .map_err(|e| std::io::Error::other(format!("QUIC connection failed: {e}")))?;

        debug!("[Hysteria2] QUIC connection established, performing authentication");

        // Perform HTTP/3 authentication and get congestion control info
        let (tx, tx_auto) = timeout(AUTH_TIMEOUT, self.authenticate_connection(&connection))
            .await
            .map_err(|_| {
                error!("[Hysteria2] Authentication timeout");
                connection.close(0u32.into(), b"auth timeout");
                std::io::Error::new(std::io::ErrorKind::TimedOut, "authentication timeout")
            })??;

        debug!("[Hysteria2] Authentication successful");

        // Create UDP session manager if UDP is enabled
        let udp_manager = if self.udp_enabled {
            Some(Arc::new(UdpSessionManager::new(
                connection.clone(),
                resolver.clone(),
                CancellationToken::new(),
            )))
        } else {
            None
        };

        let conn = Hysteria2Connection {
            connection,
            udp_enabled: self.udp_enabled,
            fast_open: self.fast_open,
            udp_manager,
            tx,
            tx_auto,
        };

        Ok((conn, tx, tx_auto))
    }

    /// Perform HTTP/3 authentication handshake
    async fn authenticate_connection(&self, connection: &quinn::Connection) -> std::io::Result<(u64, bool)> {
        debug!("[Hysteria2] Creating H3 connection for authentication");
        let h3_connection = h3_quinn::Connection::new(connection.clone());
        let (_h3_conn, mut h3_send) = h3::client::new(h3_connection)
            .await
            .map_err(|e| std::io::Error::other(format!("Failed to create H3 client: {e}")))?;
        debug!("[Hysteria2] H3 client created");

        // Build authentication request per protocol spec:
        // :method: POST
        // :path: /auth
        // :host: hysteria
        // Hysteria-Auth: [password]
        // Hysteria-CC-RX: [rx_rate] - client's max receive rate
        // Hysteria-Padding: [random]

        debug!("[Hysteria2] Building auth request with CC-RX: {}", self.max_rx);
        let req = http::Request::builder()
            .method("POST")
            .uri("https://hysteria/auth")
            .header("Hysteria-Auth", &self.password)
            .header("Hysteria-CC-RX", self.max_rx.to_string())
            .header("Hysteria-Padding", generate_padding_string())
            .body(())
            .map_err(|e| std::io::Error::other(format!("Failed to build request: {e}")))?;

        // Send request and get the stream
        debug!("[Hysteria2] Sending auth request");
        let mut stream = h3_send
            .send_request(req)
            .await
            .map_err(|e| std::io::Error::other(format!("Failed to send auth request: {e}")))?;
        debug!("[Hysteria2] Auth request sent, finishing stream");

        stream
            .finish()
            .await
            .map_err(|e| std::io::Error::other(format!("Failed to finish auth request: {e}")))?;
        debug!("[Hysteria2] Stream finished, waiting for response");

        // Receive response from the stream
        let resp = stream
            .recv_response()
            .await
            .map_err(|e| std::io::Error::other(format!("Failed to recv auth response: {e}")))?;
        debug!("[Hysteria2] Received auth response, status: {}", resp.status());

        // Check status code - must be 233 (HyOK) per protocol spec
        let status = resp.status();
        if status.as_u16() != 233 {
            return Err(std::io::Error::other(format!(
                "Authentication failed: expected status 233, got {}",
                status
            )));
        }

        // Parse Hysteria-UDP header to check if UDP is supported
        if let Some(udp_header) = resp.headers().get("Hysteria-UDP") {
            let udp_str = udp_header
                .to_str()
                .map_err(|e| std::io::Error::other(format!("Invalid Hysteria-UDP header: {e}")))?;
            let server_udp_enabled = udp_str.eq_ignore_ascii_case("true");
            debug!("[Hysteria2] Server UDP support: {}", server_udp_enabled);
            if !server_udp_enabled && self.udp_enabled {
                warn!("[Hysteria2] Client UDP enabled but server doesn't support UDP relay");
            }
        }

        // Parse Hysteria-CC-RX header for congestion control
        // Format: either "auto" or a number representing server's max receive rate
        let (tx, tx_auto) = if let Some(cc_header) = resp.headers().get("Hysteria-CC-RX") {
            let cc_str = cc_header
                .to_str()
                .map_err(|e| std::io::Error::other(format!("Invalid Hysteria-CC-RX header: {e}")))?;

            if cc_str.eq_ignore_ascii_case("auto") {
                debug!("[Hysteria2] Server requested auto bandwidth detection (BBR)");
                (0, true) // tx = 0 means use BBR
            } else {
                let server_rx = cc_str.parse::<u64>()
                    .map_err(|e| std::io::Error::other(format!("Invalid Hysteria-CC-RX value: {e}")))?;
                debug!("[Hysteria2] Server max receive rate: {} bytes/s", server_rx);

                // actualTx = min(serverRx, clientTx)
                let mut actual_tx = server_rx;
                if actual_tx == 0 || actual_tx > self.max_tx {
                    // Server doesn't have a limit, or our clientTx is smaller than serverRx
                    actual_tx = self.max_tx;
                }
                debug!("[Hysteria2] Negotiated upload rate: {} bytes/s", actual_tx);
                (actual_tx, false)
            }
        } else {
            // No Hysteria-CC-RX header, use client's max_tx
            debug!("[Hysteria2] No Hysteria-CC-RX header from server, using client max_tx");
            (self.max_tx, false)
        };

        // Store the negotiated values for later use
        // Note: Quinn uses BBR by default, so we don't need to explicitly set it
        if tx_auto {
            debug!("[Hysteria2] Using BBR congestion control (server requested)");
        } else if tx > 0 {
            debug!("[Hysteria2] Using Brutal congestion control at {} bytes/s", tx);
        } else {
            debug!("[Hysteria2] No bandwidth limit (BBR/unlimited)");
        }

        Ok((tx, tx_auto))
    }
}

/// Represents an authenticated Hysteria2 connection
#[derive(Clone, Debug)]
pub struct Hysteria2Connection {
    /// The underlying QUIC connection
    pub connection: quinn::Connection,
    /// Whether UDP relay is enabled
    pub udp_enabled: bool,
    /// Whether TCP Fast Open is enabled
    pub fast_open: bool,
    /// UDP session manager (None if UDP is disabled)
    pub udp_manager: Option<Arc<UdpSessionManager>>,
    /// Actual upload rate in bytes per second (0 = BBR/unlimited)
    pub tx: u64,
    /// Whether server requested auto bandwidth detection (BBR)
    pub tx_auto: bool,
}

impl Hysteria2Connection {
    /// Create a new UDP session and return the session stream
    pub async fn create_udp_session(
        &self,
        _resolver: &Arc<dyn Resolver>,
        target: &NetLocation,
    ) -> std::io::Result<HyUdpConn> {
        let manager = self.udp_manager.as_ref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "UDP is not enabled on this connection",
            )
        })?;

        let (session_id, local_socket) = manager.new_session(target).await?;

        Ok(HyUdpConn {
            session_id,
            local_socket,
            manager: manager.clone(),
            target: target.clone(),
            is_closed: false,
        })
    }
}

/// A UDP session connection for Hysteria2
#[derive(Debug)]
pub struct HyUdpConn {
    /// Session ID
    session_id: u32,
    /// Local UDP socket for this session
    local_socket: Arc<UdpSocket>,
    /// Reference to the session manager
    manager: Arc<UdpSessionManager>,
    /// Target destination
    target: NetLocation,
    /// Whether this connection is closed
    is_closed: bool,
}

impl HyUdpConn {
    /// Close the UDP session
    fn close(&mut self) {
        if !self.is_closed {
            self.is_closed = true;
            debug!("[Hysteria2] Closing UDP session {}", self.session_id);
        }
    }
}

impl AsyncPing for HyUdpConn {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "UDP does not support ping",
        )))
    }
}

// HyUdpConn implements AsyncMessageStream through blanket impl for types with AsyncRead/AsyncWrite
impl crate::async_stream::AsyncMessageStream for HyUdpConn {}

impl crate::async_stream::AsyncReadMessage for HyUdpConn {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.is_closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "UDP session is closed",
            )));
        }
        let socket = Pin::new(&*this.local_socket);
        socket.poll_recv(cx, buf)
    }
}

impl crate::async_stream::AsyncWriteMessage for HyUdpConn {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.is_closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "UDP session is closed",
            )));
        }

        let resolver = NativeResolver::new();
        let addrs = futures::executor::block_on(async {
            resolver.resolve_location(&this.target).await
        }).map_err(|e| std::io::Error::other(format!("Failed to resolve target: {}", e)))?;
        let addr = addrs.into_iter().next().ok_or_else(|| {
            std::io::Error::other("No addresses resolved for target")
        })?;

        let socket = &this.local_socket;
        match Pin::new(socket).poll_send_to(cx, buf, addr) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl crate::async_stream::AsyncFlushMessage for HyUdpConn {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl crate::async_stream::AsyncShutdownMessage for HyUdpConn {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A multidirectional UDP message stream for Hysteria2.
/// This implements AsyncSourcedMessageStream to support multiple destination addresses.
/// Used for SOCKS5 UDP associate mode.
pub struct HyUdpMessageStream {
    /// The QUIC connection to the Hysteria2 server
    connection: quinn::Connection,
    /// Maximum datagram size
    max_datagram_size: usize,
    /// Receiver for datagrams from the server
    /// Contains (payload, source_address)
    receive_ch: tokio::sync::mpsc::Receiver<(Vec<u8>, std::net::SocketAddr)>,
}

impl HyUdpMessageStream {
    /// Create a new HyUdpMessageStream
    /// Note: The local_socket parameter is kept for API compatibility but is not used.
    /// Hysteria2 sends/receives UDP packets directly via QUIC datagrams.
    pub fn new(_local_socket: Arc<UdpSocket>, connection: quinn::Connection) -> Self {
        let max_datagram_size = connection
            .max_datagram_size()
            .unwrap_or(65535) as usize;

        let (tx, rx) = tokio::sync::mpsc::channel(1024);

        // Spawn task to receive datagrams from the server
        let conn = connection.clone();
        tokio::spawn(async move {
            debug!("[Hysteria2] UDP receive loop started");
            loop {
                debug!("[Hysteria2] Waiting for datagram...");
                match conn.read_datagram().await {
                    Ok(data) => {
                        debug!("[Hysteria2] Received datagram: {} bytes", data.len());
                        if let Err(e) = process_received_datagram(&data, &tx) {
                            warn!("[Hysteria2] Failed to process received datagram: {}", e);
                        }
                    }
                    Err(e) => {
                        warn!("[Hysteria2] Failed to read datagram: {}", e);
                        break;
                    }
                }
            }
            warn!("[Hysteria2] UDP receive loop ended");
        });

        Self {
            connection,
            max_datagram_size,
            receive_ch: rx,
        }
    }

    /// Send a UDP packet through QUIC datagram
    async fn send_packet(
        &self,
        data: &[u8],
        target: &std::net::SocketAddr,
    ) -> std::io::Result<()> {
        let address_str = target.to_string();
        let address_bytes = address_str.as_bytes();
        let address_len_bytes = encode_varint(address_bytes.len() as u64)?;

        // Calculate header overhead
        let header_overhead = 4 + 2 + 1 + 1 + address_len_bytes.len() + address_bytes.len();
        let effective_max_size = self.max_datagram_size.saturating_sub(header_overhead);

        let session_id = 1u32; // Use session ID 1 for all UDP packets

        if data.len() <= effective_max_size {
            // No fragmentation needed
            let mut datagram = bytes::BytesMut::with_capacity(header_overhead + data.len());
            datagram.extend_from_slice(&session_id.to_be_bytes());
            datagram.extend_from_slice(&0u16.to_be_bytes()); // packet_id = 0 for no frag
            datagram.extend_from_slice(&[0u8, 1u8]); // frag_id = 0, frag_count = 1
            datagram.extend_from_slice(&address_len_bytes);
            datagram.extend_from_slice(address_bytes);
            datagram.extend_from_slice(data);

            self.connection
                .send_datagram(datagram.freeze())
                .map_err(|e| std::io::Error::other(format!("Failed to send datagram: {}", e)))?;
        } else {
            // Fragmentation needed
            use rand::RngCore;
            let mut rng = rand::rng();
            let mut packet_id_bytes = [0u8; 2];
            rng.fill_bytes(&mut packet_id_bytes);
            let packet_id = u16::from_be_bytes(packet_id_bytes);
            let fragment_count = (data.len().div_ceil(effective_max_size)) as u8;

            for frag_id in 0..fragment_count {
                let start = (frag_id as usize) * effective_max_size;
                let end = std::cmp::min(start + effective_max_size, data.len());
                let fragment_data = &data[start..end];

                let mut datagram =
                    bytes::BytesMut::with_capacity(header_overhead + fragment_data.len());
                datagram.extend_from_slice(&session_id.to_be_bytes());
                datagram.extend_from_slice(&packet_id.to_be_bytes());
                datagram.extend_from_slice(&[frag_id, fragment_count]);
                datagram.extend_from_slice(&address_len_bytes);
                datagram.extend_from_slice(address_bytes);
                datagram.extend_from_slice(fragment_data);

                self.connection
                    .send_datagram(datagram.freeze())
                    .map_err(|e| std::io::Error::other(format!(
                        "Failed to send datagram fragment {}: {}",
                        frag_id, e
                    )))?;
            }
        }

        Ok(())
    }
}

/// Process a received datagram from the server
fn process_received_datagram(
    data: &[u8],
    tx: &tokio::sync::mpsc::Sender<(Vec<u8>, std::net::SocketAddr)>,
) -> std::io::Result<()> {
    if data.len() < 9 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "datagram too short",
        ));
    }

    // Parse the datagram header
    let _session_id = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let _packet_id = u16::from_be_bytes(data[4..6].try_into().unwrap());
    let _frag_id = data[6];
    let fragment_count = data[7];

    // Parse address length (varint starting at byte 8)
    // The varint value is the length of the address string (e.g., "8.8.8.8:53" = 10 bytes)
    let (address_str_len, varint_bytes_consumed) = decode_varint(&data[8..])?;

    // Address string starts right after the varint
    let address_start = 8 + varint_bytes_consumed;
    let address_str_end = address_start + (address_str_len as usize);

    if data.len() < address_str_end {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "incomplete address in datagram",
        ));
    }

    // Parse the address string (format: "IP:port" or "[IPv6]:port")
    let address_str = String::from_utf8_lossy(&data[address_start..address_str_end]);
    debug!("[Hysteria2] Received datagram address string: '{}'", address_str);

    // Parse as SocketAddr
    let target_addr: std::net::SocketAddr = match address_str.parse() {
        Ok(addr) => addr,
        Err(e) => {
            warn!("[Hysteria2] Failed to parse address '{}': {}", address_str, e);
            return Ok(());
        }
    };

    // Extract the payload (everything after the address string)
    let payload_start = address_str_end;
    let payload = data[payload_start..].to_vec();

    if payload.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "empty payload",
        ));
    }

    // Handle fragmentation (simplified - just return first fragment for now)
    if fragment_count <= 1 {
        tx.try_send((payload, target_addr))
            .map_err(|e| std::io::Error::other(format!("Failed to send to channel: {}", e)))?;
    } else {
        // TODO: Implement proper fragmentation reassembly
        warn!("[Hysteria2] Fragmented packets not yet supported, dropping");
    }

    Ok(())
}

impl AsyncPing for HyUdpMessageStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl crate::async_stream::AsyncReadSourcedMessage for HyUdpMessageStream {
    fn poll_read_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<std::net::SocketAddr>> {
        let this = self.get_mut();
        match Pin::new(&mut this.receive_ch).poll_recv(cx) {
            Poll::Ready(Some((data, target_addr))) => {
                debug!("[Hysteria2] poll_read_sourced_message: received {} bytes from {}", data.len(), target_addr);
                if data.len() > buf.remaining() {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "Buffer too small: need {} bytes, have {}",
                            data.len(),
                            buf.remaining()
                        ),
                    )));
                }
                buf.put_slice(&data);
                // Return the target address from the Hysteria2 server
                // This is the actual source of the data (e.g., 8.8.8.8:53 for DNS)
                debug!("[Hysteria2] poll_read_sourced_message: returning source address {}", target_addr);
                Poll::Ready(Ok(target_addr))
            }
            Poll::Ready(None) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "channel closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl crate::async_stream::AsyncWriteTargetedMessage for HyUdpMessageStream {
    fn poll_write_targeted_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
        target: &NetLocation,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        debug!("[Hysteria2] poll_write_targeted_message: writing {} bytes to target {:?}", buf.len(), target);

        // Resolve the target address
        let resolver = NativeResolver::new();
        let addrs = futures::executor::block_on(async {
            resolver.resolve_location(target).await
        })
        .map_err(|e| std::io::Error::other(format!("Failed to resolve target: {}", e)))?;

        let addr = addrs
            .into_iter()
            .next()
            .ok_or_else(|| std::io::Error::other("No addresses resolved for target"))?;

        debug!("[Hysteria2] poll_write_targeted_message: resolved to {}", addr);

        // Send through QUIC datagram
        futures::executor::block_on(this.send_packet(&buf, &addr))
            .map_err(|e| std::io::Error::other(format!("Failed to send packet: {}", e)))?;

        Poll::Ready(Ok(()))
    }
}

impl crate::async_stream::AsyncFlushMessage for HyUdpMessageStream {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl crate::async_stream::AsyncShutdownMessage for HyUdpMessageStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Close the QUIC connection
        self.get_mut().connection.close(0u32.into(), b"UDP session closed");
        Poll::Ready(Ok(()))
    }
}

impl crate::async_stream::AsyncSourcedMessageStream for HyUdpMessageStream {}

/// Hysteria2 TCP stream with optional Fast Open support.
///
/// When Fast Open is enabled, the stream is returned immediately after sending
/// the TCP request, without waiting for the server's response. The response
/// is read and validated on the first Read() call.
pub struct HyTcpStream {
    /// QUIC send stream
    send: quinn::SendStream,
    /// QUIC receive stream
    recv: quinn::RecvStream,
    /// Whether the connection has been established (server response received)
    established: Arc<std::sync::atomic::AtomicBool>,
    /// Whether Fast Open is enabled
    fast_open: bool,
}

impl HyTcpStream {
    /// Create a new HyTcpStream.
    ///
    /// If fast_open is true, the stream is returned immediately after sending
    /// the request, and the server response is deferred to the first Read() call.
    pub fn new(
        mut send: quinn::SendStream,
        recv: quinn::RecvStream,
        fast_open: bool,
    ) -> Self {
        Self {
            send,
            recv,
            established: Arc::new(std::sync::atomic::AtomicBool::new(!fast_open)),
            fast_open,
        }
    }

    /// Ensure the connection is established by reading the server response.
    /// This is called on the first Read() when Fast Open is enabled.
    async fn ensure_established(&mut self) -> std::io::Result<()> {
        if self.established.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }

        // Read response per protocol spec:
        // [uint8] Status (0x00 = OK, 0x01 = Error)
        // [varint] Message length
        // [bytes] Message string
        // [varint] Padding length
        // [bytes] Random padding

        let mut status_buf = [0u8; 1];
        self.recv.read_exact(&mut status_buf).await.map_err(|e| {
            std::io::Error::other(format!("Failed to read status: {e}"))
        })?;

        let status = status_buf[0];
        if status != TCP_STATUS_OK {
            // Read error message
            let msg_len = read_varint_from_stream(&mut self.recv).await?;
            if msg_len > 1024 {
                return Err(std::io::Error::other(format!(
                    "Server returned error status and message too long"
                )));
            }
            let mut msg_buf = vec![0u8; msg_len as usize];
            self.recv.read_exact(&mut msg_buf).await.map_err(|e| {
                std::io::Error::other(format!("Failed to read error message: {e}"))
            })?;
            let msg = String::from_utf8_lossy(&msg_buf);
            return Err(std::io::Error::other(format!(
                "Server rejected connection: {}",
                msg
            )));
        }

        // Read and discard message length (should be 0 for OK status)
        let msg_len = read_varint_from_stream(&mut self.recv).await?;
        if msg_len > 0 {
            let mut discard = vec![0u8; msg_len as usize];
            self.recv.read_exact(&mut discard).await.map_err(|e| {
                std::io::Error::other(format!("Failed to discard message: {e}"))
            })?;
        }

        // Read and discard padding
        let padding_len = read_varint_from_stream(&mut self.recv).await?;
        if padding_len > 0 {
            let mut discard = vec![0u8; padding_len as usize];
            self.recv.read_exact(&mut discard).await.map_err(|e| {
                std::io::Error::other(format!("Failed to discard padding: {e}"))
            })?;
        }

        self.established.store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

impl AsyncRead for HyTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // If using Fast Open and not yet established, we need to establish first
        if !self.established.load(std::sync::atomic::Ordering::Relaxed) {
            // Create a future to establish the connection
            let establish_future = self.ensure_established();
            // Pin the future locally
            let pinned_future = std::pin::pin!(establish_future);
            // Try to complete the future
            let mut result = None;
            let mut waker = Some(cx.waker().clone());
            with_waker(&mut waker, |ctx| {
                match pinned_future.poll(ctx) {
                    Poll::Ready(Ok(())) => result = Some(Ok(())),
                    Poll::Ready(Err(e)) => result = Some(Err(e)),
                    Poll::Pending => {}
                }
            });
            match result {
                Some(Ok(())) => {}
                Some(Err(e)) => return Poll::Ready(Err(e)),
                None => return Poll::Pending,
            }
        }

        // Connection is established, proceed with normal read
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for HyTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(|e| std::io::Error::other(format!("Write error: {}", e)))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_flush(cx)
            .map_err(|e| std::io::Error::other(format!("Flush error: {}", e)))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(|e| std::io::Error::other(format!("Shutdown error: {}", e)))
    }
}

impl AsyncStream for HyTcpStream {}

impl AsyncPing for HyTcpStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

// HyTcpStream is Unpin because all its fields are Unpin
impl Unpin for HyTcpStream {}

/// Helper to set a waker for a scope
fn with_waker<F, R>(waker: &mut Option<std::task::Waker>, f: F) -> R
where
    F: FnOnce(&mut Context<'_>) -> R,
{
    if let Some(w) = waker.take() {
        f(&mut Context::from_waker(&w))
    } else {
        // This shouldn't happen, but provide a no-op waker just in case
        use std::task::{RawWaker, RawWakerVTable};
        static VTABLE: RawWakerVTable = RawWakerVTable::new(
            |_| { unreachable!() },           // clone
            |_| {},                           // wake
            |_| { unreachable!() },           // wake_by_ref
            |_| {},                           // drop
        );
        let raw = RawWaker::new(std::ptr::null(), &VTABLE);
        // SAFETY: The RawWaker is constructed from a null pointer with a VTable
        // that does nothing. This is safe because we never actually call any
        // methods that would dereference the pointer.
        unsafe {
            f(&mut Context::from_waker(&std::task::Waker::from_raw(raw)))
        }
    }
}

impl Hysteria2Connection {
    /// Create a new TCP stream through the Hysteria2 connection
    pub async fn create_tcp_stream(
        &self,
        target: &NetLocation,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        debug!("[Hysteria2] Creating TCP stream to {}", target);

        // Open bidirectional stream
        let (mut send, recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| std::io::Error::other(format!("Failed to open QUIC stream: {e}")))?;

        // Send TCP request per protocol spec:
        // [varint] 0x401 (TCPRequest ID)
        // [varint] Address length
        // [bytes] Address string (host:port)
        // [varint] Padding length
        // [bytes] Random padding

        let address_bytes = target.to_string().into_bytes();
        let address_len = address_bytes.len();

        if address_len > MAX_ADDRESS_LENGTH {
            return Err(std::io::Error::other(format!(
                "Address too long: {} bytes (max {})",
                address_len, MAX_ADDRESS_LENGTH
            )));
        }

        // Generate random padding before any async operations
        let padding_len: usize = {
            let mut rng = rand::rng();
            rng.random_range(0..=63u8) as usize
        };

        let mut padding_bytes = vec![0u8; padding_len];
        {
            let mut rng = rand::rng();
            rng.fill_bytes(&mut padding_bytes);
        }

        // Build request frame (no rng here)
        let mut request = BytesMut::new();

        // Frame type
        request.extend_from_slice(&encode_varint(FRAME_TYPE_TCP_REQUEST)?);

        // Address length and bytes
        request.extend_from_slice(&encode_varint(address_len as u64)?);
        request.extend_from_slice(&address_bytes);

        // Padding length and bytes
        request.extend_from_slice(&encode_varint(padding_len as u64)?);
        request.extend_from_slice(&padding_bytes);

        // Send request
        send.write_all(&request)
            .await
            .map_err(|e| std::io::Error::other(format!("Failed to send TCP request: {e}")))?;

        // If Fast Open is enabled, return the stream immediately without waiting for response
        if self.fast_open {
            debug!("[Hysteria2] Fast Open enabled, returning stream immediately");
            return Ok(Box::new(HyTcpStream::new(send, recv, true)));
        }

        // Fast Open disabled, wait for server response before returning
        let mut recv = recv;

        // Receive response per protocol spec:
        // [uint8] Status (0x00 = OK, 0x01 = Error)
        // [varint] Message length
        // [bytes] Message string
        // [varint] Padding length
        // [bytes] Random padding

        let mut status_buf = [0u8; 1];
        recv.read_exact(&mut status_buf)
            .await
            .map_err(|e| std::io::Error::other(format!("Failed to read status: {e}")))?;

        let status = status_buf[0];
        if status != TCP_STATUS_OK {
            // Read error message
            let msg_len = read_varint_from_stream(&mut recv).await?;
            if msg_len > 1024 {
                return Err(std::io::Error::other(format!(
                    "Server returned error status and message too long"
                )));
            }
            let mut msg_buf = vec![0u8; msg_len as usize];
            recv.read_exact(&mut msg_buf)
                .await
                .map_err(|e| std::io::Error::other(format!("Failed to read error message: {e}")))?;
            let msg = String::from_utf8_lossy(&msg_buf);
            return Err(std::io::Error::other(format!(
                "Server rejected connection: {}",
                msg
            )));
        }

        // Read and discard message length (should be 0 for OK status)
        let msg_len = read_varint_from_stream(&mut recv).await?;
        if msg_len > 0 {
            warn!("[Hysteria2] Server sent message with OK status, discarding");
            let mut discard = vec![0u8; msg_len as usize];
            recv.read_exact(&mut discard)
                .await
                .map_err(|e| std::io::Error::other(format!("Failed to discard message: {e}")))?;
        }

        // Read and discard padding
        let padding_len = read_varint_from_stream(&mut recv).await?;
        if padding_len > 0 {
            let mut discard = vec![0u8; padding_len as usize];
            recv.read_exact(&mut discard)
                .await
                .map_err(|e| std::io::Error::other(format!("Failed to discard padding: {e}")))?;
        }

        Ok(Box::new(QuicStream::from(send, recv)))
    }
}

/// Helper to read varint from QUIC stream
async fn read_varint_from_stream(recv: &mut quinn::RecvStream) -> std::io::Result<u64> {
    let mut first_byte = [0u8; 1];
    recv.read_exact(&mut first_byte)
        .await
        .map_err(|e| std::io::Error::other(format!("Failed to read varint first byte: {e}")))?;

    let first_byte = first_byte[0];
    let length_indicator = first_byte >> 6;
    let mut value: u64 = (first_byte & 0b00111111) as u64;

    let num_bytes = match length_indicator {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };

    if num_bytes > 1 {
        let mut remaining = vec![0u8; num_bytes - 1];
        recv.read_exact(&mut remaining)
            .await
            .map_err(|e| std::io::Error::other(format!("Failed to read varint remaining: {e}")))?;
        for byte in remaining {
            value <<= 8;
            value |= byte as u64;
        }
    }

    Ok(value)
}

/// A wrapper around Hysteria2Client that implements SocketConnector
///
/// This maintains a single QUIC connection and creates new streams on demand.
#[derive(Debug)]
pub struct Hysteria2SocketConnector {
    /// The Hysteria2 client
    client: Arc<Hysteria2Client>,
    /// The established Hysteria2 connection (after authentication)
    connection: Arc<Mutex<Option<Hysteria2Connection>>>,
}

impl Hysteria2SocketConnector {
    /// Create a new Hysteria2 socket connector
    pub fn new(
        endpoint: Arc<quinn::Endpoint>,
        server_address: NetLocation,
        sni_hostname: Option<String>,
        password: String,
        udp_enabled: bool,
        fast_open: bool,
        max_tx: u64,
        max_rx: u64,
    ) -> Self {
        Self {
            client: Arc::new(Hysteria2Client::new(
                endpoint,
                server_address,
                sni_hostname,
                password,
                udp_enabled,
                fast_open,
                max_tx,
                max_rx,
            )),
            connection: Arc::new(Mutex::new(None)),
        }
    }

    /// Get or create the authenticated Hysteria2 connection
    async fn get_or_create_connection(
        &self,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<Hysteria2Connection> {
        // Check if we already have a connection
        {
            let conn_guard = self.connection.lock().await;
            if let Some(ref conn) = *conn_guard {
                // Check if connection is still alive
                if conn.connection.close_reason().is_none() {
                    return Ok(conn.clone());
                }
            }
        }

        // Need to create a new connection
        let (new_conn, _tx, _tx_auto) = self.client.connect_and_authenticate(resolver).await?;

        // Store the new connection
        {
            let mut conn_guard = self.connection.lock().await;
            *conn_guard = Some(new_conn.clone());
        }

        Ok(new_conn)
    }
}

#[async_trait::async_trait]
impl crate::tcp::socket_connector::SocketConnector for Hysteria2SocketConnector {
    /// Create a TCP connection through Hysteria2
    async fn connect(
        &self,
        resolver: &Arc<dyn Resolver>,
        address: &NetLocation,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let conn = self.get_or_create_connection(resolver).await?;
        conn.create_tcp_stream(address).await
    }

    /// Create UDP socket(s) for Hysteria2 UDP relay
    async fn connect_udp(
        &self,
        resolver: &Arc<dyn Resolver>,
        request: crate::tcp_handler::UdpStreamRequest,
    ) -> std::io::Result<crate::tcp_handler::TcpClientUdpSetupResult> {
        use crate::tcp_handler::UdpStreamRequest;
        use crate::socket_util::new_udp_socket;

        let conn = self.get_or_create_connection(resolver).await?;

        match request {
            UdpStreamRequest::MultiDirectional { server_stream } => {
                // Create a local UDP socket for bidirectional communication
                let local_socket = Arc::new(new_udp_socket(true, None)?);

                // Create the Hysteria2 UDP message stream
                let hy_udp_stream = HyUdpMessageStream::new(local_socket.clone(), conn.connection.clone());

                Ok(crate::tcp_handler::TcpClientUdpSetupResult::MultiDirectional {
                    server_stream,
                    client_stream: Box::new(hy_udp_stream),
                })
            }
            UdpStreamRequest::Bidirectional { server_stream: _, target: _ } => {
                // Hysteria2 uses native UDP relay via QUIC datagrams,
                // which supports multiple destinations by design.
                // We always use MultiDirectional internally.
                let local_socket = Arc::new(new_udp_socket(true, None)?);
                let hy_udp_stream = HyUdpMessageStream::new(local_socket, conn.connection.clone());

                // Return a simple wrapped stream that discards the server_stream
                // since Hysteria2 handles UDP directly via QUIC datagrams
                Ok(crate::tcp_handler::TcpClientUdpSetupResult::MultiDirectional {
                    server_stream: Box::new(DummyTargetedStream),
                    client_stream: Box::new(hy_udp_stream),
                })
            }
            UdpStreamRequest::SessionBased { server_stream: _ } => {
                // Hysteria2 uses native UDP relay via QUIC datagrams,
                // not XUDP-style sessions. Use MultiDirectional.
                let local_socket = Arc::new(new_udp_socket(true, None)?);
                let hy_udp_stream = HyUdpMessageStream::new(local_socket, conn.connection.clone());

                Ok(crate::tcp_handler::TcpClientUdpSetupResult::MultiDirectional {
                    server_stream: Box::new(DummyTargetedStream),
                    client_stream: Box::new(hy_udp_stream),
                })
            }
        }
    }
}

/// A dummy AsyncTargetedMessageStream that does nothing.
/// Used when Hysteria2 handles UDP directly without needing server stream processing.
struct DummyTargetedStream;

impl crate::async_stream::AsyncPing for DummyTargetedStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl crate::async_stream::AsyncReadTargetedMessage for DummyTargetedStream {
    fn poll_read_targeted_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>> {
        Poll::Ready(Ok(NetLocation::UNSPECIFIED))
    }
}

impl crate::async_stream::AsyncWriteSourcedMessage for DummyTargetedStream {
    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
        _source: &std::net::SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl crate::async_stream::AsyncFlushMessage for DummyTargetedStream {
    fn poll_flush_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl crate::async_stream::AsyncShutdownMessage for DummyTargetedStream {
    fn poll_shutdown_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl crate::async_stream::AsyncTargetedMessageStream for DummyTargetedStream {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_varint() {
        // Single byte (0-63)
        assert_eq!(&*encode_varint(0).unwrap(), &[0]);
        assert_eq!(&*encode_varint(63).unwrap(), &[63]);

        // Two bytes (64-16383)
        // For 64: encoded = (0b01 << 14) | 64 = 0x4000 | 0x40 = 0x4040 = [64, 64]
        assert_eq!(&*encode_varint(64).unwrap(), &[64, 64]);
        // For 16383: encoded = (0b01 << 14) | 16383 = 0x4000 | 0x3FFF = 0x7FFF = [127, 255]
        assert_eq!(&*encode_varint(16383).unwrap(), &[127, 255]);

        // Four bytes (16384-1073741823)
        // For 16384: encoded = (0b10 << 30) | 16384 = 0x40000000 | 0x4000 = 0x40004000
        let result = encode_varint(16384).unwrap();
        assert_eq!(result[0] & 0b11000000, 0b10000000);
    }

    #[test]
    fn test_generate_padding_string() {
        let s1 = generate_padding_string();
        let s2 = generate_padding_string();
        // Should generate different strings (very unlikely to be the same)
        assert_ne!(s1, s2);
        // Should be valid ASCII
        assert!(s1.is_ascii());
        assert!(s2.is_ascii());
    }
}
