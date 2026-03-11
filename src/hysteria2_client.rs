//! Hysteria2 client implementation.
//!
//! Manages persistent QUIC connections to a Hysteria2 server with HTTP/3-based
//! authentication, per-request bidirectional streams for TCP proxying,
//! optional port hopping for censorship resistance, and native UDP relay
//! via Hysteria2 QUIC datagrams.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use bytes::BytesMut;
use log::{debug, error, info, warn};
use rand::RngCore;
use tokio::sync::RwLock;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::config::ClientQuicConfig;
use crate::quic_stream::QuicStream;
use crate::resolver::{resolve_single_address, Resolver};
use crate::rustls_config_util::create_client_config;
use crate::socket_util::new_udp_socket;
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};
use crate::thread_util::get_num_threads;

/// TCP request frame type constant from Hysteria2 protocol.
/// See: https://github.com/apernet/hysteria/blob/master/core/internal/protocol/proxy.go#L15
const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

/// HTTP/3 auth status code for successful authentication.
const STATUS_AUTH_OK: u16 = 233;

/// Maximum QUIC endpoints to create.
const MAX_QUIC_ENDPOINTS: usize = 32;

/// Maximum number of padding bytes for TCP requests/responses.
const MAX_PADDING_LENGTH: usize = 4096;

/// Maximum UDP message buffer size per Hysteria2 protocol.
const MAX_UDP_SIZE: usize = 4096;

/// Default port hopping interval.
const DEFAULT_HOP_INTERVAL: Duration = Duration::from_secs(30);

/// Minimum allowed port hopping interval.
const MIN_HOP_INTERVAL: Duration = Duration::from_secs(5);

/// Registry of active UDP sessions, keyed by session ID.
type UdpSessionRegistry = Arc<RwLock<HashMap<u32, tokio::sync::mpsc::Sender<Vec<u8>>>>>;

/// Port hopping configuration.
#[derive(Debug, Clone)]
pub struct PortHopConfig {
    /// The list of ports to hop between.
    pub ports: Vec<u16>,
    /// Interval between port hops.
    pub hop_interval: Duration,
}

/// Internal state of a Hysteria2 connection.
struct Hysteria2Connection {
    connection: quinn::Connection,
    /// Shared UDP session registry for dispatching datagram responses.
    udp_sessions: UdpSessionRegistry,
    /// Next session ID for UDP (atomic, starts at 1 per official protocol).
    next_session_id: Arc<AtomicU32>,
}

impl Hysteria2Connection {
    fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }
}

/// Manages persistent QUIC connections to a Hysteria2 server.
struct Hysteria2ConnectionManager {
    /// Cached connection (if any).
    connection: RwLock<Option<Hysteria2Connection>>,

    /// The quinn client config (reused for reconnects during port hopping).
    quinn_client_config: quinn::ClientConfig,

    /// Whether the server address is IPv6.
    is_ipv6: bool,

    /// Optional bind interface.
    bind_interface: Option<String>,

    /// Server address to connect to (hostname or IP, port used as fallback).
    server_address: NetLocation,

    /// SNI hostname for QUIC connection.
    sni_hostname: Option<String>,

    /// Password for authentication.
    password: String,

    /// Resolver for DNS lookups.
    resolver: Arc<dyn Resolver>,

    /// Port hopping configuration (if enabled).
    port_hop: Option<PortHopConfig>,
}

impl Hysteria2ConnectionManager {
    fn new(
        server_address: NetLocation,
        password: &str,
        quic_config: ClientQuicConfig,
        bind_interface: Option<String>,
        resolver: Arc<dyn Resolver>,
        port_hop: Option<PortHopConfig>,
    ) -> Self {
        let ClientQuicConfig {
            verify,
            server_fingerprints,
            alpn_protocols,
            sni_hostname,
            key,
            cert,
        } = quic_config;

        let default_sni_hostname = server_address
            .address()
            .hostname()
            .map(ToString::to_string);

        let sni_hostname = if sni_hostname.is_unspecified() {
            default_sni_hostname
        } else {
            sni_hostname.into_option()
        };

        let key_and_cert_bytes = key.zip(cert).map(|(key, cert)| {
            let cert_bytes = cert.as_bytes().to_vec();
            let key_bytes = key.as_bytes().to_vec();
            (key_bytes, cert_bytes)
        });

        // Hysteria2 uses h3 ALPN; override user-provided ALPN if empty
        let alpn_vec = {
            let user_alpn = alpn_protocols.into_vec();
            if user_alpn.is_empty() {
                vec!["h3".to_string()]
            } else {
                user_alpn
            }
        };

        let tls13_suite =
            match rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256 {
                rustls::SupportedCipherSuite::Tls13(t) => t,
                _ => panic!("Could not retrieve Tls13CipherSuite"),
            };

        let rustls_client_config = create_client_config(
            verify,
            server_fingerprints.into_vec(),
            alpn_vec,
            sni_hostname.is_some(),
            key_and_cert_bytes,
            false, // tls13_only - QUIC enforces TLS 1.3 anyway
        );

        let quic_client_config = quinn::crypto::rustls::QuicClientConfig::with_initial(
            Arc::new(rustls_client_config),
            tls13_suite.quic_suite().unwrap(),
        )
        .unwrap();

        let mut quinn_client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));

        let mut transport_config = quinn::TransportConfig::default();
        transport_config
            .max_concurrent_bidi_streams(4096_u32.into())
            .max_concurrent_uni_streams(1024_u32.into())
            .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()))
            .keep_alive_interval(Some(Duration::from_secs(10)))
            .send_window(16 * 1024 * 1024)
            .receive_window((20u32 * 1024 * 1024).into())
            .stream_receive_window((8u32 * 1024 * 1024).into())
            .initial_mtu(1200)
            .min_mtu(1200)
            .mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()))
            .enable_segmentation_offload(true)
            .initial_rtt(Duration::from_millis(100));

        quinn_client_config.transport_config(Arc::new(transport_config));

        let is_ipv6 = server_address.address().is_ipv6();

        Self {
            connection: RwLock::new(None),
            quinn_client_config,
            is_ipv6,
            bind_interface,
            server_address,
            sni_hostname,
            password: password.to_string(),
            resolver,
            port_hop,
        }
    }

    /// Pick a random port from the port hop range, or use the server address port.
    fn pick_port(&self) -> u16 {
        match &self.port_hop {
            Some(config) => {
                let mut rng = rand::rng();
                let idx = (rng.next_u32() as usize) % config.ports.len();
                config.ports[idx]
            }
            None => self.server_address.port(),
        }
    }

    /// Create a new QUIC endpoint with a fresh UDP socket.
    fn create_endpoint(&self) -> std::io::Result<quinn::Endpoint> {
        let udp_socket =
            new_udp_socket(self.is_ipv6, self.bind_interface.clone())?;
        let udp_socket = udp_socket.into_std().map_err(|e| {
            std::io::Error::other(format!("Failed to convert UDP socket: {e}"))
        })?;

        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            udp_socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|e| std::io::Error::other(format!("Failed to create endpoint: {e}")))?;

        endpoint.set_default_client_config(self.quinn_client_config.clone());
        Ok(endpoint)
    }

    /// Get or create a QUIC connection along with its UDP session registry.
    async fn get_connection_with_sessions(
        &self,
    ) -> std::io::Result<(quinn::Connection, UdpSessionRegistry, Arc<AtomicU32>)> {
        // Fast path: check existing connection
        {
            let guard = self.connection.read().await;
            if let Some(ref conn) = *guard {
                if !conn.is_closed() {
                    return Ok((
                        conn.connection.clone(),
                        conn.udp_sessions.clone(),
                        conn.next_session_id.clone(),
                    ));
                }
            }
        }

        // Slow path: need to create new connection
        let mut guard = self.connection.write().await;

        // Double-check after acquiring write lock
        if let Some(ref conn) = *guard {
            if !conn.is_closed() {
                return Ok((
                    conn.connection.clone(),
                    conn.udp_sessions.clone(),
                    conn.next_session_id.clone(),
                ));
            }
        }

        let connection = self.connect_and_authenticate().await?;
        let udp_sessions: UdpSessionRegistry = Arc::new(RwLock::new(HashMap::new()));
        let next_session_id = Arc::new(AtomicU32::new(1));

        // Spawn datagram receiver loop for UDP
        let receiver_conn = connection.clone();
        let receiver_sessions = udp_sessions.clone();
        tokio::spawn(async move {
            run_datagram_receiver_loop(receiver_conn, receiver_sessions).await;
        });

        let conn_clone = connection.clone();
        let sessions_clone = udp_sessions.clone();
        let session_id_clone = next_session_id.clone();

        *guard = Some(Hysteria2Connection {
            connection: conn_clone,
            udp_sessions: sessions_clone,
            next_session_id: session_id_clone,
        });

        Ok((connection, udp_sessions, next_session_id))
    }

    /// Get or create a QUIC connection (TCP-only convenience).
    async fn get_connection(&self) -> std::io::Result<quinn::Connection> {
        let (conn, _, _) = self.get_connection_with_sessions().await?;
        Ok(conn)
    }

    /// Connect to the server and authenticate. Uses UdpHopSocket for port
    /// hopping if configured, otherwise uses a plain endpoint.
    async fn connect_and_authenticate(&self) -> std::io::Result<quinn::Connection> {
        let base_addr =
            resolve_single_address(&self.resolver, &self.server_address).await?;

        let domain = match &self.sni_hostname {
            Some(s) => s.as_str(),
            None => self
                .server_address
                .address()
                .hostname()
                .unwrap_or("example.com"),
        };

        // Collect hop socket info but DON'T start the hop loop yet —
        // it must only start after authentication completes.
        let (endpoint, server_addr, hop_info) = if let Some(ref hop_config) = self.port_hop {
            // Non-disruptive port hopping: use UdpHopSocket
            let hop_socket = Arc::new(crate::udp_hop_socket::UdpHopSocket::new(
                base_addr.ip(),
                &hop_config.ports,
                self.is_ipv6,
                self.bind_interface.clone(),
            )?);

            let initial_addr = hop_socket.initial_server_addr();

            let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                None,
                hop_socket.clone(),
                Arc::new(quinn::TokioRuntime),
            )
            .map_err(|e| std::io::Error::other(format!("Failed to create hop endpoint: {e}")))?;

            endpoint.set_default_client_config(self.quinn_client_config.clone());

            (endpoint, initial_addr, Some((hop_socket, hop_config.hop_interval)))
        } else {
            // No port hopping: use a plain endpoint
            let port = self.server_address.port();
            let server_addr = SocketAddr::new(base_addr.ip(), port);
            let endpoint = self.create_endpoint()?;
            (endpoint, server_addr, None)
        };

        info!("Hysteria2: Connecting to {server_addr} (SNI: {domain})");

        let connection = endpoint
            .connect(server_addr, domain)
            .map_err(|e| std::io::Error::other(format!("Hysteria2 QUIC connect failed: {e}")))?
            .await
            .map_err(|e| {
                std::io::Error::other(format!("Hysteria2 QUIC connection failed: {e}"))
            })?;

        info!("Hysteria2: Connected, authenticating via HTTP/3...");

        // Perform HTTP/3 authentication
        self.h3_authenticate(&connection).await?;

        // Start hop loop AFTER auth succeeds — hopping during handshake breaks it
        if let Some((hop_socket, interval)) = hop_info {
            crate::udp_hop_socket::spawn_hop_loop(hop_socket, interval);
        }

        info!("Hysteria2: Authentication successful on port {}", server_addr.port());

        Ok(connection)
    }

    /// Perform HTTP/3 authentication handshake.
    ///
    /// Sends POST https://hysteria/auth with Hysteria-Auth header.
    /// Expects status 233 response to indicate success.
    async fn h3_authenticate(&self, connection: &quinn::Connection) -> std::io::Result<()> {
        let h3_quinn_connection = h3_quinn::Connection::new(connection.clone());

        let (mut driver, mut send_request) = h3::client::new(h3_quinn_connection)
            .await
            .map_err(|e| std::io::Error::other(format!("H3 client setup failed: {e}")))?;

        // Drive the H3 connection in the background
        let drive_handle = tokio::spawn(async move {
            let e = futures::future::poll_fn(|cx| driver.poll_close(cx)).await;
            debug!("Hysteria2 H3 driver closed: {e}");
        });

        // Build auth request
        let req = http::Request::builder()
            .method("POST")
            .uri("https://hysteria/auth")
            .header("Hysteria-Auth", &self.password)
            .header("Hysteria-CC-RX", "0")
            .header("Hysteria-Padding", generate_padding_string())
            .body(())
            .unwrap();

        let mut stream = send_request
            .send_request(req)
            .await
            .map_err(|e| std::io::Error::other(format!("H3 send auth request failed: {e}")))?;

        // Finish the request body (empty body for POST)
        stream
            .finish()
            .await
            .map_err(|e| std::io::Error::other(format!("H3 finish request failed: {e}")))?;

        let resp = stream
            .recv_response()
            .await
            .map_err(|e| std::io::Error::other(format!("H3 recv auth response failed: {e}")))?;

        let status = resp.status().as_u16();
        if status != STATUS_AUTH_OK {
            return Err(std::io::Error::other(format!(
                "Hysteria2 auth failed: server returned status {status} (expected {STATUS_AUTH_OK})"
            )));
        }

        // Parse auth response headers
        let headers = resp.headers();
        if let Some(udp_value) = headers.get("Hysteria-UDP") {
            debug!(
                "Hysteria2 server UDP support: {}",
                udp_value.to_str().unwrap_or("?")
            );
        }
        if let Some(cc_rx) = headers.get("Hysteria-CC-RX") {
            debug!(
                "Hysteria2 server CC-RX: {}",
                cc_rx.to_str().unwrap_or("?")
            );
        }

        // We don't need to keep the H3 connection alive after auth
        // The underlying QUIC connection stays open for bidirectional streams
        drop(send_request);
        drive_handle.abort();

        Ok(())
    }
}


/// Receives QUIC datagrams and dispatches Hysteria2 UDPMessage payloads to registered sessions.
async fn run_datagram_receiver_loop(connection: quinn::Connection, sessions: UdpSessionRegistry) {
    loop {
        let data = match connection.read_datagram().await {
            Ok(d) => d,
            Err(e) => {
                debug!("Hysteria2 datagram receiver: connection error: {e}");
                return;
            }
        };

        // Parse Hysteria2 UDPMessage:
        // session_id(4) + packet_id(2) + frag_id(1) + frag_count(1) + addr_len(varint) + addr + data
        if data.len() < 9 {
            debug!("Hysteria2: datagram too short ({} bytes)", data.len());
            continue;
        }

        let session_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        // packet_id, frag_id, frag_count at [4..8] - we ignore fragmentation for now
        let frag_count = data[7];

        // Parse address length (QUIC varint) starting at offset 8
        let (addr_len, varint_size) = match decode_varint(&data[8..]) {
            Some(v) => v,
            None => {
                debug!("Hysteria2: invalid varint in datagram");
                continue;
            }
        };

        let addr_end = 8 + varint_size + addr_len as usize;
        if data.len() < addr_end {
            debug!("Hysteria2: datagram truncated");
            continue;
        }

        let payload = &data[addr_end..];

        // Only handle non-fragmented messages (frag_count == 1)
        if frag_count != 1 {
            debug!("Hysteria2: ignoring fragmented datagram (frag_count={frag_count})");
            continue;
        }

        let guard = sessions.read().await;
        if let Some(tx) = guard.get(&session_id) {
            if let Err(e) = tx.try_send(payload.to_vec()) {
                debug!("Hysteria2: failed to dispatch to session {session_id}: {e}");
            }
        } else {
            debug!("Hysteria2: datagram for unknown session {session_id}");
        }
    }
}

/// Decode a QUIC variable-length integer from a byte slice.
/// Returns (value, bytes_consumed) or None if invalid.
fn decode_varint(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];
    let length = first >> 6;
    let mut value = (first & 0x3f) as u64;
    let num_bytes = match length {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };
    if data.len() < num_bytes {
        return None;
    }
    for i in 1..num_bytes {
        value <<= 8;
        value |= data[i] as u64;
    }
    Some((value, num_bytes))
}

/// Parse a port range string like "20000-50000" or "20000,20001,20002" into a Vec of ports.
pub fn parse_port_range(s: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();

    for part in s.split(',') {
        let part = part.trim();
        if let Some((start_str, end_str)) = part.split_once('-') {
            let start: u16 = start_str
                .trim()
                .parse()
                .map_err(|e| format!("invalid port number '{start_str}': {e}"))?;
            let end: u16 = end_str
                .trim()
                .parse()
                .map_err(|e| format!("invalid port number '{end_str}': {e}"))?;
            if start > end {
                return Err(format!("invalid port range: {start}-{end}"));
            }
            for port in start..=end {
                ports.push(port);
            }
        } else {
            let port: u16 = part
                .parse()
                .map_err(|e| format!("invalid port number '{part}': {e}"))?;
            ports.push(port);
        }
    }

    if ports.is_empty() {
        return Err("no ports specified".to_string());
    }

    Ok(ports)
}

/// Generate a random ASCII padding string (1-80 chars) for auth headers.
fn generate_padding_string() -> String {
    use rand::distr::Alphanumeric;
    use rand::Rng;

    let mut rng = rand::rng();
    let length = rng.random_range(1..80);
    rng.sample_iter(Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

/// Encode a QUIC-style variable-length integer.
#[inline]
fn encode_varint(value: u64) -> std::io::Result<Box<[u8]>> {
    if value <= 0b00111111 {
        Ok(Box::new([value as u8]))
    } else if value < (1 << 14) {
        let mut bytes = (value as u16).to_be_bytes();
        bytes[0] |= 0b01000000;
        Ok(Box::new(bytes))
    } else if value < (1 << 30) {
        let mut bytes = (value as u32).to_be_bytes();
        bytes[0] |= 0b10000000;
        Ok(Box::new(bytes))
    } else if value < (1 << 62) {
        let mut bytes = value.to_be_bytes();
        bytes[0] |= 0b11000000;
        Ok(Box::new(bytes))
    } else {
        Err(std::io::Error::other("value too large to encode as varint"))
    }
}

/// Read a QUIC-style variable-length integer from a RecvStream.
async fn read_varint(recv: &mut quinn::RecvStream, buf: &mut [u8; 8]) -> std::io::Result<u64> {
    recv.read_exact(&mut buf[..1])
        .await
        .map_err(|e| std::io::Error::other(format!("failed to read varint first byte: {e}")))?;

    let first_byte = buf[0];
    let length = first_byte >> 6;
    let mut value: u64 = (first_byte & 0b00111111) as u64;

    let num_bytes: usize = match length {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };

    if num_bytes > 1 {
        let remaining = num_bytes - 1;
        recv.read_exact(&mut buf[..remaining])
            .await
            .map_err(|e| std::io::Error::other(format!("failed to read varint bytes: {e}")))?;
        for i in 0..remaining {
            value <<= 8;
            value |= buf[i] as u64;
        }
    }

    Ok(value)
}

/// Hysteria2 client handler implementing TcpClientHandler.
///
/// Opens bidirectional QUIC streams with Hysteria2 TCP request headers for proxying.
/// Manages persistent QUIC connections with HTTP/3 authentication and optional port hopping.
pub struct Hysteria2TcpClientHandler {
    connection_manager: Arc<Hysteria2ConnectionManager>,
}

impl std::fmt::Debug for Hysteria2TcpClientHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2TcpClientHandler")
            .field("server", &self.connection_manager.server_address)
            .finish()
    }
}

impl Hysteria2TcpClientHandler {
    pub fn new(
        server_address: NetLocation,
        password: &str,
        quic_config: ClientQuicConfig,
        bind_interface: Option<String>,
        resolver: Arc<dyn Resolver>,
        port_hop: Option<PortHopConfig>,
    ) -> Self {
        Self {
            connection_manager: Arc::new(Hysteria2ConnectionManager::new(
                server_address,
                password,
                quic_config,
                bind_interface,
                resolver,
                port_hop,
            )),
        }
    }
}

#[async_trait]
impl TcpClientHandler for Hysteria2TcpClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        _client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let connection = self.connection_manager.get_connection().await?;

        // Open a bidirectional stream for this TCP connection
        let (mut send, mut recv) = connection.open_bi().await.map_err(|e| {
            std::io::Error::other(format!("Hysteria2: Failed to open bi-stream: {e}"))
        })?;

        // Write TCP request header per Hysteria2 protocol:
        // FrameTypeTCPRequest (0x401 as QUIC varint)
        // Address length (QUIC varint)
        // Address (bytes)
        // Padding length (QUIC varint)
        // Padding (bytes)
        let address = remote_location.location().to_string();
        let address_bytes = address.as_bytes();

        let frame_type_varint = encode_varint(FRAME_TYPE_TCP_REQUEST)?;
        let addr_len_varint = encode_varint(address_bytes.len() as u64)?;

        // Generate random padding (scope rng to avoid holding non-Send ThreadRng across await)
        let (padding_len_varint, padding_bytes) = {
            let mut rng = rand::rng();
            let padding_len = (rng.next_u32() % 257) as usize; // 0-256 bytes of padding
            let varint = encode_varint(padding_len as u64)?;
            let mut padding = vec![0u8; padding_len];
            if padding_len > 0 {
                rng.fill_bytes(&mut padding);
            }
            (varint, padding)
        };
        let padding_len = padding_bytes.len();

        let total_size = frame_type_varint.len()
            + addr_len_varint.len()
            + address_bytes.len()
            + padding_len_varint.len()
            + padding_len;

        let mut header = BytesMut::with_capacity(total_size);
        header.extend_from_slice(&frame_type_varint);
        header.extend_from_slice(&addr_len_varint);
        header.extend_from_slice(address_bytes);
        header.extend_from_slice(&padding_len_varint);

        // Add random padding bytes
        if padding_len > 0 {
            header.extend_from_slice(&padding_bytes);
        }

        use tokio::io::AsyncWriteExt;
        send.write_all(&header).await.map_err(|e| {
            std::io::Error::other(format!("Hysteria2: Failed to write TCP request header: {e}"))
        })?;

        // Read TCP response per Hysteria2 protocol:
        // Status (byte, 0=ok, 1=error)
        // Message length (QUIC varint)
        // Message (bytes)
        // Padding length (QUIC varint)
        // Padding (bytes)
        let mut varint_buf = [0u8; 8];

        // Read status byte
        let mut status_byte = [0u8; 1];
        recv.read_exact(&mut status_byte)
            .await
            .map_err(|e| std::io::Error::other(format!("Hysteria2: Failed to read TCP response status: {e}")))?;

        // Read message
        let msg_len = read_varint(&mut recv, &mut varint_buf).await?;
        if msg_len > 2048 {
            return Err(std::io::Error::other("Hysteria2: invalid response message length"));
        }
        let mut msg_buf = vec![0u8; msg_len as usize];
        if msg_len > 0 {
            recv.read_exact(&mut msg_buf)
                .await
                .map_err(|e| std::io::Error::other(format!("Hysteria2: Failed to read response message: {e}")))?;
        }

        // Read and discard padding
        let resp_padding_len = read_varint(&mut recv, &mut varint_buf).await?;
        if resp_padding_len > MAX_PADDING_LENGTH as u64 {
            return Err(std::io::Error::other("Hysteria2: invalid response padding length"));
        }
        if resp_padding_len > 0 {
            let mut discard = vec![0u8; resp_padding_len as usize];
            recv.read_exact(&mut discard)
                .await
                .map_err(|e| std::io::Error::other(format!("Hysteria2: Failed to read response padding: {e}")))?;
        }

        if status_byte[0] != 0 {
            let msg = String::from_utf8_lossy(&msg_buf);
            return Err(std::io::Error::other(format!(
                "Hysteria2: server rejected TCP connection to {}: {}",
                remote_location.location(),
                msg
            )));
        }

        debug!(
            "Hysteria2: Opened bi-stream TCP to {}",
            remote_location.location()
        );

        Ok(TcpClientSetupResult {
            client_stream: Box::new(QuicStream::from(send, recv)),
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        true
    }

    async fn setup_client_udp_bidirectional(
        &self,
        _client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        let (connection, udp_sessions, next_session_id) = self
            .connection_manager
            .get_connection_with_sessions()
            .await?;

        // Allocate a session ID (starts at 1, per official Hysteria2 protocol)
        let session_id = next_session_id.fetch_add(1, Ordering::Relaxed);

        // Target address as "host:port" string
        let target_addr = target.location().to_string();

        // Channel for receiving UDP packets from the datagram receiver
        let (recv_tx, recv_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

        // Register session
        {
            let mut sessions = udp_sessions.write().await;
            sessions.insert(session_id, recv_tx);
        }

        debug!(
            "Hysteria2: UDP relay setup for {} (session_id={})",
            target.location(),
            session_id
        );

        Ok(Box::new(Hysteria2UdpMessageStream::new(
            connection,
            session_id,
            target_addr,
            recv_rx,
            udp_sessions,
        )))
    }
}

/// A message stream that sends/receives UDP packets via Hysteria2 native QUIC datagrams.
struct Hysteria2UdpMessageStream {
    connection: quinn::Connection,
    session_id: u32,
    target_addr: String,
    recv_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    /// Buffered received data waiting to be read
    read_buf: Option<Vec<u8>>,
    /// For cleanup on drop
    udp_sessions: UdpSessionRegistry,
}

impl Hysteria2UdpMessageStream {
    fn new(
        connection: quinn::Connection,
        session_id: u32,
        target_addr: String,
        recv_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
        udp_sessions: UdpSessionRegistry,
    ) -> Self {
        Self {
            connection,
            session_id,
            target_addr,
            recv_rx,
            read_buf: None,
            udp_sessions,
        }
    }

    /// Build a Hysteria2 UDPMessage datagram for sending.
    /// Format: session_id(4) + packet_id(2) + frag_id(1) + frag_count(1)
    ///         + addr_len(varint) + addr(bytes) + data
    fn build_datagram(&self, payload: &[u8]) -> std::io::Result<Vec<u8>> {
        let addr_bytes = self.target_addr.as_bytes();
        let addr_len_varint = encode_varint(addr_bytes.len() as u64)?;

        let total = 4 + 2 + 1 + 1 + addr_len_varint.len() + addr_bytes.len() + payload.len();
        let mut buf = Vec::with_capacity(total);

        buf.extend_from_slice(&self.session_id.to_be_bytes()); // session_id
        buf.extend_from_slice(&0u16.to_be_bytes()); // packet_id = 0 (no frag)
        buf.push(0); // frag_id = 0
        buf.push(1); // frag_count = 1 (no fragmentation)
        buf.extend_from_slice(&addr_len_varint); // addr length
        buf.extend_from_slice(addr_bytes); // addr
        buf.extend_from_slice(payload); // data

        Ok(buf)
    }
}

impl Drop for Hysteria2UdpMessageStream {
    fn drop(&mut self) {
        let session_id = self.session_id;
        let sessions = self.udp_sessions.clone();
        tokio::spawn(async move {
            let mut guard = sessions.write().await;
            guard.remove(&session_id);
            debug!("Hysteria2: UDP session {session_id} unregistered");
        });
    }
}

impl crate::async_stream::AsyncPing for Hysteria2UdpMessageStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<bool>> {
        std::task::Poll::Ready(Ok(false))
    }
}

impl crate::async_stream::AsyncReadMessage for Hysteria2UdpMessageStream {
    fn poll_read_message(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // If we have buffered data, copy it out
        if let Some(data) = self.read_buf.take() {
            let to_copy = std::cmp::min(data.len(), buf.remaining());
            buf.put_slice(&data[..to_copy]);
            if to_copy < data.len() {
                self.read_buf = Some(data[to_copy..].to_vec());
            }
            return std::task::Poll::Ready(Ok(()));
        }

        // Poll the channel for new data
        match self.recv_rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(data)) => {
                let to_copy = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    self.read_buf = Some(data[to_copy..].to_vec());
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => {
                std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "Hysteria2 UDP channel closed",
                )))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl crate::async_stream::AsyncWriteMessage for Hysteria2UdpMessageStream {
    fn poll_write_message(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<()>> {
        let datagram = match self.build_datagram(buf) {
            Ok(d) => d,
            Err(e) => return std::task::Poll::Ready(Err(e)),
        };

        if let Err(e) = self.connection.send_datagram(datagram.into()) {
            debug!("Hysteria2 UDP: send_datagram failed: {e} (session_id={})", self.session_id);
            return std::task::Poll::Ready(Err(std::io::Error::other(
                format!("Hysteria2 UDP send_datagram failed: {e}"),
            )));
        }

        std::task::Poll::Ready(Ok(()))
    }
}

impl crate::async_stream::AsyncFlushMessage for Hysteria2UdpMessageStream {
    fn poll_flush_message(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl crate::async_stream::AsyncShutdownMessage for Hysteria2UdpMessageStream {
    fn poll_shutdown_message(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl AsyncMessageStream for Hysteria2UdpMessageStream {}
