//! TUIC v5 client implementation.
//!
//! Manages persistent QUIC connections to a TUIC server with authentication,
//! heartbeat, per-request bi-directional streams for TCP proxying,
//! optional port hopping for censorship resistance, and native UDP relay
//! via TUIC v5 PACKET command over QUIC uni-streams and datagrams.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::BytesMut;
use log::{debug, info, warn};
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;


use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::config::ClientQuicConfig;
use crate::hysteria2_client::PortHopConfig;
use crate::quic_stream::QuicStream;
use crate::resolver::{Resolver, resolve_single_address};
use crate::rustls_config_util::create_client_config;
use crate::socket_util::new_udp_socket;
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};
use crate::uuid_util::parse_uuid;

const COMMAND_TYPE_AUTHENTICATE: u8 = 0x00;
const COMMAND_TYPE_CONNECT: u8 = 0x01;
const COMMAND_TYPE_PACKET: u8 = 0x02;
const COMMAND_TYPE_HEARTBEAT: u8 = 0x04;

/// Heartbeat interval - client sends heartbeat datagrams at this interval.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// Registry of active UDP sessions, keyed by association ID.
type UdpSessionRegistry = Arc<RwLock<HashMap<u16, tokio::sync::mpsc::Sender<Vec<u8>>>>>;

fn serialize_address(location: &NetLocation) -> Vec<u8> {
    let mut address_bytes = match location.address() {
        Address::Hostname(hostname) => {
            let mut res = Vec::with_capacity(1 + 1 + hostname.len() + 2);
            res.push(0x00); // address type
            let hostname_bytes = hostname.as_bytes();
            res.push(hostname_bytes.len() as u8);
            res.extend_from_slice(hostname_bytes);
            res
        }
        Address::Ipv4(ipv4) => {
            let mut res = Vec::with_capacity(1 + 4 + 2);
            res.push(0x01);
            res.extend_from_slice(&ipv4.octets());
            res
        }
        Address::Ipv6(ipv6) => {
            let mut res = Vec::with_capacity(1 + 16 + 2);
            res.push(0x02);
            res.extend_from_slice(&ipv6.octets());
            res
        }
    };

    address_bytes.extend_from_slice(&location.port().to_be_bytes());
    address_bytes
}

/// Internal state of a TUIC connection.
struct TuicConnection {
    connection: quinn::Connection,
    /// Shared UDP session registry for dispatching PACKET responses.
    udp_sessions: UdpSessionRegistry,
    /// Next association ID for UDP (wrapping counter).
    next_assoc_id: Arc<std::sync::atomic::AtomicU16>,
}

impl TuicConnection {
    fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }
}

/// Manages persistent QUIC connections to a TUIC server.
struct TuicConnectionManager {
    /// Cached connection (if any).
    connection: RwLock<Option<TuicConnection>>,

    /// The quinn client config (reused for reconnects during port hopping).
    quinn_client_config: quinn::ClientConfig,

    /// Whether the server address is IPv6.
    is_ipv6: bool,

    /// Optional bind interface.
    bind_interface: Option<String>,

    /// Server address to connect to.
    server_address: NetLocation,

    /// SNI hostname for QUIC connection.
    sni_hostname: Option<String>,

    /// UUID bytes for authentication.
    uuid_bytes: Box<[u8]>,

    /// Password for authentication.
    password: String,

    /// Resolver for DNS lookups.
    resolver: Arc<dyn Resolver>,

    /// Port hopping configuration (if enabled).
    port_hop: Option<PortHopConfig>,
}

impl TuicConnectionManager {
    fn new(
        server_address: NetLocation,
        uuid: &str,
        password: &str,
        quic_config: ClientQuicConfig,
        bind_interface: Option<String>,
        resolver: Arc<dyn Resolver>,
        port_hop: Option<PortHopConfig>,
    ) -> Self {
        let uuid_bytes = parse_uuid(uuid)
            .expect("Invalid TUIC UUID")
            .into_boxed_slice();

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

        let tls13_suite =
            match rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256 {
                rustls::SupportedCipherSuite::Tls13(t) => t,
                _ => panic!("Could not retrieve Tls13CipherSuite"),
            };

        let rustls_client_config = create_client_config(
            verify,
            server_fingerprints.into_vec(),
            alpn_protocols.into_vec(),
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
            .max_concurrent_uni_streams(4096_u32.into())
            .max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()))
            .keep_alive_interval(Some(Duration::from_secs(15)))
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
            uuid_bytes,
            password: password.to_string(),
            resolver,
            port_hop,
        }
    }

    /// Pick a random port from the port hop range, or use the server address port.
    fn pick_port(&self) -> u16 {
        match &self.port_hop {
            Some(config) => {
                use rand::RngCore;
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
    ) -> std::io::Result<(quinn::Connection, UdpSessionRegistry, Arc<std::sync::atomic::AtomicU16>)> {
        // Fast path: check existing connection
        {
            let guard = self.connection.read().await;
            if let Some(ref conn) = *guard {
                if !conn.is_closed() {
                    return Ok((
                        conn.connection.clone(),
                        conn.udp_sessions.clone(),
                        conn.next_assoc_id.clone(),
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
                    conn.next_assoc_id.clone(),
                ));
            }
        }

        let connection = self.connect_and_authenticate().await?;
        let udp_sessions: UdpSessionRegistry = Arc::new(RwLock::new(HashMap::new()));
        let next_assoc_id = Arc::new(std::sync::atomic::AtomicU16::new(1));

        // Spawn heartbeat task
        let heartbeat_conn = connection.clone();
        tokio::spawn(async move {
            run_heartbeat_loop(heartbeat_conn).await;
        });

        // Spawn unified receiver (handles heartbeats AND UDP PACKET responses)
        let receiver_conn = connection.clone();
        let receiver_sessions = udp_sessions.clone();
        tokio::spawn(async move {
            run_unified_receiver_loop(receiver_conn, receiver_sessions).await;
        });

        let conn_clone = connection.clone();
        let sessions_clone = udp_sessions.clone();
        let assoc_id_clone = next_assoc_id.clone();

        *guard = Some(TuicConnection {
            connection: conn_clone,
            udp_sessions: sessions_clone,
            next_assoc_id: assoc_id_clone,
        });

        Ok((connection, udp_sessions, next_assoc_id))
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

        info!("TUIC: Connecting to {server_addr} (SNI: {domain})");

        let connection = endpoint
            .connect(server_addr, domain)
            .map_err(|e| std::io::Error::other(format!("TUIC QUIC connect failed: {e}")))?
            .await
            .map_err(|e| std::io::Error::other(format!("TUIC QUIC connection failed: {e}")))?;

        info!("TUIC: Connected, authenticating...");

        // Authenticate using keying material
        let mut token_bytes = [0u8; 32];
        connection
            .export_keying_material(
                &mut token_bytes,
                self.uuid_bytes.as_ref(),
                self.password.as_bytes(),
            )
            .map_err(|e| {
                std::io::Error::other(format!("TUIC: Failed to export keying material: {e:?}"))
            })?;

        // Send authentication on a uni-directional stream
        let mut send_stream = connection.open_uni().await.map_err(|e| {
            std::io::Error::other(format!("TUIC: Failed to open auth uni stream: {e}"))
        })?;

        // Auth header: version(1) + command(1) + uuid(16) + token(32) = 50 bytes
        let mut auth_data = BytesMut::with_capacity(50);
        auth_data.extend_from_slice(&[5, COMMAND_TYPE_AUTHENTICATE]);
        auth_data.extend_from_slice(&self.uuid_bytes);
        auth_data.extend_from_slice(&token_bytes);

        send_stream.write_all(&auth_data).await.map_err(|e| {
            std::io::Error::other(format!("TUIC: Failed to send auth: {e}"))
        })?;
        send_stream.finish().map_err(|e| {
            std::io::Error::other(format!("TUIC: Failed to finish auth stream: {e}"))
        })?;

        // Start hop loop AFTER auth succeeds — hopping during handshake breaks it
        if let Some((hop_socket, interval)) = hop_info {
            crate::udp_hop_socket::spawn_hop_loop(hop_socket, interval);
        }

        info!("TUIC: Authentication sent successfully on port {}", server_addr.port());

        Ok(connection)
    }
}

/// Sends periodic heartbeat datagrams to keep the connection alive.
async fn run_heartbeat_loop(connection: quinn::Connection) {
    let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
    // Skip the first immediate tick
    interval.tick().await;

    loop {
        interval.tick().await;

        if connection.close_reason().is_some() {
            debug!("TUIC heartbeat: connection closed, stopping");
            return;
        }

        let heartbeat = bytes::Bytes::from_static(&[5, COMMAND_TYPE_HEARTBEAT]);
        if let Err(e) = connection.send_datagram(heartbeat) {
            warn!("TUIC heartbeat failed: {e}");
            return;
        }
        debug!("TUIC heartbeat sent");
    }
}

/// Extract the UDP payload from a PACKET-format buffer.
/// Format: assoc_id(2) + packet_id(2) + frag_total(1) + frag_id(1) + size(2) + address + payload
/// Returns (assoc_id, payload) or None if malformed.
fn extract_packet_payload(data: &[u8]) -> Option<(u16, Vec<u8>)> {
    if data.len() < 8 {
        return None;
    }

    let assoc_id = u16::from_be_bytes([data[0], data[1]]);
    let _packet_id = u16::from_be_bytes([data[2], data[3]]);
    let frag_total = data[4];
    let _frag_id = data[5];
    let payload_size = u16::from_be_bytes([data[6], data[7]]) as usize;

    // Only handle non-fragmented packets
    if frag_total != 1 {
        debug!("TUIC: ignoring fragmented PACKET (frag_total={frag_total})");
        return None;
    }

    // Parse and skip the address
    let addr_data = &data[8..];
    let addr_len = parse_tuic_address_len(addr_data)?;

    let payload_start = 8 + addr_len;
    if data.len() < payload_start + payload_size {
        return None;
    }

    Some((assoc_id, data[payload_start..payload_start + payload_size].to_vec()))
}

/// Get the byte length of a TUIC v5 address (type + content + port).
fn parse_tuic_address_len(data: &[u8]) -> Option<usize> {
    if data.is_empty() {
        return None;
    }
    match data[0] {
        0xff => Some(1),
        0x00 => {
            if data.len() < 2 {
                return None;
            }
            let hostname_len = data[1] as usize;
            Some(2 + hostname_len + 2)
        }
        0x01 => Some(7),  // type(1) + IPv4(4) + port(2)
        0x02 => Some(19), // type(1) + IPv6(16) + port(2)
        _ => None,
    }
}

/// Dispatch a received PACKET to the registered UDP session.
async fn dispatch_packet(sessions: &UdpSessionRegistry, data: &[u8]) {
    if let Some((assoc_id, payload)) = extract_packet_payload(data) {
        let guard = sessions.read().await;
        if let Some(tx) = guard.get(&assoc_id) {
            if let Err(e) = tx.try_send(payload) {
                debug!("TUIC: failed to dispatch PACKET to session {assoc_id}: {e}");
            }
        } else {
            debug!("TUIC: PACKET for unknown assoc_id={assoc_id}");
        }
    } else {
        debug!("TUIC: malformed PACKET data ({} bytes)", data.len());
    }
}

/// Unified receiver loop that handles:
/// - Datagrams: heartbeat responses AND UDP PACKET responses (with version+cmd prefix)
/// - Uni-streams: UDP PACKET responses from server (without version/cmd prefix)
async fn run_unified_receiver_loop(connection: quinn::Connection, sessions: UdpSessionRegistry) {
    loop {
        tokio::select! {
            result = connection.read_datagram() => {
                match result {
                    Ok(data) => {
                        if data.len() >= 2 {
                            match data[1] {
                                COMMAND_TYPE_HEARTBEAT => {
                                    debug!("TUIC: received server heartbeat");
                                }
                                COMMAND_TYPE_PACKET => {
                                    debug!("TUIC: received PACKET via datagram ({} bytes)", data.len());
                                    // data[2..] = everything after version+command
                                    dispatch_packet(&sessions, &data[2..]).await;
                                }
                                _ => {
                                    debug!("TUIC: received unknown datagram command: {}", data[1]);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        debug!("TUIC receiver: datagram error: {e}");
                        return;
                    }
                }
            }
            result = connection.accept_uni() => {
                match result {
                    Ok(mut recv) => {
                        let sessions = sessions.clone();
                        tokio::spawn(async move {
                            // Server sends PACKET on uni-stream WITHOUT version/command prefix.
                            // Format: assoc_id(2) + packet_id(2) + frag_total(1) + frag_id(1)
                            //         + size(2) + address + payload
                            match recv.read_to_end(65535).await {
                                Ok(data) => {
                                    debug!("TUIC: received PACKET via uni-stream ({} bytes)", data.len());
                                    dispatch_packet(&sessions, &data).await;
                                }
                                Err(e) => {
                                    debug!("TUIC: uni-stream read error: {e}");
                                }
                            }
                        });
                    }
                    Err(e) => {
                        debug!("TUIC receiver: accept_uni error: {e}");
                        return;
                    }
                }
            }
        }
    }
}



/// TUIC client handler implementing TcpClientHandler.
///
/// Opens bi-directional QUIC streams with TUIC CONNECT headers for TCP proxying.
/// Manages persistent QUIC connections with authentication, heartbeat, and optional port hopping.
pub struct TuicTcpClientHandler {
    connection_manager: Arc<TuicConnectionManager>,
}

impl std::fmt::Debug for TuicTcpClientHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TuicTcpClientHandler")
            .field("server", &self.connection_manager.server_address)
            .finish()
    }
}

impl TuicTcpClientHandler {
    pub fn new(
        server_address: NetLocation,
        uuid: &str,
        password: &str,
        quic_config: ClientQuicConfig,
        bind_interface: Option<String>,
        resolver: Arc<dyn Resolver>,
        port_hop: Option<PortHopConfig>,
    ) -> Self {
        Self {
            connection_manager: Arc::new(TuicConnectionManager::new(
                server_address,
                uuid,
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
impl TcpClientHandler for TuicTcpClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        _client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let connection = self.connection_manager.get_connection().await?;

        // Open a bi-directional stream for this TCP connection
        let (mut send, recv) = connection.open_bi().await.map_err(|e| {
            std::io::Error::other(format!("TUIC: Failed to open bi-stream: {e}"))
        })?;

        // Write TUIC CONNECT header: version(1) + command(1) + address
        let address_bytes = serialize_address(remote_location.location());
        let mut header = BytesMut::with_capacity(2 + address_bytes.len());
        header.extend_from_slice(&[5, COMMAND_TYPE_CONNECT]);
        header.extend_from_slice(&address_bytes);

        send.write_all(&header).await.map_err(|e| {
            std::io::Error::other(format!("TUIC: Failed to write CONNECT header: {e}"))
        })?;

        debug!(
            "TUIC: Opened bi-stream CONNECT to {}",
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
        let (connection, udp_sessions, next_assoc_id) = self
            .connection_manager
            .get_connection_with_sessions()
            .await?;

        // Allocate an association ID
        let assoc_id = next_assoc_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Serialize target address in TUIC format
        let target_address_bytes = serialize_address(target.location());

        // Channel for receiving UDP packets from the unified receiver
        let (recv_tx, recv_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

        // Register this session in the shared registry
        {
            let mut sessions = udp_sessions.write().await;
            sessions.insert(assoc_id, recv_tx);
        }

        debug!(
            "TUIC: UDP relay setup for {} (assoc_id={})",
            target.location(),
            assoc_id
        );

        Ok(Box::new(TuicUdpMessageStream::new(
            connection,
            assoc_id,
            target_address_bytes,
            recv_rx,
            udp_sessions,
        )))
    }
}

/// A message stream that sends/receives UDP packets over TUIC v5 PACKET protocol.
///
/// Sends via QUIC uni-streams with TUIC v5 PACKET headers.
/// Receives from the unified receiver loop via an mpsc channel.
struct TuicUdpMessageStream {
    connection: quinn::Connection,
    assoc_id: u16,
    next_packet_id: u16,
    target_address_bytes: Vec<u8>,
    recv_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    /// Buffered received data waiting to be read
    read_buf: Option<Vec<u8>>,
    /// Shared session registry (for cleanup on drop)
    udp_sessions: UdpSessionRegistry,
}

impl TuicUdpMessageStream {
    fn new(
        connection: quinn::Connection,
        assoc_id: u16,
        target_address_bytes: Vec<u8>,
        recv_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
        udp_sessions: UdpSessionRegistry,
    ) -> Self {
        Self {
            connection,
            assoc_id,
            next_packet_id: 0,
            target_address_bytes,
            recv_rx,
            read_buf: None,
            udp_sessions,
        }
    }

    /// Build a TUIC v5 PACKET buffer for sending.
    /// Format: version(1) + cmd(1) + assoc_id(2) + packet_id(2) + frag_total(1) + frag_id(1)
    ///         + size(2) + address + payload
    fn build_packet(&mut self, payload: &[u8]) -> Vec<u8> {
        let addr_bytes = &self.target_address_bytes;
        let size = payload.len() as u16;
        let packet_id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.wrapping_add(1);

        let mut packet = Vec::with_capacity(2 + 2 + 2 + 1 + 1 + 2 + addr_bytes.len() + payload.len());
        packet.push(5); // version
        packet.push(COMMAND_TYPE_PACKET); // command
        packet.extend_from_slice(&self.assoc_id.to_be_bytes()); // assoc_id
        packet.extend_from_slice(&packet_id.to_be_bytes()); // packet_id
        packet.push(1); // frag_total (no fragmentation)
        packet.push(0); // frag_id
        packet.extend_from_slice(&size.to_be_bytes()); // size
        packet.extend_from_slice(addr_bytes); // address
        packet.extend_from_slice(payload); // payload
        packet
    }
}

impl Drop for TuicUdpMessageStream {
    fn drop(&mut self) {
        let assoc_id = self.assoc_id;
        let sessions = self.udp_sessions.clone();
        tokio::spawn(async move {
            let mut guard = sessions.write().await;
            guard.remove(&assoc_id);
            debug!("TUIC: UDP session {assoc_id} unregistered");
        });
    }
}

impl crate::async_stream::AsyncPing for TuicUdpMessageStream {
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

impl crate::async_stream::AsyncReadMessage for TuicUdpMessageStream {
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
                    "TUIC UDP channel closed",
                )))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl crate::async_stream::AsyncWriteMessage for TuicUdpMessageStream {
    fn poll_write_message(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<()>> {
        let packet = self.build_packet(buf);

        // Send via QUIC datagram (synchronous, like Hysteria2)
        if let Err(e) = self.connection.send_datagram(packet.into()) {
            debug!("TUIC UDP: send_datagram failed: {e} (assoc_id={})", self.assoc_id);
            return std::task::Poll::Ready(Err(std::io::Error::other(
                format!("TUIC UDP send_datagram failed: {e}"),
            )));
        }

        std::task::Poll::Ready(Ok(()))
    }
}

impl crate::async_stream::AsyncFlushMessage for TuicUdpMessageStream {
    fn poll_flush_message(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl crate::async_stream::AsyncShutdownMessage for TuicUdpMessageStream {
    fn poll_shutdown_message(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl AsyncMessageStream for TuicUdpMessageStream {}
