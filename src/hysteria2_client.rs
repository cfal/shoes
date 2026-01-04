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

use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use log::{debug, error, warn};
use rand::distr::Alphanumeric;
use rand::{Rng, RngCore};
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::quic_stream::QuicStream;
use crate::resolver::{Resolver, resolve_single_address};

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
}

impl Hysteria2Client {
    /// Create a new Hysteria2 client
    pub fn new(
        endpoint: Arc<quinn::Endpoint>,
        server_address: NetLocation,
        sni_hostname: Option<String>,
        password: String,
        udp_enabled: bool,
    ) -> Self {
        Self {
            endpoint,
            server_address,
            sni_hostname,
            password,
            udp_enabled,
        }
    }

    /// Connect to the Hysteria2 server and perform authentication
    pub async fn connect_and_authenticate(
        &self,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<Hysteria2Connection> {
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

        // Perform HTTP/3 authentication
        timeout(AUTH_TIMEOUT, self.authenticate_connection(&connection))
            .await
            .map_err(|_| {
                error!("[Hysteria2] Authentication timeout");
                connection.close(0u32.into(), b"auth timeout");
                std::io::Error::new(std::io::ErrorKind::TimedOut, "authentication timeout")
            })??;

        debug!("[Hysteria2] Authentication successful");

        Ok(Hysteria2Connection {
            connection,
            udp_enabled: self.udp_enabled,
        })
    }

    /// Perform HTTP/3 authentication handshake
    async fn authenticate_connection(&self, connection: &quinn::Connection) -> std::io::Result<()> {
        let h3_connection = h3_quinn::Connection::new(connection.clone());
        let (_h3_conn, mut h3_send) = h3::client::new(h3_connection)
            .await
            .map_err(|e| std::io::Error::other(format!("Failed to create H3 client: {e}")))?;

        // Build authentication request per protocol spec:
        // :method: POST
        // :path: /auth
        // :host: hysteria
        // Hysteria-Auth: [password]
        // Hysteria-CC-RX: [rx_rate]
        // Hysteria-Padding: [random]

        let req = http::Request::builder()
            .method("POST")
            .uri("https://hysteria/auth")
            .header("Hysteria-Auth", &self.password)
            .header("Hysteria-CC-RX", "0")
            .header("Hysteria-Padding", generate_padding_string())
            .body(())
            .map_err(|e| std::io::Error::other(format!("Failed to build request: {e}")))?;

        // Send request and get the stream
        let mut stream = h3_send
            .send_request(req)
            .await
            .map_err(|e| std::io::Error::other(format!("Failed to send auth request: {e}")))?;

        stream
            .finish()
            .await
            .map_err(|e| std::io::Error::other(format!("Failed to finish auth request: {e}")))?;

        // Receive response from the stream
        let resp = stream
            .recv_response()
            .await
            .map_err(|e| std::io::Error::other(format!("Failed to recv auth response: {e}")))?;

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

        Ok(())
    }
}

/// Represents an authenticated Hysteria2 connection
#[derive(Clone, Debug)]
pub struct Hysteria2Connection {
    /// The underlying QUIC connection
    pub connection: quinn::Connection,
    /// Whether UDP relay is enabled
    pub udp_enabled: bool,
}

impl Hysteria2Connection {
    /// Create a new TCP stream through the Hysteria2 connection
    pub async fn create_tcp_stream(
        &self,
        target: &NetLocation,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        debug!("[Hysteria2] Creating TCP stream to {}", target);

        // Open bidirectional stream
        let (mut send, mut recv) = self
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
    ) -> Self {
        Self {
            client: Arc::new(Hysteria2Client::new(
                endpoint,
                server_address,
                sni_hostname,
                password,
                udp_enabled,
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
        let new_conn = self.client.connect_and_authenticate(resolver).await?;

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
        _resolver: &Arc<dyn Resolver>,
        _request: crate::tcp_handler::UdpStreamRequest,
    ) -> std::io::Result<crate::tcp_handler::TcpClientUdpSetupResult> {
        // UDP implementation is not yet complete
        // Full implementation would require:
        // 1. Session management with unique session IDs
        // 2. Fragmentation/reassembly for large packets
        // 3. Background task to receive datagrams from server
        // 4. Forwarding to local UDP sockets
        Err(std::io::Error::other(
            "Hysteria2 UDP support is not yet implemented. Please disable UDP in the configuration.",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_varint() {
        // Single byte (0-63)
        assert_eq!(&*encode_varint(0).unwrap(), &[0]);
        assert_eq!(&*encode_varint(63).unwrap(), &[63]);

        // Two bytes (64-16383)
        assert_eq!(&*encode_varint(64).unwrap(), &[0b01000000, 0]);
        assert_eq!(&*encode_varint(16383).unwrap(), &[0b01111111, 255]);

        // Four bytes (16384-1073741823)
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
