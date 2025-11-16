// Unified connection enum for all cryptographic protocols
//
// This enum mirrors rustls::Connection, allowing different TLS-like
// protocols to be used interchangeably.

use std::io::{self, Read, Write};

use crate::reality::{
    feed_reality_client_connection, feed_reality_server_connection, RealityClientConnection,
    RealityServerConnection,
};

use crate::rustls_connection_util::{feed_rustls_client_connection, feed_rustls_server_connection};

use super::crypto_reader_writer::{CryptoReader, CryptoWriter};

/// Represents the I/O state after processing packets
#[derive(Debug, Clone, Copy)]
pub struct CryptoIoState {
    /// Number of plaintext bytes available to read
    plaintext_bytes_to_read: usize,
}

impl CryptoIoState {
    /// Create a new IoState
    pub fn new(plaintext_bytes_to_read: usize) -> Self {
        CryptoIoState {
            plaintext_bytes_to_read,
        }
    }

    /// How many plaintext bytes could be obtained via Read without further I/O
    pub fn plaintext_bytes_to_read(&self) -> usize {
        self.plaintext_bytes_to_read
    }
}

/// Unified connection type supporting multiple crypto protocols
///
/// This enum allows switching between rustls and REALITY implementations
/// while maintaining a consistent API that matches rustls.
pub enum CryptoConnection {
    /// rustls server-side connection
    RustlsServer(rustls::ServerConnection),
    /// rustls client-side connection
    RustlsClient(rustls::ClientConnection),
    /// REALITY server-side connection
    RealityServer(RealityServerConnection),
    /// REALITY client-side connection
    RealityClient(RealityClientConnection),
}

impl CryptoConnection {
    /// Create a new rustls server connection
    pub fn new_rustls_server(conn: rustls::ServerConnection) -> Self {
        CryptoConnection::RustlsServer(conn)
    }

    /// Create a new rustls client connection
    pub fn new_rustls_client(conn: rustls::ClientConnection) -> Self {
        CryptoConnection::RustlsClient(conn)
    }

    /// Create a new REALITY server connection
    pub fn new_reality_server(conn: RealityServerConnection) -> Self {
        CryptoConnection::RealityServer(conn)
    }

    /// Create a new REALITY client connection
    pub fn new_reality_client(conn: RealityClientConnection) -> Self {
        CryptoConnection::RealityClient(conn)
    }

    /// Check if this is a server-side connection
    pub fn is_server(&self) -> bool {
        matches!(
            self,
            CryptoConnection::RustlsServer(_) | CryptoConnection::RealityServer(_)
        )
    }

    /// Check if this is a client-side connection
    pub fn is_client(&self) -> bool {
        matches!(
            self,
            CryptoConnection::RustlsClient(_) | CryptoConnection::RealityClient(_)
        )
    }

    /// Read TLS messages from `rd` into internal buffers
    ///
    /// Returns the number of bytes read, or 0 if the connection is closed.
    /// This does NOT decrypt data - call `process_new_packets()` for that.
    pub fn read_tls(&mut self, rd: &mut dyn Read) -> io::Result<usize> {
        match self {
            CryptoConnection::RustlsServer(conn) => conn.read_tls(rd),
            CryptoConnection::RustlsClient(conn) => conn.read_tls(rd),
            CryptoConnection::RealityServer(conn) => conn.read_tls(rd),
            CryptoConnection::RealityClient(conn) => conn.read_tls(rd),
        }
    }

    /// Process any buffered TLS messages and update internal state
    ///
    /// This decrypts data and advances the handshake state machine.
    /// Returns the I/O state including how many plaintext bytes are available.
    pub fn process_new_packets(&mut self) -> io::Result<CryptoIoState> {
        match self {
            CryptoConnection::RustlsServer(conn) => {
                let io_state = conn.process_new_packets().map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("rustls server error processing new packets: {:?}", e),
                    )
                })?;

                Ok(CryptoIoState::new(io_state.plaintext_bytes_to_read()))
            }
            CryptoConnection::RustlsClient(conn) => {
                let io_state = conn.process_new_packets().map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("rustls client error processing new packets: {:?}", e),
                    )
                })?;

                Ok(CryptoIoState::new(io_state.plaintext_bytes_to_read()))
            }
            CryptoConnection::RealityServer(conn) => {
                let io_state = conn.process_new_packets().map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("reality server error processing new packets: {:?}", e),
                    )
                })?;

                Ok(CryptoIoState::new(io_state.plaintext_bytes_to_read()))
            }
            CryptoConnection::RealityClient(conn) => {
                let io_state = conn.process_new_packets().map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("reality client error processing new packets: {:?}", e),
                    )
                })?;

                Ok(CryptoIoState::new(io_state.plaintext_bytes_to_read()))
            }
        }
    }

    /// Get a unified reader for reading decrypted plaintext
    ///
    /// Works for both Rustls and REALITY connections.
    /// Returns a CryptoReader enum that abstracts over rustls::Reader and REALITY's reader.
    pub fn reader(&mut self) -> CryptoReader<'_> {
        match self {
            CryptoConnection::RustlsServer(conn) => CryptoReader::Rustls(conn.reader()),
            CryptoConnection::RustlsClient(conn) => CryptoReader::Rustls(conn.reader()),
            CryptoConnection::RealityServer(conn) => CryptoReader::Reality(conn.reader()),
            CryptoConnection::RealityClient(conn) => CryptoReader::Reality(conn.reader()),
        }
    }

    /// Get a unified writer for writing plaintext to be encrypted
    ///
    /// Works for both Rustls and REALITY connections.
    /// Returns a CryptoWriter enum that abstracts over rustls::Writer and REALITY's writer.
    pub fn writer(&mut self) -> CryptoWriter<'_> {
        match self {
            CryptoConnection::RustlsServer(conn) => CryptoWriter::Rustls(conn.writer()),
            CryptoConnection::RustlsClient(conn) => CryptoWriter::Rustls(conn.writer()),
            CryptoConnection::RealityServer(conn) => CryptoWriter::Reality(conn.writer()),
            CryptoConnection::RealityClient(conn) => CryptoWriter::Reality(conn.writer()),
        }
    }

    /// Write any buffered TLS messages to `wr`
    ///
    /// This encrypts any pending plaintext and writes the ciphertext.
    /// Returns the number of bytes written.
    pub fn write_tls(&mut self, wr: &mut dyn Write) -> io::Result<usize> {
        match self {
            CryptoConnection::RustlsServer(conn) => conn.write_tls(wr),
            CryptoConnection::RustlsClient(conn) => conn.write_tls(wr),
            CryptoConnection::RealityServer(conn) => conn.write_tls(wr),
            CryptoConnection::RealityClient(conn) => conn.write_tls(wr),
        }
    }

    /// Check if the connection wants to write data
    ///
    /// If true, the application should call `write_tls()` as soon as possible.
    pub fn wants_write(&self) -> bool {
        match self {
            CryptoConnection::RustlsServer(conn) => conn.wants_write(),
            CryptoConnection::RustlsClient(conn) => conn.wants_write(),
            CryptoConnection::RealityServer(conn) => conn.wants_write(),
            CryptoConnection::RealityClient(conn) => conn.wants_write(),
        }
    }

    /// Check whether the handshake is complete
    ///
    /// For both client and server connections, this returns true when
    /// the handshake has completed and application data can be exchanged.
    pub fn is_handshaking(&self) -> bool {
        match self {
            CryptoConnection::RustlsServer(conn) => conn.is_handshaking(),
            CryptoConnection::RustlsClient(conn) => conn.is_handshaking(),
            CryptoConnection::RealityServer(conn) => conn.is_handshaking(),
            CryptoConnection::RealityClient(conn) => conn.is_handshaking(),
        }
    }

    /// Queue a close notification
    ///
    /// This queues a close notification to be sent to the peer.
    /// Call `write_tls()` to actually send it.
    pub fn send_close_notify(&mut self) {
        match self {
            CryptoConnection::RustlsServer(conn) => conn.send_close_notify(),
            CryptoConnection::RustlsClient(conn) => conn.send_close_notify(),
            CryptoConnection::RealityServer(conn) => conn.send_close_notify(),
            CryptoConnection::RealityClient(conn) => conn.send_close_notify(),
        }
    }
}

#[inline(always)]
pub fn feed_crypto_connection(
    connection: &mut CryptoConnection,
    data: &[u8],
) -> std::io::Result<()> {
    match connection {
        CryptoConnection::RustlsServer(conn) => feed_rustls_server_connection(conn, data),
        CryptoConnection::RustlsClient(conn) => feed_rustls_client_connection(conn, data),
        CryptoConnection::RealityServer(conn) => feed_reality_server_connection(conn, data),
        CryptoConnection::RealityClient(conn) => feed_reality_client_connection(conn, data),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_type_queries() {
        use crate::address::{Address, NetLocation};
        use crate::reality::{
            RealityClientConfig, RealityClientConnection, RealityServerConfig,
            RealityServerConnection,
        };

        // Test with REALITY server connection
        let server_config = RealityServerConfig {
            private_key: [0u8; 32],
            short_ids: vec![[0u8; 8]],
            dest: NetLocation::new(Address::UNSPECIFIED, 443),
            max_time_diff: None,
            min_client_version: None,
            max_client_version: None,
        };
        let reality_server = RealityServerConnection::new(server_config).unwrap();
        let server_conn = CryptoConnection::new_reality_server(reality_server);

        assert!(server_conn.is_server());
        assert!(!server_conn.is_client());
        assert!(matches!(server_conn, CryptoConnection::RealityServer(_)));
        assert!(!matches!(
            server_conn,
            CryptoConnection::RustlsServer(_) | CryptoConnection::RustlsClient(_)
        ));

        // Test with REALITY client connection
        // Using a valid X25519 test public key (derived from private key [1u8; 32])
        let client_config = RealityClientConfig {
            public_key: [
                0x25, 0x31, 0x51, 0x68, 0x12, 0x8f, 0xf3, 0x7b, 0x46, 0x5e, 0x0c, 0x0c, 0xd8, 0x28,
                0x3d, 0xd5, 0x35, 0x86, 0x8d, 0x8d, 0x3e, 0x8c, 0x1c, 0x85, 0x1e, 0x0e, 0x86, 0x28,
                0xcf, 0x48, 0x0e, 0x66,
            ],
            short_id: [0u8; 8],
            server_name: "test.example.com".to_string(),
        };
        let reality_client = RealityClientConnection::new(client_config).unwrap();
        let client_conn = CryptoConnection::new_reality_client(reality_client);
        assert!(!client_conn.is_server());
        assert!(client_conn.is_client());
        assert!(matches!(client_conn, CryptoConnection::RealityClient(_)));
        assert!(!matches!(
            client_conn,
            CryptoConnection::RustlsServer(_) | CryptoConnection::RustlsClient(_)
        ));
    }
}
