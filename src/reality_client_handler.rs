// REALITY client handler
//
// This file lives at src/ (not in reality/) for two reasons:
// 1. Symmetry with tls_server_handler.rs which handles both TLS and REALITY server-side
// 2. Avoids a dependency cycle: crypto → reality (core types), but this handler → crypto

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::crypto::{CryptoConnection, CryptoTlsStream};
use crate::reality::{RealityClientConfig, RealityClientConnection};
use crate::tcp_handler::{TcpClientHandler, TcpClientSetupResult};

/// REALITY client handler using buffered Connection API
///
/// This handler establishes REALITY-obfuscated TLS connections using
/// the buffered sans-I/O pattern with RealityClientConnection.
#[derive(Debug)]
pub struct RealityClientHandler {
    public_key: [u8; 32],
    short_id: [u8; 8],
    server_name: rustls::pki_types::ServerName<'static>,
    handler: RealityInnerClientHandler,
}

#[derive(Debug)]
pub enum RealityInnerClientHandler {
    Default(Box<dyn TcpClientHandler>),
    VisionVless { uuid: Box<[u8]> },
}

impl RealityClientHandler {
    pub fn new(
        public_key: [u8; 32],
        short_id: [u8; 8],
        server_name: rustls::pki_types::ServerName<'static>,
        handler: Box<dyn TcpClientHandler>,
    ) -> Self {
        Self {
            public_key,
            short_id,
            server_name,
            handler: RealityInnerClientHandler::Default(handler),
        }
    }
    pub fn new_vision_vless(
        public_key: [u8; 32],
        short_id: [u8; 8],
        server_name: rustls::pki_types::ServerName<'static>,
        user_id: Box<[u8]>,
    ) -> Self {
        Self {
            public_key,
            short_id,
            server_name,
            handler: RealityInnerClientHandler::VisionVless { uuid: user_id },
        }
    }
}

#[async_trait]
impl TcpClientHandler for RealityClientHandler {
    async fn setup_client_stream(
        &self,
        server_stream: &mut Box<dyn AsyncStream>,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: NetLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        // Extract server name as string
        let server_name_str = match &self.server_name {
            rustls::pki_types::ServerName::DnsName(name) => name.as_ref(),
            rustls::pki_types::ServerName::IpAddress(ip) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("REALITY requires DNS name, got IP address: {:?}", ip),
                ))
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "REALITY requires DNS name",
                ))
            }
        };

        // Step 1: Create buffered REALITY client connection
        log::debug!("REALITY CLIENT: Creating buffered RealityClientConnection");
        let reality_config = RealityClientConfig {
            public_key: self.public_key,
            short_id: self.short_id,
            server_name: server_name_str.to_string(),
        };

        let mut reality_conn = RealityClientConnection::new(reality_config)?;

        // Step 2: Write ClientHello to server
        log::debug!("REALITY CLIENT: Writing ClientHello");
        {
            let mut write_buf = Vec::new();
            while reality_conn.wants_write() {
                reality_conn.write_tls(&mut write_buf)?;
            }
            if !write_buf.is_empty() {
                client_stream.write_all(&write_buf).await?;
                client_stream.flush().await?;
            }
        }

        // Step 3: Read server's handshake messages
        log::debug!("REALITY CLIENT: Reading server handshake");
        {
            let mut buf = vec![0u8; 16384]; // Large enough for server handshake
            let n = client_stream.read(&mut buf).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF while waiting for server handshake",
                ));
            }
            let mut cursor = std::io::Cursor::new(&buf[..n]);
            reality_conn.read_tls(&mut cursor)?;
        }

        // Step 4: Process server handshake
        log::debug!("REALITY CLIENT: Processing server handshake");
        reality_conn.process_new_packets()?;

        // Continue processing packets until handshake is complete
        while reality_conn.is_handshaking() {
            log::debug!("REALITY CLIENT: Handshake still in progress, checking for more work");

            // Check if we need to write (e.g., client Finished)
            if reality_conn.wants_write() {
                log::debug!("REALITY CLIENT: Writing buffered handshake data");
                let mut write_buf = Vec::new();
                while reality_conn.wants_write() {
                    reality_conn.write_tls(&mut write_buf)?;
                }
                if !write_buf.is_empty() {
                    client_stream.write_all(&write_buf).await?;
                    client_stream.flush().await?;
                    log::debug!("REALITY CLIENT: Sent {} bytes to server", write_buf.len());
                }
            }

            // Try to process more packets
            let prev_state = reality_conn.is_handshaking();
            reality_conn.process_new_packets()?;

            // If we're still handshaking and state didn't change, read more data
            if reality_conn.is_handshaking() && prev_state == reality_conn.is_handshaking() {
                log::debug!("REALITY CLIENT: Reading more server handshake data");
                let mut buf = vec![0u8; 16384];
                let n = client_stream.read(&mut buf).await?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "EOF while reading server handshake",
                    ));
                }
                log::debug!("REALITY CLIENT: Read {} bytes from server", n);
                let mut cursor = std::io::Cursor::new(&buf[..n]);
                reality_conn.read_tls(&mut cursor)?;

                // Process the new data
                reality_conn.process_new_packets()?;
            }
        }

        // Step 5: Final check for any remaining writes
        if reality_conn.wants_write() {
            log::debug!("REALITY CLIENT: Writing final handshake data");
            let mut write_buf = Vec::new();
            while reality_conn.wants_write() {
                reality_conn.write_tls(&mut write_buf)?;
            }
            if !write_buf.is_empty() {
                client_stream.write_all(&write_buf).await?;
                client_stream.flush().await?;
            }
        }

        // Step 6: Wrap in Connection enum
        log::debug!("REALITY CLIENT: Creating Connection");
        let connection = CryptoConnection::new_reality_client(reality_conn);

        log::debug!("REALITY CLIENT: Handshake completed successfully");

        let tls_stream = CryptoTlsStream::new(client_stream, connection);

        match self.handler {
            RealityInnerClientHandler::Default(ref handler) => {
                handler
                    .setup_client_stream(server_stream, Box::new(tls_stream), remote_location)
                    .await
            }
            RealityInnerClientHandler::VisionVless { ref uuid } => {
                crate::vless::vless_client_handler::setup_custom_tls_vision_vless_client_stream(
                    tls_stream,
                    uuid,
                    &remote_location,
                )
                .await
            }
        }
    }
}
