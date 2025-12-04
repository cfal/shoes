// REALITY client handler
//
// This file lives at src/ (not in reality/) for two reasons:
// 1. Symmetry with tls_server_handler.rs which handles both TLS and REALITY server-side
// 2. Avoids a dependency cycle: crypto → reality (core types), but this handler → crypto

use async_trait::async_trait;

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::crypto::{CryptoConnection, CryptoTlsStream, perform_crypto_handshake};
use crate::reality::{CipherSuite, RealityClientConfig, RealityClientConnection};
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};

/// REALITY client handler using buffered Connection API
///
/// This handler establishes REALITY-obfuscated TLS connections using
/// the buffered sans-I/O pattern with RealityClientConnection.
#[derive(Debug)]
pub struct RealityClientHandler {
    public_key: [u8; 32],
    short_id: [u8; 8],
    server_name: rustls::pki_types::ServerName<'static>,
    cipher_suites: Vec<CipherSuite>,
    handler: RealityInnerClientHandler,
}

#[derive(Debug)]
pub enum RealityInnerClientHandler {
    Default(Box<dyn TcpClientHandler>),
    VisionVless { uuid: Box<[u8]>, udp_enabled: bool },
}

impl RealityClientHandler {
    pub fn new(
        public_key: [u8; 32],
        short_id: [u8; 8],
        server_name: rustls::pki_types::ServerName<'static>,
        cipher_suites: Vec<CipherSuite>,
        handler: Box<dyn TcpClientHandler>,
    ) -> Self {
        Self {
            public_key,
            short_id,
            server_name,
            cipher_suites,
            handler: RealityInnerClientHandler::Default(handler),
        }
    }
    pub fn new_vision_vless(
        public_key: [u8; 32],
        short_id: [u8; 8],
        server_name: rustls::pki_types::ServerName<'static>,
        cipher_suites: Vec<CipherSuite>,
        user_id: Box<[u8]>,
        udp_enabled: bool,
    ) -> Self {
        Self {
            public_key,
            short_id,
            server_name,
            cipher_suites,
            handler: RealityInnerClientHandler::VisionVless {
                uuid: user_id,
                udp_enabled,
            },
        }
    }

    async fn setup_client_stream_common(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<CryptoTlsStream<Box<dyn AsyncStream>>> {
        let server_name_str = match &self.server_name {
            rustls::pki_types::ServerName::DnsName(name) => name.as_ref(),
            rustls::pki_types::ServerName::IpAddress(ip) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("REALITY requires DNS name, got IP address: {:?}", ip),
                ));
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "REALITY requires DNS name",
                ));
            }
        };

        log::debug!("REALITY CLIENT: Creating buffered RealityClientConnection");
        let reality_config = RealityClientConfig {
            public_key: self.public_key,
            short_id: self.short_id,
            server_name: server_name_str.to_string(),
            cipher_suites: self.cipher_suites.clone(),
        };

        let reality_conn = RealityClientConnection::new(reality_config)?;

        log::debug!("REALITY CLIENT: Creating Connection");
        let mut connection = CryptoConnection::new_reality_client(reality_conn);

        perform_crypto_handshake(&mut connection, &mut client_stream, 16384).await?;
        log::debug!("REALITY CLIENT: Handshake completed successfully");

        Ok(CryptoTlsStream::new(client_stream, connection))
    }
}

#[async_trait]
impl TcpClientHandler for RealityClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: NetLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let tls_stream = self.setup_client_stream_common(client_stream).await?;

        match self.handler {
            RealityInnerClientHandler::Default(ref handler) => {
                handler
                    .setup_client_tcp_stream(Box::new(tls_stream), remote_location)
                    .await
            }
            RealityInnerClientHandler::VisionVless { ref uuid, .. } => {
                crate::vless::vless_client_handler::setup_custom_tls_vision_vless_client_stream(
                    tls_stream,
                    uuid,
                    &remote_location,
                )
                .await
            }
        }
    }

    fn supports_udp_over_tcp(&self) -> bool {
        match &self.handler {
            RealityInnerClientHandler::Default(handler) => handler.supports_udp_over_tcp(),
            RealityInnerClientHandler::VisionVless { udp_enabled, .. } => *udp_enabled,
        }
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: NetLocation,
    ) -> std::io::Result<Box<dyn crate::async_stream::AsyncMessageStream>> {
        let tls_stream = self.setup_client_stream_common(client_stream).await?;

        match &self.handler {
            RealityInnerClientHandler::Default(handler) => {
                handler
                    .setup_client_udp_bidirectional(Box::new(tls_stream), target)
                    .await
            }
            RealityInnerClientHandler::VisionVless { uuid, .. } => {
                crate::vless::vless_client_handler::setup_vless_udp_bidirectional(
                    tls_stream, uuid, target,
                )
                .await
            }
        }
    }
}
