//! REALITY client setup using the shared rustls transport.

use async_trait::async_trait;

use super::{CipherSuite, Mldsa65VerifyKey, RealityClientConfig};
use crate::address::ResolvedLocation;
use crate::async_stream::AsyncStream;
use crate::crypto::{CryptoTlsStream, TlsReadMode};
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};

#[derive(Debug)]
pub struct RealityClientHandler {
    mldsa65_verify: Option<Mldsa65VerifyKey>,
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
            mldsa65_verify: None,
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
            mldsa65_verify: None,
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

    pub fn with_mldsa65_verify(mut self, key: Option<Mldsa65VerifyKey>) -> Self {
        self.mldsa65_verify = key;
        self
    }

    async fn setup_client_stream_common(
        &self,
        client_stream: Box<dyn AsyncStream>,
        mode: TlsReadMode,
    ) -> std::io::Result<CryptoTlsStream<Box<dyn AsyncStream>>> {
        match &self.server_name {
            rustls::pki_types::ServerName::DnsName(_) => {}
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

        log::debug!("REALITY CLIENT: Creating authenticated TLS connection");
        let reality_config = RealityClientConfig {
            mldsa65_verify: self.mldsa65_verify.clone(),
            public_key: self.public_key,
            short_id: self.short_id,
            server_name: self.server_name.clone(),
            cipher_suites: self.cipher_suites.clone(),
        };

        let connection = reality_config.create_connection()?;
        let stream = CryptoTlsStream::handshake(client_stream, connection, mode, &[]).await?;
        log::debug!(
            "REALITY CLIENT: Handshake completed successfully, negotiated_group={:?}",
            stream.negotiated_group()
        );

        Ok(stream)
    }
}

#[async_trait]
impl TcpClientHandler for RealityClientHandler {
    async fn try_reuse_tcp_stream(
        &self,
        target: &ResolvedLocation,
    ) -> std::io::Result<Option<TcpClientSetupResult>> {
        match &self.handler {
            RealityInnerClientHandler::Default(handler) => {
                handler.try_reuse_tcp_stream(target).await
            }
            RealityInnerClientHandler::VisionVless { .. } => Ok(None),
        }
    }

    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let mode = match self.handler {
            RealityInnerClientHandler::VisionVless { .. } => TlsReadMode::PreserveRecords,
            RealityInnerClientHandler::Default(_) => TlsReadMode::Stream,
        };
        let tls_stream = self.setup_client_stream_common(client_stream, mode).await?;

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
                    remote_location.location(),
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
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn crate::async_stream::AsyncMessageStream>> {
        let tls_stream = self
            .setup_client_stream_common(client_stream, TlsReadMode::Stream)
            .await?;

        match &self.handler {
            RealityInnerClientHandler::Default(handler) => {
                handler
                    .setup_client_udp_bidirectional(Box::new(tls_stream), target)
                    .await
            }
            RealityInnerClientHandler::VisionVless { uuid, .. } => {
                crate::vless::vless_client_handler::setup_vless_udp_bidirectional(
                    tls_stream,
                    uuid,
                    target.into_location(),
                )
                .await
            }
        }
    }
}
