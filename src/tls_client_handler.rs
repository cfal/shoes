use std::sync::Arc;

use async_trait::async_trait;

use crate::address::NetLocation;
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::AsyncStream;
use crate::crypto::{CryptoConnection, CryptoTlsStream, perform_crypto_handshake};
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};

#[derive(Debug)]
pub struct TlsClientHandler {
    pub client_config: Arc<rustls::ClientConfig>,
    pub tls_buffer_size: Option<usize>,
    pub server_name: rustls::pki_types::ServerName<'static>,
    pub handler: TlsInnerClientHandler,
}

#[derive(Debug)]
pub enum TlsInnerClientHandler {
    Default(Box<dyn TcpClientHandler>),
    VisionVless { uuid: Box<[u8]>, udp_enabled: bool },
}

impl TlsClientHandler {
    pub fn new(
        client_config: Arc<rustls::ClientConfig>,
        tls_buffer_size: Option<usize>,
        server_name: rustls::pki_types::ServerName<'static>,
        handler: Box<dyn TcpClientHandler>,
    ) -> Self {
        Self {
            client_config,
            tls_buffer_size,
            server_name,
            handler: TlsInnerClientHandler::Default(handler),
        }
    }

    pub fn new_vision_vless(
        client_config: Arc<rustls::ClientConfig>,
        tls_buffer_size: Option<usize>,
        server_name: rustls::pki_types::ServerName<'static>,
        uuid: Box<[u8]>,
        udp_enabled: bool,
    ) -> Self {
        Self {
            client_config,
            tls_buffer_size,
            server_name,
            handler: TlsInnerClientHandler::VisionVless { uuid, udp_enabled },
        }
    }
}

#[async_trait]
impl TcpClientHandler for TlsClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: NetLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let mut client_conn =
            rustls::ClientConnection::new(self.client_config.clone(), self.server_name.clone())
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Failed to create client connection: {e}"),
                    )
                })?;

        if let Some(size) = self.tls_buffer_size {
            client_conn.set_buffer_limit(Some(size));
        }

        let mut connection = CryptoConnection::new_rustls_client(client_conn);
        perform_crypto_handshake(&mut connection, &mut client_stream, 16384).await?;
        let tls_stream = CryptoTlsStream::new(client_stream, connection);

        match &self.handler {
            TlsInnerClientHandler::Default(handler) => {
                handler
                    .setup_client_tcp_stream(Box::new(tls_stream), remote_location)
                    .await
            }
            TlsInnerClientHandler::VisionVless { uuid, .. } => {
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
            TlsInnerClientHandler::Default(handler) => handler.supports_udp_over_tcp(),
            TlsInnerClientHandler::VisionVless { udp_enabled, .. } => *udp_enabled, // VLESS supports XUDP when enabled
        }
    }

    async fn setup_client_udp_bidirectional(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        target: NetLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        let mut client_conn =
            rustls::ClientConnection::new(self.client_config.clone(), self.server_name.clone())
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Failed to create client connection: {e}"),
                    )
                })?;

        if let Some(size) = self.tls_buffer_size {
            client_conn.set_buffer_limit(Some(size));
        }

        let mut connection = CryptoConnection::new_rustls_client(client_conn);
        perform_crypto_handshake(&mut connection, &mut client_stream, 16384).await?;
        let tls_stream = CryptoTlsStream::new(client_stream, connection);

        match &self.handler {
            TlsInnerClientHandler::Default(handler) => {
                handler
                    .setup_client_udp_bidirectional(Box::new(tls_stream), target)
                    .await
            }
            TlsInnerClientHandler::VisionVless { uuid, .. } => {
                crate::vless::vless_client_handler::setup_vless_udp_bidirectional(
                    tls_stream, uuid, target,
                )
                .await
            }
        }
    }
}
