use std::sync::Arc;

use async_trait::async_trait;

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::tcp_handler::{TcpClientHandler, TcpClientSetupResult};

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
    VisionVless { uuid: Box<[u8]> },
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
    ) -> Self {
        Self {
            client_config,
            tls_buffer_size,
            server_name,
            handler: TlsInnerClientHandler::VisionVless { uuid },
        }
    }
}

#[async_trait]
impl TcpClientHandler for TlsClientHandler {
    async fn setup_client_stream(
        &self,
        server_stream: &mut Box<dyn AsyncStream>,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: NetLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        use crate::crypto::{CryptoConnection, CryptoTlsStream};
        use crate::rustls_handshake::perform_handshake;

        // Create rustls ClientConnection
        let client_conn =
            rustls::ClientConnection::new(self.client_config.clone(), self.server_name.clone())
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Failed to create client connection: {e}"),
                    )
                })?;

        // Wrap in rustls::Connection enum for handshake
        let mut rustls_connection = rustls::Connection::Client(client_conn);

        // Set buffer limits if configured
        if let Some(size) = self.tls_buffer_size {
            rustls_connection.set_buffer_limit(Some(size));
        }

        // Perform the TLS handshake using the generic helper
        // This works for both TLS 1.2 and TLS 1.3
        perform_handshake(&mut rustls_connection, &mut client_stream, 16384).await?;

        // Extract the ClientConnection back from the enum
        let client_conn = match rustls_connection {
            rustls::Connection::Client(conn) => conn,
            _ => unreachable!("We created a Client variant"),
        };

        // Wrap in CryptoTlsStream
        let connection = CryptoConnection::new_rustls_client(client_conn);
        let tls_stream = CryptoTlsStream::new(client_stream, connection);

        match self.handler {
            TlsInnerClientHandler::Default(ref handler) => {
                handler
                    .setup_client_stream(server_stream, Box::new(tls_stream), remote_location)
                    .await
            }
            TlsInnerClientHandler::VisionVless { ref uuid } => {
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
