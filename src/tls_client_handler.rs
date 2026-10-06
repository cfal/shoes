use std::sync::Arc;

use async_trait::async_trait;

use crate::address::ResolvedLocation;
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::AsyncStream;
use crate::crypto::{CryptoConnection, CryptoTlsStream, TlsReadMode};
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
    async fn try_reuse_tcp_stream(
        &self,
        target: &ResolvedLocation,
    ) -> std::io::Result<Option<TcpClientSetupResult>> {
        match &self.handler {
            TlsInnerClientHandler::Default(handler) => handler.try_reuse_tcp_stream(target).await,
            TlsInnerClientHandler::VisionVless { .. } => Ok(None),
        }
    }

    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
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

        let connection = CryptoConnection::new_rustls_client(client_conn);
        let mode = match self.handler {
            TlsInnerClientHandler::VisionVless { .. } => TlsReadMode::PreserveRecords,
            TlsInnerClientHandler::Default(_) => TlsReadMode::Stream,
        };
        let tls_stream = CryptoTlsStream::handshake(client_stream, connection, mode, &[]).await?;

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
                    remote_location.location(),
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
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
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

        let connection = CryptoConnection::new_rustls_client(client_conn);
        let tls_stream =
            CryptoTlsStream::handshake(client_stream, connection, TlsReadMode::Stream, &[]).await?;

        match &self.handler {
            TlsInnerClientHandler::Default(handler) => {
                handler
                    .setup_client_udp_bidirectional(Box::new(tls_stream), target)
                    .await
            }
            TlsInnerClientHandler::VisionVless { uuid, .. } => {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct RejectReuse;

    #[async_trait]
    impl TcpClientHandler for RejectReuse {
        async fn try_reuse_tcp_stream(
            &self,
            _: &ResolvedLocation,
        ) -> std::io::Result<Option<TcpClientSetupResult>> {
            Err(std::io::Error::other("CONNECT rejected"))
        }
        async fn setup_client_tcp_stream(
            &self,
            _: Box<dyn AsyncStream>,
            _: ResolvedLocation,
        ) -> std::io::Result<TcpClientSetupResult> {
            panic!("reuse must not acquire a new transport")
        }
    }

    #[tokio::test]
    async fn only_default_tls_and_reality_handlers_forward_reuse() {
        use crate::reality_client_handler::RealityClientHandler;
        let config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        );
        let target = crate::address::NetLocation::from_str("example.com:443", None)
            .unwrap()
            .into();
        let defaults: Vec<Box<dyn TcpClientHandler>> = vec![
            Box::new(TlsClientHandler::new(
                config.clone(),
                None,
                "localhost".try_into().unwrap(),
                Box::new(RejectReuse),
            )),
            Box::new(RealityClientHandler::new(
                [0; 32],
                [0; 8],
                "localhost".try_into().unwrap(),
                vec![],
                Box::new(RejectReuse),
            )),
        ];
        for handler in defaults {
            assert_eq!(
                handler
                    .try_reuse_tcp_stream(&target)
                    .await
                    .err()
                    .unwrap()
                    .to_string(),
                "CONNECT rejected"
            );
        }
        let vision: Vec<Box<dyn TcpClientHandler>> = vec![
            Box::new(TlsClientHandler::new_vision_vless(
                config,
                None,
                "localhost".try_into().unwrap(),
                Box::new([0; 16]),
                false,
            )),
            Box::new(RealityClientHandler::new_vision_vless(
                [0; 32],
                [0; 8],
                "localhost".try_into().unwrap(),
                vec![],
                Box::new([0; 16]),
                false,
            )),
        ];
        for handler in vision {
            assert!(
                handler
                    .try_reuse_tcp_stream(&target)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }
}
