use std::sync::Arc;

use async_trait::async_trait;

use crate::address::ResolvedLocation;
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::AsyncStream;
use crate::crypto::{CryptoTlsStream, TlsConnection, TlsReadMode};
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
    async fn prepare_target(
        &self,
        target: ResolvedLocation,
        resolver: &std::sync::Arc<dyn crate::resolver::Resolver>,
    ) -> std::io::Result<ResolvedLocation> {
        match &self.handler {
            TlsInnerClientHandler::Default(handler) => {
                handler.prepare_target(target, resolver).await
            }
            TlsInnerClientHandler::VisionVless { .. } => Ok(target),
        }
    }

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

        let connection = TlsConnection::new(client_conn);
        let mode = match self.handler {
            TlsInnerClientHandler::VisionVless { .. } => TlsReadMode::PreserveRecords,
            TlsInnerClientHandler::Default(_) => TlsReadMode::Stream,
        };
        let tls_stream = CryptoTlsStream::handshake(client_stream, connection, mode, &[]).await?;

        match &self.handler {
            TlsInnerClientHandler::Default(handler) => {
                handler.validate_alpn(tls_stream.alpn_protocol())?;
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

        let connection = TlsConnection::new(client_conn);
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

    #[tokio::test]
    async fn verification_uses_hop_identity_even_without_wire_sni() {
        use crate::address::NetLocation;
        use crate::tcp::tcp_client_handler_factory::tls_verification_name;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        #[derive(Debug)]
        struct CaptureName {
            inner: Arc<dyn rustls::server::ResolvesServerCert>,
            names: Arc<std::sync::Mutex<Vec<Option<String>>>>,
        }
        impl rustls::server::ResolvesServerCert for CaptureName {
            fn resolve(
                &self,
                hello: rustls::server::ClientHello<'_>,
            ) -> Option<Arc<rustls::sign::CertifiedKey>> {
                self.names
                    .lock()
                    .unwrap()
                    .push(hello.server_name().map(str::to_owned));
                self.inner.resolve(hello)
            }
        }

        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            for (hop, sni, expected) in [
                ("localhost:443", None, "localhost"),
                ("127.0.0.1:443", None, "127.0.0.1"),
                ("[::1]:443", None, "::1"),
                ("localhost:443", Some("override.test"), "override.test"),
                ("localhost:443", Some("localhost"), "localhost"),
            ] {
                for correct in [true, false] {
                    let certificate_name = if correct { expected } else { "wrong.test" };
                    let cert =
                        rcgen::generate_simple_self_signed(vec![certificate_name.into()]).unwrap();
                    let mut roots = rustls::RootCertStore::empty();
                    roots.add(cert.cert.der().clone()).unwrap();
                    let mut client = rustls::ClientConfig::builder()
                        .with_root_certificates(roots)
                        .with_no_client_auth();
                    client.enable_sni = sni.is_some();
                    let mut server = rustls::ServerConfig::builder()
                        .with_no_client_auth()
                        .with_single_cert(
                            vec![cert.cert.der().clone()],
                            rustls::pki_types::PrivatePkcs8KeyDer::from(
                                cert.signing_key.serialize_der(),
                            )
                            .into(),
                        )
                        .unwrap();
                    let names = Arc::new(std::sync::Mutex::new(Vec::new()));
                    server.cert_resolver = Arc::new(CaptureName {
                        inner: server.cert_resolver,
                        names: names.clone(),
                    });
                    let hop = NetLocation::from_str(hop, None).unwrap();
                    let handler = TlsClientHandler::new(
                        Arc::new(client),
                        None,
                        tls_verification_name(sni.map(str::to_owned), Some(&hop)).unwrap(),
                        Box::new(crate::port_forward_handler::PortForwardClientHandler),
                    );
                    let (io, peer) = tokio::io::duplex(65536);
                    let server_task = tokio::spawn(async move {
                        let conn = TlsConnection::new(
                            rustls::ServerConnection::new(Arc::new(server)).unwrap(),
                        );
                        let Ok(mut stream) =
                            CryptoTlsStream::handshake(peer, conn, TlsReadMode::Stream, &[]).await
                        else {
                            return false;
                        };
                        let mut byte = [0];
                        stream.read_exact(&mut byte).await.unwrap();
                        assert_eq!(byte, [42]);
                        true
                    });
                    let result = handler
                        .setup_client_tcp_stream(
                            Box::new(io),
                            NetLocation::from_str("not-the-certificate.test:80", None)
                                .unwrap()
                                .into(),
                        )
                        .await;
                    assert_eq!(result.is_ok(), correct, "hop {hop}, SNI {sni:?}");
                    let mut result = result.ok();
                    if let Some(result) = &mut result {
                        result.client_stream.write_all(&[42]).await.unwrap();
                        result.client_stream.flush().await.unwrap();
                    }
                    assert_eq!(server_task.await.unwrap(), correct);
                    assert_eq!(*names.lock().unwrap(), vec![sni.map(str::to_owned)]);
                }
            }
        })
        .await
        .unwrap();
    }

    #[derive(Debug)]
    struct RejectReuse;

    #[async_trait]
    impl TcpClientHandler for RejectReuse {
        async fn prepare_target(
            &self,
            _: ResolvedLocation,
            _: &Arc<dyn crate::resolver::Resolver>,
        ) -> std::io::Result<ResolvedLocation> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "target rejected",
            ))
        }

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
        use crate::reality::RealityClientHandler;
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
        let resolver: Arc<dyn crate::resolver::Resolver> =
            Arc::new(crate::resolver::NativeResolver::new());
        for handler in &defaults {
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
        let wrappers: Vec<Box<dyn TcpClientHandler>> = vec![
            Box::new(crate::websocket::WebsocketTcpClientHandler::new(
                "localhost:443".into(),
                None,
                None,
                Default::default(),
                Box::new(RejectReuse),
            )),
            Box::new(crate::shadow_tls::ShadowTlsClientHandler::new(
                "password".into(),
                config.clone(),
                "localhost".try_into().unwrap(),
                Box::new(RejectReuse),
            )),
        ];
        for handler in defaults.into_iter().chain(wrappers) {
            assert_eq!(
                handler
                    .prepare_target(target.clone(), &resolver)
                    .await
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::PermissionDenied
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
            assert_eq!(
                handler
                    .prepare_target(target.clone(), &resolver)
                    .await
                    .unwrap()
                    .location(),
                target.location()
            );
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
