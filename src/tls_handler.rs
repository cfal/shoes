use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio_rustls::LazyConfigAcceptor;

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::option_util::NoneOrOne;
use crate::tcp_client_connector::TcpClientConnector;
use crate::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};

#[derive(Debug)]
pub struct TlsServerHandler {
    sni_targets: HashMap<String, TlsServerTarget>,
    default_target: Option<TlsServerTarget>,
}

impl TlsServerHandler {
    pub fn new(
        sni_targets: HashMap<String, TlsServerTarget>,
        default_target: Option<TlsServerTarget>,
    ) -> Self {
        Self {
            sni_targets,
            default_target,
        }
    }
}

#[async_trait]
impl TcpServerHandler for TlsServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), server_stream);
        let start_handshake = acceptor.await?;
        let client_hello = start_handshake.client_hello();
        let target = match client_hello.server_name() {
            None => match self.default_target {
                Some(ref t) => t,
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "No default target for unspecified SNI",
                    ));
                }
            },
            Some(hostname) => match self.sni_targets.get(hostname) {
                Some(t) => t,
                None => match self.default_target {
                    Some(ref t) => t,
                    None => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "No default target for unknown SNI",
                        ));
                    }
                },
            },
        };

        let tls_stream: Box<dyn AsyncStream> = Box::new(
            start_handshake
                .into_stream_with(target.server_config.clone(), |server_conn| {
                    server_conn.set_buffer_limit(Some(32768));
                })
                .await?,
        );

        let mut target_setup_result = target.handler.setup_server_stream(tls_stream).await;
        if let Ok(ref mut setup_result) = target_setup_result {
            setup_result.set_need_initial_flush(true);
            if setup_result.override_proxy_provider_unspecified()
                && !target.override_proxy_provider.is_unspecified()
            {
                setup_result.set_override_proxy_provider(target.override_proxy_provider.clone());
            }
        }

        return target_setup_result;
    }
}

#[derive(Debug)]
pub struct TlsClientHandler {
    pub client_config: Arc<rustls::ClientConfig>,
    pub server_name: rustls::pki_types::ServerName<'static>,
    pub handler: Box<dyn TcpClientHandler>,
}

impl TlsClientHandler {
    pub fn new(
        client_config: Arc<rustls::ClientConfig>,
        server_name: rustls::pki_types::ServerName<'static>,
        handler: Box<dyn TcpClientHandler>,
    ) -> Self {
        Self {
            client_config,
            server_name,
            handler,
        }
    }
}

#[async_trait]
impl TcpClientHandler for TlsClientHandler {
    async fn setup_client_stream(
        &self,
        server_stream: &mut Box<dyn AsyncStream>,
        client_stream: Box<dyn AsyncStream>,
        remote_location: NetLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let connector: tokio_rustls::TlsConnector = self.client_config.clone().into();
        let tls_stream = Box::new(
            connector
                .connect_with(self.server_name.clone(), client_stream, |client_conn| {
                    client_conn.set_buffer_limit(Some(32768));
                })
                .await?,
        );

        self.handler
            .setup_client_stream(server_stream, tls_stream, remote_location)
            .await
    }
}

#[derive(Debug)]
pub struct TlsServerTarget {
    pub server_config: Arc<rustls::ServerConfig>,
    pub handler: Box<dyn TcpServerHandler>,
    pub override_proxy_provider: NoneOrOne<Arc<ClientProxySelector<TcpClientConnector>>>,
}
