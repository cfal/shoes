use std::sync::Arc;

use async_trait::async_trait;
use rustc_hash::FxHashMap;
use tokio_rustls::TlsAcceptor;

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::option_util::NoneOrOne;
use crate::resolver::{NativeResolver, Resolver};
use crate::shadow_tls::{
    feed_server_connection, read_client_hello, setup_shadowtls_server_stream, ParsedClientHello,
    ShadowTlsServerTarget,
};
use crate::tcp_client_connector::TcpClientConnector;
use crate::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};

#[derive(Debug)]
pub struct TlsServerHandler {
    sni_targets: FxHashMap<String, TlsServerTarget>,
    default_target: Option<TlsServerTarget>,
    // used to resolve handshake server hostnames
    shadowtls_resolver: Arc<dyn Resolver>,
    tls_buffer_size: Option<usize>,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum TlsServerTarget {
    Tls {
        server_config: Arc<rustls::ServerConfig>,
        handler: Box<dyn TcpServerHandler>,
        override_proxy_provider: NoneOrOne<Arc<ClientProxySelector<TcpClientConnector>>>,
    },
    ShadowTls(ShadowTlsServerTarget),
}

impl TlsServerHandler {
    pub fn new(
        sni_targets: FxHashMap<String, TlsServerTarget>,
        default_target: Option<TlsServerTarget>,
        tls_buffer_size: Option<usize>,
    ) -> Self {
        Self {
            sni_targets,
            default_target,
            shadowtls_resolver: Arc::new(NativeResolver::new()),
            tls_buffer_size,
        }
    }
}

#[async_trait]
impl TcpServerHandler for TlsServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let parsed_client_hello = read_client_hello(&mut server_stream).await?;

        let target = match parsed_client_hello.requested_server_name.as_ref() {
            None => match self.default_target {
                Some(ref t) => t,
                None => {
                    return Err(std::io::Error::other(
                        "No default target for unspecified SNI",
                    ));
                }
            },
            Some(hostname) => match self.sni_targets.get(hostname) {
                Some(t) => t,
                None => match self.default_target {
                    Some(ref t) => t,
                    None => {
                        return Err(std::io::Error::other(
                            format!("No default target for unknown SNI: {}", hostname),
                        ));
                    }
                },
            },
        };

        match target {
            TlsServerTarget::Tls {
                ref server_config,
                ref handler,
                ref override_proxy_provider,
            } => {
                let ParsedClientHello {
                    client_hello_frame,
                    client_reader,
                    ..
                } = parsed_client_hello;
                let tls_acceptor = TlsAcceptor::from(server_config.clone());

                let accept_future = {
                    let mut accept_error: Option<std::io::Error> = None;

                    let accept_future = tls_acceptor.accept_with(server_stream, |server_conn| {
                        if let Some(size) = self.tls_buffer_size {
                            server_conn.set_buffer_limit(Some(size));
                        }

                        if let Err(e) = feed_server_connection(server_conn, &client_hello_frame) {
                            let _ = accept_error.insert(std::io::Error::other(
                                format!("Failed to feed initial frame to server connection: {}", e),
                            ));
                            return;
                        }
                        let unparsed_data = client_reader.unparsed_data();
                        if !unparsed_data.is_empty() {
                            if let Err(e) = feed_server_connection(server_conn, unparsed_data) {
                                let _ = accept_error.insert(std::io::Error::other(
                                    format!(
                                        "Failed to feed unparsed data to server connection: {}",
                                        e
                                    ),
                                ));
                                return;
                            }
                        }
                        if let Err(e) = server_conn.process_new_packets() {
                            let _ = accept_error.insert(std::io::Error::other(
                                format!("Failed to process new packets: {}", e),
                            ));
                        }
                    });

                    if let Some(e) = accept_error {
                        return Err(e);
                    }

                    accept_future
                };

                let tls_stream: Box<dyn AsyncStream> = Box::new(accept_future.await?);

                let mut target_setup_result = handler.setup_server_stream(tls_stream).await;
                if let Ok(ref mut setup_result) = target_setup_result {
                    setup_result.set_need_initial_flush(true);
                    if setup_result.override_proxy_provider_unspecified()
                        && !override_proxy_provider.is_unspecified()
                    {
                        setup_result.set_override_proxy_provider(override_proxy_provider.clone());
                    }
                }

                target_setup_result
            }
            TlsServerTarget::ShadowTls(ref target) => {
                setup_shadowtls_server_stream(
                    server_stream,
                    target,
                    parsed_client_hello,
                    &self.shadowtls_resolver,
                )
                .await
            }
        }
    }
}

#[derive(Debug)]
pub struct TlsClientHandler {
    pub client_config: Arc<rustls::ClientConfig>,
    pub tls_buffer_size: Option<usize>,
    pub server_name: rustls::pki_types::ServerName<'static>,
    pub handler: Box<dyn TcpClientHandler>,
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
                    if let Some(size) = self.tls_buffer_size {
                        client_conn.set_buffer_limit(Some(size));
                    }
                })
                .await?,
        );

        self.handler
            .setup_client_stream(server_stream, tls_stream, remote_location)
            .await
    }
}
