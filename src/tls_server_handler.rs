use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use rustc_hash::FxHashMap;

use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::crypto::perform_crypto_handshake;
use crate::crypto::{CryptoConnection, CryptoTlsStream};
use crate::naiveproxy::UserLookup;
use crate::reality::{RealityServerTarget, setup_reality_server_stream};
use crate::resolver::Resolver;
use crate::rustls_connection_util::feed_rustls_server_connection;
use crate::shadow_tls::{
    ParsedClientHello, ShadowTlsServerTarget, read_client_hello, setup_shadowtls_server_stream,
};
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

use crate::address::NetLocation;

/// Configuration for Vision VLESS inner protocol
#[derive(Debug, Clone)]
pub struct VisionVlessConfig {
    pub user_id: Box<[u8]>,
    pub udp_enabled: bool,
    pub fallback: Option<NetLocation>,
}

/// Configuration for NaiveProxy inner protocol
#[derive(Debug, Clone)]
pub struct NaiveConfig {
    pub users: Arc<UserLookup>,
    pub fallback_path: Option<PathBuf>,
    pub udp_enabled: bool,
    pub padding_enabled: bool,
}

/// What to do after TLS/Reality termination.
///
/// This enum unifies the previous `handler` + `vision_config` pattern into
/// a single field that represents the inner protocol handling.
#[derive(Debug)]
pub enum InnerProtocol {
    /// Normal handler (standard behavior for most protocols like
    /// VMess, VLESS without Vision, Shadowsocks, Trojan, etc.)
    Normal(Box<dyn TcpServerHandler>),

    /// Vision VLESS - specialized VLESS handling with Vision flow control
    VisionVless(VisionVlessConfig),

    /// NaiveProxy - hyper-based HTTP/2 proxy with built-in static file fallback
    Naive(NaiveConfig),
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum TlsServerTarget {
    Tls {
        server_config: Arc<rustls::ServerConfig>,
        /// The effective proxy selector for this TLS target.
        /// This selector is passed to inner handlers at construction and should be used
        /// for routing decisions. For Vision mode, this is passed to the VLESS setup function.
        effective_selector: Arc<ClientProxySelector>,
        /// What to do after TLS termination - normal handler, Vision VLESS, or Naive
        inner_protocol: InnerProtocol,
    },
    ShadowTls(ShadowTlsServerTarget),
    Reality(RealityServerTarget),
}

#[derive(Debug)]
pub struct TlsServerHandler {
    sni_targets: FxHashMap<String, TlsServerTarget>,
    default_target: Option<TlsServerTarget>,
    // used to resolve ShadowTLS handshake server hostnames and reality fallback destinations
    fallback_resolver: Arc<dyn Resolver>,
    tls_buffer_size: Option<usize>,
}

impl TlsServerHandler {
    pub fn new(
        sni_targets: FxHashMap<String, TlsServerTarget>,
        default_target: Option<TlsServerTarget>,
        tls_buffer_size: Option<usize>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        Self {
            sni_targets,
            default_target,
            fallback_resolver: resolver,
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
                        return Err(std::io::Error::other(format!(
                            "No default target for unknown SNI: {hostname}"
                        )));
                    }
                },
            },
        };

        match target {
            TlsServerTarget::Tls {
                server_config,
                effective_selector,
                inner_protocol,
            } => {
                let ParsedClientHello {
                    client_hello_frame,
                    client_reader,
                    ..
                } = parsed_client_hello;

                let mut server_conn = rustls::ServerConnection::new(server_config.clone())
                    .map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("Failed to create server connection: {e}"),
                        )
                    })?;

                if let Some(size) = self.tls_buffer_size {
                    server_conn.set_buffer_limit(Some(size));
                }

                // Feed the already-parsed ClientHello into rustls
                feed_rustls_server_connection(&mut server_conn, &client_hello_frame)?;
                server_conn.process_new_packets().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Failed to process ClientHello: {e}"),
                    )
                })?;

                let unparsed_data = client_reader.unparsed_data();
                if !unparsed_data.is_empty() {
                    feed_rustls_server_connection(&mut server_conn, unparsed_data)?;
                    server_conn.process_new_packets().map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("Failed to process client handshake data: {e}"),
                        )
                    })?;
                }

                let mut connection = CryptoConnection::new_rustls_server(server_conn);
                perform_crypto_handshake(&mut connection, &mut server_stream, 16384).await?;
                let tls_stream = CryptoTlsStream::new(server_stream, connection);

                let mut target_setup_result = match inner_protocol {
                    InnerProtocol::Normal(handler) => {
                        handler.setup_server_stream(Box::new(tls_stream)).await
                    }
                    InnerProtocol::VisionVless(vision_cfg) => {
                        crate::vless::vless_server_handler::setup_custom_tls_vision_vless_server_stream(
                            tls_stream,
                            &vision_cfg.user_id,
                            vision_cfg.udp_enabled,
                            effective_selector.clone(),
                            &self.fallback_resolver,
                            vision_cfg.fallback.clone(),
                        )
                        .await
                    }
                    InnerProtocol::Naive(naive_cfg) => {
                        crate::naiveproxy::setup_naive_server_stream(
                            tls_stream,
                            naive_cfg,
                            effective_selector.clone(),
                            self.fallback_resolver.clone(),
                        )
                        .await
                    }
                };

                if let Ok(ref mut setup_result) = target_setup_result {
                    if matches!(setup_result, TcpServerSetupResult::AlreadyHandled) {
                        return target_setup_result;
                    }
                    setup_result.set_need_initial_flush(true);
                }

                target_setup_result
            }
            TlsServerTarget::ShadowTls(target) => {
                setup_shadowtls_server_stream(
                    server_stream,
                    target,
                    parsed_client_hello,
                    &self.fallback_resolver,
                )
                .await
            }
            TlsServerTarget::Reality(target) => {
                setup_reality_server_stream(
                    server_stream,
                    target,
                    parsed_client_hello,
                    &self.fallback_resolver,
                )
                .await
            }
        }
    }
}
