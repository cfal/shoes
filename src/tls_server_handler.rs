use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use rustc_hash::FxHashMap;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::crypto::perform_crypto_handshake;
use crate::crypto::{CryptoConnection, CryptoTlsStream};
use crate::option_util::NoneOrOne;
use crate::reality::{
    RealityServerConfig, RealityServerConnection, feed_reality_server_connection,
};
use crate::resolver::{NativeResolver, Resolver};
use crate::rustls_connection_util::feed_rustls_server_connection;
use crate::shadow_tls::{
    ParsedClientHello, ShadowTlsServerTarget, read_client_hello, setup_shadowtls_server_stream,
};
use crate::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

#[derive(Debug, Clone)]
pub struct VisionConfig {
    pub user_id: Box<[u8]>,
    pub udp_enabled: bool,
}

#[derive(Debug)]
pub struct RealityServerTarget {
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
    pub dest: NetLocation,
    pub max_time_diff: Option<u64>, // in milliseconds
    pub min_client_version: Option<[u8; 3]>,
    pub max_client_version: Option<[u8; 3]>,
    pub cipher_suites: Vec<crate::reality::CipherSuite>,
    pub handler: Box<dyn TcpServerHandler>,
    pub override_proxy_provider: NoneOrOne<Arc<ClientProxySelector>>,
    pub vision_config: Option<VisionConfig>,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum TlsServerTarget {
    Tls {
        server_config: Arc<rustls::ServerConfig>,
        handler: Box<dyn TcpServerHandler>,
        override_proxy_provider: NoneOrOne<Arc<ClientProxySelector>>,
        vision_config: Option<VisionConfig>,
    },
    ShadowTls(ShadowTlsServerTarget),
    Reality(RealityServerTarget),
}

#[derive(Debug)]
pub struct TlsServerHandler {
    sni_targets: FxHashMap<String, TlsServerTarget>,
    default_target: Option<TlsServerTarget>,
    // used to resolve handshake server hostnames
    shadowtls_resolver: Arc<dyn Resolver>,
    tls_buffer_size: Option<usize>,
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
                handler,
                override_proxy_provider,
                vision_config,
            } => {
                let ParsedClientHello {
                    client_hello_frame,
                    client_reader,
                    ..
                } = parsed_client_hello;

                // Create rustls ServerConnection
                let mut server_conn = rustls::ServerConnection::new(server_config.clone())
                    .map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("Failed to create server connection: {e}"),
                        )
                    })?;

                // Set buffer limits if configured
                if let Some(size) = self.tls_buffer_size {
                    server_conn.set_buffer_limit(Some(size));
                }

                // Feed the ClientHello we already parsed
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

                // Perform the TLS handshake using the generic helper
                // This works for both TLS 1.2 and TLS 1.3
                let mut connection = CryptoConnection::new_rustls_server(server_conn);
                perform_crypto_handshake(&mut connection, &mut server_stream, 16384).await?;

                // Wrap in CryptoTlsStream
                let tls_stream = CryptoTlsStream::new(server_stream, connection);

                let mut target_setup_result = if let Some(vision_cfg) = vision_config {
                    // Vision is enabled - call setup_custom_tls_vision_vless_server_stream
                    crate::vless::vless_server_handler::setup_custom_tls_vision_vless_server_stream(
                        tls_stream,
                        &vision_cfg.user_id,
                        vision_cfg.udp_enabled,
                    )
                    .await
                } else {
                    // Regular TLS - call inner handler
                    handler.setup_server_stream(Box::new(tls_stream)).await
                };

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
            TlsServerTarget::ShadowTls(target) => {
                setup_shadowtls_server_stream(
                    server_stream,
                    target,
                    parsed_client_hello,
                    &self.shadowtls_resolver,
                )
                .await
            }
            TlsServerTarget::Reality(target) => {
                // Note: Vision over Reality would require updating setup_vision_vless_server_stream
                // to accept CryptoTlsStream instead of tokio_rustls::server::TlsStream.
                // For now, vision_config should always be None for Reality targets.
                // This will be enforced in tcp_handler_util.rs

                let client_hello_frame = &parsed_client_hello.client_hello_frame;
                log::debug!(
                    "REALITY ClientHello frame length: {}",
                    client_hello_frame.len()
                );

                // Create buffered REALITY connection
                let reality_config = RealityServerConfig {
                    private_key: target.private_key,
                    short_ids: target.short_ids.clone(),
                    dest: target.dest.clone(),
                    max_time_diff: target.max_time_diff,
                    min_client_version: target.min_client_version,
                    max_client_version: target.max_client_version,
                    cipher_suites: target.cipher_suites.clone(),
                };

                let mut reality_conn = RealityServerConnection::new(reality_config)?;

                // Feed the ClientHello to the connection
                feed_reality_server_connection(&mut reality_conn, client_hello_frame)?;

                // Process the ClientHello to advance handshake (this validates everything)
                log::debug!("Processing REALITY ClientHello via process_new_packets");
                if let Err(e) = reality_conn.process_new_packets() {
                    // Check if this is an authentication failure
                    if e.kind() == std::io::ErrorKind::PermissionDenied {
                        log::warn!(
                            "REALITY authentication failed, falling back to dest: {} - reason: {}",
                            target.dest,
                            e
                        );
                        // Implement fallback mechanism
                        // TODO: disable server stream setup timeout?
                        return reality_fallback_to_dest(
                            server_stream,
                            client_hello_frame,
                            &target.dest,
                        )
                        .await;
                    } else {
                        // Other errors should propagate normally
                        return Err(e);
                    }
                }

                let mut connection = CryptoConnection::new_reality_server(reality_conn);
                perform_crypto_handshake(&mut connection, &mut server_stream, 16384).await?;

                // Wrap in Connection enum and CryptoTlsStream
                log::debug!("REALITY DEBUG: Wrapping in CryptoTlsStream");
                let tls_stream = CryptoTlsStream::new(server_stream, connection);

                log::debug!("REALITY DEBUG: TLS 1.3 handshake completed successfully");

                // Check if Vision is enabled
                let mut target_setup_result = if let Some(vision_cfg) = &target.vision_config {
                    // Vision is enabled - call setup_vision_vless_server_stream_from_custom_tls
                    crate::vless::vless_server_handler::setup_custom_tls_vision_vless_server_stream(
                        tls_stream,
                        &vision_cfg.user_id,
                        vision_cfg.udp_enabled,
                    )
                    .await
                } else {
                    // Regular REALITY (no Vision) - call inner handler
                    target
                        .handler
                        .setup_server_stream(Box::new(tls_stream))
                        .await
                };
                if let Ok(ref mut setup_result) = target_setup_result {
                    setup_result.set_need_initial_flush(true);
                    if setup_result.override_proxy_provider_unspecified()
                        && !target.override_proxy_provider.is_unspecified()
                    {
                        setup_result
                            .set_override_proxy_provider(target.override_proxy_provider.clone());
                    }
                }

                target_setup_result
            }
        }
    }
}

/// Fallback mechanism for Reality authentication failures
///
/// When a client fails Reality authentication (invalid short_id, timestamp, or version),
/// instead of dropping the connection, we transparently forward it to the configured
/// destination server. This makes the server indistinguishable from a legitimate
/// reverse proxy or CDN, defeating active probing attacks.
async fn reality_fallback_to_dest(
    mut client_stream: Box<dyn AsyncStream>,
    client_hello_bytes: &[u8],
    dest: &NetLocation,
) -> std::io::Result<TcpServerSetupResult> {
    log::info!("REALITY FALLBACK: Connecting to dest server: {}", dest);

    /// Shared resolver instance for Reality fallback connections
    /// Using LazyLock to avoid creating a new resolver for each fallback connection
    static REALITY_FALLBACK_RESOLVER: LazyLock<Arc<dyn Resolver>> =
        LazyLock::new(|| Arc::new(NativeResolver::new()));

    // Resolve and connect to the fallback destination using shared resolver
    let dest_addr =
        crate::resolver::resolve_single_address(&REALITY_FALLBACK_RESOLVER, dest).await?;

    log::debug!("REALITY FALLBACK: Resolved {} to {}", dest, dest_addr);

    let mut dest_stream: Box<dyn AsyncStream> = Box::new(TcpStream::connect(dest_addr).await?);

    log::info!(
        "REALITY FALLBACK: Connected to dest, forwarding ClientHello ({} bytes)",
        client_hello_bytes.len()
    );

    // Forward the raw ClientHello that we received from the client
    dest_stream.write_all(client_hello_bytes).await?;
    dest_stream.flush().await?;

    log::info!("REALITY FALLBACK: ClientHello forwarded, entering bidirectional mode");

    // Enter bidirectional forwarding mode
    // This will copy all traffic between client and dest transparently
    crate::copy_bidirectional::copy_bidirectional(
        &mut *client_stream,
        &mut *dest_stream,
        false, // client doesn't need initial flush
        false, // dest doesn't need initial flush
    )
    .await?;

    log::info!("REALITY FALLBACK: Bidirectional forwarding completed");

    // Connection handled, no further setup needed
    // Return an error to signal that this connection has been fully handled
    Err(std::io::Error::other(
        "Connection handled by Reality fallback mechanism",
    ))
}
