use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use rustc_hash::FxHashMap;

use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::crypto::{CryptoTlsStream, TlsConnection, TlsReadMode};
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

                let mode = match inner_protocol {
                    InnerProtocol::VisionVless(_) => TlsReadMode::PreserveRecords,
                    _ => TlsReadMode::Stream,
                };
                let connection = TlsConnection::new(server_conn);
                let tls_stream = CryptoTlsStream::handshake(
                    server_stream,
                    connection,
                    mode,
                    client_reader.unparsed_data(),
                )
                .await?;

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
                    if matches!(setup_result, TcpServerSetupResult::Session(_)) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::port_forward_handler::PortForwardServerHandler;

    fn server_config(cert: &rcgen::CertifiedKey<rcgen::KeyPair>) -> rustls::ServerConfig {
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
                    .into(),
            )
            .unwrap()
    }

    #[test]
    fn large_client_hellos_split_into_tiny_records_reach_rustls() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut padding = vec![0xff, 0xa5, 0x10, 0x00];
        padding.resize(4 + 0x1000, 0);
        let hello = crate::sniff::tests::extend_hello(
            crate::sniff::tests::hello(&rustls::version::TLS13, true),
            &padding,
        );
        let records = crate::sniff::tests::records(&hello, 1);
        let mut connection = rustls::ServerConnection::new(Arc::new(server_config(&cert))).unwrap();
        feed_rustls_server_connection(&mut connection, &records).unwrap();
        connection.process_new_packets().unwrap();
        assert!(
            connection.wants_write(),
            "rustls must answer the reassembled ClientHello"
        );
    }

    #[tokio::test]
    async fn client_hellos_split_across_records_complete_the_handshake() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_config = server_config(&cert);
        let selector = Arc::new(ClientProxySelector::new(Vec::new()));
        let target = TlsServerTarget::Tls {
            server_config: Arc::new(server_config),
            effective_selector: selector.clone(),
            inner_protocol: InnerProtocol::Normal(Box::new(PortForwardServerHandler::new(
                vec![NetLocation::new(
                    crate::address::Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                    9,
                )],
                selector,
            ))),
        };
        let handler = TlsServerHandler::new(
            FxHashMap::default(),
            Some(target),
            None,
            Arc::new(crate::resolver::NativeResolver::new()),
        );
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let mut client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        // The smallest fragment rustls allows splits the ClientHello across many records.
        client_config.max_fragment_size = Some(32);
        let (server_io, client_io) = tokio::io::duplex(65536);
        let client = async {
            tokio_rustls::TlsConnector::from(Arc::new(client_config))
                .connect("localhost".try_into().unwrap(), client_io)
                .await
        };
        let (setup, client) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(handler.setup_server_stream(Box::new(server_io)), client)
        })
        .await
        .unwrap();
        setup.unwrap();
        client.unwrap();
    }
}
