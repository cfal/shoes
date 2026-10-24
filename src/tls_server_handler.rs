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
        certificate_source: Option<Arc<crate::certificates::Source>>,
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

        let name = parsed_client_hello.requested_server_name.as_deref();
        let mut target = name
            .and_then(|name| self.sni_targets.get(name))
            .or(self.default_target.as_ref());
        // Case-insensitive ACME lookup must not change REALITY/ShadowTLS routing.
        if parsed_client_hello.acme_alpn
            && target.is_none_or(|target| matches!(target, TlsServerTarget::Tls { .. }))
        {
            target = name
                .and_then(|name| self.sni_targets.get(&name.to_ascii_lowercase()))
                .filter(|target| matches!(target, TlsServerTarget::Tls { .. }))
                .or(target);
        }
        let target = target.ok_or_else(|| match name {
            Some(name) => {
                std::io::Error::other(format!("No default target for unknown SNI: {name}"))
            }
            None => std::io::Error::other("No default target for unspecified SNI"),
        })?;

        match target {
            TlsServerTarget::Tls {
                certificate_source,
                server_config,
                effective_selector,
                inner_protocol,
            } => {
                if parsed_client_hello.acme_alpn {
                    let config = certificate_source
                        .as_ref()
                        .and_then(|source| {
                            source.challenge_config(
                                parsed_client_hello.requested_server_name.as_deref(),
                            )
                        })
                        .ok_or_else(|| {
                            std::io::Error::other("no pending TLS-ALPN-01 challenge for this SNI")
                        })?;
                    let mut connection =
                        rustls::ServerConnection::new(config).map_err(std::io::Error::other)?;
                    feed_rustls_server_connection(
                        &mut connection,
                        &parsed_client_hello.client_hello_frame,
                    )?;
                    connection
                        .process_new_packets()
                        .map_err(std::io::Error::other)?;
                    let mut stream = tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        CryptoTlsStream::handshake(
                            server_stream,
                            TlsConnection::new(connection),
                            TlsReadMode::Stream,
                            parsed_client_hello.client_reader.unparsed_data(),
                        ),
                    )
                    .await??;
                    tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        tokio::io::AsyncWriteExt::shutdown(&mut stream),
                    )
                    .await??;
                    return Ok(TcpServerSetupResult::Session(Box::pin(async {})));
                }
                let ParsedClientHello {
                    client_hello_frame,
                    client_reader,
                    ..
                } = parsed_client_hello;

                let config = match certificate_source {
                    Some(source) => source.snapshot(server_config),
                    None => server_config.clone(),
                };
                let mut server_conn = rustls::ServerConnection::new(config).map_err(|e| {
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
    async fn acme_offers_preserve_reality_forwarding_and_case_sensitive_routing() {
        use crate::client_proxy_chain::{ClientProxyChain, InitialHopEntry};
        use crate::tcp::socket_connector_impl::SocketConnectorImpl;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            for uppercase in [false, true] {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let dest = NetLocation::from_ip_addr(
                    listener.local_addr().unwrap().ip(),
                    listener.local_addr().unwrap().port(),
                );
                let selector = Arc::new(ClientProxySelector::new(Vec::new()));
                let reality = TlsServerTarget::Reality(RealityServerTarget {
                    mldsa65_key: None,
                    private_key: [1; 32],
                    short_ids: vec![[0; 8]],
                    dest: dest.clone(),
                    max_time_diff: None,
                    min_client_version: None,
                    max_client_version: None,
                    cipher_suites: Vec::new(),
                    effective_selector: selector.clone(),
                    inner_protocol: InnerProtocol::Normal(Box::new(PortForwardServerHandler::new(
                        vec![dest.clone()],
                        selector.clone(),
                    ))),
                    dest_client_chain: ClientProxyChain::new(
                        vec![InitialHopEntry::Direct(Arc::new(
                            SocketConnectorImpl::from_config(
                                &crate::config::ClientConfig::default(),
                                None,
                            )
                            .unwrap(),
                        ))],
                        Vec::new(),
                    ),
                });
                let mut targets = FxHashMap::default();
                let default = if uppercase {
                    let cert =
                        rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
                    targets.insert(
                        "proxy.test".into(),
                        TlsServerTarget::Tls {
                            certificate_source: None,
                            server_config: Arc::new(server_config(&cert)),
                            effective_selector: selector.clone(),
                            inner_protocol: InnerProtocol::Normal(Box::new(
                                PortForwardServerHandler::new(vec![dest], selector),
                            )),
                        },
                    );
                    Some(reality)
                } else {
                    targets.insert("proxy.test".into(), reality);
                    None
                };
                let handler = TlsServerHandler::new(
                    targets,
                    default,
                    None,
                    Arc::new(crate::resolver::NativeResolver::new()),
                );
                let mut config = rustls::ClientConfig::builder_with_protocol_versions(&[
                    &rustls::version::TLS12,
                ])
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();
                config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
                if !uppercase {
                    config.alpn_protocols.push(b"h2".to_vec());
                }
                let name = if uppercase {
                    "PROXY.TEST"
                } else {
                    "proxy.test"
                };
                let mut client =
                    rustls::ClientConnection::new(Arc::new(config), name.try_into().unwrap())
                        .unwrap();
                let mut hello = Vec::new();
                client.write_tls(&mut hello).unwrap();
                let (server, mut peer) = tokio::io::duplex(65536);
                peer.write_all(&hello).await.unwrap();
                let decoy = async {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut received = vec![0; hello.len()];
                    socket.read_exact(&mut received).await.unwrap();
                    assert_eq!(received, hello);
                };
                let (result, ()) =
                    tokio::join!(handler.setup_server_stream(Box::new(server)), decoy);
                assert!(matches!(result.unwrap(), TcpServerSetupResult::Session(_)));
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn client_hellos_split_across_records_complete_the_handshake() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_config = server_config(&cert);
        let selector = Arc::new(ClientProxySelector::new(Vec::new()));
        let target = TlsServerTarget::Tls {
            certificate_source: None,
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
