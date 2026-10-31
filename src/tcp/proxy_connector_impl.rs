//! ProxyConnectorImpl - Implementation of ProxyConnector trait.
//!
//! Handles protocol setup for proxy connections on existing streams.
//! Created from the protocol-related fields of a ClientConfig.

use std::sync::Arc;

use async_trait::async_trait;
use log::debug;

use super::carrier_dialer::CarrierDialer;
use super::proxy_connector::ProxyConnector;
use super::tcp_client_handler_factory::create_tcp_client_handler;
use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::config::ClientConfig;
use crate::resolver::Resolver;
use crate::tcp::tcp_handler::{ClientTransport, TcpClientHandler, TcpClientSetupResult};

pub(crate) fn create_proxy_connector(
    config: ClientConfig,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Option<Box<dyn ProxyConnector>>> {
    if config.protocol.is_native_quic() {
        return Ok(Some(Box::new(crate::quic_client::Client::new(config)?)));
    }
    Ok(ProxyConnectorImpl::from_config(config, resolver)?
        .map(|connector| Box::new(connector) as Box<dyn ProxyConnector>))
}

/// Implementation of ProxyConnector for proxy protocol setup.
///
/// Created from the protocol-related fields of a ClientConfig:
/// - `protocol`
/// - `address`
///
/// This connector only wraps protocols on existing streams - it does not
/// create socket connections. Socket creation is handled by SocketConnector.
#[derive(Debug)]
pub struct ProxyConnectorImpl {
    location: NetLocation,
    client_handler: Box<dyn TcpClientHandler>,
    xhttp: Option<Arc<crate::xhttp::client::Client>>,
}

impl ProxyConnectorImpl {
    fn client_transport(&self, dialer: Arc<dyn CarrierDialer>) -> ClientTransport<'_> {
        ClientTransport {
            route: dialer.clone(),
            open: Box::pin(async move {
                match &self.xhttp {
                    Some(client) => {
                        Ok(Box::new(client.open(dialer).await?) as Box<dyn AsyncStream>)
                    }
                    None => dialer.open_stream().await,
                }
            }),
        }
    }

    /// Create a ProxyConnector from a ClientConfig's protocol-related fields.
    ///
    /// Returns None for direct protocol (direct has no ProxyConnector).
    pub fn from_config(
        config: ClientConfig,
        resolver: Arc<dyn Resolver>,
    ) -> std::io::Result<Option<Self>> {
        crate::sudoku_mask::validate_client(&config.protocol, &config.transport)?;
        if config.protocol.is_direct() {
            return Ok(None);
        }

        if let Some((xhttp, client_handler)) =
            crate::xhttp::connector::build(&config, resolver.clone())?
        {
            return Ok(Some(Self {
                location: config.address,
                client_handler,
                xhttp: Some(xhttp),
            }));
        }

        let client_handler = create_tcp_client_handler(config.protocol, &config.address, resolver)?;

        Ok(Some(Self {
            xhttp: None,
            location: config.address,
            client_handler,
        }))
    }
}

#[async_trait]
impl ProxyConnector for ProxyConnectorImpl {
    async fn prepare_target(
        &self,
        target: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<ResolvedLocation> {
        self.client_handler.prepare_target(target, resolver).await
    }

    fn needs_carrier_dialer(&self) -> bool {
        self.xhttp.is_some() || self.client_handler.has_session_pool()
    }

    async fn connect_tcp_with_dialer(
        &self,
        dialer: Arc<dyn CarrierDialer>,
        target: &ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        self.client_handler
            .connect_client_tcp(self.client_transport(dialer), target.clone())
            .await
    }

    async fn connect_udp_with_dialer(
        &self,
        dialer: Arc<dyn CarrierDialer>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        self.client_handler
            .connect_client_udp(self.client_transport(dialer), target)
            .await
    }

    fn proxy_location(&self) -> &NetLocation {
        &self.location
    }

    fn supports_udp(&self) -> bool {
        self.client_handler.supports_udp_over_tcp()
    }

    async fn try_reuse_tcp_stream(
        &self,
        target: &ResolvedLocation,
    ) -> std::io::Result<Option<TcpClientSetupResult>> {
        if self.xhttp.is_some() {
            return Ok(None);
        }
        self.client_handler.try_reuse_tcp_stream(target).await
    }

    async fn setup_tcp_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        target: &ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        if self.xhttp.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "XHTTP requires a carrier dialer",
            ));
        }
        debug!(
            "[ProxyConnector] setup_tcp_stream: {} -> {}",
            self.location, target
        );
        self.client_handler
            .setup_client_tcp_stream(stream, target.clone())
            .await
    }

    async fn setup_udp_bidirectional(
        &self,
        stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if self.xhttp.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "XHTTP requires a carrier dialer",
            ));
        }
        debug!(
            "[ProxyConnector] setup_udp_bidirectional: {} -> {}",
            self.location, target
        );
        self.client_handler
            .setup_client_udp_bidirectional(stream, target)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientProxyConfig;
    use crate::resolver::NativeResolver;
    use crate::tcp::carrier_dialer::RouteKey;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn mock_resolver() -> Arc<dyn Resolver> {
        Arc::new(NativeResolver::new())
    }

    #[derive(Debug)]
    struct UnopenedDialer(RouteKey);

    #[async_trait]
    impl CarrierDialer for UnopenedDialer {
        fn route_key(&self) -> &RouteKey {
            &self.0
        }

        async fn open_stream(&self) -> std::io::Result<Box<dyn AsyncStream>> {
            panic!("pool hit must not open a carrier")
        }
    }

    #[derive(Debug)]
    struct PoolProbe {
        open_transport: bool,
    }

    const PROBE_PAYLOAD: &[u8] = b"cleartext probe";

    impl PoolProbe {
        async fn probe(&self, transport: ClientTransport<'_>) -> std::io::Result<()> {
            if self.open_transport {
                let mut stream = transport.open.await?;
                stream.write_all(PROBE_PAYLOAD).await?;
                stream.flush().await?;
            }
            Ok(())
        }
    }

    #[async_trait]
    impl TcpClientHandler for PoolProbe {
        fn has_session_pool(&self) -> bool {
            true
        }

        async fn connect_client_tcp(
            &self,
            transport: ClientTransport<'_>,
            _: ResolvedLocation,
        ) -> std::io::Result<TcpClientSetupResult> {
            self.probe(transport).await?;
            Err(std::io::Error::other("TCP pool reached"))
        }

        async fn connect_client_udp(
            &self,
            transport: ClientTransport<'_>,
            _: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            self.probe(transport).await?;
            Err(std::io::Error::other("UDP pool reached"))
        }

        async fn setup_client_tcp_stream(
            &self,
            _: Box<dyn AsyncStream>,
            _: ResolvedLocation,
        ) -> std::io::Result<TcpClientSetupResult> {
            panic!("pool hit must use the lazy connect path")
        }
    }

    async fn assert_pool_forwarding(connector: &ProxyConnectorImpl) {
        assert!(connector.client_handler.has_session_pool());
        assert!(connector.needs_carrier_dialer());
        let dialer = Arc::new(UnopenedDialer(RouteKey(vec![1])));
        let target = NetLocation::from_str("example.com:443", None)
            .unwrap()
            .into();
        assert_eq!(
            connector
                .connect_tcp_with_dialer(dialer.clone(), &target)
                .await
                .err()
                .unwrap()
                .to_string(),
            "TCP pool reached"
        );
        assert_eq!(
            connector
                .connect_udp_with_dialer(dialer, target)
                .await
                .err()
                .unwrap()
                .to_string(),
            "UDP pool reached"
        );
    }

    fn wrapper_handlers(open_transport: bool) -> Vec<(&'static str, Box<dyn TcpClientHandler>)> {
        let tls = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        );
        let sudoku: crate::sudoku_mask::SudokuMaskConfig<()> =
            serde_json::from_value(serde_json::json!({"protocol": null})).unwrap();
        let mut public_key = [0; 32];
        public_key[0] = 9;
        let inner = || Box::new(PoolProbe { open_transport }) as Box<dyn TcpClientHandler>;
        vec![
            (
                "tls",
                Box::new(crate::tls_client_handler::TlsClientHandler::new(
                    tls.clone(),
                    None,
                    "localhost".try_into().unwrap(),
                    inner(),
                )),
            ),
            (
                "reality",
                Box::new(crate::reality::RealityClientHandler::new(
                    public_key,
                    [0; 8],
                    "localhost".try_into().unwrap(),
                    vec![],
                    inner(),
                )),
            ),
            (
                "shadowtls",
                Box::new(crate::shadow_tls::ShadowTlsClientHandler::new(
                    "test".into(),
                    tls,
                    "localhost".try_into().unwrap(),
                    inner(),
                )),
            ),
            (
                "websocket",
                Box::new(crate::websocket::WebsocketTcpClientHandler::new(
                    "localhost:443".into(),
                    None,
                    None,
                    Default::default(),
                    inner(),
                )),
            ),
            (
                "sudoku",
                Box::new(crate::sudoku_mask::handler::ClientHandler {
                    config: sudoku.prepare().unwrap(),
                    inner: inner(),
                }),
            ),
        ]
    }

    #[tokio::test]
    async fn every_wrapper_forwards_pool_hits_without_opening_the_transport() {
        for (_, client_handler) in wrapper_handlers(false) {
            let connector = ProxyConnectorImpl {
                location: NetLocation::from_str("localhost:443", None).unwrap(),
                client_handler,
                xhttp: None,
            };
            assert_pool_forwarding(&connector).await;
        }
    }

    #[tokio::test]
    async fn every_wrapper_wraps_the_transport_on_pool_misses() {
        for udp in [false, true] {
            for (name, handler) in wrapper_handlers(true) {
                tokio::time::timeout(std::time::Duration::from_secs(2), async {
                    let (client, mut peer) = tokio::io::duplex(4096);
                    let transport = ClientTransport {
                        route: Arc::new(UnopenedDialer(RouteKey(vec![1]))),
                        open: Box::pin(async { Ok(Box::new(client) as Box<dyn AsyncStream>) }),
                    };
                    let target = NetLocation::from_str("example.com:443", None)
                        .unwrap()
                        .into();
                    let connect = async {
                        if udp {
                            let _ = handler.connect_client_udp(transport, target).await;
                        } else {
                            let _ = handler.connect_client_tcp(transport, target).await;
                        }
                    };
                    let inspect = async {
                        let mut prefix = [0; 4];
                        peer.read_exact(&mut prefix).await.unwrap();
                        match name {
                            "websocket" => assert_eq!(&prefix, b"GET "),
                            "sudoku" => assert_ne!(&prefix, &PROBE_PAYLOAD[..4]),
                            _ => assert_eq!(&prefix[..2], &[0x16, 0x03]),
                        }
                        // Closing the peer ends handshakes after their first flight.
                        drop(peer);
                    };
                    tokio::join!(connect, inspect);
                })
                .await
                .unwrap_or_else(|_| panic!("wrapper did not emit bytes: {name}, udp={udp}"));
            }
        }
    }

    #[tokio::test]
    async fn xhttp_pool_hits_do_not_open_the_transport() {
        let config = serde_json::from_value(serde_json::json!({
            "address": "localhost:443",
            "protocol": {"type": "xhttp", "mode": "stream-one", "protocol": {"type": "socks"}}
        }))
        .unwrap();
        let mut connector = ProxyConnectorImpl::from_config(config, mock_resolver())
            .unwrap()
            .unwrap();
        assert!(connector.xhttp.is_some());
        connector.client_handler = Box::new(PoolProbe {
            open_transport: false,
        });
        assert_pool_forwarding(&connector).await;
    }

    #[derive(Debug)]
    struct OneTransport {
        stream: std::sync::Mutex<Option<tokio::io::DuplexStream>>,
        connects: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl crate::tcp::socket_connector::SocketConnector for OneTransport {
        async fn connect(
            &self,
            _: &Arc<dyn Resolver>,
            _: &ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncStream>> {
            self.connects
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(Box::new(self.stream.lock().unwrap().take().ok_or_else(
                || std::io::Error::other("unexpected redundant dial"),
            )?))
        }
        async fn connect_udp_bidirectional(
            &self,
            _: &Arc<dyn Resolver>,
            _: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            unreachable!()
        }
        fn bind_interface(&self) -> Option<&str> {
            None
        }
    }

    #[tokio::test]
    async fn warm_naive_streams_share_one_socket_and_tls_handshake() {
        check_warm_naive_reuse(false).await;
    }

    #[tokio::test]
    async fn mixed_xhttp_pool_preserves_warm_naive_reuse() {
        check_warm_naive_reuse(true).await;
    }

    async fn check_warm_naive_reuse(mixed: bool) {
        use crate::client_proxy_chain::{ClientProxyChain, InitialHopEntry};
        use crate::naiveproxy::NaiveProxyTcpClientHandler;
        use crate::tls_client_handler::TlsClientHandler;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
                    .into(),
            )
            .unwrap();
        let client_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let (client, peer) = tokio::io::duplex(4096);
        let peer = tokio::spawn(async move {
            let tls = tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
                .accept(peer)
                .await
                .unwrap();
            let mut h2 = h2::server::handshake(tls).await.unwrap();
            let mut echoes = tokio::task::JoinSet::new();
            while let Some(request) = h2.accept().await {
                let (request, mut respond) = request.unwrap();
                assert_eq!(
                    request.uri().authority().unwrap().as_str(),
                    "example.com:443"
                );
                let mut send = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                echoes.spawn(async move {
                    let mut receive = request.into_body();
                    let mut payload = Vec::new();
                    while let Some(data) = receive.data().await {
                        let data = data.unwrap();
                        receive.flow_control().release_capacity(data.len()).unwrap();
                        payload.extend_from_slice(&data);
                    }
                    send.send_data(payload.into(), true).unwrap();
                });
            }
        });
        let connects = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let proxy = ProxyConnectorImpl {
            xhttp: None,
            location: NetLocation::from_str("localhost:443", None).unwrap(),
            client_handler: Box::new(TlsClientHandler::new(
                client_config,
                None,
                "localhost".try_into().unwrap(),
                Box::new(NaiveProxyTcpClientHandler::new("user", "pass", false)),
            )),
        };
        let mut entries = vec![InitialHopEntry::Proxy {
            socket: Arc::new(OneTransport {
                stream: std::sync::Mutex::new(Some(client)),
                connects: connects.clone(),
            }),
            proxy: Box::new(proxy),
        }];
        if mixed {
            let config = serde_json::from_value(serde_json::json!({
                "address": "localhost:443",
                "protocol": {"type": "xhttp", "mode": "stream-one", "protocol": {"type": "socks"}}
            }))
            .unwrap();
            entries.push(InitialHopEntry::Proxy {
                socket: Arc::new(OneTransport {
                    stream: std::sync::Mutex::new(None),
                    connects: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                }),
                proxy: Box::new(
                    ProxyConnectorImpl::from_config(config, mock_resolver())
                        .unwrap()
                        .unwrap(),
                ),
            });
        }
        let chain = ClientProxyChain::new(entries, vec![]);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            for (index, payload) in [b"cold request".as_slice(), b"warm request"]
                .into_iter()
                .enumerate()
            {
                let target = NetLocation::from_str("example.com:443", None)
                    .unwrap()
                    .into();
                let mut stream = chain
                    .connect_tcp(target, &mock_resolver())
                    .await
                    .unwrap()
                    .client_stream;
                stream.write_all(payload).await.unwrap();
                stream.shutdown().await.unwrap();
                let mut response = Vec::new();
                stream.read_to_end(&mut response).await.unwrap();
                assert_eq!(response, payload);
                if mixed && index == 0 {
                    let target = NetLocation::from_str("example.com:443", None)
                        .unwrap()
                        .into();
                    assert!(chain.connect_tcp(target, &mock_resolver()).await.is_err());
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(connects.load(std::sync::atomic::Ordering::Relaxed), 1);
        drop(chain);
        peer.abort();
        let _ = peer.await;
    }

    #[test]
    fn malformed_protocol_settings_return_errors_without_validation() {
        for protocol in [
            serde_json::json!({"type": "reality", "public_key": "invalid", "sni_hostname": "example.com", "protocol": {"type": "socks"}}),
            serde_json::json!({"type": "reality", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "protocol": {"type": "socks"}}),
            serde_json::json!({"type": "anytls", "password": "test", "padding_scheme": ["stop=invalid"]}),
            serde_json::json!({"type": "reality", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "sni_hostname": "127.0.0.1", "protocol": {"type": "socks"}}),
            serde_json::json!({"type": "reality", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "sni_hostname": "::1", "protocol": {"type": "socks"}}),
            serde_json::json!({"type": "reality", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "sni_hostname": "example.com", "protocol": {"type": "direct"}}),
            serde_json::json!({"type": "tls", "protocol": {"type": "direct"}}),
            serde_json::json!({"type": "shadowtls", "password": "test", "protocol": {"type": "direct"}}),
            serde_json::json!({"type": "websocket", "protocol": {"type": "direct"}}),
        ] {
            let config = serde_json::from_value(serde_json::json!({
                "address": "127.0.0.1:443", "protocol": protocol
            }))
            .unwrap();
            assert!(ProxyConnectorImpl::from_config(config, mock_resolver()).is_err());
        }
    }

    #[test]
    fn test_from_direct_config_returns_none() {
        let config = ClientConfig::default();
        assert!(config.protocol.is_direct());
        assert!(
            ProxyConnectorImpl::from_config(config, mock_resolver())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_from_proxy_config_returns_some() {
        let config = ClientConfig {
            address: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1080),
            protocol: ClientProxyConfig::Socks {
                username: None,
                password: None,
            },
            ..Default::default()
        };
        let connector = ProxyConnectorImpl::from_config(config, mock_resolver()).unwrap();
        assert!(connector.is_some());
        let connector = connector.unwrap();
        assert_eq!(connector.proxy_location().port(), 1080);
    }
}
