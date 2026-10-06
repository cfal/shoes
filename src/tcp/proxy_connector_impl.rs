//! ProxyConnectorImpl - Implementation of ProxyConnector trait.
//!
//! Handles protocol setup for proxy connections on existing streams.
//! Created from the protocol-related fields of a ClientConfig.

use std::sync::Arc;

use async_trait::async_trait;
use log::debug;

use super::proxy_connector::ProxyConnector;
use super::tcp_client_handler_factory::create_tcp_client_handler;
use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::config::ClientConfig;
use crate::resolver::Resolver;
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};

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
}

impl ProxyConnectorImpl {
    /// Create a ProxyConnector from a ClientConfig's protocol-related fields.
    ///
    /// Returns None for direct protocol (direct has no ProxyConnector).
    pub fn from_config(config: ClientConfig, resolver: Arc<dyn Resolver>) -> Option<Self> {
        if config.protocol.is_direct() {
            return None;
        }

        let default_sni_hostname = config.address.address().hostname().map(ToString::to_string);

        Some(Self {
            location: config.address,
            client_handler: create_tcp_client_handler(
                config.protocol,
                default_sni_hostname,
                resolver,
            ),
        })
    }
}

#[async_trait]
impl ProxyConnector for ProxyConnectorImpl {
    fn proxy_location(&self) -> &NetLocation {
        &self.location
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.client_handler.supports_udp_over_tcp()
    }

    async fn try_reuse_tcp_stream(
        &self,
        target: &ResolvedLocation,
    ) -> std::io::Result<Option<TcpClientSetupResult>> {
        self.client_handler.try_reuse_tcp_stream(target).await
    }

    async fn setup_tcp_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        target: &ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
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
    use std::net::{IpAddr, Ipv4Addr};

    fn mock_resolver() -> Arc<dyn Resolver> {
        Arc::new(NativeResolver::new())
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
            Ok(Box::new(
                self.stream
                    .lock()
                    .unwrap()
                    .take()
                    .expect("unexpected redundant dial"),
            ))
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
            location: NetLocation::from_str("localhost:443", None).unwrap(),
            client_handler: Box::new(TlsClientHandler::new(
                client_config,
                None,
                "localhost".try_into().unwrap(),
                Box::new(NaiveProxyTcpClientHandler::new("user", "pass", false)),
            )),
        };
        let chain = ClientProxyChain::new(
            vec![InitialHopEntry::Proxy {
                socket: Box::new(OneTransport {
                    stream: std::sync::Mutex::new(Some(client)),
                    connects: connects.clone(),
                }),
                proxy: Box::new(proxy),
            }],
            vec![],
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            for payload in [b"cold request".as_slice(), b"warm request"] {
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
    fn test_from_direct_config_returns_none() {
        let config = ClientConfig::default();
        assert!(config.protocol.is_direct());
        assert!(ProxyConnectorImpl::from_config(config, mock_resolver()).is_none());
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
        let connector = ProxyConnectorImpl::from_config(config, mock_resolver());
        assert!(connector.is_some());
        let connector = connector.unwrap();
        assert_eq!(connector.proxy_location().port(), 1080);
    }
}
