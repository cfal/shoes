//! Custom RuntimeProvider that routes TCP connections through proxy chains.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::net::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::net::runtime::{QuicSocketBinder, RuntimeProvider, Spawn, TokioTime};

use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_chain::ClientChainGroup;
use crate::resolver::Resolver;

#[cfg(test)]
const TEST_CONNECT_TIMEOUT: Duration = Duration::from_millis(100);

/// RuntimeProvider that routes TCP connections through a proxy chain.
/// For direct-only chains, UDP and QUIC use the configured bind_interface.
#[derive(Clone)]
pub struct ProxyRuntimeProvider {
    chain_group: Arc<ClientChainGroup>,
    /// Resolver for proxy server hostnames (not the DNS queries themselves).
    /// Uses NativeResolver since we can't use the DNS server we're trying to reach.
    bootstrap_resolver: Arc<dyn Resolver>,
    /// Bind interface for UDP/QUIC (from direct-only chain).
    bind_interface: Option<String>,
    /// QUIC socket binder that uses the bind_interface.
    quic_binder: ProxyQuicBinder,
    /// Timeout for establishing connections to DNS upstreams.
    connect_timeout: Duration,
}

impl ProxyRuntimeProvider {
    /// Create with the given chain group, bootstrap resolver, and connect timeout.
    pub fn with_bootstrap(
        chain_group: Arc<ClientChainGroup>,
        bootstrap_resolver: Arc<dyn Resolver>,
        connect_timeout: Duration,
    ) -> Self {
        let bind_interface = chain_group.get_bind_interface().map(ToString::to_string);
        let quic_binder = ProxyQuicBinder {
            bind_interface: bind_interface.clone(),
        };
        Self {
            chain_group,
            bootstrap_resolver,
            bind_interface,
            quic_binder,
            connect_timeout,
        }
    }
}

/// Spawn handle for tokio runtime.
#[derive(Clone, Default)]
pub struct TokioSpawnHandle;

impl Spawn for TokioSpawnHandle {
    fn spawn_bg(&mut self, future: impl Future<Output = ()> + Send + 'static) {
        tokio::spawn(future);
    }
}

/// Type alias for our wrapped TCP stream.
type ProxiedTcp = AsyncIoTokioAsStd<Box<dyn AsyncStream>>;

impl RuntimeProvider for ProxyRuntimeProvider {
    type Handle = TokioSpawnHandle;
    type Timer = TokioTime;
    type Udp = tokio::net::UdpSocket;
    type Tcp = ProxiedTcp;

    fn create_handle(&self) -> Self::Handle {
        TokioSpawnHandle
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        _bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Tcp, io::Error>>>> {
        let chain_group = self.chain_group.clone();
        let resolver = self.bootstrap_resolver.clone();
        let timeout = timeout
            .map(|timeout| timeout.min(self.connect_timeout))
            .unwrap_or(self.connect_timeout);

        Box::pin(async move {
            let address = match server_addr.ip() {
                IpAddr::V4(addr) => Address::Ipv4(addr),
                IpAddr::V6(addr) => Address::Ipv6(addr),
            };
            let target = NetLocation::new(address, server_addr.port());

            let started = std::time::Instant::now();
            let connect_future = chain_group.connect_tcp(target.into(), &resolver);
            match tokio::time::timeout(timeout, connect_future).await {
                Ok(Ok(result)) => {
                    log::debug!(
                        "DNS upstream connect to {} succeeded in {:?}",
                        server_addr,
                        started.elapsed()
                    );
                    Ok(AsyncIoTokioAsStd(result.client_stream))
                }
                Ok(Err(e)) => {
                    log::warn!(
                        "DNS upstream connect to {} failed in {:?}: {}",
                        server_addr,
                        started.elapsed(),
                        e
                    );
                    Err(e)
                }
                Err(_) => {
                    log::warn!(
                        "DNS upstream connect to {} timed out in {:?}",
                        server_addr,
                        started.elapsed()
                    );
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "DNS server connection to {server_addr} timed out after {timeout:?}"
                        ),
                    ))
                }
            }
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Udp, io::Error>>>> {
        let bind_interface = self.bind_interface.clone();

        Box::pin(async move {
            let socket = crate::socket_util::new_outbound_socket2_udp_socket(
                local_addr.is_ipv6(),
                bind_interface,
                Some(local_addr),
            )?;
            tokio::net::UdpSocket::from_std(socket.into())
        })
    }

    fn quic_binder(&self) -> Option<&dyn QuicSocketBinder> {
        Some(&self.quic_binder)
    }
}

/// QUIC socket binder that supports bind_interface.
#[derive(Clone)]
struct ProxyQuicBinder {
    bind_interface: Option<String>,
}

impl QuicSocketBinder for ProxyQuicBinder {
    fn bind_quic(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Result<Arc<dyn quinn::AsyncUdpSocket>, io::Error> {
        let memory =
            crate::resources::try_dns_quic_memory().ok_or_else(crate::resources::exhausted)?;
        let socket = crate::socket_util::new_outbound_socket2_udp_socket(
            local_addr.is_ipv6(),
            self.bind_interface.clone(),
            Some(local_addr),
        )?;
        crate::quic_endpoint::socket_with_memory(socket.into(), memory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_stream::AsyncMessageStream;
    use crate::client_proxy_chain::{ClientProxyChain, InitialHopEntry};
    use crate::resolver::NativeResolver;
    use crate::tcp::chain_builder::build_direct_chain_group;
    use crate::tcp::socket_connector::SocketConnector;
    use async_trait::async_trait;

    #[derive(Debug)]
    struct PendingSocketConnector;

    #[async_trait]
    impl SocketConnector for PendingSocketConnector {
        async fn connect(
            &self,
            _resolver: &Arc<dyn Resolver>,
            _address: &crate::address::ResolvedLocation,
        ) -> io::Result<Box<dyn AsyncStream>> {
            std::future::pending().await
        }

        async fn connect_udp_bidirectional(
            &self,
            _resolver: &Arc<dyn Resolver>,
            _target: crate::address::ResolvedLocation,
        ) -> io::Result<Box<dyn AsyncMessageStream>> {
            unreachable!("TCP timeout tests do not open UDP streams")
        }

        fn bind_interface(&self) -> Option<&str> {
            None
        }
    }

    fn build_pending_chain_group() -> ClientChainGroup {
        ClientChainGroup::new(vec![ClientProxyChain::new(
            vec![InitialHopEntry::Direct(Box::new(PendingSocketConnector))],
            vec![],
        )])
    }

    #[test]
    fn test_provider_is_clone() {
        // RuntimeProvider requires Clone
        let resolver = Arc::new(NativeResolver::new());
        let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
        let provider =
            ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, TEST_CONNECT_TIMEOUT);
        let _cloned = provider.clone();
    }

    #[test]
    fn test_spawn_handle_is_clone() {
        let handle = TokioSpawnHandle;
        let _cloned = handle.clone();
    }

    #[tokio::test]
    async fn test_bind_udp_works_directly() {
        let resolver = Arc::new(NativeResolver::new());
        let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
        let provider =
            ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, TEST_CONNECT_TIMEOUT);

        let local_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();

        // UDP DNS works directly (not through proxy)
        let result = provider.bind_udp(local_addr, server_addr).await;
        assert!(
            result.is_ok(),
            "bind_udp should succeed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_connect_tcp_with_direct_chain_connects_to_target() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let resolver = Arc::new(NativeResolver::new());
        let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
        let provider =
            ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, TEST_CONNECT_TIMEOUT);

        let result = provider.connect_tcp(server_addr, None, None).await;
        assert!(result.is_ok());
        assert!(
            tokio::time::timeout(TEST_CONNECT_TIMEOUT, listener.accept())
                .await
                .is_ok()
        );
    }

    #[test]
    fn test_create_handle() {
        let resolver = Arc::new(NativeResolver::new());
        let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
        let provider =
            ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, TEST_CONNECT_TIMEOUT);
        let _handle = provider.create_handle();
    }

    #[test]
    fn test_quic_binder_available() {
        let resolver = Arc::new(NativeResolver::new());
        let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
        let provider =
            ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, TEST_CONNECT_TIMEOUT);
        assert!(provider.quic_binder().is_some());
    }

    fn run_quic_test_in_child(name: &str) -> bool {
        if std::env::var("SHOES_DNS_QUIC_TEST_CHILD").as_deref() == Ok(name) {
            crate::resources::configure(crate::config::GlobalLimits {
                quic_memory_bytes: Some(16 << 20),
                ..Default::default()
            })
            .unwrap();
            return false;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("dns::proxy_runtime::tests::{name}"),
                "--nocapture",
            ])
            .env("SHOES_DNS_QUIC_TEST_CHILD", name)
            .status()
            .unwrap();
        assert!(status.success());
        true
    }

    #[tokio::test]
    async fn quic_binder_reserves_shared_memory_until_last_socket_drop() {
        if run_quic_test_in_child("quic_binder_reserves_shared_memory_until_last_socket_drop") {
            return;
        }
        let binder = ProxyQuicBinder {
            bind_interface: None,
        };
        let local_addr = "0.0.0.0:0".parse().unwrap();
        let server_addr = "127.0.0.1:443".parse().unwrap();
        let memory_bytes =
            crate::resources::configure_quic_transport(&mut quinn::TransportConfig::default());
        assert!(crate::resources::try_quic_memory(memory_bytes).is_some());
        let socket = binder.bind_quic(local_addr, server_addr).unwrap();
        assert_eq!(
            crate::resources::snapshot().quic_buffer_bytes.active,
            16 << 20
        );
        assert!(crate::resources::try_quic_memory(memory_bytes).is_none());
        assert_eq!(
            binder
                .bind_quic(local_addr, server_addr)
                .unwrap_err()
                .kind(),
            io::ErrorKind::ConnectionRefused,
        );
        let clone = socket.clone();
        drop(socket);
        assert_eq!(
            crate::resources::snapshot().quic_buffer_bytes.active,
            16 << 20
        );
        drop(clone);
        assert_eq!(crate::resources::snapshot().quic_buffer_bytes.active, 0);

        let occupied = std::net::UdpSocket::bind(local_addr).unwrap();
        assert!(
            binder
                .bind_quic(occupied.local_addr().unwrap(), server_addr)
                .is_err()
        );
        assert_eq!(crate::resources::snapshot().quic_buffer_bytes.active, 0);
        assert!(binder.bind_quic(local_addr, server_addr).is_ok());
    }

    #[tokio::test]
    async fn h3_lookup_uses_budgeted_socket_and_releases_it_on_teardown() {
        use bytes::Buf;
        use hickory_resolver::config::{
            ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverConfig,
        };
        use hickory_resolver::net::h3::h3_server::H3Server;
        use hickory_resolver::proto::op::{Message, MessageType};
        use hickory_resolver::proto::rr::{RData, Record, rdata::A};

        if run_quic_test_in_child("h3_lookup_uses_budgeted_socket_and_releases_it_on_teardown") {
            return;
        }
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
                    .into(),
            )
            .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut server = H3Server::with_socket_and_tls_config(
            tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap(),
            Arc::new(tls),
        )
        .unwrap();
        let mut connection_config = ConnectionConfig::new(ProtocolConfig::H3 {
            server_name: "localhost".into(),
            path: "/dns-query".into(),
            disable_grease: true,
        });
        connection_config.port = server.local_addr().unwrap().port();
        let config = ResolverConfig::from_parts(
            None,
            vec![],
            vec![NameServerConfig::new(
                "127.0.0.1".parse().unwrap(),
                true,
                vec![connection_config],
            )],
        );
        let bootstrap = Arc::new(NativeResolver::new());
        let provider = ProxyRuntimeProvider::with_bootstrap(
            Arc::new(build_direct_chain_group(bootstrap.clone())),
            bootstrap,
            Duration::from_secs(5),
        );
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let resolver = hickory_resolver::Resolver::builder_with_config(config, provider)
            .with_tls_config(tls)
            .build()
            .unwrap();
        let answer = RData::A(A::new(192, 0, 2, 42));
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let serve = async {
            let (mut connection, _) = server.accept().await.unwrap().unwrap();
            let (request, mut stream) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.uri().path(), "/dns-query");
            let respond = async {
                let mut body = Vec::new();
                while let Some(mut data) = stream.recv_data().await.unwrap() {
                    body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
                }
                let mut response = Message::from_vec(&body).unwrap();
                response.metadata.message_type = MessageType::Response;
                response.add_answer(Record::from_rdata(
                    response.queries[0].name().clone(),
                    60,
                    answer.clone(),
                ));
                let body = response.to_vec().unwrap();
                stream
                    .send_response(
                        http::Response::builder()
                            .header("content-type", "application/dns-message")
                            .header("content-length", body.len())
                            .body(())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                stream.send_data(body.into()).await.unwrap();
                stream.finish().await.unwrap();
                done_rx.await.unwrap();
            };
            tokio::select! {
                _ = respond => {},
                _ = connection.accept() => panic!("unexpected extra H3 request or closure"),
            }
        };
        let lookup = async {
            let result = resolver.ipv4_lookup("memory.test.").await.unwrap();
            assert_eq!(result.answers()[0].data, answer);
            assert_eq!(
                crate::resources::snapshot().quic_buffer_bytes.active,
                16 << 20
            );
            done_tx.send(()).unwrap();
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(serve, lookup)
        })
        .await
        .unwrap();
        drop((resolver, server));
        tokio::time::timeout(Duration::from_secs(5), async {
            while crate::resources::snapshot().quic_buffer_bytes.active != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_connect_tcp_respects_timeout() {
        let resolver = Arc::new(NativeResolver::new());
        let chain_group = Arc::new(build_pending_chain_group());
        let provider =
            ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, TEST_CONNECT_TIMEOUT);

        let server_addr: SocketAddr = "192.0.2.1:53".parse().unwrap();

        let start = std::time::Instant::now();
        let result = provider
            .connect_tcp(server_addr, None, Some(Duration::from_millis(100)))
            .await;
        let elapsed = start.elapsed();

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("connection should fail"),
        };
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::TimedOut,
            "should be timeout error"
        );

        // Verify timeout was respected (should complete in ~100ms, not 5+ seconds)
        assert!(
            elapsed < Duration::from_secs(1),
            "timeout should fire quickly, but took {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_connect_tcp_caps_passed_timeout_by_configured_connect_timeout() {
        let resolver = Arc::new(NativeResolver::new());
        let chain_group = Arc::new(build_pending_chain_group());
        let provider =
            ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, Duration::from_millis(100));

        let server_addr: SocketAddr = "192.0.2.1:53".parse().unwrap();

        let start = std::time::Instant::now();
        let result = provider
            .connect_tcp(server_addr, None, Some(Duration::from_secs(5)))
            .await;
        let elapsed = start.elapsed();

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("connection should fail"),
        };
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            elapsed < Duration::from_secs(1),
            "configured connect timeout should cap a longer request timeout, but took {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_connect_tcp_uses_configured_timeout_when_none() {
        let resolver = Arc::new(NativeResolver::new());
        let chain_group = Arc::new(build_pending_chain_group());
        let provider =
            ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, TEST_CONNECT_TIMEOUT);

        let server_addr: SocketAddr = "192.0.2.1:53".parse().unwrap();

        let start = std::time::Instant::now();
        let result = provider.connect_tcp(server_addr, None, None).await;
        let elapsed = start.elapsed();

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("connection should fail"),
        };
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::TimedOut,
            "should be timeout error"
        );

        assert!(
            elapsed < Duration::from_secs(1),
            "configured timeout should apply, but took {:?}",
            elapsed
        );
        assert!(
            elapsed >= Duration::from_millis(50),
            "configured timeout fired too early after {:?}",
            elapsed
        );
    }
}
