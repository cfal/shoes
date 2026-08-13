//! Custom RuntimeProvider that routes TCP connections through proxy chains.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::net::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::net::runtime::{QuicSocketBinder, RuntimeProvider, Spawn, TokioTime};
use quinn::Runtime as QuinnRuntime;

use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_chain::ClientChainGroup;
use crate::resolver::Resolver;
use crate::socket_util::new_udp_socket;

/// Default connection timeout for DNS server connections. Matches hickory-dns CONNECT_TIMEOUT.
#[cfg(test)]
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

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
            if bind_interface.is_some() {
                // Use our socket_util which supports bind_interface, and which
                // excludes the socket from the VPN route for us.
                new_udp_socket(local_addr.is_ipv6(), bind_interface)
            } else {
                // Bind directly, then protect it: a query that goes out through
                // the tunnel it is meant to resolve for never comes back.
                let socket = tokio::net::UdpSocket::bind(local_addr).await?;
                crate::socket_util::protect_outbound(&socket)?;
                Ok(socket)
            }
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
        let socket = if self.bind_interface.is_some() {
            // Use socket2 for bind_interface support.
            let socket2_socket = crate::socket_util::new_socket2_udp_socket(
                local_addr.is_ipv6(),
                self.bind_interface.clone(),
                Some(local_addr),
                false,
            )?;
            // Convert socket2 -> std::net::UdpSocket.
            #[cfg(unix)]
            {
                use std::os::unix::io::FromRawFd;
                use std::os::unix::io::IntoRawFd;
                let raw_fd = socket2_socket.into_raw_fd();
                unsafe { std::net::UdpSocket::from_raw_fd(raw_fd) }
            }
            #[cfg(windows)]
            {
                use std::os::windows::io::FromRawSocket;
                use std::os::windows::io::IntoRawSocket;
                let raw_socket = socket2_socket.into_raw_socket();
                unsafe { std::net::UdpSocket::from_raw_socket(raw_socket) }
            }
        } else {
            // Default: bind directly.
            std::net::UdpSocket::bind(local_addr)?
        };

        // Both branches build the socket themselves, so neither has been
        // through the constructors that would have excluded it from the VPN
        // route. DNS-over-QUIC leaving through the tunnel it resolves for is
        // the same loop as any other outbound.
        crate::socket_util::protect_outbound(&socket)?;

        quinn::TokioRuntime.wrap_udp_socket(socket)
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::*;
    use crate::address::ResolvedLocation;
    use crate::async_stream::AsyncMessageStream;
    use crate::client_proxy_chain::{ClientProxyChain, InitialHopEntry};
    use crate::resolver::NativeResolver;
    use crate::tcp::chain_builder::build_direct_chain_group;
    use crate::tcp::socket_connector::SocketConnector;

    /// A socket connector whose connect never completes, so the only thing
    /// that can end the attempt is the timeout under test.
    ///
    /// The timeout tests used to dial 10.255.255.1:53 and assume the SYN would
    /// be dropped. That assumption does not hold: most consumer and ISP
    /// networks transparently redirect TCP port 53 to their own resolver, so
    /// the connect succeeds in milliseconds and the timeout never fires. The
    /// arithmetic being tested is ours; the kernel's is not, so no socket is
    /// involved here at all.
    #[derive(Debug)]
    struct StallingConnector;

    #[async_trait]
    impl SocketConnector for StallingConnector {
        async fn connect(
            &self,
            _resolver: &Arc<dyn Resolver>,
            _address: &ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncStream>> {
            std::future::pending::<()>().await;
            unreachable!("pending never completes")
        }

        async fn connect_udp_bidirectional(
            &self,
            _resolver: &Arc<dyn Resolver>,
            _target: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            std::future::pending::<()>().await;
            unreachable!("pending never completes")
        }

        fn bind_interface(&self) -> Option<&str> {
            None
        }
    }

    /// A provider whose chain can never connect, so `connect_tcp` can only
    /// ever end in a timeout.
    fn stalling_provider(connect_timeout: Duration) -> ProxyRuntimeProvider {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let chain = ClientProxyChain::new(
            vec![InitialHopEntry::Direct(Box::new(StallingConnector))],
            vec![],
        );
        let chain_group = Arc::new(ClientChainGroup::new(vec![chain]));
        ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, connect_timeout)
    }

    /// Never actually dialled: the stalling connector ignores it. Present only
    /// so the address plumbing is exercised and the logs read sensibly.
    fn unreachable_addr() -> SocketAddr {
        "192.0.2.1:53".parse().unwrap()
    }

    #[test]
    fn test_provider_is_clone() {
        // RuntimeProvider requires Clone
        let resolver = Arc::new(NativeResolver::new());
        let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
        let provider =
            ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, DEFAULT_CONNECT_TIMEOUT);
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
            ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, DEFAULT_CONNECT_TIMEOUT);

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
        // This test verifies the provider correctly routes to the target.
        // Use localhost with a port that should be refused quickly.
        let resolver = Arc::new(NativeResolver::new());
        let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
        let provider =
            ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, DEFAULT_CONNECT_TIMEOUT);

        // Use localhost port 1 (reserved, should be refused quickly)
        let server_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let result = provider.connect_tcp(server_addr, None, None).await;
        // Connection should fail (connection refused)
        assert!(result.is_err());
    }

    #[test]
    fn test_create_handle() {
        let resolver = Arc::new(NativeResolver::new());
        let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
        let provider =
            ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, DEFAULT_CONNECT_TIMEOUT);
        let _handle = provider.create_handle();
    }

    #[test]
    fn test_quic_binder_available() {
        let resolver = Arc::new(NativeResolver::new());
        let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
        let provider =
            ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, DEFAULT_CONNECT_TIMEOUT);
        assert!(provider.quic_binder().is_some());
    }

    #[tokio::test]
    async fn test_connect_tcp_respects_timeout() {
        // The requested timeout is shorter than the configured one, so it wins.
        let provider = stalling_provider(Duration::from_secs(5));

        let start = std::time::Instant::now();
        let result = provider
            .connect_tcp(unreachable_addr(), None, Some(Duration::from_millis(100)))
            .await;
        let elapsed = start.elapsed();

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("a stalling connector can only end in a timeout"),
        };
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::TimedOut,
            "should be timeout error"
        );

        assert!(
            elapsed >= Duration::from_millis(50),
            "returned before the 100ms timeout could have fired, in {:?}",
            elapsed
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "the 100ms request should beat the 5s configured timeout, but took {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_connect_tcp_caps_passed_timeout_by_configured_connect_timeout() {
        // The configured timeout is shorter, so it caps the longer request.
        let provider = stalling_provider(Duration::from_millis(100));

        let start = std::time::Instant::now();
        let result = provider
            .connect_tcp(unreachable_addr(), None, Some(Duration::from_secs(5)))
            .await;
        let elapsed = start.elapsed();

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("a stalling connector can only end in a timeout"),
        };
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            elapsed >= Duration::from_millis(50),
            "returned before the 100ms timeout could have fired, in {:?}",
            elapsed
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "configured connect timeout should cap a longer request timeout, but took {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_connect_tcp_uses_configured_timeout_when_none_requested() {
        // No timeout requested, so the provider's own is used.
        let provider = stalling_provider(Duration::from_millis(200));

        let start = std::time::Instant::now();
        let result = provider.connect_tcp(unreachable_addr(), None, None).await;
        let elapsed = start.elapsed();

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("a stalling connector can only end in a timeout"),
        };
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::TimedOut,
            "should be timeout error"
        );

        assert!(
            elapsed >= Duration::from_millis(150),
            "should have waited for the configured 200ms, but only waited {:?}",
            elapsed
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "configured timeout should bound the attempt, but took {:?}",
            elapsed
        );
    }
}
