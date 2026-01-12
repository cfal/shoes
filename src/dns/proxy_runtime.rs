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
}

impl ProxyRuntimeProvider {
    /// Create with the given chain group and bootstrap resolver.
    pub fn with_bootstrap(
        chain_group: Arc<ClientChainGroup>,
        bootstrap_resolver: Arc<dyn Resolver>,
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
        _timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Tcp, io::Error>>>> {
        let chain_group = self.chain_group.clone();
        let resolver = self.bootstrap_resolver.clone();

        Box::pin(async move {
            let address = match server_addr.ip() {
                IpAddr::V4(addr) => Address::Ipv4(addr),
                IpAddr::V6(addr) => Address::Ipv6(addr),
            };
            let target = NetLocation::new(address, server_addr.port());

            let result = chain_group.connect_tcp(target.into(), &resolver).await?;
            Ok(AsyncIoTokioAsStd(result.client_stream))
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
                // Use our socket_util which supports bind_interface.
                new_udp_socket(local_addr.is_ipv6(), bind_interface)
            } else {
                // Default: bind directly.
                tokio::net::UdpSocket::bind(local_addr).await
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

        quinn::TokioRuntime.wrap_udp_socket(socket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::NativeResolver;
    use crate::tcp::chain_builder::build_direct_chain_group;

    #[test]
    fn test_provider_is_clone() {
        // RuntimeProvider requires Clone
        let resolver = Arc::new(NativeResolver::new());
        let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
        let provider = ProxyRuntimeProvider::with_bootstrap(chain_group, resolver);
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
        let provider = ProxyRuntimeProvider::with_bootstrap(chain_group, resolver);

        let local_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();

        // UDP DNS works directly (not through proxy)
        let result = provider.bind_udp(local_addr, server_addr).await;
        assert!(result.is_ok(), "bind_udp should succeed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_connect_tcp_with_direct_chain_connects_to_target() {
        // This test verifies the provider correctly routes to the target.
        // Use localhost with a port that should be refused quickly.
        let resolver = Arc::new(NativeResolver::new());
        let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
        let provider = ProxyRuntimeProvider::with_bootstrap(chain_group, resolver);

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
        let provider = ProxyRuntimeProvider::with_bootstrap(chain_group, resolver);
        let _handle = provider.create_handle();
    }

    #[test]
    fn test_quic_binder_available() {
        let resolver = Arc::new(NativeResolver::new());
        let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
        let provider = ProxyRuntimeProvider::with_bootstrap(chain_group, resolver);
        assert!(provider.quic_binder().is_some());
    }
}
