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
use crate::atomic::AtomicU64;
use crate::client_proxy_chain::ClientChainGroup;
use crate::resolver::Resolver;

static NEXT_TRANSPORT_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
const TEST_CONNECT_TIMEOUT: Duration = Duration::from_millis(100);

/// RuntimeProvider that routes TCP connections through a proxy chain.
/// For direct-only chains, UDP and QUIC use the configured bind_interface.
#[derive(Clone)]
pub struct ProxyRuntimeProvider {
    id: u64,
    chain_group: Arc<ClientChainGroup>,
    /// Resolver for proxy server hostnames (not the DNS queries themselves).
    /// Uses the explicit bootstrap route, or native DNS when none was configured.
    bootstrap_resolver: Arc<dyn Resolver>,
    /// QUIC socket binder that selects from the same direct-only chain.
    quic_binder: ProxyQuicBinder,
    /// Timeout for establishing connections to DNS upstreams.
    connect_timeout: Duration,
    network: Option<crate::network_tasks::NetworkTasks>,
    retirement: tokio_util::sync::CancellationToken,
}

impl ProxyRuntimeProvider {
    /// Create with the given chain group, bootstrap resolver, and connect timeout.
    pub fn with_bootstrap(
        chain_group: Arc<ClientChainGroup>,
        bootstrap_resolver: Arc<dyn Resolver>,
        connect_timeout: Duration,
    ) -> Self {
        let retirement = tokio_util::sync::CancellationToken::new();
        let quic_binder = ProxyQuicBinder {
            chain_group: chain_group.clone(),
            memory_bytes: crate::resources::limits().quic_dns_memory_bytes,
            socket_buffer: crate::resources::limits().quic_socket_buffer,
            retirement: retirement.clone(),
        };
        Self {
            id: NEXT_TRANSPORT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            chain_group,
            bootstrap_resolver,
            quic_binder,
            connect_timeout,
            network: crate::network_tasks::NetworkTasks::current(),
            retirement,
        }
    }

    pub(super) fn retire(&self) {
        self.retirement.cancel();
    }

    pub(super) fn id(&self) -> u64 {
        self.id
    }

    pub fn with_quic_memory(mut self, bytes: usize) -> Self {
        self.quic_binder.memory_bytes = bytes;
        self
    }

    pub fn with_quic_socket_buffer(mut self, bytes: usize) -> Self {
        self.quic_binder.socket_buffer = bytes;
        self
    }
}

/// Spawn handle for tokio runtime.
#[derive(Clone, Default)]
pub struct TokioSpawnHandle {
    network: Option<crate::network_tasks::NetworkTasks>,
    retirement: tokio_util::sync::CancellationToken,
}

impl Spawn for TokioSpawnHandle {
    fn spawn_bg(&mut self, future: impl Future<Output = ()> + Send + 'static) {
        let retirement = self.retirement.clone();
        let future = async move {
            tokio::select! {
                biased;
                _ = retirement.cancelled() => {},
                _ = future => {},
            }
        };
        let background = crate::control::url_test::is_background();
        let future = async move {
            if background {
                crate::control::url_test::BACKGROUND.scope((), future).await;
            } else {
                future.await;
            }
        };
        match &self.network {
            Some(network) => {
                network.spawn(future);
            }
            None => {
                crate::network_tasks::spawn(future);
            }
        }
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
        TokioSpawnHandle {
            network: self.network.clone(),
            retirement: self.retirement.clone(),
        }
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        _bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Tcp, io::Error>>>> {
        let chain_group = self.chain_group.clone();
        let resolver = self.bootstrap_resolver.clone();
        let retirement = self.retirement.clone();
        let id = self.id;
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
            let result = tokio::select! {
                biased;
                _ = retirement.cancelled() => return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "DNS transport retired")),
                result = tokio::time::timeout(timeout, connect_future) => result,
            };
            match result {
                Ok(Ok(result)) => {
                    log::debug!(
                        "DNS transport {id} upstream connect to {} succeeded in {:?}",
                        server_addr,
                        started.elapsed()
                    );
                    let stream: Box<dyn AsyncStream> =
                        Box::new(crate::prepend_stream::PrependStream::new(
                            result.client_stream,
                            result.early_data.map(Vec::into_boxed_slice),
                        ));
                    Ok(AsyncIoTokioAsStd(stream))
                }
                Ok(Err(e)) => {
                    log::debug!(
                        "DNS transport {id} upstream connect to {} failed in {:?}: {}",
                        server_addr,
                        started.elapsed(),
                        e
                    );
                    Err(e)
                }
                Err(_) => {
                    log::debug!(
                        "DNS transport {id} upstream connect to {} timed out in {:?}",
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
        let chain_group = self.chain_group.clone();
        let retirement = self.retirement.clone();

        Box::pin(async move {
            if retirement.is_cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "DNS transport retired",
                ));
            }
            let bind_interface = chain_group.select_bind_interface()?;
            let socket = crate::socket_util::new_outbound_socket2_udp_socket(
                local_addr.is_ipv6(),
                bind_interface,
                Some(local_addr),
            )?;
            tokio::net::UdpSocket::from_std(socket.into())
        })
    }

    fn quic_binder(&self) -> Option<&dyn QuicSocketBinder> {
        self.chain_group
            .is_direct_only()
            .then_some(&self.quic_binder as &dyn QuicSocketBinder)
    }
}

/// QUIC socket binder that supports bind_interface.
#[derive(Clone)]
struct ProxyQuicBinder {
    chain_group: Arc<ClientChainGroup>,
    memory_bytes: usize,
    socket_buffer: usize,
    retirement: tokio_util::sync::CancellationToken,
}

impl QuicSocketBinder for ProxyQuicBinder {
    fn bind_quic(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Result<Arc<dyn quinn::AsyncUdpSocket>, io::Error> {
        if self.retirement.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "DNS transport retired",
            ));
        }
        let memory = crate::resources::try_quic_memory(self.memory_bytes)
            .ok_or_else(|| crate::resources::quic_memory_exhausted(self.memory_bytes))?;
        let socket = crate::socket_util::new_outbound_socket2_udp_socket(
            local_addr.is_ipv6(),
            self.chain_group.select_bind_interface()?,
            Some(local_addr),
        )?;
        crate::socket_util::set_udp_socket_buffers(
            socket2::SockRef::from(&socket),
            self.socket_buffer,
        );
        crate::quic_endpoint::socket_with_memory(socket.into(), memory)
    }
}

#[cfg(test)]
mod tests;
