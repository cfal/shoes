//! Resolver implementation using hickory-dns.
//!
//! Uses ProxyRuntimeProvider for all connections, which handles both direct
//! and proxied connections through ClientChainGroup.

use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;

use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverConfig};
use hickory_resolver::Resolver;

use crate::address::NetLocation;
use crate::client_proxy_chain::ClientChainGroup;
use crate::dns::parsed::IpStrategy;
use crate::dns::proxy_runtime::ProxyRuntimeProvider;
use crate::resolver::Resolver as ShoesResolver;

/// Resolver implementation using hickory-dns.
/// Uses ProxyRuntimeProvider for all connections (both direct and proxied).
pub struct HickoryResolver {
    inner: Resolver<ProxyRuntimeProvider>,
    description: String,
}

impl Debug for HickoryResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HickoryResolver")
            .field("description", &self.description)
            .finish()
    }
}

impl HickoryResolver {
    /// Create a UDP DNS resolver.
    /// Note: UDP uses the chain_group but only works with direct chains.
    pub fn udp(
        addr: SocketAddr,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        ip_strategy: IpStrategy,
    ) -> std::io::Result<Self> {
        let mut conn_config = ConnectionConfig::udp();
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            ip_strategy,
            format!("udp://{}", addr),
        )
    }

    /// Create a TCP DNS resolver.
    pub fn tcp(
        addr: SocketAddr,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        ip_strategy: IpStrategy,
    ) -> std::io::Result<Self> {
        let mut conn_config = ConnectionConfig::tcp();
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            ip_strategy,
            format!("tcp://{}", addr),
        )
    }

    /// Create a DNS-over-TLS resolver.
    pub fn tls(
        addr: SocketAddr,
        server_name: Arc<str>,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        ip_strategy: IpStrategy,
    ) -> std::io::Result<Self> {
        let mut conn_config = ConnectionConfig::tls(server_name.clone());
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            ip_strategy,
            format!("tls://{}#{}", addr, server_name),
        )
    }

    /// Create a DNS-over-HTTPS resolver.
    pub fn https(
        addr: SocketAddr,
        server_name: Arc<str>,
        path: Arc<str>,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        ip_strategy: IpStrategy,
    ) -> std::io::Result<Self> {
        let mut conn_config = ConnectionConfig::https(server_name.clone(), Some(path));
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            ip_strategy,
            format!("https://{}", server_name),
        )
    }

    /// Create a DNS-over-HTTP/3 resolver.
    pub fn h3(
        addr: SocketAddr,
        server_name: Arc<str>,
        path: Arc<str>,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        ip_strategy: IpStrategy,
    ) -> std::io::Result<Self> {
        // Cloudflare has a broken GREASE implementation.
        // See: https://github.com/hyperium/h3/issues/206
        let protocol = ProtocolConfig::H3 {
            server_name: server_name.clone(),
            path,
            disable_grease: true,
        };
        let mut conn_config = ConnectionConfig::new(protocol);
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            ip_strategy,
            format!("h3://{}", server_name),
        )
    }

    fn build(
        ip: std::net::IpAddr,
        conn_config: ConnectionConfig,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        ip_strategy: IpStrategy,
        description: String,
    ) -> std::io::Result<Self> {
        let ns_config = NameServerConfig::new(ip, true, vec![conn_config]);
        let config = ResolverConfig::from_parts(None, vec![], vec![ns_config]);
        let provider = ProxyRuntimeProvider::with_bootstrap(chain_group, bootstrap);

        let mut builder = Resolver::builder_with_config(config, provider);
        builder.options_mut().ip_strategy = ip_strategy.to_hickory();
        let builder = builder.with_tls_config(crate::rustls_config_util::create_dns_client_config());
        let resolver = builder
            .build()
            .map_err(|e| std::io::Error::other(format!("failed to build resolver: {e}")))?;

        Ok(Self {
            inner: resolver,
            description,
        })
    }
}

impl ShoesResolver for HickoryResolver {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>,
    > {
        // Fast path: if already an IP address, return immediately without DNS lookup
        if let Some(socket_addr) = location.to_socket_addr_nonblocking() {
            return Box::pin(std::future::ready(Ok(vec![socket_addr])));
        }

        let name = location.address().to_string();
        let port = location.port();
        let description = self.description.clone();
        let resolver = self.inner.clone();

        Box::pin(async move {
            let response = resolver
                .lookup_ip(&name)
                .await
                .map_err(|e| std::io::Error::other(format!("DNS lookup failed: {e}")))?;

            let addrs: Vec<SocketAddr> = response
                .iter()
                .filter(|ip| !ip.is_unspecified())
                .map(|ip| SocketAddr::new(ip, port))
                .collect();

            if addrs.is_empty() {
                return Err(std::io::Error::other(format!(
                    "DNS lookup returned no addresses for {name}"
                )));
            }

            log::debug!(
                "HickoryResolver ({}) resolved {name}:{port} -> {addrs:?}",
                description
            );
            Ok(addrs)
        })
    }
}
