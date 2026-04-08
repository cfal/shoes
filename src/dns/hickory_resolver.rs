//! Resolver implementation using hickory-dns.
//!
//! Uses ProxyRuntimeProvider for all connections, which handles both direct
//! and proxied connections through ClientChainGroup.

use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::Resolver;
use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverConfig,
};

use crate::address::NetLocation;
use crate::client_proxy_chain::ClientChainGroup;
use crate::dns::parsed::IpStrategy;
use crate::dns::proxy_runtime::ProxyRuntimeProvider;
use crate::resolver::Resolver as ShoesResolver;

/// Tuning options for hickory-backed resolvers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HickoryResolverOptions {
    pub ip_strategy: IpStrategy,
    /// Per-request timeout passed to hickory's ResolverOpts.timeout.
    /// None means use hickory's default.
    pub request_timeout: Option<Duration>,
    /// Timeout for establishing TCP/TLS connections to DNS upstreams.
    pub connect_timeout: Duration,
    /// Number of retry attempts for failed queries.
    pub attempts: usize,
}

impl Default for HickoryResolverOptions {
    fn default() -> Self {
        Self {
            ip_strategy: IpStrategy::default(),
            request_timeout: Some(Duration::from_secs(5)),
            connect_timeout: Duration::from_secs(5),
            attempts: 2,
        }
    }
}

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
        options: HickoryResolverOptions,
    ) -> std::io::Result<Self> {
        let mut conn_config = ConnectionConfig::udp();
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            options,
            format!("udp://{}", addr),
        )
    }

    /// Create a TCP DNS resolver.
    pub fn tcp(
        addr: SocketAddr,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
    ) -> std::io::Result<Self> {
        let mut conn_config = ConnectionConfig::tcp();
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            options,
            format!("tcp://{}", addr),
        )
    }

    /// Create a DNS-over-TLS resolver.
    pub fn tls(
        addr: SocketAddr,
        server_name: Arc<str>,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
    ) -> std::io::Result<Self> {
        let mut conn_config = ConnectionConfig::tls(server_name.clone());
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            options,
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
        options: HickoryResolverOptions,
    ) -> std::io::Result<Self> {
        let mut conn_config = ConnectionConfig::https(server_name.clone(), Some(path));
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            options,
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
        options: HickoryResolverOptions,
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
            options,
            format!("h3://{}", server_name),
        )
    }

    /// Create a resolver with multiple nameservers in a single hickory pool.
    /// Hickory's NameServerPool handles ordering and parallelism internally,
    /// avoiding the sequential fallback behavior of CompositeResolver.
    pub fn build_pooled(
        servers: Vec<(std::net::IpAddr, ConnectionConfig)>,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
        description: String,
    ) -> std::io::Result<Self> {
        let ns_configs: Vec<NameServerConfig> = servers
            .into_iter()
            .map(|(ip, conn_config)| NameServerConfig::new(ip, true, vec![conn_config]))
            .collect();

        Self::build_with_ns_configs(ns_configs, chain_group, bootstrap, options, description)
    }

    fn build(
        ip: std::net::IpAddr,
        conn_config: ConnectionConfig,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
        description: String,
    ) -> std::io::Result<Self> {
        let ns_config = NameServerConfig::new(ip, true, vec![conn_config]);
        Self::build_with_ns_configs(
            vec![ns_config],
            chain_group,
            bootstrap,
            options,
            description,
        )
    }

    fn build_with_ns_configs(
        ns_configs: Vec<NameServerConfig>,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
        description: String,
    ) -> std::io::Result<Self> {
        let config = ResolverConfig::from_parts(None, vec![], ns_configs);
        let provider =
            ProxyRuntimeProvider::with_bootstrap(chain_group, bootstrap, options.connect_timeout);

        let mut builder = Resolver::builder_with_config(config, provider);
        let resolver_opts = builder.options_mut();
        resolver_opts.ip_strategy = options.ip_strategy.to_hickory();
        if let Some(timeout) = options.request_timeout {
            resolver_opts.timeout = timeout;
        }
        resolver_opts.attempts = options.attempts;
        let builder =
            builder.with_tls_config(crate::rustls_config_util::create_dns_client_config());
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
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>
    {
        // Fast path: if already an IP address, return immediately without DNS lookup
        if let Some(socket_addr) = location.to_socket_addr_nonblocking() {
            return Box::pin(std::future::ready(Ok(vec![socket_addr])));
        }

        let name = location.address().to_string();
        let port = location.port();
        let description = self.description.clone();
        let resolver = self.inner.clone();

        Box::pin(async move {
            let started = std::time::Instant::now();

            let response = resolver.lookup_ip(&name).await.map_err(|e| {
                let elapsed = started.elapsed();
                log::warn!(
                    "DNS lookup failed via {}: {}:{} in {:?}: {}",
                    description,
                    name,
                    port,
                    elapsed,
                    e
                );
                std::io::Error::other(format!("DNS lookup failed: {e}"))
            })?;

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

            let elapsed = started.elapsed();
            if elapsed > Duration::from_millis(500) {
                log::info!(
                    "slow DNS lookup via {}: {}:{} -> {:?} in {:?}",
                    description,
                    name,
                    port,
                    addrs,
                    elapsed
                );
            } else {
                log::debug!(
                    "DNS lookup via {}: {}:{} -> {:?} in {:?}",
                    description,
                    name,
                    port,
                    addrs,
                    elapsed
                );
            }
            Ok(addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hickory_resolver_options_default() {
        let opts = HickoryResolverOptions::default();
        assert_eq!(opts.ip_strategy, IpStrategy::default());
        assert_eq!(opts.request_timeout, Some(Duration::from_secs(5)));
        assert_eq!(opts.connect_timeout, Duration::from_secs(5));
        assert_eq!(opts.attempts, 2);
    }

    #[test]
    fn test_hickory_resolver_options_zero_timeout() {
        let opts = HickoryResolverOptions {
            request_timeout: None,
            ..Default::default()
        };
        assert!(opts.request_timeout.is_none());
    }

    #[test]
    fn test_hickory_resolver_options_custom() {
        let opts = HickoryResolverOptions {
            ip_strategy: IpStrategy::Ipv4Only,
            request_timeout: Some(Duration::from_secs(3)),
            connect_timeout: Duration::from_secs(1),
            attempts: 1,
        };
        assert_eq!(opts.ip_strategy, IpStrategy::Ipv4Only);
        assert_eq!(opts.request_timeout, Some(Duration::from_secs(3)));
        assert_eq!(opts.connect_timeout, Duration::from_secs(1));
        assert_eq!(opts.attempts, 1);
    }
}
