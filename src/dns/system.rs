use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use ipnetwork::IpNetwork;
use tokio::sync::Mutex;

use crate::address::NetLocation;
use crate::resolver::{DnsExchangeFuture, ResolveFuture, Resolver};

use super::exchange::RawDnsExchange;
use super::proxy_runtime::ProxyRuntimeProvider;

#[derive(Debug)]
struct Snapshot {
    loaded: Instant,
    exchange: Arc<RawDnsExchange>,
}

#[derive(Debug)]
pub(super) struct SystemResolver {
    lookup: Arc<dyn Resolver>,
    snapshot: Arc<Mutex<Option<Snapshot>>>,
    forbidden: Arc<[IpNetwork]>,
    timeout: Duration,
}

impl SystemResolver {
    pub(super) async fn check_configuration(forbidden: Arc<[IpNetwork]>) -> io::Result<()> {
        tokio::task::spawn_blocking(move || {
            let (mut config, _) = discover()?;
            filter_endpoints(&mut config, &forbidden)
        })
        .await
        .map_err(io::Error::other)?
    }

    pub fn new(lookup: Arc<dyn Resolver>, forbidden: Arc<[IpNetwork]>, timeout: Duration) -> Self {
        Self {
            lookup,
            snapshot: Arc::new(Mutex::new(None)),
            forbidden,
            timeout,
        }
    }
}

impl Resolver for SystemResolver {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        self.lookup.resolve_location(location)
    }

    fn exchange(&self, request: Vec<u8>) -> DnsExchangeFuture {
        let snapshot = self.snapshot.clone();
        let forbidden = self.forbidden.clone();
        let lookup = self.lookup.clone();
        let timeout = self.timeout;
        Box::pin(async move {
            let exchange = {
                let mut current = snapshot.lock().await;
                if current
                    .as_ref()
                    .is_none_or(|value| value.loaded.elapsed() >= Duration::from_secs(30))
                {
                    let (mut config, mut options) = tokio::task::spawn_blocking(discover)
                        .await
                        .map_err(io::Error::other)??;
                    filter_endpoints(&mut config, &forbidden)?;
                    options.timeout = options.timeout.min(timeout);
                    let chain = Arc::new(crate::tcp::chain_builder::build_direct_chain_group(
                        lookup.clone(),
                    ));
                    let provider = ProxyRuntimeProvider::with_bootstrap(chain, lookup, timeout);
                    *current = Some(Snapshot {
                        loaded: Instant::now(),
                        exchange: Arc::new(RawDnsExchange::new(
                            config.name_servers,
                            provider,
                            options,
                        )),
                    });
                }
                current.as_ref().unwrap().exchange.clone()
            };
            let result = exchange.exchange(request).await;
            if result
                .as_ref()
                .is_err_and(|error| !crate::resolver::dns_setup_pending(error))
            {
                let mut current = snapshot.lock().await;
                if current
                    .as_ref()
                    .is_some_and(|value| Arc::ptr_eq(&value.exchange, &exchange))
                {
                    *current = None;
                }
            }
            result
        })
    }
}

fn filter_endpoints(config: &mut ResolverConfig, forbidden: &[IpNetwork]) -> io::Result<()> {
    config.name_servers.retain(|server| {
        !server.ip.is_unspecified()
            && !forbidden
                .iter()
                .any(|range| range.contains(server.ip.to_canonical()))
    });
    if config.name_servers.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "system DNS has no usable underlying endpoints; configure dns.servers",
        ));
    }
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn discover() -> io::Result<(hickory_resolver::config::ResolverConfig, ResolverOpts)> {
    hickory_resolver::system_conf::read_system_conf()
        .map_err(|error| io::Error::other(error.to_string()))
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn discover() -> io::Result<(hickory_resolver::config::ResolverConfig, ResolverOpts)> {
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "mobile host must supply underlying DNS via dns.servers; VPN system discovery is unsafe",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::config::{ConnectionConfig, NameServerConfig};

    #[test]
    fn discovery_filters_fake_and_unspecified_but_keeps_real_loopback_stubs() {
        let servers = ["198.18.0.1", "::ffff:198.18.0.1", "0.0.0.0", "127.0.0.53"]
            .into_iter()
            .map(|ip| {
                NameServerConfig::new(ip.parse().unwrap(), true, vec![ConnectionConfig::udp()])
            })
            .collect();
        let mut config = ResolverConfig::from_parts(None, vec![], servers);
        filter_endpoints(&mut config, &["198.18.0.0/15".parse().unwrap()]).unwrap();
        assert_eq!(config.name_servers.len(), 1);
        assert_eq!(config.name_servers[0].ip.to_string(), "127.0.0.53");
        assert!(filter_endpoints(&mut config, &["127.0.0.0/8".parse().unwrap()]).is_err());
    }
}
