use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;

use crate::address::{Address, Location};

#[async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve_host(&self, host: &str) -> std::io::Result<Vec<IpAddr>>;

    async fn resolve_single_address(&self, address: &Address) -> std::io::Result<IpAddr> {
        match address {
            Address::Ipv6(addr) => Ok(IpAddr::V6(*addr)),
            Address::Ipv4(addr) => Ok(IpAddr::V4(*addr)),
            Address::Hostname(hostname) => Ok(self.resolve_host(&hostname).await?[0]),
        }
    }

    async fn resolve_address(&self, address: &Address) -> std::io::Result<Vec<IpAddr>> {
        match address {
            Address::Ipv6(addr) => Ok(vec![IpAddr::V6(*addr)]),
            Address::Ipv4(addr) => Ok(vec![IpAddr::V4(*addr)]),
            Address::Hostname(hostname) => self.resolve_host(&hostname).await,
        }
    }

    async fn resolve_location(&self, location: &Location) -> std::io::Result<SocketAddr> {
        let (address, port) = location.components();
        Ok(SocketAddr::new(
            self.resolve_single_address(address).await?,
            port,
        ))
    }
}

pub struct NativeResolver;

impl NativeResolver {
    pub fn new() -> Self {
        NativeResolver {}
    }
}

#[async_trait]
impl Resolver for NativeResolver {
    async fn resolve_host(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        Ok(tokio::net::lookup_host((host, 80u16))
            .await?
            .map(|s| s.ip())
            .collect::<Vec<_>>())
    }
}
