use std::io;
use std::sync::Arc;

use ipnetwork::IpNetwork;

use crate::address::NetLocation;
use crate::resolver::{DnsExchangeFuture, ResolveFuture, Resolver};

#[derive(Debug)]
struct RealResolver {
    inner: Arc<dyn Resolver>,
    forbidden: Arc<[IpNetwork]>,
}

pub(super) fn real_only(
    inner: Arc<dyn Resolver>,
    forbidden: Arc<[IpNetwork]>,
) -> Arc<dyn Resolver> {
    if forbidden.is_empty() {
        inner
    } else {
        Arc::new(RealResolver { inner, forbidden })
    }
}

impl Resolver for RealResolver {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        let future = self.inner.resolve_location(location);
        let forbidden = self.forbidden.clone();
        Box::pin(async move {
            let addresses = future.await?;
            if addresses.iter().any(|address| {
                forbidden
                    .iter()
                    .any(|range| range.contains(address.ip().to_canonical()))
            }) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "real DNS returned a synthetic address (possible DNS loop)",
                ));
            }
            Ok(addresses)
        })
    }

    fn exchange(&self, request: Vec<u8>) -> DnsExchangeFuture {
        self.inner.exchange(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn native_resolution_cannot_seed_bootstrap_with_fake_addresses() {
        let real = real_only(
            Arc::new(crate::resolver::NativeResolver::new()),
            vec!["127.0.0.0/8".parse().unwrap()].into(),
        );
        let target = NetLocation::from_str("localhost:443", None).unwrap();
        for _ in 0..2 {
            assert_eq!(
                real.resolve_location(&target).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }
}
