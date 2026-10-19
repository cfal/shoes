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

pub(crate) fn real_only(
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
        self.check_exchange(self.inner.exchange(request))
    }

    fn exchange_with_deadline(
        &self,
        request: Vec<u8>,
        deadline: tokio::time::Instant,
    ) -> DnsExchangeFuture {
        self.check_exchange(self.inner.exchange_with_deadline(request, deadline))
    }
}

impl RealResolver {
    fn check_exchange(&self, future: DnsExchangeFuture) -> DnsExchangeFuture {
        let forbidden = self.forbidden.clone();
        Box::pin(async move {
            let bytes = future.await?;
            let message = super::message::decode(&bytes)?;
            if super::message::addresses(&message).any(|ip| {
                forbidden
                    .iter()
                    .any(|range| range.contains(ip.to_canonical()))
            }) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "real DNS returned a synthetic address (possible DNS loop)",
                ));
            }
            Ok(bytes)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Reply;

    impl Resolver for Reply {
        fn resolve_location(&self, _: &NetLocation) -> ResolveFuture {
            unreachable!()
        }
        fn exchange(&self, _: Vec<u8>) -> DnsExchangeFuture {
            Box::pin(async {
                use hickory_resolver::proto::{
                    op::Message,
                    rr::{Name, RData, Record, rdata::AAAA},
                };
                let mut answer = Message::query().into_response();
                answer.add_additional(Record::from_rdata(
                    Name::from_ascii("other.test.").unwrap(),
                    60,
                    RData::AAAA(AAAA("::ffff:198.19.0.5".parse().unwrap())),
                ));
                Ok(answer.to_vec().unwrap())
            })
        }
    }

    #[tokio::test]
    async fn exchange_rejects_other_contexts_and_reserved_endpoint_answers() {
        for forbidden in ["198.19.0.0/24", "198.19.0.5/32"] {
            let real = real_only(Arc::new(Reply), vec![forbidden.parse().unwrap()].into());
            assert_eq!(
                real.exchange(Vec::new()).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

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
