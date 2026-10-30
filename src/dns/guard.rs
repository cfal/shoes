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

#[derive(Debug)]
pub(crate) struct SyntheticDnsAnswer;

impl std::fmt::Display for SyntheticDnsAnswer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("real DNS returned a synthetic address (possible DNS loop)")
    }
}

impl std::error::Error for SyntheticDnsAnswer {}

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
    fn manual_selector_paths(&self) -> Vec<crate::control::selection::ManualSelectorPath> {
        self.inner.manual_selector_paths()
    }

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
                    SyntheticDnsAnswer,
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
                    SyntheticDnsAnswer,
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
    struct HintReply(std::net::IpAddr);

    impl Resolver for HintReply {
        fn resolve_location(&self, _: &NetLocation) -> ResolveFuture {
            unreachable!()
        }

        fn exchange(&self, request: Vec<u8>) -> DnsExchangeFuture {
            let ip = self.0;
            Box::pin(async move {
                use hickory_resolver::proto::rr::{
                    RData, Record, RecordType,
                    rdata::{
                        A, AAAA, HTTPS, SVCB,
                        svcb::{IpHint, SvcParamKey, SvcParamValue},
                    },
                };
                let mut answer = super::super::message::decode(&request)?.into_response();
                let hint = match ip {
                    std::net::IpAddr::V4(ip) => (
                        SvcParamKey::Ipv4Hint,
                        SvcParamValue::Ipv4Hint(IpHint(vec![A(ip)])),
                    ),
                    std::net::IpAddr::V6(ip) => (
                        SvcParamKey::Ipv6Hint,
                        SvcParamValue::Ipv6Hint(IpHint(vec![AAAA(ip)])),
                    ),
                };
                let svcb = SVCB::new(1, answer.queries[0].name.clone(), vec![hint]);
                let data = if answer.queries[0].query_type == RecordType::HTTPS {
                    RData::HTTPS(HTTPS(svcb))
                } else {
                    RData::SVCB(svcb)
                };
                answer.add_answer(Record::from_rdata(answer.queries[0].name.clone(), 60, data));
                answer.to_vec().map_err(io::Error::other)
            })
        }
    }

    #[tokio::test]
    async fn service_binding_hints_obey_global_and_context_address_guards() {
        use crate::dns::DnsContext;
        use crate::dns::fake_ip::FakeIpOptions;
        use hickory_resolver::proto::{
            op::{Message, Query, ResponseCode},
            rr::{Name, RecordType},
        };

        for kind in [RecordType::HTTPS, RecordType::SVCB] {
            let mut request = Message::query();
            request.add_query(Query::query(Name::from_ascii("hint.test.").unwrap(), kind));
            let bytes = request.to_vec().unwrap();
            for (ip, forbidden) in [
                ("198.18.0.5", "198.18.0.0/15"),
                ("::ffff:198.19.0.5", "198.19.0.0/24"),
                ("2001:2::5", "2001:2::/48"),
                ("192.0.2.1", "192.0.2.1/32"),
            ] {
                let reply: Arc<dyn Resolver> = Arc::new(HintReply(ip.parse().unwrap()));
                let real = real_only(reply, vec![forbidden.parse().unwrap()].into());
                assert_eq!(
                    real.exchange(bytes.clone()).await.unwrap_err().kind(),
                    io::ErrorKind::InvalidData
                );
            }
            for ip in [
                "198.18.0.5",
                "::ffff:198.18.0.5",
                "2001:2::5",
                "192.0.2.5",
                "2001:db8::5",
            ] {
                let reply: Arc<dyn Resolver> = Arc::new(HintReply(ip.parse().unwrap()));
                let options = FakeIpOptions {
                    ipv6_range: Some("2001:2::/48".into()),
                    ..Default::default()
                };
                let context = DnsContext::new(options, reply.clone()).unwrap();
                let response = context
                    .exchange(bytes.clone(), true)
                    .await
                    .unwrap()
                    .unwrap();
                let response = Message::from_vec(&response).unwrap();
                if context.contains(ip.parse().unwrap()) {
                    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
                } else {
                    let guarded = real_only(
                        reply.clone(),
                        vec![
                            "198.18.0.0/15".parse().unwrap(),
                            "2001:2::/48".parse().unwrap(),
                        ]
                        .into(),
                    );
                    assert_eq!(
                        guarded.exchange(bytes.clone()).await.unwrap(),
                        reply.exchange(bytes.clone()).await.unwrap()
                    );
                    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
                    assert_eq!(response.answers.len(), 1);
                }
            }
        }
    }

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
