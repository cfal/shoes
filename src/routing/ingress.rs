use std::io;
use std::sync::Arc;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::AsyncMessageStream;
use crate::client_proxy_chain::ClientChainGroup;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision, IngressTarget};
use crate::resolver::{Resolver, resolve_location};

pub(crate) struct UdpSetup {
    pub stream: Box<dyn AsyncMessageStream>,
    pub reply_identity: NetLocation,
}

pub(crate) enum UdpRoute<'a> {
    Local(UdpSetup),
    Forward {
        chain: &'a ClientChainGroup,
        target: ResolvedLocation,
        reply_identity: NetLocation,
    },
}

impl UdpRoute<'_> {
    pub(crate) async fn connect(self, resolver: &Arc<dyn Resolver>) -> io::Result<UdpSetup> {
        match self {
            Self::Local(setup) => Ok(setup),
            Self::Forward {
                chain,
                target,
                reply_identity,
            } => Ok(UdpSetup {
                stream: chain.connect_udp_bidirectional(resolver, target).await?,
                reply_identity,
            }),
        }
    }
}

pub(crate) async fn route_udp<'a>(
    selector: &'a ClientProxySelector,
    destination: NetLocation,
    resolver: &Arc<dyn Resolver>,
) -> io::Result<UdpRoute<'a>> {
    route_prepared_udp(
        selector,
        selector.prepare(destination.into())?,
        resolver,
        false,
    )
    .await
}

pub(crate) async fn connect_udp(
    selector: &ClientProxySelector,
    destination: NetLocation,
    resolver: &Arc<dyn Resolver>,
) -> io::Result<Box<dyn AsyncMessageStream>> {
    let target = selector.prepare(destination.into())?;
    Ok(connect_prepared_udp(selector, target, resolver, false)
        .await?
        .stream)
}

pub(crate) async fn connect_prepared_udp(
    selector: &ClientProxySelector,
    target: IngressTarget,
    resolver: &Arc<dyn Resolver>,
    legacy_hostname_reply: bool,
) -> io::Result<UdpSetup> {
    route_prepared_udp(selector, target, resolver, legacy_hostname_reply)
        .await?
        .connect(resolver)
        .await
}

async fn route_prepared_udp<'a>(
    selector: &'a ClientProxySelector,
    target: IngressTarget,
    resolver: &Arc<dyn Resolver>,
    legacy_hostname_reply: bool,
) -> io::Result<UdpRoute<'a>> {
    let target = match target {
        IngressTarget::LocalDns {
            wire_destination,
            context,
        } => {
            let reply_identity =
                if legacy_hostname_reply && wire_destination.address().hostname().is_some() {
                    let address = resolve_location(&mut wire_destination.into(), resolver).await?;
                    NetLocation::from_ip_addr(address.ip(), address.port())
                } else {
                    wire_destination
                };
            return Ok(UdpRoute::Local(UdpSetup {
                stream: context.udp_stream(),
                reply_identity,
            }));
        }
        IngressTarget::Forward(target) => target,
    };
    let routed = selector.judge_prepared(target, None, resolver).await?;
    match routed.decision {
        ConnectDecision::Allow {
            chain_group,
            mut remote_location,
        } => {
            let reply_identity = if legacy_hostname_reply
                && routed.wire_destination.address().hostname().is_some()
            {
                let address = resolve_location(&mut remote_location, resolver).await?;
                NetLocation::from_ip_addr(address.ip(), address.port())
            } else {
                routed.wire_destination
            };
            Ok(UdpRoute::Forward {
                chain: chain_group,
                target: remote_location,
                reply_identity,
            })
        }
        ConnectDecision::Block => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Destination blocked by routing rules",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::NetLocationMask;
    use crate::client_proxy_selector::{ConnectAction, ConnectRule};
    use crate::dns::fake_ip::{FakeDnsContext, FakeIpOptions};
    use crate::resolver::{DnsExchangeFuture, ResolveFuture};
    use hickory_resolver::proto::op::{Message, Query, ResponseCode};
    use hickory_resolver::proto::rr::{Name, RecordType};
    use std::pin::Pin;
    use tokio::io::ReadBuf;

    #[derive(Debug)]
    struct RealDns;

    impl Resolver for RealDns {
        fn resolve_location(&self, _: &NetLocation) -> ResolveFuture {
            Box::pin(async { Err(io::ErrorKind::NotFound.into()) })
        }

        fn exchange(&self, request: Vec<u8>) -> DnsExchangeFuture {
            Box::pin(async move {
                let mut response = Message::from_vec(&request).unwrap().into_response();
                response.metadata.response_code = ResponseCode::NXDomain;
                Ok(response.to_vec().unwrap())
            })
        }
    }

    fn query(kind: RecordType) -> Vec<u8> {
        let mut request = Message::query();
        request.metadata.id = 42;
        request.add_query(Query::query(
            Name::from_ascii("test.example.").unwrap(),
            kind,
        ));
        request.to_vec().unwrap()
    }

    async fn exchange(stream: &mut Box<dyn AsyncMessageStream>, request: &[u8]) -> Message {
        futures::future::poll_fn(|cx| Pin::new(&mut **stream).poll_write_message(cx, request))
            .await
            .unwrap();
        futures::future::poll_fn(|cx| Pin::new(&mut **stream).poll_flush_message(cx))
            .await
            .unwrap();
        let mut bytes = [0; 4096];
        let mut buf = ReadBuf::new(&mut bytes);
        futures::future::poll_fn(|cx| Pin::new(&mut **stream).poll_read_message(cx, &mut buf))
            .await
            .unwrap();
        Message::from_vec(buf.filled()).unwrap()
    }

    #[tokio::test]
    async fn local_dns_precedes_blocks_restoration_and_hostname_resolution() {
        let real: Arc<dyn Resolver> = Arc::new(RealDns);
        let context = Arc::new(FakeDnsContext::new(Default::default(), real.clone()).unwrap());
        let selector = ClientProxySelector::new(Vec::new())
            .with_fake_dns_context(Some(context))
            .unwrap();
        for wire in ["198.18.0.1:53", "unresolvable.invalid:53", "192.0.2.1:53"] {
            let wire = NetLocation::from_str(wire, None).unwrap();
            let mut setup = connect_prepared_udp(
                &selector,
                selector.prepare(wire.clone().into()).unwrap(),
                &real,
                false,
            )
            .await
            .unwrap();
            assert_eq!(setup.reply_identity, wire);
            for kind in [RecordType::A, RecordType::TXT, RecordType::A] {
                let response = exchange(&mut setup.stream, &query(kind)).await;
                assert_eq!(response.metadata.id, 42);
                if kind == RecordType::A {
                    assert_eq!(response.answers.len(), 1);
                } else {
                    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
                }
            }
        }
        let target = selector
            .prepare(
                NetLocation::from_str("unresolvable.invalid:53", None)
                    .unwrap()
                    .into(),
            )
            .unwrap();
        assert!(
            connect_prepared_udp(&selector, target, &real, true)
                .await
                .is_err(),
            "IP-only reply protocols must resolve a hostname or fail explicitly"
        );
    }

    #[tokio::test]
    async fn restored_target_is_frozen_and_override_to_53_does_not_reintercept() {
        let real: Arc<dyn Resolver> = Arc::new(RealDns);
        let context = Arc::new(
            FakeDnsContext::new(
                FakeIpOptions {
                    max_entries: 1,
                    ..Default::default()
                },
                real.clone(),
            )
            .unwrap(),
        );
        let override_address = NetLocation::from_str("127.0.0.1:53", None).unwrap();
        let selector = ClientProxySelector::new(vec![ConnectRule::new(
            vec![NetLocationMask::from("first.example").unwrap()],
            ConnectAction::new_allow(
                Some(override_address.clone()),
                crate::tcp::chain_builder::build_direct_chain_group(real.clone()),
            ),
        )])
        .with_fake_dns_context(Some(context.clone()))
        .unwrap();
        let fake = context.allocate("first.example", false).unwrap();
        let wire = NetLocation::from_ip_addr(fake, 443);
        let prepared = selector.prepare(wire.clone().into()).unwrap();
        context.allocate("second.example", false).unwrap();
        let route = route_prepared_udp(&selector, prepared, &real, false)
            .await
            .unwrap();
        let UdpRoute::Forward {
            target,
            reply_identity,
            ..
        } = route
        else {
            panic!("override must not dispatch locally")
        };
        assert_eq!(target.location(), &override_address);
        assert_eq!(reply_identity, wire);
        assert_eq!(
            selector.prepare(wire.into()).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }
}
