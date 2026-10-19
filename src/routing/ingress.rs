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

#[derive(Debug)]
struct PolicyBlock;

impl std::fmt::Display for PolicyBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Destination blocked by routing rules")
    }
}

impl std::error::Error for PolicyBlock {}

pub(crate) fn is_policy_block(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|cause| cause.is::<PolicyBlock>())
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
    require_ip_reply: bool,
) -> io::Result<UdpSetup> {
    route_prepared_udp(selector, target, resolver, require_ip_reply)
        .await?
        .connect(resolver)
        .await
}

async fn route_prepared_udp<'a>(
    selector: &'a ClientProxySelector,
    target: IngressTarget,
    resolver: &Arc<dyn Resolver>,
    require_ip_reply: bool,
) -> io::Result<UdpRoute<'a>> {
    let target = match target {
        IngressTarget::LocalDns {
            wire_destination,
            context,
        } => {
            let wire_destination = reply_destination(wire_destination, require_ip_reply);
            let reply_identity =
                if require_ip_reply && wire_destination.address().hostname().is_some() {
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
            let wire_destination = reply_destination(routed.wire_destination, require_ip_reply);
            let reply_identity =
                if require_ip_reply && wire_destination.address().hostname().is_some() {
                    let address = resolve_location(&mut remote_location, resolver).await?;
                    NetLocation::from_ip_addr(address.ip(), address.port())
                } else {
                    wire_destination
                };
            Ok(UdpRoute::Forward {
                chain: chain_group,
                target: remote_location,
                reply_identity,
            })
        }
        ConnectDecision::Block => Err(io::Error::new(io::ErrorKind::PermissionDenied, PolicyBlock)),
    }
}

fn reply_destination(wire_destination: NetLocation, require_ip_reply: bool) -> NetLocation {
    if require_ip_reply
        && let Some(hostname) = wire_destination.address().hostname()
        && let Ok(ip) = hostname.parse()
    {
        return NetLocation::from_ip_addr(ip, wire_destination.port());
    }
    wire_destination
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::address::NetLocationMask;
    use crate::client_proxy_selector::{ConnectAction, ConnectRule};
    use crate::dns::fake_ip::{FakeDnsContext, FakeIpOptions};
    use crate::resolver::{DnsExchangeFuture, ResolveFuture};
    use hickory_resolver::proto::op::{Message, Query, ResponseCode};
    use hickory_resolver::proto::rr::{Name, RecordType};
    use std::pin::Pin;
    use tokio::io::ReadBuf;

    #[derive(Clone, Copy)]
    pub(crate) enum PacketMode {
        Fixed,
        Uot,
        Socks,
    }

    impl PacketMode {
        fn address(self, target: &NetLocation) -> Vec<u8> {
            match self {
                Self::Fixed => Vec::new(),
                Self::Socks => crate::socks_handler::write_location_to_vec(target),
                Self::Uot => {
                    let mut bytes = vec![0; 260];
                    let len =
                        crate::uot::uot_common::write_uot_address(&mut bytes, target).unwrap();
                    bytes.truncate(len);
                    bytes
                }
            }
        }

        pub(crate) fn packet(self, target: &NetLocation, payload: &[u8]) -> Vec<u8> {
            let mut bytes = self.address(target);
            bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            bytes.extend_from_slice(payload);
            bytes
        }

        pub(crate) fn reply<'a>(self, target: &NetLocation, bytes: &'a [u8]) -> Option<&'a [u8]> {
            let address = self.address(target);
            if bytes.len() < address.len() + 2 {
                return None;
            }
            assert_eq!(
                &bytes[..address.len()],
                address,
                "wire reply identity changed"
            );
            let offset = address.len();
            let len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
            if bytes.len() < offset + 2 + len {
                return None;
            }
            assert_eq!(bytes.len(), offset + 2 + len, "unexpected extra datagram");
            Some(&bytes[offset + 2..])
        }
    }

    pub(crate) struct UdpFixture {
        pub selector: Arc<ClientProxySelector>,
        pub resolver: Arc<dyn Resolver>,
        pub target: NetLocation,
        dns: bool,
        payload: Vec<u8>,
    }

    impl UdpFixture {
        pub(crate) async fn new(dns: bool, tasks: &mut tokio::task::JoinSet<()>) -> Self {
            let resolver: Arc<dyn Resolver> = Arc::new(RealDns);
            let context =
                Arc::new(FakeDnsContext::new(Default::default(), resolver.clone()).unwrap());
            let payload = if dns {
                query(RecordType::A)
            } else {
                crate::sniff::tests::hello(&rustls::version::TLS13, true)
            };
            let mut rules = Vec::new();
            let target = if dns {
                NetLocation::from_str("unresolvable.invalid:53", None).unwrap()
            } else {
                let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
                let destination = NetLocation::from_str(
                    &format!("127.0.0.1:{}", socket.local_addr().unwrap().port()),
                    None,
                )
                .unwrap();
                let expected = payload.clone();
                tasks.spawn(async move {
                    let mut bytes = [0; 4096];
                    let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
                    assert_eq!(&bytes[..len], expected);
                    socket.send_to(&bytes[..len], peer).await.unwrap();
                });
                rules.push(ConnectRule::new(
                    vec![NetLocationMask::from("restored.example").unwrap()],
                    ConnectAction::new_allow(
                        Some(destination),
                        crate::tcp::chain_builder::build_direct_chain_group(resolver.clone()),
                    ),
                ));
                NetLocation::from_ip_addr(context.allocate("restored.example", false).unwrap(), 443)
            };
            // A TCP ClientHello would select this block, not the restored hostname.
            rules.insert(
                0,
                ConnectRule::new(
                    vec![NetLocationMask::from("sniff.example").unwrap()],
                    ConnectAction::Block,
                ),
            );
            let selector = Arc::new(
                ClientProxySelector::new(rules)
                    .with_sniff(true)
                    .with_fake_dns_context(Some(context))
                    .unwrap(),
            );
            Self {
                selector,
                resolver,
                target,
                dns,
                payload,
            }
        }

        pub(crate) fn request(&self, mode: PacketMode) -> Vec<u8> {
            let mut bytes = Vec::new();
            if self.dns {
                bytes.extend(mode.packet(&self.target, b"not DNS"));
            }
            bytes.extend(mode.packet(&self.target, &self.payload));
            bytes
        }

        pub(crate) fn uot_header(&self, fixed: bool) -> Vec<u8> {
            let mut bytes = vec![u8::from(fixed)];
            bytes.extend(crate::socks_handler::write_location_to_vec(&self.target));
            bytes
        }

        pub(crate) fn assert_reply(&self, payload: &[u8]) {
            if self.dns {
                let reply = Message::from_vec(payload).unwrap();
                assert_eq!(reply.metadata.id, 42);
                assert_eq!(
                    reply.queries,
                    Message::from_vec(&self.payload).unwrap().queries
                );
                assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
                assert!(matches!(
                    reply.answers[0].data,
                    hickory_resolver::proto::rr::RData::A(_)
                ));
            } else {
                assert_eq!(payload, self.payload);
            }
        }

        pub(crate) async fn read_reply(
            &self,
            peer: &mut (impl tokio::io::AsyncRead + Unpin),
            mode: PacketMode,
        ) {
            use tokio::io::AsyncReadExt;
            let mut bytes = Vec::new();
            loop {
                bytes.push(peer.read_u8().await.unwrap());
                if let Some(payload) = mode.reply(&self.target, &bytes) {
                    self.assert_reply(payload);
                    break;
                }
            }
        }
    }

    #[tokio::test]
    async fn policy_block_is_distinct_from_transport_permission_denial() {
        let resolver: Arc<dyn Resolver> = Arc::new(RealDns);
        let selector = ClientProxySelector::new(Vec::new());
        let blocked = route_udp(
            &selector,
            NetLocation::from_str("192.0.2.1:443", None).unwrap(),
            &resolver,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(blocked.kind(), io::ErrorKind::PermissionDenied);
        assert!(is_policy_block(&blocked));
        assert!(!is_policy_block(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "outbound handshake rejected"
        )));
    }

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
    async fn snell_dns_hostname_replies_are_resolved_before_ip_only_framing() {
        use crate::async_stream::{
            AsyncFlushMessage, AsyncReadSourcedMessage, AsyncWriteTargetedMessage,
        };
        use crate::snell::snell_udp_stream::{SnellUdpClientStream, SnellUdpStream};
        use futures::future::poll_fn;

        #[derive(Debug)]
        struct DnsAddress;
        impl Resolver for DnsAddress {
            fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
                assert_eq!(location.to_string(), "dns.example:53");
                Box::pin(async { Ok(vec!["192.0.2.53:53".parse().unwrap()]) })
            }
        }

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let resolver: Arc<dyn Resolver> = Arc::new(DnsAddress);
            let context =
                Arc::new(FakeDnsContext::new(Default::default(), resolver.clone()).unwrap());
            let selector = Arc::new(
                ClientProxySelector::new(vec![])
                    .with_fake_dns_context(Some(context))
                    .unwrap(),
            );
            let (client, server) = tokio::io::duplex(8192);
            let server = SnellUdpStream::new(
                Box::new(crate::vless::VlessMessageStream::new(Box::new(server))),
                4096,
            );
            let _server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(
                crate::routing::run_udp_routing(
                    crate::routing::ServerStream::Targeted(Box::new(server)),
                    selector,
                    resolver,
                    false,
                ),
            ));
            let mut client = SnellUdpClientStream::new(
                Box::new(crate::vless::VlessMessageStream::new(Box::new(client))),
                4096,
            );
            let target = NetLocation::from_str("dns.example:53", None).unwrap();
            for payload in [b"not DNS".to_vec(), query(RecordType::A)] {
                poll_fn(|cx| {
                    Pin::new(&mut client).poll_write_targeted_message(cx, &payload, &target)
                })
                .await
                .unwrap();
                poll_fn(|cx| Pin::new(&mut client).poll_flush_message(cx))
                    .await
                    .unwrap();
            }
            let mut bytes = [0; 4096];
            let mut buf = ReadBuf::new(&mut bytes);
            let source =
                poll_fn(|cx| Pin::new(&mut client).poll_read_sourced_message(cx, &mut buf))
                    .await
                    .unwrap();
            assert_eq!(source, "192.0.2.53:53".parse().unwrap());
            let response = Message::from_vec(buf.filled()).unwrap();
            assert_eq!(response.metadata.id, 42);
            assert_eq!(response.answers.len(), 1);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn legacy_replies_preserve_domain_encoded_fake_ips_without_resolution() {
        let real: Arc<dyn Resolver> = Arc::new(RealDns);
        let context = Arc::new(FakeDnsContext::new(Default::default(), real.clone()).unwrap());
        let selector = ClientProxySelector::new(vec![ConnectRule::new(
            vec![NetLocationMask::from("encoded.example").unwrap()],
            ConnectAction::new_allow(
                None,
                crate::tcp::chain_builder::build_direct_chain_group(real.clone()),
            ),
        )])
        .with_fake_dns_context(Some(context.clone()))
        .unwrap();
        let fake = context.allocate("encoded.example", false).unwrap();
        for text in [fake.to_string(), format!("::ffff:{fake}")] {
            for port in [53, 443] {
                let wire = NetLocation::new(crate::address::Address::Hostname(text.clone()), port);
                let expected = NetLocation::from_ip_addr(text.parse().unwrap(), port);
                let route = route_prepared_udp(
                    &selector,
                    selector.prepare(wire.into()).unwrap(),
                    &real,
                    true,
                )
                .await
                .unwrap();
                match route {
                    UdpRoute::Local(setup) => {
                        assert_eq!(port, 53);
                        assert_eq!(setup.reply_identity, expected);
                    }
                    UdpRoute::Forward {
                        target,
                        reply_identity,
                        ..
                    } => {
                        assert_eq!(port, 443);
                        assert_eq!(reply_identity, expected);
                        assert_eq!(target.address().hostname(), Some("encoded.example"));
                        assert!(target.resolved_addr().is_none());
                    }
                }
            }
        }
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
