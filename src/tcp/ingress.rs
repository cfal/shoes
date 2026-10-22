use std::io;
use std::sync::Arc;

use tokio::io::AsyncRead;

use crate::address::NetLocation;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision, IngressTarget};
use crate::resolver::Resolver;
use crate::sniff::{SNIFF_TIMEOUT, StreamProbe};

use super::tcp_handler::TcpClientSetupResult;

pub(crate) struct PreparedTcp {
    target: IngressTarget,
    prefix: Vec<u8>,
    probe: Option<StreamProbe>,
    source: Option<std::net::SocketAddr>,
}

pub(crate) struct RoutedTcp {
    pub wire_destination: NetLocation,
    pub is_local_dns: bool,
    pub setup: Option<TcpClientSetupResult>,
    pub prefix: Vec<u8>,
}

pub(crate) struct TcpRoute<'a> {
    wire_destination: NetLocation,
    prefix: Vec<u8>,
    target: TcpRouteTarget<'a>,
    info: crate::control::flows::FlowInfo,
}

enum TcpRouteTarget<'a> {
    LocalDns(Arc<crate::dns::fake_ip::FakeDnsContext>),
    Forward(ConnectDecision<'a>),
}

impl TcpRoute<'_> {
    pub(crate) async fn connect(self, resolver: &Arc<dyn Resolver>) -> io::Result<RoutedTcp> {
        let is_local_dns = matches!(&self.target, TcpRouteTarget::LocalDns(_));
        let setup = match self.target {
            TcpRouteTarget::LocalDns(context) => Some(TcpClientSetupResult {
                client_stream: context.tcp_stream(),
                early_data: None,
            }),
            TcpRouteTarget::Forward(ConnectDecision::Allow {
                chain_group,
                remote_location,
            }) => Some(
                chain_group
                    .connect_tcp_with_info(remote_location, resolver, self.info)
                    .await?,
            ),
            TcpRouteTarget::Forward(ConnectDecision::Block) => None,
        };
        Ok(RoutedTcp {
            wire_destination: self.wire_destination,
            is_local_dns,
            setup,
            prefix: self.prefix,
        })
    }
}

impl PreparedTcp {
    pub(crate) fn new(
        selector: &ClientProxySelector,
        target: NetLocation,
        mut prefix: Vec<u8>,
    ) -> io::Result<Self> {
        let target = selector.prepare(target.into())?;
        let probe = match &target {
            IngressTarget::Forward(target) if selector.should_sniff(target) => {
                Some(StreamProbe::from_prefix(std::mem::take(&mut prefix)))
            }
            _ => None,
        };
        Ok(Self {
            target,
            prefix,
            probe,
            source: None,
        })
    }

    pub(crate) fn with_source(mut self, source: Option<std::net::SocketAddr>) -> Self {
        self.source = source;
        self
    }

    pub(crate) fn needs_sniff_read(&self) -> bool {
        self.probe.as_ref().is_some_and(StreamProbe::needs_more)
    }

    #[cfg(test)]
    pub(crate) async fn connect<R: AsyncRead + Unpin + ?Sized>(
        self,
        inbound: &mut R,
        selector: &ClientProxySelector,
        resolver: &Arc<dyn Resolver>,
    ) -> io::Result<RoutedTcp> {
        self.route(inbound, selector, resolver)
            .await?
            .connect(resolver)
            .await
    }

    // Protocol adapters send any required optimistic reply before calling this method.
    pub(crate) async fn route<'a, R: AsyncRead + Unpin + ?Sized>(
        self,
        inbound: &mut R,
        selector: &'a ClientProxySelector,
        resolver: &Arc<dyn Resolver>,
    ) -> io::Result<TcpRoute<'a>> {
        let (hostname, prefix) = if let Some(probe) = self.probe {
            let result = probe.finish(inbound, SNIFF_TIMEOUT).await?;
            (result.hostname, result.prefix)
        } else {
            (None, self.prefix)
        };
        let mut info = crate::control::flows::FlowInfo::default();
        if selector.tracks_flows()
            && let IngressTarget::Forward(target) = &self.target
        {
            info = target.flow_info();
            info.source = self.source;
            info.sniff_host = hostname.clone();
        }
        let (wire_destination, target) = match self.target {
            IngressTarget::LocalDns {
                wire_destination,
                context,
            } => (wire_destination, TcpRouteTarget::LocalDns(context)),
            IngressTarget::Forward(target) => {
                let routed = selector
                    .judge_prepared(target, hostname.as_deref(), resolver)
                    .await?;
                (
                    routed.wire_destination,
                    TcpRouteTarget::Forward(routed.decision),
                )
            }
        };
        Ok(TcpRoute {
            wire_destination,
            target,
            prefix,
            info,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::address::{NetLocationMask, ResolvedLocation};
    use crate::async_stream::{AsyncMessageStream, AsyncStream};
    use crate::client_proxy_chain::{ClientChainGroup, ClientProxyChain, InitialHopEntry};
    use crate::client_proxy_selector::{ConnectAction, ConnectRule};
    use crate::tcp::socket_connector::SocketConnector;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::task::JoinSet;

    pub(crate) const TARGET: &str = "203.0.113.1:443";

    #[derive(Debug)]
    struct FailedConnector;

    #[async_trait::async_trait]
    impl SocketConnector for FailedConnector {
        async fn connect(
            &self,
            _: &Arc<dyn Resolver>,
            _: &ResolvedLocation,
        ) -> io::Result<Box<dyn AsyncStream>> {
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "test dial failure",
            ))
        }

        async fn connect_udp_bidirectional(
            &self,
            _: &Arc<dyn Resolver>,
            _: ResolvedLocation,
        ) -> io::Result<Box<dyn AsyncMessageStream>> {
            unreachable!()
        }

        fn bind_interface(&self) -> Option<&str> {
            None
        }
    }

    pub(crate) fn failure_selector(sniff: bool, blocked: bool) -> Arc<ClientProxySelector> {
        let action = if blocked {
            ConnectAction::Block
        } else {
            ConnectAction::new_allow(
                None,
                ClientChainGroup::new(vec![ClientProxyChain::new(
                    vec![InitialHopEntry::Direct(Arc::new(FailedConnector))],
                    vec![],
                )]),
            )
        };
        Arc::new(
            ClientProxySelector::new(vec![ConnectRule::new(
                vec![
                    NetLocationMask::from("sniff.example").unwrap(),
                    NetLocationMask::ANY,
                ],
                action,
            )])
            .with_sniff(sniff),
        )
    }

    pub(crate) async fn socks_target(
        expected: Vec<u8>,
        tasks: &mut JoinSet<()>,
    ) -> (Arc<ClientProxySelector>, Arc<dyn Resolver>) {
        socks_target_at(expected, TARGET, "sniff.example", tasks).await
    }

    async fn socks_target_at(
        expected: Vec<u8>,
        target: &str,
        mask: &str,
        tasks: &mut JoinSet<()>,
    ) -> (Arc<ClientProxySelector>, Arc<dyn Resolver>) {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let rule = serde_yaml::from_str(&format!(
            "masks: {mask}\nclient_proxy:\n  address: '127.0.0.1:{}'\n  protocol: {{type: socks}}\n",
            listener.local_addr().unwrap().port(),
        ))
        .unwrap();
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let selector = Arc::new(
            crate::tcp::tcp_client_handler_factory::create_test_selector(
                vec![rule],
                resolver.clone(),
            )
            .unwrap()
            .with_sniff(true),
        );
        let target = NetLocation::from_str(target, None).unwrap();
        tasks.spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            socket.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            socket.write_all(&[5, 0]).await.unwrap();
            let mut request = [0; 3];
            socket.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [5, 1, 0]);
            assert_eq!(
                crate::socks_handler::read_location_direct(&mut socket)
                    .await
                    .unwrap(),
                target
            );
            socket
                .write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00greeting")
                .await
                .unwrap();
            let mut payload = Vec::new();
            socket.read_to_end(&mut payload).await.unwrap();
            assert_eq!(payload, expected);
            socket.write_all(b"later").await.unwrap();
        });
        (selector, resolver)
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum FakeTcpCase {
        Dns,
        Tls,
        Http,
        Plain,
        Unknown,
    }

    impl FakeTcpCase {
        pub(crate) async fn fixture(
            self,
            tasks: &mut JoinSet<()>,
        ) -> (
            Arc<ClientProxySelector>,
            Arc<dyn Resolver>,
            NetLocation,
            Vec<u8>,
        ) {
            let payload = match self {
                Self::Tls => crate::sniff::tests::hello(&rustls::version::TLS13, true),
                Self::Http => crate::sniff::tests::http_request(),
                Self::Plain => b"not TLS".to_vec(),
                Self::Dns => {
                    use hickory_resolver::proto::{
                        op::{Message, Query},
                        rr::{Name, RecordType},
                    };
                    let mut query = Message::query();
                    query.metadata.id = 71;
                    query.add_query(Query::query(
                        Name::from_ascii("adapter.example.").unwrap(),
                        RecordType::A,
                    ));
                    let bytes = query.to_vec().unwrap();
                    let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
                    framed.extend(bytes);
                    framed
                }
                Self::Unknown => Vec::new(),
            };
            let (selector, resolver) = if matches!(self, Self::Tls | Self::Http | Self::Plain) {
                socks_target_at(
                    payload.clone(),
                    "restored.example:443",
                    if matches!(self, Self::Tls | Self::Http) {
                        "sniff.example"
                    } else {
                        "restored.example"
                    },
                    tasks,
                )
                .await
            } else {
                (
                    failure_selector(true, true),
                    Arc::new(crate::resolver::NativeResolver::new()) as Arc<dyn Resolver>,
                )
            };
            let context = Arc::new(
                crate::dns::fake_ip::FakeDnsContext::new(Default::default(), resolver.clone())
                    .unwrap(),
            );
            let target = match self {
                Self::Dns => NetLocation::from_str("198.18.0.1:53", None).unwrap(),
                Self::Unknown => NetLocation::from_str("198.18.0.1:443", None).unwrap(),
                _ => NetLocation::from_ip_addr(
                    context.allocate("restored.example", false).unwrap(),
                    443,
                ),
            };
            let selector = Arc::new(
                Arc::try_unwrap(selector)
                    .unwrap()
                    .with_fake_dns_context(Some(context))
                    .unwrap(),
            );
            (selector, resolver, target, payload)
        }

        pub(crate) fn assert_reply(self, bytes: &[u8]) {
            if self == Self::Dns {
                use hickory_resolver::proto::{op::Message, rr::RData};
                assert!(bytes.len() >= 2);
                assert_eq!(
                    u16::from_be_bytes([bytes[0], bytes[1]]) as usize,
                    bytes.len() - 2
                );
                let response = Message::from_vec(&bytes[2..]).unwrap();
                assert_eq!(response.metadata.id, 71);
                assert_eq!(response.answers.len(), 1);
                let RData::A(ip) = response.answers[0].data else {
                    panic!("not a synthetic answer")
                };
                assert_eq!(ip.0.octets()[0], 198);
                assert_eq!(ip.0.octets()[1] & 254, 18);
            } else {
                assert_eq!(bytes, b"greetinglater");
            }
        }
    }

    #[tokio::test]
    async fn http_host_routes_only_the_original_destination_and_port() {
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        for fake in [false, true] {
            let context = Arc::new(
                crate::dns::fake_ip::FakeDnsContext::new(Default::default(), resolver.clone())
                    .unwrap(),
            );
            let target = if fake {
                NetLocation::from_ip_addr(context.allocate("restored.example", false).unwrap(), 443)
            } else {
                NetLocation::from_str(TARGET, None).unwrap()
            };
            let rule = serde_yaml::from_str("masks: sniff.example:443\naction: allow").unwrap();
            let selector = crate::tcp::tcp_client_handler_factory::create_test_selector(
                vec![rule],
                resolver.clone(),
            )
            .unwrap()
            .with_sniff(true)
            .with_fake_dns_context(fake.then_some(context))
            .unwrap();
            let bytes = b"GET / HTTP/1.1\r\nHost: SnIfF.Example.:80\r\n\r\n";
            for split in [0, 5, bytes.len()] {
                let prepared =
                    PreparedTcp::new(&selector, target.clone(), bytes[..split].to_vec()).unwrap();
                assert_eq!(prepared.needs_sniff_read(), split < bytes.len());
                let route = prepared
                    .route(&mut &bytes[split..], &selector, &resolver)
                    .await
                    .unwrap();
                assert_eq!(route.wire_destination, target);
                assert_eq!(route.prefix, bytes);
                let TcpRouteTarget::Forward(ConnectDecision::Allow {
                    remote_location, ..
                }) = route.target
                else {
                    panic!("Host-only rule did not match")
                };
                assert_eq!(
                    remote_location.location().to_string(),
                    if fake { "restored.example:443" } else { TARGET }
                );
            }
        }
    }

    #[tokio::test]
    async fn http_sniff_example_blocks_private_targets_before_host_allows() {
        use crate::config::{Config, ConfigSelection, ServerProxyConfig};

        let mut configs = crate::config::create_server_configs(
            serde_yaml::from_str(include_str!("../../examples/http_host_sniffing.yaml")).unwrap(),
        )
        .unwrap();
        let Config::Server(config) = configs.configs.remove(0) else {
            panic!("expected server config")
        };
        assert!(matches!(
            config.protocol,
            ServerProxyConfig::Socks {
                username: Some(_),
                password: Some(_),
                ..
            }
        ));
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let rules = config.rules.map(ConfigSelection::unwrap_config).into_vec();
        let selector =
            crate::tcp::tcp_client_handler_factory::create_test_selector(rules, resolver.clone())
                .unwrap()
                .with_sniff(config.sniff);
        for (target, blocked) in [
            ("0.0.0.0:80", true),
            ("[::]:80", true),
            ("[::ffff:0.0.0.0]:80", true),
            ("10.0.0.1:80", true),
            ("172.16.0.1:80", true),
            ("192.168.0.1:80", true),
            ("127.0.0.1:80", true),
            ("169.254.169.254:80", true),
            ("[::1]:80", true),
            ("[fc00::1]:80", true),
            ("[fe80::1]:80", true),
            ("[::ffff:127.0.0.1]:80", true),
            ("192.0.2.1:80", false),
            ("[2001:db8::1]:80", false),
        ] {
            let prepared = PreparedTcp::new(
                &selector,
                NetLocation::from_str(target, None).unwrap(),
                b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
            )
            .unwrap();
            let route = prepared
                .route(&mut tokio::io::empty(), &selector, &resolver)
                .await
                .unwrap();
            assert_eq!(
                matches!(
                    route.target,
                    TcpRouteTarget::Forward(ConnectDecision::Block)
                ),
                blocked,
                "{target}"
            );
        }
    }

    #[tokio::test]
    async fn http_sniff_eligibility_and_misses_keep_ordinary_routing() {
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        for enabled in [false, true] {
            let rules = serde_yaml::from_str(
                "- masks: sniff.example\n  action: block\n- masks: 0.0.0.0/0\n  action: allow",
            )
            .unwrap();
            let selector = crate::tcp::tcp_client_handler_factory::create_test_selector(
                rules,
                resolver.clone(),
            )
            .unwrap()
            .with_sniff(enabled);
            for (target, bytes, blocked) in [
                (TARGET, crate::sniff::tests::http_request(), enabled),
                (
                    "supplied.example:443",
                    crate::sniff::tests::http_request(),
                    false,
                ),
                (
                    TARGET,
                    b"GET / HTTP/1.1\r\nHost: sniff.example\r\nHost: other.example\r\n\r\n"
                        .to_vec(),
                    false,
                ),
                (
                    TARGET,
                    b"GET / HTTP/1.1\r\n\r\nHost: sniff.example".to_vec(),
                    false,
                ),
            ] {
                let prepared = PreparedTcp::new(
                    &selector,
                    NetLocation::from_str(target, None).unwrap(),
                    bytes.clone(),
                )
                .unwrap();
                assert!(!prepared.needs_sniff_read());
                let route = prepared
                    .route(&mut tokio::io::empty(), &selector, &resolver)
                    .await
                    .unwrap();
                assert_eq!(
                    matches!(
                        route.target,
                        TcpRouteTarget::Forward(ConnectDecision::Block)
                    ),
                    blocked
                );
                assert_eq!(route.prefix, bytes);
            }
        }
    }

    #[tokio::test]
    async fn local_dns_is_ready_without_a_query_and_fake_names_are_probed() {
        use crate::dns::fake_ip::{FakeDnsContext, FakeIpOptions};
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let context =
            Arc::new(FakeDnsContext::new(FakeIpOptions::default(), resolver.clone()).unwrap());
        let selector =
            ClientProxySelector::new(vec![crate::client_proxy_selector::ConnectRule::new(
                vec![crate::address::NetLocationMask::from("sniff.example").unwrap()],
                crate::client_proxy_selector::ConnectAction::Block,
            )])
            .with_sniff(true)
            .with_fake_dns_context(Some(context.clone()))
            .unwrap();
        let target = NetLocation::from_str("192.0.2.1:53", None).unwrap();
        let prepared = PreparedTcp::new(&selector, target.clone(), Vec::new()).unwrap();
        assert!(!prepared.needs_sniff_read());
        let mut no_read = tokio::io::empty();
        let routed = tokio::time::timeout(
            std::time::Duration::from_millis(10),
            prepared.connect(&mut no_read, &selector, &resolver),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(routed.wire_destination, target);
        assert!(routed.setup.is_some());
        let ip = context.allocate("restored.example", false).unwrap();
        let target = NetLocation::from_str(&format!("{ip}:443"), None).unwrap();
        assert!(
            PreparedTcp::new(&selector, target.clone(), Vec::new())
                .unwrap()
                .needs_sniff_read()
        );
        let hello = crate::sniff::tests::hello(&rustls::version::TLS13, true);
        let prepared = PreparedTcp::new(&selector, target, hello.clone()).unwrap();
        assert!(!prepared.needs_sniff_read());
        let routed = prepared
            .connect(&mut no_read, &selector, &resolver)
            .await
            .unwrap();
        assert!(routed.setup.is_none());
        assert_eq!(routed.prefix, hello);
    }
}
