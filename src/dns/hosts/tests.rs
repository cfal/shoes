use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_resolver::proto::op::{Edns, Query};
use hickory_resolver::proto::rr::Name;
use serde_json::json;

use crate::dns::{DnsContext, build_dns_registry};

fn hosts(yaml: &str) -> StaticHosts {
    serde_yaml::from_str(yaml).unwrap()
}

fn request(name: &str, kind: RecordType) -> Message {
    let mut request = Message::query();
    request.metadata.id = 123;
    request.metadata.recursion_desired = true;
    request.metadata.checking_disabled = true;
    request.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    request
}

#[test]
fn hosts_validate_normalize_and_round_trip() {
    let table = hosts(
        "MiXeD.Example.: [192.0.2.2, '2001:db8::1', 192.0.2.1, 192.0.2.2]\nsingle: 192.0.2.2",
    );
    let expected =
        ["192.0.2.2", "2001:db8::1", "192.0.2.1"].map(|ip| ip.parse::<IpAddr>().unwrap());
    assert_eq!(table.lookup("MIXED.EXAMPLE").unwrap(), expected);
    assert_eq!(
        table.lookup("single.").unwrap()[0],
        "192.0.2.2".parse::<IpAddr>().unwrap()
    );
    for table in [
        serde_yaml::from_str::<StaticHosts>(&serde_yaml::to_string(&table).unwrap()).unwrap(),
        serde_json::from_str::<StaticHosts>(&serde_json::to_string(&table).unwrap()).unwrap(),
    ] {
        assert_eq!(table.lookup("mixed.example.").unwrap(), expected);
    }
    for yaml in [
        "example: []",
        "example: null",
        "example: bogus",
        "example: 123",
        "example: [192.0.2.1, invalid]",
        "example: 0.0.0.0",
        "example: '::'",
        "example: '::ffff:0.0.0.0'",
        "'*.example': 192.0.2.1",
        "'': 192.0.2.1",
        "'127.0.0.1': 192.0.2.1",
        "bad_name: 192.0.2.1",
        "foo..bar: 192.0.2.1",
        "'-example': 192.0.2.1",
        "example..: 192.0.2.1",
        "null",
        "[]",
        "example: 192.0.2.1\nEXAMPLE.: 192.0.2.2",
        "example: 192.0.2.1\nexample: 192.0.2.2",
    ] {
        assert!(
            serde_yaml::from_str::<StaticHosts>(yaml).is_err(),
            "accepted {yaml}"
        );
    }
}

#[derive(Debug, Default)]
struct Fallback {
    lookups: AtomicUsize,
    exchanges: AtomicUsize,
    deadlines: AtomicUsize,
}

impl Resolver for Fallback {
    fn resolve_location(&self, _: &NetLocation) -> ResolveFuture {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(vec!["192.0.2.99:99".parse().unwrap()]) })
    }

    fn exchange(&self, bytes: Vec<u8>) -> DnsExchangeFuture {
        self.exchanges.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok(bytes) })
    }

    fn exchange_with_deadline(&self, bytes: Vec<u8>, _: tokio::time::Instant) -> DnsExchangeFuture {
        self.deadlines.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok(bytes) })
    }
}

#[tokio::test]
async fn hosts_connection_lookup_preserves_all_candidates_and_ports_without_fallback() {
    let fallback = Arc::new(Fallback::default());
    let resolver = HostsResolver::wrap(
        Arc::new(hosts(
            "proxy.test: [47.238.193.242, '2001:db8::1', 47.238.137.75, 47.238.193.242]",
        )),
        fallback.clone(),
    );
    for name in ["proxy.test", "PrOxY.TeSt."] {
        for port in [0, 443, 8443] {
            let location = NetLocation::new(crate::address::Address::Hostname(name.into()), port);
            let addresses = resolver.resolve_location(&location).await.unwrap();
            let expected = ["47.238.193.242", "2001:db8::1", "47.238.137.75"]
                .map(|ip| SocketAddr::new(ip.parse().unwrap(), port));
            assert_eq!(addresses, expected);
            assert_eq!(location.address().hostname(), Some(name));
        }
    }
    assert_eq!(fallback.lookups.load(Ordering::SeqCst), 0);
    resolver
        .resolve_location(&NetLocation::from_str("other.test:443", None).unwrap())
        .await
        .unwrap();
    assert_eq!(fallback.lookups.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn hosts_exchange_answers_both_families_and_nodata_without_fallback() {
    let fallback = Arc::new(Fallback::default());
    let resolver = HostsResolver::wrap(
        Arc::new(hosts(
            "proxy.test: [192.0.2.2, '2001:db8::2', 192.0.2.1, '2001:db8::1', 192.0.2.2, '2001:db8::2']\nv4.test: 192.0.2.3\nv6.test: '2001:db8::3'",
        )),
        fallback.clone(),
    );
    let cases: &[(&str, RecordType, &[&str])] = &[
        ("PrOxY.TeSt.", RecordType::A, &["192.0.2.2", "192.0.2.1"]),
        (
            "proxy.test.",
            RecordType::AAAA,
            &["2001:db8::2", "2001:db8::1"],
        ),
        ("v4.test.", RecordType::AAAA, &[]),
        ("v6.test.", RecordType::A, &[]),
    ];
    for &(name, kind, expected) in cases {
        let expected: Vec<IpAddr> = expected.iter().map(|ip| ip.parse().unwrap()).collect();
        let mut query = request(name, kind);
        query.edns = Some(Edns::new());
        query.edns.as_mut().unwrap().set_dnssec_ok(true);
        let bytes = query.to_vec().unwrap();
        for reply in [
            resolver.exchange(bytes.clone()).await.unwrap(),
            resolver
                .exchange_with_deadline(bytes, tokio::time::Instant::now() + Duration::from_secs(1))
                .await
                .unwrap(),
        ] {
            let answer = Message::from_vec(&reply).unwrap();
            let addresses: Vec<_> = answer
                .answers
                .iter()
                .map(|record| match record.data {
                    RData::A(ip) => IpAddr::V4(ip.0),
                    RData::AAAA(ip) => IpAddr::V6(ip.0),
                    _ => panic!("unexpected record: {record:?}"),
                })
                .collect();
            assert_eq!(addresses, expected);
            assert_eq!(answer.queries, query.queries);
            assert_eq!(
                answer.queries[0].name.to_ascii(),
                query.queries[0].name.to_ascii()
            );
            assert_eq!(answer.metadata.id, 123);
            assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
            assert!(answer.metadata.recursion_desired && answer.metadata.checking_disabled);
            assert!(answer.metadata.recursion_available);
            assert!(!answer.metadata.authentic_data && !answer.metadata.authoritative);
            assert!(answer.edns.unwrap().flags().dnssec_ok);
            assert!(
                answer
                    .answers
                    .iter()
                    .all(|record| record.ttl == 60 && record.record_type() == kind)
            );
        }
    }
    assert_eq!(fallback.exchanges.load(Ordering::SeqCst), 0);
    assert_eq!(fallback.deadlines.load(Ordering::SeqCst), 0);
    for (name, kind) in [
        ("other.test", RecordType::A),
        ("proxy.test", RecordType::TXT),
        ("proxy.test", RecordType::HTTPS),
    ] {
        let bytes = request(name, kind).to_vec().unwrap();
        assert_eq!(resolver.exchange(bytes.clone()).await.unwrap(), bytes);
        assert_eq!(
            resolver
                .exchange_with_deadline(bytes.clone(), tokio::time::Instant::now())
                .await
                .unwrap(),
            bytes
        );
    }
    assert_eq!(fallback.exchanges.load(Ordering::SeqCst), 3);
    assert_eq!(fallback.deadlines.load(Ordering::SeqCst), 3);
}

fn groups(config: serde_json::Value) -> Vec<crate::config::ExpandedDnsGroup> {
    crate::config::create_server_configs(serde_json::from_value(config).unwrap())
        .unwrap()
        .dns_groups
}

#[tokio::test]
async fn hosts_malformed_mapped_queries_never_fall_through() {
    use crate::dns::fake_ip::FakeIpOptions;
    use hickory_resolver::proto::op::{MessageType, OpCode};

    let table = Arc::new(hosts("v4.test: 192.0.2.3"));
    let fallback = Arc::new(Fallback::default());
    let resolver = HostsResolver::wrap(table.clone(), fallback.clone());
    let contexts = [
        DnsContext::real(resolver.clone()),
        DnsContext::new(FakeIpOptions::default(), resolver.clone())
            .unwrap()
            .with_hosts(table),
    ];
    for mutation in 0..8 {
        let mut query = request("v4.test", RecordType::AAAA);
        let record = Record::from_rdata(
            Name::from_ascii("extra.test").unwrap(),
            60,
            RData::A(rdata::A("192.0.2.4".parse().unwrap())),
        );
        let expected = match mutation {
            0 => {
                query.metadata.truncation = true;
                ResponseCode::FormErr
            }
            1 => {
                query.answers.push(record);
                ResponseCode::FormErr
            }
            2 => {
                query.authorities.push(record);
                ResponseCode::FormErr
            }
            3 => {
                query.additionals.push(record);
                ResponseCode::FormErr
            }
            4 => {
                query.metadata.response_code = ResponseCode::NXDomain;
                ResponseCode::FormErr
            }
            5 => {
                query.queries.insert(
                    0,
                    Query::query(Name::from_ascii("unmapped.test").unwrap(), RecordType::A),
                );
                ResponseCode::FormErr
            }
            6 => {
                query.metadata.op_code = OpCode::Update;
                ResponseCode::Refused
            }
            _ => {
                let mut edns = Edns::new();
                edns.set_version(1);
                query.edns = Some(edns);
                ResponseCode::BADVERS
            }
        };
        let bytes = query.to_vec().unwrap();
        let mut replies = vec![
            resolver.exchange(bytes.clone()).await.unwrap(),
            resolver
                .exchange_with_deadline(bytes.clone(), tokio::time::Instant::now())
                .await
                .unwrap(),
        ];
        for context in &contexts {
            for tcp in [false, true] {
                replies.push(context.exchange(bytes.clone(), tcp).await.unwrap().unwrap());
            }
        }
        for reply in replies {
            let reply = Message::from_vec(&reply).unwrap();
            assert_eq!(
                u16::from(reply.metadata.response_code),
                u16::from(expected),
                "mutation {mutation}"
            );
            assert!(reply.answers.is_empty());
        }
    }
    let mut response = request("v4.test", RecordType::AAAA);
    response.metadata.message_type = MessageType::Response;
    let bytes = response.to_vec().unwrap();
    assert!(resolver.exchange(bytes.clone()).await.is_err());
    assert!(
        resolver
            .exchange_with_deadline(bytes.clone(), tokio::time::Instant::now())
            .await
            .is_err()
    );
    for context in contexts {
        assert!(
            context
                .exchange(bytes.clone(), true)
                .await
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(fallback.exchanges.load(Ordering::SeqCst), 0);
    assert_eq!(fallback.deadlines.load(Ordering::SeqCst), 0);

    let mut unmapped = request("unmapped.test", RecordType::A);
    unmapped.metadata.truncation = true;
    unmapped.metadata.op_code = OpCode::Update;
    let mut other_class = request("v4.test", RecordType::A);
    other_class.queries[0].query_class = DNSClass::CH;
    for bytes in [
        vec![1, 2, 3],
        unmapped.to_vec().unwrap(),
        other_class.to_vec().unwrap(),
    ] {
        assert_eq!(resolver.exchange(bytes.clone()).await.unwrap(), bytes);
        assert_eq!(
            resolver
                .exchange_with_deadline(bytes.clone(), tokio::time::Instant::now())
                .await
                .unwrap(),
            bytes
        );
    }
    assert_eq!(fallback.exchanges.load(Ordering::SeqCst), 3);
    assert_eq!(fallback.deadlines.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn hosts_survive_backend_refresh_without_using_it() {
    use crate::resolver::{RefreshPolicy, RefreshingResolver, ResolverFactory};

    #[derive(Debug)]
    struct Stale;
    impl Resolver for Stale {
        fn resolve_location(&self, _: &NetLocation) -> ResolveFuture {
            Box::pin(async { Err(io::ErrorKind::ConnectionReset.into()) })
        }
    }
    let builds = Arc::new(AtomicUsize::new(0));
    let fallback = Arc::new(Fallback::default());
    let factory: ResolverFactory = {
        let builds = builds.clone();
        let fallback = fallback.clone();
        Arc::new(move || {
            let resolver: Arc<dyn Resolver> = if builds.fetch_add(1, Ordering::SeqCst) == 0 {
                Arc::new(Stale)
            } else {
                fallback.clone()
            };
            Box::pin(async move { Ok(resolver) })
        })
    };
    let backend = RefreshingResolver::new(
        factory,
        RefreshPolicy {
            max_idle: Duration::from_secs(60),
        },
        "hosts-test".into(),
    )
    .await
    .unwrap();
    let resolver = HostsResolver::wrap(Arc::new(hosts("proxy.test: 192.0.2.1")), Arc::new(backend));
    for (phase, generation) in [1, 1, 2].into_iter().enumerate() {
        assert_eq!(
            resolver
                .resolve_location(&NetLocation::from_str("proxy.test:443", None).unwrap())
                .await
                .unwrap(),
            vec!["192.0.2.1:443".parse::<SocketAddr>().unwrap()]
        );
        let query = request("proxy.test", RecordType::AAAA).to_vec().unwrap();
        for reply in [
            resolver.exchange(query.clone()).await.unwrap(),
            resolver
                .exchange_with_deadline(query, tokio::time::Instant::now())
                .await
                .unwrap(),
        ] {
            assert!(Message::from_vec(&reply).unwrap().answers.is_empty());
        }
        assert_eq!(builds.load(Ordering::SeqCst), generation);
        assert_eq!(fallback.lookups.load(Ordering::SeqCst), generation - 1);
        assert_eq!(fallback.exchanges.load(Ordering::SeqCst), 0);
        assert_eq!(fallback.deadlines.load(Ordering::SeqCst), 0);
        if phase < 2 {
            let result = resolver
                .resolve_location(&NetLocation::from_str("other.test:443", None).unwrap())
                .await;
            if phase == 0 {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
                assert_eq!(builds.load(Ordering::SeqCst), 1);
            } else {
                result.unwrap();
                assert_eq!(builds.load(Ordering::SeqCst), 2);
            }
        }
    }
}

#[tokio::test]
async fn hosts_only_inline_and_default_maps_share_native_fallback_without_leaking() {
    use crate::config::{ResolvedConfig, create_server_configs};

    let validated = create_server_configs(
        serde_json::from_value(json!([
            {"global_settings": {"default_dns": {"hosts": {"proxy.invalid": "192.0.2.1"}}}},
            {"address": "0.0.0.0:1080", "protocol": {"type": "socks"}},
            {"address": "0.0.0.0:1081", "protocol": {"type": "socks"},
             "dns": {"hosts": {"proxy.invalid": "192.0.2.2"}}}
        ]))
        .unwrap(),
    )
    .unwrap();
    assert!(
        validated
            .dns_groups
            .iter()
            .all(|group| group.use_default_resolver)
    );
    let mut registry = build_dns_registry(validated.dns_groups).await.unwrap();
    for (config, ip) in validated.configs.iter().zip(["192.0.2.1", "192.0.2.2"]) {
        let ResolvedConfig::Server(server) = config else {
            panic!()
        };
        let resolver = registry.get_for_server(server.dns.as_ref());
        assert_eq!(
            resolver
                .resolve_location(&NetLocation::from_str("proxy.invalid:443", None).unwrap())
                .await
                .unwrap(),
            vec![SocketAddr::new(ip.parse().unwrap(), 443)]
        );
        let reply = resolver
            .exchange(request("proxy.invalid", RecordType::A).to_vec().unwrap())
            .await
            .unwrap();
        assert_eq!(
            Message::from_vec(&reply).unwrap().answers[0].data,
            RData::A(rdata::A(ip.parse().unwrap()))
        );
        let native = resolver
            .resolve_location(&NetLocation::from_str("localhost:443", None).unwrap())
            .await
            .unwrap();
        assert!(!native.is_empty());
        assert!(native.iter().all(|address| address.ip().is_loopback()));
    }
}

#[tokio::test]
async fn hosts_registry_covers_native_pooled_mixed_and_fake_resolvers() {
    let trap = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let endpoint = format!("udp://127.0.0.1:{}", trap.local_addr().unwrap().port());
    for servers in [
        json!("system"),
        json!([endpoint.clone(), endpoint.clone()]),
        json!([endpoint.clone(), "system"]),
        json!({"url": endpoint, "ip_strategy": "ipv6_only"}),
    ] {
        for fake in [false, true] {
            let registry = build_dns_registry(groups(json!([{
                "dns_group": "static", "dns_servers": servers, "fake_ip": fake,
                "hosts": {"proxy.invalid": ["192.0.2.1", "192.0.2.2"], "localhost": "192.0.2.11"}
            }])))
            .await
            .unwrap();
            let resolver = registry.get_by_name("static").unwrap();
            let localhost = resolver
                .resolve_location(&NetLocation::from_str("localhost:443", None).unwrap())
                .await
                .unwrap();
            assert_eq!(
                localhost,
                vec!["192.0.2.11:443".parse::<SocketAddr>().unwrap()]
            );
            let context = resolver
                .fake_dns_context()
                .unwrap_or_else(|| Arc::new(DnsContext::real(resolver.clone())));
            for _ in 0..2 {
                let addresses = resolver
                    .resolve_location(&NetLocation::from_str("PROXY.invalid.:443", None).unwrap())
                    .await
                    .unwrap();
                assert_eq!(addresses.len(), 2);
                for (kind, count) in [(RecordType::A, 2), (RecordType::AAAA, 0)] {
                    let bytes = request("proxy.invalid", kind).to_vec().unwrap();
                    let answer = resolver.exchange(bytes.clone()).await.unwrap();
                    assert_eq!(Message::from_vec(&answer).unwrap().answers.len(), count);
                    for tcp in [false, true] {
                        let answer = context.exchange(bytes.clone(), tcp).await.unwrap().unwrap();
                        let answer = Message::from_vec(&answer).unwrap();
                        assert_eq!(answer.answers.len(), count);
                        assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
                        assert!(answer.answers.iter().all(|record| !context.contains(
                            match record.data {
                                RData::A(ip) => ip.0.into(),
                                RData::AAAA(ip) => ip.0.into(),
                                _ => panic!(),
                            }
                        )));
                    }
                }
            }
            if fake {
                let answer = context
                    .exchange(
                        request("unmapped.invalid", RecordType::A).to_vec().unwrap(),
                        true,
                    )
                    .await
                    .unwrap()
                    .unwrap();
                let answer = Message::from_vec(&answer).unwrap();
                let RData::A(ip) = answer.answers[0].data else {
                    panic!()
                };
                assert!(context.contains(ip.0.into()));
            }
        }
    }
    assert_eq!(
        trap.try_recv(&mut [0; 512]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn hosts_bootstrap_and_reload_remain_scoped() {
    use crate::dns::build_dns_registry_reusing;
    let config = |ip: &str| {
        json!([
            {"dns_group": "bootstrap", "dns_servers": "udp://127.0.0.1:9", "hosts": {"dns.invalid": "127.0.0.1"}},
            {"dns_group": "static", "dns_servers": {"url": "tcp://dns.invalid:9", "bootstrap_url": "bootstrap"}, "hosts": {"proxy.invalid": ip}},
            {"dns_group": "other", "dns_servers": "system", "hosts": {"proxy.invalid": "192.0.2.99"}}
        ])
    };
    let old = build_dns_registry(groups(config("192.0.2.1")))
        .await
        .unwrap();
    let new = build_dns_registry_reusing(
        groups(config("192.0.2.2")),
        crate::config::GlobalLimits::default(),
        Some(&old),
    )
    .await
    .unwrap();
    let location = NetLocation::from_str("proxy.invalid:443", None).unwrap();
    for (registry, name, expected) in [
        (&old, "static", "192.0.2.1"),
        (&new, "static", "192.0.2.2"),
        (&old, "other", "192.0.2.99"),
        (&new, "other", "192.0.2.99"),
    ] {
        let addresses = registry
            .get_by_name(name)
            .unwrap()
            .resolve_location(&location)
            .await
            .unwrap();
        assert_eq!(addresses[0].ip(), expected.parse::<IpAddr>().unwrap());
    }
    let mut protected = groups(config("192.0.2.1"));
    protected
        .iter_mut()
        .find(|group| group.name == "other")
        .unwrap()
        .hosts = hosts("bad.test: 198.18.0.5");
    let fake = build_dns_registry(groups(
        json!([{"dns_group": "fake", "dns_servers": "udp://127.0.0.1:9", "fake_ip": true}]),
    ))
    .await
    .unwrap();
    let error = build_dns_registry_reusing(
        protected,
        crate::config::GlobalLimits::default(),
        Some(&fake),
    )
    .await
    .err()
    .unwrap();
    assert!(
        error
            .to_string()
            .contains("hosts address overlaps a synthetic endpoint"),
        "{error}"
    );
    let error = crate::dns::build_dns_registry_for_runtime(
        groups(config("192.0.2.1")),
        crate::config::GlobalLimits::default(),
        None,
        &["192.0.2.1".parse().unwrap()],
        true,
    )
    .await
    .err()
    .unwrap();
    assert!(
        error
            .to_string()
            .contains("hosts address overlaps a synthetic endpoint"),
        "{error}"
    );
}

#[tokio::test]
async fn hosts_static_answers_obey_tcp_framing_udp_limits_and_prechecks() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let ips: Vec<_> = (1..=100).map(|last| format!("192.0.2.{last}")).collect();
    for fake in [false, true] {
        let registry = build_dns_registry(groups(json!([{
            "dns_group": "static", "dns_servers": "udp://127.0.0.1:9", "fake_ip": fake,
            "hosts": {"large.test": ips}
        }])))
        .await
        .unwrap();
        let resolver = registry.get_by_name("static").unwrap();
        let context = resolver
            .fake_dns_context()
            .unwrap_or_else(|| Arc::new(DnsContext::real(resolver)));
        let bytes = request("large.test", RecordType::A).to_vec().unwrap();
        let udp = context
            .exchange(bytes.clone(), false)
            .await
            .unwrap()
            .unwrap();
        assert!(udp.len() <= 512);
        assert!(Message::from_vec(&udp).unwrap().metadata.truncation);
        let mut tcp = context.tcp_stream();
        tcp.write_u16(bytes.len() as u16).await.unwrap();
        tcp.write_all(&bytes).await.unwrap();
        let length = tcp.read_u16().await.unwrap();
        let mut reply = vec![0; length as usize];
        tcp.read_exact(&mut reply).await.unwrap();
        let answer = Message::from_vec(&reply).unwrap();
        assert_eq!(answer.answers.len(), 100);
        assert!(!answer.metadata.truncation);
        for (mutation, expected) in [
            (0, ResponseCode::FormErr),
            (1, ResponseCode::BADVERS),
            (2, ResponseCode::Refused),
        ] {
            let mut query = request("large.test", RecordType::A);
            match mutation {
                0 => query.queries.clear(),
                1 => {
                    let mut edns = Edns::new();
                    edns.set_version(1);
                    query.edns = Some(edns);
                }
                _ => query.metadata.op_code = hickory_resolver::proto::op::OpCode::Update,
            }
            let answer = context
                .exchange(query.to_vec().unwrap(), true)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                u16::from(Message::from_vec(&answer).unwrap().metadata.response_code),
                u16::from(expected)
            );
        }
        assert!(
            context
                .exchange(vec![1, 2, 3], true)
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn hosts_candidates_reach_real_socket_with_first_address_unavailable() {
    use crate::tcp::chain_builder::build_direct_chain_group;
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let fallback = Arc::new(Fallback::default());
    let resolver = HostsResolver::wrap(
        Arc::new(hosts("proxy.invalid: ['::1', 127.0.0.1]")),
        fallback.clone(),
    );
    let chain = build_direct_chain_group(resolver.clone());
    let target = NetLocation::from_str(&format!("proxy.invalid:{port}"), None).unwrap();
    let (result, accepted) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(
            chain.connect_tcp(target.into(), &resolver),
            listener.accept()
        )
    })
    .await
    .unwrap();
    assert!(result.is_ok());
    assert!(accepted.is_ok());
    assert_eq!(fallback.lookups.load(Ordering::SeqCst), 0);
}
