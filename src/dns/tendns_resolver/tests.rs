use super::*;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tendns::hickory_proto::{
    op::{OpCode, Query},
    rr::{RData, Record, RecordType, rdata::TXT},
    serialize::binary::{BinEncodable, BinEncoder, NameEncoding},
};
use tendns::{
    Discovery, IpStrategy, Policy,
    names::canonical_name,
    protocol::{Entry, Publication, Secret, Value, encrypt},
};

#[derive(Debug)]
struct Clock(AtomicU64);

impl tendns::resolver::Clock for Clock {
    fn now(&self) -> anyhow::Result<u64> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

#[derive(Debug, Default)]
struct Mock {
    records: Mutex<HashMap<String, Vec<Record>>>,
    calls: Mutex<Vec<(Message, Instant)>>,
    wire_calls: Mutex<Vec<Vec<u8>>>,
    lookups: Mutex<Vec<NetLocation>>,
    plain_calls: AtomicUsize,
    delay: Duration,
    alter: Option<fn(&mut Message)>,
    fail: Option<io::ErrorKind>,
    expire_on_fallback: Option<Arc<Clock>>,
}

impl Resolver for Mock {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        assert!(
            !location.to_string().contains("example.com"),
            "protected name leaked: {location}"
        );
        self.lookups.lock().unwrap().push(location.clone());
        if let Some(clock) = &self.expire_on_fallback {
            clock.0.store(200, Ordering::SeqCst);
        }
        let port = location.port();
        let delay = self.delay;
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            Ok(native_addresses(port))
        })
    }

    fn exchange(&self, bytes: Vec<u8>) -> DnsExchangeFuture {
        self.plain_calls.fetch_add(1, Ordering::SeqCst);
        self.exchange_with_deadline(bytes, Instant::now() + Duration::from_secs(60))
    }

    fn exchange_with_deadline(&self, bytes: Vec<u8>, deadline: Instant) -> DnsExchangeFuture {
        let request = super::super::message::decode(&bytes).unwrap();
        self.wire_calls.lock().unwrap().push(bytes);
        self.calls.lock().unwrap().push((request.clone(), deadline));
        let mut response = request.into_response();
        if let Some(query) = response.queries.first() {
            response.answers = self
                .records
                .lock()
                .unwrap()
                .get(&query.name().to_ascii())
                .cloned()
                .unwrap_or_default();
        }
        if let Some(alter) = self.alter {
            alter(&mut response);
        }
        let delay = self.delay;
        let fail = self.fail;
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            if let Some(kind) = fail {
                return Err(io::Error::new(kind, "test transport failed"));
            }
            response.to_vec().map_err(io::Error::other)
        })
    }
}

fn policy() -> Arc<Policy> {
    Arc::new(
        Policy::new(
            vec![Discovery {
                domain: canonical_name("example.com").unwrap(),
                key: Arc::new(
                    Secret::decode("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc").unwrap(),
                ),
            }],
            vec![canonical_name("hex.test").unwrap()],
            60,
            1024,
        )
        .unwrap(),
    )
}

fn adapter(raw: Arc<Mock>, clock: Arc<Clock>) -> TendnsResolver {
    let mut adapter = TendnsResolver::new(
        policy(),
        raw.clone(),
        IpStrategy::Ipv4AndIpv6,
        Duration::from_secs(5),
    )
    .unwrap();
    adapter.private = Arc::new(tendns::Resolver::with_clock(
        policy(),
        Arc::new(RawExchange(raw)),
        clock,
    ));
    adapter
}

fn parent(raw: &Mock, value: Value) {
    let policy = policy();
    let owner = &policy.discovery()[0].domain;
    let publication = Publication {
        issued_at: 100,
        expires_at: 200,
        entries: vec![Entry {
            subdomain: "nas".into(),
            value,
        }],
    };
    let encrypted = encrypt(&publication, &policy.discovery()[0].key, owner).unwrap();
    raw.records.lock().unwrap().insert(
        owner.to_ascii(),
        vec![Record::from_rdata(
            owner.clone(),
            60,
            RData::TXT(TXT::new(vec![encrypted])),
        )],
    );
}

fn location(host: &str) -> NetLocation {
    NetLocation::new(Address::Hostname(host.into()), 443)
}

fn native_addresses(port: u16) -> Vec<SocketAddr> {
    let scoped = SocketAddr::V6(std::net::SocketAddrV6::new(
        "fe80::1".parse().unwrap(),
        port,
        7,
        42,
    ));
    vec![
        scoped,
        SocketAddr::new("192.0.2.99".parse().unwrap(), port),
        SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::2".parse().unwrap(),
            port,
            9,
            43,
        )),
        scoped,
    ]
}

fn query(host: &str, kind: RecordType) -> Vec<u8> {
    let mut message = Message::query();
    message.metadata.id = 17;
    message.add_query(Query::query(Name::from_ascii(host).unwrap(), kind));
    message.to_vec().unwrap()
}

#[test]
fn constructor_rejects_zero_and_excessive_budgets() {
    for budget in [Duration::ZERO, Duration::from_secs(86_401), Duration::MAX] {
        let error = TendnsResolver::new(
            policy(),
            Arc::new(Mock::default()),
            IpStrategy::Ipv4AndIpv6,
            budget,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
    for budget in [Duration::from_nanos(1), Duration::from_secs(86_400)] {
        assert!(
            TendnsResolver::new(
                policy(),
                Arc::new(Mock::default()),
                IpStrategy::Ipv4AndIpv6,
                budget,
            )
            .is_ok()
        );
    }
}

#[tokio::test]
async fn private_lookup_uses_selected_raw_txt_and_preserves_the_port() {
    let raw = Arc::new(Mock::default());
    parent(&raw, Value::A("192.0.2.7".parse().unwrap()));
    let adapter = adapter(raw.clone(), Arc::new(Clock(AtomicU64::new(100))));
    assert_eq!(
        adapter
            .resolve_location(&location("NaS.Example.COM"))
            .await
            .unwrap(),
        vec!["192.0.2.7:443".parse().unwrap()]
    );
    assert!(raw.lookups.lock().unwrap().is_empty());
    let calls = raw.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0.queries[0].name().to_ascii(), "example.com.");
    assert_eq!(calls[0].0.queries[0].query_type(), RecordType::TXT);
}

#[tokio::test]
async fn unrelated_native_names_preserve_case_form_order_duplicates_and_scope() {
    let raw = Arc::new(Mock::default());
    let adapter = adapter(raw.clone(), Arc::new(Clock(AtomicU64::new(100))));
    for host in [
        "MiXeD",
        "Public.Example.",
        "[fe80::1%42]",
        "fe80::1%42",
        "192.0.2.7",
        "2001:db8::1",
        "::ffff:192.0.2.7",
    ] {
        let location = location(host);
        let addresses = adapter.resolve_location(&location).await.unwrap();
        assert_eq!(addresses, native_addresses(443));
        assert_eq!(raw.lookups.lock().unwrap().last(), Some(&location));
    }
    assert!(raw.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unicode_dot_equivalents_cannot_escape_private_resolution() {
    for separator in ['\u{3002}', '\u{ff0e}', '\u{ff61}'] {
        let raw = Arc::new(Mock::default());
        parent(&raw, Value::A("192.0.2.7".parse().unwrap()));
        let adapter = adapter(raw.clone(), Arc::new(Clock(AtomicU64::new(100))));
        let private = location(&format!("nas{separator}example{separator}com{separator}"));
        assert_eq!(
            adapter.resolve_location(&private).await.unwrap(),
            vec!["192.0.2.7:443".parse().unwrap()],
            "{private}"
        );
        assert!(raw.lookups.lock().unwrap().is_empty());
        {
            let calls = raw.calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].0.queries[0].name().to_ascii(), "example.com.");
            assert_eq!(calls[0].0.queries[0].query_type(), RecordType::TXT);
        }

        let public = location(&format!("MiXeD{separator}public{separator}"));
        assert_eq!(
            adapter.resolve_location(&public).await.unwrap(),
            native_addresses(443)
        );
        assert_eq!(raw.lookups.lock().unwrap().as_slice(), &[public]);
        assert_eq!(raw.calls.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn native_underscore_names_delegate_but_private_names_do_not() {
    let raw = Arc::new(Mock::default());
    let adapter = adapter(raw.clone(), Arc::new(Clock(AtomicU64::new(100))));
    let public = location("peer_service.public");
    adapter.resolve_location(&public).await.unwrap();
    assert_eq!(raw.lookups.lock().unwrap().as_slice(), &[public]);
    assert!(raw.calls.lock().unwrap().is_empty());
    assert!(
        adapter
            .resolve_location(&location("nas_x.example.com"))
            .await
            .is_err()
    );
    assert_eq!(raw.lookups.lock().unwrap().len(), 1);
    assert!(
        raw.calls
            .lock()
            .unwrap()
            .iter()
            .all(|(request, _)| request.queries[0].query_type() == RecordType::TXT)
    );
}

#[tokio::test]
async fn invalid_hostnames_fail_closed_before_native_or_txt_work() {
    let raw = Arc::new(Mock::default());
    let adapter = adapter(raw.clone(), Arc::new(Clock(AtomicU64::new(100))));
    for host in [
        "",
        "nas.example.com\\",
        "nas.example.com\\1",
        "nas.example.com\\12",
        "public\\.test",
        "a+b.lan",
        "a+b.example.com",
        "-edge.lan",
        "-edge.example.com",
        "my printer.local",
        "my printer.example.com",
        "fe80::1%",
        "fe80::1%4294967296",
        "[fe80::1%42",
    ] {
        let error = adapter.resolve_location(&location(host)).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{host:?}");
    }
    assert!(raw.lookups.lock().unwrap().is_empty());
    assert!(raw.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn private_failures_never_fall_back_and_keep_typed_error_kinds() {
    for mode in ["missing", "auth", "transport", "servfail"] {
        let raw = Arc::new(Mock {
            fail: (mode == "transport").then_some(io::ErrorKind::ConnectionRefused),
            alter: (mode == "servfail").then_some(|response: &mut Message| {
                response.metadata.response_code = ResponseCode::ServFail
            }),
            ..Default::default()
        });
        if mode == "auth" {
            raw.records.lock().unwrap().insert(
                "example.com.".into(),
                vec![Record::from_rdata(
                    canonical_name("example.com").unwrap(),
                    60,
                    RData::TXT(TXT::new(vec!["td1.invalid".into()])),
                )],
            );
        }
        let adapter = adapter(raw.clone(), Arc::new(Clock(AtomicU64::new(100))));
        let error = adapter
            .resolve_location(&location("nas.example.com"))
            .await
            .unwrap_err();
        assert_eq!(
            error.kind(),
            match mode {
                "missing" => io::ErrorKind::NotFound,
                "transport" => io::ErrorKind::ConnectionRefused,
                _ => io::ErrorKind::Other,
            },
            "{mode}: {error}"
        );
        if mode == "missing" {
            assert_eq!(
                error
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<tendns::LookupError>(),
                Some(&tendns::LookupError::NotFound)
            );
        }
        assert!(raw.lookups.lock().unwrap().is_empty());
        let calls = raw.calls.lock().unwrap();
        assert_eq!(calls.len(), if mode == "missing" { 2 } else { 1 });
        assert!(
            calls
                .iter()
                .all(|(request, _)| request.queries[0].query_type() == RecordType::TXT)
        );
    }
}

#[tokio::test]
async fn unassociated_and_truncated_txt_responses_fail_closed() {
    let alterations: [fn(&mut Message); 5] = [
        |response| response.metadata.id ^= 1,
        |response| response.metadata.message_type = MessageType::Query,
        |response| response.metadata.op_code = OpCode::Update,
        |response| response.queries[0].name = canonical_name("different.test").unwrap(),
        |response| response.metadata.truncation = true,
    ];
    for alter in alterations {
        let raw = Arc::new(Mock {
            alter: Some(alter),
            ..Default::default()
        });
        let adapter = adapter(raw.clone(), Arc::new(Clock(AtomicU64::new(100))));
        assert!(
            adapter
                .resolve_location(&location("nas.example.com"))
                .await
                .is_err()
        );
        assert_eq!(raw.calls.lock().unwrap().len(), 1);
        assert!(raw.lookups.lock().unwrap().is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn protected_budgets_start_before_the_returned_futures_are_polled() {
    let raw = Arc::new(Mock::default());
    parent(&raw, Value::A("192.0.2.7".parse().unwrap()));
    let adapter = adapter(raw.clone(), Arc::new(Clock(AtomicU64::new(100))));
    let lookup = adapter.resolve_location(&location("nas.example.com"));
    let exchange = adapter.exchange(query("nas.example.com.", RecordType::A));

    tokio::time::advance(Duration::from_secs(5)).await;

    for error in [lookup.await.unwrap_err(), exchange.await.unwrap_err()] {
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.get_ref().unwrap().is::<tendns::TimeoutError>());
    }
    assert!(raw.calls.lock().unwrap().is_empty());
    assert!(raw.lookups.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn one_deadline_bounds_both_txt_owners_and_external_fallback() {
    for alias in [false, true] {
        let raw = Arc::new(Mock {
            delay: Duration::from_secs(3),
            ..Default::default()
        });
        if alias {
            parent(&raw, Value::Cname(canonical_name("public.test").unwrap()));
        }
        let adapter = adapter(raw.clone(), Arc::new(Clock(AtomicU64::new(100))));
        let end = Instant::now() + Duration::from_secs(5);
        let error = adapter
            .resolve_location(&location("nas.example.com"))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.get_ref().unwrap().is::<tendns::TimeoutError>());
        assert_eq!(Instant::now(), end);
        assert!(
            raw.calls
                .lock()
                .unwrap()
                .iter()
                .all(|(_, deadline)| *deadline == end)
        );
        assert_eq!(raw.lookups.lock().unwrap().len(), usize::from(alias));
    }
}

#[tokio::test]
async fn publication_caches_are_isolated_and_completed_addresses_do_not_outlive_expiry() {
    let first = Arc::new(Mock::default());
    let second = Arc::new(Mock::default());
    parent(&first, Value::A("192.0.2.1".parse().unwrap()));
    parent(&second, Value::A("192.0.2.2".parse().unwrap()));
    let clock = Arc::new(Clock(AtomicU64::new(100)));
    let a = adapter(first, clock.clone());
    let b = adapter(second, clock.clone());
    assert_eq!(
        a.resolve_location(&location("nas.example.com"))
            .await
            .unwrap()[0]
            .ip()
            .to_string(),
        "192.0.2.1"
    );
    assert_eq!(
        b.resolve_location(&location("nas.example.com"))
            .await
            .unwrap()[0]
            .ip()
            .to_string(),
        "192.0.2.2"
    );
    clock.0.store(200, Ordering::SeqCst);
    assert!(
        a.resolve_location(&location("nas.example.com"))
            .await
            .is_err()
    );
    assert!(
        b.resolve_location(&location("nas.example.com"))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn external_cname_is_absolute_and_expiry_is_rechecked_after_fallback() {
    for expires in [false, true] {
        for strategy in [
            IpStrategy::Ipv4AndIpv6,
            IpStrategy::Ipv4Only,
            IpStrategy::Ipv6Only,
            IpStrategy::Ipv4ThenIpv6,
            IpStrategy::Ipv6ThenIpv4,
        ] {
            let clock = Arc::new(Clock(AtomicU64::new(100)));
            let raw = Arc::new(Mock {
                expire_on_fallback: expires.then_some(clock.clone()),
                ..Default::default()
            });
            parent(&raw, Value::Cname(canonical_name("public.test").unwrap()));
            let mut adapter = adapter(raw.clone(), clock);
            adapter.strategy = strategy;
            let result = adapter.resolve_location(&location("nas.example.com")).await;
            assert_eq!(result.is_err(), expires);
            if !expires {
                let native = native_addresses(443);
                let expected = match strategy {
                    IpStrategy::Ipv4Only | IpStrategy::Ipv4ThenIpv6 => vec![native[1]],
                    IpStrategy::Ipv6Only | IpStrategy::Ipv6ThenIpv4 => {
                        vec![native[0], native[2], native[3]]
                    }
                    IpStrategy::Ipv4AndIpv6 => native,
                };
                assert_eq!(result.unwrap(), expected, "{strategy:?}");
            }
            assert_eq!(
                raw.lookups.lock().unwrap().as_slice(),
                &[location("public.test.")]
            );
        }
    }
}

#[tokio::test]
async fn fake_ip_answers_precede_tendns_and_outer_guards_check_synthesized_ips() {
    let raw = Arc::new(Mock::default());
    let adapter = Arc::new(adapter(raw.clone(), Arc::new(Clock(AtomicU64::new(100)))));
    let real = crate::dns::real_only(adapter, Arc::from(["198.18.0.0/15".parse().unwrap()]));
    let context = Arc::new(
        crate::dns::DnsContext::new(crate::dns::fake_ip::FakeIpOptions::default(), real.clone())
            .unwrap(),
    );
    let fake = crate::dns::FakeDnsResolver::new(real.clone(), context.clone());
    let answer = context
        .exchange(query("nas.example.com.", RecordType::A), false)
        .await
        .unwrap()
        .unwrap();
    assert!(!Message::from_vec(&answer).unwrap().answers.is_empty());
    assert!(raw.calls.lock().unwrap().is_empty());
    assert!(fake.fake_dns_context().is_some());
    assert_eq!(
        fake.resolve_location(&location("c6120005.hex.test"))
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        real.exchange(query("c6120005.hex.test.", RecordType::A))
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
}

#[tokio::test(start_paused = true)]
async fn unclaimed_raw_queries_preserve_bytes_methods_and_deadlines() {
    let raw = Arc::new(Mock::default());
    let adapter = adapter(raw.clone(), Arc::new(Clock(AtomicU64::new(100))));
    let mut request = Message::from_vec(&query("PuBlic.TeSt.", RecordType::TXT)).unwrap();
    request.add_additional(Record::from_rdata(
        request.queries[0].name().clone(),
        60,
        RData::TXT(TXT::new(vec!["test".into()])),
    ));
    let mut bytes = Vec::new();
    let mut encoder = BinEncoder::new(&mut bytes);
    encoder.set_name_encoding(NameEncoding::Uncompressed);
    request.emit(&mut encoder).unwrap();
    assert_ne!(Message::from_vec(&bytes).unwrap().to_vec().unwrap(), bytes);
    let end = Instant::now() + Duration::from_secs(30);
    adapter.exchange(bytes.clone()).await.unwrap();
    assert_eq!(raw.plain_calls.load(Ordering::SeqCst), 1);
    adapter
        .exchange_with_deadline(bytes.clone(), end)
        .await
        .unwrap();
    assert_eq!(
        raw.wire_calls.lock().unwrap().as_slice(),
        &[bytes.clone(), bytes]
    );
    assert_eq!(raw.calls.lock().unwrap()[1].1, end);
    assert_eq!(raw.plain_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn protected_raw_queries_validate_all_questions_and_expired_deadlines() {
    let raw = Arc::new(Mock::default());
    let adapter = adapter(raw.clone(), Arc::new(Clock(AtomicU64::new(100))));
    let mut request = Message::from_vec(&query("public.test.", RecordType::A)).unwrap();
    request.add_query(Query::query(
        canonical_name("nas.example.com").unwrap(),
        RecordType::A,
    ));
    let error = adapter
        .exchange_with_deadline(request.to_vec().unwrap(), Instant::now())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    let answer = adapter.exchange(request.to_vec().unwrap()).await.unwrap();
    assert_eq!(
        Message::from_vec(&answer).unwrap().metadata.response_code,
        ResponseCode::FormErr
    );
    let error = adapter
        .exchange_with_deadline(query("nas.example.com.", RecordType::A), Instant::now())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(raw.calls.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn protected_raw_exchange_uses_the_earlier_caller_deadline_or_private_budget() {
    for caller_seconds in [2, 30] {
        let raw = Arc::new(Mock {
            delay: Duration::from_secs(10),
            ..Default::default()
        });
        let adapter = adapter(raw.clone(), Arc::new(Clock(AtomicU64::new(100))));
        let now = Instant::now();
        let end = now + Duration::from_secs(caller_seconds.min(5));
        let error = adapter
            .exchange_with_deadline(
                query("nas.example.com.", RecordType::A),
                now + Duration::from_secs(caller_seconds),
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.get_ref().unwrap().is::<tendns::TimeoutError>());
        assert_eq!(Instant::now(), end);
        let calls = raw.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, end);
        assert!(raw.lookups.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn protected_raw_answer_preserves_identity_and_synthesizes_the_address() {
    let raw = Arc::new(Mock::default());
    parent(&raw, Value::A("192.0.2.7".parse().unwrap()));
    let adapter = adapter(raw.clone(), Arc::new(Clock(AtomicU64::new(100))));
    let bytes = query("nas.example.com.", RecordType::A);
    let request = Message::from_vec(&bytes).unwrap();
    let answer = adapter.exchange(bytes).await.unwrap();
    let answer = Message::from_vec(&answer).unwrap();
    assert_eq!(answer.metadata.id, request.metadata.id);
    assert_eq!(answer.queries, request.queries);
    assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
    assert_eq!(answer.answers.len(), 1);
    assert_eq!(&answer.answers[0].name, request.queries[0].name());
    assert_eq!(
        answer.answers[0].data,
        RData::A(tendns::hickory_proto::rr::rdata::A(
            "192.0.2.7".parse().unwrap()
        ))
    );
    assert_eq!(raw.calls.lock().unwrap().len(), 1);
    assert!(raw.lookups.lock().unwrap().is_empty());
}

#[tokio::test]
async fn protected_raw_cname_rejects_truncated_and_unassociated_public_answers() {
    let alterations: [fn(&mut Message); 2] = [
        |reply| {
            if reply.queries[0].query_type() == RecordType::A {
                reply.metadata.truncation = true;
            }
        },
        |reply| {
            if reply.queries[0].query_type() == RecordType::A {
                reply.metadata.id ^= 1;
            }
        },
    ];
    for alter in alterations {
        let raw = Arc::new(Mock {
            alter: Some(alter),
            ..Default::default()
        });
        parent(&raw, Value::Cname(canonical_name("public.test").unwrap()));
        let adapter = adapter(raw.clone(), Arc::new(Clock(AtomicU64::new(100))));
        assert!(
            adapter
                .exchange(query("nas.example.com.", RecordType::A))
                .await
                .is_err()
        );
        assert!(raw.lookups.lock().unwrap().is_empty());
        let calls = raw.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0.queries[0].query_type(), RecordType::TXT);
        assert_eq!(calls[1].0.queries[0].query_type(), RecordType::A);
        assert_eq!(calls[1].0.queries[0].name().to_ascii(), "public.test.");
    }
}

#[tokio::test]
async fn protected_raw_signed_and_nonquery_messages_never_reach_upstream() {
    use tendns::hickory_proto::rr::rdata::{TSIG, tsig::TsigAlgorithm};

    let raw = Arc::new(Mock::default());
    let adapter = adapter(raw.clone(), Arc::new(Clock(AtomicU64::new(100))));
    for mode in ["signed", "response", "update"] {
        let mut request = Message::from_vec(&query("nas.example.com.", RecordType::A)).unwrap();
        let code = match mode {
            "signed" => {
                request.add_additional(Record::from_rdata(
                    canonical_name("key.test").unwrap(),
                    0,
                    RData::TSIG(TSIG::new(
                        TsigAlgorithm::HmacSha256,
                        0,
                        300,
                        vec![0; 32],
                        17,
                        None,
                        vec![],
                    )),
                ));
                ResponseCode::Refused
            }
            "response" => {
                request.metadata.message_type = MessageType::Response;
                ResponseCode::FormErr
            }
            _ => {
                request.metadata.op_code = OpCode::Update;
                ResponseCode::NotImp
            }
        };
        let answer = adapter.exchange(request.to_vec().unwrap()).await.unwrap();
        let answer = Message::from_vec(&answer).unwrap();
        assert_eq!(answer.metadata.response_code, code);
        assert!(answer.signature().is_none());
    }
    assert!(raw.calls.lock().unwrap().is_empty());
    assert!(raw.lookups.lock().unwrap().is_empty());
}
