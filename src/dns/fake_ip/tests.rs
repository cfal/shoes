use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use futures::future::poll_fn;
use hickory_resolver::proto::op::{Message, Query, ResponseCode};
use hickory_resolver::proto::rr::rdata::opt::EdnsOption;
use hickory_resolver::proto::rr::{Name, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};

use crate::address::NetLocation;
use crate::async_stream::{AsyncReadMessage, AsyncShutdownMessage, AsyncWriteMessage};
use crate::resolver::{DnsExchangeFuture, ResolveFuture, Resolver};

use super::FakeIpOptions;
use crate::dns::DnsContext;

#[derive(Debug, Default)]
struct RecordingResolver {
    exchanges: AtomicUsize,
    positive: bool,
}

impl Resolver for RecordingResolver {
    fn resolve_location(&self, _: &NetLocation) -> ResolveFuture {
        panic!("client DNS must not use address-only resolution")
    }

    fn exchange(&self, request: Vec<u8>) -> DnsExchangeFuture {
        self.exchanges.fetch_add(1, Ordering::SeqCst);
        let positive = self.positive;
        Box::pin(async move {
            let mut answer = Message::from_vec(&request)
                .map_err(io::Error::other)?
                .into_response();
            if positive {
                use hickory_resolver::proto::rr::{RData, Record, rdata};
                let query = &answer.queries[0];
                let data = match query.query_type {
                    RecordType::A => RData::A(rdata::A("192.0.2.7".parse().unwrap())),
                    RecordType::AAAA => RData::AAAA(rdata::AAAA("2001:db8::7".parse().unwrap())),
                    RecordType::TXT => RData::TXT(rdata::TXT::new(vec!["unchanged".to_owned()])),
                    _ => unreachable!(),
                };
                answer.add_answer(Record::from_rdata(query.name.clone(), 37, data));
            } else {
                answer.metadata.response_code = ResponseCode::NXDomain;
            }
            answer.to_vec().map_err(io::Error::other)
        })
    }
}

fn context() -> (Arc<DnsContext>, Arc<RecordingResolver>) {
    let real = Arc::new(RecordingResolver::default());
    let context = Arc::new(DnsContext::new(FakeIpOptions::default(), real.clone()).unwrap());
    (context, real)
}

fn query(kind: RecordType) -> Vec<u8> {
    let mut query = Message::query();
    query.metadata.id = 42;
    query.add_query(Query::query(
        Name::from_ascii("Example.Test.").unwrap(),
        kind,
    ));
    query.to_vec().unwrap()
}

#[tokio::test]
async fn real_dns_interception_uses_message_exchange_without_synthetic_addresses() {
    let real = Arc::new(RecordingResolver {
        positive: true,
        ..Default::default()
    });
    let context = Arc::new(DnsContext::real(real.clone()));
    assert!(!context.contains("198.18.0.1".parse().unwrap()));
    assert_eq!(
        context.restore("198.18.0.1".parse().unwrap()).unwrap(),
        None
    );
    for kind in [RecordType::A, RecordType::AAAA, RecordType::TXT] {
        for tcp in [false, true] {
            let reply = context.exchange(query(kind), tcp).await.unwrap().unwrap();
            let reply = Message::from_vec(&reply).unwrap();
            assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
            assert_eq!(reply.answers.len(), 1);
            assert_eq!(reply.answers[0].record_type(), kind);
            assert_eq!(reply.answers[0].ttl, 37);
            let data = reply.answers[0].data.to_string();
            assert_eq!(
                data,
                match kind {
                    RecordType::A => "192.0.2.7",
                    RecordType::AAAA => "2001:db8::7",
                    _ => "unchanged",
                }
            );
        }
    }
    let mut stream = context.tcp_stream();
    let request = query(RecordType::A);
    stream.write_u16(request.len() as u16).await.unwrap();
    stream.write_all(&request).await.unwrap();
    let length = stream.read_u16().await.unwrap() as usize;
    let mut reply = vec![0; length];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(
        Message::from_vec(&reply).unwrap().metadata.response_code,
        ResponseCode::NoError
    );
    assert_eq!(real.exchanges.load(Ordering::SeqCst), 7);
}

#[tokio::test]
async fn real_interception_rejects_unsupported_operations_before_forwarding() {
    use hickory_resolver::proto::op::{Edns, OpCode};
    let real = Arc::new(RecordingResolver::default());
    let context = DnsContext::real(real.clone());
    let ordinary = Message::from_vec(&query(RecordType::A)).unwrap();
    let mut cases = Vec::new();
    for kind in [RecordType::AXFR, RecordType::IXFR] {
        cases.push((
            Message::from_vec(&query(kind)).unwrap(),
            ResponseCode::Refused,
        ));
    }
    let mut message = ordinary.clone();
    message.metadata.op_code = OpCode::Update;
    cases.push((message, ResponseCode::Refused));
    let mut message = ordinary.clone();
    message.queries.clear();
    cases.push((message, ResponseCode::FormErr));
    let mut message = ordinary;
    message.edns = Some(Edns::new().set_version(1).clone());
    cases.push((message, ResponseCode::BADVERS));
    for (request, code) in cases {
        for tcp in [false, true] {
            let answer = context
                .exchange(request.to_vec().unwrap(), tcp)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                u16::from(Message::from_vec(&answer).unwrap().metadata.response_code),
                u16::from(code)
            );
        }
    }
    assert_eq!(real.exchanges.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn interception_drops_responses_before_synthesis_or_forwarding() {
    let real = Arc::new(RecordingResolver::default());
    for context in [
        DnsContext::real(real.clone()),
        DnsContext::new(Default::default(), real.clone()).unwrap(),
    ] {
        for tcp in [false, true] {
            let response = Message::from_vec(&query(RecordType::A))
                .unwrap()
                .into_response()
                .to_vec()
                .unwrap();
            assert!(context.exchange(response, tcp).await.unwrap().is_none());
        }
    }
    assert_eq!(real.exchanges.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn signed_requests_are_refused_without_forwarding() {
    use hickory_resolver::proto::rr::{RData, Record, rdata::TSIG, rdata::tsig::TsigAlgorithm};

    for (fake, persistent) in [(false, false), (true, false), (true, true)] {
        let directory = tempfile::tempdir().unwrap();
        let options = FakeIpOptions {
            state_file: persistent.then(|| directory.path().join("state.json")),
            ..Default::default()
        };
        let real = Arc::new(RecordingResolver::default());
        let context = if fake {
            DnsContext::new(options, real.clone()).unwrap()
        } else {
            DnsContext::real(real.clone())
        };
        for kind in [RecordType::A, RecordType::TXT] {
            let mut request = Message::from_vec(&query(kind)).unwrap();
            request.add_additional(Record::from_rdata(
                Name::from_ascii("key.test.").unwrap(),
                0,
                RData::TSIG(TSIG::new(
                    TsigAlgorithm::HmacSha256,
                    0,
                    300,
                    vec![0; 32],
                    42,
                    None,
                    vec![],
                )),
            ));
            for tcp in [false, true] {
                let reply = context
                    .exchange(request.to_vec().unwrap(), tcp)
                    .await
                    .unwrap()
                    .unwrap();
                let reply = Message::from_vec(&reply).unwrap();
                assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
                assert!(reply.answers.is_empty());
                assert!(reply.signature().is_none());
            }
        }
        assert_eq!(real.exchanges.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn mapped_ipv4_cannot_bypass_restoration_or_unknown_rejection() {
    let (context, _) = context();
    let std::net::IpAddr::V4(ip) = context.allocate("mapped.test", false).unwrap() else {
        panic!()
    };
    assert!(context.contains(ip.to_ipv6_mapped().into()));
    assert_eq!(
        context
            .restore(ip.to_ipv6_mapped().into())
            .unwrap()
            .as_deref(),
        Some("mapped.test")
    );
    assert_eq!(
        context
            .restore("::ffff:198.18.0.1".parse().unwrap())
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
}

#[tokio::test]
async fn forwarded_udp_answer_discards_oversized_edns_options() {
    let (context, _) = context();
    let mut request = Message::from_vec(&query(RecordType::TXT)).unwrap();
    let mut edns = hickory_resolver::proto::op::Edns::new();
    edns.set_max_payload(512);
    edns.options_mut()
        .insert(EdnsOption::Unknown(12, vec![0; 2000]));
    request.edns = Some(edns);
    let reply = context
        .exchange(request.to_vec().unwrap(), false)
        .await
        .unwrap()
        .unwrap();
    assert!(reply.len() <= 512);
    let reply = Message::from_vec(&reply).unwrap();
    assert!(reply.metadata.truncation);
    assert!(!reply.metadata.authentic_data);
    assert!(reply.edns.unwrap().options().as_ref().is_empty());
}

#[tokio::test(start_paused = true)]
async fn truncated_fallback_survives_deadlines_without_bypassing_guards() {
    use crate::dns::composite_resolver::CompositeResolver;
    use crate::resolver::{RefreshPolicy, RefreshingResolver, ResolverFactory, TimeoutResolver};

    #[derive(Debug)]
    struct PartialReply {
        delay: Duration,
        forbidden_answer: bool,
    }
    impl Resolver for PartialReply {
        fn resolve_location(&self, _: &NetLocation) -> ResolveFuture {
            unreachable!()
        }
        fn exchange(&self, request: Vec<u8>) -> DnsExchangeFuture {
            let delay = self.delay;
            let forbidden_answer = self.forbidden_answer;
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                let mut response = Message::from_vec(&request).unwrap().into_response();
                response.metadata.truncation = true;
                if forbidden_answer {
                    use hickory_resolver::proto::rr::{RData, Record, rdata::A};
                    response.add_answer(Record::from_rdata(
                        response.queries[0].name().clone(),
                        60,
                        RData::A(A("203.0.113.1".parse().unwrap())),
                    ));
                }
                response.to_vec().map_err(io::Error::other)
            })
        }
    }
    #[derive(Debug)]
    struct Stalled;
    impl Resolver for Stalled {
        fn resolve_location(&self, _: &NetLocation) -> ResolveFuture {
            unreachable!()
        }
        fn exchange(&self, _: Vec<u8>) -> DnsExchangeFuture {
            Box::pin(std::future::pending())
        }
    }

    for (timeout, delay, forbidden_answer) in [
        (60, 0, false),
        (60, 29, false),
        (2, 0, false),
        (60, 0, true),
    ] {
        let composite: Arc<dyn Resolver> = Arc::new(CompositeResolver::new(vec![Arc::new(
            CompositeResolver::new(vec![
                Arc::new(PartialReply {
                    delay: Duration::from_secs(delay),
                    forbidden_answer,
                }),
                Arc::new(Stalled),
            ]),
        )]));
        let factory: ResolverFactory = Arc::new(move || {
            let composite = composite.clone();
            Box::pin(async move { Ok(composite) })
        });
        let refreshing = RefreshingResolver::new(
            factory,
            RefreshPolicy {
                max_idle: Duration::from_secs(60),
                retry_once_after_refresh: true,
            },
            "partial deadline".into(),
        )
        .await
        .unwrap();
        let real = crate::dns::guard::real_only(
            Arc::new(TimeoutResolver::with_timeout(
                refreshing,
                Duration::from_secs(timeout),
            )),
            vec!["203.0.113.0/24".parse().unwrap()].into(),
        );
        let context = DnsContext::new(Default::default(), real).unwrap();
        let started = tokio::time::Instant::now();
        let reply = context
            .exchange(query(RecordType::TXT), true)
            .await
            .unwrap()
            .unwrap();
        let reply = Message::from_vec(&reply).unwrap();
        assert_eq!(reply.metadata.truncation, !forbidden_answer);
        assert_eq!(
            reply.metadata.response_code,
            if forbidden_answer {
                ResponseCode::ServFail
            } else {
                ResponseCode::NoError
            }
        );
        assert_eq!(started.elapsed(), Duration::from_secs(timeout.min(30)));
    }
}

#[tokio::test(start_paused = true)]
async fn persistent_work_waits_for_admission_with_a_deadline() {
    let directory = tempfile::tempdir().unwrap();
    let options = FakeIpOptions {
        state_file: Some(directory.path().join("state.json")),
        ..Default::default()
    };
    let pool = Arc::new(super::FakeIpPool::new(&options).unwrap());
    let permits = pool
        .persistence_admission
        .clone()
        .acquire_many_owned(16)
        .await
        .unwrap();
    let context = DnsContext::with_pool(
        options,
        Arc::new(RecordingResolver::default()),
        pool.clone(),
    )
    .unwrap();
    let response_packet = Message::from_vec(&query(RecordType::A))
        .unwrap()
        .into_response()
        .to_vec()
        .unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(1),
            context.exchange(response_packet, false)
        )
        .await
        .unwrap()
        .unwrap()
        .is_none()
    );
    let forwarded = tokio::time::timeout(
        Duration::from_millis(1),
        context.exchange(query(RecordType::TXT), false),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(
        Message::from_vec(&forwarded)
            .unwrap()
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    let response = context
        .exchange(query(RecordType::A), false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        Message::from_vec(&response).unwrap().metadata.response_code,
        ResponseCode::ServFail
    );
    assert_eq!(pool.persistence_admission.available_permits(), 0);
    drop(permits);
    assert_eq!(pool.persistence_admission.available_permits(), 16);
}

#[tokio::test]
async fn context_separates_synthesis_real_exchange_and_malformed_input() {
    let (context, real) = context();
    let a = context
        .exchange(query(RecordType::A), false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(real.exchanges.load(Ordering::SeqCst), 0);
    assert_eq!(Message::from_vec(&a).unwrap().answers.len(), 1);
    let txt = context
        .exchange(query(RecordType::TXT), true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(real.exchanges.load(Ordering::SeqCst), 1);
    let txt = Message::from_vec(&txt).unwrap();
    assert_eq!(txt.metadata.id, 42);
    assert_eq!(txt.metadata.response_code, ResponseCode::NXDomain);
    assert!(
        context
            .exchange(vec![1, 2, 3], false)
            .await
            .unwrap()
            .is_none()
    );
    context.exchange(query(RecordType::A), false).await.unwrap();
    assert_eq!(real.exchanges.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn empty_question_udp_probe_releases_its_stream_after_reply() {
    let (context, real) = context();
    let mut stream = context.udp_stream();
    let request = Message::query().to_vec().unwrap();
    std::future::poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, &request))
        .await
        .unwrap();
    let mut bytes = [0; 512];
    let mut buffer = tokio::io::ReadBuf::new(&mut bytes);
    std::future::poll_fn(|cx| Pin::new(&mut stream).poll_read_message(cx, &mut buffer))
        .await
        .unwrap();
    assert_eq!(
        Message::from_vec(buffer.filled())
            .unwrap()
            .metadata
            .response_code,
        ResponseCode::FormErr
    );
    assert_eq!(real.exchanges.load(Ordering::SeqCst), 0);
    let error = std::future::poll_fn(|cx| Pin::new(&mut stream).poll_read_message(cx, &mut buffer))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
}

#[tokio::test]
async fn udp_has_backpressure_and_keeps_synthesizing_after_forwarding() {
    let (context, real) = context();
    let mut stream = context.udp_stream();
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    for kind in [RecordType::A, RecordType::TXT, RecordType::A] {
        let request = query(kind);
        assert!(matches!(
            Pin::new(&mut stream).poll_write_message(&mut cx, &request),
            Poll::Ready(Ok(()))
        ));
        assert!(
            Pin::new(&mut stream)
                .poll_write_message(&mut cx, &request)
                .is_pending()
        );
        let mut bytes = [0; 1232];
        let mut buf = ReadBuf::new(&mut bytes);
        poll_fn(|cx| Pin::new(&mut stream).poll_read_message(cx, &mut buf))
            .await
            .unwrap();
        let reply = Message::from_vec(buf.filled()).unwrap();
        assert_eq!(reply.queries[0].query_type, kind);
    }
    assert_eq!(real.exchanges.load(Ordering::SeqCst), 1);
    assert!(!stream.read_message_eof_on_empty());
    poll_fn(|cx| Pin::new(&mut stream).poll_shutdown_message(cx))
        .await
        .unwrap();
    assert!(matches!(
        Pin::new(&mut stream).poll_write_message(&mut cx, &[]),
        Poll::Ready(Err(_))
    ));
}

#[tokio::test(start_paused = true)]
async fn non_dns_streams_never_forward_and_udp_recovers_after_a_bad_packet() {
    let (context, real) = context();
    let mut udp = context.udp_stream();
    for payload in [
        vec![1, 2, 3],
        crate::sniff::tests::hello(&rustls::version::TLS13, true),
    ] {
        poll_fn(|cx| Pin::new(&mut udp).poll_write_message(cx, &payload))
            .await
            .unwrap();
        let mut bytes = [0; 2048];
        let mut buf = ReadBuf::new(&mut bytes);
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(1),
                poll_fn(|cx| Pin::new(&mut udp).poll_read_message(cx, &mut buf)),
            )
            .await
            .is_err()
        );
        let query = query(RecordType::A);
        poll_fn(|cx| Pin::new(&mut udp).poll_write_message(cx, &query))
            .await
            .unwrap();
        poll_fn(|cx| Pin::new(&mut udp).poll_read_message(cx, &mut buf))
            .await
            .unwrap();
        assert_eq!(Message::from_vec(buf.filled()).unwrap().answers.len(), 1);
    }
    for (payload, elapsed) in [
        (vec![0, 0], 0),
        (vec![0, 3, 1, 2, 3], 0),
        (vec![0, 10, 1], 30),
        (vec![0], 60),
        (
            crate::sniff::tests::hello(&rustls::version::TLS13, true),
            30,
        ),
    ] {
        let mut tcp = context.tcp_stream();
        let start = tokio::time::Instant::now();
        tcp.write_all(&payload).await.unwrap();
        let mut reply = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(61),
            tcp.read_to_end(&mut reply),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(reply.is_empty());
        assert_eq!(start.elapsed(), std::time::Duration::from_secs(elapsed));
    }
    assert_eq!(real.exchanges.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn tcp_ready_before_query_fragmentation_and_pipelining() {
    let (context, real) = context();
    let mut stream = context.tcp_stream();
    tokio::task::yield_now().await;
    for kind in [RecordType::A, RecordType::TXT, RecordType::A] {
        let request = query(kind);
        let length = (request.len() as u16).to_be_bytes();
        stream.write_all(&length[..1]).await.unwrap();
        stream.write_all(&length[1..]).await.unwrap();
        for chunk in request.chunks(3) {
            stream.write_all(chunk).await.unwrap();
        }
    }
    for kind in [RecordType::A, RecordType::TXT, RecordType::A] {
        let len = stream.read_u16().await.unwrap() as usize;
        let mut bytes = vec![0; len];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(
            Message::from_vec(&bytes).unwrap().queries[0].query_type,
            kind
        );
    }
    assert_eq!(real.exchanges.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn tcp_accepts_maximum_frame_without_a_tls_capture_limit() {
    let (context, real) = context();
    let mut stream = context.tcp_stream();
    let mut request = Message::from_vec(&query(RecordType::A)).unwrap();
    let mut edns = hickory_resolver::proto::op::Edns::new();
    edns.options_mut().insert(EdnsOption::Unknown(12, vec![]));
    request.edns = Some(edns);
    let padding = u16::MAX as usize - request.to_vec().unwrap().len();
    request
        .edns
        .as_mut()
        .unwrap()
        .options_mut()
        .remove(12.into());
    request
        .edns
        .as_mut()
        .unwrap()
        .options_mut()
        .insert(EdnsOption::Unknown(12, vec![0; padding]));
    let bytes = request.to_vec().unwrap();
    assert_eq!(bytes.len(), 65_535);
    stream.write_u16(u16::MAX).await.unwrap();
    stream.write_all(&bytes).await.unwrap();
    let len = stream.read_u16().await.unwrap() as usize;
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(Message::from_vec(&bytes).unwrap().answers.len(), 1);
    assert_eq!(real.exchanges.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn dropping_tcp_peer_cancels_upstream_exchange() {
    #[derive(Debug)]
    struct Stalled(Arc<AtomicUsize>);
    struct Guard(Arc<AtomicUsize>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    impl Resolver for Stalled {
        fn resolve_location(&self, _: &NetLocation) -> ResolveFuture {
            unreachable!()
        }
        fn exchange(&self, _: Vec<u8>) -> DnsExchangeFuture {
            let guard = Guard(self.0.clone());
            Box::pin(async move {
                let _guard = guard;
                std::future::pending().await
            })
        }
    }
    let dropped = Arc::new(AtomicUsize::new(0));
    let context = Arc::new(
        DnsContext::new(FakeIpOptions::default(), Arc::new(Stalled(dropped.clone()))).unwrap(),
    );
    let mut stream = context.tcp_stream();
    let query = query(RecordType::TXT);
    stream.write_u16(query.len() as u16).await.unwrap();
    stream.write_all(&query).await.unwrap();
    tokio::task::yield_now().await;
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    drop(stream);
    tokio::task::yield_now().await;
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}
