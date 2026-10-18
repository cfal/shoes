use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use futures::future::poll_fn;
use hickory_resolver::proto::op::{Message, Query, ResponseCode};
use hickory_resolver::proto::rr::rdata::opt::EdnsOption;
use hickory_resolver::proto::rr::{Name, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};

use crate::address::NetLocation;
use crate::async_stream::{AsyncReadMessage, AsyncShutdownMessage, AsyncWriteMessage};
use crate::resolver::{DnsExchangeFuture, ResolveFuture, Resolver};

use super::{FakeDnsContext, FakeIpOptions};

#[derive(Debug, Default)]
struct RecordingResolver {
    exchanges: AtomicUsize,
}

impl Resolver for Arc<RecordingResolver> {
    fn resolve_location(&self, _: &NetLocation) -> ResolveFuture {
        panic!("client DNS must not use address-only resolution")
    }

    fn exchange(&self, request: Vec<u8>) -> DnsExchangeFuture {
        self.exchanges.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let mut answer = Message::from_vec(&request)
                .map_err(io::Error::other)?
                .into_response();
            answer.metadata.response_code = ResponseCode::NXDomain;
            answer.to_vec().map_err(io::Error::other)
        })
    }
}

fn context() -> (Arc<FakeDnsContext>, Arc<RecordingResolver>) {
    let real = Arc::new(RecordingResolver::default());
    let context =
        Arc::new(FakeDnsContext::new(FakeIpOptions::default(), Arc::new(real.clone())).unwrap());
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
    let context = FakeDnsContext::with_pool(
        options,
        Arc::new(Arc::new(RecordingResolver::default())),
        pool.clone(),
    )
    .unwrap();
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
        FakeDnsContext::new(FakeIpOptions::default(), Arc::new(Stalled(dropped.clone()))).unwrap(),
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
