use super::*;
use crate::async_stream::{
    AsyncFlushMessage, AsyncPing, AsyncReadMessage, AsyncShutdownMessage, AsyncWriteMessage,
};
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::Context;

#[derive(Default)]
struct FlushState {
    mode: AtomicU8,
    entered: tokio::sync::Notify,
    waker: futures::task::AtomicWaker,
}

struct StalledFlush(Arc<FlushState>);

impl AsyncReadMessage for StalledFlush {
    fn poll_read_message(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWriteMessage for StalledFlush {
    fn poll_write_message(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<()>> {
        assert_eq!(data, b"packet");
        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for StalledFlush {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.waker.register(cx.waker());
        self.0.entered.notify_one();
        match self.0.mode.load(Ordering::Acquire) {
            1 => Poll::Ready(Ok(())),
            2 => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            _ => Poll::Pending,
        }
    }
}

impl AsyncShutdownMessage for StalledFlush {
    fn poll_shutdown_message(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for StalledFlush {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncMessageStream for StalledFlush {}

async fn buffered_xudp_replies(count: u16) -> Box<dyn AsyncMessageStream> {
    use crate::xudp::frame::{FrameMetadata, FrameOption, SessionStatus};
    use bytes::{BufMut, BytesMut};
    use tokio::io::AsyncWriteExt;

    let mut frames = BytesMut::new();
    for sequence in 0..count {
        FrameMetadata {
            session_id: 0,
            status: SessionStatus::Keep,
            option: FrameOption::new().with_data(),
            target: None,
            network: None,
        }
        .encode(&mut frames)
        .unwrap();
        frames.put_u16(2);
        frames.put_u16(sequence);
    }
    let (inner, mut peer) = tokio::io::duplex(frames.len());
    peer.write_all(&frames).await.unwrap();
    Box::new(crate::xudp::client_stream::XudpClientStream::new(
        Box::new(inner),
        NetLocation::UNSPECIFIED,
    ))
}

#[tokio::test(start_paused = true)]
async fn buffered_xudp_replies_survive_response_queue_backpressure() {
    const COUNT: u16 = 128;
    let peer = "10.0.0.2:1234".parse().unwrap();
    let source = "1.1.1.1:443".parse().unwrap();
    let (_write_tx, write_rx) = mpsc::channel(1);
    let (response_tx, mut response_rx) = mpsc::channel(RESPONSE_CHANNEL_SIZE);
    let slots = Arc::new(Budget::new(Some(1)));
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(destination_task(
        peer,
        source,
        buffered_xudp_replies(COUNT).await,
        write_rx,
        response_tx,
        slots.acquire(1).unwrap(),
    ));
    tokio::time::timeout(Duration::from_secs(1), async {
        for sequence in 0..COUNT {
            let (payload, actual_source, actual_peer) = response_rx.recv().await.unwrap();
            assert_eq!(&*payload, &sequence.to_be_bytes());
            assert_eq!((actual_source, actual_peer), (source, peer));
        }
        tasks.join_next().await.unwrap().unwrap();
    })
    .await
    .unwrap();
    assert_eq!(slots.available_permits(), 1);
}

#[tokio::test(start_paused = true)]
async fn manager_replies_survive_tun_queue_backpressure() {
    const COUNT: u16 = 128;
    let (_input, from_tun) = mpsc::channel(1);
    let (to_tun, output) = mpsc::channel(1);
    let (wake, _receiver) = super::super::wake::Wake::new().unwrap();
    let (reader, writer) =
        super::super::udp_handler::UdpHandler::new(from_tun, to_tun, wake.clone()).split();
    let manager = TunUdpManager::new(
        reader,
        writer,
        Arc::new(ClientProxySelector::new(Vec::new())),
        Arc::new(crate::resolver::NativeResolver::new()),
        TunResourceLimits::default(),
    );
    let (unused, _) = mpsc::channel(1);
    let (mut received, _) =
        super::super::udp_handler::UdpHandler::new(output, unused, wake).split();
    let responses = manager.response_tx.clone();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(manager.run());
    tasks.spawn(async move {
        for sequence in 0..COUNT {
            responses
                .send((
                    PacketBuffer::copy_from_slice(&sequence.to_be_bytes()),
                    "1.1.1.1:443".parse().unwrap(),
                    "10.0.0.2:1234".parse().unwrap(),
                ))
                .await
                .unwrap();
        }
        Ok(())
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        for sequence in 0..COUNT {
            let (payload, _, _) = received.next().await.unwrap();
            assert_eq!(&*payload, &sequence.to_be_bytes());
        }
    })
    .await
    .unwrap();
    tasks.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn backpressured_reply_releases_destination_on_every_exit_path() {
    for completion in ["success", "closed", "timeout", "cancel"] {
        let peer = "10.0.0.2:1234".parse().unwrap();
        let source = "1.1.1.1:443".parse().unwrap();
        let (_write_tx, write_rx) = mpsc::channel(1);
        let (response_tx, mut response_rx) = mpsc::channel(1);
        response_tx
            .send((PacketBuffer::copy_from_slice(b"occupied"), source, peer))
            .await
            .unwrap();
        let slots = Arc::new(Budget::new(Some(1)));
        let mut task = Box::pin(destination_task(
            peer,
            source,
            buffered_xudp_replies(1).await,
            write_rx,
            response_tx,
            slots.acquire(1).unwrap(),
        ));
        assert!(futures::poll!(task.as_mut()).is_pending());
        assert_eq!(slots.available_permits(), 0);
        assert_eq!(response_rx.len(), 1);
        match completion {
            "success" => {
                response_rx.recv().await.unwrap();
                task.await;
                let (payload, _, _) = response_rx.recv().await.unwrap();
                assert_eq!(&*payload, &0u16.to_be_bytes());
            }
            "closed" => {
                drop(response_rx);
                task.await;
            }
            "timeout" => {
                tokio::time::advance(WRITE_TIMEOUT).await;
                task.await;
                assert_eq!(response_rx.len(), 1);
            }
            "cancel" => drop(task),
            _ => unreachable!(),
        }
        assert_eq!(slots.available_permits(), 1);
    }
}

#[tokio::test(start_paused = true)]
async fn buffered_reply_bursts_share_capacity_without_losing_other_flows() {
    const COUNT: u16 = 128;
    const FLOWS: usize = 4;
    let (responses, mut received) = mpsc::channel(1);
    let slots = Arc::new(Budget::new(Some(FLOWS)));
    let mut tasks = tokio::task::JoinSet::new();
    let mut writers = Vec::new();
    for flow in 0..FLOWS {
        let (tx, rx) = mpsc::channel(1);
        writers.push(tx);
        tasks.spawn(destination_task(
            SocketAddr::from(([10, 0, 0, 2], 1000 + flow as u16)),
            "1.1.1.1:443".parse().unwrap(),
            buffered_xudp_replies(COUNT).await,
            rx,
            responses.clone(),
            slots.acquire(1).unwrap(),
        ));
    }
    drop(responses);
    let mut next = [0u16; FLOWS];
    tokio::time::timeout(Duration::from_secs(1), async {
        while let Some((payload, _, peer)) = received.recv().await {
            let sequence = &mut next[usize::from(peer.port() - 1000)];
            assert_eq!(&*payload, &sequence.to_be_bytes());
            *sequence += 1;
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
    })
    .await
    .unwrap();
    assert_eq!(next, [COUNT; FLOWS]);
    assert_eq!(slots.available_permits(), FLOWS);
}

#[tokio::test(start_paused = true)]
async fn closed_tun_output_stops_the_udp_manager() {
    let (_input, from_tun) = mpsc::channel(1);
    let (to_tun, output) = mpsc::channel(1);
    let (wake, _receiver) = super::super::wake::Wake::new().unwrap();
    let (reader, writer) =
        super::super::udp_handler::UdpHandler::new(from_tun, to_tun, wake).split();
    let manager = TunUdpManager::new(
        reader,
        writer,
        Arc::new(ClientProxySelector::new(Vec::new())),
        Arc::new(crate::resolver::NativeResolver::new()),
        TunResourceLimits::default(),
    );
    manager
        .response_tx
        .send((
            PacketBuffer::copy_from_slice(b"reply"),
            "1.1.1.1:443".parse().unwrap(),
            "10.0.0.2:1234".parse().unwrap(),
        ))
        .await
        .unwrap();
    drop(output);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), manager.run())
            .await
            .unwrap()
            .unwrap_err()
            .kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[tokio::test(start_paused = true)]
async fn queued_fake_dns_writes_continue_polling_delayed_replies() {
    use hickory_resolver::proto::{
        op::{Message, Query},
        rr::{Name, RecordType},
    };
    #[derive(Debug)]
    struct DelayedDns;
    impl Resolver for DelayedDns {
        fn resolve_location(&self, _: &NetLocation) -> crate::resolver::ResolveFuture {
            unreachable!()
        }
        fn exchange(&self, bytes: Vec<u8>) -> crate::resolver::DnsExchangeFuture {
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok(Message::from_vec(&bytes)
                    .unwrap()
                    .into_response()
                    .to_vec()
                    .unwrap())
            })
        }
    }
    let context =
        Arc::new(crate::dns::DnsContext::new(Default::default(), Arc::new(DelayedDns)).unwrap());
    let budget = Arc::new(Budget::new(Some(4096)));
    let slots = Arc::new(Budget::new(Some(1)));
    let (tx, rx) = mpsc::channel(8);
    let (responses, mut received) = mpsc::channel(8);
    for id in 0..8 {
        let mut query = Message::query();
        query.metadata.id = id;
        query.add_query(Query::query(
            Name::from_ascii("queued.example.").unwrap(),
            if id % 2 == 0 {
                RecordType::TXT
            } else {
                RecordType::A
            },
        ));
        assert!(
            tx.try_send(
                QueuedPacket::reserve(
                    PacketBuffer::copy_from_slice(&query.to_vec().unwrap()),
                    &budget,
                    true,
                )
                .unwrap(),
            )
            .is_ok()
        );
    }
    let task = tokio::spawn(destination_task(
        "10.0.0.2:1234".parse().unwrap(),
        "198.18.0.1:53".parse().unwrap(),
        context.udp_stream(),
        rx,
        responses,
        slots.acquire(1).unwrap(),
    ));
    tokio::time::timeout(Duration::from_secs(1), async {
        for id in 0..8 {
            let (bytes, source, peer) = received.recv().await.unwrap();
            assert_eq!(source, "198.18.0.1:53".parse().unwrap());
            assert_eq!(peer, "10.0.0.2:1234".parse().unwrap());
            assert_eq!(Message::from_vec(&bytes).unwrap().metadata.id, id);
        }
    })
    .await
    .unwrap();
    drop(tx);
    task.await.unwrap();
    assert_eq!(budget.available_permits(), 4096);
    assert_eq!(slots.available_permits(), 1);
}

#[tokio::test(start_paused = true)]
async fn packet_permit_survives_pending_flush_and_all_termination_paths() {
    for completion in ["success", "error", "timeout", "cancel"] {
        let budget = Arc::new(Budget::new(Some(6)));
        let slots = Arc::new(Budget::new(Some(1)));
        let state = Arc::new(FlushState::default());
        let (write_tx, write_rx) = mpsc::channel(1);
        let (response_tx, _response_rx) = mpsc::channel(1);
        let packet =
            QueuedPacket::reserve(PacketBuffer::copy_from_slice(b"packet"), &budget, true).unwrap();
        assert!(write_tx.try_send(packet).is_ok());
        let task = tokio::spawn(destination_task(
            "127.0.0.1:1234".parse().unwrap(),
            "127.0.0.1:4321".parse().unwrap(),
            Box::new(StalledFlush(state.clone())),
            write_rx,
            response_tx,
            slots.acquire(1).unwrap(),
        ));
        state.entered.notified().await;
        assert_eq!(budget.available_permits(), 0);
        assert_eq!(slots.available_permits(), 0);
        match completion {
            "success" | "error" => {
                state.mode.store(
                    if completion == "success" { 1 } else { 2 },
                    Ordering::Release,
                );
                state.waker.wake();
            }
            "timeout" => tokio::time::advance(WRITE_TIMEOUT + Duration::from_secs(1)).await,
            "cancel" => task.abort(),
            _ => unreachable!(),
        }
        drop(write_tx);
        let result = task.await;
        assert!(result.is_ok() || completion == "cancel" && result.unwrap_err().is_cancelled());
        assert_eq!(budget.available_permits(), 6);
        assert_eq!(slots.available_permits(), 1);
    }
}

#[test]
fn rejected_queue_packets_release_their_payload_permits() {
    let budget = Arc::new(Budget::new(Some(64)));
    let packet =
        || QueuedPacket::reserve(PacketBuffer::copy_from_slice(b"packet"), &budget, true).unwrap();
    let (tx, mut rx) = mpsc::channel(1);
    assert!(tx.try_send(packet()).is_ok());
    assert!(tx.try_send(packet()).is_err());
    assert_eq!(budget.available_permits(), 58);
    rx.close();
    assert!(tx.try_send(packet()).is_err());
    assert_eq!(budget.available_permits(), 58);
    drop(rx);
    assert_eq!(budget.available_permits(), 64);
}

#[tokio::test]
async fn default_session_admission_does_not_evict_at_the_old_limit() {
    let (_, from_tun) = mpsc::channel(1);
    let (to_tun, _) = mpsc::channel(1);
    let (wake, _receiver) = super::super::wake::Wake::new().unwrap();
    let (reader, writer) =
        super::super::udp_handler::UdpHandler::new(from_tun, to_tun, wake).split();
    let mut manager = TunUdpManager::new(
        reader,
        writer,
        Arc::new(ClientProxySelector::new(Vec::new())),
        Arc::new(crate::resolver::NativeResolver::new()),
        TunResourceLimits::default(),
    );
    for port in 10000..10300 {
        manager.create_session(SocketAddr::from(([127, 0, 0, 1], port)));
    }
    assert_eq!(manager.sessions.len(), 300);
    assert!(
        manager
            .sessions
            .contains(&SocketAddr::from(([127, 0, 0, 1], 10000)))
    );
}

#[test]
fn session_limit_does_not_preallocate_entries() {
    let limits = TunResourceLimits {
        max_udp_sessions: Some(usize::MAX),
        ..Default::default()
    };
    limits.validate().unwrap();
    let (_, from_tun) = mpsc::channel(1);
    let (to_tun, _) = mpsc::channel(1);
    let (wake, _receiver) = super::super::wake::Wake::new().unwrap();
    let (reader, writer) =
        super::super::udp_handler::UdpHandler::new(from_tun, to_tun, wake).split();
    let manager = TunUdpManager::new(
        reader,
        writer,
        Arc::new(ClientProxySelector::new(Vec::new())),
        Arc::new(crate::resolver::NativeResolver::new()),
        limits,
    );
    assert!(manager.sessions.is_empty());
    assert_eq!(manager.sessions.cap().get(), usize::MAX);
}

#[tokio::test]
async fn burst_packets_share_a_byte_budget_across_both_queue_stages() {
    const BURST: usize = 128;
    let budget = Arc::new(Budget::new(Some(BURST * 10)));
    let (session_tx, mut session_rx) = mpsc::channel(CHANNEL_SIZE);
    let (destination_tx, destination_rx) = mpsc::channel(CHANNEL_SIZE);
    for _ in 0..BURST {
        let packet =
            QueuedPacket::reserve(PacketBuffer::copy_from_slice(&[0; 10]), &budget, true).unwrap();
        assert!(session_tx.try_send(packet).is_ok());
    }
    assert_eq!(budget.available_permits(), 0);
    assert!(QueuedPacket::reserve(PacketBuffer::copy_from_slice(&[0]), &budget, true).is_none());
    for _ in 0..BURST {
        assert!(
            destination_tx
                .try_send(session_rx.recv().await.unwrap())
                .is_ok()
        );
    }
    assert_eq!(budget.available_permits(), 0);
    drop(destination_rx);
    assert_eq!(budget.available_permits(), BURST * 10);
    assert!(
        QueuedPacket::reserve(
            PacketBuffer::copy_from_slice(&[0; BURST * 10 + 1]),
            &budget,
            true
        )
        .is_none()
    );
    let empty = QueuedPacket::reserve(PacketBuffer::copy_from_slice(&[]), &budget, true).unwrap();
    assert_eq!(budget.available_permits(), BURST * 10 - 1);
    drop(empty);
    assert_eq!(budget.available_permits(), BURST * 10);
}

#[tokio::test]
async fn empty_udp_reply_does_not_close_destination() {
    let remote = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let source = SocketAddr::from(([127, 0, 0, 1], remote.local_addr().unwrap().port()));
    socket.connect(source).await.unwrap();
    let budget = Arc::new(Budget::new(Some(64)));
    let (write_tx, write_rx) = mpsc::channel(CHANNEL_SIZE);
    let (response_tx, mut response_rx) = mpsc::channel(RESPONSE_CHANNEL_SIZE);
    let permit = Arc::new(Budget::new(Some(1))).acquire(1).unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(destination_task(
        "127.0.0.1:1234".parse().unwrap(),
        source,
        Box::new(socket),
        write_rx,
        response_tx,
        permit,
    ));
    for payload in [b"".as_slice(), b"still open".as_slice()] {
        assert!(
            write_tx
                .try_send(
                    QueuedPacket::reserve(PacketBuffer::copy_from_slice(payload), &budget, true)
                        .unwrap()
                )
                .is_ok()
        );
        let mut bytes = [0; 64];
        let (length, peer) =
            tokio::time::timeout(Duration::from_secs(1), remote.recv_from(&mut bytes))
                .await
                .unwrap()
                .unwrap();
        remote.send_to(&bytes[..length], peer).await.unwrap();
        let (response, _, _) = tokio::time::timeout(Duration::from_secs(1), response_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&*response, payload);
    }
}

#[tokio::test(start_paused = true)]
async fn reply_only_sessions_expire_only_after_inactivity() {
    let (_input, from_tun) = mpsc::channel(1);
    let (to_tun, mut output) = mpsc::channel(1);
    let (wake, _receiver) = super::super::wake::Wake::new().unwrap();
    let (reader, writer) =
        super::super::udp_handler::UdpHandler::new(from_tun, to_tun, wake).split();
    let mut manager = TunUdpManager::new(
        reader,
        writer,
        Arc::new(ClientProxySelector::new(Vec::new())),
        Arc::new(crate::resolver::NativeResolver::new()),
        TunResourceLimits::default(),
    );
    let (tx, _rx) = mpsc::channel(1);
    let (alive, mut closed) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let _alive = alive;
        std::future::pending::<()>().await;
    });
    let local = "10.0.0.2:1234".parse().unwrap();
    manager.sessions.push(
        local,
        Session {
            tx,
            handle,
            last_active: Instant::now(),
        },
    );
    let responses = manager.response_tx.clone();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(manager.run());
    for _ in 0..12 {
        tokio::time::advance(Duration::from_secs(30)).await;
        responses
            .send((
                PacketBuffer::copy_from_slice(b""),
                "1.1.1.1:443".parse().unwrap(),
                local,
            ))
            .await
            .unwrap();
        output.recv().await.unwrap();
        assert!(matches!(
            closed.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
    }
    tokio::time::advance(SESSION_TIMEOUT + Duration::from_secs(31)).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), closed)
            .await
            .unwrap()
            .is_err()
    );
    tasks.shutdown().await;
}

#[tokio::test]
async fn lru_eviction_aborts_stalled_session() {
    let marker = Arc::new(());
    let weak = Arc::downgrade(&marker);
    let make_session = |marker| {
        let (tx, _rx) = mpsc::channel(1);
        Session {
            tx,
            handle: tokio::spawn(async move {
                let _marker = marker;
                std::future::pending::<()>().await;
            }),
            last_active: Instant::now(),
        }
    };
    let mut sessions = LruCache::new(NonZeroUsize::new(1).unwrap());
    sessions.push(1, make_session(marker));
    tokio::task::yield_now().await;
    sessions.push(2, make_session(Arc::new(())));
    tokio::task::yield_now().await;
    assert_eq!(weak.strong_count(), 0);
}
