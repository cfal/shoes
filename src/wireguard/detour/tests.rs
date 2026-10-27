use super::*;
use crate::{
    address::ResolvedLocation, async_stream::AsyncStream, client_proxy_chain::InitialHopEntry,
    resolver::NativeResolver, tcp::socket_connector::SocketConnector, vless::VlessMessageStream,
};
use tokio::io::{AsyncReadExt, DuplexStream};

#[derive(Debug)]
struct Socket {
    index: usize,
    opened: mpsc::UnboundedSender<(usize, SocketAddr, DuplexStream)>,
    hang: bool,
}

#[async_trait::async_trait]
impl SocketConnector for Socket {
    async fn connect(
        &self,
        _: &Arc<dyn Resolver>,
        _: &ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncStream>> {
        unreachable!()
    }
    async fn connect_udp_bidirectional(
        &self,
        _: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        let target = target.location().to_socket_addr_nonblocking().unwrap();
        let (stream, peer) = tokio::io::duplex(16);
        self.opened.send((self.index, target, peer)).unwrap();
        if self.hang {
            std::future::pending::<()>().await;
        }
        Ok(Box::new(VlessMessageStream::new(stream)))
    }
    fn bind_interface(&self) -> Option<&str> {
        None
    }
}

async fn write(stream: &mut dyn AsyncMessageStream, bytes: &[u8]) {
    poll_fn(|cx| Pin::new(&mut *stream).poll_write_message(cx, bytes))
        .await
        .unwrap();
    poll_fn(|cx| Pin::new(&mut *stream).poll_flush_message(cx))
        .await
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn url_test_idle_reconnects_do_not_activate_lazy_groups() {
    #[derive(Debug)]
    struct FailingSocket(Arc<AtomicU64>);

    #[async_trait::async_trait]
    impl SocketConnector for FailingSocket {
        async fn connect(
            &self,
            _: &Arc<dyn Resolver>,
            _: &ResolvedLocation,
        ) -> io::Result<Box<dyn AsyncStream>> {
            unreachable!()
        }

        async fn connect_udp_bidirectional(
            &self,
            _: &Arc<dyn Resolver>,
            _: ResolvedLocation,
        ) -> io::Result<Box<dyn AsyncMessageStream>> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Err(io::ErrorKind::ConnectionRefused.into())
        }

        fn bind_interface(&self) -> Option<&str> {
            None
        }
    }

    let mut selection = crate::control::selection::SelectionView::default();
    selection
        .automatic
        .insert(
            "carrier".into(),
            crate::config::UrlTestConfig {
                url: "http://probe.invalid/".into(),
                interval: 10,
                timeout: 1000,
                tolerance: 50,
                lazy: true,
            },
            vec!["peer".into()],
        )
        .unwrap();
    let selection = Arc::new(selection);
    let attempts = Arc::new(AtomicU64::new(0));
    let chain = Arc::new(
        ClientProxyChain::new(
            vec![InitialHopEntry::Direct(Arc::new(FailingSocket(
                attempts.clone(),
            )))],
            vec![],
        )
        .with_origins(vec![vec![Some(crate::control::catalog::MemberOrigin {
            name: Arc::from("peer"),
            path: vec![("carrier".into(), "peer".into())],
            selection: selection.clone(),
        })]]),
    );
    let group = &selection.automatic.0["carrier"];
    assert!(group.due_members(Instant::now()).is_some());
    let (_sender, receiver, released) = start(
        "idle".into(),
        chain.clone(),
        Arc::new(NativeResolver::new()),
        ["127.0.0.1:51820".parse().unwrap()].into_iter(),
        Arc::new(AtomicU64::new(0)),
    );
    for _ in 0..20 {
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
    }
    assert!(attempts.load(Ordering::Relaxed) > 1);
    assert!(group.due_members(Instant::now()).is_none());
    drop(receiver);
    released.await.unwrap();

    let stack = crate::ip_stack::driver::PacketStack::new(
        vec!["10.0.0.2".parse().unwrap()],
        1420,
        false,
        Default::default(),
    )
    .unwrap();
    let connector = |carrier| {
        Arc::new(crate::wireguard::Connector {
            name: "demand".into(),
            active: Mutex::new(Some(crate::wireguard::ActiveEndpoint {
                handle: stack.handle.clone(),
                carrier: Some(carrier),
            })),
            addresses: vec!["10.0.0.2".parse().unwrap()],
            routes: vec!["0.0.0.0/0".parse().unwrap()],
        })
    };
    let outer = connector(chain);
    let nested = connector(Arc::new(ClientProxyChain::new(
        vec![InitialHopEntry::Wireguard(outer)],
        vec![],
    )));
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target: ResolvedLocation =
        NetLocation::from_ip_addr("10.0.0.1".parse().unwrap(), 80).into();
    for udp in [false, true] {
        for background in [true, false] {
            let connect = async {
                if udp {
                    let attempt = nested.connect_udp_bidirectional(&resolver, target.clone());
                    tokio::pin!(attempt);
                    let _ = futures::poll!(&mut attempt);
                } else {
                    let attempt = nested.connect(&resolver, &target);
                    tokio::pin!(attempt);
                    let _ = futures::poll!(&mut attempt);
                }
            };
            if background {
                crate::control::url_test::BACKGROUND
                    .scope((), connect)
                    .await;
            } else {
                connect.await;
            }
            assert_eq!(group.due_members(Instant::now()).is_some(), !background);
            tokio::time::advance(Duration::from_secs(11)).await;
        }
    }
}

async fn read(stream: &mut dyn AsyncMessageStream) -> Vec<u8> {
    let mut bytes = vec![0; 65536];
    let mut buffer = ReadBuf::new(&mut bytes);
    poll_fn(|cx| Pin::new(&mut *stream).poll_read_message(cx, &mut buffer))
        .await
        .unwrap();
    buffer.filled().to_vec()
}

#[tokio::test]
async fn bounded_queues_drop_offline_oversize_and_unknown_targets() {
    let target = "127.0.0.1:51820".parse().unwrap();
    let (outgoing, mut queue) = mpsc::channel(QUEUE_CAPACITY);
    let destination = Arc::new(Mutex::new(None));
    let drops = Arc::new(AtomicU64::new(0));
    let sender = Sender {
        destinations: Arc::new(HashMap::from([(target, destination.clone())])),
        drops: drops.clone(),
    };
    sender
        .send_to(Packet::copy_from(b"offline"), target)
        .unwrap();
    assert!(queue.try_recv().is_err());
    *destination.lock() = Some(outgoing);
    sender
        .send_to(Packet::copy_from(&[0; MAX_DATAGRAM + 1]), target)
        .unwrap();
    for _ in 0..QUEUE_CAPACITY + 1 {
        sender
            .send_to(Packet::copy_from(b"packet"), target)
            .unwrap();
    }
    assert_eq!(queue.len(), QUEUE_CAPACITY);
    assert_eq!(drops.load(Ordering::Relaxed), 3);
    assert!(
        sender
            .send_to(
                Packet::copy_from(b"unknown"),
                "127.0.0.1:9".parse().unwrap()
            )
            .is_err()
    );
}

#[test]
fn disconnected_queue_cannot_receive_or_replay_packets() {
    let target = "127.0.0.1:51820".parse().unwrap();
    let (old_sender, mut old_queue) = mpsc::channel(QUEUE_CAPACITY);
    let destination = Arc::new(Mutex::new(Some(old_sender)));
    let drops = Arc::new(AtomicU64::new(0));
    let sender = Sender {
        destinations: Arc::new(HashMap::from([(target, destination.clone())])),
        drops: drops.clone(),
    };
    sender.send_to(Packet::copy_from(b"old"), target).unwrap();
    let mut slot = destination.lock();
    let (started, ready) = std::sync::mpsc::channel();
    let concurrent_sender = sender.clone();
    let send = std::thread::spawn(move || {
        started.send(()).unwrap();
        concurrent_sender
            .send_to(Packet::copy_from(b"offline"), target)
            .unwrap();
    });
    ready.recv().unwrap();
    slot.take();
    drop(slot);
    send.join().unwrap();
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(old_queue.try_recv().unwrap(), b"old");
    assert!(matches!(
        old_queue.try_recv(),
        Err(mpsc::error::TryRecvError::Disconnected)
    ));
    let (fresh_sender, mut fresh_queue) = mpsc::channel(QUEUE_CAPACITY);
    *destination.lock() = Some(fresh_sender);
    sender.send_to(Packet::copy_from(b"fresh"), target).unwrap();
    assert_eq!(fresh_queue.try_recv().unwrap(), b"fresh");
    assert!(fresh_queue.try_recv().is_err());
}

#[tokio::test]
async fn associations_preserve_messages_isolate_peers_reconnect_and_release() {
    timeout(Duration::from_secs(5), async {
        let (opened, mut connections) = mpsc::unbounded_channel();
        let chain = Arc::new(ClientProxyChain::new(
            (0..2)
                .map(|index| {
                    InitialHopEntry::Direct(Arc::new(Socket {
                        index,
                        opened: opened.clone(),
                        hang: false,
                    }))
                })
                .collect(),
            vec![],
        ));
        let targets = [
            "127.0.0.1:51820".parse().unwrap(),
            "[::1]:51821".parse().unwrap(),
        ];
        let drops = Arc::new(AtomicU64::new(0));
        let (sender, mut receiver, released) = start(
            "test".into(),
            chain,
            Arc::new(NativeResolver::new()),
            [targets[0], targets[0], targets[1]].into_iter(),
            drops.clone(),
        );
        assert_eq!(sender.destinations.len(), 2);
        let mut peers = HashMap::new();
        for _ in 0..2 {
            let (index, target, stream) = connections.recv().await.unwrap();
            peers.insert(target, (index, VlessMessageStream::new(stream)));
        }
        let mut pool = PacketBufPool::new(4);
        for target in targets {
            let (_, peer) = peers.get_mut(&target).unwrap();
            for length in [1, 148, 1408] {
                let payload = vec![length as u8; length];
                sender.send_to(Packet::copy_from(&payload), target).unwrap();
                assert_eq!(read(peer).await, payload);
                write(peer, &payload).await;
                let (packet, source) = receiver.recv_from(&mut pool).await.unwrap();
                assert_eq!(source, target);
                assert_eq!(&*packet, payload);
            }
        }
        assert!(
            connections.try_recv().is_err(),
            "carrier was redialed per packet"
        );
        let (_, peer) = peers.get_mut(&targets[0]).unwrap();
        write(peer, &[0; MAX_DATAGRAM + 1]).await;
        write(peer, b"after oversize").await;
        let (packet, _) = receiver.recv_from(&mut pool).await.unwrap();
        assert_eq!(&*packet, b"after oversize");
        assert_eq!(drops.load(Ordering::Relaxed), 1);

        for _ in 0..QUEUE_CAPACITY + 4 {
            write(peer, b"bounded receive").await;
        }
        tokio::task::yield_now().await;
        assert_eq!(receiver.incoming.len(), QUEUE_CAPACITY);
        assert!(drops.load(Ordering::Relaxed) > 1);
        while receiver.incoming.try_recv().is_ok() {}

        let (_, old_peer) = peers.remove(&targets[0]).unwrap();
        drop(old_peer);
        let (index, target, stream) = connections.recv().await.unwrap();
        assert_eq!(target, targets[0]);
        assert_eq!(index, 0); // The third association wraps the two-entry pool.
        peers.insert(target, (index, VlessMessageStream::new(stream)));
        for _ in 0..QUEUE_CAPACITY + 5 {
            sender
                .send_to(Packet::copy_from(&[7; MAX_DATAGRAM]), targets[1])
                .unwrap();
        }
        sender
            .send_to(Packet::copy_from(b"independent peer"), targets[0])
            .unwrap();
        assert_eq!(
            read(&mut peers.get_mut(&targets[0]).unwrap().1).await,
            b"independent peer"
        );
        assert!(drops.load(Ordering::Relaxed) > 1);
        drop(receiver);
        released.await.unwrap();
        // Sender clones cannot keep carriers alive after the GotaTun receiver is dropped.
        assert!(sender.destinations.values().all(|destination| {
            destination
                .lock()
                .as_ref()
                .is_none_or(|queue| queue.is_closed())
        }));
        assert!(
            read(&mut peers.get_mut(&targets[0]).unwrap().1)
                .await
                .is_empty()
        );
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn stalled_connect_is_bounded_and_cancellation_joins_workers() {
    let (opened, mut connections) = mpsc::unbounded_channel();
    let chain = Arc::new(ClientProxyChain::new(
        vec![InitialHopEntry::Direct(Arc::new(Socket {
            index: 0,
            opened,
            hang: true,
        }))],
        vec![],
    ));
    let target = "127.0.0.1:51820".parse().unwrap();
    let (sender, receiver, released) = start(
        "timeout".into(),
        chain,
        Arc::new(NativeResolver::new()),
        [target].into_iter(),
        Arc::new(AtomicU64::new(0)),
    );
    let (_, _, mut first) = connections.recv().await.unwrap();
    tokio::time::advance(IO_TIMEOUT + MIN_BACKOFF).await;
    assert_eq!(first.read(&mut [0]).await.unwrap(), 0);
    let (_, _, mut second) = connections.recv().await.unwrap();
    assert!(sender.destinations[&target].lock().is_none());
    drop(receiver);
    released.await.unwrap();
    assert_eq!(second.read(&mut [0]).await.unwrap(), 0);
}

#[tokio::test(start_paused = true)]
async fn stalled_write_reconnects_without_replaying_old_queue() {
    let (opened, mut connections) = mpsc::unbounded_channel();
    let chain = Arc::new(ClientProxyChain::new(
        vec![InitialHopEntry::Direct(Arc::new(Socket {
            index: 0,
            opened,
            hang: false,
        }))],
        vec![],
    ));
    let target = "127.0.0.1:51820".parse().unwrap();
    let drops = Arc::new(AtomicU64::new(0));
    let (sender, receiver, released) = start(
        "timeout".into(),
        chain,
        Arc::new(NativeResolver::new()),
        [target].into_iter(),
        drops.clone(),
    );
    let (_, _, _blocked) = connections.recv().await.unwrap();
    for _ in 0..3 {
        sender
            .send_to(Packet::copy_from(&[1; 1000]), target)
            .unwrap();
    }
    tokio::task::yield_now().await;
    tokio::time::advance(IO_TIMEOUT + MIN_BACKOFF).await;
    let (_, _, stream) = connections.recv().await.unwrap();
    let mut peer = VlessMessageStream::new(stream);
    assert_eq!(drops.load(Ordering::Relaxed), 3);
    sender.send_to(Packet::copy_from(b"fresh"), target).unwrap();
    assert_eq!(read(&mut peer).await, b"fresh");
    drop(receiver);
    released.await.unwrap();
}
