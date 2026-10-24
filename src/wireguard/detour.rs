use std::{
    collections::{HashMap, hash_map::Entry},
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::Poll,
    time::Duration,
};

use futures::future::poll_fn;
use gotatun::packet::{Packet, PacketBufPool};
use parking_lot::Mutex;
use tokio::{
    io::ReadBuf,
    sync::{mpsc, oneshot},
    task::JoinSet,
    time::{Instant, sleep, timeout},
};
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::{
    address::NetLocation, async_stream::AsyncMessageStream, client_proxy_chain::ClientProxyChain,
    resolver::Resolver,
};

const QUEUE_CAPACITY: usize = 64;
// The supported inner MTU is at most 1420, plus WireGuard padding, header and tag.
const MAX_DATAGRAM: usize = 2048;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_BACKOFF: Duration = Duration::from_millis(250);
const MAX_BACKOFF: Duration = Duration::from_secs(10);
const STABLE_ASSOCIATION: Duration = Duration::from_secs(10);
const PING_INTERVAL: Duration = Duration::from_secs(30);

type Destination = Arc<Mutex<Option<mpsc::Sender<Vec<u8>>>>>;

#[derive(Clone)]
pub(super) struct Sender {
    destinations: Arc<HashMap<SocketAddr, Destination>>,
    drops: Arc<AtomicU64>,
}

pub(super) struct Receiver {
    incoming: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    _cancel: DropGuard,
}

impl Sender {
    pub fn send_to(&self, packet: Packet, target: SocketAddr) -> io::Result<()> {
        let destination = self.destinations.get(&target).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "WireGuard detour target is not configured",
            )
        })?;
        let outgoing = destination.lock();
        let sent = packet.len() <= MAX_DATAGRAM
            && outgoing
                .as_ref()
                .is_some_and(|queue| queue.try_send(packet.to_vec()).is_ok());
        if !sent {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }
}

impl Receiver {
    pub async fn recv_from(
        &mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<(Packet, SocketAddr)> {
        let (packet, source) = self
            .incoming
            .recv()
            .await
            .ok_or(io::ErrorKind::BrokenPipe)?;
        Ok((pool.get().overwrite_with(packet.as_slice()), source))
    }
}

pub(super) fn start(
    name: String,
    chain: Arc<ClientProxyChain>,
    resolver: Arc<dyn Resolver>,
    targets: impl Iterator<Item = SocketAddr>,
    drops: Arc<AtomicU64>,
) -> (Sender, Receiver, oneshot::Receiver<()>) {
    let cancel = CancellationToken::new();
    let (incoming, received) = mpsc::channel(QUEUE_CAPACITY);
    let (closed, released) = oneshot::channel();
    let mut destinations = HashMap::new();
    let mut workers = JoinSet::new();
    for target in targets {
        let Entry::Vacant(entry) = destinations.entry(target) else {
            continue;
        };
        let destination = Arc::new(Mutex::new(None));
        entry.insert(destination.clone());
        let worker = Worker {
            name: name.clone(),
            target,
            chain: chain.clone(),
            resolver: resolver.clone(),
            destination,
            incoming: incoming.clone(),
            drops: drops.clone(),
        };
        workers.spawn(crate::control::url_test::BACKGROUND.scope((), worker.run()));
    }
    drop(incoming);
    let shutdown = cancel.clone();
    tokio::spawn(async move {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {},
            result = workers.join_next() => {
                log::error!("WireGuard endpoint {name} outer worker stopped unexpectedly: {result:?}");
            }
        }
        workers.shutdown().await;
        let _ = closed.send(());
    });
    (
        Sender {
            destinations: Arc::new(destinations),
            drops,
        },
        Receiver {
            incoming: received,
            _cancel: cancel.drop_guard(),
        },
        released,
    )
}

struct Worker {
    name: String,
    target: SocketAddr,
    chain: Arc<ClientProxyChain>,
    resolver: Arc<dyn Resolver>,
    destination: Destination,
    incoming: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    drops: Arc<AtomicU64>,
}

impl Worker {
    async fn run(self) {
        let mut backoff = MIN_BACKOFF;
        loop {
            let target = NetLocation::from_ip_addr(self.target.ip(), self.target.port()).into();
            let connected = timeout(
                IO_TIMEOUT,
                self.chain.connect_udp_bidirectional(&self.resolver, target),
            )
            .await;
            let error = match connected {
                Ok(Ok(mut stream)) => {
                    log::debug!(
                        "WireGuard endpoint {} outer association connected to {}",
                        self.name,
                        self.target
                    );
                    let (outgoing, mut queued) = mpsc::channel(QUEUE_CAPACITY);
                    *self.destination.lock() = Some(outgoing);
                    let started = Instant::now();
                    let error = self.relay(stream.as_mut(), &mut queued).await;
                    // Removing the sender under the enqueue lock isolates failed associations.
                    self.destination.lock().take();
                    self.drops.fetch_add(queued.len() as u64, Ordering::Relaxed);
                    if started.elapsed() >= STABLE_ASSOCIATION {
                        backoff = MIN_BACKOFF;
                    }
                    error
                }
                Ok(Err(error)) => error,
                Err(_) => io::Error::new(
                    io::ErrorKind::TimedOut,
                    "outer association connect timed out",
                ),
            };
            log::warn!(
                "WireGuard endpoint {} outer association {} failed: {error}; retry in {backoff:?}",
                self.name,
                self.target
            );
            sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    async fn relay(
        &self,
        stream: &mut dyn AsyncMessageStream,
        outgoing: &mut mpsc::Receiver<Vec<u8>>,
    ) -> io::Error {
        enum Write {
            Packet(Vec<u8>),
            Ping,
            Flush { packet: bool },
        }
        let mut scratch = vec![0; 65536];
        // Flushes protocol setup buffered while opening the association.
        let mut pending = Some(Write::Flush { packet: false });
        let mut deadline = Box::pin(sleep(IO_TIMEOUT));
        let mut ping = tokio::time::interval(PING_INTERVAL);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::task::consume_budget().await;
            let result: io::Result<()> = poll_fn(|cx| {
                let mut progress = false;
                let mut buffer = ReadBuf::new(&mut scratch);
                if let Poll::Ready(result) =
                    Pin::new(&mut *stream).poll_read_message(cx, &mut buffer)
                {
                    result?;
                    let bytes = buffer.filled();
                    if bytes.is_empty() && stream.read_message_eof_on_empty() {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    if !bytes.is_empty()
                        && (bytes.len() > MAX_DATAGRAM
                            || self
                                .incoming
                                .try_send((bytes.to_vec(), self.target))
                                .is_err())
                    {
                        self.drops.fetch_add(1, Ordering::Relaxed);
                    }
                    progress = true;
                }
                if pending.is_none() {
                    match outgoing.poll_recv(cx) {
                        Poll::Ready(Some(packet)) => pending = Some(Write::Packet(packet)),
                        Poll::Ready(None) => {
                            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                        }
                        Poll::Pending => {
                            if stream.supports_ping() && ping.poll_tick(cx).is_ready() {
                                pending = Some(Write::Ping);
                            }
                        }
                    }
                    if pending.is_some() {
                        deadline.as_mut().reset(Instant::now() + IO_TIMEOUT);
                    }
                }
                if let Some(write) = &pending {
                    let result = match write {
                        Write::Packet(packet) => {
                            Pin::new(&mut *stream).poll_write_message(cx, packet)
                        }
                        Write::Ping => Pin::new(&mut *stream)
                            .poll_write_ping(cx)
                            .map(|result| result.map(|_| ())),
                        Write::Flush { .. } => Pin::new(&mut *stream).poll_flush_message(cx),
                    };
                    if let Poll::Ready(result) = result {
                        result?;
                        pending = match write {
                            Write::Packet(_) => Some(Write::Flush { packet: true }),
                            Write::Ping => Some(Write::Flush { packet: false }),
                            Write::Flush { .. } => None,
                        };
                        progress = true;
                    }
                    if pending.is_some() && deadline.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "outer association write timed out",
                        )));
                    }
                }
                if progress {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            })
            .await;
            if let Err(error) = result {
                if matches!(
                    pending,
                    Some(Write::Packet(_) | Write::Flush { packet: true })
                ) {
                    self.drops.fetch_add(1, Ordering::Relaxed);
                }
                return error;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        address::ResolvedLocation, async_stream::AsyncStream, client_proxy_chain::InitialHopEntry,
        resolver::NativeResolver, tcp::socket_connector::SocketConnector,
        vless::VlessMessageStream,
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
}
