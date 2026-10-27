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
mod tests;
