//! TPROXY UDP relay: session-based, with kernel-level source spoofing on reply.

#![allow(dead_code)]

use std::future::poll_fn;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use log::{debug, warn};
use lru::LruCache;
use parking_lot::Mutex;
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::address::NetLocation;
use crate::async_stream::AsyncMessageStream;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::resolver::Resolver;
use crate::tproxy::cmsg::recv_with_orig_dst;
use crate::tproxy::listener::new_tproxy_udp_send_socket;

const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const GC_INTERVAL: Duration = Duration::from_secs(10);
const SEND_CACHE_CAP: usize = 1024;
const RECV_BUF_SIZE: usize = 64 * 1024;
const SESSION_QUEUE_DEPTH: usize = 64;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct SessionKey {
    client_src: SocketAddr,
    orig_dst: SocketAddr,
}

struct Session {
    tx: mpsc::Sender<Vec<u8>>,
    last_activity: Mutex<Instant>,
    task: JoinHandle<()>,
}

impl Session {
    fn touch(&self) {
        *self.last_activity.lock() = Instant::now();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// LRU cache of send sockets keyed by `orig_dst`. Each socket is bound to
/// `orig_dst` with `IP_TRANSPARENT` so replies appear to come from the
/// original destination the client meant to talk to.
struct SendSocketCache {
    inner: Mutex<LruCache<SocketAddr, Arc<UdpSocket>>>,
}

impl SendSocketCache {
    fn new() -> Self {
        Self {
            inner: Mutex::new(LruCache::new(NonZeroUsize::new(SEND_CACHE_CAP).unwrap())),
        }
    }

    fn get_or_create(&self, orig_dst: SocketAddr) -> std::io::Result<Arc<UdpSocket>> {
        if let Some(s) = self.inner.lock().get(&orig_dst).cloned() {
            return Ok(s);
        }
        let socket = Arc::new(new_tproxy_udp_send_socket(orig_dst)?);
        self.inner.lock().put(orig_dst, socket.clone());
        Ok(socket)
    }
}

pub struct UdpRelay {
    recv_socket: Arc<UdpSocket>,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    send_cache: Arc<SendSocketCache>,
    sessions: Arc<DashMap<SessionKey, Arc<Session>>>,
}

impl UdpRelay {
    pub fn new(
        recv_socket: UdpSocket,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        Self {
            recv_socket: Arc::new(recv_socket),
            proxy_selector,
            resolver,
            send_cache: Arc::new(SendSocketCache::new()),
            sessions: Arc::new(DashMap::new()),
        }
    }

    /// Run the relay until the recv socket errors (no shutdown signal — matches the
    /// existing TCP server loop in tcp_server.rs).
    pub async fn run(self) -> std::io::Result<()> {
        let sessions_for_gc = self.sessions.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(GC_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let now = Instant::now();
                sessions_for_gc
                    .retain(|_, s| now.duration_since(*s.last_activity.lock()) < IDLE_TIMEOUT);
            }
        });

        let mut buf = vec![0u8; RECV_BUF_SIZE];
        loop {
            let (n, client_src, orig_dst) = match recv_with_orig_dst(&self.recv_socket, &mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    // Per-packet anomalies (MSG_CTRUNC, missing cmsg) come back as InvalidData/Other.
                    // Don't tear down the relay over one bad packet — log and keep going.
                    match e.kind() {
                        std::io::ErrorKind::InvalidData | std::io::ErrorKind::Other => {
                            debug!("tproxy udp recv (dropping packet): {e}");
                            continue;
                        }
                        _ => {
                            warn!("tproxy udp recv failed: {e}");
                            return Err(e);
                        }
                    }
                }
            };
            let key = SessionKey { client_src, orig_dst };
            let data = buf[..n].to_vec();

            if let Some(session) = self.sessions.get(&key).map(|s| s.clone()) {
                session.touch();
                let _ = session.tx.try_send(data);
                continue;
            }

            // Borrow the initial packet's data once so we can hand it to whichever session wins the race.
            let initial = data;
            match self.spawn_session(key.clone(), initial.clone()).await {
                Ok(Some(new_session)) => {
                    use dashmap::mapref::entry::Entry;
                    match self.sessions.entry(key) {
                        Entry::Occupied(occupied) => {
                            // Another packet for the same flow finished session setup first.
                            // Hand our initial packet to the winning session; drop our newly-built
                            // session (its Drop aborts the task we just spawned).
                            let existing = occupied.get().clone();
                            existing.touch();
                            let _ = existing.tx.try_send(initial);
                            drop(new_session);
                        }
                        Entry::Vacant(vacant) => {
                            vacant.insert(new_session);
                        }
                    }
                }
                Ok(None) => {
                    // Blocked by rules — drop.
                }
                Err(e) => {
                    warn!(
                        "tproxy udp session setup failed {} -> {}: {e}",
                        key.client_src, key.orig_dst
                    );
                }
            }
        }
    }

    async fn spawn_session(
        &self,
        key: SessionKey,
        initial: Vec<u8>,
    ) -> std::io::Result<Option<Arc<Session>>> {
        let net_loc = NetLocation::from_socket_addr(key.orig_dst);
        let resolved = net_loc.into();
        let decision = self.proxy_selector.judge(resolved, &self.resolver).await?;
        let (chain_group, remote) = match decision {
            ConnectDecision::Allow { chain_group, remote_location } => (chain_group, remote_location),
            ConnectDecision::Block => {
                debug!("tproxy udp blocked {} -> {}", key.client_src, key.orig_dst);
                return Ok(None);
            }
        };

        let outbound = chain_group
            .connect_udp_bidirectional(&self.resolver, remote)
            .await?;

        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(SESSION_QUEUE_DEPTH);
        let _ = tx.try_send(initial);

        let send_cache = self.send_cache.clone();
        let client_src = key.client_src;
        let orig_dst = key.orig_dst;
        let sessions = self.sessions.clone();
        let key_for_cleanup = key.clone();

        let task = tokio::spawn(async move {
            let mut outbound: Box<dyn AsyncMessageStream> = outbound;
            let mut read_buf = vec![0u8; RECV_BUF_SIZE];
            loop {
                tokio::select! {
                    maybe_data = rx.recv() => {
                        let Some(data) = maybe_data else { break };
                        if let Err(e) = write_message_async(outbound.as_mut(), &data).await {
                            debug!("tproxy outbound write {client_src} -> {orig_dst}: {e}");
                            break;
                        }
                    }
                    n = read_message_async(outbound.as_mut(), &mut read_buf) => {
                        match n {
                            Ok(0) => break,
                            Ok(n) => {
                                let send = match send_cache.get_or_create(orig_dst) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        warn!("tproxy send-cache create {orig_dst}: {e}");
                                        break;
                                    }
                                };
                                if let Err(e) = send.send_to(&read_buf[..n], client_src).await {
                                    debug!("tproxy reply send to {client_src}: {e}");
                                    break;
                                }
                                if let Some(session) = sessions.get(&key_for_cleanup) {
                                    session.touch();
                                }
                            }
                            Err(e) => {
                                debug!("tproxy outbound read {client_src} -> {orig_dst}: {e}");
                                break;
                            }
                        }
                    }
                }
            }
            sessions.remove(&key_for_cleanup);
        });

        let session = Arc::new(Session {
            tx,
            last_activity: Mutex::new(Instant::now()),
            task,
        });
        Ok(Some(session))
    }
}

async fn write_message_async(
    stream: &mut dyn AsyncMessageStream,
    buf: &[u8],
) -> std::io::Result<()> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_write_message(cx, buf)).await
}

async fn read_message_async(
    stream: &mut dyn AsyncMessageStream,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    poll_fn(|cx| {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut *stream).poll_read_message(cx, &mut read_buf) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(read_buf.filled().len())),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    })
    .await
}
