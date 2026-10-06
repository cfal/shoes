//! TUN UDP Session Manager.
//!
//! Provides session-based UDP handling for TUN devices. Each destination
//! connection runs in its own task, blocking on reads and processing writes
//! via channel. This eliminates the busy-polling loop that previously caused
//! CPU runaway under high-churn UDP workloads.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use log::debug;
use lru::LruCache;
use tokio::io::ReadBuf;
use tokio::sync::mpsc;
use tokio::time::{Instant, interval};

use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncMessageStream;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::config::tun::TunResourceLimits;
use crate::resolver::Resolver;
use crate::resources::{Budget, BudgetPermit};

use super::packet::PacketBuffer;
use super::udp_handler::{UdpMessage, UdpReader, UdpWriter};

/// Session timeout - sessions without activity are expired
const SESSION_TIMEOUT: Duration = Duration::from_secs(300);

/// Channel buffer size for session and destination packets
const CHANNEL_SIZE: usize = 64;

/// Response channel buffer size. Bounds memory growth when destination
/// tasks produce responses faster than the manager can write to TUN.
const RESPONSE_CHANNEL_SIZE: usize = 32;

/// Per-destination connection timeout (self-enforced by destination tasks)
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(120);

/// Maximum time to wait for a single write to complete before treating
/// the connection as dead. Bounds orphan lifetime if the underlying
/// stream stalls (e.g. unresponsive remote, full TCP send buffer).
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Convert a SocketAddr to a NetLocation.
fn socket_addr_to_net_location(addr: SocketAddr) -> NetLocation {
    let address = match addr.ip() {
        std::net::IpAddr::V4(v4) => Address::Ipv4(v4),
        std::net::IpAddr::V6(v6) => Address::Ipv6(v6),
    };
    NetLocation::new(address, addr.port())
}

/// TUN UDP Manager - handles all UDP traffic through the TUN.
///
/// Sessions are keyed by the local (app) address, ensuring each app's
/// traffic is handled independently and responses are routed correctly.
pub struct TunUdpManager {
    reader: UdpReader,
    writer: UdpWriter,
    sessions: LruCache<SocketAddr, Session>,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    /// Receives responses from destination tasks (across all sessions)
    response_rx: mpsc::Receiver<UdpMessage>,
    /// Cloned into each session, then into each destination task
    response_tx: mpsc::Sender<UdpMessage>,
    destination_slots: Arc<Budget>,
    destinations_per_session: Option<usize>,
    queued_bytes: Arc<Budget>,
    compact_payloads: bool,
}

struct QueuedPacket {
    payload: PacketBuffer,
    _permit: BudgetPermit,
}

impl QueuedPacket {
    fn reserve(payload: PacketBuffer, budget: &Arc<Budget>, compact: bool) -> Option<Self> {
        let permit = budget.acquire(payload.len().max(1))?;
        Some(Self {
            payload: payload.into_payload(compact),
            _permit: permit,
        })
    }
}

/// A UDP session for a single local (app) address.
struct Session {
    /// Channel to send outgoing packets to the session task
    tx: mpsc::Sender<(SocketAddr, QueuedPacket)>,
    /// Handle to the session task
    handle: tokio::task::JoinHandle<()>,
    /// Last activity time
    last_active: Instant,
}

impl Session {
    fn is_alive(&self) -> bool {
        !self.handle.is_finished()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl TunUdpManager {
    /// Create a new TUN UDP manager.
    pub fn new(
        reader: UdpReader,
        writer: UdpWriter,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
        limits: TunResourceLimits,
    ) -> Self {
        let (response_tx, response_rx) = mpsc::channel(RESPONSE_CHANNEL_SIZE);
        let mut sessions = LruCache::unbounded();
        if let Some(limit) = limits.max_udp_sessions {
            sessions.resize(NonZeroUsize::new(limit).unwrap());
        }

        Self {
            reader,
            writer,
            sessions,
            proxy_selector,
            resolver,
            response_rx,
            response_tx,
            destination_slots: Arc::new(Budget::new(limits.max_udp_destinations)),
            destinations_per_session: limits.max_udp_destinations_per_session,
            queued_bytes: Arc::new(Budget::new(limits.max_udp_queued_bytes)),
            compact_payloads: limits.max_udp_queued_bytes.is_some(),
        }
    }

    /// Run the UDP manager until shutdown.
    pub async fn run(mut self) -> io::Result<()> {
        debug!("[TunUdpManager] Starting");

        let mut cleanup_interval = interval(Duration::from_secs(30));

        loop {
            tokio::select! {
                // Handle responses from destination tasks (write to TUN)
                Some((payload, src_addr, dst_addr)) = self.response_rx.recv() => {
                    debug!(
                        "[TunUdpManager] Response: {} -> {} ({} bytes)",
                        src_addr, dst_addr, payload.len()
                    );

                    if let Err(e) = self.writer.send_sync((payload, src_addr, dst_addr)) {
                        debug!("[TunUdpManager] Failed to write response to TUN: {}", e);
                    }
                }

                // Handle packets from TUN (route to sessions)
                packet = self.reader.next() => {
                    match packet {
                        Some((payload, local_addr, remote_addr)) => {
                            debug!(
                                "[TunUdpManager] Packet: {} -> {} ({} bytes)",
                                local_addr, remote_addr, payload.len()
                            );

                            self.handle_packet(local_addr, remote_addr, payload);
                        }
                        None => {
                            debug!("[TunUdpManager] TUN reader closed");
                            break;
                        }
                    }
                }

                // Periodic cleanup
                _ = cleanup_interval.tick() => {
                    self.cleanup_sessions();
                }
            }
        }

        debug!("[TunUdpManager] Stopping");
        Ok(())
    }

    /// Handle an incoming UDP packet from the TUN.
    ///
    /// Uses try_send to avoid blocking the manager event loop on a single
    /// overloaded session (prevents head-of-line blocking at the manager level).
    fn handle_packet(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        payload: PacketBuffer,
    ) {
        let Some(packet) =
            QueuedPacket::reserve(payload, &self.queued_bytes, self.compact_payloads)
        else {
            debug!("[TunUdpManager] UDP queued byte budget exhausted, dropping packet");
            return;
        };
        if let Some(session) = self.sessions.get_mut(&local_addr) {
            session.last_active = Instant::now();

            if !session.is_alive() {
                debug!(
                    "[TunUdpManager] Session for {} died, recreating",
                    local_addr
                );
                self.sessions.pop(&local_addr);
                self.create_session(local_addr);
            }
        } else {
            self.create_session(local_addr);
        }

        let session = self.sessions.get_mut(&local_addr).unwrap();
        match session.tx.try_send((remote_addr, packet)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                debug!(
                    "[TunUdpManager] Session queue full for {}, dropping packet",
                    local_addr
                );
            }
            Err(mpsc::error::TrySendError::Closed(pkt)) => {
                debug!(
                    "[TunUdpManager] Session for {} closed, recreating",
                    local_addr
                );
                self.sessions.pop(&local_addr);
                self.create_session(local_addr);
                // Retry once on the fresh session
                if let Some(session) = self.sessions.get_mut(&local_addr) {
                    let _ = session.tx.try_send(pkt);
                }
            }
        }
    }

    /// Create a new session for a local address.
    fn create_session(&mut self, peer_addr: SocketAddr) {
        debug!("[TunUdpManager] Creating session for {}", peer_addr);

        let (tx, rx) = mpsc::channel(CHANNEL_SIZE);

        let handle = tokio::spawn(session_task(
            peer_addr,
            rx,
            self.response_tx.clone(),
            self.proxy_selector.clone(),
            self.resolver.clone(),
            self.destination_slots.clone(),
            self.destinations_per_session,
        ));

        let session = Session {
            tx,
            handle,
            last_active: Instant::now(),
        };

        self.sessions.push(peer_addr, session);
    }

    /// Clean up expired and dead sessions.
    fn cleanup_sessions(&mut self) {
        let now = Instant::now();
        let expired: Vec<SocketAddr> = self
            .sessions
            .iter()
            .filter(|(_, session)| {
                !session.is_alive() || now.duration_since(session.last_active) > SESSION_TIMEOUT
            })
            .map(|(addr, _)| *addr)
            .collect();

        for addr in expired {
            debug!("[TunUdpManager] Removing expired session for {}", addr);
            self.sessions.pop(&addr);
        }
    }
}

/// Per-destination state tracked by the session task.
///
/// Aborts the destination task on drop, ensuring child tasks are cleaned
/// up in all exit paths: graceful shutdown, LRU eviction, abort cancellation.
struct DestinationEntry {
    /// Sends write requests to the destination task
    write_tx: mpsc::Sender<QueuedPacket>,
    /// Aborted on drop to terminate the destination task immediately
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for DestinationEntry {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Session task - handles UDP traffic for one local (app) address.
///
/// Routes outbound packets to per-destination tasks and lets those tasks
/// forward responses directly to the TUN manager. The select loop is fully
/// event-driven with no polling.
async fn session_task(
    peer_addr: SocketAddr,
    mut rx: mpsc::Receiver<(SocketAddr, QueuedPacket)>,
    response_tx: mpsc::Sender<UdpMessage>,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    destination_slots: Arc<Budget>,
    destinations_per_session: Option<usize>,
) {
    debug!("[TunUdpSession {}] Starting", peer_addr);

    let mut destinations: HashMap<NetLocation, DestinationEntry> = HashMap::new();
    let mut cleanup_interval = interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            packet = rx.recv() => {
                let Some((dest_addr, packet)) = packet else {
                    debug!("[TunUdpSession {}] Channel closed", peer_addr);
                    break;
                };

                let dest = socket_addr_to_net_location(dest_addr);

                // Remove dead destination entry so we recreate below
                if let Some(entry) = destinations.get(&dest)
                    && entry.handle.is_finished()
                {
                    debug!(
                        "[TunUdpSession {}] Destination task for {} died, recreating",
                        peer_addr, dest
                    );
                    destinations.remove(&dest);
                }

                if !destinations.contains_key(&dest) {
                    if destinations_per_session.is_some_and(|limit| destinations.len() >= limit) {
                        continue;
                    }
                    let Some(permit) = destination_slots.acquire(1) else {
                        continue;
                    };
                    let setup = tokio::time::timeout(
                        WRITE_TIMEOUT,
                        create_connection(&dest, &proxy_selector, &resolver),
                    )
                    .await
                    .unwrap_or_else(|_| {
                        Err(io::Error::new(io::ErrorKind::TimedOut, "TUN UDP setup timed out"))
                    });
                    let stream = match setup {
                        Ok(stream) => stream,
                        Err(e) => {
                            debug!(
                                "[TunUdpSession {}] Failed to connect to {}: {}",
                                peer_addr, dest, e
                            );
                            continue;
                        }
                    };
                    let Some(source_addr) = dest.to_socket_addr_nonblocking() else {
                        continue;
                    };

                    let (write_tx, write_rx) = mpsc::channel(CHANNEL_SIZE);
                    let handle = tokio::spawn(destination_task(
                        peer_addr,
                        source_addr,
                        stream,
                        write_rx,
                        response_tx.clone(),
                        permit,
                    ));

                    debug!(
                        "[TunUdpSession {}] Created destination task for {}",
                        peer_addr, dest
                    );
                    destinations.insert(dest.clone(), DestinationEntry { write_tx, handle });
                }

                // Forward payload to destination task. Uses try_send to avoid
                // blocking the session loop on a single slow destination.
                let entry = destinations.get(&dest).unwrap();
                match entry.write_tx.try_send(packet) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        debug!(
                            "[TunUdpSession {}] Destination queue full for {}, dropping packet",
                            peer_addr, dest
                        );
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        debug!(
                            "[TunUdpSession {}] Destination task for {} died on send",
                            peer_addr, dest
                        );
                        destinations.remove(&dest);
                    }
                }
            }

            // Remove entries whose tasks have exited (timeout, error, etc.)
            _ = cleanup_interval.tick() => {
                destinations.retain(|dest, entry| {
                    let alive = !entry.handle.is_finished();
                    if !alive {
                        debug!(
                            "[TunUdpSession {}] Removing finished destination {}",
                            peer_addr, dest
                        );
                    }
                    alive
                });
            }
        }
    }

    // `destinations` is dropped here, aborting all destination tasks via
    // DestinationEntry::Drop. This also fires when the session is
    // abort-cancelled, since tokio drops task locals on cancellation.
    debug!("[TunUdpSession {}] Stopping", peer_addr);
}

/// Per-destination task. Owns the proxy stream exclusively, handling both
/// reads (blocking) and writes (via channel). Self-terminates after
/// CONNECTION_TIMEOUT of inactivity. Sends responses directly to the
/// TUN manager, bypassing the session task.
async fn destination_task(
    peer_addr: SocketAddr,
    source_addr: SocketAddr,
    mut stream: Box<dyn AsyncMessageStream>,
    mut write_rx: mpsc::Receiver<QueuedPacket>,
    response_tx: mpsc::Sender<UdpMessage>,
    _permit: BudgetPermit,
) {
    let mut read_buf = vec![0u8; 65535];
    let sleep = tokio::time::sleep(CONNECTION_TIMEOUT);
    tokio::pin!(sleep);

    loop {
        let mut buf = ReadBuf::new(&mut read_buf);

        // All branches return an Action value, deferring stream/buf access
        // to after the select block where all future borrows are released.
        enum Action {
            Read(io::Result<()>),
            Write(Option<QueuedPacket>),
            Timeout,
        }

        let action = tokio::select! {
            result = std::future::poll_fn(|cx| {
                Pin::new(&mut *stream).poll_read_message(cx, &mut buf)
            }) => Action::Read(result),
            msg = write_rx.recv() => Action::Write(msg),
            _ = &mut sleep => Action::Timeout,
        };

        match action {
            Action::Read(Ok(())) => {
                let len = buf.filled().len();
                if len == 0 && stream.read_message_eof_on_empty() {
                    break;
                }
                sleep.as_mut().reset(Instant::now() + CONNECTION_TIMEOUT);

                debug!(
                    "[TunUdpSession {}] Response from {}: {} bytes",
                    peer_addr, source_addr, len
                );

                // (payload, src=remote, dst=local_app)
                if response_tx
                    .try_send((
                        PacketBuffer::copy_from_slice(buf.filled()),
                        source_addr,
                        peer_addr,
                    ))
                    .is_err()
                {
                    debug!(
                        "[TunUdpSession {}] Response channel full, dropping response from {}",
                        peer_addr, source_addr
                    );
                }
            }
            Action::Read(Err(e)) => {
                debug!(
                    "[TunUdpSession {}] Read error from {}: {}",
                    peer_addr, source_addr, e
                );
                break;
            }
            Action::Write(Some(packet)) => {
                sleep.as_mut().reset(Instant::now() + CONNECTION_TIMEOUT);

                match tokio::time::timeout(
                    WRITE_TIMEOUT,
                    send_message(&mut stream, &packet.payload),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        debug!(
                            "[TunUdpSession {}] Send error to {}: {}",
                            peer_addr, source_addr, e
                        );
                        break;
                    }
                    Err(_) => {
                        debug!(
                            "[TunUdpSession {}] Send timeout to {}",
                            peer_addr, source_addr
                        );
                        break;
                    }
                }
            }
            Action::Write(None) => break,
            Action::Timeout => {
                debug!(
                    "[TunUdpSession {}] Idle timeout for {}",
                    peer_addr, source_addr
                );
                break;
            }
        }
    }
}

/// Create a connection to a destination through the proxy chain.
async fn create_connection(
    dest: &NetLocation,
    proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
) -> io::Result<Box<dyn AsyncMessageStream>> {
    let decision = proxy_selector.judge(dest.into(), resolver).await?;

    match decision {
        ConnectDecision::Allow {
            chain_group,
            remote_location,
        } => {
            let stream = chain_group
                .connect_udp_bidirectional(resolver, remote_location)
                .await?;
            Ok(stream)
        }
        ConnectDecision::Block => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "destination blocked",
        )),
    }
}

/// Send a UDP message through a stream.
async fn send_message(stream: &mut Box<dyn AsyncMessageStream>, data: &[u8]) -> io::Result<()> {
    std::future::poll_fn(|cx| Pin::new(&mut **stream).poll_write_message(cx, data)).await?;
    std::future::poll_fn(|cx| Pin::new(&mut **stream).poll_flush_message(cx)).await?;
    Ok(())
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use crate::async_stream::{
        AsyncFlushMessage, AsyncPing, AsyncReadMessage, AsyncShutdownMessage, AsyncWriteMessage,
    };
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::task::{Context, Poll};

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
        fn poll_shutdown_message(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
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

    #[tokio::test(start_paused = true)]
    async fn packet_permit_survives_pending_flush_and_all_termination_paths() {
        for completion in ["success", "error", "timeout", "cancel"] {
            let budget = Arc::new(Budget::new(Some(6)));
            let slots = Arc::new(Budget::new(Some(1)));
            let state = Arc::new(FlushState::default());
            let (write_tx, write_rx) = mpsc::channel(1);
            let (response_tx, _response_rx) = mpsc::channel(1);
            let packet =
                QueuedPacket::reserve(PacketBuffer::copy_from_slice(b"packet"), &budget, true)
                    .unwrap();
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
        let packet = || {
            QueuedPacket::reserve(PacketBuffer::copy_from_slice(b"packet"), &budget, true).unwrap()
        };
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
        let budget = Arc::new(Budget::new(Some(640)));
        let (session_tx, mut session_rx) = mpsc::channel(CHANNEL_SIZE);
        let (destination_tx, destination_rx) = mpsc::channel(CHANNEL_SIZE);
        for _ in 0..64 {
            let packet =
                QueuedPacket::reserve(PacketBuffer::copy_from_slice(&[0; 10]), &budget, true)
                    .unwrap();
            assert!(session_tx.try_send(packet).is_ok());
        }
        assert_eq!(budget.available_permits(), 0);
        assert!(
            QueuedPacket::reserve(PacketBuffer::copy_from_slice(&[0]), &budget, true).is_none()
        );
        for _ in 0..64 {
            assert!(
                destination_tx
                    .try_send(session_rx.recv().await.unwrap())
                    .is_ok()
            );
        }
        assert_eq!(budget.available_permits(), 0);
        drop(destination_rx);
        assert_eq!(budget.available_permits(), 640);
        assert!(
            QueuedPacket::reserve(PacketBuffer::copy_from_slice(&[0; 641]), &budget, true)
                .is_none()
        );
        let empty =
            QueuedPacket::reserve(PacketBuffer::copy_from_slice(&[]), &budget, true).unwrap();
        assert_eq!(budget.available_permits(), 639);
        drop(empty);
        assert_eq!(budget.available_permits(), 640);
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
                        QueuedPacket::reserve(
                            PacketBuffer::copy_from_slice(payload),
                            &budget,
                            true
                        )
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
}
