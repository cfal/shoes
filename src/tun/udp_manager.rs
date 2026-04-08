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
use crate::resolver::Resolver;

use super::udp_handler::{UdpMessage, UdpReader, UdpWriter};

/// Session timeout - sessions without activity are expired
const SESSION_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum number of sessions (LRU eviction when exceeded)
const MAX_SESSIONS: usize = 256;

/// Channel buffer size for session and destination packets
const CHANNEL_SIZE: usize = 64;

/// Response channel buffer size. Bounds memory growth when destination
/// tasks produce responses faster than the manager can write to TUN.
const RESPONSE_CHANNEL_SIZE: usize = 512;

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
}

/// A UDP session for a single local (app) address.
struct Session {
    /// Channel to send outgoing packets to the session task
    tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
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

impl TunUdpManager {
    /// Create a new TUN UDP manager.
    pub fn new(
        reader: UdpReader,
        writer: UdpWriter,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        let (response_tx, response_rx) = mpsc::channel(RESPONSE_CHANNEL_SIZE);

        Self {
            reader,
            writer,
            sessions: LruCache::new(NonZeroUsize::new(MAX_SESSIONS).unwrap()),
            proxy_selector,
            resolver,
            response_rx,
            response_tx,
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

                    if let Err(e) = self.write_to_tun(&payload, src_addr, dst_addr) {
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

                            if let Err(e) = self.handle_packet(local_addr, remote_addr, payload) {
                                debug!("[TunUdpManager] Failed to handle packet: {}", e);
                            }
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
        payload: Vec<u8>,
    ) -> io::Result<()> {
        if let Some(session) = self.sessions.get_mut(&local_addr) {
            session.last_active = Instant::now();

            if !session.is_alive() {
                debug!(
                    "[TunUdpManager] Session for {} died, recreating",
                    local_addr
                );
                self.sessions.pop(&local_addr);
                self.create_session(local_addr)?;
            }
        } else {
            self.create_session(local_addr)?;
        }

        let session = self.sessions.get_mut(&local_addr).unwrap();
        match session.tx.try_send((remote_addr, payload)) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                debug!(
                    "[TunUdpManager] Session queue full for {}, dropping packet",
                    local_addr
                );
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(pkt)) => {
                debug!(
                    "[TunUdpManager] Session for {} closed, recreating",
                    local_addr
                );
                self.sessions.pop(&local_addr);
                self.create_session(local_addr)?;
                // Retry once on the fresh session
                if let Some(session) = self.sessions.get_mut(&local_addr) {
                    let _ = session.tx.try_send(pkt);
                }
                Ok(())
            }
        }
    }

    /// Create a new session for a local address.
    fn create_session(&mut self, peer_addr: SocketAddr) -> io::Result<()> {
        debug!("[TunUdpManager] Creating session for {}", peer_addr);

        let (tx, rx) = mpsc::channel(CHANNEL_SIZE);

        let handle = tokio::spawn(session_task(
            peer_addr,
            rx,
            self.response_tx.clone(),
            self.proxy_selector.clone(),
            self.resolver.clone(),
        ));

        let session = Session {
            tx,
            handle,
            last_active: Instant::now(),
        };

        // If LRU insertion evicts an old session, abort its task to avoid
        // detached background loops accumulating over time.
        if let Some(evicted_session) = self.sessions.put(peer_addr, session) {
            evicted_session.handle.abort();
        }
        Ok(())
    }

    /// Write a response packet to the TUN.
    fn write_to_tun(
        &mut self,
        payload: &[u8],
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
    ) -> io::Result<()> {
        let message = (payload.to_vec(), src_addr, dst_addr);
        self.writer.send_sync(message)
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
            if let Some(session) = self.sessions.pop(&addr) {
                session.handle.abort();
            }
        }
    }
}

/// Per-destination state tracked by the session task.
///
/// Aborts the destination task on drop, ensuring child tasks are cleaned
/// up in all exit paths: graceful shutdown, LRU eviction, abort cancellation.
struct DestinationEntry {
    /// Sends write requests to the destination task
    write_tx: mpsc::Sender<Vec<u8>>,
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
    mut rx: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    response_tx: mpsc::Sender<UdpMessage>,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) {
    debug!("[TunUdpSession {}] Starting", peer_addr);

    let mut destinations: HashMap<NetLocation, DestinationEntry> = HashMap::new();
    let mut cleanup_interval = interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            packet = rx.recv() => {
                let Some((dest_addr, payload)) = packet else {
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

                // Create destination task if absent
                if !destinations.contains_key(&dest) {
                    match create_connection(&dest, &proxy_selector, &resolver).await {
                        Ok(stream) => {
                            let source_addr = match dest.to_socket_addr_nonblocking() {
                                Some(addr) => addr,
                                None => continue,
                            };

                            let (write_tx, write_rx) = mpsc::channel(CHANNEL_SIZE);
                            let handle = tokio::spawn(destination_task(
                                peer_addr,
                                source_addr,
                                stream,
                                write_rx,
                                response_tx.clone(),
                            ));

                            debug!(
                                "[TunUdpSession {}] Created destination task for {}",
                                peer_addr, dest
                            );
                            destinations.insert(dest.clone(), DestinationEntry { write_tx, handle });
                        }
                        Err(e) => {
                            debug!(
                                "[TunUdpSession {}] Failed to connect to {}: {}",
                                peer_addr, dest, e
                            );
                            continue;
                        }
                    }
                }

                // Forward payload to destination task. Uses try_send to avoid
                // blocking the session loop on a single slow destination.
                let entry = destinations.get(&dest).unwrap();
                match entry.write_tx.try_send(payload) {
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
    mut write_rx: mpsc::Receiver<Vec<u8>>,
    response_tx: mpsc::Sender<UdpMessage>,
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
            Write(Option<Vec<u8>>),
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
                if len == 0 {
                    break;
                }
                sleep.as_mut().reset(Instant::now() + CONNECTION_TIMEOUT);

                debug!(
                    "[TunUdpSession {}] Response from {}: {} bytes",
                    peer_addr, source_addr, len
                );

                // (payload, src=remote, dst=local_app)
                if response_tx
                    .try_send((buf.filled().to_vec(), source_addr, peer_addr))
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
            Action::Write(Some(payload)) => {
                sleep.as_mut().reset(Instant::now() + CONNECTION_TIMEOUT);

                match tokio::time::timeout(WRITE_TIMEOUT, send_message(&mut stream, &payload)).await
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
