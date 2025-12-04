//! TUN UDP Session Manager.
//!
//! This module provides session-based UDP handling for TUN devices.

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

/// Channel buffer size for session packets
const SESSION_CHANNEL_SIZE: usize = 64;

/// Per-destination connection timeout
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(120);

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
    /// Reader for packets from TUN
    reader: UdpReader,
    /// Writer for packets to TUN
    writer: UdpWriter,
    /// Sessions keyed by local (app) address
    sessions: LruCache<SocketAddr, Session>,
    /// Proxy selector for routing decisions
    proxy_selector: Arc<ClientProxySelector>,
    /// DNS resolver
    resolver: Arc<dyn Resolver>,
    /// Receiver for responses from sessions
    response_rx: mpsc::UnboundedReceiver<UdpMessage>,
    /// Sender cloned into each session for responses
    response_tx: mpsc::UnboundedSender<UdpMessage>,
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
    /// Check if the session is still alive
    fn is_alive(&self) -> bool {
        !self.handle.is_finished()
    }

    /// Send a packet through this session
    async fn send(&self, dest: SocketAddr, payload: Vec<u8>) -> io::Result<()> {
        self.tx
            .send((dest, payload))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "session closed"))
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
        let (response_tx, response_rx) = mpsc::unbounded_channel();

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
                biased;

                // Handle responses from sessions (write to TUN)
                Some((payload, src_addr, dst_addr)) = self.response_rx.recv() => {
                    debug!(
                        "[TunUdpManager] Response: {} -> {} ({} bytes)",
                        src_addr, dst_addr, payload.len()
                    );

                    // Build and send IP packet to TUN
                    // Note: src_addr is the remote server, dst_addr is the local app
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

                            if let Err(e) = self.handle_packet(local_addr, remote_addr, payload).await {
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
    async fn handle_packet(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        payload: Vec<u8>,
    ) -> io::Result<()> {
        // Get or create session for this local address
        let session = if let Some(session) = self.sessions.get_mut(&local_addr) {
            // Update last active time
            session.last_active = Instant::now();

            // Check if session task is still alive
            if !session.is_alive() {
                debug!(
                    "[TunUdpManager] Session for {} died, recreating",
                    local_addr
                );
                self.sessions.pop(&local_addr);
                self.create_session(local_addr)?;
                self.sessions.get_mut(&local_addr).unwrap()
            } else {
                session
            }
        } else {
            self.create_session(local_addr)?;
            self.sessions.get_mut(&local_addr).unwrap()
        };

        // Send packet through session
        session.send(remote_addr, payload).await
    }

    /// Create a new session for a local address.
    fn create_session(&mut self, peer_addr: SocketAddr) -> io::Result<()> {
        debug!("[TunUdpManager] Creating session for {}", peer_addr);

        let (tx, rx) = mpsc::channel(SESSION_CHANNEL_SIZE);

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

        self.sessions.put(peer_addr, session);
        Ok(())
    }

    /// Write a response packet to the TUN.
    fn write_to_tun(
        &mut self,
        payload: &[u8],
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
    ) -> io::Result<()> {
        use futures::SinkExt;

        // Build IP packet: src=remote_server, dst=local_app
        let message = (payload.to_vec(), src_addr, dst_addr);

        // Use blocking send since we're in an async context but
        // the UdpWriter is an unbounded channel
        futures::executor::block_on(async {
            Pin::new(&mut self.writer)
                .send(message)
                .await
                .map_err(io::Error::other)
        })
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

/// Per-destination connection state.
struct DestinationConn {
    remote: Box<dyn AsyncMessageStream>,
    last_active: Instant,
}

/// Session task - handles UDP traffic for one local (app) address.
///
/// Receives packets destined for various remote servers, routes each through
/// the appropriate proxy connection, and sends responses back to the peer.
async fn session_task(
    peer_addr: SocketAddr,
    mut rx: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    response_tx: mpsc::UnboundedSender<UdpMessage>,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) {
    debug!("[TunUdpSession {}] Starting", peer_addr);

    // Per-destination connections
    let mut connections: HashMap<NetLocation, DestinationConn> = HashMap::new();

    // Buffer for reading responses
    let mut read_buf = vec![0u8; 65535];

    // Cleanup interval for stale connections
    let mut cleanup_interval = interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            biased;

            // Receive outgoing packets
            packet = rx.recv() => {
                let Some((dest_addr, payload)) = packet else {
                    debug!("[TunUdpSession {}] Channel closed", peer_addr);
                    break;
                };

                let dest = socket_addr_to_net_location(dest_addr);

                // Get or create connection for this destination
                let conn = match connections.get_mut(&dest) {
                    Some(c) => {
                        c.last_active = Instant::now();
                        c
                    }
                    None => {
                        match create_connection(&dest, &proxy_selector, &resolver).await {
                            Ok(remote) => {
                                debug!(
                                    "[TunUdpSession {}] Created connection to {}",
                                    peer_addr, dest
                                );
                                connections.insert(
                                    dest.clone(),
                                    DestinationConn {
                                        remote,
                                        last_active: Instant::now(),
                                    },
                                );
                                connections.get_mut(&dest).unwrap()
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
                };

                // Send packet
                if let Err(e) = send_message(&mut conn.remote, &payload).await {
                    debug!(
                        "[TunUdpSession {}] Send error to {}: {}",
                        peer_addr, dest, e
                    );
                    connections.remove(&dest);
                }
            }

            // Poll connections for responses (round-robin to be fair)
            _ = poll_and_forward_responses(
                peer_addr,
                &mut connections,
                &mut read_buf,
                &response_tx,
            ) => {}

            // Cleanup stale connections
            _ = cleanup_interval.tick() => {
                let now = Instant::now();
                connections.retain(|dest, conn| {
                    let keep = now.duration_since(conn.last_active) < CONNECTION_TIMEOUT;
                    if !keep {
                        debug!(
                            "[TunUdpSession {}] Removing stale connection to {}",
                            peer_addr, dest
                        );
                    }
                    keep
                });
            }
        }
    }

    debug!("[TunUdpSession {}] Stopping", peer_addr);
}

/// Create a connection to a destination through the proxy chain.
async fn create_connection(
    dest: &NetLocation,
    proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
) -> io::Result<Box<dyn AsyncMessageStream>> {
    let decision = proxy_selector
        .judge_with_resolved_address(dest.clone(), None, resolver)
        .await?;

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
    // Poll-based write
    std::future::poll_fn(|cx| Pin::new(&mut **stream).poll_write_message(cx, data)).await?;

    // Flush
    std::future::poll_fn(|cx| Pin::new(&mut **stream).poll_flush_message(cx)).await?;

    Ok(())
}

/// Poll all connections for responses and forward to the response channel.
async fn poll_and_forward_responses(
    peer_addr: SocketAddr,
    connections: &mut HashMap<NetLocation, DestinationConn>,
    read_buf: &mut [u8],
    response_tx: &mpsc::UnboundedSender<UdpMessage>,
) {
    // Use tokio::select! to poll all connections
    // For simplicity, we do a quick non-blocking poll of each
    for (dest, conn) in connections.iter_mut() {
        let mut buf = ReadBuf::new(read_buf);

        let result =
            std::future::poll_fn(|cx| Pin::new(&mut *conn.remote).poll_read_message(cx, &mut buf));

        // Use a short timeout to avoid blocking
        match tokio::time::timeout(Duration::from_millis(1), result).await {
            Ok(Ok(())) => {
                let len = buf.filled().len();
                if len > 0 {
                    conn.last_active = Instant::now();

                    // Convert destination back to SocketAddr for the response
                    let source_addr = match dest.to_socket_addr_nonblocking() {
                        Some(addr) => addr,
                        None => continue, // Hostname - shouldn't happen for TUN
                    };

                    debug!(
                        "[TunUdpSession {}] Response from {}: {} bytes",
                        peer_addr, source_addr, len
                    );

                    // Send response: (payload, src=remote, dst=peer_addr)
                    // Uses stored peer_addr for correct response routing
                    let _ = response_tx.send((buf.filled().to_vec(), source_addr, peer_addr));
                }
            }
            Ok(Err(e)) => {
                debug!(
                    "[TunUdpSession {}] Read error from {}: {}",
                    peer_addr, dest, e
                );
            }
            Err(_) => {
                // Timeout - no data ready, continue
            }
        }
    }
}
