//! UDP Router - Per-destination routing for multi-destination UDP streams.
//!
//! This implementation uses:
//! - IndexMap with FxHasher for fast session storage with stable iteration order
//! - Separate buffer pools for outbound/inbound to prevent starvation
//! - Zero-copy queuing: read directly into pool buffer, queue if write pending
//! - DelayQueue for O(1) session expiry (no iteration)
//! - Work queues for pending writes/flushes/responses (no iteration over all sessions)

use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use indexmap::IndexMap;
use log::{debug, warn};
use lru::LruCache;
use rustc_hash::{FxBuildHasher, FxHashMap};
use tokio::io::ReadBuf;
use tokio::time::Instant;
use tokio_util::time::{DelayQueue, delay_queue};

use crate::address::{Address, NetLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncReadSessionMessage,
    AsyncReadTargetedMessage, AsyncSessionMessageStream, AsyncShutdownMessage,
    AsyncShutdownMessageExt, AsyncTargetedMessageStream, AsyncWriteMessage,
    AsyncWriteSessionMessage, AsyncWriteSourcedMessage,
};
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::resolver::{Resolver, resolve_single_address};
use crate::util::allocate_vec;

/// Timeout for inactive sessions
const SESSION_TIMEOUT_SECS: u64 = 200;

/// Maximum UDP packet size
const MAX_UDP_PACKET_SIZE: usize = 65535;

/// Maximum number of blocked destinations to remember (LRU eviction)
const MAX_BLOCKED_ENTRIES: usize = 80;

/// Buffer pool size for outbound (server → remote) - one per concurrent session
const REMOTE_WRITE_POOL_SIZE: usize = 8;

/// Buffer pool size for inbound (remote → server) - all go to same writer
const SERVER_WRITE_POOL_SIZE: usize = 8;

/// Max pending remote writes per session (prevents one slow session from starving others)
const MAX_PENDING_REMOTE_WRITES_PER_SESSION: usize = 4;

/// Max pending server writes per session (prevents one chatty session from starving others)
const MAX_PENDING_SERVER_WRITES_PER_SESSION: usize = 4;

/// Max concurrent session creation attempts (limits resource usage under burst)
const MAX_PENDING_CREATES: usize = 16;

/// How often to check if pings are needed
const PING_CHECK_INTERVAL: Duration = Duration::from_secs(15);

/// Ping streams that haven't had writes for this long
const PING_IDLE_THRESHOLD: Duration = Duration::from_secs(30);

/// Session identifier - incrementing counter, never reused
type SessionKey = usize;

/// Lazy buffer pool for backpressure management.
///
/// Buffers are created on-demand up to max_count, then reused.
/// Acquired buffers are either released immediately (if write succeeds)
/// or moved into a queue (zero-copy).
struct BufferPool {
    buffers: Vec<Box<[u8]>>,
    max_count: usize,
    created_count: usize,
}

impl BufferPool {
    fn new(max_count: usize) -> Self {
        Self {
            buffers: Vec::with_capacity(max_count),
            max_count,
            created_count: 0,
        }
    }

    #[inline]
    fn acquire(&mut self) -> Option<Box<[u8]>> {
        // Try to reuse existing buffer
        if let Some(buf) = self.buffers.pop() {
            return Some(buf);
        }

        // Create new if under limit
        if self.created_count < self.max_count {
            self.created_count += 1;
            Some(allocate_vec(MAX_UDP_PACKET_SIZE).into_boxed_slice())
        } else {
            None
        }
    }

    #[inline]
    fn release(&mut self, buf: Box<[u8]>) {
        self.buffers.push(buf);
    }

    #[inline]
    fn deallocate(&mut self) {
        let buffers = std::mem::take(&mut self.buffers);
        self.created_count -= buffers.len();
    }
}

/// State of a session key in the lookup map
enum KeyState {
    /// Session exists with this ID
    Active(SessionKey),
    /// Session creation in progress
    Pending,
}

/// How to look up the session for a packet
#[derive(Clone)]
enum LookupKey {
    /// For Targeted streams: use destination
    Destination(NetLocation),
    /// For SessionBased streams: use protocol session_id
    SessionId(u16),
}

/// Session lookup strategy - determined by server stream type
enum SessionLookup {
    /// For Targeted: destination -> KeyState
    ByDestination(FxHashMap<NetLocation, KeyState>),
    /// For SessionBased: session_id -> KeyState
    BySessionId(FxHashMap<u16, KeyState>),
}

/// A routing session (one per unique flow)
struct RoutingSession {
    /// The destination this session routes to
    destination: NetLocation,

    /// The session's session id if this is a session UDP stream
    session_id: u16,

    /// Resolved address for response source field
    resolved_addr: SocketAddr,

    /// The lookup key for this session (needed for removal from lookup map)
    lookup_key: LookupKey,

    /// The remote connection
    remote: Box<dyn AsyncMessageStream>,

    /// Count of pending writes in remote_write_queue for this session
    in_remote_write_queue: usize,

    /// Is there a pending flush?
    in_remote_flush_queue: bool,

    /// Count of pending responses in server_write_queue for this session
    in_server_write_queue: usize,

    /// Key for DelayQueue (to cancel/reset expiry timer)
    expiry_key: Option<delay_queue::Key>,

    /// Remote read returned EOF or error
    remote_read_eof: bool,

    /// Remote write returned error
    remote_write_eof: bool,

    /// Last time we wrote to the remote (for ping decisions)
    last_write: Instant,

    /// Last iteration when expiry was reset (to avoid redundant resets)
    last_expiry_iteration: usize,
}

impl RoutingSession {
    fn new(
        destination: NetLocation,
        session_id: u16,
        resolved_addr: SocketAddr,
        lookup_key: LookupKey,
        remote: Box<dyn AsyncMessageStream>,
    ) -> Self {
        Self {
            destination,
            session_id,
            resolved_addr,
            lookup_key,
            remote,
            in_remote_write_queue: 0,
            in_remote_flush_queue: false,
            in_server_write_queue: 0,
            expiry_key: None, // Set after insert when we have the SessionId
            remote_read_eof: false,
            remote_write_eof: false,
            last_write: Instant::now(),
            last_expiry_iteration: 0,
        }
    }

    /// Check if session should be removed.
    #[inline]
    fn should_remove(&self) -> bool {
        self.remote_read_eof && self.remote_write_eof
    }

    /// Reset session expiry timer (skips if already reset this iteration)
    #[inline]
    fn reset_expiry(
        &mut self,
        expiry_queue: &mut DelayQueue<SessionKey>,
        _id: SessionKey,
        iteration: usize,
    ) {
        if self.last_expiry_iteration == iteration {
            return; // Already reset this iteration
        }
        self.last_expiry_iteration = iteration;

        // Use reset() which is more efficient than remove() + insert()
        // as it reuses the same slab entry and key
        if let Some(ref key) = self.expiry_key {
            expiry_queue.reset(key, Duration::from_secs(SESSION_TIMEOUT_SECS));
        }
    }
}

/// A pending write waiting to be sent to remote
struct PendingWrite {
    id: SessionKey,
    buf: Box<[u8]>,
    len: usize,
}

/// Server stream variants - unified via enum
pub enum ServerStream {
    /// SOCKS5 UDP, Shadowsocks UoT, etc.
    Targeted(Box<dyn AsyncTargetedMessageStream>),
    /// XUDP (VLESS/VMess)
    Session(Box<dyn AsyncSessionMessageStream>),
}

impl ServerStream {
    fn poll_read_message(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<InboundPacket>> {
        match self {
            ServerStream::Targeted(stream) => {
                match Pin::new(stream).poll_read_targeted_message(cx, buf) {
                    Poll::Ready(Ok(dest)) => Poll::Ready(Ok(InboundPacket {
                        destination: dest,
                        session_id: 0,
                    })),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            }
            ServerStream::Session(stream) => {
                match Pin::new(stream).poll_read_session_message(cx, buf) {
                    Poll::Ready(Ok((session_id, addr))) => {
                        let address = match addr.ip() {
                            std::net::IpAddr::V4(v4) => Address::Ipv4(v4),
                            std::net::IpAddr::V6(v6) => Address::Ipv6(v6),
                        };
                        Poll::Ready(Ok(InboundPacket {
                            destination: NetLocation::new(address, addr.port()),
                            session_id,
                        }))
                    }
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn poll_write_message(
        &mut self,
        cx: &mut Context<'_>,
        data: &[u8],
        source: &SocketAddr,
        session_id: u16,
    ) -> Poll<io::Result<()>> {
        match self {
            ServerStream::Targeted(stream) => {
                Pin::new(stream).poll_write_sourced_message(cx, data, source)
            }
            ServerStream::Session(stream) => {
                Pin::new(stream).poll_write_session_message(cx, session_id, data, source)
            }
        }
    }

    fn supports_ping(&self) -> bool {
        match self {
            ServerStream::Targeted(stream) => stream.supports_ping(),
            ServerStream::Session(stream) => stream.supports_ping(),
        }
    }

    fn poll_write_ping(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        match self {
            ServerStream::Targeted(stream) => Pin::new(stream).poll_write_ping(cx),
            ServerStream::Session(stream) => Pin::new(stream).poll_write_ping(cx),
        }
    }

    fn poll_flush_message(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            ServerStream::Targeted(stream) => Pin::new(stream).poll_flush_message(cx),
            ServerStream::Session(stream) => Pin::new(stream).poll_flush_message(cx),
        }
    }

    async fn shutdown_message(&mut self) -> io::Result<()> {
        match self {
            ServerStream::Targeted(stream) => stream.shutdown_message().await,
            ServerStream::Session(stream) => stream.shutdown_message().await,
        }
    }
}

impl std::fmt::Debug for ServerStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerStream::Targeted(_) => f.debug_struct("Targeted").finish_non_exhaustive(),
            ServerStream::Session(_) => f.debug_struct("Session").finish_non_exhaustive(),
        }
    }
}

/// Packet info extracted from server stream
struct InboundPacket {
    destination: NetLocation,
    session_id: u16,
}

/// Result of session creation
struct SessionCreateResult {
    remote: Box<dyn AsyncMessageStream>,
    resolved_addr: SocketAddr,
}

/// Type alias for the session creation future
type SessionCreateFuture = Pin<Box<dyn Future<Output = io::Result<SessionCreateResult>> + Send>>;

/// Pending session creation state
struct PendingSessionCreate {
    lookup_key: LookupKey,
    destination: NetLocation,
    session_id: u16,
    initial_data: Vec<u8>,
    future: SessionCreateFuture,
}

/// The unified UDP router
pub struct UdpRouter<'a> {
    server: &'a mut ServerStream,
    /// Lookup: maps flow key -> session state
    session_lookup: SessionLookup,

    sessions: IndexMap<SessionKey, RoutingSession, FxBuildHasher>,
    next_session_id: SessionKey,
    /// Round-robin position for fair session polling
    session_poll_position: usize,
    /// Blocked destinations (LRU-bounded)
    blocked: LruCache<NetLocation, ()>,

    pending_creates: Vec<PendingSessionCreate>,

    remote_write_queue: VecDeque<PendingWrite>,
    remote_flush_queue: VecDeque<SessionKey>,
    server_write_queue: VecDeque<PendingWrite>,

    needs_server_flush: bool,

    server_read_eof: bool,
    server_write_eof: bool,

    sessions_to_remove: HashSet<SessionKey>,
    pending_shutdowns: VecDeque<Box<dyn AsyncMessageStream>>,

    remote_write_pool: BufferPool,
    server_write_pool: BufferPool,

    expiry_queue: DelayQueue<SessionKey>,
    ping_timer: tokio::time::Interval,
    expiry_iteration: usize,

    last_server_write: Instant,

    selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
}

impl<'a> UdpRouter<'a> {
    /// Create a new UDP router.
    pub fn new(
        server: &'a mut ServerStream,
        selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
        need_initial_flush: bool,
    ) -> Self {
        let session_lookup = match server {
            ServerStream::Targeted(_) => SessionLookup::ByDestination(FxHashMap::default()),
            ServerStream::Session(_) => SessionLookup::BySessionId(FxHashMap::default()),
        };

        Self {
            server,
            session_lookup,
            sessions: IndexMap::with_hasher(FxBuildHasher),
            next_session_id: 0,
            session_poll_position: 0,
            blocked: LruCache::new(NonZeroUsize::new(MAX_BLOCKED_ENTRIES).unwrap()),
            pending_creates: Vec::new(),
            remote_write_queue: VecDeque::with_capacity(REMOTE_WRITE_POOL_SIZE),
            remote_flush_queue: VecDeque::with_capacity(REMOTE_WRITE_POOL_SIZE),
            server_write_queue: VecDeque::with_capacity(SERVER_WRITE_POOL_SIZE),
            needs_server_flush: need_initial_flush,
            server_read_eof: false,
            server_write_eof: false,
            sessions_to_remove: HashSet::new(),
            pending_shutdowns: VecDeque::new(),
            remote_write_pool: BufferPool::new(REMOTE_WRITE_POOL_SIZE),
            server_write_pool: BufferPool::new(SERVER_WRITE_POOL_SIZE),
            expiry_queue: DelayQueue::new(),
            ping_timer: tokio::time::interval(PING_CHECK_INTERVAL),
            expiry_iteration: 0,
            last_server_write: Instant::now(),
            selector,
            resolver,
        }
    }

    /// Set server read EOF and clean up pending session creates.
    /// Called when server read returns an error or zero-length read.
    #[inline]
    fn set_server_read_eof(&mut self) {
        if self.server_read_eof {
            return;
        }

        self.server_read_eof = true;

        // Clean up pending creates - remove lookup entries and drop futures
        // TODO: is this correct? what if the user wanted to send a single packet and closed their
        // connection?
        for pending in self.pending_creates.drain(..) {
            match (&mut self.session_lookup, pending.lookup_key) {
                (SessionLookup::ByDestination(map), LookupKey::Destination(dest)) => {
                    map.remove(&dest);
                }
                (SessionLookup::BySessionId(map), LookupKey::SessionId(id)) => {
                    map.remove(&id);
                }
                _ => unreachable!(),
            }
            // Future and initial_data are dropped
        }
    }

    /// Set server write EOF and clean up server write queue.
    /// Called when server write or flush returns an error.
    #[inline]
    fn set_server_write_eof(&mut self) {
        if self.server_write_eof {
            return;
        }

        self.server_write_eof = true;
        self.needs_server_flush = false;

        // Return buffers to pool and clear queue.
        // We don't update session.in_server_write_queue counters here because:
        // 1. We're in shutdown mode - no more server writes will happen
        // 2. Sessions will be cleaned up through expiry anyway
        // 3. Avoids borrow conflicts when called from contexts that hold session refs
        for pending in self.server_write_queue.drain(..) {
            self.server_write_pool.release(pending.buf);
        }
        self.server_write_pool.deallocate();
    }

    /// Drain pending session shutdowns (best-effort, non-blocking)
    fn drain_remote_shutdowns(&mut self, cx: &mut Context<'_>) {
        let count = self.pending_shutdowns.len();
        for _ in 0..count {
            let mut stream = self.pending_shutdowns.pop_front().unwrap();
            if Pin::new(&mut stream).poll_shutdown_message(cx).is_pending() {
                self.pending_shutdowns.push_back(stream);
            }
            // If Ready (success or error), stream is dropped
        }
    }

    /// Read from server, route to sessions
    /// Returns (made_progress, exhausted) - exhausted only if read hit Pending, not pool exhaustion
    #[inline]
    fn poll_read_server(&mut self, cx: &mut Context<'_>) -> (bool, bool) {
        // Acquire buffer from outbound pool
        let Some(mut buf) = self.remote_write_pool.acquire() else {
            debug!("outbound pool exhausted, applying backpressure");
            return (false, false); // not exhausted, just pool-limited
        };

        let mut server_read_progress = false;
        let mut remote_writes_progress = false;

        loop {
            // Read packet from server directly into pool buffer
            let mut read_buf = ReadBuf::new(&mut buf);
            let packet = match self.server.poll_read_message(cx, &mut read_buf) {
                Poll::Ready(Ok(p)) => {
                    server_read_progress = true;
                    debug!(
                        "[UdpRouter] poll_read_server got packet: {} bytes to {}",
                        read_buf.filled().len(),
                        p.destination
                    );
                    p
                }
                Poll::Ready(Err(e)) => {
                    warn!("server read error: {}", e);
                    self.set_server_read_eof();
                    break;
                }
                Poll::Pending => {
                    break;
                }
            };

            let len = read_buf.filled().len();
            if len == 0 {
                self.set_server_read_eof();
                break;
            }

            // Look up session
            let key_state = match &self.session_lookup {
                SessionLookup::ByDestination(map) => map.get(&packet.destination),
                SessionLookup::BySessionId(map) => map.get(&packet.session_id),
            };

            match key_state {
                Some(KeyState::Active(id)) => {
                    let Some(session) = self.sessions.get_mut(id) else {
                        // session is gone, skip message
                        continue;
                    };

                    // Skip if remote write is EOF
                    if session.remote_write_eof {
                        continue;
                    }

                    // Skip if session has too many pending writes (backpressure)
                    if session.in_remote_write_queue >= MAX_PENDING_REMOTE_WRITES_PER_SESSION {
                        continue;
                    }

                    // Always try to write immediately
                    match Pin::new(&mut session.remote).poll_write_message(cx, &buf[..len]) {
                        Poll::Ready(Ok(())) => {
                            remote_writes_progress = true;

                            session.last_write = Instant::now();
                            session.reset_expiry(
                                &mut self.expiry_queue,
                                *id,
                                self.expiry_iteration,
                            );
                            if !session.in_remote_flush_queue {
                                session.in_remote_flush_queue = true;
                                self.remote_flush_queue.push_back(*id);
                            }
                        }
                        Poll::Pending => {
                            session.in_remote_write_queue += 1;
                            self.remote_write_queue
                                .push_back(PendingWrite { id: *id, buf, len });
                            let Some(new_buf) = self.remote_write_pool.acquire() else {
                                return (server_read_progress, remote_writes_progress);
                            };
                            buf = new_buf;
                        }
                        Poll::Ready(Err(e)) => {
                            warn!("remote write error: {}", e);
                            session.remote_write_eof = true;
                            if session.should_remove() {
                                self.sessions_to_remove.insert(*id);
                            }
                        }
                    }
                }
                Some(KeyState::Pending) => {
                    // Creation in progress - drop packet
                }
                None => {
                    // No session - check blocked before creating
                    if self.blocked.get(&packet.destination).is_some() {
                        debug!("UDP proxying blocked to {}", packet.destination);
                        continue;
                    }

                    if self.pending_creates.len() >= MAX_PENDING_CREATES {
                        debug!(
                            "Too many pending creates, dropping new session creation for {}",
                            packet.destination
                        );
                        continue;
                    }

                    self.start_session_creation(cx, packet, &buf[..len]);
                }
            }
        }

        self.remote_write_pool.release(buf);
        (server_read_progress, remote_writes_progress)
    }

    /// Drain pending writes to remotes
    #[inline]
    fn drain_remote_writes(&mut self, cx: &mut Context<'_>) -> bool {
        let queue_len = self.remote_write_queue.len();

        for _ in 0..queue_len {
            let PendingWrite { id, buf, len } = self.remote_write_queue.pop_front().unwrap();

            let Some(session) = self.sessions.get_mut(&id) else {
                // Session gone, release buffer
                self.remote_write_pool.release(buf);
                continue;
            };

            // If remote_write_eof, can't write - release buffer
            if session.remote_write_eof {
                session.in_remote_write_queue -= 1;
                self.remote_write_pool.release(buf);
                if session.should_remove() {
                    self.sessions_to_remove.insert(id);
                }
                continue;
            }

            let data = &buf[..len];

            match Pin::new(&mut session.remote).poll_write_message(cx, data) {
                Poll::Ready(Ok(())) => {
                    session.in_remote_write_queue -= 1;
                    session.last_write = Instant::now();
                    session.reset_expiry(&mut self.expiry_queue, id, self.expiry_iteration);
                    if !session.in_remote_flush_queue {
                        session.in_remote_flush_queue = true;
                        self.remote_flush_queue.push_back(id);
                    }
                    self.remote_write_pool.release(buf);
                }
                Poll::Pending => {
                    self.remote_write_queue
                        .push_back(PendingWrite { id, buf, len });
                }
                Poll::Ready(Err(e)) => {
                    warn!("remote write error: {}", e);
                    session.in_remote_write_queue -= 1;
                    self.remote_write_pool.release(buf);
                    session.remote_write_eof = true;
                    if session.should_remove() {
                        self.sessions_to_remove.insert(id);
                    }
                }
            }
        }

        self.remote_write_queue.len() < queue_len
    }

    /// Drain pending flushes
    #[inline]
    fn drain_remote_flushes(&mut self, cx: &mut Context<'_>) -> bool {
        let queue_len = self.remote_flush_queue.len();

        for _ in 0..queue_len {
            let id = self.remote_flush_queue.pop_front().unwrap();

            let Some(session) = self.sessions.get_mut(&id) else {
                continue;
            };

            if !session.in_remote_flush_queue {
                continue;
            }

            match Pin::new(&mut session.remote).poll_flush_message(cx) {
                Poll::Ready(Ok(())) => {
                    session.in_remote_flush_queue = false;
                }
                Poll::Pending => {
                    self.remote_flush_queue.push_back(id);
                }
                Poll::Ready(Err(_)) => {
                    session.in_remote_flush_queue = false;
                    session.remote_write_eof = true;
                    if session.should_remove() {
                        self.sessions_to_remove.insert(id);
                    }
                }
            }
        }

        self.remote_flush_queue.len() < queue_len
    }

    /// Read from remotes, write to server
    /// Returns (made_progress, write_success, exhausted) - exhausted only if reads hit Pending, not pool exhaustion
    #[inline]
    fn poll_read_remotes(&mut self, cx: &mut Context<'_>) -> (bool, bool) {
        // Acquire one buffer upfront - reused across sessions
        let Some(mut buf) = self.server_write_pool.acquire() else {
            debug!("inbound pool exhausted, applying backpressure");
            return (false, false); // pool-limited, not exhausted
        };

        let mut remote_read_progress = false;
        let mut server_write_progress = false;

        // Read from sessions, using round-robin for fairness
        let session_count = self.sessions.len();

        for i in 0..session_count {
            let idx = (self.session_poll_position + i) % session_count;
            let Some((&id, session)) = self.sessions.get_index_mut(idx) else {
                continue;
            };

            if session.remote_read_eof
                || session.in_server_write_queue >= MAX_PENDING_SERVER_WRITES_PER_SESSION
            {
                continue;
            }

            for _ in session.in_server_write_queue..MAX_PENDING_SERVER_WRITES_PER_SESSION {
                let mut read_buf = ReadBuf::new(&mut buf);

                match Pin::new(&mut session.remote).poll_read_message(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => {
                        let len = read_buf.filled().len();
                        debug!(
                            "[UdpRouter] Read {} bytes from session remote (session {})",
                            len, session.destination
                        );
                        if len == 0 {
                            session.remote_read_eof = true;
                            if session.should_remove() {
                                self.sessions_to_remove.insert(id);
                            }
                            break; // Stop bursting this session
                        }

                        remote_read_progress = true;
                        session.reset_expiry(&mut self.expiry_queue, id, self.expiry_iteration);

                        match self.server.poll_write_message(
                            cx,
                            &buf[..len],
                            &session.resolved_addr,
                            session.session_id,
                        ) {
                            Poll::Ready(Ok(())) => {
                                debug!(
                                    "[UdpRouter] Wrote {} bytes to server (to {})",
                                    len, session.resolved_addr
                                );
                                server_write_progress = true;
                                // Buffer consumed and free, reuse `buf` for next burst or session
                            }
                            Poll::Pending => {
                                debug!("[UdpRouter] Write to server pending");
                                session.in_server_write_queue += 1;
                                self.server_write_queue
                                    .push_back(PendingWrite { id, buf, len });

                                match self.server_write_pool.acquire() {
                                    Some(new_buf) => {
                                        buf = new_buf;
                                        // Queued a write, break burst to allow other sessions/draining
                                        break;
                                    }
                                    None => {
                                        // Pool exhausted, pool_limited = true but we return
                                        // immediately
                                        return (remote_read_progress, server_write_progress);
                                    }
                                }
                            }
                            Poll::Ready(Err(e)) => {
                                warn!("server write error: {}", e);
                                self.server_write_pool.release(buf); // release in-hand buffer
                                self.set_server_write_eof();
                                return (remote_read_progress, server_write_progress);
                            }
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        debug!("remote read error: {}", e);
                        session.remote_read_eof = true;
                        if session.should_remove() {
                            self.sessions_to_remove.insert(id);
                        }
                        break;
                    }
                    Poll::Pending => {
                        break;
                    }
                }
            }
        }

        // Advance position for fairness across poll calls
        if session_count > 0 {
            self.session_poll_position = (self.session_poll_position + 1) % session_count;
        }

        self.server_write_pool.release(buf);

        // exhausted only if we made no progress (all reads returned Pending)
        (remote_read_progress, server_write_progress)
    }

    /// Drain pending responses to server
    #[inline]
    fn drain_server_writes(&mut self, cx: &mut Context<'_>) -> bool {
        let mut server_write_progress = false;

        while let Some(pending) = self.server_write_queue.pop_front() {
            let PendingWrite { id, buf, len } = pending;

            let Some(session) = self.sessions.get_mut(&id) else {
                // Session gone, release buffer
                self.server_write_pool.release(buf);
                continue;
            };

            match self.server.poll_write_message(
                cx,
                &buf[..len],
                &session.resolved_addr,
                session.session_id,
            ) {
                Poll::Ready(Ok(())) => {
                    session.in_server_write_queue -= 1;
                    if session.should_remove() {
                        self.sessions_to_remove.insert(id);
                    }
                    server_write_progress = true;
                    self.server_write_pool.release(buf);
                }
                Poll::Pending => {
                    self.server_write_queue
                        .push_front(PendingWrite { id, buf, len });
                    break;
                }
                Poll::Ready(Err(e)) => {
                    warn!("server write error: {}", e);
                    session.in_server_write_queue -= 1; // last use of session borrow
                    self.server_write_pool.release(buf); // release current buffer
                    self.set_server_write_eof(); // clears remaining queue
                    break;
                }
            }
        }

        server_write_progress
    }

    /// Poll pending session creates
    #[inline]
    fn poll_pending_creates(&mut self, cx: &mut Context<'_>) -> bool {
        let mut made_progress = false;

        // Iterate backwards so swap_remove doesn't invalidate indices
        for i in (0..self.pending_creates.len()).rev() {
            made_progress |= self.poll_pending_create(cx, i);
        }

        made_progress
    }

    #[inline]
    fn poll_pending_create(&mut self, cx: &mut Context<'_>, i: usize) -> bool {
        let result = match self.pending_creates[i].future.as_mut().poll(cx) {
            Poll::Ready(result) => result,
            Poll::Pending => {
                return false;
            }
        };

        let pending = self.pending_creates.swap_remove(i);

        let PendingSessionCreate {
            lookup_key,
            destination,
            session_id,
            initial_data,
            future: _,
        } = pending;

        match result {
            Ok(SessionCreateResult {
                remote,
                resolved_addr,
            }) => {
                debug!(
                    "Session created for {} (resolved to {})",
                    destination, resolved_addr
                );

                let id = self.next_session_id;
                self.next_session_id += 1;

                // Update lookup map
                let pending_key_state = match (&mut self.session_lookup, &lookup_key) {
                    (SessionLookup::ByDestination(map), LookupKey::Destination(dest)) => {
                        map.insert(dest.clone(), KeyState::Active(id))
                    }
                    (SessionLookup::BySessionId(map), LookupKey::SessionId(sid)) => {
                        map.insert(*sid, KeyState::Active(id))
                    }
                    _ => unreachable!(),
                };
                debug_assert!(matches!(pending_key_state.unwrap(), KeyState::Pending));

                let mut session =
                    RoutingSession::new(destination, session_id, resolved_addr, lookup_key, remote);

                // TODO: part of constructor, we now know the id in advance
                let expiry_key = self
                    .expiry_queue
                    .insert(id, Duration::from_secs(SESSION_TIMEOUT_SECS));
                session.expiry_key = Some(expiry_key);

                // Try to write immediately
                if !initial_data.is_empty() {
                    debug!(
                        "Writing initial_data ({} bytes) to session for {}",
                        initial_data.len(),
                        session.destination
                    );
                    match Pin::new(&mut session.remote).poll_write_message(cx, &initial_data) {
                        Poll::Ready(Ok(())) => {
                            debug!("Initial data write succeeded, queueing flush");
                            session.last_write = Instant::now();
                            // Note: expiry was just set above when inserting into expiry_queue
                            if !session.in_remote_flush_queue {
                                session.in_remote_flush_queue = true;
                                self.remote_flush_queue.push_back(id);
                            }
                        }
                        Poll::Pending => {
                            debug!("Initial data write pending, queueing for later");
                            if let Some(mut buf) = self.remote_write_pool.acquire() {
                                let len = initial_data.len();
                                buf[..len].copy_from_slice(&initial_data);
                                session.in_remote_write_queue += 1;
                                self.remote_write_queue
                                    .push_back(PendingWrite { id, buf, len });
                            }
                        }
                        Poll::Ready(Err(e)) => {
                            warn!("remote write error: {}", e);
                            session.remote_write_eof = true;
                            if session.should_remove() {
                                self.sessions_to_remove.insert(id);
                            }
                        }
                    }
                }
                self.sessions.insert(id, session);
                true
            }
            Err(e) => {
                warn!("Failed to create session for {}: {}", destination, e);
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    // Mark as blocked
                    self.blocked.put(destination.clone(), ());
                }
                // Remove from pending in lookup
                match (&mut self.session_lookup, &lookup_key) {
                    (SessionLookup::ByDestination(map), LookupKey::Destination(dest)) => {
                        map.remove(dest);
                    }
                    (SessionLookup::BySessionId(map), LookupKey::SessionId(sid)) => {
                        map.remove(sid);
                    }
                    _ => unreachable!(),
                }
                false
            }
        }
    }

    /// Start session creation
    #[inline]
    fn start_session_creation(&mut self, cx: &mut Context<'_>, packet: InboundPacket, data: &[u8]) {
        let InboundPacket {
            destination,
            session_id,
        } = packet;

        let lookup_key = match &mut self.session_lookup {
            SessionLookup::ByDestination(map) => {
                map.insert(destination.clone(), KeyState::Pending);
                LookupKey::Destination(destination.clone())
            }
            SessionLookup::BySessionId(map) => {
                map.insert(packet.session_id, KeyState::Pending);
                LookupKey::SessionId(packet.session_id)
            }
        };

        debug!("Creating session for {}", destination);

        let initial_data = data.to_vec();
        let selector = Arc::clone(&self.selector);
        let resolver = Arc::clone(&self.resolver);
        let dest_for_future = destination.clone();

        let future: SessionCreateFuture = Box::pin(async move {
            let resolved_addr = resolve_single_address(&resolver, &dest_for_future).await?;
            let decision = selector
                .judge_with_resolved_address(dest_for_future, Some(resolved_addr), &resolver)
                .await?;

            match decision {
                ConnectDecision::Allow {
                    chain_group,
                    remote_location,
                } => {
                    let client_stream = chain_group
                        .connect_udp_bidirectional(&resolver, remote_location)
                        .await?;

                    Ok(SessionCreateResult {
                        remote: client_stream,
                        resolved_addr,
                    })
                }
                ConnectDecision::Block => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Destination blocked by routing rules",
                )),
            }
        });

        let index = self.pending_creates.len();
        self.pending_creates.push(PendingSessionCreate {
            lookup_key,
            destination,
            session_id,
            initial_data,
            future,
        });
        let _ = self.poll_pending_create(cx, index);
    }

    /// Remove a session (split-borrow friendly version)
    #[inline]
    fn remove_session(&mut self, id: SessionKey) {
        let Some(mut session) = self.sessions.swap_remove(&id) else {
            return;
        };

        debug!("Session removed: {}", session.destination);

        // Cancel expiry timer
        if let Some(key) = session.expiry_key.take() {
            self.expiry_queue.remove(&key);
        }

        // Remove from lookup map
        match (&mut self.session_lookup, session.lookup_key) {
            (SessionLookup::ByDestination(map), LookupKey::Destination(dest)) => {
                map.remove(&dest);
            }
            (SessionLookup::BySessionId(map), LookupKey::SessionId(sid)) => {
                map.remove(&sid);
            }
            _ => unreachable!(),
        }

        // Queue remote stream for graceful shutdown
        self.pending_shutdowns.push_back(session.remote);
    }

    /// Process expired sessions
    fn process_expired(&mut self, cx: &mut Context<'_>) {
        while let Poll::Ready(Some(expired)) = self.expiry_queue.poll_expired(cx) {
            let id = expired.into_inner();
            // Clear expiry_key since poll_expired already removed it from the queue
            if let Some(session) = self.sessions.get_mut(&id) {
                debug!("Session expired: {}", session.destination);
                session.expiry_key = None;
            }
            self.remove_session(id);
        }
    }

    /// Mark idle sessions for pinging
    fn write_server_ping(&mut self, cx: &mut Context<'_>) -> bool {
        let now = Instant::now();

        if self.server.supports_ping()
            && self.server_write_queue.is_empty()
            && now.duration_since(self.last_server_write) >= PING_IDLE_THRESHOLD
        {
            match self.server.poll_write_ping(cx) {
                Poll::Ready(Ok(_wrote_ping)) => {
                    // Reset regardless of if ping was written, if false, it means that the
                    // stream was already busy and it's unnecessary
                    debug!("Sent ping to server stream");
                    return true;
                }
                Poll::Ready(Err(e)) => {
                    debug!("server ping error: {}", e);
                    self.set_server_write_eof();
                }
                Poll::Pending => {
                    // Skip and wait for next ping interval
                }
            }
        }

        false
    }

    fn write_remote_pings(&mut self, cx: &mut Context<'_>) -> bool {
        let now = Instant::now();
        let mut made_progress = false;

        // Mark idle sessions for pinging
        for (&id, session) in &mut self.sessions {
            if session.remote.supports_ping()
                && session.in_remote_write_queue == 0
                && now.duration_since(session.last_write) >= PING_IDLE_THRESHOLD
            {
                // Try to send ping immediately
                match Pin::new(&mut session.remote).poll_write_ping(cx) {
                    Poll::Ready(Ok(_wrote_ping)) => {
                        debug!("Sent ping to {}", session.destination);
                        made_progress = true;
                        session.last_write = now;
                        if !session.in_remote_flush_queue {
                            session.in_remote_flush_queue = true;
                            self.remote_flush_queue.push_back(id);
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        debug!("remote ping error: {}", e);
                        session.remote_write_eof = true;
                        if session.should_remove() {
                            self.sessions_to_remove.insert(id);
                        }
                    }
                    Poll::Pending => {
                        // Skip and wait for next ping interval
                    }
                }
            }
        }

        made_progress
    }
}

impl<'a> Future for UdpRouter<'a> {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        this.expiry_iteration = this.expiry_iteration.wrapping_add(1);

        let ping_triggered = this.ping_timer.poll_tick(cx).is_ready();

        // Each direction runs independently to exhaustion.
        this.poll_outbound(cx, ping_triggered);
        this.poll_inbound(cx, ping_triggered);

        if !this.sessions_to_remove.is_empty() {
            let sessions_to_remove = std::mem::take(&mut this.sessions_to_remove);
            for id in sessions_to_remove {
                this.remove_session(id);
            }
        }
        this.process_expired(cx);

        this.drain_remote_shutdowns(cx);

        if this.server_read_eof && this.server_write_eof {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

impl UdpRouter<'_> {
    /// Poll outbound path: server -> remotes
    /// Runs until no progress (all operations pending or exhausted).
    #[inline]
    fn poll_outbound(&mut self, cx: &mut Context<'_>, ping_triggered: bool) {
        if !self.pending_creates.is_empty() {
            self.poll_pending_creates(cx);
        }

        loop {
            let mut server_read_progress = false;
            let mut remote_writes_progress = false;

            remote_writes_progress |= self.drain_remote_writes(cx);

            if ping_triggered {
                remote_writes_progress |= self.write_remote_pings(cx);
            }

            if !self.remote_flush_queue.is_empty() {
                remote_writes_progress |= self.drain_remote_flushes(cx);
            }

            // Read from server and route to remotes (if not EOF)
            if !self.server_read_eof {
                let (new_server_read_progress, new_remote_writes_progress) =
                    self.poll_read_server(cx);
                server_read_progress |= new_server_read_progress;
                remote_writes_progress |= new_remote_writes_progress;
            }

            if !server_read_progress && !remote_writes_progress {
                break;
            }

            // Cooperative yielding to prevent task starvation
            match tokio::task::coop::poll_proceed(cx) {
                Poll::Ready(coop) => coop.made_progress(),
                Poll::Pending => break,
            }
        }
    }

    /// Poll inbound path: remotes -> server
    /// Runs until no progress (all operations pending or exhausted).
    #[inline]
    fn poll_inbound(&mut self, cx: &mut Context<'_>, ping_triggered: bool) {
        loop {
            // Early exit if server write is EOF
            if self.server_write_eof {
                break;
            }

            let mut server_write_progress = false;

            // Drain pending writes to server
            server_write_progress |= self.drain_server_writes(cx);

            // Read from remotes and write to server
            let (remote_read_progress, new_server_write_progress) = self.poll_read_remotes(cx);
            server_write_progress |= new_server_write_progress;

            // Don't bother pinging if we wrote.
            if !server_write_progress && ping_triggered {
                server_write_progress |= self.write_server_ping(cx);
            }

            if server_write_progress {
                self.needs_server_flush = true;
                self.last_server_write = Instant::now();
            }

            if self.needs_server_flush {
                match self.server.poll_flush_message(cx) {
                    Poll::Ready(Ok(())) => {
                        self.needs_server_flush = false;
                        // this counts as server write progress since we can now retry writes
                        server_write_progress = true;
                    }
                    Poll::Ready(Err(e)) => {
                        warn!("server flush error: {}", e);
                        self.set_server_write_eof();
                    }
                    Poll::Pending => {}
                }
            }

            if !server_write_progress && !remote_read_progress {
                break;
            }

            // Cooperative yielding to prevent task starvation
            match tokio::task::coop::poll_proceed(cx) {
                Poll::Ready(coop) => coop.made_progress(),
                Poll::Pending => break,
            }
        }
    }
}

/// Run per-destination routing for any server UDP stream type.
pub async fn run_udp_routing(
    mut server: ServerStream,
    selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    need_initial_flush: bool,
) -> io::Result<()> {
    let result = UdpRouter::new(&mut server, selector, resolver, need_initial_flush).await;
    let _ = server.shutdown_message().await;
    result
}
