//! Direct TCP Stack Manager for smoltcp integration.
//!
//! This module manages the smoltcp TCP/IP stack in a dedicated OS thread,
//! using `select()` on the TUN fd for event-driven I/O instead of polling.

use std::{
    cell::RefCell,
    collections::HashMap,
    io, mem,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    os::unix::io::RawFd,
    panic::{self, AssertUnwindSafe},
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle, Thread},
    time::Duration,
};

use bytes::BytesMut;

use log::{debug, error, info, trace, warn};
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp::{
        CongestionControl, Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState,
    },
    time::{Duration as SmolDuration, Instant as SmolInstant},
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address,
        Ipv6Packet, TcpPacket,
    },
};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use super::tcp_conn::{TcpConnection, TcpConnectionControl, TcpSocketState};

pub type PacketBuffer = Vec<u8>;

/// Maximum number of read buffers cached globally.
///
/// Each holds one MTU plus the four-byte packet-information header, so the pool
/// retains 64 * (mtu + 4): about 576 KiB at Android's 9000-byte default and
/// 260 KiB at iOS's 4064. It is cleared when a tunnel stops, since a mobile app
/// outlives its tunnel and has no use for the memory in between.
const BUFFER_POOL_MAX_SIZE: usize = 64;

static BUFFER_POOL: LazyLock<Mutex<Vec<BytesMut>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// Pooled buffer that returns to pool on drop instead of deallocating.
pub struct PooledBuffer {
    buffer: BytesMut,
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Ok(mut pool) = BUFFER_POOL.lock()
            && pool.len() < BUFFER_POOL_MAX_SIZE
        {
            let empty = BytesMut::new();
            let mut buffer = mem::replace(&mut self.buffer, empty);
            buffer.clear();
            pool.push(buffer);
        }
    }
}

/// Drop every buffer the pool is holding.
///
/// Called when a tunnel stops. The pool exists to keep the read path from
/// allocating per packet, which is worth a few hundred kilobytes while a tunnel
/// runs and nothing at all once it has stopped.
pub fn clear_buffer_pool() {
    if let Ok(mut pool) = BUFFER_POOL.lock() {
        pool.clear();
        pool.shrink_to_fit();
    }
}

impl PooledBuffer {
    /// Get a buffer from the pool or create a new one.
    pub fn with_capacity(cap: usize) -> Self {
        if let Ok(mut pool) = BUFFER_POOL.lock()
            && let Some(mut buffer) = pool.pop()
        {
            buffer.reserve(cap);
            return Self { buffer };
        }
        Self {
            buffer: BytesMut::with_capacity(cap),
        }
    }
}

impl Deref for PooledBuffer {
    type Target = BytesMut;

    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

impl DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer
    }
}

/// Tracks socket info including addresses for proper cleanup.
struct SocketInfo {
    control: Arc<TcpConnectionControl>,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
}

/// Information about a new TCP connection from the stack.
pub struct NewTcpConnection {
    pub connection: TcpConnection,
    pub remote_addr: SocketAddr,
}

/// Shared state for communication between main thread and stack thread.
struct SharedState {
    /// Channel for UDP responses to write to TUN
    udp_response_rx: Option<UnboundedReceiver<PacketBuffer>>,
    /// Channel for notifying tokio about new TCP connections
    new_conn_tx: Option<UnboundedSender<NewTcpConnection>>,
}

/// Direct TCP Stack Manager.
///
/// Manages the smoltcp interface with direct fd access for efficient I/O.
pub struct TcpStackDirect {
    /// Handle to the stack thread
    thread_handle: Option<JoinHandle<()>>,
    /// Thread handle for waking the stack thread
    stack_thread: Thread,
    /// Flag to signal thread shutdown
    running: Arc<AtomicBool>,
    /// Receiver for UDP packets (filtered from TUN by the stack thread)
    udp_rx: Option<UnboundedReceiver<PacketBuffer>>,
    /// Shared state with the stack thread
    shared_state: Arc<Mutex<SharedState>>,
    /// TUN file descriptor.
    tun_fd: RawFd,
    /// Whether `tun_fd` belongs to us. False when the platform owns it — on
    /// mobile the app opens the device and closing its descriptor here would
    /// be a double close once the app closes it too, which on a busy process
    /// means closing whatever unrelated socket has since taken the number.
    close_fd_on_drop: bool,
    /// Write end of the pipe that wakes the stack thread out of `poll()`.
    wake_tx: RawFd,
    /// Read end, closed here once the thread that reads it has exited.
    wake_rx: RawFd,
}

impl Drop for TcpStackDirect {
    fn drop(&mut self) {
        // Signal thread to stop
        self.running.store(false, Ordering::Relaxed);
        self.stack_thread.unpark();

        // The thread spends its idle time blocked in poll(), which unpark does
        // not interrupt. Without this byte it would not look at `running` again
        // until the next packet arrived, so shutting down a quiet tunnel — a
        // phone with the screen off, most of the time — would block here until
        // something happened to arrive. The join below is what guarantees the
        // TUN descriptor has been let go, so it cannot simply be skipped.
        let wake = [0u8; 1];
        unsafe {
            libc::write(self.wake_tx, wake.as_ptr() as *const libc::c_void, 1);
        }

        // Wait for thread to finish
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }

        unsafe {
            libc::close(self.wake_tx);
            libc::close(self.wake_rx);
        }

        if self.close_fd_on_drop {
            unsafe {
                libc::close(self.tun_fd);
            }
        }
    }
}

impl TcpStackDirect {
    /// Create a new direct TCP stack.
    ///
    /// # Arguments
    /// * `fd` - Raw file descriptor for the TUN device
    /// * `options` - MTU, per-connection buffer size, connection cap, and
    ///   whether the descriptor is ours to close
    ///
    /// This spawns a dedicated OS thread for running the smoltcp interface.
    /// The thread uses `select()` on the fd for efficient event-driven I/O.
    pub fn new(fd: RawFd, options: TcpStackOptions) -> Self {
        let (udp_tx, udp_rx) = mpsc::unbounded_channel();

        // A shutdown that the stack thread can see while it is asleep. Both
        // ends stay open for the life of the stack; the thread only ever reads,
        // and Drop only ever writes.
        let (wake_rx, wake_tx) = match new_wake_pipe() {
            Ok(pipe) => pipe,
            Err(e) => {
                // -1 reads as "no wake fd" in the poll below, which costs a
                // shutdown that waits for the next packet rather than one that
                // returns immediately. Not worth refusing to start over.
                error!("Failed to create the stack wake pipe: {e}");
                (-1, -1)
            }
        };

        let running = Arc::new(AtomicBool::new(true));
        let shared_state = Arc::new(Mutex::new(SharedState {
            udp_response_rx: None,
            new_conn_tx: None,
        }));

        let thread_handle = {
            let running = running.clone();
            let shared_state = shared_state.clone();

            thread::Builder::new()
                .name("shoes-smoltcp-direct".to_owned())
                .spawn(move || {
                    let result = panic::catch_unwind(AssertUnwindSafe(|| {
                        run_direct_stack_thread(
                            fd,
                            wake_rx,
                            options,
                            udp_tx,
                            running.clone(),
                            shared_state,
                        );
                    }));

                    match result {
                        Ok(()) => {
                            info!("smoltcp direct stack thread exited normally");
                        }
                        Err(panic_info) => {
                            let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                                s.to_string()
                            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                                s.clone()
                            } else {
                                "Unknown panic".to_string()
                            };
                            error!("smoltcp direct stack thread PANICKED: {}", msg);
                        }
                    }

                    running.store(false, Ordering::Relaxed);
                })
                .expect("failed to spawn smoltcp direct thread")
        };

        let stack_thread = thread_handle.thread().clone();

        Self {
            thread_handle: Some(thread_handle),
            stack_thread,
            running,
            udp_rx: Some(udp_rx),
            shared_state,
            tun_fd: fd,
            close_fd_on_drop: options.close_fd_on_drop,
            wake_tx,
            wake_rx,
        }
    }

    /// Take the receiver for UDP packets (filtered from TUN by the stack).
    pub fn take_udp_rx(&mut self) -> Option<UnboundedReceiver<PacketBuffer>> {
        self.udp_rx.take()
    }

    /// Set the channel for UDP responses to write back to TUN.
    pub fn set_udp_response_tx(&mut self, rx: UnboundedReceiver<PacketBuffer>) {
        if let Ok(mut state) = self.shared_state.lock() {
            state.udp_response_rx = Some(rx);
        }
        self.stack_thread.unpark();
    }

    /// Set the channel for notifying about new TCP connections.
    pub fn set_new_conn_tx(&mut self, tx: UnboundedSender<NewTcpConnection>) {
        if let Ok(mut state) = self.shared_state.lock() {
            state.new_conn_tx = Some(tx);
        }
        self.stack_thread.unpark();
    }

    /// Check if the stack thread is still running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
}

/// Direct TUN device that reads/writes directly to fd.
struct DirectDevice {
    fd: RawFd,
    mtu: usize,
    pending_rx: Option<PooledBuffer>,
}

impl DirectDevice {
    fn new(fd: RawFd, mtu: usize) -> Self {
        Self {
            fd,
            mtu,
            pending_rx: None,
        }
    }

    /// Try to read a packet (non-blocking) using pooled buffer.
    /// Returns:
    /// - Ok(Some(packet)) if a packet was read
    /// - Ok(None) if no packet was available (WouldBlock)
    /// - Err(e) if a fatal error occurred (including EOF)
    fn try_recv(&mut self) -> io::Result<Option<PooledBuffer>> {
        if let Some(pkt) = self.pending_rx.take() {
            return Ok(Some(pkt));
        }

        // Get a buffer from the pool
        let mut buffer = PooledBuffer::with_capacity(self.mtu + 4);
        buffer.resize(self.mtu + 4, 0);

        match read_nonblocking(self.fd, &mut buffer) {
            Ok(n) if n > 0 => {
                buffer.truncate(n);
                Ok(Some(buffer))
            }
            Ok(_) => {
                // n == 0 means EOF
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TUN device closed (EOF)",
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // Buffer is returned to pool when dropped
                Ok(None)
            }
            Err(e) => {
                // Fatal error
                Err(e)
            }
        }
    }

    /// Store a packet for later processing by smoltcp.
    fn store_packet(&mut self, pkt: PooledBuffer) {
        self.pending_rx = Some(pkt);
    }

    /// Write a packet to TUN.
    fn write_packet(&self, data: &[u8]) -> io::Result<()> {
        write_all(self.fd, data)
    }
}

impl Device for DirectDevice {
    type RxToken<'a> = DirectRxToken;
    type TxToken<'a> = DirectTxToken;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(buffer) = self.pending_rx.take() {
            let rx = DirectRxToken { buffer };
            let tx = DirectTxToken { fd: self.fd };
            Some((rx, tx))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(DirectTxToken { fd: self.fd })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.checksum.ipv4 = smoltcp::phy::Checksum::Tx;
        caps.checksum.tcp = smoltcp::phy::Checksum::Tx;
        caps.checksum.udp = smoltcp::phy::Checksum::Tx;
        caps.checksum.icmpv4 = smoltcp::phy::Checksum::Tx;
        caps.checksum.icmpv6 = smoltcp::phy::Checksum::Tx;
        caps
    }
}

struct DirectRxToken {
    buffer: PooledBuffer,
}

impl RxToken for DirectRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
        // buffer is returned to pool when dropped
    }
}

struct DirectTxToken {
    fd: RawFd,
}

thread_local! {
    /// Scratch for the packet currently being written to the TUN.
    ///
    /// Every segment and every ACK the stack sends passes through here, so a
    /// fresh `vec![0u8; len]` per packet was an allocation per packet on the
    /// busiest path in the process. The token is consumed synchronously on the
    /// stack thread and the buffer does not outlive the call, so one buffer per
    /// thread is enough.
    static TX_SCRATCH: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

impl TxToken for DirectTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let fd = self.fd;
        let write = |buffer: &mut Vec<u8>| {
            buffer.clear();
            buffer.resize(len, 0);
            let result = f(buffer);

            if let Err(e) = write_all(fd, buffer) {
                warn!("Failed to write to TUN: {}", e);
            }

            result
        };

        TX_SCRATCH.with(|scratch| match scratch.try_borrow_mut() {
            Ok(mut buffer) => write(&mut buffer),
            // Unreachable as smoltcp uses it — a token is consumed before the
            // next one is handed out — but borrowing rather than assuming keeps
            // a future caller from turning a nested consume into a panic.
            Err(_) => write(&mut Vec::new()),
        })
    }
}

const MAX_PACKET_BATCH: usize = 64; // Process more packets per poll iteration

/// How the stack thread is sized and who owns its descriptor.
#[derive(Clone, Copy, Debug)]
pub struct TcpStackOptions {
    /// Maximum transmission unit of the TUN device.
    pub mtu: usize,
    /// Bytes per direction, per connection. Four buffers of this size are
    /// allocated when a connection is accepted: two smoltcp socket buffers and
    /// the two ring buffers in `TcpConnectionControl`.
    pub tcp_buffer_size: usize,
    /// Connections the stack will hold before it starts dropping SYNs.
    pub max_connections: usize,
    /// Whether the TUN descriptor is ours to close.
    pub close_fd_on_drop: bool,
}

/// Create the shutdown wake pipe, returning (read end, write end).
fn new_wake_pipe() -> io::Result<(RawFd, RawFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a two-element array, which is what pipe() writes.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }

    for fd in fds {
        // Nonblocking so that neither end can stall: a wake write must not
        // block Drop, and the read that drains it must not block the loop.
        // SAFETY: both descriptors were just returned by pipe().
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL, 0);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }

    Ok((fds[0], fds[1]))
}

/// Longest this thread sleeps with nothing to do.
///
/// A descriptor closed underneath a blocked `poll()` does not wake it — the
/// platform is under no obligation to, and macOS does not — so an idle stack
/// on a device whose TUN was torn down would sit there until a packet that is
/// never coming arrives. One wakeup a second bounds that, and is nothing
/// against what a tunnel does when it is carrying anything at all.
const MAX_POLL_WAIT_MILLIS: u64 = 1000;

/// Sleep until the TUN device is readable, the wake pipe fires, or `duration`
/// elapses. `None` waits [`MAX_POLL_WAIT_MILLIS`]; a negative `wake_fd` is
/// ignored.
///
/// poll() rather than select(): select's `fd_set` cannot hold a descriptor
/// numbered above `FD_SETSIZE`, and a VPN process with a thousand connections
/// open reaches those numbers.
fn wait_readable(fd: RawFd, wake_fd: RawFd, duration: Option<SmolDuration>) -> io::Result<()> {
    let mut fds = [
        libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: wake_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    let count = if wake_fd >= 0 { 2 } else { 1 };
    let timeout = duration
        .map(|d| d.total_millis())
        .unwrap_or(MAX_POLL_WAIT_MILLIS)
        .min(MAX_POLL_WAIT_MILLIS) as libc::c_int;

    // SAFETY: `fds` holds `count` initialised pollfds for the call's duration.
    let result = unsafe { libc::poll(fds.as_mut_ptr(), count, timeout) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    // POLLNVAL means the descriptor is closed, which poll reports without
    // setting errno. Turned into an error so the backstop counter sees it
    // rather than spinning on an instant return.
    if fds[0].revents & libc::POLLNVAL != 0 {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }

    Ok(())
}

/// Run the direct smoltcp stack thread.
fn run_direct_stack_thread(
    fd: RawFd,
    wake_fd: RawFd,
    options: TcpStackOptions,
    udp_tx: UnboundedSender<PacketBuffer>,
    running: Arc<AtomicBool>,
    shared_state: Arc<Mutex<SharedState>>,
) {
    info!("smoltcp direct stack thread initializing...");

    let TcpStackOptions {
        mtu,
        tcp_buffer_size,
        max_connections,
        ..
    } = options;

    // Sets fd to non-blocking mode once at startup for performance.
    if let Err(e) = set_nonblocking(fd) {
        error!("Failed to set TUN fd to non-blocking: {}", e);
        return;
    }

    let mut device = DirectDevice::new(fd, mtu);

    let mut iface_config = InterfaceConfig::new(HardwareAddress::Ip);
    iface_config.random_seed = rand::random();

    let mut iface = Interface::new(iface_config, &mut device, SmolInstant::now());

    iface.update_ip_addrs(|addrs| {
        if let Err(e) = addrs.push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0)) {
            warn!("Failed to add IPv4 address: {:?}", e);
        }
        if let Err(e) = addrs.push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 0)) {
            warn!("Failed to add IPv6 address: {:?}", e);
        }
    });

    if let Err(e) = iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
    {
        warn!("Failed to add IPv4 route: {:?}", e);
    }
    if let Err(e) = iface
        .routes_mut()
        .add_default_ipv6_route(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1))
    {
        warn!("Failed to add IPv6 route: {:?}", e);
    }

    iface.set_any_ip(true);

    let mut socket_set = SocketSet::new(vec![]);
    let mut sockets: HashMap<SocketHandle, SocketInfo> = HashMap::new();
    let mut active_connections: std::collections::HashSet<(SocketAddr, SocketAddr)> =
        std::collections::HashSet::new();

    let mut poll_count: u64 = 0;
    let mut last_log_time = std::time::Instant::now();

    let stack_thread = thread::current();

    let mut phy_wait_error_count: u32 = 0;
    const MAX_PHY_WAIT_ERRORS: u32 = 10;

    info!("smoltcp direct stack thread started, entering main loop");

    while running.load(Ordering::Relaxed) {
        // Checks for UDP responses to write to TUN.
        if let Ok(mut state) = shared_state.try_lock()
            && let Some(ref mut udp_rx) = state.udp_response_rx
        {
            while let Ok(pkt) = udp_rx.try_recv() {
                if let Err(e) = device.write_packet(&pkt) {
                    warn!("Failed to write UDP response to TUN: {}", e);
                }
            }
        }

        // Reads packets from TUN and filters by protocol (batch processing).
        let mut tcp_packets: Vec<PooledBuffer> = Vec::new();
        let mut packets_read = 0;

        while packets_read < MAX_PACKET_BATCH {
            let pkt = match device.try_recv() {
                Ok(Some(p)) => p,
                Ok(None) => break,
                Err(e) => {
                    // Critical error reading from TUN (EOF or EIO)
                    error!("TUN device read failed: {}. Stack thread stopping.", e);
                    running.store(false, Ordering::Relaxed);
                    break;
                }
            };
            packets_read += 1;

            if should_filter_packet(&pkt) {
                trace!("Filtered packet, len={}", pkt.len());
                continue;
            }

            if let Some(protocol) = get_ip_protocol(&pkt) {
                trace!(
                    "Received packet: protocol={:?}, len={}",
                    protocol,
                    pkt.len()
                );
                match protocol {
                    IpProtocol::Tcp => {
                        match extract_tcp_info(&pkt) {
                            Some((src_addr, dst_addr, is_syn)) => {
                                trace!("TCP packet: {} -> {}, SYN={}", src_addr, dst_addr, is_syn);
                                if is_syn && !active_connections.contains(&(src_addr, dst_addr)) {
                                    // Check connection limit
                                    if sockets.len() >= max_connections {
                                        warn!(
                                            "Connection limit reached ({}), dropping SYN from {}",
                                            max_connections, src_addr
                                        );
                                        continue;
                                    }

                                    // debug, not info: one line per connection
                                    // at info level fills a mobile log file
                                    // with a page load's worth of noise.
                                    debug!("New TCP SYN: {} -> {}", src_addr, dst_addr);

                                    if let Some((new_conn, control)) = create_tcp_connection(
                                        src_addr,
                                        dst_addr,
                                        tcp_buffer_size,
                                        &mut socket_set,
                                        &stack_thread,
                                    ) {
                                        sockets.insert(
                                            new_conn.handle,
                                            SocketInfo {
                                                control,
                                                src_addr,
                                                dst_addr,
                                            },
                                        );
                                        active_connections.insert((src_addr, dst_addr));
                                        // On a SYN, not per packet, so a
                                        // relaxed atomic here is not
                                        // measurable.
                                        #[cfg(feature = "control-stats")]
                                        super::traffic::connection_opened();

                                        if let Ok(state) = shared_state.try_lock()
                                            && let Some(ref tx) = state.new_conn_tx
                                        {
                                            let _ = tx.send(new_conn.new_tcp_conn);
                                        }
                                    }
                                }
                            }
                            None => {
                                warn!("Failed to parse TCP packet, len={}", pkt.len());
                            }
                        }

                        tcp_packets.push(pkt);
                    }
                    IpProtocol::Icmp | IpProtocol::Icmpv6 => {
                        // ICMP goes to smoltcp immediately
                        tcp_packets.push(pkt);
                    }
                    IpProtocol::Udp => {
                        // UDP goes to tokio - convert to Vec since it leaves our pool
                        let _ = udp_tx.send(pkt.to_vec());
                    }
                    _ => {
                        trace!("ignoring packet with protocol {:?}", protocol);
                    }
                }
            }
        }

        if packets_read > 0 {
            phy_wait_error_count = 0;
        }

        // Skip remaining work if a fatal read error was detected above.
        if !running.load(Ordering::Relaxed) {
            break;
        }

        // Processes batched TCP/ICMP packets through smoltcp.
        let has_tcp_packet = !tcp_packets.is_empty();
        for pkt in tcp_packets {
            device.store_packet(pkt);
            let now = SmolInstant::now();
            iface.poll(now, &mut device, &mut socket_set);
        }

        let now = SmolInstant::now();
        iface.poll(now, &mut device, &mut socket_set);

        let mut sockets_to_remove = Vec::new();

        for (handle, socket_info) in sockets.iter() {
            let handle = *handle;
            let control = &socket_info.control;
            let socket = socket_set.get_mut::<TcpSocket>(handle);

            // Remove socket only when smoltcp reports Closed state
            if socket.state() == TcpState::Closed {
                sockets_to_remove.push(handle);
                control.set_closed();
                trace!("socket {:?} closed", handle);
                continue;
            }

            // Handle SHUT_WR: Close -> Closing transition
            // Must check send_queue() to ensure smoltcp has transmitted all data
            if control.send_state() == TcpSocketState::Close
                && socket.send_queue() == 0
                && control.send_buffer_empty()
            {
                trace!(
                    "socket {:?}: closing write half, state={:?}",
                    handle,
                    socket.state()
                );
                socket.close();
                control.set_send_state(TcpSocketState::Closing);
            }

            // Receive data from smoltcp into our buffer
            let mut wake_receiver = false;
            while socket.can_recv() && !control.recv_buffer_full() {
                match socket.recv(|data| {
                    let n = control.enqueue_recv_data(data);
                    (n, n)
                }) {
                    Ok(n) if n > 0 => {
                        wake_receiver = true;
                    }
                    Ok(_) => break,
                    Err(e) => {
                        error!(
                            "socket {:?} recv error: {:?}, state={:?}",
                            handle,
                            e,
                            socket.state()
                        );
                        socket.abort();
                        if control.recv_state() == TcpSocketState::Normal {
                            control.set_recv_state(TcpSocketState::Closed);
                        }
                        wake_receiver = true;
                        break;
                    }
                }
            }

            // Detect recv half close using negative state matching.
            // If socket can't receive and is not in an active receiving state, mark recv closed.
            if control.recv_state() == TcpSocketState::Normal
                && !socket.may_recv()
                && !matches!(
                    socket.state(),
                    TcpState::Listen
                        | TcpState::SynReceived
                        | TcpState::Established
                        | TcpState::FinWait1
                        | TcpState::FinWait2
                )
            {
                trace!(
                    "socket {:?}: recv half closed, state={:?}",
                    handle,
                    socket.state()
                );
                control.set_recv_state(TcpSocketState::Closed);
                wake_receiver = true;
            }

            if wake_receiver {
                control.wake_receiver();
            }

            // Send data from our buffer to smoltcp
            let mut wake_sender = false;
            while socket.can_send() && !control.send_buffer_empty() {
                match socket.send(|buf| {
                    let n = control.dequeue_send_data(buf);
                    (n, n)
                }) {
                    Ok(n) if n > 0 => {
                        wake_sender = true;
                    }
                    Ok(_) => break,
                    Err(e) => {
                        error!(
                            "socket {:?} send error: {:?}, state={:?}",
                            handle,
                            e,
                            socket.state()
                        );
                        socket.abort();
                        if control.send_state() == TcpSocketState::Normal {
                            control.set_send_state(TcpSocketState::Closed);
                        }
                        wake_sender = true;
                        break;
                    }
                }
            }

            if wake_sender {
                control.wake_sender();
            }
        }

        for handle in sockets_to_remove {
            if let Some(socket_info) = sockets.remove(&handle) {
                active_connections.remove(&(socket_info.src_addr, socket_info.dst_addr));
                #[cfg(feature = "control-stats")]
                super::traffic::connection_closed();
                trace!(
                    "Cleaned up connection: {} -> {}",
                    socket_info.src_addr, socket_info.dst_addr
                );
            }
            socket_set.remove(handle);
        }

        poll_count += 1;
        if last_log_time.elapsed() >= Duration::from_secs(30) {
            debug!(
                "smoltcp direct stack: polls={}, active_sockets={}",
                poll_count,
                sockets.len()
            );
            last_log_time = std::time::Instant::now();
        }

        // Polls again after data transfer (critical for performance).
        let after_transfer = SmolInstant::now();
        iface.poll(after_transfer, &mut device, &mut socket_set);

        // Wait for data using select() - this is the key for event-driven I/O
        if !has_tcp_packet && device.pending_rx.is_none() {
            // Cap poll_delay at 10ms to balance CPU usage vs throughput
            let delay = iface.poll_delay(after_transfer, &socket_set);
            let wait_duration = delay.map(|d| {
                let millis = d.total_millis().min(10);
                SmolDuration::from_millis(millis)
            });

            // Sleeps until the TUN has something to read, the wake pipe says
            // to stop, or the delay smoltcp asked for elapses. If the fd
            // becomes invalid (e.g. device removed), poll() returns POLLNVAL
            // immediately with no sleep, creating a hot spin loop. The try_recv
            // path usually catches this first, but this counter acts as a
            // backstop: after 10 consecutive non-EINTR errors with no
            // successful reads in between, treat the fd as dead.
            if let Err(e) = wait_readable(fd, wake_fd, wait_duration)
                && e.kind() != io::ErrorKind::Interrupted
            {
                phy_wait_error_count += 1;
                if phy_wait_error_count >= MAX_PHY_WAIT_ERRORS {
                    error!(
                        "poll() failed {} consecutive times (last: {}). Stack thread stopping.",
                        phy_wait_error_count, e
                    );
                    running.store(false, Ordering::Relaxed);
                } else {
                    warn!("poll() error ({}): {}", phy_wait_error_count, e);
                }
            }
        }
    }

    info!("smoltcp direct stack thread stopped");
}

/// Result of creating a TCP connection.
struct CreateConnectionResult {
    handle: SocketHandle,
    new_tcp_conn: NewTcpConnection,
}

/// Create a new TCP connection in the smoltcp stack.
fn create_tcp_connection(
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    buffer_size: usize,
    socket_set: &mut SocketSet<'static>,
    stack_thread: &Thread,
) -> Option<(CreateConnectionResult, Arc<TcpConnectionControl>)> {
    let mut socket = TcpSocket::new(
        TcpSocketBuffer::new(vec![0u8; buffer_size]),
        TcpSocketBuffer::new(vec![0u8; buffer_size]),
    );

    // Matched to netstack-smoltcp settings for optimal performance
    socket.set_congestion_control(CongestionControl::Cubic);
    socket.set_keep_alive(Some(SmolDuration::from_secs(28)));
    // 7200s matches Linux default (tcp_keepalive_time) and shadowsocks-rust
    socket.set_timeout(Some(SmolDuration::from_secs(7200)));
    socket.set_nagle_enabled(false);
    socket.set_ack_delay(None);

    if let Err(e) = socket.listen(dst_addr) {
        warn!("Failed to listen on socket for {}: {:?}", dst_addr, e);
        return None;
    }

    debug!("Creating TCP connection: {} -> {}", src_addr, dst_addr);

    let control = Arc::new(TcpConnectionControl::new(buffer_size, buffer_size));

    let handle = socket_set.add(socket);
    let connection = TcpConnection::new(control.clone(), stack_thread.clone());

    Some((
        CreateConnectionResult {
            handle,
            new_tcp_conn: NewTcpConnection {
                connection,
                remote_addr: dst_addr,
            },
        },
        control,
    ))
}

/// Extract IP protocol from a raw IP packet.
fn get_ip_protocol(packet: &[u8]) -> Option<IpProtocol> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;
    match version {
        4 => Ipv4Packet::new_checked(packet)
            .ok()
            .map(|p| p.next_header()),
        6 => Ipv6Packet::new_checked(packet)
            .ok()
            .map(|p| p.next_header()),
        _ => None,
    }
}

/// Extract TCP connection info from a raw IP packet.
fn extract_tcp_info(packet: &[u8]) -> Option<(SocketAddr, SocketAddr, bool)> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;
    match version {
        4 => {
            let ip = Ipv4Packet::new_checked(packet).ok()?;
            if ip.next_header() != IpProtocol::Tcp {
                return None;
            }
            let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
            let src_addr = SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip.src_addr().octets())),
                tcp.src_port(),
            );
            let dst_addr = SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip.dst_addr().octets())),
                tcp.dst_port(),
            );
            let is_syn = tcp.syn() && !tcp.ack();
            Some((src_addr, dst_addr, is_syn))
        }
        6 => {
            let ip = Ipv6Packet::new_checked(packet).ok()?;
            if ip.next_header() != IpProtocol::Tcp {
                return None;
            }
            let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
            let src_addr = SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip.src_addr().octets())),
                tcp.src_port(),
            );
            let dst_addr = SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip.dst_addr().octets())),
                tcp.dst_port(),
            );
            let is_syn = tcp.syn() && !tcp.ack();
            Some((src_addr, dst_addr, is_syn))
        }
        _ => None,
    }
}

/// Check if an IP packet should be filtered.
fn should_filter_packet(packet: &[u8]) -> bool {
    if packet.is_empty() {
        return true;
    }

    let version = packet[0] >> 4;
    match version {
        4 => {
            if let Ok(ip) = Ipv4Packet::new_checked(packet) {
                let src = ip.src_addr();
                let dst = ip.dst_addr();

                let src_bytes = src.octets();
                let dst_bytes = dst.octets();

                // Filter unspecified source
                if src_bytes == [0, 0, 0, 0] {
                    return true;
                }
                // Filter multicast source
                if src_bytes[0] >= 224 && src_bytes[0] <= 239 {
                    return true;
                }
                // Filter broadcast destination
                if dst_bytes == [255, 255, 255, 255] {
                    return true;
                }
                // Filter multicast destination
                if dst_bytes[0] >= 224 && dst_bytes[0] <= 239 {
                    return true;
                }
                // Filter unspecified destination
                if dst_bytes == [0, 0, 0, 0] {
                    return true;
                }

                false
            } else {
                true
            }
        }
        6 => {
            if let Ok(ip) = Ipv6Packet::new_checked(packet) {
                let src = ip.src_addr();
                let dst = ip.dst_addr();

                let src_bytes = src.octets();
                let dst_bytes = dst.octets();

                // Filter unspecified source
                if src_bytes == [0u8; 16] {
                    return true;
                }
                // Filter multicast destination
                if dst_bytes[0] == 0xff {
                    return true;
                }
                // Filter unspecified destination
                if dst_bytes == [0u8; 16] {
                    return true;
                }

                false
            } else {
                true
            }
        }
        _ => true,
    }
}

/// Set a file descriptor to non-blocking mode (call once at startup).
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if (flags & libc::O_NONBLOCK) == 0
        && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Non-blocking read from a file descriptor (fd must already be non-blocking).
/// Returns Err(WouldBlock) when no data is available, so callers can
/// distinguish it from Ok(0) which indicates EOF.
fn read_nonblocking(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// Write all data to a file descriptor.
fn write_all(fd: RawFd, buf: &[u8]) -> io::Result<()> {
    let mut written = 0;
    while written < buf.len() {
        let n = unsafe {
            libc::write(
                fd,
                buf[written..].as_ptr() as *const libc::c_void,
                buf.len() - written,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOBUFS) || err.kind() == io::ErrorKind::WouldBlock
            {
                trace!("TUN write {}, packet dropped", err);
                return Ok(());
            }
            return Err(err);
        }
        written += n as usize;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::IntoRawFd;
    use std::os::unix::net::UnixStream;

    /// Stack options for a test that hands its descriptor over to the stack.
    fn owning_options() -> TcpStackOptions {
        TcpStackOptions {
            mtu: 1500,
            tcp_buffer_size: 32 * 1024,
            max_connections: 16,
            close_fd_on_drop: true,
        }
    }

    #[test]
    fn test_stack_shutdown_on_eof() {
        let (server, client) = UnixStream::pair().expect("Failed to create socket pair");
        let client_fd = client.into_raw_fd();

        let stack = TcpStackDirect::new(client_fd, owning_options());

        thread::sleep(Duration::from_millis(100));
        assert!(stack.is_running(), "Stack thread should be running");

        // Closing the writer end triggers EOF on the reader.
        drop(server);

        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(2);

        while stack.is_running() {
            if start.elapsed() > timeout {
                panic!("Stack thread did not exit after EOF on FD");
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn test_stack_shutdown_on_closed_fd() {
        let (server, client) = UnixStream::pair().expect("Failed to create socket pair");
        let client_fd = client.into_raw_fd();

        // Borrowed, not owned: this test closes the descriptor itself below,
        // and a stack that closed it again would be a double close.
        let stack = TcpStackDirect::new(
            client_fd,
            TcpStackOptions {
                close_fd_on_drop: false,
                ..owning_options()
            },
        );

        thread::sleep(Duration::from_millis(100));
        assert!(stack.is_running(), "Stack thread should be running");

        // Externally close the fd to produce EBADF on both read and select.
        unsafe { libc::close(client_fd) };
        // Also drop the writer so there's no other holder.
        drop(server);

        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(5);

        while stack.is_running() {
            if start.elapsed() > timeout {
                panic!("Stack thread did not exit after closed FD");
            }
            thread::sleep(Duration::from_millis(50));
        }

        // Safe to drop only because the stack was told the descriptor is not
        // its own. Closing it twice would let a concurrent test's OwnedFd take
        // the freed number in between and then lose it, which aborts the whole
        // test binary ("IO Safety violation: owned file descriptor already
        // closed") rather than failing one test.
        drop(stack);
    }

    /// Resident bytes this process is using, from `ps`.
    fn resident_bytes() -> u64 {
        let pid = std::process::id();
        let out = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &pid.to_string()])
            .output()
            .expect("ps");
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse::<u64>()
            .expect("rss")
            * 1024
    }

    /// One IPv4 SYN, checksummed, from `src_port` to 93.184.216.34:443.
    fn syn_packet(src_port: u16) -> Vec<u8> {
        use smoltcp::phy::ChecksumCapabilities;
        use smoltcp::wire::{Ipv4Repr, TcpControl, TcpRepr, TcpSeqNumber};

        let tcp = TcpRepr {
            src_port,
            dst_port: 443,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(0),
            ack_number: None,
            window_len: 64240,
            window_scale: None,
            max_seg_size: Some(1400),
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        let src_addr = Ipv4Address::new(10, 0, 0, 2);
        let dst_addr = Ipv4Address::new(93, 184, 216, 34);
        let ip = Ipv4Repr {
            src_addr,
            dst_addr,
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        };

        let checksums = ChecksumCapabilities::default();
        let mut buffer = vec![0u8; ip.buffer_len() + tcp.buffer_len()];
        ip.emit(&mut Ipv4Packet::new_unchecked(&mut buffer), &checksums);
        tcp.emit(
            &mut TcpPacket::new_unchecked(&mut buffer[ip.buffer_len()..]),
            &src_addr.into(),
            &dst_addr.into(),
            &checksums,
        );
        buffer
    }

    /// What a connection actually costs in resident memory, and whether the
    /// stack gives it back.
    ///
    /// Ignored by default: resident size is a measurement, not something to
    /// assert on across machines and allocators. Run it with
    /// `cargo test measure_memory_per_connection -- --ignored --nocapture`
    /// when changing buffer sizing.
    #[test]
    #[ignore = "measurement; run with --ignored --nocapture"]
    fn measure_memory_per_connection() {
        use std::io::Write;

        const CONNECTIONS: usize = 200;
        let buffer_size = 32 * 1024;

        let (mut server, client) = UnixStream::pair().expect("socket pair");
        let client_fd = client.into_raw_fd();

        let before = resident_bytes();
        let stack = TcpStackDirect::new(
            client_fd,
            TcpStackOptions {
                mtu: 1500,
                tcp_buffer_size: buffer_size,
                max_connections: CONNECTIONS * 2,
                close_fd_on_drop: true,
            },
        );
        thread::sleep(Duration::from_millis(100));

        for i in 0..CONNECTIONS {
            server
                .write_all(&syn_packet(20000 + i as u16))
                .expect("write SYN");
            // The stack reads in batches of 64; give it room to keep up rather
            // than filling the socket buffer and blocking this side.
            if i % 32 == 0 {
                thread::sleep(Duration::from_millis(20));
            }
        }
        thread::sleep(Duration::from_millis(500));
        let occupied = resident_bytes();

        drop(stack);
        drop(server);
        clear_buffer_pool();
        thread::sleep(Duration::from_millis(200));
        let after_free = resident_bytes();

        crate::memory::release_to_os();
        thread::sleep(Duration::from_millis(200));
        let after = resident_bytes();

        let per_connection = (occupied.saturating_sub(before)) as f64 / CONNECTIONS as f64;
        println!(
            "buffers {} KiB/direction, {} connections\n  \
             before          {:>7} KiB\n  \
             occupied        {:>7} KiB  ({:.0} KiB per connection, \
             {:.0}% of the four buffers it allocated)\n  \
             after free      {:>7} KiB  ({:+} KiB vs before)\n  \
             after purge     {:>7} KiB  ({:+} KiB vs before)",
            buffer_size / 1024,
            CONNECTIONS,
            before / 1024,
            occupied / 1024,
            per_connection / 1024.0,
            100.0 * per_connection / (4.0 * buffer_size as f64),
            after_free / 1024,
            (after_free as i64 - before as i64) / 1024,
            after / 1024,
            (after as i64 - before as i64) / 1024,
        );
    }

    #[test]
    fn stack_leaves_a_borrowed_fd_open() {
        // The mobile case: the app owns the descriptor and closes it itself.
        // Closing it here as well would be a double close in a process that is
        // opening sockets constantly, which means closing whichever socket has
        // taken the number in the meantime.
        let (server, client) = UnixStream::pair().expect("Failed to create socket pair");
        let client_fd = client.into_raw_fd();

        let stack = TcpStackDirect::new(
            client_fd,
            TcpStackOptions {
                close_fd_on_drop: false,
                ..owning_options()
            },
        );
        thread::sleep(Duration::from_millis(100));
        drop(stack);

        let still_open = unsafe { libc::fcntl(client_fd, libc::F_GETFD) } != -1;
        // Closed here, not by the stack, which is the whole point.
        unsafe { libc::close(client_fd) };
        drop(server);

        assert!(still_open, "the stack closed a descriptor it does not own");
    }

    #[test]
    fn test_stack_exits_promptly() {
        // Verifies the stack exits within 1 second of EOF, catching
        // regressions that would cause CPU spin on a dead fd.
        let (server, client) = UnixStream::pair().expect("Failed to create socket pair");
        let client_fd = client.into_raw_fd();

        let stack = TcpStackDirect::new(client_fd, owning_options());

        thread::sleep(Duration::from_millis(100));
        assert!(stack.is_running());

        drop(server);

        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(1);

        while stack.is_running() {
            if start.elapsed() > timeout {
                panic!("Stack thread took >1s to exit after EOF (possible spin)");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn test_write_all_eagain() {
        // Fill a non-blocking socket's write buffer, then verify write_all
        // treats EAGAIN the same as ENOBUFS (drops the packet, returns Ok).
        let (reader, writer) = UnixStream::pair().expect("Failed to create socket pair");
        let writer_fd = writer.into_raw_fd();

        set_nonblocking(writer_fd).expect("set_nonblocking");

        // Fill the write buffer until WouldBlock
        let big_buf = vec![0u8; 65536];
        loop {
            let n = unsafe {
                libc::write(
                    writer_fd,
                    big_buf.as_ptr() as *const libc::c_void,
                    big_buf.len(),
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                assert_eq!(
                    err.kind(),
                    io::ErrorKind::WouldBlock,
                    "unexpected error: {}",
                    err
                );
                break;
            }
        }

        // Now write_all should drop the packet gracefully
        let result = write_all(writer_fd, &[1, 2, 3]);
        assert!(
            result.is_ok(),
            "write_all should return Ok on EAGAIN, got {:?}",
            result
        );

        unsafe { libc::close(writer_fd) };
        drop(reader);
    }
}
