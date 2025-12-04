//! Direct TCP Stack Manager for smoltcp integration.
//!
//! This module manages the smoltcp TCP/IP stack in a dedicated OS thread,
//! using `select()` on the TUN fd for event-driven I/O instead of polling.

use std::{
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
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken, wait as phy_wait},
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

use super::tcp_conn::{TcpConnection, TcpConnectionControl};

pub type PacketBuffer = Vec<u8>;

/// Maximum number of buffers cached globally.
/// Each buffer has capacity ~65536, so 64 * 65536 = 4MB max.
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
    /// TUN file descriptor (owned, will be closed on drop)
    tun_fd: RawFd,
}

impl Drop for TcpStackDirect {
    fn drop(&mut self) {
        // Signal thread to stop
        self.running.store(false, Ordering::Relaxed);
        self.stack_thread.unpark();

        // Wait for thread to finish
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }

        // Close the TUN fd
        unsafe {
            libc::close(self.tun_fd);
        }
    }
}

impl TcpStackDirect {
    /// Create a new direct TCP stack.
    ///
    /// # Arguments
    /// * `fd` - Raw file descriptor for the TUN device
    /// * `mtu` - Maximum transmission unit
    ///
    /// This spawns a dedicated OS thread for running the smoltcp interface.
    /// The thread uses `select()` on the fd for efficient event-driven I/O.
    pub fn new(fd: RawFd, mtu: usize) -> Self {
        let (udp_tx, udp_rx) = mpsc::unbounded_channel();

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
                        run_direct_stack_thread(fd, mtu, udp_tx, running.clone(), shared_state);
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
    fn try_recv(&mut self) -> Option<PooledBuffer> {
        if let Some(pkt) = self.pending_rx.take() {
            return Some(pkt);
        }

        // Get a buffer from the pool
        let mut buffer = PooledBuffer::with_capacity(self.mtu + 4);
        buffer.resize(self.mtu + 4, 0);

        match read_nonblocking(self.fd, &mut buffer) {
            Ok(n) if n > 0 => {
                buffer.truncate(n);
                Some(buffer)
            }
            _ => None, // Buffer is returned to pool when dropped
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

impl TxToken for DirectTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);

        if let Err(e) = write_all(self.fd, &buffer) {
            warn!("Failed to write to TUN: {}", e);
        }

        result
    }
}

// Buffer sizes matched to netstack-smoltcp: 0x3FFF * 20 = 327,660 bytes (~320KB)
const TCP_SEND_BUFFER_SIZE: usize = 0x3FFF * 20; // ~320KB for high throughput
const TCP_RECV_BUFFER_SIZE: usize = 0x3FFF * 20; // ~320KB
const MAX_PACKET_BATCH: usize = 64; // Process more packets per poll iteration
const MAX_CONCURRENT_CONNECTIONS: usize = 1024; // Limit concurrent connections like gvisor

/// Run the direct smoltcp stack thread.
fn run_direct_stack_thread(
    fd: RawFd,
    mtu: usize,
    udp_tx: UnboundedSender<PacketBuffer>,
    running: Arc<AtomicBool>,
    shared_state: Arc<Mutex<SharedState>>,
) {
    info!("smoltcp direct stack thread initializing...");

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
                Some(p) => p,
                None => break,
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
                                    if sockets.len() >= MAX_CONCURRENT_CONNECTIONS {
                                        warn!(
                                            "Connection limit reached ({}), dropping SYN from {}",
                                            MAX_CONCURRENT_CONNECTIONS, src_addr
                                        );
                                        continue;
                                    }

                                    info!("New TCP SYN: {} -> {}", src_addr, dst_addr);

                                    if let Some((new_conn, control)) = create_tcp_connection(
                                        src_addr,
                                        dst_addr,
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

            let state = socket.state();
            if state == TcpState::Closed {
                sockets_to_remove.push(handle);
                control.set_closed();
                trace!("socket {:?} closed", handle);
                continue;
            }

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
                        error!("socket recv error: {:?}", e);
                        socket.abort();
                        control.set_closed();
                        wake_receiver = true;
                        break;
                    }
                }
            }

            let state = socket.state();
            if !socket.may_recv()
                && !socket.can_recv()
                && (state == TcpState::CloseWait
                    || state == TcpState::LastAck
                    || state == TcpState::Closed
                    || state == TcpState::TimeWait)
                && control.set_recv_closed()
            {
                trace!("socket {:?} recv closed (state={:?})", handle, state);
                wake_receiver = true;
            }

            if wake_receiver {
                control.wake_receiver();
            }

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
                        error!("socket send error: {:?}", e);
                        socket.abort();
                        control.set_closed();
                        wake_sender = true;
                        break;
                    }
                }
            }

            if control.should_close_send()
                && !control.is_send_closed()
                && control.send_buffer_empty()
            {
                trace!("socket {:?}: initiating close", handle);
                socket.close();
                control.set_send_closed();
                wake_sender = true;
            }

            if wake_sender {
                control.wake_sender();
            }
        }

        for handle in sockets_to_remove {
            if let Some(socket_info) = sockets.remove(&handle) {
                active_connections.remove(&(socket_info.src_addr, socket_info.dst_addr));
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

            if let Err(e) = phy_wait(fd, wait_duration)
                && e.kind() != io::ErrorKind::Interrupted
            {
                warn!("select() error: {}", e);
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
    socket_set: &mut SocketSet<'static>,
    stack_thread: &Thread,
) -> Option<(CreateConnectionResult, Arc<TcpConnectionControl>)> {
    let mut socket = TcpSocket::new(
        TcpSocketBuffer::new(vec![0u8; TCP_RECV_BUFFER_SIZE]),
        TcpSocketBuffer::new(vec![0u8; TCP_SEND_BUFFER_SIZE]),
    );

    // Matched to netstack-smoltcp settings for optimal performance
    socket.set_congestion_control(CongestionControl::Cubic);
    socket.set_keep_alive(Some(SmolDuration::from_secs(28)));
    socket.set_timeout(Some(SmolDuration::from_secs(300)));
    socket.set_nagle_enabled(false);
    socket.set_ack_delay(None);

    if let Err(e) = socket.listen(dst_addr) {
        warn!("Failed to listen on socket for {}: {:?}", dst_addr, e);
        return None;
    }

    debug!("Creating TCP connection: {} -> {}", src_addr, dst_addr);

    let control = Arc::new(TcpConnectionControl::new(
        TCP_SEND_BUFFER_SIZE,
        TCP_RECV_BUFFER_SIZE,
    ));

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
fn read_nonblocking(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            Ok(0)
        } else {
            Err(err)
        }
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
            if err.raw_os_error() == Some(libc::ENOBUFS) {
                trace!("TUN write ENOBUFS, packet dropped");
                return Ok(());
            }
            return Err(err);
        }
        written += n as usize;
    }
    Ok(())
}
