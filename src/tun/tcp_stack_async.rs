//! Async TCP Stack Manager for cross-platform TUN support.
//!
//! This module provides an alternative implementation that works with async TUN devices,
//! supporting Windows via WinTUN as well as Unix platforms.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
//! │  Async TUN      │ ←→  │  Virtual Device │ ←→  │  smoltcp Stack  │
//! │  (WinTUN/*nix)  │     │  (channels)     │     │  (dedicated     │
//! │                 │     │                 │     │   thread)       │
//! └─────────────────┘     └─────────────────┘     └─────────────────┘
//!         ↓                         ↓
//!    tokio runtime            tokio runtime
//! ```

use std::{
    collections::HashMap,
    io,
    mem,
    net::SocketAddr,
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle, Thread},
    time::Duration,
};

use bytes::BytesMut;
use log::{debug, error, info, warn};
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet},
    phy::{Checksum, Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp::{CongestionControl, Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState},
    time::{Duration as SmolDuration, Instant as SmolInstant},
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address,
        Ipv6Packet, TcpPacket,
    },
};
use tokio::{
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    task::JoinHandle as TokioJoinHandle,
};

use super::tcp_conn::{TcpConnection, TcpConnectionControl, TcpSocketState};

pub type PacketBuffer = Vec<u8>;

/// Maximum number of buffers cached globally.
const BUFFER_POOL_MAX_SIZE: usize = 64;
static BUFFER_POOL: LazyLock<Mutex<Vec<BytesMut>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// Pooled buffer that returns to pool on drop.
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

    pub fn extend_from_slice(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buffer
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.buffer.to_vec()
    }
}

impl std::ops::Deref for PooledBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

/// Information about a new TCP connection.
pub struct NewTcpConnection {
    pub connection: TcpConnection,
    pub remote_addr: SocketAddr,
}

/// Shared state for communication between tokio and stack thread.
struct SharedState {
    /// Channel for UDP responses to write to TUN
    udp_response_rx: Option<UnboundedReceiver<PacketBuffer>>,
    /// Channel for notifying tokio about new TCP connections
    new_conn_tx: Option<UnboundedSender<NewTcpConnection>>,
}

/// Virtual TUN device using channels for async/sync bridge.
///
/// This allows smoltcp (which is synchronous) to work with async TUN devices.
struct VirtTunDevice {
    mtu: usize,
    /// Packets from TUN device (to be processed by smoltcp)
    in_rx: UnboundedReceiver<PooledBuffer>,
    /// Packets from smoltcp (to be written to TUN device)
    out_tx: UnboundedSender<PacketBuffer>,
    pending_rx: Option<PooledBuffer>,
}

impl VirtTunDevice {
    fn new(
        mtu: usize,
        in_rx: UnboundedReceiver<PooledBuffer>,
        out_tx: UnboundedSender<PacketBuffer>,
    ) -> Self {
        Self {
            mtu,
            in_rx,
            out_tx,
            pending_rx: None,
        }
    }

    /// Try to get a packet from the input channel.
    /// Returns an error when the channel is closed so the stack thread can exit.
    fn try_recv(&mut self) -> io::Result<Option<PooledBuffer>> {
        if let Some(pkt) = self.pending_rx.take() {
            return Ok(Some(pkt));
        }
        match self.in_rx.try_recv() {
            Ok(pkt) => Ok(Some(pkt)),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tun input channel closed",
            )),
        }
    }

    /// Store a packet for later processing.
    fn store_packet(&mut self, pkt: PooledBuffer) {
        self.pending_rx = Some(pkt);
    }

    /// Write a packet to the output channel.
    fn write_packet(&self, data: &[u8]) -> io::Result<()> {
        self.out_tx
            .send(data.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "channel closed"))
    }
}

impl Device for VirtTunDevice {
    type RxToken<'a> = VirtRxToken;
    type TxToken<'a> = VirtTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(buffer) = self.pending_rx.take() {
            let rx = VirtRxToken { buffer };
            let tx = VirtTxToken { device: self };
            Some((rx, tx))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(VirtTxToken { device: self })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.checksum.ipv4 = Checksum::Tx;
        caps.checksum.tcp = Checksum::Tx;
        caps.checksum.udp = Checksum::Tx;
        caps.checksum.icmpv4 = Checksum::Tx;
        caps.checksum.icmpv6 = Checksum::Tx;
        caps
    }
}

struct VirtRxToken {
    buffer: PooledBuffer,
}

impl RxToken for VirtRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

struct VirtTxToken<'a> {
    device: &'a VirtTunDevice,
}

impl TxToken for VirtTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        if let Err(e) = self.device.write_packet(&buffer) {
            warn!("Failed to write packet: {}", e);
        }
        result
    }
}

/// Async TCP Stack Manager.
///
/// Manages the smoltcp interface with async TUN device support.
pub struct TcpStackAsync {
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
    /// Sender for packets from TUN to stack
    tun_to_stack_tx: UnboundedSender<PooledBuffer>,
    /// Receiver for packets from stack to TUN
    stack_to_tun_rx: Option<UnboundedReceiver<PacketBuffer>>,
    /// Tokio task handle for reading from TUN
    read_task: Option<TokioJoinHandle<()>>,
    /// Tokio task handle for writing to TUN
    write_task: Option<TokioJoinHandle<()>>,
}

impl Drop for TcpStackAsync {
    fn drop(&mut self) {
        // Signal thread to stop
        self.running.store(false, Ordering::Relaxed);
        self.stack_thread.unpark();

        // Abort tokio tasks
        if let Some(task) = self.read_task.take() {
            task.abort();
        }
        if let Some(task) = self.write_task.take() {
            task.abort();
        }

        // Wait for thread to finish
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

impl TcpStackAsync {
    /// Create a new async TCP stack.
    ///
    /// # Arguments
    /// * `mtu` - Maximum transmission unit
    ///
    /// This spawns:
    /// 1. A dedicated OS thread for running the smoltcp interface
    /// 2. A tokio task for reading from the async TUN device
    /// 3. A tokio task for writing to the async TUN device
    pub fn new(mtu: usize) -> Self {
        let (tun_to_stack_tx, tun_to_stack_rx) = mpsc::unbounded_channel();
        let (stack_to_tun_tx, stack_to_tun_rx) = mpsc::unbounded_channel();
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
                .name("shoes-smoltcp-async".to_owned())
                .spawn(move || {
                    let device = VirtTunDevice::new(mtu, tun_to_stack_rx, stack_to_tun_tx);
                    run_stack_thread(device, mtu, udp_tx, running, shared_state);
                })
                .expect("failed to spawn smoltcp async thread")
        };

        let stack_thread = thread_handle.thread().clone();

        Self {
            thread_handle: Some(thread_handle),
            stack_thread,
            running,
            udp_rx: Some(udp_rx),
            shared_state,
            tun_to_stack_tx,
            stack_to_tun_rx: Some(stack_to_tun_rx),
            read_task: None,
            write_task: None,
        }
    }

    /// Take the receiver for UDP packets.
    pub fn take_udp_rx(&mut self) -> Option<UnboundedReceiver<PacketBuffer>> {
        self.udp_rx.take()
    }

    /// Set the channel for UDP responses.
    pub fn set_udp_response_tx(&mut self, rx: UnboundedReceiver<PacketBuffer>) {
        if let Ok(mut state) = self.shared_state.lock() {
            state.udp_response_rx = Some(rx);
        }
        self.stack_thread.unpark();
    }

    /// Set the channel for new TCP connections.
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

    /// Get the sender for packets from TUN to stack.
    pub fn tun_to_stack_tx(&self) -> UnboundedSender<PooledBuffer> {
        self.tun_to_stack_tx.clone()
    }

    /// Get the receiver for packets from stack to TUN.
    pub fn take_stack_to_tun_rx(&mut self) -> UnboundedReceiver<PacketBuffer> {
        self.stack_to_tun_rx.take().expect("already taken")
    }
}

// Buffer sizes matched to netstack-smoltcp
const TCP_SEND_BUFFER_SIZE: usize = 0x3FFF * 20;
const TCP_RECV_BUFFER_SIZE: usize = 0x3FFF * 20;
const MAX_PACKET_BATCH: usize = 64;
const MAX_CONCURRENT_CONNECTIONS: usize = 1024;

/// Tracks socket info including addresses for proper cleanup.
struct SocketInfo {
    control: Arc<TcpConnectionControl>,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
}

/// Run the smoltcp stack thread with virtual device.
fn run_stack_thread(
    mut device: VirtTunDevice,
    _mtu: usize,
    udp_tx: UnboundedSender<PacketBuffer>,
    running: Arc<AtomicBool>,
    shared_state: Arc<Mutex<SharedState>>,
) {
    info!("smoltcp async stack thread initializing...");

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

    let stack_thread = thread::current();

    info!("smoltcp async stack thread started");

    while running.load(Ordering::Relaxed) {
        // Check for UDP responses
        if let Ok(mut state) = shared_state.try_lock()
            && let Some(ref mut udp_rx) = state.udp_response_rx
        {
            while let Ok(pkt) = udp_rx.try_recv() {
                if let Err(e) = device.write_packet(&pkt) {
                    warn!("Failed to write UDP response: {}", e);
                }
            }
        }

        // Read packets from virtual TUN device
        let mut tcp_packets: Vec<PooledBuffer> = Vec::new();
        let mut packets_read = 0;

        while packets_read < MAX_PACKET_BATCH {
            let pkt = match device.try_recv() {
                Ok(Some(p)) => p,
                Ok(None) => break,
                Err(e) => {
                    error!("TUN input channel read failed: {}. Stack thread stopping.", e);
                    running.store(false, Ordering::Relaxed);
                    break;
                }
            };
            packets_read += 1;

            if should_filter_packet(&pkt) {
                continue;
            }

            if let Some(protocol) = get_ip_protocol(&pkt) {
                match protocol {
                    IpProtocol::Tcp => {
                        if let Some((src_addr, dst_addr, is_syn)) = extract_tcp_info(&pkt) {
                            if is_syn && !active_connections.contains(&(src_addr, dst_addr)) {
                                if sockets.len() >= MAX_CONCURRENT_CONNECTIONS {
                                    warn!(
                                        "Connection limit reached, dropping SYN from {}",
                                        src_addr
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
                        tcp_packets.push(pkt);
                    }
                    IpProtocol::Icmp | IpProtocol::Icmpv6 => {
                        tcp_packets.push(pkt);
                    }
                    IpProtocol::Udp => {
                        let _ = udp_tx.send(pkt.to_vec());
                    }
                    _ => {}
                }
            }
        }

        if !running.load(Ordering::Relaxed) {
            break;
        }

        // Process packets through smoltcp
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

            if socket.state() == TcpState::Closed {
                sockets_to_remove.push(handle);
                control.set_closed();
                continue;
            }

            if control.send_state() == TcpSocketState::Close
                && socket.send_queue() == 0
                && control.send_buffer_empty()
            {
                socket.close();
                control.set_send_state(TcpSocketState::Closing);
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
                        error!("socket {:?} recv error: {:?}", handle, e);
                        socket.abort();
                        if control.recv_state() == TcpSocketState::Normal {
                            control.set_recv_state(TcpSocketState::Closed);
                        }
                        wake_receiver = true;
                        break;
                    }
                }
            }

            if control.recv_state() == TcpSocketState::Normal
                && !socket.may_recv()
                && !matches!(
                    socket.state(),
                    TcpState::Listen | TcpState::SynReceived | TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2
                )
            {
                control.set_recv_state(TcpSocketState::Closed);
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
                        error!("socket {:?} send error: {:?}", handle, e);
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
            }
            socket_set.remove(handle);
        }

        // Wait for next poll
        let now = SmolInstant::now();
        if let Some(delay) = iface.poll_delay(now, &socket_set) {
            if delay != SmolDuration::ZERO {
                thread::park_timeout(Duration::from_millis(delay.total_millis().min(10) as u64));
            }
        } else {
            thread::park_timeout(Duration::from_millis(5));
        }
    }

    info!("smoltcp async stack thread stopped");
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

    socket.set_congestion_control(CongestionControl::Cubic);
    socket.set_keep_alive(Some(SmolDuration::from_secs(28)));
    socket.set_timeout(Some(SmolDuration::from_secs(7200)));
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

                if src_bytes == [0, 0, 0, 0]
                    || (src_bytes[0] >= 224 && src_bytes[0] <= 239)
                    || dst_bytes == [255, 255, 255, 255]
                    || (dst_bytes[0] >= 224 && dst_bytes[0] <= 239)
                    || dst_bytes == [0, 0, 0, 0]
                {
                    return true;
                }
                false
            } else {
                true
            }
        }
        6 => {
            if let Ok(ip) = Ipv6Packet::new_checked(packet) {
                let src_bytes = ip.src_addr().octets();
                let dst_bytes = ip.dst_addr().octets();

                if src_bytes == [0u8; 16] || dst_bytes[0] == 0xff || dst_bytes == [0u8; 16] {
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
