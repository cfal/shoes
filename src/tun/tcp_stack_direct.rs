//! Direct TCP Stack Manager for smoltcp integration.
//!
//! This module manages the smoltcp TCP/IP stack in a dedicated OS thread,
//! using `poll()` on TUN and wake fds for event-driven I/O.

use std::{
    collections::{HashMap, HashSet},
    io,
    net::SocketAddr,
    os::fd::{AsRawFd, OwnedFd, RawFd},
    panic::{self, AssertUnwindSafe},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

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
use tokio::sync::mpsc::{self, Receiver, Sender};

use super::TunServerConfig;
use super::packet::PacketBuffer;
use super::tcp_conn::{TcpConnection, TcpConnectionControl, TcpSocketState};
use super::wake::{Wake, WakeReceiver};

pub const PACKET_QUEUE_CAPACITY: usize = 64;

/// Tracks socket info including addresses for proper cleanup.
struct SocketInfo {
    control: Arc<TcpConnectionControl>,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
}

impl Drop for SocketInfo {
    fn drop(&mut self) {
        self.control.set_closed();
    }
}

/// Information about a new TCP connection from the stack.
pub struct NewTcpConnection {
    pub connection: TcpConnection,
    pub remote_addr: SocketAddr,
}

/// Shared state for communication between main thread and stack thread.
struct SharedState {
    /// Channel for UDP responses to write to TUN
    udp_response_rx: Option<Receiver<PacketBuffer>>,
    /// Channel for notifying tokio about new TCP connections
    new_conn_tx: Option<mpsc::UnboundedSender<NewTcpConnection>>,
}

/// Direct TCP Stack Manager.
///
/// Manages the smoltcp interface with direct fd access for efficient I/O.
pub struct TcpStackDirect {
    /// Handle to the stack thread
    thread_handle: Option<JoinHandle<()>>,
    wake: Wake,
    /// Flag to signal thread shutdown
    running: Arc<AtomicBool>,
    /// Receiver for UDP packets (filtered from TUN by the stack thread)
    udp_rx: Option<Receiver<PacketBuffer>>,
    /// Shared state with the stack thread
    shared_state: Arc<Mutex<SharedState>>,
    /// TUN file descriptor (owned, will be closed on drop)
    _tun_fd: OwnedFd,
}

impl Drop for TcpStackDirect {
    fn drop(&mut self) {
        // Signal thread to stop
        self.running.store(false, Ordering::Relaxed);
        self.wake.notify();

        // Wait for thread to finish
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
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
    /// The thread waits for TUN readiness and cross-thread notifications.
    #[cfg(test)]
    pub fn new(tun_fd: OwnedFd, mtu: usize) -> Self {
        Self::with_config(tun_fd, TunServerConfig::new().mtu(mtu as u16)).unwrap()
    }

    #[cfg(test)]
    pub fn with_config(tun_fd: OwnedFd, config: TunServerConfig) -> io::Result<Self> {
        Self::with_offload(tun_fd, config, false)
    }

    pub fn with_offload(
        tun_fd: OwnedFd,
        config: TunServerConfig,
        offload: bool,
    ) -> io::Result<Self> {
        let fd = tun_fd.as_raw_fd();
        set_nonblocking(fd)?;
        let (wake, wake_rx) = Wake::new()?;
        Self::start(tun_fd, config, wake, wake_rx, offload)
    }

    fn start(
        tun_fd: OwnedFd,
        config: TunServerConfig,
        wake: Wake,
        wake_rx: WakeReceiver,
        offload: bool,
    ) -> io::Result<Self> {
        let fd = tun_fd.as_raw_fd();
        let (udp_tx, udp_rx) = mpsc::channel(PACKET_QUEUE_CAPACITY);

        let running = Arc::new(AtomicBool::new(true));
        let shared_state = Arc::new(Mutex::new(SharedState {
            udp_response_rx: None,
            new_conn_tx: None,
        }));

        let thread_handle = {
            let running = running.clone();
            let shared_state = shared_state.clone();
            let stack_wake = wake.clone();

            thread::Builder::new()
                .name("shoes-smoltcp-direct".to_owned())
                .spawn(move || {
                    let result = panic::catch_unwind(AssertUnwindSafe(|| {
                        let mut device =
                            DirectDevice::new(fd, config.mtu as usize, config.packet_information);
                        device.offload = offload;
                        run_direct_stack_thread(
                            device,
                            config,
                            udp_tx,
                            running.clone(),
                            shared_state,
                            stack_wake,
                            wake_rx,
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
                })?
        };

        Ok(Self {
            thread_handle: Some(thread_handle),
            wake,
            running,
            udp_rx: Some(udp_rx),
            shared_state,
            _tun_fd: tun_fd,
        })
    }

    pub fn wake_handle(&self) -> Wake {
        self.wake.clone()
    }

    /// Take the receiver for UDP packets (filtered from TUN by the stack).
    pub fn take_udp_rx(&mut self) -> Option<Receiver<PacketBuffer>> {
        self.udp_rx.take()
    }

    /// Set the channel for UDP responses to write back to TUN.
    pub fn set_udp_response_tx(&mut self, rx: Receiver<PacketBuffer>) {
        if let Ok(mut state) = self.shared_state.lock() {
            state.udp_response_rx = Some(rx);
        }
        self.wake.notify();
    }

    /// Set the channel for notifying about new TCP connections.
    pub fn set_new_conn_tx(&mut self, tx: mpsc::UnboundedSender<NewTcpConnection>) {
        if let Ok(mut state) = self.shared_state.lock() {
            state.new_conn_tx = Some(tx);
        }
        self.wake.notify();
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
    pending_rx: Option<PacketBuffer>,
    tx_buffer: Vec<u8>,
    packet_information: bool,
    offload: bool,
    gso_packets: u64,
}

impl DirectDevice {
    fn new(fd: RawFd, mtu: usize, packet_information: bool) -> Self {
        Self {
            fd,
            mtu,
            pending_rx: None,
            tx_buffer: Vec::with_capacity(mtu),
            packet_information,
            offload: false,
            gso_packets: 0,
        }
    }

    /// Try to read a packet (non-blocking) using pooled buffer.
    /// Returns:
    /// - Ok(Some(packet)) if a packet was read
    /// - Ok(None) if no packet was available (WouldBlock)
    /// - Err(e) if a fatal error occurred (including EOF)
    fn try_recv(&mut self) -> io::Result<Option<PacketBuffer>> {
        if let Some(pkt) = self.pending_rx.take() {
            return Ok(Some(pkt));
        }

        // Get a buffer from the pool
        let length = self.mtu
            + if self.offload {
                super::offload::HEADER_LEN + 1
            } else {
                4
            };
        let mut buffer = PacketBuffer::with_capacity(length);
        buffer.resize(length);

        match read_nonblocking(self.fd, &mut buffer) {
            Ok(n) if n > 0 => {
                buffer.truncate(n);
                if self.offload {
                    super::offload::validate_rx(&buffer, self.mtu)?;
                    buffer.retain_range(super::offload::HEADER_LEN..n);
                }
                if self.packet_information {
                    if n < 5 || buffer[..4] != packet_header(buffer[4])? {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid TUN packet information",
                        ));
                    }
                    buffer.retain_range(4..n);
                }
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
    fn store_packet(&mut self, pkt: PacketBuffer) {
        self.pending_rx = Some(pkt);
    }

    /// Write a packet to TUN.
    fn write_packet(&self, data: &[u8]) -> io::Result<()> {
        if self.offload {
            write_framed_packet(self.fd, data, &[0; super::offload::HEADER_LEN]).map(|_| ())
        } else {
            write_packet(self.fd, data, self.packet_information)
        }
    }
}

impl Device for DirectDevice {
    type RxToken<'a> = DirectRxToken;
    type TxToken<'a> = DirectTxToken<'a>;

    fn receive(
        &mut self,
        timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buffer = self.pending_rx.take()?;
        let rx = DirectRxToken { buffer };
        let tx = self.transmit(timestamp)?;
        Some((rx, tx))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(DirectTxToken {
            fd: self.fd,
            packet_information: self.packet_information,
            buffer: &mut self.tx_buffer,
            offload: self.offload,
            segment_size: None,
            gso_packets: &mut self.gso_packets,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.checksum.ipv4 = smoltcp::phy::Checksum::Tx;
        caps.checksum.tcp = smoltcp::phy::Checksum::Tx;
        if self.offload {
            caps.checksum.tcp = smoltcp::phy::Checksum::None;
            caps.segmentation.tcpv4 = std::num::NonZeroUsize::new(super::offload::MAX_PACKET_LEN);
            // smoltcp 0.14 does not forward IPv6 segmentation metadata.
            caps.segmentation.tcpv6 = None;
        }
        caps.checksum.udp = smoltcp::phy::Checksum::Tx;
        caps.checksum.icmpv4 = smoltcp::phy::Checksum::Tx;
        caps.checksum.icmpv6 = smoltcp::phy::Checksum::Tx;
        caps
    }
}

struct DirectRxToken {
    buffer: PacketBuffer,
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

struct DirectTxToken<'a> {
    fd: RawFd,
    packet_information: bool,
    buffer: &'a mut Vec<u8>,
    offload: bool,
    segment_size: Option<std::num::NonZeroU16>,
    gso_packets: &'a mut u64,
}

impl TxToken for DirectTxToken<'_> {
    fn set_meta(&mut self, meta: smoltcp::phy::PacketMeta) {
        self.segment_size = meta.segmentation_offload_size;
    }

    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        self.buffer.clear();
        self.buffer.resize(len, 0);
        let result = f(self.buffer);

        let write_result = if self.offload {
            super::offload::tx_header(self.buffer, self.segment_size)
                .and_then(|header| write_framed_packet(self.fd, self.buffer, &header))
        } else {
            write_packet(self.fd, self.buffer, self.packet_information).map(|_| true)
        };
        if self.segment_size.is_some() && matches!(write_result, Ok(true)) {
            *self.gso_packets += 1;
            if *self.gso_packets == 1 {
                info!("TUN TCPv4 transmit segmentation active");
            }
        }
        if let Err(e) = write_result {
            warn!("Failed to write to TUN: {}", e);
        }

        result
    }
}

const MAX_PACKET_BATCH: usize = 64;
const MAX_EGRESS_SWEEPS: usize = 8;

/// Run the direct smoltcp stack thread.
fn run_direct_stack_thread(
    mut device: DirectDevice,
    config: TunServerConfig,
    udp_tx: Sender<PacketBuffer>,
    running: Arc<AtomicBool>,
    shared_state: Arc<Mutex<SharedState>>,
    stack_wake: Wake,
    mut wake_rx: WakeReceiver,
) {
    info!("smoltcp direct stack thread initializing...");

    let limits = &config.resource_limits;

    let mut iface_config = InterfaceConfig::new(HardwareAddress::Ip);
    iface_config.random_seed = rand::random();

    let mut iface = Interface::new(iface_config, &mut device, stack_now());

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
    let mut active_connections = HashSet::new();

    let mut poll_count: u64 = 0;
    let mut last_log_time = std::time::Instant::now();

    let mut wait_error_count: u32 = 0;
    const MAX_WAIT_ERRORS: u32 = 10;
    let mut udp_response_rx = None;
    let mut new_conn_tx = None;

    info!("smoltcp direct stack thread started, entering main loop");

    while running.load(Ordering::Relaxed) {
        if let Err(error) = wake_rx.drain() {
            error!("TUN wake channel failed: {error}");
            break;
        }
        if let Ok(mut state) = shared_state.lock() {
            if let Some(rx) = state.udp_response_rx.take() {
                udp_response_rx = Some(rx);
            }
            if let Some(tx) = state.new_conn_tx.take() {
                new_conn_tx = Some(tx);
            }
        }
        let mut responses_written = 0;
        if let Some(ref mut udp_rx) = udp_response_rx {
            for _ in 0..MAX_PACKET_BATCH {
                let Ok(pkt) = udp_rx.try_recv() else { break };
                responses_written += 1;
                if let Err(e) = device.write_packet(&pkt) {
                    warn!("Failed to write UDP response to TUN: {}", e);
                }
            }
        }

        // Reads packets from TUN and filters by protocol (batch processing).
        let mut stack_packets = Vec::new();
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
                    IpProtocol::Tcp if config.tcp_enabled => {
                        match extract_tcp_info(&pkt) {
                            Some((src_addr, dst_addr, is_syn)) => {
                                trace!("TCP packet: {} -> {}, SYN={}", src_addr, dst_addr, is_syn);
                                if is_syn && !active_connections.contains(&(src_addr, dst_addr)) {
                                    // Check connection limit
                                    if let Some(limit) = limits.tcp_connection_limit()
                                        && sockets.len() >= limit
                                    {
                                        warn!(
                                            "Connection limit reached ({}), dropping SYN from {}",
                                            limit, src_addr
                                        );
                                        continue;
                                    }

                                    info!("New TCP SYN: {} -> {}", src_addr, dst_addr);

                                    if let Some((new_conn, control)) = create_tcp_connection(
                                        src_addr,
                                        dst_addr,
                                        &mut socket_set,
                                        &stack_wake,
                                        limits.tcp_buffer_size,
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

                                        publish_connection(
                                            new_conn.new_tcp_conn,
                                            &mut new_conn_tx,
                                            &shared_state,
                                        );
                                    }
                                }
                            }
                            None => {
                                warn!("Failed to parse TCP packet, len={}", pkt.len());
                            }
                        }

                        stack_packets.push(pkt);
                    }
                    IpProtocol::Icmp | IpProtocol::Icmpv6 if config.icmp_enabled => {
                        stack_packets.push(pkt);
                    }
                    IpProtocol::Udp if config.udp_enabled => {
                        let _ = udp_tx.try_send(pkt);
                    }
                    _ => {
                        trace!("ignoring packet with protocol {:?}", protocol);
                    }
                }
            }
        }

        if packets_read > 0 {
            wait_error_count = 0;
        }

        // Skip remaining work if a fatal read error was detected above.
        if !running.load(Ordering::Relaxed) {
            break;
        }

        iface.poll_maintenance(stack_now());
        for pkt in stack_packets {
            device.store_packet(pkt);
            iface.poll_ingress_single(stack_now(), &mut device, &mut socket_set);
        }

        for (handle, socket_info) in sockets.iter() {
            let handle = *handle;
            let control = &socket_info.control;
            let socket = socket_set.get_mut::<TcpSocket>(handle);

            if control.is_abandoned() {
                socket.abort();
            }

            if socket.state() == TcpState::Closed {
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

        // Amortizes loop overhead without starving later sockets or draining indefinitely.
        for _ in 0..MAX_EGRESS_SWEEPS {
            if iface.poll_egress(stack_now(), &mut device, &mut socket_set)
                == smoltcp::iface::PollResult::None
            {
                break;
            }
        }
        let has_local_work =
            reconcile_sockets(&mut sockets, &mut socket_set, &mut active_connections);

        poll_count += 1;
        if last_log_time.elapsed() >= Duration::from_secs(30) {
            debug!(
                "smoltcp direct stack: polls={}, active_sockets={}",
                poll_count,
                sockets.len()
            );
            last_log_time = std::time::Instant::now();
        }

        if packets_read >= MAX_PACKET_BATCH
            || responses_written >= MAX_PACKET_BATCH
            || has_local_work
        {
            continue;
        }

        let delay = iface.poll_delay(stack_now(), &socket_set);
        #[cfg(test)]
        if let Some(gate) = wake_rx.before_wait.take() {
            assert!(delay.is_none(), "idle test must not rely on a timer wakeup");
            gate.pause();
        }
        match wake_rx.wait(device.fd, delay.map(Into::into)) {
            Ok(_) => wait_error_count = 0,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                wait_error_count += 1;
                if wait_error_count >= MAX_WAIT_ERRORS {
                    error!(
                        "TUN poll failed {wait_error_count} consecutive times (last: {e}). Stack thread stopping."
                    );
                    break;
                }
                warn!("TUN poll error ({wait_error_count}): {e}");
            }
        }
    }

    info!("smoltcp direct stack thread stopped");
}

fn stack_now() -> SmolInstant {
    std::time::Instant::now().into()
}

fn publish_connection(
    connection: NewTcpConnection,
    sender: &mut Option<mpsc::UnboundedSender<NewTcpConnection>>,
    shared_state: &Mutex<SharedState>,
) {
    // Setup can publish the handler after this iteration's initial snapshot.
    if sender.is_none()
        && let Ok(mut state) = shared_state.lock()
    {
        *sender = state.new_conn_tx.take();
    }
    if let Some(sender) = sender {
        let _ = sender.send(connection);
    }
}

fn reconcile_sockets(
    sockets: &mut HashMap<SocketHandle, SocketInfo>,
    socket_set: &mut SocketSet<'_>,
    active_connections: &mut HashSet<(SocketAddr, SocketAddr)>,
) -> bool {
    let mut has_local_work = false;
    sockets.retain(|handle, info| {
        let socket = socket_set.get::<TcpSocket>(*handle);
        let is_closed = socket.state() == TcpState::Closed;
        // Timer expiry can close a socket without poll_egress reporting progress.
        // A retained tuple on a closed socket still needs its reset dispatched.
        if is_closed && socket.remote_endpoint().is_none() {
            active_connections.remove(&(info.src_addr, info.dst_addr));
            socket_set.remove(*handle);
            return false;
        }
        let control = &info.control;
        has_local_work |= (!is_closed && control.is_abandoned())
            || (socket.can_recv() && !control.recv_buffer_full())
            || (socket.can_send() && !control.send_buffer_empty())
            || (!is_closed
                && control.send_state() == TcpSocketState::Close
                && control.send_buffer_empty()
                && socket.send_queue() == 0);
        true
    });
    has_local_work
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
    wake: &Wake,
    buffer_size: usize,
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
    let connection = TcpConnection::new(control.clone(), wake.clone());

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

fn packet_header(first_byte: u8) -> io::Result<[u8; 4]> {
    let version = first_byte >> 4;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let protocol = match version {
        4 => libc::AF_INET as u32,
        6 => libc::AF_INET6 as u32,
        _ => 0,
    };
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let protocol: u32 = match version {
        4 => 0x0800,
        6 => 0x86dd,
        _ => 0,
    };
    if protocol == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid IP version",
        ));
    }
    Ok(protocol.to_be_bytes())
}

fn write_packet(fd: RawFd, data: &[u8], packet_information: bool) -> io::Result<()> {
    let header = match data.first() {
        Some(first) if packet_information => Some(packet_header(*first)?),
        _ => None,
    };
    write_framed_packet(fd, data, header.as_ref().map_or(&[], |v| &v[..])).map(|_| ())
}

fn write_framed_packet(fd: RawFd, data: &[u8], header: &[u8]) -> io::Result<bool> {
    write_framed_packet_with(data, header, |header, payload| {
        let n = if header.is_empty() {
            unsafe { libc::write(fd, payload.as_ptr().cast(), payload.len()) }
        } else {
            let buffers = [
                libc::iovec {
                    iov_base: header.as_ptr().cast_mut().cast(),
                    iov_len: header.len(),
                },
                libc::iovec {
                    iov_base: payload.as_ptr().cast_mut().cast(),
                    iov_len: payload.len(),
                },
            ];
            unsafe { libc::writev(fd, buffers.as_ptr(), buffers.len() as libc::c_int) }
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    })
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

#[cfg(test)]
fn write_packet_with(
    data: &[u8],
    packet_information: bool,
    write: impl FnMut(&[u8], &[u8]) -> io::Result<usize>,
) -> io::Result<()> {
    let Some(&first_byte) = data.first() else {
        return Ok(());
    };
    let header = if packet_information {
        Some(packet_header(first_byte)?)
    } else {
        None
    };
    let header = header.as_ref().map_or(&[][..], |header| &header[..]);
    write_framed_packet_with(data, header, write).map(|_| ())
}

fn write_framed_packet_with(
    data: &[u8],
    header: &[u8],
    mut write: impl FnMut(&[u8], &[u8]) -> io::Result<usize>,
) -> io::Result<bool> {
    if data.is_empty() {
        return Ok(false);
    }
    let length = header.len() + data.len();
    loop {
        match write(header, data) {
            Ok(n) if n == length => return Ok(true),
            // A suffix write would become a second, malformed TUN packet.
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short TUN packet write",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if error.raw_os_error() == Some(libc::ENOBUFS)
                    || error.kind() == io::ErrorKind::WouldBlock =>
            {
                trace!("TUN write {}, packet dropped", error);
                return Ok(false);
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_gate::{GateControl, TestGate};
    use super::*;
    use std::os::unix::io::IntoRawFd;
    use std::os::unix::net::{UnixDatagram, UnixStream};

    #[test]
    fn dropped_framed_writes_are_not_counted_as_transmitted() {
        for error in [libc::EAGAIN, libc::ENOBUFS] {
            assert!(
                !write_framed_packet_with(b"packet", &[0; 10], |_, _| {
                    Err(io::Error::from_raw_os_error(error))
                })
                .unwrap()
            );
        }
        assert!(
            write_framed_packet_with(b"packet", &[0; 10], |header, data| {
                Ok(header.len() + data.len())
            })
            .unwrap()
        );
    }

    #[test]
    fn interface_forwards_ipv4_segmentation_and_keeps_ipv6_mtu() {
        for ipv6 in [false, true] {
            let (peer, tun) = UnixDatagram::pair().unwrap();
            let frame_capacity =
                super::super::offload::HEADER_LEN + super::super::offload::MAX_PACKET_LEN;
            // macOS defaults cannot hold a full offloaded datagram.
            socket2::SockRef::from(&tun)
                .set_send_buffer_size(frame_capacity)
                .unwrap();
            socket2::SockRef::from(&peer)
                .set_recv_buffer_size(frame_capacity)
                .unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let mut device = DirectDevice::new(tun.as_raw_fd(), 1500, false);
            device.offload = true;
            let now = SmolInstant::from_millis(1);
            let mut iface =
                Interface::new(InterfaceConfig::new(HardwareAddress::Ip), &mut device, now);
            let (src, dst): (SocketAddr, SocketAddr) = if ipv6 {
                (
                    "[fd00::2]:1001".parse().unwrap(),
                    "[fd00::3]:443".parse().unwrap(),
                )
            } else {
                (
                    "192.0.2.1:1001".parse().unwrap(),
                    "198.51.100.2:443".parse().unwrap(),
                )
            };
            iface.update_ip_addrs(|addresses| {
                addresses.push(IpCidr::new(dst.ip().into(), 0)).unwrap();
            });
            let mut sockets = SocketSet::new(vec![]);
            let (connection, _) =
                create_tcp_connection(src, dst, &mut sockets, &Wake::new().unwrap().0, 65536)
                    .unwrap();
            let packet = |ack: Option<u32>| {
                let builder = match (src.ip(), dst.ip()) {
                    (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) => {
                        etherparse::PacketBuilder::ipv4(src.octets(), dst.octets(), 64)
                    }
                    (std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst)) => {
                        etherparse::PacketBuilder::ipv6(src.octets(), dst.octets(), 64)
                    }
                    _ => unreachable!(),
                };
                let tcp = builder.tcp(1001, 443, if ack.is_some() { 102 } else { 101 }, 65535);
                let tcp = if let Some(ack) = ack {
                    tcp.ack(ack)
                } else {
                    tcp.syn()
                };
                let mut data = Vec::new();
                tcp.write(&mut data, b"").unwrap();
                PacketBuffer::copy_from_slice(&data)
            };
            device.store_packet(packet(None));
            iface.poll(now, &mut device, &mut sockets);
            let mut frame = vec![0; frame_capacity];
            let n = peer.recv(&mut frame).unwrap();
            let ip_len = if ipv6 { 40 } else { 20 };
            let syn_ack = TcpPacket::new_checked(&frame[10 + ip_len..n]).unwrap();
            let ack = (syn_ack.seq_number().0 as u32).wrapping_add(1);
            device.store_packet(packet(Some(ack)));
            iface.poll(now, &mut device, &mut sockets);
            let socket = sockets.get_mut::<TcpSocket>(connection.handle);
            assert_eq!(socket.state(), TcpState::Established);
            socket.send_slice(&vec![23; 16001]).unwrap();
            iface.poll_egress(now, &mut device, &mut sockets);
            let n = peer.recv(&mut frame).unwrap();
            assert_eq!(frame[0], 1);
            if ipv6 {
                assert!(n <= 1510);
                assert_eq!(frame[1], 0);
                assert_eq!(device.gso_packets, 0);
            } else {
                assert!(n > 1510, "native segmentation not used: {n}");
                assert_eq!(frame[1], 1);
                assert_eq!(device.gso_packets, 1);
            }
        }
    }

    #[test]
    fn virtio_framing_is_present_on_udp_and_validated_on_ingress() {
        let (peer, tun) = UnixDatagram::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut device = DirectDevice::new(tun.as_raw_fd(), 1500, false);
        device.offload = true;
        let packet = [0x45, 1, 2, 3];
        device.write_packet(&packet).unwrap();
        let mut frame = [0; 64];
        let n = peer.recv(&mut frame).unwrap();
        assert_eq!(n, 14);
        assert_eq!(&frame[..10], &[0; 10]);
        peer.send(&frame[..n]).unwrap();
        assert_eq!(&device.try_recv().unwrap().unwrap()[..], &packet);
        frame[0] = 1;
        peer.send(&frame[..n]).unwrap();
        assert!(device.try_recv().is_err());
    }

    fn stack_at_wait(tun: OwnedFd) -> (TcpStackDirect, GateControl) {
        let (wake, mut receiver) = Wake::new().unwrap();
        let (gate, control) = TestGate::new();
        receiver.before_wait = Some(gate);
        set_nonblocking(tun.as_raw_fd()).unwrap();
        let stack =
            TcpStackDirect::start(tun, TunServerConfig::new(), wake, receiver, false).unwrap();
        control.wait();
        (stack, control)
    }

    #[test]
    fn handler_published_after_setup_snapshot_receives_the_connection() {
        let state = Mutex::new(SharedState {
            udp_response_rx: None,
            new_conn_tx: None,
        });
        let mut snapshot = state.lock().unwrap().new_conn_tx.take();
        assert!(snapshot.is_none());
        let (sender, mut receiver) = mpsc::unbounded_channel();
        state.lock().unwrap().new_conn_tx = Some(sender);

        let (wake, _wake_rx) = Wake::new().unwrap();
        let control = Arc::new(TcpConnectionControl::new(1024, 1024));
        let address = "192.0.2.1:443".parse().unwrap();
        publish_connection(
            NewTcpConnection {
                connection: TcpConnection::new(control.clone(), wake),
                remote_addr: address,
            },
            &mut snapshot,
            &state,
        );
        let connection = receiver.try_recv().unwrap();
        assert_eq!(connection.remote_addr, address);
        assert!(!control.is_abandoned());
        assert!(snapshot.is_some());
        assert!(state.lock().unwrap().new_conn_tx.is_none());
    }

    #[test]
    fn transmit_storage_is_reused_and_initialized() {
        let (peer, tun) = UnixDatagram::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut device = DirectDevice::new(tun.as_raw_fd(), 1500, false);
        let pointer = device.tx_buffer.as_ptr();
        for length in [1000, 100, 1500] {
            let token = device.transmit(stack_now()).unwrap();
            let result = token.consume(length, |buffer| {
                assert_eq!(buffer.as_ptr(), pointer);
                assert!(buffer.iter().all(|&byte| byte == 0));
                buffer.fill(42);
                123
            });
            assert_eq!(result, 123);
            let mut received = [0; 1500];
            assert_eq!(peer.recv(&mut received).unwrap(), length);
            assert!(received[..length].iter().all(|&byte| byte == 42));
        }
    }

    #[test]
    fn packet_writes_retry_only_interruptions_and_never_a_suffix() {
        let payload = [0x45, 1, 2, 3, 4];
        for framed in [false, true] {
            let expected_header = if framed {
                packet_header(payload[0]).unwrap().to_vec()
            } else {
                Vec::new()
            };
            let expected_length = payload.len() + expected_header.len();
            let mut attempts = 0;
            write_packet_with(&payload, framed, |header, data| {
                assert_eq!(header, expected_header);
                assert_eq!(data, payload);
                attempts += 1;
                if attempts < 3 {
                    Err(io::Error::from_raw_os_error(libc::EINTR))
                } else {
                    Ok(expected_length)
                }
            })
            .unwrap();
            assert_eq!(attempts, 3);

            for length in 0..expected_length {
                let mut attempts = 0;
                let error = write_packet_with(&payload, framed, |_, _| {
                    attempts += 1;
                    Ok(length)
                })
                .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::WriteZero);
                assert_eq!(attempts, 1);
            }
            for code in [libc::EAGAIN, libc::ENOBUFS, libc::EIO] {
                let mut attempts = 0;
                let result = write_packet_with(&payload, framed, |_, _| {
                    attempts += 1;
                    Err(io::Error::from_raw_os_error(code))
                });
                assert_eq!(attempts, 1);
                if code == libc::EIO {
                    assert_eq!(result.unwrap_err().raw_os_error(), Some(code));
                } else {
                    result.unwrap();
                }
            }
            write_packet_with(&[], framed, |_, _| panic!("empty packet write")).unwrap();
        }
    }

    #[test]
    fn time_wait_cleanup_does_not_depend_on_egress_progress() {
        use smoltcp::iface::PollResult;

        let (peer, tun) = UnixDatagram::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut device = DirectDevice::new(tun.as_raw_fd(), 1500, false);
        let mut iface = Interface::new(
            InterfaceConfig::new(HardwareAddress::Ip),
            &mut device,
            SmolInstant::from_millis(0),
        );
        iface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(IpAddress::v4(1, 1, 1, 1), 0))
                .unwrap();
        });
        let mut socket_set = SocketSet::new(vec![]);
        let src_addr = "10.0.0.2:10001".parse().unwrap();
        let dst_addr = "1.1.1.1:443".parse().unwrap();
        let (connection, control) = create_tcp_connection(
            src_addr,
            dst_addr,
            &mut socket_set,
            &Wake::new().unwrap().0,
            4096,
        )
        .unwrap();
        let handle = connection.handle;
        let mut sockets = HashMap::from([(
            handle,
            SocketInfo {
                control: control.clone(),
                src_addr,
                dst_addr,
            },
        )]);
        let mut active = HashSet::from([(src_addr, dst_addr)]);
        let ingress =
            |iface: &mut Interface,
             device: &mut DirectDevice,
             sockets: &mut SocketSet<'_>,
             ack: Option<u32>,
             fin| {
                let mut builder = etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64)
                    .tcp(10001, 443, if ack.is_some() { 102 } else { 101 }, 4096);
                builder = if let Some(ack) = ack {
                    builder.ack(ack)
                } else {
                    builder.syn()
                };
                if fin {
                    builder = builder.fin();
                }
                let mut packet = Vec::new();
                builder.write(&mut packet, b"").unwrap();
                device.store_packet(PacketBuffer::copy_from_slice(&packet));
                iface.poll_ingress_single(SmolInstant::from_millis(1), device, sockets);
            };
        ingress(&mut iface, &mut device, &mut socket_set, None, false);
        iface.poll_egress(SmolInstant::from_millis(1), &mut device, &mut socket_set);
        let mut data = [0; 1500];
        let length = peer.recv(&mut data).unwrap();
        let ip = Ipv4Packet::new_checked(&data[..length]).unwrap();
        let syn_ack = TcpPacket::new_checked(ip.payload()).unwrap();
        let acknowledgement = (syn_ack.seq_number().0 as u32).wrapping_add(1);
        ingress(
            &mut iface,
            &mut device,
            &mut socket_set,
            Some(acknowledgement),
            false,
        );
        socket_set.get_mut::<TcpSocket>(handle).close();
        iface.poll_egress(SmolInstant::from_millis(1), &mut device, &mut socket_set);
        ingress(
            &mut iface,
            &mut device,
            &mut socket_set,
            Some(acknowledgement.wrapping_add(1)),
            true,
        );
        assert_eq!(
            socket_set.get::<TcpSocket>(handle).state(),
            TcpState::TimeWait
        );
        iface.poll_egress(SmolInstant::from_millis(1), &mut device, &mut socket_set);

        assert_eq!(
            iface.poll_egress(
                SmolInstant::from_millis(60_001),
                &mut device,
                &mut socket_set
            ),
            PollResult::None
        );
        assert!(!reconcile_sockets(
            &mut sockets,
            &mut socket_set,
            &mut active
        ));
        assert!(sockets.is_empty());
        assert!(active.is_empty());
        assert_eq!(control.recv_state(), TcpSocketState::Closed);
        assert_eq!(control.send_state(), TcpSocketState::Closed);
    }

    #[test]
    fn closed_socket_keeps_its_pending_reset_until_a_complete_egress_sweep() {
        let (peer, tun) = UnixDatagram::pair().unwrap();
        // A full sweep must fit before reads start, including on macOS's smaller default queue.
        socket2::SockRef::from(&peer)
            .set_recv_buffer_size(256 * 1024)
            .unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut device = DirectDevice::new(tun.as_raw_fd(), 1500, false);
        let mut iface = Interface::new(
            InterfaceConfig::new(HardwareAddress::Ip),
            &mut device,
            stack_now(),
        );
        iface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(IpAddress::v4(1, 1, 1, 1), 0))
                .unwrap();
        });
        let mut socket_set = SocketSet::new(vec![]);
        let mut sockets = HashMap::new();
        let mut active = HashSet::new();
        let dst_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
        let mut last_handle = None;
        for port in 10000..10070 {
            let src_addr = SocketAddr::from(([1, 1, 1, 1], port));
            let mut socket = TcpSocket::new(
                TcpSocketBuffer::new(vec![0; 1024]),
                TcpSocketBuffer::new(vec![0; 1024]),
            );
            socket.connect(iface.context(), dst_addr, src_addr).unwrap();
            let handle = socket_set.add(socket);
            sockets.insert(
                handle,
                SocketInfo {
                    control: Arc::new(TcpConnectionControl::new(1024, 1024)),
                    src_addr,
                    dst_addr,
                },
            );
            active.insert((src_addr, dst_addr));
            last_handle = Some(handle);
        }
        let last_handle = last_handle.unwrap();
        socket_set.get_mut::<TcpSocket>(last_handle).abort();
        reconcile_sockets(&mut sockets, &mut socket_set, &mut active);
        assert_eq!(sockets.len(), 70);
        iface.poll_egress(stack_now(), &mut device, &mut socket_set);
        let mut reset = false;
        let mut data = [0; 1500];
        for index in 0..70 {
            let length = peer
                .recv(&mut data)
                .unwrap_or_else(|error| panic!("missing egress packet {index} of 70: {error}"));
            let ip = Ipv4Packet::new_checked(&data[..length]).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            if tcp.src_port() == 10069 {
                reset = tcp.rst();
            }
        }
        assert!(reset);
        reconcile_sockets(&mut sockets, &mut socket_set, &mut active);
        assert_eq!(sockets.len(), 69);
        assert!(!sockets.contains_key(&last_handle));
    }

    #[test]
    fn default_admission_preserves_bursts_beyond_old_queue_and_socket_caps() {
        use std::os::unix::net::UnixDatagram;

        let (peer, tun) = UnixDatagram::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut stack = TcpStackDirect::new(tun.into(), 1500);
        let (tx, mut rx) = mpsc::unbounded_channel();
        stack.set_new_conn_tx(tx);
        let mut buf = [0; 1500];
        for port in 10000..10300 {
            let builder = etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64)
                .tcp(port, 443, 101, 4096);
            let mut syn = Vec::new();
            builder.syn().write(&mut syn, b"").unwrap();
            peer.send(&syn).unwrap();
            let acknowledgement = loop {
                let n = peer.recv(&mut buf).unwrap();
                let ip = Ipv4Packet::new_checked(&buf[..n]).unwrap();
                let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
                assert!(!tcp.rst(), "burst connection was reset");
                if tcp.dst_port() == port && tcp.syn() && tcp.ack() {
                    break (tcp.seq_number().0 as u32).wrapping_add(1);
                }
            };
            let mut ack = Vec::new();
            etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64)
                .tcp(port, 443, 102, 4096)
                .ack(acknowledgement)
                .write(&mut ack, b"")
                .unwrap();
            peer.send(&ack).unwrap();
        }
        assert_eq!(rx.len(), 300);
        let connections: Vec<_> = (0..300).map(|_| rx.try_recv().unwrap()).collect();
        drop(connections);
    }

    #[tokio::test]
    async fn abandoned_connection_sends_reset_before_releasing_socket() {
        use std::os::unix::net::UnixDatagram;
        use tokio::io::AsyncReadExt;

        let (peer, tun) = UnixDatagram::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut stack = TcpStackDirect::new(tun.into(), 1500);
        let (tx, mut rx) = mpsc::unbounded_channel();
        stack.set_new_conn_tx(tx);
        let packet = |sequence, acknowledgment: Option<u32>, payload: &[u8]| {
            let builder = etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64)
                .tcp(10001, 443, sequence, 4096);
            let builder = match acknowledgment {
                Some(ack) => builder.ack(ack),
                None => builder.syn(),
            };
            let mut bytes = Vec::new();
            builder.write(&mut bytes, payload).unwrap();
            bytes
        };
        let mut buf = [0; 1500];
        peer.send(&packet(101, None, b"")).unwrap();
        let n = peer.recv(&mut buf).unwrap();
        let ip = Ipv4Packet::new_checked(&buf[..n]).unwrap();
        let syn_ack = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(syn_ack.syn() && syn_ack.ack());
        let acknowledgment = (syn_ack.seq_number().0 as u32).wrapping_add(1);
        let mut incoming = rx.recv().await.unwrap();
        peer.send(&packet(102, Some(acknowledgment), b"x")).unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            incoming.connection.read_exact(&mut [0]),
        )
        .await
        .unwrap()
        .unwrap();
        drop(incoming);

        loop {
            let n = peer
                .recv(&mut buf)
                .expect("abandoned connection did not send a reset");
            let ip = Ipv4Packet::new_checked(&buf[..n]).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            if tcp.rst() {
                assert!(!tcp.fin());
                break;
            }
        }
        peer.send(&packet(1001, None, b"")).unwrap();
        let n = peer.recv(&mut buf).unwrap();
        let ip = Ipv4Packet::new_checked(&buf[..n]).unwrap();
        let syn_ack = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(syn_ack.syn() && syn_ack.ack());
        assert_eq!(syn_ack.ack_number().0 as u32, 1002);
    }

    #[test]
    fn packet_information_roundtrips_ipv4_and_ipv6() {
        use std::os::unix::net::UnixDatagram;
        let (peer, tun) = UnixDatagram::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        set_nonblocking(tun.as_raw_fd()).unwrap();
        let mut device = DirectDevice::new(tun.as_raw_fd(), 1500, true);
        for version in [0x45, 0x60] {
            let packet = [version, 1, 2, 3, 4, 5];
            let mut framed = packet_header(version).unwrap().to_vec();
            framed.extend_from_slice(&packet);
            peer.send(&framed).unwrap();
            assert_eq!(&device.try_recv().unwrap().unwrap()[..], &packet);
            device.write_packet(&packet).unwrap();
            let mut buf = [0; 64];
            let n = peer.recv(&mut buf).unwrap();
            assert_eq!(&buf[..n], &framed);
        }
    }

    #[test]
    fn disabled_udp_does_not_reach_async_handler() {
        use std::os::unix::net::UnixDatagram;
        let (peer, tun) = UnixDatagram::pair().unwrap();
        let mut stack =
            TcpStackDirect::with_config(tun.into(), TunServerConfig::new().udp_enabled(false))
                .unwrap();
        let mut rx = stack.take_udp_rx().unwrap();
        let builder =
            etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64).udp(1000, 53);
        let mut packet = Vec::new();
        builder.write(&mut packet, b"dns").unwrap();
        peer.send(&packet).unwrap();
        thread::sleep(Duration::from_millis(40));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn icmp_echo_replies_respect_protocol_switch() {
        use smoltcp::wire::{Icmpv4Message, Icmpv4Packet, Icmpv6Message, Icmpv6Packet};
        use std::os::unix::net::UnixDatagram;

        let ipv4_src = [10, 0, 0, 2];
        let ipv4_dst = [1, 1, 1, 1];
        let ipv6_src = Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let ipv6_dst = Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 3);
        let mut ipv4_request = Vec::new();
        etherparse::PacketBuilder::ipv4(ipv4_src, ipv4_dst, 64)
            .icmpv4_echo_request(17, 23)
            .write(&mut ipv4_request, b"ping")
            .unwrap();
        let mut ipv6_request = Vec::new();
        etherparse::PacketBuilder::ipv6(ipv6_src.octets(), ipv6_dst.octets(), 64)
            .icmpv6_echo_request(17, 23)
            .write(&mut ipv6_request, b"ping")
            .unwrap();

        for enabled in [true, false] {
            let (peer, tun) = UnixDatagram::pair().unwrap();
            peer.set_read_timeout(Some(Duration::from_millis(if enabled {
                1000
            } else {
                200
            })))
            .unwrap();
            let stack = TcpStackDirect::with_config(
                tun.into(),
                TunServerConfig::new().icmp_enabled(enabled),
            )
            .unwrap();
            for request in [&ipv4_request, &ipv6_request] {
                peer.send(request).unwrap();
                let mut response = [0; 1500];
                let result = peer.recv(&mut response);
                if !enabled {
                    assert!(matches!(
                        result.unwrap_err().kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ));
                    assert!(stack.is_running());
                    continue;
                }
                let response = &response[..result.unwrap()];
                if request[0] >> 4 == 4 {
                    let ip = Ipv4Packet::new_checked(response).unwrap();
                    assert_eq!(ip.src_addr().octets(), ipv4_dst);
                    assert_eq!(ip.dst_addr().octets(), ipv4_src);
                    assert!(ip.verify_checksum());
                    let icmp = Icmpv4Packet::new_checked(ip.payload()).unwrap();
                    assert_eq!(icmp.msg_type(), Icmpv4Message::EchoReply);
                    assert_eq!((icmp.echo_ident(), icmp.echo_seq_no()), (17, 23));
                    assert_eq!(icmp.data(), b"ping");
                    assert!(icmp.verify_checksum());
                } else {
                    let ip = Ipv6Packet::new_checked(response).unwrap();
                    assert_eq!(ip.src_addr(), ipv6_dst);
                    assert_eq!(ip.dst_addr(), ipv6_src);
                    let icmp = Icmpv6Packet::new_checked(ip.payload()).unwrap();
                    assert_eq!(icmp.msg_type(), Icmpv6Message::EchoReply);
                    assert_eq!((icmp.echo_ident(), icmp.echo_seq_no()), (17, 23));
                    assert_eq!(icmp.payload(), b"ping");
                    assert!(icmp.verify_checksum(&ip.src_addr(), &ip.dst_addr()));
                }
            }
        }
    }

    #[test]
    fn socket_owner_drop_wakes_readers_and_writers() {
        use futures::task::{ArcWake, waker};
        use std::pin::Pin;
        use std::task::Context;
        use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

        struct WakeFlag(AtomicBool);
        impl ArcWake for WakeFlag {
            fn wake_by_ref(flag: &Arc<Self>) {
                flag.0.store(true, Ordering::Relaxed);
            }
        }
        let flag = Arc::new(WakeFlag(AtomicBool::new(false)));
        let waker = waker(flag.clone());
        let mut cx = Context::from_waker(&waker);
        let control = Arc::new(TcpConnectionControl::new(1, 1));
        let mut conn = TcpConnection::new(control.clone(), Wake::new().unwrap().0);
        let info = SocketInfo {
            control: control.clone(),
            src_addr: "127.0.0.1:1".parse().unwrap(),
            dst_addr: "127.0.0.1:2".parse().unwrap(),
        };
        let mut buf = [0; 1];
        assert!(
            Pin::new(&mut conn)
                .poll_read(&mut cx, &mut ReadBuf::new(&mut buf))
                .is_pending()
        );
        assert!(Pin::new(&mut conn).poll_write(&mut cx, b"a").is_ready());
        assert!(Pin::new(&mut conn).poll_write(&mut cx, b"b").is_pending());
        drop(info);
        assert!(flag.0.load(Ordering::Relaxed));
        assert!(
            Pin::new(&mut conn)
                .poll_read(&mut cx, &mut ReadBuf::new(&mut buf))
                .is_ready()
        );
        assert!(Pin::new(&mut conn).poll_write(&mut cx, b"b").is_ready());
        drop(conn);
        assert!(control.is_abandoned());
    }

    #[test]
    fn idle_stack_delivers_udp_output_without_inbound_traffic() {
        use super::super::udp_handler::{UdpHandler, build_udp_packet};
        let (peer, tun) = UnixDatagram::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let (wake, mut receiver) = Wake::new().unwrap();
        let (setup_gate, setup) = TestGate::new();
        let (wait_gate, waiting) = TestGate::new();
        receiver.before_clear = Some(setup_gate);
        receiver.before_wait = Some(wait_gate);
        wake.notify();
        tun.set_nonblocking(true).unwrap();
        let mut stack =
            TcpStackDirect::start(tun.into(), TunServerConfig::new(), wake, receiver, false)
                .unwrap();
        setup.wait();
        let (tx, rx) = mpsc::channel(PACKET_QUEUE_CAPACITY);
        stack.set_udp_response_tx(rx);
        // Setup coalesces into the drained notification, leaving only the writer able to wake poll.
        drop(setup);
        waiting.wait();
        let (_, from_tun) = mpsc::channel(1);
        let (_, writer) = UdpHandler::new(from_tun, tx, stack.wake_handle()).split();
        let src = "1.1.1.1:53".parse().unwrap();
        let dst = "10.0.0.2:10001".parse().unwrap();
        writer
            .send_sync((PacketBuffer::copy_from_slice(b"reply"), src, dst))
            .unwrap();
        drop(waiting);
        let expected = build_udp_packet(b"reply", src, dst).unwrap();
        let mut reply = [0; 1500];
        let length = peer.recv(&mut reply).unwrap();
        assert_eq!(&reply[..length], &*expected);
    }

    #[test]
    fn one_notification_drains_more_than_one_response_batch() {
        let (peer, tun) = UnixDatagram::pair().unwrap();
        // The entire burst must fit even if the receiving thread is not scheduled yet.
        socket2::SockRef::from(&peer)
            .set_recv_buffer_size(256 * 1024)
            .unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut stack = TcpStackDirect::new(tun.into(), 1500);
        let (tx, rx) = mpsc::channel(2 * MAX_PACKET_BATCH + 1);
        for index in 0..2 * MAX_PACKET_BATCH + 1 {
            tx.try_send(PacketBuffer::copy_from_slice(&[index as u8]))
                .unwrap();
        }
        stack.set_udp_response_tx(rx);
        for index in 0..2 * MAX_PACKET_BATCH + 1 {
            let mut reply = [0; 2];
            let length = peer
                .recv(&mut reply)
                .unwrap_or_else(|error| panic!("response {index}: {error}"));
            assert_eq!(length, 1);
            assert_eq!(reply[0], index as u8);
        }
    }

    #[test]
    fn setup_published_after_the_snapshot_interrupts_the_idle_wait() {
        let (peer, tun) = UnixDatagram::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let (mut stack, gate) = stack_at_wait(tun.into());
        let (tx, rx) = mpsc::channel(1);
        tx.try_send(PacketBuffer::copy_from_slice(b"reply"))
            .unwrap();
        stack.set_udp_response_tx(rx);
        drop(gate);
        let mut reply = [0; 5];
        assert_eq!(peer.recv(&mut reply).unwrap(), 5);
        assert_eq!(&reply, b"reply");
    }

    #[test]
    fn retransmission_deadline_runs_without_new_input() {
        let (peer, tun) = UnixDatagram::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut stack = TcpStackDirect::new(tun.into(), 1500);
        let (tx, mut rx) = mpsc::unbounded_channel();
        stack.set_new_conn_tx(tx);
        let mut syn = Vec::new();
        etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64)
            .tcp(10001, 443, 101, 4096)
            .syn()
            .write(&mut syn, b"")
            .unwrap();
        peer.send(&syn).unwrap();
        let _connection = rx.blocking_recv().unwrap();
        let mut buf = [0; 1500];
        let mut sequence = None;
        for _ in 0..2 {
            let length = peer.recv(&mut buf).unwrap();
            let ip = Ipv4Packet::new_checked(&buf[..length]).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            assert!(tcp.syn() && tcp.ack());
            if let Some(sequence) = sequence {
                assert_eq!(tcp.seq_number(), sequence);
            }
            sequence = Some(tcp.seq_number());
        }
    }

    #[test]
    fn test_stack_shutdown_on_eof() {
        let (server, client) = UnixStream::pair().expect("Failed to create socket pair");
        let stack = TcpStackDirect::new(client.into(), 1500);

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
    fn idle_stack_drop_does_not_require_incoming_io() {
        let (peer, client) = UnixStream::pair().unwrap();
        let (stack, gate) = stack_at_wait(client.into());
        let (tx, rx) = std::sync::mpsc::channel();
        let dropper = thread::spawn(move || {
            drop(stack);
            let _ = tx.send(());
        });
        drop(gate);
        let result = rx.recv_timeout(Duration::from_secs(5));
        drop(peer);
        dropper.join().unwrap();
        assert!(result.is_ok());
    }

    #[test]
    fn test_stack_exits_promptly() {
        // Verifies the stack exits within 1 second of EOF, catching
        // regressions that would cause CPU spin on a dead fd.
        let (server, client) = UnixStream::pair().expect("Failed to create socket pair");
        let stack = TcpStackDirect::new(client.into(), 1500);

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
    fn test_write_packet_eagain() {
        // Fill a non-blocking socket's write buffer, then verify write_packet
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

        // Now write_packet should drop the packet gracefully
        let result = write_packet(writer_fd, &[1, 2, 3], false);
        assert!(
            result.is_ok(),
            "write_packet should return Ok on EAGAIN, got {:?}",
            result
        );

        unsafe { libc::close(writer_fd) };
        drop(reader);
    }
}
