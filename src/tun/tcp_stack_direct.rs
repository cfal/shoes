//! Direct TCP Stack Manager for smoltcp integration.
//!
//! This module manages the smoltcp TCP/IP stack in a dedicated OS thread,
//! using `poll()` on TUN and wake fds for event-driven I/O.

use std::{
    collections::HashMap,
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

use log::{debug, info, trace, warn};
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp::{Socket as TcpSocket, State as TcpState},
    time::Instant as SmolInstant,
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address,
        Ipv6Packet, TcpPacket,
    },
};
use tokio::sync::{
    mpsc::{self, Receiver, Sender},
    oneshot,
};

use super::TunServerConfig;
use super::packet::PacketBuffer;
use super::tcp_conn::{TcpConnection, TcpConnectionControl, TcpSocketState};
use super::wake::{Wake, WakeReceiver};

pub const PACKET_QUEUE_CAPACITY: usize = 64;

/// Tracks socket info including addresses for proper cleanup.
struct SocketInfo {
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
    control: Arc<TcpConnectionControl>,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    pending: Option<NewTcpConnection>,
}

impl SocketInfo {
    fn pump(
        &mut self,
        handle: SocketHandle,
        socket: &mut TcpSocket<'_>,
        accepted: &mpsc::UnboundedSender<NewTcpConnection>,
        now: SmolInstant,
    ) {
        if matches!(socket.state(), TcpState::Established | TcpState::CloseWait)
            && let Some(connection) = self.pending.take()
        {
            socket.set_timeout(Some(crate::ip_stack::TCP_PEER_SILENCE_TIMEOUT));
            let _ = accepted.send(connection);
        }
        crate::ip_stack::pump_tcp(handle, socket, &self.control, now);
    }
}

impl Drop for SocketInfo {
    fn drop(&mut self) {
        self.control.set_closed();
    }
}

/// Information about a new TCP connection from the stack.
pub struct NewTcpConnection {
    pub connection: TcpConnection,
    pub source_addr: SocketAddr,
    pub remote_addr: SocketAddr,
}

struct StackChannels {
    admission: Option<Arc<tokio::sync::Semaphore>>,
    udp: Sender<PacketBuffer>,
    tcp: mpsc::UnboundedSender<NewTcpConnection>,
    ready: oneshot::Sender<()>,
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
    tcp_rx: Option<mpsc::UnboundedReceiver<NewTcpConnection>>,
    ready: Option<oneshot::Receiver<()>>,
    completion: oneshot::Receiver<io::Result<()>>,
    /// Receiver waiting for handoff to the stack thread.
    pending_udp_response_rx: Arc<Mutex<Option<Receiver<PacketBuffer>>>>,
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
        Self::with_offload(tun_fd, config, false, None)
    }

    pub fn with_offload(
        tun_fd: OwnedFd,
        config: TunServerConfig,
        offload: bool,
        admission: Option<Arc<tokio::sync::Semaphore>>,
    ) -> io::Result<Self> {
        let fd = tun_fd.as_raw_fd();
        set_nonblocking(fd)?;
        let (wake, wake_rx) = Wake::new()?;
        Self::start(tun_fd, config, wake, wake_rx, offload, admission)
    }

    fn start(
        tun_fd: OwnedFd,
        config: TunServerConfig,
        wake: Wake,
        wake_rx: WakeReceiver,
        offload: bool,
        admission: Option<Arc<tokio::sync::Semaphore>>,
    ) -> io::Result<Self> {
        let fd = tun_fd.as_raw_fd();
        let (udp_tx, udp_rx) = mpsc::channel(PACKET_QUEUE_CAPACITY);
        let (tcp_tx, tcp_rx) = mpsc::unbounded_channel();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (completion_tx, completion) = oneshot::channel();

        let running = Arc::new(AtomicBool::new(true));
        let pending_udp_response_rx = Arc::new(Mutex::new(None));

        let thread_handle = {
            let running = running.clone();
            let pending_udp_response_rx = pending_udp_response_rx.clone();
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
                            StackChannels {
                                admission,
                                udp: udp_tx,
                                tcp: tcp_tx,
                                ready: ready_tx,
                            },
                            running.clone(),
                            pending_udp_response_rx,
                            stack_wake,
                            wake_rx,
                        )
                    }));

                    let result = match result {
                        Ok(result) => result,
                        Err(panic_info) => {
                            let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                                s.to_string()
                            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                                s.clone()
                            } else {
                                "Unknown panic".to_string()
                            };
                            Err(io::Error::other(format!(
                                "TUN stack thread panicked: {msg}"
                            )))
                        }
                    };

                    running.store(false, Ordering::Relaxed);
                    let _ = completion_tx.send(result);
                })?
        };

        Ok(Self {
            thread_handle: Some(thread_handle),
            wake,
            running,
            udp_rx: Some(udp_rx),
            tcp_rx: Some(tcp_rx),
            ready: Some(ready_rx),
            completion,
            pending_udp_response_rx,
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

    pub fn take_tcp_rx(&mut self) -> Option<mpsc::UnboundedReceiver<NewTcpConnection>> {
        self.tcp_rx.take()
    }

    pub async fn ready(&mut self) -> io::Result<()> {
        let ready = self.ready.take().expect("stack readiness already consumed");
        if ready.await.is_err() {
            self.finished().await?;
            return Err(io::Error::other("TUN stack stopped during initialization"));
        }
        Ok(())
    }

    pub async fn finished(&mut self) -> io::Result<()> {
        (&mut self.completion)
            .await
            .map_err(|_| io::Error::other("TUN stack lost its completion result"))?
    }

    /// Set the channel for UDP responses to write back to TUN.
    pub fn set_udp_response_tx(&mut self, rx: Receiver<PacketBuffer>) {
        if let Ok(mut pending) = self.pending_udp_response_rx.lock() {
            *pending = Some(rx);
        }
        self.wake.notify();
    }

    /// Check if the stack thread is still running.
    #[cfg(test)]
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
    tx_error: Option<io::Error>,
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
            tx_error: None,
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
            error: &mut self.tx_error,
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
    error: &'a mut Option<io::Error>,
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
            self.error.get_or_insert(e);
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
    channels: StackChannels,
    running: Arc<AtomicBool>,
    pending_udp_response_rx: Arc<Mutex<Option<Receiver<PacketBuffer>>>>,
    stack_wake: Wake,
    mut wake_rx: WakeReceiver,
) -> io::Result<()> {
    let StackChannels {
        admission,
        udp: udp_tx,
        tcp: tcp_tx,
        ready,
    } = channels;
    let mut ready = Some(ready);
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
    let mut active_connections = HashMap::new();

    let mut poll_count: u64 = 0;
    let mut last_log_time = std::time::Instant::now();

    let mut wait_error_count: u32 = 0;
    const MAX_WAIT_ERRORS: u32 = 10;
    let mut udp_response_rx = None;

    info!("smoltcp direct stack thread started, entering main loop");

    while running.load(Ordering::Relaxed) {
        wake_rx.drain()?;
        if let Ok(mut pending) = pending_udp_response_rx.lock()
            && let Some(rx) = pending.take()
        {
            udp_response_rx = Some(rx);
        }
        let mut responses_written = 0;
        if let Some(ref mut udp_rx) = udp_response_rx {
            for _ in 0..MAX_PACKET_BATCH {
                let Ok(pkt) = udp_rx.try_recv() else { break };
                responses_written += 1;
                device.write_packet(&pkt)?;
            }
        }

        // Reads packets from TUN and filters by protocol (batch processing).
        let mut stack_packets = Vec::new();
        let mut packets_read = 0;

        while packets_read < MAX_PACKET_BATCH {
            let Some(pkt) = device.try_recv()? else {
                break;
            };
            packets_read += 1;

            if should_filter_packet(&pkt) {
                trace!("Filtered packet, len={}", pkt.len());
                continue;
            }

            let Some(protocol) = get_ip_protocol(&pkt) else {
                continue;
            };
            trace!(
                "Received packet: protocol={:?}, len={}",
                protocol,
                pkt.len()
            );
            match protocol {
                IpProtocol::Tcp if config.tcp_enabled => {
                    if let Some(flow) = extract_tcp_info(&pkt) {
                        stack_packets.push((pkt, Some(flow)));
                    }
                }
                IpProtocol::Icmp | IpProtocol::Icmpv6 if config.icmp_enabled => {
                    stack_packets.push((pkt, None));
                }
                IpProtocol::Udp if config.udp_enabled => {
                    let _ = udp_tx.try_send(pkt);
                }
                _ => {
                    trace!("ignoring packet with protocol {:?}", protocol);
                }
            }
        }

        if packets_read > 0 {
            wait_error_count = 0;
        }

        if !running.load(Ordering::Relaxed) {
            break;
        }

        iface.poll_maintenance(stack_now());
        for (pkt, flow) in stack_packets {
            let known = flow.and_then(|(src, dst, _)| active_connections.get(&(src, dst)).copied());
            let incoming = match (flow, known) {
                (Some((src, dst, true)), None) => {
                    if limits
                        .tcp_connection_limit()
                        .is_some_and(|limit| sockets.len() >= limit)
                    {
                        continue;
                    }
                    let permit = match &admission {
                        Some(admission) => match admission.clone().try_acquire_owned() {
                            Ok(permit) => Some(permit),
                            Err(_) => continue,
                        },
                        None => None,
                    };
                    create_tcp_connection(
                        src,
                        dst,
                        &mut socket_set,
                        &stack_wake,
                        limits.tcp_buffer_size,
                    )
                    .map(|connection| (src, dst, connection, permit))
                }
                _ => None,
            };
            device.store_packet(pkt);
            iface.poll_ingress_single(stack_now(), &mut device, &mut socket_set);
            if let Some(error) = device.tx_error.take() {
                return Err(error);
            }
            if let Some((src_addr, dst_addr, incoming, permit)) = incoming {
                let handle = incoming.handle;
                // Admission follows smoltcp's TCP flag and option validation.
                if socket_set.get::<TcpSocket>(handle).state() != TcpState::SynReceived {
                    socket_set.remove(handle);
                    continue;
                }
                sockets.insert(
                    handle,
                    SocketInfo {
                        _permit: permit,
                        control: incoming.control,
                        src_addr,
                        dst_addr,
                        pending: Some(incoming.connection),
                    },
                );
                active_connections.insert((src_addr, dst_addr), handle);
            } else if let Some(handle) = known {
                let socket = socket_set.get::<TcpSocket>(handle);
                if matches!(socket.state(), TcpState::Listen | TcpState::Closed)
                    && socket.remote_endpoint().is_none()
                {
                    // A reset passive open must not capture another peer later in this batch.
                    socket_set.remove(handle);
                    if let Some(info) = sockets.remove(&handle) {
                        active_connections.remove(&(info.src_addr, info.dst_addr));
                    }
                }
            }
        }

        for (handle, socket_info) in sockets.iter_mut() {
            let handle = *handle;
            let socket = socket_set.get_mut::<TcpSocket>(handle);

            socket_info.pump(handle, socket, &tcp_tx, stack_now());
        }

        // Amortizes loop overhead without starving later sockets or draining indefinitely.
        for _ in 0..MAX_EGRESS_SWEEPS {
            let result = iface.poll_egress(stack_now(), &mut device, &mut socket_set);
            if let Some(error) = device.tx_error.take() {
                return Err(error);
            }
            if result == smoltcp::iface::PollResult::None {
                break;
            }
        }
        let has_local_work =
            reconcile_sockets(&mut sockets, &mut socket_set, &mut active_connections);
        if let Some(ready) = ready.take() {
            let _ = ready.send(());
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

        if packets_read >= MAX_PACKET_BATCH
            || responses_written >= MAX_PACKET_BATCH
            || has_local_work
        {
            continue;
        }

        let now = stack_now();
        let delay = crate::ip_stack::tcp_poll_delay(
            now,
            iface.poll_delay(now, &socket_set),
            sockets.values().map(|info| &*info.control),
        );
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
                    return Err(e);
                }
                warn!("TUN poll error ({wait_error_count}): {e}");
            }
        }
    }

    info!("smoltcp direct stack thread stopped");
    Ok(())
}

fn stack_now() -> SmolInstant {
    std::time::Instant::now().into()
}

fn reconcile_sockets(
    sockets: &mut HashMap<SocketHandle, SocketInfo>,
    socket_set: &mut SocketSet<'_>,
    active_connections: &mut HashMap<(SocketAddr, SocketAddr), SocketHandle>,
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
        has_local_work |= (!is_closed && control.should_abort())
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

struct CreatedTcpConnection {
    handle: SocketHandle,
    connection: NewTcpConnection,
    control: Arc<TcpConnectionControl>,
}

/// Create a new TCP connection in the smoltcp stack.
fn create_tcp_connection(
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    socket_set: &mut SocketSet<'static>,
    wake: &Wake,
    buffer_size: usize,
) -> Option<CreatedTcpConnection> {
    let mut socket = crate::ip_stack::tcp_socket(buffer_size);
    socket.set_timeout(Some(crate::ip_stack::TCP_HANDSHAKE_TIMEOUT));

    if let Err(e) = socket.listen(dst_addr) {
        warn!("Failed to listen on socket for {}: {:?}", dst_addr, e);
        return None;
    }

    debug!("Creating TCP connection: {} -> {}", src_addr, dst_addr);

    let control = Arc::new(TcpConnectionControl::new(buffer_size, buffer_size));

    let handle = socket_set.add(socket);
    let connection = TcpConnection::new(control.clone(), wake.clone());

    Some(CreatedTcpConnection {
        handle,
        connection: NewTcpConnection {
            connection,
            source_addr: src_addr,
            remote_addr: dst_addr,
        },
        control,
    })
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
            if ip.next_header() != IpProtocol::Tcp || ip.frag_offset() != 0 || ip.more_frags() {
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
                if src.to_ipv4_mapped().is_some() || dst.to_ipv4_mapped().is_some() {
                    return true;
                }

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
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
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
            // Linux rejects writes to an administratively down TUN with EIO.
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Err(error) if error.raw_os_error() == Some(libc::EIO) => {
                trace!("TUN interface down, packet dropped");
                return Ok(false);
            }
            // Apple netif-mode utun reports a full input queue as ENOSPC.
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Err(error) if error.raw_os_error() == Some(libc::ENOSPC) => {
                trace!("TUN input queue full, packet dropped");
                return Ok(false);
            }
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
mod tests;
