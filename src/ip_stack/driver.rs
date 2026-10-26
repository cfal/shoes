use super::{
    TCP_HANDSHAKE_TIMEOUT,
    packet::PacketBuffer,
    tcp_conn::{TcpConnection, TcpConnectionControl},
    udp::{UdpConnection, UdpControl},
    wake::{Wake, WakeReceiver},
};
use crate::{config::tun::TunResourceLimits, resources::Budget};
use parking_lot::Mutex;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp::{Socket as TcpSocket, State},
    time::Instant,
    wire::{HardwareAddress, IpCidr, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket},
};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};

pub(crate) const QUEUE_CAPACITY: usize = 64;
const FIRST_EPHEMERAL_PORT: u16 = 49152;
const LAST_EPHEMERAL_PORT: u16 = 65535;

fn tcp_socket(buffer_size: usize) -> TcpSocket<'static> {
    let mut socket = super::tcp_socket(buffer_size);
    socket.set_timeout(Some(TCP_HANDSHAKE_TIMEOUT));
    socket
}

enum Command {
    Tcp(SocketAddr, oneshot::Sender<io::Result<TcpConnection>>),
    Udp(SocketAddr, oneshot::Sender<io::Result<UdpConnection>>),
}

#[derive(Clone)]
pub(crate) struct StackHandle {
    commands: mpsc::Sender<Command>,
    pub wake: Wake,
    running: Arc<AtomicBool>,
}

struct WakeOnDrop(Wake);
impl Drop for WakeOnDrop {
    fn drop(&mut self) {
        self.0.notify();
    }
}

impl StackHandle {
    async fn send(&self, command: Command) -> io::Result<()> {
        if !self.running.load(Ordering::Acquire) {
            return Err(io::ErrorKind::NotConnected.into());
        }
        self.commands
            .send(command)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::NotConnected))?;
        self.wake.notify();
        Ok(())
    }
    pub async fn connect(&self, target: SocketAddr) -> io::Result<TcpConnection> {
        let (tx, rx) = oneshot::channel();
        let _cancel = WakeOnDrop(self.wake.clone());
        tokio::time::timeout(Duration::from_secs(30), async {
            self.send(Command::Tcp(target, tx)).await?;
            rx.await
                .map_err(|_| io::Error::from(io::ErrorKind::NotConnected))?
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "WireGuard TCP connect timed out"))?
    }
    pub async fn open_udp(&self, target: SocketAddr) -> io::Result<UdpConnection> {
        let (tx, rx) = oneshot::channel();
        let _cancel = WakeOnDrop(self.wake.clone());
        self.send(Command::Udp(target, tx)).await?;
        rx.await
            .map_err(|_| io::Error::from(io::ErrorKind::NotConnected))?
    }
}

pub(crate) struct AcceptedTcp {
    pub connection: TcpConnection,
    pub source: SocketAddr,
    pub target: SocketAddr,
}

pub(crate) struct PacketStack {
    thread: Option<thread::JoinHandle<()>>,
    pub handle: StackHandle,
    pub input: mpsc::Sender<PacketBuffer>,
    pub output: Option<mpsc::Receiver<PacketBuffer>>,
    pub tcp: Option<mpsc::Receiver<AcceptedTcp>>,
    pub udp: Option<mpsc::Receiver<PacketBuffer>>,
    pub replies: mpsc::Sender<PacketBuffer>,
    pub done: oneshot::Receiver<()>,
    pub drops: Arc<AtomicU64>,
    pub counts: Arc<FlowCounts>,
}

#[derive(Default)]
pub(crate) struct FlowCounts {
    pub tcp: AtomicUsize,
    pub outbound_udp: AtomicUsize,
}

impl Drop for PacketStack {
    fn drop(&mut self) {
        self.handle.running.store(false, Ordering::Release);
        self.handle.wake.notify();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        self.counts.tcp.store(0, Ordering::Relaxed);
        self.counts.outbound_udp.store(0, Ordering::Relaxed);
    }
}

impl PacketStack {
    pub fn new(
        addresses: Vec<IpAddr>,
        mtu: u16,
        inbound: bool,
        limits: TunResourceLimits,
    ) -> io::Result<Self> {
        limits.validate()?;
        let (wake, wake_rx) = Wake::new()?;
        let running = Arc::new(AtomicBool::new(true));
        let drops = Arc::new(AtomicU64::new(0));
        let counts = Arc::new(FlowCounts::default());
        let (input, input_rx) = mpsc::channel(QUEUE_CAPACITY);
        let (output_tx, output) = mpsc::channel(QUEUE_CAPACITY);
        let accept_capacity = limits
            .tcp_connection_limit()
            .map_or(QUEUE_CAPACITY, |limit| limit.max(QUEUE_CAPACITY));
        let (tcp_tx, tcp) = mpsc::channel(accept_capacity);
        let (udp_tx, udp) = mpsc::channel(QUEUE_CAPACITY);
        let (replies, replies_rx) = mpsc::channel(QUEUE_CAPACITY);
        let (commands, command_rx) = mpsc::channel(QUEUE_CAPACITY);
        let (done_tx, done) = oneshot::channel();
        let handle = StackHandle {
            commands,
            wake: wake.clone(),
            running: running.clone(),
        };
        let device = QueueDevice {
            packet: None,
            output: output_tx,
            mtu: mtu as usize,
            drops: drops.clone(),
        };
        let worker_counts = counts.clone();
        let thread = thread::Builder::new()
            .name("shoes-wireguard-stack".into())
            .spawn(move || {
                struct Stop(Arc<AtomicBool>);
                impl Drop for Stop {
                    fn drop(&mut self) {
                        self.0.store(false, Ordering::Release);
                    }
                }
                let _stop = Stop(running.clone());
                run(
                    device,
                    addresses,
                    inbound,
                    limits,
                    running,
                    wake,
                    wake_rx,
                    input_rx,
                    replies_rx,
                    command_rx,
                    tcp_tx,
                    udp_tx,
                    worker_counts,
                );
                let _ = done_tx.send(());
            })?;
        Ok(Self {
            thread: Some(thread),
            handle,
            input,
            output: Some(output),
            tcp: Some(tcp),
            udp: Some(udp),
            replies,
            done,
            drops,
            counts,
        })
    }
}

struct QueueDevice {
    packet: Option<PacketBuffer>,
    output: mpsc::Sender<PacketBuffer>,
    mtu: usize,
    drops: Arc<AtomicU64>,
}
impl QueueDevice {
    fn emit(&self, packet: PacketBuffer) {
        if packet.len() > self.mtu || self.output.try_send(packet).is_err() {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }
}
struct Rx(PacketBuffer);
struct Tx<'a>(&'a QueueDevice);
impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = PacketBuffer::with_capacity(len);
        packet.resize(len);
        let result = f(&mut packet);
        self.0.emit(packet);
        result
    }
}
impl Device for QueueDevice {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx<'_>)> {
        Some((Rx(self.packet.take()?), Tx(self)))
    }
    fn transmit(&mut self, _: Instant) -> Option<Tx<'_>> {
        Some(Tx(self))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

struct TcpEntry {
    control: Arc<TcpConnectionControl>,
    remote: SocketAddr,
    local: SocketAddr,
    outbound: bool,
    established: bool,
    pending_connect: Option<(oneshot::Sender<io::Result<TcpConnection>>, TcpConnection)>,
    pending_accept: Option<(mpsc::OwnedPermit<AcceptedTcp>, AcceptedTcp)>,
}
impl TcpEntry {
    fn pump(&mut self, handle: SocketHandle, socket: &mut TcpSocket<'_>, now: Instant) {
        if !self.established && matches!(socket.state(), State::Established | State::CloseWait) {
            self.established = true;
            socket.set_timeout(Some(super::TCP_PEER_SILENCE_TIMEOUT));
        }
        if let Some((result, _)) = &self.pending_connect {
            if result.is_closed() {
                self.pending_connect = None;
                socket.abort();
            } else if self.established {
                let (result, connection) = self.pending_connect.take().unwrap();
                let _ = result.send(Ok(connection));
            } else if socket.state() == State::Closed {
                let (result, _) = self.pending_connect.take().unwrap();
                let _ = result.send(Err(io::ErrorKind::ConnectionRefused.into()));
            }
        }
        if self.established
            && let Some((permit, connection)) = self.pending_accept.take()
        {
            // Unlike OwnedPermit::send, try_send drops the connection if the receiver is gone.
            let _ = permit.release().try_send(connection);
        }
        super::pump_tcp(handle, socket, &self.control, now);
    }
}
impl Drop for TcpEntry {
    fn drop(&mut self) {
        self.control.set_closed();
    }
}
struct UdpEntry(Arc<Mutex<UdpControl>>);
impl Drop for UdpEntry {
    fn drop(&mut self) {
        self.0.lock().close();
    }
}

fn now() -> Instant {
    std::time::Instant::now().into()
}

fn reconcile_tcp(
    tcp: &mut HashMap<SocketHandle, TcpEntry>,
    sockets: &mut SocketSet<'_>,
    counts: &FlowCounts,
) -> bool {
    let mut local_work = false;
    tcp.retain(|handle, entry| {
        let socket = sockets.get::<TcpSocket>(*handle);
        if socket.state() == State::Closed && socket.remote_endpoint().is_none() {
            sockets.remove(*handle);
            return false;
        }
        local_work |= socket.can_recv() && !entry.control.recv_buffer_full()
            || socket.can_send() && !entry.control.send_buffer_empty()
            || socket.state() != State::Closed && entry.control.should_abort();
        true
    });
    counts.tcp.store(tcp.len(), Ordering::Relaxed);
    local_work
}

struct PacketInfo {
    protocol: IpProtocol,
    source: SocketAddr,
    target: SocketAddr,
    syn: bool,
    transport_offset: usize,
    length: usize,
}

/// Rejects fragments and extensions before interpreting any transport header.
fn packet_info(packet: &[u8]) -> Option<PacketInfo> {
    let (protocol, src, dst, payload, offset) = match packet.first()? >> 4 {
        4 => {
            let ip = Ipv4Packet::new_checked(packet).ok()?;
            if ip.frag_offset() != 0 || ip.more_frags() || !ip.verify_checksum() {
                return None;
            }
            (
                ip.next_header(),
                IpAddr::V4(ip.src_addr()),
                IpAddr::V4(ip.dst_addr()),
                ip.payload(),
                ip.header_len() as usize,
            )
        }
        6 => {
            let ip = Ipv6Packet::new_checked(packet).ok()?;
            // Mapped addresses can bypass the checks below and become loopback targets in socket APIs.
            if ip.src_addr().to_ipv4_mapped().is_some() || ip.dst_addr().to_ipv4_mapped().is_some()
            {
                return None;
            }
            (
                ip.next_header(),
                IpAddr::V6(ip.src_addr()),
                IpAddr::V6(ip.dst_addr()),
                ip.payload(),
                40,
            )
        }
        _ => return None,
    };
    if src.is_unspecified() || src.is_multicast() || dst.is_unspecified() || dst.is_multicast() {
        return None;
    }
    let (sport, dport, syn, length) = match protocol {
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(payload).ok()?;
            if !tcp.verify_checksum(&src.into(), &dst.into()) {
                return None;
            }
            (
                tcp.src_port(),
                tcp.dst_port(),
                tcp.syn() && !tcp.ack(),
                payload.len(),
            )
        }
        IpProtocol::Udp => {
            let udp = UdpPacket::new_checked(payload).ok()?;
            if !udp.verify_checksum(&src.into(), &dst.into()) {
                return None;
            }
            (udp.src_port(), udp.dst_port(), false, udp.len() as usize)
        }
        _ => return None,
    };
    Some(PacketInfo {
        protocol,
        source: SocketAddr::new(src, sport),
        target: SocketAddr::new(dst, dport),
        syn,
        transport_offset: offset,
        length: offset + length,
    })
}

fn allocate_local(
    addresses: &[IpAddr],
    target: SocketAddr,
    next_port: &mut u16,
    tcp: &HashMap<SocketHandle, TcpEntry>,
    udp: &HashMap<SocketAddr, UdpEntry>,
) -> io::Result<SocketAddr> {
    let ip = addresses
        .iter()
        .find(|ip| ip.is_ipv4() == target.is_ipv4())
        .copied()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "WireGuard endpoint has no local address for this family",
            )
        })?;
    for _ in FIRST_EPHEMERAL_PORT..=LAST_EPHEMERAL_PORT {
        let port = *next_port;
        *next_port = if port == LAST_EPHEMERAL_PORT {
            FIRST_EPHEMERAL_PORT
        } else {
            port + 1
        };
        let local = SocketAddr::new(ip, port);
        if !udp.contains_key(&local) && !tcp.values().any(|entry| entry.local == local) {
            return Ok(local);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "WireGuard ephemeral ports exhausted",
    ))
}

#[allow(clippy::too_many_arguments)]
fn run(
    mut device: QueueDevice,
    addresses: Vec<IpAddr>,
    inbound: bool,
    limits: TunResourceLimits,
    running: Arc<AtomicBool>,
    wake: Wake,
    mut wake_rx: WakeReceiver,
    mut input: mpsc::Receiver<PacketBuffer>,
    mut replies: mpsc::Receiver<PacketBuffer>,
    mut commands: mpsc::Receiver<Command>,
    accepted: mpsc::Sender<AcceptedTcp>,
    inbound_udp: mpsc::Sender<PacketBuffer>,
    counts: Arc<FlowCounts>,
) {
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = rand::random();
    let mut iface = Interface::new(config, &mut device, now());
    // /0 routes and any_ip allow transparent inbound targets; active dials always bind an explicit local address.
    for address in &addresses {
        iface.update_ip_addrs(|list| {
            list.push(IpCidr::new((*address).into(), 0)).unwrap();
        });
        match address {
            IpAddr::V4(ip) => {
                iface.routes_mut().add_default_ipv4_route(*ip).unwrap();
            }
            IpAddr::V6(ip) => {
                iface.routes_mut().add_default_ipv6_route(*ip).unwrap();
            }
        }
    }
    iface.set_any_ip(inbound);
    let mut sockets = SocketSet::new(vec![]);
    let mut tcp: HashMap<SocketHandle, TcpEntry> = HashMap::new();
    let mut udp: HashMap<SocketAddr, UdpEntry> = HashMap::new();
    let budget = Arc::new(Budget::new(limits.max_udp_queued_bytes));
    let mut next_port = FIRST_EPHEMERAL_PORT;
    while running.load(Ordering::Acquire) {
        if wake_rx.drain().is_err() {
            break;
        }
        for _ in 0..QUEUE_CAPACITY {
            let Ok(command) = commands.try_recv() else {
                break;
            };
            let target = match &command {
                Command::Tcp(target, _) | Command::Udp(target, _) => *target,
            };
            // Releases dropped UDP flows before replacement opens can hit stale limits.
            udp.retain(|_, entry| !entry.0.lock().closed);
            let local = allocate_local(&addresses, target, &mut next_port, &tcp, &udp);
            match command {
                Command::Tcp(target, result) => {
                    if result.is_closed() {
                        continue;
                    }
                    let local = match local {
                        Ok(local) => local,
                        Err(error) => {
                            let _ = result.send(Err(error));
                            continue;
                        }
                    };
                    if limits
                        .tcp_connection_limit()
                        .is_some_and(|limit| tcp.len() >= limit)
                    {
                        let _ = result.send(Err(crate::resources::exhausted()));
                        continue;
                    }
                    let mut socket = tcp_socket(limits.tcp_buffer_size);
                    if socket.connect(iface.context(), target, local).is_err() {
                        let _ = result.send(Err(io::ErrorKind::InvalidInput.into()));
                        continue;
                    }
                    let control = Arc::new(TcpConnectionControl::new(
                        limits.tcp_buffer_size,
                        limits.tcp_buffer_size,
                    ));
                    let connection = TcpConnection::new(control.clone(), wake.clone());
                    tcp.insert(
                        sockets.add(socket),
                        TcpEntry {
                            control,
                            remote: target,
                            local,
                            outbound: true,
                            established: false,
                            pending_connect: Some((result, connection)),
                            pending_accept: None,
                        },
                    );
                }
                Command::Udp(target, result) => {
                    if result.is_closed() {
                        continue;
                    }
                    let local = match local {
                        Ok(local) => local,
                        Err(error) => {
                            let _ = result.send(Err(error));
                            continue;
                        }
                    };
                    if [limits.max_udp_sessions, limits.max_udp_destinations]
                        .into_iter()
                        .flatten()
                        .any(|limit| udp.len() >= limit)
                    {
                        let _ = result.send(Err(crate::resources::exhausted()));
                        continue;
                    }
                    let control = Arc::new(Mutex::new(UdpControl {
                        local,
                        remote: target,
                        incoming: Default::default(),
                        outgoing: Default::default(),
                        reader: None,
                        writer: None,
                        closed: false,
                        budget: budget.clone(),
                    }));
                    let connection = UdpConnection {
                        control: control.clone(),
                        wake: wake.clone(),
                        mtu: device.mtu,
                        drops: device.drops.clone(),
                    };
                    udp.insert(local, UdpEntry(control));
                    let _ = result.send(Ok(connection));
                }
            }
        }
        let mut work = 0;
        iface.poll_maintenance(now());
        for _ in 0..QUEUE_CAPACITY {
            let Ok(mut packet) = input.try_recv() else {
                break;
            };
            work += 1;
            let Some(info) = packet_info(&packet) else {
                device.drops.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            if packet.len() > device.mtu {
                device.drops.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            packet.retain_range(0..info.length);
            if info.protocol == IpProtocol::Udp {
                if let Some(entry) = udp.get(&info.target) {
                    let mut control = entry.0.lock();
                    if control.remote == info.source {
                        packet.retain_range(info.transport_offset + 8..info.length);
                        if !control.receive(packet) {
                            device.drops.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                } else if inbound && inbound_udp.try_send(packet).is_err() {
                    device.drops.fetch_add(1, Ordering::Relaxed);
                }
                continue;
            }
            let known = tcp.iter().find_map(|(handle, entry)| {
                (entry.remote == info.source && entry.local == info.target).then_some(*handle)
            });
            let Some(handle) = known else {
                if !info.syn {
                    // Lets smoltcp reset stale flows without answering RSTs or admitting new flows.
                    device.packet = Some(packet);
                    iface.poll_ingress_single(now(), &mut device, &mut sockets);
                    continue;
                }
                if !inbound
                    || tcp
                        .values()
                        .any(|entry| entry.outbound && entry.local == info.target)
                {
                    continue;
                }
                if limits
                    .tcp_connection_limit()
                    .is_some_and(|limit| tcp.len() >= limit)
                {
                    continue;
                }
                let Ok(permit) = accepted.clone().try_reserve_owned() else {
                    continue;
                };
                let mut socket = tcp_socket(limits.tcp_buffer_size);
                if socket.listen(info.target).is_err() {
                    continue;
                }
                let handle = sockets.add(socket);
                device.packet = Some(packet);
                iface.poll_ingress_single(now(), &mut device, &mut sockets);
                // Admission follows smoltcp validation, not just the packet's SYN flag.
                if sockets.get::<TcpSocket>(handle).state() != State::SynReceived {
                    sockets.remove(handle);
                    continue;
                }
                let control = Arc::new(TcpConnectionControl::new(
                    limits.tcp_buffer_size,
                    limits.tcp_buffer_size,
                ));
                let connection = TcpConnection::new(control.clone(), wake.clone());
                let accepted_connection = AcceptedTcp {
                    connection,
                    source: info.source,
                    target: info.target,
                };
                tcp.insert(
                    handle,
                    TcpEntry {
                        control,
                        remote: info.source,
                        local: info.target,
                        outbound: false,
                        established: false,
                        pending_connect: None,
                        pending_accept: Some((permit, accepted_connection)),
                    },
                );
                continue;
            };
            device.packet = Some(packet);
            iface.poll_ingress_single(now(), &mut device, &mut sockets);
            // A reset passive open returns to Listen and must not capture the next peer's SYN.
            // Outbound entries stay until pump reports refusal to their pending connects.
            let socket = sockets.get::<TcpSocket>(handle);
            if !tcp[&handle].outbound
                && matches!(socket.state(), State::Listen | State::Closed)
                && socket.remote_endpoint().is_none()
            {
                sockets.remove(handle);
                tcp.remove(&handle);
            }
        }
        for (handle, entry) in &mut tcp {
            let socket = sockets.get_mut::<TcpSocket>(*handle);
            entry.pump(*handle, socket, now());
        }
        udp.retain(|_, entry| {
            let mut control = entry.0.lock();
            if control.closed {
                return false;
            }
            while let Some(datagram) = control.outgoing.pop_front() {
                device.emit(datagram.packet);
            }
            if let Some(writer) = control.writer.take() {
                writer.wake();
            }
            true
        });
        for _ in 0..QUEUE_CAPACITY {
            let Ok(packet) = replies.try_recv() else {
                break;
            };
            work += 1;
            device.emit(packet);
        }
        for _ in 0..8 {
            if iface.poll_egress(now(), &mut device, &mut sockets)
                == smoltcp::iface::PollResult::None
            {
                break;
            }
        }
        let local_work = reconcile_tcp(&mut tcp, &mut sockets, &counts);
        counts.outbound_udp.store(udp.len(), Ordering::Relaxed);
        if !running.load(Ordering::Acquire) {
            break;
        }
        if work >= QUEUE_CAPACITY || !commands.is_empty() || local_work {
            continue;
        }
        let timestamp = now();
        let delay = super::tcp_poll_delay(
            timestamp,
            iface.poll_delay(timestamp, &sockets),
            tcp.values().map(|entry| &*entry.control),
        );
        if let Err(error) = wake_rx.wait(-1, delay.map(Into::into))
            && error.kind() != io::ErrorKind::Interrupted
        {
            break;
        }
    }
}

#[cfg(test)]
mod tests;
