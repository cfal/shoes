use super::{
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
const TCP_HANDSHAKE_TIMEOUT: smoltcp::time::Duration = smoltcp::time::Duration::from_secs(30);
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
        let (tcp_tx, tcp) = mpsc::channel(QUEUE_CAPACITY);
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
    pending: Option<(oneshot::Sender<io::Result<TcpConnection>>, TcpConnection)>,
}
impl TcpEntry {
    fn pump(&mut self, handle: SocketHandle, socket: &mut TcpSocket<'_>, now: Instant) {
        if !self.established && matches!(socket.state(), State::Established | State::CloseWait) {
            self.established = true;
            socket.set_timeout(Some(super::TCP_PEER_SILENCE_TIMEOUT));
        }
        if let Some((result, _)) = &self.pending {
            if result.is_closed() {
                self.pending = None;
                socket.abort();
            } else if self.established {
                let (result, connection) = self.pending.take().unwrap();
                let _ = result.send(Ok(connection));
            } else if socket.state() == State::Closed {
                let (result, _) = self.pending.take().unwrap();
                let _ = result.send(Err(io::ErrorKind::ConnectionRefused.into()));
            }
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
                            pending: Some((result, connection)),
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
                let Ok(permit) = accepted.try_reserve() else {
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
                permit.send(AcceptedTcp {
                    connection,
                    source: info.source,
                    target: info.target,
                });
                tcp.insert(
                    handle,
                    TcpEntry {
                        control,
                        remote: info.source,
                        local: info.target,
                        outbound: false,
                        established: false,
                        pending: None,
                    },
                );
                continue;
            };
            device.packet = Some(packet);
            iface.poll_ingress_single(now(), &mut device, &mut sockets);
            // A reset passive open returns to Listen and must not capture the next peer's SYN.
            if sockets.get::<TcpSocket>(handle).state() == State::Listen {
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
mod tests {
    use super::*;
    use smoltcp::wire::TcpControl;

    #[test]
    fn local_allocation_preserves_family_order_wraps_and_skips_both_flow_types() {
        let ipv4 = "10.77.0.1".parse().unwrap();
        let ipv6 = "fd77::1".parse().unwrap();
        let addresses = [ipv6, ipv4, "10.77.0.3".parse().unwrap()];
        let target = "10.77.0.2:443".parse().unwrap();
        let mut sockets = SocketSet::new(vec![]);
        let tcp = HashMap::from([(
            sockets.add(tcp_socket(4096)),
            TcpEntry {
                control: Arc::new(TcpConnectionControl::new(4096, 4096)),
                remote: target,
                local: SocketAddr::new(ipv4, LAST_EPHEMERAL_PORT),
                outbound: true,
                established: false,
                pending: None,
            },
        )]);
        let local = SocketAddr::new(ipv4, FIRST_EPHEMERAL_PORT);
        let udp = HashMap::from([(
            local,
            UdpEntry(Arc::new(Mutex::new(UdpControl {
                local,
                remote: target,
                incoming: Default::default(),
                outgoing: Default::default(),
                reader: None,
                writer: None,
                closed: false,
                budget: Arc::new(Budget::new(None)),
            }))),
        )]);
        let mut next_port = LAST_EPHEMERAL_PORT;
        assert_eq!(
            allocate_local(&addresses, target, &mut next_port, &tcp, &udp).unwrap(),
            SocketAddr::new(ipv4, FIRST_EPHEMERAL_PORT + 1),
        );
        assert_eq!(next_port, FIRST_EPHEMERAL_PORT + 2);
        let error = allocate_local(&[ipv6], target, &mut next_port, &tcp, &udp).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);
        assert_eq!(
            error.to_string(),
            "WireGuard endpoint has no local address for this family",
        );
        assert_eq!(next_port, FIRST_EPHEMERAL_PORT + 2);
        next_port = LAST_EPHEMERAL_PORT;
        assert_eq!(
            allocate_local(
                &addresses,
                "[fd77::2]:443".parse().unwrap(),
                &mut next_port,
                &tcp,
                &udp,
            )
            .unwrap(),
            SocketAddr::new(ipv6, LAST_EPHEMERAL_PORT),
        );
        assert_eq!(next_port, FIRST_EPHEMERAL_PORT);
    }

    #[tokio::test]
    async fn canceled_commands_still_advance_the_local_port_cursor() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let stack = PacketStack::new(
                vec!["10.77.0.1".parse().unwrap()],
                1408,
                false,
                TunResourceLimits::default(),
            )
            .unwrap();
            let target = "10.77.0.2:443".parse().unwrap();
            let (tcp, canceled) = oneshot::channel();
            drop(canceled);
            stack.handle.send(Command::Tcp(target, tcp)).await.unwrap();
            let (udp, canceled) = oneshot::channel();
            drop(canceled);
            stack.handle.send(Command::Udp(target, udp)).await.unwrap();
            let connection = stack.handle.open_udp(target).await.unwrap();
            assert_eq!(
                connection.control.lock().local.port(),
                FIRST_EPHEMERAL_PORT + 2
            );
        })
        .await
        .unwrap();
    }

    fn tcp_segment(
        source: SocketAddr,
        target: SocketAddr,
        sequence: u32,
        control: TcpControl,
        ack: Option<u32>,
    ) -> PacketBuffer {
        let mut tcp = etherparse::TcpHeader::new(source.port(), target.port(), sequence, 65535);
        tcp.syn = control == TcpControl::Syn;
        tcp.rst = control == TcpControl::Rst;
        tcp.fin = control == TcpControl::Fin;
        tcp.ack = ack.is_some();
        tcp.acknowledgment_number = ack.unwrap_or(0);
        let builder = match (source.ip(), target.ip()) {
            (IpAddr::V4(source), IpAddr::V4(target)) => {
                etherparse::PacketBuilder::ipv4(source.octets(), target.octets(), 64)
            }
            (IpAddr::V6(source), IpAddr::V6(target)) => {
                etherparse::PacketBuilder::ipv6(source.octets(), target.octets(), 64)
            }
            _ => unreachable!(),
        }
        .tcp_header(tcp);
        let mut packet = PacketBuffer::with_capacity(builder.size(0));
        packet.resize(builder.size(0));
        builder.write(&mut &mut packet[..], &[]).unwrap();
        packet
    }

    #[tokio::test]
    async fn unknown_tcp_segments_receive_resets_without_admitting_flows() {
        tokio::time::timeout(Duration::from_secs(5), async {
            for inbound in [false, true] {
                for (local, source, transparent) in [
                    ("10.77.0.1", "10.77.0.2:40000", "198.18.0.1"),
                    ("fd77::1", "[fd77::2]:40000", "2001:db8::1"),
                ] {
                    let mut stack = PacketStack::new(
                        vec![local.parse().unwrap()],
                        1408,
                        inbound,
                        TunResourceLimits::default(),
                    )
                    .unwrap();
                    let source = source.parse().unwrap();
                    let target = SocketAddr::new(
                        if inbound { transparent } else { local }.parse().unwrap(),
                        49152,
                    );
                    let mut output = stack.output.take().unwrap();
                    let mut accepted = stack.tcp.take().unwrap();
                    stack
                        .input
                        .send(tcp_segment(source, target, 5000, TcpControl::Rst, None))
                        .await
                        .unwrap();
                    for control in [TcpControl::None, TcpControl::Fin, TcpControl::Syn] {
                        stack
                            .input
                            .send(tcp_segment(source, target, 5000, control, Some(7000)))
                            .await
                            .unwrap();
                        stack.handle.wake.notify();
                        let packet = output.recv().await.unwrap();
                        let info = packet_info(&packet).unwrap();
                        assert_eq!(info.source, target);
                        assert_eq!(info.target, source);
                        let tcp = TcpPacket::new_checked(&packet[info.transport_offset..]).unwrap();
                        assert!(tcp.rst());
                        assert_eq!(tcp.seq_number().0, 7000);
                        assert!(!tcp.ack());
                        assert!(matches!(
                            accepted.try_recv(),
                            Err(mpsc::error::TryRecvError::Empty)
                        ));
                    }
                    // FIFO processing makes the ACK reply a barrier for the preceding RST.
                    assert!(matches!(
                        output.try_recv(),
                        Err(mpsc::error::TryRecvError::Empty)
                    ));
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn inbound_rejects_mapped_ipv4_packet_addresses() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut stack = PacketStack::new(
                vec!["fd77::1".parse().unwrap()],
                1408,
                true,
                TunResourceLimits::default(),
            )
            .unwrap();
            let mut accepted = stack.tcp.take().unwrap();
            let mut inbound_udp = stack.udp.take().unwrap();
            let source: SocketAddr = "[fd77::2]:40000".parse().unwrap();
            let target: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
            let barrier =
                crate::tun::udp_handler::build_udp_packet(b"barrier", source, target).unwrap();

            for mapped in ["::ffff:0.0.0.0", "::ffff:224.0.0.251", "::ffff:127.0.0.1"] {
                let mapped = mapped.parse().unwrap();
                for (source, target) in [
                    (source, SocketAddr::new(mapped, target.port())),
                    (SocketAddr::new(mapped, source.port()), target),
                ] {
                    stack
                        .input
                        .send(tcp_segment(source, target, 1000, TcpControl::Syn, None))
                        .await
                        .unwrap();
                    stack
                        .input
                        .send(
                            crate::tun::udp_handler::build_udp_packet(b"rejected", source, target)
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    stack
                        .input
                        .send(PacketBuffer::copy_from_slice(&barrier))
                        .await
                        .unwrap();
                    stack.handle.wake.notify();
                    // Receiving the sentinel proves both preceding packets were processed.
                    assert_eq!(&*inbound_udp.recv().await.unwrap(), &*barrier);
                    assert!(matches!(
                        accepted.try_recv(),
                        Err(mpsc::error::TryRecvError::Empty)
                    ));
                }
            }
            assert_eq!(stack.drops.load(Ordering::Relaxed), 12);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn full_accept_queue_drops_syn_before_sending_synack() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut stack = PacketStack::new(
                vec!["10.77.0.1".parse().unwrap()],
                1408,
                true,
                TunResourceLimits::default(),
            )
            .unwrap();
            let mut accepted = stack.tcp.take().unwrap();
            let mut output = stack.output.take().unwrap();
            let mut inbound_udp = stack.udp.take().unwrap();
            let target = "198.18.0.1:443".parse().unwrap();
            for port in 40000..40000 + QUEUE_CAPACITY as u16 {
                let source = SocketAddr::new("10.77.0.2".parse().unwrap(), port);
                stack
                    .input
                    .send(tcp_segment(source, target, 1000, TcpControl::Syn, None))
                    .await
                    .unwrap();
                stack.handle.wake.notify();
                output.recv().await.unwrap();
            }
            assert_eq!(accepted.len(), QUEUE_CAPACITY);
            let overflow = "10.77.0.2:50000".parse().unwrap();
            stack
                .input
                .send(tcp_segment(overflow, target, 1000, TcpControl::Syn, None))
                .await
                .unwrap();
            // The UDP sentinel is delivered only after the preceding SYN has been processed.
            stack
                .input
                .send(
                    crate::tun::udp_handler::build_udp_packet(b"barrier", overflow, target)
                        .unwrap(),
                )
                .await
                .unwrap();
            stack.handle.wake.notify();
            inbound_udp.recv().await.unwrap();
            while let Ok(packet) = output.try_recv() {
                let ip = Ipv4Packet::new_checked(&*packet).unwrap();
                assert_ne!(
                    TcpPacket::new_checked(ip.payload()).unwrap().dst_port(),
                    overflow.port()
                );
            }
            let _first = accepted.recv().await.unwrap();
            stack
                .input
                .send(tcp_segment(overflow, target, 2000, TcpControl::Syn, None))
                .await
                .unwrap();
            stack.handle.wake.notify();
            loop {
                let packet = output.recv().await.unwrap();
                let ip = Ipv4Packet::new_checked(&*packet).unwrap();
                let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
                if tcp.dst_port() == overflow.port() {
                    assert!(tcp.syn() && tcp.ack());
                    assert_eq!(tcp.ack_number().0, 2001);
                    break;
                }
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn orphaned_fin_wait_releases_admission_even_when_peer_keeps_sending_acks() {
        use super::super::{TCP_ORPHAN_TIMEOUT, tcp_conn::TcpSocketState, tcp_poll_delay};
        use smoltcp::time::Duration as SmolDuration;

        for live_peer in [false, true] {
            let (output, mut packets) = mpsc::channel(QUEUE_CAPACITY);
            let mut device = QueueDevice {
                packet: None,
                output,
                mtu: 1408,
                drops: Arc::default(),
            };
            let start = now();
            let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut device, start);
            let source: SocketAddr = "10.77.0.2:40000".parse().unwrap();
            let target: SocketAddr = "10.77.0.1:443".parse().unwrap();
            iface.update_ip_addrs(|ips| ips.push(IpCidr::new(target.ip().into(), 24)).unwrap());
            let mut socket = tcp_socket(4096);
            socket.listen(target).unwrap();
            let mut sockets = SocketSet::new(vec![]);
            let handle = sockets.add(socket);
            let control = Arc::new(TcpConnectionControl::new(4096, 4096));
            let connection = TcpConnection::new(control.clone(), Wake::new().unwrap().0);
            let mut entries = HashMap::from([(
                handle,
                TcpEntry {
                    control: control.clone(),
                    remote: source,
                    local: target,
                    outbound: false,
                    established: false,
                    pending: None,
                },
            )]);
            let counts = FlowCounts::default();
            device.packet = Some(tcp_segment(source, target, 1000, TcpControl::Syn, None));
            iface.poll(start, &mut device, &mut sockets);
            let synack = packets.try_recv().unwrap();
            let ip = Ipv4Packet::new_checked(&*synack).unwrap();
            let ack = (TcpPacket::new_checked(ip.payload()).unwrap().seq_number() + 1).0 as u32;
            device.packet = Some(tcp_segment(
                source,
                target,
                1001,
                TcpControl::None,
                Some(ack),
            ));
            iface.poll(start, &mut device, &mut sockets);
            entries.get_mut(&handle).unwrap().pump(
                handle,
                sockets.get_mut::<TcpSocket>(handle),
                start,
            );
            sockets.get_mut::<TcpSocket>(handle).close();
            control.set_send_state(TcpSocketState::Closing);
            drop(connection);
            let deadline = control.orphan_deadline().unwrap();
            let abandoned = deadline - TCP_ORPHAN_TIMEOUT;
            entries.get_mut(&handle).unwrap().pump(
                handle,
                sockets.get_mut::<TcpSocket>(handle),
                abandoned,
            );
            iface.poll_egress(abandoned, &mut device, &mut sockets);
            let fin = packets.try_recv().unwrap();
            let ip = Ipv4Packet::new_checked(&*fin).unwrap();
            assert!(TcpPacket::new_checked(ip.payload()).unwrap().fin());
            let ack = ack.wrapping_add(1);
            device.packet = Some(tcp_segment(
                source,
                target,
                1001,
                TcpControl::None,
                Some(ack),
            ));
            iface.poll(abandoned, &mut device, &mut sockets);
            assert_eq!(sockets.get::<TcpSocket>(handle).state(), State::FinWait2);
            assert_eq!(sockets.get::<TcpSocket>(handle).keep_alive(), None);
            assert!(!reconcile_tcp(&mut entries, &mut sockets, &counts));
            assert_eq!(counts.tcp.load(Ordering::Relaxed), 1);

            for seconds in [1, 29, 59, 60] {
                let timestamp = abandoned + SmolDuration::from_secs(seconds);
                if live_peer {
                    device.packet = Some(tcp_segment(
                        source,
                        target,
                        1001,
                        TcpControl::None,
                        Some(ack),
                    ));
                    iface.poll_ingress_single(timestamp, &mut device, &mut sockets);
                }
                assert_eq!(
                    tcp_poll_delay(timestamp, None, std::iter::once(&*control)),
                    Some(SmolDuration::from_secs(60 - seconds)),
                );
                entries.get_mut(&handle).unwrap().pump(
                    handle,
                    sockets.get_mut::<TcpSocket>(handle),
                    timestamp,
                );
                iface.poll_egress(timestamp, &mut device, &mut sockets);
                assert!(!reconcile_tcp(&mut entries, &mut sockets, &counts));
                assert_eq!(
                    counts.tcp.load(Ordering::Relaxed),
                    usize::from(seconds < 60)
                );
            }
            assert!(entries.is_empty());
            assert_eq!(control.recv_state(), TcpSocketState::Closed);
        }
    }

    #[tokio::test]
    async fn reset_half_open_releases_admission_before_the_next_peer() {
        use tokio::io::AsyncReadExt;

        tokio::time::timeout(Duration::from_secs(3), async {
            let mut stack = PacketStack::new(
                vec!["10.77.0.1".parse().unwrap()],
                1408,
                true,
                TunResourceLimits {
                    max_tcp_connections: Some(1),
                    ..Default::default()
                },
            )
            .unwrap();
            let mut accepted = stack.tcp.take().unwrap();
            let mut output = stack.output.take().unwrap();
            let target = "198.18.0.1:443".parse().unwrap();
            let first = "10.77.0.2:40000".parse().unwrap();
            let second = "10.77.0.3:50000".parse().unwrap();
            stack
                .input
                .send(tcp_segment(first, target, 1000, TcpControl::Syn, None))
                .await
                .unwrap();
            stack.handle.wake.notify();
            let mut flow = accepted.recv().await.unwrap();
            assert_eq!(flow.source, first);
            let reply = output.recv().await.unwrap();
            let ip = Ipv4Packet::new_checked(&*reply).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            assert!(tcp.syn() && tcp.ack());
            assert_eq!(tcp.ack_number().0, 1001);

            // An abandoned connect responds to SYN-ACK with RST and no ACK flag.
            stack
                .input
                .try_send(tcp_segment(first, target, 1001, TcpControl::Rst, None))
                .unwrap();
            stack
                .input
                .try_send(tcp_segment(second, target, 5000, TcpControl::Syn, None))
                .unwrap();
            stack.handle.wake.notify();
            assert_eq!(flow.connection.read(&mut [0; 1]).await.unwrap(), 0);
            let next = accepted.recv().await.unwrap();
            assert_eq!(next.source, second);
            assert_eq!(next.target, target);
            for port in [53, 54] {
                let _barrier = stack
                    .handle
                    .open_udp(SocketAddr::new(target.ip(), port))
                    .await
                    .unwrap();
            }
            assert_eq!(stack.counts.tcp.load(Ordering::Relaxed), 1);
            assert!(accepted.try_recv().is_err());
        })
        .await
        .unwrap();
    }

    #[test]
    fn inbound_handshake_timeout_is_lifted_only_after_establishment() {
        for complete in [false, true] {
            let (output, mut packets) = mpsc::channel(QUEUE_CAPACITY);
            let mut device = QueueDevice {
                packet: None,
                output,
                mtu: 1408,
                drops: Arc::default(),
            };
            let start = Instant::from_secs(1);
            let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut device, start);
            let source: SocketAddr = "10.77.0.2:40000".parse().unwrap();
            let target: SocketAddr = "10.77.0.1:443".parse().unwrap();
            iface.update_ip_addrs(|ips| ips.push(IpCidr::new(target.ip().into(), 24)).unwrap());
            let mut socket = tcp_socket(4096);
            socket.listen(target).unwrap();
            let mut sockets = SocketSet::new(vec![]);
            let handle = sockets.add(socket);
            let mut entry = TcpEntry {
                control: Arc::new(TcpConnectionControl::new(4096, 4096)),
                remote: source,
                local: target,
                outbound: false,
                established: false,
                pending: None,
            };
            device.packet = Some(tcp_segment(source, target, 1000, TcpControl::Syn, None));
            iface.poll(start, &mut device, &mut sockets);
            let socket = sockets.get_mut::<TcpSocket>(handle);
            entry.pump(handle, socket, start);
            assert_eq!(socket.state(), State::SynReceived);
            assert_eq!(socket.timeout(), Some(TCP_HANDSHAKE_TIMEOUT));
            if complete {
                let reply = packets.try_recv().unwrap();
                let ip = Ipv4Packet::new_checked(&*reply).unwrap();
                let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
                let ack = (tcp.seq_number() + 1).0 as u32;
                device.packet = Some(tcp_segment(
                    source,
                    target,
                    1001,
                    TcpControl::None,
                    Some(ack),
                ));
                iface.poll(start, &mut device, &mut sockets);
                let socket = sockets.get_mut::<TcpSocket>(handle);
                entry.pump(handle, socket, start);
                assert!(entry.established);
                assert_eq!(
                    socket.timeout(),
                    Some(super::super::TCP_PEER_SILENCE_TIMEOUT)
                );
            }
            iface.poll(
                start + TCP_HANDSHAKE_TIMEOUT + smoltcp::time::Duration::from_secs(1),
                &mut device,
                &mut sockets,
            );
            assert_eq!(
                sockets.get::<TcpSocket>(handle).state(),
                if complete {
                    State::Established
                } else {
                    State::Closed
                }
            );
        }
    }

    #[tokio::test]
    async fn dropping_after_write_shutdown_finishes_the_fin_exchange_without_reset() {
        use tokio::io::AsyncWriteExt;

        tokio::time::timeout(Duration::from_secs(3), async {
            let mut stack = PacketStack::new(
                vec!["10.77.0.1".parse().unwrap()],
                1408,
                true,
                TunResourceLimits::default(),
            )
            .unwrap();
            let mut accepted = stack.tcp.take().unwrap();
            let mut output = stack.output.take().unwrap();
            let target = "198.18.0.1:443".parse().unwrap();
            let source = "10.77.0.2:40000".parse().unwrap();
            stack
                .input
                .send(tcp_segment(source, target, 1000, TcpControl::Syn, None))
                .await
                .unwrap();
            stack.handle.wake.notify();
            let mut flow = accepted.recv().await.unwrap();
            let synack = output.recv().await.unwrap();
            let ip = Ipv4Packet::new_checked(&*synack).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            let ack = (tcp.seq_number() + 1).0 as u32;
            stack
                .input
                .send(tcp_segment(
                    source,
                    target,
                    1001,
                    TcpControl::None,
                    Some(ack),
                ))
                .await
                .unwrap();
            stack.handle.wake.notify();
            flow.connection.shutdown().await.unwrap();
            drop(flow);

            let fin = output.recv().await.unwrap();
            let ip = Ipv4Packet::new_checked(&*fin).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            assert!(tcp.fin() && !tcp.rst());
            let ack = (tcp.seq_number() + 1).0 as u32;
            stack
                .input
                .send(tcp_segment(
                    source,
                    target,
                    1001,
                    TcpControl::Fin,
                    Some(ack),
                ))
                .await
                .unwrap();
            stack.handle.wake.notify();
            let reply = output.recv().await.unwrap();
            let ip = Ipv4Packet::new_checked(&*reply).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            assert!(tcp.ack() && !tcp.rst());
            assert_eq!(tcp.ack_number().0, 1002);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn command_channel_waits_for_capacity_and_rejects_closed_stack() {
        let (commands, mut receiver) = mpsc::channel(1);
        let (wake, _wake_rx) = Wake::new().unwrap();
        let handle = StackHandle {
            commands,
            wake,
            running: Arc::new(AtomicBool::new(true)),
        };
        let target = "10.77.0.1:53".parse().unwrap();
        let command = || Command::Udp(target, oneshot::channel().0);
        handle.commands.try_send(command()).unwrap();
        let mut opening = Box::pin(handle.open_udp(target));
        assert!(futures::poll!(&mut opening).is_pending());
        receiver.try_recv().unwrap();
        assert!(futures::poll!(&mut opening).is_pending());
        let Command::Udp(_, result) = receiver.try_recv().unwrap() else {
            panic!("expected UDP open");
        };
        let _ = result.send(Err(io::ErrorKind::AddrNotAvailable.into()));
        assert_eq!(
            opening.await.err().unwrap().kind(),
            io::ErrorKind::AddrNotAvailable
        );
        handle.commands.try_send(command()).unwrap();
        let mut opening = Box::pin(handle.open_udp(target));
        assert!(futures::poll!(&mut opening).is_pending());
        drop(receiver);
        assert_eq!(
            opening.await.err().unwrap().kind(),
            io::ErrorKind::NotConnected
        );
        assert_eq!(
            handle.open_udp(target).await.err().unwrap().kind(),
            io::ErrorKind::NotConnected
        );
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_connect_timeout_includes_waiting_for_command_capacity() {
        let (commands, mut receiver) = mpsc::channel(1);
        let (wake, _wake_rx) = Wake::new().unwrap();
        let handle = StackHandle {
            commands,
            wake,
            running: Arc::new(AtomicBool::new(true)),
        };
        let target = "10.77.0.1:443".parse().unwrap();
        handle
            .commands
            .try_send(Command::Tcp(target, oneshot::channel().0))
            .unwrap();
        let error = handle.connect(target).await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "WireGuard TCP connect timed out");
        receiver.try_recv().unwrap();
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn udp_open_bursts_respect_flow_limits_not_queue_capacity() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let limit = QUEUE_CAPACITY * 4;
            let stack = PacketStack::new(
                vec!["10.77.0.1".parse().unwrap()],
                1408,
                false,
                TunResourceLimits {
                    max_udp_sessions: Some(limit),
                    max_udp_destinations: Some(limit),
                    ..Default::default()
                },
            )
            .unwrap();
            let target = "10.77.0.2:53".parse().unwrap();
            let connections =
                futures::future::join_all((0..limit).map(|_| stack.handle.open_udp(target)))
                    .await
                    .into_iter()
                    .collect::<io::Result<Vec<_>>>()
                    .unwrap();
            assert_eq!(connections.len(), limit);
            assert_eq!(
                stack.handle.open_udp(target).await.err().unwrap().kind(),
                crate::resources::exhausted().kind()
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn malformed_syns_do_not_admit_flows_or_capture_later_peers() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let mut stack = PacketStack::new(
                vec!["10.77.0.1".parse().unwrap()],
                1408,
                true,
                TunResourceLimits {
                    max_tcp_connections: Some(1),
                    ..Default::default()
                },
            )
            .unwrap();
            let mut accepted = stack.tcp.take().unwrap();
            for malformed in 0..5 {
                let source = if malformed < 4 {
                    "10.77.0.2"
                } else {
                    "10.77.0.3"
                }
                .parse()
                .unwrap();
                let target = "198.18.0.1".parse().unwrap();
                let mut packet = PacketBuffer::with_capacity(44);
                packet.resize(44);
                let mut ip = Ipv4Packet::new_unchecked(&mut *packet);
                smoltcp::wire::Ipv4Repr {
                    src_addr: source,
                    dst_addr: target,
                    next_header: IpProtocol::Tcp,
                    payload_len: 24,
                    hop_limit: 64,
                }
                .emit(&mut ip, &Default::default());
                let mut tcp = TcpPacket::new_unchecked(ip.payload_mut());
                tcp.set_header_len(24);
                tcp.set_src_port(if malformed == 2 { 0 } else { 40000 });
                tcp.set_dst_port(443);
                tcp.set_seq_number(smoltcp::wire::TcpSeqNumber(1000));
                tcp.set_syn(true);
                tcp.set_fin(malformed == 0);
                tcp.set_rst(malformed == 1);
                tcp.set_window_len(65535);
                if malformed == 3 {
                    tcp.options_mut().copy_from_slice(&[2, 1, 0, 0]);
                }
                tcp.fill_checksum(&source.into(), &target.into());
                stack.input.send(packet).await.unwrap();
                stack.handle.wake.notify();
            }
            let flow = accepted.recv().await.unwrap();
            assert_eq!(flow.source, "10.77.0.3:40000".parse().unwrap());
            assert_eq!(flow.target, "198.18.0.1:443".parse().unwrap());
            // A command is processed after the packet batch, making the count assertion deterministic.
            let _barrier = stack
                .handle
                .open_udp("10.77.0.2:53".parse().unwrap())
                .await
                .unwrap();
            assert_eq!(stack.counts.tcp.load(Ordering::Relaxed), 1);
            assert!(accepted.try_recv().is_err());
        })
        .await
        .unwrap();
    }

    #[test]
    fn classification_tracks_transport_offset_and_length() {
        for (source, target, offset) in [
            ("10.0.0.1:1", "10.0.0.2:2", 20),
            ("[fd77::1]:1", "[fd77::2]:2", 40),
        ] {
            let source = source.parse().unwrap();
            let target = target.parse().unwrap();
            let packet =
                crate::tun::udp_handler::build_udp_packet(b"data", source, target).unwrap();
            let info = packet_info(&packet).unwrap();
            assert_eq!(info.protocol, IpProtocol::Udp);
            assert_eq!(info.source, source);
            assert_eq!(info.target, target);
            assert!(!info.syn);
            assert_eq!(info.transport_offset, offset);
            assert_eq!(info.length, packet.len());
            assert_eq!(&packet[info.transport_offset + 8..info.length], b"data");

            if source.is_ipv4() {
                let mut options = packet[..offset].to_vec();
                options.extend_from_slice(&[0; 4]);
                options.extend_from_slice(&packet[offset..]);
                let length = options.len();
                let mut ip = Ipv4Packet::new_unchecked(&mut options);
                ip.set_header_len(24);
                ip.set_total_len(length as u16);
                ip.fill_checksum();
                let info = packet_info(&options).unwrap();
                assert_eq!(info.transport_offset, 24);
                assert_eq!(info.length, length);
                assert_eq!(&options[info.transport_offset + 8..info.length], b"data");
            }
        }
    }

    #[test]
    fn classification_rejects_fragments_extensions_and_bad_checksums() {
        let packet = || {
            crate::tun::udp_handler::build_udp_packet(
                b"data",
                "10.0.0.1:1".parse().unwrap(),
                "10.0.0.2:2".parse().unwrap(),
            )
            .unwrap()
        };
        assert!(packet_info(&packet()).is_some());
        for offset in [0, 1] {
            let mut bytes = packet();
            let mut ip = Ipv4Packet::new_unchecked(&mut *bytes);
            ip.set_more_frags(true);
            ip.set_frag_offset(offset);
            ip.fill_checksum();
            assert!(packet_info(&bytes).is_none());
        }
        let mut bytes = packet();
        bytes[31] ^= 1;
        assert!(packet_info(&bytes).is_none());
        let mut bytes = packet();
        bytes[10] ^= 1;
        assert!(packet_info(&bytes).is_none());
        let mut bytes = crate::tun::udp_handler::build_udp_packet(
            b"data",
            "[fd77::1]:1".parse().unwrap(),
            "[fd77::2]:2".parse().unwrap(),
        )
        .unwrap();
        assert!(packet_info(&bytes).is_some());
        bytes[6] = 44;
        assert!(packet_info(&bytes).is_none());
    }
}
