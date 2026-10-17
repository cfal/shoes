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
    fn send(&self, command: Command) -> io::Result<()> {
        if !self.running.load(Ordering::Acquire) {
            return Err(io::ErrorKind::NotConnected.into());
        }
        self.commands
            .try_send(command)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => crate::resources::exhausted(),
                mpsc::error::TrySendError::Closed(_) => io::ErrorKind::NotConnected.into(),
            })?;
        self.wake.notify();
        Ok(())
    }
    pub async fn connect(&self, target: SocketAddr) -> io::Result<TcpConnection> {
        let (tx, rx) = oneshot::channel();
        let _cancel = WakeOnDrop(self.wake.clone());
        self.send(Command::Tcp(target, tx))?;
        tokio::time::timeout(Duration::from_secs(30), rx)
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "WireGuard TCP connect timed out")
            })?
            .map_err(|_| io::Error::from(io::ErrorKind::NotConnected))?
    }
    pub async fn open_udp(&self, target: SocketAddr) -> io::Result<UdpConnection> {
        let (tx, rx) = oneshot::channel();
        let _cancel = WakeOnDrop(self.wake.clone());
        self.send(Command::Udp(target, tx))?;
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
    pending: Option<(oneshot::Sender<io::Result<TcpConnection>>, TcpConnection)>,
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
    let mut next_port = 49152u16;
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
            let local = addresses
                .iter()
                .find(|ip| ip.is_ipv4() == target.is_ipv4())
                .copied()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "WireGuard endpoint has no local address for this family",
                    )
                });
            let local = local.and_then(|ip| {
                for _ in 49152..=65535 {
                    let port = next_port;
                    next_port = if port == 65535 { 49152 } else { port + 1 };
                    let local = SocketAddr::new(ip, port);
                    if !udp.contains_key(&local) && !tcp.values().any(|entry| entry.local == local)
                    {
                        return Ok(local);
                    }
                }
                Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "WireGuard ephemeral ports exhausted",
                ))
            });
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
                    let mut socket = super::tcp_socket(limits.tcp_buffer_size);
                    socket.set_timeout(Some(smoltcp::time::Duration::from_secs(30)));
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
            let known = tcp
                .values()
                .any(|entry| entry.remote == info.source && entry.local == info.target);
            if !known {
                if !inbound
                    || !info.syn
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
                let mut socket = super::tcp_socket(limits.tcp_buffer_size);
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
                if accepted
                    .try_send(AcceptedTcp {
                        connection,
                        source: info.source,
                        target: info.target,
                    })
                    .is_err()
                {
                    sockets.remove(handle);
                    continue;
                }
                tcp.insert(
                    handle,
                    TcpEntry {
                        control,
                        remote: info.source,
                        local: info.target,
                        outbound: false,
                        pending: None,
                    },
                );
                continue;
            }
            device.packet = Some(packet);
            iface.poll_ingress_single(now(), &mut device, &mut sockets);
        }
        for (handle, entry) in &mut tcp {
            let socket = sockets.get_mut::<TcpSocket>(*handle);
            if let Some((result, _)) = &entry.pending {
                if result.is_closed() {
                    entry.pending = None;
                    socket.abort();
                } else if socket.state() == State::Established || socket.state() == State::CloseWait
                {
                    socket.set_timeout(Some(super::TCP_PEER_SILENCE_TIMEOUT));
                    let (result, connection) = entry.pending.take().unwrap();
                    let _ = result.send(Ok(connection));
                } else if socket.state() == State::Closed {
                    let (result, _) = entry.pending.take().unwrap();
                    let _ = result.send(Err(io::ErrorKind::ConnectionRefused.into()));
                }
            }
            super::pump_tcp(*handle, socket, &entry.control);
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
        let mut local_work = false;
        tcp.retain(|handle, entry| {
            let socket = sockets.get::<TcpSocket>(*handle);
            if socket.state() == State::Closed && socket.remote_endpoint().is_none() {
                sockets.remove(*handle);
                return false;
            }
            local_work |= socket.can_recv() && !entry.control.recv_buffer_full()
                || socket.can_send() && !entry.control.send_buffer_empty()
                || socket.state() != State::Closed && entry.control.is_abandoned();
            true
        });
        counts.tcp.store(tcp.len(), Ordering::Relaxed);
        counts.outbound_udp.store(udp.len(), Ordering::Relaxed);
        if !running.load(Ordering::Acquire) {
            break;
        }
        if work >= QUEUE_CAPACITY || !commands.is_empty() || local_work {
            continue;
        }
        if let Err(error) = wake_rx.wait(-1, iface.poll_delay(now(), &sockets).map(Into::into))
            && error.kind() != io::ErrorKind::Interrupted
        {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_channel_distinguishes_full_from_closed() {
        let (commands, receiver) = mpsc::channel(1);
        let (wake, _wake_rx) = Wake::new().unwrap();
        let handle = StackHandle {
            commands,
            wake,
            running: Arc::new(AtomicBool::new(true)),
        };
        let command = || Command::Udp("10.77.0.1:53".parse().unwrap(), oneshot::channel().0);
        handle.send(command()).unwrap();
        assert_eq!(
            handle.send(command()).unwrap_err().kind(),
            crate::resources::exhausted().kind()
        );
        drop(receiver);
        assert_eq!(
            handle.send(command()).unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
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
