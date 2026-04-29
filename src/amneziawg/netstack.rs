//! Virtual network stack for AmneziaWG outbound connections.
//!
//! Uses smoltcp to provide a virtual TCP/IP stack that emits IP packets
//! for the AmneziaWG tunnel to encapsulate, and accepts decapsulated
//! IP packets from the tunnel.
//!
//! TCP connections use the TcpConnectionControl ring-buffer+waker pattern
//! (from tun/tcp_conn.rs) for bridging smoltcp's synchronous sockets to
//! tokio's async traits.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use log::{debug, trace, warn};
use parking_lot::Mutex;
use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{
    CongestionControl, Socket as SmolTcpSocket, SocketBuffer as TcpSocketBuffer,
    State as TcpState,
};
use smoltcp::socket::udp::Socket as SmolUdpSocket;
use smoltcp::socket::udp::{PacketBuffer as UdpPacketBuffer, PacketMetadata as UdpPacketMetadata};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::sync::Notify;

use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};

// ---------------------------------------------------------------------------
// Virtual smoltcp device
// ---------------------------------------------------------------------------

struct VirtualDevice {
    rx_queue: Vec<Vec<u8>>,
    tx_queue: Vec<Vec<u8>>,
    mtu: usize,
}

impl VirtualDevice {
    fn new(mtu: usize) -> Self {
        Self {
            rx_queue: Vec::new(),
            tx_queue: Vec::new(),
            mtu,
        }
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = VirtualRxToken;
    type TxToken<'a> = VirtualTxToken;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.rx_queue.is_empty() {
            return None;
        }
        let packet = self.rx_queue.remove(0);
        Some((
            VirtualRxToken { buffer: packet },
            VirtualTxToken {
                tx_queue: std::ptr::from_mut(&mut self.tx_queue),
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(VirtualTxToken {
            tx_queue: std::ptr::from_mut(&mut self.tx_queue),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

struct VirtualRxToken {
    buffer: Vec<u8>,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

struct VirtualTxToken {
    tx_queue: *mut Vec<Vec<u8>>,
}

impl TxToken for VirtualTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        // SAFETY: pointer is valid for the duration of Device::receive/transmit
        unsafe {
            (*self.tx_queue).push(buffer);
        }
        result
    }
}

// ---------------------------------------------------------------------------
// TCP: shared control buffer (ring-buffer + waker pattern)
// ---------------------------------------------------------------------------

const TCP_SEND_BUF: usize = 256 * 1024;
const TCP_RECV_BUF: usize = 256 * 1024;

/// Shared state between the smoltcp poll loop and the async VirtualTcpStream.
struct TcpControl {
    /// Data written by async side, consumed by smoltcp send.
    send_buf: smoltcp::storage::RingBuffer<'static, u8>,
    send_waker: Option<Waker>,
    send_closed: bool,

    /// Data written by smoltcp recv, consumed by async side.
    recv_buf: smoltcp::storage::RingBuffer<'static, u8>,
    recv_waker: Option<Waker>,
    recv_closed: bool,
}

// ---------------------------------------------------------------------------
// UDP: shared channel pair
// ---------------------------------------------------------------------------

struct UdpControl {
    /// Target endpoint for outgoing packets.
    target: IpEndpoint,
    /// Packets to send (async -> smoltcp).
    outgoing_tx: mpsc::Sender<Vec<u8>>,
    outgoing_rx: mpsc::Receiver<Vec<u8>>,
    /// Packets received (smoltcp -> async).
    incoming_tx: mpsc::Sender<Vec<u8>>,
    incoming_rx: mpsc::Receiver<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Netstack requests
// ---------------------------------------------------------------------------

pub enum NetStackRequest {
    ConnectTcp {
        target: SocketAddr,
        reply: tokio::sync::oneshot::Sender<std::io::Result<VirtualTcpStream>>,
    },
    ConnectUdp {
        target: SocketAddr,
        reply: tokio::sync::oneshot::Sender<std::io::Result<VirtualUdpStream>>,
    },
}

// ---------------------------------------------------------------------------
// Tracking structs inside the poll loop
// ---------------------------------------------------------------------------

struct ActiveTcp {
    control: Arc<Mutex<TcpControl>>,
    notify: Arc<Notify>,
    connected: bool,
}

struct ActiveUdp {
    target: IpEndpoint,
    outgoing_rx: mpsc::Receiver<Vec<u8>>,
    incoming_tx: mpsc::Sender<Vec<u8>>,
}

struct PendingTcp {
    control: Arc<Mutex<TcpControl>>,
    notify: Arc<Notify>,
    reply: tokio::sync::oneshot::Sender<std::io::Result<VirtualTcpStream>>,
    target: SocketAddr,
}

// ---------------------------------------------------------------------------
// VirtualNetStack
// ---------------------------------------------------------------------------

pub struct VirtualNetStack {
    ip_to_tunnel: mpsc::Sender<Vec<u8>>,
    ip_from_tunnel: mpsc::Receiver<Vec<u8>>,
    iface: Interface,
    device: VirtualDevice,
    sockets: SocketSet<'static>,
    pending_tcp: HashMap<SocketHandle, PendingTcp>,
    active_tcp: HashMap<SocketHandle, ActiveTcp>,
    active_udp: HashMap<SocketHandle, ActiveUdp>,
}

impl VirtualNetStack {
    pub fn new(
        local_addresses: &[(IpAddr, u8)],
        mtu: u16,
        ip_to_tunnel: mpsc::Sender<Vec<u8>>,
        ip_from_tunnel: mpsc::Receiver<Vec<u8>>,
    ) -> Self {
        let mut device = VirtualDevice::new(mtu as usize);

        let mut config = InterfaceConfig::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut iface = Interface::new(config, &mut device, SmolInstant::now());

        let cidrs: Vec<IpCidr> = local_addresses
            .iter()
            .map(|(addr, prefix)| {
                let ip = match addr {
                    IpAddr::V4(v4) => IpAddress::Ipv4(smoltcp::wire::Ipv4Address::from(*v4)),
                    IpAddr::V6(v6) => IpAddress::Ipv6(smoltcp::wire::Ipv6Address::from(*v6)),
                };
                IpCidr::new(ip, *prefix)
            })
            .collect();

        iface.update_ip_addrs(|addrs| {
            for cidr in &cidrs {
                addrs.push(*cidr).ok();
            }
        });

        for (addr, _) in local_addresses {
            match addr {
                IpAddr::V4(_) => {
                    iface
                        .routes_mut()
                        .add_default_ipv4_route(smoltcp::wire::Ipv4Address::new(0, 0, 0, 1))
                        .ok();
                }
                IpAddr::V6(_) => {
                    iface
                        .routes_mut()
                        .add_default_ipv6_route(smoltcp::wire::Ipv6Address::new(
                            0, 0, 0, 0, 0, 0, 0, 1,
                        ))
                        .ok();
                }
            }
        }

        Self {
            ip_to_tunnel,
            ip_from_tunnel,
            iface,
            device,
            sockets: SocketSet::new(vec![]),
            pending_tcp: HashMap::new(),
            active_tcp: HashMap::new(),
            active_udp: HashMap::new(),
        }
    }

    // ------------------------------------------------------------------
    // Main event loop
    // ------------------------------------------------------------------

    pub async fn run(mut self, mut conn_rx: mpsc::Receiver<NetStackRequest>) {
        let mut poll_interval = tokio::time::interval(std::time::Duration::from_millis(1));

        loop {
            tokio::select! {
                request = conn_rx.recv() => {
                    match request {
                        Some(NetStackRequest::ConnectTcp { target, reply }) => {
                            self.initiate_tcp(target, reply);
                        }
                        Some(NetStackRequest::ConnectUdp { target, reply }) => {
                            self.initiate_udp(target, reply);
                        }
                        None => {
                            debug!("AmneziaWG netstack: request channel closed");
                            break;
                        }
                    }
                }
                Some(packet) = self.ip_from_tunnel.recv() => {
                    self.device.rx_queue.push(packet);
                }
                _ = poll_interval.tick() => {}
            }

            // Poll smoltcp
            let now = SmolInstant::now();
            self.iface.poll(now, &mut self.device, &mut self.sockets);

            // Flush outbound IP packets to tunnel
            for packet in self.device.tx_queue.drain(..) {
                if self.ip_to_tunnel.try_send(packet).is_err() {
                    warn!("AmneziaWG netstack: tunnel TX full, dropping packet");
                }
            }

            // Service TCP connections
            self.service_pending_tcp();
            self.service_active_tcp();

            // Service UDP sockets
            self.service_active_udp();
        }
    }

    // ------------------------------------------------------------------
    // TCP initiation
    // ------------------------------------------------------------------

    fn initiate_tcp(
        &mut self,
        target: SocketAddr,
        reply: tokio::sync::oneshot::Sender<std::io::Result<VirtualTcpStream>>,
    ) {
        let rx_buf = TcpSocketBuffer::new(vec![0u8; TCP_SEND_BUF]);
        let tx_buf = TcpSocketBuffer::new(vec![0u8; TCP_RECV_BUF]);
        let mut socket = SmolTcpSocket::new(rx_buf, tx_buf);
        socket.set_nagle_enabled(false);
        socket.set_congestion_control(CongestionControl::Cubic);

        let local_port = allocate_ephemeral_port();
        let remote = to_smol_endpoint(target);

        if let Err(e) = socket.connect(self.iface.context(), remote, local_port) {
            let _ = reply.send(Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("smoltcp connect: {}", e),
            )));
            return;
        }

        let control = Arc::new(Mutex::new(TcpControl {
            send_buf: smoltcp::storage::RingBuffer::new(vec![0u8; TCP_SEND_BUF]),
            send_waker: None,
            send_closed: false,
            recv_buf: smoltcp::storage::RingBuffer::new(vec![0u8; TCP_RECV_BUF]),
            recv_waker: None,
            recv_closed: false,
        }));
        let notify = Arc::new(Notify::new());

        let handle = self.sockets.add(socket);
        self.pending_tcp.insert(
            handle,
            PendingTcp {
                control,
                notify,
                reply,
                target,
            },
        );
    }

    fn service_pending_tcp(&mut self) {
        let mut completed = Vec::new();

        for (handle, pending) in &self.pending_tcp {
            let socket = self.sockets.get::<SmolTcpSocket>(*handle);
            match socket.state() {
                TcpState::Established => completed.push((*handle, true)),
                TcpState::Closed | TcpState::TimeWait => completed.push((*handle, false)),
                _ => {}
            }
        }

        for (handle, success) in completed {
            let pending = self.pending_tcp.remove(&handle).unwrap();
            if success {
                let stream = VirtualTcpStream {
                    control: pending.control.clone(),
                    notify: pending.notify.clone(),
                };
                self.active_tcp.insert(
                    handle,
                    ActiveTcp {
                        control: pending.control,
                        notify: pending.notify,
                        connected: true,
                    },
                );
                let _ = pending.reply.send(Ok(stream));
            } else {
                let _ = pending.reply.send(Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("TCP to {} failed", pending.target),
                )));
                self.sockets.remove(handle);
            }
        }
    }

    // ------------------------------------------------------------------
    // TCP data transfer
    // ------------------------------------------------------------------

    fn service_active_tcp(&mut self) {
        let mut to_remove = Vec::new();

        for (handle, active) in &self.active_tcp {
            let socket = self.sockets.get_mut::<SmolTcpSocket>(*handle);
            let mut ctrl = active.control.lock();

            // smoltcp recv -> ctrl.recv_buf (data for the async reader)
            if socket.can_recv() && !ctrl.recv_buf.is_full() {
                let _ = socket.recv(|data| {
                    let n = ctrl.recv_buf.enqueue_slice(data);
                    (n, ())
                });
                // Wake the async reader
                if let Some(w) = ctrl.recv_waker.take() {
                    w.wake();
                }
            }

            // ctrl.send_buf -> smoltcp send (data from the async writer)
            if socket.can_send() && !ctrl.send_buf.is_empty() {
                let _ = socket.send(|buf| {
                    let n = ctrl.send_buf.dequeue_slice(buf);
                    (n, ())
                });
                // Wake the async writer (buffer space freed)
                if let Some(w) = ctrl.send_waker.take() {
                    w.wake();
                }
            }

            // Handle send-side close: async side requested shutdown
            if ctrl.send_closed && ctrl.send_buf.is_empty() && socket.send_queue() == 0 {
                socket.close();
            }

            // Detect recv-side close from remote
            if !socket.may_recv() && !ctrl.recv_closed {
                ctrl.recv_closed = true;
                if let Some(w) = ctrl.recv_waker.take() {
                    w.wake();
                }
            }

            // Detect fully closed
            if socket.state() == TcpState::Closed || socket.state() == TcpState::TimeWait {
                ctrl.recv_closed = true;
                ctrl.send_closed = true;
                if let Some(w) = ctrl.recv_waker.take() {
                    w.wake();
                }
                if let Some(w) = ctrl.send_waker.take() {
                    w.wake();
                }
                to_remove.push(*handle);
            }
        }

        for handle in to_remove {
            self.active_tcp.remove(&handle);
            self.sockets.remove(handle);
        }
    }

    // ------------------------------------------------------------------
    // UDP initiation + data transfer
    // ------------------------------------------------------------------

    fn initiate_udp(
        &mut self,
        target: SocketAddr,
        reply: tokio::sync::oneshot::Sender<std::io::Result<VirtualUdpStream>>,
    ) {
        let rx_buf = UdpPacketBuffer::new(
            vec![UdpPacketMetadata::EMPTY; 64],
            vec![0u8; 65536],
        );
        let tx_buf = UdpPacketBuffer::new(
            vec![UdpPacketMetadata::EMPTY; 64],
            vec![0u8; 65536],
        );
        let mut socket = SmolUdpSocket::new(rx_buf, tx_buf);

        let local_port = allocate_ephemeral_port();
        if let Err(e) = socket.bind(local_port) {
            let _ = reply.send(Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("smoltcp UDP bind: {}", e),
            )));
            return;
        }

        let handle = self.sockets.add(socket);
        let endpoint = to_smol_endpoint(target);

        let (outgoing_tx, outgoing_rx) = mpsc::channel::<Vec<u8>>(128);
        let (incoming_tx, incoming_rx) = mpsc::channel::<Vec<u8>>(128);

        self.active_udp.insert(
            handle,
            ActiveUdp {
                target: endpoint,
                outgoing_rx,
                incoming_tx,
            },
        );

        let stream = VirtualUdpStream {
            send_tx: outgoing_tx,
            recv_rx: incoming_rx,
        };

        let _ = reply.send(Ok(stream));
    }

    fn service_active_udp(&mut self) {
        let mut to_remove = Vec::new();

        for (handle, active) in &mut self.active_udp {
            let socket = self.sockets.get_mut::<SmolUdpSocket>(*handle);

            // Drain outgoing packets from async side -> smoltcp send
            while let Ok(data) = active.outgoing_rx.try_recv() {
                if socket.can_send() {
                    if let Err(e) = socket.send_slice(&data, active.target) {
                        debug!("AmneziaWG UDP send error: {}", e);
                    }
                }
            }

            // Drain incoming packets from smoltcp recv -> async side
            while socket.can_recv() {
                match socket.recv() {
                    Ok((data, _endpoint)) => {
                        let _ = active.incoming_tx.try_send(data.to_vec());
                    }
                    Err(_) => break,
                }
            }

            // If the sender was dropped, mark for cleanup
            if active.outgoing_rx.is_closed() && active.incoming_tx.is_closed() {
                to_remove.push(*handle);
            }
        }

        for handle in to_remove {
            self.active_udp.remove(&handle);
            self.sockets.remove(handle);
        }
    }
}

// ---------------------------------------------------------------------------
// VirtualTcpStream: AsyncRead + AsyncWrite + AsyncPing => AsyncStream
// ---------------------------------------------------------------------------

pub struct VirtualTcpStream {
    control: Arc<Mutex<TcpControl>>,
    notify: Arc<Notify>,
}

impl AsyncRead for VirtualTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut ctrl = self.control.lock();

        if !ctrl.recv_buf.is_empty() {
            let unfilled = buf.initialize_unfilled();
            let n = ctrl.recv_buf.dequeue_slice(unfilled);
            buf.advance(n);
            // Notify netstack that buffer space is available
            drop(ctrl);
            self.notify.notify_waiters();
            return Poll::Ready(Ok(()));
        }

        if ctrl.recv_closed {
            return Poll::Ready(Ok(())); // EOF
        }

        // Register waker
        ctrl.recv_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for VirtualTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut ctrl = self.control.lock();

        if ctrl.send_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }

        if !ctrl.send_buf.is_full() {
            let n = ctrl.send_buf.enqueue_slice(buf);
            drop(ctrl);
            self.notify.notify_waiters();
            return Poll::Ready(Ok(n));
        }

        ctrl.send_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut ctrl = self.control.lock();
        ctrl.send_closed = true;
        drop(ctrl);
        self.notify.notify_waiters();
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for VirtualTcpStream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl Unpin for VirtualTcpStream {}
unsafe impl Send for VirtualTcpStream {}
unsafe impl Sync for VirtualTcpStream {}

impl AsyncStream for VirtualTcpStream {}

// ---------------------------------------------------------------------------
// VirtualUdpStream: AsyncMessageStream
// ---------------------------------------------------------------------------

pub struct VirtualUdpStream {
    send_tx: mpsc::Sender<Vec<u8>>,
    recv_rx: mpsc::Receiver<Vec<u8>>,
}

impl AsyncReadMessage for VirtualUdpStream {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.recv_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let unfilled = buf.initialize_unfilled();
                let n = data.len().min(unfilled.len());
                unfilled[..n].copy_from_slice(&data[..n]);
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWriteMessage for VirtualUdpStream {
    fn poll_write_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.send_tx.try_send(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Drop the packet — UDP is lossy
                warn!("AmneziaWG: UDP send buffer full, dropping packet");
                Poll::Ready(Ok(()))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            }
        }
    }
}

impl AsyncFlushMessage for VirtualUdpStream {
    fn poll_flush_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for VirtualUdpStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for VirtualUdpStream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl Unpin for VirtualUdpStream {}

impl AsyncMessageStream for VirtualUdpStream {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn to_smol_endpoint(addr: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(
        match addr.ip() {
            IpAddr::V4(v4) => IpAddress::Ipv4(smoltcp::wire::Ipv4Address::from(v4)),
            IpAddr::V6(v6) => IpAddress::Ipv6(smoltcp::wire::Ipv6Address::from(v6)),
        },
        addr.port(),
    )
}

static NEXT_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(40000);

fn allocate_ephemeral_port() -> u16 {
    let port = NEXT_PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if port == 0 || port >= 65535 {
        NEXT_PORT.store(40000, std::sync::atomic::Ordering::Relaxed);
        40000
    } else {
        port
    }
}
