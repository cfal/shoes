//! Virtual network stack for AmneziaWG outbound connections.
//!
//! Uses smoltcp to provide a virtual TCP/IP stack that emits IP packets
//! for the AmneziaWG tunnel to encapsulate, and accepts decapsulated
//! IP packets from the tunnel.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use log::{debug, error, warn};
use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{
    CongestionControl, Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState,
};
use smoltcp::socket::udp::{
    PacketBuffer as UdpPacketBuffer, PacketMetadata as UdpPacketMetadata, Socket as UdpSocket,
};
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use super::tunnel::TunnelRuntime;

/// TCP send/recv buffer size.
const TCP_BUFFER_SIZE: usize = 256 * 1024;

/// Virtual device that queues IP packets instead of sending them on a wire.
struct VirtualDevice {
    /// Packets received from the tunnel (to inject into smoltcp).
    rx_queue: Vec<Vec<u8>>,
    /// Packets emitted by smoltcp (to send through the tunnel).
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

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.rx_queue.is_empty() {
            return None;
        }
        let packet = self.rx_queue.remove(0);
        // Collect tx_queue pointer for deferred push
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
        // SAFETY: The tx_queue pointer is valid for the duration of the Device::receive/transmit
        // call, and VirtualTxToken is consumed within that scope by smoltcp's poll().
        unsafe {
            (*self.tx_queue).push(buffer);
        }
        result
    }
}

/// Virtual network stack manager.
///
/// Runs in a tokio task, polling smoltcp and bridging IP packets
/// to/from the tunnel runtime.
pub struct VirtualNetStack {
    /// Send IP packets from smoltcp to tunnel for encapsulation.
    ip_to_tunnel: mpsc::Sender<Vec<u8>>,
    /// Receive decapsulated IP packets from tunnel.
    ip_from_tunnel: mpsc::Receiver<Vec<u8>>,
    /// The smoltcp interface.
    iface: Interface,
    /// The virtual device.
    device: VirtualDevice,
    /// Socket set.
    sockets: SocketSet<'static>,
    /// Active TCP connections waiting for completion.
    pending_tcp: HashMap<SocketHandle, PendingTcpConn>,
    /// Active UDP sockets.
    pending_udp: HashMap<SocketHandle, PendingUdpSession>,
}

struct PendingTcpConn {
    tx: tokio::sync::oneshot::Sender<std::io::Result<VirtualTcpStream>>,
    target: SocketAddr,
}

struct PendingUdpSession {
    target: SocketAddr,
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

        // Add local addresses to the interface
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

        // Add default routes
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

        let sockets = SocketSet::new(vec![]);

        Self {
            ip_to_tunnel,
            ip_from_tunnel,
            iface,
            device,
            sockets,
            pending_tcp: HashMap::new(),
            pending_udp: HashMap::new(),
        }
    }

    /// Run the netstack polling loop. This is the main event loop.
    pub async fn run(mut self, mut conn_rx: mpsc::Receiver<NetStackRequest>) {
        let mut poll_interval = tokio::time::interval(std::time::Duration::from_millis(1));

        loop {
            tokio::select! {
                // Process new connection requests
                request = conn_rx.recv() => {
                    match request {
                        Some(NetStackRequest::ConnectTcp { target, reply }) => {
                            self.initiate_tcp_connect(target, reply);
                        }
                        Some(NetStackRequest::ConnectUdp { target, reply }) => {
                            self.initiate_udp_connect(target, reply);
                        }
                        None => {
                            debug!("AmneziaWG netstack: request channel closed, stopping");
                            break;
                        }
                    }
                }
                // Receive decapsulated IP packets from tunnel
                Some(packet) = self.ip_from_tunnel.recv() => {
                    self.device.rx_queue.push(packet);
                }
                // Periodic poll
                _ = poll_interval.tick() => {}
            }

            // Poll smoltcp
            let now = SmolInstant::now();
            let changed = self.iface.poll(now, &mut self.device, &mut self.sockets);

            // Send any outbound IP packets to the tunnel
            for packet in self.device.tx_queue.drain(..) {
                if self.ip_to_tunnel.try_send(packet).is_err() {
                    warn!("AmneziaWG netstack: tunnel TX channel full, dropping packet");
                }
            }

            // Check TCP connection states
            self.check_tcp_connections();
        }
    }

    fn initiate_tcp_connect(
        &mut self,
        target: SocketAddr,
        reply: tokio::sync::oneshot::Sender<std::io::Result<VirtualTcpStream>>,
    ) {
        let mut rx_buf = TcpSocketBuffer::new(vec![0u8; TCP_BUFFER_SIZE]);
        let mut tx_buf = TcpSocketBuffer::new(vec![0u8; TCP_BUFFER_SIZE]);
        let mut socket = TcpSocket::new(rx_buf, tx_buf);
        socket.set_nagle_enabled(false);
        socket.set_congestion_control(CongestionControl::Cubic);

        let local_port = allocate_ephemeral_port();
        let remote = IpEndpoint::new(
            match target.ip() {
                IpAddr::V4(v4) => IpAddress::Ipv4(smoltcp::wire::Ipv4Address::from(v4)),
                IpAddr::V6(v6) => IpAddress::Ipv6(smoltcp::wire::Ipv6Address::from(v6)),
            },
            target.port(),
        );

        if let Err(e) = socket.connect(
            self.iface.context(),
            remote,
            local_port,
        ) {
            let _ = reply.send(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("smoltcp connect error: {}", e),
            )));
            return;
        }

        let handle = self.sockets.add(socket);
        self.pending_tcp.insert(handle, PendingTcpConn { tx: reply, target });
    }

    fn initiate_udp_connect(
        &mut self,
        target: SocketAddr,
        reply: tokio::sync::oneshot::Sender<std::io::Result<VirtualUdpSession>>,
    ) {
        let rx_buf = UdpPacketBuffer::new(
            vec![UdpPacketMetadata::EMPTY; 64],
            vec![0u8; 65536],
        );
        let tx_buf = UdpPacketBuffer::new(
            vec![UdpPacketMetadata::EMPTY; 64],
            vec![0u8; 65536],
        );
        let mut socket = UdpSocket::new(rx_buf, tx_buf);

        let local_port = allocate_ephemeral_port();
        if let Err(e) = socket.bind(local_port) {
            let _ = reply.send(Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("smoltcp UDP bind error: {}", e),
            )));
            return;
        }

        let handle = self.sockets.add(socket);

        // Create the UDP session with channels
        let (send_tx, send_rx) = mpsc::channel::<Vec<u8>>(128);
        let (recv_tx, recv_rx) = mpsc::channel::<Vec<u8>>(128);

        self.pending_udp.insert(handle, PendingUdpSession { target });

        let session = VirtualUdpSession {
            handle,
            target,
            send_tx,
            recv_rx,
        };

        let _ = reply.send(Ok(session));
    }

    fn check_tcp_connections(&mut self) {
        let mut completed = Vec::new();

        for (handle, pending) in &self.pending_tcp {
            let socket = self.sockets.get::<TcpSocket>(*handle);
            match socket.state() {
                TcpState::Established => {
                    completed.push(*handle);
                }
                TcpState::Closed | TcpState::Closing | TcpState::TimeWait => {
                    completed.push(*handle);
                }
                _ => {}
            }
        }

        for handle in completed {
            if let Some(pending) = self.pending_tcp.remove(&handle) {
                let socket = self.sockets.get::<TcpSocket>(handle);
                if socket.state() == TcpState::Established {
                    // Create channels for the TCP stream
                    let (send_tx, send_rx) = mpsc::channel::<Vec<u8>>(64);
                    let (recv_tx, recv_rx) = mpsc::channel::<Vec<u8>>(64);

                    let stream = VirtualTcpStream {
                        handle,
                        send_tx,
                        recv_rx,
                    };

                    let _ = pending.tx.send(Ok(stream));
                } else {
                    let _ = pending.tx.send(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        format!(
                            "TCP connection to {} failed (state: {:?})",
                            pending.target,
                            socket.state()
                        ),
                    )));
                    self.sockets.remove(handle);
                }
            }
        }
    }
}

/// Request to the netstack.
pub enum NetStackRequest {
    ConnectTcp {
        target: SocketAddr,
        reply: tokio::sync::oneshot::Sender<std::io::Result<VirtualTcpStream>>,
    },
    ConnectUdp {
        target: SocketAddr,
        reply: tokio::sync::oneshot::Sender<std::io::Result<VirtualUdpSession>>,
    },
}

/// A virtual TCP stream backed by a smoltcp TCP socket.
pub struct VirtualTcpStream {
    handle: SocketHandle,
    send_tx: mpsc::Sender<Vec<u8>>,
    recv_rx: mpsc::Receiver<Vec<u8>>,
}

/// A virtual UDP session backed by a smoltcp UDP socket.
pub struct VirtualUdpSession {
    handle: SocketHandle,
    target: SocketAddr,
    send_tx: mpsc::Sender<Vec<u8>>,
    recv_rx: mpsc::Receiver<Vec<u8>>,
}

/// Port allocator for ephemeral ports.
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
