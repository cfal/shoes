use crate::ip_stack::{packet::PacketBuffer, wake::Wake};
use gotatun::{
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
    udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams},
};
use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::{mpsc, oneshot};

pub(super) struct IpSink {
    pub sender: mpsc::Sender<PacketBuffer>,
    pub wake: Wake,
    pub mtu: u16,
    pub drops: Arc<AtomicU64>,
}
impl IpSend for IpSink {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let packet = packet.into_bytes();
        if packet.len() > self.mtu as usize {
            self.drops.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        match self.sender.try_send(PacketBuffer::copy_from_slice(&packet)) {
            Ok(()) => self.wake.notify(),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.drops.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
        }
        Ok(())
    }
}
pub(super) struct IpSource {
    pub receiver: mpsc::Receiver<PacketBuffer>,
    pub mtu: u16,
}
impl IpRecv for IpSource {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let packet = self
            .receiver
            .recv()
            .await
            .ok_or(io::ErrorKind::BrokenPipe)?;
        let packet = pool
            .get()
            .overwrite_with(&*packet)
            .try_into_ip()
            .map_err(io::Error::other)?;
        Ok(std::iter::once(packet))
    }
    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(self.mtu)
    }
}

struct Socket {
    socket: Option<tokio::net::UdpSocket>,
    closed: Option<oneshot::Sender<()>>,
    ipv6: bool,
}
impl Drop for Socket {
    fn drop(&mut self) {
        drop(self.socket.take());
        if let Some(closed) = self.closed.take() {
            let _ = closed.send(());
        }
    }
}
#[derive(Clone)]
pub(super) struct Udp(Arc<Socket>);
pub(super) struct Factory(Option<(UdpSender, UdpReceiver)>);

#[derive(Clone)]
pub(super) enum UdpSender {
    Direct(Udp),
    Detour(super::detour::Sender),
}

pub(super) enum UdpReceiver {
    Direct(Udp),
    Detour(super::detour::Receiver),
}

impl Factory {
    pub fn new(
        listen: Option<SocketAddr>,
        interface: Option<String>,
    ) -> io::Result<(Self, oneshot::Receiver<()>, SocketAddr)> {
        let socket = if let Some(listen) = listen {
            let socket = crate::socket_util::new_outbound_socket2_udp_socket(
                listen.is_ipv6(),
                interface,
                Some(listen),
            )?;
            tokio::net::UdpSocket::from_std(socket.into())?
        } else {
            crate::socket_util::new_hostname_udp_socket(interface)?
        };
        let local = socket.local_addr()?;
        let (closed, released) = oneshot::channel();
        let udp = Udp(Arc::new(Socket {
            socket: Some(socket),
            closed: Some(closed),
            ipv6: local.is_ipv6(),
        }));
        Ok((
            Self(Some((
                UdpSender::Direct(udp.clone()),
                UdpReceiver::Direct(udp),
            ))),
            released,
            local,
        ))
    }

    pub fn detour(sender: super::detour::Sender, receiver: super::detour::Receiver) -> Self {
        Self(Some((
            UdpSender::Detour(sender),
            UdpReceiver::Detour(receiver),
        )))
    }
}
impl UdpTransportFactory for Factory {
    type Send = UdpSender;
    type Recv = UdpReceiver;
    async fn bind(
        &mut self,
        _: &UdpTransportFactoryParams,
    ) -> io::Result<(UdpSender, UdpReceiver)> {
        self.0.take().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "WireGuard socket reconfiguration requires reload",
            )
        })
    }
}

impl UdpSend for UdpSender {
    type SendManyBuf = ();
    async fn send_to(&self, packet: Packet, target: SocketAddr) -> io::Result<()> {
        match self {
            Self::Direct(socket) => socket.send_to(packet, target).await,
            Self::Detour(sender) => sender.send_to(packet, target),
        }
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        match self {
            Self::Direct(socket) => socket.local_addr(),
            Self::Detour(_) => Ok(None),
        }
    }
}

impl UdpRecv for UdpReceiver {
    type RecvManyBuf = ();
    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        match self {
            Self::Direct(socket) => socket.recv_from(pool).await,
            Self::Detour(receiver) => receiver.recv_from(pool).await,
        }
    }
}
impl UdpSend for Udp {
    type SendManyBuf = ();
    async fn send_to(&self, packet: Packet, mut target: SocketAddr) -> io::Result<()> {
        if self.0.ipv6
            && let std::net::IpAddr::V4(ip) = target.ip()
        {
            target.set_ip(ip.to_ipv6_mapped().into());
        }
        let len = self
            .0
            .socket
            .as_ref()
            .unwrap()
            .send_to(&packet, target)
            .await?;
        if len != packet.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        Ok(())
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.0.socket.as_ref().unwrap().local_addr().map(Some)
    }
}
impl UdpRecv for Udp {
    type RecvManyBuf = ();
    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let mut packet = pool.get();
        let (len, mut source) = self
            .0
            .socket
            .as_ref()
            .unwrap()
            .recv_from(packet.buf_mut())
            .await?;
        packet.truncate(len);
        if let std::net::IpAddr::V6(ip) = source.ip()
            && let Some(ip) = ip.to_ipv4_mapped()
        {
            source.set_ip(ip.into());
        }
        Ok((packet, source))
    }
}
