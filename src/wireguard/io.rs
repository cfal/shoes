use crate::ip_stack::{driver::PacketDrops, packet::PacketBuffer, wake::Wake};
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
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tokio::sync::{mpsc, oneshot};

const IP_BATCH_SIZE: usize = 64;

pub(super) struct IpSink {
    pub sender: mpsc::Sender<PacketBuffer>,
    pub wake: Wake,
    pub mtu: u16,
    pub drops: Arc<PacketDrops>,
}
impl IpSend for IpSink {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let packet = packet.into_bytes();
        if packet.len() > self.mtu as usize {
            self.drops.mtu_exceeded.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        self.sender
            .send(PacketBuffer::copy_from_slice(&packet))
            .await
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        self.wake.notify();
        Ok(())
    }
}

pub(super) struct IpSource {
    receiver: mpsc::Receiver<PacketBuffer>,
    wake: Wake,
    egress_backpressured: Arc<AtomicBool>,
    batch: Vec<PacketBuffer>,
    mtu: u16,
}
impl IpSource {
    pub fn new(
        receiver: mpsc::Receiver<PacketBuffer>,
        wake: Wake,
        egress_backpressured: Arc<AtomicBool>,
        mtu: u16,
    ) -> Self {
        Self {
            receiver,
            wake,
            egress_backpressured,
            batch: Vec::with_capacity(IP_BATCH_SIZE),
            mtu,
        }
    }
}
impl IpRecv for IpSource {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        self.batch.clear();
        if self
            .receiver
            .recv_many(&mut self.batch, IP_BATCH_SIZE)
            .await
            == 0
        {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        // Draining before clearing the flag lets a paused stack observe the freed capacity.
        if self.egress_backpressured.swap(false, Ordering::AcqRel) {
            self.wake.notify();
        }
        let mut packets = Vec::with_capacity(self.batch.len());
        for packet in self.batch.drain(..) {
            packets.push(
                pool.get()
                    .overwrite_with(&*packet)
                    .try_into_ip()
                    .map_err(io::Error::other)?,
            );
        }
        Ok(packets.into_iter())
    }
    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(self.mtu)
    }
}

struct Socket {
    socket: Option<tokio::net::UdpSocket>,
    closed: Option<oneshot::Sender<()>>,
    ipv6: bool,
    receive_errors: AtomicUsize,
    send_errors: AtomicUsize,
}
impl Drop for Socket {
    fn drop(&mut self) {
        // Releases the bind before notifying shutdown waiters.
        drop(self.socket.take());
        if let Some(closed) = self.closed.take() {
            let _ = closed.send(());
        }
    }
}
impl Socket {
    fn socket(&self) -> &tokio::net::UdpSocket {
        self.socket.as_ref().unwrap()
    }

    /// Reports whether a receive error is per-datagram and the socket remains usable.
    fn retry_receive(&self, error: &io::Error) -> bool {
        if error.kind() == io::ErrorKind::Interrupted {
            return true;
        }
        if !matches!(
            error.raw_os_error(),
            Some(
                libc::ENOBUFS
                    | libc::ENOMEM
                    | libc::EMSGSIZE
                    | libc::ECONNREFUSED
                    | libc::EHOSTUNREACH
                    | libc::ENETUNREACH
            )
        ) {
            return false;
        }
        let count = self.receive_errors.fetch_add(1, Ordering::Relaxed) + 1;
        if count.is_power_of_two() {
            log::warn!("WireGuard UDP receive error ignored: {error} ({count} total)");
        } else {
            log::debug!("WireGuard UDP receive error ignored: {error}");
        }
        true
    }

    /// Reports whether a batched send error is specific to the failing datagram so the rest of
    /// the batch for healthy peers can still be sent.
    fn skip_send_error(&self, error: &io::Error) -> bool {
        if !matches!(
            error.raw_os_error(),
            Some(
                libc::EHOSTUNREACH
                    | libc::ENETUNREACH
                    | libc::ECONNREFUSED
                    | libc::EMSGSIZE
                    | libc::EPERM
                    | libc::EACCES
                    | libc::EINVAL
                    | libc::EADDRNOTAVAIL
                    | libc::EAFNOSUPPORT
                    | libc::ENOBUFS
                    | libc::ENOMEM
                    | libc::ENETDOWN
                    | libc::EHOSTDOWN
            )
        ) {
            return false;
        }
        let count = self.send_errors.fetch_add(1, Ordering::Relaxed) + 1;
        if count.is_power_of_two() {
            log::warn!("WireGuard UDP send error dropped datagram: {error} ({count} total)");
        } else {
            log::debug!("WireGuard UDP send error dropped datagram: {error}");
        }
        true
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
        buffer_size: usize,
    ) -> io::Result<(Self, oneshot::Receiver<()>, SocketAddr)> {
        let socket = if let Some(listen) = listen {
            let socket = crate::socket_util::new_outbound_socket2_udp_socket_with_buffer_size(
                listen.is_ipv6(),
                interface,
                Some(listen),
                Some(buffer_size),
            )?;
            tokio::net::UdpSocket::from_std(socket.into())?
        } else {
            crate::socket_util::new_hostname_udp_socket_with_buffer_size(
                interface,
                Some(buffer_size),
            )?
        };
        let local = socket.local_addr()?;
        let (closed, released) = oneshot::channel();
        let udp = Udp(Arc::new(Socket {
            socket: Some(socket),
            closed: Some(closed),
            ipv6: local.is_ipv6(),
            receive_errors: AtomicUsize::new(0),
            send_errors: AtomicUsize::new(0),
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
    type SendManyBuf = <Udp as UdpSend>::SendManyBuf;
    async fn send_to(&self, packet: Packet, target: SocketAddr) -> io::Result<()> {
        match self {
            Self::Direct(socket) => socket.send_to(packet, target).await,
            Self::Detour(sender) => sender.send_to(packet, target),
        }
    }
    fn max_number_of_packets_to_send(&self) -> usize {
        match self {
            Self::Direct(socket) => socket.max_number_of_packets_to_send(),
            Self::Detour(_) => 1,
        }
    }
    async fn send_many_to(
        &self,
        buffer: &mut Self::SendManyBuf,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        match self {
            Self::Direct(socket) => socket.send_many_to(buffer, packets).await,
            Self::Detour(sender) => {
                for (packet, target) in packets.drain(..) {
                    sender.send_to(packet, target)?;
                }
                Ok(())
            }
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
    type RecvManyBuf = <Udp as UdpRecv>::RecvManyBuf;
    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        match self {
            Self::Direct(socket) => socket.recv_from(pool).await,
            Self::Detour(receiver) => receiver.recv_from(pool).await,
        }
    }
    async fn recv_many_from(
        &mut self,
        buffer: &mut Self::RecvManyBuf,
        pool: &mut PacketBufPool,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        match self {
            Self::Direct(socket) => socket.recv_many_from(buffer, pool, packets).await,
            Self::Detour(receiver) => receiver.recv_many_from(pool, packets).await,
        }
    }
}

impl UdpSend for Udp {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    type SendManyBuf = batch::DirectSendManyBuf;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    type SendManyBuf = ();
    async fn send_to(&self, packet: Packet, mut target: SocketAddr) -> io::Result<()> {
        if self.0.ipv6
            && let std::net::IpAddr::V4(ip) = target.ip()
        {
            target.set_ip(ip.to_ipv6_mapped().into());
        }
        let len = self.0.socket().send_to(&packet, target).await?;
        if len != packet.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        Ok(())
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn max_number_of_packets_to_send(&self) -> usize {
        batch::UDP_BATCH_SIZE
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    async fn send_many_to(
        &self,
        buffer: &mut batch::DirectSendManyBuf,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let socket = self.0.socket();
        let fd = socket.as_raw_fd();
        let mut offset = 0;
        while offset < packets.len() {
            let count = (packets.len() - offset).min(batch::UDP_BATCH_SIZE);
            buffer.prepare(&packets[offset..offset + count], self.0.ipv6);
            match socket
                .async_io(tokio::io::Interest::WRITABLE, || buffer.send(fd, count))
                .await
            {
                Ok(0) => {
                    packets.drain(..offset);
                    return Err(io::ErrorKind::WriteZero.into());
                }
                Ok(sent) => {
                    offset += sent;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                // On Linux, `sendmmsg` returns an error only when the first message in the slice
                // fails; discard that datagram so remaining peers in the batch still send.
                Err(error) if self.0.skip_send_error(&error) => {
                    offset += 1;
                }
                Err(error) => {
                    packets.drain(..offset);
                    return Err(error);
                }
            }
        }
        packets.clear();
        Ok(())
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.0.socket().local_addr().map(Some)
    }
}
impl UdpRecv for Udp {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    type RecvManyBuf = batch::DirectRecvManyBuf;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    type RecvManyBuf = ();
    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        loop {
            let mut packet = pool.get();
            match self.0.socket().recv_from(packet.buf_mut()).await {
                Ok((len, source)) => {
                    packet.truncate(len);
                    return Ok((packet, super::canonical_socket_addr(source)));
                }
                Err(error) if self.0.retry_receive(&error) => {}
                Err(error) => return Err(error),
            }
        }
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    async fn recv_many_from(
        &mut self,
        buffer: &mut batch::DirectRecvManyBuf,
        pool: &mut PacketBufPool,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let socket = self.0.socket();
        let fd = socket.as_raw_fd();
        loop {
            buffer.stage(pool);
            match socket
                .async_io(tokio::io::Interest::READABLE, || buffer.receive(fd))
                .await
            {
                // Batches consisting only of empty or truncated datagrams wait for more input.
                Ok(count) => {
                    if buffer.collect(count, packets) > 0 {
                        return Ok(());
                    }
                }
                Err(error) if self.0.retry_receive(&error) => {}
                Err(error) => return Err(error),
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod batch {
    use gotatun::packet::{Packet, PacketBufPool};
    use std::{
        io,
        mem::{size_of, zeroed},
        net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
        os::fd::RawFd,
    };

    pub(super) const UDP_BATCH_SIZE: usize = 64;

    /// Points `recvmmsg` directly at pooled packet buffers, avoiding a scratch copy.
    pub(crate) struct DirectRecvManyBuf {
        headers: Box<[libc::mmsghdr; UDP_BATCH_SIZE]>,
        iovecs: Box<[libc::iovec; UDP_BATCH_SIZE]>,
        addresses: Box<[libc::sockaddr_storage; UDP_BATCH_SIZE]>,
        staged: Vec<Packet>,
    }

    // SAFETY: The raw pointers only reference buffers owned by this value and are rebuilt
    // before each syscall, which runs while the value is exclusively borrowed.
    unsafe impl Send for DirectRecvManyBuf {}

    impl Default for DirectRecvManyBuf {
        fn default() -> Self {
            // SAFETY: These are plain C structs for which all-zero bytes are valid.
            unsafe {
                Self {
                    headers: Box::new(zeroed()),
                    iovecs: Box::new(zeroed()),
                    addresses: Box::new(zeroed()),
                    staged: Vec::with_capacity(UDP_BATCH_SIZE),
                }
            }
        }
    }

    impl DirectRecvManyBuf {
        pub(super) fn stage(&mut self, pool: &PacketBufPool) {
            while self.staged.len() < UDP_BATCH_SIZE {
                self.staged.push(pool.get());
            }
            for (index, packet) in self.staged.iter_mut().enumerate() {
                self.iovecs[index] = libc::iovec {
                    iov_base: packet.as_mut_ptr().cast(),
                    iov_len: packet.len(),
                };
                let header = &mut self.headers[index].msg_hdr;
                header.msg_name = (&raw mut self.addresses[index]).cast();
                header.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                header.msg_iov = &raw mut self.iovecs[index];
                header.msg_iovlen = 1 as _;
                header.msg_control = std::ptr::null_mut();
                header.msg_controllen = 0 as _;
                header.msg_flags = 0;
            }
        }

        pub(super) fn receive(&mut self, fd: RawFd) -> io::Result<usize> {
            // SAFETY: `stage` pointed every header at live buffers owned by `self`.
            let count = unsafe {
                libc::recvmmsg(
                    fd,
                    self.headers.as_mut_ptr(),
                    UDP_BATCH_SIZE as libc::c_uint,
                    libc::MSG_DONTWAIT as _,
                    std::ptr::null_mut::<libc::timespec>(),
                )
            };
            if count < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(count as usize)
        }

        /// Moves received datagrams into `packets` and returns how many were accepted.
        pub(super) fn collect(
            &mut self,
            count: usize,
            packets: &mut Vec<(Packet, SocketAddr)>,
        ) -> usize {
            let before = packets.len();
            for (index, mut packet) in self.staged.drain(..count).enumerate() {
                let header = &self.headers[index];
                let len = header.msg_len as usize;
                if len == 0 || header.msg_hdr.msg_flags & libc::MSG_TRUNC != 0 {
                    continue;
                }
                let Some(source) =
                    decode_address(&self.addresses[index], header.msg_hdr.msg_namelen)
                else {
                    continue;
                };
                packet.truncate(len);
                packets.push((packet, super::super::canonical_socket_addr(source)));
            }
            packets.len() - before
        }
    }

    pub(crate) struct DirectSendManyBuf {
        headers: Box<[libc::mmsghdr; UDP_BATCH_SIZE]>,
        iovecs: Box<[libc::iovec; UDP_BATCH_SIZE]>,
        addresses: Box<[libc::sockaddr_storage; UDP_BATCH_SIZE]>,
    }

    // SAFETY: The raw pointers are rebuilt from caller-owned packets before each syscall,
    // which runs while the value is exclusively borrowed.
    unsafe impl Send for DirectSendManyBuf {}
    unsafe impl Sync for DirectSendManyBuf {}

    impl Default for DirectSendManyBuf {
        fn default() -> Self {
            // SAFETY: These are plain C structs for which all-zero bytes are valid.
            unsafe {
                Self {
                    headers: Box::new(zeroed()),
                    iovecs: Box::new(zeroed()),
                    addresses: Box::new(zeroed()),
                }
            }
        }
    }

    impl DirectSendManyBuf {
        pub(super) fn prepare(&mut self, packets: &[(Packet, SocketAddr)], ipv6: bool) {
            for (index, (packet, target)) in packets.iter().enumerate() {
                let mut target = *target;
                if ipv6 && let std::net::IpAddr::V4(ip) = target.ip() {
                    target.set_ip(ip.to_ipv6_mapped().into());
                }
                self.iovecs[index] = libc::iovec {
                    iov_base: packet.as_ptr().cast_mut().cast(),
                    iov_len: packet.len(),
                };
                let header = &mut self.headers[index].msg_hdr;
                header.msg_name = (&raw mut self.addresses[index]).cast();
                header.msg_namelen = encode_address(target, &mut self.addresses[index]);
                header.msg_iov = &raw mut self.iovecs[index];
                header.msg_iovlen = 1 as _;
                header.msg_control = std::ptr::null_mut();
                header.msg_controllen = 0 as _;
                header.msg_flags = 0;
            }
        }

        pub(super) fn send(&mut self, fd: RawFd, count: usize) -> io::Result<usize> {
            // SAFETY: `prepare` pointed the first `count` headers at live packets and addresses.
            let sent = unsafe {
                libc::sendmmsg(
                    fd,
                    self.headers.as_mut_ptr(),
                    count as libc::c_uint,
                    libc::MSG_DONTWAIT as _,
                )
            };
            if sent < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(sent as usize)
        }
    }

    fn encode_address(
        address: SocketAddr,
        storage: &mut libc::sockaddr_storage,
    ) -> libc::socklen_t {
        // SAFETY: sockaddr_storage is large and aligned enough for both address families.
        unsafe {
            *storage = zeroed();
            match address {
                SocketAddr::V4(address) => {
                    let raw =
                        &mut *(storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>();
                    raw.sin_family = libc::AF_INET as libc::sa_family_t;
                    raw.sin_port = address.port().to_be();
                    raw.sin_addr = libc::in_addr {
                        s_addr: u32::from_ne_bytes(address.ip().octets()),
                    };
                    size_of::<libc::sockaddr_in>() as libc::socklen_t
                }
                SocketAddr::V6(address) => {
                    let raw =
                        &mut *(storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>();
                    raw.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                    raw.sin6_port = address.port().to_be();
                    raw.sin6_flowinfo = address.flowinfo();
                    raw.sin6_addr = libc::in6_addr {
                        s6_addr: address.ip().octets(),
                    };
                    raw.sin6_scope_id = address.scope_id();
                    size_of::<libc::sockaddr_in6>() as libc::socklen_t
                }
            }
        }
    }

    fn decode_address(
        storage: &libc::sockaddr_storage,
        len: libc::socklen_t,
    ) -> Option<SocketAddr> {
        let len = len as usize;
        match storage.ss_family as libc::c_int {
            libc::AF_INET if len >= size_of::<libc::sockaddr_in>() => {
                // SAFETY: The kernel reported an AF_INET address of sufficient length.
                let raw = unsafe {
                    &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>()
                };
                Some(SocketAddr::new(
                    Ipv4Addr::from(raw.sin_addr.s_addr.to_ne_bytes()).into(),
                    u16::from_be(raw.sin_port),
                ))
            }
            libc::AF_INET6 if len >= size_of::<libc::sockaddr_in6>() => {
                // SAFETY: The kernel reported an AF_INET6 address of sufficient length.
                let raw = unsafe {
                    &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
                };
                Some(
                    SocketAddrV6::new(
                        Ipv6Addr::from(raw.sin6_addr.s6_addr),
                        u16::from_be(raw.sin6_port),
                        raw.sin6_flowinfo,
                        raw.sin6_scope_id,
                    )
                    .into(),
                )
            }
            _ => None,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn addresses_round_trip_through_socket_storage() {
            for address in [
                "192.0.2.1:51820",
                "[2001:db8::1]:51820",
                "[::ffff:192.0.2.1]:51820",
            ] {
                let address: SocketAddr = address.parse().unwrap();
                let mut storage = unsafe { zeroed() };
                let len = encode_address(address, &mut storage);
                assert_eq!(decode_address(&storage, len), Some(address));
                assert_eq!(decode_address(&storage, len - 1), None);
            }
        }
    }
}

#[cfg(test)]
mod tests;
