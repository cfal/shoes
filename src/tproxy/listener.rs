//! Socket factories that apply the IP_TRANSPARENT family of options.

// Functions are pub API consumed by Task 8 (wiring); suppress dead-code lint
// until that wiring is in place.
#![allow(dead_code)]

use std::net::SocketAddr;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// Set `IP_TRANSPARENT` (v4) or `IPV6_TRANSPARENT` (v6) on the socket.
fn set_ip_transparent(socket: &Socket, is_ipv6: bool) -> std::io::Result<()> {
    let fd = std::os::fd::AsRawFd::as_raw_fd(socket);
    let on: libc::c_int = 1;
    let (level, name) = if is_ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_TRANSPARENT)
    } else {
        (libc::IPPROTO_IP, libc::IP_TRANSPARENT)
    };
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of_val(&on) as libc::socklen_t,
        )
    };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Set `IP_RECVORIGDSTADDR` (v4) and/or `IPV6_RECVORIGDSTADDR` (v6) on a UDP socket.
fn set_recv_orig_dst_addr(socket: &Socket, is_ipv6: bool) -> std::io::Result<()> {
    let fd = std::os::fd::AsRawFd::as_raw_fd(socket);
    let on: libc::c_int = 1;
    let (level, name) = if is_ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVORIGDSTADDR)
    } else {
        (libc::IPPROTO_IP, libc::IP_RECVORIGDSTADDR)
    };
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of_val(&on) as libc::socklen_t,
        )
    };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Create a TCP listener with `IP_TRANSPARENT` set, ready for `tokio::accept`.
pub fn new_tproxy_tcp_listener(bind: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    let domain = if bind.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    set_ip_transparent(&socket, bind.is_ipv6())?;
    socket.bind(&SockAddr::from(bind))?;
    socket.listen(4096)?;
    let std_listener: std::net::TcpListener = socket.into();
    tokio::net::TcpListener::from_std(std_listener)
}

/// Create a UDP socket with `IP_TRANSPARENT` and `IP_RECVORIGDSTADDR` set.
pub fn new_tproxy_udp_socket(bind: SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
    let domain = if bind.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    set_ip_transparent(&socket, bind.is_ipv6())?;
    set_recv_orig_dst_addr(&socket, bind.is_ipv6())?;
    socket.bind(&SockAddr::from(bind))?;
    let std_sock: std::net::UdpSocket = socket.into();
    tokio::net::UdpSocket::from_std(std_sock)
}

/// Create a per-orig-dst send socket bound to `orig_dst` with `IP_TRANSPARENT`
/// for spoofing the source of UDP replies back to the client.
pub fn new_tproxy_udp_send_socket(orig_dst: SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
    let domain = if orig_dst.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    // SO_REUSEPORT lets multiple per-orig_dst sockets coexist on the same local address.
    socket.set_reuse_port(true)?;
    set_ip_transparent(&socket, orig_dst.is_ipv6())?;
    socket.bind(&SockAddr::from(orig_dst))?;
    let std_sock: std::net::UdpSocket = socket.into();
    tokio::net::UdpSocket::from_std(std_sock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn tcp_listener_accepts_local_connection() {
        let listener = match new_tproxy_tcp_listener(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)) {
            Ok(l) => l,
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
                eprintln!("skipping: tproxy listener bind requires CAP_NET_ADMIN");
                return;
            }
            Err(e) => panic!("listener bind failed: {e}"),
        };
        let bind_addr = listener.local_addr().unwrap();

        let connect = tokio::spawn(async move {
            tokio::net::TcpStream::connect(bind_addr).await
        });

        let (server_stream, _peer) = listener.accept().await.unwrap();
        let server_local = server_stream.local_addr().unwrap();
        assert_eq!(server_local.port(), bind_addr.port());
        let _ = connect.await.unwrap().expect("client connect");
    }

    #[tokio::test]
    async fn udp_socket_round_trip_loopback() {
        let socket = match new_tproxy_udp_socket(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)) {
            Ok(s) => s,
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
                eprintln!("skipping: tproxy udp bind requires CAP_NET_ADMIN");
                return;
            }
            Err(e) => panic!("udp bind failed: {e}"),
        };
        let bind_addr = socket.local_addr().unwrap();

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"hello", bind_addr).await.unwrap();

        let mut buf = [0u8; 64];
        let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(peer.ip(), std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));
    }
}
