use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};

use log::error;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

pub fn new_udp_socket(
    is_ipv6: bool,
    bind_interface: Option<String>,
) -> std::io::Result<tokio::net::UdpSocket> {
    let socket = new_socket2_udp_socket(
        is_ipv6,
        bind_interface,
        Some(get_unspecified_socket_addr(is_ipv6)),
        false,
    )?;

    into_tokio_udp_socket(socket)
}

pub fn new_reuse_udp_sockets(
    is_ipv6: bool,
    bind_interface: Option<String>,
    count: usize,
) -> std::io::Result<Vec<tokio::net::UdpSocket>> {
    let mut sockets = Vec::with_capacity(count);
    if count == 0 {
        return Ok(sockets);
    }

    let socket = new_socket2_udp_socket(
        is_ipv6,
        bind_interface.clone(),
        Some(get_unspecified_socket_addr(is_ipv6)),
        true,
    )?;

    let local_addr = socket.local_addr()?.as_socket().unwrap();

    sockets.push(into_tokio_udp_socket(socket)?);

    for _ in 1..count {
        let socket =
            new_socket2_udp_socket(is_ipv6, bind_interface.clone(), Some(local_addr), true)?;
        sockets.push(into_tokio_udp_socket(socket)?);
    }

    Ok(sockets)
}

fn get_unspecified_socket_addr(is_ipv6: bool) -> SocketAddr {
    if !is_ipv6 {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)
    } else {
        "[::]:0".parse().unwrap()
    }
}

pub fn new_socket2_udp_socket(
    is_ipv6: bool,
    bind_interface: Option<String>,
    bind_address: Option<SocketAddr>,
    reuse_port: bool,
) -> std::io::Result<socket2::Socket> {
    let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_nonblocking(true)?;

    if reuse_port {
        #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
        socket.set_reuse_port(true)?;

        #[cfg(any(not(unix), target_os = "solaris", target_os = "illumos"))]
        panic!("Cannot support reuse sockets");
    }

    if let Some(ref interface) = bind_interface {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        socket.bind_device(Some(interface.as_bytes()))?;

        // This should be handled during config validation.
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        panic!("Could not bind to device, unsupported platform.")
    }

    if let Some(bind_address) = bind_address {
        socket.bind(&SockAddr::from(bind_address))?;
    }

    Ok(socket)
}

fn into_tokio_udp_socket(socket: socket2::Socket) -> std::io::Result<tokio::net::UdpSocket> {
    let raw_fd = socket.into_raw_fd();
    let std_udp_socket = unsafe { std::net::UdpSocket::from_raw_fd(raw_fd) };
    tokio::net::UdpSocket::from_std(std_udp_socket)
}

pub fn set_server_tcp_fastopen<T: AsRawFd>(tcp_socket: &T) {
    // TODO: implement for windows
    #[cfg(unix)]
    {
        // queue length on linux, enable/disable otherwise
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let value: libc::c_int = 256;

        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let value: libc::c_int = 1;

        unsafe {
            let ret = libc::setsockopt(
                tcp_socket.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_FASTOPEN,
                &value as *const libc::c_int as *const libc::c_void,
                std::mem::size_of_val(&value) as libc::socklen_t,
            );
            if ret < 0 {
                error!(
                    "failed to set TCP fastopen: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }
}

pub fn new_tcp_socket(
    bind_interface: Option<String>,
    is_ipv6: bool,
) -> std::io::Result<tokio::net::TcpSocket> {
    let tcp_socket = if is_ipv6 {
        tokio::net::TcpSocket::new_v6()?
    } else {
        tokio::net::TcpSocket::new_v4()?
    };

    if let Some(_b) = bind_interface {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        tcp_socket.bind_device(Some(_b.as_bytes()))?;

        // This should be handled during config validation.
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        panic!("Could not find to device, unsupported platform.")
    }

    Ok(tcp_socket)
}
