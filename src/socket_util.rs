use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[cfg(unix)]
use std::mem::ManuallyDrop;

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
#[cfg(target_family = "unix")]
use std::path::Path;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

pub fn new_udp_socket(
    is_ipv6: bool,
    bind_interface: Option<String>,
) -> std::io::Result<tokio::net::UdpSocket> {
    let socket = new_outbound_socket2_udp_socket(
        is_ipv6,
        bind_interface,
        Some(get_unspecified_socket_addr(is_ipv6)),
    )?;

    into_tokio_udp_socket(socket)
}

pub fn new_hostname_udp_socket(
    bind_interface: Option<String>,
) -> std::io::Result<tokio::net::UdpSocket> {
    let socket = prefer_ipv6_socket(|ipv6| {
        new_socket2_udp_socket(ipv6, None, Some(get_unspecified_socket_addr(ipv6)), false)
    })?;
    bind_udp_interface(&socket, bind_interface.as_deref())?;
    #[cfg(any(target_os = "android", target_os = "ios", all(unix, feature = "ffi")))]
    crate::tun::protect_socket(socket.as_raw_fd())?;
    into_tokio_udp_socket(socket)
}

fn prefer_ipv6_socket(
    mut create: impl FnMut(bool) -> std::io::Result<Socket>,
) -> std::io::Result<Socket> {
    match create(true) {
        Err(error) if ipv6_unavailable(&error) => create(false),
        result => result,
    }
}

fn ipv6_unavailable(error: &std::io::Error) -> bool {
    #[cfg(unix)]
    let codes = [
        libc::EAFNOSUPPORT,
        libc::EPROTONOSUPPORT,
        libc::ENOPROTOOPT,
        libc::EADDRNOTAVAIL,
    ];
    // WSAENOPROTOOPT, WSAEPROTONOSUPPORT, WSAEAFNOSUPPORT, WSAEADDRNOTAVAIL.
    #[cfg(windows)]
    let codes = [10042, 10043, 10047, 10049];
    error
        .raw_os_error()
        .is_some_and(|code| codes.contains(&code))
}

fn bind_udp_interface(socket: &Socket, interface: Option<&str>) -> std::io::Result<()> {
    if let Some(interface) = interface {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        socket.bind_device(Some(interface.as_bytes()))?;
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        {
            let _ = (socket, interface);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "binding UDP sockets to an interface is unsupported",
            ));
        }
    }
    Ok(())
}

pub fn new_outbound_socket2_udp_socket(
    is_ipv6: bool,
    bind_interface: Option<String>,
    bind_address: Option<SocketAddr>,
) -> std::io::Result<Socket> {
    let socket = new_socket2_udp_socket(is_ipv6, bind_interface, bind_address, false)?;
    #[cfg(any(target_os = "android", target_os = "ios", all(unix, feature = "ffi")))]
    crate::tun::protect_socket(socket.as_raw_fd())?;
    Ok(socket)
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
    new_socket2_udp_socket_with_buffer_size(is_ipv6, bind_interface, bind_address, reuse_port, None)
}

pub fn new_socket2_udp_socket_with_buffer_size(
    is_ipv6: bool,
    bind_interface: Option<String>,
    bind_address: Option<SocketAddr>,
    reuse_port: bool,
    buffer_size: Option<usize>,
) -> std::io::Result<socket2::Socket> {
    let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    if is_ipv6 {
        socket.set_only_v6(false)?;
    }

    socket.set_nonblocking(true)?;

    // Set socket buffer sizes if specified.
    // This helps prevent packet drops during bursts for high-throughput connections.
    if let Some(size) = buffer_size {
        // Ignore errors - kernel may cap the value
        let _ = socket.set_recv_buffer_size(size);
        let _ = socket.set_send_buffer_size(size);
    }

    if reuse_port {
        #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
        socket.set_reuse_port(true)?;

        #[cfg(any(not(unix), target_os = "solaris", target_os = "illumos"))]
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "UDP port reuse is unsupported on this platform",
        ));
    }

    bind_udp_interface(&socket, bind_interface.as_deref())?;

    if let Some(bind_address) = bind_address {
        socket.bind(&SockAddr::from(bind_address))?;
    }

    Ok(socket)
}

fn into_tokio_udp_socket(socket: socket2::Socket) -> std::io::Result<tokio::net::UdpSocket> {
    #[cfg(unix)]
    {
        let raw_fd = socket.into_raw_fd();
        let std_udp_socket = unsafe { std::net::UdpSocket::from_raw_fd(raw_fd) };
        tokio::net::UdpSocket::from_std(std_udp_socket)
    }
    #[cfg(windows)]
    {
        let std_udp_socket: std::net::UdpSocket = socket.into();
        tokio::net::UdpSocket::from_std(std_udp_socket)
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
    #[cfg(any(target_os = "android", target_os = "ios", all(unix, feature = "ffi")))]
    crate::tun::protect_socket(tcp_socket.as_raw_fd())?;

    if let Some(_b) = bind_interface {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        tcp_socket.bind_device(Some(_b.as_bytes()))?;

        // This should be handled during config validation.
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        panic!("Could not bind to device, unsupported platform.")
    }

    Ok(tcp_socket)
}

pub fn set_tcp_keepalive(
    tcp_stream: &tokio::net::TcpStream,
    idle_time: std::time::Duration,
    send_interval: std::time::Duration,
) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let raw_fd = tcp_stream.as_raw_fd();
        let socket2_socket = ManuallyDrop::new(unsafe { Socket::from_raw_fd(raw_fd) });
        if idle_time.is_zero() && send_interval.is_zero() {
            socket2_socket.set_keepalive(false)?;
        } else {
            let keepalive = socket2::TcpKeepalive::new()
                .with_time(idle_time)
                .with_interval(send_interval);
            socket2_socket.set_keepalive(true)?;
            socket2_socket.set_tcp_keepalive(&keepalive)?;
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let _ = (tcp_stream, idle_time, send_interval);
        Ok(())
    }
}

// TODO: change backlog to Option<u32> and make configuration, backlog -1 uses somaxconn on linux
// https://github.com/rust-lang/rust/blob/3534594029ed1495290e013647a1f53da561f7f1/library/std/src/os/unix/net/listener.rs#L93
pub fn new_tcp_listener(
    bind_address: SocketAddr,
    backlog: u32,
    bind_interface: Option<String>,
) -> std::io::Result<tokio::net::TcpListener> {
    let domain = if bind_address.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;

    if let Some(ref interface) = bind_interface {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        socket.bind_device(Some(interface.as_bytes()))?;

        // This should be handled during config validation.
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        panic!("Could not bind to device, unsupported platform.")
    }

    socket.bind(&SockAddr::from(bind_address))?;

    let backlog = backlog.try_into().unwrap_or(4096);
    socket.listen(backlog)?;

    let std_listener: std::net::TcpListener = socket.into();
    tokio::net::TcpListener::from_std(std_listener)
}

#[cfg(target_family = "unix")]
pub fn new_unix_listener<P: AsRef<Path>>(
    path: P,
    backlog: u32,
) -> std::io::Result<tokio::net::UnixListener> {
    let path = path.as_ref();

    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    socket.set_nonblocking(true)?;

    let addr = SockAddr::unix(path)?;
    socket.bind(&addr)?;

    let backlog = backlog.try_into().unwrap_or(4096);
    socket.listen(backlog)?;

    let std_listener: std::os::unix::net::UnixListener = socket.into();
    tokio::net::UnixListener::from_std(std_listener)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_socket_fallback_is_limited_to_family_errors() {
        #[cfg(unix)]
        let unavailable = libc::EAFNOSUPPORT;
        #[cfg(windows)]
        let unavailable = 10047;
        let mut attempts = Vec::new();
        let socket = prefer_ipv6_socket(|ipv6| {
            attempts.push(ipv6);
            if ipv6 {
                Err(std::io::Error::from_raw_os_error(unavailable))
            } else {
                new_socket2_udp_socket(false, None, Some("0.0.0.0:0".parse().unwrap()), false)
            }
        })
        .unwrap();
        assert_eq!(attempts, [true, false]);
        assert!(socket.local_addr().unwrap().as_socket().unwrap().is_ipv4());

        attempts.clear();
        let error = prefer_ipv6_socket(|ipv6| {
            attempts.push(ipv6);
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "denied",
            ))
        })
        .unwrap_err();
        assert_eq!(attempts, [true]);
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn hostname_socket_prefers_dual_stack_and_enforces_interface_binding() {
        let ipv6_available =
            match new_socket2_udp_socket(true, None, Some("[::]:0".parse().unwrap()), false) {
                Ok(_) => true,
                Err(error) if ipv6_unavailable(&error) => false,
                Err(error) => panic!("IPv6 socket probe failed: {error}"),
            };
        let socket = new_hostname_udp_socket(None).unwrap();
        assert_eq!(socket.local_addr().unwrap().is_ipv6(), ipv6_available);
        assert!(new_hostname_udp_socket(Some("shoes-missing-interface".into())).is_err());
    }

    #[tokio::test]
    async fn ipv6_udp_listener_accepts_both_address_families() {
        let socket =
            match new_socket2_udp_socket(true, None, Some("[::]:0".parse().unwrap()), false) {
                Ok(socket) => socket,
                Err(error) if ipv6_unavailable(&error) => return,
                Err(error) => panic!("IPv6 socket creation failed: {error}"),
            };
        assert!(!socket.only_v6().unwrap());
        let socket = into_tokio_udp_socket(socket).unwrap();
        let port = socket.local_addr().unwrap().port();
        for (bind, destination) in [
            ("127.0.0.1:0", format!("127.0.0.1:{port}")),
            ("[::1]:0", format!("[::1]:{port}")),
        ] {
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                let peer = match tokio::net::UdpSocket::bind(bind).await {
                    Ok(peer) => peer,
                    Err(error) if bind == "[::1]:0" && ipv6_unavailable(&error) => return,
                    Err(error) => panic!("UDP peer bind failed: {error}"),
                };
                peer.send_to(b"request", destination).await.unwrap();
                let mut buf = [0; 16];
                let (len, sender) = socket.recv_from(&mut buf).await.unwrap();
                assert_eq!(&buf[..len], b"request");
                socket.send_to(b"reply", sender).await.unwrap();
                let len = peer.recv(&mut buf).await.unwrap();
                assert_eq!(&buf[..len], b"reply");
            })
            .await
            .unwrap();
        }
    }
}

#[cfg(all(test, unix, feature = "ffi"))]
mod protection_tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn outbound_protection_fails_closed_without_affecting_listeners() {
        struct Restore(Arc<dyn crate::tun::SocketProtector>);
        impl Drop for Restore {
            fn drop(&mut self) {
                crate::tun::set_global_socket_protector(self.0.clone());
            }
        }
        let _restore = Restore(crate::tun::get_global_socket_protector());
        let owner = std::thread::current().id();
        crate::tun::set_global_socket_protector(Arc::new(crate::tun::FnSocketProtector::new(
            move |_| {
                if std::thread::current().id() == owner {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "protection denied",
                    ))
                } else {
                    Ok(())
                }
            },
        )));
        assert!(new_tcp_socket(None, false).is_err());
        assert!(new_udp_socket(false, None).is_err());
        assert!(new_hostname_udp_socket(None).is_err());
        assert!(
            new_outbound_socket2_udp_socket(false, None, Some("0.0.0.0:0".parse().unwrap()))
                .is_err()
        );
        assert!(new_tcp_listener("0.0.0.0:0".parse().unwrap(), 10, None).is_ok());
        assert!(
            new_socket2_udp_socket(false, None, Some("0.0.0.0:0".parse().unwrap()), false).is_ok()
        );
    }
}
