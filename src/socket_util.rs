#[inline]
pub fn new_udp_socket(bind_interface: Option<String>) -> std::io::Result<tokio::net::UdpSocket> {
    // TODO: this is blocking?
    let std_socket = std::net::UdpSocket::bind("[::]:0")?;
    std_socket.set_nonblocking(true)?;

    // tokio's UdpSocket has bind_device, so construct that instead of having to
    // handle SO_BINDTODEVICE ourselves.
    let tokio_socket = tokio::net::UdpSocket::from_std(std_socket).unwrap();
    if let Some(_b) = bind_interface {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        tokio_socket.bind_device(Some(_b.as_bytes()))?;

        // This should be handled during config validation.
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        panic!("Could not find to device, unsupported platform.")
    }

    Ok(tokio_socket)
}

#[inline]
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
