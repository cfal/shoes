#[inline]
pub fn new_udp_socket(bind_interface: Option<String>) -> std::io::Result<tokio::net::UdpSocket> {
    // TODO: this is blocking?
    let std_socket = std::net::UdpSocket::bind("[::]:0")?;
    std_socket.set_nonblocking(true)?;

    // tokio's UdpSocket has bind_device, so construct that instead of having to
    // handle SO_BINDTODEVICE ourselves.
    let tokio_socket = tokio::net::UdpSocket::from_std(std_socket).unwrap();
    if let Some(b) = bind_interface {
        tokio_socket.bind_device(Some(b.as_bytes()))?;
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

    if let Some(b) = bind_interface {
        tcp_socket.bind_device(Some(b.as_bytes()))?;
    }

    Ok(tcp_socket)
}
