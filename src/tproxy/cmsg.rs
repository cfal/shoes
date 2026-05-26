//! `recvmsg` with `IP_RECVORIGDSTADDR` / `IPV6_RECVORIGDSTADDR` cmsg parsing.

use std::io;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;

use tokio::io::Interest;
use tokio::net::UdpSocket;

/// Max ancillary data we expect: room for one `sockaddr_in6` cmsg.
/// Generously sized to absorb alignment + future options.
const CMSG_BUF_SIZE: usize = 128;

/// `recvmsg` from the socket, returning the bytes read, the peer (client_src),
/// and the original destination decoded from `IP_RECVORIGDSTADDR` /
/// `IPV6_RECVORIGDSTADDR` cmsg.
pub async fn recv_with_orig_dst(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    loop {
        socket.readable().await?;
        match socket.try_io(Interest::READABLE, || recv_with_orig_dst_blocking(socket, buf)) {
            Ok(v) => return Ok(v),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

fn recv_with_orig_dst_blocking(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    let fd = socket.as_raw_fd();

    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    let mut src_storage: MaybeUninit<libc::sockaddr_in6> = MaybeUninit::zeroed();
    let mut cmsg_buf = [0u8; CMSG_BUF_SIZE];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = src_storage.as_mut_ptr() as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len() as _;

    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let n = n as usize;

    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::other(
            "tproxy recvmsg control buffer truncated; orig_dst cmsg may be incomplete",
        ));
    }

    let client_src = sockaddr_to_socket_addr(
        src_storage.as_ptr() as *const libc::sockaddr,
        msg.msg_namelen,
    )?;

    let orig_dst = parse_orig_dst_cmsg(&msg)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing orig_dst cmsg"))?;

    Ok((n, client_src, orig_dst))
}

/// Walk cmsg headers via `CMSG_FIRSTHDR`/`CMSG_NXTHDR` and pull out the
/// original destination if present.
fn parse_orig_dst_cmsg(msg: &libc::msghdr) -> io::Result<Option<SocketAddr>> {
    let mut cmsg = unsafe { libc_cmsg_firsthdr(msg) };
    while !cmsg.is_null() {
        let hdr = unsafe { *cmsg };
        match (hdr.cmsg_level, hdr.cmsg_type) {
            (libc::IPPROTO_IP, libc::IP_RECVORIGDSTADDR) => {
                let data_ptr = unsafe { libc::CMSG_DATA(cmsg) } as *const libc::sockaddr_in;
                let sin = unsafe { std::ptr::read_unaligned(data_ptr) };
                let port = u16::from_be(sin.sin_port);
                let addr = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                return Ok(Some(SocketAddr::V4(SocketAddrV4::new(addr, port))));
            }
            (libc::IPPROTO_IPV6, libc::IPV6_ORIGDSTADDR) => {
                let data_ptr = unsafe { libc::CMSG_DATA(cmsg) } as *const libc::sockaddr_in6;
                let sin6 = unsafe { std::ptr::read_unaligned(data_ptr) };
                let port = u16::from_be(sin6.sin6_port);
                let addr = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                return Ok(Some(SocketAddr::V6(SocketAddrV6::new(
                    addr,
                    port,
                    u32::from_be(sin6.sin6_flowinfo),
                    sin6.sin6_scope_id,
                ))));
            }
            _ => {}
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(msg, cmsg) };
    }
    Ok(None)
}

/// Shim for `CMSG_FIRSTHDR` (libc exposes `CMSG_NXTHDR` but not always `CMSG_FIRSTHDR`).
#[inline]
unsafe fn libc_cmsg_firsthdr(msg: &libc::msghdr) -> *mut libc::cmsghdr {
    if msg.msg_controllen < std::mem::size_of::<libc::cmsghdr>() {
        std::ptr::null_mut()
    } else {
        msg.msg_control as *mut libc::cmsghdr
    }
}

fn sockaddr_to_socket_addr(
    addr: *const libc::sockaddr,
    len: libc::socklen_t,
) -> io::Result<SocketAddr> {
    let family = unsafe { (*addr).sa_family } as libc::c_int;
    match family {
        libc::AF_INET if (len as usize) >= std::mem::size_of::<libc::sockaddr_in>() => {
            let sin = unsafe { std::ptr::read_unaligned(addr as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            Ok(SocketAddr::V4(SocketAddrV4::new(ip, u16::from_be(sin.sin_port))))
        }
        libc::AF_INET6 if (len as usize) >= std::mem::size_of::<libc::sockaddr_in6>() => {
            let sin6 = unsafe { std::ptr::read_unaligned(addr as *const libc::sockaddr_in6) };
            Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                u16::from_be(sin6.sin6_port),
                u32::from_be(sin6.sin6_flowinfo),
                sin6.sin6_scope_id,
            )))
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected sockaddr family/len")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loopback_recv_returns_client_src_and_orig_dst() {
        use crate::tproxy::listener::new_tproxy_udp_socket;
        use std::net::Ipv4Addr;

        let recv = match new_tproxy_udp_socket(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)) {
            Ok(s) => s,
            Err(e) if matches!(e.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES)) => {
                eprintln!("skipping: tproxy udp bind requires CAP_NET_ADMIN");
                return;
            }
            Err(e) => panic!("udp bind failed: {e}"),
        };
        let bind_addr = recv.local_addr().unwrap();

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        client.send_to(b"ping", bind_addr).await.unwrap();

        let mut buf = [0u8; 64];
        let (n, peer, orig_dst) = recv_with_orig_dst(&recv, &mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(peer.ip(), client_addr.ip());
        assert_eq!(peer.port(), client_addr.port());
        assert_eq!(orig_dst.port(), bind_addr.port());
        assert_eq!(orig_dst.ip(), bind_addr.ip());
    }
}
