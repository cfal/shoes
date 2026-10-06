use super::*;
use etherparse::PacketBuilder;
use futures::FutureExt;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv6Packet, UdpPacket};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::panic::AssertUnwindSafe;
use std::time::Duration;
use tokio::net::{UdpSocket, UnixDatagram as AsyncDatagram};
use tokio::time::timeout;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

fn packet_information(ipv6: bool) -> [u8; 4] {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let protocol = if ipv6 { libc::AF_INET6 } else { libc::AF_INET } as u32;
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let protocol: u32 = if ipv6 { 0x86dd } else { 0x0800 };
    protocol.to_be_bytes()
}

fn request(src: SocketAddr, dst: SocketAddr, payload: &[u8], framed: bool) -> Vec<u8> {
    let builder = match (src.ip(), dst.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => PacketBuilder::ipv4(src.octets(), dst.octets(), 64),
        (IpAddr::V6(src), IpAddr::V6(dst)) => PacketBuilder::ipv6(src.octets(), dst.octets(), 64),
        _ => unreachable!(),
    }
    .udp(src.port(), dst.port());
    let mut packet = Vec::new();
    if framed {
        packet.extend_from_slice(&packet_information(src.is_ipv6()));
    }
    builder.write(&mut packet, payload).unwrap();
    packet
}

fn check_reply(packet: &[u8], src: SocketAddr, dst: SocketAddr, payload: &[u8], framed: bool) {
    let packet = if framed {
        assert_eq!(&packet[..4], packet_information(src.is_ipv6()));
        &packet[4..]
    } else {
        packet
    };
    let (udp_bytes, source, destination) = if src.is_ipv6() {
        assert_eq!(packet[0] >> 4, 6);
        let ip = Ipv6Packet::new_checked(packet).unwrap();
        assert_eq!(ip.next_header(), IpProtocol::Udp);
        assert_eq!(usize::from(ip.payload_len()) + 40, packet.len());
        assert_eq!(usize::from(ip.payload_len()), payload.len() + 8);
        assert_eq!(IpAddr::V6(ip.src_addr()), src.ip());
        assert_eq!(IpAddr::V6(ip.dst_addr()), dst.ip());
        (
            &packet[40..],
            IpAddress::from(ip.src_addr()),
            IpAddress::from(ip.dst_addr()),
        )
    } else {
        assert_eq!(packet[0] >> 4, 4);
        let ip = Ipv4Packet::new_checked(packet).unwrap();
        assert_eq!(ip.next_header(), IpProtocol::Udp);
        assert!(ip.verify_checksum());
        assert_eq!(usize::from(ip.total_len()), packet.len());
        assert_eq!(
            packet.len(),
            usize::from(ip.header_len()) + 8 + payload.len()
        );
        assert_eq!(IpAddr::V4(ip.src_addr()), src.ip());
        assert_eq!(IpAddr::V4(ip.dst_addr()), dst.ip());
        (
            &packet[usize::from(ip.header_len())..],
            IpAddress::from(ip.src_addr()),
            IpAddress::from(ip.dst_addr()),
        )
    };
    let udp = UdpPacket::new_checked(udp_bytes).unwrap();
    assert_eq!(udp.src_port(), src.port());
    assert_eq!(udp.dst_port(), dst.port());
    assert_eq!(usize::from(udp.len()), payload.len() + 8);
    assert_ne!(udp.checksum(), 0);
    assert!(udp.verify_checksum(&source, &destination));
    assert_eq!(udp.payload(), payload);
}

async fn roundtrips(ipv6: bool, framed: bool) {
    let (wire, tun) = UnixDatagram::pair().unwrap();
    wire.set_nonblocking(true).unwrap();
    let wire = AsyncDatagram::from_std(wire).unwrap();
    let config = TunServerConfig::new()
        .raw_fd(tun.as_raw_fd())
        .close_fd_on_drop(false)
        .packet_information(framed);
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    let selector = Arc::new(create_tcp_client_proxy_selector(
        vec![crate::config::RuleConfig::default()],
        resolver.clone(),
    ));
    let (shutdown, shutdown_rx) = oneshot::channel();
    let mut tasks = JoinSet::new();
    tasks.spawn(run_tun_server(config, selector, resolver, shutdown_rx));

    let outcome = AssertUnwindSafe(timeout(TEST_TIMEOUT, async {
        let bind = if ipv6 { "[::]:0" } else { "0.0.0.0:0" };
        let destinations = [
            UdpSocket::bind(bind).await.unwrap(),
            UdpSocket::bind(bind).await.unwrap(),
        ];
        let source_ip: IpAddr = if ipv6 {
            "fd12:3456::2".parse().unwrap()
        } else {
            "10.23.0.2".parse().unwrap()
        };
        let target_ip = if ipv6 {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        };
        let mut packet = [0; 2048];
        let mut received = [0; 2048];
        for round in 0..3u8 {
            for port in [12001, 12002] {
                let source = SocketAddr::new(source_ip, port);
                for destination in &destinations {
                    let target =
                        SocketAddr::new(target_ip, destination.local_addr().unwrap().port());
                    for size in [0, 1, 31, 256, 1200] {
                        let payload: Vec<u8> = (0..size)
                            .map(|index| (index as u8).wrapping_mul(37).wrapping_add(round))
                            .collect();
                        let input = request(source, target, &payload, framed);
                        assert_eq!(wire.send(&input).await.unwrap(), input.len());
                        let (length, sender) = destination.recv_from(&mut received).await.unwrap();
                        assert_eq!(sender.is_ipv6(), ipv6);
                        assert_eq!(&received[..length], payload);

                        let reply: Vec<u8> = payload.iter().map(|byte| byte ^ 0x5a).collect();
                        assert_eq!(
                            destination.send_to(&reply, sender).await.unwrap(),
                            reply.len()
                        );
                        let length = wire.recv(&mut packet).await.unwrap();
                        check_reply(&packet[..length], target, source, &reply, framed);
                    }
                }
            }
        }
    }))
    .catch_unwind()
    .await;

    let _ = shutdown.send(());
    let stopped = timeout(TEST_TIMEOUT, tasks.join_next()).await;
    // A rescue packet is allowed only after the liveness check has failed.
    if stopped.is_err() {
        let _ = wire.send(&[0]).await;
        let _ = timeout(TEST_TIMEOUT, tasks.join_next()).await;
    }
    match outcome {
        Ok(result) => result.expect("raw-FD UDP pipeline stalled"),
        Err(panic) => std::panic::resume_unwind(panic),
    }
    stopped
        .expect("TUN shutdown stalled")
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(unsafe { libc::fcntl(tun.as_raw_fd(), libc::F_GETFD) } >= 0);
    assert!(tasks.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_fd_ipv4_udp_roundtrips() {
    roundtrips(false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_fd_ipv6_udp_roundtrips() {
    roundtrips(true, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn framed_raw_fd_ipv4_udp_roundtrips() {
    roundtrips(false, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn framed_raw_fd_ipv6_udp_roundtrips() {
    roundtrips(true, true).await;
}
