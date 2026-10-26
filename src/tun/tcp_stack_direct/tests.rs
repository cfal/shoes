use super::super::test_gate::{GateControl, TestGate};
use super::*;
use smoltcp::socket::tcp::SocketBuffer as TcpSocketBuffer;
use std::os::unix::io::IntoRawFd;
use std::os::unix::net::{UnixDatagram, UnixStream};

#[test]
fn dropped_framed_writes_are_not_counted_as_transmitted() {
    for error in [libc::EAGAIN, libc::ENOBUFS] {
        assert!(
            !write_framed_packet_with(b"packet", &[0; 10], |_, _| {
                Err(io::Error::from_raw_os_error(error))
            })
            .unwrap()
        );
    }
    assert!(
        write_framed_packet_with(b"packet", &[0; 10], |header, data| {
            Ok(header.len() + data.len())
        })
        .unwrap()
    );
}

#[test]
fn eio_writes_are_packet_drops_only_on_linux_kernels() {
    for header in [&[][..], &[0; 4][..], &[0; 10][..]] {
        let mut attempts = 0;
        let result = write_framed_packet_with(b"packet", header, |_, _| {
            attempts += 1;
            Err(io::Error::from_raw_os_error(libc::EIO))
        });
        if cfg!(any(target_os = "linux", target_os = "android")) {
            assert!(!result.unwrap());
        } else {
            assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EIO));
        }
        assert_eq!(attempts, 1);
    }
}

#[test]
fn enospc_writes_are_packet_drops_only_on_apple_kernels() {
    for header in [&[][..], &[0; 4][..], &[0; 10][..]] {
        let mut attempts = 0;
        let result = write_framed_packet_with(b"packet", header, |_, _| {
            attempts += 1;
            Err(io::Error::from_raw_os_error(libc::ENOSPC))
        });
        if cfg!(any(target_os = "macos", target_os = "ios")) {
            assert!(!result.unwrap());
        } else {
            assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::ENOSPC));
        }
        assert_eq!(attempts, 1);
    }
}

#[test]
fn interface_forwards_ipv4_segmentation_and_keeps_ipv6_mtu() {
    for ipv6 in [false, true] {
        let (peer, tun) = UnixDatagram::pair().unwrap();
        let frame_capacity =
            super::super::offload::HEADER_LEN + super::super::offload::MAX_PACKET_LEN;
        // macOS defaults cannot hold a full offloaded datagram.
        socket2::SockRef::from(&tun)
            .set_send_buffer_size(frame_capacity)
            .unwrap();
        socket2::SockRef::from(&peer)
            .set_recv_buffer_size(frame_capacity)
            .unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut device = DirectDevice::new(tun.as_raw_fd(), 1500, false);
        device.offload = true;
        let now = SmolInstant::from_millis(1);
        let mut iface = Interface::new(InterfaceConfig::new(HardwareAddress::Ip), &mut device, now);
        let (src, dst): (SocketAddr, SocketAddr) = if ipv6 {
            (
                "[fd00::2]:1001".parse().unwrap(),
                "[fd00::3]:443".parse().unwrap(),
            )
        } else {
            (
                "192.0.2.1:1001".parse().unwrap(),
                "198.51.100.2:443".parse().unwrap(),
            )
        };
        iface.update_ip_addrs(|addresses| {
            addresses.push(IpCidr::new(dst.ip().into(), 0)).unwrap();
        });
        let mut sockets = SocketSet::new(vec![]);
        let connection =
            create_tcp_connection(src, dst, &mut sockets, &Wake::new().unwrap().0, 65536).unwrap();
        let packet = |ack: Option<u32>| {
            let builder = match (src.ip(), dst.ip()) {
                (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) => {
                    etherparse::PacketBuilder::ipv4(src.octets(), dst.octets(), 64)
                }
                (std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst)) => {
                    etherparse::PacketBuilder::ipv6(src.octets(), dst.octets(), 64)
                }
                _ => unreachable!(),
            };
            let tcp = builder.tcp(1001, 443, if ack.is_some() { 102 } else { 101 }, 65535);
            let tcp = if let Some(ack) = ack {
                tcp.ack(ack)
            } else {
                tcp.syn()
            };
            let mut data = Vec::new();
            tcp.write(&mut data, b"").unwrap();
            PacketBuffer::copy_from_slice(&data)
        };
        device.store_packet(packet(None));
        iface.poll(now, &mut device, &mut sockets);
        let mut frame = vec![0; frame_capacity];
        let n = peer.recv(&mut frame).unwrap();
        let ip_len = if ipv6 { 40 } else { 20 };
        let syn_ack = TcpPacket::new_checked(&frame[10 + ip_len..n]).unwrap();
        let ack = (syn_ack.seq_number().0 as u32).wrapping_add(1);
        device.store_packet(packet(Some(ack)));
        iface.poll(now, &mut device, &mut sockets);
        let socket = sockets.get_mut::<TcpSocket>(connection.handle);
        assert_eq!(socket.state(), TcpState::Established);
        socket.send_slice(&vec![23; 16001]).unwrap();
        iface.poll_egress(now, &mut device, &mut sockets);
        let n = peer.recv(&mut frame).unwrap();
        assert_eq!(frame[0], 1);
        if ipv6 {
            assert!(n <= 1510);
            assert_eq!(frame[1], 0);
            assert_eq!(device.gso_packets, 0);
        } else {
            assert!(n > 1510, "native segmentation not used: {n}");
            assert_eq!(frame[1], 1);
            assert_eq!(device.gso_packets, 1);
        }
    }
}

#[test]
fn virtio_framing_is_present_on_udp_and_validated_on_ingress() {
    let (peer, tun) = UnixDatagram::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut device = DirectDevice::new(tun.as_raw_fd(), 1500, false);
    device.offload = true;
    let packet = [0x45, 1, 2, 3];
    device.write_packet(&packet).unwrap();
    let mut frame = [0; 64];
    let n = peer.recv(&mut frame).unwrap();
    assert_eq!(n, 14);
    assert_eq!(&frame[..10], &[0; 10]);
    peer.send(&frame[..n]).unwrap();
    assert_eq!(&device.try_recv().unwrap().unwrap()[..], &packet);
    frame[0] = 1;
    peer.send(&frame[..n]).unwrap();
    assert!(device.try_recv().is_err());
}

fn stack_at_wait(tun: OwnedFd) -> (TcpStackDirect, GateControl) {
    let (wake, mut receiver) = Wake::new().unwrap();
    let (gate, control) = TestGate::new();
    receiver.before_wait = Some(gate);
    set_nonblocking(tun.as_raw_fd()).unwrap();
    let stack = TcpStackDirect::start(tun, TunServerConfig::new(), wake, receiver, false).unwrap();
    control.wait();
    (stack, control)
}

#[tokio::test]
async fn hard_tcp_write_errors_fail_startup_and_running_workers() {
    for startup in [true, false] {
        let (peer, tun) = UnixDatagram::pair().unwrap();
        let mut syn = Vec::new();
        etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64)
            .tcp(10001, 443, 101, 4096)
            .syn()
            .write(&mut syn, &[])
            .unwrap();
        tun.shutdown(std::net::Shutdown::Write).unwrap();
        if startup {
            peer.send(&syn).unwrap();
        }
        let mut stack = TcpStackDirect::new(tun.into(), 1500);
        let error = tokio::time::timeout(Duration::from_secs(5), async {
            if startup {
                stack.ready().await.unwrap_err()
            } else {
                stack.ready().await.unwrap();
                peer.send(&syn).unwrap();
                stack.finished().await.unwrap_err()
            }
        })
        .await
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }
}

#[tokio::test]
async fn hard_udp_write_errors_reach_the_owner() {
    let (_peer, tun) = UnixDatagram::pair().unwrap();
    tun.shutdown(std::net::Shutdown::Write).unwrap();
    let mut stack = TcpStackDirect::new(tun.into(), 1500);
    stack.ready().await.unwrap();
    let (tx, rx) = mpsc::channel(1);
    tx.try_send(PacketBuffer::copy_from_slice(&[0x45, 1, 2, 3]))
        .unwrap();
    stack.set_udp_response_tx(rx);
    let error = tokio::time::timeout(Duration::from_secs(5), stack.finished())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
}

#[tokio::test]
async fn queued_syn_survives_delayed_handler_setup() {
    use tokio::io::AsyncReadExt;
    for ipv6 in [false, true] {
        for framed in [false, true] {
            let (peer, tun) = UnixDatagram::pair().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let (source, target): (SocketAddr, SocketAddr) = if ipv6 {
                (
                    "[fd00::2]:10001".parse().unwrap(),
                    "[2001:db8::1]:443".parse().unwrap(),
                )
            } else {
                (
                    "10.0.0.2:10001".parse().unwrap(),
                    "1.1.1.1:443".parse().unwrap(),
                )
            };
            let packet = |ack: Option<u32>| {
                let builder = match (source.ip(), target.ip()) {
                    (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) => {
                        etherparse::PacketBuilder::ipv4(src.octets(), dst.octets(), 64)
                    }
                    (std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst)) => {
                        etherparse::PacketBuilder::ipv6(src.octets(), dst.octets(), 64)
                    }
                    _ => unreachable!(),
                }
                .tcp(10001, 443, if ack.is_some() { 102 } else { 101 }, 4096);
                let mut bytes = if framed {
                    packet_header(if ipv6 { 0x60 } else { 0x45 })
                        .unwrap()
                        .to_vec()
                } else {
                    Vec::new()
                };
                match ack {
                    Some(ack) => builder
                        .ack(ack)
                        .fin()
                        .write(&mut bytes, b"first data")
                        .unwrap(),
                    None => builder.syn().write(&mut bytes, b"").unwrap(),
                }
                bytes
            };
            peer.send(&packet(None)).unwrap();
            peer.send(&packet(None)).unwrap();
            let mut stack = TcpStackDirect::with_config(
                tun.into(),
                TunServerConfig::new().packet_information(framed),
            )
            .unwrap();
            let mut buffer = [0; 1500];
            let length = peer.recv(&mut buffer).unwrap();
            let bytes = &buffer[if framed { 4 } else { 0 }..length];
            let payload = if ipv6 {
                let ip = Ipv6Packet::new_checked(bytes).unwrap();
                assert_eq!(std::net::IpAddr::V6(ip.dst_addr()), source.ip());
                &bytes[40..]
            } else {
                let ip = Ipv4Packet::new_checked(bytes).unwrap();
                assert!(ip.verify_checksum());
                assert_eq!(std::net::IpAddr::V4(ip.dst_addr()), source.ip());
                &bytes[ip.header_len() as usize..]
            };
            let tcp = TcpPacket::new_checked(payload).unwrap();
            assert!(tcp.verify_checksum(&target.ip().into(), &source.ip().into()));
            assert!(tcp.syn() && tcp.ack() && !tcp.rst());
            assert_eq!(tcp.ack_number().0, 102);
            assert!(
                stack.tcp_rx.as_ref().unwrap().is_empty(),
                "routing must wait for the handshake"
            );
            peer.send(&packet(Some((tcp.seq_number() + 1).0 as u32)))
                .unwrap();
            let mut rx = stack.take_tcp_rx().unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                let mut flow = rx.recv().await.unwrap();
                assert_eq!(flow.remote_addr, target);
                let mut bytes = Vec::new();
                flow.connection.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, b"first data");
                assert!(matches!(
                    rx.try_recv(),
                    Err(mpsc::error::TryRecvError::Empty)
                ));
            })
            .await
            .unwrap();
        }
    }
}

#[tokio::test]
async fn reset_half_open_releases_admission_before_the_next_packet() {
    use tokio::io::AsyncReadExt;

    tokio::time::timeout(Duration::from_secs(5), async {
        let (peer, tun) = UnixDatagram::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        for (port, sequence, reset) in
            [(10001, 101, false), (10001, 102, true), (10002, 501, false)]
        {
            let builder = etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64)
                .tcp(port, 443, sequence, 4096);
            let mut packet = Vec::new();
            if reset { builder.rst() } else { builder.syn() }
                .write(&mut packet, b"")
                .unwrap();
            peer.send(&packet).unwrap();
        }
        let mut config = TunServerConfig::new();
        config.resource_limits.max_tcp_connections = Some(1);
        let mut stack = TcpStackDirect::with_config(tun.into(), config).unwrap();
        let mut rx = stack.take_tcp_rx().unwrap();
        let mut reply = [0; 1500];
        let n = peer.recv(&mut reply).unwrap();
        let ip = Ipv4Packet::new_checked(&reply[..n]).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(tcp.syn() && tcp.ack() && !tcp.rst());
        assert_eq!(tcp.dst_port(), 10002);
        assert_eq!(tcp.ack_number().0, 502);
        let mut packet = Vec::new();
        etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64)
            .tcp(10002, 443, 502, 4096)
            .ack((tcp.seq_number() + 1).0 as u32)
            .write(&mut packet, b"second peer")
            .unwrap();
        peer.send(&packet).unwrap();
        let mut second = rx.recv().await.unwrap();
        let mut received = [0; 11];
        second.connection.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"second peer");
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn malformed_syns_never_publish_connections() {
    let (peer, tun) = UnixDatagram::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let source = Ipv4Address::new(10, 0, 0, 2);
    let target = Ipv4Address::new(1, 1, 1, 1);
    for malformed in 0..6 {
        let mut packet = vec![0; 44];
        let mut ip = Ipv4Packet::new_unchecked(&mut packet[..]);
        smoltcp::wire::Ipv4Repr {
            src_addr: source,
            dst_addr: target,
            next_header: IpProtocol::Tcp,
            payload_len: 24,
            hop_limit: 64,
        }
        .emit(&mut ip, &Default::default());
        let mut tcp = TcpPacket::new_unchecked(ip.payload_mut());
        tcp.set_header_len(24);
        tcp.set_src_port(if malformed == 2 { 0 } else { 10001 + malformed });
        tcp.set_dst_port(443);
        tcp.set_seq_number(smoltcp::wire::TcpSeqNumber(101));
        tcp.set_syn(true);
        tcp.set_fin(malformed == 0);
        tcp.set_rst(malformed == 1);
        tcp.set_window_len(4096);
        if malformed == 3 {
            tcp.options_mut().copy_from_slice(&[2, 1, 0, 0]);
        }
        tcp.fill_checksum(&source.into(), &target.into());
        if malformed == 4 {
            ip.set_more_frags(true);
            ip.fill_checksum();
        }
        peer.send(&packet).unwrap();
    }
    let mut config = TunServerConfig::new();
    config.resource_limits.max_tcp_connections = Some(1);
    let mut stack = TcpStackDirect::with_config(tun.into(), config).unwrap();
    let mut buffer = [0; 1500];
    let n = peer.recv(&mut buffer).unwrap();
    let ip = Ipv4Packet::new_checked(&buffer[..n]).unwrap();
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    assert!(tcp.syn() && tcp.ack() && !tcp.rst());
    assert_eq!(tcp.dst_port(), 10006);
    let mut ack = Vec::new();
    etherparse::PacketBuilder::ipv4(source.octets(), target.octets(), 64)
        .tcp(10006, 443, 102, 4096)
        .ack((tcp.seq_number() + 1).0 as u32)
        .write(&mut ack, b"")
        .unwrap();
    peer.send(&ack).unwrap();
    let mut rx = stack.take_tcp_rx().unwrap();
    let _flow = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[test]
fn handshake_timeout_is_lifted_only_when_the_connection_is_published() {
    for complete in [false, true] {
        let (peer, tun) = UnixDatagram::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut device = DirectDevice::new(tun.as_raw_fd(), 1500, false);
        let start = SmolInstant::from_secs(1);
        let mut iface = Interface::new(
            InterfaceConfig::new(HardwareAddress::Ip),
            &mut device,
            start,
        );
        let src = "10.0.0.2:10001".parse().unwrap();
        let dst: SocketAddr = "1.1.1.1:443".parse().unwrap();
        iface.update_ip_addrs(|ips| ips.push(IpCidr::new(dst.ip().into(), 0)).unwrap());
        let mut sockets = SocketSet::new(vec![]);
        let incoming =
            create_tcp_connection(src, dst, &mut sockets, &Wake::new().unwrap().0, 4096).unwrap();
        let handle = incoming.handle;
        let mut entry = SocketInfo {
            control: incoming.control,
            src_addr: src,
            dst_addr: dst,
            pending: Some(incoming.connection),
        };
        let (accepted, mut rx) = mpsc::unbounded_channel();
        let mut syn = Vec::new();
        etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64)
            .tcp(10001, 443, 101, 4096)
            .syn()
            .write(&mut syn, b"")
            .unwrap();
        device.store_packet(PacketBuffer::copy_from_slice(&syn));
        iface.poll(start, &mut device, &mut sockets);
        entry.pump(
            handle,
            sockets.get_mut::<TcpSocket>(handle),
            &accepted,
            start,
        );
        assert!(rx.is_empty());
        assert_eq!(
            sockets.get::<TcpSocket>(handle).timeout(),
            Some(smoltcp::time::Duration::from_secs(30))
        );
        let mut buffer = [0; 1500];
        let n = peer.recv(&mut buffer).unwrap();
        let ip = Ipv4Packet::new_checked(&buffer[..n]).unwrap();
        let syn_ack = TcpPacket::new_checked(ip.payload()).unwrap();
        if complete {
            let mut ack = Vec::new();
            etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64)
                .tcp(10001, 443, 102, 4096)
                .ack((syn_ack.seq_number() + 1).0 as u32)
                .write(&mut ack, b"")
                .unwrap();
            device.store_packet(PacketBuffer::copy_from_slice(&ack));
            iface.poll(start, &mut device, &mut sockets);
            entry.pump(
                handle,
                sockets.get_mut::<TcpSocket>(handle),
                &accepted,
                start,
            );
        }
        let flow = rx.try_recv().ok();
        assert_eq!(flow.is_some(), complete);
        let after_handshake_deadline = start + smoltcp::time::Duration::from_secs(31);
        iface.poll(after_handshake_deadline, &mut device, &mut sockets);
        let socket = sockets.get_mut::<TcpSocket>(handle);
        entry.pump(handle, socket, &accepted, after_handshake_deadline);
        assert_eq!(
            socket.state(),
            if complete {
                TcpState::Established
            } else {
                TcpState::Closed
            }
        );
        assert!(rx.is_empty(), "published twice");
    }
}

#[test]
fn transmit_storage_is_reused_and_initialized() {
    let (peer, tun) = UnixDatagram::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut device = DirectDevice::new(tun.as_raw_fd(), 1500, false);
    let pointer = device.tx_buffer.as_ptr();
    for length in [1000, 100, 1500] {
        let token = device.transmit(stack_now()).unwrap();
        let result = token.consume(length, |buffer| {
            assert_eq!(buffer.as_ptr(), pointer);
            assert!(buffer.iter().all(|&byte| byte == 0));
            buffer.fill(42);
            123
        });
        assert_eq!(result, 123);
        let mut received = [0; 1500];
        assert_eq!(peer.recv(&mut received).unwrap(), length);
        assert!(received[..length].iter().all(|&byte| byte == 42));
    }
}

#[test]
fn packet_writes_retry_only_interruptions_and_never_a_suffix() {
    let payload = [0x45, 1, 2, 3, 4];
    for framed in [false, true] {
        let expected_header = if framed {
            packet_header(payload[0]).unwrap().to_vec()
        } else {
            Vec::new()
        };
        let expected_length = payload.len() + expected_header.len();
        let mut attempts = 0;
        write_packet_with(&payload, framed, |header, data| {
            assert_eq!(header, expected_header);
            assert_eq!(data, payload);
            attempts += 1;
            if attempts < 3 {
                Err(io::Error::from_raw_os_error(libc::EINTR))
            } else {
                Ok(expected_length)
            }
        })
        .unwrap();
        assert_eq!(attempts, 3);

        for length in 0..expected_length {
            let mut attempts = 0;
            let error = write_packet_with(&payload, framed, |_, _| {
                attempts += 1;
                Ok(length)
            })
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WriteZero);
            assert_eq!(attempts, 1);
        }
        for code in [libc::EAGAIN, libc::ENOBUFS, libc::EBADF, libc::EPIPE] {
            let mut attempts = 0;
            let result = write_packet_with(&payload, framed, |_, _| {
                attempts += 1;
                Err(io::Error::from_raw_os_error(code))
            });
            assert_eq!(attempts, 1);
            if matches!(code, libc::EBADF | libc::EPIPE) {
                assert_eq!(result.unwrap_err().raw_os_error(), Some(code));
            } else {
                result.unwrap();
            }
        }
        write_packet_with(&[], framed, |_, _| panic!("empty packet write")).unwrap();
    }
}

#[test]
fn time_wait_cleanup_does_not_depend_on_egress_progress() {
    use smoltcp::iface::PollResult;

    let (peer, tun) = UnixDatagram::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut device = DirectDevice::new(tun.as_raw_fd(), 1500, false);
    let mut iface = Interface::new(
        InterfaceConfig::new(HardwareAddress::Ip),
        &mut device,
        SmolInstant::from_millis(0),
    );
    iface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::v4(1, 1, 1, 1), 0))
            .unwrap();
    });
    let mut socket_set = SocketSet::new(vec![]);
    let src_addr = "10.0.0.2:10001".parse().unwrap();
    let dst_addr = "1.1.1.1:443".parse().unwrap();
    let CreatedTcpConnection {
        handle,
        connection,
        control,
    } = create_tcp_connection(
        src_addr,
        dst_addr,
        &mut socket_set,
        &Wake::new().unwrap().0,
        4096,
    )
    .unwrap();
    let (accepted, mut accepted_rx) = mpsc::unbounded_channel();
    let mut sockets = HashMap::from([(
        handle,
        SocketInfo {
            control: control.clone(),
            src_addr,
            dst_addr,
            pending: Some(connection),
        },
    )]);
    let mut active = HashMap::from([((src_addr, dst_addr), handle)]);
    let ingress = |iface: &mut Interface,
                   device: &mut DirectDevice,
                   sockets: &mut SocketSet<'_>,
                   ack: Option<u32>,
                   fin| {
        let mut builder = etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64).tcp(
            10001,
            443,
            if ack.is_some() { 102 } else { 101 },
            4096,
        );
        builder = if let Some(ack) = ack {
            builder.ack(ack)
        } else {
            builder.syn()
        };
        if fin {
            builder = builder.fin();
        }
        let mut packet = Vec::new();
        builder.write(&mut packet, b"").unwrap();
        device.store_packet(PacketBuffer::copy_from_slice(&packet));
        iface.poll_ingress_single(SmolInstant::from_millis(1), device, sockets);
    };
    ingress(&mut iface, &mut device, &mut socket_set, None, false);
    iface.poll_egress(SmolInstant::from_millis(1), &mut device, &mut socket_set);
    let mut data = [0; 1500];
    let length = peer.recv(&mut data).unwrap();
    let ip = Ipv4Packet::new_checked(&data[..length]).unwrap();
    let syn_ack = TcpPacket::new_checked(ip.payload()).unwrap();
    let acknowledgement = (syn_ack.seq_number().0 as u32).wrapping_add(1);
    ingress(
        &mut iface,
        &mut device,
        &mut socket_set,
        Some(acknowledgement),
        false,
    );
    sockets.get_mut(&handle).unwrap().pump(
        handle,
        socket_set.get_mut::<TcpSocket>(handle),
        &accepted,
        SmolInstant::from_millis(1),
    );
    let connection = accepted_rx.try_recv().unwrap();
    socket_set.get_mut::<TcpSocket>(handle).close();
    control.set_send_state(TcpSocketState::Closing);
    drop(connection);
    crate::ip_stack::pump_tcp(
        handle,
        socket_set.get_mut::<TcpSocket>(handle),
        &control,
        stack_now(),
    );
    assert_eq!(
        socket_set.get::<TcpSocket>(handle).state(),
        TcpState::FinWait1
    );
    assert!(!reconcile_sockets(
        &mut sockets,
        &mut socket_set,
        &mut active
    ));
    iface.poll_egress(SmolInstant::from_millis(1), &mut device, &mut socket_set);
    ingress(
        &mut iface,
        &mut device,
        &mut socket_set,
        Some(acknowledgement.wrapping_add(1)),
        true,
    );
    assert_eq!(
        socket_set.get::<TcpSocket>(handle).state(),
        TcpState::TimeWait
    );
    iface.poll_egress(SmolInstant::from_millis(1), &mut device, &mut socket_set);

    assert_eq!(
        iface.poll_egress(
            SmolInstant::from_millis(60_001),
            &mut device,
            &mut socket_set
        ),
        PollResult::None
    );
    assert!(!reconcile_sockets(
        &mut sockets,
        &mut socket_set,
        &mut active
    ));
    assert!(sockets.is_empty());
    assert!(active.is_empty());
    assert_eq!(control.recv_state(), TcpSocketState::Closed);
    assert_eq!(control.send_state(), TcpSocketState::Closed);
}

#[test]
fn closed_socket_keeps_its_pending_reset_until_a_complete_egress_sweep() {
    let (peer, tun) = UnixDatagram::pair().unwrap();
    // A full sweep must fit before reads start, including on macOS's smaller default queue.
    socket2::SockRef::from(&peer)
        .set_recv_buffer_size(256 * 1024)
        .unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut device = DirectDevice::new(tun.as_raw_fd(), 1500, false);
    let mut iface = Interface::new(
        InterfaceConfig::new(HardwareAddress::Ip),
        &mut device,
        stack_now(),
    );
    iface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::v4(1, 1, 1, 1), 0))
            .unwrap();
    });
    let mut socket_set = SocketSet::new(vec![]);
    let mut sockets = HashMap::new();
    let mut active = HashMap::new();
    let dst_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let mut last_handle = None;
    for port in 10000..10070 {
        let src_addr = SocketAddr::from(([1, 1, 1, 1], port));
        let mut socket = TcpSocket::new(
            TcpSocketBuffer::new(vec![0; 1024]),
            TcpSocketBuffer::new(vec![0; 1024]),
        );
        socket.connect(iface.context(), dst_addr, src_addr).unwrap();
        let handle = socket_set.add(socket);
        sockets.insert(
            handle,
            SocketInfo {
                control: Arc::new(TcpConnectionControl::new(1024, 1024)),
                src_addr,
                dst_addr,
                pending: None,
            },
        );
        active.insert((src_addr, dst_addr), handle);
        last_handle = Some(handle);
    }
    let last_handle = last_handle.unwrap();
    socket_set.get_mut::<TcpSocket>(last_handle).abort();
    reconcile_sockets(&mut sockets, &mut socket_set, &mut active);
    assert_eq!(sockets.len(), 70);
    iface.poll_egress(stack_now(), &mut device, &mut socket_set);
    let mut reset = false;
    let mut data = [0; 1500];
    for index in 0..70 {
        let length = peer
            .recv(&mut data)
            .unwrap_or_else(|error| panic!("missing egress packet {index} of 70: {error}"));
        let ip = Ipv4Packet::new_checked(&data[..length]).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        if tcp.src_port() == 10069 {
            reset = tcp.rst();
        }
    }
    assert!(reset);
    reconcile_sockets(&mut sockets, &mut socket_set, &mut active);
    assert_eq!(sockets.len(), 69);
    assert!(!sockets.contains_key(&last_handle));
}

#[tokio::test]
async fn default_admission_preserves_bursts_beyond_old_queue_and_socket_caps() {
    use std::os::unix::net::UnixDatagram;

    let (peer, tun) = UnixDatagram::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut stack = TcpStackDirect::new(tun.into(), 1500);
    let mut rx = stack.take_tcp_rx().unwrap();
    let mut buf = [0; 1500];
    for port in 10000..10300 {
        let builder = etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64)
            .tcp(port, 443, 101, 4096);
        let mut syn = Vec::new();
        builder.syn().write(&mut syn, b"").unwrap();
        peer.send(&syn).unwrap();
        let acknowledgement = loop {
            let n = peer.recv(&mut buf).unwrap();
            let ip = Ipv4Packet::new_checked(&buf[..n]).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            assert!(!tcp.rst(), "burst connection was reset");
            if tcp.dst_port() == port && tcp.syn() && tcp.ack() {
                break (tcp.seq_number().0 as u32).wrapping_add(1);
            }
        };
        let mut ack = Vec::new();
        etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64)
            .tcp(port, 443, 102, 4096)
            .ack(acknowledgement)
            .write(&mut ack, b"")
            .unwrap();
        peer.send(&ack).unwrap();
    }
    let connections = tokio::time::timeout(Duration::from_secs(5), async {
        let mut connections = Vec::new();
        for _ in 0..300 {
            connections.push(rx.recv().await.unwrap());
        }
        connections
    })
    .await
    .unwrap();
    drop(connections);
}

#[tokio::test]
async fn abandoned_connection_sends_reset_before_releasing_socket() {
    use std::os::unix::net::UnixDatagram;
    use tokio::io::AsyncReadExt;

    let (peer, tun) = UnixDatagram::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut stack = TcpStackDirect::new(tun.into(), 1500);
    let mut rx = stack.take_tcp_rx().unwrap();
    let packet = |sequence, acknowledgment: Option<u32>, payload: &[u8]| {
        let builder = etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64)
            .tcp(10001, 443, sequence, 4096);
        let builder = match acknowledgment {
            Some(ack) => builder.ack(ack),
            None => builder.syn(),
        };
        let mut bytes = Vec::new();
        builder.write(&mut bytes, payload).unwrap();
        bytes
    };
    let mut buf = [0; 1500];
    peer.send(&packet(101, None, b"")).unwrap();
    let n = peer.recv(&mut buf).unwrap();
    let ip = Ipv4Packet::new_checked(&buf[..n]).unwrap();
    let syn_ack = TcpPacket::new_checked(ip.payload()).unwrap();
    assert!(syn_ack.syn() && syn_ack.ack());
    let acknowledgment = (syn_ack.seq_number().0 as u32).wrapping_add(1);
    peer.send(&packet(102, Some(acknowledgment), b"x")).unwrap();
    let mut incoming = rx.recv().await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(1),
        incoming.connection.read_exact(&mut [0]),
    )
    .await
    .unwrap()
    .unwrap();
    drop(incoming);

    loop {
        let n = peer
            .recv(&mut buf)
            .expect("abandoned connection did not send a reset");
        let ip = Ipv4Packet::new_checked(&buf[..n]).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        if tcp.rst() {
            assert!(!tcp.fin());
            break;
        }
    }
    peer.send(&packet(1001, None, b"")).unwrap();
    let n = peer.recv(&mut buf).unwrap();
    let ip = Ipv4Packet::new_checked(&buf[..n]).unwrap();
    let syn_ack = TcpPacket::new_checked(ip.payload()).unwrap();
    assert!(syn_ack.syn() && syn_ack.ack());
    assert_eq!(syn_ack.ack_number().0 as u32, 1002);
}

#[test]
fn mapped_ipv6_addresses_are_filtered_before_transport_dispatch() {
    for (source, target) in [
        ("::ffff:10.0.0.2", "2001:db8::1"),
        ("fd00::2", "::ffff:1.1.1.1"),
        ("fd00::2", "2001:db8::1"),
    ] {
        let source: std::net::Ipv6Addr = source.parse().unwrap();
        let target: std::net::Ipv6Addr = target.parse().unwrap();
        for tcp in [false, true] {
            let builder = etherparse::PacketBuilder::ipv6(source.octets(), target.octets(), 64);
            let mut packet = Vec::new();
            if tcp {
                builder
                    .tcp(10001, 443, 101, 4096)
                    .syn()
                    .write(&mut packet, b"")
                    .unwrap();
            } else {
                builder.udp(10001, 443).write(&mut packet, b"").unwrap();
            }
            assert_eq!(
                should_filter_packet(&packet),
                source.to_ipv4_mapped().is_some() || target.to_ipv4_mapped().is_some()
            );
        }
    }
}

#[test]
fn dropped_tcp_receiver_resets_established_connections() {
    let (peer, tun) = UnixDatagram::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut stack = TcpStackDirect::new(tun.into(), 1500);
    drop(stack.take_tcp_rx());
    let packet = |ack: Option<u32>| {
        let builder = etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64).tcp(
            10001,
            443,
            if ack.is_some() { 102 } else { 101 },
            4096,
        );
        let mut bytes = Vec::new();
        match ack {
            Some(ack) => builder.ack(ack).write(&mut bytes, b"x").unwrap(),
            None => builder.syn().write(&mut bytes, b"").unwrap(),
        }
        bytes
    };
    peer.send(&packet(None)).unwrap();
    let mut buffer = [0; 1500];
    let n = peer.recv(&mut buffer).unwrap();
    let ip = Ipv4Packet::new_checked(&buffer[..n]).unwrap();
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    assert!(tcp.syn() && tcp.ack() && !tcp.rst());
    peer.send(&packet(Some((tcp.seq_number() + 1).0 as u32)))
        .unwrap();
    loop {
        let n = peer.recv(&mut buffer).unwrap();
        let ip = Ipv4Packet::new_checked(&buffer[..n]).unwrap();
        if TcpPacket::new_checked(ip.payload()).unwrap().rst() {
            break;
        }
    }
    assert!(stack.is_running());
}

#[test]
fn packet_information_roundtrips_ipv4_and_ipv6() {
    use std::os::unix::net::UnixDatagram;
    let (peer, tun) = UnixDatagram::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    set_nonblocking(tun.as_raw_fd()).unwrap();
    let mut device = DirectDevice::new(tun.as_raw_fd(), 1500, true);
    for version in [0x45, 0x60] {
        let packet = [version, 1, 2, 3, 4, 5];
        let mut framed = packet_header(version).unwrap().to_vec();
        framed.extend_from_slice(&packet);
        peer.send(&framed).unwrap();
        assert_eq!(&device.try_recv().unwrap().unwrap()[..], &packet);
        device.write_packet(&packet).unwrap();
        let mut buf = [0; 64];
        let n = peer.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], &framed);
    }
}

#[test]
fn disabled_tcp_and_udp_do_not_reach_async_handlers() {
    use smoltcp::wire::Icmpv4Packet;
    for tcp in [false, true] {
        let (peer, tun) = UnixDatagram::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut stack = TcpStackDirect::with_config(
            tun.into(),
            TunServerConfig::new().tcp_enabled(!tcp).udp_enabled(tcp),
        )
        .unwrap();
        let mut udp_rx = stack.take_udp_rx().unwrap();
        let mut tcp_rx = stack.take_tcp_rx().unwrap();
        let builder = etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64);
        let mut packet = Vec::new();
        if tcp {
            builder
                .tcp(10001, 443, 101, 4096)
                .syn()
                .write(&mut packet, b"")
                .unwrap();
        } else {
            builder.udp(1000, 53).write(&mut packet, b"dns").unwrap();
        }
        peer.send(&packet).unwrap();
        // Two ingress replies also fence TCP egress from the preceding iteration.
        for sequence in [1, 2] {
            let mut sentinel = Vec::new();
            etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64)
                .icmpv4_echo_request(17, sequence)
                .write(&mut sentinel, b"processed")
                .unwrap();
            peer.send(&sentinel).unwrap();
            let mut response = [0; 1500];
            let n = peer.recv(&mut response).unwrap();
            let ip = Ipv4Packet::new_checked(&response[..n]).unwrap();
            assert_eq!(ip.next_header(), IpProtocol::Icmp);
            assert_eq!(
                Icmpv4Packet::new_checked(ip.payload())
                    .unwrap()
                    .echo_seq_no(),
                sequence
            );
        }
        assert!(matches!(
            udp_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert!(matches!(
            tcp_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert!(stack.is_running());
    }
}

#[test]
fn icmp_echo_replies_respect_protocol_switch() {
    use smoltcp::wire::{Icmpv4Message, Icmpv4Packet, Icmpv6Message, Icmpv6Packet};
    use std::os::unix::net::UnixDatagram;

    let ipv4_src = [10, 0, 0, 2];
    let ipv4_dst = [1, 1, 1, 1];
    let ipv6_src = Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let ipv6_dst = Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 3);
    let mut ipv4_request = Vec::new();
    etherparse::PacketBuilder::ipv4(ipv4_src, ipv4_dst, 64)
        .icmpv4_echo_request(17, 23)
        .write(&mut ipv4_request, b"ping")
        .unwrap();
    let mut ipv6_request = Vec::new();
    etherparse::PacketBuilder::ipv6(ipv6_src.octets(), ipv6_dst.octets(), 64)
        .icmpv6_echo_request(17, 23)
        .write(&mut ipv6_request, b"ping")
        .unwrap();

    for enabled in [true, false] {
        let (peer, tun) = UnixDatagram::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let stack =
            TcpStackDirect::with_config(tun.into(), TunServerConfig::new().icmp_enabled(enabled))
                .unwrap();
        if !enabled {
            peer.send(&ipv4_request).unwrap();
            peer.send(&ipv6_request).unwrap();
            let mut syn = Vec::new();
            etherparse::PacketBuilder::ipv4(ipv4_src, ipv4_dst, 64)
                .tcp(10001, 443, 101, 4096)
                .syn()
                .write(&mut syn, b"")
                .unwrap();
            peer.send(&syn).unwrap();
            let mut response = [0; 1500];
            let n = peer.recv(&mut response).unwrap();
            let ip = Ipv4Packet::new_checked(&response[..n]).unwrap();
            assert_eq!(ip.next_header(), IpProtocol::Tcp);
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            assert!(tcp.syn() && tcp.ack() && !tcp.rst());
            assert!(stack.is_running());
            continue;
        }
        for request in [&ipv4_request, &ipv6_request] {
            peer.send(request).unwrap();
            let mut response = [0; 1500];
            let result = peer.recv(&mut response);
            let response = &response[..result.unwrap()];
            if request[0] >> 4 == 4 {
                let ip = Ipv4Packet::new_checked(response).unwrap();
                assert_eq!(ip.src_addr().octets(), ipv4_dst);
                assert_eq!(ip.dst_addr().octets(), ipv4_src);
                assert!(ip.verify_checksum());
                let icmp = Icmpv4Packet::new_checked(ip.payload()).unwrap();
                assert_eq!(icmp.msg_type(), Icmpv4Message::EchoReply);
                assert_eq!((icmp.echo_ident(), icmp.echo_seq_no()), (17, 23));
                assert_eq!(icmp.data(), b"ping");
                assert!(icmp.verify_checksum());
            } else {
                let ip = Ipv6Packet::new_checked(response).unwrap();
                assert_eq!(ip.src_addr(), ipv6_dst);
                assert_eq!(ip.dst_addr(), ipv6_src);
                let icmp = Icmpv6Packet::new_checked(ip.payload()).unwrap();
                assert_eq!(icmp.msg_type(), Icmpv6Message::EchoReply);
                assert_eq!((icmp.echo_ident(), icmp.echo_seq_no()), (17, 23));
                assert_eq!(icmp.payload(), b"ping");
                assert!(icmp.verify_checksum(&ip.src_addr(), &ip.dst_addr()));
            }
        }
    }
}

#[test]
fn socket_owner_drop_wakes_readers_and_writers() {
    use futures::task::{ArcWake, waker};
    use std::pin::Pin;
    use std::task::Context;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    struct WakeFlag(AtomicBool);
    impl ArcWake for WakeFlag {
        fn wake_by_ref(flag: &Arc<Self>) {
            flag.0.store(true, Ordering::Relaxed);
        }
    }
    let read_flag = Arc::new(WakeFlag(AtomicBool::new(false)));
    let write_flag = Arc::new(WakeFlag(AtomicBool::new(false)));
    let read_waker = waker(read_flag.clone());
    let write_waker = waker(write_flag.clone());
    let mut read_cx = Context::from_waker(&read_waker);
    let mut write_cx = Context::from_waker(&write_waker);
    let control = Arc::new(TcpConnectionControl::new(1, 1));
    let mut conn = TcpConnection::new(control.clone(), Wake::new().unwrap().0);
    let info = SocketInfo {
        control: control.clone(),
        src_addr: "127.0.0.1:1".parse().unwrap(),
        dst_addr: "127.0.0.1:2".parse().unwrap(),
        pending: None,
    };
    let mut buf = [0; 1];
    assert!(
        Pin::new(&mut conn)
            .poll_read(&mut read_cx, &mut ReadBuf::new(&mut buf))
            .is_pending()
    );
    assert!(
        Pin::new(&mut conn)
            .poll_write(&mut write_cx, b"a")
            .is_ready()
    );
    assert!(
        Pin::new(&mut conn)
            .poll_write(&mut write_cx, b"b")
            .is_pending()
    );
    drop(info);
    assert!(read_flag.0.load(Ordering::Relaxed));
    assert!(write_flag.0.load(Ordering::Relaxed));
    assert!(
        Pin::new(&mut conn)
            .poll_read(&mut read_cx, &mut ReadBuf::new(&mut buf))
            .is_ready()
    );
    assert!(
        Pin::new(&mut conn)
            .poll_write(&mut write_cx, b"b")
            .is_ready()
    );
    drop(conn);
    assert!(control.orphan_deadline().is_some());
}

#[test]
fn idle_stack_delivers_udp_output_without_inbound_traffic() {
    use super::super::udp_handler::{UdpHandler, build_udp_packet};
    let (peer, tun) = UnixDatagram::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let (wake, mut receiver) = Wake::new().unwrap();
    let (setup_gate, setup) = TestGate::new();
    let (wait_gate, waiting) = TestGate::new();
    receiver.before_clear = Some(setup_gate);
    receiver.before_wait = Some(wait_gate);
    wake.notify();
    tun.set_nonblocking(true).unwrap();
    let mut stack =
        TcpStackDirect::start(tun.into(), TunServerConfig::new(), wake, receiver, false).unwrap();
    setup.wait();
    let (tx, rx) = mpsc::channel(PACKET_QUEUE_CAPACITY);
    stack.set_udp_response_tx(rx);
    // Setup coalesces into the drained notification, leaving only the writer able to wake poll.
    drop(setup);
    waiting.wait();
    let (_, from_tun) = mpsc::channel(1);
    let (_, writer) = UdpHandler::new(from_tun, tx, stack.wake_handle()).split();
    let src = "1.1.1.1:53".parse().unwrap();
    let dst = "10.0.0.2:10001".parse().unwrap();
    writer
        .send_sync((PacketBuffer::copy_from_slice(b"reply"), src, dst))
        .unwrap();
    drop(waiting);
    let expected = build_udp_packet(b"reply", src, dst).unwrap();
    let mut reply = [0; 1500];
    let length = peer.recv(&mut reply).unwrap();
    assert_eq!(&reply[..length], &*expected);
}

#[test]
fn one_notification_drains_more_than_one_response_batch() {
    let (peer, tun) = UnixDatagram::pair().unwrap();
    // The entire burst must fit even if the receiving thread is not scheduled yet.
    socket2::SockRef::from(&peer)
        .set_recv_buffer_size(256 * 1024)
        .unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut stack = TcpStackDirect::new(tun.into(), 1500);
    let (tx, rx) = mpsc::channel(2 * MAX_PACKET_BATCH + 1);
    for index in 0..2 * MAX_PACKET_BATCH + 1 {
        tx.try_send(PacketBuffer::copy_from_slice(&[index as u8]))
            .unwrap();
    }
    stack.set_udp_response_tx(rx);
    for index in 0..2 * MAX_PACKET_BATCH + 1 {
        let mut reply = [0; 2];
        let length = peer
            .recv(&mut reply)
            .unwrap_or_else(|error| panic!("response {index}: {error}"));
        assert_eq!(length, 1);
        assert_eq!(reply[0], index as u8);
    }
}

#[test]
fn setup_published_after_the_snapshot_interrupts_the_idle_wait() {
    let (peer, tun) = UnixDatagram::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let (mut stack, gate) = stack_at_wait(tun.into());
    let (tx, rx) = mpsc::channel(1);
    tx.try_send(PacketBuffer::copy_from_slice(b"reply"))
        .unwrap();
    stack.set_udp_response_tx(rx);
    drop(gate);
    let mut reply = [0; 5];
    assert_eq!(peer.recv(&mut reply).unwrap(), 5);
    assert_eq!(&reply, b"reply");
}

#[test]
fn retransmission_deadline_runs_without_new_input() {
    let (peer, tun) = UnixDatagram::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut stack = TcpStackDirect::new(tun.into(), 1500);
    let rx = stack.take_tcp_rx().unwrap();
    let mut syn = Vec::new();
    etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64)
        .tcp(10001, 443, 101, 4096)
        .syn()
        .write(&mut syn, b"")
        .unwrap();
    peer.send(&syn).unwrap();
    let mut buf = [0; 1500];
    let mut sequence = None;
    for _ in 0..2 {
        let length = peer.recv(&mut buf).unwrap();
        let ip = Ipv4Packet::new_checked(&buf[..length]).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(tcp.syn() && tcp.ack());
        if let Some(sequence) = sequence {
            assert_eq!(tcp.seq_number(), sequence);
        }
        sequence = Some(tcp.seq_number());
    }
    assert!(rx.is_empty());
}

#[test]
fn test_stack_shutdown_on_eof() {
    let (server, client) = UnixStream::pair().expect("Failed to create socket pair");
    let stack = TcpStackDirect::new(client.into(), 1500);

    thread::sleep(Duration::from_millis(100));
    assert!(stack.is_running(), "Stack thread should be running");

    // Closing the writer end triggers EOF on the reader.
    drop(server);

    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(2);

    while stack.is_running() {
        if start.elapsed() > timeout {
            panic!("Stack thread did not exit after EOF on FD");
        }
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn idle_stack_drop_does_not_require_incoming_io() {
    let (peer, client) = UnixStream::pair().unwrap();
    let (stack, gate) = stack_at_wait(client.into());
    let (tx, rx) = std::sync::mpsc::channel();
    let dropper = thread::spawn(move || {
        drop(stack);
        let _ = tx.send(());
    });
    drop(gate);
    let result = rx.recv_timeout(Duration::from_secs(5));
    drop(peer);
    dropper.join().unwrap();
    assert!(result.is_ok());
}

#[test]
fn test_stack_exits_promptly() {
    // Verifies the stack exits within 1 second of EOF, catching
    // regressions that would cause CPU spin on a dead fd.
    let (server, client) = UnixStream::pair().expect("Failed to create socket pair");
    let stack = TcpStackDirect::new(client.into(), 1500);

    thread::sleep(Duration::from_millis(100));
    assert!(stack.is_running());

    drop(server);

    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(1);

    while stack.is_running() {
        if start.elapsed() > timeout {
            panic!("Stack thread took >1s to exit after EOF (possible spin)");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn test_write_packet_eagain() {
    // Fill a non-blocking socket's write buffer, then verify write_packet
    // treats EAGAIN the same as ENOBUFS (drops the packet, returns Ok).
    let (reader, writer) = UnixStream::pair().expect("Failed to create socket pair");
    let writer_fd = writer.into_raw_fd();

    set_nonblocking(writer_fd).expect("set_nonblocking");

    // Fill the write buffer until WouldBlock
    let big_buf = vec![0u8; 65536];
    loop {
        let n = unsafe {
            libc::write(
                writer_fd,
                big_buf.as_ptr() as *const libc::c_void,
                big_buf.len(),
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            assert_eq!(
                err.kind(),
                io::ErrorKind::WouldBlock,
                "unexpected error: {}",
                err
            );
            break;
        }
    }

    // Now write_packet should drop the packet gracefully
    let result = write_packet(writer_fd, &[1, 2, 3], false);
    assert!(
        result.is_ok(),
        "write_packet should return Ok on EAGAIN, got {:?}",
        result
    );

    unsafe { libc::close(writer_fd) };
    drop(reader);
}
