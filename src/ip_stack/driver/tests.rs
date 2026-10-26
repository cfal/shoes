use super::*;
use smoltcp::wire::TcpControl;

#[test]
fn local_allocation_preserves_family_order_wraps_and_skips_both_flow_types() {
    let ipv4 = "10.77.0.1".parse().unwrap();
    let ipv6 = "fd77::1".parse().unwrap();
    let addresses = [ipv6, ipv4, "10.77.0.3".parse().unwrap()];
    let target = "10.77.0.2:443".parse().unwrap();
    let mut sockets = SocketSet::new(vec![]);
    let tcp = HashMap::from([(
        sockets.add(tcp_socket(4096)),
        TcpEntry {
            control: Arc::new(TcpConnectionControl::new(4096, 4096)),
            remote: target,
            local: SocketAddr::new(ipv4, LAST_EPHEMERAL_PORT),
            outbound: true,
            established: false,
            pending_connect: None,
            pending_accept: None,
        },
    )]);
    let local = SocketAddr::new(ipv4, FIRST_EPHEMERAL_PORT);
    let udp = HashMap::from([(
        local,
        UdpEntry(Arc::new(Mutex::new(UdpControl {
            local,
            remote: target,
            incoming: Default::default(),
            outgoing: Default::default(),
            reader: None,
            writer: None,
            closed: false,
            budget: Arc::new(Budget::new(None)),
        }))),
    )]);
    let mut next_port = LAST_EPHEMERAL_PORT;
    assert_eq!(
        allocate_local(&addresses, target, &mut next_port, &tcp, &udp).unwrap(),
        SocketAddr::new(ipv4, FIRST_EPHEMERAL_PORT + 1),
    );
    assert_eq!(next_port, FIRST_EPHEMERAL_PORT + 2);
    let error = allocate_local(&[ipv6], target, &mut next_port, &tcp, &udp).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);
    assert_eq!(
        error.to_string(),
        "WireGuard endpoint has no local address for this family",
    );
    assert_eq!(next_port, FIRST_EPHEMERAL_PORT + 2);
    next_port = LAST_EPHEMERAL_PORT;
    assert_eq!(
        allocate_local(
            &addresses,
            "[fd77::2]:443".parse().unwrap(),
            &mut next_port,
            &tcp,
            &udp,
        )
        .unwrap(),
        SocketAddr::new(ipv6, LAST_EPHEMERAL_PORT),
    );
    assert_eq!(next_port, FIRST_EPHEMERAL_PORT);
}

#[tokio::test]
async fn canceled_commands_still_advance_the_local_port_cursor() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let stack = PacketStack::new(
            vec!["10.77.0.1".parse().unwrap()],
            1408,
            false,
            TunResourceLimits::default(),
        )
        .unwrap();
        let target = "10.77.0.2:443".parse().unwrap();
        let (tcp, canceled) = oneshot::channel();
        drop(canceled);
        stack.handle.send(Command::Tcp(target, tcp)).await.unwrap();
        let (udp, canceled) = oneshot::channel();
        drop(canceled);
        stack.handle.send(Command::Udp(target, udp)).await.unwrap();
        let connection = stack.handle.open_udp(target).await.unwrap();
        assert_eq!(
            connection.control.lock().local.port(),
            FIRST_EPHEMERAL_PORT + 2
        );
    })
    .await
    .unwrap();
}

fn tcp_segment(
    source: SocketAddr,
    target: SocketAddr,
    sequence: u32,
    control: TcpControl,
    ack: Option<u32>,
) -> PacketBuffer {
    tcp_segment_with_data(source, target, sequence, control, ack, &[])
}

fn tcp_segment_with_data(
    source: SocketAddr,
    target: SocketAddr,
    sequence: u32,
    control: TcpControl,
    ack: Option<u32>,
    payload: &[u8],
) -> PacketBuffer {
    let mut tcp = etherparse::TcpHeader::new(source.port(), target.port(), sequence, 65535);
    tcp.syn = control == TcpControl::Syn;
    tcp.rst = control == TcpControl::Rst;
    tcp.fin = control == TcpControl::Fin;
    tcp.ack = ack.is_some();
    tcp.acknowledgment_number = ack.unwrap_or(0);
    let builder = match (source.ip(), target.ip()) {
        (IpAddr::V4(source), IpAddr::V4(target)) => {
            etherparse::PacketBuilder::ipv4(source.octets(), target.octets(), 64)
        }
        (IpAddr::V6(source), IpAddr::V6(target)) => {
            etherparse::PacketBuilder::ipv6(source.octets(), target.octets(), 64)
        }
        _ => unreachable!(),
    }
    .tcp_header(tcp);
    let mut packet = PacketBuffer::with_capacity(builder.size(payload.len()));
    packet.resize(builder.size(payload.len()));
    builder.write(&mut &mut packet[..], payload).unwrap();
    packet
}

#[tokio::test]
async fn inbound_publication_waits_for_handshake_and_preserves_final_ack_data_and_fin() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tokio::time::timeout(Duration::from_secs(5), async {
        for (source, target) in [
            ("10.77.0.2:40000", "198.18.0.1:443"),
            ("[fd77::2]:40000", "[fd77::1]:443"),
        ] {
            for fin in [false, true] {
                let source: SocketAddr = source.parse().unwrap();
                let target: SocketAddr = target.parse().unwrap();
                let mut stack =
                    PacketStack::new(vec![target.ip()], 1408, true, TunResourceLimits::default())
                        .unwrap();
                let mut accepted = stack.tcp.take().unwrap();
                let mut output = stack.output.take().unwrap();
                let syn = tcp_segment(source, target, 1000, TcpControl::Syn, None);
                stack
                    .input
                    .send(PacketBuffer::copy_from_slice(&syn))
                    .await
                    .unwrap();
                stack.input.send(syn).await.unwrap();
                stack.handle.wake.notify();
                let reply = output.recv().await.unwrap();
                let info = packet_info(&reply).unwrap();
                let tcp =
                    TcpPacket::new_checked(&reply[info.transport_offset..info.length]).unwrap();
                assert!(tcp.syn() && tcp.ack() && !tcp.rst());
                assert!(matches!(
                    accepted.try_recv(),
                    Err(mpsc::error::TryRecvError::Empty)
                ));
                stack
                    .input
                    .send(tcp_segment_with_data(
                        source,
                        target,
                        1001,
                        if fin {
                            TcpControl::Fin
                        } else {
                            TcpControl::None
                        },
                        Some((tcp.seq_number() + 1).0 as u32),
                        b"request",
                    ))
                    .await
                    .unwrap();
                stack.handle.wake.notify();
                let mut flow = accepted.recv().await.unwrap();
                assert_eq!(flow.source, source);
                assert_eq!(flow.target, target);
                let mut data = [0; 7];
                flow.connection.read_exact(&mut data).await.unwrap();
                assert_eq!(&data, b"request");
                if fin {
                    assert_eq!(flow.connection.read(&mut [0; 1]).await.unwrap(), 0);
                }
                flow.connection.write_all(b"response").await.unwrap();
                loop {
                    let reply = output.recv().await.unwrap();
                    let info = packet_info(&reply).unwrap();
                    let tcp =
                        TcpPacket::new_checked(&reply[info.transport_offset..info.length]).unwrap();
                    assert!(!tcp.rst());
                    if !tcp.payload().is_empty() {
                        assert_eq!(tcp.payload(), b"response");
                        break;
                    }
                }
                assert!(matches!(
                    accepted.try_recv(),
                    Err(mpsc::error::TryRecvError::Empty)
                ));
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unknown_tcp_segments_receive_resets_without_admitting_flows() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for inbound in [false, true] {
            for (local, source, transparent) in [
                ("10.77.0.1", "10.77.0.2:40000", "198.18.0.1"),
                ("fd77::1", "[fd77::2]:40000", "2001:db8::1"),
            ] {
                let mut stack = PacketStack::new(
                    vec![local.parse().unwrap()],
                    1408,
                    inbound,
                    TunResourceLimits::default(),
                )
                .unwrap();
                let source = source.parse().unwrap();
                let target = SocketAddr::new(
                    if inbound { transparent } else { local }.parse().unwrap(),
                    49152,
                );
                let mut output = stack.output.take().unwrap();
                let mut accepted = stack.tcp.take().unwrap();
                stack
                    .input
                    .send(tcp_segment(source, target, 5000, TcpControl::Rst, None))
                    .await
                    .unwrap();
                for control in [TcpControl::None, TcpControl::Fin, TcpControl::Syn] {
                    stack
                        .input
                        .send(tcp_segment(source, target, 5000, control, Some(7000)))
                        .await
                        .unwrap();
                    stack.handle.wake.notify();
                    let packet = output.recv().await.unwrap();
                    let info = packet_info(&packet).unwrap();
                    assert_eq!(info.source, target);
                    assert_eq!(info.target, source);
                    let tcp = TcpPacket::new_checked(&packet[info.transport_offset..]).unwrap();
                    assert!(tcp.rst());
                    assert_eq!(tcp.seq_number().0, 7000);
                    assert!(!tcp.ack());
                    assert!(matches!(
                        accepted.try_recv(),
                        Err(mpsc::error::TryRecvError::Empty)
                    ));
                }
                // FIFO processing makes the ACK reply a barrier for the preceding RST.
                assert!(matches!(
                    output.try_recv(),
                    Err(mpsc::error::TryRecvError::Empty)
                ));
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn inbound_rejects_mapped_ipv4_packet_addresses() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut stack = PacketStack::new(
            vec!["fd77::1".parse().unwrap()],
            1408,
            true,
            TunResourceLimits::default(),
        )
        .unwrap();
        let mut accepted = stack.tcp.take().unwrap();
        let mut inbound_udp = stack.udp.take().unwrap();
        let source: SocketAddr = "[fd77::2]:40000".parse().unwrap();
        let target: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let barrier =
            crate::tun::udp_handler::build_udp_packet(b"barrier", source, target).unwrap();

        for mapped in ["::ffff:0.0.0.0", "::ffff:224.0.0.251", "::ffff:127.0.0.1"] {
            let mapped = mapped.parse().unwrap();
            for (source, target) in [
                (source, SocketAddr::new(mapped, target.port())),
                (SocketAddr::new(mapped, source.port()), target),
            ] {
                stack
                    .input
                    .send(tcp_segment(source, target, 1000, TcpControl::Syn, None))
                    .await
                    .unwrap();
                stack
                    .input
                    .send(
                        crate::tun::udp_handler::build_udp_packet(b"rejected", source, target)
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                stack
                    .input
                    .send(PacketBuffer::copy_from_slice(&barrier))
                    .await
                    .unwrap();
                stack.handle.wake.notify();
                // Receiving the sentinel proves both preceding packets were processed.
                assert_eq!(&*inbound_udp.recv().await.unwrap(), &*barrier);
                assert!(matches!(
                    accepted.try_recv(),
                    Err(mpsc::error::TryRecvError::Empty)
                ));
            }
        }
        assert_eq!(stack.drops.load(Ordering::Relaxed), 12);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn full_accept_queue_drops_syn_before_sending_synack() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut stack = PacketStack::new(
            vec!["10.77.0.1".parse().unwrap()],
            1408,
            true,
            TunResourceLimits::default(),
        )
        .unwrap();
        let mut accepted = stack.tcp.take().unwrap();
        let mut output = stack.output.take().unwrap();
        let mut inbound_udp = stack.udp.take().unwrap();
        let target = "198.18.0.1:443".parse().unwrap();
        let mut first_ack = None;
        for port in 40000..40000 + QUEUE_CAPACITY as u16 {
            let source = SocketAddr::new("10.77.0.2".parse().unwrap(), port);
            stack
                .input
                .send(tcp_segment(source, target, 1000, TcpControl::Syn, None))
                .await
                .unwrap();
            stack.handle.wake.notify();
            let reply = output.recv().await.unwrap();
            if first_ack.is_none() {
                let ip = Ipv4Packet::new_checked(&*reply).unwrap();
                let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
                first_ack = Some((tcp.seq_number() + 1).0 as u32);
            }
        }
        assert!(matches!(
            accepted.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        let overflow = "10.77.0.2:50000".parse().unwrap();
        stack
            .input
            .send(tcp_segment(overflow, target, 1000, TcpControl::Syn, None))
            .await
            .unwrap();
        // The UDP sentinel is delivered only after the preceding SYN has been processed.
        stack
            .input
            .send(crate::tun::udp_handler::build_udp_packet(b"barrier", overflow, target).unwrap())
            .await
            .unwrap();
        stack.handle.wake.notify();
        inbound_udp.recv().await.unwrap();
        while let Ok(packet) = output.try_recv() {
            let ip = Ipv4Packet::new_checked(&*packet).unwrap();
            assert_ne!(
                TcpPacket::new_checked(ip.payload()).unwrap().dst_port(),
                overflow.port()
            );
        }
        stack
            .input
            .send(tcp_segment(
                "10.77.0.2:40000".parse().unwrap(),
                target,
                1001,
                TcpControl::None,
                first_ack,
            ))
            .await
            .unwrap();
        stack.handle.wake.notify();
        let _first = accepted.recv().await.unwrap();
        stack
            .input
            .send(tcp_segment(overflow, target, 2000, TcpControl::Syn, None))
            .await
            .unwrap();
        stack.handle.wake.notify();
        loop {
            let packet = output.recv().await.unwrap();
            let ip = Ipv4Packet::new_checked(&*packet).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            if tcp.dst_port() == overflow.port() {
                assert!(tcp.syn() && tcp.ack());
                assert_eq!(tcp.ack_number().0, 2001);
                break;
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn inbound_handshakes_use_the_configured_limit_not_the_packet_queue_limit() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut stack = PacketStack::new(
            vec!["10.77.0.1".parse().unwrap()],
            1408,
            true,
            TunResourceLimits {
                max_tcp_connections: Some(128),
                ..Default::default()
            },
        )
        .unwrap();
        let mut output = stack.output.take().unwrap();
        let mut accepted = stack.tcp.take().unwrap();
        let target = "198.18.0.1:443".parse().unwrap();
        let mut acknowledgments = Vec::new();
        for port in 40000..40096 {
            let source = SocketAddr::new("10.77.0.2".parse().unwrap(), port);
            stack
                .input
                .send(tcp_segment(source, target, 1000, TcpControl::Syn, None))
                .await
                .unwrap();
            stack.handle.wake.notify();
            loop {
                let reply = output.recv().await.unwrap();
                let ip = Ipv4Packet::new_checked(&*reply).unwrap();
                let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
                assert!(tcp.syn() && tcp.ack() && !tcp.rst());
                if tcp.dst_port() == port {
                    acknowledgments.push((source, (tcp.seq_number() + 1).0 as u32));
                    break;
                }
            }
            assert!(matches!(
                accepted.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
        }
        let mut connections = Vec::new();
        for (source, ack) in acknowledgments {
            stack
                .input
                .send(tcp_segment(
                    source,
                    target,
                    1001,
                    TcpControl::None,
                    Some(ack),
                ))
                .await
                .unwrap();
            stack.handle.wake.notify();
            let connection = accepted.recv().await.unwrap();
            assert_eq!(connection.source, source);
            connections.push(connection);
        }
        assert_eq!(connections.len(), 96);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn accept_receiver_dropped_during_handshake_resets_the_connection() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut stack = PacketStack::new(
            vec!["10.77.0.1".parse().unwrap()],
            1408,
            true,
            TunResourceLimits {
                max_tcp_connections: Some(1),
                ..Default::default()
            },
        )
        .unwrap();
        let mut output = stack.output.take().unwrap();
        let source = "10.77.0.2:40000".parse().unwrap();
        let target = "198.18.0.1:443".parse().unwrap();
        stack
            .input
            .send(tcp_segment(source, target, 1000, TcpControl::Syn, None))
            .await
            .unwrap();
        stack.handle.wake.notify();
        let reply = output.recv().await.unwrap();
        let ip = Ipv4Packet::new_checked(&*reply).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(tcp.syn() && tcp.ack());
        let ack = (tcp.seq_number() + 1).0 as u32;
        drop(stack.tcp.take());
        stack
            .input
            .send(tcp_segment_with_data(
                source,
                target,
                1001,
                TcpControl::None,
                Some(ack),
                b"request",
            ))
            .await
            .unwrap();
        stack.handle.wake.notify();
        loop {
            let reply = output.recv().await.unwrap();
            let ip = Ipv4Packet::new_checked(&*reply).unwrap();
            if TcpPacket::new_checked(ip.payload()).unwrap().rst() {
                break;
            }
        }
        // Commands run before ingress, so two barriers also observe post-egress cleanup.
        for port in [53, 54] {
            let _barrier = stack
                .handle
                .open_udp(SocketAddr::new(target.ip(), port))
                .await
                .unwrap();
        }
        assert_eq!(stack.counts.tcp.load(Ordering::Relaxed), 0);
    })
    .await
    .unwrap();
}

#[test]
fn orphaned_fin_wait_releases_admission_even_when_peer_keeps_sending_acks() {
    use super::super::{TCP_ORPHAN_TIMEOUT, tcp_conn::TcpSocketState, tcp_poll_delay};
    use smoltcp::time::Duration as SmolDuration;

    for live_peer in [false, true] {
        let (output, mut packets) = mpsc::channel(QUEUE_CAPACITY);
        let mut device = QueueDevice {
            packet: None,
            output,
            mtu: 1408,
            drops: Arc::default(),
        };
        let start = now();
        let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut device, start);
        let source: SocketAddr = "10.77.0.2:40000".parse().unwrap();
        let target: SocketAddr = "10.77.0.1:443".parse().unwrap();
        iface.update_ip_addrs(|ips| ips.push(IpCidr::new(target.ip().into(), 24)).unwrap());
        let mut socket = tcp_socket(4096);
        socket.listen(target).unwrap();
        let mut sockets = SocketSet::new(vec![]);
        let handle = sockets.add(socket);
        let control = Arc::new(TcpConnectionControl::new(4096, 4096));
        let connection = TcpConnection::new(control.clone(), Wake::new().unwrap().0);
        let mut entries = HashMap::from([(
            handle,
            TcpEntry {
                control: control.clone(),
                remote: source,
                local: target,
                outbound: false,
                established: false,
                pending_connect: None,
                pending_accept: None,
            },
        )]);
        let counts = FlowCounts::default();
        device.packet = Some(tcp_segment(source, target, 1000, TcpControl::Syn, None));
        iface.poll(start, &mut device, &mut sockets);
        let synack = packets.try_recv().unwrap();
        let ip = Ipv4Packet::new_checked(&*synack).unwrap();
        let ack = (TcpPacket::new_checked(ip.payload()).unwrap().seq_number() + 1).0 as u32;
        device.packet = Some(tcp_segment(
            source,
            target,
            1001,
            TcpControl::None,
            Some(ack),
        ));
        iface.poll(start, &mut device, &mut sockets);
        entries
            .get_mut(&handle)
            .unwrap()
            .pump(handle, sockets.get_mut::<TcpSocket>(handle), start);
        sockets.get_mut::<TcpSocket>(handle).close();
        control.set_send_state(TcpSocketState::Closing);
        drop(connection);
        let deadline = control.orphan_deadline().unwrap();
        let abandoned = deadline - TCP_ORPHAN_TIMEOUT;
        entries.get_mut(&handle).unwrap().pump(
            handle,
            sockets.get_mut::<TcpSocket>(handle),
            abandoned,
        );
        iface.poll_egress(abandoned, &mut device, &mut sockets);
        let fin = packets.try_recv().unwrap();
        let ip = Ipv4Packet::new_checked(&*fin).unwrap();
        assert!(TcpPacket::new_checked(ip.payload()).unwrap().fin());
        let ack = ack.wrapping_add(1);
        device.packet = Some(tcp_segment(
            source,
            target,
            1001,
            TcpControl::None,
            Some(ack),
        ));
        iface.poll(abandoned, &mut device, &mut sockets);
        assert_eq!(sockets.get::<TcpSocket>(handle).state(), State::FinWait2);
        assert_eq!(sockets.get::<TcpSocket>(handle).keep_alive(), None);
        assert!(!reconcile_tcp(&mut entries, &mut sockets, &counts));
        assert_eq!(counts.tcp.load(Ordering::Relaxed), 1);

        for seconds in [1, 29, 59, 60] {
            let timestamp = abandoned + SmolDuration::from_secs(seconds);
            if live_peer {
                device.packet = Some(tcp_segment(
                    source,
                    target,
                    1001,
                    TcpControl::None,
                    Some(ack),
                ));
                iface.poll_ingress_single(timestamp, &mut device, &mut sockets);
            }
            assert_eq!(
                tcp_poll_delay(timestamp, None, std::iter::once(&*control)),
                Some(SmolDuration::from_secs(60 - seconds)),
            );
            entries.get_mut(&handle).unwrap().pump(
                handle,
                sockets.get_mut::<TcpSocket>(handle),
                timestamp,
            );
            iface.poll_egress(timestamp, &mut device, &mut sockets);
            assert!(!reconcile_tcp(&mut entries, &mut sockets, &counts));
            assert_eq!(
                counts.tcp.load(Ordering::Relaxed),
                usize::from(seconds < 60)
            );
        }
        assert!(entries.is_empty());
        assert_eq!(control.recv_state(), TcpSocketState::Closed);
    }
}

#[tokio::test]
async fn reset_releases_half_open_and_established_flows_before_the_next_syn() {
    for established in [false, true] {
        tokio::time::timeout(Duration::from_secs(3), async {
            let mut stack = PacketStack::new(
                vec!["10.77.0.1".parse().unwrap()],
                1408,
                true,
                TunResourceLimits {
                    max_tcp_connections: Some(1),
                    ..Default::default()
                },
            )
            .unwrap();
            let mut accepted = stack.tcp.take().unwrap();
            let mut output = stack.output.take().unwrap();
            let target = "198.18.0.1:443".parse().unwrap();
            let first = "10.77.0.2:40000".parse().unwrap();
            let second = if established {
                first
            } else {
                "10.77.0.3:50000".parse().unwrap()
            };
            stack
                .input
                .send(tcp_segment(first, target, 1000, TcpControl::Syn, None))
                .await
                .unwrap();
            stack.handle.wake.notify();
            let reply = output.recv().await.unwrap();
            let ip = Ipv4Packet::new_checked(&*reply).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            assert!(tcp.syn() && tcp.ack());
            assert_eq!(tcp.ack_number().0, 1001);
            assert!(matches!(
                accepted.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
            let mut previous = if established {
                stack
                    .input
                    .send(tcp_segment(
                        first,
                        target,
                        1001,
                        TcpControl::None,
                        Some((tcp.seq_number() + 1).0 as u32),
                    ))
                    .await
                    .unwrap();
                stack.handle.wake.notify();
                Some(accepted.recv().await.unwrap())
            } else {
                None
            };

            // An abandoned connect responds to SYN-ACK with RST and no ACK flag.
            stack
                .input
                .try_send(tcp_segment(first, target, 1001, TcpControl::Rst, None))
                .unwrap();
            stack
                .input
                .try_send(tcp_segment(second, target, 5000, TcpControl::Syn, None))
                .unwrap();
            stack.handle.wake.notify();
            let reply = output.recv().await.unwrap();
            let ip = Ipv4Packet::new_checked(&*reply).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            assert_eq!(tcp.dst_port(), second.port());
            assert!(tcp.syn() && tcp.ack());
            stack
                .input
                .send(tcp_segment(
                    second,
                    target,
                    5001,
                    TcpControl::None,
                    Some((tcp.seq_number() + 1).0 as u32),
                ))
                .await
                .unwrap();
            stack.handle.wake.notify();
            let next = accepted.recv().await.unwrap();
            assert_eq!(next.source, second);
            assert_eq!(next.target, target);
            if let Some(previous) = &mut previous {
                use tokio::io::AsyncReadExt;
                assert_eq!(previous.connection.read(&mut [0; 1]).await.unwrap(), 0);
            }
            for port in [53, 54] {
                let _barrier = stack
                    .handle
                    .open_udp(SocketAddr::new(target.ip(), port))
                    .await
                    .unwrap();
            }
            assert_eq!(stack.counts.tcp.load(Ordering::Relaxed), 1);
            assert!(accepted.try_recv().is_err());
        })
        .await
        .unwrap();
    }
}

#[test]
fn inbound_handshake_timeout_is_lifted_only_after_establishment() {
    for complete in [false, true] {
        let (output, mut packets) = mpsc::channel(QUEUE_CAPACITY);
        let mut device = QueueDevice {
            packet: None,
            output,
            mtu: 1408,
            drops: Arc::default(),
        };
        let start = Instant::from_secs(1);
        let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut device, start);
        let source: SocketAddr = "10.77.0.2:40000".parse().unwrap();
        let target: SocketAddr = "10.77.0.1:443".parse().unwrap();
        iface.update_ip_addrs(|ips| ips.push(IpCidr::new(target.ip().into(), 24)).unwrap());
        let mut socket = tcp_socket(4096);
        socket.listen(target).unwrap();
        let mut sockets = SocketSet::new(vec![]);
        let handle = sockets.add(socket);
        let control = Arc::new(TcpConnectionControl::new(4096, 4096));
        let (accepted, mut accepted_rx) = mpsc::channel(1);
        let mut entry = TcpEntry {
            control: control.clone(),
            remote: source,
            local: target,
            outbound: false,
            established: false,
            pending_connect: None,
            pending_accept: Some((
                accepted.clone().try_reserve_owned().unwrap(),
                AcceptedTcp {
                    connection: TcpConnection::new(control, Wake::new().unwrap().0),
                    source,
                    target,
                },
            )),
        };
        device.packet = Some(tcp_segment(source, target, 1000, TcpControl::Syn, None));
        iface.poll(start, &mut device, &mut sockets);
        let socket = sockets.get_mut::<TcpSocket>(handle);
        entry.pump(handle, socket, start);
        assert_eq!(socket.state(), State::SynReceived);
        assert_eq!(socket.timeout(), Some(TCP_HANDSHAKE_TIMEOUT));
        assert!(matches!(
            accepted_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert_eq!(accepted.capacity(), 0);
        if complete {
            let reply = packets.try_recv().unwrap();
            let ip = Ipv4Packet::new_checked(&*reply).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            let ack = (tcp.seq_number() + 1).0 as u32;
            device.packet = Some(tcp_segment(
                source,
                target,
                1001,
                TcpControl::None,
                Some(ack),
            ));
            iface.poll(start, &mut device, &mut sockets);
            let socket = sockets.get_mut::<TcpSocket>(handle);
            entry.pump(handle, socket, start);
            assert!(entry.established);
            assert_eq!(
                socket.timeout(),
                Some(super::super::TCP_PEER_SILENCE_TIMEOUT)
            );
        }
        iface.poll(
            start + TCP_HANDSHAKE_TIMEOUT + smoltcp::time::Duration::from_secs(1),
            &mut device,
            &mut sockets,
        );
        assert_eq!(
            sockets.get::<TcpSocket>(handle).state(),
            if complete {
                State::Established
            } else {
                State::Closed
            }
        );
        let flow = accepted_rx.try_recv().ok();
        assert_eq!(flow.is_some(), complete);
        drop(entry);
        assert_eq!(accepted.capacity(), 1);
    }
}

#[tokio::test]
async fn dropping_after_write_shutdown_finishes_the_fin_exchange_without_reset() {
    use tokio::io::AsyncWriteExt;

    tokio::time::timeout(Duration::from_secs(3), async {
        let mut stack = PacketStack::new(
            vec!["10.77.0.1".parse().unwrap()],
            1408,
            true,
            TunResourceLimits::default(),
        )
        .unwrap();
        let mut accepted = stack.tcp.take().unwrap();
        let mut output = stack.output.take().unwrap();
        let target = "198.18.0.1:443".parse().unwrap();
        let source = "10.77.0.2:40000".parse().unwrap();
        stack
            .input
            .send(tcp_segment(source, target, 1000, TcpControl::Syn, None))
            .await
            .unwrap();
        stack.handle.wake.notify();
        let synack = output.recv().await.unwrap();
        let ip = Ipv4Packet::new_checked(&*synack).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let ack = (tcp.seq_number() + 1).0 as u32;
        stack
            .input
            .send(tcp_segment(
                source,
                target,
                1001,
                TcpControl::None,
                Some(ack),
            ))
            .await
            .unwrap();
        stack.handle.wake.notify();
        let mut flow = accepted.recv().await.unwrap();
        flow.connection.shutdown().await.unwrap();
        drop(flow);

        let fin = output.recv().await.unwrap();
        let ip = Ipv4Packet::new_checked(&*fin).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(tcp.fin() && !tcp.rst());
        let ack = (tcp.seq_number() + 1).0 as u32;
        stack
            .input
            .send(tcp_segment(
                source,
                target,
                1001,
                TcpControl::Fin,
                Some(ack),
            ))
            .await
            .unwrap();
        stack.handle.wake.notify();
        let reply = output.recv().await.unwrap();
        let ip = Ipv4Packet::new_checked(&*reply).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(tcp.ack() && !tcp.rst());
        assert_eq!(tcp.ack_number().0, 1002);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn command_channel_waits_for_capacity_and_rejects_closed_stack() {
    let (commands, mut receiver) = mpsc::channel(1);
    let (wake, _wake_rx) = Wake::new().unwrap();
    let handle = StackHandle {
        commands,
        wake,
        running: Arc::new(AtomicBool::new(true)),
    };
    let target = "10.77.0.1:53".parse().unwrap();
    let command = || Command::Udp(target, oneshot::channel().0);
    handle.commands.try_send(command()).unwrap();
    let mut opening = Box::pin(handle.open_udp(target));
    assert!(futures::poll!(&mut opening).is_pending());
    receiver.try_recv().unwrap();
    assert!(futures::poll!(&mut opening).is_pending());
    let Command::Udp(_, result) = receiver.try_recv().unwrap() else {
        panic!("expected UDP open");
    };
    let _ = result.send(Err(io::ErrorKind::AddrNotAvailable.into()));
    assert_eq!(
        opening.await.err().unwrap().kind(),
        io::ErrorKind::AddrNotAvailable
    );
    handle.commands.try_send(command()).unwrap();
    let mut opening = Box::pin(handle.open_udp(target));
    assert!(futures::poll!(&mut opening).is_pending());
    drop(receiver);
    assert_eq!(
        opening.await.err().unwrap().kind(),
        io::ErrorKind::NotConnected
    );
    assert_eq!(
        handle.open_udp(target).await.err().unwrap().kind(),
        io::ErrorKind::NotConnected
    );
}

#[tokio::test]
async fn refused_outbound_handshakes_report_connection_refused() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for (local, target) in [("10.77.0.1", "10.77.0.2:443"), ("fd77::1", "[fd77::2]:443")] {
            let target: SocketAddr = target.parse().unwrap();
            let mut stack = PacketStack::new(
                vec![local.parse().unwrap()],
                1408,
                false,
                TunResourceLimits::default(),
            )
            .unwrap();
            let mut output = stack.output.take().unwrap();
            let reject = async {
                let syn = output.recv().await.unwrap();
                let info = packet_info(&syn).unwrap();
                let tcp = TcpPacket::new_checked(&syn[info.transport_offset..info.length]).unwrap();
                assert!(tcp.syn() && !tcp.ack());
                stack
                    .input
                    .send(tcp_segment(
                        target,
                        info.source,
                        0,
                        TcpControl::Rst,
                        Some((tcp.seq_number() + 1).0 as u32),
                    ))
                    .await
                    .unwrap();
                stack.handle.wake.notify();
            };
            let (result, ()) = tokio::join!(stack.handle.connect(target), reject);
            assert_eq!(
                result.err().unwrap().kind(),
                io::ErrorKind::ConnectionRefused
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn tcp_connect_timeout_includes_waiting_for_command_capacity() {
    let (commands, mut receiver) = mpsc::channel(1);
    let (wake, _wake_rx) = Wake::new().unwrap();
    let handle = StackHandle {
        commands,
        wake,
        running: Arc::new(AtomicBool::new(true)),
    };
    let target = "10.77.0.1:443".parse().unwrap();
    handle
        .commands
        .try_send(Command::Tcp(target, oneshot::channel().0))
        .unwrap();
    let error = handle.connect(target).await.err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(error.to_string(), "WireGuard TCP connect timed out");
    receiver.try_recv().unwrap();
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn udp_open_bursts_respect_flow_limits_not_queue_capacity() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let limit = QUEUE_CAPACITY * 4;
        let stack = PacketStack::new(
            vec!["10.77.0.1".parse().unwrap()],
            1408,
            false,
            TunResourceLimits {
                max_udp_sessions: Some(limit),
                max_udp_destinations: Some(limit),
                ..Default::default()
            },
        )
        .unwrap();
        let target = "10.77.0.2:53".parse().unwrap();
        let connections =
            futures::future::join_all((0..limit).map(|_| stack.handle.open_udp(target)))
                .await
                .into_iter()
                .collect::<io::Result<Vec<_>>>()
                .unwrap();
        assert_eq!(connections.len(), limit);
        assert_eq!(
            stack.handle.open_udp(target).await.err().unwrap().kind(),
            crate::resources::exhausted().kind()
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn malformed_syns_do_not_admit_flows_or_capture_later_peers() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut stack = PacketStack::new(
            vec!["10.77.0.1".parse().unwrap()],
            1408,
            true,
            TunResourceLimits {
                max_tcp_connections: Some(1),
                ..Default::default()
            },
        )
        .unwrap();
        let mut accepted = stack.tcp.take().unwrap();
        let mut output = stack.output.take().unwrap();
        for malformed in 0..5 {
            let source = if malformed < 4 {
                "10.77.0.2"
            } else {
                "10.77.0.3"
            }
            .parse()
            .unwrap();
            let target = "198.18.0.1".parse().unwrap();
            let mut packet = PacketBuffer::with_capacity(44);
            packet.resize(44);
            let mut ip = Ipv4Packet::new_unchecked(&mut *packet);
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
            tcp.set_src_port(if malformed == 2 { 0 } else { 40000 });
            tcp.set_dst_port(443);
            tcp.set_seq_number(smoltcp::wire::TcpSeqNumber(1000));
            tcp.set_syn(true);
            tcp.set_fin(malformed == 0);
            tcp.set_rst(malformed == 1);
            tcp.set_window_len(65535);
            if malformed == 3 {
                tcp.options_mut().copy_from_slice(&[2, 1, 0, 0]);
            }
            tcp.fill_checksum(&source.into(), &target.into());
            stack.input.send(packet).await.unwrap();
            stack.handle.wake.notify();
        }
        let reply = output.recv().await.unwrap();
        let ip = Ipv4Packet::new_checked(&*reply).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert_eq!(
            ip.dst_addr(),
            "10.77.0.3".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert!(tcp.syn() && tcp.ack());
        stack
            .input
            .send(tcp_segment(
                "10.77.0.3:40000".parse().unwrap(),
                "198.18.0.1:443".parse().unwrap(),
                1001,
                TcpControl::None,
                Some((tcp.seq_number() + 1).0 as u32),
            ))
            .await
            .unwrap();
        stack.handle.wake.notify();
        let flow = accepted.recv().await.unwrap();
        assert_eq!(flow.source, "10.77.0.3:40000".parse().unwrap());
        assert_eq!(flow.target, "198.18.0.1:443".parse().unwrap());
        // A command is processed after the packet batch, making the count assertion deterministic.
        let _barrier = stack
            .handle
            .open_udp("10.77.0.2:53".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(stack.counts.tcp.load(Ordering::Relaxed), 1);
        assert!(accepted.try_recv().is_err());
    })
    .await
    .unwrap();
}

#[test]
fn classification_tracks_transport_offset_and_length() {
    for (source, target, offset) in [
        ("10.0.0.1:1", "10.0.0.2:2", 20),
        ("[fd77::1]:1", "[fd77::2]:2", 40),
    ] {
        let source = source.parse().unwrap();
        let target = target.parse().unwrap();
        let packet = crate::tun::udp_handler::build_udp_packet(b"data", source, target).unwrap();
        let info = packet_info(&packet).unwrap();
        assert_eq!(info.protocol, IpProtocol::Udp);
        assert_eq!(info.source, source);
        assert_eq!(info.target, target);
        assert!(!info.syn);
        assert_eq!(info.transport_offset, offset);
        assert_eq!(info.length, packet.len());
        assert_eq!(&packet[info.transport_offset + 8..info.length], b"data");

        if source.is_ipv4() {
            let mut options = packet[..offset].to_vec();
            options.extend_from_slice(&[0; 4]);
            options.extend_from_slice(&packet[offset..]);
            let length = options.len();
            let mut ip = Ipv4Packet::new_unchecked(&mut options);
            ip.set_header_len(24);
            ip.set_total_len(length as u16);
            ip.fill_checksum();
            let info = packet_info(&options).unwrap();
            assert_eq!(info.transport_offset, 24);
            assert_eq!(info.length, length);
            assert_eq!(&options[info.transport_offset + 8..info.length], b"data");
        }
    }
}

#[test]
fn classification_rejects_fragments_extensions_and_bad_checksums() {
    let packet = || {
        crate::tun::udp_handler::build_udp_packet(
            b"data",
            "10.0.0.1:1".parse().unwrap(),
            "10.0.0.2:2".parse().unwrap(),
        )
        .unwrap()
    };
    assert!(packet_info(&packet()).is_some());
    for offset in [0, 1] {
        let mut bytes = packet();
        let mut ip = Ipv4Packet::new_unchecked(&mut *bytes);
        ip.set_more_frags(true);
        ip.set_frag_offset(offset);
        ip.fill_checksum();
        assert!(packet_info(&bytes).is_none());
    }
    let mut bytes = packet();
    bytes[31] ^= 1;
    assert!(packet_info(&bytes).is_none());
    let mut bytes = packet();
    bytes[10] ^= 1;
    assert!(packet_info(&bytes).is_none());
    let mut bytes = crate::tun::udp_handler::build_udp_packet(
        b"data",
        "[fd77::1]:1".parse().unwrap(),
        "[fd77::2]:2".parse().unwrap(),
    )
    .unwrap();
    assert!(packet_info(&bytes).is_some());
    bytes[6] = 44;
    assert!(packet_info(&bytes).is_none());
}
