use super::*;
use smoltcp::wire::TcpControl;

fn queue_device(output: mpsc::Sender<PacketBuffer>) -> QueueDevice {
    QueueDevice {
        packet: None,
        output,
        mtu: 1408,
        drops: Arc::default(),
        egress_backpressured: Arc::default(),
    }
}

#[test]
fn local_allocation_preserves_family_order_wraps_and_skips_both_flow_types() {
    let ipv4 = "10.77.0.1".parse().unwrap();
    let ipv6 = "fd77::1".parse().unwrap();
    let addresses = [ipv6, ipv4, "10.77.0.3".parse().unwrap()];
    let target = "10.77.0.2:443".parse().unwrap();
    let mut sockets = SocketSet::new(vec![]);
    let mut tcp = TcpFlows::default();
    tcp.insert(
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
    );
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

fn port_offset(port: u16) -> usize {
    assert!((FIRST_EPHEMERAL_PORT..=LAST_EPHEMERAL_PORT).contains(&port));
    usize::from(port - FIRST_EPHEMERAL_PORT)
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
        let probe = stack.handle.open_udp(target).await.unwrap();
        let first = probe.control.lock().local.port();
        let (tcp, canceled) = oneshot::channel();
        drop(canceled);
        stack.handle.send(Command::Tcp(target, tcp)).await.unwrap();
        let (udp, canceled) = oneshot::channel();
        drop(canceled);
        stack.handle.send(Command::Udp(target, udp)).await.unwrap();
        let connection = stack.handle.open_udp(target).await.unwrap();
        let range = usize::from(LAST_EPHEMERAL_PORT - FIRST_EPHEMERAL_PORT) + 1;
        let last = connection.control.lock().local.port();
        assert_eq!((port_offset(last) + range - port_offset(first)) % range, 3);
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
        assert_eq!(stack.drops.invalid_packet.load(Ordering::Relaxed), 12);
        assert_eq!(stack.drops.total(), 12);
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
        for port in 40000..40000 + ACCEPT_QUEUE_CAPACITY as u16 {
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
        let (output, mut packets) = mpsc::channel(OUTPUT_QUEUE_CAPACITY);
        let mut device = queue_device(output);
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
        let mut entries = TcpFlows::default();
        entries.insert(
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
        );
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
        entries.entries.get_mut(&handle).unwrap().pump(
            handle,
            sockets.get_mut::<TcpSocket>(handle),
            start,
        );
        sockets.get_mut::<TcpSocket>(handle).close();
        control.set_send_state(TcpSocketState::Closing);
        drop(connection);
        let deadline = control.orphan_deadline().unwrap();
        let abandoned = deadline - TCP_ORPHAN_TIMEOUT;
        entries.entries.get_mut(&handle).unwrap().pump(
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
        assert!(!reconcile_tcp(
            &mut entries,
            &mut sockets,
            &counts,
            false,
            abandoned
        ));
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
            entries.entries.get_mut(&handle).unwrap().pump(
                handle,
                sockets.get_mut::<TcpSocket>(handle),
                timestamp,
            );
            iface.poll_egress(timestamp, &mut device, &mut sockets);
            assert!(!reconcile_tcp(
                &mut entries,
                &mut sockets,
                &counts,
                false,
                timestamp
            ));
            assert_eq!(
                counts.tcp.load(Ordering::Relaxed),
                usize::from(seconds < 60)
            );
        }
        assert_eq!(entries.len(), 0);
        assert!(!entries.uses_local(target));
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
        let (output, mut packets) = mpsc::channel(OUTPUT_QUEUE_CAPACITY);
        let mut device = queue_device(output);
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
        let limit = COMMAND_QUEUE_CAPACITY * 4;
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

fn tcp_segment_with_timestamp(
    source: SocketAddr,
    target: SocketAddr,
    sequence: u32,
    ack: u32,
    timestamp: Option<(u32, u32)>,
) -> PacketBuffer {
    let mut tcp = etherparse::TcpHeader::new(source.port(), target.port(), sequence, 65535);
    tcp.syn = true;
    tcp.ack = true;
    tcp.acknowledgment_number = ack;
    if let Some((tsval, tsecr)) = timestamp {
        tcp.set_options(&[etherparse::TcpOptionElement::Timestamp(tsval, tsecr)])
            .unwrap();
    }
    let (IpAddr::V4(source), IpAddr::V4(target)) = (source.ip(), target.ip()) else {
        unreachable!();
    };
    let builder =
        etherparse::PacketBuilder::ipv4(source.octets(), target.octets(), 64).tcp_header(tcp);
    let mut packet = PacketBuffer::with_capacity(builder.size(0));
    packet.resize(builder.size(0));
    builder.write(&mut &mut packet[..], &[]).unwrap();
    packet
}

/// Parses an emitted segment as smoltcp sees it, including TCP options.
fn tcp_repr(packet: &[u8]) -> (PacketInfo, smoltcp::wire::TcpRepr<'_>) {
    let info = packet_info(packet).unwrap();
    assert_eq!(info.protocol, IpProtocol::Tcp);
    let tcp = TcpPacket::new_checked(&packet[info.transport_offset..info.length]).unwrap();
    let repr = smoltcp::wire::TcpRepr::parse(
        &tcp,
        &info.source.ip().into(),
        &info.target.ip().into(),
        &Default::default(),
    )
    .unwrap();
    (info, repr)
}

async fn write_datagram(connection: &mut UdpConnection, data: &[u8]) {
    use crate::async_stream::AsyncWriteMessage;
    futures::future::poll_fn(|cx| {
        std::pin::Pin::new(&mut *connection).poll_write_message(cx, data)
    })
    .await
    .unwrap();
}

async fn wait_until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

/// Queues UDP datagrams until `output` holds `len` undrained packets.
async fn fill_output(
    datagrams: &mut UdpConnection,
    output: &mpsc::Receiver<PacketBuffer>,
    len: usize,
) {
    for _ in output.len()..len {
        write_datagram(datagrams, b"fill").await;
    }
    wait_until(|| output.len() == len).await;
}

/// Drains up to one batch the way WireGuard's IpSource does.
async fn drain_batch(
    stack: &PacketStack,
    output: &mut mpsc::Receiver<PacketBuffer>,
) -> Vec<PacketBuffer> {
    let mut batch = Vec::new();
    output.recv_many(&mut batch, 64).await;
    if stack.egress_backpressured.swap(false, Ordering::AcqRel) {
        stack.handle.wake.notify();
    }
    batch
}

fn is_udp(packet: &[u8]) -> bool {
    packet_info(packet).unwrap().protocol == IpProtocol::Udp
}

#[tokio::test]
async fn egress_backpressure_pauses_tcp_without_dropping_and_resumes_on_drain() {
    use tokio::io::AsyncWriteExt;

    tokio::time::timeout(Duration::from_secs(10), async {
        let mut stack = PacketStack::new(
            vec!["10.77.0.1".parse().unwrap()],
            1408,
            false,
            TunResourceLimits::default(),
        )
        .unwrap();
        let mut output = stack.output.take().unwrap();
        let mut datagrams = stack
            .handle
            .open_udp("10.77.0.2:53".parse().unwrap())
            .await
            .unwrap();
        let paused = OUTPUT_QUEUE_CAPACITY - OUTPUT_UDP_HEADROOM;
        fill_output(&mut datagrams, &output, paused).await;

        let target: SocketAddr = "10.77.0.2:443".parse().unwrap();
        let handle = stack.handle.clone();
        let connect = tokio::spawn(async move { handle.connect(target).await });
        wait_until(|| stack.egress_backpressured.load(Ordering::Acquire)).await;
        // A paused stack parks until the drainer wakes it instead of polling its unsent SYN.
        let iterations = stack.counts.iterations.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(stack.counts.iterations.load(Ordering::Relaxed) - iterations <= 2);
        assert_eq!(output.len(), paused);
        assert_eq!(stack.drops.total(), 0);

        let mut queued = drain_batch(&stack, &mut output).await;
        let syn = loop {
            if queued.is_empty() {
                queued = drain_batch(&stack, &mut output).await;
            }
            let packet = queued.remove(0);
            if !is_udp(&packet) {
                break packet;
            }
        };
        assert!(queued.is_empty());
        let (syn_info, syn_repr) = tcp_repr(&syn);
        assert_eq!(syn_repr.control, TcpControl::Syn);
        let local = syn_info.source;
        stack
            .input
            .send(tcp_segment(
                target,
                local,
                5000,
                TcpControl::Syn,
                Some((syn_repr.seq_number + 1).0 as u32),
            ))
            .await
            .unwrap();
        stack.handle.wake.notify();
        let mut connection = connect.await.unwrap().unwrap();
        let ack = output.recv().await.unwrap();
        let (_, ack) = tcp_repr(&ack);
        assert!(ack.payload.is_empty() && ack.ack_number.is_some());

        // Pauses established data the same way, then emits it in order once drained.
        fill_output(&mut datagrams, &output, paused).await;
        let data: Vec<u8> = (0..20_000).map(|index| index as u8).collect();
        connection.write_all(&data).await.unwrap();
        wait_until(|| stack.egress_backpressured.load(Ordering::Acquire)).await;
        assert_eq!(output.len(), paused);

        let mut next = syn_repr.seq_number + 1;
        let mut received = Vec::new();
        while received.len() < data.len() {
            for packet in drain_batch(&stack, &mut output).await {
                if is_udp(&packet) {
                    continue;
                }
                let (_, repr) = tcp_repr(&packet);
                if repr.payload.is_empty() {
                    continue;
                }
                assert_eq!(repr.seq_number, next, "segment retransmitted or reordered");
                next += repr.payload.len();
                received.extend_from_slice(repr.payload);
                stack
                    .input
                    .send(tcp_segment(
                        target,
                        local,
                        5001,
                        TcpControl::None,
                        Some(next.0 as u32),
                    ))
                    .await
                    .unwrap();
                stack.handle.wake.notify();
            }
        }
        assert_eq!(received, data);
        assert_eq!(stack.drops.total(), 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tcp_egress_backpressure_preserves_udp_headroom() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut stack = PacketStack::new(
            vec!["10.77.0.1".parse().unwrap()],
            1408,
            false,
            TunResourceLimits::default(),
        )
        .unwrap();
        let output = stack.output.take().unwrap();
        let mut datagrams = stack
            .handle
            .open_udp("10.77.0.2:53".parse().unwrap())
            .await
            .unwrap();
        fill_output(
            &mut datagrams,
            &output,
            OUTPUT_QUEUE_CAPACITY - OUTPUT_UDP_HEADROOM,
        )
        .await;
        let handle = stack.handle.clone();
        let _connect =
            tokio::spawn(async move { handle.connect("10.77.0.2:443".parse().unwrap()).await });
        wait_until(|| stack.egress_backpressured.load(Ordering::Acquire)).await;

        fill_output(&mut datagrams, &output, OUTPUT_QUEUE_CAPACITY).await;
        assert_eq!(stack.drops.total(), 0);
        write_datagram(&mut datagrams, b"overflow").await;
        wait_until(|| stack.drops.output_full.load(Ordering::Relaxed) == 1).await;
        assert_eq!(stack.drops.total(), 1);
        let mut output = output;
        while let Ok(packet) = output.try_recv() {
            assert!(is_udp(&packet), "TCP consumed UDP headroom");
        }
    })
    .await
    .unwrap();
}

#[test]
fn backpressured_poll_delay_keeps_only_real_deadlines() {
    use smoltcp::time::Duration as SmolDuration;

    let deadline = Some(SmolDuration::from_millis(200));
    assert_eq!(
        egress_poll_delay(Some(SmolDuration::ZERO), false),
        Some(SmolDuration::ZERO)
    );
    assert_eq!(egress_poll_delay(Some(SmolDuration::ZERO), true), None);
    assert_eq!(egress_poll_delay(deadline, true), deadline);
    assert_eq!(egress_poll_delay(None, true), None);
}

#[test]
fn transmit_reserves_output_and_flags_backpressure_at_udp_headroom() {
    let (output, mut packets) = mpsc::channel(OUTPUT_QUEUE_CAPACITY);
    let filler = output.clone();
    let mut device = queue_device(output);
    for _ in 0..OUTPUT_QUEUE_CAPACITY - OUTPUT_UDP_HEADROOM - 1 {
        filler
            .try_send(PacketBuffer::copy_from_slice(b"udp"))
            .unwrap();
    }
    let token = device.transmit(Instant::from_millis(0)).unwrap();
    assert!(matches!(token, Tx::Reserved { .. }));
    token.consume(20, |bytes| bytes.fill(0));
    assert!(!device.is_egress_backpressured());
    assert!(device.transmit(Instant::from_millis(0)).is_none());
    assert!(device.is_egress_backpressured());

    // Ingress replies stay best-effort and may use the UDP headroom.
    device.packet = Some(PacketBuffer::copy_from_slice(b"ingress"));
    let (_, reply) = device.receive(Instant::from_millis(0)).unwrap();
    assert!(matches!(reply, Tx::BestEffort(_)));
    reply.consume(20, |bytes| bytes.fill(0));
    assert_eq!(
        packets.len(),
        OUTPUT_QUEUE_CAPACITY - OUTPUT_UDP_HEADROOM + 1
    );

    // The drainer clears the flag after freeing capacity, as IpSource does.
    packets.try_recv().unwrap();
    packets.try_recv().unwrap();
    assert!(device.egress_backpressured.swap(false, Ordering::AcqRel));
    assert!(matches!(
        device.transmit(Instant::from_millis(0)),
        Some(Tx::Reserved { .. })
    ));
    assert!(!device.is_egress_backpressured());
    assert_eq!(device.drops.total(), 0);
}

#[tokio::test]
async fn outbound_syn_includes_tcp_timestamp_and_echoes_peer_tsval() {
    use tokio::io::AsyncWriteExt;

    tokio::time::timeout(Duration::from_secs(5), async {
        for peer_timestamps in [true, false] {
            let mut stack = PacketStack::new(
                vec!["10.77.0.1".parse().unwrap()],
                1408,
                false,
                TunResourceLimits::default(),
            )
            .unwrap();
            let mut output = stack.output.take().unwrap();
            let target: SocketAddr = "10.77.0.2:443".parse().unwrap();
            let handle = stack.handle.clone();
            let connect = tokio::spawn(async move { handle.connect(target).await });
            let syn = output.recv().await.unwrap();
            let (info, repr) = tcp_repr(&syn);
            let timestamp = repr.timestamp.unwrap();
            assert_ne!(timestamp.tsval, 0);
            assert_eq!(timestamp.tsecr, 0);
            assert!(
                super::super::tcp_timestamp_ms().wrapping_sub(timestamp.tsval) < 5_000,
                "timestamps follow the shared millisecond clock"
            );
            stack
                .input
                .send(tcp_segment_with_timestamp(
                    target,
                    info.source,
                    5000,
                    (repr.seq_number + 1).0 as u32,
                    peer_timestamps.then_some((777, timestamp.tsval)),
                ))
                .await
                .unwrap();
            stack.handle.wake.notify();
            let mut connection = connect.await.unwrap().unwrap();
            let ack = tcp_repr(&output.recv().await.unwrap()).1.timestamp;
            connection.write_all(b"after handshake").await.unwrap();
            let data = loop {
                let packet = output.recv().await.unwrap();
                if !tcp_repr(&packet).1.payload.is_empty() {
                    break packet;
                }
            };
            let (_, data) = tcp_repr(&data);
            assert_eq!(data.payload, b"after handshake");
            if peer_timestamps {
                assert_eq!(ack.unwrap().tsecr, 777);
                assert_eq!(data.timestamp.unwrap().tsecr, 777);
            } else {
                assert!(ack.is_none());
                assert!(data.timestamp.is_none());
            }
        }
    })
    .await
    .unwrap();
}

type Segments = Vec<(smoltcp::wire::TcpSeqNumber, Vec<u8>)>;

/// Polls the interface and returns emitted SYN and data segments.
fn poll_segments(
    iface: &mut Interface,
    device: &mut QueueDevice,
    sockets: &mut SocketSet<'_>,
    packets: &mut mpsc::Receiver<PacketBuffer>,
    at: Instant,
) -> Segments {
    iface.poll(at, device, sockets);
    let mut segments = Vec::new();
    while let Ok(packet) = packets.try_recv() {
        let (_, repr) = tcp_repr(&packet);
        if repr.control == TcpControl::Syn || !repr.payload.is_empty() {
            segments.push((repr.seq_number, repr.payload.to_vec()));
        }
    }
    segments
}

#[test]
fn tcp_retransmit_uses_200ms_min_rto_after_rtt_sample() {
    use smoltcp::time::Duration as SmolDuration;

    let (output, mut packets) = mpsc::channel(OUTPUT_QUEUE_CAPACITY);
    let mut device = queue_device(output);
    let start = Instant::from_secs(1);
    let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut device, start);
    let local: SocketAddr = "10.77.0.1:49152".parse().unwrap();
    let remote: SocketAddr = "10.77.0.2:443".parse().unwrap();
    iface.update_ip_addrs(|ips| ips.push(IpCidr::new(local.ip().into(), 24)).unwrap());
    let mut socket = tcp_socket(4096);
    assert_eq!(socket.min_rto(), SmolDuration::from_millis(200));
    assert_eq!(socket.initial_rto(), SmolDuration::from_secs(1));
    socket.connect(iface.context(), remote, local).unwrap();
    let mut sockets = SocketSet::new(vec![]);
    let handle = sockets.add(socket);
    let mut data_segments =
        |iface: &mut Interface,
         device: &mut QueueDevice,
         sockets: &mut SocketSet<'_>,
         at: Instant| { poll_segments(iface, device, sockets, &mut packets, at) };
    let syn = data_segments(&mut iface, &mut device, &mut sockets, start);
    assert_eq!(syn.len(), 1);
    let isn = syn[0].0;
    let at = start + SmolDuration::from_millis(1);
    device.packet = Some(tcp_segment(
        remote,
        local,
        5000,
        TcpControl::Syn,
        Some((isn + 1).0 as u32),
    ));
    data_segments(&mut iface, &mut device, &mut sockets, at);
    sockets
        .get_mut::<TcpSocket>(handle)
        .send_slice(b"first")
        .unwrap();
    let first = data_segments(&mut iface, &mut device, &mut sockets, at);
    assert_eq!(first, [(isn + 1, b"first".to_vec())]);
    let at = at + SmolDuration::from_millis(1);
    device.packet = Some(tcp_segment(
        remote,
        local,
        5001,
        TcpControl::None,
        Some((isn + 6).0 as u32),
    ));
    data_segments(&mut iface, &mut device, &mut sockets, at);
    sockets
        .get_mut::<TcpSocket>(handle)
        .send_slice(b"lost")
        .unwrap();
    let lost = data_segments(&mut iface, &mut device, &mut sockets, at);
    assert_eq!(lost, [(isn + 6, b"lost".to_vec())]);
    let early = at + SmolDuration::from_millis(199);
    assert!(data_segments(&mut iface, &mut device, &mut sockets, early).is_empty());
    let expired = at + SmolDuration::from_millis(201);
    assert_eq!(
        data_segments(&mut iface, &mut device, &mut sockets, expired),
        lost
    );
}

#[tokio::test]
async fn ephemeral_port_cursor_randomizes_across_stack_instances() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut ports = Vec::new();
        for _ in 0..8 {
            let stack = PacketStack::new(
                vec!["10.77.0.1".parse().unwrap()],
                1408,
                false,
                TunResourceLimits::default(),
            )
            .unwrap();
            let connection = stack
                .handle
                .open_udp("10.77.0.2:53".parse().unwrap())
                .await
                .unwrap();
            let port = connection.control.lock().local.port();
            port_offset(port);
            ports.push(port);
        }
        ports.sort_unstable();
        ports.dedup();
        // Eight sequential starts would all pick 49152; random starts collide with negligible odds.
        assert!(ports.len() > 1, "ports did not vary: {ports:?}");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn drop_counters_distinguish_mtu_invalid_and_udp_drops() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut stack = PacketStack::new(
            vec!["10.77.0.1".parse().unwrap()],
            1408,
            false,
            TunResourceLimits::default(),
        )
        .unwrap();
        let _output = stack.output.take().unwrap();
        let remote: SocketAddr = "10.77.0.2:53".parse().unwrap();
        let mut connection = stack.handle.open_udp(remote).await.unwrap();
        let local = connection.control.lock().local;

        let mut corrupted =
            crate::tun::udp_handler::build_udp_packet(b"bad", remote, local).unwrap();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        stack.input.send(corrupted).await.unwrap();
        let oversized =
            crate::tun::udp_handler::build_udp_packet(&[0; 1400], remote, local).unwrap();
        assert!(oversized.len() > 1408);
        stack.input.send(oversized).await.unwrap();
        for _ in 0..9 {
            stack
                .input
                .send(crate::tun::udp_handler::build_udp_packet(b"queued", remote, local).unwrap())
                .await
                .unwrap();
        }
        stack.handle.wake.notify();
        write_datagram(&mut connection, &[0; 1400]).await;
        wait_until(|| stack.drops.udp_queue_full.load(Ordering::Relaxed) == 1).await;

        let drops = &stack.drops;
        assert_eq!(drops.invalid_packet.load(Ordering::Relaxed), 1);
        assert_eq!(drops.mtu_exceeded.load(Ordering::Relaxed), 2);
        assert_eq!(drops.udp_queue_full.load(Ordering::Relaxed), 1);
        assert_eq!(drops.output_full.load(Ordering::Relaxed), 0);
        assert_eq!(drops.detour_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(drops.total(), 4);
        assert_eq!(
            drops.to_string(),
            "packet_drops=4 output_drops=0 mtu_drops=2 invalid_drops=1 udp_drops=1 detour_drops=0"
        );
    })
    .await
    .unwrap();
}

#[test]
fn expired_orphan_under_backpressure_is_reclaimed_without_spinning() {
    use crate::ip_stack::{TCP_ORPHAN_TIMEOUT, tcp_conn::TcpSocketState, tcp_poll_delay};
    use smoltcp::time::Duration as SmolDuration;

    let (output, mut packets) = mpsc::channel(OUTPUT_QUEUE_CAPACITY);
    let mut device = QueueDevice {
        packet: None,
        output: output.clone(),
        mtu: 1408,
        drops: Arc::new(PacketDrops::default()),
        egress_backpressured: Arc::new(AtomicBool::new(false)),
    };
    let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut device, now());
    iface.update_ip_addrs(|list| {
        list.push(IpCidr::new(
            IpAddr::V4("10.77.0.1".parse().unwrap()).into(),
            0,
        ))
        .unwrap();
    });
    iface
        .routes_mut()
        .add_default_ipv4_route("10.77.0.1".parse().unwrap())
        .unwrap();
    iface.set_any_ip(true);

    let source: SocketAddr = "10.77.0.2:40000".parse().unwrap();
    let target: SocketAddr = "10.77.0.1:443".parse().unwrap();
    let mut sockets = SocketSet::new(vec![]);
    let mut socket = tcp_socket(32 * 1024);
    socket.listen(target).unwrap();
    let handle = sockets.add(socket);
    let start = now();
    device.packet = Some(tcp_segment(source, target, 1000, TcpControl::Syn, None));
    iface.poll_ingress_single(start, &mut device, &mut sockets);
    iface.poll_egress(start, &mut device, &mut sockets);
    let syn_ack = packets.try_recv().unwrap();
    let ip = Ipv4Packet::new_checked(&*syn_ack).unwrap();
    let ack = (TcpPacket::new_checked(ip.payload()).unwrap().seq_number() + 1).0 as u32;
    device.packet = Some(tcp_segment(
        source,
        target,
        1001,
        TcpControl::None,
        Some(ack),
    ));
    iface.poll(start, &mut device, &mut sockets);

    let (wake, _wake_rx) = Wake::new().unwrap();
    let control = Arc::new(TcpConnectionControl::new(32 * 1024, 32 * 1024));
    let connection = TcpConnection::new(control.clone(), wake);
    let mut entries = TcpFlows::default();
    entries.insert(
        handle,
        TcpEntry {
            control: control.clone(),
            remote: source,
            local: target,
            outbound: false,
            established: true,
            pending_connect: None,
            pending_accept: None,
        },
    );
    let counts = FlowCounts::default();
    sockets.get_mut::<TcpSocket>(handle).close();
    control.set_send_state(TcpSocketState::Closing);
    drop(connection);
    let deadline = control.orphan_deadline().unwrap();
    let abandoned = deadline - TCP_ORPHAN_TIMEOUT;
    entries.entries.get_mut(&handle).unwrap().pump(
        handle,
        sockets.get_mut::<TcpSocket>(handle),
        abandoned,
    );
    iface.poll_egress(abandoned, &mut device, &mut sockets);
    let _fin = packets.try_recv().unwrap();

    // Fill output to the backpressure threshold so smoltcp cannot transmit the final RST.
    for _ in 0..(OUTPUT_QUEUE_CAPACITY - OUTPUT_UDP_HEADROOM) {
        output
            .try_send(PacketBuffer::copy_from_slice(b"x"))
            .unwrap();
    }
    let expired = abandoned + SmolDuration::from_secs(60);
    entries.entries.get_mut(&handle).unwrap().pump(
        handle,
        sockets.get_mut::<TcpSocket>(handle),
        expired,
    );
    assert_eq!(sockets.get::<TcpSocket>(handle).state(), State::Closed);
    iface.poll_egress(expired, &mut device, &mut sockets);
    assert!(device.is_egress_backpressured());
    // smoltcp still holds remote_endpoint because the final RST could not be queued.
    assert!(sockets.get::<TcpSocket>(handle).remote_endpoint().is_some());

    // Reclaiming the expired orphan under backpressure releases admission and removes the
    // expired deadline so tcp_poll_delay does not busy-poll with Duration::ZERO.
    assert!(!reconcile_tcp(
        &mut entries,
        &mut sockets,
        &counts,
        true,
        expired
    ));
    assert_eq!(entries.len(), 0);
    assert_eq!(counts.tcp.load(Ordering::Relaxed), 0);
    assert_eq!(
        tcp_poll_delay(
            expired,
            egress_poll_delay(iface.poll_delay(expired, &sockets), true),
            entries.entries.values().map(|entry| &*entry.control),
        ),
        None
    );
}
