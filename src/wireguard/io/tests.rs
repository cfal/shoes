use super::*;
use std::time::Duration;

fn direct(factory: Factory) -> (Udp, UdpSender, UdpReceiver) {
    let (sender, receiver) = factory.0.unwrap();
    let UdpSender::Direct(udp) = &sender else {
        panic!("expected a direct socket");
    };
    (udp.clone(), sender, receiver)
}

fn bound(listen: &str) -> Option<(Udp, UdpSender, UdpReceiver, SocketAddr)> {
    match Factory::new(Some(listen.parse().unwrap()), None, 1 << 20) {
        Ok((factory, _, local)) => {
            let (udp, sender, receiver) = direct(factory);
            Some((udp, sender, receiver, local))
        }
        Err(error) if listen.starts_with('[') => {
            eprintln!("skipping IPv6 socket: {error}");
            None
        }
        Err(error) => panic!("UDP bind failed: {error}"),
    }
}

fn packet(bytes: &[u8]) -> Packet {
    Packet::copy_from(bytes)
}

async fn receive_at_least(
    receiver: &mut UdpReceiver,
    buffer: &mut <UdpReceiver as UdpRecv>::RecvManyBuf,
    pool: &mut PacketBufPool,
    count: usize,
) -> Vec<(Vec<u8>, SocketAddr)> {
    let mut packets = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), async {
        while packets.len() < count {
            receiver
                .recv_many_from(buffer, pool, &mut packets)
                .await
                .unwrap();
        }
    })
    .await
    .unwrap();
    packets
        .into_iter()
        .map(|(packet, source)| (packet.to_vec(), source))
        .collect()
}

#[tokio::test]
async fn decrypted_packets_wait_for_capacity_and_fail_only_when_closed() {
    let (sender, mut receiver) = mpsc::channel(1);
    let (wake, _wake_rx) = Wake::new().unwrap();
    let drops = Arc::new(PacketDrops::default());
    let mut sink = IpSink {
        sender,
        wake,
        mtu: 1408,
        drops: Arc::clone(&drops),
    };
    let bytes = crate::tun::udp_handler::build_udp_packet(
        b"packet",
        "10.77.0.1:1".parse().unwrap(),
        "10.77.0.2:2".parse().unwrap(),
    )
    .unwrap();
    let pool: PacketBufPool = PacketBufPool::new(4);
    sink.sender
        .send(PacketBuffer::copy_from_slice(b"full"))
        .await
        .unwrap();
    let packet = pool.get().overwrite_with(&*bytes).try_into_ip().unwrap();
    {
        let send = sink.send(packet);
        tokio::pin!(send);
        assert!(futures::poll!(&mut send).is_pending());
        assert_eq!(&*receiver.recv().await.unwrap(), b"full");
        send.await.unwrap();
    }
    assert_eq!(&*receiver.recv().await.unwrap(), &*bytes);
    assert_eq!(drops.total(), 0);
    drop(receiver);
    let packet = pool.get().overwrite_with(&*bytes).try_into_ip().unwrap();
    assert_eq!(
        sink.send(packet).await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[tokio::test]
async fn ip_source_drains_batches_and_notifies_backpressured_stack() {
    let (sender, receiver) = mpsc::channel(crate::ip_stack::driver::OUTPUT_QUEUE_CAPACITY);
    let (wake, mut wake_rx) = Wake::new().unwrap();
    let backpressured = Arc::new(AtomicBool::new(true));
    let mut source = IpSource::new(receiver, wake, backpressured.clone(), 1408);
    let mut sent = Vec::new();
    for port in 0..32 {
        let bytes = crate::tun::udp_handler::build_udp_packet(
            &[port as u8],
            "10.77.0.1:1".parse().unwrap(),
            SocketAddr::new("10.77.0.2".parse().unwrap(), 1000 + port),
        )
        .unwrap();
        sent.push(bytes.to_vec());
        sender.try_send(bytes).unwrap();
    }
    assert!(!wake_rx.wait(-1, Some(Duration::ZERO)).unwrap());
    let mut pool = PacketBufPool::new(64);
    let received: Vec<_> = source
        .recv(&mut pool)
        .await
        .unwrap()
        .map(|packet| packet.into_bytes().to_vec())
        .collect();
    assert_eq!(received, sent);
    assert!(!backpressured.load(Ordering::Acquire));
    assert!(wake_rx.wait(-1, Some(Duration::ZERO)).unwrap());
    wake_rx.drain().unwrap();

    // An idle stack is not woken by ordinary drains.
    sender
        .try_send(PacketBuffer::copy_from_slice(&sent[0]))
        .unwrap();
    assert_eq!(source.recv(&mut pool).await.unwrap().count(), 1);
    assert!(!wake_rx.wait(-1, Some(Duration::ZERO)).unwrap());
    drop(sender);
    assert_eq!(
        source.recv(&mut pool).await.err().unwrap().kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[tokio::test]
async fn factory_sockets_request_the_configured_buffer_size() {
    for size in [65536, 4 << 20] {
        let reference = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();
        let _ = reference.set_recv_buffer_size(size);
        let _ = reference.set_send_buffer_size(size);
        for listen in [Some("127.0.0.1:0".parse().unwrap()), None] {
            let (factory, _, _) = Factory::new(listen, None, size).unwrap();
            let (udp, _, _) = direct(factory);
            let socket = socket2::SockRef::from(udp.0.socket());
            assert_eq!(
                socket.recv_buffer_size().unwrap(),
                reference.recv_buffer_size().unwrap()
            );
            assert_eq!(
                socket.send_buffer_size().unwrap(),
                reference.send_buffer_size().unwrap()
            );
        }
    }
}

#[tokio::test]
async fn batched_round_trip_preserves_order_family_and_canonical_sources() {
    for (listen, peer_listen, destination) in [
        ("127.0.0.1:0", "127.0.0.1:0", "127.0.0.1"),
        ("[::1]:0", "[::1]:0", "::1"),
        // Dual-stack senders map IPv4 targets; dual-stack receivers canonicalize mapped sources.
        ("[::]:0", "127.0.0.1:0", "127.0.0.1"),
        ("127.0.0.1:0", "[::]:0", "127.0.0.1"),
    ] {
        let Some((_, sender, _, local)) = bound(listen) else {
            continue;
        };
        let Some((_, _, mut receiver, peer)) = bound(peer_listen) else {
            continue;
        };
        let target = SocketAddr::new(destination.parse().unwrap(), peer.port());
        assert_eq!(
            sender.max_number_of_packets_to_send(),
            if cfg!(any(target_os = "linux", target_os = "android")) {
                64
            } else {
                1
            }
        );
        let payloads: Vec<Vec<u8>> = (0..100u8)
            .map(|index| vec![index; 1 + index as usize])
            .collect();
        let mut packets: Vec<_> = payloads
            .iter()
            .map(|payload| (packet(payload), target))
            .collect();
        let mut send_buffer = Default::default();
        sender
            .send_many_to(&mut send_buffer, &mut packets)
            .await
            .unwrap();
        assert!(packets.is_empty());
        let mut buffer = Default::default();
        let mut pool = PacketBufPool::new(128);
        let received = receive_at_least(&mut receiver, &mut buffer, &mut pool, 100).await;
        let expected_source = SocketAddr::new(
            match local.ip() {
                std::net::IpAddr::V6(ip) if ip.is_unspecified() => destination.parse().unwrap(),
                ip => ip,
            },
            local.port(),
        );
        assert_eq!(received.len(), 100);
        for ((bytes, source), payload) in received.iter().zip(&payloads) {
            assert_eq!(bytes, payload);
            assert_eq!(*source, expected_source);
            assert!(source.is_ipv4() == destination.contains('.'));
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn empty_and_truncated_datagrams_do_not_stall_or_fail_batched_receive() {
    let (_, _, mut receiver, local) = bound("127.0.0.1:0").unwrap();
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.send_to(&[], local).unwrap();
    peer.send_to(&[0; 5000], local).unwrap();
    peer.send_to(b"after empty", local).unwrap();
    let mut buffer = Default::default();
    let mut pool = PacketBufPool::new(8);
    let received = receive_at_least(&mut receiver, &mut buffer, &mut pool, 1).await;
    let received: Vec<_> = received.into_iter().map(|(bytes, _)| bytes).collect();
    assert_eq!(received, [b"after empty".to_vec()]);

    peer.send_to(&[], local).unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            receiver.recv_many_from(&mut buffer, &mut pool, &mut Vec::new())
        )
        .await
        .is_err(),
        "an empty-only batch must keep waiting"
    );
    peer.send_to(b"later", local).unwrap();
    let received = receive_at_least(&mut receiver, &mut buffer, &mut pool, 1).await;
    assert_eq!(received[0].0, b"later");
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn partial_batches_keep_the_unsent_tail_on_error() {
    let (_, sender, _, _) = bound("127.0.0.1:0").unwrap();
    let (_, _, mut receiver, peer) = bound("127.0.0.1:0").unwrap();
    // IPv4 sockets reject IPv6 destinations, failing after the deliverable prefix.
    let unreachable: SocketAddr = "[::1]:9".parse().unwrap();
    let mut packets = vec![
        (packet(b"first"), peer),
        (packet(b"second"), peer),
        (packet(b"rejected"), unreachable),
        (packet(b"tail"), peer),
    ];
    let mut send_buffer = Default::default();
    assert!(
        sender
            .send_many_to(&mut send_buffer, &mut packets)
            .await
            .is_err()
    );
    let remaining: Vec<_> = packets.iter().map(|(packet, _)| packet.to_vec()).collect();
    assert_eq!(remaining, [b"rejected".to_vec(), b"tail".to_vec()]);
    let mut buffer = Default::default();
    let mut pool = PacketBufPool::new(8);
    let received = receive_at_least(&mut receiver, &mut buffer, &mut pool, 2).await;
    assert_eq!(received[0].0, b"first");
    assert_eq!(received[1].0, b"second");
}
