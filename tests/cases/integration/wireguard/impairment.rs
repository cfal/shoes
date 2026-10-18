use super::support::{exchange, start, target, udp_echo};
use crate::wireguard_support as config;
use serde_json::json;
use shoes_test_support::{
    port_helper::PortHelper,
    socks5::Socks5UdpAssociation,
    wireguard::{EchoTargets, connect},
};
use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
    time::timeout,
};

async fn impair(
    socket: &UdpSocket,
    target: SocketAddr,
    packet: &[u8],
    held: &mut Option<Vec<u8>>,
    sequence: &mut usize,
    counts: &[AtomicUsize; 2],
) -> io::Result<()> {
    if packet.starts_with(&[4, 0, 0, 0]) {
        *sequence += 1;
        if sequence.is_multiple_of(97) {
            counts[0].fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        if held.is_none() && sequence.is_multiple_of(7) {
            *held = Some(packet.to_vec());
            return Ok(());
        }
    }
    socket.send_to(packet, target).await?;
    if let Some(packet) = held.take() {
        socket.send_to(&packet, target).await?;
        counts[1].fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

#[tokio::test]
async fn loss_reordering_and_outer_roaming_preserve_existing_tcp_and_udp_flows() -> io::Result<()> {
    timeout(Duration::from_secs(90), async {
        let reservation = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let port = reservation.local_addr()?.port();
        let server = SocketAddr::from(([127, 0, 0, 1], port));
        let front = UdpSocket::bind("0.0.0.0:0").await?;
        let relay = front.local_addr()?;
        let mut back = UdpSocket::bind("0.0.0.0:0").await?;
        let mut old_port = back.local_addr()?.port();
        let counts = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
        let relay_counts = counts.clone();
        let (roam, mut commands) = mpsc::channel::<oneshot::Sender<u16>>(1);
        let relay_task = tokio::spawn(async move {
            let mut client = None;
            let (mut up, mut down) = ([0; 2048], [0; 2048]);
            let (mut pending_up, mut pending_down) = (None, None);
            let (mut up_sequence, mut down_sequence) = (0, 0);
            let mut flush = tokio::time::interval(Duration::from_millis(20));
            loop {
                tokio::select! {
                    request = front.recv_from(&mut up) => {
                        let (length, source) = request.unwrap();
                        client = Some(source);
                        impair(&back, server, &up[..length], &mut pending_up, &mut up_sequence, &relay_counts).await.unwrap();
                    }
                    response = back.recv_from(&mut down), if client.is_some() => {
                        let (length, source) = response.unwrap();
                        assert_eq!(source, server);
                        impair(&front, client.unwrap(), &down[..length], &mut pending_down, &mut down_sequence, &relay_counts).await.unwrap();
                    }
                    Some(reply) = commands.recv() => {
                        // Binding before release forces roaming to use a different port.
                        back = UdpSocket::bind("0.0.0.0:0").await.unwrap();
                        reply.send(back.local_addr().unwrap().port()).unwrap();
                    }
                    _ = flush.tick() => {
                        if let Some(packet) = pending_up.take() { back.send_to(&packet, server).await.unwrap(); }
                        if let Some(packet) = pending_down.take() { front.send_to(&packet, client.unwrap()).await.unwrap(); }
                    }
                }
            }
        });
        let _relay = tokio_util::task::AbortOnDropHandle::new(relay_task);
        let mut ports = PortHelper::new();
        let (_, entry) = ports.get_localhost_listener_port();
        drop(reservation);
        let _server = start(&json!([config::server(port)]))?;
        let _client = start(&json!([config::client(relay.port()), config::socks(entry)]))?;
        ports.wait_for_all_ports().await?;
        for ipv6 in [false, true] {
            let echo = EchoTargets::new(ipv6).await?;
            let mut tcp = connect(entry, target(ipv6, echo.tcp().port())).await?;
            let udp = Socks5UdpAssociation::connect("127.0.0.1", entry).await?;
            let data: Vec<_> = (0..256_007).map(|i| (i ^ (i >> 8)) as u8).collect();
            for roaming in [false, true] {
                if roaming {
                    let (reply, port) = oneshot::channel();
                    roam.send(reply).await.unwrap();
                    let port = port.await.unwrap();
                    assert_ne!(port, old_port);
                    old_port = port;
                }
                let (read, write) = tcp.split();
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut read = read;
                let mut write = write;
                let send = write.write_all(&data);
                let receive = async {
                    let mut bytes = vec![0; data.len()];
                    read.read_exact(&mut bytes).await?;
                    assert_eq!(bytes, data);
                    io::Result::Ok(())
                };
                let datagrams = async {
                    for _ in 0..16 { udp_echo(&udp, target(ipv6, echo.udp().port()), b"lossy path").await?; }
                    io::Result::Ok(())
                };
                tokio::try_join!(send, receive, datagrams)?;
                exchange(&mut tcp, b"same TCP connection").await?;
            }
        }
        assert!(counts[0].load(Ordering::Relaxed) > 0, "no packet loss injected");
        assert!(counts[1].load(Ordering::Relaxed) > 0, "no packets reordered");
        Ok(())
    }).await?
}
