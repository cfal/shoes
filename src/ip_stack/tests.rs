use super::{driver::PacketStack, udp::UdpConnection};
use crate::{async_stream::*, config::tun::TunResourceLimits};
use std::{io, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinSet,
};

fn stack(inbound: bool, ip: &str) -> PacketStack {
    PacketStack::new(
        vec![ip.parse().unwrap()],
        1408,
        inbound,
        TunResourceLimits {
            max_tcp_connections: Some(8),
            max_udp_sessions: Some(8),
            max_udp_queued_bytes: Some(65535),
            ..Default::default()
        },
    )
    .unwrap()
}
fn bridge(left: &mut PacketStack, right: &mut PacketStack) -> JoinSet<()> {
    let mut tasks = JoinSet::new();
    for (mut input, output, wake) in [
        (
            left.output.take().unwrap(),
            right.input.clone(),
            right.handle.wake.clone(),
        ),
        (
            right.output.take().unwrap(),
            left.input.clone(),
            left.handle.wake.clone(),
        ),
    ] {
        tasks.spawn(async move {
            while let Some(packet) = input.recv().await {
                if output.send(packet).await.is_err() {
                    break;
                }
                wake.notify();
            }
        });
    }
    tasks
}
async fn write_udp(stream: &mut UdpConnection, bytes: &[u8]) -> io::Result<()> {
    futures::future::poll_fn(|cx| std::pin::Pin::new(&mut *stream).poll_write_message(cx, bytes))
        .await
}
async fn read_udp(stream: &mut UdpConnection) -> io::Result<Vec<u8>> {
    let mut bytes = [0; 2048];
    let mut buf = tokio::io::ReadBuf::new(&mut bytes);
    futures::future::poll_fn(|cx| std::pin::Pin::new(&mut *stream).poll_read_message(cx, &mut buf))
        .await?;
    Ok(buf.filled().to_vec())
}

#[tokio::test]
async fn tcp_half_close_preserves_reply_and_large_transfer() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut client = stack(false, "10.77.0.2");
        let mut server = stack(true, "10.77.0.1");
        let mut tasks = bridge(&mut client, &mut server);
        let mut incoming = server.tcp.take().unwrap();
        tasks.spawn(async move {
            let mut stream = incoming.recv().await.unwrap().connection;
            let mut data = Vec::new();
            stream.read_to_end(&mut data).await.unwrap();
            assert_eq!(data, vec![0x5a; 200_000]);
            stream.write_all(b"after FIN").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let mut stream = client
            .handle
            .connect("198.18.0.1:443".parse().unwrap())
            .await
            .unwrap();
        stream.write_all(&vec![0x5a; 200_000]).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"after FIN");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn udp_empty_datagrams_boundaries_mtu_and_shutdown() {
    for (local, remote) in [("10.77.0.2", "10.77.0.1"), ("fd77::2", "fd77::1")] {
        tokio::time::timeout(Duration::from_secs(3), async {
            let mut client = stack(false, local);
            let mut server = stack(false, remote);
            let _bridge = bridge(&mut client, &mut server);
            let target = SocketAddr::new(remote.parse().unwrap(), 49152);
            let mut outbound = client.handle.open_udp(target).await.unwrap();
            let mut reverse = server
                .handle
                .open_udp(SocketAddr::new(local.parse().unwrap(), 49152))
                .await
                .unwrap();
            for data in [&b"one"[..], &b""[..], &b"three"[..]] {
                write_udp(&mut outbound, data).await.unwrap();
                assert_eq!(read_udp(&mut reverse).await.unwrap(), data);
                write_udp(&mut reverse, data).await.unwrap();
                assert_eq!(read_udp(&mut outbound).await.unwrap(), data);
            }
            write_udp(&mut outbound, &[0; 1408]).await.unwrap();
            assert_eq!(client.drops.load(std::sync::atomic::Ordering::Relaxed), 1);
            write_udp(&mut outbound, b"after oversize").await.unwrap();
            assert_eq!(read_udp(&mut reverse).await.unwrap(), b"after oversize");
            let permit = outbound.control.lock().budget.acquire(65535).unwrap();
            write_udp(&mut outbound, b"over budget").await.unwrap();
            assert_eq!(client.drops.load(std::sync::atomic::Ordering::Relaxed), 2);
            drop(permit);
            write_udp(&mut outbound, b"after budget").await.unwrap();
            assert_eq!(read_udp(&mut reverse).await.unwrap(), b"after budget");
            drop(client);
            assert!(read_udp(&mut outbound).await.is_err());
            assert!(write_udp(&mut outbound, b"closed").await.is_err());
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn canceled_connects_release_admission_and_stopped_handles_fail() {
    let mut client = stack(false, "10.77.0.2");
    for _ in 0..16 {
        assert!(
            tokio::time::timeout(
                Duration::from_millis(10),
                client.handle.connect("10.77.0.1:80".parse().unwrap())
            )
            .await
            .is_err()
        );
    }
    let mut server = stack(true, "10.77.0.1");
    while client.output.as_mut().unwrap().try_recv().is_ok() {}
    let _bridge = bridge(&mut client, &mut server);
    let stream = tokio::time::timeout(
        Duration::from_secs(2),
        client.handle.connect("10.77.0.1:80".parse().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    let handle = client.handle.clone();
    drop(stream);
    drop(client);
    assert_eq!(
        handle
            .open_udp("10.77.0.1:80".parse().unwrap())
            .await
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::NotConnected
    );
}

#[test]
fn adapters_have_the_required_traits() {
    fn tcp<T: AsyncStream>() {}
    fn udp<T: AsyncMessageStream>() {}
    tcp::<super::tcp_conn::TcpConnection>();
    udp::<UdpConnection>();
}

#[test]
fn shutdown_during_wake_acknowledgment_never_parks_the_worker() {
    let (sent, received) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for _ in 0..256 {
            let stack = stack(false, "10.77.0.2");
            stack.handle.wake.notify();
            drop(stack);
        }
        sent.send(()).unwrap();
    });
    received.recv_timeout(Duration::from_secs(5)).unwrap();
}

#[tokio::test]
async fn udp_receive_saturation_is_bounded_and_counted() {
    use std::sync::atomic::Ordering;

    tokio::time::timeout(Duration::from_secs(3), async {
        let stack = stack(false, "10.77.0.2");
        let remote = "10.77.0.1:53".parse().unwrap();
        let mut stream = stack.handle.open_udp(remote).await.unwrap();
        let local = stream.control.lock().local;
        for byte in 0..32 {
            stack
                .input
                .send(crate::tun::udp_handler::build_udp_packet(&[byte], remote, local).unwrap())
                .await
                .unwrap();
            stack.handle.wake.notify();
        }
        while stack.drops.load(Ordering::Relaxed) != 24
            || stack.counts.outbound_udp.load(Ordering::Relaxed) != 1
        {
            tokio::task::yield_now().await;
        }
        assert_eq!(stack.counts.outbound_udp.load(Ordering::Relaxed), 1);
        for byte in 0..8 {
            assert_eq!(read_udp(&mut stream).await.unwrap(), [byte]);
        }
        drop(stream);
        while stack.counts.outbound_udp.load(Ordering::Relaxed) != 0 {
            tokio::task::yield_now().await;
        }
        let counts = stack.counts.clone();
        drop(stack);
        assert_eq!(counts.tcp.load(Ordering::Relaxed), 0);
        assert_eq!(counts.outbound_udp.load(Ordering::Relaxed), 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn udp_admission_and_remote_tuple_isolation() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut stack = stack(false, "10.77.0.2");
        let remote: SocketAddr = "10.77.0.1:53".parse().unwrap();
        let mut streams = Vec::new();
        for _ in 0..8 {
            streams.push(stack.handle.open_udp(remote).await.unwrap());
        }
        assert!(stack.handle.open_udp(remote).await.is_err());
        let local = streams[0].control.lock().local;
        for source in ["10.77.0.3:53", "10.77.0.1:54"] {
            stack
                .input
                .send(
                    crate::tun::udp_handler::build_udp_packet(
                        b"spoofed",
                        source.parse().unwrap(),
                        local,
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            stack.handle.wake.notify();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), read_udp(&mut streams[0]))
                .await
                .is_err()
        );
        stack
            .input
            .send(crate::tun::udp_handler::build_udp_packet(b"valid", remote, local).unwrap())
            .await
            .unwrap();
        stack.handle.wake.notify();
        assert_eq!(read_udp(&mut streams[0]).await.unwrap(), b"valid");
        assert!(stack.udp.as_mut().unwrap().try_recv().is_err());
        drop(streams);
        let connection = stack.handle.open_udp(remote).await.unwrap();
        drop(connection);
        drop(stack);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn udp_drop_releases_each_admission_limit_without_retrying() {
    tokio::time::timeout(Duration::from_secs(3), async {
        for (sessions, destinations) in [(Some(1), None), (None, Some(1)), (Some(1), Some(1))] {
            let stack = PacketStack::new(
                vec!["10.77.0.2".parse().unwrap()],
                1408,
                false,
                TunResourceLimits {
                    max_udp_sessions: sessions,
                    max_udp_destinations: destinations,
                    ..Default::default()
                },
            )
            .unwrap();
            let remote = "10.77.0.1:53".parse().unwrap();
            let connection = stack.handle.open_udp(remote).await.unwrap();
            assert!(stack.handle.open_udp(remote).await.is_err());
            drop(connection);
            for _ in 0..128 {
                drop(stack.handle.open_udp(remote).await.unwrap());
            }
        }
    })
    .await
    .unwrap();
}
