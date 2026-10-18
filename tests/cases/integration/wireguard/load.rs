use super::support::{Pair, exchange, target, udp_echo};
use serde_json::json;
use shoes_test_support::{
    socks5::Socks5UdpAssociation,
    wireguard::{EchoTargets, connect},
};
use std::{io, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Barrier, watch},
    task::JoinSet,
    time::timeout,
};

#[tokio::test]
async fn tcp_and_udp_progress_together_through_direct_and_detoured_endpoints() -> io::Result<()> {
    timeout(Duration::from_secs(90), async {
        for detour in [false, true] {
            for ipv6 in [false, true] {
                let pair = Pair::start(detour, |_, _| {}).await?;
                let echo = EchoTargets::new(ipv6).await?;
                let barrier = Arc::new(Barrier::new(17));
                let (finished, stop) = watch::channel(false);
                let mut tcp = JoinSet::new();
                for id in 0..8u8 {
                    let mut stream = connect(pair.entry, target(ipv6, echo.tcp().port())).await?;
                    let barrier = barrier.clone();
                    let stop = stop.clone();
                    tcp.spawn(async move {
                        barrier.wait().await;
                        let mut count = 0;
                        while !*stop.borrow() {
                            exchange(&mut stream, &vec![id; 16 * 1024]).await?;
                            if !*stop.borrow() {
                                count += 1;
                            }
                        }
                        stream.shutdown().await?;
                        assert_eq!(stream.read(&mut [0]).await?, 0);
                        io::Result::Ok(count)
                    });
                }
                let mut udp = JoinSet::new();
                for id in 0..8u8 {
                    let association =
                        Socks5UdpAssociation::connect("127.0.0.1", pair.entry).await?;
                    let barrier = barrier.clone();
                    let destination = target(ipv6, echo.udp().port());
                    udp.spawn(async move {
                        barrier.wait().await;
                        let bytes = vec![id; 512];
                        for _ in 0..128 {
                            udp_echo(&association, destination, &bytes).await?;
                        }
                        io::Result::Ok(())
                    });
                }
                barrier.wait().await;
                while let Some(result) = udp.join_next().await {
                    result??;
                }
                finished.send(true).unwrap();
                while let Some(result) = tcp.join_next().await {
                    assert!(result?? > 0);
                }
            }
        }
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn stalled_tcp_reader_does_not_starve_udp_or_lose_buffered_data() -> io::Result<()> {
    timeout(Duration::from_secs(60), async {
        for detour in [false, true] {
            let pair = Pair::start(detour, |_, _| {}).await?;
            let echo = EchoTargets::new(false).await?;
            let mut stream = connect(pair.entry, target(false, echo.tcp().port())).await?;
            socket2::SockRef::from(&stream).set_recv_buffer_size(128 * 1024)?;
            socket2::SockRef::from(&stream).set_send_buffer_size(64 * 1024)?;
            let association = Socks5UdpAssociation::connect("127.0.0.1", pair.entry).await?;
            let bytes: Vec<_> = (0..8 * 1024 * 1024).map(|i| (i ^ (i >> 8)) as u8).collect();
            let (mut read, mut write) = stream.split();
            let send = write.write_all(&bytes);
            tokio::pin!(send);
            assert!(
                timeout(Duration::from_millis(250), &mut send)
                    .await
                    .is_err(),
                "writer did not backpressure"
            );
            for sequence in 0..64u8 {
                assert_eq!(
                    association
                        .send_to(target(false, echo.udp().port()), &[sequence; 1200])
                        .await?,
                    [sequence; 1200]
                );
            }
            let receive = async {
                let mut response = vec![0; bytes.len()];
                read.read_exact(&mut response).await?;
                assert_eq!(response, bytes);
                io::Result::Ok(())
            };
            timeout(Duration::from_secs(20), async {
                tokio::try_join!(send, receive)
            })
            .await??;
        }
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn udp_connection_burst_and_quota_release_preserve_service() -> io::Result<()> {
    timeout(Duration::from_secs(45), async {
        let echo = EchoTargets::new(false).await?;
        let pair = Pair::start(false, |_, _| {}).await?;
        let mut associations = Vec::new();
        for _ in 0..128 {
            associations.push(Socks5UdpAssociation::connect("127.0.0.1", pair.entry).await?);
        }
        let barrier = Arc::new(Barrier::new(128));
        let mut tasks = JoinSet::new();
        for (id, association) in associations.into_iter().enumerate() {
            let barrier = barrier.clone();
            let target = target(false, echo.udp().port());
            tasks.spawn(async move {
                barrier.wait().await;
                let bytes = (id as u64).to_be_bytes();
                udp_echo(&association, target, &bytes).await
            });
        }
        while let Some(result) = tasks.join_next().await {
            result??;
        }
        drop(pair);
        let pair = Pair::start(false, |_, client| {
            client["client_proxies"][0]["protocol"]["resource_limits"] =
                json!({"max_tcp_connections": 1, "max_udp_sessions": 1});
        })
        .await?;
        let mut first = connect(pair.entry, target(false, echo.tcp().port())).await?;
        exchange(&mut first, b"admitted").await?;
        assert!(
            connect(pair.entry, target(false, echo.tcp().port()))
                .await
                .is_err()
        );
        exchange(&mut first, b"still admitted").await?;
        first.shutdown().await?;
        assert_eq!(first.read(&mut [0]).await?, 0);
        drop(first);
        let first = Socks5UdpAssociation::connect("127.0.0.1", pair.entry).await?;
        let second = Socks5UdpAssociation::connect("127.0.0.1", pair.entry).await?;
        let destination = target(false, echo.udp().port());
        assert_eq!(first.send_to(destination, b"first").await?, b"first");
        assert!(
            timeout(
                Duration::from_millis(250),
                second.send_to(destination, b"rejected")
            )
            .await
            .is_err()
        );
        assert_eq!(
            first.send_to(destination, b"still first").await?,
            b"still first"
        );
        drop(first);
        drop(second);
        timeout(Duration::from_secs(15), async {
            loop {
                if let Ok(mut stream) = connect(pair.entry, target(false, echo.tcp().port())).await
                {
                    exchange(&mut stream, b"reclaimed").await?;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            loop {
                let udp = Socks5UdpAssociation::connect("127.0.0.1", pair.entry).await?;
                if let Ok(Ok(bytes)) = timeout(
                    Duration::from_millis(250),
                    udp.send_to(destination, b"reclaimed"),
                )
                .await
                {
                    assert_eq!(bytes, b"reclaimed");
                    break;
                }
            }
            io::Result::Ok(())
        })
        .await??;
        Ok(())
    })
    .await?
}
