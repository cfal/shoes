use std::{net::SocketAddr, time::Duration};

use aws_lc_rs::signature::{self, KeyPair};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use shoes_test_support::{
    socks5::Socks5UdpAssociation,
    test_fixture::{generate_reality_keypair, start_shoes_server},
    test_servers::{start_tcp_stream_echo_server, start_udp_echo_server_with_suffix},
    xray,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[path = "xhttp_fixture.rs"]
mod fixture;
use fixture::{Fixture, Peer, UUID, port};

#[path = "xhttp_wire.rs"]
mod wire;

fn payload(size: usize, session: usize) -> Vec<u8> {
    (0..size)
        .map(|i| ((i * 31 + i / 251 + session * 73) % 256) as u8)
        .collect()
}

async fn exchange(
    socks: SocketAddr,
    target: SocketAddr,
    session: usize,
) -> std::io::Result<tokio::net::TcpStream> {
    let mut stream = xray::connect(socks, target).await?;
    for size in [1, 32768, 512 * 1024 + 17] {
        let data = payload(size, session);
        let mut response = vec![0; size];
        let (mut read, mut write) = stream.split();
        tokio::try_join!(write.write_all(&data), read.read_exact(&mut response))?;
        assert_eq!(data, response, "session {session}, {size} bytes");
    }
    // Packet mode has no upload FIN; streaming peers may couple their halves.
    stream.shutdown().await?;
    Ok(stream)
}

async fn matrix_peer(
    peer: Peer,
    shoes_client: bool,
    protocol: &str,
    versions: &[&str],
) -> fixture::Result {
    let echo_port = port();
    let _echo = start_tcp_stream_echo_server("0.0.0.0", echo_port).await?;
    let target: SocketAddr = ([127, 0, 0, 1], echo_port).into();
    let _udp_echo = start_udp_echo_server_with_suffix("0.0.0.0", echo_port, b"").await?;
    let second_udp = start_udp_echo_server_with_suffix("0.0.0.0", 0, b"second").await?;
    let second_target = ([127, 0, 0, 1], second_udp.local_addr().port()).into();
    let fixture = Fixture::new(peer).await?;
    for &version in versions {
        for mode in ["packet-up", "stream-up", "stream-one", "auto"] {
            if mode == "auto" && !matches!(version, "reality" | "h2") {
                continue;
            }
            eprintln!("XHTTP {peer:?}, shoes_client={shoes_client}, {version} {mode} {protocol}");
            let pair = fixture
                .start(peer, shoes_client, protocol, version, mode)
                .await?;
            tokio::time::timeout(Duration::from_secs(30), async {
                let (mut first, mut second) = tokio::try_join!(
                    exchange(pair.socks, target, 0),
                    exchange(pair.socks, target, 1),
                )?;
                if version == "h3" && mode == "stream-one" {
                    assert_eq!(first.read(&mut [0]).await?, 0);
                    assert_eq!(second.read(&mut [0]).await?, 0);
                }
                drop((first, second));
                let mut next = exchange(pair.socks, target, 2).await?;
                if version == "h3" && mode == "stream-one" {
                    assert_eq!(next.read(&mut [0]).await?, 0);
                }
                drop(next);
                if peer == Peer::Xray
                    && !shoes_client
                    && protocol == "vless"
                    && version == "plain"
                    && mode == "packet-up"
                {
                    let mut stream = xray::connect(pair.socks, target).await?;
                    stream.write_all(b"open").await?;
                    let mut response = [0; 4];
                    stream.read_exact(&mut response).await?;
                    assert_eq!(&response, b"open");
                    tokio::time::sleep(Duration::from_secs(6)).await;
                    stream.write_all(b"idle").await?;
                    stream.read_exact(&mut response).await?;
                    assert_eq!(&response, b"idle");
                }
                if protocol == "vless" {
                    let udp = Socks5UdpAssociation::connect("127.0.0.1", pair.socks.port()).await?;
                    let large = payload(
                        if peer == Peer::Shoes {
                            40 * 1024
                        } else {
                            7 * 1024
                        },
                        9,
                    );
                    for data in [
                        b"ok\0\xff".as_slice(),
                        b"data: SSE-looking bytes\n\n",
                        &[0; 4096],
                        large.as_slice(),
                    ] {
                        assert_eq!(udp.send_to(target, data).await?, data);
                        assert_eq!(
                            udp.send_to(second_target, data).await?,
                            [data, b"second"].concat()
                        );
                        assert_eq!(udp.send_to(target, data).await?, data);
                    }
                }
                Ok::<_, std::io::Error>(())
            })
            .await
            .map_err(|error| {
                format!("{peer:?}, shoes_client={shoes_client}, {version} {mode}: {error}")
            })??;
        }
    }
    Ok(())
}

#[tokio::test]
async fn shoes_to_shoes_modes_and_transports() -> fixture::Result {
    matrix_peer(
        Peer::Shoes,
        true,
        "vless",
        &["plain", "h2c", "h1", "h2", "h3", "reality"],
    )
    .await
}

#[tokio::test]
async fn shoes_client_mihomo_alpha_server() -> fixture::Result {
    matrix_peer(
        Peer::Mihomo,
        true,
        "vless",
        &["plain", "h2c", "h1", "h2", "reality"],
    )
    .await
}

#[tokio::test]
async fn mihomo_alpha_client_shoes_server() -> fixture::Result {
    matrix_peer(
        Peer::Mihomo,
        false,
        "vless",
        &["plain", "h2c", "h1", "h2", "h3", "reality"],
    )
    .await
}

#[tokio::test]
async fn shoes_default_http_versions_follow_the_transport() -> fixture::Result {
    let fixture = Fixture::new(Peer::Shoes).await?;
    let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
    for version in ["plain", "h2", "h3"] {
        let pair = fixture
            .start_with_client_patch(
                fixture::Case {
                    peer: Peer::Shoes,
                    shoes_client: true,
                    protocol: "vless",
                    version,
                    mode: "auto",
                },
                |client| {
                    fixture::shoes_xhttp(client)
                        .as_object_mut()
                        .unwrap()
                        .remove("http_version");
                },
            )
            .await?;
        tokio::time::timeout(
            Duration::from_secs(10),
            exchange(
                pair.socks,
                ([127, 0, 0, 1], echo.local_addr().port()).into(),
                41,
            ),
        )
        .await??;
    }
    Ok(())
}

#[tokio::test]
async fn udp_datagrams_cross_post_boundaries_without_mixing_associations() -> fixture::Result {
    let first = start_udp_echo_server_with_suffix("0.0.0.0", 0, b"first").await?;
    let second = start_udp_echo_server_with_suffix("0.0.0.0", 0, b"second").await?;
    for (peer, shoes_client) in [
        (Peer::Shoes, true),
        (Peer::Xray, true),
        (Peer::Xray, false),
        (Peer::Mihomo, true),
        (Peer::Mihomo, false),
    ] {
        let mut fixture = Fixture::new(peer).await?;
        // Force fragmentation without exceeding the peers' UDP socket buffers.
        fixture.post_bytes = 1024;
        let pair = fixture
            .start(peer, shoes_client, "vless", "h2", "packet-up")
            .await?;
        tokio::time::timeout(Duration::from_secs(15), async {
            let a = Socks5UdpAssociation::connect("127.0.0.1", pair.socks.port()).await?;
            let b = Socks5UdpAssociation::connect("127.0.0.1", pair.socks.port()).await?;
            let exercise = async |association: &Socks5UdpAssociation, session| {
                for _ in 0..3 {
                    for (server, suffix) in [(&first, b"first".as_slice()), (&second, b"second")] {
                        let data = payload(4096, session);
                        let destination = ([127, 0, 0, 1], server.local_addr().port()).into();
                        assert_eq!(
                            association.send_to(destination, &data).await?,
                            [data.as_slice(), suffix].concat()
                        );
                    }
                }
                Ok::<_, std::io::Error>(())
            };
            tokio::try_join!(exercise(&a, 61), exercise(&b, 62))?;
            Ok::<_, std::io::Error>(())
        })
        .await
        .map_err(|error| {
            format!("UDP fragmentation {peer:?}, shoes_client={shoes_client}: {error}")
        })??;
    }
    Ok(())
}

#[tokio::test]
async fn tcp_prefix_and_quic_suffix_chains_carry_tcp_and_udp() -> fixture::Result {
    let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
    let udp =
        start_udp_echo_server_with_suffix("0.0.0.0", echo.local_addr().port(), b"chain").await?;
    let target = ([127, 0, 0, 1], udp.local_addr().port()).into();
    for (peer, suffix) in [
        (Peer::Shoes, false),
        (Peer::Xray, false),
        (Peer::Mihomo, false),
        (Peer::Shoes, true),
    ] {
        let fixture = Fixture::new(peer).await?;
        let hop = port();
        let readiness = port();
        let hop_protocol = if suffix {
            json!({"type":"vless","user_id":UUID,"udp_enabled":true})
        } else {
            json!({"type":"socks"})
        };
        let extra = start_shoes_server(&serde_yaml::to_string(&json!([
            {"address":format!("0.0.0.0:{hop}"),"protocol":hop_protocol},
            {"address":format!("0.0.0.0:{readiness}"),"protocol":{"type":"socks"}}
        ]))?)?;
        xray::wait_socks(([127, 0, 0, 1], readiness).into()).await?;
        let pair = fixture
            .start_with_client_patch(
                fixture::Case {
                    peer,
                    shoes_client: true,
                    protocol: "vless",
                    version: if suffix { "h3" } else { "h2" },
                    mode: "packet-up",
                },
                |client| {
                    let xhttp = client.take();
                    let other =
                        json!({"address":format!("127.0.0.1:{hop}"),"protocol":hop_protocol});
                    *client = if suffix {
                        json!({"chain":[xhttp,other]})
                    } else {
                        json!({"chain":[other,xhttp]})
                    };
                },
            )
            .await?;
        tokio::time::timeout(Duration::from_secs(15), async {
            exchange(pair.socks, target, 42).await?;
            let association = Socks5UdpAssociation::connect("127.0.0.1", pair.socks.port()).await?;
            assert_eq!(
                association.send_to(target, b"prefix\0\xff").await?,
                b"prefix\0\xffchain"
            );
            Ok::<_, std::io::Error>(())
        })
        .await??;
        drop(extra);
        // A dead hop must never turn into a direct connection to the destination.
        assert_rejected(pair.socks, target).await?;
    }
    Ok(())
}

async fn assert_rejected(socks: SocketAddr, target: SocketAddr) -> fixture::Result {
    let rejected = tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = match xray::connect(socks, target).await {
            Ok(stream) => stream,
            Err(_) => return true,
        };
        if stream.write_all(b"must not reach target").await.is_err() {
            return true;
        }
        matches!(stream.read(&mut [0]).await, Ok(0) | Err(_))
    })
    .await?;
    assert!(rejected, "rejected connection delivered application data");
    Ok(())
}

async fn pause_with_exchange(
    duration: Duration,
    exchange: impl Future<Output = std::io::Result<tokio::net::TcpStream>>,
) -> std::io::Result<bool> {
    let deadline = tokio::time::Instant::now() + duration;
    let completed = match tokio::time::timeout_at(deadline, exchange).await {
        Ok(result) => {
            result?;
            true
        }
        Err(_) => false,
    };
    tokio::time::sleep_until(deadline).await;
    Ok(completed)
}

async fn pressure(peer: Peer, shoes_client: bool, version: &str) -> fixture::Result {
    pressure_with_limits(peer, shoes_client, version, true).await
}

async fn pressure_with_limits(
    peer: Peer,
    shoes_client: bool,
    version: &str,
    tight: bool,
) -> fixture::Result {
    use std::sync::Arc;
    use tokio::sync::{Notify, oneshot};

    let mut fixture = Fixture::new(peer).await?;
    // Small byte budgets force backpressure while retaining the default request-count limits.
    fixture.pressure = tight;
    let pair = fixture
        .start(peer, shoes_client, "vless", version, "packet-up")
        .await?;
    let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
    let echo_address = ([127, 0, 0, 1], echo.local_addr().port()).into();
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
    socket2::SockRef::from(&listener).set_recv_buffer_size(65536)?;
    let target = ([127, 0, 0, 1], listener.local_addr()?.port()).into();
    let resume = Arc::new(Notify::new());
    let drain = resume.clone();
    let (accepted, ready) = oneshot::channel();
    let mut tasks = tokio::task::JoinSet::new();
    let size = 16 * 1024 * 1024;
    tasks.spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let mut data = vec![0; size];
        socket.read_exact(&mut data).await?;
        assert_eq!(data, payload(size, 70), "invalid upload control");
        socket.write_all(b"control!").await?;
        socket.read_exact(&mut data[..1]).await?;
        accepted.send(()).unwrap();
        drain.notified().await;
        socket.read_exact(&mut data[1..]).await?;
        assert_eq!(data, payload(size, 71), "reordered or truncated upload");
        socket.write_all(b"received").await?;
        Ok::<_, std::io::Error>(())
    });
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut upload = xray::connect(pair.socks, target).await?;
        socket2::SockRef::from(&upload).set_send_buffer_size(65536)?;
        let start = tokio::time::Instant::now();
        upload.write_all(&payload(size, 70)).await?;
        let mut response = [0; 8];
        upload.read_exact(&mut response).await?;
        assert_eq!(&response, b"control!");
        let upload_pause = (2 * start.elapsed()).max(Duration::from_secs(1));
        let mut writers = tokio::task::JoinSet::new();
        let (sent, mut uploaded) = oneshot::channel();
        writers.spawn(async move {
            upload.write_all(&payload(size, 71)).await?;
            sent.send(()).unwrap();
            let mut response = [0; 8];
            upload.read_exact(&mut response).await?;
            assert_eq!(&response, b"received");
            Ok::<_, std::io::Error>(())
        });
        ready.await.unwrap();
        let other = exchange(pair.socks, echo_address, 72);
        tokio::pin!(other);
        // Shared flow-control credit may block both sessions until consumption resumes.
        let completed = pause_with_exchange(upload_pause, &mut other).await?;
        assert!(
            matches!(
                uploaded.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ),
            "{peer:?}, shoes_client={shoes_client}, {version}: stalled upload was entirely buffered or failed after {upload_pause:?}"
        );
        resume.notify_one();
        if !completed {
            other.await?;
        }
        writers.join_next().await.unwrap().unwrap()?;
        tasks.join_next().await.unwrap().unwrap()?;

        // The peer's transport windows and both TCP hops can collectively retain 16 MiB.
        let download_size = 64 * 1024 * 1024;
        let source = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
        let target = ([127, 0, 0, 1], source.local_addr()?.port()).into();
        tasks.spawn(async move {
            let (mut socket, _) = source.accept().await?;
            socket2::SockRef::from(&socket).set_send_buffer_size(65536)?;
            socket.read_exact(&mut [0]).await?;
            socket.write_all(&payload(download_size, 72)).await?;
            socket.read_exact(&mut [0]).await?;
            socket.write_all(&payload(download_size, 73)).await?;
            Ok::<_, std::io::Error>(())
        });
        let mut download = xray::connect(pair.socks, target).await?;
        socket2::SockRef::from(&download).set_recv_buffer_size(65536)?;
        let start = tokio::time::Instant::now();
        download.write_all(b"c").await?;
        let mut control = vec![0; download_size];
        download.read_exact(&mut control).await?;
        assert_eq!(control, payload(download_size, 72), "invalid download control");
        let download_pause = (2 * start.elapsed()).max(Duration::from_secs(1));
        download.write_all(b"p").await?;
        let mut first = [0];
        download.read_exact(&mut first).await?;
        assert_eq!(first[0], payload(1, 73)[0]);
        let other = exchange(pair.socks, echo_address, 74);
        tokio::pin!(other);
        let completed = pause_with_exchange(download_pause, &mut other).await?;
        let source_result = tasks.try_join_next();
        assert!(
            source_result.is_none(),
            "{peer:?}, shoes_client={shoes_client}, {version}: stalled download completed after {download_pause:?}: {source_result:?}"
        );
        let mut rest = vec![0; download_size - 1];
        tokio::try_join!(download.read_exact(&mut rest), async {
            if !completed {
                other.await?;
            }
            Ok::<_, std::io::Error>(())
        })?;
        assert_eq!(rest, payload(download_size, 73)[1..]);
        tasks.join_next().await.unwrap().unwrap()?;

        // Cancel a live transfer, not just an idle SOCKS connection.
        let mut cancelled = xray::connect(pair.socks, echo_address).await?;
        cancelled.write_all(&payload(128 * 1024, 75)).await?;
        cancelled.read_exact(&mut first).await?;
        drop(cancelled);
        exchange(pair.socks, echo_address, 76).await?;
        for session in 0..16 {
            let mut stream = xray::connect(pair.socks, echo_address).await?;
            let data = payload(67, session);
            stream.write_all(&data).await?;
            let mut response = vec![0; data.len()];
            stream.read_exact(&mut response).await?;
            assert_eq!(data, response);
        }
        Ok::<_, std::io::Error>(())
    })
    .await
    .map_err(|error| {
        format!("pressure: {peer:?}, shoes_client={shoes_client}, {version}: {error}")
    })??;
    Ok(())
}

#[tokio::test]
async fn shoes_backpressure_cancellation_and_churn() -> fixture::Result {
    for version in ["h2", "h3"] {
        pressure(Peer::Shoes, true, version).await?;
    }
    Ok(())
}

#[tokio::test]
async fn xray_backpressure_cancellation_and_churn() -> fixture::Result {
    for shoes_client in [true, false] {
        for version in ["h2", "h3"] {
            pressure(Peer::Xray, shoes_client, version).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn xray_h2_packet_inactivity_bounds_permanent_stalls() -> fixture::Result {
    let mut fixture = Fixture::new(Peer::Xray).await?;
    fixture.server_packet_timeout_secs = Some(2);
    let pair = fixture.start_with_client_patch(fixture::Case {
        peer: Peer::Xray, shoes_client: false, protocol: "vless", version: "h2", mode: "packet-up",
    }, |config| {
        config["outbounds"][0]["streamSettings"]["xhttpSettings"]["extra"]["scMinPostsIntervalMs"] = json!(30);
    }).await?;
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
    socket2::SockRef::from(&listener).set_recv_buffer_size(65536)?;
    let target = ([127, 0, 0, 1], listener.local_addr()?.port()).into();
    let result = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::try_join!(
            async {
                let (mut socket, _) = listener.accept().await?;
                socket.read_exact(&mut [0]).await?;
                let _socket = socket;
                std::future::pending::<std::io::Result<()>>().await
            },
            async {
                let mut stream = xray::connect(pair.socks, target).await?;
                stream.write_all(&payload(16 * 1024 * 1024, 78)).await?;
                stream.read_exact(&mut [0]).await?;
                Ok::<_, std::io::Error>(())
            }
        )
    })
    .await
    .expect("stalled POST admission must expire without unbounded accumulation");
    let error = result.unwrap_err();
    assert!(
        matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof
        ),
        "{error}"
    );
    let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
    tokio::time::timeout(
        Duration::from_secs(10),
        exchange(
            pair.socks,
            ([127, 0, 0, 1], echo.local_addr().port()).into(),
            79,
        ),
    )
    .await??;
    Ok(())
}

#[tokio::test]
async fn xray_h2_default_byte_budgets_stalled_upload() -> fixture::Result {
    xray_stalled_upload("h2", None).await
}

#[tokio::test]
async fn xray_h3_default_byte_budgets_stalled_upload() -> fixture::Result {
    xray_stalled_upload("h3", None).await
}

#[tokio::test]
async fn xray_h2_explicit_request_cap_stalled_upload() -> fixture::Result {
    xray_stalled_upload("h2", Some(128)).await
}

async fn xray_stalled_upload(version: &str, request_limit: Option<usize>) -> fixture::Result {
    let mut fixture = Fixture::new(Peer::Xray).await?;
    fixture.server_request_limit = request_limit;
    let pair = fixture.start_with_client_patch(fixture::Case {
            peer: Peer::Xray, shoes_client: false, protocol: "vless", version, mode: "packet-up",
        }, |config| {
            config["outbounds"][0]["streamSettings"]["xhttpSettings"]["extra"]["scMinPostsIntervalMs"] = json!(30);
        }).await?;
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
    socket2::SockRef::from(&listener).set_recv_buffer_size(65536)?;
    let target = ([127, 0, 0, 1], listener.local_addr()?.port()).into();
    let size = 16 * 1024 * 1024;
    let resume = tokio::sync::Notify::new();
    let (accepted, ready) = tokio::sync::oneshot::channel();
    tokio::time::timeout(Duration::from_secs(40), async {
        tokio::try_join!(
            async {
                let (mut socket, _) = listener.accept().await?;
                let mut data = vec![0; size];
                socket.read_exact(&mut data[..1]).await?;
                accepted.send(()).unwrap();
                let (mut read, mut write) = socket.into_split();
                let done = tokio_util::sync::CancellationToken::new();
                tokio::try_join!(
                    async {
                        resume.notified().await;
                        read.read_exact(&mut data[1..]).await?;
                        assert_eq!(data, payload(size, 77));
                        done.cancel();
                        Ok::<_, std::io::Error>(())
                    },
                    async {
                        loop {
                            write.write_all(b"progress").await?;
                            tokio::select! {
                                _ = done.cancelled() => break,
                                _ = tokio::time::sleep(Duration::from_millis(200)) => {},
                            }
                        }
                        write.write_all(b"received").await
                    }
                )?;
                Ok::<_, std::io::Error>(())
            },
            async {
                let stream = xray::connect(pair.socks, target).await?;
                let (mut read, mut write) = tokio::io::split(stream);
                tokio::try_join!(async { write.write_all(&payload(size, 77)).await }, async {
                    let mut progress = 0;
                    loop {
                        let mut response = [0; 8];
                        tokio::time::timeout(
                            Duration::from_secs(3),
                            read.read_exact(&mut response),
                        )
                        .await??;
                        if &response == b"received" {
                            assert!(progress >= 10);
                            break;
                        }
                        assert_eq!(&response, b"progress");
                        progress += 1;
                    }
                    Ok::<_, std::io::Error>(())
                })?;
                Ok::<_, std::io::Error>(())
            },
            async {
                ready.await.unwrap();
                tokio::time::sleep(Duration::from_secs(10)).await;
                resume.notify_one();
                Ok::<_, std::io::Error>(())
            }
        )?;
        Ok::<_, std::io::Error>(())
    })
    .await
    .map_err(|error| {
        format!("default byte budgets, {version}, request cap {request_limit:?}: {error}")
    })??;
    Ok(())
}

#[tokio::test]
async fn mihomo_backpressure_cancellation_and_churn() -> fixture::Result {
    pressure(Peer::Mihomo, true, "h2").await?;
    for version in ["h2", "h3"] {
        pressure(Peer::Mihomo, false, version).await?;
    }
    Ok(())
}

#[tokio::test]
async fn mihomo_server_stall_recovery_with_default_client_limits() -> fixture::Result {
    pressure_with_limits(Peer::Mihomo, true, "h2", false).await
}

#[tokio::test]
async fn h1_packet_upload_survives_peer_stalls() -> fixture::Result {
    for peer in [Peer::Xray, Peer::Mihomo] {
        pressure_with_limits(peer, true, "h1", false).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "real-peer throughput and stall qualification; configure XHTTP_BENCH_* sweeps"]
async fn packet_up_throughput_and_stall_qualification() -> fixture::Result {
    fn values(name: &str, default: &str) -> Vec<u64> {
        std::env::var(name)
            .unwrap_or_else(|_| default.into())
            .split(',')
            .map(|value| value.parse().unwrap())
            .collect()
    }
    let directions = std::env::var("XHTTP_BENCH_DIRECTIONS")
        .unwrap_or_else(|_| "xray-xray,xray-shoes,shoes-xray".into());
    for rtt in values("XHTTP_BENCH_RTT_MS", "0,150") {
        for pause in values("XHTTP_BENCH_PAUSE_SECS", "0") {
            for post in values("XHTTP_BENCH_POST_BYTES", "32768,1000000") {
                for cap in values("XHTTP_BENCH_REQUEST_CAP", "128") {
                    for sessions in values("XHTTP_BENCH_SESSIONS", "1") {
                        for direction in directions.split(',') {
                            assert!(matches!(
                                direction,
                                "xray-xray" | "xray-shoes" | "shoes-xray"
                            ));
                            let mut fixture = Fixture::new(Peer::Xray).await?;
                            fixture.post_bytes = post as usize;
                            fixture.post_interval_ms = 30;
                            fixture.latency_ms = rtt;
                            fixture.server_request_limit = Some(cap as usize);
                            fixture.h2_window_bytes = std::env::var("XHTTP_BENCH_H2_WINDOW_BYTES")
                                .ok()
                                .map(|value| value.parse().unwrap());
                            let pair = if direction == "xray-xray" {
                                fixture.start_xray_reference().await?
                            } else {
                                fixture
                                    .start(
                                        Peer::Xray,
                                        direction == "shoes-xray",
                                        "vless",
                                        "h2",
                                        "packet-up",
                                    )
                                    .await?
                            };
                            let pids = pair.pids();
                            let peak_rss =
                                std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
                            let peak = peak_rss.clone();
                            let stop = tokio_util::sync::CancellationToken::new();
                            let stopped = stop.clone();
                            let sampler = tokio::spawn(async move {
                                loop {
                                    let rss: u64 = pids
                                        .iter()
                                        .filter_map(|pid| {
                                            let status = std::fs::read_to_string(format!(
                                                "/proc/{pid}/status"
                                            ))
                                            .ok()?;
                                            status.lines().find_map(|line| {
                                                line.strip_prefix("VmRSS:")?
                                                    .split_whitespace()
                                                    .next()?
                                                    .parse::<u64>()
                                                    .ok()
                                            })
                                        })
                                        .sum();
                                    peak.fetch_max(rss, std::sync::atomic::Ordering::Relaxed);
                                    tokio::select! {
                                        _ = stopped.cancelled() => break,
                                        _ = tokio::time::sleep(Duration::from_millis(50)) => {},
                                    }
                                }
                            });
                            let started = std::time::Instant::now();
                            let mut transfers = tokio::task::JoinSet::new();
                            let size = 16 * 1024 * 1024;
                            for session in 0..sessions {
                                let socks = pair.socks;
                                transfers.spawn(async move {
                                    let listener =
                                        tokio::net::TcpListener::bind("0.0.0.0:0").await?;
                                    socket2::SockRef::from(&listener)
                                        .set_recv_buffer_size(65536)?;
                                    let target =
                                        ([127, 0, 0, 1], listener.local_addr()?.port()).into();
                                    tokio::try_join!(
                                        async {
                                            let (socket, _) = listener.accept().await?;
                                            let (mut read, mut write) = socket.into_split();
                                            tokio::try_join!(
                                                async {
                                                    let mut bytes = vec![0; size];
                                                    read.read_exact(&mut bytes[..1]).await?;
                                                    tokio::time::sleep(Duration::from_secs(pause))
                                                        .await;
                                                    read.read_exact(&mut bytes[1..]).await?;
                                                    assert_eq!(
                                                        bytes,
                                                        payload(size, session as usize)
                                                    );
                                                    Ok::<_, std::io::Error>(())
                                                },
                                                async { write.write_all(&payload(size, 97)).await }
                                            )?;
                                            write.write_all(b"!").await?;
                                            Ok::<_, std::io::Error>(())
                                        },
                                        async {
                                            let socket = xray::connect(socks, target).await?;
                                            let (mut read, mut write) = tokio::io::split(socket);
                                            tokio::try_join!(
                                                async {
                                                    write
                                                        .write_all(&payload(size, session as usize))
                                                        .await
                                                },
                                                async {
                                                    let mut bytes = vec![0; size];
                                                    read.read_exact(&mut bytes).await?;
                                                    assert_eq!(bytes, payload(size, 97));
                                                    Ok::<_, std::io::Error>(())
                                                }
                                            )?;
                                            assert_eq!(read.read_u8().await?, b'!');
                                            Ok::<_, std::io::Error>(())
                                        }
                                    )?;
                                    Ok::<_, std::io::Error>(())
                                });
                            }
                            let result =
                                tokio::time::timeout(Duration::from_secs(pause + 180), async {
                                    while let Some(result) = transfers.join_next().await {
                                        result??;
                                    }
                                    Ok::<_, Box<dyn std::error::Error>>(())
                                })
                                .await;
                            stop.cancel();
                            sampler.await?;
                            let elapsed = started.elapsed().as_secs_f64();
                            eprintln!(
                                "XHTTP_QUALIFICATION {}",
                                json!({
                                    "direction":direction,"rtt_ms":rtt,"pause_secs":pause,
                                    "post_bytes":post,"server_request_cap":cap,"sessions":sessions,
                                "shoes_window_override":fixture.h2_window_bytes,
                                    "seconds":elapsed,"duplex_mib_per_sec":32.0 * sessions as f64 / elapsed,
                                    "peer_peak_rss_kib":peak_rss.load(std::sync::atomic::Ordering::Relaxed),
                                    "success":matches!(&result, Ok(Ok(())))
                                })
                            );
                            result??;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn wrong_credentials_never_reach_the_destination() -> fixture::Result {
    for (peer, shoes_client) in [
        (Peer::Shoes, true),
        (Peer::Xray, true),
        (Peer::Xray, false),
        (Peer::Mihomo, true),
        (Peer::Mihomo, false),
    ] {
        let fixture = Fixture::new(peer).await?;
        for mode in ["packet-up", "stream-up", "stream-one"] {
            let destination = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
            let target = ([127, 0, 0, 1], destination.local_addr()?.port()).into();
            let pair = fixture
                .start_with_client_patch(
                    fixture::Case {
                        peer,
                        shoes_client,
                        protocol: "vless",
                        version: "h2",
                        mode,
                    },
                    |client| {
                        let wrong = json!("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
                        if shoes_client {
                            fixture::shoes_xhttp(client)["protocol"]["user_id"] = wrong;
                        } else if peer == Peer::Xray {
                            client["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"] =
                                wrong;
                        } else {
                            client["proxies"][0]["uuid"] = wrong;
                        }
                    },
                )
                .await?;
            assert_rejected(pair.socks, target).await.map_err(|error| {
                format!("{peer:?}, shoes_client={shoes_client}, {mode}: {error}")
            })?;
            assert!(
                tokio::time::timeout(Duration::from_millis(100), destination.accept())
                    .await
                    .is_err(),
                "{peer:?}, shoes_client={shoes_client}, {mode}: rejected request dialed the target"
            );
            drop(pair);
            let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
            let good = fixture
                .start(peer, shoes_client, "vless", "h2", mode)
                .await?;
            tokio::time::timeout(
                Duration::from_secs(5),
                exchange(
                    good.socks,
                    ([127, 0, 0, 1], echo.local_addr().port()).into(),
                    83,
                ),
            )
            .await??;
        }
    }
    Ok(())
}

#[tokio::test]
async fn xray_client_matching_headers() -> fixture::Result {
    client_matching_headers(Peer::Xray).await
}

#[tokio::test]
async fn mihomo_alpha_client_matching_headers() -> fixture::Result {
    client_matching_headers(Peer::Mihomo).await
}

async fn client_matching_headers(peer: Peer) -> fixture::Result {
    let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
    let target: SocketAddr = ([127, 0, 0, 1], echo.local_addr().port()).into();
    let mut fixture = Fixture::new(peer).await?;
    fixture.matching_headers = Some(json!({"X-Tunnel-Key":"test-secret"}));
    let start = |version, mode, key: Option<&'static str>| {
        fixture.start_with_client_patch(
            fixture::Case {
                peer,
                shoes_client: false,
                protocol: "vless",
                version,
                mode,
            },
            move |client| {
                let Some(key) = key else { return };
                let headers = json!({"X-Tunnel-Key":key});
                if peer == Peer::Xray {
                    // With extra set, Xray keeps only host/path/mode from top-level xhttpSettings.
                    client["outbounds"][0]["streamSettings"]["xhttpSettings"]["extra"]["headers"] =
                        headers;
                } else {
                    client["proxies"][0]["xhttp-opts"]["headers"] = headers;
                }
            },
        )
    };
    for (version, mode) in [
        ("h2", "packet-up"),
        ("h2", "stream-up"),
        ("h2", "stream-one"),
        ("h1", "packet-up"),
        ("h3", "packet-up"),
    ] {
        eprintln!("XHTTP matching headers: {peer:?} {version} {mode}");
        let pair = start(version, mode, Some("test-secret")).await?;
        tokio::time::timeout(Duration::from_secs(30), async {
            tokio::try_join!(
                exchange(pair.socks, target, 0),
                exchange(pair.socks, target, 1),
            )?;
            exchange(pair.socks, target, 2).await
        })
        .await??;
    }
    for key in [None, Some("wrong-secret")] {
        let destination = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
        let target = ([127, 0, 0, 1], destination.local_addr()?.port()).into();
        let pair = start("h2", "packet-up", key).await?;
        assert_rejected(pair.socks, target)
            .await
            .map_err(|error| format!("{peer:?}, header {key:?}: {error}"))?;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), destination.accept())
                .await
                .is_err(),
            "{peer:?}, header {key:?}: rejected request dialed the target"
        );
    }
    Ok(())
}

#[tokio::test]
async fn shoes_client_xray_server_all_modes_and_versions() -> Result<(), Box<dyn std::error::Error>>
{
    matrix_peer(
        Peer::Xray,
        true,
        "vless",
        &["h1", "h2", "h3", "plain", "h2c"],
    )
    .await
}

#[tokio::test]
async fn xray_client_shoes_server_all_modes_and_versions() -> Result<(), Box<dyn std::error::Error>>
{
    matrix_peer(
        Peer::Xray,
        false,
        "vless",
        &["h1", "h2", "h3", "plain", "reality"],
    )
    .await
}

#[tokio::test]
async fn trojan_transport_independence() -> Result<(), Box<dyn std::error::Error>> {
    matrix_peer(
        Peer::Xray,
        true,
        "trojan",
        &["h1", "h2", "h3", "plain", "h2c", "reality"],
    )
    .await?;
    matrix_peer(
        Peer::Xray,
        false,
        "trojan",
        &["h1", "h2", "h3", "plain", "reality"],
    )
    .await
}

#[tokio::test]
async fn shoes_reality_client_and_udp_through_a_tcp_prefix()
-> Result<(), Box<dyn std::error::Error>> {
    let echo_port = port();
    let _echo = start_tcp_stream_echo_server("0.0.0.0", echo_port).await?;
    let _udp = start_udp_echo_server_with_suffix("0.0.0.0", echo_port, b"").await?;
    let target: SocketAddr = ([127, 0, 0, 1], echo_port).into();
    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()])?;
    // The cover flight must fit REALITY's ML-DSA certificate.
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 55555, 1],
            vec![0; 5000],
        ));
    let certificate = params.self_signed(&key)?;
    let (private_key, public_key) = generate_reality_keypair();
    let seed = URL_SAFE_NO_PAD.encode([7; 32]);
    let [verify, wrong_verify] = [7, 8].map(|byte| {
        let signing =
            signature::PqdsaKeyPair::from_seed(&signature::ML_DSA_65_SIGNING, &[byte; 32]).unwrap();
        URL_SAFE_NO_PAD.encode(signing.public_key().as_ref())
    });
    for (mode, sign, pin, accepted) in [
        ("auto", false, None, true),
        ("stream-one", false, None, true),
        ("stream-up", false, None, true),
        ("packet-up", false, None, true),
        ("auto", true, Some(&verify), true),
        ("stream-one", true, Some(&verify), true),
        ("stream-up", true, Some(&verify), true),
        ("packet-up", true, Some(&verify), true),
        ("auto", true, None, true),
        ("auto", true, Some(&wrong_verify), false),
        ("auto", false, Some(&verify), false),
    ] {
        eprintln!(
            "REALITY XHTTP prefix: {mode}, sign={sign}, pin={}, accepted={accepted}",
            pin.is_some()
        );
        let destination = port();
        let remote = port();
        let prefix = port();
        let socks = port();
        let inner = json!({"type":"vless","user_id":UUID,"udp_enabled":true});
        let xhttp = json!({"type":"xhttp","path":"/reality","mode":mode,"protocol":inner});
        let config = json!([
            {"address":format!("0.0.0.0:{destination}"),"protocol":{"type":"tls","default_target":{
                "cert":certificate.pem(),"key":key.serialize_pem(),
                "key_exchange_groups":["X25519MLKEM768"],
                "alpn_protocols":["h2","http/1.1"],"protocol":{"type":"http"}
            }}},
            {"address":format!("0.0.0.0:{remote}"),"protocol":{"type":"tls","reality_targets":{"localhost":{
                "private_key":private_key,"short_ids":["0123456789abcdef"],
                "mldsa65_seed":sign.then_some(&seed),
                "dest":format!("localhost:{destination}"),"protocol":xhttp
            }}}},
            {"address":format!("0.0.0.0:{prefix}"),"protocol":{"type":"socks"}},
            {"address":format!("0.0.0.0:{socks}"),"protocol":{"type":"socks","udp_enabled":true},
                "rules":[{"masks":"0.0.0.0/0","client_chains":[[
                    {"address":format!("127.0.0.1:{prefix}"),"protocol":{"type":"socks"}},
                    {"address":format!("127.0.0.1:{remote}"),"protocol":{"type":"reality",
                        "public_key":public_key,"short_id":"0123456789abcdef",
                        "mldsa65_verify":pin,
                        "sni_hostname":"localhost","protocol":xhttp}}
                ]]}]}
        ]);
        let _server = start_shoes_server(&serde_yaml::to_string(&config)?)?;
        let address: SocketAddr = ([127, 0, 0, 1], socks).into();
        xray::wait_socks(address).await?;
        let connected =
            tokio::time::timeout(Duration::from_secs(15), xray::connect(address, target)).await?;
        if !accepted {
            assert!(
                connected.is_err(),
                "REALITY pin must fail before SOCKS CONNECT succeeds"
            );
            continue;
        }
        let mut stream = connected?;
        tokio::time::timeout(Duration::from_secs(15), async {
            let payload = vec![71; 300_000];
            let mut response = vec![0; payload.len()];
            let (mut read, mut write) = stream.split();
            tokio::try_join!(write.write_all(&payload), read.read_exact(&mut response))?;
            assert_eq!(response, payload);
            let udp = Socks5UdpAssociation::connect("127.0.0.1", socks).await?;
            assert_eq!(udp.send_to(target, b"prefix\0\xff").await?, b"prefix\0\xff");
            Ok::<_, std::io::Error>(())
        })
        .await??;
    }
    Ok(())
}

#[tokio::test]
async fn xray_packet_upload_survives_a_slow_consumer() -> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
    socket2::SockRef::from(&listener).set_recv_buffer_size(65536)?;
    let target: SocketAddr = ([127, 0, 0, 1], listener.local_addr()?.port()).into();
    let size = 16 * 1024 * 1024;
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = 0;
        let mut buffer = [0; 16 * 1024];
        while received < size {
            let len = socket.read(&mut buffer).await.unwrap();
            assert_ne!(len, 0, "upload ended after {received} bytes");
            assert!(buffer[..len].iter().all(|byte| *byte == 73));
            received += len;
            tokio::time::sleep(Duration::from_millis(8)).await;
        }
        socket.write_all(b"ok").await.unwrap();
    });
    let remote = port();
    let socks_port = port();
    let _shoes = start_shoes_server(&serde_yaml::to_string(&json!([
        {"address":format!("0.0.0.0:{remote}"),"protocol":{"type":"xhttp","path":"/slow",
            "protocol":{"type":"vless","user_id":UUID}}}
    ]))?)?;
    tokio::time::timeout(Duration::from_secs(10), async {
        while tokio::net::TcpStream::connect(("127.0.0.1", remote))
            .await
            .is_err()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    let _xray = xray::start(json!({
        "log":{"loglevel":"warning"},
        "inbounds":[{"listen":"0.0.0.0","port":socks_port,"protocol":"socks","settings":{"auth":"noauth"}}],
        "outbounds":[{"protocol":"vless","settings":{"vnext":[{
            "address":"127.0.0.1","port":remote,"users":[{"id":UUID,"encryption":"none"}]
        }]},"streamSettings":{"network":"xhttp","security":"none",
            "xhttpSettings":{"path":"/slow","mode":"packet-up"}}}]
    })).await?;
    let socks = ([127, 0, 0, 1], socks_port).into();
    xray::wait_socks(socks).await?;
    tokio::time::timeout(Duration::from_secs(25), async {
        let mut stream = xray::connect(socks, target).await?;
        stream.write_all(&vec![73; size]).await?;
        let mut response = [0; 2];
        stream.read_exact(&mut response).await?;
        assert_eq!(&response, b"ok");
        tasks.join_next().await.unwrap().unwrap();
        Ok::<_, std::io::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn xhttp_tls_and_quic_enforce_key_exchange_allowlists()
-> Result<(), Box<dyn std::error::Error>> {
    let echo_port = port();
    let _echo = start_tcp_stream_echo_server("0.0.0.0", echo_port).await?;
    let target: SocketAddr = ([127, 0, 0, 1], echo_port).into();
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let mut configs = Vec::new();
    let mut cases = Vec::new();
    for version in ["h2", "h3"] {
        for client_group in ["X25519MLKEM768", "X25519"] {
            for server_group in ["X25519MLKEM768", "X25519"] {
                let remote = port();
                let socks = port();
                let xhttp = json!({"type":"xhttp", "http_version":version, "mode":"stream-one",
                    "protocol":{"type":"vless", "user_id":UUID}});
                let server_tls = json!({"cert":certificate.cert.pem(), "key":certificate.signing_key.serialize_pem(),
                    "key_exchange_groups":[server_group]});
                let client_tls = json!({"verify":false, "sni_hostname":"localhost",
                    "key_exchange_groups":[client_group]});
                let mut server = json!({"address":format!("0.0.0.0:{remote}"), "protocol":xhttp});
                let mut client = json!({"address":format!("127.0.0.1:{remote}"), "protocol":xhttp});
                if version == "h3" {
                    server["transport"] = json!("quic");
                    server["quic_settings"] = server_tls;
                    client["transport"] = json!("quic");
                    client["quic_settings"] = client_tls;
                } else {
                    let mut server_tls = server_tls;
                    server_tls["protocol"] = xhttp.clone();
                    server["protocol"] = json!({"type":"tls", "default_target":server_tls});
                    client["protocol"] = client_tls;
                    client["protocol"]["type"] = json!("tls");
                    client["protocol"]["protocol"] = xhttp;
                }
                configs.push(server);
                configs.push(
                    json!({"address":format!("0.0.0.0:{socks}"), "protocol":{"type":"socks"},
                    "rules":[{"masks":"0.0.0.0/0", "client_chain":client}]}),
                );
                cases.push((version, client_group, server_group, socks));
            }
        }
    }
    let _server = start_shoes_server(&serde_yaml::to_string(&configs)?)?;
    for (version, client_group, server_group, socks) in cases {
        let address = ([127, 0, 0, 1], socks).into();
        xray::wait_socks(address).await?;
        let connected =
            tokio::time::timeout(Duration::from_secs(10), xray::connect(address, target)).await?;
        assert_eq!(
            connected.is_ok(),
            client_group == server_group,
            "{version}: {client_group} client / {server_group} server: {connected:?}"
        );
        if let Ok(mut stream) = connected {
            tokio::time::timeout(Duration::from_secs(10), async {
                stream.write_all(b"allowlisted").await?;
                let mut response = [0; 11];
                stream.read_exact(&mut response).await?;
                assert_eq!(&response, b"allowlisted");
                Ok::<_, std::io::Error>(())
            })
            .await??;
        }
    }
    Ok(())
}

#[tokio::test]
async fn shoes_client_xray_reality_server() -> Result<(), Box<dyn std::error::Error>> {
    matrix_peer(Peer::Xray, true, "vless", &["reality"]).await
}
