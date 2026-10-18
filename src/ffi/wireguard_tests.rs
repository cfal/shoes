use super::{is_service_running, stop_service, tests::start_test_service};
use crate::{
    async_stream::{AsyncReadMessage, AsyncWriteMessage},
    ip_stack::{driver::PacketStack, packet::PacketBuffer},
    wireguard::test_support as config,
};
use serde_json::json;
use shoes_test_support::wireguard::EchoTargets;
use std::{
    io,
    net::SocketAddr,
    os::{
        fd::{AsRawFd, BorrowedFd},
        unix::net::UnixDatagram,
    },
    pin::Pin,
    sync::{Arc, atomic::Ordering, mpsc},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadBuf},
    task::JoinSet,
    time::timeout,
};

fn header(ipv6: bool) -> [u8; 4] {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let family = if ipv6 { libc::AF_INET6 } else { libc::AF_INET } as u32;
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let family: u32 = if ipv6 { 0x86dd } else { 0x0800 };
    family.to_be_bytes()
}

async fn bridge(wire: UnixDatagram, framed: bool) -> io::Result<(PacketStack, JoinSet<()>)> {
    wire.set_nonblocking(true)?;
    let wire = Arc::new(tokio::net::UnixDatagram::from_std(wire)?);
    let mut stack = PacketStack::new(
        vec!["10.90.0.2".parse().unwrap(), "fd90::2".parse().unwrap()],
        1408,
        false,
        Default::default(),
    )?;
    let mut output = stack.output.take().unwrap();
    let input = stack.input.clone();
    let wake = stack.handle.wake.clone();
    let outgoing = wire.clone();
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        while let Some(packet) = output.recv().await {
            let mut bytes = Vec::with_capacity(packet.len() + 4);
            if framed {
                bytes.extend(header(packet[0] >> 4 == 6));
            }
            bytes.extend_from_slice(&packet);
            match outgoing.send(&bytes).await {
                Ok(length) => assert_eq!(length, bytes.len()),
                // macOS reports a full datagram queue as ENOBUFS, not WouldBlock.
                Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => {}
                Err(error) => panic!("failed to send TUN packet: {error}"),
            }
        }
    });
    tasks.spawn(async move {
        let mut bytes = [0; 2048];
        loop {
            let length = wire.recv(&mut bytes).await.unwrap();
            let packet = if framed {
                assert_eq!(&bytes[..4], header(bytes[4] >> 4 == 6));
                &bytes[4..length]
            } else {
                &bytes[..length]
            };
            if input
                .send(PacketBuffer::copy_from_slice(packet))
                .await
                .is_err()
            {
                break;
            }
            wake.notify();
        }
    });
    Ok((stack, tasks))
}

#[test]
fn raw_fd_wireguard_service_forwards_and_restarts_without_leaks() {
    const CHILD: &str = "SHOES_FFI_WIREGUARD_LIFECYCLE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "ffi::common::wireguard_tests::raw_fd_wireguard_service_forwards_and_restarts_without_leaks",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("test result: ok. 1 passed;"),
            "FFI child did not run successfully: {}\n{stdout}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
        );
        return;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let reservation = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);
    for framed in [false, true] {
        let (wire, tun) = UnixDatagram::pair().unwrap();
        for socket in [&wire, &tun] {
            let socket = socket2::SockRef::from(socket);
            socket.set_send_buffer_size(256 * 1024).unwrap();
            socket.set_recv_buffer_size(256 * 1024).unwrap();
        }
        let mut duplicate = config::client(port);
        duplicate["client_group"] = json!("copy");
        let configs = json!([
            config::server(port),
            config::client(port),
            duplicate,
            {
                "device_fd": tun.as_raw_fd(),
                "packet_information": framed,
                "rules": [{
                    "masks": ["0.0.0.0/0", "::/0"],
                    "action": "allow",
                    "client_chain": [{"pool": ["wg", "copy"]}],
                }],
            },
        ]);
        let (protected_tx, protected_rx) = mpsc::channel();
        let protector = Arc::new(crate::tun::FnSocketProtector::new(move |fd| {
            let fd = unsafe { BorrowedFd::borrow_raw(fd) };
            let socket = socket2::SockRef::from(&fd);
            let info = (socket.r#type()?, socket.local_addr()?.as_socket().unwrap());
            let _ = protected_tx.send(info);
            Ok(())
        }));
        let (running, service) =
            start_test_service(serde_yaml::to_string(&configs).unwrap(), protector);
        // Only WireGuard opens sockets before the first forwarded packet.
        let protected_sockets: Vec<_> = (0..2)
            .map(|_| {
                protected_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("WireGuard socket was not protected")
            })
            .collect();
        assert!(
            protected_sockets
                .iter()
                .all(|(kind, _)| *kind == socket2::Type::DGRAM)
        );
        assert!(
            protected_sockets
                .iter()
                .any(|(_, address)| address.port() == port)
        );
        assert!(
            protected_sockets
                .iter()
                .any(|(_, address)| address.port() != 0 && address.port() != port)
        );
        let (stack, mut tasks) = runtime.block_on(bridge(wire, framed)).unwrap();
        let _active = runtime.block_on(async {
            timeout(Duration::from_secs(30), async {
                let mut active = Vec::new();
                for ipv6 in [false, true] {
                    let echo = EchoTargets::new(ipv6).await.unwrap();
                    let destination = |port| {
                        SocketAddr::new(
                            if ipv6 { "fd88::1" } else { "198.18.0.1" }.parse().unwrap(),
                            port,
                        )
                    };
                    let mut tcp = stack
                        .handle
                        .connect(destination(echo.tcp().port()))
                        .await
                        .unwrap();
                    let data: Vec<_> = (0..128_007).map(|i| (i ^ (i >> 8)) as u8).collect();
                    let (mut read, mut write) = tokio::io::split(&mut tcp);
                    let send = async {
                        write.write_all(&data).await.unwrap();
                        write.shutdown().await.unwrap();
                    };
                    let receive = async {
                        let mut reply = vec![0; data.len()];
                        read.read_exact(&mut reply).await.unwrap();
                        assert_eq!(reply, data);
                        assert_eq!(read.read(&mut [0]).await.unwrap(), 0);
                    };
                    tokio::join!(send, receive);
                    let mut udp = stack
                        .handle
                        .open_udp(destination(echo.udp().port()))
                        .await
                        .unwrap();
                    for size in [0, 1, 1200, 0] {
                        let payload = vec![0xa7; size];
                        futures::future::poll_fn(|cx| {
                            Pin::new(&mut udp).poll_write_message(cx, &payload)
                        })
                        .await
                        .unwrap();
                        let mut bytes = [0; 1500];
                        let mut reply = ReadBuf::new(&mut bytes);
                        futures::future::poll_fn(|cx| {
                            Pin::new(&mut udp).poll_read_message(cx, &mut reply)
                        })
                        .await
                        .unwrap();
                        assert_eq!(reply.filled(), payload);
                    }
                    let live_tcp = stack
                        .handle
                        .connect(destination(echo.tcp().port()))
                        .await
                        .unwrap();
                    active.push((echo, live_tcp, udp));
                }
                active
            })
            .await
            .expect("FFI WireGuard forwarding stalled")
        });
        assert!(is_service_running());
        let stopping = Instant::now();
        assert!(stop_service());
        assert!(
            stopping.elapsed() < Duration::from_secs(4),
            "service required forced shutdown"
        );
        assert!(service.is_finished());
        assert!(!running.load(Ordering::SeqCst));
        assert!(!is_service_running());
        assert_eq!(
            crate::tun::protect_socket(-1).unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        assert!(
            unsafe { libc::fcntl(tun.as_raw_fd(), libc::F_GETFD) } >= 0,
            "service closed the caller's TUN descriptor"
        );
        std::net::UdpSocket::bind(("0.0.0.0", port)).unwrap();
        runtime.block_on(tasks.shutdown());
        drop(stack);
    }
}
