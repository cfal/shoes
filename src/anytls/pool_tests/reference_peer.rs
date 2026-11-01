use super::*;
use tokio::io::AsyncBufReadExt;
use tokio::net::UdpSocket;

#[tokio::test]
#[ignore = "requires ANYTLS_REFERENCE_PEER pointing to the pinned Go peer"]
async fn reference_peer_tcp_uot_and_concurrent_session_reuse() {
    let executable = std::env::var("ANYTLS_REFERENCE_PEER").expect("ANYTLS_REFERENCE_PEER");
    let mut child = tokio::process::Command::new(executable)
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdout = tokio::io::BufReader::new(child.stdout.take().unwrap());
    let mut port = String::new();
    assert_ne!(
        tokio::time::timeout(Duration::from_secs(5), stdout.read_line(&mut port))
            .await
            .expect("reference peer did not announce its port")
            .unwrap(),
        0
    );
    let dialer = Arc::new(NetworkDialer {
        address: format!("127.0.0.1:{}", port.trim()),
        calls: AtomicUsize::new(0),
        key: RouteKey(vec![1]),
    });
    let handler = handler(PoolOptions::default());
    tokio::time::timeout(Duration::from_secs(15), async {
        for _ in 0..16 {
            let mut stream = connect(&handler, &dialer).await;
            stream.write_all(b"reference tcp").await.unwrap();
            let mut response = [0; 13];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"reference tcp");
            stream.shutdown().await.unwrap();
        }
        let server = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let destination = NetLocation::from_str(
            &format!("127.0.0.1:{}", server.local_addr().unwrap().port()),
            None,
        )
        .unwrap()
        .into();
        let mut udp = handler
            .connect_client_udp(transport(&dialer), destination)
            .await
            .unwrap();
        // A small packet after the maximum IPv4 UDP payload detects leftover framing.
        // Mutated UDP replies cannot pass via a byte-stream echo.
        for size in [1, 13, 4095, 16384, 65507, 7] {
            let payload: Vec<_> = (0..size).map(|index| (index * 37 + size) as u8).collect();
            let expected: Vec<_> = payload.iter().map(|byte| byte ^ 0x5a).collect();
            let ((), ()) = tokio::join!(
                async {
                    futures::future::poll_fn(|cx| {
                        Pin::new(&mut *udp).poll_write_message(cx, &payload)
                    })
                    .await
                    .unwrap();
                    futures::future::poll_fn(|cx| Pin::new(&mut *udp).poll_flush_message(cx))
                        .await
                        .unwrap();
                    let mut bytes = vec![0; 65535];
                    let mut response = ReadBuf::new(&mut bytes);
                    futures::future::poll_fn(|cx| {
                        Pin::new(&mut *udp).poll_read_message(cx, &mut response)
                    })
                    .await
                    .unwrap();
                    assert_eq!(response.filled(), expected, "UoT response size={size}");
                },
                async {
                    let mut bytes = vec![0; 65535];
                    let (length, source) = server.recv_from(&mut bytes).await.unwrap();
                    assert_eq!(&bytes[..length], payload, "UDP payload size={size}");
                    assert_eq!(server.send_to(&expected, source).await.unwrap(), size);
                }
            );
        }
        assert_eq!(dialer.calls.load(Ordering::Relaxed), 1);
        // A live UoT association must not share its carrier with a TCP request.
        let mut tcp = connect(&handler, &dialer).await;
        tcp.write_all(b"parallel").await.unwrap();
        let mut response = [0; 8];
        tcp.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"parallel");
        assert_eq!(dialer.calls.load(Ordering::Relaxed), 2);
        tcp.shutdown().await.unwrap();
        drop(udp);
        let mut tcp = connect(&handler, &dialer).await;
        tcp.write_all(b"reuse").await.unwrap();
        let mut response = [0; 5];
        tcp.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"reuse");
        assert_eq!(dialer.calls.load(Ordering::Relaxed), 2);
    })
    .await
    .unwrap();
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}
