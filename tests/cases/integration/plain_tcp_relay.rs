use shoes_test_support::port_helper::PortHelper;
use shoes_test_support::test_fixture::start_shoes_server;
use std::{io, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

async fn headers(socket: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(socket.read_u8().await?);
        assert!(bytes.len() < 4096);
    }
    Ok(bytes)
}

async fn request(socket: &mut TcpStream, protocol: &str, port: u16, data: &[u8]) -> io::Result<()> {
    let mut request = match protocol {
        "socks" => {
            socket.write_all(&[5, 1, 0]).await?;
            let mut method = [0; 2];
            socket.read_exact(&mut method).await?;
            assert_eq!(method, [5, 0]);
            let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
            request.extend_from_slice(&port.to_be_bytes());
            request
        }
        "http" => format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")
            .into_bytes(),
        "forward" => Vec::new(),
        _ => unreachable!(),
    };
    request.extend_from_slice(data);
    socket.write_all(&request).await?;
    match protocol {
        "socks" => {
            let mut response = [0; 10];
            socket.read_exact(&mut response).await?;
            assert_eq!(&response[..4], &[5, 0, 0, 1]);
        }
        "http" => assert!(headers(socket).await?.starts_with(b"HTTP/1.1 200")),
        _ => {}
    }
    Ok(())
}

#[tokio::test]
async fn pipelined_payload_banner_and_delayed_response_after_half_close() -> io::Result<()> {
    timeout(Duration::from_secs(30), async {
        for protocol in ["forward", "socks", "http"] {
            let peer = TcpListener::bind("0.0.0.0:0").await?;
            let peer_port = peer.local_addr()?.port();
            let mut ports = PortHelper::new();
            let (_, port) = ports.get_localhost_listener_port();
            let target = if protocol == "forward" {
                format!("    target: '127.0.0.1:{peer_port}'\n")
            } else {
                String::new()
            };
            let (_process, _config) = start_shoes_server(&format!(
                "- address: '0.0.0.0:{port}'\n  protocol:\n    type: {protocol}\n{target}"
            ))?;
            ports.wait_for_all_ports().await?;
            // A forward listener's readiness probe also connects to its target.
            if protocol == "forward" {
                let (mut probe, _) = peer.accept().await?;
                assert_eq!(probe.read(&mut [0]).await?, 0);
            }
            let data: Vec<_> = (0..1_000_007usize).map(|i| (i ^ (i >> 8)) as u8).collect();
            let server_data = data.clone();
            let server = async {
                let (mut socket, _) = peer.accept().await?;
                socket.write_all(b"banner").await?;
                let mut received = Vec::new();
                socket.read_to_end(&mut received).await?;
                assert_eq!(received, server_data);
                tokio::time::sleep(Duration::from_millis(20)).await;
                socket.write_all(&received).await?;
                socket.shutdown().await
            };
            let client = async {
                let mut socket = TcpStream::connect(("127.0.0.1", port)).await?;
                request(&mut socket, protocol, peer_port, &data[..2048]).await?;
                let mut banner = [0; 6];
                socket.read_exact(&mut banner).await?;
                assert_eq!(&banner, b"banner");
                socket.write_all(&data[2048..]).await?;
                socket.shutdown().await?;
                let mut response = Vec::new();
                socket.read_to_end(&mut response).await?;
                assert_eq!(response, data);
                io::Result::Ok(())
            };
            tokio::try_join!(server, client)?;
        }
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn upstream_handshake_banner_follows_inbound_success_response() -> io::Result<()> {
    timeout(Duration::from_secs(10), async {
        let peer = TcpListener::bind("0.0.0.0:0").await?;
        let peer_port = peer.local_addr()?.port();
        let mut ports = PortHelper::new();
        let (_, port) = ports.get_localhost_listener_port();
        let (_process, _config) = start_shoes_server(&format!(
            r#"
- address: '0.0.0.0:{port}'
  protocol:
    type: socks
  rules:
    - masks: '0.0.0.0/0'
      action: allow
      client_chain:
        - address: '127.0.0.1:{peer_port}'
          protocol:
            type: http
"#
        ))?;
        ports.wait_for_all_ports().await?;
        let server = async {
            let (mut socket, _) = peer.accept().await?;
            assert!(headers(&mut socket).await?.starts_with(b"CONNECT "));
            socket.write_all(b"HTTP/1.1 200 OK\r\n\r\nbanner").await?;
            let mut data = Vec::new();
            socket.read_to_end(&mut data).await?;
            assert_eq!(data, b"payload");
            socket.shutdown().await
        };
        let client = async {
            let mut socket = TcpStream::connect(("127.0.0.1", port)).await?;
            request(&mut socket, "socks", 443, b"payload").await?;
            socket.shutdown().await?;
            let mut data = Vec::new();
            socket.read_to_end(&mut data).await?;
            assert_eq!(data, b"banner");
            io::Result::Ok(())
        };
        tokio::try_join!(server, client)?;
        Ok(())
    })
    .await?
}
