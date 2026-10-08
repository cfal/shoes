use std::error::Error;
use std::time::Duration;

use shoes_test_support as common;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use common::process::start_mihomo_server;
use common::socks5::Socks5UdpAssociation;
use common::test_fixture::start_shoes_server;
use common::test_servers::{start_tcp_stream_echo_server, start_udp_echo_server};

async fn roundtrip(version: u8, cipher: &str) -> Result<(), Box<dyn Error>> {
    let mut ports = common::port_helper::PortHelper::new();
    let (server_ip, server_port) = ports.get_listener_port();
    let (client_ip, client_port) = ports.get_localhost_listener_port();
    let tcp_echo = start_tcp_stream_echo_server("127.0.0.1", 0).await?;
    let udp_echo = start_udp_echo_server("127.0.0.1", 0).await?;
    let _server = start_shoes_server(&format!(
        "- address: '{server_ip}:{server_port}'\n  protocol:\n    type: snell\n    cipher: {cipher}\n    password: snell-peer-test\n"
    ))?;
    let _client = start_mihomo_server(&format!(
        "mixed-port: {client_port}\nmode: rule\nproxies:\n  - name: snell\n    type: snell\n    server: {server_ip}\n    port: {server_port}\n    psk: snell-peer-test\n    version: {version}\n    udp: {}\nrules:\n  - MATCH,snell\n", version == 3
    ))
    .await?;
    ports.wait_for_all_ports().await?;

    tokio::time::timeout(Duration::from_secs(10), async {
        let mut stream =
            BufReader::new(TcpStream::connect((client_ip.as_str(), client_port)).await?);
        let destination = tcp_echo.local_addr();
        stream
            .write_all(
                format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n\r\n").as_bytes(),
            )
            .await?;
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        assert!(line.starts_with("HTTP/1.1 200"), "{line}");
        loop {
            line.clear();
            assert_ne!(stream.read_line(&mut line).await?, 0);
            if line == "\r\n" {
                break;
            }
        }
        let payload = b"independent Snell framing";
        stream.write_all(payload).await?;
        let mut response = vec![0; payload.len()];
        stream.read_exact(&mut response).await?;
        assert_eq!(response, payload);
        if version == 3 {
            let association = Socks5UdpAssociation::connect(&client_ip, client_port).await?;
            let response = association.send_to(udp_echo.local_addr(), payload).await?;
            assert_eq!(response, [payload.as_slice(), b" [ECHO]"].concat());
        }
        Ok::<_, Box<dyn Error>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn chacha20_tcp() -> Result<(), Box<dyn Error>> {
    roundtrip(1, "chacha20-ietf-poly1305").await
}

#[tokio::test]
async fn aes128_tcp_and_udp() -> Result<(), Box<dyn Error>> {
    roundtrip(3, "aes-128-gcm").await
}
