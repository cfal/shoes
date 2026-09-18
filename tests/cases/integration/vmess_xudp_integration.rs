/// Integration tests for VMess XUDP (UDP-over-TCP) protocol
///
/// Test Architecture:
/// ==================
/// VMess XUDP allows UDP traffic to be multiplexed over a single TCP connection.
/// This is command 0x03 (MUX) in the VMess protocol.
///
/// Test Scenario:
/// ==============
/// Test Client (manual VMess UDP encoding)
///   -> sing-box VMess inbound
///      -> shoes VMess+XUDP Server
///         -> UDP Echo Server (modifies packets)
///
use shoes_test_support as common;

use common::test_fixture::{start_shoes_server, start_singbox_server};
use common::test_servers::start_udp_echo_server;

use std::time::Duration;
use tokio::net::UdpSocket;

const TEST_UUID: &str = "b85798ef-e9dc-46a4-9a87-8da4499d36d0";

/// Test UDP through VMess XUDP using sing-box as client
#[tokio::test]
async fn test_shoes_vmess_xudp_udp_echo() -> Result<(), Box<dyn std::error::Error>> {
    // Allocate random ports
    let mut port_helper = common::port_helper::PortHelper::new();
    let (shoes_vmess_ip, shoes_vmess_port) = port_helper.get_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port(); // UDP server - don't track for TCP readiness check

    eprintln!(
        "[TEST] Using ports: shoes VMess={}, sing-box SOCKS={}, UDP Echo={}",
        shoes_vmess_port, singbox_socks_port, udp_echo_port
    );

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    // shoes VMess server with XUDP enabled
    let shoes_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: vmess
    user_id: "{}"
    cipher: chacha20-poly1305
    udp_enabled: true
"#,
        shoes_vmess_ip, shoes_vmess_port, TEST_UUID
    );

    // sing-box with SOCKS5 inbound -> VMess outbound with xudp
    let singbox_config = format!(
        r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "mixed",
      "tag": "socks-in",
      "listen": "{}",
      "listen_port": {},
      "users": []
    }}
  ],
  "outbounds": [
    {{
      "type": "vmess",
      "tag": "vmess-out",
      "server": "{}",
      "server_port": {},
      "uuid": "{}",
      "security": "chacha20-poly1305",
      "packet_encoding": "xudp"
    }}
  ],
  "route": {{
    "final": "vmess-out"
  }}
}}"#,
        singbox_socks_ip, singbox_socks_port, shoes_vmess_ip, shoes_vmess_port, TEST_UUID
    );

    // Start shoes VMess server
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    // Start sing-box proxy
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for both servers to be ready
    port_helper.wait_for_all_ports().await?;

    // Use netcat through sing-box SOCKS5 proxy to send UDP packet
    eprintln!("[TEST] Sending UDP packet through SOCKS5 proxy...");
    let test_message = b"Hello, VMess XUDP!";

    // Create a test using SOCKS5 UDP associate
    // For simplicity, we'll use a Rust SOCKS5 client
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut socks_stream =
        TcpStream::connect(format!("{}:{}", singbox_socks_ip, singbox_socks_port)).await?;

    // SOCKS5 handshake
    // Send: VER(5) NMETHODS(1) METHODS(0=no auth)
    socks_stream.write_all(&[5, 1, 0]).await?;

    // Receive: VER(5) METHOD(0)
    let mut response = [0u8; 2];
    socks_stream.read_exact(&mut response).await?;
    assert_eq!(response, [5, 0], "SOCKS5 handshake failed");

    // Send UDP ASSOCIATE request
    // VER(5) CMD(3=UDP ASSOCIATE) RSV(0) ATYP(1=IPv4) DST.ADDR(0.0.0.0) DST.PORT(0)
    socks_stream
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await?;

    // Receive response
    let mut udp_response = [0u8; 10];
    socks_stream.read_exact(&mut udp_response).await?;
    assert_eq!(udp_response[0], 5, "SOCKS5 version mismatch");
    assert_eq!(udp_response[1], 0, "UDP ASSOCIATE failed");

    // Extract UDP relay address and port
    let udp_relay_port = u16::from_be_bytes([udp_response[8], udp_response[9]]);
    eprintln!("[TEST] UDP relay port: {}", udp_relay_port);

    // Create UDP socket for sending
    let udp_client = UdpSocket::bind(format!("{}:0", singbox_socks_ip)).await?;

    // Build SOCKS5 UDP packet
    // RSV(2 bytes=0) FRAG(1 byte=0) ATYP(1) DST.ADDR DST.PORT DATA
    let mut udp_packet = Vec::new();
    udp_packet.extend_from_slice(&[0, 0, 0]); // RSV + FRAG
    udp_packet.push(1); // ATYP = IPv4
    // Parse udp_echo_ip into 4 octets
    let udp_echo_ip_parts: Vec<u8> = udp_echo_ip.split('.').map(|s| s.parse().unwrap()).collect();
    udp_packet.extend_from_slice(&udp_echo_ip_parts); // IP address
    udp_packet.extend_from_slice(&udp_echo_port.to_be_bytes()); // port
    udp_packet.extend_from_slice(test_message); // data

    eprintln!(
        "[TEST] Sending UDP packet: {:?}",
        std::str::from_utf8(test_message)
    );
    udp_client
        .send_to(
            &udp_packet,
            format!("{}:{}", singbox_socks_ip, udp_relay_port),
        )
        .await?;

    // Wait for response
    eprintln!("[TEST] Waiting for UDP echo response...");
    let mut recv_buf = vec![0u8; 65536];

    let read_result =
        tokio::time::timeout(Duration::from_secs(5), udp_client.recv_from(&mut recv_buf)).await;

    match read_result {
        Ok(Ok((n, _addr))) => {
            eprintln!("[TEST] Received {} bytes", n);

            // Parse SOCKS5 UDP response header
            // RSV(2) FRAG(1) ATYP(1) SRC.ADDR SRC.PORT DATA
            if n < 10 {
                return Err("Response too short for SOCKS5 UDP header".into());
            }

            // Skip header (RSV + FRAG + ATYP + IPv4 addr + port = 10 bytes)
            let payload = &recv_buf[10..n];
            let response_str = std::str::from_utf8(payload)?;
            eprintln!("[TEST] Response payload: {:?}", response_str);

            // Verify the response contains our original message + " [ECHO]"
            assert!(
                response_str.contains("Hello, VMess XUDP!"),
                "Response should contain original message"
            );
            assert!(
                response_str.ends_with(" [ECHO]"),
                "Response should end with [ECHO] suffix"
            );

            eprintln!("[TEST] ✓ VMess XUDP UDP echo test passed!");
            Ok(())
        }
        Ok(Err(e)) => Err(format!("UDP receive error: {}", e).into()),
        Err(_) => Err("Timeout waiting for UDP response".into()),
    }
}
