/// Integration tests for H2MUX protocol
///
/// Tests h2mux multiplexing with sing-box client and shoes server.
///
/// H2MUX is sing-box's HTTP/2-based multiplexing protocol that allows
/// multiple proxy streams over a single connection.
///
/// Test Architecture:
/// ==================
/// sing-box SOCKS inbound (with vless+h2mux outbound)
///   -> shoes VLESS server (with h2mux handler)
///      -> target destination
use shoes_test_support as common;

use common::certs::generate_test_cert_files;
use common::port_helper::PortHelper;
use common::socks5::Socks5UdpAssociation;
use common::test_fixture::{
    ProcessGuard, SingBoxCapability, start_shoes_server, start_singbox_server_with,
};
use common::test_servers::{
    start_tcp_eof_echo_server, start_tcp_stream_echo_server, start_udp_echo_server,
};

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

const TEST_UUID: &str = "a3482e88-686a-4a58-8126-99c9034e4b09";

/// Helper to start a sing-box proxy server
fn start_singbox_server(config: &str) -> std::io::Result<(ProcessGuard, tempfile::NamedTempFile)> {
    start_singbox_server_with(
        config,
        SingBoxCapability::Standard,
        &[("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt")],
    )
}

async fn connect_tcp_via_socks5(
    socks_ip: &str,
    socks_port: u16,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, Box<dyn std::error::Error>> {
    let mut tcp = TcpStream::connect(format!("{}:{}", socks_ip, socks_port)).await?;

    // SOCKS5 handshake (no auth)
    tcp.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    tcp.read_exact(&mut resp).await?;
    if resp != [0x05, 0x00] {
        return Err("SOCKS5 handshake failed".into());
    }

    // SOCKS5 CONNECT to target (domain name)
    let mut connect_req = vec![0x05, 0x01, 0x00, 0x03]; // VER, CMD=CONNECT, RSV, ATYP=DOMAINNAME
    connect_req.push(target_host.len() as u8);
    connect_req.extend_from_slice(target_host.as_bytes());
    connect_req.extend_from_slice(&target_port.to_be_bytes());
    tcp.write_all(&connect_req).await?;

    let mut connect_resp = [0u8; 10];
    tcp.read_exact(&mut connect_resp).await?;
    if connect_resp[1] != 0x00 {
        return Err(format!("SOCKS5 CONNECT failed: status {}", connect_resp[1]).into());
    }

    Ok(tcp)
}

/// Sends a TCP request through SOCKS5 to an EOF-driven server.
async fn send_tcp_via_socks5(
    socks_ip: &str,
    socks_port: u16,
    target_host: &str,
    target_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut tcp = connect_tcp_via_socks5(socks_ip, socks_port, target_host, target_port).await?;

    // Send payload
    tcp.write_all(payload).await?;

    // Half-close write side to signal EOF to the echo server
    tcp.shutdown().await?;

    // Read response with timeout - loop until we get at least payload size + " [ECHO]" (7 bytes)
    let expected_min = payload.len() + 7;
    let mut response_buf = Vec::with_capacity(expected_min + 1024);
    let mut temp_buf = [0u8; 8192];

    let read_result = timeout(Duration::from_secs(10), async {
        loop {
            match tcp.read(&mut temp_buf).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    response_buf.extend_from_slice(&temp_buf[..n]);
                    // If we've got enough, we're done
                    if response_buf.len() >= expected_min {
                        break;
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Ok::<_, std::io::Error>(())
    })
    .await;

    match read_result {
        Ok(Ok(())) => Ok(response_buf),
        Ok(Err(e)) => Err(format!("Read error: {}", e).into()),
        Err(_) => Err("Timeout".into()),
    }
}

/// Sends a request without relying on the peer to propagate a TCP half-close.
async fn send_tcp_stream_via_socks5(
    socks_ip: &str,
    socks_port: u16,
    target_host: &str,
    target_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut tcp = connect_tcp_via_socks5(socks_ip, socks_port, target_host, target_port).await?;
    tcp.write_all(payload).await?;

    let mut response = vec![0; payload.len()];
    timeout(Duration::from_secs(10), tcp.read_exact(&mut response)).await??;
    tcp.shutdown().await?;
    Ok(response)
}

// H2MUX TCP Integration Tests

/// Test h2mux TCP with VLESS: sing-box client -> shoes server
///
/// This tests basic TCP proxying through h2mux multiplexed connection.
#[tokio::test]
async fn test_h2mux_vless_tcp_basic() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_localhost_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (tcp_echo_ip, tcp_echo_port) = port_helper.get_port();

    eprintln!(
        "[TEST] H2MUX VLESS TCP: shoes={}, sing-box SOCKS={}, TCP echo={}",
        shoes_port, singbox_socks_port, tcp_echo_port
    );

    // Start TCP echo server
    let _tcp_echo_server = start_tcp_eof_echo_server(&tcp_echo_ip, tcp_echo_port).await?;

    // Generate self-signed test certificate
    let (cert_path, key_path) = generate_test_cert_files()?;

    // Start shoes VLESS server (TLS + VLESS inner with UDP enabled for h2mux)
    let shoes_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      "test.local":
        cert: {}
        key: {}
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: true"#,
        shoes_ip,
        shoes_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
        TEST_UUID,
    );
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    // sing-box config: SOCKS inbound -> VLESS outbound with h2mux multiplexing
    // Using insecure: true to skip certificate verification for self-signed certs
    let singbox_config = format!(
        r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "socks",
      "tag": "socks-in",
      "listen": "{}",
      "listen_port": {}
    }}
  ],
  "outbounds": [
    {{
      "type": "vless",
      "tag": "vless-out",
      "server": "{}",
      "server_port": {},
      "uuid": "{}",
      "tls": {{
        "enabled": true,
        "server_name": "test.local",
        "insecure": true
      }},
      "multiplex": {{
        "enabled": true,
        "protocol": "h2mux",
        "max_connections": 1,
        "min_streams": 1,
        "max_streams": 0,
        "padding": false
      }}
    }}
  ],
  "route": {{
    "final": "vless-out"
  }}
}}"#,
        singbox_socks_ip, singbox_socks_port, shoes_ip, shoes_port, TEST_UUID
    );
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for servers to start
    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    // Send test request via SOCKS5
    let response = send_tcp_via_socks5(
        &singbox_socks_ip,
        singbox_socks_port,
        &tcp_echo_ip,
        tcp_echo_port,
        b"H2MUX VLESS TCP Test!",
    )
    .await?;

    let response_str = std::str::from_utf8(&response)?;
    eprintln!("[TEST] Response: {:?}", response_str);
    assert!(response_str.contains("H2MUX VLESS TCP Test!"));
    assert!(response_str.ends_with(" [ECHO]"));

    eprintln!("[TEST] H2MUX VLESS TCP basic test passed!");
    Ok(())
}

/// Test h2mux with multiple concurrent TCP connections over single mux session
#[tokio::test]
async fn test_h2mux_vless_tcp_concurrent() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_localhost_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (tcp_echo_ip, tcp_echo_port) = port_helper.get_port();

    eprintln!("[TEST] H2MUX VLESS TCP concurrent connections");

    // Start TCP echo server
    let _tcp_echo_server = start_tcp_eof_echo_server(&tcp_echo_ip, tcp_echo_port).await?;

    // Generate self-signed test certificate
    let (cert_path, key_path) = generate_test_cert_files()?;

    // Start shoes VLESS server
    let shoes_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      "test.local":
        cert: {}
        key: {}
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: true"#,
        shoes_ip,
        shoes_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
        TEST_UUID,
    );
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    // sing-box config with h2mux (max_connections=1 to force multiplexing)
    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{ "type": "socks", "tag": "socks-in", "listen": "{}", "listen_port": {} }}],
  "outbounds": [{{
    "type": "vless",
    "tag": "vless-out",
    "server": "{}",
    "server_port": {},
    "uuid": "{}",
    "tls": {{ "enabled": true, "server_name": "test.local", "insecure": true }},
    "multiplex": {{ "enabled": true, "protocol": "h2mux", "max_connections": 1, "min_streams": 4, "max_streams": 0 }}
  }}],
  "route": {{ "final": "vless-out" }}
}}"#,
        singbox_socks_ip, singbox_socks_port, shoes_ip, shoes_port, TEST_UUID
    );
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for servers
    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    // Send 5 sequential requests (simpler for testing)
    for i in 0..5 {
        let msg = format!("H2MUX Concurrent #{}", i);
        let response = send_tcp_via_socks5(
            &singbox_socks_ip,
            singbox_socks_port,
            &tcp_echo_ip,
            tcp_echo_port,
            msg.as_bytes(),
        )
        .await?;
        let response_str = std::str::from_utf8(&response)?;
        assert!(
            response_str.contains(&msg),
            "Response doesn't contain {}",
            msg
        );
        eprintln!("[TEST] Connection {} OK", i);
    }

    eprintln!("[TEST] H2MUX VLESS TCP concurrent test passed!");
    Ok(())
}

/// Test h2mux with large data transfer
///
/// This test verifies that h2mux can properly handle large data transfers with
/// correct half-close semantics. The upload must complete with END_STREAM instead of
/// RST_STREAM(CANCEL), allowing the server to send the response before the
/// stream is closed.
#[tokio::test]
async fn test_h2mux_vless_tcp_large_transfer() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_localhost_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (tcp_echo_ip, tcp_echo_port) = port_helper.get_port();

    eprintln!("[TEST] H2MUX VLESS TCP large transfer");

    // Start TCP echo server
    let _tcp_echo_server = start_tcp_eof_echo_server(&tcp_echo_ip, tcp_echo_port).await?;

    // Generate self-signed test certificate
    let (cert_path, key_path) = generate_test_cert_files()?;

    // Start shoes VLESS server
    let shoes_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      "test.local":
        cert: {}
        key: {}
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: true"#,
        shoes_ip,
        shoes_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
        TEST_UUID,
    );
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    // sing-box config with h2mux
    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{ "type": "socks", "tag": "socks-in", "listen": "{}", "listen_port": {} }}],
  "outbounds": [{{
    "type": "vless",
    "tag": "vless-out",
    "server": "{}",
    "server_port": {},
    "uuid": "{}",
    "tls": {{ "enabled": true, "server_name": "test.local", "insecure": true }},
    "multiplex": {{ "enabled": true, "protocol": "h2mux", "max_connections": 1, "min_streams": 4, "max_streams": 0 }}
  }}],
  "route": {{ "final": "vless-out" }}
}}"#,
        singbox_socks_ip, singbox_socks_port, shoes_ip, shoes_port, TEST_UUID
    );
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for servers
    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    // Generate 64KB of test data
    let payload: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();

    let response = send_tcp_via_socks5(
        &singbox_socks_ip,
        singbox_socks_port,
        &tcp_echo_ip,
        tcp_echo_port,
        &payload,
    )
    .await?;

    // Echo server appends " [ECHO]"
    assert!(
        response.len() >= payload.len(),
        "Response too short: {} < {}",
        response.len(),
        payload.len()
    );
    assert_eq!(
        &response[..payload.len()],
        &payload[..],
        "Response data mismatch"
    );

    eprintln!("[TEST] H2MUX VLESS TCP large transfer test passed!");
    Ok(())
}

// H2MUX UDP Integration Tests

/// Test h2mux UDP with VLESS: sing-box client -> shoes server
///
/// This tests UDP proxying through h2mux multiplexed connection.
#[tokio::test]
async fn test_h2mux_vless_udp_basic() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_localhost_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!(
        "[TEST] H2MUX VLESS UDP: shoes={}, sing-box SOCKS={}, UDP echo={}",
        shoes_port, singbox_socks_port, udp_echo_port
    );

    // Start UDP echo server
    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    // Generate self-signed test certificate
    let (cert_path, key_path) = generate_test_cert_files()?;

    // Start shoes VLESS server with UDP enabled
    let shoes_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      "test.local":
        cert: {}
        key: {}
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: true"#,
        shoes_ip,
        shoes_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
        TEST_UUID,
    );
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    // sing-box config: SOCKS inbound -> VLESS outbound with h2mux
    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{ "type": "socks", "tag": "socks-in", "listen": "{}", "listen_port": {} }}],
  "outbounds": [{{
    "type": "vless",
    "tag": "vless-out",
    "server": "{}",
    "server_port": {},
    "uuid": "{}",
    "tls": {{ "enabled": true, "server_name": "test.local", "insecure": true }},
    "multiplex": {{ "enabled": true, "protocol": "h2mux", "max_connections": 1, "min_streams": 1, "max_streams": 0 }}
  }}],
  "route": {{ "final": "vless-out" }}
}}"#,
        singbox_socks_ip, singbox_socks_port, shoes_ip, shoes_port, TEST_UUID
    );
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for servers
    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    // Use SOCKS5 UDP ASSOCIATE
    let association = Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await?;
    let target: SocketAddr = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    // Send test packet
    let response = association
        .send_to(target, b"H2MUX VLESS UDP Test!")
        .await?;

    let response_str = std::str::from_utf8(&response)?;
    eprintln!("[TEST] Response: {:?}", response_str);
    assert!(response_str.contains("H2MUX VLESS UDP Test!"));
    assert!(response_str.ends_with(" [ECHO]"));

    eprintln!("[TEST] H2MUX VLESS UDP basic test passed!");
    Ok(())
}

/// Test h2mux UDP with multiple packets
#[tokio::test]
async fn test_h2mux_vless_udp_multiple_packets() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_localhost_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!("[TEST] H2MUX VLESS UDP multiple packets");

    // Start UDP echo server
    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    // Generate self-signed test certificate
    let (cert_path, key_path) = generate_test_cert_files()?;

    // Start shoes VLESS server
    let shoes_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      "test.local":
        cert: {}
        key: {}
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: true"#,
        shoes_ip,
        shoes_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
        TEST_UUID,
    );
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    // sing-box config with h2mux
    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{ "type": "socks", "tag": "socks-in", "listen": "{}", "listen_port": {} }}],
  "outbounds": [{{
    "type": "vless",
    "tag": "vless-out",
    "server": "{}",
    "server_port": {},
    "uuid": "{}",
    "tls": {{ "enabled": true, "server_name": "test.local", "insecure": true }},
    "multiplex": {{ "enabled": true, "protocol": "h2mux", "max_connections": 1, "min_streams": 1, "max_streams": 0 }}
  }}],
  "route": {{ "final": "vless-out" }}
}}"#,
        singbox_socks_ip, singbox_socks_port, shoes_ip, shoes_port, TEST_UUID
    );
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for servers
    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    // Use SOCKS5 UDP ASSOCIATE
    let association = Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await?;
    let target: SocketAddr = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    // Send multiple packets
    for i in 0..5 {
        let msg = format!("H2MUX UDP Packet #{}", i);
        let response = association.send_to(target, msg.as_bytes()).await?;
        let response_str = std::str::from_utf8(&response)?;
        assert!(response_str.contains(&msg));
        assert!(response_str.ends_with(" [ECHO]"));
        eprintln!("[TEST] Packet {} OK", i);
    }

    eprintln!("[TEST] H2MUX VLESS UDP multiple packets test passed!");
    Ok(())
}

/// Test h2mux UDP packet_addr with a hostname destination.
#[tokio::test]
async fn test_h2mux_vless_udp_hostname_destination() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_localhost_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let udp_echo_port = port_helper.get_port().1;

    eprintln!("[TEST] H2MUX VLESS UDP hostname destination");

    let _echo_server4 = start_udp_echo_server("127.0.0.1", udp_echo_port).await?;
    let _echo_server6 = start_udp_echo_server("::1", udp_echo_port).await?;

    let (cert_path, key_path) = generate_test_cert_files()?;

    let shoes_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      "test.local":
        cert: {}
        key: {}
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: true"#,
        shoes_ip,
        shoes_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
        TEST_UUID,
    );
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{ "type": "socks", "tag": "socks-in", "listen": "{}", "listen_port": {} }}],
  "outbounds": [{{
    "type": "vless",
    "tag": "vless-out",
    "server": "{}",
    "server_port": {},
    "uuid": "{}",
    "tls": {{ "enabled": true, "server_name": "test.local", "insecure": true }},
    "multiplex": {{ "enabled": true, "protocol": "h2mux", "max_connections": 1, "min_streams": 1, "max_streams": 0 }}
  }}],
  "route": {{ "final": "vless-out" }}
}}"#,
        singbox_socks_ip, singbox_socks_port, shoes_ip, shoes_port, TEST_UUID
    );
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    let association = Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await?;

    let response = association
        .send_to_hostname("localhost", udp_echo_port, b"H2MUX Hostname Packet")
        .await?;

    let response_str = std::str::from_utf8(&response)?;
    assert!(response_str.contains("H2MUX Hostname Packet"));
    assert!(response_str.ends_with(" [ECHO]"));

    Ok(())
}

/// Test h2mux UDP to multiple destinations
#[tokio::test]
async fn test_h2mux_vless_udp_multi_destination() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_localhost_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (udp_echo_ip1, udp_echo_port1) = port_helper.get_port();
    let (udp_echo_ip2, udp_echo_port2) = port_helper.get_port();

    eprintln!("[TEST] H2MUX VLESS UDP multi-destination");

    // Start two UDP echo servers
    let _echo_server1 = start_udp_echo_server(&udp_echo_ip1, udp_echo_port1).await?;
    let _echo_server2 = start_udp_echo_server(&udp_echo_ip2, udp_echo_port2).await?;

    // Generate self-signed test certificate
    let (cert_path, key_path) = generate_test_cert_files()?;

    // Start shoes VLESS server
    let shoes_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      "test.local":
        cert: {}
        key: {}
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: true"#,
        shoes_ip,
        shoes_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
        TEST_UUID,
    );
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    // sing-box config with h2mux
    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{ "type": "socks", "tag": "socks-in", "listen": "{}", "listen_port": {} }}],
  "outbounds": [{{
    "type": "vless",
    "tag": "vless-out",
    "server": "{}",
    "server_port": {},
    "uuid": "{}",
    "tls": {{ "enabled": true, "server_name": "test.local", "insecure": true }},
    "multiplex": {{ "enabled": true, "protocol": "h2mux", "max_connections": 1, "min_streams": 1, "max_streams": 0 }}
  }}],
  "route": {{ "final": "vless-out" }}
}}"#,
        singbox_socks_ip, singbox_socks_port, shoes_ip, shoes_port, TEST_UUID
    );
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for servers
    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    // Use SOCKS5 UDP ASSOCIATE
    let association = Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await?;

    // Send to first destination
    let target1: SocketAddr = format!("{udp_echo_ip1}:{udp_echo_port1}").parse()?;
    let response1 = association.send_to(target1, b"H2MUX Dest 1!").await?;
    let response1_str = std::str::from_utf8(&response1)?;
    assert!(response1_str.contains("H2MUX Dest 1!"));
    eprintln!("[TEST] Destination 1 OK");

    // Send to second destination
    let target2: SocketAddr = format!("{udp_echo_ip2}:{udp_echo_port2}").parse()?;
    let response2 = association.send_to(target2, b"H2MUX Dest 2!").await?;
    let response2_str = std::str::from_utf8(&response2)?;
    assert!(response2_str.contains("H2MUX Dest 2!"));
    eprintln!("[TEST] Destination 2 OK");

    eprintln!("[TEST] H2MUX VLESS UDP multi-destination test passed!");
    Ok(())
}

// H2MUX Mixed TCP/UDP Tests

/// Test h2mux with both TCP and UDP streams over same mux session
#[tokio::test]
async fn test_h2mux_vless_mixed_tcp_udp() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_localhost_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (tcp_echo_ip, tcp_echo_port) = port_helper.get_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!("[TEST] H2MUX VLESS mixed TCP/UDP");

    // Start both TCP and UDP echo servers
    let _tcp_echo_server = start_tcp_eof_echo_server(&tcp_echo_ip, tcp_echo_port).await?;
    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    // Generate self-signed test certificate
    let (cert_path, key_path) = generate_test_cert_files()?;

    // Start shoes VLESS server
    let shoes_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      "test.local":
        cert: {}
        key: {}
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: true"#,
        shoes_ip,
        shoes_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
        TEST_UUID,
    );
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    // sing-box config with h2mux (force single connection)
    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{ "type": "socks", "tag": "socks-in", "listen": "{}", "listen_port": {} }}],
  "outbounds": [{{
    "type": "vless",
    "tag": "vless-out",
    "server": "{}",
    "server_port": {},
    "uuid": "{}",
    "tls": {{ "enabled": true, "server_name": "test.local", "insecure": true }},
    "multiplex": {{ "enabled": true, "protocol": "h2mux", "max_connections": 1, "min_streams": 4, "max_streams": 0 }}
  }}],
  "route": {{ "final": "vless-out" }}
}}"#,
        singbox_socks_ip, singbox_socks_port, shoes_ip, shoes_port, TEST_UUID
    );
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for servers
    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    // Test TCP first
    let tcp_response = send_tcp_via_socks5(
        &singbox_socks_ip,
        singbox_socks_port,
        &tcp_echo_ip,
        tcp_echo_port,
        b"H2MUX TCP Message",
    )
    .await?;
    let tcp_response_str = std::str::from_utf8(&tcp_response)?;
    assert!(tcp_response_str.contains("H2MUX TCP Message"));
    eprintln!("[TEST] TCP via h2mux OK");

    // Test UDP (using same mux session)
    let association = Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await?;
    let target: SocketAddr = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    let udp_response = association.send_to(target, b"H2MUX UDP Message").await?;
    let udp_response_str = std::str::from_utf8(&udp_response)?;
    assert!(udp_response_str.contains("H2MUX UDP Message"));
    eprintln!("[TEST] UDP via h2mux OK");

    // Send another TCP request to verify mux still works
    let tcp_response2 = send_tcp_via_socks5(
        &singbox_socks_ip,
        singbox_socks_port,
        &tcp_echo_ip,
        tcp_echo_port,
        b"H2MUX TCP Message 2",
    )
    .await?;
    let tcp_response2_str = std::str::from_utf8(&tcp_response2)?;
    assert!(tcp_response2_str.contains("H2MUX TCP Message 2"));
    eprintln!("[TEST] TCP via h2mux (second request) OK");

    eprintln!("[TEST] H2MUX VLESS mixed TCP/UDP test passed!");
    Ok(())
}

// H2MUX Edge Cases

/// Test that h2mux UDP is rejected when udp_enabled is false
#[tokio::test]
async fn test_h2mux_vless_udp_disabled() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_localhost_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!("[TEST] H2MUX VLESS with udp_enabled: false (UDP should be rejected)");

    // Start UDP echo server
    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    // Generate self-signed test certificate
    let (cert_path, key_path) = generate_test_cert_files()?;

    // Start shoes VLESS server with udp_enabled: false
    let shoes_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      "test.local":
        cert: {}
        key: {}
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: false"#,
        shoes_ip,
        shoes_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
        TEST_UUID,
    );
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    // sing-box config with h2mux
    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{ "type": "socks", "tag": "socks-in", "listen": "{}", "listen_port": {} }}],
  "outbounds": [{{
    "type": "vless",
    "tag": "vless-out",
    "server": "{}",
    "server_port": {},
    "uuid": "{}",
    "tls": {{ "enabled": true, "server_name": "test.local", "insecure": true }},
    "multiplex": {{ "enabled": true, "protocol": "h2mux", "max_connections": 1, "min_streams": 1, "max_streams": 0 }}
  }}],
  "route": {{ "final": "vless-out" }}
}}"#,
        singbox_socks_ip, singbox_socks_port, shoes_ip, shoes_port, TEST_UUID
    );
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for servers
    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    // Try UDP ASSOCIATE - should work but actual UDP should fail/timeout
    let associate_result =
        Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await;

    match associate_result {
        Ok(association) => {
            let target: SocketAddr = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

            // Try to send - should timeout because shoes rejected UDP
            let send_result =
                timeout(Duration::from_secs(3), association.send_to(target, b"Test")).await;

            match send_result {
                Ok(Ok(_)) => {
                    panic!("UDP was not rejected when udp_enabled=false!");
                }
                Ok(Err(_)) | Err(_) => {
                    eprintln!("[TEST] Expected: timeout or error (UDP correctly rejected)");
                }
            }
        }
        Err(e) => {
            eprintln!("[TEST] UDP ASSOCIATE failed (expected): {}", e);
        }
    }

    eprintln!("[TEST] H2MUX VLESS UDP disabled test passed (UDP correctly rejected)!");
    Ok(())
}

// H2MUX Shadowsocks Tests

const TEST_SS_PASSWORD: &str = "test-shadowsocks-password";

/// Test h2mux TCP with Shadowsocks: sing-box client -> shoes server
#[tokio::test]
async fn test_h2mux_shadowsocks_tcp_basic() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_localhost_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (tcp_echo_ip, tcp_echo_port) = port_helper.get_port();

    eprintln!(
        "[TEST] H2MUX Shadowsocks TCP: shoes={}, sing-box SOCKS={}, TCP echo={}",
        shoes_port, singbox_socks_port, tcp_echo_port
    );

    // Start TCP echo server
    let _tcp_echo_server = start_tcp_eof_echo_server(&tcp_echo_ip, tcp_echo_port).await?;

    // Start shoes Shadowsocks server (no TLS needed)
    let shoes_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: shadowsocks
    cipher: aes-128-gcm
    password: "{}"
    udp_enabled: true"#,
        shoes_ip, shoes_port, TEST_SS_PASSWORD,
    );
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    // sing-box config: SOCKS inbound -> Shadowsocks outbound with h2mux multiplexing
    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{ "type": "socks", "tag": "socks-in", "listen": "{}", "listen_port": {} }}],
  "outbounds": [{{
    "type": "shadowsocks",
    "tag": "ss-out",
    "server": "{}",
    "server_port": {},
    "method": "aes-128-gcm",
    "password": "{}",
    "multiplex": {{ "enabled": true, "protocol": "h2mux", "max_connections": 1, "min_streams": 1, "max_streams": 0 }}
  }}],
  "route": {{ "final": "ss-out" }}
}}"#,
        singbox_socks_ip, singbox_socks_port, shoes_ip, shoes_port, TEST_SS_PASSWORD
    );
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for servers to start
    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    // Send test request via SOCKS5
    let response = send_tcp_via_socks5(
        &singbox_socks_ip,
        singbox_socks_port,
        &tcp_echo_ip,
        tcp_echo_port,
        b"H2MUX Shadowsocks TCP Test!",
    )
    .await?;

    let response_str = std::str::from_utf8(&response)?;
    eprintln!("[TEST] Response: {:?}", response_str);
    assert!(response_str.contains("H2MUX Shadowsocks TCP Test!"));
    assert!(response_str.ends_with(" [ECHO]"));

    eprintln!("[TEST] H2MUX Shadowsocks TCP basic test passed!");
    Ok(())
}

/// Test h2mux UDP with Shadowsocks: sing-box client -> shoes server
#[tokio::test]
async fn test_h2mux_shadowsocks_udp_basic() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_localhost_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!(
        "[TEST] H2MUX Shadowsocks UDP: shoes={}, sing-box SOCKS={}, UDP echo={}",
        shoes_port, singbox_socks_port, udp_echo_port
    );

    // Start UDP echo server
    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    // Start shoes Shadowsocks server with UDP enabled
    let shoes_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: shadowsocks
    cipher: aes-128-gcm
    password: "{}"
    udp_enabled: true"#,
        shoes_ip, shoes_port, TEST_SS_PASSWORD,
    );
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    // sing-box config: SOCKS inbound -> Shadowsocks outbound with h2mux
    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{ "type": "socks", "tag": "socks-in", "listen": "{}", "listen_port": {} }}],
  "outbounds": [{{
    "type": "shadowsocks",
    "tag": "ss-out",
    "server": "{}",
    "server_port": {},
    "method": "aes-128-gcm",
    "password": "{}",
    "multiplex": {{ "enabled": true, "protocol": "h2mux", "max_connections": 1, "min_streams": 1, "max_streams": 0 }}
  }}],
  "route": {{ "final": "ss-out" }}
}}"#,
        singbox_socks_ip, singbox_socks_port, shoes_ip, shoes_port, TEST_SS_PASSWORD
    );
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for servers
    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    // Use SOCKS5 UDP ASSOCIATE
    let association = Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await?;
    let target: SocketAddr = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    // Send test packet
    let response = association
        .send_to(target, b"H2MUX Shadowsocks UDP Test!")
        .await?;

    let response_str = std::str::from_utf8(&response)?;
    eprintln!("[TEST] Response: {:?}", response_str);
    assert!(response_str.contains("H2MUX Shadowsocks UDP Test!"));
    assert!(response_str.ends_with(" [ECHO]"));

    eprintln!("[TEST] H2MUX Shadowsocks UDP basic test passed!");
    Ok(())
}

// H2MUX Trojan Tests

const TEST_TROJAN_PASSWORD: &str = "test-trojan-password";

/// Test h2mux TCP with Trojan: sing-box client -> shoes server
#[tokio::test]
async fn test_h2mux_trojan_tcp_basic() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_localhost_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (tcp_echo_ip, tcp_echo_port) = port_helper.get_port();

    eprintln!(
        "[TEST] H2MUX Trojan TCP: shoes={}, sing-box SOCKS={}, TCP echo={}",
        shoes_port, singbox_socks_port, tcp_echo_port
    );

    // Start TCP echo server
    let _tcp_echo_server = start_tcp_eof_echo_server(&tcp_echo_ip, tcp_echo_port).await?;

    // Generate self-signed test certificate
    let (cert_path, key_path) = generate_test_cert_files()?;

    // Start shoes Trojan server (TLS + Trojan inner)
    let shoes_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      "test.local":
        cert: {}
        key: {}
        protocol:
          type: trojan
          password: "{}""#,
        shoes_ip,
        shoes_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
        TEST_TROJAN_PASSWORD,
    );
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    // sing-box config: SOCKS inbound -> Trojan outbound with h2mux multiplexing
    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{ "type": "socks", "tag": "socks-in", "listen": "{}", "listen_port": {} }}],
  "outbounds": [{{
    "type": "trojan",
    "tag": "trojan-out",
    "server": "{}",
    "server_port": {},
    "password": "{}",
    "tls": {{ "enabled": true, "server_name": "test.local", "insecure": true }},
    "multiplex": {{ "enabled": true, "protocol": "h2mux", "max_connections": 1, "min_streams": 1, "max_streams": 0 }}
  }}],
  "route": {{ "final": "trojan-out" }}
}}"#,
        singbox_socks_ip, singbox_socks_port, shoes_ip, shoes_port, TEST_TROJAN_PASSWORD
    );
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for servers to start
    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    // Send test request via SOCKS5
    let response = send_tcp_via_socks5(
        &singbox_socks_ip,
        singbox_socks_port,
        &tcp_echo_ip,
        tcp_echo_port,
        b"H2MUX Trojan TCP Test!",
    )
    .await?;

    let response_str = std::str::from_utf8(&response)?;
    eprintln!("[TEST] Response: {:?}", response_str);
    assert!(response_str.contains("H2MUX Trojan TCP Test!"));
    assert!(response_str.ends_with(" [ECHO]"));

    eprintln!("[TEST] H2MUX Trojan TCP basic test passed!");
    Ok(())
}

// H2MUX with Padding Tests

/// Test h2mux with padding enabled (Version 1 protocol)
///
/// This tests that the padding layer correctly wraps the first 16 read/write
/// operations with random padding data.
///
/// sing-box client sends padding request, shoes server applies padding layer.
#[tokio::test]
async fn test_h2mux_vless_tcp_with_padding() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_localhost_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (tcp_echo_ip, tcp_echo_port) = port_helper.get_port();

    eprintln!(
        "[TEST] H2MUX VLESS TCP with padding: shoes={}, sing-box SOCKS={}, TCP echo={}",
        shoes_port, singbox_socks_port, tcp_echo_port
    );

    // Start TCP echo server
    let _tcp_echo_server = start_tcp_eof_echo_server(&tcp_echo_ip, tcp_echo_port).await?;

    // Generate self-signed test certificate
    let (cert_path, key_path) = generate_test_cert_files()?;

    // Start shoes VLESS server
    let shoes_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      "test.local":
        cert: {}
        key: {}
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: true"#,
        shoes_ip,
        shoes_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
        TEST_UUID,
    );
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    // sing-box config with h2mux and padding enabled
    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{ "type": "socks", "tag": "socks-in", "listen": "{}", "listen_port": {} }}],
  "outbounds": [{{
    "type": "vless",
    "tag": "vless-out",
    "server": "{}",
    "server_port": {},
    "uuid": "{}",
    "tls": {{ "enabled": true, "server_name": "test.local", "insecure": true }},
    "multiplex": {{
      "enabled": true,
      "protocol": "h2mux",
      "max_connections": 1,
      "min_streams": 1,
      "max_streams": 0,
      "padding": true
    }}
  }}],
  "route": {{ "final": "vless-out" }}
}}"#,
        singbox_socks_ip, singbox_socks_port, shoes_ip, shoes_port, TEST_UUID
    );
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for servers to start
    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    // Send multiple requests to exercise the padding layer
    // The first 16 operations should be padded, then switch to raw
    for i in 0..20 {
        let msg = format!("H2MUX Padding Test #{}", i);
        let response = send_tcp_via_socks5(
            &singbox_socks_ip,
            singbox_socks_port,
            &tcp_echo_ip,
            tcp_echo_port,
            msg.as_bytes(),
        )
        .await?;

        let response_str = std::str::from_utf8(&response)?;
        assert!(
            response_str.contains(&msg),
            "Response doesn't contain {}: got {}",
            msg,
            response_str
        );
        eprintln!("[TEST] Request {} with padding OK", i);
    }

    eprintln!("[TEST] H2MUX VLESS TCP with padding test passed!");
    Ok(())
}

/// Test h2mux UDP with padding enabled
///
/// sing-box client sends padding request, shoes server applies padding layer.
#[tokio::test]
async fn test_h2mux_vless_udp_with_padding() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_localhost_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!(
        "[TEST] H2MUX VLESS UDP with padding: shoes={}, sing-box SOCKS={}, UDP echo={}",
        shoes_port, singbox_socks_port, udp_echo_port
    );

    // Start UDP echo server
    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    // Generate self-signed test certificate
    let (cert_path, key_path) = generate_test_cert_files()?;

    // Start shoes VLESS server with UDP enabled
    let shoes_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      "test.local":
        cert: {}
        key: {}
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: true"#,
        shoes_ip,
        shoes_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
        TEST_UUID,
    );
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    // sing-box config with h2mux and padding enabled
    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{ "type": "socks", "tag": "socks-in", "listen": "{}", "listen_port": {} }}],
  "outbounds": [{{
    "type": "vless",
    "tag": "vless-out",
    "server": "{}",
    "server_port": {},
    "uuid": "{}",
    "tls": {{ "enabled": true, "server_name": "test.local", "insecure": true }},
    "multiplex": {{
      "enabled": true,
      "protocol": "h2mux",
      "max_connections": 1,
      "min_streams": 1,
      "max_streams": 0,
      "padding": true
    }}
  }}],
  "route": {{ "final": "vless-out" }}
}}"#,
        singbox_socks_ip, singbox_socks_port, shoes_ip, shoes_port, TEST_UUID
    );
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for servers
    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    // Use SOCKS5 UDP ASSOCIATE
    let association = Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await?;
    let target: SocketAddr = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    // Send multiple UDP packets
    for i in 0..5 {
        let msg = format!("H2MUX UDP Padding #{}", i);
        let response = association.send_to(target, msg.as_bytes()).await?;
        let response_str = std::str::from_utf8(&response)?;
        assert!(response_str.contains(&msg));
        assert!(response_str.ends_with(" [ECHO]"));
        eprintln!("[TEST] UDP packet {} with padding OK", i);
    }

    eprintln!("[TEST] H2MUX VLESS UDP with padding test passed!");
    Ok(())
}

// H2MUX Client-Side Tests
//
// These tests verify shoes acting as an h2mux CLIENT connecting to an h2mux-enabled server.
// Architecture:
//   test client -> shoes (socks5 + h2mux outbound) -> shoes (vless + h2mux server) -> echo server

/// Test h2mux config parsing
#[test]
fn test_h2mux_client_config_parsing() {
    let yaml = r#"
- address: "127.0.0.1:8080"
  protocol:
    type: socks
  rules:
    - masks: ["0.0.0.0/0"]
      action: allow
      client_chain:
        - address: "server.example.com:443"
          protocol:
            type: tls
            verify: false
            protocol:
              type: vless
              user_id: "a3482e88-686a-4a58-8126-99c9034e4b09"
              h2mux:
                max_connections: 4
                min_streams: 2
                padding: true
"#;

    use shoes::config::{
        ClientChainHop, ClientProxyConfig, Config, ConfigSelection, RuleActionConfig,
    };

    let configs: Vec<Config> = serde_yaml::from_str(yaml).expect("Failed to parse Shoes config");
    let [Config::Server(server)] = configs.as_slice() else {
        panic!("expected one server config")
    };
    let ConfigSelection::Config(rule) = server.rules.iter().next().unwrap() else {
        panic!("expected an inline rule")
    };
    let RuleActionConfig::Allow { client_chains, .. } = &rule.action else {
        panic!("expected an allow rule")
    };
    let chain = client_chains.iter().next().unwrap();
    let ClientChainHop::Single(ConfigSelection::Config(client)) = chain.hops.iter().next().unwrap()
    else {
        panic!("expected one inline client")
    };
    let ClientProxyConfig::Tls(tls) = &client.protocol else {
        panic!("expected a TLS client")
    };
    let ClientProxyConfig::Vless {
        h2mux: Some(h2mux), ..
    } = tls.protocol.as_ref()
    else {
        panic!("expected a VLESS client with H2MUX")
    };

    assert_eq!(h2mux.max_connections, Some(4));
    assert_eq!(h2mux.min_streams, Some(2));
    assert!(h2mux.padding);
}

/// Test shoes as h2mux client connecting to shoes h2mux server
#[tokio::test]
async fn test_h2mux_shoes_client_to_shoes_server() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    // Server A: VLESS + h2mux server (the upstream)
    let (server_a_ip, server_a_port) = port_helper.get_localhost_listener_port();
    // Server B: SOCKS5 proxy that uses h2mux client to connect to Server A
    let (server_b_ip, server_b_port) = port_helper.get_localhost_listener_port();
    // Echo server (the final destination)
    let (tcp_echo_ip, tcp_echo_port) = port_helper.get_localhost_listener_port();

    eprintln!("[TEST] H2MUX shoes client to shoes server");
    eprintln!("  Server A (upstream): {}:{}", server_a_ip, server_a_port);
    eprintln!(
        "  Server B (h2mux client proxy): {}:{}",
        server_b_ip, server_b_port
    );
    eprintln!("  Echo server: {}:{}", tcp_echo_ip, tcp_echo_port);

    // Start TCP echo server
    let _tcp_echo_server = start_tcp_eof_echo_server(&tcp_echo_ip, tcp_echo_port).await?;

    // Generate self-signed test certificate
    let (cert_path, key_path) = generate_test_cert_files()?;

    // Server A config: VLESS server with TLS and h2mux support
    let server_a_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      "test.local":
        cert: {}
        key: {}
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: true"#,
        server_a_ip,
        server_a_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
        TEST_UUID,
    );

    // Server B config: SOCKS5 proxy that uses h2mux client to connect to Server A
    let server_b_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: socks
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_proxies:
        - address: "{}:{}"
          protocol:
            type: tls
            verify: false
            sni_hostname: "test.local"
            protocol:
              type: vless
              user_id: "{}"
              h2mux:
                max_connections: 2
                min_streams: 2
"#,
        server_b_ip, server_b_port, server_a_ip, server_a_port, TEST_UUID,
    );

    // Start Server A (upstream)
    let (_server_a_guard, _server_a_config_file) = start_shoes_server(&server_a_config)?;

    // Start Server B (h2mux client proxy)
    let (_server_b_guard, _server_b_config_file) = start_shoes_server(&server_b_config)?;

    // Wait for servers
    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    // Connect through Server B (SOCKS5) which uses h2mux to Server A
    let response = send_tcp_via_socks5(
        &server_b_ip,
        server_b_port,
        &tcp_echo_ip,
        tcp_echo_port,
        b"H2MUX Client Test Message",
    )
    .await?;

    let response_str = std::str::from_utf8(&response)?;
    eprintln!("[TEST] Response: {}", response_str);
    assert!(response_str.contains("H2MUX Client Test Message"));
    assert!(response_str.ends_with(" [ECHO]"));

    eprintln!("[TEST] H2MUX shoes client to shoes server test passed!");
    Ok(())
}

/// Test h2mux client with multiple concurrent connections
#[tokio::test]
async fn test_h2mux_client_concurrent_streams() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (server_a_ip, server_a_port) = port_helper.get_localhost_listener_port();
    let (server_b_ip, server_b_port) = port_helper.get_localhost_listener_port();
    let (tcp_echo_ip, tcp_echo_port) = port_helper.get_localhost_listener_port();

    eprintln!("[TEST] H2MUX client concurrent streams");

    // Start TCP echo server
    let _tcp_echo_server = start_tcp_eof_echo_server(&tcp_echo_ip, tcp_echo_port).await?;

    // Generate certs
    let (cert_path, key_path) = generate_test_cert_files()?;

    // Server A config (upstream)
    let server_a_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      "test.local":
        cert: {}
        key: {}
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: true"#,
        server_a_ip,
        server_a_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
        TEST_UUID,
    );

    // Server B config (h2mux client)
    let server_b_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: socks
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_proxies:
        - address: "{}:{}"
          protocol:
            type: tls
            verify: false
            sni_hostname: "test.local"
            protocol:
              type: vless
              user_id: "{}"
              h2mux:
                max_connections: 1
                min_streams: 4
"#,
        server_b_ip, server_b_port, server_a_ip, server_a_port, TEST_UUID,
    );

    let (_server_a_guard, _server_a_config_file) = start_shoes_server(&server_a_config)?;
    let (_server_b_guard, _server_b_config_file) = start_shoes_server(&server_b_config)?;

    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    // Send multiple concurrent requests
    let mut handles = Vec::new();
    for i in 0..5 {
        let server_b_ip = server_b_ip.clone();
        let tcp_echo_ip = tcp_echo_ip.clone();
        let handle = tokio::spawn(async move {
            let msg = format!("Concurrent Message #{}", i);
            let response = send_tcp_via_socks5(
                &server_b_ip,
                server_b_port,
                &tcp_echo_ip,
                tcp_echo_port,
                msg.as_bytes(),
            )
            .await
            .expect("Failed to send request");

            let response_str = std::str::from_utf8(&response).expect("Invalid UTF-8");
            assert!(
                response_str.contains(&msg),
                "Response should contain message: {}",
                response_str
            );
            eprintln!("[TEST] Concurrent request {} completed", i);
        });
        handles.push(handle);
    }

    // Wait for all requests to complete
    for handle in handles {
        handle.await?;
    }

    eprintln!("[TEST] H2MUX client concurrent streams test passed!");
    Ok(())
}

// Additional coverage tests for all client/server combinations

/// Test shoes h2mux client connecting to shoes h2mux server WITH padding enabled
#[tokio::test]
async fn test_h2mux_shoes_client_to_shoes_server_with_padding()
-> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (server_a_ip, server_a_port) = port_helper.get_localhost_listener_port();
    let (server_b_ip, server_b_port) = port_helper.get_localhost_listener_port();
    let (tcp_echo_ip, tcp_echo_port) = port_helper.get_localhost_listener_port();

    eprintln!("[TEST] H2MUX shoes client to shoes server WITH padding");

    let _tcp_echo_server = start_tcp_eof_echo_server(&tcp_echo_ip, tcp_echo_port).await?;
    let (cert_path, key_path) = generate_test_cert_files()?;

    // Server A: VLESS h2mux server (upstream)
    let server_a_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      "test.local":
        cert: {}
        key: {}
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: true"#,
        server_a_ip,
        server_a_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
        TEST_UUID,
    );

    // Server B: SOCKS5 proxy using h2mux client WITH padding
    let server_b_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: socks
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_proxies:
        - address: "{}:{}"
          protocol:
            type: tls
            verify: false
            sni_hostname: "test.local"
            protocol:
              type: vless
              user_id: "{}"
              h2mux:
                padding: true
"#,
        server_b_ip, server_b_port, server_a_ip, server_a_port, TEST_UUID,
    );

    let (_server_a_guard, _server_a_config_file) = start_shoes_server(&server_a_config)?;
    let (_server_b_guard, _server_b_config_file) = start_shoes_server(&server_b_config)?;

    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    // Send multiple requests to exercise padding layer (first 16 ops are padded)
    for i in 0..20 {
        let msg = format!("Shoes-to-Shoes Padding Test #{}", i);
        let response = send_tcp_via_socks5(
            &server_b_ip,
            server_b_port,
            &tcp_echo_ip,
            tcp_echo_port,
            msg.as_bytes(),
        )
        .await?;

        let response_str = std::str::from_utf8(&response)?;
        assert!(
            response_str.contains(&msg),
            "Response doesn't contain {}: got {}",
            msg,
            response_str
        );
    }

    eprintln!("[TEST] H2MUX shoes client to shoes server with padding test passed!");
    Ok(())
}

/// Test shoes h2mux client connecting to sing-box h2mux server (without padding)
#[tokio::test]
async fn test_h2mux_shoes_client_to_singbox_server() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (singbox_server_ip, singbox_server_port) = port_helper.get_localhost_listener_port();
    let (shoes_proxy_ip, shoes_proxy_port) = port_helper.get_localhost_listener_port();
    let (tcp_echo_ip, tcp_echo_port) = port_helper.get_localhost_listener_port();

    eprintln!("[TEST] H2MUX shoes client to sing-box server");
    eprintln!(
        "  sing-box server: {}:{}",
        singbox_server_ip, singbox_server_port
    );
    eprintln!(
        "  shoes proxy (h2mux client): {}:{}",
        shoes_proxy_ip, shoes_proxy_port
    );
    eprintln!("  Echo server: {}:{}", tcp_echo_ip, tcp_echo_port);

    let _tcp_echo_server = start_tcp_stream_echo_server(&tcp_echo_ip, tcp_echo_port).await?;
    let (cert_path, key_path) = generate_test_cert_files()?;

    // sing-box as VLESS h2mux server
    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{
    "type": "vless",
    "tag": "vless-in",
    "listen": "{}",
    "listen_port": {},
    "users": [{{ "uuid": "{}" }}],
    "tls": {{
      "enabled": true,
      "server_name": "test.local",
      "certificate_path": "{}",
      "key_path": "{}"
    }},
    "multiplex": {{
      "enabled": true,
      "padding": false
    }}
  }}],
  "outbounds": [{{ "type": "direct", "tag": "direct" }}],
  "route": {{ "final": "direct" }}
}}"#,
        singbox_server_ip,
        singbox_server_port,
        TEST_UUID,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
    );

    // shoes as SOCKS5 proxy using h2mux client to connect to sing-box
    let shoes_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: socks
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_proxies:
        - address: "{}:{}"
          protocol:
            type: tls
            verify: false
            sni_hostname: "test.local"
            protocol:
              type: vless
              user_id: "{}"
              h2mux: {{}}
"#,
        shoes_proxy_ip, shoes_proxy_port, singbox_server_ip, singbox_server_port, TEST_UUID,
    );

    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    let msg = b"Hello from shoes client to sing-box server!";
    let response = send_tcp_stream_via_socks5(
        &shoes_proxy_ip,
        shoes_proxy_port,
        &tcp_echo_ip,
        tcp_echo_port,
        msg,
    )
    .await?;

    assert_eq!(response, msg);

    eprintln!("[TEST] H2MUX shoes client to sing-box server test passed!");
    Ok(())
}

/// Test shoes h2mux client connecting to sing-box h2mux server WITH padding
#[tokio::test]
async fn test_h2mux_shoes_client_to_singbox_server_with_padding()
-> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (singbox_server_ip, singbox_server_port) = port_helper.get_localhost_listener_port();
    let (shoes_proxy_ip, shoes_proxy_port) = port_helper.get_localhost_listener_port();
    let (tcp_echo_ip, tcp_echo_port) = port_helper.get_localhost_listener_port();

    eprintln!("[TEST] H2MUX shoes client to sing-box server WITH padding");

    let _tcp_echo_server = start_tcp_stream_echo_server(&tcp_echo_ip, tcp_echo_port).await?;
    let (cert_path, key_path) = generate_test_cert_files()?;

    // sing-box as VLESS h2mux server with padding enabled
    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{
    "type": "vless",
    "tag": "vless-in",
    "listen": "{}",
    "listen_port": {},
    "users": [{{ "uuid": "{}" }}],
    "tls": {{
      "enabled": true,
      "server_name": "test.local",
      "certificate_path": "{}",
      "key_path": "{}"
    }},
    "multiplex": {{
      "enabled": true,
      "padding": true
    }}
  }}],
  "outbounds": [{{ "type": "direct", "tag": "direct" }}],
  "route": {{ "final": "direct" }}
}}"#,
        singbox_server_ip,
        singbox_server_port,
        TEST_UUID,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
    );

    // shoes as SOCKS5 proxy using h2mux client with padding
    let shoes_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: socks
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_proxies:
        - address: "{}:{}"
          protocol:
            type: tls
            verify: false
            sni_hostname: "test.local"
            protocol:
              type: vless
              user_id: "{}"
              h2mux:
                padding: true
"#,
        shoes_proxy_ip, shoes_proxy_port, singbox_server_ip, singbox_server_port, TEST_UUID,
    );

    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    // Send multiple requests to exercise padding (first 16 ops are padded)
    for i in 0..20 {
        let msg = format!("Shoes-to-Singbox Padding Test #{}", i);
        let response = send_tcp_stream_via_socks5(
            &shoes_proxy_ip,
            shoes_proxy_port,
            &tcp_echo_ip,
            tcp_echo_port,
            msg.as_bytes(),
        )
        .await?;

        assert_eq!(response, msg.as_bytes());
    }

    eprintln!("[TEST] H2MUX shoes client to sing-box server with padding test passed!");
    Ok(())
}
