/// Integration tests for Hysteria2 UDP relay functionality
///
/// Test Architecture:
/// ==================
/// These tests verify that shoes correctly implements UDP relay over Hysteria2 QUIC.
///
/// Test Chain:
/// UDP Client -> sing-box SOCKS5 (UDP ASSOCIATE) -> Hysteria2 client -> shoes Hysteria2 server -> UDP echo server
///
/// Key Protocol Points:
/// 1. Client establishes SOCKS5 UDP ASSOCIATE with sing-box
/// 2. sing-box forwards UDP packets via Hysteria2 to shoes
/// 3. shoes Hysteria2 server relays UDP to the target (echo server)
/// 4. Response flows back through the same path
use shoes_test_support as common;

use common::certs::generate_test_cert_files;
use common::port_helper::PortHelper;
use common::socks5::Socks5UdpAssociation;
use common::test_fixture::{ProcessGuard, start_shoes_server, start_singbox_server};
use common::test_servers::start_udp_echo_server;

use std::net::SocketAddr;
use tempfile::NamedTempFile;

/// Start sing-box with SOCKS5 inbound (UDP enabled) and Hysteria2 outbound
fn start_singbox_hysteria2_socks_client(
    socks_ip: &str,
    socks_port: u16,
    hysteria2_ip: &str,
    hysteria2_port: u16,
    password: &str,
) -> std::io::Result<(ProcessGuard, NamedTempFile)> {
    let config = format!(
        r#"{{
  "log": {{"level": "trace"}},
  "inbounds": [{{
    "type": "socks",
    "tag": "socks-in",
    "listen": "{}",
    "listen_port": {},
    "udp_timeout": "30s"
  }}],
  "outbounds": [{{
    "type": "hysteria2",
    "tag": "hy2-out",
    "server": "{}",
    "server_port": {},
    "password": "{}",
    "tls": {{
      "enabled": true,
      "insecure": true,
      "alpn": ["h3"]
    }}
  }}],
  "route": {{
    "final": "hy2-out"
  }}
}}"#,
        socks_ip, socks_port, hysteria2_ip, hysteria2_port, password
    );

    start_singbox_server(&config)
}

// HYSTERIA2 UDP RELAY TESTS

/// Test basic UDP relay through Hysteria2
/// Chain: UDP client -> sing-box SOCKS5 -> Hysteria2 -> shoes Hysteria2 server -> UDP echo
#[tokio::test]
async fn test_hysteria2_udp_relay_basic() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_quic_listener_port();
    let (socks_ip, socks_port) = port_helper.get_listener_port();
    let (echo_ip, echo_port) = port_helper.get_port();

    let password = "test_hysteria2_udp_password";

    eprintln!(
        "[TEST] Hysteria2 UDP relay: shoes={}:{}, socks={}:{}, echo={}:{}",
        shoes_ip, shoes_port, socks_ip, socks_port, echo_ip, echo_port
    );

    // Start UDP echo server
    let _echo_server = start_udp_echo_server(&echo_ip, echo_port).await?;

    // Generate certificates
    let (cert, key) = generate_test_cert_files()?;

    // Start shoes Hysteria2 server
    let shoes_config = format!(
        r#"
- address: "{}:{}"
  transport: quic
  quic_settings:
    cert: "{}"
    key: "{}"
    num_endpoints: 1
    alpn_protocols:
      - h3
  protocol:
    type: hysteria2
    password: "{}"
    udp_enabled: true
"#,
        shoes_ip,
        shoes_port,
        cert.to_str().unwrap(),
        key.to_str().unwrap(),
        password
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    // Start sing-box SOCKS5 -> Hysteria2 client
    let (_singbox_guard, _temp_dir) = start_singbox_hysteria2_socks_client(
        &socks_ip, socks_port, &shoes_ip, shoes_port, password,
    )?;

    // Wait for servers to start
    port_helper.wait_for_all_ports().await?;

    // Do SOCKS5 UDP ASSOCIATE
    let association = Socks5UdpAssociation::connect(&socks_ip, socks_port).await?;
    let target: SocketAddr = format!("{echo_ip}:{echo_port}").parse()?;

    // Send a test packet
    let response = association.send_to(target, b"Hello Hysteria2 UDP!").await?;

    let response_str = std::str::from_utf8(&response)?;
    eprintln!("[TEST] Response: {}", response_str);

    assert!(
        response_str.starts_with("Hello Hysteria2 UDP!"),
        "Response should contain our message"
    );
    assert!(
        response_str.contains("[ECHO"),
        "Response should contain echo marker"
    );

    eprintln!("[TEST] Hysteria2 UDP relay basic test PASSED");
    Ok(())
}

/// Test multiple UDP packets through Hysteria2
#[tokio::test]
async fn test_hysteria2_udp_relay_multiple_packets()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_quic_listener_port();
    let (socks_ip, socks_port) = port_helper.get_listener_port();
    let (echo_ip, echo_port) = port_helper.get_port();

    let password = "test_hysteria2_udp_multi";

    eprintln!("[TEST] Hysteria2 UDP relay multiple packets");

    // Start UDP echo server
    let _echo_server = start_udp_echo_server(&echo_ip, echo_port).await?;

    // Generate certificates
    let (cert, key) = generate_test_cert_files()?;

    // Start shoes Hysteria2 server
    let shoes_config = format!(
        r#"
- address: "{}:{}"
  transport: quic
  quic_settings:
    cert: "{}"
    key: "{}"
    num_endpoints: 1
    alpn_protocols:
      - h3
  protocol:
    type: hysteria2
    password: "{}"
    udp_enabled: true
"#,
        shoes_ip,
        shoes_port,
        cert.to_str().unwrap(),
        key.to_str().unwrap(),
        password
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    // Start sing-box SOCKS5 -> Hysteria2 client
    let (_singbox_guard, _temp_dir) = start_singbox_hysteria2_socks_client(
        &socks_ip, socks_port, &shoes_ip, shoes_port, password,
    )?;

    // Wait for servers to start
    port_helper.wait_for_all_ports().await?;

    // Do SOCKS5 UDP ASSOCIATE
    let association = Socks5UdpAssociation::connect(&socks_ip, socks_port).await?;
    let target: SocketAddr = format!("{echo_ip}:{echo_port}").parse()?;

    // Send multiple packets
    for i in 0..20 {
        let msg = format!("Packet-{:04}", i);
        let response = association.send_to(target, msg.as_bytes()).await?;
        let response_str = std::str::from_utf8(&response)?;
        assert!(response_str.contains(&msg), "Packet {} mismatch", i);

        if i % 5 == 0 {
            eprintln!("[TEST] Packet {} OK", i);
        }
    }

    eprintln!("[TEST] Hysteria2 UDP relay multiple packets test PASSED (20 packets)");
    Ok(())
}

/// Test various UDP packet sizes through Hysteria2
#[tokio::test]
async fn test_hysteria2_udp_relay_various_sizes()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_quic_listener_port();
    let (socks_ip, socks_port) = port_helper.get_listener_port();
    let (echo_ip, echo_port) = port_helper.get_port();

    let password = "test-password";

    eprintln!("[TEST] Hysteria2 UDP relay various sizes");

    // Start UDP echo server
    let _echo_server = start_udp_echo_server(&echo_ip, echo_port).await?;

    // Generate certificates
    let (cert, key) = generate_test_cert_files()?;

    // Start shoes Hysteria2 server
    let shoes_config = format!(
        r#"
- address: "{}:{}"
  transport: quic
  quic_settings:
    cert: "{}"
    key: "{}"
    num_endpoints: 1
    alpn_protocols:
      - h3
  protocol:
    type: hysteria2
    password: "{}"
    udp_enabled: true
"#,
        shoes_ip,
        shoes_port,
        cert.to_str().unwrap(),
        key.to_str().unwrap(),
        password
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    // Start sing-box SOCKS5 -> Hysteria2 client
    let (_singbox_guard, _temp_dir) = start_singbox_hysteria2_socks_client(
        &socks_ip, socks_port, &shoes_ip, shoes_port, password,
    )?;

    // Wait for servers to start
    port_helper.wait_for_all_ports().await?;

    // Do SOCKS5 UDP ASSOCIATE
    let association = Socks5UdpAssociation::connect(&socks_ip, socks_port).await?;
    let target: SocketAddr = format!("{echo_ip}:{echo_port}").parse()?;

    // Test various sizes (small to medium - QUIC max datagram size limits large packets)
    let sizes = [1, 10, 100, 500, 1000];

    for &size in &sizes {
        let payload: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let response = association.send_to(target, &payload).await?;

        // Response is payload + " [ECHO-N]" (variable length)
        assert!(
            response.len() > payload.len(),
            "Response should be larger than payload for size {}",
            size
        );
        assert_eq!(
            &response[..payload.len()],
            &payload[..],
            "Payload mismatch for size {}",
            size
        );
        eprintln!("[TEST] {} bytes OK", size);
    }

    eprintln!("[TEST] Hysteria2 UDP relay various sizes test PASSED");
    Ok(())
}

/// Test UDP relay to multiple destinations through same Hysteria2 connection
#[tokio::test]
async fn test_hysteria2_udp_relay_multi_destination()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_quic_listener_port();
    let (socks_ip, socks_port) = port_helper.get_listener_port();
    let (echo_ip1, echo_port1) = port_helper.get_port();
    let (echo_ip2, echo_port2) = port_helper.get_port();

    let password = "test_hysteria2_udp_multidest";

    eprintln!("[TEST] Hysteria2 UDP relay multi-destination");

    // Start two UDP echo servers
    let _echo_server1 = start_udp_echo_server(&echo_ip1, echo_port1).await?;
    let _echo_server2 = start_udp_echo_server(&echo_ip2, echo_port2).await?;

    // Generate certificates
    let (cert, key) = generate_test_cert_files()?;

    // Start shoes Hysteria2 server
    let shoes_config = format!(
        r#"
- address: "{}:{}"
  transport: quic
  quic_settings:
    cert: "{}"
    key: "{}"
    num_endpoints: 1
    alpn_protocols:
      - h3
  protocol:
    type: hysteria2
    password: "{}"
    udp_enabled: true
"#,
        shoes_ip,
        shoes_port,
        cert.to_str().unwrap(),
        key.to_str().unwrap(),
        password
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    // Start sing-box SOCKS5 -> Hysteria2 client
    let (_singbox_guard, _temp_dir) = start_singbox_hysteria2_socks_client(
        &socks_ip, socks_port, &shoes_ip, shoes_port, password,
    )?;

    // Wait for servers to start
    port_helper.wait_for_all_ports().await?;

    // Do SOCKS5 UDP ASSOCIATE
    let association = Socks5UdpAssociation::connect(&socks_ip, socks_port).await?;

    let targets = [
        (
            format!("{echo_ip1}:{echo_port1}").parse::<SocketAddr>()?,
            "Server1",
        ),
        (
            format!("{echo_ip2}:{echo_port2}").parse::<SocketAddr>()?,
            "Server2",
        ),
    ];

    // Send to each destination
    for (target, name) in &targets {
        let msg = format!("Hello {}", name);
        let response = association.send_to(*target, msg.as_bytes()).await?;
        let response_str = std::str::from_utf8(&response)?;
        assert!(
            response_str.contains(&msg),
            "Response should contain message for {}",
            name
        );
        eprintln!("[TEST] {} responded correctly", name);
    }

    // Interleave packets to different destinations
    for i in 0..5 {
        for (target, name) in &targets {
            let msg = format!("{}-round-{}", name, i);
            let response = association.send_to(*target, msg.as_bytes()).await?;
            assert!(std::str::from_utf8(&response)?.contains(&msg));
        }
    }

    eprintln!("[TEST] Hysteria2 UDP relay multi-destination test PASSED");
    Ok(())
}
