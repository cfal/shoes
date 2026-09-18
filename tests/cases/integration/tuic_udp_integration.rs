/// Integration tests for TUIC v5 UDP relay functionality
///
/// Test Architecture:
/// ==================
/// These tests verify that shoes correctly implements UDP relay over TUIC v5 QUIC.
///
/// Test Chain:
/// UDP Client -> sing-box SOCKS5 (UDP ASSOCIATE) -> TUIC client -> shoes TUIC server -> UDP echo server
///
/// Key Protocol Points:
/// 1. Client establishes SOCKS5 UDP ASSOCIATE with sing-box
/// 2. sing-box forwards UDP packets via TUIC to shoes
/// 3. shoes TUIC server relays UDP to the target (echo server)
/// 4. Response flows back through the same path
use shoes_test_support as common;

use common::certs::generate_test_cert_files;
use common::port_helper::PortHelper;
use common::socks5::Socks5UdpAssociation;
use common::test_fixture::{ProcessGuard, start_shoes_server, start_singbox_server};
use common::test_servers::start_udp_echo_server;

use std::net::SocketAddr;
use tempfile::NamedTempFile;

/// UUID used across all tests for consistency (same as test_fixture.rs)
const TEST_UUID: &str = "b85798ef-e9dc-46a4-9a87-8da4499d36d0";

/// Start sing-box with SOCKS5 inbound (UDP enabled) and TUIC outbound
fn start_singbox_tuic_socks_client(
    socks_ip: &str,
    socks_port: u16,
    tuic_ip: &str,
    tuic_port: u16,
    password: &str,
) -> std::io::Result<(ProcessGuard, NamedTempFile)> {
    let config = format!(
        r#"{{
  "log": {{"level": "debug"}},
  "inbounds": [{{
    "type": "socks",
    "tag": "socks-in",
    "listen": "{}",
    "listen_port": {},
    "udp_timeout": "30s"
  }}],
  "outbounds": [{{
    "type": "tuic",
    "tag": "tuic-out",
    "server": "{}",
    "server_port": {},
    "uuid": "{}",
    "password": "{}",
    "tls": {{
      "enabled": true,
      "insecure": true,
      "alpn": ["h3"]
    }}
  }}],
  "route": {{
    "final": "tuic-out"
  }}
}}"#,
        socks_ip, socks_port, tuic_ip, tuic_port, TEST_UUID, password
    );

    start_singbox_server(&config)
}

// TUIC UDP RELAY TESTS

/// Test basic UDP relay through TUIC
/// Chain: UDP client -> sing-box SOCKS5 -> TUIC -> shoes TUIC server -> UDP echo
#[tokio::test]
async fn test_tuic_udp_relay_basic() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_quic_listener_port();
    let (socks_ip, socks_port) = port_helper.get_listener_port();
    let (echo_ip, echo_port) = port_helper.get_port();

    let password = "test_tuic_udp_password";

    eprintln!(
        "[TEST] TUIC UDP relay: shoes={}:{}, socks={}:{}, echo={}:{}",
        shoes_ip, shoes_port, socks_ip, socks_port, echo_ip, echo_port
    );

    // Start UDP echo server
    let _echo_server = start_udp_echo_server(&echo_ip, echo_port).await?;

    // Generate certificates
    let (cert, key) = generate_test_cert_files()?;

    // Start shoes TUIC server
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
    type: tuic
    uuid: "{}"
    password: "{}"
"#,
        shoes_ip,
        shoes_port,
        cert.to_str().unwrap(),
        key.to_str().unwrap(),
        TEST_UUID,
        password
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    // Start sing-box SOCKS5 -> TUIC client
    let (_singbox_guard, _temp_dir) =
        start_singbox_tuic_socks_client(&socks_ip, socks_port, &shoes_ip, shoes_port, password)?;

    // Wait for servers to start
    port_helper.wait_for_all_ports().await?;

    // Do SOCKS5 UDP ASSOCIATE
    let association = Socks5UdpAssociation::connect(&socks_ip, socks_port).await?;
    let target: SocketAddr = format!("{echo_ip}:{echo_port}").parse()?;

    // Send a test packet
    let response = association.send_to(target, b"Hello TUIC UDP!").await?;

    let response_str = std::str::from_utf8(&response)?;
    eprintln!("[TEST] Response: {}", response_str);

    assert!(
        response_str.starts_with("Hello TUIC UDP!"),
        "Response should contain our message"
    );
    assert!(
        response_str.contains("[ECHO"),
        "Response should contain echo marker"
    );

    eprintln!("[TEST] TUIC UDP relay basic test PASSED");
    Ok(())
}

/// Test multiple UDP packets through TUIC
#[tokio::test]
async fn test_tuic_udp_relay_multiple_packets()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_quic_listener_port();
    let (socks_ip, socks_port) = port_helper.get_listener_port();
    let (echo_ip, echo_port) = port_helper.get_port();

    let password = "test_tuic_udp_multi";

    eprintln!("[TEST] TUIC UDP relay multiple packets");

    // Start UDP echo server
    let _echo_server = start_udp_echo_server(&echo_ip, echo_port).await?;

    // Generate certificates
    let (cert, key) = generate_test_cert_files()?;

    // Start shoes TUIC server
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
    type: tuic
    uuid: "{}"
    password: "{}"
"#,
        shoes_ip,
        shoes_port,
        cert.to_str().unwrap(),
        key.to_str().unwrap(),
        TEST_UUID,
        password
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    // Start sing-box SOCKS5 -> TUIC client
    let (_singbox_guard, _temp_dir) =
        start_singbox_tuic_socks_client(&socks_ip, socks_port, &shoes_ip, shoes_port, password)?;

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

    eprintln!("[TEST] TUIC UDP relay multiple packets test PASSED (20 packets)");
    Ok(())
}

/// Test various UDP packet sizes through TUIC
#[tokio::test]
async fn test_tuic_udp_relay_various_sizes() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_quic_listener_port();
    let (socks_ip, socks_port) = port_helper.get_listener_port();
    let (echo_ip, echo_port) = port_helper.get_port();

    let password = "test_tuic_udp_sizes";

    eprintln!("[TEST] TUIC UDP relay various sizes");

    // Start UDP echo server
    let _echo_server = start_udp_echo_server(&echo_ip, echo_port).await?;

    // Generate certificates
    let (cert, key) = generate_test_cert_files()?;

    // Start shoes TUIC server
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
    type: tuic
    uuid: "{}"
    password: "{}"
"#,
        shoes_ip,
        shoes_port,
        cert.to_str().unwrap(),
        key.to_str().unwrap(),
        TEST_UUID,
        password
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    // Start sing-box SOCKS5 -> TUIC client
    let (_singbox_guard, _temp_dir) =
        start_singbox_tuic_socks_client(&socks_ip, socks_port, &shoes_ip, shoes_port, password)?;

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

    eprintln!("[TEST] TUIC UDP relay various sizes test PASSED");
    Ok(())
}

/// Test UDP relay to multiple destinations through same TUIC connection
#[tokio::test]
async fn test_tuic_udp_relay_multi_destination()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_quic_listener_port();
    let (socks_ip, socks_port) = port_helper.get_listener_port();
    let (echo_ip1, echo_port1) = port_helper.get_port();
    let (echo_ip2, echo_port2) = port_helper.get_port();

    let password = "test_tuic_udp_multidest";

    eprintln!("[TEST] TUIC UDP relay multi-destination");

    // Start two UDP echo servers
    let _echo_server1 = start_udp_echo_server(&echo_ip1, echo_port1).await?;
    let _echo_server2 = start_udp_echo_server(&echo_ip2, echo_port2).await?;

    // Generate certificates
    let (cert, key) = generate_test_cert_files()?;

    // Start shoes TUIC server
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
    type: tuic
    uuid: "{}"
    password: "{}"
"#,
        shoes_ip,
        shoes_port,
        cert.to_str().unwrap(),
        key.to_str().unwrap(),
        TEST_UUID,
        password
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    // Start sing-box SOCKS5 -> TUIC client
    let (_singbox_guard, _temp_dir) =
        start_singbox_tuic_socks_client(&socks_ip, socks_port, &shoes_ip, shoes_port, password)?;

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

    eprintln!("[TEST] TUIC UDP relay multi-destination test PASSED");
    Ok(())
}
