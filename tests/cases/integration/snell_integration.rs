/// Integration tests for Snell protocol
///
/// Test Architecture:
/// ==================
/// Snell is similar to Shadowsocks but uses Argon2id for key derivation and
/// has a different protocol format.
///
/// Test Scenarios:
/// ===============
/// 1. shoes as Snell Server (with shoes HTTP client) - TCP tests
/// 2. shoes as Snell Client (connecting to shoes Snell server) - TCP tests
/// 3. UDP tests via SOCKS5 UDP ASSOCIATE -> Snell chain
///
/// Note: sing-box does not support Snell as an outbound type, so we test
/// shoes-to-shoes interoperability.
use shoes_test_support as common;

use common::port_helper::PortHelper;
use common::socks5::Socks5UdpAssociation;
use common::test_fixture::{ProxyTestFixture, ShadowsocksCipher, start_shoes_server};
use common::test_servers::start_udp_echo_server;
use std::net::SocketAddr;

const TEST_PASSWORD: &str = "test-snell-password-1234";

// Snell Server Tests (shoes as server, shoes as client)

#[tokio::test]
async fn test_snell_server_aes256gcm() -> Result<(), Box<dyn std::error::Error>> {
    // Chain: curl -> shoes HTTP proxy (with Snell client) -> shoes Snell server -> internet
    ProxyTestFixture::new()
        .with_shoes_snell_client(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .with_shoes_snell_server(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .test_local_http_hostname(1024)
        .await
}

#[tokio::test]
async fn test_snell_server_aes128gcm() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_shoes_snell_client(ShadowsocksCipher::Aes128Gcm, TEST_PASSWORD)
        .with_shoes_snell_server(ShadowsocksCipher::Aes128Gcm, TEST_PASSWORD)
        .test_local_http(1024)
        .await
}

#[tokio::test]
async fn test_snell_server_chacha20() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_shoes_snell_client(ShadowsocksCipher::ChaCha20IetfPoly1305, TEST_PASSWORD)
        .with_shoes_snell_server(ShadowsocksCipher::ChaCha20IetfPoly1305, TEST_PASSWORD)
        .test_local_http(1024)
        .await
}

// HTTPS Tests (verify TLS passthrough works)

#[tokio::test]
async fn test_snell_https_aes256gcm() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_shoes_snell_client(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .with_shoes_snell_server(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .test_local_https_tls13(1024)
        .await
}

#[tokio::test]
async fn test_snell_multiple_requests() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_snell_client(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .with_shoes_snell_server(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .with_local_http_server()
        .build()
        .await?;

    // Make multiple requests to test connection reuse
    for i in 0..5 {
        let size = 100 * (i + 1);
        let body = fixture
            .test_local_server(&format!("/bytes/{}", size), false)
            .await?;
        assert_eq!(
            body.len(),
            size,
            "Request {} should return {} bytes",
            i,
            size
        );
    }

    Ok(())
}

// UDP Tests (SOCKS5 UDP ASSOCIATE -> Snell chain -> UDP echo server)

/// Test basic UDP through Snell chain
#[tokio::test]
async fn test_snell_udp_basic() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut ports = PortHelper::new();
    let (socks5_ip, socks5_port) = ports.get_listener_port();
    let (snell_ip, snell_port) = ports.get_listener_port();
    let (echo_ip, echo_port) = ports.get_port(); // UDP server - don't track for TCP readiness

    // Start UDP echo server
    let _echo_server = start_udp_echo_server(&echo_ip, echo_port).await?;

    // shoes config: SOCKS5 server -> Snell client -> Snell server
    let config = format!(
        r#"
- address: "{socks5_ip}:{socks5_port}"
  protocol:
    type: socks
    udp_enabled: true
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_proxy:
        address: "{snell_ip}:{snell_port}"
        protocol:
          type: snell
          cipher: aes-256-gcm
          password: "{TEST_PASSWORD}"
          udp_enabled: true

- address: "{snell_ip}:{snell_port}"
  protocol:
    type: snell
    cipher: aes-256-gcm
    password: "{TEST_PASSWORD}"
"#,
        socks5_ip = socks5_ip,
        socks5_port = socks5_port,
        snell_ip = snell_ip,
        snell_port = snell_port,
        TEST_PASSWORD = TEST_PASSWORD
    );

    let _shoes = start_shoes_server(&config)?;
    ports.wait_for_all_ports().await?;

    // Perform UDP ASSOCIATE
    let association = Socks5UdpAssociation::connect(&socks5_ip, socks5_port).await?;

    // Send test message
    let test_message = b"Hello via Snell UDP!";
    let target: SocketAddr = format!("{echo_ip}:{echo_port}").parse()?;
    let response = association.send_to(target, test_message).await?;

    let response_str = String::from_utf8_lossy(&response);
    eprintln!("[TEST] Received response: {}", response_str);
    assert!(
        response_str.starts_with("Hello via Snell UDP!"),
        "Response should start with original message"
    );
    assert!(
        response_str.ends_with(" [ECHO]"),
        "Response should contain echo marker"
    );

    Ok(())
}

/// Test multiple UDP packets through Snell
#[tokio::test]
async fn test_snell_udp_multiple_packets() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut ports = PortHelper::new();
    let (socks5_ip, socks5_port) = ports.get_listener_port();
    let (snell_ip, snell_port) = ports.get_listener_port();
    let (echo_ip, echo_port) = ports.get_port(); // UDP server - don't track for TCP readiness

    let _echo_server = start_udp_echo_server(&echo_ip, echo_port).await?;

    let config = format!(
        r#"
- address: "{socks5_ip}:{socks5_port}"
  protocol:
    type: socks
    udp_enabled: true
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_proxy:
        address: "{snell_ip}:{snell_port}"
        protocol:
          type: snell
          cipher: aes-256-gcm
          password: "{TEST_PASSWORD}"
          udp_enabled: true

- address: "{snell_ip}:{snell_port}"
  protocol:
    type: snell
    cipher: aes-256-gcm
    password: "{TEST_PASSWORD}"
"#,
        socks5_ip = socks5_ip,
        socks5_port = socks5_port,
        snell_ip = snell_ip,
        snell_port = snell_port,
        TEST_PASSWORD = TEST_PASSWORD
    );

    let _shoes = start_shoes_server(&config)?;
    ports.wait_for_all_ports().await?;

    let association = Socks5UdpAssociation::connect(&socks5_ip, socks5_port).await?;
    let target: SocketAddr = format!("{echo_ip}:{echo_port}").parse()?;

    // Send multiple packets
    for i in 0..20 {
        let msg = format!("Packet number {}", i);
        let response = association.send_to(target, msg.as_bytes()).await?;

        let response_str = String::from_utf8_lossy(&response);
        assert!(
            response_str.starts_with(&msg),
            "Packet {}: expected '{}', got '{}'",
            i,
            msg,
            response_str
        );
    }

    eprintln!("[TEST] Successfully sent and received 20 UDP packets through Snell");
    Ok(())
}

/// Test UDP through Snell with ChaCha20 cipher
#[tokio::test]
async fn test_snell_udp_chacha20() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut ports = PortHelper::new();
    let (socks5_ip, socks5_port) = ports.get_listener_port();
    let (snell_ip, snell_port) = ports.get_listener_port();
    let (echo_ip, echo_port) = ports.get_port(); // UDP server - don't track for TCP readiness

    let _echo_server = start_udp_echo_server(&echo_ip, echo_port).await?;

    let config = format!(
        r#"
- address: "{socks5_ip}:{socks5_port}"
  protocol:
    type: socks
    udp_enabled: true
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_proxy:
        address: "{snell_ip}:{snell_port}"
        protocol:
          type: snell
          cipher: chacha20-ietf-poly1305
          password: "{TEST_PASSWORD}"
          udp_enabled: true

- address: "{snell_ip}:{snell_port}"
  protocol:
    type: snell
    cipher: chacha20-ietf-poly1305
    password: "{TEST_PASSWORD}"
"#,
        socks5_ip = socks5_ip,
        socks5_port = socks5_port,
        snell_ip = snell_ip,
        snell_port = snell_port,
        TEST_PASSWORD = TEST_PASSWORD
    );

    let _shoes = start_shoes_server(&config)?;
    ports.wait_for_all_ports().await?;

    let association = Socks5UdpAssociation::connect(&socks5_ip, socks5_port).await?;

    let test_message = b"ChaCha20 Snell UDP test";
    let target: SocketAddr = format!("{echo_ip}:{echo_port}").parse()?;
    let response = association.send_to(target, test_message).await?;

    let response_str = String::from_utf8_lossy(&response);
    assert!(
        response_str.starts_with("ChaCha20 Snell UDP test"),
        "Response should contain original message"
    );

    eprintln!("[TEST] ChaCha20 Snell UDP test passed");
    Ok(())
}

/// Test UDP with various packet sizes through Snell
#[tokio::test]
async fn test_snell_udp_various_sizes() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut ports = PortHelper::new();
    let (socks5_ip, socks5_port) = ports.get_listener_port();
    let (snell_ip, snell_port) = ports.get_listener_port();
    let (echo_ip, echo_port) = ports.get_port(); // UDP server - don't track for TCP readiness

    let _echo_server = start_udp_echo_server(&echo_ip, echo_port).await?;

    let config = format!(
        r#"
- address: "{socks5_ip}:{socks5_port}"
  protocol:
    type: socks
    udp_enabled: true
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_proxy:
        address: "{snell_ip}:{snell_port}"
        protocol:
          type: snell
          cipher: aes-256-gcm
          password: "{TEST_PASSWORD}"
          udp_enabled: true

- address: "{snell_ip}:{snell_port}"
  protocol:
    type: snell
    cipher: aes-256-gcm
    password: "{TEST_PASSWORD}"
"#,
        socks5_ip = socks5_ip,
        socks5_port = socks5_port,
        snell_ip = snell_ip,
        snell_port = snell_port,
        TEST_PASSWORD = TEST_PASSWORD
    );

    let _shoes = start_shoes_server(&config)?;
    ports.wait_for_all_ports().await?;

    let association = Socks5UdpAssociation::connect(&socks5_ip, socks5_port).await?;
    let target: SocketAddr = format!("{echo_ip}:{echo_port}").parse()?;

    // Test various sizes
    let sizes = [1, 10, 100, 500, 1000, 2000, 4000, 8000];

    for &size in &sizes {
        let payload: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let response = association.send_to(target, &payload).await?;

        // Response includes echo marker, so it's longer than original
        assert!(
            response.len() >= size,
            "Size {}: response {} bytes, expected at least {}",
            size,
            response.len(),
            size
        );
        // Verify payload prefix matches
        assert_eq!(
            &response[..size],
            &payload[..],
            "Size {}: payload mismatch",
            size
        );
        eprintln!("[TEST] Size {} passed", size);
    }

    eprintln!("[TEST] All size tests passed");
    Ok(())
}

/// Test UDP through Snell with multiple concurrent destinations
/// This verifies the UDP router correctly demultiplexes packets to different destinations
#[tokio::test]
async fn test_snell_udp_multi_destination() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let mut ports = PortHelper::new();
    let (socks5_ip, socks5_port) = ports.get_listener_port();
    let (snell_ip, snell_port) = ports.get_listener_port();
    // Create 3 different echo servers to test multi-destination routing
    let (echo1_ip, echo1_port) = ports.get_port();
    let (echo2_ip, echo2_port) = ports.get_port();
    let (echo3_ip, echo3_port) = ports.get_port();

    // Start all echo servers
    let _echo_server1 = start_udp_echo_server(&echo1_ip, echo1_port).await?;
    let _echo_server2 = start_udp_echo_server(&echo2_ip, echo2_port).await?;
    let _echo_server3 = start_udp_echo_server(&echo3_ip, echo3_port).await?;

    let config = format!(
        r#"
- address: "{socks5_ip}:{socks5_port}"
  protocol:
    type: socks
    udp_enabled: true
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_proxy:
        address: "{snell_ip}:{snell_port}"
        protocol:
          type: snell
          cipher: aes-256-gcm
          password: "{TEST_PASSWORD}"
          udp_enabled: true

- address: "{snell_ip}:{snell_port}"
  protocol:
    type: snell
    cipher: aes-256-gcm
    password: "{TEST_PASSWORD}"
"#,
        socks5_ip = socks5_ip,
        socks5_port = socks5_port,
        snell_ip = snell_ip,
        snell_port = snell_port,
        TEST_PASSWORD = TEST_PASSWORD
    );

    let _shoes = start_shoes_server(&config)?;
    ports.wait_for_all_ports().await?;

    let association = Socks5UdpAssociation::connect(&socks5_ip, socks5_port).await?;
    let target1: SocketAddr = format!("{echo1_ip}:{echo1_port}").parse()?;
    let target2: SocketAddr = format!("{echo2_ip}:{echo2_port}").parse()?;
    let target3: SocketAddr = format!("{echo3_ip}:{echo3_port}").parse()?;

    // Send packets to different destinations in an interleaved pattern
    // This tests that the router correctly maintains separate sessions
    for round in 0..5 {
        // Send to echo1
        let msg1 = format!("Echo1 round {}", round);
        let response1 = association.send_to(target1, msg1.as_bytes()).await?;
        let resp1_str = String::from_utf8_lossy(&response1);
        assert!(
            resp1_str.starts_with(&msg1),
            "Round {} Echo1: expected '{}', got '{}'",
            round,
            msg1,
            resp1_str
        );

        // Send to echo2
        let msg2 = format!("Echo2 round {}", round);
        let response2 = association.send_to(target2, msg2.as_bytes()).await?;
        let resp2_str = String::from_utf8_lossy(&response2);
        assert!(
            resp2_str.starts_with(&msg2),
            "Round {} Echo2: expected '{}', got '{}'",
            round,
            msg2,
            resp2_str
        );

        // Send to echo3
        let msg3 = format!("Echo3 round {}", round);
        let response3 = association.send_to(target3, msg3.as_bytes()).await?;
        let resp3_str = String::from_utf8_lossy(&response3);
        assert!(
            resp3_str.starts_with(&msg3),
            "Round {} Echo3: expected '{}', got '{}'",
            round,
            msg3,
            resp3_str
        );

        eprintln!("[TEST] Round {} completed for all 3 destinations", round);
    }

    eprintln!(
        "[TEST] Multi-destination test passed - 15 total packets to 3 different destinations"
    );
    Ok(())
}

/// Test UDP through Snell with rapid alternation between destinations
/// This stress-tests the session management
#[tokio::test]
async fn test_snell_udp_rapid_destination_switching()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut ports = PortHelper::new();
    let (socks5_ip, socks5_port) = ports.get_listener_port();
    let (snell_ip, snell_port) = ports.get_listener_port();
    let (echo1_ip, echo1_port) = ports.get_port();
    let (echo2_ip, echo2_port) = ports.get_port();

    let _echo_server1 = start_udp_echo_server(&echo1_ip, echo1_port).await?;
    let _echo_server2 = start_udp_echo_server(&echo2_ip, echo2_port).await?;

    let config = format!(
        r#"
- address: "{socks5_ip}:{socks5_port}"
  protocol:
    type: socks
    udp_enabled: true
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_proxy:
        address: "{snell_ip}:{snell_port}"
        protocol:
          type: snell
          cipher: aes-256-gcm
          password: "{TEST_PASSWORD}"
          udp_enabled: true

- address: "{snell_ip}:{snell_port}"
  protocol:
    type: snell
    cipher: aes-256-gcm
    password: "{TEST_PASSWORD}"
"#,
        socks5_ip = socks5_ip,
        socks5_port = socks5_port,
        snell_ip = snell_ip,
        snell_port = snell_port,
        TEST_PASSWORD = TEST_PASSWORD
    );

    let _shoes = start_shoes_server(&config)?;
    ports.wait_for_all_ports().await?;

    let association = Socks5UdpAssociation::connect(&socks5_ip, socks5_port).await?;
    let target1: SocketAddr = format!("{echo1_ip}:{echo1_port}").parse()?;
    let target2: SocketAddr = format!("{echo2_ip}:{echo2_port}").parse()?;

    // Rapidly alternate between destinations
    for i in 0..50 {
        let (target, label) = if i % 2 == 0 {
            (target1, "A")
        } else {
            (target2, "B")
        };

        let msg = format!("Packet {} to {}", i, label);
        let response = association.send_to(target, msg.as_bytes()).await?;

        let resp_str = String::from_utf8_lossy(&response);
        assert!(
            resp_str.starts_with(&msg),
            "Packet {}: expected '{}', got '{}'",
            i,
            msg,
            resp_str
        );
    }

    eprintln!("[TEST] Rapid switching test passed - 50 packets alternating between 2 destinations");
    Ok(())
}

/// Test UDP through Snell with hostname-based destination
/// This tests the ATYP=3 (domain name) path through the protocol
#[tokio::test]
async fn test_snell_udp_hostname_destination()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut ports = PortHelper::new();
    let (socks5_ip, socks5_port) = ports.get_listener_port();
    let (snell_ip, snell_port) = ports.get_listener_port();
    let (_echo_ip, echo_port) = ports.get_port(); // UDP server - don't track for TCP readiness

    // Bind echo servers to both IPv4 and IPv6 localhost since DNS may resolve to either
    // This ensures the test works regardless of IPv4/IPv6 preference
    let _echo_server4 = start_udp_echo_server("127.0.0.1", echo_port).await?;
    let _echo_server6 = start_udp_echo_server("::1", echo_port).await?;

    let config = format!(
        r#"
- address: "{socks5_ip}:{socks5_port}"
  protocol:
    type: socks
    udp_enabled: true
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_proxy:
        address: "{snell_ip}:{snell_port}"
        protocol:
          type: snell
          cipher: aes-256-gcm
          password: "{TEST_PASSWORD}"
          udp_enabled: true

- address: "{snell_ip}:{snell_port}"
  protocol:
    type: snell
    cipher: aes-256-gcm
    password: "{TEST_PASSWORD}"
"#,
        socks5_ip = socks5_ip,
        socks5_port = socks5_port,
        snell_ip = snell_ip,
        snell_port = snell_port,
        TEST_PASSWORD = TEST_PASSWORD
    );

    let _shoes = start_shoes_server(&config)?;
    ports.wait_for_all_ports().await?;

    let association = Socks5UdpAssociation::connect(&socks5_ip, socks5_port).await?;

    // Test with hostname "localhost" instead of IP address
    // This exercises the hostname encoding path in Snell UDP
    for i in 0..5 {
        let msg = format!("Hostname test packet {}", i);
        let response = association
            .send_to_hostname("localhost", echo_port, msg.as_bytes())
            .await?;

        let resp_str = String::from_utf8_lossy(&response);
        assert!(
            resp_str.starts_with(&msg),
            "Packet {}: expected '{}', got '{}'",
            i,
            msg,
            resp_str
        );
        eprintln!("[TEST] Hostname packet {} OK", i);
    }

    eprintln!("[TEST] Hostname destination test passed");
    Ok(())
}
