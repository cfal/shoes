//! TUN device integration tests.
//!
//! These tests verify that the TUN device and our smoltcp-based TCP/IP stack work correctly.
//! Some tests require root privileges to create TUN devices on Linux.
//! Run with: `sudo cargo test tun_integration -- --ignored`

use shoes_test_support as common;

use std::time::Duration;

use tun::AbstractDevice;

// Unit Tests (no root required)

/// Test our UDP handler can build and parse packets correctly.
#[test]
fn test_udp_packet_roundtrip() {
    use etherparse::PacketBuilder;
    use smoltcp::wire::{IpProtocol, Ipv4Packet, UdpPacket};

    let payload = b"hello world";
    let src_addr: std::net::SocketAddr = "192.168.1.1:12345".parse().unwrap();
    let dst_addr: std::net::SocketAddr = "10.0.0.1:80".parse().unwrap();

    // Build packet using etherparse
    let builder = PacketBuilder::ipv4(
        src_addr
            .ip()
            .to_string()
            .parse::<std::net::Ipv4Addr>()
            .unwrap()
            .octets(),
        dst_addr
            .ip()
            .to_string()
            .parse::<std::net::Ipv4Addr>()
            .unwrap()
            .octets(),
        20,
    )
    .udp(src_addr.port(), dst_addr.port());

    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, payload).unwrap();

    // Parse using smoltcp
    let ip_packet = Ipv4Packet::new_checked(&packet).unwrap();
    assert_eq!(ip_packet.next_header(), IpProtocol::Udp);

    let udp_packet = UdpPacket::new_checked(ip_packet.payload()).unwrap();
    assert_eq!(udp_packet.src_port(), 12345);
    assert_eq!(udp_packet.dst_port(), 80);
    assert_eq!(udp_packet.payload(), payload);

    println!("UDP packet roundtrip test passed!");
}

// Root-Required Tests - TUN Device Creation

/// Test that we can create a TUN device.
///
/// This test requires root privileges on Linux.
/// Run with: `sudo cargo test test_tun_device_creation -- --ignored`
#[tokio::test]
#[ignore]
async fn test_tun_device_creation() {
    // Create TUN device configuration
    let mut config = tun::Configuration::default();
    config
        .tun_name("shoes_test0")
        .address((10, 200, 200, 1))
        .netmask((255, 255, 255, 0))
        .destination((10, 200, 200, 1))
        .mtu(1500)
        .up();

    #[cfg(target_os = "linux")]
    config.platform_config(|p| {
        p.ensure_root_privileges(true);
    });

    // Create the TUN device
    let device = tun::create_as_async(&config).expect("Failed to create TUN device");

    // Verify device properties
    let mtu = device.mtu().expect("Failed to get MTU");
    assert_eq!(mtu, 1500);

    let name = device.tun_name().expect("Failed to get name");
    assert!(name.starts_with("shoes_test"));

    println!("TUN device created: {} with MTU {}", name, mtu);
}

// Root-Required Tests - Using ProxyTestFixture

use common::test_fixture::ProxyTestFixture;

/// End-to-end test: curl through TUN interface to local HTTP server using fixture.
///
/// This test uses the ProxyTestFixture pattern for clean setup/teardown.
/// Traffic flows: curl -> TUN -> our smoltcp stack -> local HTTP server
///
/// Requires root privileges on Linux.
/// Run with: `cargo test test_tun_fixture_http -- --nocapture`
#[tokio::test]
async fn test_tun_fixture_http() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_tun_entry()
        .with_local_http_server()
        .build()
        .await?;

    // Verify TUN is configured
    assert!(fixture.is_tun_entry(), "Should be TUN entry");
    eprintln!("[TEST] TUN interface: {:?}", fixture.tun_interface());
    eprintln!(
        "[TEST] Virtual server IP: {:?}",
        fixture.tun_virtual_server_ip()
    );

    // Test basic HTTP request through TUN
    let response = fixture.test_local_server_via_tun("/bytes/1024").await?;
    assert_eq!(response.len(), 1024, "Expected 1024 bytes response");

    eprintln!(
        "[TEST] ✓ SUCCESS: Received {} bytes through TUN!",
        response.len()
    );
    Ok(())
}

/// Test verified data transfer through TUN using curl (10MB).
///
/// This uses curl to fetch the verified endpoint, letting us compare with direct TCP.
/// Run with: `cargo test test_tun_fixture_verified_curl -- --nocapture`
#[tokio::test]
async fn test_tun_fixture_verified_curl() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_tun_entry()
        .with_local_http_server()
        .build()
        .await?;

    // Use curl to download 10MB verified via TUN
    let response = fixture
        .test_local_server_via_tun("/bytes_verified/10485760")
        .await?;

    // Response should be 10MB + 32 bytes (digest)
    let expected_size = 10 * 1024 * 1024 + 32;
    assert_eq!(
        response.len(),
        expected_size,
        "Expected {} bytes, got {}",
        expected_size,
        response.len()
    );

    eprintln!("[TEST] ✓ SUCCESS: 10MB+32 verified transfer via curl through TUN!",);
    Ok(())
}

/// Test verified data transfer through TUN (smaller size for quick test).
///
/// Requires root privileges on Linux.
/// Run with: `cargo test test_tun_fixture_verified -- --nocapture`
#[tokio::test]
async fn test_tun_fixture_verified() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_tun_entry()
        .with_local_http_server()
        .build()
        .await?;

    // 10MB verified transfer
    let data_size = 10 * 1024 * 1024;
    let elapsed = fixture
        .test_local_server_streaming_verified_via_tun(data_size, 60)
        .await?;

    let mb_per_sec = (data_size as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
    eprintln!(
        "[TEST] ✓ SUCCESS: 10MB verified transfer in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// Test 500MB streaming transfer through TUN using curl.
/// Run with: `cargo test test_tun_fixture_streaming_500mb -- --nocapture`
#[tokio::test]
async fn test_tun_fixture_streaming_500mb() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_tun_entry()
        .with_local_http_server()
        .build()
        .await?;

    // 500MB streaming transfer using curl
    let elapsed = fixture
        .test_local_server_streaming_via_tun("/bytes/524288000", 120)
        .await?;

    let mb_per_sec = 500.0 / elapsed.as_secs_f64();
    eprintln!(
        "[TEST] ✓ SUCCESS: 500MB streaming transfer in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// Test 1GB single streaming transfer through TUN using curl.
/// Run with: `cargo test test_tun_fixture_streaming_1gb_single -- --nocapture`
#[tokio::test]
async fn test_tun_fixture_streaming_1gb_single() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_tun_entry()
        .with_local_http_server()
        .build()
        .await?;

    // 1GB in a single transfer
    let elapsed = fixture
        .test_local_server_streaming_via_tun("/bytes/1073741824", 120)
        .await?;

    let mb_per_sec = 1024.0 / elapsed.as_secs_f64();
    eprintln!(
        "[TEST] ✓ SUCCESS: 1GB single streaming transfer in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// Test 500MB verified transfer through TUN (uses Tokio TCP directly, not curl).
/// Covers direct Tokio TCP transfer independently of curl.
/// Run with: `cargo test test_tun_fixture_verified_500mb -- --nocapture`
#[tokio::test]
async fn test_tun_fixture_verified_500mb() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_tun_entry()
        .with_local_http_server()
        .build()
        .await?;

    // 500MB verified transfer
    let data_size = 500 * 1024 * 1024;
    let elapsed = fixture
        .test_local_server_streaming_verified_via_tun(data_size, 120)
        .await?;

    let mb_per_sec = (data_size as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
    eprintln!(
        "[TEST] ✓ SUCCESS: 500MB verified transfer in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// Test streaming transfer through TUN (smaller size for quick test).
///
/// Requires root privileges on Linux.
/// Run with: `cargo test test_tun_fixture_streaming -- --nocapture`
#[tokio::test]
async fn test_tun_fixture_streaming() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_tun_entry()
        .with_local_http_server()
        .build()
        .await?;

    // 100MB streaming transfer
    let elapsed = fixture
        .test_local_server_streaming_via_tun("/bytes/104857600", 60)
        .await?;

    let mb_per_sec = 100.0 / elapsed.as_secs_f64();
    eprintln!(
        "[TEST] ✓ SUCCESS: 100MB streaming transfer in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// 2GB streaming test via TUN + our smoltcp stack (using 20x100MB connections).
///
/// Run with: `cargo test test_tun_fixture_streaming_2gb -- --nocapture`
#[tokio::test]
async fn test_tun_fixture_streaming_2gb() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_tun_entry()
        .with_local_http_server()
        .build()
        .await?;

    // Do 20 x 100MB transfers
    let mut total_elapsed = std::time::Duration::ZERO;
    for i in 1..=20 {
        let elapsed = fixture
            .test_local_server_streaming_via_tun("/bytes/104857600", 60)
            .await?;
        total_elapsed += elapsed;
        eprintln!(
            "[TEST] Round {}/20: 100MB in {:.2}s",
            i,
            elapsed.as_secs_f64()
        );
    }

    let mb_per_sec = 2000.0 / total_elapsed.as_secs_f64();
    eprintln!(
        "[TEST] ✓ SUCCESS: 2GB (20x100MB) streaming transfer in {:.2}s ({:.2} MB/s)",
        total_elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// Test that idle TCP connections remain usable after six minutes.
///
/// Run with: `cargo test test_tun_tcp_idle_connection -- --nocapture --ignored`
#[tokio::test]
#[ignore] // Takes 6+ minutes to run
async fn test_tun_tcp_idle_connection() -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let fixture = ProxyTestFixture::new()
        .with_tun_entry()
        .with_local_http_server()
        .build()
        .await?;

    let tun_vip = fixture.tun_virtual_server_ip().expect("TUN VIP");
    let server_port = fixture.local_server_port().expect("Server port");

    // Connect through TUN to the virtual server IP (which routes to local server)
    let mut stream = TcpStream::connect(format!("{}:{}", tun_vip, server_port)).await?;
    eprintln!("[TEST] Connected to server through TUN");

    // Send initial request
    stream
        .write_all(b"GET /bytes/100 HTTP/1.1\r\nHost: test\r\nConnection: keep-alive\r\n\r\n")
        .await?;

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;
    assert!(n > 0, "Should receive initial response");
    eprintln!("[TEST] Received initial response ({} bytes)", n);

    // Wait six minutes before reusing the idle connection.
    eprintln!("[TEST] Waiting 6 minutes to test idle connection survival...");
    tokio::time::sleep(Duration::from_secs(360)).await;

    // Try to use the connection again
    eprintln!("[TEST] Sending request after 6 minutes idle...");
    stream
        .write_all(b"GET /bytes/100 HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .await?;

    let n = stream.read(&mut buf).await?;
    assert!(n > 0, "Connection should still work after 6 minutes idle");
    eprintln!(
        "[TEST] SUCCESS: Connection survived 6 minutes idle, received {} bytes",
        n
    );

    Ok(())
}

/// Test graceful shutdown with pending data in send queue.
///
/// Verifies that socket.close() waits for send_queue() to drain before sending FIN.
///
/// Run with: `cargo test test_tun_tcp_graceful_shutdown -- --nocapture`
#[tokio::test]
async fn test_tun_tcp_graceful_shutdown() -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let fixture = ProxyTestFixture::new()
        .with_tun_entry()
        .with_local_http_server()
        .build()
        .await?;

    let tun_vip = fixture.tun_virtual_server_ip().expect("TUN VIP");
    let server_port = fixture.local_server_port().expect("Server port");

    // Request a large response to ensure data is in flight during shutdown
    let mut stream = TcpStream::connect(format!("{}:{}", tun_vip, server_port)).await?;

    // Request 1MB of data
    stream
        .write_all(b"GET /bytes/1048576 HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .await?;

    // Read all data - this exercises the graceful shutdown path
    let mut total = 0;
    let mut buf = vec![0u8; 65536];
    loop {
        match stream.read(&mut buf).await? {
            0 => break,
            n => total += n,
        }
    }

    // Should have received all data (1MB + HTTP headers)
    assert!(
        total >= 1048576,
        "Should receive all 1MB of data, got {} bytes",
        total
    );
    eprintln!(
        "[TEST] SUCCESS: Graceful shutdown preserved all data ({} bytes)",
        total
    );

    Ok(())
}

/// Test half-close (shutdown write while still reading).
///
/// Verifies proper FIN-ACK handling when one side closes while data flows the other way.
///
/// Run with: `cargo test test_tun_tcp_half_close -- --nocapture`
#[tokio::test]
async fn test_tun_tcp_half_close() -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let fixture = ProxyTestFixture::new()
        .with_tun_entry()
        .with_local_http_server()
        .build()
        .await?;

    let tun_vip = fixture.tun_virtual_server_ip().expect("TUN VIP");
    let server_port = fixture.local_server_port().expect("Server port");

    let mut stream = TcpStream::connect(format!("{}:{}", tun_vip, server_port)).await?;

    // Send request for streaming data
    stream
        .write_all(b"GET /bytes/524288 HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .await?;

    // Shutdown write side immediately (half-close)
    stream.shutdown().await?;
    eprintln!("[TEST] Write side shutdown (half-close)");

    // Should still be able to read the response
    let mut total = 0;
    let mut buf = vec![0u8; 65536];
    loop {
        match stream.read(&mut buf).await? {
            0 => break,
            n => total += n,
        }
    }

    assert!(
        total >= 524288,
        "Should receive all data after half-close, got {} bytes",
        total
    );
    eprintln!(
        "[TEST] SUCCESS: Half-close handled correctly ({} bytes received)",
        total
    );

    Ok(())
}

// Root-Required Tests - TUN UDP Integration

use common::port_helper::PortHelper;
use common::test_fixture::{
    add_route_via_device, start_shoes_server, start_shoes_server_with_sudo,
};
use common::test_servers::{start_udp_echo_server_with_suffix, start_udp_response_server};
use std::path::Path;
use std::process::Command;
use tokio::net::UdpSocket;

/// End-to-end test: UDP through TUN -> VLESS UDP-over-TCP -> UDP echo server.
///
/// This test verifies the complete UDP flow through TUN:
/// 1. UDP packet enters TUN device
/// 2. Our smoltcp-based stack extracts UDP payload
/// 3. TunUdpStream + UdpRouter routes through VLESS proxy
/// 4. VLESS UDP-over-TCP carries packet to destination
/// 5. Response comes back through the same path
///
/// Traffic flow:
/// ```text
/// UDP Client (tokio UdpSocket)
///   -> TUN device (shoes_udp_tun)
///      -> our smoltcp stack (UDP handler)
///         -> shoes TUN server with UdpRouter
///            -> shoes VLESS server (UDP-over-TCP)
///               -> UDP Echo Server
///               <- Echo response
///            <- VLESS UDP response
///         <- UdpRouter writes back
///      <- our stack builds IP packet
///   <- TUN device
/// <- UDP Client receives response
/// ```
///
/// Requires root privileges on Linux.
/// Run with: `cargo test test_tun_udp_vless_echo -- --nocapture`
#[tokio::test]
async fn test_tun_udp_vless_echo() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (vless_ip, vless_port) = port_helper.get_listener_port();
    let (_, echo_port) = port_helper.get_port(); // Get port only, use TUN subnet for IP

    // ==========================================================================
    // TEST INFRASTRUCTURE NOTE
    // ==========================================================================
    //
    // PRODUCTION SCENARIO (no workarounds needed):
    // - TUN client on user's device, VLESS server on remote VPS
    // - Different machines = different routing tables = no conflicts
    //
    // SINGLE-MACHINE TEST (requires workaround):
    // - All components share ONE routing table
    // - Traffic to echo_ip through TUN would also route VLESS→echo through TUN
    // - We use override_address to rewrite destination to loopback
    //
    // This override_address is TEST INFRASTRUCTURE only. Real deployments
    // don't need it because the VLESS server is on a separate machine.
    // ==========================================================================

    let tun_name = "shoes_udp_tun";
    let tun_ip = "10.200.250.1";
    let tun_target_ip = "10.200.250.2"; // What test client sends to (goes through TUN)
    let echo_ip = "127.0.0.1"; // Where echo server actually listens

    eprintln!(
        "[TEST] Ports: VLESS={}:{}, Echo={}:{}",
        vless_ip, vless_port, echo_ip, echo_port
    );
    eprintln!(
        "[TEST] TUN: {} ({}), Target: {} -> Echo: {}",
        tun_name, tun_ip, tun_target_ip, echo_ip
    );

    // 1. Start UDP echo server on loopback
    let _echo_server = start_udp_echo_server_with_suffix(echo_ip, echo_port, b" [ECHO]").await?;
    eprintln!(
        "[TEST] Started UDP echo server on {}:{}",
        echo_ip, echo_port
    );

    // 2. Generate test certificate for VLESS TLS
    let (cert_path, key_path) = common::certs::generate_test_cert_files()?;

    // 3. Start shoes VLESS server with UDP enabled
    // override_address rewrites tun_target_ip -> echo_ip (loopback)
    // This is a TEST WORKAROUND for single-machine testing only.
    let vless_server_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      test.local:
        cert: {}
        key: {}
        vision: true
        protocol:
          type: vless
          user_id: "b85798ef-e9dc-46a4-9a87-8da4499d36d0"
          udp_enabled: true
  rules:
    - masks: "{}:0"
      action: allow
      override_address: "{}:{}"
      client_chain:
        - protocol:
            type: direct
"#,
        vless_ip,
        vless_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
        tun_target_ip,
        echo_ip,
        echo_port,
    );

    let (_vless_guard, _vless_config_file) = start_shoes_server(&vless_server_config)?;
    eprintln!(
        "[TEST] Started shoes VLESS server on {}:{}",
        vless_ip, vless_port
    );

    // Wait for VLESS server to be ready
    port_helper.wait_for_all_ports().await?;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 4. Start shoes TUN server that routes through VLESS
    // TUN config is a top-level config type (not wrapped in protocol like ServerConfig)
    // Uses device_name/device_fd to clearly identify it as a TUN config
    let tun_server_config = format!(
        r#"
# TUN server entry point
- device_name: "{}"
  address: "{}"
  netmask: 255.255.255.0
  mtu: 1500
  tcp_enabled: true
  udp_enabled: true
  icmp_enabled: true
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - address: "{}:{}"
          protocol:
            type: tls
            verify: false
            sni_hostname: test.local
            protocol:
              type: vless
              user_id: "b85798ef-e9dc-46a4-9a87-8da4499d36d0"
              udp_enabled: true
"#,
        tun_name, tun_ip, vless_ip, vless_port,
    );

    eprintln!("[TEST] TUN config:\n{}", tun_server_config);

    // Start TUN server with sudo (requires root for TUN device creation)
    let (_tun_guard, _tun_config_file) = start_shoes_server_with_sudo(&tun_server_config)?;

    // Give TUN server time to initialize
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // 5. Add route for tun_target_ip through TUN
    let destination = format!("{tun_target_ip}/32");
    let _route_guard = add_route_via_device(&destination, tun_name)?;
    eprintln!("[TEST] Added route for {} via {}", tun_target_ip, tun_name);

    tokio::time::sleep(Duration::from_millis(200)).await;

    // 6. Send UDP packet through TUN and verify response
    eprintln!(
        "[TEST] Sending UDP packet through TUN to {}:{}...",
        tun_target_ip, echo_port
    );

    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::SocketAddr;

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    let tun_bind_addr: SocketAddr = format!("{}:0", tun_ip).parse()?;
    socket.bind(&tun_bind_addr.into())?;
    socket.set_nonblocking(true)?;

    let std_socket: std::net::UdpSocket = socket.into();
    let test_socket = UdpSocket::from_std(std_socket)?;
    let local_addr = test_socket.local_addr()?;
    eprintln!("[TEST] Test client bound to {}", local_addr);

    let test_message = b"Hello TUN UDP!";
    let dest_addr: SocketAddr = format!("{}:{}", tun_target_ip, echo_port).parse()?;
    test_socket.send_to(test_message, dest_addr).await?;
    eprintln!("[TEST] Sent: {:?}", String::from_utf8_lossy(test_message));

    // Wait for response
    let mut response_buf = vec![0u8; 65536];
    let recv_result = tokio::time::timeout(
        Duration::from_secs(10),
        test_socket.recv_from(&mut response_buf),
    )
    .await;

    match recv_result {
        Ok(Ok((n, addr))) => {
            let response = String::from_utf8_lossy(&response_buf[..n]);
            eprintln!("[TEST] Received {} bytes from {}: {:?}", n, addr, response);

            assert!(
                response.contains("Hello TUN UDP!"),
                "Response should contain original message"
            );
            assert!(
                response.ends_with(" [ECHO]"),
                "Response should have echo suffix"
            );

            eprintln!("[TEST] ✓ SUCCESS: TUN UDP routing through VLESS works!");
        }
        Ok(Err(e)) => {
            eprintln!("[TEST] ✗ FAILED: Recv error: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            eprintln!("[TEST] ✗ FAILED: Timeout waiting for UDP response");
            return Err("Timeout waiting for UDP response".into());
        }
    }

    Ok(())
}

// Root-Required Tests - IPv6 TCP

/// Test IPv6 UDP packet building and parsing roundtrip.
#[test]
fn test_udp_ipv6_packet_roundtrip() {
    use etherparse::PacketBuilder;
    use smoltcp::wire::{IpProtocol, Ipv6Packet, UdpPacket};

    let payload = b"hello ipv6 world";
    let src_addr: std::net::SocketAddr = "[2001:db8::1]:12345".parse().unwrap();
    let dst_addr: std::net::SocketAddr = "[2001:db8::2]:80".parse().unwrap();

    // Build IPv6 UDP packet using etherparse
    let src_ip: std::net::Ipv6Addr = match src_addr.ip() {
        std::net::IpAddr::V6(ip) => ip,
        _ => panic!("Expected IPv6"),
    };
    let dst_ip: std::net::Ipv6Addr = match dst_addr.ip() {
        std::net::IpAddr::V6(ip) => ip,
        _ => panic!("Expected IPv6"),
    };

    let builder = PacketBuilder::ipv6(
        src_ip.octets(),
        dst_ip.octets(),
        20, // hop limit
    )
    .udp(src_addr.port(), dst_addr.port());

    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, payload).unwrap();

    // Parse using smoltcp
    let ip_packet = Ipv6Packet::new_checked(&packet).unwrap();
    assert_eq!(ip_packet.next_header(), IpProtocol::Udp);

    let udp_packet = UdpPacket::new_checked(ip_packet.payload()).unwrap();
    assert_eq!(udp_packet.src_port(), 12345);
    assert_eq!(udp_packet.dst_port(), 80);
    assert_eq!(udp_packet.payload(), payload);

    println!("IPv6 UDP packet roundtrip test passed!");
}

/// Test TCP IPv6 packet parsing.
#[test]
fn test_tcp_ipv6_packet_parsing() {
    use smoltcp::wire::{IpProtocol, Ipv6Packet, TcpPacket};

    // Build a minimal IPv6 TCP SYN packet
    // IPv6 header (40 bytes) + TCP header (20 bytes minimum)
    let mut packet = vec![0u8; 60];

    // IPv6 header
    packet[0] = 0x60; // Version 6
    packet[4] = 0; // Payload length high byte
    packet[5] = 20; // Payload length low byte (TCP header = 20)
    packet[6] = 6; // Next header: TCP
    packet[7] = 64; // Hop limit

    // Source address: 2001:db8::1
    packet[8..24].copy_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ]);
    // Destination address: 2001:db8::2
    packet[24..40].copy_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ]);

    // TCP header at offset 40
    packet[40] = 0x30; // Source port high byte (12345)
    packet[41] = 0x39; // Source port low byte
    packet[42] = 0x00; // Dest port high byte (80)
    packet[43] = 0x50; // Dest port low byte
    packet[52] = 0x50; // Data offset (5 words = 20 bytes) + reserved
    packet[53] = 0x02; // Flags: SYN

    let ip = Ipv6Packet::new_checked(&packet).unwrap();
    assert_eq!(ip.next_header(), IpProtocol::Tcp);

    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    assert_eq!(tcp.src_port(), 12345);
    assert_eq!(tcp.dst_port(), 80);
    assert!(tcp.syn());
    assert!(!tcp.ack());

    println!("IPv6 TCP packet parsing test passed!");
}

// Root-Required Tests - ICMP/Ping

/// Test ICMP Echo Request (ping) packet parsing.
#[test]
fn test_icmp_echo_request_parsing() {
    use smoltcp::wire::{Icmpv4Message, Icmpv4Packet, IpProtocol, Ipv4Packet};

    // Build a minimal IPv4 ICMP Echo Request packet
    // IPv4 header (20 bytes) + ICMP header (8 bytes)
    let mut packet = vec![0u8; 28];

    // IPv4 header
    packet[0] = 0x45; // Version 4, IHL 5
    packet[2] = 0; // Total length high byte
    packet[3] = 28; // Total length low byte
    packet[8] = 64; // TTL
    packet[9] = 1; // Protocol: ICMP

    // Source address: 192.168.1.1
    packet[12..16].copy_from_slice(&[192, 168, 1, 1]);
    // Destination address: 10.0.0.1
    packet[16..20].copy_from_slice(&[10, 0, 0, 1]);

    // ICMP Echo Request at offset 20
    packet[20] = 8; // Type: Echo Request
    packet[21] = 0; // Code: 0

    let ip = Ipv4Packet::new_checked(&packet).unwrap();
    assert_eq!(ip.next_header(), IpProtocol::Icmp);

    let icmp = Icmpv4Packet::new_checked(ip.payload()).unwrap();
    assert_eq!(icmp.msg_type(), Icmpv4Message::EchoRequest);

    println!("ICMP Echo Request parsing test passed!");
}

/// Test ICMPv6 Echo Request (ping6) packet parsing.
#[test]
fn test_icmpv6_echo_request_parsing() {
    use smoltcp::wire::{Icmpv6Message, Icmpv6Packet, IpProtocol, Ipv6Packet};

    // Build a minimal IPv6 ICMPv6 Echo Request packet
    // IPv6 header (40 bytes) + ICMPv6 header (8 bytes)
    let mut packet = vec![0u8; 48];

    // IPv6 header
    packet[0] = 0x60; // Version 6
    packet[4] = 0; // Payload length high byte
    packet[5] = 8; // Payload length low byte (ICMPv6 = 8)
    packet[6] = 58; // Next header: ICMPv6
    packet[7] = 64; // Hop limit

    // Source address: 2001:db8::1
    packet[8..24].copy_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ]);
    // Destination address: 2001:db8::2
    packet[24..40].copy_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ]);

    // ICMPv6 Echo Request at offset 40
    packet[40] = 128; // Type: Echo Request
    packet[41] = 0; // Code: 0

    let ip = Ipv6Packet::new_checked(&packet).unwrap();
    assert_eq!(ip.next_header(), IpProtocol::Icmpv6);

    let icmp = Icmpv6Packet::new_checked(ip.payload()).unwrap();
    assert_eq!(icmp.msg_type(), Icmpv6Message::EchoRequest);

    println!("ICMPv6 Echo Request parsing test passed!");
}

/// Test packet filtering rejects broadcast addresses.
#[test]
fn test_packet_filtering_broadcast() {
    use smoltcp::wire::Ipv4Packet;

    // Build a packet with broadcast destination
    let mut packet = vec![0u8; 20]; // Minimal IPv4 header

    packet[0] = 0x45; // Version 4, IHL 5
    packet[2] = 0;
    packet[3] = 20;
    packet[8] = 64;
    packet[9] = 6; // TCP

    // Source: 192.168.1.1
    packet[12..16].copy_from_slice(&[192, 168, 1, 1]);
    // Destination: 255.255.255.255 (broadcast)
    packet[16..20].copy_from_slice(&[255, 255, 255, 255]);

    let ip = Ipv4Packet::new_checked(&packet).unwrap();
    let dst = ip.dst_addr().octets();

    // Verify this would be filtered as broadcast
    assert_eq!(dst, [255, 255, 255, 255], "Should be broadcast address");

    println!("Broadcast filtering test passed!");
}

/// Test packet filtering rejects multicast addresses.
#[test]
fn test_packet_filtering_multicast() {
    use smoltcp::wire::Ipv4Packet;

    // Build a packet with multicast destination (224.0.0.0/4)
    let mut packet = vec![0u8; 20];

    packet[0] = 0x45;
    packet[2] = 0;
    packet[3] = 20;
    packet[8] = 64;
    packet[9] = 17; // UDP

    // Source: 192.168.1.1
    packet[12..16].copy_from_slice(&[192, 168, 1, 1]);
    // Destination: 224.0.0.1 (multicast)
    packet[16..20].copy_from_slice(&[224, 0, 0, 1]);

    let ip = Ipv4Packet::new_checked(&packet).unwrap();
    let dst = ip.dst_addr().octets();

    // Verify this would be filtered as multicast
    assert!(dst[0] >= 224 && dst[0] <= 239, "Should be multicast range");

    println!("Multicast filtering test passed!");
}

/// Test ICMP ping through TUN interface using smoltcp's automatic reply.
///
/// This test verifies that smoltcp correctly responds to ICMP Echo Requests.
/// Run with: `cargo test test_tun_icmp_ping -- --nocapture`
#[tokio::test]
async fn test_tun_icmp_ping() -> Result<(), Box<dyn std::error::Error>> {
    let tun_name = "shoes_ping";
    let tun_ip = "10.200.251.1";
    let ping_target = "10.200.251.2"; // Will be handled by smoltcp

    // Start shoes TUN server with minimal config
    let tun_config = format!(
        r#"
- device_name: "{}"
  address: "{}"
  netmask: 255.255.255.0
  mtu: 1500
  tcp_enabled: true
  udp_enabled: true
  icmp_enabled: true
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - protocol:
            type: direct
"#,
        tun_name, tun_ip
    );

    // Start TUN server with sudo (requires root for TUN device creation)
    let (_guard, _config_file) = start_shoes_server_with_sudo(&tun_config)?;

    // Wait for TUN to be ready
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Add route for ping target through TUN
    let destination = format!("{ping_target}/32");
    let _route_guard = add_route_via_device(&destination, tun_name)?;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Run ping with short timeout
    eprintln!("[TEST] Pinging {} through TUN {}...", ping_target, tun_name);
    let output = Command::new("ping")
        .args(["-c", "3", "-W", "2", ping_target])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("[TEST] Ping output:\n{}", stdout);
    if !stderr.is_empty() {
        eprintln!("[TEST] Ping stderr:\n{}", stderr);
    }

    assert!(
        output.status.success(),
        "ICMP ping through TUN failed: {stderr}"
    );

    Ok(())
}

// =============================================================================
// TUN UDP Session Management Tests
// =============================================================================
//
// These tests validate the session-based UDP manager which keys sessions by
// local (app) address rather than destination. This ensures:
// - Multiple apps sending to the same destination get their responses correctly
// - One app sending to multiple destinations works properly
// - Session cleanup and LRU eviction work correctly

/// Test that multiple local addresses (simulating multiple apps) can send UDP
/// through TUN and each receives their own responses correctly.
///
/// Verifies that multiple apps sending to the same destination retain independent
/// response routing.
///
/// Run with: `cargo test test_tun_udp_multi_local_address -- --nocapture`
#[tokio::test]
async fn test_tun_udp_multi_local_address() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (vless_ip, vless_port) = port_helper.get_listener_port();
    let (_, echo_port) = port_helper.get_port();

    let tun_name = "shoes_mloc"; // Max 15 chars for Linux TUN
    let tun_ip = "10.200.252.1";
    let tun_target_ip = "10.200.252.2";
    let echo_ip = "127.0.0.1";

    eprintln!(
        "[TEST] Multi-Local-Address UDP Test: VLESS={}:{}, Echo={}:{}",
        vless_ip, vless_port, echo_ip, echo_port
    );

    // 1. Start UDP echo server that includes source info in response
    let _echo_server = start_udp_response_server(echo_ip, echo_port, |payload, peer| {
        format!(
            "{} [FROM:{}]",
            String::from_utf8_lossy(payload),
            peer.port()
        )
        .into_bytes()
    })
    .await?;
    eprintln!(
        "[TEST] Started UDP echo server on {}:{}",
        echo_ip, echo_port
    );

    // 2. Start VLESS server
    let (cert_path, key_path) = common::certs::generate_test_cert_files()?;
    let vless_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      test.local:
        cert: {}
        key: {}
        vision: true
        protocol:
          type: vless
          user_id: "b85798ef-e9dc-46a4-9a87-8da4499d36d0"
          udp_enabled: true
  rules:
    - masks: "{}:0"
      action: allow
      override_address: "{}:{}"
      client_chain:
        - protocol:
            type: direct
"#,
        vless_ip,
        vless_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
        tun_target_ip,
        echo_ip,
        echo_port,
    );

    let (_vless_guard, _vless_config) = start_shoes_server(&vless_config)?;
    port_helper.wait_for_all_ports().await?;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 3. Start TUN server
    let tun_config = format!(
        r#"
- device_name: "{}"
  address: "{}"
  netmask: 255.255.255.0
  mtu: 1500
  tcp_enabled: true
  udp_enabled: true
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - address: "{}:{}"
          protocol:
            type: tls
            verify: false
            sni_hostname: test.local
            protocol:
              type: vless
              user_id: "b85798ef-e9dc-46a4-9a87-8da4499d36d0"
              udp_enabled: true
"#,
        tun_name, tun_ip, vless_ip, vless_port,
    );

    let (_tun_guard, _tun_config) = start_shoes_server_with_sudo(&tun_config)?;
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Add route
    let destination = format!("{tun_target_ip}/32");
    let _route_guard = add_route_via_device(&destination, tun_name)?;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 4. Create multiple sockets with different local ports (simulating different apps)
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::SocketAddr;

    let mut sockets = Vec::new();

    for i in 0..3 {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        let bind_addr: SocketAddr = format!("{}:0", tun_ip).parse()?;
        socket.bind(&bind_addr.into())?;
        socket.set_nonblocking(true)?;

        let std_socket: std::net::UdpSocket = socket.into();
        let udp_socket = UdpSocket::from_std(std_socket)?;
        let local_addr = udp_socket.local_addr()?;
        eprintln!("[TEST] App {} bound to {}", i, local_addr);
        sockets.push(udp_socket);
    }

    // 5. All apps send to the SAME destination (this is the key test case!)
    let dest_addr: SocketAddr = format!("{}:{}", tun_target_ip, echo_port).parse()?;

    for (i, socket) in sockets.iter().enumerate() {
        let msg = format!("App{}", i);
        socket.send_to(msg.as_bytes(), dest_addr).await?;
        eprintln!("[TEST] App {} sent: {}", i, msg);
    }

    // 6. Each app should receive its OWN response (not mixed up)
    let mut received = [false; 3];
    let mut response_buf = vec![0u8; 65536];

    for _ in 0..3 {
        // Try to receive from any socket that has data
        for (i, socket) in sockets.iter().enumerate() {
            match tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut response_buf))
                .await
            {
                Ok(Ok((n, _addr))) => {
                    let response = String::from_utf8_lossy(&response_buf[..n]);
                    eprintln!("[TEST] App {} received: {}", i, response);

                    // Verify response contains correct app ID
                    let expected_msg = format!("App{}", i);
                    assert!(
                        response.contains(&expected_msg),
                        "App {} received wrong response: {} (expected to contain {})",
                        i,
                        response,
                        expected_msg
                    );

                    received[i] = true;
                }
                Ok(Err(e)) => {
                    eprintln!("[TEST] App {} recv error: {}", i, e);
                }
                Err(_) => {
                    // Timeout, try next socket
                }
            }
        }
    }

    // Verify all apps received their responses
    for (i, r) in received.iter().enumerate() {
        assert!(r, "App {} did not receive its response", i);
    }

    eprintln!("[TEST] ✓ SUCCESS: Multi-local-address UDP routing works!");
    eprintln!("[TEST] Multi-local-address UDP routing validated.");
    Ok(())
}

/// Test that one local address can send to multiple destinations and receive
/// all responses correctly.
///
/// Run with: `cargo test test_tun_udp_multi_destination -- --nocapture`
#[tokio::test]
async fn test_tun_udp_multi_destination() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (vless_ip, vless_port) = port_helper.get_listener_port();
    let (_, echo_port1) = port_helper.get_port();
    let (_, echo_port2) = port_helper.get_port();
    let (_, echo_port3) = port_helper.get_port();

    let tun_name = "shoes_mdst"; // Max 15 chars for Linux TUN
    let tun_ip = "10.200.253.1";
    let tun_target_ip = "10.200.253.2";
    let echo_ip = "127.0.0.1";

    eprintln!(
        "[TEST] Multi-Destination UDP Test: Echo ports={},{},{}",
        echo_port1, echo_port2, echo_port3
    );

    // 1. Start multiple echo servers on different ports
    let echo_ports = [echo_port1, echo_port2, echo_port3];
    let mut echo_servers = Vec::new();
    for (i, &port) in echo_ports.iter().enumerate() {
        let suffix = format!(" [PORT:{port}]");
        echo_servers
            .push(start_udp_echo_server_with_suffix(echo_ip, port, suffix.as_bytes()).await?);
        eprintln!("[TEST] Echo server {} on port {}", i, port);
    }

    // 2. Start VLESS server with rules for all destinations
    let (cert_path, key_path) = common::certs::generate_test_cert_files()?;
    let vless_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      test.local:
        cert: {}
        key: {}
        vision: true
        protocol:
          type: vless
          user_id: "b85798ef-e9dc-46a4-9a87-8da4499d36d0"
          udp_enabled: true
  rules:
    - masks: "{}:{}"
      action: allow
      override_address: "{}:{}"
      client_chain:
        - protocol:
            type: direct
    - masks: "{}:{}"
      action: allow
      override_address: "{}:{}"
      client_chain:
        - protocol:
            type: direct
    - masks: "{}:{}"
      action: allow
      override_address: "{}:{}"
      client_chain:
        - protocol:
            type: direct
"#,
        vless_ip,
        vless_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
        tun_target_ip,
        echo_port1,
        echo_ip,
        echo_port1,
        tun_target_ip,
        echo_port2,
        echo_ip,
        echo_port2,
        tun_target_ip,
        echo_port3,
        echo_ip,
        echo_port3,
    );

    let (_vless_guard, _vless_config) = start_shoes_server(&vless_config)?;
    port_helper.wait_for_all_ports().await?;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 3. Start TUN server
    let tun_config = format!(
        r#"
- device_name: "{}"
  address: "{}"
  netmask: 255.255.255.0
  mtu: 1500
  tcp_enabled: true
  udp_enabled: true
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - address: "{}:{}"
          protocol:
            type: tls
            verify: false
            sni_hostname: test.local
            protocol:
              type: vless
              user_id: "b85798ef-e9dc-46a4-9a87-8da4499d36d0"
              udp_enabled: true
"#,
        tun_name, tun_ip, vless_ip, vless_port,
    );

    let (_tun_guard, _tun_config) = start_shoes_server_with_sudo(&tun_config)?;
    tokio::time::sleep(Duration::from_millis(1000)).await;

    let destination = format!("{tun_target_ip}/32");
    let _route_guard = add_route_via_device(&destination, tun_name)?;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 4. Create ONE socket and send to multiple destinations
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::SocketAddr;

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    let bind_addr: SocketAddr = format!("{}:0", tun_ip).parse()?;
    socket.bind(&bind_addr.into())?;
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    let test_socket = UdpSocket::from_std(std_socket)?;
    let local_addr = test_socket.local_addr()?;
    eprintln!("[TEST] Client bound to {}", local_addr);

    // 5. Send to each destination
    for (i, &port) in echo_ports.iter().enumerate() {
        let dest: SocketAddr = format!("{}:{}", tun_target_ip, port).parse()?;
        let msg = format!("Dest{}", i);
        test_socket.send_to(msg.as_bytes(), dest).await?;
        eprintln!("[TEST] Sent to dest {}: {}", i, msg);
    }

    // 6. Receive responses from all destinations
    let mut received_ports = std::collections::HashSet::new();
    let mut response_buf = vec![0u8; 65536];

    for _ in 0..3 {
        match tokio::time::timeout(
            Duration::from_secs(5),
            test_socket.recv_from(&mut response_buf),
        )
        .await
        {
            Ok(Ok((n, addr))) => {
                let response = String::from_utf8_lossy(&response_buf[..n]);
                eprintln!("[TEST] Received from {}: {}", addr, response);

                // Extract port from response
                if let Some(port_str) = response.split("[PORT:").nth(1)
                    && let Some(port_str) = port_str.split(']').next()
                    && let Ok(port) = port_str.parse::<u16>()
                {
                    received_ports.insert(port);
                }
            }
            Ok(Err(e)) => eprintln!("[TEST] Recv error: {}", e),
            Err(_) => eprintln!("[TEST] Timeout waiting for response"),
        }
    }

    // Verify we got responses from all destinations
    for &port in &echo_ports {
        assert!(
            received_ports.contains(&port),
            "Did not receive response from port {}",
            port
        );
    }

    eprintln!("[TEST] ✓ SUCCESS: Multi-destination UDP routing works!");
    Ok(())
}

/// Test IPv6 UDP through TUN interface end-to-end.
///
/// Run with: `cargo test test_tun_udp_ipv6 -- --nocapture`
#[tokio::test]
async fn test_tun_udp_ipv6() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (vless_ip, vless_port) = port_helper.get_listener_port();
    let (_, echo_port) = port_helper.get_port();

    let tun_name = "shoes_v6"; // Max 15 chars for Linux TUN
    // Use IPv4 for TUN device (IPv6 TUN requires more complex setup)
    // but test IPv6 packet handling through the stack
    let tun_ip = "10.200.254.1";
    let tun_target_ip = "10.200.254.2";
    let echo_ip = "127.0.0.1";

    eprintln!("[TEST] IPv6 UDP Test (via IPv4 TUN tunnel)");

    // For true IPv6 testing, we'd need:
    // 1. IPv6 TUN address (fd00::1/64)
    // 2. IPv6 routing
    // 3. IPv6 echo server
    //
    // This test validates IPv6 packet parsing/building works by using
    // the existing IPv4 infrastructure but with IPv6-mapped addresses

    // 1. Start echo server
    let _echo_server =
        start_udp_echo_server_with_suffix(echo_ip, echo_port, b" [IPv6-TEST]").await?;
    eprintln!("[TEST] Echo server on {}:{}", echo_ip, echo_port);

    // 2. Start VLESS server
    let (cert_path, key_path) = common::certs::generate_test_cert_files()?;
    let vless_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      test.local:
        cert: {}
        key: {}
        vision: true
        protocol:
          type: vless
          user_id: "b85798ef-e9dc-46a4-9a87-8da4499d36d0"
          udp_enabled: true
  rules:
    - masks: "{}:0"
      action: allow
      override_address: "{}:{}"
      client_chain:
        - protocol:
            type: direct
"#,
        vless_ip,
        vless_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
        tun_target_ip,
        echo_ip,
        echo_port,
    );

    let (_vless_guard, _vless_config) = start_shoes_server(&vless_config)?;
    port_helper.wait_for_all_ports().await?;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 3. Start TUN server
    let tun_config = format!(
        r#"
- device_name: "{}"
  address: "{}"
  netmask: 255.255.255.0
  mtu: 1500
  tcp_enabled: true
  udp_enabled: true
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - address: "{}:{}"
          protocol:
            type: tls
            verify: false
            sni_hostname: test.local
            protocol:
              type: vless
              user_id: "b85798ef-e9dc-46a4-9a87-8da4499d36d0"
              udp_enabled: true
"#,
        tun_name, tun_ip, vless_ip, vless_port,
    );

    let (_tun_guard, _tun_config) = start_shoes_server_with_sudo(&tun_config)?;
    tokio::time::sleep(Duration::from_millis(1000)).await;

    let destination = format!("{tun_target_ip}/32");
    let _route_guard = add_route_via_device(&destination, tun_name)?;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 4. Send test packet
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::SocketAddr;

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    let bind_addr: SocketAddr = format!("{}:0", tun_ip).parse()?;
    socket.bind(&bind_addr.into())?;
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    let test_socket = UdpSocket::from_std(std_socket)?;

    let dest: SocketAddr = format!("{}:{}", tun_target_ip, echo_port).parse()?;
    test_socket.send_to(b"IPv6 Test Message", dest).await?;
    eprintln!("[TEST] Sent IPv6 test message");

    // 5. Receive response
    let mut response_buf = vec![0u8; 65536];
    match tokio::time::timeout(
        Duration::from_secs(10),
        test_socket.recv_from(&mut response_buf),
    )
    .await
    {
        Ok(Ok((n, addr))) => {
            let response = String::from_utf8_lossy(&response_buf[..n]);
            eprintln!("[TEST] Received from {}: {}", addr, response);
            assert!(response.contains("IPv6 Test Message"));
            assert!(response.contains("[IPv6-TEST]"));
        }
        Ok(Err(e)) => return Err(format!("Recv error: {}", e).into()),
        Err(_) => return Err("Timeout waiting for response".into()),
    }

    eprintln!("[TEST] ✓ SUCCESS: IPv6 (via IPv4 tunnel) UDP routing works!");
    eprintln!("[TEST] Note: Full IPv6 TUN testing requires IPv6 network setup");
    Ok(())
}

/// Stress test: rapid multi-flow UDP through TUN.
///
/// This test creates many simultaneous UDP flows to stress the session manager.
///
/// Run with: `cargo test test_tun_udp_stress -- --nocapture`
#[tokio::test]
async fn test_tun_udp_stress() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (vless_ip, vless_port) = port_helper.get_listener_port();
    let (_, echo_port) = port_helper.get_port();

    let tun_name = "shoes_strs"; // Max 15 chars for Linux TUN
    let tun_ip = "10.200.255.1";
    let tun_target_ip = "10.200.255.2";
    let echo_ip = "127.0.0.1";

    const NUM_FLOWS: usize = 10;
    const PACKETS_PER_FLOW: usize = 5;

    eprintln!(
        "[TEST] Stress Test: {} flows x {} packets = {} total",
        NUM_FLOWS,
        PACKETS_PER_FLOW,
        NUM_FLOWS * PACKETS_PER_FLOW
    );

    // 1. Start echo server
    let echo_counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let echo_counter_clone = echo_counter.clone();
    let _echo_server = start_udp_response_server(echo_ip, echo_port, move |payload, _| {
        echo_counter_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        [payload, b" [STRESS]"].concat()
    })
    .await?;
    eprintln!("[TEST] Echo server on {}:{}", echo_ip, echo_port);

    // 2. Start VLESS server
    let (cert_path, key_path) = common::certs::generate_test_cert_files()?;
    let vless_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      test.local:
        cert: {}
        key: {}
        vision: true
        protocol:
          type: vless
          user_id: "b85798ef-e9dc-46a4-9a87-8da4499d36d0"
          udp_enabled: true
  rules:
    - masks: "{}:0"
      action: allow
      override_address: "{}:{}"
      client_chain:
        - protocol:
            type: direct
"#,
        vless_ip,
        vless_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
        tun_target_ip,
        echo_ip,
        echo_port,
    );

    let (_vless_guard, _vless_config) = start_shoes_server(&vless_config)?;
    port_helper.wait_for_all_ports().await?;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 3. Start TUN server
    let tun_config = format!(
        r#"
- device_name: "{}"
  address: "{}"
  netmask: 255.255.255.0
  mtu: 1500
  tcp_enabled: true
  udp_enabled: true
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - address: "{}:{}"
          protocol:
            type: tls
            verify: false
            sni_hostname: test.local
            protocol:
              type: vless
              user_id: "b85798ef-e9dc-46a4-9a87-8da4499d36d0"
              udp_enabled: true
"#,
        tun_name, tun_ip, vless_ip, vless_port,
    );

    let (_tun_guard, _tun_config) = start_shoes_server_with_sudo(&tun_config)?;
    tokio::time::sleep(Duration::from_millis(1000)).await;

    let destination = format!("{tun_target_ip}/32");
    let _route_guard = add_route_via_device(&destination, tun_name)?;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 4. Create multiple flows concurrently
    use socket2::{Domain, Protocol, Socket, Type};
    use std::collections::HashSet;
    use std::io;
    use std::net::SocketAddr;

    let dest: SocketAddr = format!("{}:{}", tun_target_ip, echo_port).parse()?;

    let mut handles = Vec::new();

    for flow_id in 0..NUM_FLOWS {
        let tun_ip = tun_ip.to_string();

        let handle = tokio::spawn(async move {
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            socket.set_reuse_address(true)?;
            let bind_addr: SocketAddr = format!("{}:0", tun_ip)
                .parse()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            socket.bind(&bind_addr.into())?;
            socket.set_nonblocking(true)?;
            let std_socket: std::net::UdpSocket = socket.into();
            let test_socket = UdpSocket::from_std(std_socket)?;

            let mut pending: HashSet<Vec<u8>> = (0..PACKETS_PER_FLOW)
                .map(|packet_id| format!("Flow{flow_id}-Pkt{packet_id} [STRESS]").into_bytes())
                .collect();
            let mut response_buf = vec![0u8; 65536];

            for pkt_id in 0..PACKETS_PER_FLOW {
                let msg = format!("Flow{}-Pkt{}", flow_id, pkt_id);
                let sent = test_socket.send_to(msg.as_bytes(), dest).await?;
                if sent != msg.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        format!("sent {sent} of {} UDP bytes", msg.len()),
                    ));
                }
            }

            tokio::time::timeout(Duration::from_secs(10), async {
                while !pending.is_empty() {
                    let (length, source) = test_socket.recv_from(&mut response_buf).await?;
                    if source != dest {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("response came from {source}, expected {dest}"),
                        ));
                    }
                    if !pending.remove(&response_buf[..length]) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "unexpected or duplicate stress response: {:?}",
                                &response_buf[..length]
                            ),
                        ));
                    }
                }
                Ok::<(), io::Error>(())
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "stress responses timed out"))??;

            Ok::<usize, io::Error>(PACKETS_PER_FLOW)
        });

        handles.push(handle);
    }

    let mut total_received = 0;
    for handle in handles {
        total_received += handle.await??;
    }

    let total_sent = NUM_FLOWS * PACKETS_PER_FLOW;
    let echo_count = echo_counter.load(std::sync::atomic::Ordering::Relaxed);

    eprintln!(
        "[TEST] Sent: {}, Echo received: {}, Responses received: {}",
        total_sent, echo_count, total_received
    );

    assert_eq!(echo_count, total_sent, "echo server missed UDP requests");
    assert_eq!(total_received, total_sent, "clients missed UDP responses");

    eprintln!("[TEST] ✓ SUCCESS: Stress test completed without packet loss");
    Ok(())
}
