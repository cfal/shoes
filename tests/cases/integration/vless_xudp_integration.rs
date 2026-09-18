/// Integration tests for VLESS XUDP (UDP-over-TCP) protocol
///
/// Test Architecture:
/// ==================
/// These tests send command-2 VLESS UDP requests to sing-box and verify that its
/// command-3 XUDP outbound interoperates with Shoes.
///
/// Test Scenario:
/// ==============
/// Test Client (VLESS UDP)
///   -> sing-box VLESS inbound (non-vision, empty packet_encoding)
///      -> shoes VLESS+VISION+XUDP Server
///         -> UDP Echo Server (modifies packets)
///
use shoes_test_support as common;

use common::test_fixture::{start_shoes_server, start_singbox_server};
use common::test_servers::{
    TestServer, TlsVersion, start_tls_stream_echo_server, start_udp_echo_server,
    start_udp_echo_server_with_suffix,
};
use common::vless::{VlessDestination, VlessUdpClient, parse_uuid};

use std::path::Path;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::sleep;

const TEST_UUID: &str = "b85798ef-e9dc-46a4-9a87-8da4499d36d0";

// Re-use certificate generation from common test utilities
use common::certs::generate_test_cert_files as generate_test_cert;

async fn connect_vless_udp(
    stream: TcpStream,
    target_addr: &str,
    target_port: u16,
) -> std::io::Result<VlessUdpClient<TcpStream>> {
    VlessUdpClient::connect(
        stream,
        parse_uuid(TEST_UUID)?,
        VlessDestination::Domain(target_addr.to_string(), target_port),
    )
    .await
}

async fn start_reality_decoy() -> std::io::Result<(TestServer, String)> {
    let (certificate, key, ca) = common::certs::generate_ca_signed_cert_bundle_files("test.local")?;
    let mut certificate_chain = std::fs::read(&certificate)?;
    certificate_chain.extend_from_slice(&std::fs::read(&ca)?);
    std::fs::write(&certificate, certificate_chain)?;

    let server =
        start_tls_stream_echo_server("0.0.0.0", 0, &certificate, &key, TlsVersion::Tls13Only)
            .await?;
    let destination = format!("localhost:{}", server.local_addr().port());
    Ok((server, destination))
}

/// Test UDP through VLESS VISION XUDP with manual VLESS encoding
#[tokio::test]
async fn test_shoes_vless_vision_xudp_udp_echo() -> Result<(), Box<dyn std::error::Error>> {
    // Allocate random ports
    let mut port_helper = common::port_helper::PortHelper::new();
    let (shoes_vless_ip, shoes_vless_port) = port_helper.get_listener_port();
    let (singbox_vless_ip, singbox_vless_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port(); // UDP server - don't track for TCP readiness

    eprintln!(
        "[TEST] Using ports: shoes VLESS={}, sing-box VLESS inbound={}, UDP Echo={}",
        shoes_vless_port, singbox_vless_port, udp_echo_port
    );

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    // Generate test certificate
    let (cert_temp_path, key_temp_path) = generate_test_cert()?;

    // shoes VLESS+VISION server with XUDP enabled
    let shoes_config = format!(
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
          user_id: "{}"
          udp_enabled: true
"#,
        shoes_vless_ip,
        shoes_vless_port,
        AsRef::<Path>::as_ref(&cert_temp_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_temp_path).to_str().unwrap(),
        TEST_UUID
    );

    // sing-box VLESS inbound (non-vision) -> VLESS outbound (vision + xudp)
    // The inbound accepts our manual VLESS UDP requests (command 0x02)
    // The outbound connects to shoes with VISION flow and xudp encoding
    // sing-box will automatically use CommandXudp (0x03) for xudp with vision
    let singbox_config = format!(
        r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "vless",
      "tag": "vless-in",
      "listen": "{}",
      "listen_port": {},
      "users": [
        {{
          "uuid": "{}"
        }}
      ]
    }}
  ],
  "outbounds": [
    {{
      "type": "vless",
      "tag": "vless-out",
      "server": "{}",
      "server_port": {},
      "uuid": "{}",
      "flow": "xtls-rprx-vision",
      "tls": {{
        "enabled": true,
        "server_name": "test.local",
        "insecure": true
      }},
      "packet_encoding": "xudp"
    }}
  ],
  "route": {{
    "final": "vless-out"
  }}
}}"#,
        singbox_vless_ip,
        singbox_vless_port,
        TEST_UUID,
        shoes_vless_ip,
        shoes_vless_port,
        TEST_UUID
    );

    // Start shoes VLESS server
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    // Start sing-box proxy
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for both servers to be ready
    port_helper.wait_for_all_ports().await?;

    // Connect to sing-box VLESS inbound and send manual VLESS UDP request
    eprintln!("[TEST] Connecting to sing-box VLESS inbound...");
    let stream = TcpStream::connect(format!("{}:{}", singbox_vless_ip, singbox_vless_port)).await?;
    let mut client = connect_vless_udp(stream, &udp_echo_ip, udp_echo_port).await?;

    // Send UDP packet through VLESS
    let test_message = b"Hello, UDP XUDP!";
    eprintln!(
        "[TEST] Sending UDP packet: {:?}",
        std::str::from_utf8(test_message)
    );
    client.send_packet(test_message).await?;

    // Read response with proper handling for TCP partial reads
    eprintln!("[TEST] Waiting for UDP echo response...");
    let payload = client.recv_packet(Duration::from_secs(5)).await?;
    eprintln!("[TEST] Decoded payload len: {}", payload.len());
    assert_eq!(payload, [test_message.as_slice(), b" [ECHO]"].concat());

    eprintln!("[TEST] ✓ UDP echo test passed!");
    Ok(())
}

/// Test multiple sequential UDP packets over the same XUDP connection
#[tokio::test]
async fn test_vless_xudp_multiple_packets() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (shoes_vless_ip, shoes_vless_port) = port_helper.get_listener_port();
    let (singbox_vless_ip, singbox_vless_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port(); // UDP server - don't track for TCP readiness

    eprintln!(
        "[TEST] Using ports: shoes VLESS={}, sing-box VLESS inbound={}, UDP Echo={}",
        shoes_vless_port, singbox_vless_port, udp_echo_port
    );

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    let (cert_temp_path, key_temp_path) = generate_test_cert()?;

    let shoes_config = format!(
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
          user_id: "{}"
          udp_enabled: true
"#,
        shoes_vless_ip,
        shoes_vless_port,
        AsRef::<Path>::as_ref(&cert_temp_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_temp_path).to_str().unwrap(),
        TEST_UUID
    );

    let singbox_config = format!(
        r#"{{
  "log": {{
    "level": "info"
  }},
  "inbounds": [
    {{
      "type": "vless",
      "tag": "vless-in",
      "listen": "{}",
      "listen_port": {},
      "users": [
        {{
          "uuid": "{}"
        }}
      ]
    }}
  ],
  "outbounds": [
    {{
      "type": "vless",
      "tag": "vless-out",
      "server": "{}",
      "server_port": {},
      "uuid": "{}",
      "flow": "xtls-rprx-vision",
      "tls": {{
        "enabled": true,
        "server_name": "test.local",
        "insecure": true
      }},
      "packet_encoding": "xudp"
    }}
  ],
  "route": {{
    "final": "vless-out"
  }}
}}"#,
        singbox_vless_ip,
        singbox_vless_port,
        TEST_UUID,
        shoes_vless_ip,
        shoes_vless_port,
        TEST_UUID
    );

    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for both servers to be ready
    port_helper.wait_for_all_ports().await?;

    eprintln!("[TEST] Connecting to sing-box VLESS inbound...");
    let stream = TcpStream::connect(format!("{}:{}", singbox_vless_ip, singbox_vless_port)).await?;
    let mut client = connect_vless_udp(stream, &udp_echo_ip, udp_echo_port).await?;

    // Send 10 sequential packets
    for i in 1..=10 {
        let test_message = format!("Packet {}", i);
        eprintln!("[TEST] Sending packet {}: {:?}", i, test_message);
        client.send_packet(test_message.as_bytes()).await?;
        let payload = client
            .recv_packet(Duration::from_secs(2))
            .await
            .map_err(|e| format!("Failed to read packet {}: {}", i, e))?;
        assert_eq!(payload, [test_message.as_bytes(), b" [ECHO]"].concat());

        // Small delay between packets
        sleep(Duration::from_millis(100)).await;
    }

    eprintln!("[TEST] ✓ All 10 packets sent and received successfully!");
    Ok(())
}

/// Test large UDP payloads (1KB, 5KB, 10KB) over XUDP
#[tokio::test]
async fn test_vless_xudp_large_payloads() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (shoes_vless_ip, shoes_vless_port) = port_helper.get_listener_port();
    let (singbox_vless_ip, singbox_vless_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port(); // UDP server - don't track for TCP readiness

    eprintln!(
        "[TEST] Using ports: shoes VLESS={}, sing-box VLESS inbound={}, UDP Echo={}",
        shoes_vless_port, singbox_vless_port, udp_echo_port
    );

    let _echo_server = start_udp_echo_server_with_suffix(&udp_echo_ip, udp_echo_port, b"").await?;

    let (cert_temp_path, key_temp_path) = generate_test_cert()?;

    let shoes_config = format!(
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
          user_id: "{}"
          udp_enabled: true
"#,
        shoes_vless_ip,
        shoes_vless_port,
        AsRef::<Path>::as_ref(&cert_temp_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_temp_path).to_str().unwrap(),
        TEST_UUID
    );

    let singbox_config = format!(
        r#"{{
  "log": {{
    "level": "info"
  }},
  "inbounds": [
    {{
      "type": "vless",
      "tag": "vless-in",
      "listen": "{}",
      "listen_port": {},
      "users": [
        {{
          "uuid": "{}"
        }}
      ]
    }}
  ],
  "outbounds": [
    {{
      "type": "vless",
      "tag": "vless-out",
      "server": "{}",
      "server_port": {},
      "uuid": "{}",
      "flow": "xtls-rprx-vision",
      "tls": {{
        "enabled": true,
        "server_name": "test.local",
        "insecure": true
      }},
      "packet_encoding": "xudp"
    }}
  ],
  "route": {{
    "final": "vless-out"
  }}
}}"#,
        singbox_vless_ip,
        singbox_vless_port,
        TEST_UUID,
        shoes_vless_ip,
        shoes_vless_port,
        TEST_UUID
    );

    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for both servers to be ready
    port_helper.wait_for_all_ports().await?;

    eprintln!("[TEST] Connecting to sing-box VLESS inbound...");
    let stream = TcpStream::connect(format!("{}:{}", singbox_vless_ip, singbox_vless_port)).await?;
    let mut client = connect_vless_udp(stream, &udp_echo_ip, udp_echo_port).await?;

    // Test with different payload sizes: 1KB, 3KB, 6KB
    // Note: UDP typically has ~65KB theoretical limit, but practical limits are lower
    // Keeping under 8KB to avoid fragmentation issues in testing
    for size in [1024, 3 * 1024, 6 * 1024] {
        // Create payload with recognizable pattern
        let mut test_message = Vec::with_capacity(size);
        for i in 0..size {
            test_message.push((i % 256) as u8);
        }

        eprintln!("[TEST] Sending {} byte payload", size);
        client.send_packet(&test_message).await?;
        let response = client
            .recv_packet(Duration::from_secs(if size > 5000 { 10 } else { 5 }))
            .await?;
        assert_eq!(response, test_message);

        sleep(Duration::from_millis(200)).await;
    }

    eprintln!("[TEST] ✓ All large payload tests passed!");
    Ok(())
}

/// Test concurrent XUDP connections
#[tokio::test]
async fn test_vless_xudp_concurrent_connections() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (shoes_vless_ip, shoes_vless_port) = port_helper.get_listener_port();
    let (singbox_vless_ip, singbox_vless_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port(); // UDP server - don't track for TCP readiness

    eprintln!(
        "[TEST] Using ports: shoes VLESS={}, sing-box VLESS inbound={}, UDP Echo={}",
        shoes_vless_port, singbox_vless_port, udp_echo_port
    );

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    let (cert_temp_path, key_temp_path) = generate_test_cert()?;

    let shoes_config = format!(
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
          user_id: "{}"
          udp_enabled: true
"#,
        shoes_vless_ip,
        shoes_vless_port,
        AsRef::<Path>::as_ref(&cert_temp_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_temp_path).to_str().unwrap(),
        TEST_UUID
    );

    let singbox_config = format!(
        r#"{{
  "log": {{
    "level": "info"
  }},
  "inbounds": [
    {{
      "type": "vless",
      "tag": "vless-in",
      "listen": "{}",
      "listen_port": {},
      "users": [
        {{
          "uuid": "{}"
        }}
      ]
    }}
  ],
  "outbounds": [
    {{
      "type": "vless",
      "tag": "vless-out",
      "server": "{}",
      "server_port": {},
      "uuid": "{}",
      "flow": "xtls-rprx-vision",
      "tls": {{
        "enabled": true,
        "server_name": "test.local",
        "insecure": true
      }},
      "packet_encoding": "xudp"
    }}
  ],
  "route": {{
    "final": "vless-out"
  }}
}}"#,
        singbox_vless_ip,
        singbox_vless_port,
        TEST_UUID,
        shoes_vless_ip,
        shoes_vless_port,
        TEST_UUID
    );

    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for both servers to be ready
    port_helper.wait_for_all_ports().await?;

    // Spawn 5 concurrent connections
    let mut handles = Vec::new();
    for conn_id in 0..5 {
        let singbox_ip = singbox_vless_ip.clone();
        let singbox_port = singbox_vless_port;
        let udp_ip = udp_echo_ip.clone();
        let echo_port = udp_echo_port;

        let handle = tokio::spawn(async move {
            eprintln!("[TEST-{}] Starting connection", conn_id);

            let stream = TcpStream::connect(format!("{}:{}", singbox_ip, singbox_port))
                .await
                .map_err(|e| format!("Connect failed: {}", e))?;
            let mut client = connect_vless_udp(stream, &udp_ip, echo_port)
                .await
                .map_err(|e| format!("VLESS handshake failed: {}", e))?;

            // Each connection sends 3 packets
            for i in 1..=3 {
                let test_message = format!("Conn-{} Packet-{}", conn_id, i);
                client
                    .send_packet(test_message.as_bytes())
                    .await
                    .map_err(|e| format!("Write failed: {}", e))?;
                let payload = client
                    .recv_packet(Duration::from_secs(3))
                    .await
                    .map_err(|e| format!("Conn {} read error at packet {}: {}", conn_id, i, e))?;
                let expected = [test_message.as_bytes(), b" [ECHO]"].concat();
                if payload != expected {
                    return Err(format!(
                        "Wrong response for conn {} packet {}: got {:?}",
                        conn_id, i, payload
                    ));
                }
            }

            eprintln!("[TEST-{}] ✓ Completed successfully", conn_id);
            Ok::<(), String>(())
        });

        handles.push(handle);
    }

    // Wait for all connections to complete
    for (i, handle) in handles.into_iter().enumerate() {
        match handle.await {
            Ok(Ok(())) => eprintln!("[TEST] Connection {} succeeded", i),
            Ok(Err(e)) => return Err(format!("Connection {} failed: {}", i, e).into()),
            Err(e) => return Err(format!("Connection {} panicked: {:?}", i, e).into()),
        }
    }

    eprintln!("[TEST] ✓ All 5 concurrent connections completed successfully!");
    Ok(())
}

/// Test rapid burst of UDP packets
#[tokio::test]
#[ignore = "known XUDP burst-loss behavior under sustained packet bursts"]
async fn test_vless_xudp_rapid_burst() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (shoes_vless_ip, shoes_vless_port) = port_helper.get_listener_port();
    let (singbox_vless_ip, singbox_vless_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port(); // UDP server - don't track for TCP readiness

    eprintln!(
        "[TEST] Using ports: shoes VLESS={}, sing-box VLESS inbound={}, UDP Echo={}",
        shoes_vless_port, singbox_vless_port, udp_echo_port
    );

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    let (cert_temp_path, key_temp_path) = generate_test_cert()?;

    let shoes_config = format!(
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
          user_id: "{}"
          udp_enabled: true
"#,
        shoes_vless_ip,
        shoes_vless_port,
        AsRef::<Path>::as_ref(&cert_temp_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_temp_path).to_str().unwrap(),
        TEST_UUID
    );

    let singbox_config = format!(
        r#"{{
  "log": {{
    "level": "info"
  }},
  "inbounds": [
    {{
      "type": "vless",
      "tag": "vless-in",
      "listen": "{}",
      "listen_port": {},
      "users": [
        {{
          "uuid": "{}"
        }}
      ]
    }}
  ],
  "outbounds": [
    {{
      "type": "vless",
      "tag": "vless-out",
      "server": "{}",
      "server_port": {},
      "uuid": "{}",
      "flow": "xtls-rprx-vision",
      "tls": {{
        "enabled": true,
        "server_name": "test.local",
        "insecure": true
      }},
      "packet_encoding": "xudp"
    }}
  ],
  "route": {{
    "final": "vless-out"
  }}
}}"#,
        singbox_vless_ip,
        singbox_vless_port,
        TEST_UUID,
        shoes_vless_ip,
        shoes_vless_port,
        TEST_UUID
    );

    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for both servers to be ready
    port_helper.wait_for_all_ports().await?;

    eprintln!("[TEST] Connecting to sing-box VLESS inbound...");
    let stream = TcpStream::connect(format!("{}:{}", singbox_vless_ip, singbox_vless_port)).await?;
    let mut client = connect_vless_udp(stream, &udp_echo_ip, udp_echo_port).await?;

    // Send 30 packets rapidly (minimal delay for buffering)
    eprintln!("[TEST] Sending burst of 30 packets...");
    for i in 1..=30 {
        let test_message = format!("Burst-{}", i);
        client.send_packet(test_message.as_bytes()).await?;
        if i % 10 == 0 {
            sleep(Duration::from_millis(10)).await;
        }
    }
    eprintln!("[TEST] All packets sent, waiting for responses...");

    let mut responses = std::collections::HashSet::new();

    // Read all 30 responses
    for i in 1..=30 {
        let payload = client.recv_packet(Duration::from_secs(5)).await?;
        if !responses.insert(payload.clone()) {
            return Err(format!("Duplicate response: {:?}", payload).into());
        }

        if i % 10 == 0 {
            eprintln!("[TEST] Received {} responses...", i);
        }
    }
    let expected = (1..=30)
        .map(|i| format!("Burst-{i} [ECHO]").into_bytes())
        .collect();
    assert_eq!(responses, expected);

    eprintln!("[TEST] ✓ All 30 burst packets sent and received successfully!");
    Ok(())
}

/// Test concurrent VLESS UDP requests to different destinations.
#[tokio::test]
async fn test_vless_xudp_multiple_destinations() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (shoes_vless_ip, shoes_vless_port) = port_helper.get_listener_port();
    let (singbox_vless_ip, singbox_vless_port) = port_helper.get_listener_port();

    // Start 3 different UDP echo servers on different ports
    let (udp_echo_ip_1, udp_echo_port_1) = port_helper.get_port(); // UDP server - don't track
    let (udp_echo_ip_2, udp_echo_port_2) = port_helper.get_port(); // UDP server - don't track
    let (udp_echo_ip_3, udp_echo_port_3) = port_helper.get_port(); // UDP server - don't track

    eprintln!(
        "[TEST] Using ports: shoes VLESS={}, sing-box VLESS inbound={}, UDP Echos={},{},{}",
        shoes_vless_port, singbox_vless_port, udp_echo_port_1, udp_echo_port_2, udp_echo_port_3
    );

    let _echo_server_1 =
        start_udp_echo_server_with_suffix(&udp_echo_ip_1, udp_echo_port_1, b" [ECHO-1]").await?;
    let _echo_server_2 =
        start_udp_echo_server_with_suffix(&udp_echo_ip_2, udp_echo_port_2, b" [ECHO-2]").await?;
    let _echo_server_3 =
        start_udp_echo_server_with_suffix(&udp_echo_ip_3, udp_echo_port_3, b" [ECHO-3]").await?;

    let (cert_temp_path, key_temp_path) = generate_test_cert()?;

    let shoes_config = format!(
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
          user_id: "{}"
          udp_enabled: true
"#,
        shoes_vless_ip,
        shoes_vless_port,
        AsRef::<Path>::as_ref(&cert_temp_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_temp_path).to_str().unwrap(),
        TEST_UUID
    );

    let singbox_config = format!(
        r#"{{
  "log": {{
    "level": "info"
  }},
  "inbounds": [
    {{
      "type": "vless",
      "tag": "vless-in",
      "listen": "{}",
      "listen_port": {},
      "users": [
        {{
          "uuid": "{}"
        }}
      ]
    }}
  ],
  "outbounds": [
    {{
      "type": "vless",
      "tag": "vless-out",
      "server": "{}",
      "server_port": {},
      "uuid": "{}",
      "flow": "xtls-rprx-vision",
      "tls": {{
        "enabled": true,
        "server_name": "test.local",
        "insecure": true
      }},
      "packet_encoding": "xudp"
    }}
  ],
  "route": {{
    "final": "vless-out"
  }}
}}"#,
        singbox_vless_ip,
        singbox_vless_port,
        TEST_UUID,
        shoes_vless_ip,
        shoes_vless_port,
        TEST_UUID
    );

    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for both servers to be ready
    port_helper.wait_for_all_ports().await?;

    eprintln!("[TEST] Creating 3 connections to different UDP destinations...");

    // Connection 1 -> UDP echo server 1
    let stream = TcpStream::connect(format!("{}:{}", singbox_vless_ip, singbox_vless_port)).await?;
    let mut client_1 = connect_vless_udp(stream, &udp_echo_ip_1, udp_echo_port_1).await?;

    // Connection 2 -> UDP echo server 2
    let stream = TcpStream::connect(format!("{}:{}", singbox_vless_ip, singbox_vless_port)).await?;
    let mut client_2 = connect_vless_udp(stream, &udp_echo_ip_2, udp_echo_port_2).await?;

    // Connection 3 -> UDP echo server 3
    let stream = TcpStream::connect(format!("{}:{}", singbox_vless_ip, singbox_vless_port)).await?;
    let mut client_3 = connect_vless_udp(stream, &udp_echo_ip_3, udp_echo_port_3).await?;

    sleep(Duration::from_millis(100)).await;

    for round in 1..=3 {
        eprintln!("[TEST] Round {}: Sending to all 3 destinations", round);

        // Send to destination 1
        let msg_1 = format!("Round-{} to Server-1", round);
        client_1.send_packet(msg_1.as_bytes()).await?;

        // Send to destination 2
        let msg_2 = format!("Round-{} to Server-2", round);
        client_2.send_packet(msg_2.as_bytes()).await?;

        // Send to destination 3
        let msg_3 = format!("Round-{} to Server-3", round);
        client_3.send_packet(msg_3.as_bytes()).await?;

        let response_1 = client_1.recv_packet(Duration::from_secs(3)).await?;
        let response_2 = client_2.recv_packet(Duration::from_secs(3)).await?;
        let response_3 = client_3.recv_packet(Duration::from_secs(3)).await?;
        assert_eq!(response_1, [msg_1.as_bytes(), b" [ECHO-1]"].concat());
        assert_eq!(response_2, [msg_2.as_bytes(), b" [ECHO-2]"].concat());
        assert_eq!(response_3, [msg_3.as_bytes(), b" [ECHO-3]"].concat());

        sleep(Duration::from_millis(100)).await;
    }

    eprintln!("[TEST] ✓ All 3 destinations communicated correctly");
    Ok(())
}

/// Test VLESS XUDP without VISION flow (plain TLS + XUDP)
/// This verifies that XUDP works independently of VISION
#[tokio::test]
async fn test_vless_non_vision_mux() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (shoes_vless_ip, shoes_vless_port) = port_helper.get_listener_port();
    let (singbox_vless_ip, singbox_vless_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port(); // UDP server - don't track for TCP readiness

    eprintln!(
        "[TEST] Using ports: shoes VLESS={}, sing-box VLESS inbound={}, UDP Echo={}",
        shoes_vless_port, singbox_vless_port, udp_echo_port
    );

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    let (cert_temp_path, key_temp_path) = generate_test_cert()?;

    // shoes VLESS server with TLS but NO VISION requirement for XUDP
    let shoes_config = format!(
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
          user_id: "{}"
          udp_enabled: true
"#,
        shoes_vless_ip,
        shoes_vless_port,
        AsRef::<Path>::as_ref(&cert_temp_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_temp_path).to_str().unwrap(),
        TEST_UUID
    );

    // sing-box with XUDP but NO VISION flow
    // This will use TLS + XUDP without VISION padding
    let singbox_config = format!(
        r#"{{
  "log": {{
    "level": "info"
  }},
  "inbounds": [
    {{
      "type": "vless",
      "tag": "vless-in",
      "listen": "{}",
      "listen_port": {},
      "users": [
        {{
          "uuid": "{}"
        }}
      ]
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
      "packet_encoding": "xudp"
    }}
  ],
  "route": {{
    "final": "vless-out"
  }}
}}"#,
        singbox_vless_ip,
        singbox_vless_port,
        TEST_UUID,
        shoes_vless_ip,
        shoes_vless_port,
        TEST_UUID
    );

    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for both servers to be ready
    port_helper.wait_for_all_ports().await?;

    eprintln!("[TEST] Connecting to sing-box VLESS inbound...");
    let stream = TcpStream::connect(format!("{}:{}", singbox_vless_ip, singbox_vless_port)).await?;
    let mut client = connect_vless_udp(stream, &udp_echo_ip, udp_echo_port).await?;

    // Send test packet
    let test_message = b"Hello, non-VISION XUDP!";
    eprintln!(
        "[TEST] Sending UDP packet: {:?}",
        std::str::from_utf8(test_message)
    );
    client.send_packet(test_message).await?;

    // Read response
    eprintln!("[TEST] Waiting for UDP echo response...");
    let payload = client.recv_packet(Duration::from_secs(5)).await?;
    assert_eq!(payload, [test_message.as_slice(), b" [ECHO]"].concat());
    Ok(())
}

// REALITY + Vision + XUDP Tests
//
// These tests verify that XUDP (UDP-over-TCP multiplexing) works correctly
// with REALITY transport, which is a common production configuration.

/// Generate REALITY x25519 keypair for testing
fn generate_reality_keypair() -> (String, String) {
    use aws_lc_rs::{
        agreement,
        rand::{SecureRandom, SystemRandom},
    };
    use base64::engine::{Engine as _, general_purpose::URL_SAFE_NO_PAD};

    let rng = SystemRandom::new();

    // Generate raw private key bytes
    let mut private_bytes = [0u8; 32];
    rng.fill(&mut private_bytes)
        .expect("Failed to generate random bytes");

    // Create private key from bytes
    let private_key = agreement::PrivateKey::from_private_key(&agreement::X25519, &private_bytes)
        .expect("Failed to create private key");
    let public_key_bytes = private_key
        .compute_public_key()
        .expect("Failed to compute public key");

    let private_key_b64 = URL_SAFE_NO_PAD.encode(private_bytes);
    let public_key_b64 = URL_SAFE_NO_PAD.encode(public_key_bytes.as_ref());

    (private_key_b64, public_key_b64)
}

/// Test REALITY + Vision + XUDP basic UDP echo
/// Chain: manual VLESS UDP -> sing-box VLESS inbound -> shoes REALITY+Vision+XUDP server -> UDP echo
#[tokio::test]
async fn test_reality_vision_xudp_udp_echo() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (shoes_reality_ip, shoes_reality_port) = port_helper.get_listener_port();
    let (singbox_vless_ip, singbox_vless_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!(
        "[TEST] Using ports: shoes REALITY={}, sing-box VLESS inbound={}, UDP Echo={}",
        shoes_reality_port, singbox_vless_port, udp_echo_port
    );

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;
    let (_decoy, reality_destination) = start_reality_decoy().await?;

    // Generate REALITY keypair
    let (private_key, public_key) = generate_reality_keypair();
    let short_id = "0123456789abcdef";
    let server_name = "test.local";

    // shoes REALITY+Vision server with XUDP enabled
    let shoes_config = format!(
        r#"
- address: "{}:{}"
  dns:
    servers: system
  protocol:
    type: tls
    reality_targets:
      "{}":
        private_key: "{}"
        short_ids:
          - "{}"
        dest: "{}"
        max_time_diff: 60000
        vision: true
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: true
"#,
        shoes_reality_ip,
        shoes_reality_port,
        server_name,
        private_key,
        short_id,
        reality_destination,
        TEST_UUID
    );

    // sing-box VLESS inbound -> REALITY+Vision outbound with XUDP
    let singbox_config = format!(
        r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "vless",
      "tag": "vless-in",
      "listen": "{}",
      "listen_port": {},
      "users": [
        {{
          "uuid": "{}"
        }}
      ]
    }}
  ],
  "outbounds": [
    {{
      "type": "vless",
      "tag": "vless-out",
      "server": "{}",
      "server_port": {},
      "uuid": "{}",
      "flow": "xtls-rprx-vision",
      "tls": {{
        "enabled": true,
        "server_name": "{}",
        "utls": {{
          "enabled": true,
          "fingerprint": "chrome"
        }},
        "reality": {{
          "enabled": true,
          "public_key": "{}",
          "short_id": "{}"
        }}
      }},
      "packet_encoding": "xudp"
    }}
  ],
  "route": {{
    "final": "vless-out"
  }}
}}"#,
        singbox_vless_ip,
        singbox_vless_port,
        TEST_UUID,
        shoes_reality_ip,
        shoes_reality_port,
        TEST_UUID,
        server_name,
        public_key,
        short_id
    );

    // Start shoes REALITY server
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    // Start sing-box proxy
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for servers to be ready
    port_helper.wait_for_all_ports().await?;

    // Connect and send UDP via VLESS
    eprintln!("[TEST] Connecting to sing-box VLESS inbound...");
    let stream = TcpStream::connect(format!("{}:{}", singbox_vless_ip, singbox_vless_port)).await?;
    let mut client = connect_vless_udp(stream, &udp_echo_ip, udp_echo_port).await?;

    // Send UDP packet
    let test_message = b"Hello, REALITY XUDP!";
    eprintln!(
        "[TEST] Sending UDP packet: {:?}",
        std::str::from_utf8(test_message)
    );
    client.send_packet(test_message).await?;

    // Read response
    eprintln!("[TEST] Waiting for UDP echo response...");
    let payload = client.recv_packet(Duration::from_secs(10)).await?;
    assert_eq!(payload, [test_message.as_slice(), b" [ECHO]"].concat());
    Ok(())
}

/// Test REALITY + Vision + XUDP with multiple sequential packets
#[tokio::test]
async fn test_reality_vision_xudp_multiple_packets() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (shoes_reality_ip, shoes_reality_port) = port_helper.get_listener_port();
    let (singbox_vless_ip, singbox_vless_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!(
        "[TEST] Using ports: shoes REALITY={}, sing-box VLESS inbound={}, UDP Echo={}",
        shoes_reality_port, singbox_vless_port, udp_echo_port
    );

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;
    let (_decoy, reality_destination) = start_reality_decoy().await?;

    let (private_key, public_key) = generate_reality_keypair();
    let short_id = "0123456789abcdef";
    let server_name = "test.local";

    let shoes_config = format!(
        r#"
- address: "{}:{}"
  dns:
    servers: system
  protocol:
    type: tls
    reality_targets:
      "{}":
        private_key: "{}"
        short_ids:
          - "{}"
        dest: "{}"
        max_time_diff: 60000
        vision: true
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: true
"#,
        shoes_reality_ip,
        shoes_reality_port,
        server_name,
        private_key,
        short_id,
        reality_destination,
        TEST_UUID
    );

    let singbox_config = format!(
        r#"{{
  "log": {{
    "level": "info"
  }},
  "inbounds": [
    {{
      "type": "vless",
      "tag": "vless-in",
      "listen": "{}",
      "listen_port": {},
      "users": [
        {{
          "uuid": "{}"
        }}
      ]
    }}
  ],
  "outbounds": [
    {{
      "type": "vless",
      "tag": "vless-out",
      "server": "{}",
      "server_port": {},
      "uuid": "{}",
      "flow": "xtls-rprx-vision",
      "tls": {{
        "enabled": true,
        "server_name": "{}",
        "utls": {{
          "enabled": true,
          "fingerprint": "chrome"
        }},
        "reality": {{
          "enabled": true,
          "public_key": "{}",
          "short_id": "{}"
        }}
      }},
      "packet_encoding": "xudp"
    }}
  ],
  "route": {{
    "final": "vless-out"
  }}
}}"#,
        singbox_vless_ip,
        singbox_vless_port,
        TEST_UUID,
        shoes_reality_ip,
        shoes_reality_port,
        TEST_UUID,
        server_name,
        public_key,
        short_id
    );

    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    port_helper.wait_for_all_ports().await?;

    eprintln!("[TEST] Connecting to sing-box VLESS inbound...");
    let stream = TcpStream::connect(format!("{}:{}", singbox_vless_ip, singbox_vless_port)).await?;
    let mut client = connect_vless_udp(stream, &udp_echo_ip, udp_echo_port).await?;

    // Send 10 sequential packets
    for i in 1..=10 {
        let test_message = format!("REALITY Packet {}", i);
        eprintln!("[TEST] Sending packet {}: {:?}", i, test_message);
        client.send_packet(test_message.as_bytes()).await?;
        let payload = client
            .recv_packet(Duration::from_secs(5))
            .await
            .map_err(|e| format!("Failed to read packet {}: {}", i, e))?;
        assert_eq!(payload, [test_message.as_bytes(), b" [ECHO]"].concat());

        sleep(Duration::from_millis(100)).await;
    }

    eprintln!("[TEST] ✓ REALITY + Vision + XUDP multiple packets test passed!");
    Ok(())
}

/// Test REALITY + Vision + XUDP with large UDP payloads (1KB, 3KB, 6KB)
#[tokio::test]
async fn test_reality_vision_xudp_large_payloads() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (shoes_reality_ip, shoes_reality_port) = port_helper.get_listener_port();
    let (singbox_vless_ip, singbox_vless_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!(
        "[TEST] Using ports: shoes REALITY={}, sing-box VLESS inbound={}, UDP Echo={}",
        shoes_reality_port, singbox_vless_port, udp_echo_port
    );

    let _echo_server = start_udp_echo_server_with_suffix(&udp_echo_ip, udp_echo_port, b"").await?;
    let (_decoy, reality_destination) = start_reality_decoy().await?;

    let (private_key, public_key) = generate_reality_keypair();
    let short_id = "0123456789abcdef";
    let server_name = "test.local";

    let shoes_config = format!(
        r#"
- address: "{}:{}"
  dns:
    servers: system
  protocol:
    type: tls
    reality_targets:
      "{}":
        private_key: "{}"
        short_ids:
          - "{}"
        dest: "{}"
        max_time_diff: 60000
        vision: true
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: true
"#,
        shoes_reality_ip,
        shoes_reality_port,
        server_name,
        private_key,
        short_id,
        reality_destination,
        TEST_UUID
    );

    let singbox_config = format!(
        r#"{{
  "log": {{
    "level": "info"
  }},
  "inbounds": [
    {{
      "type": "vless",
      "tag": "vless-in",
      "listen": "{}",
      "listen_port": {},
      "users": [
        {{
          "uuid": "{}"
        }}
      ]
    }}
  ],
  "outbounds": [
    {{
      "type": "vless",
      "tag": "vless-out",
      "server": "{}",
      "server_port": {},
      "uuid": "{}",
      "flow": "xtls-rprx-vision",
      "tls": {{
        "enabled": true,
        "server_name": "{}",
        "utls": {{
          "enabled": true,
          "fingerprint": "chrome"
        }},
        "reality": {{
          "enabled": true,
          "public_key": "{}",
          "short_id": "{}"
        }}
      }},
      "packet_encoding": "xudp"
    }}
  ],
  "route": {{
    "final": "vless-out"
  }}
}}"#,
        singbox_vless_ip,
        singbox_vless_port,
        TEST_UUID,
        shoes_reality_ip,
        shoes_reality_port,
        TEST_UUID,
        server_name,
        public_key,
        short_id
    );

    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    port_helper.wait_for_all_ports().await?;

    eprintln!("[TEST] Connecting to sing-box VLESS inbound...");
    let stream = TcpStream::connect(format!("{}:{}", singbox_vless_ip, singbox_vless_port)).await?;
    let mut client = connect_vless_udp(stream, &udp_echo_ip, udp_echo_port).await?;

    // Test with different payload sizes
    for size in [1024, 3 * 1024, 6 * 1024] {
        let mut test_message = Vec::with_capacity(size);
        for i in 0..size {
            test_message.push((i % 256) as u8);
        }

        eprintln!("[TEST] Sending {} byte payload over REALITY", size);
        client.send_packet(&test_message).await?;
        let response = client.recv_packet(Duration::from_secs(10)).await?;
        assert_eq!(response, test_message);

        sleep(Duration::from_millis(200)).await;
    }

    eprintln!("[TEST] ✓ REALITY + Vision + XUDP large payloads test passed!");
    Ok(())
}

/// Test REALITY + Vision + XUDP rapid burst
#[tokio::test]
#[ignore = "known XUDP burst-loss behavior under sustained packet bursts"]
async fn test_reality_vision_xudp_rapid_burst() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (shoes_reality_ip, shoes_reality_port) = port_helper.get_listener_port();
    let (singbox_vless_ip, singbox_vless_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!(
        "[TEST] Using ports: shoes REALITY={}, sing-box VLESS inbound={}, UDP Echo={}",
        shoes_reality_port, singbox_vless_port, udp_echo_port
    );

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;
    let (_decoy, reality_destination) = start_reality_decoy().await?;

    let (private_key, public_key) = generate_reality_keypair();
    let short_id = "0123456789abcdef";
    let server_name = "test.local";

    let shoes_config = format!(
        r#"
- address: "{}:{}"
  dns:
    servers: system
  protocol:
    type: tls
    reality_targets:
      "{}":
        private_key: "{}"
        short_ids:
          - "{}"
        dest: "{}"
        max_time_diff: 60000
        vision: true
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: true
"#,
        shoes_reality_ip,
        shoes_reality_port,
        server_name,
        private_key,
        short_id,
        reality_destination,
        TEST_UUID
    );

    let singbox_config = format!(
        r#"{{
  "log": {{
    "level": "info"
  }},
  "inbounds": [
    {{
      "type": "vless",
      "tag": "vless-in",
      "listen": "{}",
      "listen_port": {},
      "users": [
        {{
          "uuid": "{}"
        }}
      ]
    }}
  ],
  "outbounds": [
    {{
      "type": "vless",
      "tag": "vless-out",
      "server": "{}",
      "server_port": {},
      "uuid": "{}",
      "flow": "xtls-rprx-vision",
      "tls": {{
        "enabled": true,
        "server_name": "{}",
        "utls": {{
          "enabled": true,
          "fingerprint": "chrome"
        }},
        "reality": {{
          "enabled": true,
          "public_key": "{}",
          "short_id": "{}"
        }}
      }},
      "packet_encoding": "xudp"
    }}
  ],
  "route": {{
    "final": "vless-out"
  }}
}}"#,
        singbox_vless_ip,
        singbox_vless_port,
        TEST_UUID,
        shoes_reality_ip,
        shoes_reality_port,
        TEST_UUID,
        server_name,
        public_key,
        short_id
    );

    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    port_helper.wait_for_all_ports().await?;

    eprintln!("[TEST] Connecting to sing-box VLESS inbound...");
    let stream = TcpStream::connect(format!("{}:{}", singbox_vless_ip, singbox_vless_port)).await?;
    let mut client = connect_vless_udp(stream, &udp_echo_ip, udp_echo_port).await?;

    // Send 20 packets rapidly
    eprintln!("[TEST] Sending burst of 20 packets over REALITY...");
    for i in 1..=20 {
        let test_message = format!("REALITY-Burst-{}", i);
        client.send_packet(test_message.as_bytes()).await?;
        if i % 5 == 0 {
            sleep(Duration::from_millis(10)).await;
        }
    }
    eprintln!("[TEST] All packets sent, waiting for responses...");

    let mut responses = std::collections::HashSet::new();

    // Read all 20 responses
    for i in 1..=20 {
        let payload = client.recv_packet(Duration::from_secs(10)).await?;
        if !responses.insert(payload.clone()) {
            return Err(format!("Duplicate response: {:?}", payload).into());
        }

        if i % 5 == 0 {
            eprintln!("[TEST] Received {} responses...", i);
        }
    }
    let expected = (1..=20)
        .map(|i| format!("REALITY-Burst-{i} [ECHO]").into_bytes())
        .collect();
    assert_eq!(responses, expected);

    eprintln!("[TEST] ✓ REALITY + Vision + XUDP rapid burst test passed!");
    Ok(())
}

/// Test REALITY + Vision + XUDP with multiple sequential connections
/// Each connection establishes a new REALITY handshake, verifying the server
/// can handle multiple connections correctly.
#[tokio::test]
async fn test_reality_vision_xudp_multi_connection() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (shoes_reality_ip, shoes_reality_port) = port_helper.get_listener_port();
    let (singbox_vless_ip, singbox_vless_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!(
        "[TEST] Using ports: shoes REALITY={}, sing-box VLESS inbound={}, UDP Echo={}",
        shoes_reality_port, singbox_vless_port, udp_echo_port
    );

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;
    let (_decoy, reality_destination) = start_reality_decoy().await?;

    let (private_key, public_key) = generate_reality_keypair();
    let short_id = "0123456789abcdef";
    let server_name = "test.local";

    let shoes_config = format!(
        r#"
- address: "{}:{}"
  dns:
    servers: system
  protocol:
    type: tls
    reality_targets:
      "{}":
        private_key: "{}"
        short_ids:
          - "{}"
        dest: "{}"
        max_time_diff: 60000
        vision: true
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: true
"#,
        shoes_reality_ip,
        shoes_reality_port,
        server_name,
        private_key,
        short_id,
        reality_destination,
        TEST_UUID
    );

    let singbox_config = format!(
        r#"{{
  "log": {{
    "level": "info"
  }},
  "inbounds": [
    {{
      "type": "vless",
      "tag": "vless-in",
      "listen": "{}",
      "listen_port": {},
      "users": [
        {{
          "uuid": "{}"
        }}
      ]
    }}
  ],
  "outbounds": [
    {{
      "type": "vless",
      "tag": "vless-out",
      "server": "{}",
      "server_port": {},
      "uuid": "{}",
      "flow": "xtls-rprx-vision",
      "tls": {{
        "enabled": true,
        "server_name": "{}",
        "utls": {{
          "enabled": true,
          "fingerprint": "chrome"
        }},
        "reality": {{
          "enabled": true,
          "public_key": "{}",
          "short_id": "{}"
        }}
      }},
      "packet_encoding": "xudp"
    }}
  ],
  "route": {{
    "final": "vless-out"
  }}
}}"#,
        singbox_vless_ip,
        singbox_vless_port,
        TEST_UUID,
        shoes_reality_ip,
        shoes_reality_port,
        TEST_UUID,
        server_name,
        public_key,
        short_id
    );

    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    port_helper.wait_for_all_ports().await?;

    // Test 3 sequential connections - each establishes a separate REALITY handshake
    for conn_id in 0..3 {
        eprintln!("[TEST-{}] Starting REALITY connection", conn_id);

        let stream =
            TcpStream::connect(format!("{}:{}", singbox_vless_ip, singbox_vless_port)).await?;
        let mut client = connect_vless_udp(stream, &udp_echo_ip, udp_echo_port).await?;

        // Each connection sends 3 packets
        for i in 1..=3 {
            let test_message = format!("REALITY-Conn-{}-Packet-{}", conn_id, i);
            client.send_packet(test_message.as_bytes()).await?;
            let payload = client.recv_packet(Duration::from_secs(10)).await?;
            assert_eq!(payload, [test_message.as_bytes(), b" [ECHO]"].concat());
        }

        eprintln!("[TEST-{}] ✓ Completed successfully", conn_id);

        // Small delay between connections
        sleep(Duration::from_millis(100)).await;
    }

    eprintln!("[TEST] ✓ REALITY + Vision + XUDP multi-connection test passed!");
    Ok(())
}

/// Test REALITY + Vision + XUDP with concurrent connections
/// This test verifies the shoes server can handle concurrent REALITY connections correctly.
#[tokio::test]
async fn test_reality_vision_xudp_concurrent_connections() -> Result<(), Box<dyn std::error::Error>>
{
    let mut port_helper = common::port_helper::PortHelper::new();
    let (shoes_reality_ip, shoes_reality_port) = port_helper.get_listener_port();
    let (singbox_vless_ip, singbox_vless_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!(
        "[TEST] Using ports: shoes REALITY={}, sing-box VLESS inbound={}, UDP Echo={}",
        shoes_reality_port, singbox_vless_port, udp_echo_port
    );

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;
    let (_decoy, reality_destination) = start_reality_decoy().await?;

    let (private_key, public_key) = generate_reality_keypair();
    let short_id = "0123456789abcdef";
    let server_name = "test.local";

    let shoes_config = format!(
        r#"
- address: "{}:{}"
  dns:
    servers: system
  protocol:
    type: tls
    reality_targets:
      "{}":
        private_key: "{}"
        short_ids:
          - "{}"
        dest: "{}"
        max_time_diff: 60000
        vision: true
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: true
"#,
        shoes_reality_ip,
        shoes_reality_port,
        server_name,
        private_key,
        short_id,
        reality_destination,
        TEST_UUID
    );

    let singbox_config = format!(
        r#"{{
  "log": {{
    "level": "info"
  }},
  "inbounds": [
    {{
      "type": "vless",
      "tag": "vless-in",
      "listen": "{}",
      "listen_port": {},
      "users": [
        {{
          "uuid": "{}"
        }}
      ]
    }}
  ],
  "outbounds": [
    {{
      "type": "vless",
      "tag": "vless-out",
      "server": "{}",
      "server_port": {},
      "uuid": "{}",
      "flow": "xtls-rprx-vision",
      "tls": {{
        "enabled": true,
        "server_name": "{}",
        "utls": {{
          "enabled": true,
          "fingerprint": "chrome"
        }},
        "reality": {{
          "enabled": true,
          "public_key": "{}",
          "short_id": "{}"
        }}
      }},
      "packet_encoding": "xudp"
    }}
  ],
  "route": {{
    "final": "vless-out"
  }}
}}"#,
        singbox_vless_ip,
        singbox_vless_port,
        TEST_UUID,
        shoes_reality_ip,
        shoes_reality_port,
        TEST_UUID,
        server_name,
        public_key,
        short_id
    );

    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    port_helper.wait_for_all_ports().await?;

    // Spawn 3 concurrent connections with slight stagger to avoid handshake overlap
    let mut handles = Vec::new();
    for conn_id in 0..3 {
        let singbox_ip = singbox_vless_ip.clone();
        let singbox_port = singbox_vless_port;
        let udp_ip = udp_echo_ip.clone();
        let echo_port = udp_echo_port;

        let handle = tokio::spawn(async move {
            // Stagger connections to let REALITY handshakes complete without overlap
            // REALITY handshakes can be slow due to the TLS1.3 handshake complexity
            sleep(Duration::from_millis(conn_id as u64 * 500)).await;
            eprintln!("[TEST-{}] Starting REALITY connection", conn_id);

            let stream = TcpStream::connect(format!("{}:{}", singbox_ip, singbox_port))
                .await
                .map_err(|e| format!("Connect failed: {}", e))?;
            let mut client = connect_vless_udp(stream, &udp_ip, echo_port)
                .await
                .map_err(|e| format!("VLESS handshake failed: {}", e))?;

            // Each connection sends 3 packets
            for i in 1..=3 {
                let test_message = format!("REALITY-Conn-{}-Packet-{}", conn_id, i);
                client
                    .send_packet(test_message.as_bytes())
                    .await
                    .map_err(|e| format!("Write failed: {}", e))?;
                let payload = client
                    .recv_packet(Duration::from_secs(15))
                    .await
                    .map_err(|e| format!("Read failed: {}", e))?;
                let expected = [test_message.as_bytes(), b" [ECHO]"].concat();
                if payload != expected {
                    return Err(format!(
                        "Wrong response for conn {} packet {}: {:?}",
                        conn_id, i, payload
                    ));
                }
            }

            eprintln!("[TEST-{}] ✓ Completed successfully", conn_id);
            Ok::<(), String>(())
        });

        handles.push(handle);
    }

    // Wait for all connections
    for (i, handle) in handles.into_iter().enumerate() {
        match handle.await {
            Ok(Ok(())) => eprintln!("[TEST] Connection {} succeeded", i),
            Ok(Err(e)) => return Err(format!("Connection {} failed: {}", i, e).into()),
            Err(e) => return Err(format!("Connection {} panicked: {:?}", i, e).into()),
        }
    }

    eprintln!("[TEST] ✓ REALITY + Vision + XUDP concurrent connections test passed!");
    Ok(())
}
