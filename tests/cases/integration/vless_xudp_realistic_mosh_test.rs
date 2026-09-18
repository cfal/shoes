/// Realistic mosh-like test for XUDP with hostname resolution
///
/// This test closely simulates the real mosh scenario:
/// 1. Client uses sing-box with XUDP enabled
/// 2. Sends to "localhost" hostname (not IP)
/// 3. shoes server resolves and forwards UDP
/// 4. UDP echo server responds
/// 5. Response should come back through XUDP to client
///
/// This should catch any issues with hostname resolution or session management.
use shoes_test_support as common;

use common::test_fixture::{start_shoes_server, start_singbox_server};
use common::test_servers::start_udp_echo_server_with_suffix;
use common::vless::{VlessDestination, VlessUdpClient, parse_uuid};

use std::path::Path;
use std::time::Duration;
use tokio::net::TcpStream;

const TEST_UUID: &str = "b85798ef-e9dc-46a4-9a87-8da4499d36d0";

use common::certs::generate_test_cert_files as generate_test_cert;

/// Test XUDP with localhost hostname - should work perfectly
#[tokio::test]
async fn test_xudp_with_localhost_hostname() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (shoes_vless_ip, shoes_vless_port) = port_helper.get_listener_port();
    let (singbox_vless_ip, singbox_vless_port) = port_helper.get_listener_port();

    let echo_v6 = start_udp_echo_server_with_suffix("::1", 0, b" [ECHOED]").await?;
    let udp_echo_port = echo_v6.local_addr().port();
    let _echo_v4 =
        start_udp_echo_server_with_suffix("127.0.0.1", udp_echo_port, b" [ECHOED]").await?;

    eprintln!(
        "[TEST] Using ports: shoes VLESS={}, sing-box VLESS inbound={}, UDP Echo={}",
        shoes_vless_port, singbox_vless_port, udp_echo_port
    );

    eprintln!(
        "[TEST] Started UDP echo servers on localhost:{}",
        udp_echo_port
    );

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

    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for both servers to be ready
    port_helper.wait_for_all_ports().await?;

    eprintln!("[TEST] Connecting to sing-box VLESS inbound...");
    let stream = TcpStream::connect(format!("{}:{}", singbox_vless_ip, singbox_vless_port)).await?;
    let mut client = VlessUdpClient::connect(
        stream,
        parse_uuid(TEST_UUID)?,
        VlessDestination::Domain("localhost".to_string(), udp_echo_port),
    )
    .await?;

    // Send test message
    let test_message = b"Hello mosh!";
    eprintln!(
        "[TEST] Sending UDP packet: {:?}",
        std::str::from_utf8(test_message)
    );
    client.send_packet(test_message).await?;
    let response = client.recv_packet(Duration::from_secs(5)).await?;
    assert_eq!(response, b"Hello mosh! [ECHOED]");
    Ok(())
}
