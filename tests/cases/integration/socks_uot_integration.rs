/// Integration tests for SOCKS UDP-over-TCP (UoT) protocol
///
/// Test Architecture:
/// ==================
/// UoT allows UDP traffic to be tunneled over a SOCKS TCP connection
/// by using magic addresses:
/// - V1: `sp.udp-over-tcp.arpa` - each packet has full address
/// - V2: `sp.v2.udp-over-tcp.arpa` - optional connect mode for single destination
///
/// Test Scenario:
/// ==============
/// sing-box SOCKS client (with UoT enabled via direct outbound)
///   -> shoes SOCKS Server with UoT
///      -> UDP Echo Server (local)
use shoes_test_support as common;

use common::port_helper::PortHelper;
use common::socks5::Socks5UdpAssociation;
use common::test_fixture::{start_shoes_server, start_singbox_server};
use common::test_servers::start_udp_echo_server;

use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::sleep;

// SOCKS UoT V1 TESTS

/// Test SOCKS UoT V1 - basic functionality
/// Architecture: singbox(socks client + socks outbound w/ uot_v1) -> shoes(socks server) -> udp echo
#[tokio::test]
async fn test_socks_uot_v1_basic() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!(
        "[TEST] SOCKS UoT V1: shoes SOCKS={}, sing-box SOCKS={}, UDP echo={}",
        shoes_port, singbox_socks_port, udp_echo_port
    );

    // Start UDP echo server
    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    // Start shoes SOCKS server
    let shoes_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: socks
"#,
        shoes_ip, shoes_port
    );
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    // sing-box config: SOCKS inbound -> SOCKS outbound with UoT V1
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
      "type": "socks",
      "tag": "socks-out",
      "server": "{}",
      "server_port": {},
      "udp_over_tcp": {{
        "enabled": true,
        "version": 1
      }}
    }}
  ],
  "route": {{
    "final": "socks-out"
  }}
}}"#,
        singbox_socks_ip, singbox_socks_port, shoes_ip, shoes_port
    );
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for servers to start
    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(300)).await;

    // Use SOCKS5 UDP ASSOCIATE
    let association = Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await?;
    let target: SocketAddr = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    // Send test packet
    let response = association.send_to(target, b"SOCKS UoT V1 Test!").await?;

    let response_str = std::str::from_utf8(&response)?;
    eprintln!("[TEST] Response: {:?}", response_str);
    assert!(response_str.contains("SOCKS UoT V1 Test!"));
    assert!(response_str.ends_with(" [ECHO]"));

    eprintln!("[TEST] ✓ SOCKS UoT V1 basic test passed!");
    Ok(())
}

/// Test SOCKS UoT V1 with multiple packets
#[tokio::test]
async fn test_socks_uot_v1_multiple_packets() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!("[TEST] SOCKS UoT V1 multiple packets");

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    let shoes_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: socks
"#,
        shoes_ip, shoes_port
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "info" }},
  "inbounds": [{{ "type": "socks", "tag": "socks-in", "listen": "{}", "listen_port": {} }}],
  "outbounds": [{{
    "type": "socks", "tag": "socks-out", "server": "{}", "server_port": {},
    "udp_over_tcp": {{ "enabled": true, "version": 1 }}
  }}],
  "route": {{ "final": "socks-out" }}
}}"#,
        singbox_socks_ip, singbox_socks_port, shoes_ip, shoes_port
    );
    let (_singbox_guard, _singbox_cfg) = start_singbox_server(&singbox_config)?;

    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(200)).await;

    let association = Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await?;
    let target: SocketAddr = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    // Send multiple packets
    for i in 0..5 {
        let msg = format!("SOCKS Packet #{}", i);
        let response = association.send_to(target, msg.as_bytes()).await?;
        let response_str = std::str::from_utf8(&response)?;

        assert!(response_str.contains(&msg));
        assert!(response_str.ends_with(" [ECHO]"));
        eprintln!("[TEST] Packet {} OK", i);
    }

    eprintln!("[TEST] ✓ SOCKS UoT V1 multiple packets test passed!");
    Ok(())
}

/// Test SOCKS UoT V1 multi-destination
#[tokio::test]
async fn test_socks_uot_v1_multi_destination() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (udp_echo_ip1, udp_echo_port1) = port_helper.get_port();
    let (udp_echo_ip2, udp_echo_port2) = port_helper.get_port();

    eprintln!("[TEST] SOCKS UoT V1 multi-destination");

    let _echo_server1 = start_udp_echo_server(&udp_echo_ip1, udp_echo_port1).await?;
    let _echo_server2 = start_udp_echo_server(&udp_echo_ip2, udp_echo_port2).await?;

    let shoes_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: socks
"#,
        shoes_ip, shoes_port
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "info" }},
  "inbounds": [{{ "type": "socks", "tag": "socks-in", "listen": "{}", "listen_port": {} }}],
  "outbounds": [{{
    "type": "socks", "tag": "socks-out", "server": "{}", "server_port": {},
    "udp_over_tcp": {{ "enabled": true, "version": 1 }}
  }}],
  "route": {{ "final": "socks-out" }}
}}"#,
        singbox_socks_ip, singbox_socks_port, shoes_ip, shoes_port
    );
    let (_singbox_guard, _singbox_cfg) = start_singbox_server(&singbox_config)?;

    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(200)).await;

    let association = Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await?;

    // Send to first destination
    let target1: SocketAddr = format!("{udp_echo_ip1}:{udp_echo_port1}").parse()?;
    let response = association.send_to(target1, b"To Server 1").await?;
    assert!(std::str::from_utf8(&response)?.contains("To Server 1"));
    eprintln!("[TEST] Server 1 OK");

    // Send to second destination
    let target2: SocketAddr = format!("{udp_echo_ip2}:{udp_echo_port2}").parse()?;
    let response = association.send_to(target2, b"To Server 2").await?;
    assert!(std::str::from_utf8(&response)?.contains("To Server 2"));
    eprintln!("[TEST] Server 2 OK");

    eprintln!("[TEST] ✓ SOCKS UoT V1 multi-destination test passed!");
    Ok(())
}

// SOCKS UoT V2 TESTS

/// Test SOCKS UoT V2 - basic functionality
#[tokio::test]
async fn test_socks_uot_v2_basic() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!(
        "[TEST] SOCKS UoT V2: shoes SOCKS={}, sing-box SOCKS={}, UDP echo={}",
        shoes_port, singbox_socks_port, udp_echo_port
    );

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    let shoes_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: socks
"#,
        shoes_ip, shoes_port
    );
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    // sing-box config: SOCKS inbound -> SOCKS outbound with UoT V2
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
      "type": "socks",
      "tag": "socks-out",
      "server": "{}",
      "server_port": {},
      "udp_over_tcp": {{
        "enabled": true,
        "version": 2
      }}
    }}
  ],
  "route": {{
    "final": "socks-out"
  }}
}}"#,
        singbox_socks_ip, singbox_socks_port, shoes_ip, shoes_port
    );
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(300)).await;

    let association = Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await?;
    let target: SocketAddr = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    let response = association.send_to(target, b"SOCKS UoT V2 Test!").await?;

    let response_str = std::str::from_utf8(&response)?;
    eprintln!("[TEST] Response: {:?}", response_str);
    assert!(response_str.contains("SOCKS UoT V2 Test!"));
    assert!(response_str.ends_with(" [ECHO]"));

    eprintln!("[TEST] ✓ SOCKS UoT V2 basic test passed!");
    Ok(())
}

/// Test SOCKS UoT V2 with multiple packets
#[tokio::test]
async fn test_socks_uot_v2_multiple_packets() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!("[TEST] SOCKS UoT V2 multiple packets");

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    let shoes_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: socks
"#,
        shoes_ip, shoes_port
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "info" }},
  "inbounds": [{{ "type": "socks", "tag": "socks-in", "listen": "{}", "listen_port": {} }}],
  "outbounds": [{{
    "type": "socks", "tag": "socks-out", "server": "{}", "server_port": {},
    "udp_over_tcp": {{ "enabled": true, "version": 2 }}
  }}],
  "route": {{ "final": "socks-out" }}
}}"#,
        singbox_socks_ip, singbox_socks_port, shoes_ip, shoes_port
    );
    let (_singbox_guard, _singbox_cfg) = start_singbox_server(&singbox_config)?;

    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(200)).await;

    let association = Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await?;
    let target: SocketAddr = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    for i in 0..5 {
        let msg = format!("SOCKS V2 Packet #{}", i);
        let response = association.send_to(target, msg.as_bytes()).await?;
        let response_str = std::str::from_utf8(&response)?;

        assert!(response_str.contains(&msg));
        assert!(response_str.ends_with(" [ECHO]"));
        eprintln!("[TEST] Packet {} OK", i);
    }

    eprintln!("[TEST] ✓ SOCKS UoT V2 multiple packets test passed!");
    Ok(())
}

// COMBINED TESTS

/// Test SOCKS UoT with various packet sizes
#[tokio::test]
async fn test_socks_uot_various_sizes() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!("[TEST] SOCKS UoT various sizes");

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    let shoes_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: socks
"#,
        shoes_ip, shoes_port
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "info" }},
  "inbounds": [{{ "type": "socks", "tag": "socks-in", "listen": "{}", "listen_port": {} }}],
  "outbounds": [{{
    "type": "socks", "tag": "socks-out", "server": "{}", "server_port": {},
    "udp_over_tcp": {{ "enabled": true, "version": 1 }}
  }}],
  "route": {{ "final": "socks-out" }}
}}"#,
        singbox_socks_ip, singbox_socks_port, shoes_ip, shoes_port
    );
    let (_singbox_guard, _singbox_cfg) = start_singbox_server(&singbox_config)?;

    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(200)).await;

    let association = Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await?;
    let target: SocketAddr = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    // Test various sizes
    let sizes = [1, 10, 100, 500, 1000, 2000, 4000, 8000];

    for &size in &sizes {
        let payload: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let response = association.send_to(target, &payload).await?;

        assert_eq!(response.len(), payload.len() + 7, "Size {} failed", size);
        assert_eq!(&response[..payload.len()], &payload[..]);
        eprintln!("[TEST] {} bytes OK", size);
    }

    eprintln!("[TEST] ✓ SOCKS UoT various sizes test passed!");
    Ok(())
}

/// Test that SOCKS server config parses correctly
#[tokio::test]
async fn test_socks_uot_config_parses() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_listener_port();

    let shoes_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: socks
"#,
        shoes_ip, shoes_port
    );

    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    port_helper.wait_for_all_ports().await?;

    eprintln!("[TEST] ✓ SOCKS server started successfully with UoT support");

    Ok(())
}
