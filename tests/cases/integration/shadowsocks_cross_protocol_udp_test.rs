/// Integration tests for Cross-Protocol UDP support
///
/// These tests verify the cross-protocol UDP bridging functionality:
/// - SessionToMulti: VLESS/VMess server (XUDP) -> Shadowsocks client (UoT)
/// - MultiToSession: Shadowsocks server (UoT) -> VLESS/VMess client (XUDP)
///
/// This tests the newly added cross-protocol variants in TcpClientUdpSetupResult
/// and the copy_session_to_sourced / copy_targeted_to_session functions.
use shoes_test_support as common;

use common::port_helper::PortHelper;
use common::socks5::Socks5UdpAssociation;
use common::test_fixture::{start_shoes_server, start_singbox_server as start_singbox};
use common::test_servers::start_udp_echo_server;

use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::sleep;

const TEST_PASSWORD: &str = "cross-protocol-test-password";
const VLESS_UUID: &str = "b85798ef-e9dc-46a4-9a87-8da4499d36d0";

// CROSS-PROTOCOL TESTS

/// Test: VLESS server (shoes, XUDP) -> Shadowsocks client (shoes, UoT) -> SS server (sing-box)
///
/// This tests the SessionToMulti cross-protocol variant.
/// Architecture:
///   sing-box VLESS client (XUDP) -> shoes VLESS server -> shoes SS client (UoT) -> sing-box SS server -> UDP echo
///
/// The shoes VLESS server receives SessionBased UDP, and the shoes SS client
/// outputs MultiDirectional (Sourced) UDP. This requires copy_session_to_sourced().
#[tokio::test]
async fn test_vless_server_to_ss_client_cross_protocol() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (shoes_vless_ip, shoes_vless_port) = port_helper.get_listener_port();
    let (singbox_ss_ip, singbox_ss_port) = port_helper.get_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!(
        "[TEST] Cross-protocol: VLESS(shoes)={} -> SS client(shoes) -> SS server(sing-box)={} -> echo={}",
        shoes_vless_port, singbox_ss_port, udp_echo_port
    );

    // Start UDP echo server
    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    // Start sing-box as Shadowsocks SERVER (final destination for SS client)
    // Note: sing-box SS inbound automatically supports UoT - no config option needed
    let singbox_ss_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{
    "type": "shadowsocks",
    "tag": "ss-in",
    "listen": "{}",
    "listen_port": {},
    "method": "aes-256-gcm",
    "password": "{}"
  }}],
  "outbounds": [{{ "type": "direct", "tag": "direct" }}],
  "route": {{ "final": "direct" }}
}}"#,
        singbox_ss_ip, singbox_ss_port, TEST_PASSWORD
    );
    let (_singbox_ss_guard, _singbox_ss_cfg) = start_singbox(&singbox_ss_config)?;

    // Start shoes with VLESS server that chains to SS client
    let shoes_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: vless
    user_id: "{}"
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_proxy:
        address: "{}:{}"
        protocol:
          type: shadowsocks
          cipher: aes-256-gcm
          password: "{}"
          udp_enabled: true
"#,
        shoes_vless_ip, shoes_vless_port, VLESS_UUID, singbox_ss_ip, singbox_ss_port, TEST_PASSWORD
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    // Start sing-box as VLESS CLIENT with SOCKS inbound (to test from)
    let singbox_client_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{
    "type": "socks",
    "tag": "socks-in",
    "listen": "{}",
    "listen_port": {}
  }}],
  "outbounds": [{{
    "type": "vless",
    "tag": "vless-out",
    "server": "{}",
    "server_port": {},
    "uuid": "{}",
    "packet_encoding": "xudp"
  }}],
  "route": {{ "final": "vless-out" }}
}}"#,
        singbox_socks_ip, singbox_socks_port, shoes_vless_ip, shoes_vless_port, VLESS_UUID
    );
    let (_singbox_client_guard, _singbox_client_cfg) = start_singbox(&singbox_client_config)?;

    // Wait for all servers
    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    // Test UDP through the cross-protocol chain
    let association = Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await?;
    let target: SocketAddr = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    let response = association
        .send_to(target, b"Cross-protocol VLESS->SS test!")
        .await?;

    let response_str = std::str::from_utf8(&response)?;
    eprintln!("[TEST] Response: {:?}", response_str);
    assert!(response_str.contains("Cross-protocol VLESS->SS test!"));
    assert!(response_str.ends_with(" [ECHO]"));

    eprintln!("[TEST] VLESS server -> SS client cross-protocol test passed!");
    Ok(())
}

/// Test: Shadowsocks server (shoes, UoT) -> VLESS client (shoes, XUDP) -> VLESS server (sing-box)
///
/// This tests the MultiToSession cross-protocol variant.
/// Architecture:
///   sing-box SS client (UoT) -> shoes SS server -> shoes VLESS client (XUDP) -> sing-box VLESS server -> UDP echo
///
/// The shoes SS server receives MultiDirectional (Targeted) UDP, and the shoes VLESS client
/// outputs SessionBased UDP. This requires copy_targeted_to_session().
#[tokio::test]
async fn test_ss_server_to_vless_client_cross_protocol() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ss_ip, shoes_ss_port) = port_helper.get_listener_port();
    let (singbox_vless_ip, singbox_vless_port) = port_helper.get_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!(
        "[TEST] Cross-protocol: SS(shoes)={} -> VLESS client(shoes) -> VLESS server(sing-box)={} -> echo={}",
        shoes_ss_port, singbox_vless_port, udp_echo_port
    );

    // Start UDP echo server
    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    // Start sing-box as VLESS SERVER (final destination for VLESS client)
    // Note: sing-box VLESS inbound automatically supports XUDP - no config option needed
    let singbox_vless_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{
    "type": "vless",
    "tag": "vless-in",
    "listen": "{}",
    "listen_port": {},
    "users": [{{ "uuid": "{}" }}]
  }}],
  "outbounds": [{{ "type": "direct", "tag": "direct" }}],
  "route": {{ "final": "direct" }}
}}"#,
        singbox_vless_ip, singbox_vless_port, VLESS_UUID
    );
    let (_singbox_vless_guard, _singbox_vless_cfg) = start_singbox(&singbox_vless_config)?;

    // Start shoes with SS server that chains to VLESS client
    let shoes_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: shadowsocks
    cipher: aes-256-gcm
    password: "{}"
    udp_enabled: true
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_proxy:
        address: "{}:{}"
        protocol:
          type: vless
          user_id: "{}"
"#,
        shoes_ss_ip, shoes_ss_port, TEST_PASSWORD, singbox_vless_ip, singbox_vless_port, VLESS_UUID
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    // Start sing-box as SS CLIENT with SOCKS inbound (to test from)
    let singbox_client_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{
    "type": "socks",
    "tag": "socks-in",
    "listen": "{}",
    "listen_port": {}
  }}],
  "outbounds": [{{
    "type": "shadowsocks",
    "tag": "ss-out",
    "server": "{}",
    "server_port": {},
    "method": "aes-256-gcm",
    "password": "{}",
    "udp_over_tcp": {{ "enabled": true, "version": 1 }}
  }}],
  "route": {{ "final": "ss-out" }}
}}"#,
        singbox_socks_ip, singbox_socks_port, shoes_ss_ip, shoes_ss_port, TEST_PASSWORD
    );
    let (_singbox_client_guard, _singbox_client_cfg) = start_singbox(&singbox_client_config)?;

    // Wait for all servers
    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    // Test UDP through the cross-protocol chain
    let association = Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await?;
    let target: SocketAddr = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    let response = association
        .send_to(target, b"Cross-protocol SS->VLESS test!")
        .await?;

    let response_str = std::str::from_utf8(&response)?;
    eprintln!("[TEST] Response: {:?}", response_str);
    assert!(response_str.contains("Cross-protocol SS->VLESS test!"));
    assert!(response_str.ends_with(" [ECHO]"));

    eprintln!("[TEST] SS server -> VLESS client cross-protocol test passed!");
    Ok(())
}

/// Test: Double hop - SS server -> SS client -> different SS server
///
/// This tests same-protocol chaining (MultiDirectional -> MultiDirectional).
#[tokio::test]
async fn test_ss_to_ss_chain() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ss1_ip, shoes_ss1_port) = port_helper.get_listener_port();
    let (singbox_ss2_ip, singbox_ss2_port) = port_helper.get_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    let password1 = "password-hop-1";
    let password2 = "password-hop-2";

    eprintln!(
        "[TEST] SS chain: SS1(shoes)={} -> SS2(sing-box)={} -> echo={}",
        shoes_ss1_port, singbox_ss2_port, udp_echo_port
    );

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    // Start sing-box as second SS server (final hop)
    // Note: sing-box SS inbound automatically supports UoT - no config option needed
    let singbox_ss2_config = format!(
        r#"{{
  "log": {{ "level": "info" }},
  "inbounds": [{{
    "type": "shadowsocks",
    "tag": "ss-in",
    "listen": "{}",
    "listen_port": {},
    "method": "aes-256-gcm",
    "password": "{}"
  }}],
  "outbounds": [{{ "type": "direct", "tag": "direct" }}],
  "route": {{ "final": "direct" }}
}}"#,
        singbox_ss2_ip, singbox_ss2_port, password2
    );
    let (_singbox_ss2_guard, _singbox_ss2_cfg) = start_singbox(&singbox_ss2_config)?;

    // Start shoes SS server that chains to sing-box SS
    let shoes_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: shadowsocks
    cipher: aes-256-gcm
    password: "{}"
    udp_enabled: true
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_proxy:
        address: "{}:{}"
        protocol:
          type: shadowsocks
          cipher: aes-256-gcm
          password: "{}"
          udp_enabled: true
"#,
        shoes_ss1_ip, shoes_ss1_port, password1, singbox_ss2_ip, singbox_ss2_port, password2
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    // Start sing-box as first SS client
    let singbox_client_config = format!(
        r#"{{
  "log": {{ "level": "info" }},
  "inbounds": [{{
    "type": "socks",
    "tag": "socks-in",
    "listen": "{}",
    "listen_port": {}
  }}],
  "outbounds": [{{
    "type": "shadowsocks",
    "tag": "ss-out",
    "server": "{}",
    "server_port": {},
    "method": "aes-256-gcm",
    "password": "{}",
    "udp_over_tcp": {{ "enabled": true, "version": 1 }}
  }}],
  "route": {{ "final": "ss-out" }}
}}"#,
        singbox_socks_ip, singbox_socks_port, shoes_ss1_ip, shoes_ss1_port, password1
    );
    let (_singbox_client_guard, _singbox_client_cfg) = start_singbox(&singbox_client_config)?;

    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    let association = Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await?;
    let target: SocketAddr = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    let response = association.send_to(target, b"SS chain test!").await?;

    let response_str = std::str::from_utf8(&response)?;
    assert!(response_str.contains("SS chain test!"));
    eprintln!("[TEST] SS chain test passed!");
    Ok(())
}
