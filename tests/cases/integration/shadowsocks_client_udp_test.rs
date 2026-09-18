/// Integration tests for Shadowsocks Client UDP-over-TCP (UoT) support
///
/// These tests verify shoes acting as a Shadowsocks CLIENT with UDP support,
/// which is the newly implemented functionality. The tests cover:
///
/// 1. Shoes as Shadowsocks client connecting to external SS server with UoT
/// 2. Cross-protocol UDP: VLESS server (SessionBased) -> SS client (MultiDirectional)
/// 3. UDP disabled scenarios on client side
/// 4. Various chain configurations with UDP
use shoes_test_support as common;

use common::port_helper::PortHelper;
use common::socks5::Socks5UdpAssociation;
use common::test_fixture::{start_shoes_server, start_singbox_server as start_singbox_ss_server};
use common::test_servers::start_udp_echo_server;

use std::net::SocketAddr;
use std::time::Duration;

// SHOES AS SHADOWSOCKS CLIENT TESTS

/// Test: Shoes SS server + SS client chain with UDP support
///
/// This tests the newly implemented client UDP support in ShadowsocksTcpHandler.
/// Architecture:
///   sing-box SOCKS5 (UoT client) -> shoes SS server -> shoes SS client (UoT) -> sing-box SS server -> UDP echo
///
/// The flow:
/// 1. Test client does SOCKS5 UDP ASSOCIATE to sing-box
/// 2. sing-box converts UDP to UoT and sends to shoes SS server
/// 3. shoes SS server receives UoT, chains to shoes SS client
/// 4. shoes SS client sends UoT to final sing-box SS server
/// 5. sing-box SS server sends UDP to echo server
#[tokio::test]
async fn test_shoes_ss_client_uot_v1() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (shoes_ss_ip, shoes_ss_port) = port_helper.get_listener_port();
    let (singbox_ss_ip, singbox_ss_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    let password_hop1 = "password-first-hop";
    let password_hop2 = "password-second-hop";

    eprintln!(
        "[TEST] shoes SS client test: SOCKS={}, shoes SS={}, sing-box SS={}, echo={}",
        singbox_socks_port, shoes_ss_port, singbox_ss_port, udp_echo_port
    );

    // Start UDP echo server
    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    // Start sing-box as final Shadowsocks SERVER
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
  "outbounds": [{{
    "type": "direct",
    "tag": "direct"
  }}],
  "route": {{ "final": "direct" }}
}}"#,
        singbox_ss_ip, singbox_ss_port, password_hop2
    );
    let (_singbox_ss_guard, _singbox_ss_cfg) = start_singbox_ss_server(&singbox_ss_config)?;

    // Start shoes with SS server that chains to SS client
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
        shoes_ss_ip, shoes_ss_port, password_hop1, singbox_ss_ip, singbox_ss_port, password_hop2
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    // Start sing-box as SOCKS5 entry point with SS client (UoT enabled)
    let singbox_socks_config = format!(
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
        singbox_socks_ip, singbox_socks_port, shoes_ss_ip, shoes_ss_port, password_hop1
    );
    let (_singbox_socks_guard, _singbox_socks_cfg) =
        start_singbox_ss_server(&singbox_socks_config)?;

    // Wait for servers to start
    port_helper.wait_for_all_ports().await?;

    // Test UDP through the chain
    let association = Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await?;
    let target: SocketAddr = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    let response = association
        .send_to(target, b"Hello from shoes SS client!")
        .await?;

    assert_eq!(response, b"Hello from shoes SS client! [ECHO]");

    eprintln!("[TEST] shoes SS client UoT V1 test passed!");
    Ok(())
}

/// Test: Shoes SS server + SS client chain with udp_enabled: false on client - should reject UoT
///
/// Architecture:
///   sing-box SOCKS5 (UoT client) -> shoes SS server -> shoes SS client (udp_enabled: false) -> sing-box SS server
///
/// When shoes SS client has udp_enabled: false, it should reject UoT connections.
#[tokio::test]
async fn test_shoes_ss_client_udp_disabled() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (shoes_ss_ip, shoes_ss_port) = port_helper.get_listener_port();
    let (singbox_ss_ip, singbox_ss_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    let password_hop1 = "password-first-hop";
    let password_hop2 = "password-second-hop";

    eprintln!(
        "[TEST] shoes SS client UDP disabled test: SOCKS={}, shoes SS={}, final SS={}",
        singbox_socks_port, shoes_ss_port, singbox_ss_port
    );

    // Start UDP echo server (won't actually receive anything)
    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    // Start sing-box as final Shadowsocks SERVER
    let singbox_ss_config = format!(
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
        singbox_ss_ip, singbox_ss_port, password_hop2
    );
    let (_singbox_ss_guard, _singbox_ss_cfg) = start_singbox_ss_server(&singbox_ss_config)?;

    // Start shoes with SS server -> SS client (udp_enabled: false)
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
          udp_enabled: false
"#,
        shoes_ss_ip, shoes_ss_port, password_hop1, singbox_ss_ip, singbox_ss_port, password_hop2
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    // Start sing-box as SOCKS5 entry point with SS client (UoT enabled)
    let singbox_socks_config = format!(
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
        singbox_socks_ip, singbox_socks_port, shoes_ss_ip, shoes_ss_port, password_hop1
    );
    let (_singbox_socks_guard, _singbox_socks_cfg) =
        start_singbox_ss_server(&singbox_socks_config)?;

    port_helper.wait_for_all_ports().await?;

    let association = Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await?;
    let target: SocketAddr = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;
    let error = association
        .send_to_with_timeout(
            common::socks5::SocksDestination::Ip(target),
            b"must not arrive",
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    Ok(())
}

/// Test: Shoes SS server + SS client chain with multiple UDP packets
///
/// Architecture:
///   sing-box SOCKS5 (UoT client) -> shoes SS server -> shoes SS client (UoT) -> sing-box SS server -> UDP echo
#[tokio::test]
async fn test_shoes_ss_client_multiple_packets() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (shoes_ss_ip, shoes_ss_port) = port_helper.get_listener_port();
    let (singbox_ss_ip, singbox_ss_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    let password_hop1 = "password-first-hop";
    let password_hop2 = "password-second-hop";

    eprintln!("[TEST] shoes SS client multiple packets test");

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    // Start sing-box as final Shadowsocks SERVER
    let singbox_ss_config = format!(
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
        singbox_ss_ip, singbox_ss_port, password_hop2
    );
    let (_singbox_ss_guard, _singbox_ss_cfg) = start_singbox_ss_server(&singbox_ss_config)?;

    // Start shoes with SS server -> SS client
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
        shoes_ss_ip, shoes_ss_port, password_hop1, singbox_ss_ip, singbox_ss_port, password_hop2
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    // Start sing-box as SOCKS5 entry point with SS client (UoT enabled)
    let singbox_socks_config = format!(
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
        singbox_socks_ip, singbox_socks_port, shoes_ss_ip, shoes_ss_port, password_hop1
    );
    let (_singbox_socks_guard, _singbox_socks_cfg) =
        start_singbox_ss_server(&singbox_socks_config)?;

    port_helper.wait_for_all_ports().await?;

    let association = Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await?;
    let target: SocketAddr = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    // Send multiple packets
    for i in 0..5 {
        let msg = format!("Packet #{} from shoes client", i);
        let response = association.send_to(target, msg.as_bytes()).await?;
        assert_eq!(response, format!("{msg} [ECHO]").into_bytes());
        eprintln!("[TEST] Packet {} OK", i);
    }

    eprintln!("[TEST] Multiple packets test passed!");
    Ok(())
}

/// Test: Shoes SS server + SS client chain with chacha20-ietf-poly1305 cipher
///
/// Architecture:
///   sing-box SOCKS5 (UoT client) -> shoes SS server -> shoes SS client (UoT) -> sing-box SS server -> UDP echo
#[tokio::test]
async fn test_shoes_ss_client_chacha20() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (shoes_ss_ip, shoes_ss_port) = port_helper.get_listener_port();
    let (singbox_ss_ip, singbox_ss_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    let password_hop1 = "password-chacha20-hop1";
    let password_hop2 = "password-chacha20-hop2";

    eprintln!("[TEST] shoes SS client chacha20 test");

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    // Start sing-box as final Shadowsocks SERVER (chacha20)
    let singbox_ss_config = format!(
        r#"{{
  "log": {{ "level": "info" }},
  "inbounds": [{{
    "type": "shadowsocks",
    "tag": "ss-in",
    "listen": "{}",
    "listen_port": {},
    "method": "chacha20-ietf-poly1305",
    "password": "{}"
  }}],
  "outbounds": [{{ "type": "direct", "tag": "direct" }}],
  "route": {{ "final": "direct" }}
}}"#,
        singbox_ss_ip, singbox_ss_port, password_hop2
    );
    let (_singbox_ss_guard, _singbox_ss_cfg) = start_singbox_ss_server(&singbox_ss_config)?;

    // Start shoes with SS server (aes-256-gcm) -> SS client (chacha20)
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
          cipher: chacha20-ietf-poly1305
          password: "{}"
          udp_enabled: true
"#,
        shoes_ss_ip, shoes_ss_port, password_hop1, singbox_ss_ip, singbox_ss_port, password_hop2
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    // Start sing-box as SOCKS5 entry point with SS client (UoT enabled, aes-256-gcm)
    let singbox_socks_config = format!(
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
        singbox_socks_ip, singbox_socks_port, shoes_ss_ip, shoes_ss_port, password_hop1
    );
    let (_singbox_socks_guard, _singbox_socks_cfg) =
        start_singbox_ss_server(&singbox_socks_config)?;

    port_helper.wait_for_all_ports().await?;

    let association = Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await?;
    let target: SocketAddr = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    let response = association.send_to(target, b"ChaCha20 test!").await?;
    assert_eq!(response, b"ChaCha20 test! [ECHO]");
    eprintln!("[TEST] ChaCha20 test passed!");
    Ok(())
}

/// Test: Shoes SS server + SS client chain with 2022-blake3-aes-256-gcm cipher
///
/// Architecture:
///   sing-box SOCKS5 (UoT client) -> shoes SS server -> shoes SS client (UoT) -> sing-box SS server -> UDP echo
#[tokio::test]
async fn test_shoes_ss_client_2022_blake3() -> Result<(), Box<dyn std::error::Error>> {
    // 32-byte keys for 2022-blake3-aes-256-gcm
    let password_hop1 = "test-blake3-password-hop1-xxxxx"; // 32 bytes
    let password_hop2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; // base64 encoded 32-byte key

    let mut port_helper = PortHelper::new();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (shoes_ss_ip, shoes_ss_port) = port_helper.get_listener_port();
    let (singbox_ss_ip, singbox_ss_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!("[TEST] shoes SS client 2022-blake3 test");

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    // Start sing-box as final Shadowsocks SERVER (2022-blake3)
    let singbox_ss_config = format!(
        r#"{{
  "log": {{ "level": "info" }},
  "inbounds": [{{
    "type": "shadowsocks",
    "tag": "ss-in",
    "listen": "{}",
    "listen_port": {},
    "method": "2022-blake3-aes-256-gcm",
    "password": "{}"
  }}],
  "outbounds": [{{ "type": "direct", "tag": "direct" }}],
  "route": {{ "final": "direct" }}
}}"#,
        singbox_ss_ip, singbox_ss_port, password_hop2
    );
    let (_singbox_ss_guard, _singbox_ss_cfg) = start_singbox_ss_server(&singbox_ss_config)?;

    // Start shoes with SS server (aes-256-gcm) -> SS client (2022-blake3)
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
          cipher: 2022-blake3-aes-256-gcm
          password: "{}"
          udp_enabled: true
"#,
        shoes_ss_ip, shoes_ss_port, password_hop1, singbox_ss_ip, singbox_ss_port, password_hop2
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    // Start sing-box as SOCKS5 entry point with SS client (UoT enabled, aes-256-gcm)
    let singbox_socks_config = format!(
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
        singbox_socks_ip, singbox_socks_port, shoes_ss_ip, shoes_ss_port, password_hop1
    );
    let (_singbox_socks_guard, _singbox_socks_cfg) =
        start_singbox_ss_server(&singbox_socks_config)?;

    port_helper.wait_for_all_ports().await?;

    let association = Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await?;
    let target: SocketAddr = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    let response = association.send_to(target, b"2022-blake3 test!").await?;
    assert_eq!(response, b"2022-blake3 test! [ECHO]");
    eprintln!("[TEST] 2022-blake3 test passed!");
    Ok(())
}

// UNIT TESTS FOR CONFIG AND HANDLER
