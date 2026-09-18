/// Integration tests for NaiveProxy UDP-over-TCP (UoT) protocol
///
/// NaiveProxy supports UDP traffic tunneling via the sing-box UoT protocol:
/// - V1: Multi-destination mode (sp.udp-over-tcp.arpa)
/// - V2: Connect mode with single destination (sp.v2.udp-over-tcp.arpa)
///
/// Test architecture:
/// sing-box (SOCKS inbound + naive outbound with UoT)
///   -> shoes NaiveProxy server (inside TLS)
///   -> UDP target
use shoes_test_support as common;

use common::certs::generate_ca_signed_cert_bundle_files;
use common::port_helper::PortHelper;
use common::socks5::Socks5UdpAssociation;
use common::test_fixture::{
    ProcessGuard, SingBoxCapability, start_shoes_server, start_singbox_server_with,
};
use common::test_servers::start_udp_echo_server;

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use tokio::time::{sleep, timeout};

/// Helper to start a sing-box proxy server with naive outbound support
fn start_singbox_server(config: &str) -> std::io::Result<(ProcessGuard, tempfile::NamedTempFile)> {
    start_singbox_server_with(config, SingBoxCapability::NaiveOutbound, &[])
}

// NaiveProxy UoT V2 TESTS (Connect mode - default for sing-box)

/// Test NaiveProxy UoT V2 - basic functionality
/// Architecture: singbox(socks + naive outbound w/ uot) -> shoes(tls + naiveproxy) -> udp echo
///
/// Note: Requires sing-box compiled with libcronet for naive outbound support.
/// Run with: sudo LD_LIBRARY_PATH=/tmp cargo test --test naiveproxy_uot_integration
/// Prerequisites:
/// - Build sing-box with: go build -tags "with_naive_outbound,with_purego" ./cmd/sing-box
/// - Download libcronet.so from https://github.com/sagernet/cronet-go/releases
/// - The generated private CA is passed directly to sing-box
#[tokio::test]
#[ignore = "manual test requires a Naive-enabled sing-box build and libcronet"]
async fn test_naiveproxy_uot_v2_basic() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    // Use 127.0.0.1 for shoes server since libcronet only works with 127.0.0.1
    let (shoes_ip, shoes_port) = port_helper.get_localhost_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!(
        "[TEST] NaiveProxy UoT V2: shoes={}, sing-box SOCKS={}, UDP echo={}",
        shoes_port, singbox_socks_port, udp_echo_port
    );

    // Start UDP echo server
    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    // Generate test certificate
    let (cert_path, key_path, ca_path) = generate_ca_signed_cert_bundle_files("test.local")?;

    // Start shoes NaiveProxy server (TLS + NaiveProxy inner)
    let shoes_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      "test.local":
        cert: {}
        key: {}
        alpn_protocols: ["h2"]
        protocol:
          type: naiveproxy
          udp_enabled: true
          users:
            - name: "testuser"
              username: "testuser"
              password: "testpassword123""#,
        shoes_ip,
        shoes_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
    );
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    // sing-box config: SOCKS inbound -> naive outbound with UoT V2
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
      "type": "naive",
      "tag": "naive-out",
      "server": "{}",
      "server_port": {},
      "username": "testuser",
      "password": "testpassword123",
      "tls": {{
        "enabled": true,
        "server_name": "test.local",
        "certificate_path": "{}"
      }},
      "udp_over_tcp": {{
        "enabled": true,
        "version": 2
      }}
    }}
  ],
  "route": {{
    "final": "naive-out"
  }}
}}"#,
        singbox_socks_ip,
        singbox_socks_port,
        shoes_ip,
        shoes_port,
        ca_path.to_str().unwrap()
    );
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for servers to start
    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    // Use SOCKS5 UDP ASSOCIATE
    let association = Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await?;
    let target: SocketAddr = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    // Send test packet
    let response = association
        .send_to(target, b"NaiveProxy UoT V2 Test!")
        .await?;

    let response_str = std::str::from_utf8(&response)?;
    eprintln!("[TEST] Response: {:?}", response_str);
    assert!(response_str.contains("NaiveProxy UoT V2 Test!"));
    assert!(response_str.ends_with(" [ECHO]"));

    eprintln!("[TEST] NaiveProxy UoT V2 basic test passed!");
    Ok(())
}

/// Test NaiveProxy UoT V2 with multiple packets
#[tokio::test]
#[ignore = "manual test requires a Naive-enabled sing-box build and libcronet"]
async fn test_naiveproxy_uot_v2_multiple_packets() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    // Use 127.0.0.1 for shoes server since libcronet only works with 127.0.0.1
    let (shoes_ip, shoes_port) = port_helper.get_localhost_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!("[TEST] NaiveProxy UoT V2 multiple packets");

    // Start UDP echo server
    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    // Generate test certificate
    let (cert_path, key_path, ca_path) = generate_ca_signed_cert_bundle_files("test.local")?;

    // Start shoes NaiveProxy server
    let shoes_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      "test.local":
        cert: {}
        key: {}
        alpn_protocols: ["h2"]
        protocol:
          type: naiveproxy
          udp_enabled: true
          users:
            - name: "testuser"
              username: "testuser"
              password: "testpassword123""#,
        shoes_ip,
        shoes_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
    );
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    // sing-box config with UoT V2
    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{ "type": "socks", "tag": "socks-in", "listen": "{}", "listen_port": {} }}],
  "outbounds": [{{
    "type": "naive",
    "tag": "naive-out",
    "server": "{}",
    "server_port": {},
    "username": "testuser",
    "password": "testpassword123",
    "tls": {{ "enabled": true, "server_name": "test.local", "certificate_path": "{}" }},
    "udp_over_tcp": {{ "enabled": true, "version": 2 }}
  }}],
  "route": {{ "final": "naive-out" }}
}}"#,
        singbox_socks_ip,
        singbox_socks_port,
        shoes_ip,
        shoes_port,
        ca_path.to_str().unwrap()
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
        let msg = format!("NaiveProxy UoT V2 Packet #{}", i);
        let response = association.send_to(target, msg.as_bytes()).await?;
        let response_str = std::str::from_utf8(&response)?;
        assert!(response_str.contains(&msg));
        assert!(response_str.ends_with(" [ECHO]"));
        eprintln!("[TEST] Packet {} OK", i);
    }

    eprintln!("[TEST] NaiveProxy UoT V2 multiple packets test passed!");
    Ok(())
}

// NaiveProxy UoT V1 TESTS (Multi-destination mode)

/// Test NaiveProxy UoT V1 - basic functionality
#[tokio::test]
#[ignore = "manual test requires a Naive-enabled sing-box build and libcronet"]
async fn test_naiveproxy_uot_v1_basic() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    // Use 127.0.0.1 for shoes server since libcronet only works with 127.0.0.1
    let (shoes_ip, shoes_port) = port_helper.get_localhost_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!(
        "[TEST] NaiveProxy UoT V1: shoes={}, sing-box SOCKS={}, UDP echo={}",
        shoes_port, singbox_socks_port, udp_echo_port
    );

    // Start UDP echo server
    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    // Generate test certificate
    let (cert_path, key_path, ca_path) = generate_ca_signed_cert_bundle_files("test.local")?;

    // Start shoes NaiveProxy server
    let shoes_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      "test.local":
        cert: {}
        key: {}
        alpn_protocols: ["h2"]
        protocol:
          type: naiveproxy
          udp_enabled: true
          users:
            - name: "testuser"
              username: "testuser"
              password: "testpassword123""#,
        shoes_ip,
        shoes_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
    );
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    // sing-box config with UoT V1
    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{ "type": "socks", "tag": "socks-in", "listen": "{}", "listen_port": {} }}],
  "outbounds": [{{
    "type": "naive",
    "tag": "naive-out",
    "server": "{}",
    "server_port": {},
    "username": "testuser",
    "password": "testpassword123",
    "tls": {{ "enabled": true, "server_name": "test.local", "certificate_path": "{}" }},
    "udp_over_tcp": {{ "enabled": true, "version": 1 }}
  }}],
  "route": {{ "final": "naive-out" }}
}}"#,
        singbox_socks_ip,
        singbox_socks_port,
        shoes_ip,
        shoes_port,
        ca_path.to_str().unwrap()
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
        .send_to(target, b"NaiveProxy UoT V1 Test!")
        .await?;

    let response_str = std::str::from_utf8(&response)?;
    eprintln!("[TEST] Response: {:?}", response_str);
    assert!(response_str.contains("NaiveProxy UoT V1 Test!"));
    assert!(response_str.ends_with(" [ECHO]"));

    eprintln!("[TEST] NaiveProxy UoT V1 basic test passed!");
    Ok(())
}

/// Test NaiveProxy UoT V1 multi-destination
#[tokio::test]
#[ignore = "manual test requires a Naive-enabled sing-box build and libcronet"]
async fn test_naiveproxy_uot_v1_multi_destination() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    // Use 127.0.0.1 for shoes server since libcronet only works with 127.0.0.1
    let (shoes_ip, shoes_port) = port_helper.get_localhost_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (udp_echo_ip1, udp_echo_port1) = port_helper.get_port();
    let (udp_echo_ip2, udp_echo_port2) = port_helper.get_port();

    eprintln!("[TEST] NaiveProxy UoT V1 multi-destination");

    // Start two UDP echo servers
    let _echo_server1 = start_udp_echo_server(&udp_echo_ip1, udp_echo_port1).await?;
    let _echo_server2 = start_udp_echo_server(&udp_echo_ip2, udp_echo_port2).await?;

    // Generate test certificate
    let (cert_path, key_path, ca_path) = generate_ca_signed_cert_bundle_files("test.local")?;

    // Start shoes NaiveProxy server
    let shoes_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      "test.local":
        cert: {}
        key: {}
        alpn_protocols: ["h2"]
        protocol:
          type: naiveproxy
          udp_enabled: true
          users:
            - name: "testuser"
              username: "testuser"
              password: "testpassword123""#,
        shoes_ip,
        shoes_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
    );
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    // sing-box config with UoT V1
    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{ "type": "socks", "tag": "socks-in", "listen": "{}", "listen_port": {} }}],
  "outbounds": [{{
    "type": "naive",
    "tag": "naive-out",
    "server": "{}",
    "server_port": {},
    "username": "testuser",
    "password": "testpassword123",
    "tls": {{ "enabled": true, "server_name": "test.local", "certificate_path": "{}" }},
    "udp_over_tcp": {{ "enabled": true, "version": 1 }}
  }}],
  "route": {{ "final": "naive-out" }}
}}"#,
        singbox_socks_ip,
        singbox_socks_port,
        shoes_ip,
        shoes_port,
        ca_path.to_str().unwrap()
    );
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for servers
    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    // Use SOCKS5 UDP ASSOCIATE
    let association = Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await?;

    // Send to first destination
    let target1: SocketAddr = format!("{udp_echo_ip1}:{udp_echo_port1}").parse()?;
    let response1 = association.send_to(target1, b"NaiveProxy Dest 1!").await?;
    let response1_str = std::str::from_utf8(&response1)?;
    assert!(response1_str.contains("NaiveProxy Dest 1!"));
    eprintln!("[TEST] Destination 1 OK");

    // Send to second destination
    let target2: SocketAddr = format!("{udp_echo_ip2}:{udp_echo_port2}").parse()?;
    let response2 = association.send_to(target2, b"NaiveProxy Dest 2!").await?;
    let response2_str = std::str::from_utf8(&response2)?;
    assert!(response2_str.contains("NaiveProxy Dest 2!"));
    eprintln!("[TEST] Destination 2 OK");

    eprintln!("[TEST] NaiveProxy UoT V1 multi-destination test passed!");
    Ok(())
}

// NaiveProxy UoT EDGE CASES

/// Test that NaiveProxy UoT is rejected when udp_enabled is false
#[tokio::test]
#[ignore = "manual test requires a Naive-enabled sing-box build and libcronet"]
async fn test_naiveproxy_uot_disabled() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    // Use 127.0.0.1 for shoes server since libcronet only works with 127.0.0.1
    let (shoes_ip, shoes_port) = port_helper.get_localhost_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!("[TEST] NaiveProxy UoT with udp_enabled: false (should reject)");

    // Start UDP echo server
    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    // Generate test certificate
    let (cert_path, key_path, ca_path) = generate_ca_signed_cert_bundle_files("test.local")?;

    // Start shoes NaiveProxy server with udp_enabled: false
    let shoes_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      "test.local":
        cert: {}
        key: {}
        alpn_protocols: ["h2"]
        protocol:
          type: naiveproxy
          udp_enabled: false
          users:
            - name: "testuser"
              username: "testuser"
              password: "testpassword123""#,
        shoes_ip,
        shoes_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
    );
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    // sing-box config with UoT V2
    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{ "type": "socks", "tag": "socks-in", "listen": "{}", "listen_port": {} }}],
  "outbounds": [{{
    "type": "naive",
    "tag": "naive-out",
    "server": "{}",
    "server_port": {},
    "username": "testuser",
    "password": "testpassword123",
    "tls": {{ "enabled": true, "server_name": "test.local", "certificate_path": "{}" }},
    "udp_over_tcp": {{ "enabled": true, "version": 2 }}
  }}],
  "route": {{ "final": "naive-out" }}
}}"#,
        singbox_socks_ip,
        singbox_socks_port,
        shoes_ip,
        shoes_port,
        ca_path.to_str().unwrap()
    );
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for servers
    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    // Try SOCKS5 UDP ASSOCIATE - this should work but actual UDP should fail
    let associate_result =
        Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await;

    match associate_result {
        Ok(association) => {
            let target: SocketAddr = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

            // Try to send - should timeout because shoes rejected UoT
            let send_result =
                timeout(Duration::from_secs(3), association.send_to(target, b"Test")).await;

            match send_result {
                Ok(Ok(_)) => {
                    // If we got a response, that's wrong - UoT should be disabled
                    panic!("UoT was not rejected when udp_enabled=false!");
                }
                Ok(Err(_)) | Err(_) => {
                    // Expected - either error or timeout
                    eprintln!("[TEST] Expected: timeout or error (UoT connection was rejected)");
                }
            }
        }
        Err(e) => {
            // Also acceptable - connection failed
            eprintln!("[TEST] UDP ASSOCIATE failed (expected): {}", e);
        }
    }

    eprintln!("[TEST] NaiveProxy UoT disabled test passed (UDP correctly rejected)!");
    Ok(())
}

/// Test NaiveProxy UoT with various packet sizes
#[tokio::test]
#[ignore = "manual test requires a Naive-enabled sing-box build and libcronet"]
async fn test_naiveproxy_uot_various_sizes() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = PortHelper::new();
    // Use 127.0.0.1 for shoes server since libcronet only works with 127.0.0.1
    let (shoes_ip, shoes_port) = port_helper.get_localhost_listener_port();
    let (singbox_socks_ip, singbox_socks_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!("[TEST] NaiveProxy UoT various sizes");

    // Start UDP echo server
    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    // Generate test certificate
    let (cert_path, key_path, ca_path) = generate_ca_signed_cert_bundle_files("test.local")?;

    // Start shoes NaiveProxy server
    let shoes_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      "test.local":
        cert: {}
        key: {}
        alpn_protocols: ["h2"]
        protocol:
          type: naiveproxy
          udp_enabled: true
          users:
            - name: "testuser"
              username: "testuser"
              password: "testpassword123""#,
        shoes_ip,
        shoes_port,
        AsRef::<Path>::as_ref(&cert_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_path).to_str().unwrap(),
    );
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;

    // sing-box config with UoT V2
    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{ "type": "socks", "tag": "socks-in", "listen": "{}", "listen_port": {} }}],
  "outbounds": [{{
    "type": "naive",
    "tag": "naive-out",
    "server": "{}",
    "server_port": {},
    "username": "testuser",
    "password": "testpassword123",
    "tls": {{ "enabled": true, "server_name": "test.local", "certificate_path": "{}" }},
    "udp_over_tcp": {{ "enabled": true, "version": 2 }}
  }}],
  "route": {{ "final": "naive-out" }}
}}"#,
        singbox_socks_ip,
        singbox_socks_port,
        shoes_ip,
        shoes_port,
        ca_path.to_str().unwrap()
    );
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;

    // Wait for servers
    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(500)).await;

    // Use SOCKS5 UDP ASSOCIATE
    let association = Socks5UdpAssociation::connect(&singbox_socks_ip, singbox_socks_port).await?;
    let target: SocketAddr = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    // Test various sizes
    let sizes = [1, 10, 100, 500, 1000];
    for size in sizes {
        let msg: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let response = association.send_to(target, &msg).await?;
        // Echo server appends " [ECHO]" so response is larger
        assert!(response.len() >= size);
        eprintln!("[TEST] Size {} OK", size);
    }

    eprintln!("[TEST] NaiveProxy UoT various sizes test passed!");
    Ok(())
}
