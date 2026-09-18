/// Integration tests for VLESS VISION with DNS over HTTPS (DoH) requests
///
/// This test file specifically tests DoH requests to Cloudflare DNS (1.1.1.1)
/// to catch issues that may not be caught by simple HTTPS payload tests.
///
/// DoH characteristics that make it a good test case:
/// - Small request/response sizes (typically < 512 bytes)
/// - Uses application/dns-message content type
/// - Often uses HTTP/2
/// - Real-world use case for VISION protocol
///
/// Test Architecture:
/// ==================
/// sing-box client (DoH request)
///   -> shoes VLESS+VISION Server
///      -> Cloudflare DNS (1.1.1.1 or cloudflare-dns.com)
use shoes_test_support as common;

use common::test_fixture::{ProcessGuard, find_singbox_binary};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;

const TEST_UUID: &str = "b85798ef-e9dc-46a4-9a87-8da4499d36d0";

/// Test DoH request to cloudflare-dns.com through VISION
///
/// This test uses sing-box as a client to make a DoH request through
/// a shoes VLESS+VISION server to Cloudflare's DNS over HTTPS endpoint.
#[tokio::test]
async fn test_shoes_vless_vision_doh_cloudflare() -> Result<(), Box<dyn std::error::Error>> {
    use common::test_servers::*;

    // Allocate random ports
    let mut port_helper = common::port_helper::PortHelper::new();
    let (vless_ip, vless_port) = port_helper.get_listener_port();
    let (http_ip, http_port) = port_helper.get_listener_port();
    eprintln!(
        "[TEST] Using ports: VLESS={}, HTTP={}",
        vless_port, http_port
    );

    // Generate certificates for VLESS VISION
    let (vless_cert, vless_key) = generate_test_cert()?;

    // shoes VLESS+VISION server
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
        vless_ip,
        vless_port,
        AsRef::<Path>::as_ref(&vless_cert).to_str().unwrap(),
        AsRef::<Path>::as_ref(&vless_key).to_str().unwrap(),
        TEST_UUID
    );

    let shoes_config_path = std::env::temp_dir().join("shoes_vision_doh_test.yaml");
    std::fs::write(&shoes_config_path, shoes_config)?;

    // Start shoes server
    eprintln!("[DEBUG] Starting shoes VLESS+VISION server...");
    let shoes_process = Command::new(env!("CARGO_BIN_EXE_shoes"))
        .arg(shoes_config_path.to_str().unwrap())
        .env("RUST_LOG", "debug")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    let _shoes_guard = ProcessGuard::new(shoes_process, "shoes".to_string());

    // sing-box client configuration with DoH outbound through VLESS+VISION
    let singbox_config = format!(
        r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "http",
      "tag": "http-in",
      "listen": "{}",
      "listen_port": {}
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
        "insecure": true,
        "server_name": "test.local"
      }}
    }}
  ]
}}"#,
        http_ip, http_port, vless_ip, vless_port, TEST_UUID
    );

    let singbox_config_path = std::env::temp_dir().join("singbox_vision_doh_test.json");
    std::fs::write(&singbox_config_path, singbox_config)?;

    // Start sing-box client
    let singbox_path = find_singbox_binary()?;
    eprintln!("[DEBUG] Starting sing-box client...");
    let singbox_process = Command::new(&singbox_path)
        .args(["run", "-c", singbox_config_path.to_str().unwrap()])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    let _singbox_guard = ProcessGuard::new(singbox_process, "sing-box".to_string());
    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(2000)).await;

    // Test 1: DoH request to cloudflare-dns.com (JSON format)
    eprintln!("[TEST] Testing DoH request to cloudflare-dns.com (JSON format)");
    let doh_url = "https://cloudflare-dns.com/dns-query?name=example.com&type=A";
    let output = common::curl::run_curl(
        doh_url,
        common::curl::CurlOptions::new()
            .proxy(format!("http://{}:{}", http_ip, http_port))
            .header("accept", "application/dns-json")
            .timeout(30),
    )
    .await?;

    eprintln!(
        "[TEST] DoH request completed with status: {:?}",
        output.status.code()
    );
    eprintln!("[TEST] Response body length: {} bytes", output.stdout.len());
    eprintln!(
        "[TEST] Response (first 200 chars): {}",
        String::from_utf8_lossy(&output.stdout[..std::cmp::min(200, output.stdout.len())])
    );

    if !output.status.success() {
        eprintln!("[TEST] stderr: {}", String::from_utf8_lossy(&output.stderr));
    }

    assert!(
        output.status.success(),
        "DoH request failed with exit code: {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify we got a JSON response
    let response_text = String::from_utf8_lossy(&output.stdout);
    assert!(
        response_text.contains("Answer")
            || response_text.contains("\"Status\"")
            || response_text.contains("\"Question\""),
        "DoH response doesn't look like valid DNS JSON response: {}",
        response_text
    );

    eprintln!("[TEST] Successfully completed DoH request through VISION");

    Ok(())
}

/// Test DoH request to 1.1.1.1 through VISION
///
/// This test uses the IP address directly instead of hostname,
/// which may trigger different code paths.
#[tokio::test]
async fn test_shoes_vless_vision_doh_1_1_1_1() -> Result<(), Box<dyn std::error::Error>> {
    use common::test_servers::*;

    // Allocate random ports
    let mut port_helper = common::port_helper::PortHelper::new();
    let (vless_ip, vless_port) = port_helper.get_listener_port();
    let (http_ip, http_port) = port_helper.get_listener_port();
    eprintln!(
        "[TEST] Using ports: VLESS={}, HTTP={}",
        vless_port, http_port
    );

    // Generate certificates for VLESS VISION
    let (vless_cert, vless_key) = generate_test_cert()?;

    // shoes VLESS+VISION server
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
        vless_ip,
        vless_port,
        AsRef::<Path>::as_ref(&vless_cert).to_str().unwrap(),
        AsRef::<Path>::as_ref(&vless_key).to_str().unwrap(),
        TEST_UUID
    );

    let shoes_config_path = std::env::temp_dir().join("shoes_vision_doh_1111_test.yaml");
    std::fs::write(&shoes_config_path, shoes_config)?;

    // Start shoes server
    eprintln!("[DEBUG] Starting shoes VLESS+VISION server...");
    let shoes_process = Command::new(env!("CARGO_BIN_EXE_shoes"))
        .arg(shoes_config_path.to_str().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let _shoes_guard = ProcessGuard::new(shoes_process, "shoes".to_string());

    // sing-box client configuration with DoH outbound through VLESS+VISION
    let singbox_config = format!(
        r#"{{
  "log": {{
    "level": "debug"
  }},
  "inbounds": [
    {{
      "type": "http",
      "tag": "http-in",
      "listen": "{}",
      "listen_port": {}
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
        "insecure": true,
        "server_name": "test.local"
      }}
    }}
  ]
}}"#,
        http_ip, http_port, vless_ip, vless_port, TEST_UUID
    );

    let singbox_config_path = std::env::temp_dir().join("singbox_vision_doh_1111_test.json");
    std::fs::write(&singbox_config_path, singbox_config)?;

    // Start sing-box client
    let singbox_path = find_singbox_binary()?;
    eprintln!("[DEBUG] Starting sing-box client...");
    let singbox_process = Command::new(&singbox_path)
        .args(["run", "-c", singbox_config_path.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let _singbox_guard = ProcessGuard::new(singbox_process, "sing-box".to_string());
    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(2000)).await;

    // Test: DoH request to 1.1.1.1 directly (JSON format)
    eprintln!("[TEST] Testing DoH request to 1.1.1.1 (JSON format)");
    let doh_url = "https://1.1.1.1/dns-query?name=example.com&type=A";
    let output = common::curl::run_curl(
        doh_url,
        common::curl::CurlOptions::new()
            .proxy(format!("http://{}:{}", http_ip, http_port))
            .header("accept", "application/dns-json")
            .timeout(30),
    )
    .await?;

    eprintln!(
        "[TEST] DoH request completed with status: {:?}",
        output.status.code()
    );
    eprintln!("[TEST] Response body length: {} bytes", output.stdout.len());
    eprintln!(
        "[TEST] Response (first 200 chars): {}",
        String::from_utf8_lossy(&output.stdout[..std::cmp::min(200, output.stdout.len())])
    );

    if !output.status.success() {
        eprintln!("[TEST] stderr: {}", String::from_utf8_lossy(&output.stderr));
    }

    assert!(
        output.status.success(),
        "DoH request to 1.1.1.1 failed with exit code: {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify we got a JSON response
    let response_text = String::from_utf8_lossy(&output.stdout);
    assert!(
        response_text.contains("Answer") || response_text.contains("\"Status\""),
        "DoH response doesn't look like valid DNS JSON response: {}",
        response_text
    );

    eprintln!("[TEST] Successfully completed DoH request to 1.1.1.1 through VISION");

    Ok(())
}
