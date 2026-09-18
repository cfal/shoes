//! VLESS integration tests using sing-box as a peer.
use shoes_test_support as common;

// Import shared test infrastructure
use common::test_fixture::{ProxyTestFixture, TEST_UUID, start_shoes_server, start_singbox_server};

use std::path::Path;

#[tokio::test]
async fn test_shoes_vless_tls_vision_server() -> Result<(), Box<dyn std::error::Error>> {
    // Chain: curl -> sing-box HTTP proxy -> shoes VLESS+Vision server -> local HTTPS
    ProxyTestFixture::new()
        .with_singbox_vision_client()
        .with_shoes_vision_server()
        .test_local_https_tls13(1024)
        .await
}

#[tokio::test]
async fn test_shoes_vless_tls_vision_client() -> Result<(), Box<dyn std::error::Error>> {
    // Chain: curl -> shoes HTTP proxy (with Vision client) -> sing-box Vision server -> local HTTPS
    ProxyTestFixture::new()
        .with_shoes_vision_client()
        .with_singbox_vision_server()
        .test_local_https_tls13(1024)
        .await
}

#[tokio::test]
async fn test_shoes_vless_server() -> Result<(), Box<dyn std::error::Error>> {
    // Chain: curl -> sing-box HTTP proxy -> shoes VLESS server -> local hostname
    ProxyTestFixture::new()
        .with_singbox_vless_client()
        .with_shoes_vless_server()
        .test_local_http_hostname(1024)
        .await
}

#[tokio::test]
async fn test_shoes_vless_client() -> Result<(), Box<dyn std::error::Error>> {
    // Chain: curl -> shoes HTTP proxy (with VLESS client) -> sing-box VLESS server -> local hostname
    ProxyTestFixture::new()
        .with_shoes_vless_client()
        .with_singbox_vless_server()
        .test_local_http_hostname(1024)
        .await
}

#[tokio::test]
async fn test_shoes_vless_tls_server() -> Result<(), Box<dyn std::error::Error>> {
    // Chain: curl -> sing-box HTTP proxy -> shoes VLESS+TLS server -> local HTTPS
    ProxyTestFixture::new()
        .with_singbox_vless_tls_client()
        .with_shoes_vless_tls_server()
        .test_local_https_tls13(1024)
        .await
}

#[tokio::test]
async fn test_shoes_vless_tls_client() -> Result<(), Box<dyn std::error::Error>> {
    // Chain: curl -> shoes HTTP proxy (with VLESS+TLS client) -> sing-box VLESS+TLS server -> local HTTPS
    ProxyTestFixture::new()
        .with_shoes_vless_tls_client()
        .with_singbox_vless_tls_server()
        .test_local_https_tls13(1024)
        .await
}

#[tokio::test]
async fn test_shoes_vless_tls_vision_server_http_endpoint() -> Result<(), Box<dyn std::error::Error>>
{
    // Chain: curl -> sing-box HTTP proxy -> shoes VLESS+Vision server -> local HTTP server
    // Tests Vision End command with HTTP (non-TLS) endpoint
    // Uses local server that properly closes connections after response
    let fixture = ProxyTestFixture::new()
        .with_singbox_vision_client()
        .with_shoes_vision_server()
        .with_local_http_server()
        .build()
        .await?;

    // Test with a reasonably sized response (similar to www.example.com's ~1256 bytes)
    let body = fixture.test_local_server("/bytes/1256", false).await?;
    assert_eq!(body.len(), 1256, "Expected exactly 1256 bytes");
    Ok(())
}

#[tokio::test]
async fn test_shoes_vless_tls_vision_client_http_endpoint() -> Result<(), Box<dyn std::error::Error>>
{
    // Chain: curl -> shoes HTTP proxy (Vision client) -> sing-box Vision server -> local HTTP server
    // Tests Vision End command with HTTP (non-TLS) endpoint
    // Uses local server that properly closes connections after response
    let fixture = ProxyTestFixture::new()
        .with_shoes_vision_client()
        .with_singbox_vision_server()
        .with_local_http_server()
        .build()
        .await?;

    // Test with a reasonably sized response (similar to www.example.com's ~1256 bytes)
    let body = fixture.test_local_server("/bytes/1256", false).await?;
    assert_eq!(body.len(), 1256, "Expected exactly 1256 bytes");
    Ok(())
}

// Local Test Server Helpers

// Comprehensive VISION Tests with Local Test Servers

/// Test VISION with small data (1 byte) over local HTTP server
/// Tests End command behavior with minimal data transfer
#[tokio::test]
async fn test_shoes_vless_tls_vision_local_http_small() -> Result<(), Box<dyn std::error::Error>> {
    // Chain: curl -> sing-box HTTP proxy -> shoes Vision server -> local HTTP server
    // Tests Vision End command with small transfer (1 byte)
    let fixture = ProxyTestFixture::new()
        .with_singbox_vision_client()
        .with_shoes_vision_server()
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1", false).await?;
    assert_eq!(body.len(), 1, "Expected exactly 1 byte");
    Ok(())
}

/// Test VISION with large data (200KB) over local HTTP server
/// Tests End command behavior with substantial data transfer beyond 8 packet threshold
#[tokio::test]
async fn test_shoes_vless_tls_vision_local_http_large() -> Result<(), Box<dyn std::error::Error>> {
    // Chain: curl -> sing-box HTTP proxy -> shoes Vision server -> local HTTP server
    // Tests Vision End command with large transfer (200KB)
    let fixture = ProxyTestFixture::new()
        .with_singbox_vision_client()
        .with_shoes_vision_server()
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/200000", false).await?;
    assert_eq!(body.len(), 200000, "Expected exactly 200000 bytes");
    Ok(())
}

/// Test VISION with small data (1 byte) over local HTTPS/TLS 1.3 server
/// Tests Direct mode behavior with TLS 1.3
#[tokio::test]
async fn test_shoes_vless_tls_vision_local_https_tls13_small()
-> Result<(), Box<dyn std::error::Error>> {
    // Chain: curl -> sing-box HTTP proxy -> shoes Vision server -> local HTTPS/TLS1.3 server
    // Tests Vision Direct mode with small transfer (1 byte) over TLS 1.3
    let fixture = ProxyTestFixture::new()
        .with_singbox_vision_client()
        .with_shoes_vision_server()
        .with_local_https_tls13_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1", true).await?;
    assert_eq!(body.len(), 1, "Expected exactly 1 byte");
    Ok(())
}

/// Test VISION with large data (200KB) over local HTTPS/TLS 1.3 server
/// Tests Direct mode behavior with substantial data transfer
#[tokio::test]
async fn test_shoes_vless_tls_vision_local_https_tls13_large()
-> Result<(), Box<dyn std::error::Error>> {
    // Chain: curl -> sing-box HTTP proxy -> shoes Vision server -> local HTTPS/TLS1.3 server
    // Tests Vision Direct mode with large transfer (200KB) over TLS 1.3
    let fixture = ProxyTestFixture::new()
        .with_singbox_vision_client()
        .with_shoes_vision_server()
        .with_local_https_tls13_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/200000", true).await?;
    assert_eq!(body.len(), 200000, "Expected exactly 200000 bytes");
    Ok(())
}

/// Test VISION with small data (1 byte) over local HTTPS/TLS 1.2 server
/// Tests End mode behavior with TLS 1.2
#[tokio::test]
async fn test_shoes_vless_tls_vision_local_https_tls12_small()
-> Result<(), Box<dyn std::error::Error>> {
    // Chain: curl -> sing-box HTTP proxy -> shoes Vision server -> local HTTPS/TLS1.2 server
    // Tests Vision End mode with small transfer (1 byte) over TLS 1.2
    let fixture = ProxyTestFixture::new()
        .with_singbox_vision_client()
        .with_shoes_vision_server()
        .with_local_https_tls12_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1", true).await?;
    assert_eq!(body.len(), 1, "Expected exactly 1 byte");
    Ok(())
}

/// Test VISION with large data (200KB) over local HTTPS/TLS 1.2 server
/// Tests End mode behavior with substantial data transfer
#[tokio::test]
async fn test_shoes_vless_tls_vision_local_https_tls12_large()
-> Result<(), Box<dyn std::error::Error>> {
    // Chain: curl -> sing-box HTTP proxy -> shoes Vision server -> local HTTPS/TLS1.2 server
    // Tests Vision End mode with large transfer (200KB) over TLS 1.2
    let fixture = ProxyTestFixture::new()
        .with_singbox_vision_client()
        .with_shoes_vision_server()
        .with_local_https_tls12_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/200000", true).await?;
    assert_eq!(body.len(), 200000, "Expected exactly 200000 bytes");
    Ok(())
}

// POST Upload Tests - Testing Write Path

/// Test VISION with small HTTP POST upload (1KB) to local server
/// Tests write path with minimal data transfer
#[tokio::test]
async fn test_shoes_vless_tls_vision_small_http_upload() -> Result<(), Box<dyn std::error::Error>> {
    use common::curl::*;
    use common::test_servers::*;

    // Allocate random ports
    let mut port_helper = common::port_helper::PortHelper::new();
    let (vless_ip, vless_port) = port_helper.get_listener_port();
    let (http_ip, http_port) = port_helper.get_listener_port();
    let (local_http_ip, local_http_port) = port_helper.get_listener_port();
    eprintln!(
        "[TEST] Using ports: VLESS={}, HTTP={}, Local HTTP={}",
        vless_port, http_port, local_http_port
    );

    // Start local HTTP test server with POST support
    let _local_server = start_local_http_server(&local_http_ip, local_http_port).await?;

    // Generate test certificate
    let (cert_temp_path, key_temp_path) = generate_test_cert()?;

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
        AsRef::<Path>::as_ref(&cert_temp_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_temp_path).to_str().unwrap(),
        TEST_UUID
    );

    // sing-box HTTP proxy
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
        "server_name": "test.local",
        "insecure": true
      }}
    }}
  ],
  "route": {{
    "final": "vless-out"
  }}
}}"#,
        http_ip, http_port, vless_ip, vless_port, TEST_UUID
    );

    // Start servers
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;
    port_helper.wait_for_all_ports().await?;

    // Test small HTTP POST upload (1KB)
    eprintln!("[TEST] Testing small HTTP POST upload (1KB) via VISION");
    let upload_data = vec![b'Y'; 1024];
    let url = format!("http://{}:{}/echo", local_http_ip, local_http_port);

    let output = curl_post_via_proxy(
        &format!("http://{}:{}", http_ip, http_port),
        &url,
        upload_data.clone(),
    )
    .await?;

    assert!(
        output.status.success(),
        "curl failed with exit code: {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify echo response matches uploaded data
    assert_eq!(output.stdout.len(), 1024, "Expected 1024 bytes echoed back");
    assert_eq!(
        output.stdout, upload_data,
        "Echoed data doesn't match uploaded data"
    );

    eprintln!("[TEST] ✅ Successfully uploaded and echoed 1KB via VISION");
    Ok(())
}

/// Test VISION with large HTTP POST upload (200KB) to local server
/// Tests write path with substantial data transfer
#[tokio::test]
async fn test_shoes_vless_tls_vision_large_http_upload() -> Result<(), Box<dyn std::error::Error>> {
    use common::curl::*;
    use common::test_servers::*;

    // Allocate random ports
    let mut port_helper = common::port_helper::PortHelper::new();
    let (vless_ip, vless_port) = port_helper.get_listener_port();
    let (http_ip, http_port) = port_helper.get_listener_port();
    let (local_http_ip, local_http_port) = port_helper.get_listener_port();
    eprintln!(
        "[TEST] Using ports: VLESS={}, HTTP={}, Local HTTP={}",
        vless_port, http_port, local_http_port
    );

    // Start local HTTP test server with POST support
    let _local_server = start_local_http_server(&local_http_ip, local_http_port).await?;

    // Generate test certificate
    let (cert_temp_path, key_temp_path) = generate_test_cert()?;

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
        AsRef::<Path>::as_ref(&cert_temp_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_temp_path).to_str().unwrap(),
        TEST_UUID
    );

    // sing-box HTTP proxy
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
        "server_name": "test.local",
        "insecure": true
      }}
    }}
  ],
  "route": {{
    "final": "vless-out"
  }}
}}"#,
        http_ip, http_port, vless_ip, vless_port, TEST_UUID
    );

    // Start servers
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;
    port_helper.wait_for_all_ports().await?;

    // Test large HTTP POST upload (200KB) - exercises write path heavily
    eprintln!("[TEST] Testing large HTTP POST upload (200KB) via VISION");
    let upload_data = vec![b'Z'; 200_000];
    let url = format!("http://{}:{}/validate/90", local_http_ip, local_http_port); // 90 = 'Z'

    let output = curl_post_via_proxy(
        &format!("http://{}:{}", http_ip, http_port),
        &url,
        upload_data,
    )
    .await?;

    assert!(
        output.status.success(),
        "curl failed with exit code: {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    // Parse JSON response
    let response = String::from_utf8_lossy(&output.stdout);
    eprintln!("[TEST] Server response: {}", response);

    assert!(
        response.contains(r#""received": 200000"#),
        "Expected 200000 bytes received"
    );
    assert!(
        response.contains(r#""valid": true"#),
        "Expected validation to pass"
    );

    eprintln!("[TEST] ✅ Successfully uploaded and validated 200KB via VISION");
    Ok(())
}

/// Test VISION with small HTTPS/TLS 1.3 POST upload (1KB) to local server
/// Tests write path in Direct mode with TLS 1.3
#[tokio::test]
async fn test_shoes_vless_tls_vision_small_https_tls13_upload()
-> Result<(), Box<dyn std::error::Error>> {
    use common::curl::*;
    use common::test_servers::*;

    // Allocate random ports
    let mut port_helper = common::port_helper::PortHelper::new();
    let (vless_ip, vless_port) = port_helper.get_listener_port();
    let (http_ip, http_port) = port_helper.get_listener_port();
    let (local_https_ip, local_https_port) = port_helper.get_listener_port();
    eprintln!(
        "[TEST] Using ports: VLESS={}, HTTP={}, Local HTTPS={}",
        vless_port, http_port, local_https_port
    );

    // Generate certificates for both VLESS VISION and local HTTPS server
    let (vless_cert, vless_key) = generate_test_cert()?;
    let (local_cert, local_key) = generate_test_cert()?;

    // Start local HTTPS/TLS1.3 test server with POST support
    let _local_server = start_local_https_server(
        &local_https_ip,
        local_https_port,
        AsRef::<Path>::as_ref(&local_cert),
        AsRef::<Path>::as_ref(&local_key),
        TlsVersion::Tls13Only,
    )
    .await?;

    // Generate test certificate
    let (cert_temp_path, key_temp_path) = (vless_cert, vless_key);

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
        AsRef::<Path>::as_ref(&cert_temp_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_temp_path).to_str().unwrap(),
        TEST_UUID
    );

    // sing-box HTTP proxy
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
        "server_name": "test.local",
        "insecure": true
      }}
    }}
  ],
  "route": {{
    "final": "vless-out"
  }}
}}"#,
        http_ip, http_port, vless_ip, vless_port, TEST_UUID
    );

    // Start servers
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;
    port_helper.wait_for_all_ports().await?;

    // Test small HTTPS POST upload (1KB)
    eprintln!("[TEST] Testing small HTTPS/TLS1.3 POST upload (1KB) via VISION");
    let upload_data = vec![b'A'; 1024];
    let url = format!("https://{}:{}/echo", local_https_ip, local_https_port);

    let output = curl_post_https_via_proxy(
        &format!("http://{}:{}", http_ip, http_port),
        &url,
        upload_data.clone(),
    )
    .await?;

    assert!(
        output.status.success(),
        "curl failed with exit code: {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify echo response matches uploaded data
    assert_eq!(output.stdout.len(), 1024, "Expected 1024 bytes echoed back");
    assert_eq!(
        output.stdout, upload_data,
        "Echoed data doesn't match uploaded data"
    );

    eprintln!("[TEST] ✅ Successfully uploaded and echoed 1KB via VISION HTTPS/TLS1.3");
    Ok(())
}

/// Test VISION with large HTTPS/TLS 1.3 POST upload (200KB) to local server
/// Tests write path in Direct mode with substantial data transfer
#[tokio::test]
async fn test_shoes_vless_tls_vision_large_https_tls13_upload()
-> Result<(), Box<dyn std::error::Error>> {
    use common::curl::*;
    use common::test_servers::*;

    // Allocate random ports
    let mut port_helper = common::port_helper::PortHelper::new();
    let (vless_ip, vless_port) = port_helper.get_listener_port();
    let (http_ip, http_port) = port_helper.get_listener_port();
    let (local_https_ip, local_https_port) = port_helper.get_listener_port();
    eprintln!(
        "[TEST] Using ports: VLESS={}, HTTP={}, Local HTTPS={}",
        vless_port, http_port, local_https_port
    );

    // Generate certificates for both VLESS VISION and local HTTPS server
    let (vless_cert, vless_key) = generate_test_cert()?;
    let (local_cert, local_key) = generate_test_cert()?;

    // Start local HTTPS/TLS1.3 test server with POST support
    let _local_server = start_local_https_server(
        &local_https_ip,
        local_https_port,
        AsRef::<Path>::as_ref(&local_cert),
        AsRef::<Path>::as_ref(&local_key),
        TlsVersion::Tls13Only,
    )
    .await?;

    // Generate test certificate
    let (cert_temp_path, key_temp_path) = (vless_cert, vless_key);

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
        AsRef::<Path>::as_ref(&cert_temp_path).to_str().unwrap(),
        AsRef::<Path>::as_ref(&key_temp_path).to_str().unwrap(),
        TEST_UUID
    );

    // sing-box HTTP proxy
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
        "server_name": "test.local",
        "insecure": true
      }}
    }}
  ],
  "route": {{
    "final": "vless-out"
  }}
}}"#,
        http_ip, http_port, vless_ip, vless_port, TEST_UUID
    );

    // Start servers
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;
    port_helper.wait_for_all_ports().await?;

    // Test large HTTPS POST upload (200KB) - heavily exercises optimized write path
    eprintln!("[TEST] Testing large HTTPS/TLS1.3 POST upload (200KB) via VISION");
    let upload_data = vec![b'B'; 200_000];
    let url = format!(
        "https://{}:{}/validate/66",
        local_https_ip, local_https_port
    ); // 66 = 'B'

    let output = curl_post_https_via_proxy(
        &format!("http://{}:{}", http_ip, http_port),
        &url,
        upload_data,
    )
    .await?;

    assert!(
        output.status.success(),
        "curl failed with exit code: {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    // Parse JSON response
    let response = String::from_utf8_lossy(&output.stdout);
    eprintln!("[TEST] Server response: {}", response);

    assert!(
        response.contains(r#""received": 200000"#),
        "Expected 200000 bytes received"
    );
    assert!(
        response.contains(r#""valid": true"#),
        "Expected validation to pass"
    );

    eprintln!("[TEST] ✅ Successfully uploaded and validated 200KB via VISION HTTPS/TLS1.3");
    Ok(())
}

// VLESS Vision Proxy Chaining Test

/// Test Vision with proxy chaining to verify Direct mode activation
///
/// Architecture:
/// sing-box HTTP client
///   -> shoes VLESS+Vision server #1 (intermediate proxy)
///      -> shoes VLESS server #2 (non-Vision)
///         -> local HTTPS/TLS1.3 server
///
/// This test verifies that Vision correctly handles the scenario where:
/// 1. Client connects through Vision VLESS to an intermediate proxy
/// 2. Intermediate proxy connects to a non-Vision VLESS server
/// 3. Final target is an HTTPS server
///
/// Expected behavior: Vision should detect the inner TLS handshake (client → target)
/// and switch to Direct mode for optimal performance.
#[tokio::test]
async fn test_shoes_vless_tls_vision_proxy_chain_to_https() -> Result<(), Box<dyn std::error::Error>>
{
    use common::test_servers::*;

    // Allocate random ports
    let mut port_helper = common::port_helper::PortHelper::new();
    let (vision_vless_ip, vision_vless_port) = port_helper.get_listener_port();
    let (non_vision_vless_ip, non_vision_vless_port) = port_helper.get_listener_port();
    let (http_proxy_ip, http_proxy_port) = port_helper.get_listener_port();
    let (local_https_ip, local_https_port) = port_helper.get_listener_port();

    eprintln!(
        "[TEST] Using ports: Vision VLESS={}, Non-Vision VLESS={}, HTTP Proxy={}, Local HTTPS={}",
        vision_vless_port, non_vision_vless_port, http_proxy_port, local_https_port
    );

    // Generate certificates
    let (vision_cert, vision_key) = generate_test_cert()?;
    let (https_cert, https_key) = generate_test_cert()?;

    // Start local HTTPS/TLS1.3 test server (final destination)
    let _local_server = start_local_https_server(
        &local_https_ip,
        local_https_port,
        AsRef::<Path>::as_ref(&https_cert),
        AsRef::<Path>::as_ref(&https_key),
        TlsVersion::Tls13Only,
    )
    .await?;

    // shoes config with TWO VLESS servers:
    // 1. Vision VLESS server (intermediate proxy) - this has a client_proxy to #2
    // 2. Non-Vision VLESS server (routes to local HTTPS)
    let shoes_config = format!(
        r#"
# Non-Vision VLESS server that proxies to the local HTTPS server
- address: "{}:{}"
  protocol:
    type: vless
    user_id: "{}"

# Vision VLESS server (intermediate proxy) with client_proxy to non-Vision VLESS
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
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_proxies:
        - address: "{}:{}"
          protocol:
            type: vless
            user_id: "{}"
"#,
        non_vision_vless_ip,
        non_vision_vless_port,
        TEST_UUID,
        vision_vless_ip,
        vision_vless_port,
        AsRef::<Path>::as_ref(&vision_cert).to_str().unwrap(),
        AsRef::<Path>::as_ref(&vision_key).to_str().unwrap(),
        TEST_UUID,
        non_vision_vless_ip,
        non_vision_vless_port,
        TEST_UUID
    );

    // sing-box HTTP proxy that connects to shoes Vision VLESS #1
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
        "server_name": "test.local",
        "insecure": true
      }}
    }}
  ],
  "route": {{
    "final": "vless-out"
  }}
}}"#,
        http_proxy_ip, http_proxy_port, vision_vless_ip, vision_vless_port, TEST_UUID
    );

    // Start servers
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;
    port_helper.wait_for_all_ports().await?;

    // Test HTTPS request through the proxy chain
    eprintln!("[TEST] Testing HTTPS/TLS1.3 request through Vision proxy chain");
    eprintln!(
        "[TEST] Flow: sing-box → shoes Vision VLESS → shoes non-Vision VLESS → local HTTPS server"
    );
    eprintln!("[TEST] Expected: Vision should detect inner TLS and switch to Direct mode");

    let url = format!("https://{}:{}/bytes/1000", local_https_ip, local_https_port);
    let output = common::curl::run_curl(
        &url,
        common::curl::CurlOptions::new()
            .proxy(format!("http://{}:{}", http_proxy_ip, http_proxy_port))
            .insecure(true)
            .timeout(30),
    )
    .await?;

    assert!(
        output.status.success(),
        "curl failed with exit code: {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let body_len = output.stdout.len();
    eprintln!(
        "[TEST] ✅ Successfully transferred {} bytes via Vision proxy chain",
        body_len
    );
    assert_eq!(body_len, 1000, "Expected exactly 1000 bytes");

    eprintln!("[TEST] Check the logs above to verify if Vision switched to Direct mode");
    eprintln!(
        "[TEST] Look for: 'VISION WRITE: Detected ApplicationData' and 'Switching to direct copy mode'"
    );

    Ok(())
}

/// Test Vision behavior when sing-box uses detour to chain multiple VLESS outbounds
///
/// Architecture:
/// sing-box HTTP client
///   -> sing-box vless-outer (Vision flow)
///      -> sing-box vless-inner (detour target, initiates inner TLS)
///         -> shoes Vision VLESS server
///            -> shoes non-Vision VLESS client
///               -> local HTTPS/TLS1.3 server
///
/// This test demonstrates an important architectural limitation:
/// 1. sing-box's vless-outer has Vision flow and connects to shoes Vision server
/// 2. sing-box's vless-inner is the detour target that makes the actual HTTPS connection
/// 3. The inner TLS handshake (vless-inner → HTTPS) is wrapped in VLESS protocol
/// 4. shoes Vision server never sees the raw inner TLS records
///
/// Expected behavior: Vision will NOT switch to Direct mode in this configuration.
/// - sing-box's Vision client filters the outer TLS layer (sing-box ↔ shoes)
/// - The inner TLS (to HTTPS server) is encapsulated inside VLESS protocol
/// - shoes Vision server only sees VLESS protocol data, not raw inner TLS
/// - After sing-box's filter count expires, it sends END command → TLS mode
///
/// This is correct behavior! Vision is designed to detect TLS at the layer it operates on,
/// not to unwrap nested protocols. For Direct mode with proxy chaining, the proxy server
/// itself must initiate the inner TLS connection (see test_shoes_vless_vision_proxy_chain_to_https).
#[tokio::test]
async fn test_shoes_vless_tls_vision_server_with_singbox_detour_chain()
-> Result<(), Box<dyn std::error::Error>> {
    use common::test_servers::*;

    // Allocate random ports
    let mut port_helper = common::port_helper::PortHelper::new();
    let (vision_vless_ip, vision_vless_port) = port_helper.get_listener_port();
    let (non_vision_vless_ip, non_vision_vless_port) = port_helper.get_listener_port();
    let (http_proxy_ip, http_proxy_port) = port_helper.get_listener_port();
    let (local_https_ip, local_https_port) = port_helper.get_listener_port();

    eprintln!(
        "[TEST] Using ports: Vision VLESS={}, Non-Vision VLESS={}, HTTP Proxy={}, Local HTTPS={}",
        vision_vless_port, non_vision_vless_port, http_proxy_port, local_https_port
    );

    // Generate certificates
    let (vision_cert, vision_key) = generate_test_cert()?;
    let (https_cert, https_key) = generate_test_cert()?;

    // Start local HTTPS/TLS1.3 test server (final destination)
    let _local_server = start_local_https_server(
        &local_https_ip,
        local_https_port,
        AsRef::<Path>::as_ref(&https_cert),
        AsRef::<Path>::as_ref(&https_key),
        TlsVersion::Tls13Only,
    )
    .await?;

    // shoes config with TWO servers:
    // 1. Non-Vision VLESS server - intermediate proxy to target
    // 2. Vision VLESS server - entry point from sing-box
    let shoes_config = format!(
        r#"
# Non-Vision VLESS server (intermediate) - proxies to target
- address: "{}:{}"
  protocol:
    type: vless
    user_id: "{}"

# Vision VLESS server - entry point from sing-box
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
        non_vision_vless_ip,
        non_vision_vless_port,
        TEST_UUID,
        vision_vless_ip,
        vision_vless_port,
        AsRef::<Path>::as_ref(&vision_cert).to_str().unwrap(),
        AsRef::<Path>::as_ref(&vision_key).to_str().unwrap(),
        TEST_UUID
    );

    // sing-box config with detour-based chaining:
    // - HTTP inbound
    // - vless-inner: Non-Vision VLESS to shoes non-Vision server, with detour to vless-outer
    // - vless-outer: Vision VLESS+TLS to shoes Vision server
    // - Route final goes to vless-inner
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
      "tag": "vless-inner",
      "server": "{}",
      "server_port": {},
      "uuid": "{}",
      "detour": "vless-outer"
    }},
    {{
      "type": "vless",
      "tag": "vless-outer",
      "server": "{}",
      "server_port": {},
      "uuid": "{}",
      "flow": "xtls-rprx-vision",
      "tls": {{
        "enabled": true,
        "server_name": "test.local",
        "insecure": true
      }}
    }}
  ],
  "route": {{
    "final": "vless-inner"
  }}
}}"#,
        http_proxy_ip,
        http_proxy_port,
        non_vision_vless_ip,
        non_vision_vless_port,
        TEST_UUID,
        vision_vless_ip,
        vision_vless_port,
        TEST_UUID
    );

    // Start servers
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;
    port_helper.wait_for_all_ports().await?;

    // Test HTTPS request through the proxy chain
    eprintln!("[TEST] Testing HTTPS/TLS1.3 request through sing-box detour chain");
    eprintln!(
        "[TEST] Flow: HTTP client → sing-box Vision VLESS (detour) → sing-box non-Vision VLESS → shoes Vision VLESS → local HTTPS server"
    );
    eprintln!("[TEST] Expected: Vision should detect inner TLS and switch to Direct mode");

    let url = format!("https://{}:{}/bytes/1000", local_https_ip, local_https_port);
    let output = common::curl::run_curl(
        &url,
        common::curl::CurlOptions::new()
            .proxy(format!("http://{}:{}", http_proxy_ip, http_proxy_port))
            .insecure(true)
            .timeout(30),
    )
    .await?;

    assert!(
        output.status.success(),
        "curl failed with exit code: {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let body_len = output.stdout.len();
    eprintln!(
        "[TEST] ✅ Successfully transferred {} bytes via sing-box detour chain",
        body_len
    );
    assert_eq!(body_len, 1000, "Expected exactly 1000 bytes");

    eprintln!("[TEST] Check the logs above to verify if Vision switched to Direct mode");
    eprintln!(
        "[TEST] Look for: 'VISION WRITE: Detected ApplicationData' and 'Switching to direct copy mode'"
    );

    Ok(())
}

/// Test VISION server with HTTP proxy detour chain
/// Tests FuzzyTlsDeframer's ability to skip HTTP CONNECT headers before TLS data
///
/// This test creates a proxy chain with an HTTP proxy as the intermediate:
/// curl → sing-box (Vision VLESS) → shoes (Vision VLESS) → shoes (HTTP proxy) → target HTTPS server
///
/// The inner TLS handshake (client hello to target) gets prefixed with HTTP CONNECT headers
/// when it passes through the HTTP proxy. FuzzyTlsDeframer should detect and skip these headers.
#[tokio::test]
async fn test_shoes_vless_tls_vision_server_with_http_detour_chain()
-> Result<(), Box<dyn std::error::Error>> {
    use common::test_servers::*;

    // Allocate random ports
    let mut port_helper = common::port_helper::PortHelper::new();
    let (vision_vless_ip, vision_vless_port) = port_helper.get_listener_port();
    let (http_proxy_ip, http_proxy_port) = port_helper.get_listener_port();
    let (singbox_http_ip, singbox_http_port) = port_helper.get_listener_port();
    let (local_https_ip, local_https_port) = port_helper.get_listener_port();

    eprintln!(
        "[TEST] Using ports: Vision VLESS={}, HTTP Proxy={}, sing-box HTTP={}, Local HTTPS={}",
        vision_vless_port, http_proxy_port, singbox_http_port, local_https_port
    );

    // Generate certificates
    let (vision_cert, vision_key) = generate_test_cert()?;
    let (https_cert, https_key) = generate_test_cert()?;

    // Start local HTTPS/TLS1.3 test server (final destination)
    let _local_server = start_local_https_server(
        &local_https_ip,
        local_https_port,
        AsRef::<Path>::as_ref(&https_cert),
        AsRef::<Path>::as_ref(&https_key),
        TlsVersion::Tls13Only,
    )
    .await?;

    // shoes config with TWO servers:
    // 1. HTTP proxy server - intermediate proxy to target
    // 2. Vision VLESS server - entry point from sing-box
    let shoes_config = format!(
        r#"
# HTTP proxy server (intermediate) - proxies to target
- address: "{}:{}"
  protocol:
    type: http

# Vision VLESS server - entry point from sing-box
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
        http_proxy_ip,
        http_proxy_port,
        vision_vless_ip,
        vision_vless_port,
        AsRef::<Path>::as_ref(&vision_cert).to_str().unwrap(),
        AsRef::<Path>::as_ref(&vision_key).to_str().unwrap(),
        TEST_UUID
    );

    // sing-box config with HTTP proxy detour:
    // - HTTP inbound
    // - http-inner: HTTP proxy to shoes HTTP server, with detour to vless-outer
    // - vless-outer: Vision VLESS+TLS to shoes Vision server
    // - Route final goes to http-inner
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
      "type": "http",
      "tag": "http-inner",
      "server": "{}",
      "server_port": {},
      "detour": "vless-outer"
    }},
    {{
      "type": "vless",
      "tag": "vless-outer",
      "server": "{}",
      "server_port": {},
      "uuid": "{}",
      "flow": "xtls-rprx-vision",
      "tls": {{
        "enabled": true,
        "server_name": "test.local",
        "insecure": true
      }}
    }}
  ],
  "route": {{
    "final": "http-inner"
  }}
}}"#,
        singbox_http_ip,
        singbox_http_port,
        http_proxy_ip,
        http_proxy_port,
        vision_vless_ip,
        vision_vless_port,
        TEST_UUID
    );

    // Start servers
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    let (_singbox_guard, _singbox_config_file) = start_singbox_server(&singbox_config)?;
    port_helper.wait_for_all_ports().await?;

    // Test HTTPS request through the proxy chain
    eprintln!("[TEST] Testing HTTPS/TLS1.3 request through HTTP proxy detour chain");
    eprintln!(
        "[TEST] Flow: curl → sing-box HTTP → sing-box Vision VLESS (detour) → shoes Vision VLESS → shoes HTTP proxy → local HTTPS server"
    );
    eprintln!("[TEST] Expected: FuzzyTlsDeframer should skip HTTP CONNECT headers before TLS data");

    let url = format!("https://{}:{}/bytes/1000", local_https_ip, local_https_port);
    let output = common::curl::run_curl(
        &url,
        common::curl::CurlOptions::new()
            .proxy(format!("http://{}:{}", singbox_http_ip, singbox_http_port))
            .insecure(true)
            .timeout(30),
    )
    .await?;

    assert!(
        output.status.success(),
        "curl failed with exit code: {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let body_len = output.stdout.len();
    eprintln!(
        "[TEST] ✅ Successfully transferred {} bytes via HTTP proxy detour chain",
        body_len
    );
    assert_eq!(body_len, 1000, "Expected exactly 1000 bytes");

    eprintln!("[TEST] Check the logs above to verify:");
    eprintln!("[TEST] - FuzzyTlsDeframer found and skipped prefix (HTTP CONNECT headers)");
    eprintln!("[TEST] - Vision detected inner TLS and switched to Direct mode");
    eprintln!("[TEST] Look for: 'FuzzyTlsDeframer: Found TLS pattern after N byte prefix'");

    Ok(())
}

/// Test shoes VLESS+Vision client connecting to shoes VLESS+Vision server
/// This tests the complete shoes-to-shoes Vision implementation without sing-box
///
/// Flow: curl → shoes HTTP proxy (with Vision client) → shoes Vision server → internet
#[tokio::test]
async fn test_shoes_tls_vision_client_to_shoes_tls_vision_server()
-> Result<(), Box<dyn std::error::Error>> {
    eprintln!("[TEST] Testing shoes Vision client → shoes Vision server");
    eprintln!("[TEST] This validates the complete shoes Vision implementation");

    ProxyTestFixture::new()
        .with_shoes_vision_client() // Entry: HTTP proxy that routes through Vision client
        .with_shoes_vision_server() // Exit: Vision server
        .test_local_https_tls13(1024)
        .await
}
