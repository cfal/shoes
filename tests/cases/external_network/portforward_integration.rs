/// Integration tests for portforward protocol with TLS client connections
///
/// This specifically tests the TLS client handler's ability to handle both TLS 1.2 and 1.3
use shoes_test_support as common;

use common::test_fixture::start_shoes_server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Test portforward handshake completion through a TLS 1.2 connection to httpbin.org:443
#[tokio::test]
async fn test_portforward_through_tls12_httpbin() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (ip, port) = port_helper.get_listener_port();
    let config = format!(
        r#"- address: {}:{}
  protocol:
    type: portforward
    target: 192.0.2.1:80
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_proxy:
        address: httpbin.org:443
        protocol:
          type: tls
          verify: true
          protocol:
            type: portforward
"#,
        ip, port
    );

    let (_guard, _config_file) = start_shoes_server(&config)?;
    port_helper.wait_for_all_ports().await?;

    // Connect to the shoes portforward server
    let mut stream = TcpStream::connect(format!("{}:{}", ip, port)).await?;

    // Send a simple HTTP request through the TLS tunnel
    eprintln!("[TEST] Sending HTTP request to httpbin.org...");
    stream
        .write_all(b"GET /get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
        .await?;
    eprintln!("[TEST] Request sent, waiting for response...");

    // Read response - if the TLS handshake hung, this will timeout
    let mut buf = vec![0u8; 4096];
    let n =
        tokio::time::timeout(std::time::Duration::from_secs(10), stream.read(&mut buf)).await??;

    eprintln!("[TEST] Received {} bytes", n);

    // We should get some response
    assert!(
        n > 0,
        "Expected response from httpbin.org through TLS 1.2 connection"
    );

    // Check for HTTP response
    let response = String::from_utf8_lossy(&buf[..n]);
    eprintln!(
        "[TEST] Response preview: {}",
        &response[..std::cmp::min(200, response.len())]
    );
    assert!(
        response.contains("HTTP/") && (response.contains("200") || response.contains("httpbin")),
        "Expected valid HTTP response, got: {}",
        &response[..std::cmp::min(500, response.len())]
    );

    Ok(())
}

/// Test portforward through plain TCP connection (control test)
#[tokio::test]
async fn test_portforward_through_plain_tcp_google() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (ip, port) = port_helper.get_listener_port();
    let config = format!(
        r#"- address: {}:{}
  protocol:
    type: portforward
    target: 192.0.2.1:80
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_proxy:
        address: google.com:80
        protocol:
          type: portforward
"#,
        ip, port
    );

    let (_guard, _config_file) = start_shoes_server(&config)?;
    port_helper.wait_for_all_ports().await?;

    // Connect to the shoes portforward server
    let mut stream = TcpStream::connect(format!("{}:{}", ip, port)).await?;

    // Send a simple HTTP request
    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: google.com\r\n\r\n")
        .await?;

    // Read response
    let mut buf = vec![0u8; 1024];
    let n =
        tokio::time::timeout(std::time::Duration::from_secs(10), stream.read(&mut buf)).await??;

    // We should get some response
    assert!(n > 0, "Expected response from google.com through plain TCP");

    // Check for HTTP response
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("HTTP/") || response.contains("html") || response.contains("google"),
        "Expected valid HTTP response, got: {}",
        response
    );

    Ok(())
}

/// Test portforward through TLS 1.3 connection to cloudflare.com:443
/// Cloudflare supports TLS 1.3 and will negotiate it
#[tokio::test]
async fn test_portforward_through_tls13_cloudflare() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (ip, port) = port_helper.get_listener_port();
    let config = format!(
        r#"- address: {}:{}
  protocol:
    type: portforward
    target: 192.0.2.1:80
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_proxy:
        address: cloudflare.com:443
        protocol:
          type: tls
          verify: true
          protocol:
            type: portforward
"#,
        ip, port
    );

    let (_guard, _config_file) = start_shoes_server(&config)?;
    port_helper.wait_for_all_ports().await?;

    // Connect to the shoes portforward server
    let mut stream = TcpStream::connect(format!("{}:{}", ip, port)).await?;

    // Send a simple HTTP request through the TLS tunnel
    eprintln!("[TEST] Sending HTTP request to cloudflare.com...");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: cloudflare.com\r\nConnection: close\r\n\r\n")
        .await?;
    eprintln!("[TEST] Request sent, waiting for response...");

    // Read response
    let mut buf = vec![0u8; 4096];
    let n =
        tokio::time::timeout(std::time::Duration::from_secs(10), stream.read(&mut buf)).await??;

    eprintln!("[TEST] Received {} bytes", n);

    // We should get some response
    assert!(
        n > 0,
        "Expected response from cloudflare.com through TLS 1.3 connection"
    );

    // Check for HTTP response
    let response = String::from_utf8_lossy(&buf[..n]);
    eprintln!(
        "[TEST] Response preview: {}",
        &response[..std::cmp::min(200, response.len())]
    );
    assert!(
        response.contains("HTTP/")
            && (response.contains("cloudflare")
                || response.contains("200")
                || response.contains("301")),
        "Expected valid HTTP response, got: {}",
        &response[..std::cmp::min(500, response.len())]
    );

    Ok(())
}
