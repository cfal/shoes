/// Integration tests for VLESS VISION with DNS over TLS (DoT) requests
///
/// This test file specifically tests DoT requests to Cloudflare DNS (1.1.1.1:853)
/// to verify that VLESS VISION properly handles TLS-in-TLS connections.
///
/// DoT characteristics that make it a good test case:
/// - Uses port 853 (not 443)
/// - Binary DNS protocol over TLS
/// - Small request/response sizes
/// - Real-world use case for VISION protocol
///
/// Test Architecture:
/// ==================
/// Test client (raw TCP + TLS)
///   -> sing-box SOCKS5 proxy
///      -> shoes VLESS+VISION Server
///         -> Cloudflare DNS (1.1.1.1:853)
use shoes_test_support as common;

use common::test_fixture::{ProcessGuard, find_singbox_binary};

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;

const TEST_UUID: &str = "b85798ef-e9dc-46a4-9a87-8da4499d36d0";

/// Create a DNS query for example.com A record in wire format
/// Returns the query packet (without length prefix)
fn create_dns_query() -> Vec<u8> {
    let mut query = Vec::new();

    // DNS Header (12 bytes)
    query.extend_from_slice(&[
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags: standard query, recursion desired
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
    ]);

    // Question: example.com
    query.push(7); // Length of "example"
    query.extend_from_slice(b"example");
    query.push(3); // Length of "com"
    query.extend_from_slice(b"com");
    query.push(0); // End of name

    // Type A (1) and Class IN (1)
    query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

    query
}

/// Parse DNS response and extract answer count and first A record if present
fn parse_dns_response(response: &[u8]) -> Result<(u16, Option<std::net::Ipv4Addr>), String> {
    if response.len() < 12 {
        return Err(format!("Response too short: {} bytes", response.len()));
    }

    // Parse header
    let answer_count = u16::from_be_bytes([response[6], response[7]]);

    eprintln!("[DNS] Response has {} answers", answer_count);

    // For simplicity, just check if we got answers
    // A full parser would need to skip the question section and parse answers
    if answer_count > 0 {
        // Try to find an IP address pattern in the response (4 bytes that look like an IP)
        // This is a simplified parser - a real one would properly parse the answer section
        for i in 12..response.len().saturating_sub(4) {
            // Look for A record type (0x00 0x01) followed by IN class (0x00 0x01)
            if i > 0
                && i + 10 < response.len()
                && response[i] == 0x00
                && response[i + 1] == 0x01
                && response[i + 2] == 0x00
                && response[i + 3] == 0x01
            {
                // Skip TTL (4 bytes) and check data length
                let data_len = u16::from_be_bytes([response[i + 8], response[i + 9]]);
                if data_len == 4 && i + 10 + 4 <= response.len() {
                    let ip = std::net::Ipv4Addr::new(
                        response[i + 10],
                        response[i + 11],
                        response[i + 12],
                        response[i + 13],
                    );
                    return Ok((answer_count, Some(ip)));
                }
            }
        }
        Ok((answer_count, None))
    } else {
        Ok((0, None))
    }
}

/// Connect to target through SOCKS5 proxy
async fn socks5_connect(
    proxy_addr: &str,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, Box<dyn std::error::Error>> {
    eprintln!("[SOCKS5] Connecting to proxy at {}", proxy_addr);
    let mut stream = TcpStream::connect(proxy_addr).await?;

    // SOCKS5 greeting
    stream.write_all(&[0x05, 0x01, 0x00]).await?; // Version 5, 1 method, no auth

    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;

    if response[0] != 0x05 || response[1] != 0x00 {
        return Err(format!("SOCKS5 greeting failed: {:?}", response).into());
    }

    eprintln!("[SOCKS5] Greeting successful, sending connect request");

    // SOCKS5 connect request
    let mut request = vec![0x05, 0x01, 0x00]; // Version, CONNECT, reserved

    // Address type: domain name
    request.push(0x03);
    request.push(target_host.len() as u8);
    request.extend_from_slice(target_host.as_bytes());
    request.extend_from_slice(&target_port.to_be_bytes());

    stream.write_all(&request).await?;

    // Read response
    let mut response = vec![0u8; 4];
    stream.read_exact(&mut response).await?;

    if response[1] != 0x00 {
        return Err(format!("SOCKS5 connect failed with code: {}", response[1]).into());
    }

    // Read remaining address and port (varying length)
    match response[3] {
        0x01 => {
            // IPv4
            let mut addr = [0u8; 6];
            stream.read_exact(&mut addr).await?;
        }
        0x03 => {
            // Domain
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut addr = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut addr).await?;
        }
        0x04 => {
            // IPv6
            let mut addr = [0u8; 18];
            stream.read_exact(&mut addr).await?;
        }
        _ => return Err("Unknown address type in SOCKS5 response".into()),
    }

    eprintln!("[SOCKS5] Connected to {}:{}", target_host, target_port);
    Ok(stream)
}

/// Test DNS over TLS to 1.1.1.1:853 directly (no proxy) to validate test code
#[tokio::test]
async fn test_dot_direct_no_proxy() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("[TEST] Testing DNS over TLS to 1.1.1.1:853 (direct connection, no proxy)");

    // Connect directly to 1.1.1.1:853
    let tcp_stream = TcpStream::connect("1.1.1.1:853").await?;
    eprintln!("[TEST] TCP connection established to 1.1.1.1:853");

    // Wrap in TLS with system root certificates
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    ));

    let domain = rustls::pki_types::ServerName::try_from("cloudflare-dns.com")
        .map_err(|_| "Invalid DNS name")?
        .to_owned();

    eprintln!("[TEST] Starting TLS handshake...");
    let mut tls_stream = connector.connect(domain, tcp_stream).await?;
    eprintln!("[TEST] TLS handshake completed!");

    // Create and send DNS query
    let query = create_dns_query();
    eprintln!("[DNS] Sending query ({} bytes)", query.len());

    // DNS over TLS uses 2-byte length prefix
    let len_prefix = (query.len() as u16).to_be_bytes();
    tls_stream.write_all(&len_prefix).await?;
    tls_stream.write_all(&query).await?;
    tls_stream.flush().await?;

    eprintln!("[DNS] Query sent, waiting for response");

    // Read response length
    let mut len_buf = [0u8; 2];
    tls_stream.read_exact(&mut len_buf).await?;
    let response_len = u16::from_be_bytes(len_buf) as usize;

    eprintln!("[DNS] Response length: {} bytes", response_len);

    // Read response
    let mut response = vec![0u8; response_len];
    tls_stream.read_exact(&mut response).await?;

    eprintln!("[DNS] Received response ({} bytes)", response.len());

    // Parse response
    let (answer_count, ip) = parse_dns_response(&response)?;

    assert!(answer_count > 0, "DNS response has no answers");

    if let Some(ip) = ip {
        eprintln!("[DNS] Resolved example.com to {}", ip);
    } else {
        eprintln!("[DNS] Got {} answers but couldn't parse IP", answer_count);
    }

    eprintln!("[TEST] Successfully completed DNS over TLS request (direct, no proxy)");

    Ok(())
}

/// Test DNS over TLS to 1.1.1.1:853 through VISION
#[tokio::test]
async fn test_shoes_vless_vision_dot_cloudflare() -> Result<(), Box<dyn std::error::Error>> {
    use common::test_servers::*;

    // Allocate random ports
    let mut port_helper = common::port_helper::PortHelper::new();
    let (vless_ip, vless_port) = port_helper.get_listener_port();
    let (socks_ip, socks_port) = port_helper.get_listener_port();
    eprintln!(
        "[TEST] Using ports: VLESS={}, SOCKS5={}",
        vless_port, socks_port
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

    let shoes_config_path = std::env::temp_dir().join("shoes_vision_dot_test.yaml");
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

    // sing-box client configuration with SOCKS5 inbound through VLESS+VISION
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
  ],
    "route": {{
      "final": "vless-out"
    }}
}}"#,
        socks_ip, socks_port, vless_ip, vless_port, TEST_UUID
    );

    let singbox_config_path = std::env::temp_dir().join("singbox_vision_dot_test.json");
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

    // Test: DNS over TLS to 1.1.1.1:853
    eprintln!("[TEST] Testing DNS over TLS to 1.1.1.1:853");

    // Connect through SOCKS5 proxy
    let tcp_stream =
        socks5_connect(&format!("{}:{}", socks_ip, socks_port), "1.1.1.1", 853).await?;

    eprintln!("[TEST] Attempting TLS handshake to 1.1.1.1:853...");

    // Wrap in TLS with system root certificates
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    ));

    let domain = rustls::pki_types::ServerName::try_from("cloudflare-dns.com")
        .map_err(|_| "Invalid DNS name")?
        .to_owned();

    let tls_result = tokio::time::timeout(
        Duration::from_secs(30),
        connector.connect(domain, tcp_stream),
    )
    .await;

    let mut tls_stream = match tls_result {
        Ok(Ok(stream)) => {
            eprintln!("[TEST] TLS handshake completed successfully!");
            stream
        }
        Ok(Err(e)) => {
            return Err(format!("TLS handshake failed: {}", e).into());
        }
        Err(_) => {
            return Err("TLS handshake timed out after 30 seconds".into());
        }
    };

    eprintln!("[TEST] TLS connection established, sending DNS query");

    // Create and send DNS query
    let query = create_dns_query();
    eprintln!("[DNS] Sending query ({} bytes)", query.len());

    // DNS over TLS uses 2-byte length prefix
    let len_prefix = (query.len() as u16).to_be_bytes();
    tls_stream.write_all(&len_prefix).await?;
    tls_stream.write_all(&query).await?;
    tls_stream.flush().await?;

    eprintln!("[DNS] Query sent, waiting for response");

    // Read response length
    let mut len_buf = [0u8; 2];
    tls_stream.read_exact(&mut len_buf).await?;
    let response_len = u16::from_be_bytes(len_buf) as usize;

    eprintln!("[DNS] Response length: {} bytes", response_len);

    // Read response
    let mut response = vec![0u8; response_len];
    tls_stream.read_exact(&mut response).await?;

    eprintln!("[DNS] Received response ({} bytes)", response.len());

    // Parse response
    let (answer_count, ip) = parse_dns_response(&response)?;

    assert!(answer_count > 0, "DNS response has no answers");

    if let Some(ip) = ip {
        eprintln!("[DNS] Resolved example.com to {}", ip);
    } else {
        eprintln!("[DNS] Got {} answers but couldn't parse IP", answer_count);
    }

    eprintln!("[TEST] Successfully completed DNS over TLS request through VISION");

    Ok(())
}
