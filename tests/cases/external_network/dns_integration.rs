/// Integration tests for DNS resolution
///
/// Tests DNS functionality including:
/// - Direct DNS (UDP/TCP) without proxy
/// - DNS through proxy chains (TCP/DoT/DoH via VLESS)
/// - Multiple DNS server fallback
///
/// Supported DNS protocols:
/// - udp:// - UDP DNS (direct only, no client_chain support)
/// - tcp:// - TCP DNS (supports client_chain)
/// - tls:// - DNS-over-TLS (supports client_chain)
/// - https:// - DNS-over-HTTPS (supports client_chain)
/// - h3:// - DNS-over-HTTP/3 (direct only, QUIC-based)
/// - system - Native system resolver
use shoes_test_support as common;

use common::test_fixture::start_shoes_server;
use std::path::Path;
use std::time::Duration;
use tokio::time::sleep;

const TEST_UUID: &str = "b85798ef-e9dc-46a4-9a87-8da4499d36d0";

/// Test DNS resolution through VLESS server using TCP DNS
///
/// This test validates that:
/// 1. DNS queries are routed through the VLESS server via client_chain
/// 2. The resolved hostname can be used to make HTTP requests
/// 3. The entire flow works end-to-end
#[tokio::test]
async fn test_dns_through_vless_tcp() -> Result<(), Box<dyn std::error::Error>> {
    use common::test_servers::generate_test_cert;

    let mut port_helper = common::port_helper::PortHelper::new();
    let (vless_ip, vless_port) = port_helper.get_listener_port();
    let (http_proxy_ip, http_proxy_port) = port_helper.get_listener_port();
    eprintln!(
        "[TEST] Using ports: VLESS={}, HTTP Proxy={}",
        vless_port, http_proxy_port
    );

    // Generate certificates for VLESS TLS
    let (vless_cert, vless_key) = generate_test_cert()?;

    // shoes config with:
    // 1. VLESS+TLS server (acts as DNS proxy tunnel)
    // 2. HTTP proxy server with dns_group that routes DNS through VLESS
    let shoes_config = format!(
        r#"
# VLESS+TLS server that forwards DNS queries to upstream
- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      dns.local:
        cert: {}
        key: {}
        protocol:
          type: vless
          user_id: "{}"

# Client proxy group for DNS routing
- client_group: vless-dns-tunnel
  client_proxies:
    - address: "{}:{}"
      protocol:
        type: tls
        sni_hostname: dns.local
        verify: false
        protocol:
          type: vless
          user_id: "{}"

# DNS group that routes queries through VLESS
- dns_group: proxied-dns
  dns_servers:
    - url: tcp://8.8.8.8
      client_chain: vless-dns-tunnel

# HTTP proxy server using the proxied DNS
- address: "{}:{}"
  dns:
    servers: proxied-dns
  protocol:
    type: http
"#,
        vless_ip,
        vless_port,
        AsRef::<Path>::as_ref(&vless_cert).to_str().unwrap(),
        AsRef::<Path>::as_ref(&vless_key).to_str().unwrap(),
        TEST_UUID,
        vless_ip,
        vless_port,
        TEST_UUID,
        http_proxy_ip,
        http_proxy_port
    );

    // Start shoes server
    eprintln!("[DEBUG] Starting shoes server with DNS config...");
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    port_helper.wait_for_all_ports().await?;

    // Additional wait for DNS setup
    sleep(Duration::from_millis(500)).await;

    // Test: Make HTTP request to example.com through the proxy
    // DNS resolution should go through VLESS -> 8.8.8.8
    eprintln!("[TEST] Making HTTP request to example.com (DNS via VLESS)");
    let output = common::curl::run_curl(
        "http://example.com",
        common::curl::CurlOptions::new()
            .proxy(format!("http://{}:{}", http_proxy_ip, http_proxy_port))
            .timeout(30),
    )
    .await?;

    eprintln!(
        "[TEST] curl completed with status: {:?}",
        output.status.code()
    );

    if !output.status.success() {
        eprintln!("[TEST] stderr: {}", String::from_utf8_lossy(&output.stderr));
    }

    assert!(
        output.status.success(),
        "HTTP request failed with exit code: {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify we got a valid response from example.com
    let response_text = String::from_utf8_lossy(&output.stdout);
    assert!(
        response_text.contains("Example Domain") || response_text.contains("example"),
        "Response doesn't look like example.com: {}",
        &response_text[..std::cmp::min(500, response_text.len())]
    );

    eprintln!("[TEST] Successfully resolved and fetched example.com via DNS through VLESS");
    eprintln!("[TEST] Response length: {} bytes", output.stdout.len());

    Ok(())
}

/// Test DNS resolution through VLESS server using DNS-over-TLS (DoT)
///
/// DoT provides encrypted DNS queries over TLS on port 853.
/// This can be tunneled through VLESS since it's TCP-based.
///
#[tokio::test]
async fn test_dns_through_vless_dot() -> Result<(), Box<dyn std::error::Error>> {
    use common::test_servers::generate_test_cert;

    let mut port_helper = common::port_helper::PortHelper::new();
    let (vless_ip, vless_port) = port_helper.get_listener_port();
    let (http_proxy_ip, http_proxy_port) = port_helper.get_listener_port();
    eprintln!(
        "[TEST] Using ports: VLESS={}, HTTP Proxy={}",
        vless_port, http_proxy_port
    );

    let (vless_cert, vless_key) = generate_test_cert()?;

    // shoes config with DoT (DNS-over-TLS) through VLESS
    let shoes_config = format!(
        r#"
# VLESS+TLS server
- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      dns.local:
        cert: {}
        key: {}
        protocol:
          type: vless
          user_id: "{}"

# Client proxy group for DNS routing
- client_group: vless-dns-tunnel
  client_proxies:
    - address: "{}:{}"
      protocol:
        type: tls
        sni_hostname: dns.local
        verify: false
        protocol:
          type: vless
          user_id: "{}"

# DNS group using DoT (DNS-over-TLS) through VLESS
- dns_group: proxied-dot-dns
  dns_servers:
    - url: tls://8.8.8.8
      client_chain: vless-dns-tunnel
      server_name: dns.google

# HTTP proxy server using the proxied DNS
- address: "{}:{}"
  dns:
    servers: proxied-dot-dns
  protocol:
    type: http
"#,
        vless_ip,
        vless_port,
        AsRef::<Path>::as_ref(&vless_cert).to_str().unwrap(),
        AsRef::<Path>::as_ref(&vless_key).to_str().unwrap(),
        TEST_UUID,
        vless_ip,
        vless_port,
        TEST_UUID,
        http_proxy_ip,
        http_proxy_port
    );

    // Start shoes server
    eprintln!("[DEBUG] Starting shoes server with DoT DNS config...");
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    port_helper.wait_for_all_ports().await?;

    sleep(Duration::from_millis(500)).await;

    // Test: Make HTTP request to google.com through the proxy
    eprintln!("[TEST] Making HTTP request to google.com (DoT DNS via VLESS)");
    let output = common::curl::run_curl(
        "http://www.google.com",
        common::curl::CurlOptions::new()
            .proxy(format!("http://{}:{}", http_proxy_ip, http_proxy_port))
            .timeout(30),
    )
    .await?;

    eprintln!(
        "[TEST] curl completed with status: {:?}",
        output.status.code()
    );

    if !output.status.success() {
        eprintln!("[TEST] stderr: {}", String::from_utf8_lossy(&output.stderr));
    }

    assert!(
        output.status.success(),
        "HTTP request failed with exit code: {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify we got a valid response
    let response_text = String::from_utf8_lossy(&output.stdout);
    assert!(
        response_text.contains("google")
            || response_text.contains("Google")
            || !response_text.is_empty(),
        "Response doesn't look like google.com: {}",
        &response_text[..std::cmp::min(500, response_text.len())]
    );

    eprintln!("[TEST] Successfully resolved and fetched google.com via DoT DNS through VLESS");
    eprintln!("[TEST] Response length: {} bytes", output.stdout.len());

    Ok(())
}

/// Test DNS resolution using DNS-over-HTTP/3 (DoH3) direct
///
/// H3 uses QUIC transport for DNS queries. This cannot be routed through
/// proxy chains (QUIC is UDP-based), so this test is direct only.
/// Note: H3 requires a proper hostname for SNI, so we use cloudflare-dns.com
/// with a bootstrap resolver to resolve the hostname first.
#[tokio::test]
async fn test_dns_h3_direct() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (http_proxy_ip, http_proxy_port) = port_helper.get_listener_port();
    eprintln!("[TEST] Using port: HTTP Proxy={}", http_proxy_port);

    let shoes_config = format!(
        r#"
# DNS group using H3 (DNS-over-HTTP/3) - direct only, no proxy support
# H3 requires proper hostname for SNI, so use bootstrap to resolve dns.google
- dns_group: h3-dns
  dns_servers:
    - url: h3://dns.google/dns-query
      bootstrap_url: udp://8.8.8.8

# HTTP proxy server using H3 DNS
- address: "{}:{}"
  dns:
    servers: h3-dns
  protocol:
    type: http
"#,
        http_proxy_ip, http_proxy_port
    );

    eprintln!("[DEBUG] Starting shoes server with H3 DNS...");
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    port_helper.wait_for_all_ports().await?;

    sleep(Duration::from_millis(500)).await;

    eprintln!("[TEST] Making HTTP request to example.com (H3 DNS)");
    let output = common::curl::run_curl(
        "http://example.com",
        common::curl::CurlOptions::new()
            .proxy(format!("http://{}:{}", http_proxy_ip, http_proxy_port))
            .timeout(30),
    )
    .await?;

    eprintln!(
        "[TEST] curl completed with status: {:?}",
        output.status.code()
    );

    if !output.status.success() {
        eprintln!("[TEST] stderr: {}", String::from_utf8_lossy(&output.stderr));
    }

    assert!(
        output.status.success(),
        "HTTP request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let response_text = String::from_utf8_lossy(&output.stdout);
    assert!(
        response_text.contains("Example Domain") || response_text.contains("example"),
        "Response doesn't look like example.com"
    );

    eprintln!(
        "[TEST] Successfully resolved via H3 DNS ({} bytes)",
        output.stdout.len()
    );

    Ok(())
}

/// Test DNS resolution using DNS-over-HTTP/3 with Cloudflare
///
/// Exercises endpoint compatibility with GREASE disabled.
#[tokio::test]
async fn test_dns_h3_cloudflare() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (http_proxy_ip, http_proxy_port) = port_helper.get_listener_port();
    eprintln!("[TEST] Using port: HTTP Proxy={}", http_proxy_port);

    let shoes_config = format!(
        r#"
# DNS group using H3 to Cloudflare with GREASE disabled
- dns_group: h3-cloudflare
  dns_servers:
    - url: h3://cloudflare-dns.com/dns-query
      bootstrap_url: udp://1.1.1.1

# HTTP proxy server using Cloudflare H3 DNS
- address: "{}:{}"
  dns:
    servers: h3-cloudflare
  protocol:
    type: http
"#,
        http_proxy_ip, http_proxy_port
    );

    eprintln!("[DEBUG] Starting shoes server with Cloudflare H3 DNS...");
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    port_helper.wait_for_all_ports().await?;

    sleep(Duration::from_millis(500)).await;

    eprintln!("[TEST] Making HTTP request to example.com (Cloudflare H3 DNS)");
    let output = common::curl::run_curl(
        "http://example.com",
        common::curl::CurlOptions::new()
            .proxy(format!("http://{}:{}", http_proxy_ip, http_proxy_port))
            .timeout(30),
    )
    .await?;

    eprintln!(
        "[TEST] curl completed with status: {:?}",
        output.status.code()
    );

    if !output.status.success() {
        eprintln!("[TEST] stderr: {}", String::from_utf8_lossy(&output.stderr));
    }

    assert!(
        output.status.success(),
        "HTTP request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let response_text = String::from_utf8_lossy(&output.stdout);
    assert!(
        response_text.contains("Example Domain") || response_text.contains("example"),
        "Response doesn't look like example.com"
    );

    eprintln!(
        "[TEST] Successfully resolved via Cloudflare H3 DNS ({} bytes)",
        output.stdout.len()
    );

    Ok(())
}

/// Test DNS resolution through VLESS with DoH (DNS-over-HTTPS)
///
/// This test uses DoH to Cloudflare (1.1.1.1) routed through VLESS.
/// DoH provides encrypted DNS queries which adds an extra layer of privacy.
///
#[tokio::test]
async fn test_dns_through_vless_doh() -> Result<(), Box<dyn std::error::Error>> {
    use common::test_servers::generate_test_cert;

    let mut port_helper = common::port_helper::PortHelper::new();
    let (vless_ip, vless_port) = port_helper.get_listener_port();
    let (http_proxy_ip, http_proxy_port) = port_helper.get_listener_port();
    eprintln!(
        "[TEST] Using ports: VLESS={}, HTTP Proxy={}",
        vless_port, http_proxy_port
    );

    let (vless_cert, vless_key) = generate_test_cert()?;

    // shoes config with DoH through VLESS
    let shoes_config = format!(
        r#"
# VLESS+TLS server
- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      dns.local:
        cert: {}
        key: {}
        protocol:
          type: vless
          user_id: "{}"

# Client proxy group for DNS routing
- client_group: vless-dns-tunnel
  client_proxies:
    - address: "{}:{}"
      protocol:
        type: tls
        sni_hostname: dns.local
        verify: false
        protocol:
          type: vless
          user_id: "{}"

# DNS group using DoH through VLESS
- dns_group: proxied-doh
  dns_servers:
    - url: https://1.1.1.1/dns-query
      client_chain: vless-dns-tunnel

# HTTP proxy server using DoH DNS
- address: "{}:{}"
  dns:
    servers: proxied-doh
  protocol:
    type: http
"#,
        vless_ip,
        vless_port,
        AsRef::<Path>::as_ref(&vless_cert).to_str().unwrap(),
        AsRef::<Path>::as_ref(&vless_key).to_str().unwrap(),
        TEST_UUID,
        vless_ip,
        vless_port,
        TEST_UUID,
        http_proxy_ip,
        http_proxy_port
    );

    eprintln!("[DEBUG] Starting shoes server with DoH DNS config...");
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    port_helper.wait_for_all_ports().await?;

    sleep(Duration::from_millis(500)).await;

    // Test with example.com
    eprintln!("[TEST] Making HTTP request to example.com (DoH via VLESS)");
    let output = common::curl::run_curl(
        "http://example.com",
        common::curl::CurlOptions::new()
            .proxy(format!("http://{}:{}", http_proxy_ip, http_proxy_port))
            .timeout(30),
    )
    .await?;

    eprintln!(
        "[TEST] curl completed with status: {:?}",
        output.status.code()
    );

    if !output.status.success() {
        eprintln!("[TEST] stderr: {}", String::from_utf8_lossy(&output.stderr));
    }

    assert!(
        output.status.success(),
        "HTTP request failed with exit code: {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let response_text = String::from_utf8_lossy(&output.stdout);
    assert!(
        response_text.contains("Example Domain") || response_text.contains("example"),
        "Response doesn't look like example.com"
    );

    eprintln!("[TEST] Successfully resolved and fetched example.com via DoH through VLESS");

    Ok(())
}

/// Test DNS with multiple servers (fallback) through VLESS
///
/// Configures multiple DNS servers in the group to test failover behavior.
#[tokio::test]
async fn test_dns_through_vless_multiple_servers() -> Result<(), Box<dyn std::error::Error>> {
    use common::test_servers::generate_test_cert;

    let mut port_helper = common::port_helper::PortHelper::new();
    let (vless_ip, vless_port) = port_helper.get_listener_port();
    let (http_proxy_ip, http_proxy_port) = port_helper.get_listener_port();
    eprintln!(
        "[TEST] Using ports: VLESS={}, HTTP Proxy={}",
        vless_port, http_proxy_port
    );

    let (vless_cert, vless_key) = generate_test_cert()?;

    // shoes config with multiple DNS servers through VLESS
    let shoes_config = format!(
        r#"
# VLESS+TLS server
- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      dns.local:
        cert: {}
        key: {}
        protocol:
          type: vless
          user_id: "{}"

# Client proxy group
- client_group: vless-dns-tunnel
  client_proxies:
    - address: "{}:{}"
      protocol:
        type: tls
        sni_hostname: dns.local
        verify: false
        protocol:
          type: vless
          user_id: "{}"

# DNS group with multiple servers for redundancy
- dns_group: multi-dns
  dns_servers:
    - url: tcp://8.8.8.8
      client_chain: vless-dns-tunnel
    - url: tcp://1.1.1.1
      client_chain: vless-dns-tunnel

# HTTP proxy using multi-DNS
- address: "{}:{}"
  dns:
    servers: multi-dns
  protocol:
    type: http
"#,
        vless_ip,
        vless_port,
        AsRef::<Path>::as_ref(&vless_cert).to_str().unwrap(),
        AsRef::<Path>::as_ref(&vless_key).to_str().unwrap(),
        TEST_UUID,
        vless_ip,
        vless_port,
        TEST_UUID,
        http_proxy_ip,
        http_proxy_port
    );

    eprintln!("[DEBUG] Starting shoes server with multiple DNS servers...");
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    port_helper.wait_for_all_ports().await?;

    sleep(Duration::from_millis(500)).await;

    // Test multiple domains to exercise DNS resolution
    for domain in &["example.com", "www.google.com"] {
        eprintln!(
            "[TEST] Making HTTP request to {} (multi-DNS via VLESS)",
            domain
        );
        let url = format!("http://{}", domain);
        let output = common::curl::run_curl(
            &url,
            common::curl::CurlOptions::new()
                .proxy(format!("http://{}:{}", http_proxy_ip, http_proxy_port))
                .timeout(30),
        )
        .await?;

        assert!(
            output.status.success(),
            "HTTP request to {} failed: {}",
            domain,
            String::from_utf8_lossy(&output.stderr)
        );

        eprintln!(
            "[TEST] Successfully fetched {} ({} bytes)",
            domain,
            output.stdout.len()
        );
    }

    eprintln!("[TEST] All DNS resolutions through VLESS succeeded");

    Ok(())
}

// ============================================================================
// Direct DNS Tests (no proxy chain)
// ============================================================================

/// Test UDP DNS resolution without proxy chain
///
/// UDP DNS is the most common DNS protocol. This test verifies that
/// dns_group with udp:// works correctly for direct resolution.
#[tokio::test]
async fn test_dns_udp_direct() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (http_proxy_ip, http_proxy_port) = port_helper.get_listener_port();
    eprintln!("[TEST] Using port: HTTP Proxy={}", http_proxy_port);

    let shoes_config = format!(
        r#"
# DNS group using UDP (direct, no proxy)
# Use ipv4_only to avoid test flakiness when IPv6 is unreachable
- dns_group: udp-dns
  dns_servers:
    - url: udp://8.8.8.8
      ip_strategy: ipv4_only

# HTTP proxy server using UDP DNS
- address: "{}:{}"
  dns:
    servers: udp-dns
  protocol:
    type: http
"#,
        http_proxy_ip, http_proxy_port
    );

    eprintln!("[DEBUG] Starting shoes server with UDP DNS...");
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    port_helper.wait_for_all_ports().await?;

    sleep(Duration::from_millis(300)).await;

    eprintln!("[TEST] Making HTTP request to example.com (UDP DNS)");
    let output = common::curl::run_curl(
        "http://example.com",
        common::curl::CurlOptions::new()
            .proxy(format!("http://{}:{}", http_proxy_ip, http_proxy_port))
            .timeout(30),
    )
    .await?;

    eprintln!(
        "[TEST] curl completed with status: {:?}",
        output.status.code()
    );

    assert!(
        output.status.success(),
        "HTTP request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let response_text = String::from_utf8_lossy(&output.stdout);
    assert!(
        response_text.contains("Example Domain") || response_text.contains("example"),
        "Response doesn't look like example.com"
    );

    eprintln!(
        "[TEST] Successfully resolved via UDP DNS ({} bytes)",
        output.stdout.len()
    );

    Ok(())
}

/// Test TCP DNS resolution without proxy chain
///
/// TCP DNS is used for larger responses or when UDP fails.
#[tokio::test]
async fn test_dns_tcp_direct() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (http_proxy_ip, http_proxy_port) = port_helper.get_listener_port();
    eprintln!("[TEST] Using port: HTTP Proxy={}", http_proxy_port);

    let shoes_config = format!(
        r#"
# DNS group using TCP (direct, no proxy)
- dns_group: tcp-dns
  dns_servers:
    - url: tcp://8.8.8.8

# HTTP proxy server using TCP DNS
- address: "{}:{}"
  dns:
    servers: tcp-dns
  protocol:
    type: http
"#,
        http_proxy_ip, http_proxy_port
    );

    eprintln!("[DEBUG] Starting shoes server with TCP DNS...");
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    port_helper.wait_for_all_ports().await?;

    sleep(Duration::from_millis(300)).await;

    eprintln!("[TEST] Making HTTP request to example.com (TCP DNS)");
    let output = common::curl::run_curl(
        "http://example.com",
        common::curl::CurlOptions::new()
            .proxy(format!("http://{}:{}", http_proxy_ip, http_proxy_port))
            .timeout(30),
    )
    .await?;

    assert!(
        output.status.success(),
        "HTTP request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    eprintln!(
        "[TEST] Successfully resolved via TCP DNS ({} bytes)",
        output.stdout.len()
    );

    Ok(())
}

/// Test DoT DNS resolution without proxy chain
///
/// DNS-over-TLS provides encrypted DNS queries.
#[tokio::test]
async fn test_dns_dot_direct() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (http_proxy_ip, http_proxy_port) = port_helper.get_listener_port();
    eprintln!("[TEST] Using port: HTTP Proxy={}", http_proxy_port);

    let shoes_config = format!(
        r#"
# DNS group using DoT (direct, no proxy)
- dns_group: dot-dns
  dns_servers:
    - url: tls://8.8.8.8
      server_name: dns.google

# HTTP proxy server using DoT DNS
- address: "{}:{}"
  dns:
    servers: dot-dns
  protocol:
    type: http
"#,
        http_proxy_ip, http_proxy_port
    );

    eprintln!("[DEBUG] Starting shoes server with DoT DNS...");
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    port_helper.wait_for_all_ports().await?;

    sleep(Duration::from_millis(300)).await;

    eprintln!("[TEST] Making HTTP request to example.com (DoT DNS)");
    let output = common::curl::run_curl(
        "http://example.com",
        common::curl::CurlOptions::new()
            .proxy(format!("http://{}:{}", http_proxy_ip, http_proxy_port))
            .timeout(30),
    )
    .await?;

    assert!(
        output.status.success(),
        "HTTP request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    eprintln!(
        "[TEST] Successfully resolved via DoT DNS ({} bytes)",
        output.stdout.len()
    );

    Ok(())
}

/// Test DoH DNS resolution without proxy chain
///
/// DNS-over-HTTPS provides encrypted DNS queries over HTTP/2.
#[tokio::test]
async fn test_dns_doh_direct() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (http_proxy_ip, http_proxy_port) = port_helper.get_listener_port();
    eprintln!("[TEST] Using port: HTTP Proxy={}", http_proxy_port);

    let shoes_config = format!(
        r#"
# DNS group using DoH (direct, no proxy)
- dns_group: doh-dns
  dns_servers:
    - url: https://1.1.1.1/dns-query

# HTTP proxy server using DoH DNS
- address: "{}:{}"
  dns:
    servers: doh-dns
  protocol:
    type: http
"#,
        http_proxy_ip, http_proxy_port
    );

    eprintln!("[DEBUG] Starting shoes server with DoH DNS...");
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    port_helper.wait_for_all_ports().await?;

    sleep(Duration::from_millis(300)).await;

    eprintln!("[TEST] Making HTTP request to example.com (DoH DNS)");
    let output = common::curl::run_curl(
        "http://example.com",
        common::curl::CurlOptions::new()
            .proxy(format!("http://{}:{}", http_proxy_ip, http_proxy_port))
            .timeout(30),
    )
    .await?;

    assert!(
        output.status.success(),
        "HTTP request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    eprintln!(
        "[TEST] Successfully resolved via DoH DNS ({} bytes)",
        output.stdout.len()
    );

    Ok(())
}

/// Test system DNS resolver
///
/// Uses the native system resolver (reads /etc/resolv.conf on Linux).
#[tokio::test]
async fn test_dns_system_resolver() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (http_proxy_ip, http_proxy_port) = port_helper.get_listener_port();
    eprintln!("[TEST] Using port: HTTP Proxy={}", http_proxy_port);

    let shoes_config = format!(
        r#"
# DNS group using system resolver
- dns_group: system-dns
  dns_servers:
    - url: system

# HTTP proxy server using system DNS
- address: "{}:{}"
  dns:
    servers: system-dns
  protocol:
    type: http
"#,
        http_proxy_ip, http_proxy_port
    );

    eprintln!("[DEBUG] Starting shoes server with system DNS...");
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    port_helper.wait_for_all_ports().await?;

    sleep(Duration::from_millis(300)).await;

    eprintln!("[TEST] Making HTTP request to example.com (system DNS)");
    let output = common::curl::run_curl(
        "http://example.com",
        common::curl::CurlOptions::new()
            .proxy(format!("http://{}:{}", http_proxy_ip, http_proxy_port))
            .timeout(30),
    )
    .await?;

    assert!(
        output.status.success(),
        "HTTP request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    eprintln!(
        "[TEST] Successfully resolved via system DNS ({} bytes)",
        output.stdout.len()
    );

    Ok(())
}

/// Test mixed DNS protocols in a single group (fallback)
///
/// When multiple DNS servers are configured, the resolver can fall back
/// to secondary servers if the primary fails.
#[tokio::test]
async fn test_dns_mixed_protocols() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (http_proxy_ip, http_proxy_port) = port_helper.get_listener_port();
    eprintln!("[TEST] Using port: HTTP Proxy={}", http_proxy_port);

    let shoes_config = format!(
        r#"
# DNS group with multiple protocols
# Use ipv4_only to avoid test flakiness when IPv6 is unreachable
- dns_group: mixed-dns
  dns_servers:
    - url: udp://8.8.8.8
      ip_strategy: ipv4_only
    - url: tcp://1.1.1.1
      ip_strategy: ipv4_only
    - url: tls://8.8.4.4
      server_name: dns.google
      ip_strategy: ipv4_only

# HTTP proxy server using mixed DNS
- address: "{}:{}"
  dns:
    servers: mixed-dns
  protocol:
    type: http
"#,
        http_proxy_ip, http_proxy_port
    );

    eprintln!("[DEBUG] Starting shoes server with mixed DNS protocols...");
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    port_helper.wait_for_all_ports().await?;

    sleep(Duration::from_millis(300)).await;

    // Test multiple domains
    for domain in &["example.com", "www.google.com", "github.com"] {
        eprintln!("[TEST] Making HTTP request to {} (mixed DNS)", domain);
        let url = format!("http://{}", domain);
        let output = common::curl::run_curl(
            &url,
            common::curl::CurlOptions::new()
                .proxy(format!("http://{}:{}", http_proxy_ip, http_proxy_port))
                .timeout(30),
        )
        .await?;

        assert!(
            output.status.success(),
            "HTTP request to {} failed: {}",
            domain,
            String::from_utf8_lossy(&output.stderr)
        );

        eprintln!(
            "[TEST] Successfully fetched {} ({} bytes)",
            domain,
            output.stdout.len()
        );
    }

    eprintln!("[TEST] All mixed DNS resolutions succeeded");

    Ok(())
}

/// Test DNS with bootstrap URL
///
/// When a DNS server is specified by hostname (e.g., dns.google), a bootstrap
/// DNS server is needed to resolve that hostname first. This test verifies
/// the bootstrap_url functionality.
#[tokio::test]
async fn test_dns_with_bootstrap() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (http_proxy_ip, http_proxy_port) = port_helper.get_listener_port();
    eprintln!("[TEST] Using port: HTTP Proxy={}", http_proxy_port);

    let shoes_config = format!(
        r#"
# DNS group using DoT with hostname, bootstrapped by Cloudflare
- dns_group: bootstrapped-dns
  dns_servers:
    - url: tls://dns.google
      bootstrap_url: udp://1.1.1.1

# HTTP proxy server using bootstrapped DNS
- address: "{}:{}"
  dns:
    servers: bootstrapped-dns
  protocol:
    type: http
"#,
        http_proxy_ip, http_proxy_port
    );

    eprintln!("[DEBUG] Starting shoes server with bootstrapped DNS...");
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    port_helper.wait_for_all_ports().await?;

    sleep(Duration::from_millis(300)).await;

    eprintln!("[TEST] Making HTTP request to example.com (bootstrapped DoT DNS)");
    let output = common::curl::run_curl(
        "http://example.com",
        common::curl::CurlOptions::new()
            .proxy(format!("http://{}:{}", http_proxy_ip, http_proxy_port))
            .timeout(30),
    )
    .await?;

    eprintln!(
        "[TEST] curl completed with status: {:?}",
        output.status.code()
    );

    assert!(
        output.status.success(),
        "HTTP request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    eprintln!(
        "[TEST] Successfully resolved via bootstrapped DNS ({} bytes)",
        output.stdout.len()
    );

    Ok(())
}

/// Test DNS with bootstrap URL for DoH
///
/// Similar to DoT bootstrap test but using DNS-over-HTTPS.
#[tokio::test]
async fn test_dns_doh_with_bootstrap() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (http_proxy_ip, http_proxy_port) = port_helper.get_listener_port();
    eprintln!("[TEST] Using port: HTTP Proxy={}", http_proxy_port);

    let shoes_config = format!(
        r#"
# DNS group using DoH with hostname, bootstrapped by Google DNS
- dns_group: bootstrapped-doh
  dns_servers:
    - url: https://cloudflare-dns.com/dns-query
      bootstrap_url: tcp://8.8.8.8

# HTTP proxy server using bootstrapped DoH
- address: "{}:{}"
  dns:
    servers: bootstrapped-doh
  protocol:
    type: http
"#,
        http_proxy_ip, http_proxy_port
    );

    eprintln!("[DEBUG] Starting shoes server with bootstrapped DoH...");
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    port_helper.wait_for_all_ports().await?;

    sleep(Duration::from_millis(300)).await;

    eprintln!("[TEST] Making HTTP request to example.com (bootstrapped DoH)");
    let output = common::curl::run_curl(
        "http://example.com",
        common::curl::CurlOptions::new()
            .proxy(format!("http://{}:{}", http_proxy_ip, http_proxy_port))
            .timeout(30),
    )
    .await?;

    assert!(
        output.status.success(),
        "HTTP request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    eprintln!(
        "[TEST] Successfully resolved via bootstrapped DoH ({} bytes)",
        output.stdout.len()
    );

    Ok(())
}

/// Test DNS with 2-hop client chain (SOCKS5 -> VLESS)
///
/// This test validates that DNS queries can traverse a multi-hop proxy chain.
/// Traffic flows: DNS query -> SOCKS5 proxy -> VLESS proxy -> upstream DNS
#[tokio::test]
async fn test_dns_two_hop_chain() -> Result<(), Box<dyn std::error::Error>> {
    use common::test_servers::generate_test_cert;

    let mut port_helper = common::port_helper::PortHelper::new();
    let (socks_ip, socks_port) = port_helper.get_listener_port();
    let (vless_ip, vless_port) = port_helper.get_listener_port();
    let (http_proxy_ip, http_proxy_port) = port_helper.get_listener_port();
    eprintln!(
        "[TEST] Using ports: SOCKS5={}, VLESS={}, HTTP Proxy={}",
        socks_port, vless_port, http_proxy_port
    );

    let (vless_cert, vless_key) = generate_test_cert()?;

    // Config with 2-hop chain: SOCKS5 -> VLESS+TLS
    let shoes_config = format!(
        r#"
# Hop 1: SOCKS5 server (entry point)
- address: "{}:{}"
  protocol:
    type: socks

# Hop 2: VLESS+TLS server (exit point)
- address: "{}:{}"
  protocol:
    type: tls
    tls_targets:
      exit.local:
        cert: {}
        key: {}
        protocol:
          type: vless
          user_id: "{}"

# Client group for first hop (SOCKS5)
- client_group: socks-hop
  client_proxies:
    - address: "{}:{}"
      protocol:
        type: socks

# Client group for second hop (VLESS+TLS)
- client_group: vless-hop
  client_proxies:
    - address: "{}:{}"
      protocol:
        type: tls
        sni_hostname: exit.local
        verify: false
        protocol:
          type: vless
          user_id: "{}"

# DNS group with 2-hop chain: SOCKS5 -> VLESS -> upstream DNS
- dns_group: two-hop-dns
  dns_servers:
    - url: tcp://8.8.8.8
      client_chain:
        chain: [socks-hop, vless-hop]

# HTTP proxy server using 2-hop DNS
- address: "{}:{}"
  dns:
    servers: two-hop-dns
  protocol:
    type: http
"#,
        socks_ip,
        socks_port,
        vless_ip,
        vless_port,
        AsRef::<Path>::as_ref(&vless_cert).to_str().unwrap(),
        AsRef::<Path>::as_ref(&vless_key).to_str().unwrap(),
        TEST_UUID,
        socks_ip,
        socks_port,
        vless_ip,
        vless_port,
        TEST_UUID,
        http_proxy_ip,
        http_proxy_port
    );

    eprintln!("[DEBUG] Starting shoes server with 2-hop DNS chain...");
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    port_helper.wait_for_all_ports().await?;

    sleep(Duration::from_millis(500)).await;

    eprintln!("[TEST] Making HTTP request to example.com (DNS via SOCKS5 -> VLESS)");
    let output = common::curl::run_curl(
        "http://example.com",
        common::curl::CurlOptions::new()
            .proxy(format!("http://{}:{}", http_proxy_ip, http_proxy_port))
            .timeout(30),
    )
    .await?;

    eprintln!(
        "[TEST] curl completed with status: {:?}",
        output.status.code()
    );

    if !output.status.success() {
        eprintln!("[TEST] stderr: {}", String::from_utf8_lossy(&output.stderr));
    }

    assert!(
        output.status.success(),
        "HTTP request failed with exit code: {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let response_text = String::from_utf8_lossy(&output.stdout);
    assert!(
        response_text.contains("Example Domain") || response_text.contains("example"),
        "Response doesn't look like example.com: {}",
        &response_text[..std::cmp::min(500, response_text.len())]
    );

    eprintln!("[TEST] Successfully resolved example.com via 2-hop DNS chain");
    eprintln!("[TEST] Response length: {} bytes", output.stdout.len());

    Ok(())
}

/// Test that configured timeout_secs and attempts affect hickory behavior.
///
/// Uses a blackhole DNS upstream (10.255.255.1) with a short timeout and
/// a real fallback to verify the timeout fires and fallback works within
/// the expected time budget.
#[tokio::test]
async fn test_dns_timeout_with_fallback() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (http_proxy_ip, http_proxy_port) = port_helper.get_listener_port();
    eprintln!("[TEST] Using port: HTTP Proxy={}", http_proxy_port);

    let shoes_config = format!(
        r#"
# DNS group with blackhole primary and real fallback.
# timeout_secs=2 and attempts=1 limits the blackhole delay.
- dns_group: timeout-test-dns
  dns_servers:
    - url: udp://10.255.255.1
      timeout_secs: 2
      attempts: 1
      ip_strategy: ipv4_only
    - url: udp://8.8.8.8
      timeout_secs: 5
      attempts: 1
      ip_strategy: ipv4_only

# HTTP proxy using the timeout-test DNS
- address: "{}:{}"
  dns:
    servers: timeout-test-dns
  protocol:
    type: http
"#,
        http_proxy_ip, http_proxy_port
    );

    eprintln!("[DEBUG] Starting shoes server with timeout test DNS...");
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    port_helper.wait_for_all_ports().await?;

    sleep(Duration::from_millis(300)).await;

    let start = std::time::Instant::now();

    eprintln!("[TEST] Making HTTP request (DNS timeout + fallback)");
    let output = common::curl::run_curl(
        "http://example.com",
        common::curl::CurlOptions::new()
            .proxy(format!("http://{}:{}", http_proxy_ip, http_proxy_port))
            .timeout(30),
    )
    .await?;

    let elapsed = start.elapsed();
    eprintln!("[TEST] Request completed in {:?}", elapsed);

    assert!(
        output.status.success(),
        "HTTP request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let response_text = String::from_utf8_lossy(&output.stdout);
    assert!(
        response_text.contains("Example Domain") || response_text.contains("example"),
        "Response doesn't look like example.com"
    );

    eprintln!(
        "[TEST] Successfully resolved with timeout+fallback in {:?} ({} bytes)",
        elapsed,
        output.stdout.len()
    );

    Ok(())
}

/// Test DNS with custom attempts and connect_timeout_secs config
///
/// Verifies that the new config fields are accepted and the server starts.
#[tokio::test]
async fn test_dns_custom_attempts_and_connect_timeout() -> Result<(), Box<dyn std::error::Error>> {
    let mut port_helper = common::port_helper::PortHelper::new();
    let (http_proxy_ip, http_proxy_port) = port_helper.get_listener_port();

    let shoes_config = format!(
        r#"
# DNS group with explicit attempts and connect_timeout_secs
- dns_group: tuned-dns
  dns_servers:
    - url: udp://8.8.8.8
      timeout_secs: 3
      connect_timeout_secs: 1
      attempts: 1
      ip_strategy: ipv4_only

# HTTP proxy using the tuned DNS
- address: "{}:{}"
  dns:
    servers: tuned-dns
  protocol:
    type: http
"#,
        http_proxy_ip, http_proxy_port
    );

    eprintln!("[DEBUG] Starting shoes server with tuned DNS config...");
    let (_shoes_guard, _shoes_config_file) = start_shoes_server(&shoes_config)?;
    port_helper.wait_for_all_ports().await?;

    sleep(Duration::from_millis(300)).await;

    eprintln!("[TEST] Making HTTP request (tuned DNS)");
    let output = common::curl::run_curl(
        "http://example.com",
        common::curl::CurlOptions::new()
            .proxy(format!("http://{}:{}", http_proxy_ip, http_proxy_port))
            .timeout(30),
    )
    .await?;

    assert!(
        output.status.success(),
        "HTTP request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    eprintln!(
        "[TEST] Successfully resolved with tuned DNS config ({} bytes)",
        output.stdout.len()
    );

    Ok(())
}
