use common::test_fixture::ProxyTestFixture;
use futures::future::join_all;
/// Integration tests for NaiveProxy protocol
///
/// Tests NaiveProxy server/client implementations
/// Tests interoperability with sing-box (when libcronet is available)
use shoes_test_support as common;

// Shoes-to-Shoes Tests (NaiveProxy client -> NaiveProxy server)

#[tokio::test]
async fn test_shoes_naiveproxy_to_naiveproxy() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_client()
        .with_shoes_naiveproxy_server()
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1024", false).await?;
    assert_eq!(body.len(), 1024);
    Ok(())
}

#[tokio::test]
async fn test_shoes_naiveproxy_large_transfer() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_client()
        .with_shoes_naiveproxy_server()
        .with_local_http_server()
        .build()
        .await?;

    // Test larger transfer to exercise padding beyond first 8 frames
    let body = fixture.test_local_server("/bytes/65536", false).await?;
    assert_eq!(body.len(), 65536);
    Ok(())
}

// Sing-box Server Tests (shoes as client, sing-box as server)

#[tokio::test]
async fn test_shoes_naiveproxy_client_singbox_server() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_client()
        .with_singbox_naive_server()
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1024", false).await?;
    assert_eq!(body.len(), 1024);
    Ok(())
}

// Sing-box Client Tests (sing-box as client, shoes as server)
// Note: These tests require libcronet which may not be available

#[tokio::test]
#[ignore = "Requires libcronet for sing-box naive client and sudo for CA installation"]
async fn test_singbox_naiveproxy_client_shoes_server() -> Result<(), Box<dyn std::error::Error>> {
    // sing-box naive client uses cronet which requires proper TLS cert verification
    // Use system CA version which installs our test CA (requires sudo)
    let fixture = ProxyTestFixture::new()
        .with_singbox_naive_client()
        .with_shoes_naiveproxy_server_system_ca()
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1024", false).await?;
    assert_eq!(body.len(), 1024);
    Ok(())
}

// Edge Case Size Tests

#[tokio::test]
async fn test_shoes_naiveproxy_tiny_transfer() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_client()
        .with_shoes_naiveproxy_server()
        .with_local_http_server()
        .build()
        .await?;

    // Test very small transfers (1 byte)
    let body = fixture.test_local_server("/bytes/1", false).await?;
    assert_eq!(body.len(), 1);
    Ok(())
}

#[tokio::test]
async fn test_shoes_naiveproxy_boundary_sizes() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_client()
        .with_shoes_naiveproxy_server()
        .with_local_http_server()
        .build()
        .await?;

    // Test boundary sizes around frame limits
    for size in [100, 255, 256, 1023, 1024, 1025, 4096, 16384] {
        let body = fixture
            .test_local_server(&format!("/bytes/{}", size), false)
            .await?;
        assert_eq!(body.len(), size, "Size mismatch for {}", size);
    }
    Ok(())
}

// Concurrent Connection Tests

#[tokio::test]
async fn test_shoes_naiveproxy_concurrent_requests() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_client()
        .with_shoes_naiveproxy_server()
        .with_local_http_server()
        .build()
        .await?;

    // Create 5 concurrent requests
    // Pre-create paths so they live long enough for the futures
    let paths: Vec<String> = (0..5)
        .map(|i| format!("/bytes/{}", 1024 * (i + 1)))
        .collect();

    let futures: Vec<_> = paths
        .iter()
        .map(|path| fixture.test_local_server(path, false))
        .collect();

    let results = join_all(futures).await;

    for (i, result) in results.into_iter().enumerate() {
        let body = result?;
        let expected_size = 1024 * (i + 1);
        assert_eq!(body.len(), expected_size, "Size mismatch for request {}", i);
    }

    Ok(())
}

// Authentication Failure Tests

#[tokio::test]
async fn test_shoes_naiveproxy_wrong_password() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_client_with_params("naiveuser", "wrongpassword", "test.naive.local")
        .with_shoes_naiveproxy_server()
        .with_local_http_server()
        .build()
        .await?;

    // Use raw curl to check for failure without panicking
    let ip = fixture.local_server_ip().ok_or("No local server IP")?;
    let port = fixture.local_server_port().ok_or("No local server port")?;
    let url = format!("http://{}:{}/bytes/1024", ip, port);
    let options = common::curl::CurlOptions::new()
        .proxy(format!(
            "http://{}:{}",
            fixture.entry_ip(),
            fixture.entry_port()
        ))
        .timeout(10);

    let output = common::curl::run_curl(&url, options).await?;

    // Should fail with non-zero exit code (authentication error causes connection failure)
    assert!(
        !output.status.success(),
        "Expected authentication failure but curl succeeded"
    );
    Ok(())
}

#[tokio::test]
async fn test_shoes_naiveproxy_wrong_username() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_client_with_params("wronguser", "naivepass123", "test.naive.local")
        .with_shoes_naiveproxy_server()
        .with_local_http_server()
        .build()
        .await?;

    // Use raw curl to check for failure without panicking
    let ip = fixture.local_server_ip().ok_or("No local server IP")?;
    let port = fixture.local_server_port().ok_or("No local server port")?;
    let url = format!("http://{}:{}/bytes/1024", ip, port);
    let options = common::curl::CurlOptions::new()
        .proxy(format!(
            "http://{}:{}",
            fixture.entry_ip(),
            fixture.entry_port()
        ))
        .timeout(10);

    let output = common::curl::run_curl(&url, options).await?;

    // Should fail with non-zero exit code (authentication error causes connection failure)
    assert!(
        !output.status.success(),
        "Expected authentication failure but curl succeeded"
    );
    Ok(())
}

// IPv6 and Hostname Destination Tests

#[tokio::test]
async fn test_shoes_naiveproxy_ipv6_destination() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_client()
        .with_shoes_naiveproxy_server()
        .with_local_http_server_ipv6()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/512", false).await?;
    assert_eq!(body, vec![b'X'; 512]);
    Ok(())
}

#[tokio::test]
async fn test_shoes_naiveproxy_hostname_destination() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_client()
        .with_shoes_naiveproxy_server()
        .with_local_http_server_on_localhost()
        .build()
        .await?;

    let url = format!(
        "http://localhost:{}/bytes/512",
        fixture.local_server_port().unwrap()
    );
    let output = fixture
        .test_http_with_options(&url, common::curl::CurlOptions::new().timeout(10))
        .await?;
    assert!(output.status.success());
    assert_eq!(output.stdout, vec![b'X'; 512]);
    Ok(())
}

// HTTP/2 Multiplexing Verification
//
// NaiveProxy uses true HTTP/2 multiplexing on both client and server sides:
//
// **Client-side multiplexing (NaiveClientSession):**
// - Maintains a persistent H2 session to the NaiveProxy server
// - Clones the SendRequest handle for each new CONNECT request
// - Multiple concurrent requests share the same underlying TLS connection
// - Session is reused until the connection is closed
// - Verified by test_shoes_naiveproxy_concurrent_requests and
//   test_shoes_naiveproxy_rapid_sequential
//
// **Server-side multiplexing (NaiveServerSession):**
// - Accepts streams in a loop via connection.accept()
// - Spawns a handler task for each stream
// - Each stream operates independently with its own upstream connection
//
// The concurrent requests test verifies that multiple simultaneous requests
// complete successfully, which exercises the H2 stream creation and
// multiplexing on both client and server.

// Additional Edge Case Tests

/// Test that empty responses work correctly
#[tokio::test]
async fn test_shoes_naiveproxy_empty_response() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_client()
        .with_shoes_naiveproxy_server()
        .with_local_http_server()
        .build()
        .await?;

    // Test /bytes/0 which returns an empty body
    let local_ip = fixture.local_server_ip().unwrap();
    let local_port = fixture.local_server_port().unwrap();
    fixture
        .test_http(&format!("http://{}:{}/bytes/0", local_ip, local_port))
        .await
}

/// Test rapid sequential requests to verify connection reuse
#[tokio::test]
async fn test_shoes_naiveproxy_rapid_sequential() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_client()
        .with_shoes_naiveproxy_server()
        .with_local_http_server()
        .build()
        .await?;

    let local_ip = fixture.local_server_ip().unwrap();
    let local_port = fixture.local_server_port().unwrap();
    let url = format!("http://{}:{}/bytes/100", local_ip, local_port);

    // Make 10 rapid sequential requests
    for _ in 0..10 {
        fixture.test_http(&url).await?;
    }

    Ok(())
}

/// Test very large transfer to stress test the proxy
#[tokio::test]
async fn test_shoes_naiveproxy_very_large_transfer() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_client()
        .with_shoes_naiveproxy_server()
        .with_local_http_server()
        .build()
        .await?;

    // Test with 5MB transfer
    let local_ip = fixture.local_server_ip().unwrap();
    let local_port = fixture.local_server_port().unwrap();
    fixture
        .test_http(&format!("http://{}:{}/bytes/5242880", local_ip, local_port))
        .await
}

// Fallback/Probe Resistance Tests

/// Test fallback to static file serving
#[tokio::test]
async fn test_shoes_naiveproxy_fallback_static_files() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    use tempfile::tempdir;

    // Create a temp directory with test files
    let temp_dir = tempdir()?;
    let index_content = b"<html><body>Hello from fallback!</body></html>";
    let test_content = b"Test file content 12345";

    fs::write(temp_dir.path().join("index.html"), index_content)?;
    fs::write(temp_dir.path().join("test.txt"), test_content)?;

    // Create subdir with file
    fs::create_dir(temp_dir.path().join("subdir"))?;
    fs::write(
        temp_dir.path().join("subdir").join("nested.txt"),
        b"Nested file",
    )?;

    let fallback_path = temp_dir.path().to_str().unwrap();

    // Build fixture with fallback
    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_server_with_fallback(
            "naiveuser",
            "naivepass123",
            "test.naive.local",
            fallback_path,
        )
        .build()
        .await?;

    let server_ip = fixture.entry_ip();
    let server_port = fixture.entry_port();
    let sni = "test.naive.local";

    // Use --resolve to map the SNI hostname to the test server IP
    let resolve_entry = format!("{}:{}:{}", sni, server_port, server_ip);

    // Test: Direct HTTPS request (non-CONNECT, no auth) should get index.html
    let options = common::curl::CurlOptions::new()
        .insecure(true)
        .timeout(10)
        .resolve(&resolve_entry);
    let output =
        common::curl::run_curl(&format!("https://{}:{}/", sni, server_port), options).await?;

    assert!(
        output.status.success(),
        "Expected success for index.html, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body = String::from_utf8_lossy(&output.stdout);
    assert!(
        body.contains("Hello from fallback"),
        "Expected fallback content, got: {}",
        body
    );

    // Test: Request specific file
    let options = common::curl::CurlOptions::new()
        .insecure(true)
        .timeout(10)
        .resolve(&resolve_entry);
    let output = common::curl::run_curl(
        &format!("https://{}:{}/test.txt", sni, server_port),
        options,
    )
    .await?;

    assert!(output.status.success(), "Expected success for test.txt");
    let body = String::from_utf8_lossy(&output.stdout);
    assert!(
        body.contains("Test file content"),
        "Expected test.txt content, got: {}",
        body
    );

    // Test: Nested file
    let options = common::curl::CurlOptions::new()
        .insecure(true)
        .timeout(10)
        .resolve(&resolve_entry);
    let output = common::curl::run_curl(
        &format!("https://{}:{}/subdir/nested.txt", sni, server_port),
        options,
    )
    .await?;

    assert!(output.status.success(), "Expected success for nested.txt");
    let body = String::from_utf8_lossy(&output.stdout);
    assert!(
        body.contains("Nested file"),
        "Expected nested file content, got: {}",
        body
    );

    // Test: Non-existent file should return 404
    let options = common::curl::CurlOptions::new()
        .insecure(true)
        .timeout(10)
        .fail_on_http_error(true)
        .resolve(&resolve_entry);
    let output = common::curl::run_curl(
        &format!("https://{}:{}/nonexistent.txt", sni, server_port),
        options,
    )
    .await?;

    assert!(
        !output.status.success(),
        "Expected failure for non-existent file"
    );

    // Test: Path traversal should be blocked
    let options = common::curl::CurlOptions::new()
        .insecure(true)
        .timeout(10)
        .fail_on_http_error(true)
        .resolve(&resolve_entry);
    let output = common::curl::run_curl(
        &format!("https://{}:{}/subdir/../../../etc/passwd", sni, server_port),
        options,
    )
    .await?;

    assert!(
        !output.status.success(),
        "Expected failure for path traversal attempt"
    );

    Ok(())
}

/// Test that valid proxy requests still work when fallback is configured
#[tokio::test]
async fn test_shoes_naiveproxy_with_fallback_proxy_still_works()
-> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    use tempfile::tempdir;

    // Create a temp directory for fallback
    let temp_dir = tempdir()?;
    fs::write(temp_dir.path().join("index.html"), b"<html>Fallback</html>")?;
    let fallback_path = temp_dir.path().to_str().unwrap();

    // Build fixture with both fallback and local server
    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_client()
        .with_shoes_naiveproxy_server_with_fallback(
            "naiveuser",
            "naivepass123",
            "test.naive.local",
            fallback_path,
        )
        .with_local_http_server()
        .build()
        .await?;

    // Test: Normal proxy request should work (authenticated CONNECT)
    let body = fixture.test_local_server("/bytes/1024", false).await?;
    assert_eq!(body.len(), 1024, "Expected 1024 bytes through proxy");

    Ok(())
}

// Probe Resistance Tests
// These tests verify that the server behaves like a normal HTTPS server
// when accessed by non-NaiveProxy clients (browsers, censors, etc.)

/// Test HTTP/1.1 probe resistance - CONNECT should return 400, not reveal proxy
#[tokio::test]
async fn test_naiveproxy_probe_resistance_http11_connect() -> Result<(), Box<dyn std::error::Error>>
{
    use std::fs;
    use tempfile::tempdir;

    let temp_dir = tempdir()?;
    fs::write(temp_dir.path().join("index.html"), b"<html>Fallback</html>")?;
    let fallback_path = temp_dir.path().to_str().unwrap();

    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_server_with_fallback(
            "naiveuser",
            "naivepass123",
            "test.naive.local",
            fallback_path,
        )
        .build()
        .await?;

    let server_ip = fixture.entry_ip();
    let server_port = fixture.entry_port();
    let sni = "test.naive.local";
    let resolve_entry = format!("{}:{}:{}", sni, server_port, server_ip);

    // HTTP/1.1 CONNECT should return 400 Bad Request (not 407 Proxy Auth Required)
    let options = common::curl::CurlOptions::new()
        .insecure(true)
        .timeout(10)
        .http_version("1.1")
        .method("CONNECT")
        .headers_to_stderr(true)
        .resolve(&resolve_entry);
    let output =
        common::curl::run_curl(&format!("https://{}:{}/", sni, server_port), options).await?;

    assert_eq!(common::curl::response_status(&output), Some(400));

    Ok(())
}

/// Test HTTP/1.1 probe resistance - POST should return 400
#[tokio::test]
async fn test_naiveproxy_probe_resistance_http11_post() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    use tempfile::tempdir;

    let temp_dir = tempdir()?;
    fs::write(temp_dir.path().join("index.html"), b"<html>Fallback</html>")?;
    let fallback_path = temp_dir.path().to_str().unwrap();

    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_server_with_fallback(
            "naiveuser",
            "naivepass123",
            "test.naive.local",
            fallback_path,
        )
        .build()
        .await?;

    let server_ip = fixture.entry_ip();
    let server_port = fixture.entry_port();
    let sni = "test.naive.local";
    let resolve_entry = format!("{}:{}:{}", sni, server_port, server_ip);

    // HTTP/1.1 POST should return 400 Bad Request
    let options = common::curl::CurlOptions::new()
        .insecure(true)
        .timeout(10)
        .http_version("1.1")
        .method("POST")
        .headers_to_stderr(true)
        .resolve(&resolve_entry);
    let output =
        common::curl::run_curl(&format!("https://{}:{}/", sni, server_port), options).await?;

    assert_eq!(common::curl::response_status(&output), Some(400));

    Ok(())
}

/// Test HTTP/1.1 probe resistance - OPTIONS should return 200 OK
#[tokio::test]
async fn test_naiveproxy_probe_resistance_http11_options() -> Result<(), Box<dyn std::error::Error>>
{
    use std::fs;
    use tempfile::tempdir;

    let temp_dir = tempdir()?;
    fs::write(temp_dir.path().join("index.html"), b"<html>Fallback</html>")?;
    let fallback_path = temp_dir.path().to_str().unwrap();

    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_server_with_fallback(
            "naiveuser",
            "naivepass123",
            "test.naive.local",
            fallback_path,
        )
        .build()
        .await?;

    let server_ip = fixture.entry_ip();
    let server_port = fixture.entry_port();
    let sni = "test.naive.local";
    let resolve_entry = format!("{}:{}:{}", sni, server_port, server_ip);

    // HTTP/1.1 OPTIONS should return 200 OK
    let options = common::curl::CurlOptions::new()
        .insecure(true)
        .timeout(10)
        .http_version("1.1")
        .method("OPTIONS")
        .headers_to_stderr(true)
        .resolve(&resolve_entry);
    let output =
        common::curl::run_curl(&format!("https://{}:{}/", sni, server_port), options).await?;

    assert_eq!(common::curl::response_status(&output), Some(200));

    Ok(())
}

/// Test HTTP/2 probe resistance - POST should return 400
#[tokio::test]
async fn test_naiveproxy_probe_resistance_http2_post() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    use tempfile::tempdir;

    let temp_dir = tempdir()?;
    fs::write(temp_dir.path().join("index.html"), b"<html>Fallback</html>")?;
    let fallback_path = temp_dir.path().to_str().unwrap();

    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_server_with_fallback(
            "naiveuser",
            "naivepass123",
            "test.naive.local",
            fallback_path,
        )
        .build()
        .await?;

    let server_ip = fixture.entry_ip();
    let server_port = fixture.entry_port();
    let sni = "test.naive.local";
    let resolve_entry = format!("{}:{}:{}", sni, server_port, server_ip);

    // HTTP/2 POST should return 400 Bad Request
    let options = common::curl::CurlOptions::new()
        .insecure(true)
        .timeout(10)
        .http_version("2")
        .method("POST")
        .headers_to_stderr(true)
        .resolve(&resolve_entry);
    let output =
        common::curl::run_curl(&format!("https://{}:{}/", sni, server_port), options).await?;

    assert_eq!(common::curl::response_status(&output), Some(400));

    Ok(())
}

/// Test HTTP/2 probe resistance - OPTIONS should return 200 OK
#[tokio::test]
async fn test_naiveproxy_probe_resistance_http2_options() -> Result<(), Box<dyn std::error::Error>>
{
    use std::fs;
    use tempfile::tempdir;

    let temp_dir = tempdir()?;
    fs::write(temp_dir.path().join("index.html"), b"<html>Fallback</html>")?;
    let fallback_path = temp_dir.path().to_str().unwrap();

    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_server_with_fallback(
            "naiveuser",
            "naivepass123",
            "test.naive.local",
            fallback_path,
        )
        .build()
        .await?;

    let server_ip = fixture.entry_ip();
    let server_port = fixture.entry_port();
    let sni = "test.naive.local";
    let resolve_entry = format!("{}:{}:{}", sni, server_port, server_ip);

    // HTTP/2 OPTIONS should return 200 OK
    let options = common::curl::CurlOptions::new()
        .insecure(true)
        .timeout(10)
        .http_version("2")
        .method("OPTIONS")
        .headers_to_stderr(true)
        .resolve(&resolve_entry);
    let output =
        common::curl::run_curl(&format!("https://{}:{}/", sni, server_port), options).await?;

    assert_eq!(common::curl::response_status(&output), Some(200));

    Ok(())
}

/// Test no fallback path configured - GET should return 401 Unauthorized
#[tokio::test]
async fn test_naiveproxy_no_fallback_returns_401() -> Result<(), Box<dyn std::error::Error>> {
    // Server without fallback path
    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_server()
        .build()
        .await?;

    let server_ip = fixture.entry_ip();
    let server_port = fixture.entry_port();
    let sni = "test.naive.local";
    let resolve_entry = format!("{}:{}:{}", sni, server_port, server_ip);

    // Direct GET should return 401 Unauthorized (not 407 Proxy Auth Required)
    let options = common::curl::CurlOptions::new()
        .insecure(true)
        .timeout(10)
        .headers_to_stderr(true)
        .resolve(&resolve_entry);
    let output =
        common::curl::run_curl(&format!("https://{}:{}/", sni, server_port), options).await?;

    assert_eq!(common::curl::response_status(&output), Some(401));

    Ok(())
}

/// Test HEAD returns headers but no body
#[tokio::test]
async fn test_naiveproxy_head_request() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    use tempfile::tempdir;

    let temp_dir = tempdir()?;
    let content = b"This is test content for HEAD request";
    fs::write(temp_dir.path().join("test.txt"), content)?;
    let fallback_path = temp_dir.path().to_str().unwrap();

    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_server_with_fallback(
            "naiveuser",
            "naivepass123",
            "test.naive.local",
            fallback_path,
        )
        .build()
        .await?;

    let server_ip = fixture.entry_ip();
    let server_port = fixture.entry_port();
    let sni = "test.naive.local";
    let resolve_entry = format!("{}:{}:{}", sni, server_port, server_ip);

    // HEAD should return headers (including content-length) but empty body
    let options = common::curl::CurlOptions::new()
        .insecure(true)
        .timeout(10)
        .method("HEAD")
        .include_headers(true)
        .resolve(&resolve_entry);
    let output = common::curl::run_curl(
        &format!("https://{}:{}/test.txt", sni, server_port),
        options,
    )
    .await?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should have Content-Length header matching file size
    assert!(
        stdout.contains(&format!("content-length: {}", content.len()))
            || stdout.contains(&format!("Content-Length: {}", content.len())),
        "Expected content-length header with value {}, got: {}",
        content.len(),
        stdout
    );

    // Body should be empty (only headers in output when using -i)
    // The actual body part after headers should be empty
    let parts: Vec<&str> = stdout.splitn(2, "\r\n\r\n").collect();
    if parts.len() > 1 {
        assert!(
            parts[1].trim().is_empty(),
            "Expected empty body for HEAD, got: {}",
            parts[1]
        );
    }

    Ok(())
}
