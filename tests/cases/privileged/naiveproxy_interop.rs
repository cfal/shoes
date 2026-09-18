use common::test_fixture::{ProxyTestFixture, find_naive_binary};
/// Integration tests for NaiveProxy interoperability with native binaries
///
/// These tests require the native naiveproxy binaries to be installed:
/// - ~/naive/naive - NaiveProxy client (requires proper TLS certs, no insecure mode)
/// - ~/naive/caddy - Caddy with forwardproxy plugin (NaiveProxy server)
///
/// Note: Native NaiveProxy binaries are built with Chromium's network stack
/// which requires proper TLS certificate validation. This makes testing with
/// self-signed certificates difficult. The tests below are marked as ignored
/// and require additional setup to run.
///
/// To install:
///   # Download naive client
///   curl -L -o /tmp/naive.tar.xz $(curl -s https://api.github.com/repos/klzgrad/naiveproxy/releases/latest | grep linux-x64 | grep browser_download_url | cut -d'"' -f4)
///   tar -xf /tmp/naive.tar.xz -C ~/naive/
///
///   # Build caddy with forwardproxy
///   go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
///   cd ~/naive && xcaddy build --with github.com/caddyserver/forwardproxy=github.com/klzgrad/forwardproxy@naive
///
/// Run with: cargo test --test naiveproxy_interop -- --ignored
use shoes_test_support as common;

fn require_naive_client() -> std::io::Result<()> {
    find_naive_binary()
        .map(drop)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "naive binary not found"))
}

// Shoes Client -> Native NaiveProxy Server (Caddy) Tests
//
// Note: These tests may have authentication issues due to differences
// in how forwardproxy handles JSON config vs Caddyfile config.

#[tokio::test]
#[ignore = "Requires native naive caddy binary - may have auth config issues"]
async fn test_shoes_client_to_naive_caddy_server() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_client()
        .with_naive_caddy_server()
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1024", false).await?;
    assert_eq!(body, vec![b'X'; 1024]);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires native naive caddy binary - may have auth config issues"]
async fn test_shoes_client_to_naive_caddy_server_large() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_client()
        .with_naive_caddy_server()
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/65536", false).await?;
    assert_eq!(body, vec![b'X'; 65_536]);
    Ok(())
}

// Native NaiveProxy Client -> Shoes Server Tests
//
// Note: Native naive client requires proper TLS certificates - it has no
// insecure mode since it's built for production security.
// These tests use a CA cert installed to the system trust store.
// Must be run with sudo: sudo cargo test --test naiveproxy_interop -- --ignored

#[tokio::test]
#[ignore = "Requires native naive binary and sudo for CA installation"]
async fn test_naive_client_to_shoes_server() -> Result<(), Box<dyn std::error::Error>> {
    require_naive_client()?;

    let fixture = ProxyTestFixture::new()
        .with_naive_client()
        .with_shoes_naiveproxy_server_system_ca()
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1024", false).await?;
    assert_eq!(body, vec![b'X'; 1024]);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires native naive binary and sudo for CA installation"]
async fn test_naive_client_to_shoes_server_large() -> Result<(), Box<dyn std::error::Error>> {
    require_naive_client()?;

    let fixture = ProxyTestFixture::new()
        .with_naive_client()
        .with_shoes_naiveproxy_server_system_ca()
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/65536", false).await?;
    assert_eq!(body, vec![b'X'; 65_536]);
    Ok(())
}

// Native NaiveProxy Client -> Native NaiveProxy Server (Caddy) Tests

#[tokio::test]
#[ignore = "Requires both native naive binaries - native client requires proper TLS certs"]
async fn test_naive_client_to_naive_caddy_server() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_naive_client()
        .with_naive_caddy_server()
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1024", false).await?;
    assert_eq!(body, vec![b'X'; 1024]);
    Ok(())
}

// Sing-box Client -> Native NaiveProxy Server (Caddy) Tests

#[tokio::test]
#[ignore = "Requires native naive caddy binary and libcronet for sing-box naive client"]
async fn test_singbox_client_to_naive_caddy_server() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_naive_client()
        .with_naive_caddy_server()
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1024", false).await?;
    assert_eq!(body, vec![b'X'; 1024]);
    Ok(())
}

// Native NaiveProxy Client -> Sing-box Server Tests

#[tokio::test]
#[ignore = "Requires native naive binary - native client requires proper TLS certs"]
async fn test_naive_client_to_singbox_server() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_naive_client()
        .with_singbox_naive_server()
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1024", false).await?;
    assert_eq!(body, vec![b'X'; 1024]);
    Ok(())
}
