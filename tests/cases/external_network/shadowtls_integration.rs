/// ShadowTLS v3 cases that depend on a public TLS handshake server (www.cloudflare.com).
///
/// The shoes server performs its remote handshake against Cloudflare, and the sing-box
/// ShadowTLS server fixture always handshakes with it. Local-handshake cases live in the
/// `integration` target.
///
/// Chains use an HTTP proxy as the outer layer and VLESS as the inner protocol:
/// curl -> HTTP proxy (ShadowTLS client) -> ShadowTLS+VLESS server -> local HTTP server.
use shoes_test_support as common;

use common::test_fixture::ProxyTestFixture;

const SHADOWTLS_PASSWORD: &str = "test-shadowtls-password-123";

// ShadowTLS Server Tests - shoes server with remote TLS handshake

/// Test shoes ShadowTLS server with remote handshake (www.cloudflare.com)
/// Chain: curl -> shoes HTTP proxy (ShadowTLS client) -> shoes ShadowTLS+VLESS server -> local HTTP server
/// The TLS handshake is performed against the real www.cloudflare.com server
#[tokio::test]
async fn test_shoes_shadowtls_remote_server() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_shadowtls_client(SHADOWTLS_PASSWORD, "www.cloudflare.com")
        .with_shoes_shadowtls_remote_server(SHADOWTLS_PASSWORD, "www.cloudflare.com")
        .with_local_http_server()
        .build()
        .await?;

    fixture.test_local_server("/bytes/1", false).await?;
    Ok(())
}

/// Test shoes ShadowTLS server with remote handshake - large data (200KB)
#[tokio::test]
async fn test_shoes_shadowtls_remote_http_200kb() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_shadowtls_client(SHADOWTLS_PASSWORD, "www.cloudflare.com")
        .with_shoes_shadowtls_remote_server(SHADOWTLS_PASSWORD, "www.cloudflare.com")
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/204800", false).await?;
    assert_eq!(body.len(), 204800, "Expected exactly 200KB");
    Ok(())
}

// Interoperability Tests - sing-box server with shoes client

/// Test sing-box ShadowTLS server with shoes client
/// Chain: curl -> shoes HTTP proxy (ShadowTLS client) -> sing-box ShadowTLS+VLESS server -> local HTTP server
#[tokio::test]
async fn test_singbox_shadowtls_server_shoes_client() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_shadowtls_client(SHADOWTLS_PASSWORD, "www.cloudflare.com")
        .with_singbox_shadowtls_server(SHADOWTLS_PASSWORD)
        .with_local_http_server()
        .build()
        .await?;

    fixture.test_local_server("/bytes/1", false).await?;
    Ok(())
}

/// Test sing-box ShadowTLS server with shoes client - large data
#[tokio::test]
async fn test_singbox_shadowtls_server_shoes_client_200kb() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = ProxyTestFixture::new()
        .with_shoes_shadowtls_client(SHADOWTLS_PASSWORD, "www.cloudflare.com")
        .with_singbox_shadowtls_server(SHADOWTLS_PASSWORD)
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/204800", false).await?;
    assert_eq!(body.len(), 204800, "Expected exactly 200KB");
    Ok(())
}

// Interoperability Tests - shoes server with sing-box client

/// Test shoes ShadowTLS server with sing-box client
/// Chain: curl -> sing-box HTTP proxy (ShadowTLS client) -> shoes ShadowTLS+VLESS server -> local HTTP server
#[tokio::test]
async fn test_shoes_shadowtls_server_singbox_client() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_shadowtls_client(SHADOWTLS_PASSWORD, "www.cloudflare.com")
        .with_shoes_shadowtls_remote_server(SHADOWTLS_PASSWORD, "www.cloudflare.com")
        .with_local_http_server()
        .build()
        .await?;

    fixture.test_local_server("/bytes/1", false).await?;
    Ok(())
}

/// Test shoes ShadowTLS server with sing-box client - large data
#[tokio::test]
async fn test_shoes_shadowtls_server_singbox_client_200kb() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = ProxyTestFixture::new()
        .with_singbox_shadowtls_client(SHADOWTLS_PASSWORD, "www.cloudflare.com")
        .with_shoes_shadowtls_remote_server(SHADOWTLS_PASSWORD, "www.cloudflare.com")
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/204800", false).await?;
    assert_eq!(body.len(), 204800, "Expected exactly 200KB");
    Ok(())
}

// Note: Proxy chaining tests (e.g., SOCKS -> ShadowTLS) are not included because
// the test infrastructure doesn't support multiple shoes clients in a single config
// (each client generates a `client_group: default` entry, causing conflicts).
// This is a test infrastructure limitation, not a ShadowTLS implementation limitation.
