/// Integration tests for ShadowTLS v3 protocol
///
/// This module provides comprehensive testing of ShadowTLS v3 protocol implementation
/// in shoes, testing both client and server scenarios against sing-box and shoes itself.
///
/// Test Architecture:
/// ==================
/// ShadowTLS is an obfuscation layer that wraps an inner protocol (VLESS in these tests).
/// We use an HTTP proxy as the outer layer for testing, which allows us to easily make
/// test requests using curl.
///
/// Test Scenarios Covered:
/// =======================
///
/// 1. **shoes ShadowTLS SERVER with local handshake** (shoes client):
///    HTTP Client (curl) -> shoes HTTP Proxy -> shoes ShadowTLS+VLESS Server -> Local Server
///    - Tests: Local TLS handshake using test certificates
///    - Data sizes: 1 byte (small), 200KB (large)
///    - Endpoints: HTTP and HTTPS/TLS 1.3
///    - Operations: GET and POST
///
/// 2. **shoes ShadowTLS SERVER with remote handshake** (shoes client):
///    HTTP Client (curl) -> shoes HTTP Proxy -> shoes ShadowTLS+VLESS Server -> Local Server
///    - Tests: Remote TLS handshake to real server (www.cloudflare.com)
///
/// 3. **sing-box ShadowTLS SERVER** (shoes client):
///    HTTP Client (curl) -> shoes HTTP Proxy -> sing-box ShadowTLS+VLESS Server -> Local Server
///    - Tests interoperability with sing-box as server
///
/// 4. **shoes ShadowTLS CLIENT** (sing-box server):
///    HTTP Client (curl) -> sing-box HTTP Proxy -> shoes ShadowTLS+VLESS Client -> sing-box ShadowTLS Server -> Local Server
///    - Tests interoperability with sing-box as client
///
/// Key Features Tested:
/// ====================
/// - TLS 1.3 handshake (required for ShadowTLS v3)
/// - HMAC-SHA1 authentication with 4-byte truncated tags
/// - Password-based key derivation
/// - Local vs Remote TLS handshake modes
/// - Large data transfers (to test framing)
/// - Both HTTP and HTTPS final destinations
/// - shoes-to-shoes compatibility
/// - sing-box interoperability
use shoes_test_support as common;

use common::test_fixture::ProxyTestFixture;

const SHADOWTLS_PASSWORD: &str = "test-shadowtls-password-123";

// ShadowTLS Server Tests - shoes server with local TLS handshake

/// Test shoes ShadowTLS server with local handshake
/// Chain: curl -> shoes HTTP proxy (ShadowTLS client) -> shoes ShadowTLS+VLESS server -> local HTTP server
#[tokio::test]
async fn test_shoes_shadowtls_local_server() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_shadowtls_client(SHADOWTLS_PASSWORD, "test.local")
        .with_shoes_shadowtls_local_server(SHADOWTLS_PASSWORD)
        .with_local_http_server()
        .build()
        .await?;

    fixture.test_local_server("/bytes/1", false).await?;
    Ok(())
}

/// Test shoes ShadowTLS server with local handshake - small data (1 byte)
#[tokio::test]
async fn test_shoes_shadowtls_local_http_1byte() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_shadowtls_client(SHADOWTLS_PASSWORD, "test.local")
        .with_shoes_shadowtls_local_server(SHADOWTLS_PASSWORD)
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1", false).await?;
    assert_eq!(body.len(), 1, "Expected exactly 1 byte");
    Ok(())
}

/// Test shoes ShadowTLS server with local handshake - large data (200KB)
/// Tests framing and buffering with larger payloads
#[tokio::test]
async fn test_shoes_shadowtls_local_http_200kb() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_shadowtls_client(SHADOWTLS_PASSWORD, "test.local")
        .with_shoes_shadowtls_local_server(SHADOWTLS_PASSWORD)
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/204800", false).await?;
    assert_eq!(body.len(), 204800, "Expected exactly 200KB");
    Ok(())
}

/// Test shoes ShadowTLS server with local handshake - HTTPS/TLS 1.3 destination
/// Tests TLS-in-TLS scenario
#[tokio::test]
async fn test_shoes_shadowtls_local_https_tls13() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_shadowtls_client(SHADOWTLS_PASSWORD, "test.local")
        .with_shoes_shadowtls_local_server(SHADOWTLS_PASSWORD)
        .with_local_https_tls13_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1", true).await?;
    assert_eq!(body.len(), 1, "Expected exactly 1 byte over HTTPS");
    Ok(())
}

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
