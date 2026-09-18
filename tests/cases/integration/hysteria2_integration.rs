//! Hysteria2 integration tests using sing-box as a peer.
use shoes_test_support as common;

// Import shared test infrastructure
use common::test_fixture::ProxyTestFixture;

/// Test shoes Hysteria2 server with sing-box client
/// Chain: curl -> sing-box HTTP proxy (Hysteria2 client) -> shoes Hysteria2 server -> local HTTPS
#[tokio::test]
async fn test_shoes_hysteria2_server() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_singbox_hysteria2_client()
        .with_shoes_hysteria2_server()
        .test_local_https_tls13(1024)
        .await
}

/// Test shoes Hysteria2 server with sing-box client using local HTTP server
/// Chain: curl -> sing-box HTTP proxy (Hysteria2 client) -> shoes Hysteria2 server -> local HTTP server
#[tokio::test]
async fn test_shoes_hysteria2_server_local_http() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_singbox_hysteria2_client()
        .with_shoes_hysteria2_server()
        .test_local_http_hostname(10_000)
        .await
}

/// Test shoes Hysteria2 server with custom password
/// Ensures password authentication works correctly
#[tokio::test]
async fn test_shoes_hysteria2_server_custom_password() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_singbox_hysteria2_client_with_password("custom_hysteria2_password_123")
        .with_shoes_hysteria2_server_with_password("custom_hysteria2_password_123")
        .test_local_https_tls13(1024)
        .await
}

/// Test shoes Hysteria2 server with large data transfer
/// Ensures the protocol handles larger payloads correctly
#[tokio::test]
async fn test_shoes_hysteria2_server_large_transfer() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_hysteria2_client()
        .with_shoes_hysteria2_server()
        .with_local_http_server()
        .build()
        .await?;

    // Test with 200KB response
    let body = fixture.test_local_server("/bytes/200000", false).await?;
    assert_eq!(body.len(), 200000, "Expected exactly 200000 bytes");
    Ok(())
}
