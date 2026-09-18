//! TUIC v5 integration tests using sing-box as a peer.
use shoes_test_support as common;

// Import shared test infrastructure
use common::test_fixture::ProxyTestFixture;

/// Test shoes TUIC server with sing-box client
/// Chain: curl -> sing-box HTTP proxy (TUIC client) -> shoes TUIC server -> local HTTPS
#[tokio::test]
async fn test_shoes_tuic_server() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_singbox_tuic_client()
        .with_shoes_tuic_server()
        .test_local_https_tls13(1024)
        .await
}

/// Test shoes TUIC server with sing-box client using local HTTP server
/// Chain: curl -> sing-box HTTP proxy (TUIC client) -> shoes TUIC server -> local HTTP server
#[tokio::test]
async fn test_shoes_tuic_server_local_http() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_singbox_tuic_client()
        .with_shoes_tuic_server()
        .test_local_http_hostname(10_000)
        .await
}

/// Test shoes TUIC server with custom password
/// Ensures UUID and password authentication works correctly
#[tokio::test]
async fn test_shoes_tuic_server_custom_password() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_singbox_tuic_client_with_password("custom_tuic_password_123")
        .with_shoes_tuic_server_with_password("custom_tuic_password_123")
        .test_local_https_tls13(1024)
        .await
}

/// Test shoes TUIC server with large data transfer
/// Ensures the protocol handles larger payloads correctly
#[tokio::test]
async fn test_shoes_tuic_server_large_transfer() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_tuic_client()
        .with_shoes_tuic_server()
        .with_local_http_server()
        .build()
        .await?;

    // Test with 200KB response
    let body = fixture.test_local_server("/bytes/200000", false).await?;
    assert_eq!(body.len(), 200000, "Expected exactly 200000 bytes");
    Ok(())
}
