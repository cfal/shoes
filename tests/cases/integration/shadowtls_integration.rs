//! ShadowTLS v3 with a local TLS handshake server, so no Internet access is needed.
//!
//! Chain: curl -> shoes HTTP proxy (ShadowTLS client) -> shoes ShadowTLS+VLESS server
//! -> local HTTP(S) server. Remote-handshake and sing-box cases depend on a public
//! handshake server and live in the `external_network` target.
use shoes_test_support as common;

use common::test_fixture::ProxyTestFixture;

const SHADOWTLS_PASSWORD: &str = "test-shadowtls-password-123";

async fn local_fixture(
    https_destination: bool,
) -> Result<common::test_fixture::BuiltFixture, Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_shadowtls_client(SHADOWTLS_PASSWORD, "test.local")
        .with_shoes_shadowtls_local_server(SHADOWTLS_PASSWORD);
    let fixture = if https_destination {
        fixture.with_local_https_tls13_server()
    } else {
        fixture.with_local_http_server()
    };
    fixture.build().await
}

#[tokio::test]
async fn test_shoes_shadowtls_local_http_1byte() -> Result<(), Box<dyn std::error::Error>> {
    let body = local_fixture(false)
        .await?
        .test_local_server("/bytes/1", false)
        .await?;
    assert_eq!(body.len(), 1, "Expected exactly 1 byte");
    Ok(())
}

/// Exercises framing across many ShadowTLS application-data records.
#[tokio::test]
async fn test_shoes_shadowtls_local_http_200kb() -> Result<(), Box<dyn std::error::Error>> {
    let body = local_fixture(false)
        .await?
        .test_local_server("/bytes/204800", false)
        .await?;
    assert_eq!(body.len(), 204800, "Expected exactly 200KB");
    Ok(())
}

/// TLS 1.3 inside ShadowTLS.
#[tokio::test]
async fn test_shoes_shadowtls_local_https_tls13() -> Result<(), Box<dyn std::error::Error>> {
    let body = local_fixture(true)
        .await?
        .test_local_server("/bytes/1", true)
        .await?;
    assert_eq!(body.len(), 1, "Expected exactly 1 byte over HTTPS");
    Ok(())
}
