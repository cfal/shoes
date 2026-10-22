//! ShadowTLS v3 cases whose handshake servers are local, so no Internet access is needed.
//!
//! Chain: curl -> HTTP proxy (ShadowTLS client) -> ShadowTLS+VLESS server -> local HTTP(S)
//! server, with shoes or sing-box on either ShadowTLS side. Cases against a public handshake
//! server live in the `external_network` target.
use shoes_test_support as common;

use common::test_fixture::ProxyTestFixture;
use common::test_servers::TestServer;

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

/// Starts a TLS 1.3 server for `test.local` that stands in for the real site whose
/// handshake ShadowTLS servers relay, and returns it with its certificate.
async fn handshake_server() -> Result<(TestServer, tempfile::TempPath), Box<dyn std::error::Error>>
{
    let (cert, key) = common::test_servers::generate_test_cert()?;
    let server = common::test_servers::start_tls_stream_echo_server(
        "127.0.0.1",
        0,
        cert.as_ref(),
        key.as_ref(),
        common::test_servers::TlsVersion::Tls13Only,
    )
    .await?;
    Ok((server, cert))
}

/// Relays the handshake to a separate local TLS 1.3 server, as deployments relay it to a
/// real site.
#[tokio::test]
async fn test_shoes_shadowtls_remote_handshake_to_local_tls13_server()
-> Result<(), Box<dyn std::error::Error>> {
    let (handshake_server, _cert) = handshake_server().await?;
    let body = ProxyTestFixture::new()
        .with_shoes_shadowtls_client(SHADOWTLS_PASSWORD, "test.local")
        .with_shoes_shadowtls_remote_server_at(
            SHADOWTLS_PASSWORD,
            "test.local",
            &handshake_server.local_addr().to_string(),
        )
        .with_local_http_server()
        .build()
        .await?
        .test_local_server("/bytes/204800", false)
        .await?;
    assert_eq!(body.len(), 204800, "Expected exactly 200KB");
    Ok(())
}

#[tokio::test]
async fn test_singbox_shadowtls_server_shoes_client() -> Result<(), Box<dyn std::error::Error>> {
    let (handshake_server, _cert) = handshake_server().await?;
    let fixture = ProxyTestFixture::new()
        .with_shoes_shadowtls_client(SHADOWTLS_PASSWORD, "test.local")
        .with_singbox_shadowtls_server(
            SHADOWTLS_PASSWORD,
            "127.0.0.1",
            handshake_server.local_addr().port(),
        )
        .with_local_http_server()
        .build()
        .await?;
    assert_eq!(fixture.test_local_server("/bytes/1", false).await?.len(), 1);
    let body = fixture.test_local_server("/bytes/204800", false).await?;
    assert_eq!(body.len(), 204800, "Expected exactly 200KB");
    Ok(())
}

#[tokio::test]
async fn test_shoes_shadowtls_server_singbox_client() -> Result<(), Box<dyn std::error::Error>> {
    let (handshake_server, cert) = handshake_server().await?;
    let fixture = ProxyTestFixture::new()
        .with_singbox_shadowtls_client(SHADOWTLS_PASSWORD, "test.local", cert.as_ref())
        .with_shoes_shadowtls_remote_server_at(
            SHADOWTLS_PASSWORD,
            "test.local",
            &handshake_server.local_addr().to_string(),
        )
        .with_local_http_server()
        .build()
        .await?;
    assert_eq!(fixture.test_local_server("/bytes/1", false).await?.len(), 1);
    let body = fixture.test_local_server("/bytes/204800", false).await?;
    assert_eq!(body.len(), 204800, "Expected exactly 200KB");
    Ok(())
}
