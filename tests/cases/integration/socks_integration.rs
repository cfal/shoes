use common::test_fixture::ProxyTestFixture;
/// Integration tests for SOCKS protocol
///
/// Tests SOCKS5 server/client implementations
/// Tests interoperability with sing-box
use shoes_test_support as common;

// SOCKS Server Tests (shoes as server, sing-box as client)

#[tokio::test]
async fn test_shoes_socks_server() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_singbox_socks_client()
        .with_shoes_socks_server()
        .test_local_http_hostname(1024)
        .await
}

// SOCKS Client Tests (shoes as client, sing-box as server)

#[tokio::test]
async fn test_shoes_socks_client() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_shoes_socks_client()
        .with_singbox_socks_server()
        .test_local_http_hostname(1024)
        .await
}

// SOCKS to SOCKS Tests (shoes client -> shoes server)

#[tokio::test]
async fn test_shoes_socks_to_socks() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_socks_client()
        .with_shoes_socks_server()
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1024", false).await?;
    assert_eq!(body, vec![b'X'; 1024]);
    Ok(())
}
