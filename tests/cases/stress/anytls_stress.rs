use std::error::Error;

use shoes_test_support::test_fixture::ProxyTestFixture;

#[tokio::test]
async fn test_anytls_streaming_100mb() -> Result<(), Box<dyn Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_anytls_client()
        .with_shoes_anytls_server()
        .with_local_http_server()
        .build()
        .await?;

    fixture
        .test_local_server_streaming("/bytes/104857600", false, 120)
        .await?;
    Ok(())
}
