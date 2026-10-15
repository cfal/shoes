use shoes_test_support::curl::CurlOptions;
use shoes_test_support::test_fixture::ProxyTestFixture;
use shoes_test_support::test_servers::start_reality_tls_template;

#[tokio::test]
async fn separate_mode_downloads() -> Result<(), Box<dyn std::error::Error>> {
    let template = start_reality_tls_template().await?;
    let dest = format!("localhost:{}", template.local_addr().port());
    let fixture = ProxyTestFixture::new()
        .with_singbox_reality_vless_client()
        .with_shoes_reality_vless_server_for_dest("localhost", &dest)
        .with_local_http_server()
        .build()
        .await?;

    for size in [1, 204_800] {
        let body = fixture
            .test_local_server(&format!("/bytes/{size}"), false)
            .await?;
        assert_eq!(body, vec![b'X'; size]);
    }
    Ok(())
}

#[tokio::test]
async fn separate_mode_uploads() -> Result<(), Box<dyn std::error::Error>> {
    let template = start_reality_tls_template().await?;
    let dest = format!("localhost:{}", template.local_addr().port());
    let fixture = ProxyTestFixture::new()
        .with_singbox_reality_vless_client()
        .with_shoes_reality_vless_server_for_dest("localhost", &dest)
        .with_local_http_server()
        .build()
        .await?;
    let url = format!(
        "http://{}:{}/echo",
        fixture.local_server_ip().unwrap(),
        fixture.local_server_port().unwrap(),
    );

    for size in [1, 204_800] {
        let payload: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
        let output = fixture
            .test_http_with_options(&url, CurlOptions::new().post_data(payload.clone()))
            .await?;
        assert!(
            output.status.success(),
            "curl failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, payload);
    }
    Ok(())
}
