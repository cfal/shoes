//! AnyTLS integration tests using sing-box as a peer.
use shoes_test_support as common;

use common::curl::CurlOptions;
use common::test_fixture::ProxyTestFixture;

// Basic TCP Tests

/// Test basic AnyTLS connectivity (sing-box client -> shoes server)
#[tokio::test]
async fn test_anytls_basic() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_singbox_anytls_client()
        .with_shoes_anytls_server()
        .test_local_http_hostname(1024)
        .await
}

/// Test AnyTLS with HTTPS endpoint
#[tokio::test]
async fn test_anytls_https() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_anytls_client()
        .with_shoes_anytls_server()
        .with_local_https_tls13_server()
        .build()
        .await?;
    assert!(!fixture.test_local_server("/", true).await?.is_empty());
    Ok(())
}

/// Test AnyTLS with concurrent requests (multiplexing)
#[tokio::test]
async fn test_anytls_multiplex() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_anytls_client()
        .with_shoes_anytls_server()
        .with_local_http_server()
        .build()
        .await?;

    let (r1, r2, r3) = tokio::join!(
        fixture.test_local_server("/bytes/101", false),
        fixture.test_local_server("/bytes/102", false),
        fixture.test_local_server("/bytes/103", false),
    );
    assert_eq!(r1?.len(), 101);
    assert_eq!(r2?.len(), 102);
    assert_eq!(r3?.len(), 103);
    Ok(())
}

/// Test AnyTLS with wrong password (should fail)
#[tokio::test]
async fn test_anytls_wrong_password() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_anytls_client_with_params("wrongpassword", "test.anytls.local")
        .with_shoes_anytls_server_with_params("correctpassword", "test.anytls.local")
        .with_local_http_server()
        .build()
        .await?;

    let url = format!(
        "http://{}:{}/",
        fixture.local_server_ip().unwrap(),
        fixture.local_server_port().unwrap()
    );
    let output = fixture
        .test_http_with_options(
            &url,
            CurlOptions::new().timeout(10).fail_on_http_error(true),
        )
        .await?;
    assert!(!output.status.success());
    Ok(())
}

/// Test AnyTLS with wrong SNI (should fail due to no matching target)
#[tokio::test]
async fn test_anytls_wrong_sni() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_anytls_client_with_params("testpassword123", "wrong.sni.local")
        .with_shoes_anytls_server_with_params("testpassword123", "correct.sni.local")
        .with_local_http_server()
        .build()
        .await?;

    let url = format!(
        "http://{}:{}/",
        fixture.local_server_ip().unwrap(),
        fixture.local_server_port().unwrap()
    );
    let output = fixture
        .test_http_with_options(
            &url,
            CurlOptions::new().timeout(10).fail_on_http_error(true),
        )
        .await?;
    assert!(!output.status.success());
    Ok(())
}

// Local Server Tests (for controlled testing)

/// Test AnyTLS with local HTTP server
#[tokio::test]
async fn test_anytls_local_http() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_anytls_client()
        .with_shoes_anytls_server()
        .with_local_http_server()
        .build()
        .await?;

    let result = fixture.test_local_server("/", false).await?;
    assert!(
        !result.is_empty(),
        "Expected non-empty response from local HTTP server"
    );

    Ok(())
}

/// Test AnyTLS with local HTTPS server (TLS 1.3)
#[tokio::test]
async fn test_anytls_local_https_tls13() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_anytls_client()
        .with_shoes_anytls_server()
        .with_local_https_tls13_server()
        .build()
        .await?;

    let result = fixture.test_local_server("/", true).await?;
    assert!(
        !result.is_empty(),
        "Expected non-empty response from local HTTPS server"
    );

    Ok(())
}

/// Test AnyTLS large data transfer (1MB)
#[tokio::test]
async fn test_anytls_large_transfer() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_anytls_client()
        .with_shoes_anytls_server()
        .with_local_http_server()
        .build()
        .await?;

    // Test 1MB transfer
    let elapsed = fixture
        .test_local_server_streaming("/bytes/1048576", false, 60)
        .await?;

    let mb_per_sec = 1.0 / elapsed.as_secs_f64();
    eprintln!(
        "[TEST] AnyTLS 1MB transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );

    Ok(())
}

// Streaming Tests

/// Test AnyTLS streaming with 10MB transfer
#[tokio::test]
async fn test_anytls_streaming_10mb() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_anytls_client()
        .with_shoes_anytls_server()
        .with_local_http_server()
        .build()
        .await?;

    // 10MB = 10485760 bytes, timeout 60 seconds
    let elapsed = fixture
        .test_local_server_streaming("/bytes/10485760", false, 60)
        .await?;

    let mb_per_sec = 10.0 / elapsed.as_secs_f64();
    eprintln!(
        "[TEST] AnyTLS 10MB streaming completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );

    Ok(())
}

// Shoes-to-Shoes Tests (shoes client -> shoes server)

/// Test shoes AnyTLS client -> shoes AnyTLS server (basic connectivity)
#[tokio::test]
async fn test_anytls_shoes_to_shoes_basic() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_anytls_client()
        .with_shoes_anytls_server()
        .with_local_http_server()
        .build()
        .await?;
    assert!(!fixture.test_local_server("/", false).await?.is_empty());
    Ok(())
}

/// Test shoes AnyTLS client -> shoes AnyTLS server (HTTPS)
#[tokio::test]
async fn test_anytls_shoes_to_shoes_https() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_anytls_client()
        .with_shoes_anytls_server()
        .with_local_https_tls13_server()
        .build()
        .await?;
    assert!(!fixture.test_local_server("/", true).await?.is_empty());
    Ok(())
}

/// Test shoes AnyTLS client -> shoes AnyTLS server with local HTTP server
#[tokio::test]
async fn test_anytls_shoes_to_shoes_local() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_anytls_client()
        .with_shoes_anytls_server()
        .with_local_http_server()
        .build()
        .await?;

    let result = fixture.test_local_server("/", false).await?;
    assert!(
        !result.is_empty(),
        "Expected non-empty response from local HTTP server"
    );

    Ok(())
}

/// Test shoes AnyTLS client -> shoes AnyTLS server (1MB transfer)
#[tokio::test]
async fn test_anytls_shoes_to_shoes_1mb() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_anytls_client()
        .with_shoes_anytls_server()
        .with_local_http_server()
        .build()
        .await?;

    // Test 1MB transfer
    let elapsed = fixture
        .test_local_server_streaming("/bytes/1048576", false, 60)
        .await?;

    let mb_per_sec = 1.0 / elapsed.as_secs_f64();
    eprintln!(
        "[TEST] Shoes-to-Shoes AnyTLS 1MB transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );

    Ok(())
}

// Bidirectional Interop Tests (shoes client -> sing-box server)

/// Test shoes AnyTLS client connecting to sing-box AnyTLS server
#[tokio::test]
async fn test_anytls_shoes_to_singbox_basic() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_shoes_anytls_client()
        .with_singbox_anytls_server()
        .test_local_http_hostname(1024)
        .await
}

/// Test shoes AnyTLS client to sing-box server with HTTPS
#[tokio::test]
async fn test_anytls_shoes_to_singbox_https() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_anytls_client()
        .with_singbox_anytls_server()
        .with_local_https_tls13_server()
        .build()
        .await?;
    assert!(!fixture.test_local_server("/", true).await?.is_empty());
    Ok(())
}

/// Test shoes AnyTLS client to sing-box server with local HTTP server
#[tokio::test]
async fn test_anytls_shoes_to_singbox_local() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_anytls_client()
        .with_singbox_anytls_server()
        .with_local_http_server()
        .build()
        .await?;

    let result = fixture.test_local_server("/", false).await?;
    assert!(
        !result.is_empty(),
        "Expected non-empty response from local HTTP server"
    );

    Ok(())
}

/// Test shoes AnyTLS client to sing-box server - 1MB transfer
#[tokio::test]
async fn test_anytls_shoes_to_singbox_1mb() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_anytls_client()
        .with_singbox_anytls_server()
        .with_local_http_server()
        .build()
        .await?;

    // Test 1MB transfer
    let elapsed = fixture
        .test_local_server_streaming("/bytes/1048576", false, 60)
        .await?;

    let mb_per_sec = 1.0 / elapsed.as_secs_f64();
    eprintln!(
        "[TEST] Shoes-to-Singbox AnyTLS 1MB transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );

    Ok(())
}

// Stream lifecycle tests

/// Test rapid stream open/close cycles leave the session usable
///
/// Repeatedly creates and closes streams, then verifies that another request succeeds.
#[tokio::test]
async fn test_anytls_rapid_stream_cycles() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_anytls_client()
        .with_shoes_anytls_server()
        .with_local_http_server()
        .build()
        .await?;

    const NUM_CYCLES: usize = 100;
    eprintln!(
        "[TEST] Running {} rapid stream open/close cycles",
        NUM_CYCLES
    );

    // Run many quick requests in sequence
    for i in 0..NUM_CYCLES {
        fixture
            .test_local_server("/", false)
            .await
            .map_err(|error| format!("request {i} failed: {error}"))?;
    }

    eprintln!(
        "[TEST] Completed {} cycles, verifying session still healthy",
        NUM_CYCLES
    );

    // Final request should still work (proves no resource exhaustion)
    let result = fixture.test_local_server("/bytes/1024", false).await?;
    assert!(!result.is_empty(), "Final request should return data");

    eprintln!("[TEST] Rapid stream cycles test passed!");
    Ok(())
}

/// Test concurrent streams can close simultaneously without exhausting the session
#[tokio::test]
async fn test_anytls_concurrent_stream_cleanup() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_anytls_client()
        .with_shoes_anytls_server()
        .with_local_http_server()
        .build()
        .await?;

    const NUM_BATCHES: usize = 10;
    const STREAMS_PER_BATCH: usize = 5;

    eprintln!(
        "[TEST] Running {} batches of {} concurrent streams",
        NUM_BATCHES, STREAMS_PER_BATCH
    );

    for batch in 0..NUM_BATCHES {
        // Launch concurrent requests using fixed paths
        let (r1, r2, r3, r4, r5) = tokio::join!(
            fixture.test_local_server("/bytes/1024", false),
            fixture.test_local_server("/bytes/1124", false),
            fixture.test_local_server("/bytes/1224", false),
            fixture.test_local_server("/bytes/1324", false),
            fixture.test_local_server("/bytes/1424", false),
        );

        for (index, result) in [r1, r2, r3, r4, r5].into_iter().enumerate() {
            result.map_err(|error| format!("batch {batch} stream {index} failed: {error}"))?;
        }
    }

    // Verify session is still healthy after all the churn
    let final_result = fixture.test_local_server("/bytes/2048", false).await?;
    assert!(!final_result.is_empty());

    eprintln!("[TEST] Concurrent stream cleanup test passed!");
    Ok(())
}
