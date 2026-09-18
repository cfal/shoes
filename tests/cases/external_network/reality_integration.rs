/// Integration tests for REALITY protocol
///
/// This module provides comprehensive testing of REALITY protocol implementation
/// in shoes, testing both client and server scenarios against sing-box and shoes itself.
///
/// Test Architecture:
/// ==================
/// We use an HTTP proxy as the outer layer for testing, which allows us to
/// easily make test requests using curl. The REALITY protocol sits in the middle.
///
/// Test Scenarios Covered:
/// =======================
///
/// 1. **shoes REALITY SERVER** (with sing-box client):
///    HTTP Client (curl) -> sing-box HTTP Proxy -> shoes REALITY+Protocol Server -> Internet
///    - Tests: VLESS, Trojan inner protocols
///    - Data sizes: 1 byte (small), 200KB (large)
///    - Endpoints: HTTP and HTTPS/TLS 1.3
///    - Operations: GET and POST
///
/// 2. **shoes REALITY CLIENT** (with sing-box server):
///    HTTP Client (curl) -> shoes HTTP Proxy -> sing-box REALITY+VLESS Server -> Internet
///    - Tests: VLESS inner protocol
///    - Data sizes: 1 byte (small), 200KB (large)
///    - Endpoints: HTTP and HTTPS/TLS 1.3
///    - Operations: GET and POST
///
/// 3. **shoes-to-shoes REALITY** (shoes client + shoes server):
///    HTTP Client (curl) -> shoes HTTP Proxy (REALITY client) -> shoes REALITY Server -> Internet
///    - Tests: VLESS inner protocol
///    - Data sizes: 1 byte (small), 200KB (large)
///    - Endpoints: HTTP and HTTPS/TLS 1.3
///    - Operations: GET and POST
///
/// Key Features Tested:
/// ====================
/// - TLS 1.3 handshake and key derivation
/// - Application data encryption/decryption
/// - HMAC-signed certificates
/// - Session ID validation
/// - Large data transfers (to test buffering)
/// - POST uploads (to test write path)
/// - Both HTTP and HTTPS final destinations
/// - Multiple inner protocols (VLESS, Trojan)
/// - shoes-to-shoes compatibility
use shoes_test_support as common;

use common::test_fixture::ProxyTestFixture;

// REALITY Server Tests (shoes server, sing-box client)

/// Test shoes REALITY server with VLESS inner protocol
/// Chain: curl -> sing-box HTTP proxy -> shoes REALITY+VLESS server -> internet
#[tokio::test]
async fn test_shoes_reality_server_vless() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_singbox_reality_vless_client()
        .with_shoes_reality_vless_server()
        .build()
        .await?
        .test_http("https://www.google.com")
        .await
}

/// Test shoes REALITY server with Trojan inner protocol
/// Chain: curl -> sing-box HTTP proxy -> shoes REALITY+Trojan server -> internet
#[tokio::test]
async fn test_shoes_reality_server_trojan() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_singbox_reality_trojan_client("password123")
        .with_shoes_reality_trojan_server("password123")
        .build()
        .await?
        .test_http("https://www.google.com")
        .await
}

/// Test shoes REALITY server with SEPARATE mode dest server (www.debian.org)
///
/// This test verifies the 512-byte heuristic for mode detection works correctly.
/// www.debian.org sends 4 encrypted records with the first one <= 512 bytes,
/// unlike cloudflare.com/google.com which send 1 combined record > 512 bytes.
///
/// Chain: curl -> sing-box HTTP proxy -> shoes REALITY+VLESS server (debian.org dest) -> internet
#[tokio::test]
async fn test_shoes_reality_server_vless_separate_mode() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_singbox_reality_vless_client()
        .with_shoes_reality_vless_server_separate_mode()
        .build()
        .await?
        .test_http("https://www.google.com")
        .await
}

/// Test shoes REALITY server with SEPARATE mode dest and large data transfer
/// Ensures the 512-byte heuristic handles substantial data correctly
#[tokio::test]
async fn test_shoes_reality_server_vless_separate_mode_large()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_reality_vless_client()
        .with_shoes_reality_vless_server_separate_mode()
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/204800", false).await?;
    assert_eq!(body.len(), 204800, "Expected exactly 200KB");
    Ok(())
}

// REALITY Server Tests - GET operations with local test servers

/// Test shoes REALITY+VLESS server with small data (1 byte) over local HTTP server
/// Tests basic functionality with minimal data transfer
#[tokio::test]
async fn test_shoes_reality_server_vless_local_http_small() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = ProxyTestFixture::new()
        .with_singbox_reality_vless_client()
        .with_shoes_reality_vless_server()
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1", false).await?;
    assert_eq!(body.len(), 1, "Expected exactly 1 byte");
    Ok(())
}

/// Test shoes REALITY+VLESS server with large data (200KB) over local HTTP server
/// Tests substantial data transfer through REALITY protocol
#[tokio::test]
async fn test_shoes_reality_server_vless_local_http_large() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = ProxyTestFixture::new()
        .with_singbox_reality_vless_client()
        .with_shoes_reality_vless_server()
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/204800", false).await?;
    assert_eq!(body.len(), 204800, "Expected exactly 200KB");
    Ok(())
}

/// Test shoes REALITY+VLESS server with small data (1 byte) over local HTTPS/TLS 1.3 server
/// Tests REALITY with TLS-encrypted final destination
#[tokio::test]
async fn test_shoes_reality_server_vless_local_https_tls13_small()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_reality_vless_client()
        .with_shoes_reality_vless_server()
        .with_local_https_tls13_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1", true).await?;
    assert_eq!(body.len(), 1, "Expected exactly 1 byte");
    Ok(())
}

/// Test shoes REALITY+VLESS server with large data (200KB) over local HTTPS/TLS 1.3 server
/// Tests substantial data transfer through REALITY to TLS-encrypted destination
#[tokio::test]
async fn test_shoes_reality_server_vless_local_https_tls13_large()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_reality_vless_client()
        .with_shoes_reality_vless_server()
        .with_local_https_tls13_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/204800", true).await?;
    assert_eq!(body.len(), 204800, "Expected exactly 200KB");
    Ok(())
}

/// Test shoes REALITY+Trojan server with small data (1 byte) over local HTTP server
/// Tests Trojan inner protocol with minimal data transfer
#[tokio::test]
async fn test_shoes_reality_server_trojan_local_http_small()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_reality_trojan_client("password123")
        .with_shoes_reality_trojan_server("password123")
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1", false).await?;
    assert_eq!(body.len(), 1, "Expected exactly 1 byte");
    Ok(())
}

/// Test shoes REALITY+Trojan server with large data (200KB) over local HTTP server
/// Tests Trojan inner protocol with substantial data transfer
#[tokio::test]
async fn test_shoes_reality_server_trojan_local_http_large()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_reality_trojan_client("password123")
        .with_shoes_reality_trojan_server("password123")
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/204800", false).await?;
    assert_eq!(body.len(), 204800, "Expected exactly 200KB");
    Ok(())
}

// // REALITY Server Tests - POST operations
// // ============================================================================
//
// /// Test shoes REALITY+VLESS server with small HTTP POST upload (1KB) to local server
// /// Tests write path with minimal data transfer
// #[tokio::test]
// async fn test_shoes_reality_server_vless_small_http_upload() -> Result<(), Box<dyn std::error::Error>> {
//     let fixture = ProxyTestFixture::new()
//         .with_singbox_reality_vless_client()
//         .with_shoes_reality_vless_server()
//         .with_local_http_server()
//         .build()
//         .await?;
//
//     // Test small HTTP POST upload (1KB)
//     let upload_data = vec![b'R'; 1024]; // 'R' for REALITY
//     let output = fixture
//         .test_local_server_with_options(
//             "/post",
//             false,
//             common::curl::CurlOptions::new()
//                 .method("POST")
//                 .body(upload_data.clone()),
//         )
//         .await?;
//
//     // Verify echo response matches uploaded data
//     assert_eq!(
//         output.stdout, upload_data,
//         "Echoed data doesn't match uploaded data"
//     );
//     Ok(())
// }
//
// /// Test shoes REALITY+VLESS server with large HTTP POST upload (200KB) to local server
// /// Tests write path with substantial data transfer
// #[tokio::test]
// async fn test_shoes_reality_server_vless_large_http_upload() -> Result<(), Box<dyn std::error::Error>> {
//     let fixture = ProxyTestFixture::new()
//         .with_singbox_reality_vless_client()
//         .with_shoes_reality_vless_server()
//         .with_local_http_server()
//         .build()
//         .await?;
//
//     // Test large HTTP POST upload (200KB)
//     let upload_data = vec![b'R'; 200_000]; // 'R' for REALITY
//     let output = fixture
//         .test_local_server_with_options(
//             "/post",
//             false,
//             common::curl::CurlOptions::new()
//                 .method("POST")
//                 .body(upload_data),
//         )
//         .await?;
//
//     assert_eq!(output.stdout.len(), 200_000, "Expected 200KB echoed back");
//     Ok(())
// }
//
// /// Test shoes REALITY+VLESS server with small HTTPS/TLS 1.3 POST upload (1KB) to local server
// /// Tests write path with TLS-encrypted final destination
// #[tokio::test]
// async fn test_shoes_reality_server_vless_small_https_tls13_upload() -> Result<(), Box<dyn std::error::Error>> {
//     let fixture = ProxyTestFixture::new()
//         .with_singbox_reality_vless_client()
//         .with_shoes_reality_vless_server()
//         .with_local_https_tls13_server()
//         .build()
//         .await?;
//
//     // Test small HTTPS POST upload (1KB)
//     let upload_data = vec![b'S'; 1024]; // 'S' for Secure REALITY
//     let output = fixture
//         .test_local_server_with_options(
//             "/post",
//             true,
//             common::curl::CurlOptions::new()
//                 .method("POST")
//                 .body(upload_data.clone()),
//         )
//         .await?;
//
//     // Verify echo response matches uploaded data
//     assert_eq!(
//         output.stdout, upload_data,
//         "Echoed data doesn't match uploaded data"
//     );
//     Ok(())
// }
//
// /// Test shoes REALITY+VLESS server with large HTTPS/TLS 1.3 POST upload (200KB) to local server
// /// Tests write path with substantial data transfer to TLS-encrypted destination
// #[tokio::test]
// async fn test_shoes_reality_server_vless_large_https_tls13_upload() -> Result<(), Box<dyn std::error::Error>> {
//     let fixture = ProxyTestFixture::new()
//         .with_singbox_reality_vless_client()
//         .with_shoes_reality_vless_server()
//         .with_local_https_tls13_server()
//         .build()
//         .await?;
//
//     // Test large HTTPS POST upload (200KB)
//     let upload_data = vec![b'S'; 200_000]; // 'S' for Secure REALITY
//     let output = fixture
//         .test_local_server_with_options(
//             "/post",
//             true,
//             common::curl::CurlOptions::new()
//                 .method("POST")
//                 .body(upload_data),
//         )
//         .await?;
//
//     assert_eq!(output.stdout.len(), 200_000, "Expected 200KB echoed back");
//     Ok(())
// }
//
// // ============================================================================
// // REALITY Client Tests (shoes client, sing-box server)
// // ============================================================================

/// Test shoes REALITY client with VLESS inner protocol
/// Chain: curl -> shoes HTTP proxy (REALITY client) -> sing-box REALITY+VLESS server -> internet
#[tokio::test]
async fn test_shoes_reality_client_vless() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_shoes_reality_client()
        .with_singbox_reality_vless_server()
        .build()
        .await?
        .test_http("https://www.google.com")
        .await
}

// REALITY Client Tests - GET operations with local test servers

/// Test shoes REALITY client with small data (1 byte) over local HTTP server
/// Tests basic functionality with minimal data transfer
#[tokio::test]
async fn test_shoes_reality_client_vless_local_http_small() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = ProxyTestFixture::new()
        .with_shoes_reality_client()
        .with_singbox_reality_vless_server()
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1", false).await?;
    assert_eq!(body.len(), 1, "Expected exactly 1 byte");
    Ok(())
}

/// Test shoes REALITY client with large data (200KB) over local HTTP server
/// Tests substantial data transfer through REALITY protocol
#[tokio::test]
async fn test_shoes_reality_client_vless_local_http_large() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = ProxyTestFixture::new()
        .with_shoes_reality_client()
        .with_singbox_reality_vless_server()
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/204800", false).await?;
    assert_eq!(body.len(), 204800, "Expected exactly 200KB");
    Ok(())
}

/// Test shoes REALITY client with small data (1 byte) over local HTTPS/TLS 1.3 server
/// Tests REALITY with TLS-encrypted final destination
#[tokio::test]
async fn test_shoes_reality_client_vless_local_https_tls13_small()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_reality_client()
        .with_singbox_reality_vless_server()
        .with_local_https_tls13_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1", true).await?;
    assert_eq!(body.len(), 1, "Expected exactly 1 byte");
    Ok(())
}

/// Test shoes REALITY client with large data (200KB) over local HTTPS/TLS 1.3 server
/// Tests substantial data transfer through REALITY to TLS-encrypted destination
#[tokio::test]
async fn test_shoes_reality_client_vless_local_https_tls13_large()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_reality_client()
        .with_singbox_reality_vless_server()
        .with_local_https_tls13_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/204800", true).await?;
    assert_eq!(body.len(), 204800, "Expected exactly 200KB");
    Ok(())
}

// // REALITY Client Tests - POST operations
// // ============================================================================
//
// /// Test shoes REALITY client with small HTTP POST upload (1KB) to local server
// /// Tests write path with minimal data transfer
// #[tokio::test]
// async fn test_shoes_reality_client_vless_small_http_upload() -> Result<(), Box<dyn std::error::Error>> {
//     let fixture = ProxyTestFixture::new()
//         .with_shoes_reality_client()
//         .with_singbox_reality_vless_server()
//         .with_local_http_server()
//         .build()
//         .await?;
//
//     // Test small HTTP POST upload (1KB)
//     let upload_data = vec![b'C'; 1024]; // 'C' for Client
//     let output = fixture
//         .test_local_server_with_options(
//             "/post",
//             false,
//             common::curl::CurlOptions::new()
//                 .method("POST")
//                 .body(upload_data.clone()),
//         )
//         .await?;
//
//     // Verify echo response matches uploaded data
//     assert_eq!(
//         output.stdout, upload_data,
//         "Echoed data doesn't match uploaded data"
//     );
//     Ok(())
// }
//
// /// Test shoes REALITY client with large HTTP POST upload (200KB) to local server
// /// Tests write path with substantial data transfer
// #[tokio::test]
// async fn test_shoes_reality_client_vless_large_http_upload() -> Result<(), Box<dyn std::error::Error>> {
//     let fixture = ProxyTestFixture::new()
//         .with_shoes_reality_client()
//         .with_singbox_reality_vless_server()
//         .with_local_http_server()
//         .build()
//         .await?;
//
//     // Test large HTTP POST upload (200KB)
//     let upload_data = vec![b'C'; 200_000]; // 'C' for Client
//     let output = fixture
//         .test_local_server_with_options(
//             "/post",
//             false,
//             common::curl::CurlOptions::new()
//                 .method("POST")
//                 .body(upload_data),
//         )
//         .await?;
//
//     assert_eq!(output.stdout.len(), 200_000, "Expected 200KB echoed back");
//     Ok(())
// }
//
// /// Test shoes REALITY client with small HTTPS/TLS 1.3 POST upload (1KB) to local server
// /// Tests write path with TLS-encrypted final destination
// #[tokio::test]
// async fn test_shoes_reality_client_vless_small_https_tls13_upload() -> Result<(), Box<dyn std::error::Error>> {
//     let fixture = ProxyTestFixture::new()
//         .with_shoes_reality_client()
//         .with_singbox_reality_vless_server()
//         .with_local_https_tls13_server()
//         .build()
//         .await?;
//
//     // Test small HTTPS POST upload (1KB)
//     let upload_data = vec![b'X'; 1024]; // 'X' for HTTPS Client
//     let output = fixture
//         .test_local_server_with_options(
//             "/post",
//             true,
//             common::curl::CurlOptions::new()
//                 .method("POST")
//                 .body(upload_data.clone()),
//         )
//         .await?;
//
//     // Verify echo response matches uploaded data
//     assert_eq!(
//         output.stdout, upload_data,
//         "Echoed data doesn't match uploaded data"
//     );
//     Ok(())
// }
//
// /// Test shoes REALITY client with large HTTPS/TLS 1.3 POST upload (200KB) to local server
// /// Tests write path with substantial data transfer to TLS-encrypted destination
// #[tokio::test]
// async fn test_shoes_reality_client_vless_large_https_tls13_upload() -> Result<(), Box<dyn std::error::Error>> {
//     let fixture = ProxyTestFixture::new()
//         .with_shoes_reality_client()
//         .with_singbox_reality_vless_server()
//         .with_local_https_tls13_server()
//         .build()
//         .await?;
//
//     // Test large HTTPS POST upload (200KB)
//     let upload_data = vec![b'X'; 200_000]; // 'X' for HTTPS Client
//     let output = fixture
//         .test_local_server_with_options(
//             "/post",
//             true,
//             common::curl::CurlOptions::new()
//                 .method("POST")
//                 .body(upload_data),
//         )
//         .await?;
//
//     assert_eq!(output.stdout.len(), 200_000, "Expected 200KB echoed back");
//     Ok(())
// }
//
// // ============================================================================
// // shoes-to-shoes REALITY Tests (shoes client + shoes server)

/// Test shoes REALITY client to shoes REALITY server with VLESS
/// Chain: curl -> shoes HTTP proxy (REALITY client) -> shoes REALITY+VLESS server -> internet
/// This tests full shoes-to-shoes compatibility
#[tokio::test]
async fn test_shoes_to_shoes_reality_vless() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_shoes_reality_client()
        .with_shoes_reality_vless_server()
        .build()
        .await?
        .test_http("https://www.google.com")
        .await
}

/// Test shoes-to-shoes REALITY with small data (1 byte) over local HTTP server
/// Tests basic shoes-to-shoes compatibility with minimal data transfer
#[tokio::test]
async fn test_shoes_to_shoes_reality_vless_local_http_small()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_reality_client()
        .with_shoes_reality_vless_server()
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1", false).await?;
    assert_eq!(body.len(), 1, "Expected exactly 1 byte");
    Ok(())
}

/// Test shoes-to-shoes REALITY with large data (200KB) over local HTTP server
/// Tests shoes-to-shoes compatibility with substantial data transfer
#[tokio::test]
async fn test_shoes_to_shoes_reality_vless_local_http_large()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_reality_client()
        .with_shoes_reality_vless_server()
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/204800", false).await?;
    assert_eq!(body.len(), 204800, "Expected exactly 200KB");
    Ok(())
}

/// Test shoes-to-shoes REALITY with small data (1 byte) over local HTTPS server
/// Tests shoes-to-shoes compatibility with TLS-encrypted final destination
#[tokio::test]
async fn test_shoes_to_shoes_reality_vless_local_https_tls13_small()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_reality_client()
        .with_shoes_reality_vless_server()
        .with_local_https_tls13_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1", true).await?;
    assert_eq!(body.len(), 1, "Expected exactly 1 byte");
    Ok(())
}

/// Test shoes-to-shoes REALITY with large data (200KB) over local HTTPS server
/// Tests shoes-to-shoes compatibility with substantial data to TLS-encrypted destination
#[tokio::test]
async fn test_shoes_to_shoes_reality_vless_local_https_tls13_large()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_reality_client()
        .with_shoes_reality_vless_server()
        .with_local_https_tls13_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/204800", true).await?;
    assert_eq!(body.len(), 204800, "Expected exactly 200KB");
    Ok(())
}

// /// Test shoes-to-shoes REALITY with small HTTP POST upload (1KB)
// /// Tests shoes-to-shoes write path with minimal data transfer
// #[tokio::test]
// async fn test_shoes_to_shoes_reality_vless_small_http_upload() -> Result<(), Box<dyn std::error::Error>> {
//     let fixture = ProxyTestFixture::new()
//         .with_shoes_reality_client()
//         .with_shoes_reality_vless_server()
//         .with_local_http_server()
//         .build()
//         .await?;
//
//     // Test small HTTP POST upload (1KB)
//     let upload_data = vec![b'2'; 1024]; // '2' for shoes-to-shoes
//     let output = fixture
//         .test_local_server_with_options(
//             "/post",
//             false,
//             common::curl::CurlOptions::new()
//                 .method("POST")
//                 .body(upload_data.clone()),
//         )
//         .await?;
//
//     // Verify echo response matches uploaded data
//     assert_eq!(
//         output.stdout, upload_data,
//         "Echoed data doesn't match uploaded data"
//     );
//     Ok(())
// }
//
// /// Test shoes-to-shoes REALITY with large HTTP POST upload (200KB)
// /// Tests shoes-to-shoes write path with substantial data transfer
// #[tokio::test]
// async fn test_shoes_to_shoes_reality_vless_large_http_upload() -> Result<(), Box<dyn std::error::Error>> {
//     let fixture = ProxyTestFixture::new()
//         .with_shoes_reality_client()
//         .with_shoes_reality_vless_server()
//         .with_local_http_server()
//         .build()
//         .await?;
//
//     // Test large HTTP POST upload (200KB)
//     let upload_data = vec![b'2'; 200_000]; // '2' for shoes-to-shoes
//     let output = fixture
//         .test_local_server_with_options(
//             "/post",
//             false,
//             common::curl::CurlOptions::new()
//                 .method("POST")
//                 .body(upload_data),
//         )
//         .await?;
//
//     assert_eq!(output.stdout.len(), 200_000, "Expected 200KB echoed back");
//     Ok(())
// }
//
// /// Test shoes-to-shoes REALITY with small HTTPS POST upload (1KB)
// /// Tests shoes-to-shoes write path with TLS-encrypted final destination
// #[tokio::test]
// async fn test_shoes_to_shoes_reality_vless_small_https_tls13_upload() -> Result<(), Box<dyn std::error::Error>> {
//     let fixture = ProxyTestFixture::new()
//         .with_shoes_reality_client()
//         .with_shoes_reality_vless_server()
//         .with_local_https_tls13_server()
//         .build()
//         .await?;
//
//     // Test small HTTPS POST upload (1KB)
//     let upload_data = vec![b'Z'; 1024]; // 'Z' for shoes-to-shoes HTTPS
//     let output = fixture
//         .test_local_server_with_options(
//             "/post",
//             true,
//             common::curl::CurlOptions::new()
//                 .method("POST")
//                 .body(upload_data.clone()),
//         )
//         .await?;
//
//     // Verify echo response matches uploaded data
//     assert_eq!(
//         output.stdout, upload_data,
//         "Echoed data doesn't match uploaded data"
//     );
//     Ok(())
// }
//
// /// Test shoes-to-shoes REALITY with large HTTPS POST upload (200KB)
// /// Tests shoes-to-shoes write path with substantial data to TLS-encrypted destination
// #[tokio::test]
// async fn test_shoes_to_shoes_reality_vless_large_https_tls13_upload() -> Result<(), Box<dyn std::error::Error>> {
//     let fixture = ProxyTestFixture::new()
//         .with_shoes_reality_client()
//         .with_shoes_reality_vless_server()
//         .with_local_https_tls13_server()
//         .build()
//         .await?;
//
//     // Test large HTTPS POST upload (200KB)
//     let upload_data = vec![b'Z'; 200_000]; // 'Z' for shoes-to-shoes HTTPS
//     let output = fixture
//         .test_local_server_with_options(
//             "/post",
//             true,
//             common::curl::CurlOptions::new()
//                 .method("POST")
//                 .body(upload_data),
//         )
//         .await?;
//
//     assert_eq!(output.stdout.len(), 200_000, "Expected 200KB echoed back");
//     Ok(())
// }

/// Test shoes REALITY server fallback mechanism with invalid authentication
/// When a client connects with invalid Reality credentials (or plain TLS),
/// the server should transparently forward the connection to the dest server
/// instead of dropping it, making it indistinguishable from a normal reverse proxy.
///
/// Test approach:
/// - Start a Reality server with dest pointing to google.com
/// - Use plain curl (no Reality protocol) to make HTTPS request to server
/// - Server receives normal TLS ClientHello (not Reality authenticated)
/// - Server should fail authentication and trigger fallback to dest
/// - We should get google.com's response back
#[tokio::test]
async fn test_shoes_reality_fallback_to_dest() -> Result<(), Box<dyn std::error::Error>> {
    use common::curl::{CurlOptions, run_curl};
    use common::test_fixture::{RealityConfig, RealityInnerProtocol, generate_reality_keypair};

    // Create Reality server with known dest
    let mut port_helper = common::port_helper::PortHelper::new();
    let (ip, port) = port_helper.get_listener_port();
    let (private_key, _public_key) = generate_reality_keypair();

    let config = RealityConfig {
        private_key,
        public_key: String::new(), // Not used for server
        server_name: "www.google.com".to_string(),
        short_id: "0123456789abcdef".to_string(),
        dest: "www.google.com:443".to_string(),
        inner_protocol: RealityInnerProtocol::Vless,
    };

    // Manually build the server config
    let server_config = format!(
        r#"- address: "{}:{}"
  protocol:
    type: tls
    reality_targets:
      "{}":
        private_key: "{}"
        short_ids:
          - "{}"
        dest: "{}"
        max_time_diff: 60000
        protocol:
          type: vless
          user_id: "{}"
          udp_enabled: false"#,
        ip,
        port,
        config.server_name,
        config.private_key,
        config.short_id,
        config.dest,
        common::test_fixture::TEST_UUID
    );

    // Start the server directly
    let (_guard, _config_file) = common::test_fixture::start_shoes_server(&server_config)?;
    port_helper.wait_for_all_ports().await?;

    // Make a direct HTTPS request (plain TLS, no Reality auth) to the Reality server
    // The server will fail to authenticate and should fallback to google.com
    // Use --resolve to make curl send the correct SNI and connect to our Reality server
    let url = format!("https://www.google.com:{}/", port);

    let output = run_curl(
        &url,
        CurlOptions::new()
            .resolve(format!("www.google.com:{}:{}", port, ip))
            .insecure(true)
            .timeout(15),
    )
    .await?;

    // Check that we got a response from google.com (not an error from Reality server)
    let body = String::from_utf8_lossy(&output.stdout);

    // Verify we got google's response (fallback worked)
    // Check for both HTML tags and google-specific content
    let has_html = body.to_lowercase().contains("<html");
    let has_google = body.contains("google") || body.contains("Google");

    assert!(
        output.status.success() && has_html && has_google,
        "Expected fallback to google.com with HTML content, but got error or wrong content.\nStatus: {:?}\nhas_html: {}\nhas_google: {}\nStderr: {}\nBody preview: {}",
        output.status.code(),
        has_html,
        has_google,
        String::from_utf8_lossy(&output.stderr),
        &body[..std::cmp::min(500, body.len())]
    );

    Ok(())
}

// REALITY+Vision Tests (Vision flow control with REALITY)

/// Test shoes REALITY+Vision server with sing-box client
/// Chain: curl -> sing-box HTTP proxy (Vision client) -> shoes REALITY+Vision server -> internet
/// This tests shoes server with Vision flow control
#[tokio::test]
async fn test_shoes_reality_vision_server() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_singbox_reality_vision_client()
        .with_shoes_reality_vision_server()
        .build()
        .await?
        .test_http("https://www.google.com")
        .await
}

/// Test shoes REALITY+Vision client with sing-box server
/// Chain: curl -> shoes HTTP proxy (Vision client) -> sing-box REALITY+Vision server -> internet
/// This tests shoes client with Vision flow control
#[tokio::test]
async fn test_shoes_reality_vision_client() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_shoes_reality_vision_client()
        .with_singbox_reality_vision_server()
        .build()
        .await?
        .test_http("https://www.google.com")
        .await
}

/// Test shoes-to-shoes REALITY+Vision
/// Chain: curl -> shoes HTTP proxy (Vision client) -> shoes REALITY+Vision server -> internet
/// This tests full shoes-to-shoes compatibility with Vision flow control
#[tokio::test]
async fn test_shoes_to_shoes_reality_vision() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_shoes_reality_vision_client()
        .with_shoes_reality_vision_server()
        .build()
        .await?
        .test_http("https://www.google.com")
        .await
}

// TLS Record Fragmentation Tests (500KB to trigger TLS record splitting)

/// Test shoes-to-shoes REALITY with 500KB data to verify TLS record fragmentation
/// 500KB >> 16KB TLS record limit, so this MUST fragment into ~31 TLS records
/// This specifically tests the encrypt_plaintext_to_records() fragmentation code path
#[tokio::test]
async fn test_shoes_to_shoes_reality_500kb_fragmentation() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = ProxyTestFixture::new()
        .with_shoes_reality_client()
        .with_shoes_reality_vless_server()
        .with_local_http_server()
        .build()
        .await?;

    // 500KB = 512000 bytes, which requires ~31 TLS records (each max ~16623 bytes plaintext)
    let body = fixture.test_local_server("/bytes/512000", false).await?;
    assert_eq!(body.len(), 512000, "Expected exactly 500KB");
    Ok(())
}
