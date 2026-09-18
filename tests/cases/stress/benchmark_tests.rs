use common::test_fixture::{ProxyTestFixture, VmessCipher};
/// Benchmark tests for proxy protocols
///
/// These tests stream 2GB through various proxy configurations to measure throughput.
/// Tests are separated into:
/// - Non-verified: Uses curl with output discarded, fastest for pure throughput testing
/// - Verified: Computes SHA256 on both ends to verify data integrity
use shoes_test_support as common;

// REALITY Benchmark Tests

/// 2GB streaming test for REALITY+VLESS (sing-box client -> shoes server)
#[tokio::test]
async fn test_reality_vless_singbox_client_shoes_server_2gb()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_reality_vless_client()
        .with_shoes_reality_vless_server()
        .with_local_http_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes, timeout 300 seconds
    let elapsed = fixture
        .test_local_server_streaming("/bytes/2147483648", false, 300)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] REALITY+VLESS 2GB transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// 2GB streaming test for REALITY+VLESS with SHA256 verification (sing-box client -> shoes server)
#[tokio::test]
async fn test_reality_vless_singbox_client_shoes_server_2gb_verified()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_reality_vless_client()
        .with_shoes_reality_vless_server()
        .with_local_http_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes, timeout 600 seconds (longer for verification overhead)
    let elapsed = fixture
        .test_local_server_streaming_verified(2147483648, 600)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] REALITY+VLESS 2GB verified transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// 2GB streaming test for REALITY Vision over HTTPS (sing-box client -> shoes server)
#[tokio::test]
async fn test_reality_vision_https_singbox_client_shoes_server_2gb()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_reality_vision_client()
        .with_shoes_reality_vision_server()
        .with_local_https_tls13_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes, timeout 300 seconds
    let elapsed = fixture
        .test_local_server_streaming("/bytes/2147483648", true, 300)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] REALITY Vision HTTPS 2GB transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// 2GB streaming test for REALITY Vision over HTTPS with SHA256 verification (sing-box client -> shoes server)
#[tokio::test]
async fn test_reality_vision_https_singbox_client_shoes_server_2gb_verified()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_reality_vision_client()
        .with_shoes_reality_vision_server()
        .with_local_https_tls13_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes, timeout 600 seconds (longer for verification overhead)
    let elapsed = fixture
        .test_local_server_streaming_verified(2147483648, 600)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] REALITY Vision HTTPS 2GB verified transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

// VMess Benchmark Tests

/// 2GB streaming test for VMess ChaCha20-Poly1305 (sing-box client -> shoes server)
#[tokio::test]
async fn test_vmess_chacha_singbox_client_shoes_server_2gb()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_vmess_client(VmessCipher::ChaCha20Poly1305)
        .with_shoes_vmess_server(VmessCipher::ChaCha20Poly1305)
        .with_local_http_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes, timeout 300 seconds
    let elapsed = fixture
        .test_local_server_streaming("/bytes/2147483648", false, 300)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] VMess ChaCha20 2GB transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );

    Ok(())
}

/// 2GB streaming test for VMess AES-128-GCM (sing-box client -> shoes server)
#[tokio::test]
async fn test_vmess_aes_singbox_client_shoes_server_2gb() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = ProxyTestFixture::new()
        .with_singbox_vmess_client(VmessCipher::Aes128Gcm)
        .with_shoes_vmess_server(VmessCipher::Aes128Gcm)
        .with_local_http_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes, timeout 300 seconds
    let elapsed = fixture
        .test_local_server_streaming("/bytes/2147483648", false, 300)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] VMess AES-GCM 2GB transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );

    Ok(())
}

/// 2GB streaming test for VMess ChaCha20-Poly1305 with SHA256 verification (sing-box client -> shoes server)
#[tokio::test]
async fn test_vmess_chacha_singbox_client_shoes_server_2gb_verified()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_vmess_client(VmessCipher::ChaCha20Poly1305)
        .with_shoes_vmess_server(VmessCipher::ChaCha20Poly1305)
        .with_local_http_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes, timeout 600 seconds
    let elapsed = fixture
        .test_local_server_streaming_verified(2147483648, 600)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] VMess ChaCha20 2GB verified transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );

    Ok(())
}

/// 2GB streaming test for VMess AES-128-GCM with SHA256 verification (sing-box client -> shoes server)
#[tokio::test]
async fn test_vmess_aes_singbox_client_shoes_server_2gb_verified()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_vmess_client(VmessCipher::Aes128Gcm)
        .with_shoes_vmess_server(VmessCipher::Aes128Gcm)
        .with_local_http_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes, timeout 600 seconds
    let elapsed = fixture
        .test_local_server_streaming_verified(2147483648, 600)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] VMess AES-GCM 2GB verified transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );

    Ok(())
}

// Shoes-to-Shoes Benchmark Tests (no sing-box)
// These isolate shoes performance without sing-box in the path

/// 2GB streaming test for REALITY+VLESS (shoes client -> shoes server)
#[tokio::test]
async fn test_reality_vless_shoes_client_shoes_server_2gb() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = ProxyTestFixture::new()
        .with_shoes_reality_client()
        .with_shoes_reality_vless_server()
        .with_local_http_server()
        .build()
        .await?;

    let elapsed = fixture
        .test_local_server_streaming("/bytes/2147483648", false, 300)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] Shoes-to-Shoes REALITY+VLESS 2GB transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// 2GB streaming test for REALITY+VLESS with verification (shoes client -> shoes server)
#[tokio::test]
async fn test_reality_vless_shoes_client_shoes_server_2gb_verified()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_reality_client()
        .with_shoes_reality_vless_server()
        .with_local_http_server()
        .build()
        .await?;

    let elapsed = fixture
        .test_local_server_streaming_verified(2147483648, 600)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] Shoes-to-Shoes REALITY+VLESS 2GB verified transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// 2GB streaming test for REALITY Vision over HTTPS (shoes client -> shoes server)
#[tokio::test]
async fn test_reality_vision_https_shoes_client_shoes_server_2gb()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_reality_vision_client()
        .with_shoes_reality_vision_server()
        .with_local_https_tls13_server()
        .build()
        .await?;

    let elapsed = fixture
        .test_local_server_streaming("/bytes/2147483648", true, 300)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] Shoes-to-Shoes REALITY Vision HTTPS 2GB transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// 2GB streaming test for REALITY Vision over HTTPS with verification (shoes client -> shoes server)
#[tokio::test]
async fn test_reality_vision_https_shoes_client_shoes_server_2gb_verified()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_reality_vision_client()
        .with_shoes_reality_vision_server()
        .with_local_https_tls13_server()
        .build()
        .await?;

    let elapsed = fixture
        .test_local_server_streaming_verified(2147483648, 600)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] Shoes-to-Shoes REALITY Vision HTTPS 2GB verified transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// 2GB streaming test for VMess ChaCha20 (shoes client -> shoes server)
#[tokio::test]
async fn test_vmess_chacha_shoes_client_shoes_server_2gb() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = ProxyTestFixture::new()
        .with_shoes_vmess_client(VmessCipher::ChaCha20Poly1305)
        .with_shoes_vmess_server(VmessCipher::ChaCha20Poly1305)
        .with_local_http_server()
        .build()
        .await?;

    let elapsed = fixture
        .test_local_server_streaming("/bytes/2147483648", false, 300)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] Shoes-to-Shoes VMess ChaCha20 2GB transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// 2GB streaming test for VMess ChaCha20 with verification (shoes client -> shoes server)
#[tokio::test]
async fn test_vmess_chacha_shoes_client_shoes_server_2gb_verified()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_vmess_client(VmessCipher::ChaCha20Poly1305)
        .with_shoes_vmess_server(VmessCipher::ChaCha20Poly1305)
        .with_local_http_server()
        .build()
        .await?;

    let elapsed = fixture
        .test_local_server_streaming_verified(2147483648, 600)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] Shoes-to-Shoes VMess ChaCha20 2GB verified transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// 2GB streaming test for VMess AES-GCM (shoes client -> shoes server)
#[tokio::test]
async fn test_vmess_aes_shoes_client_shoes_server_2gb() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_vmess_client(VmessCipher::Aes128Gcm)
        .with_shoes_vmess_server(VmessCipher::Aes128Gcm)
        .with_local_http_server()
        .build()
        .await?;

    let elapsed = fixture
        .test_local_server_streaming("/bytes/2147483648", false, 300)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] Shoes-to-Shoes VMess AES-GCM 2GB transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// 2GB streaming test for VMess AES-GCM with verification (shoes client -> shoes server)
#[tokio::test]
async fn test_vmess_aes_shoes_client_shoes_server_2gb_verified()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_vmess_client(VmessCipher::Aes128Gcm)
        .with_shoes_vmess_server(VmessCipher::Aes128Gcm)
        .with_local_http_server()
        .build()
        .await?;

    let elapsed = fixture
        .test_local_server_streaming_verified(2147483648, 600)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] Shoes-to-Shoes VMess AES-GCM 2GB verified transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

// AnyTLS Benchmark Tests

/// 2GB streaming test for AnyTLS with verification (sing-box client -> shoes server)
#[tokio::test]
async fn test_anytls_singbox_client_shoes_server_2gb_verified()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_anytls_client()
        .with_shoes_anytls_server()
        .with_local_http_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes, timeout 600 seconds (longer for verification overhead)
    let elapsed = fixture
        .test_local_server_streaming_verified(2147483648, 600)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] AnyTLS 2GB verified transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// 2GB streaming test for AnyTLS over HTTPS (sing-box client -> shoes server)
#[tokio::test]
async fn test_anytls_https_singbox_client_shoes_server_2gb()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_anytls_client()
        .with_shoes_anytls_server()
        .with_local_https_tls13_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes, timeout 300 seconds
    let elapsed = fixture
        .test_local_server_streaming("/bytes/2147483648", true, 300)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] AnyTLS HTTPS 2GB transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// 2GB streaming test for AnyTLS over HTTPS with verification (sing-box client -> shoes server)
#[tokio::test]
async fn test_anytls_https_singbox_client_shoes_server_2gb_verified()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_anytls_client()
        .with_shoes_anytls_server()
        .with_local_https_tls13_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes, timeout 600 seconds
    let elapsed = fixture
        .test_local_server_streaming_verified(2147483648, 600)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] AnyTLS HTTPS 2GB verified transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

// AnyTLS Client Benchmark Tests (shoes client)
// These test the shoes AnyTLS client implementation

/// 2GB streaming: shoes AnyTLS client -> shoes AnyTLS server
#[tokio::test]
async fn test_anytls_shoes_client_shoes_server_2gb() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_anytls_client()
        .with_shoes_anytls_server()
        .with_local_http_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes
    let elapsed = fixture
        .test_local_server_streaming("/bytes/2147483648", false, 300)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] AnyTLS (shoes->shoes) 2GB completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// 2GB streaming: shoes AnyTLS client -> sing-box AnyTLS server
#[tokio::test]
async fn test_anytls_shoes_client_singbox_server_2gb() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_anytls_client()
        .with_singbox_anytls_server()
        .with_local_http_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes
    let elapsed = fixture
        .test_local_server_streaming("/bytes/2147483648", false, 300)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] AnyTLS (shoes->singbox) 2GB completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// 2GB streaming: sing-box AnyTLS client -> shoes AnyTLS server
#[tokio::test]
async fn test_anytls_singbox_client_shoes_server_2gb() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_anytls_client()
        .with_shoes_anytls_server()
        .with_local_http_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes
    let elapsed = fixture
        .test_local_server_streaming("/bytes/2147483648", false, 300)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] AnyTLS (singbox->shoes) 2GB completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// 2GB streaming: sing-box AnyTLS client -> sing-box AnyTLS server
#[tokio::test]
async fn test_anytls_singbox_client_singbox_server_2gb() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_anytls_client()
        .with_singbox_anytls_server()
        .with_local_http_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes
    let elapsed = fixture
        .test_local_server_streaming("/bytes/2147483648", false, 300)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] AnyTLS (singbox->singbox) 2GB completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

// NaiveProxy Benchmark Tests

/// 2GB streaming test for NaiveProxy (shoes client -> shoes server)
#[tokio::test]
async fn test_naiveproxy_shoes_client_shoes_server_2gb() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_client()
        .with_shoes_naiveproxy_server()
        .with_local_http_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes, timeout 300 seconds
    let elapsed = fixture
        .test_local_server_streaming("/bytes/2147483648", false, 300)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] NaiveProxy 2GB transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// 2GB streaming test for NaiveProxy with verification (shoes client -> shoes server)
#[tokio::test]
async fn test_naiveproxy_shoes_client_shoes_server_2gb_verified()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_naiveproxy_client()
        .with_shoes_naiveproxy_server()
        .with_local_http_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes, timeout 600 seconds (longer for verification overhead)
    let elapsed = fixture
        .test_local_server_streaming_verified(2147483648, 600)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] NaiveProxy 2GB verified transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

// Hysteria2 Benchmark Tests (QUIC-based protocol)

/// 2GB streaming test for Hysteria2 (sing-box client -> shoes server)
#[tokio::test]
async fn test_hysteria2_singbox_client_shoes_server_2gb() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = ProxyTestFixture::new()
        .with_singbox_hysteria2_client()
        .with_shoes_hysteria2_server()
        .with_local_http_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes, timeout 300 seconds
    let elapsed = fixture
        .test_local_server_streaming("/bytes/2147483648", false, 300)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] Hysteria2 2GB transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// 2GB streaming test for Hysteria2 with verification (sing-box client -> shoes server)
#[tokio::test]
async fn test_hysteria2_singbox_client_shoes_server_2gb_verified()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_hysteria2_client()
        .with_shoes_hysteria2_server()
        .with_local_http_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes, timeout 600 seconds (longer for verification overhead)
    let elapsed = fixture
        .test_local_server_streaming_verified(2147483648, 600)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] Hysteria2 2GB verified transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

// TUIC v5 Benchmark Tests (QUIC-based protocol)

/// 2GB streaming test for TUIC v5 (sing-box client -> shoes server)
#[tokio::test]
async fn test_tuic_singbox_client_shoes_server_2gb() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_tuic_client()
        .with_shoes_tuic_server()
        .with_local_http_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes, timeout 300 seconds
    let elapsed = fixture
        .test_local_server_streaming("/bytes/2147483648", false, 300)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] TUIC v5 2GB transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// 2GB streaming test for TUIC v5 with verification (sing-box client -> shoes server)
#[tokio::test]
async fn test_tuic_singbox_client_shoes_server_2gb_verified()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_tuic_client()
        .with_shoes_tuic_server()
        .with_local_http_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes, timeout 600 seconds (longer for verification overhead)
    let elapsed = fixture
        .test_local_server_streaming_verified(2147483648, 600)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] TUIC v5 2GB verified transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

// NOTE: Shoes-to-shoes tests for Hysteria2/TUIC are not yet available because
// only the server side has been implemented (tokio-quiche). Client implementations
// would need to be added first.
//
// Singbox-to-singbox tests are also not included due to test fixture configuration
// issues with the singbox server routing to the local test HTTP server.

// TUN + Netstack Benchmark Tests
//
// These tests measure the performance of the TUN device + netstack-smoltcp path.
// Traffic flows: test client -> TUN device -> netstack -> TCP handler -> local HTTP server
//
// **IMPORTANT**: These tests require root privileges to create TUN devices.
// Run with: `cargo test tun -- --nocapture`

/// 2GB streaming test via TUN + netstack (no verification)
/// This test streams 2GB through the TUN device and netstack TCP/IP stack.
/// Uses sudo internally for TUN device creation.
#[tokio::test]
async fn test_tun_streaming_2gb() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_tun_entry()
        .with_local_http_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes, timeout 600 seconds (TUN may be slower)
    let elapsed = fixture
        .test_local_server_streaming_via_tun("/bytes/2147483648", 600)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] TUN + netstack 2GB transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// 2GB streaming test via TUN + netstack with SHA256 verification
/// Verifies data integrity by computing SHA256 digest on both server and client.
/// Uses sudo internally for TUN device creation.
#[tokio::test]
async fn test_tun_streaming_2gb_verified() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_tun_entry()
        .with_local_http_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes, timeout 900 seconds (TUN + verification overhead)
    let elapsed = fixture
        .test_local_server_streaming_verified_via_tun(2147483648, 900)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] TUN + netstack 2GB verified transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

// H2MUX Benchmark Tests (HTTP/2 multiplexing)
//
// These tests measure h2mux performance with sing-box client and shoes server.
// H2MUX multiplexes multiple streams over a single HTTP/2 connection.

/// 2GB streaming test for VLESS+h2mux (sing-box client -> shoes server)
#[tokio::test]
async fn test_h2mux_vless_singbox_client_shoes_server_2gb() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = ProxyTestFixture::new()
        .with_singbox_h2mux_vless_client()
        .with_shoes_vless_tls_server()
        .with_local_http_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes, timeout 600 seconds
    let elapsed = fixture
        .test_local_server_streaming("/bytes/2147483648", false, 600)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] H2MUX VLESS 2GB transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// 2GB streaming test for VLESS+h2mux with verification (sing-box client -> shoes server)
#[tokio::test]
async fn test_h2mux_vless_singbox_client_shoes_server_2gb_verified()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_h2mux_vless_client()
        .with_shoes_vless_tls_server()
        .with_local_http_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes, timeout 600 seconds
    let elapsed = fixture
        .test_local_server_streaming_verified(2147483648, 600)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] H2MUX VLESS 2GB verified transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// 2GB streaming test for VLESS+h2mux (shoes client -> shoes server)
#[tokio::test]
async fn test_h2mux_vless_shoes_client_shoes_server_2gb() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = ProxyTestFixture::new()
        .with_shoes_h2mux_vless_client()
        .with_shoes_vless_tls_server()
        .with_local_http_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes, timeout 600 seconds
    let elapsed = fixture
        .test_local_server_streaming("/bytes/2147483648", false, 600)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] H2MUX VLESS (shoes->shoes) 2GB transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}

/// 2GB streaming test for VLESS+h2mux with verification (shoes client -> shoes server)
#[tokio::test]
async fn test_h2mux_vless_shoes_client_shoes_server_2gb_verified()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_shoes_h2mux_vless_client()
        .with_shoes_vless_tls_server()
        .with_local_http_server()
        .build()
        .await?;

    // 2GB = 2147483648 bytes, timeout 600 seconds
    let elapsed = fixture
        .test_local_server_streaming_verified(2147483648, 600)
        .await?;

    let mb_per_sec = 2048.0 / elapsed.as_secs_f64();
    eprintln!(
        "[BENCHMARK] H2MUX VLESS (shoes->shoes) 2GB verified transfer completed in {:.2}s ({:.2} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );
    Ok(())
}
