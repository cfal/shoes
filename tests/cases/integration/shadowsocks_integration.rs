use base64::engine::{Engine as _, general_purpose::STANDARD};
use common::test_fixture::{ProxyTestFixture, ShadowsocksCipher};
/// Integration tests for Shadowsocks protocol
///
/// Tests Shadowsocks server/client with different ciphers:
/// - AEAD ciphers: aes-256-gcm, aes-128-gcm, chacha20-ietf-poly1305
/// - 2022 ciphers: 2022-blake3-aes-256-gcm, 2022-blake3-aes-128-gcm, 2022-blake3-chacha20-poly1305
///
/// Tests interoperability with sing-box
use shoes_test_support as common;

const TEST_PASSWORD: &str = "test-shadowsocks-password-1234";

/// Generate a base64-encoded key of the correct length for 2022 ciphers
fn generate_2022_key(cipher: &ShadowsocksCipher) -> String {
    let key_bytes = vec![0x42u8; cipher.key_len()];
    STANDARD.encode(&key_bytes)
}

// Shadowsocks Server Tests (shoes as server, sing-box as client)

// AEAD Ciphers

#[tokio::test]
async fn test_shoes_shadowsocks_server_aes256gcm() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_singbox_shadowsocks_client(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .with_shoes_shadowsocks_server(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .test_local_http_hostname(1024)
        .await
}

#[tokio::test]
async fn test_shoes_shadowsocks_server_aes128gcm() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_singbox_shadowsocks_client(ShadowsocksCipher::Aes128Gcm, TEST_PASSWORD)
        .with_shoes_shadowsocks_server(ShadowsocksCipher::Aes128Gcm, TEST_PASSWORD)
        .test_local_http(1024)
        .await
}

#[tokio::test]
async fn test_shoes_shadowsocks_server_chacha20() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_singbox_shadowsocks_client(ShadowsocksCipher::ChaCha20IetfPoly1305, TEST_PASSWORD)
        .with_shoes_shadowsocks_server(ShadowsocksCipher::ChaCha20IetfPoly1305, TEST_PASSWORD)
        .test_local_http(1024)
        .await
}

// 2022 BLAKE3 Ciphers

#[tokio::test]
async fn test_shoes_shadowsocks_server_2022_aes256gcm() -> Result<(), Box<dyn std::error::Error>> {
    let cipher = ShadowsocksCipher::Blake3Aes256Gcm;
    let key = generate_2022_key(&cipher);
    ProxyTestFixture::new()
        .with_singbox_shadowsocks_client(cipher.clone(), &key)
        .with_shoes_shadowsocks_server(cipher, &key)
        .test_local_http(1024)
        .await
}

#[tokio::test]
async fn test_shoes_shadowsocks_server_2022_aes128gcm() -> Result<(), Box<dyn std::error::Error>> {
    let cipher = ShadowsocksCipher::Blake3Aes128Gcm;
    let key = generate_2022_key(&cipher);
    ProxyTestFixture::new()
        .with_singbox_shadowsocks_client(cipher.clone(), &key)
        .with_shoes_shadowsocks_server(cipher, &key)
        .test_local_http(1024)
        .await
}

#[tokio::test]
async fn test_shoes_shadowsocks_server_2022_chacha20() -> Result<(), Box<dyn std::error::Error>> {
    let cipher = ShadowsocksCipher::Blake3ChaCha20Poly1305;
    let key = generate_2022_key(&cipher);
    ProxyTestFixture::new()
        .with_singbox_shadowsocks_client(cipher.clone(), &key)
        .with_shoes_shadowsocks_server(cipher, &key)
        .test_local_http(1024)
        .await
}

// Shadowsocks Client Tests (shoes as client, sing-box as server)

// AEAD Ciphers

#[tokio::test]
async fn test_shoes_shadowsocks_client_aes256gcm() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_shoes_shadowsocks_client(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .with_singbox_shadowsocks_server(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .test_local_http_hostname(1024)
        .await
}

#[tokio::test]
async fn test_shoes_shadowsocks_client_aes128gcm() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_shoes_shadowsocks_client(ShadowsocksCipher::Aes128Gcm, TEST_PASSWORD)
        .with_singbox_shadowsocks_server(ShadowsocksCipher::Aes128Gcm, TEST_PASSWORD)
        .test_local_http(1024)
        .await
}

#[tokio::test]
async fn test_shoes_shadowsocks_client_chacha20() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_shoes_shadowsocks_client(ShadowsocksCipher::ChaCha20IetfPoly1305, TEST_PASSWORD)
        .with_singbox_shadowsocks_server(ShadowsocksCipher::ChaCha20IetfPoly1305, TEST_PASSWORD)
        .test_local_http(1024)
        .await
}

// 2022 BLAKE3 Ciphers

#[tokio::test]
async fn test_shoes_shadowsocks_client_2022_aes256gcm() -> Result<(), Box<dyn std::error::Error>> {
    let cipher = ShadowsocksCipher::Blake3Aes256Gcm;
    let key = generate_2022_key(&cipher);
    ProxyTestFixture::new()
        .with_shoes_shadowsocks_client(cipher.clone(), &key)
        .with_singbox_shadowsocks_server(cipher, &key)
        .test_local_http(1024)
        .await
}

#[tokio::test]
async fn test_shoes_shadowsocks_client_2022_aes128gcm() -> Result<(), Box<dyn std::error::Error>> {
    let cipher = ShadowsocksCipher::Blake3Aes128Gcm;
    let key = generate_2022_key(&cipher);
    ProxyTestFixture::new()
        .with_shoes_shadowsocks_client(cipher.clone(), &key)
        .with_singbox_shadowsocks_server(cipher, &key)
        .test_local_http(1024)
        .await
}

#[tokio::test]
async fn test_shoes_shadowsocks_client_2022_chacha20() -> Result<(), Box<dyn std::error::Error>> {
    let cipher = ShadowsocksCipher::Blake3ChaCha20Poly1305;
    let key = generate_2022_key(&cipher);
    ProxyTestFixture::new()
        .with_shoes_shadowsocks_client(cipher.clone(), &key)
        .with_singbox_shadowsocks_server(cipher, &key)
        .test_local_http(1024)
        .await
}

// Shadowsocks to Shadowsocks Tests (shoes client -> shoes server)

#[tokio::test]
async fn test_shoes_shadowsocks_to_shadowsocks_aes256gcm() -> Result<(), Box<dyn std::error::Error>>
{
    ProxyTestFixture::new()
        .with_shoes_shadowsocks_client(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .with_shoes_shadowsocks_server(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .test_local_http(1024)
        .await
}

#[tokio::test]
async fn test_shoes_shadowsocks_to_shadowsocks_chacha20() -> Result<(), Box<dyn std::error::Error>>
{
    ProxyTestFixture::new()
        .with_shoes_shadowsocks_client(ShadowsocksCipher::ChaCha20IetfPoly1305, TEST_PASSWORD)
        .with_shoes_shadowsocks_server(ShadowsocksCipher::ChaCha20IetfPoly1305, TEST_PASSWORD)
        .test_local_http(1024)
        .await
}

#[tokio::test]
async fn test_shoes_shadowsocks_to_shadowsocks_2022_aes256gcm()
-> Result<(), Box<dyn std::error::Error>> {
    let cipher = ShadowsocksCipher::Blake3Aes256Gcm;
    let key = generate_2022_key(&cipher);
    ProxyTestFixture::new()
        .with_shoes_shadowsocks_client(cipher.clone(), &key)
        .with_shoes_shadowsocks_server(cipher, &key)
        .test_local_http(1024)
        .await
}

// Shadowsocks with Local Servers

#[tokio::test]
async fn test_shoes_shadowsocks_with_local_http() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_shadowsocks_client(ShadowsocksCipher::ChaCha20IetfPoly1305, TEST_PASSWORD)
        .with_shoes_shadowsocks_server(ShadowsocksCipher::ChaCha20IetfPoly1305, TEST_PASSWORD)
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1024", false).await?;
    assert_eq!(body.len(), 1024);
    Ok(())
}

#[tokio::test]
async fn test_shoes_shadowsocks_with_local_https() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_shadowsocks_client(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .with_shoes_shadowsocks_server(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .with_local_https_tls13_server()
        .build()
        .await?;

    // Test small transfer
    let body = fixture.test_local_server("/bytes/100", true).await?;
    assert_eq!(body.len(), 100);

    // Test larger transfer
    let body = fixture.test_local_server("/bytes/10240", true).await?;
    assert_eq!(body.len(), 10240);

    Ok(())
}

// Edge Case Tests - Payload Sizes

/// Test with minimal payload (1 byte) - tests edge case handling
#[tokio::test]
async fn test_shoes_shadowsocks_local_http_1_byte() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_shadowsocks_client(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .with_shoes_shadowsocks_server(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1", false).await?;
    assert_eq!(body.len(), 1, "Expected exactly 1 byte");
    Ok(())
}

/// Test with large payload (100KB) over HTTP
#[tokio::test]
async fn test_shoes_shadowsocks_local_http_100kb() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_shadowsocks_client(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .with_shoes_shadowsocks_server(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/100000", false).await?;
    assert_eq!(body.len(), 100000, "Expected exactly 100KB");
    Ok(())
}

/// Test with large payload (200KB) over HTTP - beyond typical buffer sizes
#[tokio::test]
async fn test_shoes_shadowsocks_local_http_200kb() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_shadowsocks_client(ShadowsocksCipher::ChaCha20IetfPoly1305, TEST_PASSWORD)
        .with_shoes_shadowsocks_server(ShadowsocksCipher::ChaCha20IetfPoly1305, TEST_PASSWORD)
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/200000", false).await?;
    assert_eq!(body.len(), 200000, "Expected exactly 200KB");
    Ok(())
}

/// Test with minimal payload (1 byte) over HTTPS/TLS 1.3
#[tokio::test]
async fn test_shoes_shadowsocks_local_https_tls13_1_byte() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = ProxyTestFixture::new()
        .with_singbox_shadowsocks_client(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .with_shoes_shadowsocks_server(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .with_local_https_tls13_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1", true).await?;
    assert_eq!(body.len(), 1, "Expected exactly 1 byte");
    Ok(())
}

/// Test with large payload (100KB) over HTTPS/TLS 1.3
#[tokio::test]
async fn test_shoes_shadowsocks_local_https_tls13_100kb() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = ProxyTestFixture::new()
        .with_singbox_shadowsocks_client(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .with_shoes_shadowsocks_server(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .with_local_https_tls13_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/100000", true).await?;
    assert_eq!(body.len(), 100000, "Expected exactly 100KB");
    Ok(())
}

/// Test with large payload (200KB) over HTTPS/TLS 1.3
#[tokio::test]
async fn test_shoes_shadowsocks_local_https_tls13_200kb() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = ProxyTestFixture::new()
        .with_singbox_shadowsocks_client(ShadowsocksCipher::ChaCha20IetfPoly1305, TEST_PASSWORD)
        .with_shoes_shadowsocks_server(ShadowsocksCipher::ChaCha20IetfPoly1305, TEST_PASSWORD)
        .with_local_https_tls13_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/200000", true).await?;
    assert_eq!(body.len(), 200000, "Expected exactly 200KB");
    Ok(())
}

/// Test with HTTPS/TLS 1.2 - different TLS version handling
#[tokio::test]
async fn test_shoes_shadowsocks_local_https_tls12_small() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = ProxyTestFixture::new()
        .with_singbox_shadowsocks_client(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .with_shoes_shadowsocks_server(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .with_local_https_tls12_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1", true).await?;
    assert_eq!(body.len(), 1, "Expected exactly 1 byte");
    Ok(())
}

/// Test with HTTPS/TLS 1.2 large payload
#[tokio::test]
async fn test_shoes_shadowsocks_local_https_tls12_large() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = ProxyTestFixture::new()
        .with_singbox_shadowsocks_client(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .with_shoes_shadowsocks_server(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .with_local_https_tls12_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/200000", true).await?;
    assert_eq!(body.len(), 200000, "Expected exactly 200KB");
    Ok(())
}

// Edge Case Tests - 2022 Ciphers with Various Sizes

/// Test 2022-blake3-aes-256-gcm with 1 byte payload
#[tokio::test]
async fn test_shoes_shadowsocks_2022_aes256_1_byte() -> Result<(), Box<dyn std::error::Error>> {
    let cipher = ShadowsocksCipher::Blake3Aes256Gcm;
    let key = generate_2022_key(&cipher);
    let fixture = ProxyTestFixture::new()
        .with_singbox_shadowsocks_client(cipher.clone(), &key)
        .with_shoes_shadowsocks_server(cipher, &key)
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1", false).await?;
    assert_eq!(body.len(), 1, "Expected exactly 1 byte");
    Ok(())
}

/// Test 2022-blake3-aes-256-gcm with 200KB payload
#[tokio::test]
async fn test_shoes_shadowsocks_2022_aes256_200kb() -> Result<(), Box<dyn std::error::Error>> {
    let cipher = ShadowsocksCipher::Blake3Aes256Gcm;
    let key = generate_2022_key(&cipher);
    let fixture = ProxyTestFixture::new()
        .with_singbox_shadowsocks_client(cipher.clone(), &key)
        .with_shoes_shadowsocks_server(cipher, &key)
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/200000", false).await?;
    assert_eq!(body.len(), 200000, "Expected exactly 200KB");
    Ok(())
}

/// Test 2022-blake3-chacha20-poly1305 with 1 byte payload
#[tokio::test]
async fn test_shoes_shadowsocks_2022_chacha20_1_byte() -> Result<(), Box<dyn std::error::Error>> {
    let cipher = ShadowsocksCipher::Blake3ChaCha20Poly1305;
    let key = generate_2022_key(&cipher);
    let fixture = ProxyTestFixture::new()
        .with_singbox_shadowsocks_client(cipher.clone(), &key)
        .with_shoes_shadowsocks_server(cipher, &key)
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1", false).await?;
    assert_eq!(body.len(), 1, "Expected exactly 1 byte");
    Ok(())
}

/// Test 2022-blake3-chacha20-poly1305 with 200KB payload
#[tokio::test]
async fn test_shoes_shadowsocks_2022_chacha20_200kb() -> Result<(), Box<dyn std::error::Error>> {
    let cipher = ShadowsocksCipher::Blake3ChaCha20Poly1305;
    let key = generate_2022_key(&cipher);
    let fixture = ProxyTestFixture::new()
        .with_singbox_shadowsocks_client(cipher.clone(), &key)
        .with_shoes_shadowsocks_server(cipher, &key)
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/200000", false).await?;
    assert_eq!(body.len(), 200000, "Expected exactly 200KB");
    Ok(())
}

// Boundary Size Tests - Testing at power-of-2 and block boundaries

/// Test various power-of-2 sizes over HTTP
#[tokio::test]
async fn test_shoes_shadowsocks_power_of_2_sizes() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_shadowsocks_client(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .with_shoes_shadowsocks_server(ShadowsocksCipher::Aes256Gcm, TEST_PASSWORD)
        .with_local_http_server()
        .build()
        .await?;

    // Test power-of-2 sizes which often reveal buffer handling issues
    for size in [
        1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
    ] {
        let path = format!("/bytes/{}", size);
        let body = fixture.test_local_server(&path, false).await?;
        assert_eq!(body.len(), size, "Failed at size {}", size);
    }

    Ok(())
}

/// Test sizes around common buffer boundaries (e.g., 16KB block size)
#[tokio::test]
async fn test_shoes_shadowsocks_buffer_boundary_sizes() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_shadowsocks_client(ShadowsocksCipher::ChaCha20IetfPoly1305, TEST_PASSWORD)
        .with_shoes_shadowsocks_server(ShadowsocksCipher::ChaCha20IetfPoly1305, TEST_PASSWORD)
        .with_local_http_server()
        .build()
        .await?;

    // Test sizes around common buffer boundaries
    // 16KB is a common block size in TLS and encryption
    for size in [
        16383, 16384, 16385, 32767, 32768, 32769, 65535, 65536, 65537,
    ] {
        let path = format!("/bytes/{}", size);
        let body = fixture.test_local_server(&path, false).await?;
        assert_eq!(body.len(), size, "Failed at size {}", size);
    }

    Ok(())
}
