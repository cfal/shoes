use common::test_fixture::{ProxyTestFixture, VmessCipher};
/// Integration tests for VMess protocol
///
/// Tests VMess server/client with different ciphers (ChaCha20-Poly1305, AES-128-GCM)
/// Tests both plain VMess and VMess+TLS configurations
/// Tests interoperability with sing-box
use shoes_test_support as common;

// VMess Server Tests (shoes as server, sing-box as client)

#[tokio::test]
async fn test_shoes_vmess_server_chacha() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_singbox_vmess_client(VmessCipher::ChaCha20Poly1305)
        .with_shoes_vmess_server(VmessCipher::ChaCha20Poly1305)
        .test_local_http_hostname(1024)
        .await
}

#[tokio::test]
async fn test_shoes_vmess_server_aes_gcm() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_singbox_vmess_client(VmessCipher::Aes128Gcm)
        .with_shoes_vmess_server(VmessCipher::Aes128Gcm)
        .test_local_http(1024)
        .await
}

#[tokio::test]
async fn test_shoes_vmess_tls_server_chacha() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_singbox_vmess_tls_client(VmessCipher::ChaCha20Poly1305)
        .with_shoes_vmess_tls_server(VmessCipher::ChaCha20Poly1305)
        .test_local_http(1024)
        .await
}

#[tokio::test]
async fn test_shoes_vmess_tls_server_aes_gcm() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_singbox_vmess_tls_client(VmessCipher::Aes128Gcm)
        .with_shoes_vmess_tls_server(VmessCipher::Aes128Gcm)
        .test_local_http(1024)
        .await
}

// VMess Client Tests (shoes as client, sing-box as server)

#[tokio::test]
async fn test_shoes_vmess_client_chacha() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_shoes_vmess_client(VmessCipher::ChaCha20Poly1305)
        .with_singbox_vmess_server(VmessCipher::ChaCha20Poly1305)
        .test_local_http_hostname(1024)
        .await
}

#[tokio::test]
async fn test_shoes_vmess_client_aes_gcm() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_shoes_vmess_client(VmessCipher::Aes128Gcm)
        .with_singbox_vmess_server(VmessCipher::Aes128Gcm)
        .test_local_http(1024)
        .await
}

#[tokio::test]
async fn test_shoes_vmess_tls_client_chacha() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_shoes_vmess_tls_client(VmessCipher::ChaCha20Poly1305)
        .with_singbox_vmess_tls_server(VmessCipher::ChaCha20Poly1305)
        .test_local_http(1024)
        .await
}

#[tokio::test]
async fn test_shoes_vmess_tls_client_aes_gcm() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_shoes_vmess_tls_client(VmessCipher::Aes128Gcm)
        .with_singbox_vmess_tls_server(VmessCipher::Aes128Gcm)
        .test_local_http(1024)
        .await
}

// VMess to VMess Tests (shoes client -> shoes server)

#[tokio::test]
async fn test_shoes_vmess_to_vmess_chacha() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_shoes_vmess_client(VmessCipher::ChaCha20Poly1305)
        .with_shoes_vmess_server(VmessCipher::ChaCha20Poly1305)
        .test_local_http(1024)
        .await
}

#[tokio::test]
async fn test_shoes_vmess_to_vmess_aes_gcm() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_shoes_vmess_client(VmessCipher::Aes128Gcm)
        .with_shoes_vmess_server(VmessCipher::Aes128Gcm)
        .test_local_http(1024)
        .await
}

#[tokio::test]
async fn test_shoes_vmess_tls_to_vmess_tls_chacha() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_shoes_vmess_tls_client(VmessCipher::ChaCha20Poly1305)
        .with_shoes_vmess_tls_server(VmessCipher::ChaCha20Poly1305)
        .test_local_http(1024)
        .await
}

#[tokio::test]
async fn test_shoes_vmess_tls_to_vmess_tls_aes_gcm() -> Result<(), Box<dyn std::error::Error>> {
    ProxyTestFixture::new()
        .with_shoes_vmess_tls_client(VmessCipher::Aes128Gcm)
        .with_shoes_vmess_tls_server(VmessCipher::Aes128Gcm)
        .test_local_http(1024)
        .await
}

// VMess with Local Servers

#[tokio::test]
async fn test_shoes_vmess_with_local_http() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_vmess_client(VmessCipher::ChaCha20Poly1305)
        .with_shoes_vmess_server(VmessCipher::ChaCha20Poly1305)
        .with_local_http_server()
        .build()
        .await?;

    let body = fixture.test_local_server("/bytes/1024", false).await?;
    assert_eq!(body.len(), 1024);
    Ok(())
}

#[tokio::test]
async fn test_shoes_vmess_tls_with_local_https() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProxyTestFixture::new()
        .with_singbox_vmess_tls_client(VmessCipher::ChaCha20Poly1305)
        .with_shoes_vmess_tls_server(VmessCipher::ChaCha20Poly1305)
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
