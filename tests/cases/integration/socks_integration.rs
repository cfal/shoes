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

// SOCKS client chains with credentials or inside ShadowTLS, where each negotiation
// reply must reach the client before it sends the next request.

const SOCKS_TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Opens a tunnel through a shoes SOCKS inbound to an echo server and checks the echo.
async fn echo_through_socks_inbound(
    inbound_port: u16,
    echo_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", inbound_port)).await?;
    socket.write_all(&[5, 1, 0]).await?;
    let mut method = [0; 2];
    socket.read_exact(&mut method).await?;
    assert_eq!(method, [5, 0]);

    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&echo_port.to_be_bytes());
    socket.write_all(&request).await?;
    let mut reply = [0; 10];
    socket.read_exact(&mut reply).await?;
    assert_eq!(&reply[..2], &[5, 0], "CONNECT through the chain failed");

    socket.write_all(b"ping").await?;
    let mut echoed = [0; 4];
    socket.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"ping");
    Ok(())
}

/// SOCKS listener that sends every connection through `protocol`, an inline YAML mapping.
fn socks_chain_listener(inbound_port: u16, upstream_port: u16, protocol: &str) -> String {
    format!(
        r#"
- address: "127.0.0.1:{inbound_port}"
  protocol:
    type: socks
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        address: "127.0.0.1:{upstream_port}"
        protocol: {protocol}
"#
    )
}

#[tokio::test]
async fn test_shoes_socks_client_with_auth_to_singbox() -> Result<(), Box<dyn std::error::Error>> {
    let mut ports = common::port_helper::PortHelper::new();
    let (_, singbox_port) = ports.get_localhost_listener_port();
    let (_, inbound_port) = ports.get_localhost_listener_port();
    let (_, echo_port) = ports.get_localhost_listener_port();
    let _echo = common::test_servers::start_tcp_stream_echo_server("127.0.0.1", echo_port).await?;
    let (_singbox, _singbox_config) = common::test_fixture::start_singbox_server(&format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [
    {{
      "type": "socks",
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "listen_port": {singbox_port},
      "users": [{{ "username": "user", "password": "pass" }}]
    }}
  ],
  "outbounds": [{{ "type": "direct", "tag": "direct" }}],
  "route": {{ "final": "direct" }}
}}"#
    ))?;
    let (_shoes, _shoes_config) = common::test_fixture::start_shoes_server(&socks_chain_listener(
        inbound_port,
        singbox_port,
        "{ type: socks, username: user, password: pass }",
    ))?;
    ports.wait_for_all_ports().await?;

    tokio::time::timeout(
        SOCKS_TEST_TIMEOUT,
        echo_through_socks_inbound(inbound_port, echo_port),
    )
    .await?
}

#[tokio::test]
async fn test_shoes_socks_to_socks_with_auth() -> Result<(), Box<dyn std::error::Error>> {
    let mut ports = common::port_helper::PortHelper::new();
    let (_, server_port) = ports.get_localhost_listener_port();
    let (_, inbound_port) = ports.get_localhost_listener_port();
    let (_, echo_port) = ports.get_localhost_listener_port();
    let _echo = common::test_servers::start_tcp_stream_echo_server("127.0.0.1", echo_port).await?;
    let config = format!(
        r#"
- address: "127.0.0.1:{server_port}"
  protocol:
    type: socks
    username: user
    password: pass
{}"#,
        socks_chain_listener(
            inbound_port,
            server_port,
            "{ type: socks, username: user, password: pass }",
        )
    );
    let (_shoes, _shoes_config) = common::test_fixture::start_shoes_server(&config)?;
    ports.wait_for_all_ports().await?;

    tokio::time::timeout(
        SOCKS_TEST_TIMEOUT,
        echo_through_socks_inbound(inbound_port, echo_port),
    )
    .await?
}

/// The configuration that regressed when the client first waited for each reply: the
/// shoes SOCKS server did not flush its replies inside ShadowTLS.
#[tokio::test]
async fn test_shoes_socks_over_shadowtls() -> Result<(), Box<dyn std::error::Error>> {
    let (cert_path, key_path) = common::certs::generate_test_cert_files()?;
    for credentials in ["", ", username: user, password: pass"] {
        let mut ports = common::port_helper::PortHelper::new();
        let (_, server_port) = ports.get_localhost_listener_port();
        let (_, inbound_port) = ports.get_localhost_listener_port();
        let (_, echo_port) = ports.get_localhost_listener_port();
        let _echo =
            common::test_servers::start_tcp_stream_echo_server("127.0.0.1", echo_port).await?;
        let socks = format!("{{ type: socks{credentials} }}");
        let config = format!(
            r#"
- address: "127.0.0.1:{server_port}"
  protocol:
    type: tls
    shadowtls_targets:
      "test.local":
        password: "shadowtls-pass"
        handshake:
          cert: "{}"
          key: "{}"
        protocol: {socks}
{}"#,
            cert_path.display(),
            key_path.display(),
            socks_chain_listener(
                inbound_port,
                server_port,
                &format!(
                    "{{ type: shadowtls, password: shadowtls-pass, sni_hostname: test.local, protocol: {socks} }}"
                ),
            )
        );
        let (_shoes, _shoes_config) = common::test_fixture::start_shoes_server(&config)?;
        ports.wait_for_all_ports().await?;

        tokio::time::timeout(
            SOCKS_TEST_TIMEOUT,
            echo_through_socks_inbound(inbound_port, echo_port),
        )
        .await??;
    }
    Ok(())
}
