//! AnyTLS UDP-over-TCP interoperability coverage using sing-box.

use std::error::Error;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use shoes_test_support as common;
use tempfile::NamedTempFile;

use common::certs::generate_test_cert_files;
use common::process::ProcessGuard;
use common::socks5::{Socks5UdpAssociation, SocksDestination};
use common::test_fixture::{start_shoes_server, start_singbox_server};
use common::test_servers::{TestServer, start_udp_echo_server};

const PASSWORD: &str = "testpassword123";
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct AnyTlsUotFixture {
    association: Socks5UdpAssociation,
    destination: SocketAddr,
    _echo: TestServer,
    _shoes: ProcessGuard,
    _shoes_config: NamedTempFile,
    _singbox: ProcessGuard,
    _singbox_config: NamedTempFile,
}

impl AnyTlsUotFixture {
    async fn send(&self, payload: &[u8]) -> TestResult<Vec<u8>> {
        Ok(self
            .association
            .send_to_with_timeout(
                SocksDestination::Ip(self.destination),
                payload,
                Duration::from_secs(5),
            )
            .await?)
    }
}

async fn start_fixture(udp_enabled: Option<bool>) -> TestResult<AnyTlsUotFixture> {
    let mut ports = common::port_helper::PortHelper::new();
    let (shoes_ip, shoes_port) = ports.get_listener_port();
    let (singbox_ip, singbox_port) = ports.get_listener_port();
    let echo = start_udp_echo_server("127.0.0.1", 0).await?;
    let destination = echo.local_addr();
    let udp_setting = udp_enabled
        .map(|enabled| format!("          udp_enabled: {enabled}\n"))
        .unwrap_or_default();

    let (cert_path, key_path) = generate_test_cert_files()?;
    let shoes_config = format!(
        r#"- address: "{shoes_ip}:{shoes_port}"
  protocol:
    type: tls
    tls_targets:
      test.local:
        cert: {}
        key: {}
        protocol:
          type: anytls
{udp_setting}          users:
            - name: testuser
              password: "{PASSWORD}"
"#,
        AsRef::<Path>::as_ref(&cert_path).display(),
        AsRef::<Path>::as_ref(&key_path).display(),
    );
    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{
    "type": "socks",
    "tag": "socks-in",
    "listen": "{singbox_ip}",
    "listen_port": {singbox_port}
  }}],
  "outbounds": [{{
    "type": "anytls",
    "tag": "anytls-out",
    "server": "{shoes_ip}",
    "server_port": {shoes_port},
    "password": "{PASSWORD}",
    "tls": {{
      "enabled": true,
      "insecure": true,
      "server_name": "test.local"
    }}
  }}],
  "route": {{ "final": "anytls-out" }}
}}"#
    );

    let (shoes, shoes_config) = start_shoes_server(&shoes_config)?;
    let (singbox, singbox_config) = start_singbox_server(&singbox_config)?;
    ports.wait_for_all_ports().await?;
    let association = Socks5UdpAssociation::connect(&singbox_ip, singbox_port).await?;

    Ok(AnyTlsUotFixture {
        association,
        destination,
        _echo: echo,
        _shoes: shoes,
        _shoes_config: shoes_config,
        _singbox: singbox,
        _singbox_config: singbox_config,
    })
}

#[tokio::test]
async fn test_anytls_uot_basic() -> TestResult {
    let fixture = start_fixture(Some(true)).await?;
    assert_eq!(
        fixture.send(b"AnyTLS UoT Test").await?,
        b"AnyTLS UoT Test [ECHO]"
    );
    Ok(())
}

#[tokio::test]
async fn test_anytls_uot_multiple_packets() -> TestResult {
    let fixture = start_fixture(Some(true)).await?;
    for index in 0..5 {
        let payload = format!("AnyTLS packet {index}");
        assert_eq!(
            fixture.send(payload.as_bytes()).await?,
            format!("{payload} [ECHO]").into_bytes()
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_anytls_uot_multiple_destinations() -> TestResult {
    let fixture = start_fixture(Some(true)).await?;
    let second_echo = start_udp_echo_server("127.0.0.1", 0).await?;
    let cases = [
        (fixture.destination, b"first destination".as_slice()),
        (second_echo.local_addr(), b"second destination".as_slice()),
    ];

    for (destination, payload) in cases {
        let response = fixture
            .association
            .send_to_with_timeout(
                SocksDestination::Ip(destination),
                payload,
                Duration::from_secs(5),
            )
            .await?;
        assert_eq!(response, [payload, b" [ECHO]"].concat());
    }
    Ok(())
}

#[tokio::test]
async fn test_anytls_uot_various_sizes() -> TestResult {
    let fixture = start_fixture(Some(true)).await?;
    for size in [1, 10, 100, 500, 1000, 2000, 4000, 8000] {
        let payload: Vec<_> = (0..size).map(|index| (index % 256) as u8).collect();
        assert_eq!(
            fixture.send(&payload).await?,
            [payload.as_slice(), b" [ECHO]"].concat()
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_anytls_uot_defaults_to_enabled() -> TestResult {
    let fixture = start_fixture(None).await?;
    assert_eq!(
        fixture.send(b"default enabled").await?,
        b"default enabled [ECHO]"
    );
    Ok(())
}

#[tokio::test]
async fn test_anytls_uot_can_be_disabled() -> TestResult {
    let healthy = start_fixture(Some(true)).await?;
    assert_eq!(healthy.send(b"control").await?, b"control [ECHO]");
    drop(healthy);

    let disabled = start_fixture(Some(false)).await?;
    let result = disabled
        .association
        .send_to_with_timeout(
            SocksDestination::Ip(disabled.destination),
            b"must not arrive",
            Duration::from_secs(2),
        )
        .await;
    assert!(
        result.is_err(),
        "UDP reached an AnyTLS listener with UDP disabled"
    );
    Ok(())
}
