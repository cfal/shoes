//! Shadowsocks UDP-over-TCP interoperability coverage.

use std::error::Error;
use std::net::SocketAddr;
use std::time::Duration;

use shoes_test_support as common;
use tempfile::NamedTempFile;

use common::process::ProcessGuard;
use common::socks5::Socks5UdpAssociation;
use common::test_fixture::{start_shoes_server, start_singbox_server};
use common::test_servers::{TestServer, start_udp_echo_server};

const TEST_PASSWORD: &str = "test-shadowsocks-uot-password";
const TEST_PASSWORD_2022_AES128: &str = "AAAAAAAAAAAAAAAAAAAAAA==";
const TEST_PASSWORD_2022_AES256: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct UotFixture {
    association: Socks5UdpAssociation,
    destination: SocketAddr,
    _echo: TestServer,
    _shoes: ProcessGuard,
    _shoes_config: NamedTempFile,
    _singbox: ProcessGuard,
    _singbox_config: NamedTempFile,
}

impl UotFixture {
    async fn send(&self, payload: &[u8]) -> TestResult<Vec<u8>> {
        Ok(self
            .association
            .send_to_with_timeout(
                common::socks5::SocksDestination::Ip(self.destination),
                payload,
                Duration::from_secs(5),
            )
            .await?)
    }
}

async fn start_uot_fixture(method: &str, password: &str, version: u8) -> TestResult<UotFixture> {
    start_uot_fixture_with_server_udp(method, password, version, None).await
}

async fn start_uot_fixture_with_server_udp(
    method: &str,
    password: &str,
    version: u8,
    udp_enabled: Option<bool>,
) -> TestResult<UotFixture> {
    let mut ports = common::port_helper::PortHelper::new();
    let (shoes_ip, shoes_port) = ports.get_listener_port();
    let (singbox_ip, singbox_port) = ports.get_listener_port();
    let echo = start_udp_echo_server("127.0.0.1", 0).await?;
    let destination = echo.local_addr();

    let udp_enabled = udp_enabled
        .map(|enabled| format!("    udp_enabled: {enabled}\n"))
        .unwrap_or_default();
    let shoes_config = format!(
        r#"
- address: "{shoes_ip}:{shoes_port}"
  protocol:
    type: shadowsocks
    cipher: {method}
    password: "{password}"
{udp_enabled}
"#
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
    "type": "shadowsocks",
    "tag": "ss-out",
    "server": "{shoes_ip}",
    "server_port": {shoes_port},
    "method": "{method}",
    "password": "{password}",
    "udp_over_tcp": {{
      "enabled": true,
      "version": {version}
    }}
  }}],
  "route": {{ "final": "ss-out" }}
}}"#
    );

    let (shoes, shoes_config) = start_shoes_server(&shoes_config)?;
    let (singbox, singbox_config) = start_singbox_server(&singbox_config)?;
    ports.wait_for_all_ports().await?;
    let association = Socks5UdpAssociation::connect(&singbox_ip, singbox_port).await?;

    Ok(UotFixture {
        association,
        destination,
        _echo: echo,
        _shoes: shoes,
        _shoes_config: shoes_config,
        _singbox: singbox,
        _singbox_config: singbox_config,
    })
}

async fn assert_uot_round_trip(
    method: &str,
    password: &str,
    version: u8,
    payload: &[u8],
) -> TestResult {
    let fixture = start_uot_fixture(method, password, version).await?;
    assert_eq!(fixture.send(payload).await?, [payload, b" [ECHO]"].concat());
    Ok(())
}

#[tokio::test]
async fn test_shadowsocks_uot_v1_aes256gcm() -> TestResult {
    assert_uot_round_trip("aes-256-gcm", TEST_PASSWORD, 1, b"Hello UoT V1!").await
}

#[tokio::test]
async fn test_shadowsocks_uot_v2_connect_chacha20() -> TestResult {
    assert_uot_round_trip("chacha20-ietf-poly1305", TEST_PASSWORD, 2, b"Hello UoT V2!").await
}

#[tokio::test]
async fn test_shadowsocks_uot_v1_2022_blake3_aes128() -> TestResult {
    assert_uot_round_trip(
        "2022-blake3-aes-128-gcm",
        TEST_PASSWORD_2022_AES128,
        1,
        b"Hello 2022 UoT!",
    )
    .await
}

#[tokio::test]
async fn test_shadowsocks_uot_v2_2022_blake3_aes256() -> TestResult {
    assert_uot_round_trip(
        "2022-blake3-aes-256-gcm",
        TEST_PASSWORD_2022_AES256,
        2,
        b"Hello 2022-256 V2!",
    )
    .await
}

#[tokio::test]
async fn test_shadowsocks_uot_v1_multiple_packets() -> TestResult {
    let fixture = start_uot_fixture("aes-128-gcm", TEST_PASSWORD, 1).await?;
    for index in 0..3 {
        let request = format!("Packet #{index}");
        assert_eq!(
            fixture.send(request.as_bytes()).await?,
            format!("{request} [ECHO]").into_bytes()
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_shadowsocks_uot_v1_multi_destination() -> TestResult {
    let fixture = start_uot_fixture("aes-256-gcm", TEST_PASSWORD, 1).await?;
    let second_echo = start_udp_echo_server("127.0.0.1", 0).await?;
    let cases = [
        (fixture.destination, b"Hello Server 1!".as_slice()),
        (second_echo.local_addr(), b"Hello Server 2!".as_slice()),
    ];

    for (destination, payload) in cases {
        let response = fixture
            .association
            .send_to_with_timeout(
                common::socks5::SocksDestination::Ip(destination),
                payload,
                Duration::from_secs(5),
            )
            .await?;
        assert_eq!(response, [payload, b" [ECHO]"].concat());
    }
    Ok(())
}

#[tokio::test]
async fn test_shadowsocks_uot_config_parses() -> TestResult {
    let mut ports = common::port_helper::PortHelper::new();
    let (ip, port) = ports.get_listener_port();
    let config = format!(
        r#"
- address: "{ip}:{port}"
  protocol:
    type: shadowsocks
    cipher: aes-256-gcm
    password: "{TEST_PASSWORD}"
"#
    );
    let (_shoes, _config) = start_shoes_server(&config)?;
    ports.wait_for_all_ports().await?;
    Ok(())
}

#[tokio::test]
async fn test_shadowsocks_server_rejects_uot_when_disabled() -> TestResult {
    let enabled = start_uot_fixture_with_server_udp("aes-256-gcm", TEST_PASSWORD, 1, None).await?;
    assert_eq!(
        enabled.send(b"control").await?,
        b"control [ECHO]".as_slice()
    );
    drop(enabled);

    let disabled =
        start_uot_fixture_with_server_udp("aes-256-gcm", TEST_PASSWORD, 1, Some(false)).await?;
    let error = disabled
        .association
        .send_to_with_timeout(
            common::socks5::SocksDestination::Ip(disabled.destination),
            b"must not arrive",
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    Ok(())
}
