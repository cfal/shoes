//! AnyTLS UDP-over-TCP interoperability coverage using Mihomo.

use std::error::Error;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use shoes_test_support as common;
use tempfile::NamedTempFile;

use common::certs::generate_test_cert_files;
use common::process::{ProcessGuard, start_mihomo_server};
use common::socks5::{Socks5UdpAssociation, SocksDestination};
use common::test_fixture::start_shoes_server;
use common::test_servers::{TestServer, start_udp_echo_server};

const PASSWORD: &str = "testpassword123";
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct MihomoFixture {
    association: Socks5UdpAssociation,
    destination: SocketAddr,
    _echo: TestServer,
    _shoes: ProcessGuard,
    _shoes_config: NamedTempFile,
    _mihomo: ProcessGuard,
    _mihomo_config: NamedTempFile,
}

impl MihomoFixture {
    async fn send_to(&self, destination: SocketAddr, payload: &[u8]) -> TestResult<Vec<u8>> {
        Ok(self
            .association
            .send_to_with_timeout(
                SocksDestination::Ip(destination),
                payload,
                Duration::from_secs(5),
            )
            .await?)
    }
}

async fn start_fixture() -> TestResult<MihomoFixture> {
    let mut ports = common::port_helper::PortHelper::new();
    let (shoes_ip, shoes_port) = ports.get_listener_port();
    let (mihomo_ip, mihomo_port) = ports.get_localhost_listener_port();
    let echo = start_udp_echo_server("127.0.0.1", 0).await?;
    let destination = echo.local_addr();
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
          udp_enabled: true
          users:
            - name: testuser
              password: "{PASSWORD}"
"#,
        AsRef::<Path>::as_ref(&cert_path).display(),
        AsRef::<Path>::as_ref(&key_path).display(),
    );
    let mihomo_config = format!(
        r#"mixed-port: {mihomo_port}
mode: rule
log-level: debug
ipv6: false
proxies:
  - name: anytls-proxy
    type: anytls
    server: {shoes_ip}
    port: {shoes_port}
    password: {PASSWORD}
    udp: true
    sni: test.local
    skip-cert-verify: true
rules:
  - MATCH,anytls-proxy
"#
    );

    let (shoes, shoes_config) = start_shoes_server(&shoes_config)?;
    let (mihomo, mihomo_config) = start_mihomo_server(&mihomo_config)?;
    ports.wait_for_all_ports().await?;
    let association = Socks5UdpAssociation::connect(&mihomo_ip, mihomo_port).await?;

    Ok(MihomoFixture {
        association,
        destination,
        _echo: echo,
        _shoes: shoes,
        _shoes_config: shoes_config,
        _mihomo: mihomo,
        _mihomo_config: mihomo_config,
    })
}

#[tokio::test]
async fn test_anytls_uot_mihomo_basic() -> TestResult {
    let fixture = start_fixture().await?;
    assert_eq!(
        fixture
            .send_to(fixture.destination, b"Mihomo AnyTLS UoT")
            .await?,
        b"Mihomo AnyTLS UoT [ECHO]"
    );
    Ok(())
}

#[tokio::test]
async fn test_anytls_uot_mihomo_multiple_packets() -> TestResult {
    let fixture = start_fixture().await?;
    for index in 0..5 {
        let payload = format!("Mihomo packet {index}");
        assert_eq!(
            fixture
                .send_to(fixture.destination, payload.as_bytes())
                .await?,
            format!("{payload} [ECHO]").into_bytes()
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_anytls_uot_mihomo_multi_destination() -> TestResult {
    let fixture = start_fixture().await?;
    let second_echo = start_udp_echo_server("127.0.0.1", 0).await?;
    for (destination, payload) in [
        (fixture.destination, b"Mihomo first".as_slice()),
        (second_echo.local_addr(), b"Mihomo second".as_slice()),
    ] {
        assert_eq!(
            fixture.send_to(destination, payload).await?,
            [payload, b" [ECHO]"].concat()
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_anytls_uot_mihomo_various_sizes() -> TestResult {
    let fixture = start_fixture().await?;
    for size in [1, 10, 100, 500, 1000, 2000, 4000, 8000] {
        let payload: Vec<_> = (0..size).map(|index| (index % 256) as u8).collect();
        assert_eq!(
            fixture.send_to(fixture.destination, &payload).await?,
            [payload.as_slice(), b" [ECHO]"].concat()
        );
    }
    Ok(())
}
