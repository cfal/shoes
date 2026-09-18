//! Shadowsocks UDP-over-TCP framing and lifecycle coverage.

use std::collections::HashSet;
use std::error::Error;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use shoes_test_support as common;
use tempfile::NamedTempFile;
use tokio::time::sleep;

use common::port_helper::PortHelper;
use common::process::ProcessGuard;
use common::socks5::{
    Socks5UdpAssociation, SocksDestination, decode_udp_datagram, encode_udp_datagram,
};
use common::test_fixture::{start_shoes_server, start_singbox_server};
use common::test_servers::{TestServer, start_udp_echo_server, start_udp_echo_server_with_suffix};

const TEST_PASSWORD: &str = "test-shadowsocks-uot-edge-case-password";
const IO_TIMEOUT: Duration = Duration::from_secs(5);

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
    async fn send(&self, payload: &[u8]) -> io::Result<Vec<u8>> {
        self.send_to(self.destination, payload).await
    }

    async fn send_to(&self, destination: SocketAddr, payload: &[u8]) -> io::Result<Vec<u8>> {
        with_deadline(
            IO_TIMEOUT,
            self.association.send_to_with_timeout(
                SocksDestination::Ip(destination),
                payload,
                IO_TIMEOUT,
            ),
        )
        .await
    }
}

async fn with_deadline<T>(
    duration: Duration,
    operation: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    tokio::time::timeout(duration, operation)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "test operation timed out"))?
}

async fn start_uot_fixture(
    method: &str,
    version: u8,
    connect_mode: bool,
) -> TestResult<UotFixture> {
    let mut ports = PortHelper::new();
    let (shoes_ip, shoes_port) = ports.get_listener_port();
    let (singbox_ip, singbox_port) = ports.get_listener_port();
    let echo = start_udp_echo_server("127.0.0.1", 0).await?;
    let destination = echo.local_addr();

    let shoes_config = format!(
        r#"
- address: "{shoes_ip}:{shoes_port}"
  protocol:
    type: shadowsocks
    cipher: {method}
    password: "{TEST_PASSWORD}"
"#
    );
    let route = if connect_mode {
        r#""route": {
    "rules": [{
      "network": "udp",
      "action": "route",
      "outbound": "ss-out",
      "udp_connect": true
    }],
    "final": "ss-out"
  }"#
    } else {
        r#""route": { "final": "ss-out" }"#
    };
    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "info" }},
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
    "password": "{TEST_PASSWORD}",
    "udp_over_tcp": {{ "enabled": true, "version": {version} }}
  }}],
  {route}
}}"#
    );

    let (shoes, shoes_config) = start_shoes_server(&shoes_config)?;
    let (singbox, singbox_config) = start_singbox_server(&singbox_config)?;
    ports.wait_for_all_ports().await?;
    let association = with_deadline(
        IO_TIMEOUT,
        Socks5UdpAssociation::connect(&singbox_ip, singbox_port),
    )
    .await?;

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

fn echoed(payload: &[u8], suffix: &[u8]) -> Vec<u8> {
    [payload, suffix].concat()
}

#[tokio::test]
async fn test_shadowsocks_uot_v2_connect_mode() -> TestResult {
    let fixture = start_uot_fixture("aes-256-gcm", 2, true).await?;

    for payload in [b"V2 connect first".as_slice(), b"V2 connect second"] {
        assert_eq!(fixture.send(payload).await?, echoed(payload, b" [ECHO]"));
    }
    Ok(())
}

#[tokio::test]
async fn test_shadowsocks_uot_small_packets() -> TestResult {
    let fixture = start_uot_fixture("aes-256-gcm", 1, false).await?;

    with_deadline(Duration::from_secs(10), async {
        for size in 1..=10 {
            let payload: Vec<u8> = (0..size).map(|value| value as u8).collect();
            assert_eq!(
                fixture.send(&payload).await?,
                echoed(&payload, b" [ECHO]"),
                "payload size {size}"
            );
        }
        Ok(())
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn test_shadowsocks_uot_selected_large_packets() -> TestResult {
    let fixture = start_uot_fixture("aes-256-gcm", 1, false).await?;

    with_deadline(Duration::from_secs(10), async {
        for size in [1_000, 2_000, 4_000, 8_000, 12_000, 16_000] {
            let payload: Vec<u8> = (0..size).map(|value| (value % 256) as u8).collect();
            assert_eq!(
                fixture.send(&payload).await?,
                echoed(&payload, b" [ECHO]"),
                "payload size {size}"
            );
        }
        Ok(())
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn test_shadowsocks_uot_cold_start_rapid_burst() -> TestResult {
    let fixture = start_uot_fixture("aes-256-gcm", 1, false).await?;
    assert_complete_burst(&fixture).await?;
    Ok(())
}

async fn assert_complete_burst(fixture: &UotFixture) -> io::Result<()> {
    let mut pending: HashSet<Vec<u8>> = (0..20)
        .map(|index| format!("Burst packet #{index:03} [ECHO]").into_bytes())
        .collect();
    with_deadline(Duration::from_secs(10), async {
        for index in 0..20 {
            let payload = format!("Burst packet #{index:03}");
            let request = encode_udp_datagram(
                &SocksDestination::Ip(fixture.destination),
                payload.as_bytes(),
            )?;
            let sent = fixture
                .association
                .socket()
                .send_to(&request, fixture.association.relay_addr())
                .await?;
            assert_eq!(sent, request.len());
        }

        let mut response = vec![0; 65_536];
        while !pending.is_empty() {
            let (length, source) = fixture
                .association
                .socket()
                .recv_from(&mut response)
                .await?;
            assert_eq!(source, fixture.association.relay_addr());
            let payload = decode_udp_datagram(&response[..length])?;
            assert!(
                pending.remove(payload),
                "unexpected, corrupted, or duplicate burst response: {payload:?}"
            );
        }
        Ok(())
    })
    .await?;
    assert!(pending.is_empty());
    Ok(())
}

#[tokio::test]
async fn test_shadowsocks_uot_steady_state_rapid_burst() -> TestResult {
    let fixture = start_uot_fixture("aes-256-gcm", 1, false).await?;
    assert_eq!(
        fixture.send(b"warm-up").await?,
        b"warm-up [ECHO]".as_slice()
    );
    assert_complete_burst(&fixture).await?;
    Ok(())
}

#[tokio::test]
async fn test_shadowsocks_uot_boundary_packet_sizes() -> TestResult {
    let fixture = start_uot_fixture("aes-256-gcm", 1, false).await?;
    let sizes = [
        1, 2, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 511, 512, 1_023, 1_024, 1_500,
    ];

    with_deadline(Duration::from_secs(10), async {
        for size in sizes {
            let payload: Vec<u8> = (0..size).map(|value| (value % 256) as u8).collect();
            assert_eq!(
                fixture.send(&payload).await?,
                echoed(&payload, b" [ECHO]"),
                "payload size {size}"
            );
        }
        Ok(())
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn test_shadowsocks_uot_v2_non_connect_ciphers() -> TestResult {
    for method in ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"] {
        let fixture = start_uot_fixture(method, 2, false).await?;
        let payload = format!("V2 {method}");
        assert_eq!(
            fixture.send(payload.as_bytes()).await?,
            echoed(payload.as_bytes(), b" [ECHO]"),
            "cipher {method}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_shadowsocks_uot_sequential_exchanges() -> TestResult {
    let fixture = start_uot_fixture("aes-256-gcm", 1, false).await?;

    with_deadline(Duration::from_secs(10), async {
        for index in 0..10 {
            let payload = format!("Exchange #{index}");
            assert_eq!(
                fixture.send(payload.as_bytes()).await?,
                echoed(payload.as_bytes(), b" [ECHO]")
            );
        }
        Ok(())
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn test_shadowsocks_uot_v1_multi_destination_sequence() -> TestResult {
    let fixture = start_uot_fixture("aes-256-gcm", 1, false).await?;
    let second = start_udp_echo_server_with_suffix("127.0.0.1", 0, b" [SECOND]").await?;
    let third = start_udp_echo_server_with_suffix("127.0.0.1", 0, b" [THIRD]").await?;
    let targets = [
        (fixture.destination, b" [ECHO]".as_slice()),
        (second.local_addr(), b" [SECOND]".as_slice()),
        (third.local_addr(), b" [THIRD]".as_slice()),
    ];

    with_deadline(Duration::from_secs(10), async {
        for round in 0..3 {
            for (destination, suffix) in targets {
                let payload = format!("Round {round}");
                assert_eq!(
                    fixture.send_to(destination, payload.as_bytes()).await?,
                    echoed(payload.as_bytes(), suffix)
                );
            }
        }
        Ok(())
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn test_shadowsocks_uot_connection_persistence() -> TestResult {
    let fixture = start_uot_fixture("aes-256-gcm", 1, false).await?;

    with_deadline(Duration::from_secs(20), async {
        assert_eq!(fixture.send(b"Message 1").await?, b"Message 1 [ECHO]");
        sleep(Duration::from_secs(2)).await;
        assert_eq!(fixture.send(b"Message 2").await?, b"Message 2 [ECHO]");
        sleep(Duration::from_secs(3)).await;
        assert_eq!(fixture.send(b"Message 3").await?, b"Message 3 [ECHO]");
        Ok(())
    })
    .await?;
    Ok(())
}
