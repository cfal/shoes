use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use shoes_test_support::certs::generate_test_cert_files;
use shoes_test_support::port_helper::PortHelper;
use shoes_test_support::process::ProcessGuard;
use shoes_test_support::test_fixture::{TEST_UUID, start_shoes_server, start_singbox_server};
use shoes_test_support::test_servers::{TestServer, start_udp_echo_server_with_suffix};
use shoes_test_support::vless::{VlessDestination, VlessUdpClient, parse_uuid};
use tempfile::{NamedTempFile, TempPath};
use tokio::net::TcpStream;
use tokio::time::sleep;

struct StressFixture {
    client: VlessUdpClient<TcpStream>,
    _echo_server: TestServer,
    _shoes_guard: ProcessGuard,
    _shoes_config: NamedTempFile,
    _singbox_guard: ProcessGuard,
    _singbox_config: NamedTempFile,
    _certificate: TempPath,
    _key: TempPath,
}

impl StressFixture {
    async fn start(echo_suffix: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let mut ports = PortHelper::new();
        let (shoes_ip, shoes_port) = ports.get_listener_port();
        let (singbox_ip, singbox_port) = ports.get_listener_port();
        let (echo_ip, echo_port) = ports.get_port();
        let echo_address: SocketAddr = format!("{echo_ip}:{echo_port}").parse()?;
        let echo_server =
            start_udp_echo_server_with_suffix(&echo_ip, echo_port, echo_suffix).await?;
        let (certificate, key) = generate_test_cert_files()?;

        let shoes_config = format!(
            r#"
- address: "{shoes_ip}:{shoes_port}"
  protocol:
    type: tls
    tls_targets:
      test.local:
        cert: {}
        key: {}
        vision: true
        protocol:
          type: vless
          user_id: "{TEST_UUID}"
          udp_enabled: true
"#,
            AsRef::<Path>::as_ref(&certificate).display(),
            AsRef::<Path>::as_ref(&key).display(),
        );
        let singbox_config = format!(
            r#"{{
  "log": {{"level": "warn"}},
  "inbounds": [{{
    "type": "vless",
    "tag": "vless-in",
    "listen": "{singbox_ip}",
    "listen_port": {singbox_port},
    "users": [{{"uuid": "{TEST_UUID}"}}]
  }}],
  "outbounds": [{{
    "type": "vless",
    "tag": "vless-out",
    "server": "{shoes_ip}",
    "server_port": {shoes_port},
    "uuid": "{TEST_UUID}",
    "flow": "xtls-rprx-vision",
    "tls": {{
      "enabled": true,
      "server_name": "test.local",
      "insecure": true
    }},
    "packet_encoding": "xudp"
  }}],
  "route": {{"final": "vless-out"}}
}}"#,
        );

        let (shoes_guard, shoes_config) = start_shoes_server(&shoes_config)?;
        let (singbox_guard, singbox_config) = start_singbox_server(&singbox_config)?;
        ports.wait_for_all_ports().await?;

        let stream = TcpStream::connect((singbox_ip.as_str(), singbox_port)).await?;
        let client = VlessUdpClient::connect(
            stream,
            parse_uuid(TEST_UUID)?,
            VlessDestination::Ip(echo_address),
        )
        .await?;

        Ok(Self {
            client,
            _echo_server: echo_server,
            _shoes_guard: shoes_guard,
            _shoes_config: shoes_config,
            _singbox_guard: singbox_guard,
            _singbox_config: singbox_config,
            _certificate: certificate,
            _key: key,
        })
    }
}

#[tokio::test]
#[ignore = "manual 60-second sustained traffic test"]
async fn test_sustained_traffic_500_packets() -> Result<(), Box<dyn std::error::Error>> {
    const TOTAL_PACKETS: u32 = 500;
    let mut fixture = StressFixture::start(b" [ECHO]").await?;
    let delay = Duration::from_secs(60) / TOTAL_PACKETS;

    for index in 1..=TOTAL_PACKETS {
        let request = format!("Long-lived-{index:04}");
        fixture.client.send_packet(request.as_bytes()).await?;
        let response = fixture.client.recv_packet(Duration::from_secs(5)).await?;
        assert_eq!(response, format!("{request} [ECHO]").as_bytes());
        sleep(delay).await;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "manual 1000-packet burst test"]
async fn test_high_volume_burst_1000_packets() -> Result<(), Box<dyn std::error::Error>> {
    const TOTAL_PACKETS: u32 = 1000;
    let mut fixture = StressFixture::start(b" [ECHO]").await?;
    let mut expected = HashSet::with_capacity(TOTAL_PACKETS as usize);

    for index in 1..=TOTAL_PACKETS {
        let request = format!("Burst-{index:04}");
        fixture.client.send_packet(request.as_bytes()).await?;
        expected.insert(format!("{request} [ECHO]").into_bytes());
    }

    for _ in 0..TOTAL_PACKETS {
        let response = fixture.client.recv_packet(Duration::from_secs(10)).await?;
        assert!(
            expected.remove(&response),
            "duplicate or unexpected response"
        );
    }
    assert!(expected.is_empty(), "missing {} responses", expected.len());
    Ok(())
}

#[tokio::test]
async fn test_content_integrity_varying_sizes() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = StressFixture::start(b"").await?;
    let test_sizes = [1, 7, 16, 100, 255, 256, 512, 1024, 1400, 2048, 4096, 8192];

    for size in test_sizes {
        let payload: Vec<u8> = (0..size)
            .map(|index| ((index * 17 + 42) % 256) as u8)
            .collect();
        fixture.client.send_packet(&payload).await?;
        let response = fixture.client.recv_packet(Duration::from_secs(5)).await?;
        assert_eq!(response, payload, "payload mismatch at {size} bytes");
    }
    Ok(())
}
