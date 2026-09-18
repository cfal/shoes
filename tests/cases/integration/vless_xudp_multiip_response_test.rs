use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use shoes_test_support::certs::generate_test_cert_files;
use shoes_test_support::port_helper::PortHelper;
use shoes_test_support::test_fixture::{TEST_UUID, start_shoes_server, start_singbox_server};
use shoes_test_support::test_servers::start_udp_asymmetric_echo_server;
use shoes_test_support::vless::{VlessDestination, VlessUdpClient, parse_uuid};
use tokio::net::TcpStream;

#[tokio::test]
async fn test_xudp_accepts_response_from_alternate_source() -> Result<(), Box<dyn std::error::Error>>
{
    let mut ports = PortHelper::new();
    let (shoes_ip, shoes_port) = ports.get_listener_port();
    let (singbox_ip, singbox_port) = ports.get_listener_port();
    let (primary_ip, primary_port) = ports.get_port();
    let (response_ip, response_port) = loop {
        let candidate = ports.get_port();
        if candidate.0 != primary_ip {
            break candidate;
        }
    };
    let primary_address: SocketAddr = format!("{primary_ip}:{primary_port}").parse()?;
    let (echo_server, response_address) = start_udp_asymmetric_echo_server(
        &primary_ip,
        primary_port,
        &response_ip,
        response_port,
        b" [ALTERNATE_SOURCE]",
    )
    .await?;
    assert_eq!(echo_server.local_addr(), primary_address);
    assert_ne!(response_address.ip(), primary_address.ip());

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

    let (_shoes_guard, _shoes_config) = start_shoes_server(&shoes_config)?;
    let (_singbox_guard, _singbox_config) = start_singbox_server(&singbox_config)?;
    ports.wait_for_all_ports().await?;

    let stream = TcpStream::connect((singbox_ip.as_str(), singbox_port)).await?;
    let mut client = VlessUdpClient::connect(
        stream,
        parse_uuid(TEST_UUID)?,
        VlessDestination::Ip(primary_address),
    )
    .await?;
    client.send_packet(b"asymmetric response").await?;
    assert_eq!(
        client.recv_packet(Duration::from_secs(5)).await?,
        b"asymmetric response [ALTERNATE_SOURCE]"
    );
    Ok(())
}
