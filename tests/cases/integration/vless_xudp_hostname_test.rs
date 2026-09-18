//! VLESS XUDP hostname interoperability coverage.

use std::error::Error;
use std::path::Path;
use std::time::Duration;

use shoes_test_support as common;
use tokio::net::TcpStream;

use common::certs::generate_test_cert_files;
use common::test_fixture::{TEST_UUID, start_shoes_server, start_singbox_server};
use common::test_servers::start_udp_echo_server_with_suffix;
use common::vless::{VlessDestination, VlessUdpClient, parse_uuid};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[tokio::test]
async fn xudp_preserves_a_domain_destination_across_the_proxy_chain() -> TestResult {
    let mut ports = common::port_helper::PortHelper::new();
    let (shoes_ip, shoes_port) = ports.get_listener_port();
    let (singbox_ip, singbox_port) = ports.get_listener_port();

    let ipv6_echo = start_udp_echo_server_with_suffix("::1", 0, b" [ECHO]").await?;
    let echo_port = ipv6_echo.local_addr().port();
    let _ipv4_echo = start_udp_echo_server_with_suffix("127.0.0.1", echo_port, b" [ECHO]").await?;

    let (cert_path, key_path) = generate_test_cert_files()?;
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
        AsRef::<Path>::as_ref(&cert_path).display(),
        AsRef::<Path>::as_ref(&key_path).display(),
    );
    let singbox_config = format!(
        r#"{{
  "log": {{ "level": "debug" }},
  "inbounds": [{{
    "type": "vless",
    "tag": "vless-in",
    "listen": "{singbox_ip}",
    "listen_port": {singbox_port},
    "users": [{{ "uuid": "{TEST_UUID}" }}]
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
  "route": {{ "final": "vless-out" }}
}}"#
    );

    let (_shoes, _shoes_config) = start_shoes_server(&shoes_config)?;
    let (_singbox, _singbox_config) = start_singbox_server(&singbox_config)?;
    ports.wait_for_all_ports().await?;

    let stream = TcpStream::connect((singbox_ip.as_str(), singbox_port)).await?;
    let mut client = VlessUdpClient::connect(
        stream,
        parse_uuid(TEST_UUID)?,
        VlessDestination::Domain("localhost".to_string(), echo_port),
    )
    .await?;
    client.send_packet(b"hostname destination").await?;

    assert_eq!(
        client.recv_packet(Duration::from_secs(5)).await?,
        b"hostname destination [ECHO]"
    );
    Ok(())
}
