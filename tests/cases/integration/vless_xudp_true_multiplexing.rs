//! Multiple-destination coverage through one SOCKS5 UDP association.

use std::collections::HashSet;
use std::error::Error;
use std::path::Path;
use std::time::Duration;

use shoes_test_support as common;
use tokio::time::{Instant, timeout_at};

use common::certs::generate_test_cert_files;
use common::socks5::{
    Socks5UdpAssociation, SocksDestination, decode_udp_datagram, encode_udp_datagram,
};
use common::test_fixture::{TEST_UUID, start_shoes_server, start_singbox_server};
use common::test_servers::start_udp_echo_server_with_suffix;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[tokio::test]
async fn one_socks_association_reaches_multiple_xudp_destinations() -> TestResult {
    let mut ports = common::port_helper::PortHelper::new();
    let (shoes_ip, shoes_port) = ports.get_listener_port();
    let (singbox_ip, singbox_port) = ports.get_listener_port();
    let echoes = [
        start_udp_echo_server_with_suffix("127.0.0.1", 0, b" [SERVER-1]").await?,
        start_udp_echo_server_with_suffix("127.0.0.1", 0, b" [SERVER-2]").await?,
        start_udp_echo_server_with_suffix("127.0.0.1", 0, b" [SERVER-3]").await?,
    ];

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
    "type": "socks",
    "tag": "socks-in",
    "listen": "{singbox_ip}",
    "listen_port": {singbox_port}
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

    let association = Socks5UdpAssociation::connect(&singbox_ip, singbox_port).await?;
    let cases = [
        (
            echoes[0].local_addr(),
            b"request-1".as_slice(),
            b" [SERVER-1]".as_slice(),
        ),
        (
            echoes[1].local_addr(),
            b"request-2".as_slice(),
            b" [SERVER-2]".as_slice(),
        ),
        (
            echoes[2].local_addr(),
            b"request-3".as_slice(),
            b" [SERVER-3]".as_slice(),
        ),
    ];

    for (destination, request, _) in cases {
        let datagram = encode_udp_datagram(&SocksDestination::Ip(destination), request)?;
        association
            .socket()
            .send_to(&datagram, association.relay_addr())
            .await?;
    }

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut responses = HashSet::new();
    for _ in cases {
        let mut buffer = [0; 65_536];
        let (length, source) =
            timeout_at(deadline, association.socket().recv_from(&mut buffer)).await??;
        assert_eq!(source, association.relay_addr());
        responses.insert(decode_udp_datagram(&buffer[..length])?.to_vec());
    }
    let expected: HashSet<_> = cases
        .iter()
        .map(|(_, request, suffix)| [*request, *suffix].concat())
        .collect();
    assert_eq!(responses, expected);

    for (destination, _, suffix) in cases.iter().rev() {
        let response = association
            .send_to_with_timeout(
                SocksDestination::Ip(*destination),
                b"repeat",
                Duration::from_secs(5),
            )
            .await?;
        assert_eq!(response, [b"repeat".as_slice(), *suffix].concat());
    }
    Ok(())
}
