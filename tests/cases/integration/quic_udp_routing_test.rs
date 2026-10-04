use std::net::SocketAddr;

use shoes_test_support::certs::generate_test_cert_files;
use shoes_test_support::port_helper::PortHelper;
use shoes_test_support::socks5::Socks5UdpAssociation;
use shoes_test_support::test_fixture::{start_shoes_server, start_singbox_server};
use shoes_test_support::test_servers::start_udp_echo_server;

const UUID: &str = "b85798ef-e9dc-46a4-9a87-8da4499d36d0";

async fn check_proxy_routing(
    protocol: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut ports = PortHelper::new();
    let (_, quic_port) = ports.get_quic_listener_port();
    let (_, downstream_port) = ports.get_localhost_listener_port();
    let (_, socks_port) = ports.get_localhost_listener_port();
    let (_, echo_port) = ports.get_quic_listener_port();
    let _echo = start_udp_echo_server("0.0.0.0", echo_port).await?;
    let (cert, key) = generate_test_cert_files()?;

    // Only the downstream proxy knows the real target. A direct bypass cannot reply.
    let blackhole = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    let requested_target = SocketAddr::from(([127, 0, 0, 1], blackhole.local_addr()?.port()));
    let credentials = match protocol {
        "hysteria2" => "    udp_enabled: true".to_string(),
        "tuic" => format!("    uuid: {UUID}"),
        _ => unreachable!(),
    };
    let config = format!(
        r#"
- address: "0.0.0.0:{downstream_port}"
  protocol:
    type: vless
    user_id: {UUID}
  rules:
    - mask: 0.0.0.0/0
      action: allow
      override_address: "127.0.0.1:{echo_port}"
- address: "0.0.0.0:{quic_port}"
  transport: quic
  quic_settings:
    cert: "{}"
    key: "{}"
    num_endpoints: 1
    alpn_protocols: [h3]
  protocol:
    type: {protocol}
    password: routing-test
{credentials}
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_chain:
        - address: "127.0.0.1:{downstream_port}"
          protocol:
            type: vless
            user_id: {UUID}
"#,
        cert.display(),
        key.display(),
    );
    let (_shoes, _config) = start_shoes_server(&config)?;
    let mut outbound = serde_json::json!({
        "type": protocol,
        "tag": "quic-out",
        "server": "127.0.0.1",
        "server_port": quic_port,
        "password": "routing-test",
        "tls": { "enabled": true, "insecure": true, "alpn": ["h3"] }
    });
    if protocol == "tuic" {
        outbound["uuid"] = UUID.into();
    }
    let singbox = serde_json::json!({
        "log": { "level": "warn" },
        "inbounds": [{ "type": "socks", "listen": "0.0.0.0", "listen_port": socks_port }],
        "outbounds": [outbound],
        "route": { "final": "quic-out" }
    });
    let (_singbox, _config) = start_singbox_server(&singbox.to_string())?;
    ports.wait_for_all_ports().await?;

    let association = Socks5UdpAssociation::connect("127.0.0.1", socks_port).await?;
    for sequence in 0..3 {
        let payload = format!("{protocol}-routed-{sequence}");
        let reply = association
            .send_to(requested_target, payload.as_bytes())
            .await?;
        assert!(reply.starts_with(payload.as_bytes()));
        assert!(std::str::from_utf8(&reply)?.contains("[ECHO"));
    }
    Ok(())
}

#[tokio::test]
async fn hysteria2_udp_obeys_selected_proxy_chain()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    check_proxy_routing("hysteria2").await
}

#[tokio::test]
async fn tuic_udp_obeys_selected_proxy_chain()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    check_proxy_routing("tuic").await
}
