use super::support::{start, target};
use crate::wireguard_support as config;
use serde_json::json;
use shoes_test_support::{port_helper::PortHelper, wireguard::EchoTargets};
use std::{io, time::Duration};

#[tokio::test]
async fn named_outer_chains_carry_wireguard_over_each_supported_stream_protocol() -> io::Result<()>
{
    tokio::time::timeout(Duration::from_secs(90), async {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        for mode in ["tls-vless", "vmess", "shadowsocks", "tls-anytls"] {
            let reservation = std::net::UdpSocket::bind("0.0.0.0:0")?;
            let port = reservation.local_addr()?.port();
            let mut ports = PortHelper::new();
            let (_, entry) = ports.get_localhost_listener_port();
            let (_, outer) = ports.get_localhost_listener_port();
            let protocol = match mode {
                "tls-vless" => config::vless_protocol(),
                "vmess" => json!({"type": "vmess", "user_id": shoes_test_support::test_fixture::TEST_UUID, "cipher": "aes-128-gcm"}),
                "shadowsocks" => json!({"type": "shadowsocks", "cipher": "aes-256-gcm", "password": "wireguard-test"}),
                "tls-anytls" => json!({"type": "anytls", "password": "wireguard-test"}),
                _ => unreachable!(),
            };
            let server_protocol = if mode == "tls-anytls" {
                json!({"type": "anytls", "users": [{"password": "wireguard-test"}]})
            } else { protocol.clone() };
            let (server_protocol, client_protocol) = if mode.starts_with("tls-") {
                (json!({"type": "tls", "tls_targets": {"localhost": {
                    "cert": certificate.cert.pem(), "key": certificate.signing_key.serialize_pem(), "protocol": server_protocol,
                }}}), json!({"type": "tls", "sni_hostname": "localhost", "verify": false, "protocol": protocol}))
            } else { (protocol.clone(), protocol) };
            let mut client = config::client(port);
            client["client_proxies"][0]["address"] = json!(format!("192.0.2.200:{port}"));
            client["client_proxies"][0]["protocol"]["peer_client_chain"] = json!("outer");
            let server = json!([
                config::server(port),
                {"address": format!("0.0.0.0:{outer}"), "protocol": server_protocol,
                 "rules": [{"masks": "192.0.2.200/32", "action": "allow", "override_address": "127.0.0.1:0"}]},
            ]);
            drop(reservation);
            let _server = start(&server)?;
            let _client = start(&json!([
                {"client_group": "outer", "client_proxies": [{"address": format!("127.0.0.1:{outer}"), "protocol": client_protocol}]},
                client, config::socks(entry),
            ]))?;
            ports.wait_for_all_ports().await?;
            for ipv6 in [false, true] {
                EchoTargets::new(ipv6).await?.check(entry, Some(target(ipv6, 0).ip())).await?;
            }
        }
        Ok(())
    }).await?
}

#[tokio::test]
async fn nested_endpoints_start_in_dependency_order_in_a_real_process() -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let carrier_socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        let inner_socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        let carrier_port = carrier_socket.local_addr()?.port();
        let inner_port = inner_socket.local_addr()?.port();
        let mut ports = PortHelper::new();
        let (_, entry) = ports.get_localhost_listener_port();
        let mut carrier = config::client(carrier_port);
        carrier["client_group"] = json!("carrier");
        let mut inner = config::client(inner_port);
        inner["client_proxies"][0]["protocol"]["mtu"] = json!(1280);
        inner["client_proxies"][0]["address"] = json!(format!("198.18.0.1:{inner_port}"));
        inner["client_proxies"][0]["protocol"]["peer_client_chain"] = json!("carrier");
        drop((carrier_socket, inner_socket));
        let _carrier = start(&json!([config::server(carrier_port)]))?;
        let _inner = start(&json!([config::server(inner_port)]))?;
        let _client = start(&json!([inner, config::socks(entry), carrier]))?;
        ports.wait_for_all_ports().await?;
        for ipv6 in [false, true] {
            EchoTargets::new(ipv6)
                .await?
                .check(entry, Some(target(ipv6, 0).ip()))
                .await?;
        }
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn outer_pool_reconnects_through_an_alternate_member_without_restarting_flows()
-> io::Result<()> {
    use super::support::{exchange, udp_echo};
    use shoes_test_support::{socks5::Socks5UdpAssociation, wireguard::connect};
    tokio::time::timeout(Duration::from_secs(90), async {
        let reservation = std::net::UdpSocket::bind("0.0.0.0:0")?;
        let port = reservation.local_addr()?.port();
        let mut ports = PortHelper::new();
        let (_, entry) = ports.get_localhost_listener_port();
        let (_, primary) = ports.get_localhost_listener_port();
        let backup_socket = tokio::net::TcpSocket::new_v4()?;
        backup_socket.bind("127.0.0.1:0".parse().unwrap())?;
        let backup = backup_socket.local_addr()?.port();
        let proxy = |port| json!([{
            "address": format!("0.0.0.0:{port}"), "protocol": config::vless_protocol(),
            "rules": [{"masks": "192.0.2.200/32", "action": "allow", "override_address": "127.0.0.1:0"}],
        }]);
        let mut client = config::client(port);
        client["client_proxies"][0]["address"] = json!(format!("192.0.2.200:{port}"));
        client["client_proxies"][0]["protocol"]["peer_client_chain"] = json!([{"pool": ["primary", "backup"]}]);
        let group = |name, port| json!({"client_group": name, "client_proxies": [{
            "address": format!("127.0.0.1:{port}"), "protocol": config::vless_protocol(),
        }]});
        drop(reservation);
        let _server = start(&json!([config::server(port)]))?;
        let primary_process = start(&proxy(primary))?;
        let _client = start(&json!([
            group("primary", primary), group("backup", backup), client, config::socks(entry),
        ]))?;
        ports.wait_for_all_ports().await?;
        let echo = EchoTargets::new(false).await?;
        let mut tcp = connect(entry, target(false, echo.tcp().port())).await?;
        exchange(&mut tcp, b"primary").await?;
        let udp = Socks5UdpAssociation::connect("127.0.0.1", entry).await?;
        udp_echo(&udp, target(false, echo.udp().port()), b"pool").await?;
        drop(primary_process);
        drop(backup_socket);
        let _backup = start(&proxy(backup))?;
        // An encrypted association is rebuilt, not the inner TCP/UDP connections.
        tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                if udp_echo(&udp, target(false, echo.udp().port()), b"pool").await.is_ok() { break; }
            }
        }).await?;
        exchange(&mut tcp, b"backup, same TCP connection").await?;
        EchoTargets::new(true).await?.check(entry, Some(target(true, 0).ip())).await?;
        Ok(())
    }).await?
}
