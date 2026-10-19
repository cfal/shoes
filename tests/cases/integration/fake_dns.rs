use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_resolver::proto::op::{Message, Query, ResponseCode};
use hickory_resolver::proto::rr::{Name, RData, RecordType};
use serde_json::json;
use shoes_test_support::certs::generate_test_cert_files;
use shoes_test_support::port_helper::PortHelper;
use shoes_test_support::socks5::{Socks5UdpAssociation, SocksDestination, encode_udp_datagram};
use shoes_test_support::test_fixture::{start_shoes_server, start_singbox_server};
use shoes_test_support::test_servers::start_udp_echo_server_with_suffix;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const UUID: &str = "b85798ef-e9dc-46a4-9a87-8da4499d36d0";

fn question(name: &str, kind: RecordType) -> Vec<u8> {
    let mut query = Message::query();
    query.metadata.id = 42;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    query.to_vec().unwrap()
}

async fn send(
    association: &Socks5UdpAssociation,
    target: SocksDestination,
    payload: &[u8],
) -> Result<Vec<u8>> {
    association
        .socket()
        .send_to(
            &encode_udp_datagram(&target, payload)?,
            association.relay_addr(),
        )
        .await?;
    let mut bytes = [0; 65536];
    let (len, relay) = tokio::time::timeout(
        Duration::from_secs(5),
        association.socket().recv_from(&mut bytes),
    )
    .await??;
    assert_eq!(relay, association.relay_addr());
    let header = encode_udp_datagram(&target, b"")?;
    assert!(
        bytes[..len].starts_with(&header),
        "reply identity differs from wire destination {target:?}"
    );
    Ok(bytes[header.len()..len].to_vec())
}

async fn udp_case(protocol: &str) -> Result<()> {
    let mut tasks = tokio::task::JoinSet::new();
    let upstream = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    let upstream_port = upstream.local_addr()?.port();
    let exchanges = Arc::new(AtomicUsize::new(0));
    let calls = exchanges.clone();
    tasks.spawn(async move {
        let mut bytes = [0; 4096];
        loop {
            let (len, peer) = upstream.recv_from(&mut bytes).await.unwrap();
            calls.fetch_add(1, Ordering::SeqCst);
            let mut response = Message::from_vec(&bytes[..len]).unwrap().into_response();
            response.metadata.response_code = ResponseCode::NXDomain;
            upstream
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let mut ports = PortHelper::new();
    let quic = matches!(protocol, "hysteria2" | "tuic");
    let (_, ingress_port) = if quic {
        ports.get_quic_listener_port()
    } else {
        ports.get_localhost_listener_port()
    };
    let (_, shared_port) = ports.get_localhost_listener_port();
    let (_, first_port) = ports.get_port();
    let (_, second_port) = ports.get_port();
    let _first = start_udp_echo_server_with_suffix("0.0.0.0", first_port, b" [FIRST]").await?;
    let _second = start_udp_echo_server_with_suffix("0.0.0.0", second_port, b" [SECOND]").await?;
    let rules = json!([
        {"mask":"first.example", "action":"allow", "override_address":format!("127.0.0.1:{first_port}")},
        {"mask":"second.example", "action":"allow", "override_address":format!("127.0.0.1:{second_port}")},
        {"mask":"127.0.0.1", "action":"allow"},
        {"mask":"0.0.0.0/0", "action":"block"}
    ]);
    let (certificate, key) = generate_test_cert_files()?;
    let server_protocol = match protocol {
        "native" | "uot1" | "uot2" => json!({"type":"socks", "udp_enabled":true}),
        "vless" | "h2mux" => json!({"type":"vless", "user_id":UUID, "udp_enabled":true}),
        "vmess" => {
            json!({"type":"vmess", "user_id":UUID, "cipher":"chacha20-poly1305", "udp_enabled":true})
        }
        "hysteria2" => json!({"type":"hysteria2", "password":"fake-dns-test", "udp_enabled":true}),
        "tuic" => json!({"type":"tuic", "uuid":UUID, "password":"fake-dns-test"}),
        "anytls" => json!({"type":"tls", "tls_targets":{"test.local":{
            "cert":certificate.display().to_string(),
            "key":key.display().to_string(),
            "protocol":{"type":"anytls", "users":[{"name":"test","password":"fake-dns-test"}]}
        }}}),
        _ => unreachable!(),
    };
    let mut ingress = json!({
        "address":format!("0.0.0.0:{ingress_port}"),
        "protocol":server_protocol,
        "dns":{"servers":"shared"},
        "rules":rules
    });
    if quic {
        ingress["transport"] = "quic".into();
        ingress["quic_settings"] = json!({
            "cert":certificate.display().to_string(), "key":key.display().to_string(), "num_endpoints":1, "alpn_protocols":["h3"]
        });
    }
    let config = json!([
        {"dns_group":"shared", "dns_servers":format!("udp://127.0.0.1:{upstream_port}"), "fake_ip":true},
        ingress,
        {"address":format!("0.0.0.0:{shared_port}"), "protocol":{"type":"socks"},
         "dns":{"servers":"shared"}, "rules":rules}
    ]);
    let (_shoes, _config) = start_shoes_server(&config.to_string())?;
    let mut client_port = ingress_port;
    let mut client_guard = None;
    if protocol != "native" {
        let (_, port) = ports.get_localhost_listener_port();
        client_port = port;
        let mut outbound = json!({
            "type": if protocol.starts_with("uot") { "socks" } else if protocol == "h2mux" { "vless" } else { protocol },
            "tag":"out", "server":"127.0.0.1", "server_port":ingress_port
        });
        match protocol {
            "uot1" | "uot2" => {
                outbound["udp_over_tcp"] =
                    json!({"enabled":true, "version":if protocol == "uot1" {1} else {2}})
            }
            "vless" | "vmess" | "h2mux" => {
                outbound["uuid"] = UUID.into();
                if protocol == "h2mux" {
                    outbound["multiplex"] = json!({"enabled":true, "protocol":"h2mux", "max_connections":1, "padding":true});
                } else {
                    outbound["packet_encoding"] = "xudp".into();
                }
                if protocol == "vmess" {
                    outbound["security"] = "chacha20-poly1305".into();
                }
            }
            "hysteria2" | "tuic" | "anytls" => {
                outbound["password"] = "fake-dns-test".into();
                outbound["tls"] = if protocol == "anytls" {
                    json!({"enabled":true, "insecure":true, "server_name":"test.local"})
                } else {
                    json!({"enabled":true, "insecure":true, "alpn":["h3"]})
                };
                if protocol == "tuic" {
                    outbound["uuid"] = UUID.into();
                }
            }
            _ => unreachable!(),
        }
        let config = json!({
            "log":{"level":"warn"},
            "inbounds":[{"type":"socks", "listen":"0.0.0.0", "listen_port":client_port}],
            "outbounds":[outbound], "route":{"final":"out"}
        });
        client_guard = Some(start_singbox_server(&config.to_string())?);
    }
    ports.wait_for_all_ports().await?;
    let association = Socks5UdpAssociation::connect("127.0.0.1", client_port).await?;
    let initial = SocksDestination::Ip(SocketAddr::from(([127, 0, 0, 1], first_port)));
    assert_eq!(
        send(&association, initial, b"initial").await?,
        b"initial [FIRST]"
    );
    let shared = Socks5UdpAssociation::connect("127.0.0.1", shared_port).await?;
    let mut fake_addresses = Vec::new();
    for name in ["first.example.", "second.example."] {
        let query = question(name, RecordType::A);
        let reply = send(
            &association,
            SocksDestination::Ip("198.18.0.1:53".parse()?),
            &query,
        )
        .await?;
        let response = Message::from_vec(&reply)?;
        assert_eq!(response.metadata.id, 42);
        let RData::A(address) = response.answers[0].data else {
            panic!("missing fake A answer")
        };
        let fake = SocksDestination::Ip(SocketAddr::new(IpAddr::V4(address.0), 9999));
        fake_addresses.push(fake);
    }
    for association in [&association, &shared] {
        for _ in 0..2 {
            for (target, suffix) in fake_addresses.iter().zip([" [FIRST]", " [SECOND]"]) {
                assert_eq!(
                    send(association, target.clone(), b"mapped").await?,
                    format!("mapped{suffix}").as_bytes()
                );
            }
        }
    }
    let reply = send(
        &association,
        SocksDestination::Ip("192.0.2.1:53".parse()?),
        &question("txt.example.", RecordType::TXT),
    )
    .await?;
    assert_eq!(
        Message::from_vec(&reply)?.metadata.response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(exchanges.load(Ordering::SeqCst), 1);
    // SOCKS itself must retain a hostname DNS destination without trying native DNS first.
    if protocol == "native" {
        let SocksDestination::Ip(first) = &fake_addresses[0] else {
            unreachable!()
        };
        assert_eq!(
            send(
                &association,
                SocksDestination::Hostname(first.ip().to_string(), first.port()),
                b"encoded"
            )
            .await?,
            b"encoded [FIRST]"
        );
        let mut invalid = vec![0, 0, 0, 3, 0, 0, 53];
        invalid.extend_from_slice(&question("first.example.", RecordType::A));
        association
            .socket()
            .send_to(&invalid, association.relay_addr())
            .await?;
        let reply = send(
            &association,
            SocksDestination::Hostname("unresolvable.invalid".into(), 53),
            &question("first.example.", RecordType::A),
        )
        .await?;
        assert_eq!(Message::from_vec(&reply)?.answers.len(), 1);
    }
    drop(client_guard);
    Ok(())
}

#[tokio::test]
async fn native_udp_fake_dns() -> Result<()> {
    udp_case("native").await
}
#[tokio::test]
async fn uot_v1_fake_dns() -> Result<()> {
    udp_case("uot1").await
}
#[tokio::test]
async fn uot_v2_fake_dns() -> Result<()> {
    udp_case("uot2").await
}
#[tokio::test]
async fn vless_xudp_fake_dns() -> Result<()> {
    udp_case("vless").await
}
#[tokio::test]
async fn vmess_xudp_fake_dns() -> Result<()> {
    udp_case("vmess").await
}
#[tokio::test]
async fn hysteria2_udp_fake_dns() -> Result<()> {
    udp_case("hysteria2").await
}
#[tokio::test]
async fn tuic_udp_fake_dns() -> Result<()> {
    udp_case("tuic").await
}

#[tokio::test]
async fn anytls_udp_fake_dns() -> Result<()> {
    udp_case("anytls").await
}

#[tokio::test]
async fn h2mux_udp_fake_dns() -> Result<()> {
    udp_case("h2mux").await
}

#[tokio::test]
async fn port_53_interception_does_not_probe_or_forward_non_dns() -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(Duration::from_secs(20), async {
        for enabled in [false, true] {
            let tcp = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
            let echo_port = tcp.local_addr()?.port();
            let udp = tokio::net::UdpSocket::bind(("0.0.0.0", echo_port)).await?;
            let upstream = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
            let calls = Arc::new(AtomicUsize::new(0));
            let mut tasks = tokio::task::JoinSet::new();
            let count = calls.clone();
            tasks.spawn(async move {
                loop {
                    let (mut stream, _) = tcp.accept().await.unwrap();
                    count.fetch_add(1, Ordering::SeqCst);
                    let mut bytes = Vec::new();
                    stream.read_to_end(&mut bytes).await.unwrap();
                    stream.write_all(&bytes).await.unwrap();
                }
            });
            let count = calls.clone();
            tasks.spawn(async move {
                let mut bytes = [0; 2048];
                loop {
                    let (length, peer) = udp.recv_from(&mut bytes).await.unwrap();
                    count.fetch_add(1, Ordering::SeqCst);
                    udp.send_to(&bytes[..length], peer).await.unwrap();
                }
            });
            let mut ports = PortHelper::new();
            let (_, port) = ports.get_localhost_listener_port();
            let config = json!([{
                "address": format!("0.0.0.0:{port}"),
                "protocol": {"type":"socks", "udp_enabled":true},
                "sniff":true,
                "dns":{"fake_ip":enabled, "servers":format!("udp://127.0.0.1:{}", upstream.local_addr()?.port())},
                "rules":[
                    {"mask":"sniff.invalid", "action":"block"},
                    {"mask":"0.0.0.0/0", "action":"allow", "override_address":format!("127.0.0.1:{echo_port}")}
                ]
            }]);
            let (_process, _config) = start_shoes_server(&config.to_string())?;
            ports.wait_for_all_ports().await?;
            let payload = [0, 3, 1, 2, 3];
            let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
            super::plain_tcp_relay::request_to(&mut tcp, "socks", "127.0.0.1:53".parse()?, &payload).await?;
            tcp.shutdown().await?;
            let mut reply = Vec::new();
            tcp.read_to_end(&mut reply).await?;
            assert_eq!(reply, if enabled { vec![] } else { payload.to_vec() });

            let association = Socks5UdpAssociation::connect("127.0.0.1", port).await?;
            let target = SocksDestination::Ip("127.0.0.1:53".parse()?);
            if enabled {
                association.socket().send_to(&encode_udp_datagram(&target, &payload)?, association.relay_addr()).await?;
                let reply = send(&association, target, &question("recovered.example", RecordType::A)).await?;
                assert_eq!(Message::from_vec(&reply)?.answers.len(), 1);
            } else {
                assert_eq!(send(&association, target, &payload).await?, payload);
            }
            assert_eq!(calls.load(Ordering::SeqCst), if enabled { 0 } else { 2 });
            assert!(tokio::time::timeout(Duration::from_millis(20), upstream.recv(&mut [0; 2048])).await.is_err());
        }
        Result::Ok(())
    }).await?
}
