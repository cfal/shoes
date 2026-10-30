use crate::wireguard_support as config;
use gotatun::packet::{Packet, WgKind};
use serde_json::{Value, json};
use shoes_test_support::{
    port_helper::PortHelper, process::start_singbox_server_with_binary,
    test_fixture::start_shoes_server, wireguard::EchoTargets,
};
use std::{io, path::PathBuf, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn singbox_server(port: u16) -> Value {
    json!({
        "log": {"level": "warn"},
        "endpoints": [{
            "type": "wireguard", "tag": "wg", "system": false,
            "address": ["10.77.0.1/32", "fd77::1/128"],
            "private_key": config::key(41), "listen_port": port, "mtu": 1408,
            "peers": [{
                "public_key": config::public(42), "pre_shared_key": config::key(43),
                "allowed_ips": ["10.77.0.2/32", "fd77::2/128"]
            }]
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct", "rules": [
            {"ip_cidr": ["0.0.0.0/0"], "action": "route", "outbound": "direct", "override_address": "127.0.0.1"},
            {"ip_cidr": ["::/0"], "action": "route", "outbound": "direct", "override_address": "::1"}
        ]}
    })
}

#[tokio::test]
#[ignore = "Requires Xray 26.10.29; set SHOES_TEST_XRAY_BIN"]
async fn wireguard_xray_both_roles_tcp_udp_ipv4_ipv6() -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(90), async {
        for shoes_is_server in [false, true] {
            let reservation = std::net::UdpSocket::bind("0.0.0.0:0")?;
            let port = reservation.local_addr()?.port();
            let mut ports = PortHelper::new();
            let (_, entry) = ports.get_localhost_listener_port();
            let (shoes, peer) = if shoes_is_server {
                let peer = json!({
                    "log": {"loglevel": "warning"},
                    "inbounds": [{
                        "protocol": "socks", "listen": "0.0.0.0", "port": entry,
                        "settings": {"auth": "noauth", "udp": true}
                    }],
                    "outbounds": [{"protocol": "wireguard", "settings": {
                        "noKernelTun": true, "address": ["10.77.0.2/32", "fd77::2/128"],
                        "secretKey": config::key(42), "mtu": 1408,
                        "peers": [{
                            "publicKey": config::public(41), "preSharedKey": config::key(43),
                            "endpoint": format!("127.0.0.1:{port}"),
                            "allowedIPs": ["0.0.0.0/0", "::/0"]
                        }]
                    }}]
                });
                (json!([config::server(port)]), peer)
            } else {
                // Xray blocks private destinations from WireGuard inbounds unless explicitly allowed.
                let peer = json!({
                    "log": {"loglevel": "warning"},
                    "inbounds": [{
                        "protocol": "wireguard", "listen": "0.0.0.0", "port": port,
                        "settings": {
                            "noKernelTun": true, "address": ["10.77.0.1/32", "fd77::1/128"],
                            "secretKey": config::key(41), "mtu": 1408,
                            "peers": [{
                                "publicKey": config::public(42), "preSharedKey": config::key(43),
                                "allowedIPs": ["10.77.0.2/32", "fd77::2/128"]
                            }]
                        }
                    }],
                    "outbounds": [
                        {"protocol": "freedom", "tag": "direct4", "settings": {
                            "redirect": "127.0.0.1:0",
                            "finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"]}]
                        }},
                        {"protocol": "freedom", "tag": "direct6", "settings": {
                            "redirect": "[::1]:0",
                            "finalRules": [{"action": "allow", "ip": ["::1/128"]}]
                        }}
                    ],
                    "routing": {"rules": [{"type": "field", "ip": ["::/0"], "outboundTag": "direct6"}]}
                });
                (json!([config::client(port), config::socks(entry)]), peer)
            };
            let peer_reservation = if shoes_is_server {
                drop(reservation);
                None
            } else {
                Some(reservation)
            };
            let _shoes = start_shoes_server(&serde_yaml::to_string(&shoes).unwrap())?;
            if !shoes_is_server {
                // Xray allocates a readiness listener; bind Shoes' SOCKS port first.
                shoes_test_support::xray::wait_socks(([127, 0, 0, 1], entry).into()).await?;
            }
            drop(peer_reservation);
            let _peer = shoes_test_support::xray::start(peer).await?;
            ports.wait_for_all_ports().await?;
            for ipv6 in [false, true] {
                let target = Some(if ipv6 { "fd88::1" } else { "198.18.0.1" }.parse().unwrap());
                EchoTargets::new(ipv6).await?.check(entry, target).await?;
            }
        }
        Ok(())
    }).await?
}

#[tokio::test]
#[ignore = "Requires sing-box with WireGuard and gVisor; set SHOES_TEST_SING_BOX_BIN"]
async fn wireguard_singbox_both_roles_tcp_udp_ipv4_ipv6() -> io::Result<()> {
    let binary = PathBuf::from(
        std::env::var_os("SHOES_TEST_SING_BOX_BIN").expect("set SHOES_TEST_SING_BOX_BIN"),
    );
    tokio::time::timeout(Duration::from_secs(90), async {
        for shoes_is_server in [false, true] {
            let reservation = std::net::UdpSocket::bind("0.0.0.0:0")?;
            let port = reservation.local_addr()?.port();
            let mut ports = PortHelper::new();
            let (_, entry) = ports.get_localhost_listener_port();
            let (shoes, peer) = if shoes_is_server {
                let peer = json!({
                    "log": {"level": "warn"},
                    "inbounds": [{"type": "socks", "listen": "0.0.0.0", "listen_port": entry}],
                    "endpoints": [{
                        "type": "wireguard", "tag": "wg", "system": false,
                        "address": ["10.77.0.2/32", "fd77::2/128"],
                        "private_key": config::key(42), "mtu": 1408,
                        "peers": [{
                            "public_key": config::public(41), "pre_shared_key": config::key(43),
                            "address": "127.0.0.1", "port": port,
                            "allowed_ips": ["0.0.0.0/0", "::/0"]
                        }]
                    }],
                    "route": {"final": "wg"}
                });
                (json!([config::server(port)]), peer)
            } else {
                (
                    json!([config::client(port), config::socks(entry)]),
                    singbox_server(port),
                )
            };
            drop(reservation);
            let _shoes = start_shoes_server(&serde_yaml::to_string(&shoes).unwrap())?;
            let _peer = start_singbox_server_with_binary(
                &peer.to_string(),
                &binary,
                &[("GOMAXPROCS", "1")],
            )?;
            ports.wait_for_all_ports().await?;
            for ipv6 in [false, true] {
                let target = Some(if ipv6 { "fd88::1" } else { "198.18.0.1" }.parse().unwrap());
                EchoTargets::new(ipv6).await?.check(entry, target).await?;
            }
        }
        Ok(())
    })
    .await?
}

#[tokio::test]
#[ignore = "Requires sing-box and a real WireGuard rekey (about two minutes)"]
async fn wireguard_singbox_tcp_survives_real_rekey_without_psk() -> io::Result<()> {
    run_rekey(false).await
}

#[tokio::test]
#[ignore = "Requires sing-box and a real WireGuard rekey (about two minutes)"]
async fn wireguard_singbox_detoured_tcp_survives_real_rekey_without_psk() -> io::Result<()> {
    run_rekey(true).await
}

async fn run_rekey(detour: bool) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(180), async {
        let binary = PathBuf::from(
            std::env::var_os("SHOES_TEST_SING_BOX_BIN").expect("set SHOES_TEST_SING_BOX_BIN"),
        );
        let reservation = std::net::UdpSocket::bind("0.0.0.0:0")?;
        let peer_port = reservation.local_addr()?.port();
        let front = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        let relay_port = front.local_addr()?.port();
        let back = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        back.connect(("127.0.0.1", peer_port)).await?;
        let sessions = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
        let observed = sessions.clone();
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            let mut outbound = [0; 65536];
            let mut inbound = [0; 65536];
            let mut client = None;
            loop {
                tokio::select! {
                    packet = front.recv_from(&mut outbound) => {
                        let (len, source) = packet?;
                        client = Some(source);
                        if let Ok(WgKind::Data(packet)) = Packet::copy_from(&outbound[..len]).try_into_wg() {
                            observed.lock().unwrap().insert(packet.header.receiver_idx.get());
                        }
                        if let Err(error) = back.send(&outbound[..len]).await
                            && error.kind() != io::ErrorKind::ConnectionRefused
                        {
                            return Err(error);
                        }
                    }
                    packet = back.recv(&mut inbound) => {
                        // The first handshake can precede the peer's UDP bind.
                        let len = match packet {
                            Ok(len) => len,
                            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => continue,
                            Err(error) => return Err(error),
                        };
                        front.send_to(&inbound[..len], client.unwrap()).await?;
                    }
                }
            }
            #[allow(unreachable_code)]
            Ok::<_, io::Error>(())
        });
        let mut ports = PortHelper::new();
        let (_, entry) = ports.get_localhost_listener_port();
        let mut client = config::client(relay_port);
        client["client_proxies"][0]["protocol"]["mtu"] = json!(1280);
        client["client_proxies"][0]["protocol"].as_object_mut().unwrap().remove("pre_shared_key");
        let mut shoes_config = Vec::new();
        if detour {
            let (_, outer_port) = ports.get_localhost_listener_port();
            let protocol = config::vless_protocol();
            client["client_proxies"][0]["address"] = json!(format!("192.0.2.200:{relay_port}"));
            client["client_proxies"][0]["protocol"]["peer_client_chain"] = json!([{"address": format!("127.0.0.1:{outer_port}"), "protocol": protocol}]);
            shoes_config.push(json!({
                "address": format!("0.0.0.0:{outer_port}"), "protocol": protocol,
                "rules": [{"masks": "192.0.2.200/32", "action": "allow", "override_address": "127.0.0.1:0"}],
            }));
        }
        shoes_config.extend([client, config::socks(entry)]);
        let mut peer = singbox_server(peer_port);
        peer["endpoints"][0]["mtu"] = json!(1280);
        peer["endpoints"][0]["peers"][0].as_object_mut().unwrap().remove("pre_shared_key");
        drop(reservation);
        let _peer = start_singbox_server_with_binary(&peer.to_string(), &binary, &[("GOMAXPROCS", "1")])?;
        let _shoes = start_shoes_server(&serde_yaml::to_string(&shoes_config).unwrap())?;
        ports.wait_for_all_ports().await?;
        let echoes = EchoTargets::new(false).await?;
        let mut target = echoes.tcp();
        target.set_ip("198.18.0.1".parse().unwrap());
        let mut stream = tokio::select! {
            result = shoes_test_support::wireguard::connect(entry, target) => result?,
            result = tasks.join_next() => {
                return Err(io::Error::other(format!("WireGuard observer stopped before connection: {result:?}")));
            }
        };
        let udp = shoes_test_support::socks5::Socks5UdpAssociation::connect("127.0.0.1", entry).await?;
        let udp_target = std::net::SocketAddr::new(target.ip(), echoes.udp().port());
        assert_eq!(udp.send_to(udp_target, b"before rekey").await?, b"before rekey");
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut sequence = 0u64;
        loop {
            tick.tick().await;
            let rekeyed = sessions.lock().unwrap().len() > 1;
            let payload = sequence.to_be_bytes();
            tokio::time::timeout(Duration::from_secs(5), async {
                stream.write_all(&payload).await?;
                let mut received = [0; 8];
                stream.read_exact(&mut received).await?;
                assert_eq!(received, payload);
                assert_eq!(udp.send_to(udp_target, &payload).await?, payload);
                Ok::<_, io::Error>(())
            }).await??;
            if rekeyed {
                break;
            }
            sequence += 1;
        }
        assert!(sequence >= 100, "unexpectedly early key rotation");
        stream.shutdown().await?;
        tasks.shutdown().await;
        Ok(())
    }).await?
}
