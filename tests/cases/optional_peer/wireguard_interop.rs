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
#[ignore = "Requires Xray 26.10.31; set SHOES_TEST_XRAY_BIN"]
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
#[ignore = "Requires sing-box with WireGuard and gVisor; set SHOES_TEST_SING_BOX_BIN"]
async fn wireguard_singbox_lazy_whole_path_carrier_tracks_demand_and_reconnects() -> io::Result<()>
{
    use bytes::Bytes;
    use http_body_util::Empty;
    use hyper::{Request, Response, body::Incoming, server::conn::http1, service::service_fn};
    use hyper_util::rt::TokioIo;
    use shoes_test_support::socks5::{Socks5UdpAssociation, SocksDestination};
    use shoes_test_support::test_servers::{
        start_tcp_stream_echo_server, start_udp_response_server,
    };
    use tokio::{
        net::{TcpListener, TcpStream},
        sync::{mpsc, oneshot, watch},
        task::JoinSet,
        time::timeout,
    };

    async fn wait_for_lazy_probe(probes: &mut mpsc::UnboundedReceiver<bool>) -> io::Result<()> {
        timeout(Duration::from_secs(10), async {
            while !probes.recv().await.expect("probe observer stopped") {}
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "lazy carrier probe did not resume"))
    }

    async fn expect_idle_probes(probes: &mut mpsc::UnboundedReceiver<bool>) -> io::Result<()> {
        // Only fresh control requests establish progress in this idle phase.
        while let Ok(lazy) = probes.try_recv() {
            assert!(!lazy, "idle carrier activity woke the lazy group");
        }
        for _ in 0..5 {
            assert_eq!(
                timeout(Duration::from_secs(5), probes.recv())
                    .await
                    .map_err(|_| io::Error::new(
                        io::ErrorKind::TimedOut,
                        "idle control probes stalled"
                    ))?,
                Some(false),
                "idle carrier activity woke the lazy group"
            );
        }
        Ok(())
    }

    async fn reconnect(
        reset: &mpsc::UnboundedSender<oneshot::Sender<usize>>,
        accepted: &mut watch::Receiver<usize>,
    ) -> io::Result<()> {
        let (reply, acknowledged) = oneshot::channel();
        reset
            .send(reply)
            .map_err(|_| io::Error::other("carrier reset channel closed"))?;
        let previous = timeout(Duration::from_secs(5), acknowledged)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "carrier reset was not acknowledged",
                )
            })?
            .map_err(|_| io::Error::other("carrier reset acknowledgement dropped"))?;
        timeout(
            Duration::from_secs(5),
            accepted.wait_for(|count| *count > previous),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "carrier did not reconnect within 5s",
            )
        })?
        .map_err(io::Error::other)?;
        Ok(())
    }

    timeout(Duration::from_secs(300), async {
        let binary = PathBuf::from(
            std::env::var_os("SHOES_TEST_SING_BOX_BIN").expect("set SHOES_TEST_SING_BOX_BIN"),
        );
        for udp in [true, false] {
            let reservation = std::net::UdpSocket::bind("0.0.0.0:0")?;
            let peer_port = reservation.local_addr()?.port();
            let mut ports = PortHelper::new();
            let (_, prefix_port) = ports.get_localhost_listener_port();
            let (_, exit_port) = ports.get_localhost_listener_port();
            let _proxies = start_shoes_server(&serde_yaml::to_string(&json!([
                {"address":format!("0.0.0.0:{prefix_port}"), "protocol":{"type":"socks"}},
                {"address":format!("0.0.0.0:{exit_port}"), "protocol":config::vless_protocol(),
                 "rules":[
                    {"masks":["192.0.2.200/32", "192.0.2.1/32"], "action":"allow", "override_address":"127.0.0.1:0"}
                 ]}
            ])).unwrap())?;
            ports.wait_for_all_ports().await?;
            drop(reservation);
            let _peer = start_singbox_server_with_binary(
                &singbox_server(peer_port).to_string(), &binary, &[("GOMAXPROCS", "1")],
            )?;

            let mut fixtures: JoinSet<io::Result<()>> = JoinSet::new();
            let listener = TcpListener::bind("0.0.0.0:0").await?;
            let carrier_port = listener.local_addr()?.port();
            let (reset, mut resets) = mpsc::unbounded_channel::<oneshot::Sender<usize>>();
            let (connected, mut accepted) = watch::channel(0usize);
            fixtures.spawn(async move {
                let mut connections = JoinSet::new();
                let mut count = 0;
                loop {
                    tokio::select! {
                        incoming = listener.accept() => {
                            let (mut client, _) = incoming?;
                            let mut upstream = TcpStream::connect(("127.0.0.1", prefix_port)).await?;
                            count += 1;
                            connected.send_replace(count);
                            connections.spawn(async move {
                                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                            });
                        }
                        reset = resets.recv() => {
                            let Some(reset) = reset else { return Ok(()); };
                            connections.shutdown().await;
                            let _ = reset.send(count);
                        }
                        result = connections.join_next(), if !connections.is_empty() => {
                            result.unwrap().unwrap();
                        }
                    }
                }
            });

            let listener = TcpListener::bind("0.0.0.0:0").await?;
            let probe_port = listener.local_addr()?.port();
            let (observed, mut probes) = mpsc::unbounded_channel();
            fixtures.spawn(async move {
                let mut connections = JoinSet::new();
                loop {
                    tokio::select! {
                        incoming = listener.accept() => {
                            let (stream, _) = incoming?;
                            let observed = observed.clone();
                            connections.spawn(async move {
                                let _ = http1::Builder::new().keep_alive(false).serve_connection(
                                    TokioIo::new(stream), service_fn(move |request: Request<Incoming>| {
                                        assert_eq!(request.method(), hyper::Method::HEAD);
                                        assert!(matches!(request.uri().path(), "/lazy" | "/control"));
                                        observed.send(request.uri().path() == "/lazy").unwrap();
                                        std::future::ready(Ok::<_, io::Error>(Response::builder()
                                            .status(204).body(Empty::<Bytes>::new()).unwrap()))
                                    }),
                                ).await;
                            });
                        }
                        result = connections.join_next(), if !connections.is_empty() => {
                            result.unwrap().unwrap();
                        }
                    }
                }
            });

            let (_, entry) = ports.get_localhost_listener_port();
            let mut client = config::client(peer_port);
            client["client_chains"][0]["address"] = json!(format!("192.0.2.200:{peer_port}"));
            client["client_chains"][0]["protocol"]["peer_client_chain"] = json!("carrier");
            let _client = start_shoes_server(&serde_yaml::to_string(&json!([
                {"client_group":"carrier", "type":"url-test", "lazy":true, "interval":3, "timeout":1000,
                 "url":format!("http://192.0.2.1:{probe_port}/lazy"), "client_chains":[{"name":"via-exit", "chain":[
                    {"address":format!("127.0.0.1:{carrier_port}"), "protocol":{"type":"socks"}},
                    {"address":format!("127.0.0.1:{exit_port}"), "protocol":config::vless_protocol()}
                 ]}]},
                {"client_group":"control", "type":"url-test", "lazy":false, "interval":1, "timeout":1000,
                 "url":format!("http://192.0.2.1:{probe_port}/control"), "client_chains":[
                    {"address":format!("127.0.0.1:{exit_port}"), "protocol":config::vless_protocol()}
                 ]},
                client, config::socks(entry)
            ])).unwrap())?;

            let scenario = async {
                ports.wait_for_all_ports().await?;
                wait_for_lazy_probe(&mut probes).await?;
                expect_idle_probes(&mut probes).await?;
                reconnect(&reset, &mut accepted).await?;
                expect_idle_probes(&mut probes).await?;

                let tcp_echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
                let udp_echo = start_udp_response_server("0.0.0.0", 0, |payload, source| {
                    serde_json::to_vec(&(payload, source)).unwrap()
                }).await?;
                let target = |port| std::net::SocketAddr::new("198.18.0.1".parse().unwrap(), port);
                let mut tcp = if udp { None } else {
                    Some(timeout(Duration::from_secs(10), shoes_test_support::wireguard::connect(
                        entry, target(tcp_echo.local_addr().port()),
                    )).await??)
                };
                let association = if udp {
                    Some(timeout(Duration::from_secs(10), Socks5UdpAssociation::connect("127.0.0.1", entry)).await??)
                } else { None };
                let mut udp_source = None;
                for payload in [b"before reconnect".as_slice(), b"after reconnect".as_slice()] {
                    timeout(Duration::from_secs(10), async {
                        if let Some(stream) = &mut tcp {
                            stream.write_all(payload).await?;
                            let mut received = vec![0; payload.len()];
                            stream.read_exact(&mut received).await?;
                            assert_eq!(received, payload);
                        } else {
                            loop {
                                match association.as_ref().unwrap().send_to_with_timeout(
                                    SocksDestination::Ip(target(udp_echo.local_addr().port())), payload, Duration::from_millis(250),
                                ).await {
                                    Ok(response) => {
                                        let (received, source): (Vec<u8>, std::net::SocketAddr) =
                                            serde_json::from_slice(&response).map_err(io::Error::other)?;
                                        if received == payload {
                                            if let Some(previous) = udp_source {
                                                assert_eq!(source, previous, "native UDP flow was replaced");
                                            } else {
                                                udp_source = Some(source);
                                            }
                                            break;
                                        }
                                        assert_eq!(received, b"before reconnect");
                                    }
                                    Err(error) if error.kind() == io::ErrorKind::TimedOut => {},
                                    Err(error) => return Err(error),
                                }
                            }
                        }
                        Ok::<_, io::Error>(())
                    }).await??;
                    if payload == b"before reconnect" {
                        wait_for_lazy_probe(&mut probes).await.map_err(|error| {
                            io::Error::new(error.kind(), format!("{} demand: {error}", if udp { "UDP" } else { "TCP" }))
                        })?;
                        // Setup can touch demand on either side of a scheduler tick.
                        timeout(Duration::from_secs(20), async {
                            let mut quiet = 0;
                            while quiet < 5 {
                                if probes.recv().await.expect("probe observer stopped") {
                                    quiet = 0;
                                } else {
                                    quiet += 1;
                                }
                            }
                        }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "lazy carrier activity never settled"))?;
                        reconnect(&reset, &mut accepted).await?;
                    }
                }
                Ok::<_, io::Error>(())
            };
            tokio::select! {
                biased;
                result = fixtures.join_next() => return Err(io::Error::other(format!("WireGuard fixture stopped: {result:?}"))),
                result = scenario => result?,
            }
        }
        Ok(())
    }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "native WireGuard lazy carrier scenario timed out"))?
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
        client["client_chains"][0]["protocol"]["mtu"] = json!(1280);
        client["client_chains"][0]["protocol"].as_object_mut().unwrap().remove("pre_shared_key");
        let mut shoes_config = Vec::new();
        if detour {
            let (_, outer_port) = ports.get_localhost_listener_port();
            let protocol = config::vless_protocol();
            client["client_chains"][0]["address"] = json!(format!("192.0.2.200:{relay_port}"));
            client["client_chains"][0]["protocol"]["peer_client_chain"] = json!([{"address": format!("127.0.0.1:{outer_port}"), "protocol": protocol}]);
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
