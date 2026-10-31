use std::{io, net::SocketAddr, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use shoes_test_support::{
    certs::generate_test_cert_files,
    port_helper::PortHelper,
    process::{ProcessGuard, start_singbox_server},
    socks5::Socks5UdpAssociation,
    test_fixture::start_shoes_server,
    test_servers::{start_tcp_stream_echo_server, start_udp_echo_server_with_suffix},
    xray,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinSet,
};

const UUID: &str = "11111111-1111-4111-8111-111111111111";

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Shoes,
    #[cfg_attr(not(feature = "optional-peer-tests"), expect(dead_code))]
    SingBox,
    Xray,
}

enum Running {
    Other {
        _process: ProcessGuard,
        _config: tempfile::NamedTempFile,
    },
    Xray {
        _peer: xray::Peer,
    },
}

async fn start(kind: Kind, config: Value) -> io::Result<Running> {
    if kind == Kind::Xray {
        return Ok(Running::Xray {
            _peer: xray::start(config).await?,
        });
    }
    let (process, config) = if kind == Kind::Shoes {
        start_shoes_server(&config.to_string())?
    } else {
        start_singbox_server(&config.to_string())?
    };
    Ok(Running::Other {
        _process: process,
        _config: config,
    })
}

#[derive(Clone, Copy)]
struct Ws<'a> {
    max: usize,
    header: Option<&'a str>,
    tls: bool,
    cert: &'a str,
    key: &'a str,
}

fn config(kind: Kind, server: bool, port: u16, remote: u16, ws: Ws<'_>) -> Value {
    let Ws {
        max,
        header,
        tls,
        cert,
        key,
    } = ws;
    match kind {
        Kind::Shoes => {
            let mut transport = json!({
                "matching_path": "/ws",
                "protocol": {"type": "vless", "user_id": UUID, "udp_enabled": true}
            });
            if max > 0 || !server {
                transport["max_early_data"] = max.into();
            }
            if let Some(header) = header {
                transport["early_data_header_name"] = header.into();
            }
            let mut protocol = if server {
                json!({"type": "ws", "targets": [transport]})
            } else {
                transport["type"] = "ws".into();
                transport["matching_headers"] = json!({"Host": "localhost"});
                transport
            };
            if tls {
                protocol = if server {
                    json!({
                        "type": "tls",
                        "default_target": {"cert": cert, "key": key, "protocol": protocol}
                    })
                } else {
                    json!({
                        "type": "tls",
                        "verify": false,
                        "sni_hostname": "localhost",
                        "protocol": protocol
                    })
                };
            }
            if server {
                json!([{"address": format!("0.0.0.0:{port}"), "protocol": protocol}])
            } else {
                json!([{
                    "address": format!("0.0.0.0:{port}"),
                    "protocol": {"type": "socks", "udp_enabled": true},
                    "rules": [{
                        "masks": "0.0.0.0/0",
                        "action": "allow",
                        "client_chain": {
                            "address": format!("127.0.0.1:{remote}"),
                            "protocol": protocol
                        }
                    }]
                }])
            }
        }
        Kind::SingBox => {
            let mut transport = json!({"type": "ws", "path": "/ws", "max_early_data": max});
            if let Some(header) = header {
                transport["early_data_header_name"] = header.into();
            }
            let mut endpoint = if server {
                json!({
                    "type": "vless",
                    "listen": "0.0.0.0",
                    "listen_port": port,
                    "users": [{"uuid": UUID}],
                    "transport": transport
                })
            } else {
                json!({
                    "type": "vless",
                    "server": "127.0.0.1",
                    "server_port": remote,
                    "uuid": UUID,
                    "packet_encoding": "",
                    "transport": transport
                })
            };
            if tls {
                endpoint["tls"] = if server {
                    json!({"enabled": true, "certificate_path": cert, "key_path": key})
                } else {
                    json!({"enabled": true, "server_name": "localhost", "insecure": true})
                };
            }
            if server {
                json!({
                    "log": {"level": "warn"},
                    "inbounds": [endpoint],
                    "outbounds": [{"type": "direct"}]
                })
            } else {
                json!({
                    "log": {"level": "warn"},
                    "inbounds": [{"type": "socks", "listen": "0.0.0.0", "listen_port": port}],
                    "outbounds": [endpoint]
                })
            }
        }
        Kind::Xray => {
            let path = if server || max == 0 {
                "/ws".into()
            } else {
                format!("/ws?ed={max}")
            };
            let mut transport = json!({"network": "ws", "wsSettings": {"path": path}});
            if tls {
                transport["security"] = "tls".into();
                transport["tlsSettings"] = if server {
                    json!({"certificates": [{"certificateFile": cert, "keyFile": key}]})
                } else {
                    use rustls::pki_types::{CertificateDer, pem::PemObject};
                    let pem = std::fs::read(cert).unwrap();
                    let der = CertificateDer::from_pem_slice(&pem).unwrap();
                    let pin: String = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &der)
                        .as_ref()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    json!({
                        "serverName": "localhost",
                        "pinnedPeerCertSha256": pin,
                        "alpn": ["http/1.1"]
                    })
                };
            }
            let endpoint = if server {
                json!({
                    "listen": "0.0.0.0",
                    "port": port,
                    "protocol": "vless",
                    "settings": {"clients": [{"id": UUID}], "decryption": "none"},
                    "streamSettings": transport
                })
            } else {
                json!({
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": "127.0.0.1",
                            "port": remote,
                            "users": [{"id": UUID, "encryption": "none"}]
                        }]
                    },
                    "streamSettings": transport
                })
            };
            if server {
                json!({
                    "log": {"loglevel": "warning"},
                    "inbounds": [endpoint],
                    "outbounds": [{
                        "protocol": "freedom",
                        "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1"]}]}
                    }]
                })
            } else {
                json!({
                    "log": {"loglevel": "warning"},
                    "inbounds": [{
                        "listen": "0.0.0.0",
                        "port": port,
                        "protocol": "socks",
                        "settings": {"auth": "noauth", "udp": true}
                    }],
                    "outbounds": [endpoint]
                })
            }
        }
    }
}

async fn capture(
    remote: u16,
    tls: bool,
) -> io::Result<(u16, mpsc::UnboundedReceiver<String>, JoinSet<()>)> {
    let listener = TcpListener::bind("0.0.0.0:0").await?;
    let port = listener.local_addr()?.port();
    let (sender, receiver) = mpsc::unbounded_channel();
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut client, _) = accepted.unwrap();
                    let sender = sender.clone();
                    connections.spawn(async move {
                        let mut server = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, remote)).await.unwrap();
                        if !tls {
                            let mut header = Vec::new();
                            while !header.ends_with(b"\r\n\r\n") {
                                assert!(header.len() < 32768);
                                let Ok(byte) = client.read_u8().await else { return };
                                header.push(byte);
                            }
                            sender.send(String::from_utf8(header.clone()).unwrap()).unwrap();
                            server.write_all(&header).await.unwrap();
                        }
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                    });
                }
                result = connections.join_next(), if !connections.is_empty() => { result.unwrap().unwrap(); }
            }
        }
    });
    Ok((port, receiver, tasks))
}

fn check_capture(request: &str, header: Option<&str>, expected_max: usize, fallback: bool) {
    let first = request.lines().next().unwrap();
    let encoded = if let Some(header) = header {
        assert_eq!(first, "GET /ws HTTP/1.1");
        request
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(key, _)| key.eq_ignore_ascii_case(header))
            .map(|(_, value)| value.trim())
            .unwrap_or("")
    } else {
        first
            .strip_prefix("GET /ws")
            .unwrap()
            .strip_suffix(" HTTP/1.1")
            .unwrap()
    };
    let decoded = URL_SAFE_NO_PAD.decode(encoded).unwrap();
    if fallback {
        assert!(decoded.is_empty());
    } else {
        assert!(
            !decoded.is_empty(),
            "early data missing from captured request"
        );
        assert!(decoded.len() <= expected_max);
        assert_eq!(decoded[0], 0); // VLESS version.
        assert_eq!(
            &decoded[1..decoded.len().min(5)],
            &vec![0x11; decoded.len().min(5) - 1]
        );
    }
}

async fn run_case(
    peer: Kind,
    shoes_client: bool,
    header: Option<&str>,
    max: usize,
    server_max: usize,
    tls: bool,
) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(45), async {
        eprintln!(
            "WS peer={peer:?}, shoes_client={shoes_client}, header={header:?}, max={max}, server_max={server_max}, tls={tls}"
        );
        let mut ports = PortHelper::new();
        let (_, server_port) = ports.get_localhost_listener_port();
        let (cert, key) = generate_test_cert_files()?;
        let ws = Ws {
            max,
            header,
            tls,
            cert: cert.to_str().unwrap(),
            key: key.to_str().unwrap(),
        };
        let server_kind = if shoes_client { peer } else { Kind::Shoes };
        let client_kind = if shoes_client { Kind::Shoes } else { peer };
        // Xray sends no early data unless the complete 26-byte IPv4 VLESS header fits.
        let fallback = max == 0 || (client_kind == Kind::Xray && max < 26);
        let server_ws = Ws {
            max: server_max,
            header: header.filter(|_| server_max > 0),
            ..ws
        };
        let _server = start(server_kind, config(server_kind, true, server_port, 0, server_ws)).await?;
        // Bind the server before the capture listener can reuse its released reservation.
        ports.wait_for_all_ports().await?;
        let (carrier, mut captures, mut tasks) = capture(server_port, tls).await?;
        let (_, socks_port) = ports.get_localhost_listener_port();
        let _client = start(
            client_kind,
            config(client_kind, false, socks_port, carrier, ws),
        )
        .await?;
        ports.wait_for_all_ports().await?;
        let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
        let target: SocketAddr = ([127, 0, 0, 1], echo.local_addr().port()).into();
        let socks: SocketAddr = ([127, 0, 0, 1], socks_port).into();
        let exchange = || async {
            let mut stream = xray::connect(socks, target).await?;
            for size in [1, 2048, 70_000] {
                let data: Vec<_> = (0..size).map(|i| (i * 131 + 255) as u8).collect();
                let mut response = vec![0; data.len()];
                let (mut read, mut write) = stream.split();
                tokio::time::timeout(Duration::from_secs(10), async {
                    tokio::try_join!(write.write_all(&data), read.read_exact(&mut response))
                })
                .await
                .map_err(|_| io::Error::other(format!("TCP echo timed out at {size} bytes")))??;
                assert_eq!(response, data);
            }
            io::Result::Ok(())
        };
        tokio::try_join!(exchange(), exchange())?;
        if !tls {
            for _ in 0..2 {
                let captured = captures.recv().await.unwrap();
                check_capture(&captured, header, max, fallback);
            }
        }
        let udp = start_udp_echo_server_with_suffix("0.0.0.0", 0, b"").await?;
        let association = Socks5UdpAssociation::connect("127.0.0.1", socks_port).await?;
        let target = ([127, 0, 0, 1], udp.local_addr().port()).into();
        for data in [b"first UDP\0\xff".as_slice(), &[0xa5; 4096]] {
            let response =
                tokio::time::timeout(Duration::from_secs(10), association.send_to(target, data))
                    .await
                    .map_err(|_| io::Error::other("UDP echo timed out"))??;
            assert_eq!(response, data);
        }
        if !tls {
            let captured = captures.recv().await.unwrap();
            check_capture(&captured, header, max, fallback);
        }
        tasks.shutdown().await;
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn shoes_ws_wss_tcp_udp_and_split_first_flight() -> io::Result<()> {
    for header in [None, Some("X-Early-Data"), Some("Sec-WebSocket-Protocol")] {
        for max in [8, 2048] {
            run_case(Kind::Shoes, true, header, max, max, false).await?;
        }
        run_case(Kind::Shoes, true, header, 2048, 2048, true).await?;
    }
    run_case(Kind::Shoes, true, None, 0, 0, false).await
}

#[tokio::test]
async fn shoes_standard_header_to_default_server_ws_wss_tcp_udp() -> io::Result<()> {
    for tls in [false, true] {
        run_case(
            Kind::Shoes,
            false,
            Some("Sec-WebSocket-Protocol"),
            2048,
            0,
            tls,
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn vless_mixed_configuration_accepts_plain_and_automatic_but_rejects_other_mismatches()
-> io::Result<()> {
    for tls in [false, true] {
        for header in [None, Some("X-Early-Data"), Some("Sec-WebSocket-Protocol")] {
            for client_enabled in [false, true] {
                tokio::time::timeout(Duration::from_secs(15), async {
                    let mut ports = PortHelper::new();
                    let (_, server_port) = ports.get_localhost_listener_port();
                    let (cert, key) = generate_test_cert_files()?;
                    let defaults = Ws {
                        max: 0,
                        header: None,
                        tls,
                        cert: cert.to_str().unwrap(),
                        key: key.to_str().unwrap(),
                    };
                    // A split VLESS header lets an unaware server reject its framed tail promptly.
                    let enabled = Ws {
                        max: 8,
                        header,
                        ..defaults
                    };
                    let (client_ws, server_ws) = if client_enabled {
                        (enabled, defaults)
                    } else {
                        (defaults, enabled)
                    };
                    let mut server_config = config(Kind::Shoes, true, server_port, 0, server_ws);
                    if client_enabled {
                        let protocol = &mut server_config[0]["protocol"];
                        let ws = if tls {
                            &mut protocol["default_target"]["protocol"]
                        } else {
                            protocol
                        };
                        ws["targets"][0]["max_early_data"] = 0.into();
                    }
                    let _server = start(Kind::Shoes, server_config).await?;
                    ports.wait_for_all_ports().await?;
                    let (carrier, mut captures, mut tasks) = capture(server_port, tls).await?;
                    let (_, socks_port) = ports.get_localhost_listener_port();
                    let _client = start(
                        Kind::Shoes,
                        config(Kind::Shoes, false, socks_port, carrier, client_ws),
                    )
                    .await?;
                    ports.wait_for_all_ports().await?;
                    let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
                    let target: SocketAddr = ([127, 0, 0, 1], echo.local_addr().port()).into();
                    let socks = ([127, 0, 0, 1], socks_port).into();
                    let result = tokio::time::timeout(Duration::from_secs(5), async {
                        let mut stream = xray::connect(socks, target).await?;
                        stream.write_all(b"mixed enablement").await?;
                        let mut response = [0; 16];
                        stream.read_exact(&mut response).await?;
                        assert_eq!(&response, b"mixed enablement");
                        io::Result::Ok(())
                    })
                    .await
                    .expect("this VLESS mismatch must succeed or fail without hanging");
                    assert_eq!(
                        result.is_ok(),
                        !client_enabled || header == Some("Sec-WebSocket-Protocol"),
                        "client_enabled={client_enabled}, header={header:?}, tls={tls}: {result:?}"
                    );
                    if !tls {
                        check_capture(
                            &captures.recv().await.unwrap(),
                            header,
                            client_ws.max,
                            !client_enabled,
                        );
                    }
                    tasks.shutdown().await;
                    io::Result::Ok(())
                })
                .await??;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn shoes_websocket_after_socks_hop_supports_server_first_noop() -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let listener = TcpListener::bind("0.0.0.0:0").await?;
        let mut ports = PortHelper::new();
        let (_, hop_port) = ports.get_localhost_listener_port();
        let (_, ws_port) = ports.get_localhost_listener_port();
        let target: SocketAddr = ([127, 0, 0, 1], listener.local_addr()?.port()).into();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            connection.write_all(b"server-first banner").await.unwrap();
            let mut data = [0; 5];
            connection.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"reply");
        });
        let protocol = json!({
            "type": "ws",
            "targets": [{
                "matching_path": "/ws",
                "max_early_data": 2048,
                "early_data_header_name": "Sec-WebSocket-Protocol",
                "protocol": {"type": "forward", "targets": target.to_string()}
            }]
        });
        let server_config = json!([
            {"address": format!("0.0.0.0:{hop_port}"), "protocol": {"type": "socks"}},
            {"address": format!("0.0.0.0:{ws_port}"), "protocol": protocol}
        ]);
        let (_server, _server_config) = start_shoes_server(&server_config.to_string())?;
        ports.wait_for_all_ports().await?;
        let (_, client_port) = ports.get_localhost_listener_port();
        let client_config = json!([{
            "address": format!("0.0.0.0:{client_port}"),
            "protocol": {"type": "socks"},
            "rules": [{
                "masks": "0.0.0.0/0",
                "action": "allow",
                "client_chain": [
                    {
                        "address": format!("127.0.0.1:{hop_port}"),
                        "protocol": {"type": "socks"}
                    },
                    {
                        "address": format!("127.0.0.1:{ws_port}"),
                        "protocol": {
                            "type": "ws",
                            "matching_path": "/ws",
                            "matching_headers": {"Host": "localhost"},
                            "max_early_data": 2048,
                            "early_data_header_name": "Sec-WebSocket-Protocol",
                            "protocol": {"type": "portforward"}
                        }
                    }
                ]
            }]
        }]);
        let (_client, _client_config) = start_shoes_server(&client_config.to_string())?;
        ports.wait_for_all_ports().await?;
        let mut stream = xray::connect(([127, 0, 0, 1], client_port).into(), target).await?;
        let mut banner = [0; 19];
        stream.read_exact(&mut banner).await?;
        assert_eq!(&banner, b"server-first banner");
        stream.write_all(b"reply").await?;
        tasks.join_next().await.unwrap().unwrap();
        Ok(())
    })
    .await?
}

#[cfg(feature = "optional-peer-tests")]
#[tokio::test]
async fn sing_box_both_directions_all_carriers_ws_wss_tcp_udp() -> io::Result<()> {
    for shoes_client in [false, true] {
        for header in [None, Some("X-Early-Data"), Some("Sec-WebSocket-Protocol")] {
            for max in [8, 2048] {
                run_case(Kind::SingBox, shoes_client, header, max, max, false).await?;
            }
            run_case(Kind::SingBox, shoes_client, header, 2048, 2048, true).await?;
        }
    }
    Ok(())
}

#[cfg(feature = "optional-peer-tests")]
#[tokio::test]
async fn xray_both_directions_ws_wss_tcp_udp_and_oversize_fallback() -> io::Result<()> {
    for shoes_client in [true, false] {
        for max in [8, 2048] {
            run_case(
                Kind::Xray,
                shoes_client,
                Some("Sec-WebSocket-Protocol"),
                max,
                max,
                false,
            )
            .await?;
        }
        run_case(
            Kind::Xray,
            shoes_client,
            Some("Sec-WebSocket-Protocol"),
            2048,
            2048,
            true,
        )
        .await?;
    }
    Ok(())
}

#[cfg(feature = "optional-peer-tests")]
#[tokio::test]
async fn reference_standard_header_clients_to_default_server_ws_wss_tcp_udp() -> io::Result<()> {
    for peer in [Kind::SingBox, Kind::Xray] {
        for tls in [false, true] {
            run_case(peer, false, Some("Sec-WebSocket-Protocol"), 2048, 0, tls).await?;
        }
    }
    Ok(())
}
