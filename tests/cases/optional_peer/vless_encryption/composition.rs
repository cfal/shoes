use super::*;
use shoes_test_support::{
    socks5::Socks5UdpAssociation, test_servers::start_udp_echo_server_with_suffix,
};

pub(super) fn wrap_xhttp(
    kind: Kind,
    mut config: Value,
    server: bool,
    (version, mode): (&str, &str),
    cert: &str,
    key: &str,
    cover: u16,
) -> Value {
    let carrier = match (version, kind) {
        ("reality", _) => Some(Transport::Reality),
        ("plain" | "h2c", _) => None,
        ("h3", Kind::Shoes) => Some(Transport::Quic),
        _ => Some(Transport::Tls),
    };
    if let Some(carrier) = carrier {
        config = wrap(kind, config, server, carrier, cert, key, cover);
    }
    let alpn = match version {
        "plain" | "h1" => "http/1.1",
        "h3" => "h3",
        _ => "h2",
    };
    match kind {
        Kind::SingBox => unreachable!("sing-box does not implement XHTTP"),
        Kind::Shoes => {
            let mut protocol = shoes_protocol_mut(&mut config, server);
            if protocol["type"] == "tls" {
                protocol = if !server {
                    &mut protocol["protocol"]
                } else if version == "reality" {
                    &mut protocol["reality_targets"]["localhost"]["protocol"]
                } else {
                    &mut protocol["default_target"]["protocol"]
                };
            } else if protocol["type"] == "reality" {
                protocol = &mut protocol["protocol"];
            }
            let inner = protocol.take();
            let http_version = match version {
                "plain" => "h1",
                "h2c" => "h2",
                "reality" => "auto",
                other => other,
            };
            *protocol = json!({"type":"xhttp", "path":"/native", "host":"localhost", "mode":mode,
                "http_version":http_version,
                "sc_max_each_post_bytes":1024, "protocol":inner});
        }
        Kind::Xray => {
            let stream = &mut xray_endpoint_mut(&mut config, server)["streamSettings"];
            if stream.is_null() {
                *stream = json!({"security":"none"});
            }
            stream["network"] = json!("xhttp");
            stream["xhttpSettings"] = json!({"path":"/native", "host":"localhost", "mode":mode,
                "extra":{"scMaxEachPostBytes":1024, "scMinPostsIntervalMs":0}});
            if stream["security"] == "tls" {
                stream["tlsSettings"]["alpn"] = json!([alpn]);
            }
            if server && version == "h3" {
                let port = config["inbounds"][0]["port"].clone();
                config["inbounds"].as_array_mut().unwrap().push(json!({
                    "listen":"0.0.0.0","port":port,"protocol":"socks","settings":{"auth":"noauth"}
                }));
            }
        }
        Kind::Mihomo => {
            let options = json!({"path":"/native", "host":"localhost", "mode":mode,
                "sc-max-each-post-bytes":"1024", "sc-min-posts-interval-ms":"1"});
            if server {
                assert_ne!(version, "h3", "Mihomo does not serve XHTTP over QUIC");
                config["listeners"][0]["xhttp-config"] = options;
                if matches!(version, "plain" | "h2c") {
                    config["listeners"][0]["allow-insecure"] = json!(true);
                }
            } else {
                config["proxies"][0]["network"] = json!("xhttp");
                config["proxies"][0]["alpn"] = json!([alpn]);
                config["proxies"][0]["xhttp-opts"] = options;
            }
        }
    }
    config
}

async fn wrapped_case(
    peer: Kind,
    peer_client: bool,
    transport: Transport,
    encrypted: bool,
    vision: bool,
) {
    eprintln!(
        "composition: {peer:?} client={peer_client} {transport:?} encrypted={encrypted} vision={vision}"
    );
    let (encryption, decryption) = if encrypted {
        let (encryption, decryption, _) = credentials("random", &["mlkem768"]);
        (encryption, decryption)
    } else {
        ("none".into(), "none".into())
    };
    let (server_kind, client_kind) = peer_roles(peer, peer_client);
    let (cover, connector, mut cover_task) = tls_echo(false).await;
    let (target, _, mut target_task) = echo().await;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (cert, key) = (cert.cert.pem(), cert.signing_key.serialize_pem());
    let server_port = free_port().await;
    let mut server_settings = server_config(server_kind, server_port, &decryption, vision);
    if server_kind == Kind::Mihomo && !encrypted {
        server_settings["listeners"][0]["allow-insecure"] = json!(true);
    }
    let server = start(
        server_kind,
        server_port,
        wrap(
            server_kind,
            server_settings,
            true,
            transport,
            &cert,
            &key,
            cover,
        ),
    )
    .await;
    let client_port = free_port().await;
    let mut client_settings =
        client_config(client_kind, client_port, server_port, &encryption, vision);
    if client_kind == Kind::Mihomo {
        client_settings["proxies"][0]["packet-encoding"] = json!("xudp");
    }
    let client = start(
        client_kind,
        client_port,
        wrap(
            client_kind,
            client_settings,
            false,
            transport,
            &cert,
            &key,
            cover,
        ),
    )
    .await;
    let data: Vec<_> = (0..32769).map(|n| (n % 251) as u8).collect();
    for _ in 0..2 {
        if vision {
            let result = timeout(LIMIT, async {
                let socket = socks_connect(client_port, cover).await?;
                let mut stream = connector
                    .connect("localhost".try_into().unwrap(), socket)
                    .await?;
                for payload in [&[42; 64][..], &[43; 64], &data] {
                    let (mut r, mut w) = tokio::io::split(&mut stream);
                    let mut reply = vec![0; payload.len()];
                    tokio::try_join!(w.write_all(payload), r.read_exact(&mut reply))?;
                    assert_eq!(reply, payload);
                }
                // Close inner TLS without requiring WebSocket to support a TCP half-close.
                stream.get_mut().1.send_close_notify();
                stream.flush().await?;
                assert_eq!(stream.read(&mut [0]).await?, 0, "data after TLS close");
                Ok::<_, io::Error>(())
            })
            .await;
            assert!(
                matches!(result, Ok(Ok(()))),
                "{result:?}\n{}",
                pair_logs(&client, &server)
            );
        } else {
            exchange(client_port, target, &data)
                .await
                .unwrap_or_else(|e| panic!("{e}\n{}", pair_logs(&client, &server)));
        }
    }
    let shoes = if peer_client { &server } else { &client };
    if encrypted {
        shoes.assert_handshakes(&["fresh", "resumed"]);
    }
    if vision {
        for direction in ["READ", "WRITE"] {
            assert_eq!(
                shoes
                    .logs()
                    .matches(&format!(
                        "VISION {direction}: Switching to direct copy mode"
                    ))
                    .count(),
                2,
                "{}",
                shoes.logs()
            );
        }
    }
    // Force UDP frames across HTTP POST and native-record boundaries.
    let udp = start_udp_echo_server_with_suffix("0.0.0.0", 0, b"reply")
        .await
        .unwrap();
    let destination = (std::net::Ipv4Addr::LOCALHOST, udp.local_addr().port()).into();
    for _ in 0..2 {
        let association = timeout(
            LIMIT,
            Socks5UdpAssociation::connect("127.0.0.1", client_port),
        )
        .await
        .unwrap_or_else(|e| panic!("{e}\n{}", pair_logs(&client, &server)))
        .unwrap_or_else(|e| panic!("{e}\n{}", pair_logs(&client, &server)));
        let payload = vec![37; 4096];
        let reply = association
            .send_to(destination, &payload)
            .await
            .unwrap_or_else(|e| panic!("{e}\n{}", pair_logs(&client, &server)));
        assert_eq!(reply, [payload, b"reply".to_vec()].concat());
    }
    drop((client, server));
    cover_task.stop().await;
    target_task.stop().await;
}

#[tokio::test]
async fn encrypted_xhttp_xray_client_resumes_and_carries_tcp_udp_and_vision() {
    xhttp_matrix(Kind::Xray, true).await;
}

#[tokio::test]
async fn encrypted_xhttp_xray_server_resumes_and_carries_tcp_udp_and_vision() {
    xhttp_matrix(Kind::Xray, false).await;
}

#[tokio::test]
async fn encrypted_xhttp_mihomo_client_resumes_and_carries_tcp_udp_and_vision() {
    xhttp_matrix(Kind::Mihomo, true).await;
}

#[tokio::test]
async fn encrypted_xhttp_mihomo_server_resumes_and_carries_tcp_udp_and_vision() {
    xhttp_matrix(Kind::Mihomo, false).await;
}

async fn xhttp_matrix(peer: Kind, peer_client: bool) {
    for version in ["plain", "h1", "h2c", "h2", "h3", "reality"] {
        // Xray's client selects HTTP/1.1 without TLS; its server accepts h2c.
        if peer == Kind::Xray && peer_client && version == "h2c" {
            continue;
        }
        if peer == Kind::Mihomo && !peer_client && version == "h3" {
            continue;
        }
        for mode in ["packet-up", "stream-up", "stream-one", "auto"] {
            if mode == "auto" && !matches!(version, "h2" | "reality") {
                continue;
            }
            for vision in [false, true] {
                wrapped_case(
                    peer,
                    peer_client,
                    Transport::XhttpMode { version, mode },
                    true,
                    vision,
                )
                .await;
            }
        }
    }
}

#[tokio::test]
async fn encrypted_non_vision_and_wss_resume_through_wrappers() {
    for peer in [Kind::Xray, Kind::Mihomo] {
        for client in [false, true] {
            for transport in [
                Transport::Tls,
                Transport::Websocket,
                Transport::Wss,
                Transport::Reality,
            ] {
                wrapped_case(peer, client, transport, true, false).await;
            }
            wrapped_case(peer, client, Transport::Wss, true, true).await;
        }
    }
    for vision in [false, true] {
        wrapped_case(Kind::Shoes, false, Transport::Quic, true, vision).await;
    }
}

#[tokio::test]
async fn legacy_vless_websocket_and_mihomo_transports_carry_tcp_and_udp() {
    for peer in [Kind::Xray, Kind::Mihomo] {
        for client in [false, true] {
            for transport in [Transport::Websocket, Transport::Wss] {
                wrapped_case(peer, client, transport, false, false).await;
            }
        }
    }
    for client in [false, true] {
        for transport in [Transport::Raw, Transport::Tls, Transport::Reality] {
            wrapped_case(Kind::Mihomo, client, transport, false, false).await;
        }
    }
}
