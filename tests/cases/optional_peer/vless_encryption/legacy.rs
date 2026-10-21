use super::*;

pub(super) fn wrap_singbox(
    mut config: Value,
    server: bool,
    transport: Transport,
    cert: &str,
    key: &str,
    cover: u16,
) -> Value {
    let tls = if matches!(transport, Transport::Reality) {
        let (private, public) = reality_keys();
        if server {
            json!({"enabled":true,"server_name":"localhost","reality":{"enabled":true,
                "handshake":{"server":"localhost","server_port":cover},"private_key":private,"short_id":["0123456789abcdef"]}})
        } else {
            json!({"enabled":true,"server_name":"localhost","utls":{"enabled":true,"fingerprint":"chrome"},
                "reality":{"enabled":true,"public_key":public,"short_id":"0123456789abcdef"}})
        }
    } else {
        assert!(matches!(transport, Transport::Tls));
        if server {
            json!({"enabled":true,"certificate":cert.lines().collect::<Vec<_>>(),"key":key.lines().collect::<Vec<_>>()})
        } else {
            json!({"enabled":true,"server_name":"localhost","insecure":true})
        }
    };
    config[if server { "inbounds" } else { "outbounds" }][0]["tls"] = tls;
    config
}

fn enable_legacy_vision(config: &mut Value, server: bool, transport: Transport) {
    let outer = shoes_protocol_mut(config, server);
    let target = if !server {
        outer
    } else if matches!(transport, Transport::Tls) {
        &mut outer["default_target"]
    } else {
        &mut outer["reality_targets"]["localhost"]
    };
    target["vision"] = json!(true);
}

async fn checked_transfer<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut stream: S,
    half_close_before_reply: bool,
) -> io::Result<S> {
    for _ in 0..2 {
        stream.write_all(&[42; 64]).await?;
        stream.flush().await?;
        let mut reply = [0; 64];
        stream.read_exact(&mut reply).await?;
        assert_eq!(reply, [42; 64]);
    }
    let data: Vec<_> = (0..1024 * 1024 + 17).map(|i| (i % 251) as u8).collect();
    let (mut r, mut w) = tokio::io::split(&mut stream);
    let ((), output) = tokio::try_join!(
        async {
            w.write_all(&data).await?;
            if half_close_before_reply {
                w.shutdown().await?;
            }
            Ok::<_, io::Error>(())
        },
        async {
            let mut output = Vec::new();
            let mut buf = [0; 8192];
            let mut next_pause = 65536;
            while output.len() < data.len() {
                let n = r.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                output.extend_from_slice(&buf[..n]);
                assert!(output.len() <= data.len(), "duplicate data before EOF");
                if output.len() >= next_pause {
                    next_pause += 65536;
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
            if half_close_before_reply {
                assert_eq!(r.read(&mut buf).await?, 0, "data after expected reply");
            }
            Ok::<_, io::Error>(output)
        }
    )?;
    if output != data {
        return Err(io::Error::other(format!(
            "echo mismatch before EOF: received {} of {} bytes, first mismatch {:?}",
            output.len(),
            data.len(),
            output.iter().zip(&data).position(|(a, b)| a != b),
        )));
    }
    drop((r, w));
    Ok(stream)
}

#[tokio::test]
async fn legacy_peers_assert_direct_end_and_eof_over_tls_and_reality() {
    for peer in [Kind::Xray, Kind::Mihomo, Kind::SingBox] {
        for peer_client in [false, true] {
            for transport in [Transport::Tls, Transport::Reality] {
                for inner_tls12 in [None, Some(true), Some(false)] {
                    let mihomo_requires_reply_first = peer == Kind::Mihomo
                        && !peer_client
                        && matches!(transport, Transport::Reality)
                        && inner_tls12 == Some(true);
                    // sing-box's Vision wrapper has no CloseWrite. Clients close both sides on
                    // upload EOF; servers can reset TLS 1.2 replies when the target closes first.
                    // Upstream fix: https://github.com/SagerNet/sing-vmess/pull/16
                    let singbox_requires_reply_first =
                        peer == Kind::SingBox && (peer_client || inner_tls12 == Some(true));
                    let half_close_before_reply =
                        !mihomo_requires_reply_first && !singbox_requires_reply_first;
                    decision_case(
                        peer,
                        peer_client,
                        transport,
                        inner_tls12,
                        half_close_before_reply,
                    )
                    .await;
                }
            }
        }
    }
}

#[tokio::test]
#[ignore = "pinned Mihomo REALITY server fully closes on target EOF and can reset pending TLS 1.2 replies"]
async fn mihomo_reality_tls12_half_close_preserves_reply() {
    decision_case(Kind::Mihomo, false, Transport::Reality, Some(true), true).await;
}

#[tokio::test]
#[ignore = "pinned sing-box Vision client closes both directions on upload EOF"]
async fn singbox_vision_client_half_close_preserves_pending_reply() {
    decision_case(Kind::SingBox, true, Transport::Tls, None, true).await;
}

#[tokio::test]
#[ignore = "pinned sing-box Vision server can reset TLS 1.2 replies during upload half-close"]
async fn singbox_vision_server_half_close_preserves_tls12_reply() {
    for transport in [Transport::Tls, Transport::Reality] {
        decision_case(Kind::SingBox, false, transport, Some(true), true).await;
    }
}

async fn decision_case(
    peer: Kind,
    peer_client: bool,
    transport: Transport,
    inner_tls12: Option<bool>,
    half_close_before_reply: bool,
) {
    eprintln!(
        "legacy decisions: {peer:?} client={peer_client} {transport:?} inner_tls12={inner_tls12:?}"
    );
    let (server_kind, client_kind) = peer_roles(peer, peer_client);
    let (cover, _, mut cover_task) = tls_echo(false).await;
    let (target, connector, mut target_task) = if let Some(tls12) = inner_tls12 {
        let (port, connector, task) = tls_echo(tls12).await;
        (port, Some(connector), task)
    } else {
        let (port, _, task) = echo().await;
        (port, None, task)
    };
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (cert, key) = (cert.cert.pem(), cert.signing_key.serialize_pem());
    let server_port = free_port().await;
    let client_port = free_port().await;
    let mut server_settings = wrap(
        server_kind,
        server_config(server_kind, server_port, "none", server_kind != Kind::Shoes),
        true,
        transport,
        &cert,
        &key,
        cover,
    );
    let mut client_settings = wrap(
        client_kind,
        client_config(
            client_kind,
            client_port,
            server_port,
            "none",
            client_kind != Kind::Shoes,
        ),
        false,
        transport,
        &cert,
        &key,
        cover,
    );
    if server_kind == Kind::Shoes {
        enable_legacy_vision(&mut server_settings, true, transport);
    } else {
        enable_legacy_vision(&mut client_settings, false, transport);
    }
    let server = start(server_kind, server_port, server_settings).await;
    let client = start(client_kind, client_port, client_settings).await;
    timeout(Duration::from_secs(20), async {
        let socket = socks_connect(client_port, target).await?;
        if let Some(connector) = connector {
            let mut tls = checked_transfer(
                connector
                    .connect("localhost".try_into().unwrap(), socket)
                    .await?,
                half_close_before_reply,
            )
            .await?;
            if !half_close_before_reply {
                tls.get_mut().1.send_close_notify();
                tls.flush().await?;
                assert_eq!(tls.read(&mut [0]).await?, 0, "data after TLS close");
            }
        } else {
            let mut socket = checked_transfer(socket, half_close_before_reply).await?;
            if !half_close_before_reply {
                socket.shutdown().await?;
                assert_eq!(socket.read(&mut [0]).await?, 0, "data after expected reply");
            }
        }
        Ok::<_, io::Error>(())
    })
    .await
    .unwrap_or_else(|e| panic!("{e}\n{}", pair_logs(&client, &server)))
    .unwrap_or_else(|e| panic!("{e}\n{}", pair_logs(&client, &server)));
    let shoes = if peer_client { &server } else { &client };
    let direct = inner_tls12 == Some(false);
    for direction in ["READ", "WRITE"] {
        let logs = shoes.logs();
        assert_eq!(
            logs.contains(&format!(
                "VISION {direction}: Switching to direct copy mode"
            )),
            direct,
            "{logs}"
        );
        if !direct {
            assert!(
                logs.contains(&format!("VISION {direction}: Switching to Tls mode")),
                "{logs}"
            );
        }
    }
    drop((client, server));
    cover_task.stop().await;
    target_task.stop().await;
}

#[derive(Debug, PartialEq, Eq)]
struct LegacyObservation {
    eof: bool,
    read_direct: bool,
    write_direct: bool,
}

#[tokio::test]
#[ignore = "requires debug Shoes binaries; SHOES_BASELINE_BINARY from 001495285ac16e2121a539682d1a1f6a7c07c5ed"]
async fn legacy_baseline_matches_backpressure_and_half_close() {
    let baseline = std::env::var_os("SHOES_BASELINE_BINARY").expect("baseline binary required");
    let transport = Transport::Tls;
    for shoes_server in [false, true] {
        let mut observations = Vec::new();
        for binary in [PathBuf::from(&baseline), Kind::Shoes.binary()] {
            observations.push(
                timeout(
                    Duration::from_secs(30),
                    exchange_legacy(binary, transport, shoes_server),
                )
                .await
                .unwrap(),
            );
        }
        assert_eq!(
            observations[0], observations[1],
            "{transport:?}, server={shoes_server}"
        );
    }
}

async fn exchange_legacy(
    binary: PathBuf,
    transport: Transport,
    shoes_server: bool,
) -> LegacyObservation {
    let (target, connector, mut target_task) = tls_echo(false).await;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (cert, key) = (cert.cert.pem(), cert.signing_key.serialize_pem());
    let server_kind = if shoes_server {
        Kind::Shoes
    } else {
        Kind::Xray
    };
    let client_kind = if shoes_server {
        Kind::Xray
    } else {
        Kind::Shoes
    };
    let server_port = free_port().await;
    let client_port = free_port().await;
    let mut server_config = wrap(
        server_kind,
        server_config(server_kind, server_port, "none", !shoes_server),
        true,
        transport,
        &cert,
        &key,
        target,
    );
    let mut client_config = wrap(
        client_kind,
        client_config(client_kind, client_port, server_port, "none", shoes_server),
        false,
        transport,
        &cert,
        &key,
        target,
    );
    if shoes_server {
        match transport {
            Transport::Tls => {
                server_config[0]["protocol"]["default_target"]["vision"] = json!(true)
            }
            Transport::Reality => {
                server_config[0]["protocol"]["reality_targets"]["localhost"]["vision"] = json!(true)
            }
            _ => unreachable!(),
        }
    } else {
        client_config[0]["rules"][0]["client_chain"]["protocol"]["vision"] = json!(true);
    }
    let server = start_binary(
        server_kind,
        server_port,
        server_config,
        if shoes_server {
            binary.clone()
        } else {
            server_kind.binary()
        },
    )
    .await;
    let client = start_binary(
        client_kind,
        client_port,
        client_config,
        if shoes_server {
            client_kind.binary()
        } else {
            binary
        },
    )
    .await;
    let socket = socks_connect(client_port, target).await.unwrap();
    let mut tls = connector
        .connect("localhost".try_into().unwrap(), socket)
        .await
        .unwrap();
    // Small records finish the Vision decision before the backpressured DIRECT transfer.
    for _ in 0..2 {
        tls.write_all(&[42; 64]).await.unwrap();
        tls.flush().await.unwrap();
        let mut reply = [0; 64];
        tls.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [42; 64]);
    }
    let (mut read, mut write) = tokio::io::split(tls);
    let data: Vec<_> = (0..2 * 1024 * 1024).map(|n| (n % 251) as u8).collect();
    let ((), output) = tokio::join!(
        async {
            for chunk in data.chunks(8192) {
                write.write_all(chunk).await.unwrap();
            }
            write.flush().await.unwrap();
            write.shutdown().await.unwrap();
        },
        async {
            let mut output = Vec::new();
            let mut buf = [0; 8192];
            while output.len() < data.len() {
                let n = buf.len().min(data.len() - output.len());
                read.read_exact(&mut buf[..n]).await.unwrap();
                output.extend_from_slice(&buf[..n]);
                if output.len().is_multiple_of(65536) {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
            output
        }
    );
    assert_eq!(output, data);
    let eof = match timeout(Duration::from_secs(5), read.read(&mut [0; 1])).await {
        Ok(Ok(0)) => true,
        Err(_) => false,
        result => panic!("unexpected data or read error after half-close: {result:?}"),
    };
    let logs = if shoes_server {
        server.logs()
    } else {
        client.logs()
    };
    let observation = LegacyObservation {
        eof,
        read_direct: logs.contains("VISION READ: Switching to direct copy mode"),
        write_direct: logs.contains("VISION WRITE: Switching to direct copy mode"),
    };
    assert!(observation.eof, "half-close did not reach EOF\n{logs}");
    assert!(observation.read_direct, "read never entered DIRECT\n{logs}");
    assert!(
        observation.write_direct,
        "write never entered DIRECT\n{logs}"
    );
    drop((client, server));
    target_task.stop().await;
    observation
}
