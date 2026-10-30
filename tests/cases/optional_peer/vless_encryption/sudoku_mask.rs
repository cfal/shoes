use super::*;
use shoes_test_support::{
    socks5::Socks5UdpAssociation, test_servers::start_udp_echo_server_with_suffix,
};

struct Case {
    peer: Kind,
    peer_client: bool,
    transport: Transport,
    masks: Vec<Value>,
    native: Option<&'static str>,
    vision: bool,
}

impl Case {
    fn new(peer: Kind, peer_client: bool, transport: Transport) -> Self {
        Self {
            peer,
            peer_client,
            transport,
            masks: vec![json!({"password":"outer","ascii":"ascii"})],
            native: None,
            vision: false,
        }
    }
}

fn mask_protocol(protocol: &mut Value, masks: &[Value]) {
    for options in masks.iter().rev() {
        let inner = protocol.take();
        *protocol = options.clone();
        protocol["type"] = json!("sudoku_mask");
        protocol["protocol"] = inner;
    }
}

fn masked(kind: Kind, mut config: Value, server: bool, case: &Case) -> Value {
    match kind {
        Kind::Shoes => {
            mask_protocol(shoes_protocol_mut(&mut config, server), &case.masks);
        }
        Kind::Xray => {
            let stream = &mut xray_endpoint_mut(&mut config, server)["streamSettings"];
            if stream.is_null() {
                *stream = json!({"network":"tcp","security":"none"});
            }
            let masks: Vec<_> = case
                .masks
                .iter()
                .rev()
                .map(|options| {
                    let mut settings = options.clone();
                    for (shoes, xray) in [
                        ("custom_tables", "customTables"),
                        ("padding_min", "paddingMin"),
                        ("padding_max", "paddingMax"),
                    ] {
                        if let Some(value) = settings.as_object_mut().unwrap().remove(shoes) {
                            settings[xray] = value;
                        }
                    }
                    json!({"type":"sudoku","settings":settings})
                })
                .collect();
            stream["finalmask"] = json!({"tcp":masks});
        }
        _ => unreachable!(),
    }
    config
}

fn legacy_vision(kind: Kind, config: &mut Value, server: bool, transport: Transport) {
    if kind == Kind::Shoes {
        let outer = shoes_protocol_mut(config, server);
        let target = if !server {
            outer
        } else if matches!(transport, Transport::Tls) {
            &mut outer["default_target"]
        } else {
            &mut outer["reality_targets"]["localhost"]
        };
        target["vision"] = json!(true);
    } else {
        let endpoint = xray_endpoint_mut(config, server);
        let user = if server {
            &mut endpoint["settings"]["clients"][0]
        } else {
            &mut endpoint["settings"]["vnext"][0]["users"][0]
        };
        user["flow"] = json!("xtls-rprx-vision");
    }
}

async fn transfer<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
) -> io::Result<()> {
    for size in [1, 2, 3, 32 * 1024 + 1] {
        let data: Vec<_> = (0..size).map(|i| (i * 37 + size) as u8).collect();
        let mut output = vec![0; size];
        let (mut read, mut write) = tokio::io::split(&mut *stream);
        tokio::try_join!(
            async {
                write.write_all(&data).await?;
                write.flush().await
            },
            read.read_exact(&mut output)
        )?;
        assert_eq!(output, data);
    }
    Ok(())
}

async fn run(case: Case) {
    eprintln!(
        "Sudoku {:?} client={} {:?} native={:?} vision={}",
        case.peer, case.peer_client, case.transport, case.native, case.vision
    );
    let (server_kind, client_kind) = peer_roles(case.peer, case.peer_client);
    let (encryption, decryption) = case
        .native
        .map(|mode| {
            let (enc, dec, _) = credentials(mode, &["x25519"]);
            (enc, dec)
        })
        .unwrap_or_else(|| ("none".into(), "none".into()));
    let (cover, connector, mut cover_task) = tls_echo(false).await;
    let (target, _, mut echo_task) = echo().await;
    let udp = start_udp_echo_server_with_suffix("0.0.0.0", 0, b"")
        .await
        .unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (cert, key) = (cert.cert.pem(), cert.signing_key.serialize_pem());
    let server_port = free_port().await;
    let mut server_settings = wrap(
        server_kind,
        server_config(
            server_kind,
            server_port,
            &decryption,
            case.vision && case.native.is_some(),
        ),
        true,
        case.transport,
        &cert,
        &key,
        cover,
    );
    if case.vision && case.native.is_none() {
        legacy_vision(server_kind, &mut server_settings, true, case.transport);
    }
    let server = start(
        server_kind,
        server_port,
        masked(server_kind, server_settings, true, &case),
    )
    .await;
    let (tap_port, captures, downlink, mut tap_task) = tap_both(server_port).await;
    let client_port = free_port().await;
    let mut client_settings = wrap(
        client_kind,
        client_config(
            client_kind,
            client_port,
            tap_port,
            &encryption,
            case.vision && case.native.is_some(),
        ),
        false,
        case.transport,
        &cert,
        &key,
        cover,
    );
    if case.vision && case.native.is_none() {
        legacy_vision(client_kind, &mut client_settings, false, case.transport);
    }
    let client = start(
        client_kind,
        client_port,
        masked(client_kind, client_settings, false, &case),
    )
    .await;
    let result = timeout(Duration::from_secs(30), async {
        for _ in 0..3 {
            let mut stream = socks_connect(client_port, target).await?;
            transfer(&mut stream).await?;
            stream.shutdown().await?;
            if matches!(
                case.transport,
                Transport::Raw | Transport::Tls | Transport::Reality
            ) {
                assert_eq!(stream.read(&mut [0]).await?, 0);
            }
        }
        let association = Socks5UdpAssociation::connect("127.0.0.1", client_port).await?;
        for payload in [b"masked UDP".as_slice(), &[42; 4096]] {
            let reply = association
                .send_to(
                    (std::net::Ipv4Addr::LOCALHOST, udp.local_addr().port()).into(),
                    payload,
                )
                .await?;
            assert_eq!(reply, payload);
        }
        if case.vision {
            let stream = socks_connect(client_port, cover).await?;
            let mut tls = connector
                .connect("localhost".try_into().unwrap(), stream)
                .await?;
            for size in [64, 64, 8192] {
                let data = vec![42; size];
                tls.write_all(&data).await?;
                tls.flush().await?;
                let mut response = vec![0; size];
                tls.read_exact(&mut response).await?;
                assert_eq!(response, data);
            }
        }
        Ok::<_, io::Error>(())
    })
    .await;
    assert!(
        matches!(result, Ok(Ok(()))),
        "{result:?}\n{}",
        pair_logs(&client, &server)
    );
    {
        let all = captures.lock().unwrap();
        assert!(all.iter().any(|c| !c.is_empty()));
        if case.masks[0]["ascii"] == "ascii" {
            let downlink = downlink.lock().unwrap();
            assert!(downlink.iter().any(|bytes| !bytes.is_empty()));
            for bytes in all.iter().chain(downlink.iter()) {
                assert!(
                    bytes
                        .iter()
                        .all(|b| *b == b'\n' || (0x20..=0x7e).contains(b)),
                    "unmasked wire bytes"
                );
            }
        }
    }
    if case.vision {
        let shoes = if server_kind == Kind::Shoes {
            &server
        } else {
            &client
        };
        assert!(
            shoes.logs().contains("Switching to direct copy mode"),
            "{}",
            pair_logs(&client, &server)
        );
    }
    drop((client, server));
    tap_task.stop().await;
    echo_task.stop().await;
    cover_task.stop().await;
}

#[tokio::test]
async fn shoes_tcp_outer_stacking() {
    for transport in [
        Transport::Raw,
        Transport::Tls,
        Transport::Websocket,
        Transport::Reality,
    ] {
        let mut case = Case::new(Kind::Shoes, false, transport);
        case.masks.push(json!({"password":"distinct inner mapping","custom_tables":["xpxvvpvv","vxpvxvvp"],"padding_min":100}));
        run(case).await;
    }
}

#[tokio::test]
async fn shoes_xhttp_masked_carriers() {
    for version in ["plain", "h1", "h2c", "h2", "reality"] {
        for mode in ["packet-up", "stream-up", "stream-one"] {
            let mut case = Case::new(Kind::Shoes, false, Transport::XhttpMode { version, mode });
            case.masks.push(json!({"password":"distinct carrier mapping","custom_tables":["","vxpvxvvp"],"padding_min":100}));
            run(case).await;
        }
    }
}

#[tokio::test]
async fn xray_layouts_padding_and_stack_order() {
    for peer_client in [false, true] {
        for masks in [
            vec![json!({"password":"example"})],
            vec![json!({"ascii":"ascii","password":"example","padding_min":100,"padding_max":100})],
            vec![
                json!({"custom_tables":["xpxvvpvv","vxpvxvvp"],"password":"rotating","padding_min":5,"padding_max":15}),
            ],
            vec![
                json!({"ascii":"ascii","password":"outer"}),
                json!({"password":"inner","custom_tables":["","vxpvxvvp"]}),
            ],
        ] {
            let mut case = Case::new(Kind::Xray, peer_client, Transport::Raw);
            case.masks = masks;
            run(case).await;
        }
    }
}

#[tokio::test]
async fn xray_tcp_carriers_and_native_encryption() {
    for peer_client in [false, true] {
        for transport in [
            Transport::Tls,
            Transport::Reality,
            Transport::Websocket,
            Transport::XhttpMode {
                version: "h1",
                mode: "packet-up",
            },
            Transport::XhttpMode {
                version: "h2",
                mode: "stream-one",
            },
        ] {
            run(Case::new(Kind::Xray, peer_client, transport)).await;
        }
        for native in ["native", "random"] {
            let mut case = Case::new(Kind::Xray, peer_client, Transport::Raw);
            case.native = Some(native);
            run(case).await;
        }
    }
}

#[tokio::test]
async fn vision_direct_cannot_bypass_the_mask() {
    for (peer, peer_client) in [
        (Kind::Shoes, false),
        (Kind::Xray, false),
        (Kind::Xray, true),
    ] {
        for transport in [Transport::Tls, Transport::Reality] {
            let mut case = Case::new(peer, peer_client, transport);
            case.vision = true;
            run(case).await;
        }
        for native in ["native", "random"] {
            let mut case = Case::new(peer, peer_client, Transport::Raw);
            case.native = Some(native);
            case.vision = true;
            run(case).await;
        }
    }
}

#[tokio::test]
async fn later_hop_mixed_pool_preserves_masks_and_carrier_reuse() {
    let prefix_port = free_port().await;
    let prefix = start(
        Kind::Shoes,
        prefix_port,
        json!([{
            "address":format!("0.0.0.0:{prefix_port}"),"protocol":{"type":"socks"}
        }]),
    )
    .await;
    let (target, _, mut echo_task) = echo().await;
    let client_port = free_port().await;
    let mut peers = Vec::new();
    let mut taps = Vec::new();
    let mut pool = Vec::new();
    for (index, xhttp) in [false, true].into_iter().enumerate() {
        let server_port = free_port().await;
        let mut server = server_config(Kind::Shoes, server_port, "none", false);
        let mut client = client_config(Kind::Shoes, client_port, server_port, "none", false);
        if xhttp {
            for (config, is_server) in [(&mut server, true), (&mut client, false)] {
                let protocol = shoes_protocol_mut(config, is_server);
                let inner = protocol.take();
                *protocol = json!({"type":"xhttp","http_version":"h2","mode":"stream-one",
                    "path":"/pooled", "protocol":inner});
            }
        } else {
            shoes_protocol_mut(&mut client, false)["h2mux"] =
                json!({"max_connections":1,"min_streams":8,"padding":true});
        }
        let masks = [json!({"password":format!("pool-{index}"),"ascii":"ascii","padding_min":100})];
        mask_protocol(shoes_protocol_mut(&mut server, true), &masks);
        mask_protocol(shoes_protocol_mut(&mut client, false), &masks);
        peers.push(start(Kind::Shoes, server_port, server).await);
        let (tap_port, captures, task) = tap(server_port).await;
        let mut hop = client[0]["rules"][0]["client_chain"].take();
        hop["address"] = json!(format!("127.0.0.1:{tap_port}"));
        pool.push(hop);
        taps.push((captures, task));
    }
    let client = start(
        Kind::Shoes,
        client_port,
        json!([{
            "address":format!("0.0.0.0:{client_port}"), "protocol":{"type":"socks"},
            "rules":[{"masks":"0.0.0.0/0","action":"allow","client_chain":[
                {"address":format!("127.0.0.1:{prefix_port}"),"protocol":{"type":"socks"}},
                {"pool":pool}
            ]}]
        }]),
    )
    .await;
    let result = timeout(Duration::from_secs(30), async {
        for _ in 0..8 {
            let mut stream = socks_connect(client_port, target).await?;
            transfer(&mut stream).await?;
        }
        Ok::<_, io::Error>(())
    })
    .await;
    assert!(
        matches!(result, Ok(Ok(()))),
        "{result:?}\n{}\n{}\n{}",
        client.logs(),
        peers[0].logs(),
        peers[1].logs()
    );
    for (index, (captures, _)) in taps.iter().enumerate() {
        let captures = captures.lock().unwrap();
        let active: Vec<_> = captures.iter().filter(|bytes| !bytes.is_empty()).collect();
        // Eight round-robin sessions: H2MUX uses each supplied transport; H2 reuses one.
        assert_eq!(active.len(), if index == 0 { 4 } else { 1 }, "pool {index}");
        assert!(active.iter().all(|bytes| {
            bytes
                .iter()
                .all(|b| *b == b'\n' || (0x20..=0x7e).contains(b))
        }));
    }
    drop((client, peers, prefix));
    for (_, mut task) in taps {
        task.stop().await;
    }
    echo_task.stop().await;
}

#[tokio::test]
async fn anytls_separate_tasks_preserve_full_duplex_under_backpressure() {
    for transport in [Transport::Raw, Transport::Tls] {
        let (target, _, mut echo_task) = echo().await;
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let (cert, key) = (cert.cert.pem(), cert.signing_key.serialize_pem());
        let server_port = free_port().await;
        let client_port = free_port().await;
        let mut server = server_config(Kind::Shoes, server_port, "none", false);
        *shoes_protocol_mut(&mut server, true) = json!({"type":"anytls",
            "users":[{"name":"test","password":"anytls-secret"}]});
        let mut client = client_config(Kind::Shoes, client_port, server_port, "none", false);
        *shoes_protocol_mut(&mut client, false) =
            json!({"type":"anytls","password":"anytls-secret"});
        let mut case = Case::new(Kind::Shoes, false, transport);
        case.masks[0]["padding_min"] = json!(100);
        let server = start(
            Kind::Shoes,
            server_port,
            masked(
                Kind::Shoes,
                wrap(Kind::Shoes, server, true, transport, &cert, &key, 0),
                true,
                &case,
            ),
        )
        .await;
        let client = start(
            Kind::Shoes,
            client_port,
            masked(
                Kind::Shoes,
                wrap(Kind::Shoes, client, false, transport, &cert, &key, 0),
                false,
                &case,
            ),
        )
        .await;
        let result = timeout(Duration::from_secs(30), async {
            for _ in 0..2 {
                let mut stream = socks_connect(client_port, target).await?;
                let (mut read, mut write) = stream.split();
                let payload: Vec<_> = (0..2 * 1024 * 1024 + 17).map(|i| (i % 251) as u8).collect();
                tokio::try_join!(
                    async {
                        write.write_all(&payload).await?;
                        write.flush().await
                    },
                    async {
                        let mut output = vec![0; payload.len()];
                        for chunk in output.chunks_mut(4096) {
                            read.read_exact(chunk).await?;
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                        assert_eq!(output, payload);
                        Ok::<_, io::Error>(())
                    }
                )?;
            }
            Ok::<_, io::Error>(())
        })
        .await;
        assert!(
            matches!(result, Ok(Ok(()))),
            "{result:?}\n{}",
            pair_logs(&client, &server)
        );
        drop((client, server));
        echo_task.stop().await;
    }
}
