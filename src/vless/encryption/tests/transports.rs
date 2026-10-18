use std::{net::SocketAddr, sync::Arc, time::Duration};

use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

use super::fixture_settings;
use crate::{
    config::ServerConfig, quic_stream::QuicStream, resolver::NativeResolver,
    vless::encryption::ClientEncryption,
};

const UUID: &str = "550e8400-e29b-41d4-a716-446655440000";
const LIMIT: Duration = Duration::from_secs(10);

pub(super) struct Tasks(pub(super) Vec<JoinHandle<()>>);
impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}
impl Tasks {
    pub(super) async fn stop(&mut self) {
        for task in self.0.drain(..) {
            task.abort();
            let _ = task.await;
        }
    }
}

pub(super) async fn echo() -> (u16, Tasks) {
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (mut stream, _) = result.unwrap();
                    tasks.spawn(async move {
                        let (mut read, mut write) = stream.split();
                        let _ = tokio::io::copy(&mut read, &mut write).await;
                    });
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    });
    (port, Tasks(vec![task]))
}

#[tokio::test]
async fn native_vision_rejects_h2mux_before_opening_a_stream() {
    use crate::{
        client_proxy_selector::ClientProxySelector,
        h2mux::{MUX_DESTINATION_HOST, MUX_DESTINATION_PORT},
        tcp::tcp_handler::TcpServerHandler,
        vless::{encryption::ServerEncryption, vless_server_handler::VlessTcpServerHandler},
    };
    use shoes_test_support::vless::{VlessDestination, encode_vless_udp_request, parse_uuid};

    let (encryption, decryption) = fixture_settings("random", true, &[32]);
    let handler = VlessTcpServerHandler::new(
        UUID,
        true,
        Arc::new(ClientProxySelector::new(Vec::new())),
        Arc::new(NativeResolver::new()),
        None,
        Some(Arc::new(
            ServerEncryption::new(&decryption, Default::default()).unwrap(),
        )),
        true,
    )
    .unwrap();
    let (a, b) = tokio::io::duplex(8192);
    let (result, _client) = timeout(LIMIT, async {
        tokio::join!(handler.setup_server_stream(Box::new(b)), async {
            let mut client = ClientEncryption::new(&encryption)
                .unwrap()
                .handshake(a)
                .await
                .unwrap();
            let mut request = encode_vless_udp_request(
                parse_uuid(UUID).unwrap(),
                &VlessDestination::Domain(MUX_DESTINATION_HOST.into(), MUX_DESTINATION_PORT),
            )
            .unwrap();
            request[18] = 1;
            request[17] = 18;
            request.splice(18..18, b"\x0a\x10xtls-rprx-vision".iter().copied());
            client.write_all(&request).await.unwrap();
            client.flush().await.unwrap();
            client
        })
    })
    .await
    .unwrap();
    let error = result.err().expect("native Vision accepted H2MUX");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(
        error.to_string(),
        "Native VLESS Vision does not support H2MUX"
    );
}

#[tokio::test]
async fn legacy_and_native_address_forms_and_empty_udp_responses() {
    use crate::async_stream::AsyncStream;
    use shoes_test_support::{
        test_servers::{start_tcp_stream_echo_server, start_udp_response_server},
        vless::{
            VlessDestination, VlessUdpClient, XUDP_OPTION_DATA, XUDP_STATUS_NEW, XudpClient,
            XudpFrame, encode_vless_udp_request, parse_uuid,
        },
    };

    let udp_response = |payload: &[u8], _| {
        if payload == b"empty reply" {
            vec![]
        } else {
            payload.to_vec()
        }
    };
    let udp = start_udp_response_server("0.0.0.0", 0, udp_response)
        .await
        .unwrap();
    let (tcp_port, mut target) = echo().await;
    // Separate listeners serve either localhost address without requiring dual-stack sockets.
    let ipv6_targets = match TcpListener::bind("[::1]:0").await {
        Ok(_probe) => Some((
            start_tcp_stream_echo_server("::1", tcp_port).await.unwrap(),
            start_udp_response_server("::1", udp.local_addr().port(), udp_response)
                .await
                .unwrap(),
        )),
        Err(error) => {
            eprintln!("IPv6 loopback unavailable; skipping IPv6 cases: {error}");
            None
        }
    };
    for (native, vision) in [(false, false), (true, false), (true, true)] {
        let (encryption, decryption) = fixture_settings("random", true, &[32]);
        let client = ClientEncryption::new(&encryption).unwrap();
        let port = TcpListener::bind("0.0.0.0:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let config: ServerConfig = serde_json::from_value(json!({
            "address":format!("0.0.0.0:{port}"),
            "protocol":{"type":"vless","user_id":UUID,"udp_enabled":true,
                "decryption":if native {decryption.as_str()} else {"none"},"vision":vision}
        }))
        .unwrap();
        let mut listeners = Tasks(
            crate::tcp::tcp_server::start_servers(
                crate::config::Config::Server(config),
                Arc::new(NativeResolver::new()),
            )
            .await
            .unwrap(),
        );
        let connect = || async {
            let socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let stream: Box<dyn AsyncStream> = if native {
                Box::new(client.handshake(socket).await.unwrap())
            } else {
                Box::new(socket)
            };
            stream
        };
        timeout(LIMIT, async {
            let destinations = |port, ipv6: Option<SocketAddr>| {
                let mut destinations = vec![
                    VlessDestination::Ip(SocketAddr::from(([127, 0, 0, 1], port))),
                    VlessDestination::Domain("localhost".into(), port),
                ];
                if let Some(address) = ipv6 {
                    destinations.push(VlessDestination::Ip(address));
                }
                destinations
            };
            for _ in 0..2 {
                if !vision {
                    for destination in destinations(
                        tcp_port,
                        ipv6_targets.as_ref().map(|(tcp, _)| tcp.local_addr()),
                    ) {
                        let mut stream = connect().await;
                        let mut request =
                            encode_vless_udp_request(parse_uuid(UUID).unwrap(), &destination)
                                .unwrap();
                        request[18] = 1;
                        stream.write_all(&request).await.unwrap();
                        stream.write_all(b"address roundtrip").await.unwrap();
                        stream.flush().await.unwrap();
                        let mut reply = [0; 19];
                        stream.read_exact(&mut reply).await.unwrap();
                        assert_eq!(&reply[..2], &[0, 0]);
                        assert_eq!(&reply[2..], b"address roundtrip");
                    }
                }
                for destination in destinations(
                    udp.local_addr().port(),
                    ipv6_targets.as_ref().map(|(_, udp)| udp.local_addr()),
                ) {
                    let stream = connect().await;
                    let mut udp = VlessUdpClient::connect(
                        stream,
                        parse_uuid(UUID).unwrap(),
                        destination.clone(),
                    )
                    .await
                    .unwrap();
                    for (payload, expected) in [
                        (b"empty reply".as_slice(), b"".as_slice()),
                        (
                            b"nonempty after empty".as_slice(),
                            b"nonempty after empty".as_slice(),
                        ),
                    ] {
                        udp.send_packet(payload).await.unwrap();
                        let reply = udp.recv_packet(LIMIT).await.unwrap();
                        assert_eq!(reply, expected);
                    }
                    let mut xudp = XudpClient::connect(connect().await, parse_uuid(UUID).unwrap())
                        .await
                        .unwrap();
                    xudp.send_frame(&XudpFrame {
                        session_id: 17,
                        status: XUDP_STATUS_NEW,
                        options: XUDP_OPTION_DATA,
                        destination: Some(destination),
                        payload: Some(b"xudp address".to_vec()),
                    })
                    .await
                    .unwrap();
                    let reply = xudp.recv_frame(LIMIT).await.unwrap();
                    assert_eq!(reply.session_id, 17);
                    assert_eq!(reply.payload.unwrap(), b"xudp address");
                }
            }
        })
        .await
        .unwrap_or_else(|e| panic!("native={native}, vision={vision}: {e}"));
        listeners.stop().await;
    }
    target.stop().await;
}

pub(super) fn request(port: u16, command: u8, flow: bool) -> Vec<u8> {
    let mut request = vec![0];
    request.extend(crate::uuid_util::parse_uuid(UUID).unwrap());
    if flow {
        request.push(18);
        request.extend_from_slice(b"\x0a\x10xtls-rprx-vision");
    } else {
        request.push(0);
    }
    request.push(command);
    request.extend_from_slice(&port.to_be_bytes());
    request.extend_from_slice(&[1, 127, 0, 0, 1]);
    request
}

#[tokio::test]
async fn non_vision_server_rejects_flow_with_backend_specific_guidance() {
    use crate::{
        async_stream::AsyncStream,
        client_proxy_selector::ClientProxySelector,
        tcp::tcp_handler::TcpServerHandler,
        vless::{encryption::ServerEncryption, vless_server_handler::VlessTcpServerHandler},
    };

    for native in [false, true] {
        let (encryption, decryption) = fixture_settings("native", false, &[32]);
        let server_encryption = native
            .then(|| Arc::new(ServerEncryption::new(&decryption, Default::default()).unwrap()));
        let handler = VlessTcpServerHandler::new(
            UUID,
            true,
            Arc::new(ClientProxySelector::new(Vec::new())),
            Arc::new(NativeResolver::new()),
            None,
            server_encryption,
            false,
        )
        .unwrap();
        let (client, server) = tokio::io::duplex(8192);
        let (result, _client) = timeout(LIMIT, async {
            tokio::join!(handler.setup_server_stream(Box::new(server)), async {
                let mut client: Box<dyn AsyncStream> = if native {
                    Box::new(
                        ClientEncryption::new(&encryption)
                            .unwrap()
                            .handshake(client)
                            .await
                            .unwrap(),
                    )
                } else {
                    Box::new(client)
                };
                client.write_all(&request(443, 1, true)).await.unwrap();
                client.flush().await.unwrap();
                client
            })
        })
        .await
        .unwrap();
        let error = result.err().expect("non-Vision server accepted a flow");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        let guidance = if native {
            "set vision: true on this VLESS server"
        } else {
            "use TLS protocol config"
        };
        assert!(error.to_string().contains(guidance), "{error}");
    }
}

#[tokio::test]
async fn h2mux_multiplexes_concurrent_streams_over_one_encrypted_connection() {
    use crate::{
        address::{Address, NetLocation, ResolvedLocation},
        h2mux::{H2MuxClientSession, H2MuxOptions, MUX_DESTINATION_HOST, MUX_DESTINATION_PORT},
        tcp::tcp_handler::TcpClientHandler,
        vless::vless_client_handler::VlessTcpClientHandler,
    };

    for mode in ["native", "xorpub", "random"] {
        let (encryption, decryption) = fixture_settings(mode, true, &[64]);
        let client = VlessTcpClientHandler::new(
            UUID,
            true,
            Some(ClientEncryption::new(&encryption).unwrap()),
            false,
        )
        .unwrap();
        let port = TcpListener::bind("0.0.0.0:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let config: ServerConfig = serde_json::from_value(json!({
            "address": format!("0.0.0.0:{port}"),
            "protocol": {"type": "vless", "user_id": UUID, "decryption": decryption},
        }))
        .unwrap();
        let mut listeners = Tasks(
            crate::tcp::tcp_server::start_servers(
                crate::config::Config::Server(config),
                Arc::new(NativeResolver::new()),
            )
            .await
            .unwrap(),
        );
        let (target, mut target_task) = echo().await;
        let target = NetLocation::new(Address::Ipv4(std::net::Ipv4Addr::LOCALHOST), target);
        for padding in [false, true] {
            timeout(LIMIT, async {
                let socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
                let carrier = client
                    .setup_client_tcp_stream(
                        Box::new(socket),
                        ResolvedLocation::new(NetLocation::new(
                            Address::Hostname(MUX_DESTINATION_HOST.into()),
                            MUX_DESTINATION_PORT,
                        )),
                    )
                    .await
                    .unwrap()
                    .client_stream;
                let mut session = H2MuxClientSession::new(
                    carrier,
                    &H2MuxOptions {
                        padding,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
                let mut streams = Vec::new();
                for _ in 0..16 {
                    streams.push(session.open_tcp(&target).await.unwrap());
                }
                assert_eq!(session.active_streams(), 16);
                let mut tasks = JoinSet::new();
                for (id, mut stream) in streams.into_iter().enumerate() {
                    tasks.spawn(async move {
                        let data: Vec<_> = (0..131072).map(|n| ((n + id) % 251) as u8).collect();
                        let (mut read, mut write) = tokio::io::split(&mut stream);
                        let mut reply = vec![0; data.len()];
                        let ((), ()) = tokio::join!(
                            async {
                                for chunk in data.chunks(8192) {
                                    write.write_all(chunk).await.unwrap();
                                }
                                write.flush().await.unwrap();
                            },
                            async {
                                read.read_exact(&mut reply).await.unwrap();
                            },
                        );
                        assert_eq!(reply, data);
                        stream.shutdown().await.unwrap();
                    });
                }
                while let Some(result) = tasks.join_next().await {
                    result.unwrap();
                }
                assert_eq!(session.active_streams(), 0);
            })
            .await
            .unwrap_or_else(|error| panic!("{mode}, padding={padding}: {error}"));
        }
        listeners.stop().await;
        target_task.stop().await;
    }
}

#[tokio::test]
async fn raw_quic_bind_addresses_share_tickets_and_capacity() {
    let (encryption, decryption) = fixture_settings("random", true, &[32]);
    let client = ClientEncryption::new(&encryption).unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let config: ServerConfig = serde_json::from_value(json!({
        "addresses": [format!("127.0.0.1:{port}"), format!("127.0.0.2:{port}")],
        "transport": "quic",
        "quic_settings": {"cert": cert.cert.pem(), "key": cert.signing_key.serialize_pem(), "num_endpoints": 1},
        "protocol": {"type": "vless", "user_id": UUID, "decryption": decryption,
            "encryption_limits": {"max_sessions": 100, "max_replays": 100, "max_replays_per_session": 1}},
    })).unwrap();
    let mut listeners = Tasks(
        crate::quic_server::start_quic_servers(config, Arc::new(NativeResolver::new()))
            .await
            .unwrap(),
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(
        quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap(),
    );
    let (target, mut echo) = echo().await;
    timeout(LIMIT, async {
        for (ip, resumed, rejected) in [
            (1, false, false),
            (2, true, false),
            (1, true, true),
            (2, false, false),
        ] {
            let connection = endpoint
                .connect(SocketAddr::from(([127, 0, 0, ip], port)), "localhost")
                .unwrap()
                .await
                .unwrap();
            let (send, recv) = connection.open_bi().await.unwrap();
            let mut stream = client
                .handshake(QuicStream::from(send, recv))
                .await
                .unwrap();
            assert_eq!(stream.is_resumed(), resumed);
            stream.write_all(&request(target, 1, false)).await.unwrap();
            stream.flush().await.unwrap();
            let mut response = [0; 2];
            // Even a silent destination receives the native VLESS response immediately.
            let result = stream.read_exact(&mut response).await;
            if rejected {
                assert!(result.is_err());
            } else {
                result.unwrap();
                assert_eq!(response, [0, 0]);
                stream.write_all(b"shared ticket").await.unwrap();
                stream.flush().await.unwrap();
                let mut reply = [0; 13];
                stream.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"shared ticket");
            }
            drop(stream);
            connection.close(0u32.into(), b"done");
        }
    })
    .await
    .unwrap();
    endpoint.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    listeners.stop().await;
    echo.stop().await;
}

#[tokio::test]
async fn encrypted_xudp_control_empty_and_multiple_sessions_and_udp_flow_rejection() {
    use shoes_test_support::{
        test_servers::start_udp_echo_server_with_suffix,
        vless::{
            VlessDestination, XUDP_OPTION_DATA, XUDP_STATUS_END, XUDP_STATUS_KEEPALIVE,
            XUDP_STATUS_NEW, XudpClient, XudpFrame,
        },
    };
    let (encryption, decryption) = fixture_settings("random", true, &[64]);
    let client = ClientEncryption::new(&encryption).unwrap();
    let port = TcpListener::bind("0.0.0.0:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config: ServerConfig = serde_json::from_value(json!({
        "address": format!("0.0.0.0:{port}"),
        "protocol": {"type": "vless", "user_id": UUID, "decryption": decryption, "vision": true},
    }))
    .unwrap();
    let mut listeners = Tasks(
        crate::tcp::tcp_server::start_servers(
            crate::config::Config::Server(config),
            Arc::new(NativeResolver::new()),
        )
        .await
        .unwrap(),
    );
    let target = start_udp_echo_server_with_suffix("0.0.0.0", 0, b"reply")
        .await
        .unwrap();
    let destination = SocketAddr::from(([127, 0, 0, 1], target.local_addr().port()));
    timeout(LIMIT, async {
        for _ in 0..2 {
            let stream = client
                .handshake(TcpStream::connect(("127.0.0.1", port)).await.unwrap())
                .await
                .unwrap();
            let uuid = shoes_test_support::vless::parse_uuid(UUID).unwrap();
            let mut xudp = XudpClient::connect(stream, uuid).await.unwrap();
            for session_id in [1, 2, 3] {
                for payload in [vec![], vec![42; 16384]] {
                    xudp.send_frame(&XudpFrame {
                        session_id,
                        status: XUDP_STATUS_NEW,
                        options: XUDP_OPTION_DATA,
                        destination: Some(VlessDestination::Ip(destination)),
                        payload: Some(payload.clone()),
                    })
                    .await
                    .unwrap();
                    if payload.is_empty() {
                        // Shared XUDP semantics ignore empty DATA without treating it as EOF.
                        assert!(xudp.recv_frame(Duration::from_millis(50)).await.is_err());
                    } else {
                        let reply = xudp.recv_frame(LIMIT).await.unwrap();
                        assert_eq!(reply.session_id, session_id);
                        assert_eq!(
                            reply.payload.unwrap(),
                            [payload, b"reply".to_vec()].concat()
                        );
                    }
                    for status in [XUDP_STATUS_KEEPALIVE, XUDP_STATUS_END] {
                        xudp.send_frame(&XudpFrame {
                            session_id,
                            status,
                            options: 0,
                            destination: None,
                            payload: None,
                        })
                        .await
                        .unwrap();
                    }
                }
            }
        }
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let mut stream = client
            .handshake(TcpStream::connect(("127.0.0.1", port)).await.unwrap())
            .await
            .unwrap();
        let mut bytes = request(socket.local_addr().unwrap().port(), 2, true);
        bytes.extend_from_slice(b"\x00\x03bad");
        stream.write_all(&bytes).await.unwrap();
        stream.flush().await.unwrap();
        assert!(stream.read_exact(&mut [0; 2]).await.is_err());
        assert!(
            timeout(Duration::from_millis(50), socket.recv(&mut [0; 8]))
                .await
                .is_err()
        );
    })
    .await
    .unwrap();
    listeners.stop().await;
}
