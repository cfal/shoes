use std::{
    future::poll_fn,
    io,
    net::{Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream, UdpSocket},
};
use tokio_util::task::AbortOnDropHandle;

use crate::{
    address::{Address, NetLocation},
    async_stream::{AsyncMessageStream, AsyncShutdownMessageExt},
    client_proxy_chain::ClientProxyChain,
    config::ResolvedClientChain,
    resolver::{NativeResolver, Resolver},
    tcp::chain_builder::try_build_client_proxy_chain,
};

#[path = "interop_relay.rs"]
mod relay;

#[derive(Clone, Copy, Default)]
enum TlsPolicy {
    #[default]
    Insecure,
    Pinned,
    WrongPin,
    WebPkiAndPin,
}

#[derive(Default)]
struct PeerOptions {
    ipv6: bool,
    tls: TlsPolicy,
    relay_ports: usize,
    impaired: bool,
}

struct Peer {
    chain: ClientProxyChain,
    resolver: Arc<dyn Resolver>,
    relay: Option<relay::Relay>,
    _process: shoes_test_support::process::ProcessGuard,
    _config: tempfile::NamedTempFile,
}

async fn peer(protocol: serde_json::Value) -> Peer {
    peer_with_options(protocol, PeerOptions::default()).await
}

async fn peer_with_options(mut protocol: serde_json::Value, options: PeerOptions) -> Peer {
    let kind = protocol["type"].as_str().unwrap();
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let listen = if options.ipv6 { "::" } else { "0.0.0.0" };
    let host = if options.ipv6 { "[::1]" } else { "127.0.0.1" };
    let socket = UdpSocket::bind((listen, 0)).await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let ready = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let ready_port = ready.local_addr().unwrap().port();
    drop((socket, ready));
    let mut config = json!({
        "log": {"level": "warn"},
        "inbounds": [
            {"type": "mixed", "listen": "0.0.0.0", "listen_port": ready_port},
            {"type": kind, "listen": listen, "listen_port": port,
             "users": [{"password": "test-password"}],
             "tls": {"enabled": true, "alpn": ["h3"], "certificate": [certificate.cert.pem()], "key": [certificate.signing_key.serialize_pem()]}}
        ],
        "outbounds": [{"type": "direct"}]
    });
    if kind == "tuic" {
        config["inbounds"][1]["users"][0]["uuid"] = protocol["uuid"].clone();
    }
    if let Some(obfs) = protocol.get("obfs") {
        config["inbounds"][1]["obfs"] = obfs.clone();
    }
    let (process, file) =
        shoes_test_support::process::start_singbox_server(&config.to_string()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if TcpStream::connect(("127.0.0.1", ready_port)).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let relay = if options.relay_ports > 0 {
        Some(
            relay::Relay::start(
                format!("{host}:{port}").parse().unwrap(),
                options.relay_ports,
                options.impaired,
            )
            .await,
        )
    } else {
        None
    };
    if protocol.get("hopping").is_some() {
        protocol["hopping"]["ports"] = json!(relay.as_ref().map_or_else(
            || port.to_string(),
            |relay| {
                relay
                    .ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            },
        ));
    }
    let port = relay.as_ref().map_or(port, |relay| relay.ports[0]);
    let mut tls = json!({"verify": false, "sni_hostname": "localhost"});
    if !matches!(options.tls, TlsPolicy::Insecure) {
        let digest =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, certificate.cert.der().as_ref());
        let mut fingerprint = digest.as_ref().to_vec();
        if matches!(options.tls, TlsPolicy::WrongPin) {
            fingerprint[0] ^= 1;
        }
        tls["server_fingerprints"] = json!([fingerprint
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":")]);
        tls["verify"] = json!(matches!(options.tls, TlsPolicy::WebPkiAndPin));
    }
    let endpoint_host = if protocol.get("hopping").is_some() && !options.ipv6 {
        "localhost"
    } else {
        host
    };
    let chain: ResolvedClientChain = crate::config::test_support::from_json(json!({
        "address": format!("{endpoint_host}:{port}"),
        "quic_settings": tls,
        "protocol": protocol
    }))
    .unwrap();
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let chain = try_build_client_proxy_chain(chain.hops, resolver.clone()).unwrap();
    Peer {
        chain,
        resolver,
        relay,
        _process: process,
        _config: file,
    }
}

fn loopback_target(port: u16) -> NetLocation {
    NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), port)
}

async fn write_message(stream: &mut dyn AsyncMessageStream, data: &[u8]) -> io::Result<()> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_write_message(cx, data)).await
}

async fn read_message(
    stream: &mut dyn AsyncMessageStream,
    buffer: &mut ReadBuf<'_>,
) -> io::Result<()> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_read_message(cx, buffer)).await
}

async fn exercise(protocol: serde_json::Value) {
    exercise_with_options(protocol, PeerOptions::default()).await;
}

async fn exercise_with_options(protocol: serde_json::Value, options: PeerOptions) {
    let bind = if options.ipv6 { "[::]:0" } else { "0.0.0.0:0" };
    let address = if options.ipv6 {
        Address::Ipv6(Ipv6Addr::LOCALHOST)
    } else {
        Address::Ipv4(Ipv4Addr::LOCALHOST)
    };
    let impaired = options.impaired;
    let peer = peer_with_options(protocol, options).await;
    let (chain, resolver) = (&peer.chain, &peer.resolver);
    let listener = TcpListener::bind(bind).await.unwrap();
    let target = NetLocation::new(address.clone(), listener.local_addr().unwrap().port());
    let tcp_task = AbortOnDropHandle::new(tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tasks.spawn(async move {
                let (mut read, mut write) = stream.split();
                tokio::io::copy(&mut read, &mut write).await.unwrap();
                write.shutdown().await.unwrap();
            });
        }
    }));
    let udp = UdpSocket::bind(bind).await.unwrap();
    let udp_target = NetLocation::new(address, udp.local_addr().unwrap().port());
    let udp_task = AbortOnDropHandle::new(tokio::spawn(async move {
        let mut buffer = vec![0; 65536];
        loop {
            let (length, peer) = udp.recv_from(&mut buffer).await.unwrap();
            udp.send_to(&buffer[..length], peer).await.unwrap();
        }
    }));
    tokio::time::timeout(Duration::from_secs(40), async {
        let mut streams = Vec::new();
        for _ in 0..4 {
            streams.push(
                chain
                    .connect_tcp(target.clone().into(), resolver)
                    .await
                    .unwrap()
                    .client_stream,
            );
        }
        let data = vec![42; 256 * 1024];
        for mut stream in streams {
            let (mut read, mut write) = tokio::io::split(&mut stream);
            let mut response = vec![0; data.len()];
            tokio::try_join!(write.write_all(&data), read.read_exact(&mut response)).unwrap();
            assert_eq!(response, data);
            drop((read, write));
            stream.shutdown().await.unwrap();
            assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        }
        if impaired {
            assert!(
                peer.relay
                    .as_ref()
                    .unwrap()
                    .dropped()
                    .iter()
                    .all(|count| *count > 0)
            );
            let mut association = chain
                .connect_udp_bidirectional(resolver, udp_target.into())
                .await
                .unwrap();
            // Datagram relays need application retries under deliberate loss.
            // The same association must still deliver a complete fragmented reply.
            let payload = vec![71; 4096];
            let mut response = vec![0; payload.len()];
            for attempt in 0..10 {
                write_message(&mut *association, &payload).await.unwrap();
                let mut buffer = ReadBuf::new(&mut response);
                match tokio::time::timeout(
                    Duration::from_secs(1),
                    read_message(&mut *association, &mut buffer),
                )
                .await
                {
                    Ok(result) => {
                        result.unwrap();
                        assert_eq!(buffer.filled(), payload);
                        association.shutdown_message().await.unwrap();
                        return;
                    }
                    Err(_) => assert!(attempt < 9, "UDP association did not recover under loss"),
                }
            }
            return;
        }
        let mut associations = Vec::new();
        for _ in 0..8 {
            associations.push(
                chain
                    .connect_udp_bidirectional(resolver, udp_target.clone().into())
                    .await
                    .unwrap(),
            );
        }
        for length in [0, 1, 1200, 4096] {
            // No retries: every association must receive its own first packet.
            for (index, association) in associations.iter_mut().enumerate() {
                let data = vec![index as u8; length];
                write_message(&mut **association, &data).await.unwrap();
            }
            for (index, association) in associations.iter_mut().enumerate() {
                let mut data = vec![0; 65535];
                let mut buffer = ReadBuf::new(&mut data);
                read_message(&mut **association, &mut buffer).await.unwrap();
                assert_eq!(buffer.filled(), vec![index as u8; length]);
            }
        }
    })
    .await
    .unwrap();
    drop((tcp_task, udp_task));
}

#[tokio::test]
async fn hysteria2_sing_box_tcp_and_concurrent_udp() {
    exercise(json!({"type": "hysteria2", "password": "test-password"})).await;
}

#[tokio::test]
async fn tuic_sing_box_tcp_and_both_udp_modes() {
    for mode in ["native", "quic"] {
        exercise(
            json!({"type": "tuic", "uuid": "01234567-89ab-4def-8123-456789abcdef",
            "password": "test-password", "udp_relay_mode": mode}),
        )
        .await;
    }
}

#[tokio::test]
async fn hysteria2_sing_box_salamander() {
    exercise(json!({"type": "hysteria2", "password": "test-password",
        "obfs": {"type": "salamander", "password": "obfs-password"}}))
    .await;
}

#[tokio::test]
async fn hysteria2_sing_box_hopping_with_salamander_keeps_existing_flows() {
    let peer = peer_with_options(
        json!({"type": "hysteria2", "password": "test-password",
        "obfs": {"type": "salamander", "password": "obfs-password"},
        "hopping": {"ports": "peer", "interval_secs": 5}}),
        PeerOptions {
            // Random selection may repeat a port. Many live ports make a long
            // same-port run negligible without changing production randomness.
            relay_ports: 32,
            tls: TlsPolicy::Pinned,
            ..Default::default()
        },
    )
    .await;
    tokio::time::timeout(Duration::from_secs(40), async {
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let target = loopback_target(listener.local_addr().unwrap().port());
        let echo_task = AbortOnDropHandle::new(tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (mut read, mut write) = stream.split();
            tokio::io::copy(&mut read, &mut write).await.unwrap();
            write.shutdown().await.unwrap();
        }));
        let mut stream = peer
            .chain
            .connect_tcp(target.into(), &peer.resolver)
            .await
            .unwrap()
            .client_stream;
        let udp = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let target = loopback_target(udp.local_addr().unwrap().port());
        let mut association = peer
            .chain
            .connect_udp_bidirectional(&peer.resolver, target.into())
            .await
            .unwrap();
        let mut original_source = None;
        let mut after_hops = 0;
        for sequence in 0u32.. {
            let (paths, ports) = peer.relay.as_ref().unwrap().paths_seen();
            let hopped = paths >= 3 && ports >= 2;
            let data = sequence
                .to_be_bytes()
                .repeat(if hopped { 16 * 1024 } else { 1 });
            let mut response = vec![0; data.len()];
            {
                let (mut read, mut write) = tokio::io::split(&mut stream);
                tokio::try_join!(
                    async {
                        write.write_all(&data).await?;
                        write.flush().await
                    },
                    read.read_exact(&mut response),
                )
                .unwrap();
            }
            assert_eq!(response, data);
            let data = sequence.to_be_bytes().repeat(if hopped { 1024 } else { 1 });
            let mut response = vec![0; data.len()];
            write_message(&mut *association, &data).await.unwrap();
            let (length, source) = udp.recv_from(&mut response).await.unwrap();
            assert_eq!(&response[..length], data);
            assert_eq!(
                *original_source.get_or_insert(source),
                source,
                "hopping must preserve the server's UDP association"
            );
            udp.send_to(&response[..length], source).await.unwrap();
            let mut buffer = ReadBuf::new(&mut response);
            read_message(&mut *association, &mut buffer).await.unwrap();
            assert_eq!(buffer.filled(), data);
            if hopped {
                after_hops += 1;
                if after_hops == 5 {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        association.shutdown_message().await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        drop(echo_task);
    })
    .await
    .unwrap();
}

fn native_protocols() -> [serde_json::Value; 3] {
    [
        json!({"type": "hysteria2", "password": "test-password"}),
        json!({"type": "tuic", "uuid": "01234567-89ab-4def-8123-456789abcdef",
            "password": "test-password", "udp_relay_mode": "native"}),
        json!({"type": "tuic", "uuid": "01234567-89ab-4def-8123-456789abcdef",
            "password": "test-password", "udp_relay_mode": "quic"}),
    ]
}

#[tokio::test]
async fn sing_box_ipv6_pinned_tls_tcp_and_udp() {
    for protocol in native_protocols() {
        exercise_with_options(
            protocol,
            PeerOptions {
                ipv6: true,
                tls: TlsPolicy::Pinned,
                ..Default::default()
            },
        )
        .await;
    }
}

#[tokio::test]
async fn sing_box_tcp_and_udp_recover_from_bidirectional_loss_and_delay() {
    for protocol in native_protocols() {
        exercise_with_options(
            protocol,
            PeerOptions {
                relay_ports: 1,
                impaired: true,
                tls: TlsPolicy::Pinned,
                ..Default::default()
            },
        )
        .await;
    }
}

#[tokio::test]
async fn sing_box_rejects_wrong_pins_and_untrusted_certificates() {
    for ipv6 in [false, true] {
        for protocol in native_protocols().into_iter().take(2) {
            for tls in [TlsPolicy::WrongPin, TlsPolicy::WebPkiAndPin] {
                let peer = peer_with_options(
                    protocol.clone(),
                    PeerOptions {
                        ipv6,
                        tls,
                        ..Default::default()
                    },
                )
                .await;
                let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
                let target = loopback_target(listener.local_addr().unwrap().port());
                let result = tokio::time::timeout(
                    Duration::from_secs(5),
                    peer.chain.connect_tcp(target.into(), &peer.resolver),
                )
                .await
                .unwrap();
                let error = match result {
                    Err(error) => error,
                    Ok(_) => panic!("TLS rejection unexpectedly succeeded"),
                };
                let message = error.to_string();
                let expected = match tls {
                    TlsPolicy::WrongPin => "unknown server fingerprint",
                    TlsPolicy::WebPkiAndPin => "UnknownIssuer",
                    _ => unreachable!(),
                };
                assert!(message.contains(expected), "{message}");
                assert!(
                    tokio::time::timeout(Duration::from_millis(30), listener.accept())
                        .await
                        .is_err()
                );
            }
        }
    }
}

#[tokio::test]
async fn sing_box_rejects_wrong_credentials_without_target_data() {
    for (kind, protocol) in [
        (
            "hysteria2",
            json!({"type":"hysteria2", "password":"wrong-password"}),
        ),
        (
            "tuic",
            json!({"type":"tuic", "password":"wrong-password", "uuid":"01234567-89ab-4def-8123-456789abcdef"}),
        ),
    ] {
        let peer = peer(protocol).await;
        let (chain, resolver) = (&peer.chain, &peer.resolver);
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let target = loopback_target(listener.local_addr().unwrap().port());
        tokio::time::timeout(Duration::from_secs(5), async {
            match chain.connect_tcp(target.into(), resolver).await {
                Err(error) if kind == "hysteria2" => {
                    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied)
                }
                Err(_) => {}
                Ok(mut setup) => {
                    assert_eq!(
                        kind, "tuic",
                        "HY2 must authenticate before publishing a connection"
                    );
                    assert!(setup.client_stream.read_exact(&mut [0; 1]).await.is_err());
                }
            }
        })
        .await
        .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn tuic_quic_downlink_burst_preserves_the_server_association() {
    let peer = peer(json!({"type":"tuic", "password":"test-password",
        "uuid":"01234567-89ab-4def-8123-456789abcdef", "udp_relay_mode":"quic"}))
    .await;
    let (chain, resolver) = (&peer.chain, &peer.resolver);
    tokio::time::timeout(Duration::from_secs(10), async {
        let echo = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let target = loopback_target(echo.local_addr().unwrap().port());
        let mut association = chain
            .connect_udp_bidirectional(resolver, target.into())
            .await
            .unwrap();
        write_message(&mut *association, b"start").await.unwrap();
        let mut buffer = [0; 2048];
        let (_, first) = echo.recv_from(&mut buffer).await.unwrap();
        // More than the old 64-stream credit, without waiting for client replies.
        for index in 0u16..256 {
            echo.send_to(&index.to_be_bytes(), first).await.unwrap();
        }
        let mut received = 0;
        let deadline = tokio::time::sleep(Duration::from_millis(300));
        tokio::pin!(deadline);
        loop {
            let mut data = ReadBuf::new(&mut buffer);
            tokio::select! {
                _ = &mut deadline => break,
                result = read_message(&mut *association, &mut data) => {
                    result.unwrap();
                    received += 1;
                }
            }
        }
        assert!(received > 64, "only {received} replies arrived");
        write_message(&mut *association, b"again").await.unwrap();
        let (_, second) = echo.recv_from(&mut buffer).await.unwrap();
        assert_eq!(
            first, second,
            "burst must not close the server's UDP association"
        );
        association.shutdown_message().await.unwrap();
    })
    .await
    .unwrap();
}
