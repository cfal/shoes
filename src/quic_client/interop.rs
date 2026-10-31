use std::{io, sync::Arc, time::Duration};

use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream, UdpSocket},
};
use tokio_util::task::AbortOnDropHandle;

use crate::{
    address::NetLocation,
    client_proxy_chain::ClientProxyChain,
    config::ClientChain,
    resolver::{NativeResolver, Resolver},
    tcp::chain_builder::try_build_client_proxy_chain,
};

async fn peer(
    mut protocol: serde_json::Value,
    kind: &str,
) -> (
    ClientProxyChain,
    Arc<dyn Resolver>,
    shoes_test_support::process::ProcessGuard,
    tempfile::NamedTempFile,
) {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let ready = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let ready_port = ready.local_addr().unwrap().port();
    drop((socket, ready));
    let mut config = json!({
        "log": {"level": "warn"},
        "inbounds": [
            {"type": "mixed", "listen": "0.0.0.0", "listen_port": ready_port},
            {"type": kind, "listen": "0.0.0.0", "listen_port": port,
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
    if protocol.get("hopping").is_some() {
        protocol["hopping"]["ports"] = json!(port.to_string());
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
    let chain: ClientChain = serde_json::from_value(json!({
        "address": format!("127.0.0.1:{port}"),
        "quic_settings": {"verify": false, "sni_hostname": "localhost"},
        "protocol": protocol
    }))
    .unwrap();
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let chain = try_build_client_proxy_chain(chain.hops, resolver.clone()).unwrap();
    (chain, resolver, process, file)
}

async fn exercise(protocol: serde_json::Value, kind: &str) {
    let hopping = protocol.get("hopping").is_some();
    let (chain, resolver, _peer, _config) = peer(protocol, kind).await;
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let target = NetLocation::from_str(
        &format!("127.0.0.1:{}", listener.local_addr().unwrap().port()),
        None,
    )
    .unwrap();
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
    let udp = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let udp_target = NetLocation::from_str(
        &format!("127.0.0.1:{}", udp.local_addr().unwrap().port()),
        None,
    )
    .unwrap();
    let udp_task = AbortOnDropHandle::new(tokio::spawn(async move {
        let mut buffer = vec![0; 65536];
        loop {
            let (length, peer) = udp.recv_from(&mut buffer).await.unwrap();
            udp.send_to(&buffer[..length], peer).await.unwrap();
        }
    }));
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut streams = Vec::new();
        for _ in 0..4 {
            streams.push(
                chain
                    .connect_tcp(target.clone().into(), &resolver)
                    .await
                    .unwrap()
                    .client_stream,
            );
        }
        let data = vec![42; 256 * 1024];
        if hopping {
            tokio::time::sleep(Duration::from_secs(6)).await;
        }
        for mut stream in streams {
            let (mut read, mut write) = tokio::io::split(&mut stream);
            let mut response = vec![0; data.len()];
            tokio::try_join!(write.write_all(&data), read.read_exact(&mut response)).unwrap();
            assert_eq!(response, data);
            drop((read, write));
            stream.shutdown().await.unwrap();
            assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        }
        let mut associations = Vec::new();
        for _ in 0..8 {
            associations.push(
                chain
                    .connect_udp_bidirectional(&resolver, udp_target.clone().into())
                    .await
                    .unwrap(),
            );
        }
        for length in [0, 1, 1200, 4096] {
            if hopping && length == 1200 {
                tokio::time::sleep(Duration::from_secs(6)).await;
            }
            // No retries: every association must receive its own first packet.
            for (index, association) in associations.iter_mut().enumerate() {
                let data = vec![index as u8; length];
                std::future::poll_fn(|cx| {
                    std::pin::Pin::new(&mut **association).poll_write_message(cx, &data)
                })
                .await
                .unwrap();
            }
            for (index, association) in associations.iter_mut().enumerate() {
                let mut data = vec![0; 65535];
                let mut buffer = ReadBuf::new(&mut data);
                std::future::poll_fn(|cx| {
                    std::pin::Pin::new(&mut **association).poll_read_message(cx, &mut buffer)
                })
                .await
                .unwrap();
                assert_eq!(buffer.filled(), vec![index as u8; length]);
            }
        }
        Ok::<_, io::Error>(())
    })
    .await
    .unwrap()
    .unwrap();
    drop((tcp_task, udp_task));
}

#[tokio::test]
async fn hysteria2_sing_box_tcp_and_concurrent_udp() {
    exercise(
        json!({"type": "hysteria2", "password": "test-password"}),
        "hysteria2",
    )
    .await;
}

#[tokio::test]
async fn tuic_sing_box_tcp_and_both_udp_modes() {
    for mode in ["native", "quic"] {
        exercise(
            json!({"type": "tuic", "uuid": "01234567-89ab-4def-8123-456789abcdef",
            "password": "test-password", "udp_relay_mode": mode}),
            "tuic",
        )
        .await;
    }
}

#[tokio::test]
async fn hysteria2_sing_box_salamander() {
    exercise(
        json!({"type": "hysteria2", "password": "test-password",
        "obfs": {"type": "salamander", "password": "obfs-password"}}),
        "hysteria2",
    )
    .await;
}

#[tokio::test]
async fn hysteria2_sing_box_hopping_with_salamander_keeps_existing_flows() {
    exercise(
        json!({"type": "hysteria2", "password": "test-password",
        "obfs": {"type": "salamander", "password": "obfs-password"},
        "hopping": {"ports": "peer", "interval_secs": 5}}),
        "hysteria2",
    )
    .await;
}
