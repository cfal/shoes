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

struct Tasks(Vec<JoinHandle<()>>);
impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}
impl Tasks {
    async fn stop(&mut self) {
        for task in self.0.drain(..) {
            task.abort();
            let _ = task.await;
        }
    }
}

async fn echo() -> (u16, Tasks) {
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

fn request(port: u16, command: u8, flow: bool) -> Vec<u8> {
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
