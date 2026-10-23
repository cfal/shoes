use super::*;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use serde_json::Value;
use tokio_util::task::AbortOnDropHandle;

async fn request(address: SocketAddr, method: &str, path: &str) -> Value {
    timeout(Duration::from_secs(5), async {
        let stream = TcpStream::connect(address).await.unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                .await
                .unwrap();
        let _driver = AbortOnDropHandle::new(tokio::spawn(connection));
        let response = sender
            .send_request(
                hyper::Request::builder()
                    .method(method)
                    .uri(path)
                    .header("Host", "localhost")
                    .header("Authorization", "Bearer tun-controller-test")
                    .body(Empty::<Bytes>::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status().is_success());
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn clash_api_tun_counts_payload_and_cancels_destinations_independently() {
    let listener = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    let controller = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
    drop(listener);
    let tun = KernelTun::start_with(false, Some(false), 1500, 32768, |config| {
        start_shoes_server_with_sudo(&format!(
            "{config}\n- clash_api_address: '0.0.0.0:{}'\n  secret: tun-controller-test\n",
            controller.port()
        ))
    })
    .await
    .unwrap();
    let baseline = request(controller, "GET", "/connections").await;
    let tcp_peer = start_tcp_stream_echo_server("0.0.0.0", 0).await.unwrap();
    let udp_peer = start_udp_echo_server_with_suffix("0.0.0.0", 0, b"")
        .await
        .unwrap();
    let sibling_peer = start_udp_echo_server_with_suffix("0.0.0.0", 0, b"")
        .await
        .unwrap();
    let mut tcp = tun.connect_tcp(tcp_peer.local_addr().port()).await.unwrap();
    tcp.write_all(b"tcp-payload").await.unwrap();
    let mut received = [0; 11];
    timeout(Duration::from_secs(5), tcp.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received, b"tcp-payload");
    let udp = UdpSocket::bind(SocketAddr::new(tun.source, 0))
        .await
        .unwrap();
    let destination = SocketAddr::new(tun.target, udp_peer.local_addr().port());
    udp_exchange(&udp, destination, b"udp-payload")
        .await
        .unwrap();
    let sibling = SocketAddr::new(tun.target, sibling_peer.local_addr().port());
    udp_exchange(&udp, sibling, b"udp-sibling").await.unwrap();
    let snapshot = request(controller, "GET", "/connections").await;
    let sibling_id = snapshot["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|flow| {
            flow["metadata"]["network"] == "udp"
                && flow["metadata"]["destinationPort"].as_str() == Some(&sibling.port().to_string())
        })
        .unwrap()["id"]
        .clone();
    assert_eq!(
        snapshot["uploadTotal"].as_u64().unwrap() - baseline["uploadTotal"].as_u64().unwrap(),
        33
    );
    assert_eq!(
        snapshot["downloadTotal"].as_u64().unwrap() - baseline["downloadTotal"].as_u64().unwrap(),
        33
    );
    for network in ["tcp", "udp"] {
        let port = if network == "tcp" {
            tcp_peer.local_addr().port()
        } else {
            udp_peer.local_addr().port()
        };
        let flow = snapshot["connections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|flow| {
                flow["metadata"]["network"] == network
                    && flow["metadata"]["destinationPort"].as_str() == Some(&port.to_string())
            })
            .unwrap();
        assert_eq!(flow["metadata"]["sourceIP"], tun.source.to_string());
        assert_eq!(flow["upload"], 11);
        assert_eq!(flow["download"], 11);
        request(
            controller,
            "DELETE",
            &format!("/connections/{}", flow["id"].as_str().unwrap()),
        )
        .await;
        timeout(Duration::from_secs(3), async {
            loop {
                let current = request(controller, "GET", "/connections").await;
                if !current["connections"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|item| item["id"] == flow["id"])
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        udp_exchange(&udp, sibling, b"still alive").await.unwrap();
        let current = request(controller, "GET", "/connections").await;
        assert!(
            current["connections"]
                .as_array()
                .unwrap()
                .iter()
                .any(|flow| flow["id"] == sibling_id),
            "sibling flow must retain its identity"
        );
        udp_exchange(&udp, destination, b"again").await.unwrap();
        if network == "udp" {
            let current = request(controller, "GET", "/connections").await;
            let reopened = current["connections"]
                .as_array()
                .unwrap()
                .iter()
                .find(|flow| {
                    flow["metadata"]["network"] == "udp"
                        && flow["metadata"]["destinationPort"].as_str()
                            == Some(&destination.port().to_string())
                })
                .unwrap();
            assert_ne!(reopened["id"], flow["id"]);
        }
    }
    assert!(matches!(
        timeout(Duration::from_secs(3), tcp.read_u8()).await,
        Ok(Err(_))
    ));
}
