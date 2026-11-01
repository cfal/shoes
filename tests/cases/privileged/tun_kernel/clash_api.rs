use super::*;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use serde_json::{Value, json};
use tokio_util::task::AbortOnDropHandle;

async fn request(address: SocketAddr, method: &str, path: &str) -> Value {
    request_with_body(address, method, path, Value::Null).await
}

async fn request_with_body(address: SocketAddr, method: &str, path: &str, body: Value) -> Value {
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
                    .body(Full::new(Bytes::from(if body.is_null() {
                        Vec::new()
                    } else {
                        serde_json::to_vec(&body).unwrap()
                    })))
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
async fn whole_path_selector_pins_kernel_tcp_and_udp_flows() {
    timeout(TEST_TIMEOUT, async {
        for ipv6 in [false, true] {
            let mut ports = shoes_test_support::port_helper::PortHelper::new();
            let (_, api_port) = ports.get_localhost_listener_port();
            let (_, socks_port) = ports.get_localhost_listener_port();
            let (_, exit_port) = ports.get_localhost_listener_port();
            let controller = SocketAddr::from(([127, 0, 0, 1], api_port));
            let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
            let prefix_port = listener.local_addr().unwrap().port();
            let count = Arc::new(AtomicUsize::new(0));
            let observed = count.clone();
            let _prefix = AbortOnDropHandle::new(tokio::spawn(async move {
                let mut connections = JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let (mut client, _) = accepted.unwrap();
                            observed.fetch_add(1, Ordering::SeqCst);
                            connections.spawn(async move {
                                let mut upstream = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
                                tokio::io::copy_bidirectional(&mut client, &mut upstream).await
                            });
                        }
                        result = connections.join_next(), if !connections.is_empty() => {
                            result.expect("prefix connection task missing")
                                .expect("prefix connection task panicked")
                                .expect("prefix forwarding failed");
                        }
                    }
                }
            }));
            let protocol = json!({"type":"vless", "user_id":"550e8400-e29b-41d4-a716-446655440000", "udp_enabled":true});
            let tun = KernelTun::start_with(ipv6, Some(false), 1500, 32768, |config| {
                let mut config: Value = serde_yaml::from_str(config).unwrap();
                config[0]["rules"][0]["client_chain"] = json!("outbound");
                config.as_array_mut().unwrap().extend([
                    json!({"clash_api_address":format!("0.0.0.0:{api_port}"), "secret":"tun-controller-test"}),
                    json!({"client_group":"outbound", "type":"selector", "default":"short", "client_chains":[
                        {"name":"short", "protocol":{"type":"direct"}},
                        {"name":"long", "chain":[
                            {"name":"prefix", "address":format!("127.0.0.1:{prefix_port}"), "protocol":{"type":"socks"}},
                            {"name":"exit", "address":format!("127.0.0.1:{exit_port}"), "protocol":protocol}
                        ]},
                        {"name":"tcp-only", "address":"192.0.2.1:80", "protocol":{"type":"http"}}
                    ]}),
                    json!({"address":format!("0.0.0.0:{socks_port}"), "protocol":{"type":"socks"}}),
                    json!({"address":format!("0.0.0.0:{exit_port}"), "protocol":protocol}),
                ]);
                start_shoes_server_with_sudo(&serde_yaml::to_string(&config).unwrap())
            }).await.unwrap();
            let bind = if ipv6 { "::" } else { "0.0.0.0" };
            let tcp_peer = start_tcp_stream_echo_server(bind, 0).await.unwrap();
            let udp_peer = start_udp_echo_server_with_suffix(bind, 0, b"").await.unwrap();
            let destination = SocketAddr::new(tun.target, udp_peer.local_addr().port());
            let old_udp = UdpSocket::bind(SocketAddr::new(tun.source, 0)).await.unwrap();
            let mut old_tcp = tun.connect_tcp(tcp_peer.local_addr().port()).await.unwrap();
            tcp_exchange(&mut old_tcp, b"short").await.unwrap();
            udp_exchange(&old_udp, destination, b"short").await.unwrap();
            assert_eq!(count.load(Ordering::SeqCst), 0);

            request_with_body(controller, "PUT", "/proxies/outbound", json!({"name":"long"})).await;
            let long_udp = UdpSocket::bind(SocketAddr::new(tun.source, 0)).await.unwrap();
            let mut long_tcp = tun.connect_tcp(tcp_peer.local_addr().port()).await.unwrap();
            tcp_exchange(&mut long_tcp, b"long").await.unwrap();
            udp_exchange(&long_udp, destination, b"long").await.unwrap();
            tcp_exchange(&mut old_tcp, b"short retained").await.unwrap();
            udp_exchange(&old_udp, destination, b"short retained").await.unwrap();
            assert_eq!(count.load(Ordering::SeqCst), 2);

            request_with_body(controller, "PUT", "/proxies/outbound", json!({"name":"tcp-only"})).await;
            let rejected = UdpSocket::bind(SocketAddr::new(tun.source, 0)).await.unwrap();
            rejected.send_to(b"rejected", destination).await.unwrap();
            assert!(timeout(Duration::from_millis(200), rejected.recv(&mut [0; 32])).await.is_err());
            for stream in [&mut long_tcp, &mut old_tcp] {
                tcp_exchange(stream, b"still pinned").await.unwrap();
            }
            for socket in [&long_udp, &old_udp] {
                udp_exchange(socket, destination, b"still pinned").await.unwrap();
            }
            request_with_body(controller, "PUT", "/proxies/outbound", json!({"name":"short"})).await;
            let fresh_udp = UdpSocket::bind(SocketAddr::new(tun.source, 0)).await.unwrap();
            udp_exchange(&fresh_udp, destination, b"short again").await.unwrap();
            let mut fresh_tcp = tun.connect_tcp(tcp_peer.local_addr().port()).await.unwrap();
            tcp_exchange(&mut fresh_tcp, b"short again").await.unwrap();
            assert_eq!(count.load(Ordering::SeqCst), 2);
            let snapshot = request(controller, "GET", "/connections").await;
            for (network, port) in [("tcp", long_tcp.local_addr().unwrap().port()), ("udp", long_udp.local_addr().unwrap().port())] {
                let port = port.to_string();
                let flow = snapshot["connections"].as_array().unwrap().iter().find(|flow| {
                    flow["metadata"]["network"] == network
                        && flow["metadata"]["sourceIP"] == tun.source.to_string()
                        && flow["metadata"]["sourcePort"] == port
                }).unwrap();
                assert_eq!(flow["chains"], json!(["exit", "outbound", "prefix", "outbound"]));
            }
        }
    }).await.unwrap();
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
