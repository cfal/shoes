use std::io::BufRead;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use serde_json::{Value, json};
use shoes_test_support::process::ProcessGuard;
use tokio_util::task::AbortOnDropHandle;

const SECRET: &str = "controller-differential-test";

fn address() -> SocketAddr {
    std::net::TcpListener::bind("0.0.0.0:0")
        .unwrap()
        .local_addr()
        .map(|address| SocketAddr::from(([127, 0, 0, 1], address.port())))
        .unwrap()
}

async fn request(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Value,
    authenticated: bool,
) -> (u16, Value) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                .await
                .unwrap();
        let _driver = AbortOnDropHandle::new(tokio::spawn(connection));
        let mut builder = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("Host", "localhost");
        if authenticated {
            builder = builder.header("Authorization", format!("Bearer {SECRET}"));
        }
        let response = sender
            .send_request(
                builder
                    .body(Full::new(Bytes::from(if body.is_null() {
                        Vec::new()
                    } else {
                        serde_json::to_vec(&body).unwrap()
                    })))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status().as_u16();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes)
                    .unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes)))
            },
        )
    })
    .await
    .unwrap()
}

async fn ready(address: SocketAddr, process: &mut ProcessGuard) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            assert!(
                process.try_wait().unwrap().is_none(),
                "backend exited during startup"
            );
            if tokio::net::TcpStream::connect(address).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

async fn start_shoes(path: &Path) -> ProcessGuard {
    let mut child = Command::new(env!("CARGO_BIN_EXE_shoes"))
        .args(["-t", "1", "--no-reload"])
        .arg(path)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let process = ProcessGuard::new(child, "Clash API Shoes");
    let (ready, started) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let mut ready = Some(ready);
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
        {
            if line.contains("Servers ready")
                && let Some(ready) = ready.take()
            {
                let _ = ready.send(());
            }
        }
    });
    tokio::time::timeout(Duration::from_secs(10), started)
        .await
        .expect("Shoes forwarding activation timed out")
        .expect("Shoes exited before forwarding activation");
    process
}

async fn proxy_ready(address: SocketAddr, name: &str) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while request(
            address,
            "GET",
            &format!("/proxies/{name}"),
            Value::Null,
            true,
        )
        .await
        .0 != 200
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

async fn forwarding_ready(socks: SocketAddr, target: SocketAddr, process: &mut ProcessGuard) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Mihomo publishes its catalog/listeners before the tunnel leaves its loading state.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            assert!(
                process.try_wait().unwrap().is_none(),
                "Mihomo exited during activation"
            );
            let attempt = tokio::time::timeout(Duration::from_secs(1), async {
                let mut stream =
                    shoes_test_support::wireguard::connect(socks.port(), target).await?;
                stream.write_all(b"ready").await?;
                let mut reply = [0; 5];
                stream.read_exact(&mut reply).await?;
                Ok::<_, std::io::Error>(reply == *b"ready")
            })
            .await;
            if matches!(attempt, Ok(Ok(true))) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("Mihomo forwarding activation timed out");
}

#[tokio::test]
async fn clash_api_pinned_mihomo_contract() {
    let binary = std::env::var_os("SHOES_TEST_MIHOMO_BIN").expect(
        "set SHOES_TEST_MIHOMO_BIN to Mihomo built at 94b13aed49b8dc41973e4bb3f721c5fa2c5c5c1f",
    );
    let directory = tempfile::tempdir().unwrap();
    let shoes = address();
    let mihomo = address();
    let shoes_config = directory.path().join("shoes.yaml");
    let mihomo_config = directory.path().join("mihomo.yaml");
    std::fs::write(
        &shoes_config,
        serde_yaml::to_string(&json!([
            {"clash_api_address":format!("0.0.0.0:{}", shoes.port()), "secret":SECRET},
            {"client_group":"outbound", "strategy":"selector", "client_proxies":["direct"]}
        ]))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(
        &mihomo_config,
        serde_yaml::to_string(&json!({
            "external-controller":format!("0.0.0.0:{}", mihomo.port()), "secret":SECRET,
            "mode":"rule", "log-level":"silent", "ipv6":true,
            "proxy-groups":[{"name":"outbound", "type":"select", "proxies":["DIRECT"]}],
            "rules":["MATCH,outbound"], "profile":{"store-selected":false}
        }))
        .unwrap(),
    )
    .unwrap();
    let mut shoes_process = start_shoes(&shoes_config).await;
    let mut mihomo_process = ProcessGuard::new(
        Command::new(binary)
            .arg("-d")
            .arg(directory.path())
            .arg("-f")
            .arg(&mihomo_config)
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
        "pinned Mihomo",
    );
    ready(shoes, &mut shoes_process).await;
    ready(mihomo, &mut mihomo_process).await;
    proxy_ready(mihomo, "outbound").await;
    for (method, path, body, auth, status) in [
        ("GET", "/proxies", Value::Null, false, 401),
        ("GET", "/proxies/missing", Value::Null, true, 404),
        (
            "PUT",
            "/proxies/DIRECT",
            json!({"name":"DIRECT"}),
            true,
            400,
        ),
        (
            "PUT",
            "/proxies/outbound",
            json!({"name":"missing"}),
            true,
            400,
        ),
        (
            "PUT",
            "/proxies/outbound",
            json!({"name":"DIRECT"}),
            true,
            204,
        ),
        ("DELETE", "/connections/missing", Value::Null, true, 204),
        ("DELETE", "/connections", Value::Null, true, 204),
    ] {
        let ours = request(shoes, method, path, body.clone(), auth).await;
        let reference = request(mihomo, method, path, body, auth).await;
        assert_eq!(ours.0, status, "Shoes {path}: {ours:?}");
        assert_eq!(reference.0, status, "Mihomo {path}: {reference:?}");
        if status >= 400 {
            assert!(ours.1["message"].is_string(), "{ours:?}");
            assert!(reference.1["message"].is_string(), "{reference:?}");
        } else {
            assert_eq!(ours.1, reference.1);
        }
    }
    for backend in [shoes, mihomo] {
        let (status, proxies) = request(backend, "GET", "/proxies", Value::Null, true).await;
        assert_eq!(status, 200);
        assert!(proxies["proxies"].is_object());
        assert_eq!(proxies["proxies"]["outbound"]["now"], "DIRECT");
        let (_, groups) = request(backend, "GET", "/group", Value::Null, true).await;
        assert!(groups["proxies"].is_array());
        for path in ["/providers/proxies", "/providers/rules"] {
            let (status, providers) = request(backend, "GET", path, Value::Null, true).await;
            assert_eq!(status, 200);
            assert!(providers["providers"].is_object());
            // Mihomo synthesizes Compatible providers; Shoes has no managed providers.
            if backend == shoes || path == "/providers/rules" {
                assert_eq!(providers, json!({"providers":{}}));
            }
        }
        let (_, connections) = request(backend, "GET", "/connections", Value::Null, true).await;
        // The pinned Go backend encodes an empty slice as null; Shoes always emits an array.
        assert!(
            connections["connections"].is_array()
                || (backend == mihomo && connections["connections"].is_null())
        );
        assert_eq!(connections["uploadTotal"], 0);
        assert_eq!(connections["downloadTotal"], 0);
    }
}

#[tokio::test]
async fn clash_api_quic_tcp_udp_accounting_and_stream_cancellation() {
    use shoes_test_support::socks5::Socks5UdpAssociation;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let binary = std::env::var_os("SHOES_TEST_MIHOMO_BIN")
        .expect("set SHOES_TEST_MIHOMO_BIN to pinned Mihomo");
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let tcp = shoes_test_support::test_servers::start_tcp_stream_echo_server("0.0.0.0", 0)
        .await
        .unwrap();
    let readiness = shoes_test_support::test_servers::start_tcp_stream_echo_server("0.0.0.0", 0)
        .await
        .unwrap();
    let readiness_target = SocketAddr::from(([127, 0, 0, 1], readiness.local_addr().port()));
    let udp =
        shoes_test_support::test_servers::start_udp_echo_server_with_suffix("0.0.0.0", 0, b"")
            .await
            .unwrap();
    let tcp_target = SocketAddr::from(([127, 0, 0, 1], tcp.local_addr().port()));
    let udp_target = SocketAddr::from(([127, 0, 0, 1], udp.local_addr().port()));
    for protocol in ["tuic", "hysteria2"] {
        let directory = tempfile::tempdir().unwrap();
        let controller = address();
        let remote = address();
        let socks = address();
        let mihomo_api = address();
        let shoes_path = directory.path().join("shoes.yaml");
        let mihomo_path = directory.path().join("mihomo.yaml");
        let mut server = json!({"type":protocol, "password":"quic-test-password"});
        let mut proxy = json!({"name":"quic-out", "type":protocol, "server":"127.0.0.1", "port":remote.port(), "password":"quic-test-password", "sni":"localhost", "skip-cert-verify":true, "alpn":["h3"], "udp":true});
        if protocol == "tuic" {
            server["uuid"] = json!(shoes_test_support::test_fixture::TEST_UUID);
            proxy["uuid"] = json!(shoes_test_support::test_fixture::TEST_UUID);
            proxy["congestion-controller"] = json!("bbr");
        }
        std::fs::write(&shoes_path, serde_yaml::to_string(&json!([
            {"clash_api_address":format!("0.0.0.0:{}", controller.port()), "secret":SECRET},
            {"name":protocol, "address":format!("0.0.0.0:{}", remote.port()), "transport":"quic", "quic_settings":{"cert":certificate.cert.pem(), "key":certificate.signing_key.serialize_pem(), "alpn_protocols":["h3"], "num_endpoints":1}, "protocol":server, "rules":"allow-all-direct"}
        ])).unwrap()).unwrap();
        std::fs::write(&mihomo_path, serde_yaml::to_string(&json!({"external-controller":format!("0.0.0.0:{}",mihomo_api.port()), "secret":SECRET, "socks-port":socks.port(), "allow-lan":true, "bind-address":"*", "log-level":"error", "proxies":[proxy], "rules":[format!("AND,((NETWORK,TCP),(DST-PORT,{})),DIRECT",readiness_target.port()),"MATCH,quic-out"]})).unwrap()).unwrap();
        let mut shoes = start_shoes(&shoes_path).await;
        let mut client = ProcessGuard::new(
            Command::new(&binary)
                .arg("-d")
                .arg(directory.path())
                .arg("-f")
                .arg(&mihomo_path)
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
            "Mihomo QUIC client",
        );
        ready(controller, &mut shoes).await;
        ready(socks, &mut client).await;
        ready(mihomo_api, &mut client).await;
        proxy_ready(mihomo_api, "quic-out").await;
        forwarding_ready(socks, readiness_target, &mut client).await;
        let mut streams = Vec::new();
        let mut first_id = None;
        for _ in 0..2 {
            let mut stream = tokio::time::timeout(
                Duration::from_secs(10),
                shoes_test_support::wireguard::connect(socks.port(), tcp_target),
            )
            .await
            .unwrap()
            .unwrap();
            stream.write_all(b"payload").await.unwrap();
            let mut reply = [0; 7];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&reply, b"payload", "{protocol}");
            streams.push(stream);
            if first_id.is_none() {
                let (_, snapshot) =
                    request(controller, "GET", "/connections", Value::Null, true).await;
                let flows = snapshot["connections"].as_array().unwrap();
                assert_eq!(flows.len(), 1, "{protocol}: {snapshot}");
                first_id = Some(flows[0]["id"].as_str().unwrap().to_owned());
            }
        }
        let association = Socks5UdpAssociation::connect("127.0.0.1", socks.port())
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(10),
                association.send_to(udp_target, b"datagram")
            )
            .await
            .unwrap()
            .unwrap(),
            b"datagram",
            "{protocol}"
        );
        let (_, snapshot) = request(controller, "GET", "/connections", Value::Null, true).await;
        assert_eq!(snapshot["uploadTotal"], 22, "{protocol}: {snapshot}");
        assert_eq!(snapshot["downloadTotal"], 22, "{protocol}: {snapshot}");
        let flows = snapshot["connections"].as_array().unwrap();
        assert_eq!(flows.len(), 3, "{protocol}: {snapshot}");
        assert!(
            flows
                .iter()
                .all(|flow| flow["metadata"]["sourceIP"] == "127.0.0.1"),
            "{protocol}: {snapshot}"
        );
        let id = first_id.unwrap();
        assert_eq!(
            request(
                controller,
                "DELETE",
                &format!("/connections/{id}"),
                Value::Null,
                true
            )
            .await
            .0,
            204
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(3), streams[0].read_u8())
                .await
                .unwrap_or_else(|_| panic!("{protocol}: cancelled stream did not close"))
                .is_err(),
            "{protocol}: cancelled stream delivered unexpected data"
        );
        let remaining = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let (_, snapshot) =
                    request(controller, "GET", "/connections", Value::Null, true).await;
                if snapshot["connections"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|flow| flow["id"] != id)
                {
                    break snapshot;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{protocol}: cancelled flow remained registered"));
        assert_eq!(
            remaining["connections"].as_array().unwrap().len(),
            2,
            "{protocol}"
        );
        tokio::time::timeout(Duration::from_secs(3), async {
            streams[1].write_all(b"payload").await.unwrap();
            let mut reply = [0; 7];
            streams[1].read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"payload", "{protocol}: sibling payload");
        })
        .await
        .unwrap_or_else(|_| panic!("{protocol}: sibling stopped relaying"));
        assert_eq!(
            association.send_to(udp_target, b"survivor").await.unwrap(),
            b"survivor"
        );
    }
}
