use super::{Process, available_address};
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_util::task::AbortOnDropHandle;

const SECRET: &str = "controller-test-secret";

#[tokio::test]
async fn controller_accept_recovers_after_descriptor_exhaustion() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let address = available_address();
    let socket = directory.path().join("api.sock");
    let config = directory.path().join("config.yaml");
    std::fs::write(
        &config,
        serde_yaml::to_string(&json!([
            {"clash_api_address":format!("0.0.0.0:{}",address.port()),"secret":SECRET},
            {"clash_api_path":socket,"secret":SECRET}
        ]))
        .unwrap(),
    )
    .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_shoes"));
    command
        .args(["-t", "1", "--no-reload"])
        .arg(&config)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: 48,
                rlim_max: 48,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut process = Process::from_child(command.spawn().unwrap());
    process.wait_for("Servers ready").await;
    let mut tcp = Vec::new();
    for _ in 0..64 {
        tcp.push(TcpStream::connect(address).await.unwrap());
    }
    process.wait_for("Clash API TCP accept failed").await;
    let unix = tokio::net::UnixStream::connect(&socket).await.unwrap();
    process.wait_for("Clash API Unix accept failed").await;
    drop(tcp);
    drop(unix);
    assert_eq!(api(address, "GET", "/version", Value::Null).await.0, 200);
    let (status, _, _) = request_io(
        tokio::net::UnixStream::connect(&socket).await.unwrap(),
        "GET",
        "/version",
        Value::Null,
        &[("Authorization", &format!("Bearer {SECRET}"))],
    )
    .await;
    assert_eq!(status, 200);
    process.signal(libc::SIGTERM);
    assert!(process.exit().await.success());
}

async fn request_io<T>(
    stream: T,
    method: &str,
    path: &str,
    body: Value,
    headers: &[(&str, &str)],
) -> (u16, hyper::HeaderMap, Value)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    timeout(Duration::from_secs(5), async {
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        let _driver = AbortOnDropHandle::new(tokio::spawn(connection));
        let mut request = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("Host", "localhost");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = sender
            .send_request(
                request
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
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            headers,
            if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            },
        )
    })
    .await
    .unwrap()
}

async fn api(address: SocketAddr, method: &str, path: &str, body: Value) -> (u16, Value) {
    let stream = TcpStream::connect(address).await.unwrap();
    let (status, _, value) = request_io(
        stream,
        method,
        path,
        body,
        &[("Authorization", &format!("Bearer {SECRET}"))],
    )
    .await;
    (status, value)
}

async fn websocket(address: SocketAddr) -> hyper_tungstenite::WebSocketStream<TcpStream> {
    websocket_path(address, "/connections?interval=250").await
}

async fn websocket_path(
    address: SocketAddr,
    path: &str,
) -> hyper_tungstenite::WebSocketStream<TcpStream> {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let separator = if path.contains('?') { '&' } else { '?' };
    stream.write_all(format!("GET {path}{separator}token={SECRET} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").as_bytes()).await.unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.unwrap());
    }
    assert!(
        head.starts_with(b"HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    hyper_tungstenite::WebSocketStream::from_raw_socket(
        stream,
        hyper_tungstenite::tungstenite::protocol::Role::Client,
        None,
    )
    .await
}

async fn frame(ws: &mut hyper_tungstenite::WebSocketStream<TcpStream>) -> Value {
    let message = timeout(Duration::from_secs(3), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    serde_json::from_str(message.to_text().unwrap()).unwrap()
}

async fn egress(marker: u8) -> (SocketAddr, AbortOnDropHandle<()>) {
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let address = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
    let task = tokio::spawn(async move {
        let mut sessions = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut socket, _) = accepted.unwrap();
                    sessions.spawn(async move {
                        let mut greeting = [0; 3];
                        socket.read_exact(&mut greeting).await?;
                        assert_eq!(greeting, [5, 1, 0]);
                        socket.write_all(&[5, 0]).await?;
                        let mut header = [0; 4];
                        socket.read_exact(&mut header).await?;
                        let length = match header[3] { 1 => 4, 4 => 16, 3 => socket.read_u8().await? as usize, _ => panic!("invalid address") };
                        socket.read_exact(&mut vec![0; length + 2]).await?;
                        socket.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                        let mut first = true;
                        let mut buffer = [0; 4096];
                        loop {
                            let count = socket.read(&mut buffer).await?;
                            if count == 0 { break; }
                            if first && buffer[..count].starts_with(b"HEAD ") {
                                socket.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await?;
                                break;
                            }
                            first = false;
                            buffer[0] = marker;
                            socket.write_all(&buffer[..count]).await?;
                        }
                        Ok::<_, std::io::Error>(())
                    });
                }
                _ = sessions.join_next(), if !sessions.is_empty() => {}
            }
        }
    });
    (address, AbortOnDropHandle::new(task))
}

async fn flow(entry: SocketAddr, marker: u8) -> TcpStream {
    let mut stream =
        shoes_test_support::wireguard::connect(entry.port(), "192.0.2.100:80".parse().unwrap())
            .await
            .unwrap();
    check_flow(&mut stream, marker).await;
    stream
}

async fn check_flow(stream: &mut TcpStream, marker: u8) {
    stream.write_all(b"ping").await.unwrap();
    let mut bytes = [0; 4];
    timeout(Duration::from_secs(3), stream.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bytes, [marker, b'i', b'n', b'g']);
}

struct Fixture {
    directory: tempfile::TempDir,
    config: Value,
    api: SocketAddr,
    entry: SocketAddr,
    _egress: Vec<AbortOnDropHandle<()>>,
}

impl Fixture {
    async fn new() -> Self {
        let (east, east_task) = egress(b'E').await;
        let (west, west_task) = egress(b'W').await;
        let directory = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let api = available_address();
        let entry = available_address();
        let config = json!([
            {"clash_api_address":format!("0.0.0.0:{}", api.port()), "secret":SECRET, "cors_origins":["https://dashboard.example"]},
            {"clash_api_path":directory.path().join("api.sock"), "secret":SECRET},
            {"cache_file_path":directory.path().join("cache.db")},
            {"client_group":"outbound", "strategy":"selector", "default":"east", "client_proxies":[
                {"name":"east", "address":east.to_string(), "protocol":{"type":"socks"}},
                {"name":"west", "address":west.to_string(), "protocol":{"type":"socks"}}
            ]},
            {"name":"local-socks", "address":format!("0.0.0.0:{}", entry.port()), "protocol":{"type":"socks"}, "rules":[{"mask":"0.0.0.0/0", "action":"allow", "client_chain":"outbound"}]}
        ]);
        Self {
            directory,
            config,
            api,
            entry,
            _egress: vec![east_task, west_task],
        }
    }
    fn write(&self) {
        std::fs::write(
            self.directory.path().join("config.yaml"),
            serde_yaml::to_string(&self.config).unwrap(),
        )
        .unwrap();
    }
    async fn start(&self) -> Process {
        self.write();
        let mut process =
            Process::start(&self.directory.path().join("config.yaml"), &["--no-reload"]);
        process.wait_for("Servers ready").await;
        process
    }
    async fn stop(&self, process: &mut Process) {
        process.signal(libc::SIGTERM);
        assert!(process.exit().await.success());
    }
    async fn selected(&self) -> Value {
        api(self.api, "GET", "/proxies/outbound", Value::Null)
            .await
            .1["now"]
            .clone()
    }
    async fn select(&self, name: &str) {
        assert_eq!(
            api(self.api, "PUT", "/proxies/outbound", json!({"name":name}))
                .await
                .0,
            204
        );
    }
}

#[tokio::test]
async fn selectors_change_real_traffic_and_restore_after_restart() {
    let mut fixture = Fixture::new().await;
    let mut process = fixture.start().await;
    assert_eq!(fixture.selected().await, "east");
    let mut old = flow(fixture.entry, b'E').await;
    let snapshot = api(fixture.api, "GET", "/connections", Value::Null).await.1;
    assert_eq!(snapshot["connections"].as_array().unwrap().len(), 1);
    assert_eq!(snapshot["uploadTotal"], 4);
    assert_eq!(snapshot["downloadTotal"], 4);
    let id = snapshot["connections"][0]["id"].as_str().unwrap();
    assert_eq!(
        snapshot["connections"][0]["metadata"]["sourceIP"],
        "127.0.0.1"
    );
    assert_eq!(
        snapshot["connections"][0]["metadata"]["sourcePort"],
        old.local_addr().unwrap().port().to_string()
    );
    assert_eq!(
        snapshot["connections"][0]["chains"],
        json!(["east", "outbound"])
    );
    fixture.select("west").await;
    let mut new = flow(fixture.entry, b'W').await;
    check_flow(&mut old, b'E').await;
    let socket = tokio::net::UnixStream::connect(fixture.directory.path().join("api.sock"))
        .await
        .unwrap();
    let (_, _, proxy) = request_io(
        socket,
        "GET",
        "/proxies/outbound",
        Value::Null,
        &[("Authorization", &format!("Bearer {SECRET}"))],
    )
    .await;
    assert_eq!(proxy["now"], "west");
    assert_eq!(
        api(
            fixture.api,
            "DELETE",
            &format!("/connections/{id}"),
            Value::Null
        )
        .await
        .0,
        204
    );
    assert!(!matches!(
        timeout(Duration::from_secs(3), old.read_u8()).await,
        Err(_) | Ok(Ok(_))
    ));
    check_flow(&mut new, b'W').await;
    let mut ws = websocket(fixture.api).await;
    frame(&mut ws).await;
    fixture.config[3]["default"] = json!("west");
    fixture.write();
    process.signal(libc::SIGHUP);
    process.wait_for("Servers ready").await;
    assert_eq!(fixture.selected().await, "west");
    frame(&mut ws).await;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(fixture.directory.path().join("cache.db.lock"))
        .unwrap();
    assert!(lock.try_lock().is_err());
    assert!(
        api(fixture.api, "GET", "/connections", Value::Null).await.1["uploadTotal"]
            .as_u64()
            .unwrap()
            >= 16
    );
    fixture.stop(&mut process).await;
    assert!(!fixture.directory.path().join("api.sock").exists());
    fixture.config[3]["default"] = json!("east");
    let mut process = fixture.start().await;
    assert_eq!(fixture.selected().await, "west");
    flow(fixture.entry, b'W').await;
    fixture.stop(&mut process).await;
}

#[tokio::test]
async fn auth_errors_rules_providers_and_outbound_probes() {
    let mut fixture = Fixture::new().await;
    let mut unused = super::wireguard_support::client(51820);
    unused["client_proxies"][0]["name"] = json!("inactive-wireguard");
    unused["client_proxies"][0]["address"] = json!("unresolvable.invalid:51820");
    fixture.config.as_array_mut().unwrap().push(unused);
    let mut process = fixture.start().await;
    assert_eq!(
        api(
            fixture.api,
            "GET",
            "/proxies/inactive-wireguard/delay?url=http%3A%2F%2F192.0.2.1%2F&timeout=1000",
            Value::Null
        )
        .await
        .0,
        503
    );
    for path in [
        "/",
        "/proxies",
        "/connections?token=controller-test-secret",
        "/restart",
    ] {
        let (status, headers, body) = request_io(
            TcpStream::connect(fixture.api).await.unwrap(),
            "GET",
            path,
            Value::Null,
            &[("Origin", "https://dashboard.example")],
        )
        .await;
        assert_eq!(status, 401);
        assert_eq!(
            headers["access-control-allow-origin"],
            "https://dashboard.example"
        );
        assert_eq!(body["message"], "Unauthorized");
    }
    let (status, _, _) = request_io(
        TcpStream::connect(fixture.api).await.unwrap(),
        "GET",
        "/version",
        Value::Null,
        &[
            ("Authorization", &format!("Bearer {SECRET}")),
            ("Origin", "null"),
        ],
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(
        api(fixture.api, "POST", "/restart", Value::Null).await.0,
        501
    );
    assert_eq!(
        api(fixture.api, "GET", "/missing", Value::Null).await.0,
        404
    );
    assert_eq!(
        api(fixture.api, "PUT", "/proxies/east", json!({"name":"west"}))
            .await
            .0,
        400
    );
    assert_eq!(
        api(
            fixture.api,
            "PUT",
            "/proxies/outbound",
            json!({"name":"missing"})
        )
        .await
        .0,
        400
    );
    for path in ["/providers/proxies", "/providers/rules"] {
        assert_eq!(
            api(fixture.api, "GET", path, Value::Null).await.1,
            json!({"providers":{}})
        );
    }
    let rules = api(fixture.api, "GET", "/rules", Value::Null).await.1;
    assert!(!rules["rules"].as_array().unwrap().is_empty());
    for rule in rules["rules"].as_array().unwrap() {
        assert!(!rule["proxy"].as_str().unwrap().is_empty());
        assert!(rule.get("uuid").is_none() && rule.get("extra").is_none());
    }
    let (status, delay) = api(
        fixture.api,
        "GET",
        "/proxies/outbound/delay?url=http%3A%2F%2F192.0.2.100%2F&timeout=1000",
        Value::Null,
    )
    .await;
    assert_eq!(status, 200, "{delay}");
    assert!(delay["delay"].as_u64().unwrap() > 0);
    assert_eq!(
        api(fixture.api, "GET", "/proxies/outbound", Value::Null)
            .await
            .1["history"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let (status, delays) = api(
        fixture.api,
        "GET",
        "/group/outbound/delay?url=http%3A%2F%2Fproxy-only.invalid%2F&timeout=1000",
        Value::Null,
    )
    .await;
    assert_eq!(status, 200, "{delays}");
    assert_eq!(delays.as_object().unwrap().len(), 2);
    assert_eq!(
        api(fixture.api, "GET", "/connections", Value::Null).await.1["uploadTotal"],
        0
    );
    assert_eq!(
        api(
            fixture.api,
            "GET",
            "/proxies/east/delay?url=http%3A%2F%2F127.0.0.1%2F&timeout=1000",
            Value::Null
        )
        .await
        .0,
        503
    );
    fixture.stop(&mut process).await;
}

#[tokio::test]
async fn defaults_follow_config_without_cache_writes_and_controller_changes_reject_reload() {
    let mut fixture = Fixture::new().await;
    let mut process = fixture.start().await;
    assert_eq!(fixture.selected().await, "east");
    flow(fixture.entry, b'E').await;
    fixture.config[3]["default"] = json!("west");
    fixture.write();
    process.signal(libc::SIGHUP);
    process.wait_for("Servers ready").await;
    assert_eq!(fixture.selected().await, "west");
    flow(fixture.entry, b'W').await;
    assert!(!fixture.directory.path().join("cache.db").exists());
    fixture.stop(&mut process).await;
    fixture.config[3]["default"] = json!("east");
    let mut process = fixture.start().await;
    assert_eq!(fixture.selected().await, "east");
    flow(fixture.entry, b'E').await;
    fixture.config[0]["secret"] = json!("changed-secret");
    fixture.write();
    process.signal(libc::SIGHUP);
    process.wait_for("require a restart").await;
    assert_eq!(fixture.selected().await, "east");
    flow(fixture.entry, b'E').await;
    fixture.stop(&mut process).await;
}

#[tokio::test]
async fn udp_payload_totals_and_destination_cancellation_are_isolated() {
    use shoes_test_support::{
        socks5::Socks5UdpAssociation, test_servers::start_udp_echo_server_with_suffix,
    };
    let mut fixture = Fixture::new().await;
    fixture.config[3]["client_proxies"] = json!([
        {"name":"east", "protocol":{"type":"direct"}},
        {"name":"west", "protocol":{"type":"direct"}}
    ]);
    let mut process = fixture.start().await;
    let a = start_udp_echo_server_with_suffix("0.0.0.0", 0, b"")
        .await
        .unwrap();
    let b = start_udp_echo_server_with_suffix("0.0.0.0", 0, b"")
        .await
        .unwrap();
    let a = SocketAddr::from(([127, 0, 0, 1], a.local_addr().port()));
    let b = SocketAddr::from(([127, 0, 0, 1], b.local_addr().port()));
    let udp = Socks5UdpAssociation::connect("127.0.0.1", fixture.entry.port())
        .await
        .unwrap();
    assert_eq!(udp.send_to(a, b"first").await.unwrap(), b"first");
    assert_eq!(udp.send_to(b, b"second").await.unwrap(), b"second");
    let snapshot = api(fixture.api, "GET", "/connections", Value::Null).await.1;
    let connections = snapshot["connections"].as_array().unwrap();
    assert_eq!(connections.len(), 2);
    assert!(
        connections
            .iter()
            .all(|flow| flow["metadata"]["sourceIP"] == "127.0.0.1")
    );
    assert_eq!(snapshot["uploadTotal"], 11);
    assert_eq!(snapshot["downloadTotal"], 11);
    let id = connections
        .iter()
        .find(|flow| flow["metadata"]["destinationPort"].as_str() == Some(&a.port().to_string()))
        .unwrap()["id"]
        .as_str()
        .unwrap();
    assert_eq!(
        api(
            fixture.api,
            "DELETE",
            &format!("/connections/{id}"),
            Value::Null
        )
        .await
        .0,
        204
    );
    timeout(Duration::from_secs(2), async {
        loop {
            let snapshot = api(fixture.api, "GET", "/connections", Value::Null).await.1;
            if snapshot["connections"].as_array().unwrap().len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(udp.send_to(b, b"survives").await.unwrap(), b"survives");
    assert_eq!(udp.send_to(a, b"reopened").await.unwrap(), b"reopened");
    let snapshot = api(fixture.api, "GET", "/connections", Value::Null).await.1;
    assert_eq!(snapshot["uploadTotal"], 27);
    assert_eq!(snapshot["downloadTotal"], 27);
    assert!(
        snapshot["connections"]
            .as_array()
            .unwrap()
            .iter()
            .all(|flow| flow["id"] != id)
    );
    fixture.stop(&mut process).await;
}

#[tokio::test]
async fn stalled_requests_release_shared_connection_budget() {
    let fixture = Fixture::new().await;
    let mut process = fixture.start().await;
    let mut subscriptions = Vec::new();
    for _ in 0..16 {
        subscriptions.push(websocket(fixture.api).await);
    }
    let mut stalled = Vec::new();
    for _ in 0..48 {
        let mut socket = TcpStream::connect(fixture.api).await.unwrap();
        socket
            .write_all(b"GET /version HTTP/1.1\r\nHost: local")
            .await
            .unwrap();
        stalled.push(socket);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut excess = TcpStream::connect(fixture.api).await.unwrap();
    assert!(matches!(
        timeout(Duration::from_secs(2), excess.read_u8()).await,
        Ok(Err(_))
    ));
    assert!(matches!(
        timeout(Duration::from_secs(17), stalled[0].read_u8()).await,
        Ok(Err(_))
    ));
    drop(stalled);
    assert_eq!(
        api(fixture.api, "GET", "/version", Value::Null).await.0,
        200
    );
    frame(&mut subscriptions[0]).await;
    drop(subscriptions);
    let mut body = TcpStream::connect(fixture.api).await.unwrap();
    body.write_all(format!("PUT /proxies/outbound HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {SECRET}\r\nContent-Length: 100\r\n\r\n{{").as_bytes()).await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(12), body.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 408"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    assert_eq!(
        api(fixture.api, "GET", "/version", Value::Null).await.0,
        200
    );
    fixture.stop(&mut process).await;
}

#[tokio::test]
async fn shared_rates_live_connection_snapshots_and_ndjson_streams() {
    let fixture = Fixture::new().await;
    let mut process = fixture.start().await;
    let mut live = flow(fixture.entry, b'E').await;
    let mut connections = websocket(fixture.api).await;
    assert_eq!(frame(&mut connections).await["connections"][0]["upload"], 4);
    let mut rates = websocket_path(fixture.api, "/traffic").await;
    let mut other_rates = websocket_path(fixture.api, "/traffic").await;
    let mut memory = websocket_path(fixture.api, "/memory").await;
    check_flow(&mut live, b'E').await;
    let rate = frame(&mut rates).await;
    assert_eq!(rate, frame(&mut other_rates).await);
    assert_eq!(rate["upTotal"], 8);
    assert!(rate["up"].as_u64().unwrap() > 0);
    assert_eq!(frame(&mut memory).await["inuse"], 0);
    assert!(frame(&mut memory).await["inuse"].as_u64().unwrap() > 0);
    let snapshot = frame(&mut connections).await;
    assert_eq!(snapshot["connections"][0]["upload"], 8);
    assert_eq!(snapshot["connections"][0]["download"], 8);
    let stream = TcpStream::connect(fixture.api).await.unwrap();
    let (mut sender, driver) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let _driver = AbortOnDropHandle::new(tokio::spawn(driver));
    let response = sender
        .send_request(
            hyper::Request::builder()
                .uri("/traffic")
                .header("Host", "localhost")
                .header("Authorization", format!("Bearer {SECRET}"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    for _ in 0..2 {
        let frame = timeout(Duration::from_secs(3), body.frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let bytes = frame.into_data().unwrap();
        assert_eq!(bytes.last(), Some(&b'\n'));
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["upTotal"], 8);
    }
    fixture.stop(&mut process).await;
}

#[tokio::test]
async fn failed_save_keeps_routing_and_streams_real_logs_in_both_formats() {
    let fixture = Fixture::new().await;
    let mut process = fixture.start().await;
    let mut logs = websocket_path(fixture.api, "/logs?level=warning").await;
    let mut structured = websocket_path(fixture.api, "/logs?level=error&format=structured").await;
    std::fs::create_dir(fixture.directory.path().join("cache.db")).unwrap();
    let (status, _) = api(
        fixture.api,
        "PUT",
        "/proxies/outbound",
        json!({"name":"west"}),
    )
    .await;
    assert_eq!(status, 500);
    let event = frame(&mut logs).await;
    assert_eq!(event["type"], "error");
    assert!(
        event["payload"]
            .as_str()
            .unwrap()
            .contains("persist selector choice")
    );
    let event = frame(&mut structured).await;
    assert_eq!(event["level"], "error");
    assert!(event["time"].is_string());
    assert_eq!(event["fields"], json!([]));
    assert_eq!(fixture.selected().await, "east");
    flow(fixture.entry, b'E').await;
    std::fs::remove_dir(fixture.directory.path().join("cache.db")).unwrap();
    fixture.select("west").await;
    flow(fixture.entry, b'W').await;
    fixture.stop(&mut process).await;
}

#[tokio::test]
async fn layered_and_multiplexed_tcp_counts_payload_and_cancels_only_one_stream() {
    let echo = shoes_test_support::test_servers::start_tcp_stream_echo_server("0.0.0.0", 0)
        .await
        .unwrap();
    let destination = SocketAddr::from(([127, 0, 0, 1], echo.local_addr().port()));
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let vless = json!({"type":"vless", "user_id":shoes_test_support::test_fixture::TEST_UUID});
    let mut mux = vless.clone();
    mux["h2mux"] = json!({});
    let mut protocols = vec![
        (
            "socks",
            json!({"type":"socks"}),
            json!({"type":"socks"}),
            false,
        ),
        (
            "http",
            json!({"type":"http"}),
            json!({"type":"http"}),
            false,
        ),
        ("vless", vless.clone(), vless.clone(), false),
        ("h2mux", vless.clone(), mux, false),
        (
            "http2",
            json!({"type":"http"}),
            json!({"type":"http", "http_version":"h2"}),
            true,
        ),
        (
            "anytls",
            json!({"type":"anytls", "users":[{"name":"test", "password":"test-secret"}]}),
            json!({"type":"anytls", "password":"test-secret"}),
            true,
        ),
    ];
    for name in ["shadowsocks", "snell", "trojan"] {
        let mut protocol = json!({"type":name, "password":"test-secret"});
        if name != "trojan" {
            protocol["cipher"] = json!("chacha20-ietf-poly1305");
        }
        protocols.push((name, protocol.clone(), protocol, false));
    }
    for version in ["h1", "h2", "h3"] {
        let server =
            json!({"type":"xhttp", "path":"/tunnel", "http_version":version, "protocol":vless});
        let mut client = server.clone();
        client["mode"] = json!("stream-one");
        protocols.push((version, server, client, version != "h3"));
    }
    for (name, mut server, mut client, tls) in protocols {
        if tls {
            let alpn = if name == "h1" { "http/1.1" } else { "h2" };
            server = json!({"type":"tls", "default_tls_target":{"cert":certificate.cert.pem(), "key":certificate.signing_key.serialize_pem(), "alpn_protocols":[alpn], "protocol":server}});
            client = json!({"type":"tls", "sni_hostname":"localhost", "verify":false, "alpn_protocols":[alpn], "protocol":client});
        }
        let directory = tempfile::tempdir().unwrap();
        let controller = available_address();
        let remote = available_address();
        let entry = available_address();
        let server_path = directory.path().join("server.yaml");
        let client_path = directory.path().join("client.yaml");
        let mut server_config = json!([
            {"clash_api_address":format!("0.0.0.0:{}", controller.port()), "secret":SECRET},
            {"name":name, "address":format!("0.0.0.0:{}", remote.port()), "protocol":server, "rules":"allow-all-direct"}
        ]);
        let mut client_config = json!([
            {"address":format!("0.0.0.0:{}", entry.port()), "protocol":{"type":"socks"}, "rules":[{"mask":"0.0.0.0/0", "action":"allow", "client_chain":[{"address":remote.to_string(), "protocol":client}]}]}
        ]);
        if name == "h3" {
            server_config[1]["transport"] = json!("quic");
            server_config[1]["quic_settings"] = json!({"cert":certificate.cert.pem(), "key":certificate.signing_key.serialize_pem(), "alpn_protocols":["h3"], "num_endpoints":1});
            let outbound = &mut client_config[0]["rules"][0]["client_chain"][0];
            outbound["transport"] = json!("quic");
            outbound["quic_settings"] = json!({"verify":false, "sni_hostname":"localhost", "alpn_protocols":["h3"], "num_endpoints":1});
        }
        std::fs::write(&server_path, serde_yaml::to_string(&server_config).unwrap()).unwrap();
        std::fs::write(&client_path, serde_yaml::to_string(&client_config).unwrap()).unwrap();
        let mut server = Process::start(&server_path, &["--no-reload"]);
        server.wait_for("Servers ready").await;
        let mut client = Process::start(&client_path, &["--no-reload"]);
        client.wait_for("Servers ready").await;
        let payload = vec![b'x'; 4096];
        let mut streams = Vec::new();
        for _ in 0..2 {
            let mut stream = timeout(
                Duration::from_secs(5),
                shoes_test_support::wireguard::connect(entry.port(), destination),
            )
            .await
            .unwrap()
            .unwrap();
            stream.write_all(&payload).await.unwrap();
            let mut bytes = vec![0; payload.len()];
            timeout(Duration::from_secs(5), stream.read_exact(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(bytes, payload, "{name}");
            streams.push(stream);
        }
        let snapshot = api(controller, "GET", "/connections", Value::Null).await.1;
        let connections = snapshot["connections"].as_array().unwrap();
        assert_eq!(connections.len(), 2, "{name}: {snapshot}");
        assert_eq!(snapshot["uploadTotal"], 8192, "{name}: {snapshot}");
        assert_eq!(snapshot["downloadTotal"], 8192, "{name}: {snapshot}");
        assert!(
            connections
                .iter()
                .all(|flow| flow["metadata"]["sourceIP"] == "127.0.0.1"),
            "{name}: {snapshot}"
        );
        let id = connections[0]["id"].as_str().unwrap();
        assert_eq!(
            api(
                controller,
                "DELETE",
                &format!("/connections/{id}"),
                Value::Null
            )
            .await
            .0,
            204
        );
        let mut alive = 0;
        for stream in &mut streams {
            if stream.write_all(&payload).await.is_ok() {
                let mut bytes = vec![0; payload.len()];
                if matches!(
                    timeout(Duration::from_secs(2), stream.read_exact(&mut bytes)).await,
                    Ok(Ok(_))
                ) {
                    assert_eq!(bytes, payload, "{name}");
                    alive += 1;
                }
            }
        }
        assert_eq!(alive, 1, "{name}");
        assert_eq!(
            api(controller, "DELETE", "/connections", Value::Null)
                .await
                .0,
            204
        );
        if matches!(name, "vless" | "h2mux" | "anytls" | "shadowsocks" | "snell") {
            timeout(Duration::from_secs(3), async {
                while !api(controller, "GET", "/connections", Value::Null).await.1["connections"]
                    .as_array()
                    .unwrap()
                    .is_empty()
                {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap();
            let baseline = api(controller, "GET", "/connections", Value::Null).await.1;
            let udp_peer = shoes_test_support::test_servers::start_udp_echo_server_with_suffix(
                "0.0.0.0", 0, b"",
            )
            .await
            .unwrap();
            let destination = SocketAddr::from(([127, 0, 0, 1], udp_peer.local_addr().port()));
            let udp = shoes_test_support::socks5::Socks5UdpAssociation::connect(
                "127.0.0.1",
                entry.port(),
            )
            .await
            .unwrap();
            assert_eq!(
                timeout(
                    Duration::from_secs(5),
                    udp.send_to(destination, b"datagram")
                )
                .await
                .unwrap_or_else(|_| panic!("{name} UDP receive timed out"))
                .unwrap(),
                b"datagram",
                "{name}"
            );
            let snapshot = api(controller, "GET", "/connections", Value::Null).await.1;
            assert_eq!(
                snapshot["uploadTotal"].as_u64().unwrap()
                    - baseline["uploadTotal"].as_u64().unwrap(),
                8,
                "{name}: {snapshot}"
            );
            assert_eq!(
                snapshot["downloadTotal"].as_u64().unwrap()
                    - baseline["downloadTotal"].as_u64().unwrap(),
                8,
                "{name}: {snapshot}"
            );
            assert_eq!(
                snapshot["connections"].as_array().unwrap().len(),
                1,
                "{name}: {snapshot}"
            );
            assert_eq!(
                snapshot["connections"][0]["metadata"]["network"], "udp",
                "{name}"
            );
            assert_eq!(
                snapshot["connections"][0]["metadata"]["sourceIP"], "127.0.0.1",
                "{name}"
            );
        }
        client.signal(libc::SIGTERM);
        server.signal(libc::SIGTERM);
        assert!(client.exit().await.success());
        assert!(server.exit().await.success());
    }
}
