use super::{Process, available_address};
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
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
    process
        .wait_for(&format!(
            "Starting Clash API controller at 0.0.0.0:{}",
            address.port()
        ))
        .await;
    process
        .wait_for(&format!(
            "Starting Clash API controller at {}",
            socket.display()
        ))
        .await;
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
    fn outbound_mut(&mut self) -> &mut Value {
        self.config
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|entry| entry["client_group"] == "outbound")
            .unwrap()
    }

    fn tcp_controller_mut(&mut self) -> &mut Value {
        self.config
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|entry| entry.get("clash_api_address").is_some())
            .unwrap()
    }

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
    let snapshot = api(fixture.api, "GET", "/connections", Value::Null).await.1;
    let source_port = new.local_addr().unwrap().port().to_string();
    let before_reload = snapshot["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["metadata"]["sourcePort"] == source_port)
        .unwrap()
        .clone();
    let mut ws = websocket(fixture.api).await;
    frame(&mut ws).await;
    assert_eq!(fixture.outbound_mut()["default"], "east");
    fixture.write();
    process.signal(libc::SIGHUP);
    process.wait_for("Servers ready").await;
    assert_eq!(fixture.selected().await, "west");
    check_flow(&mut new, b'W').await;
    let mut reopened = flow(fixture.entry, b'W').await;
    let snapshot = api(fixture.api, "GET", "/connections", Value::Null).await.1;
    let connections = snapshot["connections"].as_array().unwrap();
    let retained = connections
        .iter()
        .find(|entry| entry["id"] == before_reload["id"])
        .unwrap();
    assert_eq!(
        retained["shoesGeneration"],
        before_reload["shoesGeneration"]
    );
    let reopened_port = reopened.local_addr().unwrap().port().to_string();
    let after_reload = connections
        .iter()
        .find(|entry| entry["metadata"]["sourcePort"] == reopened_port)
        .unwrap();
    assert!(
        after_reload["shoesGeneration"].as_u64().unwrap()
            > before_reload["shoesGeneration"].as_u64().unwrap()
    );
    let retained_id = before_reload["id"].as_str().unwrap();
    assert_eq!(
        api(
            fixture.api,
            "DELETE",
            &format!("/connections/{retained_id}"),
            Value::Null
        )
        .await
        .0,
        204
    );
    assert!(
        timeout(Duration::from_secs(3), new.read_u8())
            .await
            .unwrap()
            .is_err()
    );
    timeout(Duration::from_secs(3), async {
        loop {
            let snapshot = api(fixture.api, "GET", "/connections", Value::Null).await.1;
            if snapshot["connections"]
                .as_array()
                .unwrap()
                .iter()
                .all(|entry| entry["id"] != retained_id)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    check_flow(&mut reopened, b'W').await;
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
    let (status, headers, _) = request_io(
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
    assert_eq!(headers["connection"], "close");
    assert!(headers.get("access-control-allow-origin").is_none());
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
    let url = "http://192.0.2.100/";
    let (status, delay) = api(
        fixture.api,
        "GET",
        "/proxies/east/delay?url=http%3A%2F%2F192.0.2.100%2F&timeout=1000&expected=200",
        Value::Null,
    )
    .await;
    assert_eq!(status, 200, "{delay}");
    assert!(delay["delay"].as_u64().unwrap() > 0);
    let proxy = api(fixture.api, "GET", "/proxies/east", Value::Null)
        .await
        .1;
    assert_eq!(proxy["alive"], true);
    assert_eq!(
        proxy["history"].as_array().unwrap().last().unwrap()["delay"],
        delay["delay"]
    );
    assert_eq!(proxy["extra"][url]["alive"], false);
    assert_eq!(
        proxy["extra"][url]["history"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()["delay"],
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
async fn controller_dispatch_preserves_preflight_and_error_ordering() {
    let fixture = Fixture::new().await;
    let mut process = fixture.start().await;
    let origin = "https://dashboard.example";
    for (method, status) in [("PUT", 204), ("TRACE", 403)] {
        let (actual, headers, _) = request_io(
            TcpStream::connect(fixture.api).await.unwrap(),
            "OPTIONS",
            "/proxies/outbound",
            Value::Null,
            &[
                ("Origin", origin),
                ("Access-Control-Request-Method", method),
            ],
        )
        .await;
        assert_eq!(actual, status);
        assert_eq!(headers["access-control-allow-origin"], origin);
        assert_eq!(headers["connection"], "close");
        if status == 204 {
            assert_eq!(
                headers["access-control-allow-methods"],
                "GET, POST, PUT, PATCH, DELETE"
            );
            assert_eq!(
                headers["access-control-allow-headers"],
                "Authorization, Content-Type"
            );
            assert_eq!(headers["access-control-max-age"], "300");
        }
    }

    let authorization = format!("Bearer {SECRET}");
    for (path, authenticated, status, message) in [
        ("/%FF", false, 401, "Unauthorized"),
        ("/%FF", true, 400, "invalid path encoding"),
        (
            "/version?token=controller-test-secret",
            false,
            401,
            "Unauthorized",
        ),
        (
            "/traffic?interval=invalid",
            true,
            400,
            "invalid stream parameters",
        ),
    ] {
        let mut headers = vec![("Origin", origin)];
        if authenticated {
            headers.push(("Authorization", authorization.as_str()));
        }
        let (actual, headers, body) = request_io(
            TcpStream::connect(fixture.api).await.unwrap(),
            "GET",
            path,
            Value::Null,
            &headers,
        )
        .await;
        assert_eq!(actual, status, "{path}");
        assert_eq!(body["message"], message);
        assert_eq!(headers["access-control-allow-origin"], origin);
        assert_eq!(headers["connection"], "close");
    }

    let (status, headers, body) = request_io(
        TcpStream::connect(fixture.api).await.unwrap(),
        "PUT",
        "/%FF",
        json!({"name": "x".repeat(65 * 1024)}),
        &[("Origin", origin), ("Authorization", &authorization)],
    )
    .await;
    assert_eq!(status, 413);
    assert_eq!(
        body["message"],
        "request body exceeds 64 KiB or is incomplete"
    );
    assert_eq!(headers["access-control-allow-origin"], origin);
    assert_eq!(headers["connection"], "close");
    assert_eq!(
        api(
            fixture.api,
            "GET",
            "/connections?interval=invalid",
            Value::Null
        )
        .await
        .0,
        200
    );
    fixture.stop(&mut process).await;
}

#[tokio::test]
async fn wildcard_cors_preserves_authentication_and_preflight_restrictions() {
    let mut fixture = Fixture::new().await;
    fixture.tcp_controller_mut()["cors_origins"] = json!(["*"]);
    let mut process = fixture.start().await;
    let authorization = format!("Bearer {SECRET}");
    for origin in ["https://other.example", "http://localhost:3000", "null"] {
        for (credential, expected) in [
            (None, 401),
            (Some("Bearer wrong"), 401),
            (Some(authorization.as_str()), 200),
        ] {
            let mut headers = vec![("Origin", origin)];
            if let Some(credential) = credential {
                headers.push(("Authorization", credential));
            }
            let (status, headers, _) = request_io(
                TcpStream::connect(fixture.api).await.unwrap(),
                "GET",
                "/version",
                Value::Null,
                &headers,
            )
            .await;
            assert_eq!(status, expected);
            assert_eq!(headers["access-control-allow-origin"], origin);
            assert_eq!(headers["vary"], "Origin");
        }
    }
    let origin = "https://other.example";
    for (method, requested_headers, private_network, expected) in [
        ("PUT", "Authorization, Content-Type", false, 204),
        ("TRACE", "Authorization", false, 403),
        ("PUT", "X-Custom", false, 403),
        ("PUT", "Authorization", true, 403),
    ] {
        let mut headers = vec![
            ("Origin", origin),
            ("Access-Control-Request-Method", method),
            ("Access-Control-Request-Headers", requested_headers),
        ];
        if private_network {
            headers.push(("Access-Control-Request-Private-Network", "true"));
        }
        let (status, headers, _) = request_io(
            TcpStream::connect(fixture.api).await.unwrap(),
            "OPTIONS",
            "/proxies/outbound",
            Value::Null,
            &headers,
        )
        .await;
        assert_eq!(status, expected);
        assert_eq!(headers["access-control-allow-origin"], origin);
        assert!(
            headers
                .get("access-control-allow-private-network")
                .is_none()
        );
    }
    for (token, expected) in [("", 401), ("wrong", 401), (SECRET, 101)] {
        let (status, headers, _) = request_io(
            TcpStream::connect(fixture.api).await.unwrap(),
            "GET",
            &format!("/connections?token={token}"),
            Value::Null,
            &[
                ("Origin", origin),
                ("Connection", "Upgrade"),
                ("Upgrade", "websocket"),
                ("Sec-WebSocket-Version", "13"),
                ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ],
        )
        .await;
        assert_eq!(status, expected);
        assert_eq!(headers["access-control-allow-origin"], origin);
    }
    fixture.stop(&mut process).await;
}

#[tokio::test]
async fn defaults_follow_config_without_cache_writes_and_controller_changes_reject_reload() {
    let mut fixture = Fixture::new().await;
    let mut process = fixture.start().await;
    assert_eq!(fixture.selected().await, "east");
    flow(fixture.entry, b'E').await;
    fixture.outbound_mut()["default"] = json!("west");
    fixture.write();
    process.signal(libc::SIGHUP);
    process.wait_for("Servers ready").await;
    assert_eq!(fixture.selected().await, "west");
    flow(fixture.entry, b'W').await;
    assert!(!fixture.directory.path().join("cache.db").exists());
    fixture.stop(&mut process).await;
    fixture.outbound_mut()["default"] = json!("east");
    let mut process = fixture.start().await;
    assert_eq!(fixture.selected().await, "east");
    flow(fixture.entry, b'E').await;
    fixture.tcp_controller_mut()["secret"] = json!("changed-secret");
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
    fixture.outbound_mut()["client_proxies"] = json!([
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
async fn websocket_ping_before_first_frame_preserves_snapshot() {
    use hyper_tungstenite::tungstenite::Message;
    let fixture = Fixture::new().await;
    let mut process = fixture.start().await;
    let mut ws = websocket_path(fixture.api, "/connections?interval=60000").await;
    ws.send(Message::Ping(b"before-first-frame".to_vec().into()))
        .await
        .unwrap();
    timeout(Duration::from_secs(2), async {
        let mut pong = false;
        let mut snapshot = false;
        while !pong || !snapshot {
            match ws.next().await.unwrap().unwrap() {
                Message::Pong(bytes) => {
                    assert_eq!(&bytes[..], b"before-first-frame");
                    pong = true;
                }
                Message::Text(bytes) => {
                    let frame: Value = serde_json::from_str(&bytes).unwrap();
                    assert!(frame["connections"].is_array());
                    snapshot = true;
                }
                message => panic!("unexpected frame: {message:?}"),
            }
        }
    })
    .await
    .unwrap();
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
    let mut samples = Vec::new();
    for socket in [&mut rates, &mut other_rates] {
        samples.push(
            timeout(Duration::from_secs(3), async {
                loop {
                    let sample = frame(socket).await;
                    if sample["upTotal"] == 8 {
                        break sample;
                    }
                }
            })
            .await
            .unwrap(),
        );
    }
    let rate = &samples[0];
    assert_eq!(rate, &samples[1]);
    assert_eq!(rate["upTotal"], 8);
    assert!(rate["up"].as_u64().unwrap() > 0);
    assert_eq!(frame(&mut memory).await["inuse"], 0);
    assert!(frame(&mut memory).await["inuse"].as_u64().unwrap() > 0);
    let snapshot = timeout(Duration::from_secs(3), async {
        loop {
            let snapshot = frame(&mut connections).await;
            if snapshot["uploadTotal"] == 8 && snapshot["downloadTotal"] == 8 {
                break snapshot;
            }
        }
    })
    .await
    .unwrap();
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
    struct ProtocolCase {
        name: &'static str,
        server: Value,
        client: Value,
        tls_alpn: Option<&'static str>,
        quic: bool,
        exercise_udp: bool,
    }
    let mut protocols = vec![
        ProtocolCase {
            name: "socks",
            server: json!({"type":"socks"}),
            client: json!({"type":"socks"}),
            tls_alpn: None,
            quic: false,
            exercise_udp: false,
        },
        ProtocolCase {
            name: "http",
            server: json!({"type":"http"}),
            client: json!({"type":"http"}),
            tls_alpn: None,
            quic: false,
            exercise_udp: false,
        },
        ProtocolCase {
            name: "vless",
            server: vless.clone(),
            client: vless.clone(),
            tls_alpn: None,
            quic: false,
            exercise_udp: true,
        },
        ProtocolCase {
            name: "h2mux",
            server: vless.clone(),
            client: mux,
            tls_alpn: None,
            quic: false,
            exercise_udp: true,
        },
        ProtocolCase {
            name: "http2",
            server: json!({"type":"http"}),
            client: json!({"type":"http", "http_version":"h2"}),
            tls_alpn: Some("h2"),
            quic: false,
            exercise_udp: false,
        },
        ProtocolCase {
            name: "anytls",
            server: json!({"type":"anytls", "users":[{"name":"test", "password":"test-secret"}]}),
            client: json!({"type":"anytls", "password":"test-secret"}),
            tls_alpn: Some("h2"),
            quic: false,
            exercise_udp: true,
        },
        ProtocolCase {
            name: "naive",
            server: json!({"type":"naiveproxy", "users":[{"name":"test", "username":"test", "password":"test-secret"}]}),
            client: json!({"type":"naiveproxy", "username":"test", "password":"test-secret"}),
            tls_alpn: Some("h2"),
            quic: false,
            exercise_udp: false,
        },
    ];
    for (name, exercise_udp) in [("shadowsocks", true), ("snell", true), ("trojan", false)] {
        let mut protocol = json!({"type":name, "password":"test-secret"});
        if name != "trojan" {
            protocol["cipher"] = json!("chacha20-ietf-poly1305");
        }
        protocols.push(ProtocolCase {
            name,
            server: protocol.clone(),
            client: protocol,
            tls_alpn: None,
            quic: false,
            exercise_udp,
        });
    }
    for (version, tls_alpn, quic) in [
        ("h1", Some("http/1.1"), false),
        ("h2", Some("h2"), false),
        ("h3", None, true),
    ] {
        let server =
            json!({"type":"xhttp", "path":"/tunnel", "http_version":version, "protocol":vless});
        let mut client = server.clone();
        client["mode"] = json!("stream-one");
        protocols.push(ProtocolCase {
            name: version,
            server,
            client,
            tls_alpn,
            quic,
            exercise_udp: false,
        });
    }
    for ProtocolCase {
        name,
        mut server,
        mut client,
        tls_alpn,
        quic,
        exercise_udp,
    } in protocols
    {
        if let Some(alpn) = tls_alpn {
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
        if quic {
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
        let mut first_id = None;
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
            if first_id.is_none() {
                let snapshot = api(controller, "GET", "/connections", Value::Null).await.1;
                let connections = snapshot["connections"].as_array().unwrap();
                assert_eq!(connections.len(), 1, "{name}: {snapshot}");
                first_id = Some(connections[0]["id"].as_str().unwrap().to_owned());
            }
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
        let id = first_id.unwrap();
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
        assert!(
            timeout(Duration::from_secs(3), streams[0].read_u8())
                .await
                .unwrap_or_else(|_| panic!("{name}: cancelled stream did not close"))
                .is_err(),
            "{name}: cancelled stream delivered unexpected data"
        );
        let remaining = timeout(Duration::from_secs(3), async {
            loop {
                let snapshot = api(controller, "GET", "/connections", Value::Null).await.1;
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
        .unwrap_or_else(|_| panic!("{name}: cancelled flow remained registered"));
        assert_eq!(
            remaining["connections"].as_array().unwrap().len(),
            1,
            "{name}"
        );
        timeout(Duration::from_secs(3), async {
            streams[1].write_all(&payload).await.unwrap();
            let mut bytes = vec![0; payload.len()];
            streams[1].read_exact(&mut bytes).await.unwrap();
            assert_eq!(bytes, payload, "{name}: sibling payload");
        })
        .await
        .unwrap_or_else(|_| panic!("{name}: sibling stopped relaying"));
        assert_eq!(
            api(controller, "DELETE", "/connections", Value::Null)
                .await
                .0,
            204
        );
        if exercise_udp {
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
