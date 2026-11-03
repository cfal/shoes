use super::*;
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::UdpSocket;

struct TimeServer {
    address: SocketAddr,
    requests: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl TimeServer {
    async fn start(offset: Option<i64>) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let count = requests.clone();
        let task = tokio::spawn(async move {
            let mut request = [0; 48];
            loop {
                let (length, peer) = socket.recv_from(&mut request).await.unwrap();
                assert_eq!(length, 48);
                count.fetch_add(1, Ordering::Relaxed);
                let Some(offset) = offset else { continue };
                let mut response = [0; 48];
                response[0] = 0x24;
                response[1] = 1;
                response[3] = (-20i8) as u8;
                response[24..32].copy_from_slice(&request[40..48]);
                let timestamp = u64::from_be_bytes(request[40..48].try_into().unwrap())
                    .wrapping_add_signed(offset * (1i64 << 32))
                    .to_be_bytes();
                response[32..40].copy_from_slice(&timestamp);
                response[40..48].copy_from_slice(&timestamp);
                socket.send_to(&response, peer).await.unwrap();
            }
        });
        Self {
            address,
            requests,
            task,
        }
    }

    fn settings(&self) -> Value {
        json!({"server": self.address.to_string(), "interval_secs": 86400, "timeout_secs": 1})
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::Relaxed)
    }
}

impl Drop for TimeServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn protocol() -> Value {
    json!({"type": "shadowsocks", "cipher": "2022-blake3-aes-128-gcm",
        "password": "MzMzMzMzMzMzMzMzMzMzMw=="})
}

fn write(path: &Path, config: &Value) {
    std::fs::write(path, serde_yaml::to_string(config).unwrap()).unwrap();
}

async fn accepts(address: SocketAddr) -> bool {
    let result = timeout(Duration::from_secs(2), async {
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(b"clock").await?;
        let mut response = [0; 5];
        stream.read_exact(&mut response).await?;
        Ok::<_, io::Error>(response == *b"clock")
    })
    .await;
    matches!(result, Ok(Ok(true)))
}

#[tokio::test]
async fn ntp_protocol_time_survives_reload_and_rollback_and_can_be_disabled() {
    let directory = tempfile::tempdir().unwrap();
    let server_path = directory.path().join("server.yaml");
    let client_path = directory.path().join("client.yaml");
    let raw_path = directory.path().join("raw.yaml");
    let ntp = TimeServer::start(Some(600)).await;
    let changed = TimeServer::start(Some(1200)).await;
    let echo = shoes_test_support::test_servers::start_tcp_stream_echo_server("127.0.0.1", 0)
        .await
        .unwrap();
    let upstream = available_address();
    let entry = available_address();
    let raw_entry = available_address();
    let mut server_config = json!([
        {"global_settings": {"ntp": ntp.settings()}},
        {"address": upstream.to_string(), "protocol": protocol(), "rules": "allow-all-direct"}
    ]);
    let client_config = |address: SocketAddr, time: Value| {
        json!([
            {"global_settings": {"ntp": time}},
            {"address": address.to_string(),
             "protocol": {"type": "forward", "target": echo.local_addr().to_string()},
             "rules": [{"masks": "0.0.0.0/0", "action": "allow",
                 "client_chain": [{"address": upstream.to_string(), "protocol": protocol()}]}]}
        ])
    };
    write(&server_path, &server_config);
    write(&client_path, &client_config(entry, ntp.settings()));
    write(&raw_path, &client_config(raw_entry, Value::Null));
    let mut server = Process::start(&server_path, &["--no-reload"]);
    let mut client = Process::start(&client_path, &["--no-reload"]);
    let mut raw = Process::start(&raw_path, &["--no-reload"]);
    server.wait_for("Servers ready").await;
    client.wait_for("Servers ready").await;
    raw.wait_for("Servers ready").await;
    assert_eq!(ntp.requests(), 2);
    assert!(accepts(entry).await);
    assert!(!accepts(raw_entry).await);

    server.signal(libc::SIGHUP);
    server.wait_for("Servers ready").await;
    assert_eq!(ntp.requests(), 2, "unchanged reload repeated initial query");
    assert!(accepts(entry).await);

    std::fs::write(&server_path, "not: [valid").unwrap();
    server.signal(libc::SIGHUP);
    server.wait_for("Reload rejected").await;
    assert!(accepts(entry).await);

    let mut failed = server_config.clone();
    failed[0]["global_settings"]["ntp"] = changed.settings();
    failed.as_array_mut().unwrap().push(json!({
        "path": directory.path().join("missing/listener.sock"), "protocol": {"type": "http"}
    }));
    write(&server_path, &failed);
    server.signal(libc::SIGHUP);
    server
        .wait_for("Reload rejected; previous servers restored")
        .await;
    assert_eq!(changed.requests(), 1);
    assert_eq!(ntp.requests(), 2, "rollback repeated initial query");
    assert!(accepts(entry).await);
    assert!(!accepts(raw_entry).await);

    let unavailable = TimeServer::start(None).await;
    server_config[0]["global_settings"]["ntp"] = unavailable.settings();
    write(&server_path, &server_config);
    server.signal(libc::SIGHUP);
    server.wait_for("Servers ready").await;
    assert_eq!(unavailable.requests(), 1);
    assert!(
        accepts(entry).await,
        "failed synchronization lost the last correction"
    );
    assert!(!accepts(raw_entry).await);

    server_config[0]["global_settings"]["ntp"] = Value::Null;
    write(&server_path, &server_config);
    server.signal(libc::SIGHUP);
    server.wait_for("Servers ready").await;
    assert!(accepts(raw_entry).await);
    assert!(!accepts(entry).await);
    assert_eq!(ntp.requests(), 2);

    server_config[0]["global_settings"]["ntp"] = changed.settings();
    write(&server_path, &server_config);
    write(&client_path, &client_config(entry, changed.settings()));
    server.signal(libc::SIGHUP);
    client.signal(libc::SIGHUP);
    server.wait_for("Servers ready").await;
    client.wait_for("Servers ready").await;
    assert_eq!(changed.requests(), 3);
    assert!(accepts(entry).await);
    assert!(!accepts(raw_entry).await);
    for process in [&mut server, &mut client, &mut raw] {
        process.signal(libc::SIGTERM);
        assert!(process.exit().await.success());
    }
}

#[tokio::test]
async fn ntp_check_dry_run_and_disabled_startup_do_not_query() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let ntp = TimeServer::start(Some(600)).await;
    let mut config = json!([
        {"global_settings": {"ntp": ntp.settings()}},
        {"address": available_address().to_string(), "protocol": {"type": "socks"}}
    ]);
    for endpoint in [ntp.address.to_string(), "unresolvable.invalid:123".into()] {
        config[0]["global_settings"]["ntp"]["server"] = endpoint.into();
        write(&path, &config);
        for mode in ["check", "--dry-run"] {
            let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_shoes"))
                .args([mode, "-t", "1"])
                .arg(&path)
                .output()
                .await
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    for settings in [json!({}), json!({"ntp": null})] {
        config[0]["global_settings"] = settings;
        write(&path, &config);
        let mut child = Process::start(&path, &["--no-reload"]);
        child.wait_for("Servers ready").await;
        child.signal(libc::SIGTERM);
        assert!(child.exit().await.success());
    }
    assert_eq!(ntp.requests(), 0);
}

#[tokio::test]
async fn ntp_failure_is_bounded_and_shutdown_interrupts_startup_and_reload_sync() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let ntp = TimeServer::start(None).await;
    let mut config = json!([
        {"global_settings": {"ntp": ntp.settings()}},
        {"address": available_address().to_string(), "protocol": {"type": "socks"}}
    ]);
    write(&path, &config);
    let mut child = Process::start(&path, &["--no-reload"]);
    child
        .wait_for_timeout("Servers ready", Duration::from_secs(4))
        .await;
    assert_eq!(ntp.requests(), 1);
    child.signal(libc::SIGTERM);
    assert!(child.exit().await.success());

    config[0]["global_settings"]["ntp"]["timeout_secs"] = 30.into();
    write(&path, &config);
    let mut child = Process::start(&path, &["--no-reload"]);
    timeout(Duration::from_secs(4), async {
        while ntp.requests() < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    child.signal(libc::SIGTERM);
    assert!(
        timeout(Duration::from_secs(3), child.exit())
            .await
            .unwrap()
            .success()
    );

    config[0]["global_settings"]["ntp"] = Value::Null;
    write(&path, &config);
    let mut child = Process::start(&path, &["--no-reload"]);
    child.wait_for("Servers ready").await;
    config[0]["global_settings"]["ntp"] = ntp.settings();
    config[0]["global_settings"]["ntp"]["timeout_secs"] = 30.into();
    write(&path, &config);
    child.signal(libc::SIGHUP);
    timeout(Duration::from_secs(4), async {
        while ntp.requests() < 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    child.signal(libc::SIGTERM);
    assert!(
        timeout(Duration::from_secs(3), child.exit())
            .await
            .unwrap()
            .success()
    );
}

#[tokio::test]
async fn ntp_initial_query_does_not_consume_the_reload_bind_retry_window() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let address = available_address();
    let mut config = json!([
        {"global_settings": {}},
        {"address": address.to_string(), "protocol": {"type": "socks"}}
    ]);
    write(&path, &config);
    let mut child = Process::start(&path, &["--no-reload"]);
    child.wait_for("Servers ready").await;
    let silent = TimeServer::start(None).await;
    config[0]["global_settings"]["ntp"] = silent.settings();
    config[0]["global_settings"]["ntp"]["timeout_secs"] = 4.into();
    let occupied = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let blocked = occupied.local_addr().unwrap();
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    config.as_array_mut().unwrap().push(json!({
        "address": blocked.to_string(), "transport": "quic",
        "quic_settings": {"cert": certificate.cert.pem(), "key": certificate.signing_key.serialize_pem(), "num_endpoints": 1},
        "protocol": {"type": "socks"}
    }));
    write(&path, &config);
    child.signal(libc::SIGHUP);
    child.wait_for(&format!("QUIC server at {blocked}")).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(occupied);
    child.wait_for("Servers ready").await;
    assert_eq!(
        silent.requests(),
        1,
        "bind retry repeated initial synchronization"
    );
    child.signal(libc::SIGTERM);
    assert!(child.exit().await.success());
}
