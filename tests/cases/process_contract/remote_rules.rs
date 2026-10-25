use crate::{Process, available_address, roundtrip};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const BLOCK: &[u8] = br#"{"version":1,"rules":[{"ip_cidr":["127.0.0.0/8"]}]}"#;
const MISS: &[u8] = br#"{"version":1,"rules":[{"ip_cidr":["192.0.2.0/24"]}]}"#;

fn directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn config(path: &Path, address: std::net::SocketAddr, target: std::net::SocketAddr, url: &str) {
    std::fs::write(path, serde_json::json!([{
        "address": address.to_string(), "protocol": {"type": "forward", "target": target.to_string()},
        "rules": [
            {"url": url, "path": "cache.json", "update_interval": "1s", "download": {"client_chain": "direct", "bootstrap_url": "system"}, "action": "block"},
            {"masks": {"any_destination": true}, "action": "allow"}
        ]
    }]).to_string()).unwrap();
}

async fn request(listener: &TcpListener) -> TcpStream {
    timeout(Duration::from_secs(8), async {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(stream.read_u8().await.unwrap());
            assert!(bytes.len() < 16384);
        }
        stream
    })
    .await
    .unwrap()
}

async fn respond(mut stream: TcpStream, body: &[u8]) {
    stream
        .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes())
        .await
        .unwrap();
    stream.write_all(body).await.unwrap();
}

async fn blocked(address: std::net::SocketAddr) {
    timeout(Duration::from_secs(2), async {
        let mut stream = TcpStream::connect(address).await.unwrap();
        let _ = stream.write_all(b"denied").await;
        assert!(stream.read_u8().await.is_err());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cold_installs_do_not_queue_an_extra_watcher_reload() {
    let dir = directory();
    let path = dir.path().join("config.yaml");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo = shoes_test_support::test_servers::start_tcp_stream_echo_server("127.0.0.1", 0)
        .await
        .unwrap();
    let address = available_address();
    config(
        &path,
        address,
        echo.local_addr(),
        &format!("http://{}/rules.json", listener.local_addr().unwrap()),
    );
    let mut config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    config[0]["rules"][0]["update_interval"] = serde_json::json!("7d");
    std::fs::write(&path, config.to_string()).unwrap();
    // A filesystem clock ahead of SystemTime makes freshly installed caches due.
    // Serve those legitimate no-op refreshes without mistaking them for cold fetches.
    let fixture = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        let mut requests = 0;
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            requests += 1;
            assert!(requests <= 4, "unexpected repeated refreshes");
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                headers.push(stream.read_u8().await.unwrap());
                assert!(headers.len() < 16384);
            }
            respond(stream, MISS).await;
        }
    }));
    let mut child = Process::start(&path, &[]);
    for cache in ["cache.json", "replacement.json"] {
        if cache == "replacement.json" {
            config[0]["rules"][0]["path"] = serde_json::json!(cache);
            std::fs::write(&path, config.to_string()).unwrap();
        }
        child.wait_for("Servers ready").await;
        roundtrip(&mut TcpStream::connect(address).await.unwrap()).await;
        assert!(
            timeout(Duration::from_secs(6), async {
                while let Some(line) = child.lines.recv().await {
                    assert!(!line.contains("Reload rejected"), "{line}");
                    if line.contains("Servers ready") {
                        return;
                    }
                }
                panic!("process exited unexpectedly");
            })
            .await
            .is_err(),
            "cold installation queued a duplicate reload"
        );
    }
    child.signal(libc::SIGTERM);
    assert!(child.exit().await.success());
    fixture.abort();
    assert!(fixture.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn cold_fetch_periodic_reload_noop_last_good_and_offline_restart() {
    let dir = directory();
    let path = dir.path().join("config.yaml");
    let cache = dir.path().join("cache.json");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo = shoes_test_support::test_servers::start_tcp_stream_echo_server("127.0.0.1", 0)
        .await
        .unwrap();
    let address = available_address();
    config(
        &path,
        address,
        echo.local_addr(),
        &format!(
            "http://{}/rules.json?SECRET",
            listener.local_addr().unwrap()
        ),
    );
    for mode in ["check", "--dry-run"] {
        let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
            .args([mode, "-t", "1"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("offline checks never download"), "{stderr}");
        assert!(!stderr.contains("SECRET"));
    }
    assert!(
        timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    let mut child = Process::start(&path, &["--no-reload"]);
    let first = request(&listener).await;
    assert!(TcpStream::connect(address).await.is_err());
    respond(first, MISS).await;
    child.wait_for("Servers ready").await;
    let mut retained = TcpStream::connect(address).await.unwrap();
    roundtrip(&mut retained).await;
    respond(request(&listener).await, BLOCK).await;
    child.wait_for("Servers ready").await;
    blocked(address).await;
    roundtrip(&mut retained).await;
    let original = std::fs::metadata(&cache).unwrap();
    respond(request(&listener).await, BLOCK).await;
    respond(request(&listener).await, b"SECRET invalid data").await;
    let pending = request(&listener).await;
    assert_eq!(std::fs::read(&cache).unwrap(), BLOCK);
    let current = std::fs::metadata(&cache).unwrap();
    assert_eq!(current.ino(), original.ino());
    assert_eq!(current.modified().unwrap(), original.modified().unwrap());
    assert!(
        timeout(Duration::from_millis(50), child.lines.recv())
            .await
            .is_err()
    );
    blocked(address).await;
    child.signal(libc::SIGTERM);
    assert!(child.exit().await.success());
    drop(pending);
    drop(listener);
    assert!(!dir.path().join("cache.json.shoes-update.tmp").exists());
    let mut restarted = Process::start(&path, &["--no-reload"]);
    restarted.wait_for("Servers ready").await;
    blocked(address).await;
    restarted.signal(libc::SIGTERM);
    assert!(restarted.exit().await.success());
}

#[tokio::test]
async fn removing_remote_source_cancels_inflight_refresh() {
    let dir = directory();
    let path = dir.path().join("config.yaml");
    let cache = dir.path().join("cache.json");
    std::fs::write(&cache, MISS).unwrap();
    std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o600)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo = shoes_test_support::test_servers::start_tcp_stream_echo_server("127.0.0.1", 0)
        .await
        .unwrap();
    let address = available_address();
    config(
        &path,
        address,
        echo.local_addr(),
        &format!("http://{}/rules.json", listener.local_addr().unwrap()),
    );
    let mut child = Process::start(&path, &["--no-reload"]);
    child.wait_for("Servers ready").await;
    let mut pending = request(&listener).await;
    let stage = dir.path().join("cache.json.shoes-update.tmp");
    assert!(stage.exists());
    std::fs::write(&path, crate::forward(address, echo.local_addr())).unwrap();
    child.signal(libc::SIGHUP);
    child.wait_for("Servers ready").await;
    assert!(!stage.exists());
    assert!(
        timeout(Duration::from_secs(2), pending.read_u8())
            .await
            .unwrap()
            .is_err()
    );
    roundtrip(&mut TcpStream::connect(address).await.unwrap()).await;
    child.signal(libc::SIGTERM);
    assert!(child.exit().await.success());
}

#[tokio::test]
async fn cold_download_lock_shutdown_and_kill_recovery() {
    for signal in [libc::SIGTERM, libc::SIGKILL] {
        let dir = directory();
        let path = dir.path().join("config.yaml");
        let stage = dir.path().join("cache.json.shoes-update.tmp");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = available_address();
        config(
            &path,
            address,
            address,
            &format!("http://{}/rules.json", listener.local_addr().unwrap()),
        );
        let mut first = Process::start(&path, &["--no-reload"]);
        let pending = request(&listener).await;
        let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
            .args(["-t", "1", "--no-reload"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("already owned"));
        first.signal(signal);
        assert_eq!(first.exit().await.success(), signal == libc::SIGTERM);
        drop(pending);
        assert_eq!(stage.exists(), signal == libc::SIGKILL);
        let mut recovered = Process::start(&path, &["--no-reload"]);
        respond(request(&listener).await, BLOCK).await;
        recovered.wait_for("Servers ready").await;
        assert!(!stage.exists());
        recovered.signal(libc::SIGTERM);
        assert!(recovered.exit().await.success());
    }
}

#[tokio::test]
async fn managed_changes_coalesce_with_filesystem_watches() {
    let dir = directory();
    let path = dir.path().join("config.yaml");
    let cache = dir.path().join("cache.json");
    std::fs::write(&cache, MISS).unwrap();
    std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o600)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo = shoes_test_support::test_servers::start_tcp_stream_echo_server("127.0.0.1", 0)
        .await
        .unwrap();
    let address = available_address();
    config(
        &path,
        address,
        echo.local_addr(),
        &format!("http://{}/rules.json", listener.local_addr().unwrap()),
    );
    let mut child = Process::start(&path, &[]);
    child.wait_for("Servers ready").await;
    respond(request(&listener).await, BLOCK).await;
    child.wait_for("Servers ready").await;
    blocked(address).await;
    respond(request(&listener).await, BLOCK).await;
    let pending = request(&listener).await;
    assert!(
        timeout(Duration::from_millis(50), child.lines.recv())
            .await
            .is_err()
    );
    child.signal(libc::SIGTERM);
    assert!(child.exit().await.success());
    drop(pending);
}
