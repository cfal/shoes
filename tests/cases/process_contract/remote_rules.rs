use crate::{Process, available_address, roundtrip};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const BLOCK: &[u8] = br#"{"version":1,"rules":[{"ip_cidr":["127.0.0.0/8"]}]}"#;
const MISS: &[u8] = br#"{"version":1,"rules":[{"ip_cidr":["192.0.2.0/24"]}]}"#;

fn directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    std::fs::create_dir(dir.path().join("cache")).unwrap();
    std::fs::set_permissions(
        dir.path().join("cache"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    dir
}

fn cached(path: &Path, body: &[u8]) {
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::File::open(path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(std::time::SystemTime::now()))
        .unwrap();
}

fn config(
    path: &Path,
    address: std::net::SocketAddr,
    target: std::net::SocketAddr,
    url: &str,
    interval: &str,
) -> serde_json::Value {
    let value = serde_json::json!([
        {"rule_cache_dir": "./cache"},
        {"address": address.to_string(), "protocol": {"type": "forward", "target": target.to_string()},
         "rules": [
            {"url": url, "path": "cache/rules.json", "update_interval": interval, "download": {"client_chain": "direct", "bootstrap_url": "system"}, "action": "block"},
            {"masks": {"any_destination": true}, "action": "allow"}
         ]}
    ]);
    std::fs::write(path, value.to_string()).unwrap();
    value
}

async fn command(path: &Path, args: &[&str]) -> std::process::Output {
    let path = path.to_owned();
    let args: Vec<_> = args.iter().map(|arg| arg.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_shoes"))
            .args(["-t", "1"])
            .args(args)
            .arg(path)
            .output()
            .unwrap()
    })
    .await
    .unwrap()
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

async fn quiet(child: &mut Process) {
    assert!(
        timeout(Duration::from_secs(6), async {
            while let Some(line) = child.lines.recv().await {
                assert!(!line.contains("SECRET"), "{line}");
                assert!(
                    !line.contains("Servers ready") && !line.contains("Reload rejected"),
                    "{line}"
                );
            }
            panic!("process exited unexpectedly");
        })
        .await
        .is_err()
    );
}

#[tokio::test]
async fn offline_checks_and_invalid_caches_never_download() {
    let dir = directory();
    let path = dir.path().join("config.yaml");
    let root = dir.path().join("cache");
    let cache = root.join("rules.json");
    std::fs::remove_dir(&root).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = available_address();
    config(
        &path,
        address,
        address,
        &format!(
            "http://{}/rules.json?SECRET",
            listener.local_addr().unwrap()
        ),
        "7d",
    );
    let output = command(&path, &["--dry-run"]).await;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("offline checks never download"));
    let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
        .args(["check", "-t", "1"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("offline checks never download"));
    assert!(!root.exists());
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    cached(&cache, br#"{"version":1,"SECRET":[]}"#);
    for args in [vec!["--dry-run"], vec![]] {
        let output = command(&path, &args).await;
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("repair or remove"), "{error}");
        assert!(!error.contains("SECRET"), "{error}");
    }
    assert_eq!(
        std::fs::read(&cache).unwrap(),
        br#"{"version":1,"SECRET":[]}"#
    );
    std::fs::remove_file(&cache).unwrap();
    let external = dir.path().join("external.json");
    cached(&external, MISS);
    std::os::unix::fs::symlink(&external, &cache).unwrap();
    assert!(!command(&path, &[]).await.status.success());
    assert_eq!(std::fs::read(&external).unwrap(), MISS);
    std::fs::remove_file(&cache).unwrap();
    cached(&cache, MISS);
    std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(!command(&path, &[]).await.status.success());
    assert_eq!(std::fs::read(&cache).unwrap(), MISS);
    assert!(
        timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
    assert!(TcpStream::connect(address).await.is_err());
}

#[tokio::test]
async fn startup_bootstraps_before_listeners_and_respects_root_ownership() {
    let dir = directory();
    let path = dir.path().join("config.yaml");
    let root = dir.path().join("cache");
    std::fs::remove_dir(&root).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = available_address();
    config(
        &path,
        address,
        address,
        &format!("http://{}/rules.json", listener.local_addr().unwrap()),
        "7d",
    );
    let mut child = Process::start(&path, &[]);
    let pending = request(&listener).await;
    assert!(TcpStream::connect(address).await.is_err());
    let output = command(&path, &[]).await;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already owned"));
    respond(pending, BLOCK).await;
    child.wait_for("Servers ready").await;
    assert_eq!(std::fs::read(root.join("rules.json")).unwrap(), BLOCK);
    blocked(address).await;
    quiet(&mut child).await;
    child.signal(libc::SIGTERM);
    assert!(child.exit().await.success());
    assert!(command(&path, &["--dry-run"]).await.status.success());
}

#[tokio::test]
async fn restrictive_umasks_require_explicit_cache_directory_setup() {
    use std::os::unix::process::CommandExt;
    for mask in [0o200, 0o400, 0o600, 0o777] {
        let dir = directory();
        let root = dir.path().join("cache");
        std::fs::remove_dir(&root).unwrap();
        let path = dir.path().join("config.yaml");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = available_address();
        config(
            &path,
            address,
            address,
            &format!("http://{}/rules.json", listener.local_addr().unwrap()),
            "7d",
        );
        let start = || {
            let mut command = Command::new(env!("CARGO_BIN_EXE_shoes"));
            command
                .args(["-t", "1", "--no-reload"])
                .arg(&path)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            unsafe {
                command.pre_exec(move || {
                    libc::umask(mask);
                    Ok(())
                });
            }
            Process::from_child(command.spawn().unwrap())
        };
        let mut child = start();
        child.wait_for("install -d -m 700").await;
        assert!(!child.exit().await.success());
        let mode = std::fs::metadata(&root).unwrap().mode() & 0o777;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(u64::from(mode), 0o700 & !u64::from(mask));
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        assert!(
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        let mut child = start();
        respond(request(&listener).await, MISS).await;
        child.wait_for("Servers ready").await;
        child.signal(libc::SIGTERM);
        assert!(child.exit().await.success());
        assert!(command(&path, &["--dry-run"]).await.status.success());
    }
}

#[tokio::test]
async fn bootstrap_keeps_completed_files_without_activating_a_failed_candidate() {
    for failure in ["download", "compile"] {
        let dir = directory();
        let path = dir.path().join("config.yaml");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = available_address();
        let mut value = config(
            &path,
            address,
            address,
            &format!("http://{}/rules.json", listener.local_addr().unwrap()),
            "7d",
        );
        let mut second = value[1]["rules"][0].clone();
        second["path"] = serde_json::json!("cache/second.json");
        if failure == "download" {
            value[1]["rules"].as_array_mut().unwrap().push(second);
        } else {
            value[1]["rules"][0]["action"] = serde_json::json!("allow");
            value[1]["rules"][0]["client_chain"] = serde_json::json!("missing-client");
        }
        std::fs::write(&path, value.to_string()).unwrap();
        let mut child = Process::start(&path, &["--no-reload"]);
        respond(request(&listener).await, BLOCK).await;
        if failure == "download" {
            respond(request(&listener).await, b"DOWNLOADED_SECRET").await;
        }
        assert!(!child.exit().await.success());
        assert_eq!(
            std::fs::read(dir.path().join("cache/rules.json")).unwrap(),
            BLOCK
        );
        assert!(!dir.path().join("cache/second.json").exists());
        assert!(TcpStream::connect(address).await.is_err());
        while let Some(line) = child.lines.recv().await {
            assert!(!line.contains("DOWNLOADED_SECRET"), "{line}");
        }
    }
}

#[tokio::test]
async fn bootstrap_uses_inline_proxy_and_never_falls_back_to_direct() {
    let dir = directory();
    let path = dir.path().join("config.yaml");
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = available_address();
    let mut value = config(
        &path,
        address,
        address,
        &format!("http://{}/rules.json", origin.local_addr().unwrap()),
        "7d",
    );
    value[1]["rules"][0]["download"]["client_chain"] = serde_json::json!({
        "address": format!("localhost:{}", proxy.local_addr().unwrap().port()), "protocol": {"type": "socks"}
    });
    std::fs::write(&path, value.to_string()).unwrap();
    let mut child = Process::start(&path, &["--no-reload"]);
    let (mut stream, _) = timeout(Duration::from_secs(8), proxy.accept())
        .await
        .unwrap()
        .unwrap();
    let mut greeting = [0; 3];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 1, 0]);
    stream.write_all(&[5, 0]).await.unwrap();
    let mut connect = [0; 10];
    stream.read_exact(&mut connect).await.unwrap();
    assert_eq!(&connect[..8], &[5, 1, 0, 1, 127, 0, 0, 1]);
    assert_eq!(
        u16::from_be_bytes([connect[8], connect[9]]),
        origin.local_addr().unwrap().port()
    );
    stream
        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
        .await
        .unwrap();
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        headers.push(stream.read_u8().await.unwrap());
    }
    assert!(TcpStream::connect(address).await.is_err());
    respond(stream, BLOCK).await;
    child.wait_for("Servers ready").await;
    child.signal(libc::SIGTERM);
    assert!(child.exit().await.success());
    std::fs::remove_file(dir.path().join("cache/rules.json")).unwrap();
    drop(proxy);
    let output = command(&path, &[]).await;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no direct fallback"));
    assert!(
        timeout(Duration::from_millis(100), origin.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn unsupported_bootstrap_routes_only_fail_when_caches_are_missing() {
    for route in ["round-robin", "selector", "url-test", "named-dns", "quic"] {
        let dir = directory();
        let path = dir.path().join("config.yaml");
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = available_address();
        let mut value = config(
            &path,
            address,
            address,
            &format!("http://{}/rules.json", origin.local_addr().unwrap()),
            "7d",
        );
        match route {
            "named-dns" => {
                value.as_array_mut().unwrap().push(
                    serde_json::json!({"dns_group": "system", "dns_servers": "tcp://127.0.0.1:1"}),
                );
            }
            "quic" => {
                value[1]["rules"][0]["download"]["client_chain"] = serde_json::json!({"address": "127.0.0.1:1", "transport": "quic", "quic_settings": {"verify": false}, "protocol": {"type": "socks"}});
            }
            _ => {
                let mut group = serde_json::json!({"client_group": "outbound", "type": route, "client_proxies": ["direct"]});
                if route == "url-test" {
                    group["url"] = serde_json::json!("http://probe.invalid/");
                    group["lazy"] = serde_json::json!(true);
                }
                value.as_array_mut().unwrap().push(group);
                value[1]["rules"][0]["download"]["client_chain"] = serde_json::json!("outbound");
            }
        }
        std::fs::write(&path, value.to_string()).unwrap();
        let output = command(&path, &[]).await;
        assert!(!output.status.success(), "{route}");
        let expected = if route == "named-dns" {
            "named DNS groups are not supported"
        } else {
            "missing-cache bootstrap supports only"
        };
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(TcpStream::connect(address).await.is_err());
        assert!(!dir.path().join("cache/rules.json").exists());
        cached(&dir.path().join("cache/rules.json"), MISS);
        let mut child = Process::start(&path, &["--no-reload"]);
        child.wait_for("Servers ready").await;
        child.signal(libc::SIGTERM);
        assert!(child.exit().await.success());
        assert!(
            timeout(Duration::from_millis(100), origin.accept())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn reload_bootstrap_failure_retains_active_traffic_and_success_activates_once() {
    let dir = directory();
    let path = dir.path().join("config.yaml");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo = shoes_test_support::test_servers::start_tcp_stream_echo_server("127.0.0.1", 0)
        .await
        .unwrap();
    let address = available_address();
    let mut value = config(
        &path,
        address,
        echo.local_addr(),
        &format!("http://{}/rules.json", listener.local_addr().unwrap()),
        "7d",
    );
    let cache = dir.path().join("cache/rules.json");
    cached(&cache, MISS);
    let mut child = Process::start(&path, &[]);
    child.wait_for("Servers ready").await;
    let mut retained = TcpStream::connect(address).await.unwrap();
    roundtrip(&mut retained).await;
    std::fs::remove_file(&cache).unwrap();
    child.signal(libc::SIGHUP);
    let pending = request(&listener).await;
    roundtrip(&mut retained).await;
    roundtrip(&mut TcpStream::connect(address).await.unwrap()).await;
    respond(pending, b"DOWNLOADED_SECRET").await;
    child
        .wait_for("Reload rejected; current servers retained")
        .await;
    assert!(!cache.exists());
    roundtrip(&mut retained).await;
    child.signal(libc::SIGHUP);
    respond(request(&listener).await, BLOCK).await;
    child.wait_for("Servers ready").await;
    blocked(address).await;
    roundtrip(&mut retained).await;
    quiet(&mut child).await;
    value[0]["rule_cache_dir"] = serde_json::json!("./other");
    value[1]["rules"][0]["path"] = serde_json::json!("other/rules.json");
    std::fs::write(&path, value.to_string()).unwrap();
    child.signal(libc::SIGHUP);
    child
        .wait_for("changing rule_cache_dir requires a restart")
        .await;
    assert!(!dir.path().join("other").exists());
    value[0]["rule_cache_dir"] = serde_json::json!("./cache");
    value[1]["rules"][0]["path"] = serde_json::json!("cache/rules.json");
    std::fs::write(&path, value.to_string()).unwrap();
    std::fs::remove_dir_all(dir.path().join("cache")).unwrap();
    child.signal(libc::SIGHUP);
    child
        .wait_for("Reload rejected; current servers retained")
        .await;
    assert!(!dir.path().join("cache").exists());
    blocked(address).await;
    roundtrip(&mut retained).await;
    child.signal(libc::SIGTERM);
    assert!(child.exit().await.success());
}

#[tokio::test]
async fn refresh_owns_reload_and_retains_noops_failures_and_existing_flows() {
    for flags in [vec![], vec!["--no-reload"]] {
        let dir = directory();
        let path = dir.path().join("config.yaml");
        let cache = dir.path().join("cache/rules.json");
        cached(&cache, MISS);
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
            "1s",
        );
        let mut child = Process::start(&path, &flags);
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
        quiet(&mut child).await;
        assert_eq!(std::fs::read(&cache).unwrap(), BLOCK);
        let current = std::fs::metadata(&cache).unwrap();
        assert_eq!(current.ino(), original.ino());
        assert_eq!(current.modified().unwrap(), original.modified().unwrap());
        child.signal(libc::SIGTERM);
        assert!(child.exit().await.success());
        drop(pending);
        assert!(
            !dir.path()
                .join("cache/rules.json.shoes-update.tmp")
                .exists()
        );
        let mut restarted = Process::start(&path, &["--no-reload"]);
        restarted.wait_for("Servers ready").await;
        blocked(address).await;
        restarted.signal(libc::SIGTERM);
        assert!(restarted.exit().await.success());
    }
}

#[tokio::test]
async fn cache_edits_require_explicit_reload_but_yaml_remains_watched() {
    let dir = directory();
    let path = dir.path().join("config.yaml");
    let cache = dir.path().join("cache/rules.json");
    cached(&cache, MISS);
    let echo = shoes_test_support::test_servers::start_tcp_stream_echo_server("127.0.0.1", 0)
        .await
        .unwrap();
    let address = available_address();
    let mut value = config(
        &path,
        address,
        echo.local_addr(),
        "http://127.0.0.1:1/rules.json",
        "7d",
    );
    let mut child = Process::start(&path, &[]);
    child.wait_for("Servers ready").await;
    cached(&cache, BLOCK);
    quiet(&mut child).await;
    roundtrip(&mut TcpStream::connect(address).await.unwrap()).await;
    child.signal(libc::SIGHUP);
    child.wait_for("Servers ready").await;
    blocked(address).await;
    value[1]["rules"].as_array_mut().unwrap().remove(0);
    std::fs::write(&path, value.to_string()).unwrap();
    child.wait_for("Servers ready").await;
    roundtrip(&mut TcpStream::connect(address).await.unwrap()).await;
    child.signal(libc::SIGTERM);
    assert!(child.exit().await.success());
}

#[tokio::test]
async fn config_edits_cancel_inflight_refresh_without_publishing() {
    let dir = directory();
    let path = dir.path().join("config.yaml");
    let cache = dir.path().join("cache/rules.json");
    cached(&cache, MISS);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = available_address();
    let mut value = config(
        &path,
        address,
        address,
        &format!("http://{}/rules.json", listener.local_addr().unwrap()),
        "1s",
    );
    let mut child = Process::start(&path, &[]);
    child.wait_for("Servers ready").await;
    let mut pending = request(&listener).await;
    value[1]["rules"] =
        serde_json::json!([{"masks": {"any_destination": true}, "action": "block"}]);
    std::fs::write(&path, value.to_string()).unwrap();
    child.wait_for("Servers ready").await;
    assert!(
        timeout(Duration::from_secs(2), pending.read_u8())
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(std::fs::read(&cache).unwrap(), MISS);
    assert!(
        !dir.path()
            .join("cache/rules.json.shoes-update.tmp")
            .exists()
    );
    blocked(address).await;
    child.signal(libc::SIGTERM);
    assert!(child.exit().await.success());
}

#[tokio::test]
async fn cancelled_bootstrap_releases_lease_and_recovers_staging() {
    for signal in [libc::SIGTERM, libc::SIGKILL] {
        let dir = directory();
        let path = dir.path().join("config.yaml");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = available_address();
        config(
            &path,
            address,
            address,
            &format!("http://{}/rules.json", listener.local_addr().unwrap()),
            "7d",
        );
        let mut first = Process::start(&path, &["--no-reload"]);
        let pending = request(&listener).await;
        first.signal(signal);
        let _ = first.exit().await;
        drop(pending);
        assert!(!dir.path().join("cache/rules.json").exists());
        let mut recovered = Process::start(&path, &["--no-reload"]);
        respond(request(&listener).await, BLOCK).await;
        recovered.wait_for("Servers ready").await;
        recovered.signal(libc::SIGTERM);
        assert!(recovered.exit().await.success());
        assert!(
            !dir.path()
                .join("cache/rules.json.shoes-update.tmp")
                .exists()
        );
        assert_eq!(
            std::fs::read(dir.path().join("cache/rules.json")).unwrap(),
            BLOCK
        );
    }
}
