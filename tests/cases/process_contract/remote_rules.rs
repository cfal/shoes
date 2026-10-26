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

fn updater(path: &Path) -> Process {
    Process::from_child(
        Command::new(env!("CARGO_BIN_EXE_shoes"))
            .args(["-t", "1", "update-rules", "--direct"])
            .arg(path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    )
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
async fn startup_check_and_reload_never_download() {
    let dir = directory();
    let path = dir.path().join("config.yaml");
    let cache = dir.path().join("cache/rules.json");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo = shoes_test_support::test_servers::start_tcp_stream_echo_server("127.0.0.1", 0)
        .await
        .unwrap();
    let address = available_address();
    let mut value = config(
        &path,
        address,
        echo.local_addr(),
        &format!(
            "http://{}/rules.json?SECRET",
            listener.local_addr().unwrap()
        ),
        "7d",
    );
    for args in [
        vec!["--dry-run"],
        vec![],
        vec!["--dry-run", "update-rules", "--direct"],
    ] {
        let output = command(&path, &args).await;
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(!error.contains("SECRET"), "{error}");
        assert!(
            error.contains("never download") || error.contains("cannot be combined"),
            "{error}"
        );
    }
    // The check alias is parsed before global flags.
    let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
        .args(["check", "-t", "1"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("never download"));
    cached(&cache, br#"{"version":1,"SECRET":[]}"#);
    let output = command(&path, &["--dry-run"]).await;
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("SECRET"));
    cached(&cache, MISS);
    let mut child = Process::start(&path, &["--no-reload"]);
    child.wait_for("Servers ready").await;
    std::fs::remove_file(&cache).unwrap();
    child.signal(libc::SIGHUP);
    child
        .wait_for("Reload rejected; current servers retained")
        .await;
    roundtrip(&mut TcpStream::connect(address).await.unwrap()).await;
    value[0]["rule_cache_dir"] = serde_json::json!("./other");
    value[1]["rules"][0]["path"] = serde_json::json!("other/rules.json");
    std::fs::write(&path, value.to_string()).unwrap();
    child.signal(libc::SIGHUP);
    child
        .wait_for("changing rule_cache_dir requires a restart")
        .await;
    assert!(
        timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
    child.signal(libc::SIGTERM);
    assert!(child.exit().await.success());
}

#[tokio::test]
async fn explicit_update_overrides_routing_and_respects_root_ownership() {
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
    value[1]["rules"][0]["download"]["client_chain"] = serde_json::json!("unavailable-group");
    std::fs::write(&path, value.to_string()).unwrap();
    assert!(!command(&path, &["update-rules"]).await.status.success());
    assert!(
        timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
    std::fs::remove_dir(dir.path().join("cache")).unwrap();
    let update = command(&path, &["update-rules", "--direct"]);
    let fixture = async {
        respond(request(&listener).await, MISS).await;
    };
    let (output, ()) = tokio::join!(update, fixture);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!command(&path, &["--dry-run"]).await.status.success());
    value[1]["rules"][0]["download"]["client_chain"] = serde_json::json!("direct");
    std::fs::write(&path, value.to_string()).unwrap();
    cached(&dir.path().join("cache/rules.json"), MISS);
    let mut child = Process::start(&path, &["--no-reload"]);
    child.wait_for("Servers ready").await;
    let output = command(&path, &["update-rules", "--direct"]).await;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already owned"));
    assert!(
        timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
    child.signal(libc::SIGTERM);
    assert!(child.exit().await.success());
}

#[tokio::test]
async fn restrictive_umasks_require_explicit_cache_directory_setup() {
    use std::os::unix::process::CommandExt;

    async fn masked_update(path: &Path, mask: libc::mode_t) -> std::process::Output {
        let path = path.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut command = Command::new(env!("CARGO_BIN_EXE_shoes"));
            command
                .args(["-t", "1", "update-rules", "--direct"])
                .arg(path);
            unsafe {
                command.pre_exec(move || {
                    libc::umask(mask);
                    Ok(())
                });
            }
            command.output().unwrap()
        })
        .await
        .unwrap()
    }

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
        let output = masked_update(&path, mask).await;
        let mode = std::fs::metadata(&root).unwrap().mode() & 0o777;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains("rule_cache_dir") && error.contains("install -d -m 700"),
            "{error}"
        );
        assert_eq!(u64::from(mode), 0o700 & !u64::from(mask));
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        assert!(
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );

        let update = masked_update(&path, mask);
        let fixture = async { respond(request(&listener).await, MISS).await };
        let (output, ()) = tokio::join!(update, fixture);
        assert!(
            output.status.success(),
            "umask {mask:o}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::metadata(&root).unwrap().mode() & 0o777, 0o700);
        assert_eq!(std::fs::read(root.join("rules.json")).unwrap(), MISS);
        assert!(command(&path, &["--dry-run"]).await.status.success());
    }
}

#[tokio::test]
async fn explicit_update_keeps_completed_files_when_a_later_download_fails() {
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
    value[1]["rules"].as_array_mut().unwrap().push(second);
    std::fs::write(&path, value.to_string()).unwrap();
    cached(&dir.path().join("cache/second.json"), MISS);
    let update = command(&path, &["update-rules", "--direct"]);
    let fixture = async {
        respond(request(&listener).await, BLOCK).await;
        respond(request(&listener).await, b"DOWNLOADED_SECRET").await;
    };
    let (output, ()) = tokio::join!(update, fixture);
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("DOWNLOADED_SECRET"));
    assert_eq!(
        std::fs::read(dir.path().join("cache/rules.json")).unwrap(),
        BLOCK
    );
    assert_eq!(
        std::fs::read(dir.path().join("cache/second.json")).unwrap(),
        MISS
    );
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
async fn killed_explicit_updater_releases_lease_and_recovers_staging() {
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
    let mut first = updater(&path);
    let pending = request(&listener).await;
    let output = command(&path, &["update-rules", "--direct"]).await;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already owned"));
    first.signal(libc::SIGKILL);
    assert!(!first.exit().await.success());
    drop(pending);
    assert!(!dir.path().join("cache/rules.json").exists());
    let mut recovered = updater(&path);
    respond(request(&listener).await, BLOCK).await;
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
