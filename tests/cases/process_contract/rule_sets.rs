use crate::{Process, available_address, roundtrip};
use serde_json::json;
use std::{path::Path, process::Command, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

fn source(path: &Path, blocked: bool) {
    let rules = if blocked {
        json!([{"ip_cidr": ["127.0.0.0/8"]}])
    } else {
        json!([])
    };
    std::fs::write(path, json!({"version": 1, "rules": rules}).to_string()).unwrap();
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
async fn rule_only_reload_rejects_invalid_sources_and_recovers_missing_candidates() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");
    let list = dir.path().join("list.json");
    let echo = shoes_test_support::test_servers::start_tcp_stream_echo_server("0.0.0.0", 0)
        .await
        .unwrap();
    let address = available_address();
    let mut config = json!([
        {"global_limits": {"reload_grace_secs": 60}},
        {"rule_group": "deny", "rules": ["list.json"]},
        {"address": address.to_string(), "protocol": {"type": "forward", "target": format!("127.0.0.1:{}", echo.local_addr().port())},
         "rules": [{"masks": {"rule_group": "deny"}, "action": "block"}, {"masks": {"any_destination": true}, "action": "allow"}]}
    ]);
    source(&list, false);
    std::fs::write(&config_path, config.to_string()).unwrap();
    let mut process = Process::start(&config_path, &[]);
    process.wait_for("Servers ready").await;
    let mut established = TcpStream::connect(address).await.unwrap();
    roundtrip(&mut established).await;

    source(&list, true);
    process.wait_for("Servers ready").await;
    blocked(address).await;
    roundtrip(&mut established).await;

    std::fs::write(&list, "corrupt").unwrap();
    process.wait_for("Reload rejected").await;
    blocked(address).await;
    roundtrip(&mut established).await;
    for mode in ["check", "--dry-run"] {
        let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
            .args([mode, "-t", "1"])
            .arg(&config_path)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("rule group deny"));
    }

    config[1]["rules"] = json!(["missing/new.json"]);
    std::fs::write(&config_path, config.to_string()).unwrap();
    process.wait_for("Reload rejected").await;
    blocked(address).await;
    std::fs::create_dir(dir.path().join("missing")).unwrap();
    source(&dir.path().join("missing/new.json"), false);
    process.wait_for("Servers ready").await;
    roundtrip(&mut TcpStream::connect(address).await.unwrap()).await;
    roundtrip(&mut established).await;
    process.signal(libc::SIGTERM);
    assert!(process.exit().await.success());
}

#[tokio::test]
async fn rule_sources_follow_symlink_retargeting_and_atomic_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");
    let allowed = dir.path().join("allowed.json");
    let denied = dir.path().join("denied.json");
    let link = dir.path().join("list.json");
    source(&allowed, false);
    source(&denied, true);
    std::os::unix::fs::symlink(&allowed, &link).unwrap();
    let echo = shoes_test_support::test_servers::start_tcp_stream_echo_server("0.0.0.0", 0)
        .await
        .unwrap();
    let address = available_address();
    let config = json!([
        {"rule_group": "deny", "rules": [{"path": "list.json", "format": "singbox_json"}]},
        {"address": address.to_string(), "protocol": {"type": "forward", "target": format!("127.0.0.1:{}", echo.local_addr().port())},
         "rules": [{"masks": {"rule_group": "deny"}, "action": "block"}, {"masks": "0.0.0.0/0", "action": "allow"}]}
    ]);
    std::fs::write(&config_path, config.to_string()).unwrap();
    let mut process = Process::start(&config_path, &[]);
    process.wait_for("Servers ready").await;
    roundtrip(&mut TcpStream::connect(address).await.unwrap()).await;
    std::os::unix::fs::symlink(&denied, dir.path().join("next")).unwrap();
    std::fs::rename(dir.path().join("next"), &link).unwrap();
    process.wait_for("Servers ready").await;
    blocked(address).await;
    source(&dir.path().join("replacement"), false);
    std::fs::rename(dir.path().join("replacement"), &denied).unwrap();
    process.wait_for("Servers ready").await;
    roundtrip(&mut TcpStream::connect(address).await.unwrap()).await;
    process.signal(libc::SIGTERM);
    assert!(process.exit().await.success());
}

#[tokio::test]
async fn rejected_cyclic_source_recovers_without_a_config_edit() {
    let dir = tempfile::tempdir().unwrap();
    let candidate_dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");
    let list = dir.path().join("list.json");
    source(&list, true);
    let loop_path = candidate_dir.path().join("loop.json");
    let other = candidate_dir.path().join("other");
    std::os::unix::fs::symlink(&other, &loop_path).unwrap();
    std::os::unix::fs::symlink(&loop_path, &other).unwrap();
    let echo = shoes_test_support::test_servers::start_tcp_stream_echo_server("0.0.0.0", 0)
        .await
        .unwrap();
    let address = available_address();
    let mut config = json!([
        {"rule_group": "deny", "rules": [{"path": list, "format": "singbox_json"}]},
        {"address": address.to_string(), "protocol": {"type": "forward", "target": format!("127.0.0.1:{}", echo.local_addr().port())},
         "rules": [{"masks": {"rule_group": "deny"}, "action": "block"}, {"masks": {"any_destination": true}, "action": "allow"}]}
    ]);
    std::fs::write(&config_path, config.to_string()).unwrap();
    let mut process = Process::start(&config_path, &[]);
    process.wait_for("Servers ready").await;
    blocked(address).await;
    config[0]["rules"][0]["path"] = json!(loop_path);
    std::fs::write(&config_path, config.to_string()).unwrap();
    process.wait_for("Reload rejected").await;
    blocked(address).await;
    let replacement = candidate_dir.path().join("replacement");
    source(&replacement, false);
    std::fs::rename(&replacement, &loop_path).unwrap();
    process.wait_for("Servers ready").await;
    roundtrip(&mut TcpStream::connect(address).await.unwrap()).await;
    process.signal(libc::SIGTERM);
    assert!(process.exit().await.success());
}

#[tokio::test]
async fn inline_sources_reload_and_missing_nested_sources_recover() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");
    let list = dir.path().join("list.json");
    source(&list, false);
    let echo = shoes_test_support::test_servers::start_tcp_stream_echo_server("0.0.0.0", 0)
        .await
        .unwrap();
    let address = available_address();
    let nested_address = available_address();
    let mut config = json!([
        {"address": address.to_string(), "protocol": {"type": "forward", "target": format!("127.0.0.1:{}", echo.local_addr().port())},
         "rules": [{"masks": {"all": [{"path": "list.json"}, {"any_destination": true}]}, "action": "block"},
                   {"masks": "0.0.0.0/0"}]},
        {"address": nested_address.to_string(), "protocol": {"type": "websocket", "targets": [{
            "protocol": {"type": "socks"},
            "override_rules": [{"masks": {"not": {"path": "list.json"}}, "action": "block"}]
        }]}}
    ]);
    std::fs::write(&config_path, config.to_string()).unwrap();
    let mut process = Process::start(&config_path, &[]);
    process.wait_for("Servers ready").await;
    roundtrip(&mut TcpStream::connect(address).await.unwrap()).await;
    source(&list, true);
    process.wait_for("Servers ready").await;
    blocked(address).await;

    config[1]["protocol"]["targets"][0]["override_rules"][0]["masks"]["not"]["path"] =
        json!("missing/nested.json");
    std::fs::write(&config_path, config.to_string()).unwrap();
    process.wait_for("Reload rejected").await;
    blocked(address).await;
    for mode in ["check", "--dry-run"] {
        let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
            .args([mode, "-t", "1"])
            .arg(&config_path)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("nested.json"));
    }
    std::fs::create_dir(dir.path().join("missing")).unwrap();
    source(&dir.path().join("missing/nested.json"), false);
    process.wait_for("Servers ready").await;
    blocked(address).await;
    source(&list, false);
    process.wait_for("Servers ready").await;
    roundtrip(&mut TcpStream::connect(address).await.unwrap()).await;
    process.signal(libc::SIGTERM);
    assert!(process.exit().await.success());
}
