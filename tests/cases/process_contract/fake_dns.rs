use crate::{Process, available_address};
use hickory_resolver::proto::{
    op::{Message, Query},
    rr::{Name, RData, RecordType},
};
use serde_json::json;
use shoes_test_support::socks5::Socks5UdpAssociation;
use std::{net::Ipv4Addr, os::unix::fs::PermissionsExt, process::Command, time::Duration};

async fn query(port: u16, name: &str) -> Ipv4Addr {
    let association = Socks5UdpAssociation::connect("127.0.0.1", port)
        .await
        .unwrap();
    let mut request = Message::query();
    request.metadata.id = 92;
    request.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    let reply = association
        .send_to("198.18.0.1:53".parse().unwrap(), &request.to_vec().unwrap())
        .await
        .unwrap();
    let response = Message::from_vec(&reply).unwrap();
    assert_eq!(response.metadata.id, 92);
    let RData::A(ip) = response.answers[0].data else {
        panic!("missing synthetic address")
    };
    ip.0
}

#[tokio::test]
async fn fake_dns_reload_shutdown_and_crash_preserve_safe_mapping_state() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        let state = directory.path().join("fake.json");
        let port = available_address().port();
        let mut config = json!([
            {"dns_group":"shared", "dns_servers":"udp://127.0.0.1:9",
             "fake_ip":{"state_file":state,"max_entries":16}},
            {"address":format!("0.0.0.0:{port}"),"protocol":{"type":"socks","udp_enabled":true},
             "dns":{"servers":"shared"}}
        ]);
        std::fs::write(&path, config.to_string()).unwrap();
        let checked = Command::new(env!("CARGO_BIN_EXE_shoes"))
            .args(["check", "-t", "1"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(checked.status.success(), "{:?}", checked);
        assert!(!state.exists(), "check must not acquire persistent state");

        let mut process = Process::start(&path, &["--no-reload"]);
        process.wait_for("Servers ready").await;
        let stable = query(port, "stable.example.").await;
        config[0]["fake_ip"]["https_records"] = "suppress".into();
        std::fs::write(&path, config.to_string()).unwrap();
        process.signal(libc::SIGHUP);
        process.wait_for("Servers ready").await;
        assert_eq!(query(port, "stable.example.").await, stable);
        process.signal(libc::SIGTERM);
        assert!(process.exit().await.success());
        assert_eq!(
            std::fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let mut process = Process::start(&path, &["--no-reload"]);
        process.wait_for("Servers ready").await;
        assert_eq!(query(port, "stable.example.").await, stable);
        let uncheckpointed = query(port, "crash.example.").await;
        process.signal(libc::SIGKILL);
        assert!(!process.exit().await.success());

        let mut process = Process::start(&path, &["--no-reload"]);
        process.wait_for("Servers ready").await;
        assert_eq!(query(port, "stable.example.").await, stable);
        assert_ne!(query(port, "crash.example.").await, uncheckpointed);
        process.signal(libc::SIGTERM);
        assert!(process.exit().await.success());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn fake_dns_reload_checkpoint_failure_keeps_the_service_available() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        let state = directory.path().join("fake.json");
        let port = available_address().port();
        let config = json!([
            {"dns_group":"shared", "dns_servers":"udp://127.0.0.1:9",
             "fake_ip":{"state_file":state,"max_entries":16}},
            {"address":format!("0.0.0.0:{port}"),"protocol":{"type":"socks","udp_enabled":true},
             "dns":{"servers":"shared"}}
        ]);
        std::fs::write(&path, config.to_string()).unwrap();
        let mut process = Process::start(&path, &["--no-reload"]);
        process.wait_for("Servers ready").await;
        let stable = query(port, "stable.example.").await;
        std::fs::remove_file(&state).unwrap();
        std::fs::create_dir(&state).unwrap();
        process.signal(libc::SIGHUP);
        process.wait_for("Servers ready").await;
        assert_eq!(query(port, "stable.example.").await, stable);
        std::fs::remove_dir(&state).unwrap();
        process.signal(libc::SIGTERM);
        assert!(process.exit().await.success());
        assert!(state.is_file());
    })
    .await
    .unwrap();
}
