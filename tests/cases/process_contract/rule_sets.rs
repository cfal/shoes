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

fn check_config(path: &Path, error: Option<&str>) {
    for mode in ["check", "--dry-run"] {
        let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
            .args([mode, "-t", "1"])
            .arg(path)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.success(), error.is_none(), "{mode}: {stderr}");
        if let Some(error) = error {
            assert!(stderr.contains(error), "{mode}: {stderr}");
        }
    }
}

#[tokio::test]
async fn binary_sources_route_inline_and_named_and_reject_corrupt_reloads() {
    let echo = shoes_test_support::test_servers::start_tcp_stream_echo_server("0.0.0.0", 0)
        .await
        .unwrap();
    for (format, bytes, hit, miss) in [
        (
            "srs",
            include_bytes!("../../fixtures/rule_sets/singbox-v2.srs").as_slice(),
            "192.0.2.1:443",
            "198.51.100.1:443",
        ),
        (
            "mrs-domain",
            include_bytes!("../../fixtures/rule_sets/mihomo-domain.mrs").as_slice(),
            "exact.example:443",
            "other.example:443",
        ),
        (
            "mrs-ip",
            include_bytes!("../../fixtures/rule_sets/mihomo-ip.mrs").as_slice(),
            "192.0.2.1:443",
            "198.51.100.1:443",
        ),
    ] {
        for named in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let config_path = dir.path().join("config.yaml");
            let source = dir.path().join("list.data");
            std::fs::write(&source, bytes).unwrap();
            let mut config = Vec::new();
            let masks = if named {
                config.push(json!({"rule_group": "binary", "rule": "list.data"}));
                json!({"rule_group": "binary"})
            } else {
                json!({"path": "list.data"})
            };
            let reservations = [
                std::net::TcpListener::bind("0.0.0.0:0").unwrap(),
                std::net::TcpListener::bind("0.0.0.0:0").unwrap(),
            ];
            let addresses = reservations.each_ref().map(|listener| {
                std::net::SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()))
            });
            for (address, target) in addresses.into_iter().zip([hit, miss]) {
                config.push(json!({
                    "address": address.to_string(),
                    "protocol": {"type": "forward", "target": target},
                    "rules": [
                        {"masks": masks, "no_resolve": true,
                         "override_address": format!("127.0.0.1:{}", echo.local_addr().port())},
                        "block-all"
                    ]
                }));
            }
            std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
            // Check modes must validate sources without binding occupied listeners.
            check_config(&config_path, None);
            drop(reservations);
            let mut process = Process::start(&config_path, &[]);
            process.wait_for("Servers ready").await;
            roundtrip(&mut TcpStream::connect(addresses[0]).await.unwrap()).await;
            blocked(addresses[1]).await;

            std::fs::write(&source, &bytes[..4]).unwrap();
            process.wait_for("Reload rejected").await;
            check_config(&config_path, Some("list.data"));
            roundtrip(&mut TcpStream::connect(addresses[0]).await.unwrap()).await;
            blocked(addresses[1]).await;

            std::fs::write(&source, bytes).unwrap();
            process.wait_for("Servers ready").await;
            roundtrip(&mut TcpStream::connect(addresses[0]).await.unwrap()).await;
            process.signal(libc::SIGTERM);
            assert!(process.exit().await.success(), "{format}, named={named}");
        }
    }
}

#[tokio::test]
async fn source_groups_route_socks_udp_names_ips_and_ports_without_dns() {
    use shoes_test_support::socks5::{Socks5UdpAssociation, SocksDestination};

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("domains.mrs"),
        include_bytes!("../../fixtures/rule_sets/mihomo-domain.mrs"),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("ips.mrs"),
        include_bytes!("../../fixtures/rule_sets/mihomo-ip.mrs"),
    )
    .unwrap();
    let echo =
        shoes_test_support::test_servers::start_udp_echo_server_with_suffix("0.0.0.0", 0, b"")
            .await
            .unwrap();
    let dns = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let address = available_address();
    let config_path = dir.path().join("config.yaml");
    let config = json!([
        {"rule_group": "sources", "rules": ["domains.mrs", {"path": "ips.mrs"}]},
        {"address": address.to_string(), "protocol": {"type": "socks"},
         "dns": {"servers": format!("udp://127.0.0.1:{}", dns.local_addr().unwrap().port())},
         "rules": [
            {"masks": {"not": {"ip_cidr": ["192.0.2.0/24"]}}, "no_resolve": true, "action": "block"},
            {"masks": {"all": [{"rule_group": "sources"}, {"destination_port": [443]}]},
             "no_resolve": true, "override_address": format!("127.0.0.1:{}", echo.local_addr().port())},
            "block-all"
         ]}
    ]);
    std::fs::write(&config_path, config.to_string()).unwrap();
    let mut process = Process::start(&config_path, &["--no-reload"]);
    process.wait_for("Servers ready").await;
    let udp = Socks5UdpAssociation::connect("127.0.0.1", address.port())
        .await
        .unwrap();
    for target in [
        SocksDestination::Hostname("exact.example".into(), 443),
        SocksDestination::Ip("192.0.2.1:443".parse().unwrap()),
        SocksDestination::Hostname("exact.example".into(), 444),
        SocksDestination::Ip("192.0.2.1:444".parse().unwrap()),
        SocksDestination::Hostname("other.example".into(), 443),
        SocksDestination::Ip("198.51.100.1:443".parse().unwrap()),
    ] {
        let allowed = matches!(&target, SocksDestination::Hostname(name, 443) if name == "exact.example")
            || target == SocksDestination::Ip("192.0.2.1:443".parse().unwrap());
        let result = udp
            .send_to_with_timeout(target.clone(), b"source route", Duration::from_secs(1))
            .await;
        if allowed {
            assert_eq!(result.unwrap(), b"source route", "{target:?}");
        } else {
            assert_eq!(
                result.unwrap_err().kind(),
                std::io::ErrorKind::TimedOut,
                "{target:?}"
            );
        }
    }
    assert_eq!(
        udp.send_to_hostname("exact.example", 443, b"still usable")
            .await
            .unwrap(),
        b"still usable"
    );
    assert!(
        timeout(Duration::from_millis(100), dns.recv(&mut [0; 512]))
            .await
            .is_err(),
        "no_resolve routing issued a DNS query"
    );
    drop(udp);
    process.signal(libc::SIGTERM);
    assert!(process.exit().await.success());
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
    check_config(&config_path, Some("rule group deny"));

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
    check_config(&config_path, Some("nested.json"));
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
