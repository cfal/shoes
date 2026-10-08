use std::io::{self, BufRead};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

struct Process {
    child: Child,
    lines: tokio::sync::mpsc::UnboundedReceiver<String>,
}

impl Process {
    fn start(path: &Path, arguments: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_shoes"))
            .args(["-t", "1"])
            .args(arguments)
            .arg(path)
            .env("RUST_LOG", "error")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (tx, lines) = tokio::sync::mpsc::unbounded_channel();
        let readers: Vec<Box<dyn io::Read + Send>> = vec![
            Box::new(child.stdout.take().unwrap()),
            Box::new(child.stderr.take().unwrap()),
        ];
        for reader in readers {
            let tx = tx.clone();
            std::thread::spawn(move || {
                for line in io::BufReader::new(reader).lines().map_while(Result::ok) {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });
        }
        Self { child, lines }
    }

    async fn wait_for(&mut self, marker: &str) {
        let mut seen = String::new();
        let result = timeout(Duration::from_secs(8), async {
            while let Some(line) = self.lines.recv().await {
                seen.push_str(&line);
                seen.push('\n');
                if line.contains(marker) {
                    return;
                }
            }
            panic!("process exited waiting for {marker}: {seen}");
        })
        .await;
        assert!(result.is_ok(), "timed out waiting for {marker}: {seen}");
    }

    async fn exit(&mut self) -> ExitStatus {
        timeout(Duration::from_secs(8), async {
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("process did not exit")
    }

    #[cfg(unix)]
    fn signal(&self, signal: i32) {
        assert_eq!(unsafe { libc::kill(self.child.id() as i32, signal) }, 0);
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn available_address() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn forward(address: SocketAddr, target: SocketAddr) -> String {
    format!(
        "- global_limits: {{reload_grace_secs: 2}}\n- address: '{address}'\n  protocol:\n    type: forward\n    target: '{target}'\n"
    )
}

async fn roundtrip(stream: &mut TcpStream) {
    timeout(Duration::from_secs(2), async {
        stream.write_all(b"still serving").await.unwrap();
        let mut response = [0; 13];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"still serving");
    })
    .await
    .unwrap();
}

fn invalid_protocol_configs(address: SocketAddr) -> Vec<String> {
    use serde_json::json;
    let reality = json!({
        "type": "reality", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "sni_hostname": "example.com", "protocol": {"type": "socks"}
    });
    let mut bad_key = reality.clone();
    bad_key["public_key"] = json!("invalid");
    let mut bad_sni = reality.clone();
    bad_sni["sni_hostname"] = json!("invalid name");
    let mut ipv4_sni = reality.clone();
    ipv4_sni["sni_hostname"] = json!("127.0.0.1");
    let mut ipv6_sni = reality.clone();
    ipv6_sni["sni_hostname"] = json!("::1");
    let mut nested_direct = reality.clone();
    nested_direct["protocol"] = json!({"type": "direct"});
    let mut missing_sni = reality;
    missing_sni.as_object_mut().unwrap().remove("sni_hostname");
    let padding = json!({"type": "anytls", "password": "test", "padding_scheme": ["stop=invalid"]});
    let protocols = [
        bad_key,
        bad_sni,
        missing_sni,
        ipv4_sni,
        ipv6_sni,
        nested_direct,
        padding.clone(),
        json!({"type": "tls", "protocol": {"type": "direct"}}),
        json!({"type": "shadowtls", "password": "test", "protocol": {"type": "direct"}}),
        json!({"type": "websocket", "protocol": {"type": "direct"}}),
    ];
    let mut configs: Vec<_> = protocols
        .iter()
        .map(|protocol| {
            serde_yaml::to_string(&json!([{
                "address": address.to_string(), "protocol": {"type": "http"},
                "rules": [{"masks": "0.0.0.0/0", "client_proxy": {
                    "address": "127.0.0.1:443", "protocol": protocol
                }}]
            }]))
            .unwrap()
        })
        .collect();
    let mut invalid_chains: Vec<_> = protocols
        .into_iter()
        .map(|protocol| {
            json!({
                "address": "127.0.0.1:443", "protocol": protocol
            })
        })
        .collect();
    invalid_chains.extend([
        json!("missing-group"),
        json!(["direct", "direct"]),
        json!({"address": "127.0.0.1:443", "protocol": {
            "type": "tls", "cert": "-----BEGIN CERTIFICATE-----bad",
            "key": "-----BEGIN PRIVATE KEY-----bad", "protocol": {"type": "socks"}
        }}),
    ]);
    for chain in invalid_chains {
        for protocol in handshake_protocols(chain) {
            configs.push(
                serde_yaml::to_string(&json!([{
                    "address": address.to_string(), "protocol": protocol
                }]))
                .unwrap(),
            );
        }
    }
    configs.push(
        serde_yaml::to_string(&json!([{"address": address.to_string(), "protocol": padding}]))
            .unwrap(),
    );
    configs
}

fn handshake_protocols(chain: serde_json::Value) -> [serde_json::Value; 2] {
    use serde_json::json;
    [
        json!({"type": "tls", "reality_targets": {"example.com": {
            "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "dest": "example.com:443", "dest_client_chain": chain,
            "protocol": {"type": "socks"}
        }}}),
        json!({"type": "tls", "shadowtls_targets": {"example.com": {
            "password": "test", "handshake": {
                "address": "example.com:443", "client_chain": chain
            }, "protocol": {"type": "socks"}
        }}}),
    ]
}

#[tokio::test]
async fn handshake_chains_expand_groups_and_load_certificates() {
    use serde_json::json;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let cert_path = directory.path().join("client.pem");
    let key_path = directory.path().join("client.key");
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
    let client = json!({"address": "127.0.0.1:443", "protocol": {
        "type": "tls", "cert": cert_path, "key": key_path,
        "protocol": {"type": "socks"}
    }});
    for chain in [json!("fallback"), client.clone()] {
        for protocol in handshake_protocols(chain) {
            let config = json!([
                {"client_group": "fallback", "client_proxies": [client.clone(), client.clone()]},
                {"address": available_address().to_string(), "protocol": protocol}
            ]);
            std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
            let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
                .args(["check", "-t", "1"])
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let mut child = Process::start(&path, &["--no-reload"]);
            child.wait_for("Servers ready").await;
        }
    }
}

#[test]
fn check_rejects_invalid_protocol_constructor_settings() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    for config in invalid_protocol_configs(available_address()) {
        std::fs::write(&path, config).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
            .args(["check", "-t", "1"])
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(!error.contains("panicked"), "{error}");
    }
}

#[tokio::test]
async fn check_alias_and_validation_exit_codes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let valid = format!(
        "- address: '{}'\n  protocol: {{type: http}}\n",
        occupied.local_addr().unwrap()
    );
    for option in ["--dry-run", "check"] {
        for (config, expected) in [
            (valid.as_str(), 0),
            (
                "- address: '127.0.0.1:1'\n  transport: udp\n  protocol: {type: http}\n",
                1,
            ),
            ("not: [valid", 1),
        ] {
            std::fs::write(&path, config).unwrap();
            let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
                .args([option, "-t", "1"])
                .arg(&path)
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(expected),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
        }
    }
    std::fs::remove_file(&path).unwrap();
    let mut child = Process::start(&path, &[]);
    assert_eq!(child.exit().await.code(), Some(1));
    let version = Command::new(env!("CARGO_BIN_EXE_shoes"))
        .arg("version")
        .output()
        .unwrap();
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8(version.stdout).unwrap().trim(),
        concat!("shoes ", env!("CARGO_PKG_VERSION"))
    );
}

#[tokio::test]
async fn initial_partial_bind_failure_exits_and_releases_addresses() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let first = available_address();
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    for config in [
        format!(
            "- address: ['{first}', '{}']\n  protocol: {{type: http}}\n",
            occupied.local_addr().unwrap()
        ),
        format!(
            "- address: '{first}'\n  protocol: {{type: http}}\n- address: '{}'\n  protocol: {{type: http}}\n",
            occupied.local_addr().unwrap()
        ),
    ] {
        std::fs::write(&path, config).unwrap();
        let mut child = Process::start(&path, &["--no-reload"]);
        assert_eq!(child.exit().await.code(), Some(1));
        std::net::TcpListener::bind(first).unwrap();
    }
}

#[cfg(unix)]
#[tokio::test]
async fn rejected_reload_preserves_traffic_and_valid_reload_drains_tcp() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let echo = shoes_test_support::test_servers::start_tcp_stream_echo_server("127.0.0.1", 0)
        .await
        .unwrap();
    let address = available_address();
    let valid = forward(address, echo.local_addr());
    std::fs::write(&path, &valid).unwrap();
    let mut child = Process::start(&path, &["--no-reload"]);
    child.wait_for("Servers ready").await;
    let mut existing = TcpStream::connect(address).await.unwrap();
    roundtrip(&mut existing).await;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mismatched_identity = serde_yaml::to_string(&serde_json::json!([{
        "address": address.to_string(),
        "protocol": {"type": "tls", "tls_targets": {"localhost": {
            "cert": cert.cert.pem(),
            "key": other.signing_key.serialize_pem(),
            "protocol": {"type": "http"}
        }}}
    }]))
    .unwrap();
    let mut invalid_configs = vec![
        "invalid: [yaml".to_owned(),
        format!(
            "- address: '{address}'\n  protocol:\n    type: tls\n    tls_targets:\n      localhost:\n        cert: absent.pem\n        key: absent.key\n        protocol: {{type: http}}\n"
        ),
        format!(
            "- address: '{address}'\n  protocol:\n    type: tls\n    tls_targets:\n      localhost:\n        cert: '-----BEGIN CERTIFICATE-----bad'\n        key: '-----BEGIN PRIVATE KEY-----bad'\n        protocol: {{type: http}}\n"
        ),
        mismatched_identity,
    ];
    invalid_configs.extend(invalid_protocol_configs(address));
    if cfg!(target_os = "linux") {
        invalid_configs.push(format!("{valid}\n- dns_group: failing\n  dns_servers:\n    - url: udp://127.0.0.1\n      client_chain:\n        address: '127.0.0.1:443'\n        transport: quic\n        bind_interface: shoes-missing-interface\n        protocol: {{type: socks}}\n"));
    }
    for invalid in invalid_configs {
        std::fs::write(&path, invalid).unwrap();
        child.signal(libc::SIGHUP);
        child.wait_for("Reload rejected").await;
        roundtrip(&mut existing).await;
        roundtrip(&mut TcpStream::connect(address).await.unwrap()).await;
    }
    std::fs::write(&path, valid).unwrap();
    child.signal(libc::SIGHUP);
    child.wait_for("Servers ready").await;
    roundtrip(&mut existing).await;
    roundtrip(&mut TcpStream::connect(address).await.unwrap()).await;
    let result = timeout(Duration::from_secs(4), existing.read_u8())
        .await
        .unwrap();
    assert!(result.is_err());
    child.signal(libc::SIGTERM);
    assert_eq!(child.exit().await.code(), Some(0));
}

#[cfg(unix)]
#[tokio::test]
async fn shutdown_interrupts_watcher_debounce() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let config = format!(
        "- address: '{}'\n  protocol: {{type: http}}\n",
        available_address()
    );
    std::fs::write(&path, &config).unwrap();
    let mut child = Process::start(&path, &[]);
    child.wait_for("Servers ready").await;
    std::fs::write(&path, config).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    child.signal(libc::SIGTERM);
    assert_eq!(
        timeout(Duration::from_secs(2), child.exit())
            .await
            .unwrap()
            .code(),
        Some(0)
    );
}

#[cfg(unix)]
#[tokio::test]
async fn sighup_completes_pending_file_reload_without_waiting_for_debounce() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let config = format!(
        "- address: '{}'\n  protocol: {{type: http}}\n",
        available_address()
    );
    std::fs::write(&path, &config).unwrap();
    let mut child = Process::start(&path, &[]);
    child.wait_for("Servers ready").await;
    std::fs::write(&path, config).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    child.signal(libc::SIGHUP);
    timeout(Duration::from_secs(2), child.wait_for("Servers ready"))
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(3500), async {
            while let Some(line) = child.lines.recv().await {
                assert!(!line.contains("Servers ready"), "duplicate reload");
            }
        })
        .await
        .is_err()
    );
    child.signal(libc::SIGTERM);
    assert_eq!(child.exit().await.code(), Some(0));
}

#[cfg(unix)]
#[tokio::test]
async fn atomic_replace_keeps_serving_through_debounce() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let echo = shoes_test_support::test_servers::start_tcp_stream_echo_server("127.0.0.1", 0)
        .await
        .unwrap();
    let address = available_address();
    let valid = forward(address, echo.local_addr());
    std::fs::write(&path, &valid).unwrap();
    let mut child = Process::start(&path, &[]);
    child.wait_for("Servers ready").await;
    let replacement = directory.path().join("replacement.yaml");
    std::fs::write(&replacement, &valid).unwrap();
    std::fs::rename(replacement, &path).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    roundtrip(&mut TcpStream::connect(address).await.unwrap()).await;
    child.wait_for("Servers ready").await;
    roundtrip(&mut TcpStream::connect(address).await.unwrap()).await;
    child.signal(libc::SIGINT);
    assert_eq!(child.exit().await.code(), Some(0));
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_targets_remain_watched_after_retargeting() {
    let directory = tempfile::tempdir().unwrap();
    let targets = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let first = targets.path().join("first.yaml");
    let second = targets.path().join("second.yaml");
    let config = format!(
        "- address: '{}'\n  protocol: {{type: http}}\n",
        available_address()
    );
    std::fs::write(&first, &config).unwrap();
    std::fs::write(&second, &config).unwrap();
    std::os::unix::fs::symlink(&first, &path).unwrap();
    let mut child = Process::start(&path, &[]);
    child.wait_for("Servers ready").await;
    std::fs::write(&first, &config).unwrap();
    child.wait_for("Servers ready").await;
    let link = directory.path().join("replacement.yaml");
    std::os::unix::fs::symlink(&second, &link).unwrap();
    std::fs::rename(link, &path).unwrap();
    child.wait_for("Servers ready").await;
    std::fs::write(&second, &config).unwrap();
    child.wait_for("Servers ready").await;
    std::fs::remove_file(&second).unwrap();
    child.wait_for("Reload rejected").await;
    std::fs::write(&second, &config).unwrap();
    child.wait_for("Servers ready").await;
    let missing = targets.path().join("missing.yaml");
    let link = directory.path().join("replacement.yaml");
    std::os::unix::fs::symlink(&missing, &link).unwrap();
    std::fs::rename(link, &path).unwrap();
    child.wait_for("Reload rejected").await;
    std::fs::write(&missing, &config).unwrap();
    child.wait_for("Servers ready").await;
    child.signal(libc::SIGTERM);
    assert_eq!(child.exit().await.code(), Some(0));
}

#[cfg(unix)]
#[tokio::test]
async fn shutdown_interrupts_dns_preparation_without_retiring_listeners() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let echo = shoes_test_support::test_servers::start_tcp_stream_echo_server("127.0.0.1", 0)
        .await
        .unwrap();
    let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = available_address();
    let valid = forward(address, echo.local_addr());
    std::fs::write(&path, &valid).unwrap();
    let mut child = Process::start(&path, &["--no-reload"]);
    child.wait_for("Servers ready").await;
    std::fs::write(&path, format!("{valid}\n- dns_group: pending\n  dns_servers:\n    - url: https://pending.test/dns-query\n      bootstrap_url: udp://{}\n", blackhole.local_addr().unwrap())).unwrap();
    child.signal(libc::SIGHUP);
    timeout(Duration::from_secs(3), blackhole.recv(&mut [0; 512]))
        .await
        .unwrap()
        .unwrap();
    roundtrip(&mut TcpStream::connect(address).await.unwrap()).await;
    child.signal(libc::SIGTERM);
    assert_eq!(
        timeout(Duration::from_secs(2), child.exit())
            .await
            .unwrap()
            .code(),
        Some(0)
    );
}

#[cfg(unix)]
#[tokio::test]
async fn replacement_bind_failure_is_fatal_and_cleans_partial_generation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let address = available_address();
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let config = format!("- address: '{address}'\n  protocol: {{type: http}}\n");
    std::fs::write(&path, &config).unwrap();
    let mut child = Process::start(&path, &["--no-reload"]);
    child.wait_for("Servers ready").await;
    std::fs::write(
        &path,
        format!(
            "{config}- address: '{}'\n  protocol: {{type: http}}\n",
            occupied.local_addr().unwrap()
        ),
    )
    .unwrap();
    child.signal(libc::SIGHUP);
    assert_eq!(child.exit().await.code(), Some(1));
    std::net::TcpListener::bind(address).unwrap();
}
