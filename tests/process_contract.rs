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

#[cfg(unix)]
#[path = "cases/wireguard_support.rs"]
mod wireguard_support;

#[cfg(unix)]
#[path = "cases/process_contract/wireguard_dns.rs"]
mod wireguard_dns;

#[cfg(unix)]
#[path = "cases/process_contract/fake_dns.rs"]
mod fake_dns;

#[cfg(unix)]
#[path = "cases/process_contract/rule_sets.rs"]
mod rule_sets;

#[cfg(unix)]
#[path = "cases/process_contract/clash_api.rs"]
mod clash_api;

#[cfg(unix)]
#[path = "cases/process_contract/certificates.rs"]
mod certificates;

#[cfg(unix)]
#[tokio::test]
async fn wireguard_reload_retains_invalid_candidates_rebinds_and_releases_on_exit() {
    wireguard_reload(false).await;
}

#[cfg(unix)]
#[tokio::test]
async fn wireguard_outer_chain_reload_retains_invalid_candidates_and_releases_on_exit() {
    wireguard_reload(true).await;
}

#[cfg(unix)]
#[test]
fn wireguard_check_validates_outer_udp_without_dns_or_listeners() {
    use serde_json::json;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let occupied = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let server = wireguard_support::server(occupied.local_addr().unwrap().port());
    let mut endpoint = wireguard_support::client(51820);
    endpoint["client_proxies"][0]["address"] = json!("unresolvable.invalid:51820");
    for mode in ["check", "--dry-run"] {
        for (protocol, valid) in [
            (json!({"type": "socks"}), false),
            (json!({"type": "trojan", "password": "test"}), false),
            (
                json!({"type": "vless", "user_id": shoes_test_support::test_fixture::TEST_UUID, "udp_enabled": false}),
                false,
            ),
            (wireguard_support::vless_protocol(), true),
        ] {
            endpoint["client_proxies"][0]["protocol"]["peer_client_chain"] = json!([{
                "address": "unresolvable.invalid:443", "protocol": protocol,
                "transport": "quic",
            }]);
            if cfg!(any(
                target_os = "android",
                target_os = "fuchsia",
                target_os = "linux"
            )) {
                endpoint["client_proxies"][0]["protocol"]["peer_client_chain"][0]["bind_interface"] =
                    json!("shoes-missing-interface");
            }
            let config = json!([server, endpoint]);
            std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
            let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
                .args([mode, "-t", "1"])
                .arg(&path)
                .output()
                .unwrap();
            let error = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.success(), valid, "{error}");
            if !valid {
                assert!(error.contains("does not support UDP"), "{error}");
            }
        }
        let mut invalid = wireguard_support::server(51820);
        invalid["protocol"]["addresses"] = json!(["255.255.255.255/32"]);
        std::fs::write(&path, serde_yaml::to_string(&json!([invalid])).unwrap()).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
            .args([mode, "-t", "1"])
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("unicast local address"));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn wireguard_conflicting_shared_client_reload_retains_live_flows() {
    use serde_json::json;
    use shoes_test_support::socks5::Socks5UdpAssociation;
    use shoes_test_support::wireguard::{EchoTargets, connect};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    let mut ports = shoes_test_support::port_helper::PortHelper::new();
    let (_, entry) = ports.get_localhost_listener_port();
    let first = wireguard_support::client(port);
    let mut second = first.clone();
    second["client_group"] = json!("copy");
    let mut socks = wireguard_support::socks(entry);
    socks["rules"][0]["client_chain"] = json!([{"pool": ["wg", "copy"]}]);
    let mut configs = json!([wireguard_support::server(port), first, second, socks]);
    std::fs::write(&path, serde_yaml::to_string(&configs).unwrap()).unwrap();
    drop(socket);
    let mut process = Process::start(&path, &["--no-reload"]);
    process.wait_for("Servers ready").await;
    let echo = EchoTargets::new(false).await.unwrap();
    let mut tcp = connect(entry, echo.tcp()).await.unwrap();
    let udp = Socks5UdpAssociation::connect("127.0.0.1", entry)
        .await
        .unwrap();
    roundtrip(&mut tcp).await;
    assert_eq!(udp.send_to(echo.udp(), b"before").await.unwrap(), b"before");

    configs[2]["client_proxies"][0]["protocol"]["pre_shared_key"] =
        json!(wireguard_support::key(44));
    std::fs::write(&path, serde_yaml::to_string(&configs).unwrap()).unwrap();
    process.signal(libc::SIGHUP);
    process
        .wait_for("conflicting WireGuard client settings")
        .await;
    roundtrip(&mut tcp).await;
    assert_eq!(udp.send_to(echo.udp(), b"after").await.unwrap(), b"after");
    echo.check(entry, None).await.unwrap();

    process.signal(libc::SIGTERM);
    assert!(process.exit().await.success());
    std::net::UdpSocket::bind(("0.0.0.0", port)).unwrap();
    std::net::TcpListener::bind(("0.0.0.0", entry)).unwrap();
}

#[cfg(unix)]
async fn wireguard_reload(detour: bool) {
    use serde_json::json;
    let directory = tempfile::tempdir().unwrap();
    let server_path = directory.path().join("server.yaml");
    let client_path = directory.path().join("client.yaml");
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    let mut ports = shoes_test_support::port_helper::PortHelper::new();
    let (_, entry) = ports.get_localhost_listener_port();
    let mut servers = vec![wireguard_support::server(port)];
    let mut endpoint = wireguard_support::client(port);
    if detour {
        let (_, outer_port) = ports.get_localhost_listener_port();
        let protocol = wireguard_support::vless_protocol();
        endpoint["client_proxies"][0]["address"] = json!(format!("192.0.2.200:{port}"));
        endpoint["client_proxies"][0]["protocol"]["peer_client_chain"] =
            json!([{"address": format!("127.0.0.1:{outer_port}"), "protocol": protocol}]);
        servers.push(json!({
            "address": format!("0.0.0.0:{outer_port}"), "protocol": protocol,
            "rules": [{"masks": "192.0.2.200/32", "action": "allow", "override_address": "127.0.0.1:0"}],
        }));
    }
    let server_config = serde_yaml::to_string(&servers).unwrap();
    let mut client_configs = json!([endpoint, wireguard_support::socks(entry)]);
    let client_config = serde_yaml::to_string(&client_configs).unwrap();
    std::fs::write(&server_path, &server_config).unwrap();
    std::fs::write(&client_path, &client_config).unwrap();
    drop(socket);
    let mut server = Process::start(&server_path, &["--no-reload"]);
    let mut client = Process::start(&client_path, &["--no-reload"]);
    server.wait_for("Servers ready").await;
    client.wait_for("Servers ready").await;
    let echo = shoes_test_support::wireguard::EchoTargets::new(false)
        .await
        .unwrap();
    let mut active = shoes_test_support::wireguard::connect(entry, echo.tcp())
        .await
        .unwrap();
    roundtrip(&mut active).await;
    if detour {
        client_configs[0]["client_proxies"][0]["protocol"]["peer_client_chain"][0]["protocol"]["udp_enabled"] =
            json!(false);
    } else {
        client_configs[1]["rules"][0]["client_chain"] = json!("missing");
    }
    let invalid = serde_yaml::to_string(&client_configs).unwrap();
    assert_ne!(invalid, client_config);
    std::fs::write(&client_path, invalid).unwrap();
    client.signal(libc::SIGHUP);
    client.wait_for("Reload rejected").await;
    roundtrip(&mut active).await;
    std::fs::write(&client_path, &client_config).unwrap();
    client.signal(libc::SIGHUP);
    client.wait_for("Servers ready").await;
    let mut byte = [0; 1];
    assert!(!matches!(
        timeout(Duration::from_secs(3), active.read(&mut byte)).await,
        Ok(Ok(1)) | Err(_)
    ));
    let udp = shoes_test_support::socks5::Socks5UdpAssociation::connect("127.0.0.1", entry)
        .await
        .unwrap();
    assert_eq!(
        udp.send_to(echo.udp(), b"before server reload")
            .await
            .unwrap(),
        b"before server reload"
    );
    server.signal(libc::SIGHUP);
    server.wait_for("Servers ready").await;
    // The unchanged client must replace its stale handshake without operator intervention.
    timeout(Duration::from_secs(45), async {
        loop {
            match udp
                .send_to_with_timeout(
                    shoes_test_support::socks5::SocksDestination::Ip(echo.udp()),
                    b"after server reload",
                    Duration::from_secs(1),
                )
                .await
            {
                Ok(bytes) => {
                    assert_eq!(bytes, b"after server reload");
                    break;
                }
                Err(error) => assert_eq!(error.kind(), io::ErrorKind::TimedOut),
            }
        }
    })
    .await
    .unwrap();
    echo.check(entry, None).await.unwrap();

    // A new association excludes delayed recovery replies from the revocation check.
    drop(udp);
    let udp = shoes_test_support::socks5::Socks5UdpAssociation::connect("127.0.0.1", entry)
        .await
        .unwrap();
    assert_eq!(
        udp.send_to(echo.udp(), b"old key").await.unwrap(),
        b"old key"
    );
    let mut old_stream = shoes_test_support::wireguard::connect(entry, echo.tcp())
        .await
        .unwrap();
    roundtrip(&mut old_stream).await;
    servers[0]["protocol"]["peers"][0]["public_key"] = json!(wireguard_support::public(44));
    std::fs::write(&server_path, serde_yaml::to_string(&servers).unwrap()).unwrap();
    server.signal(libc::SIGHUP);
    server.wait_for("Servers ready").await;
    assert!(
        udp.send_to_with_timeout(
            shoes_test_support::socks5::SocksDestination::Ip(echo.udp()),
            b"revoked key",
            Duration::from_secs(2),
        )
        .await
        .is_err()
    );
    let old_flow = async {
        old_stream.write_all(b"revoked key").await?;
        old_stream.read_exact(&mut [0; 11]).await
    };
    assert!(!matches!(
        timeout(Duration::from_secs(2), old_flow).await,
        Ok(Ok(_))
    ));
    // A fresh old-key device distinguishes revocation from a stale handshake after reload.
    client.signal(libc::SIGHUP);
    client.wait_for("Servers ready").await;
    let revoked = shoes_test_support::socks5::Socks5UdpAssociation::connect("127.0.0.1", entry)
        .await
        .unwrap();
    assert_eq!(
        revoked
            .send_to_with_timeout(
                shoes_test_support::socks5::SocksDestination::Ip(echo.udp()),
                b"fresh revoked key",
                Duration::from_secs(3),
            )
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert!(!matches!(
        timeout(
            Duration::from_secs(3),
            shoes_test_support::wireguard::connect(entry, echo.tcp())
        )
        .await,
        Ok(Ok(_))
    ));
    let mut rotated: serde_json::Value = serde_yaml::from_str(&client_config).unwrap();
    rotated[0]["client_proxies"][0]["protocol"]["private_key"] = json!(wireguard_support::key(44));
    std::fs::write(&client_path, serde_yaml::to_string(&rotated).unwrap()).unwrap();
    client.signal(libc::SIGHUP);
    client.wait_for("Servers ready").await;
    echo.check(entry, None).await.unwrap();
    client.signal(libc::SIGTERM);
    server.signal(libc::SIGTERM);
    assert!(client.exit().await.success());
    assert!(server.exit().await.success());
    std::net::UdpSocket::bind(("0.0.0.0", port)).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn wireguard_partial_startup_releases_previously_started_endpoint() {
    use serde_json::json;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    let occupied = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let second = wireguard_support::server(occupied.local_addr().unwrap().port());
    std::fs::write(
        &path,
        serde_yaml::to_string(&json!([wireguard_support::server(port), second])).unwrap(),
    )
    .unwrap();
    drop(socket);
    let mut child = Process::start(&path, &["--no-reload"]);
    assert_eq!(child.exit().await.code(), Some(1));
    std::net::UdpSocket::bind(("0.0.0.0", port)).unwrap();
}

#[test]
fn vless_encryption_generator_prints_only_matched_yaml_credentials() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    for (args, expected_public_lengths, expected_private_lengths) in [
        (vec![], vec![1184], vec![64]),
        (
            vec![
                "--auth", "x25519", "--auth", "mlkem768", "--auth", "mlkem768",
            ],
            vec![32, 1184, 1184],
            vec![32, 64, 64],
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
            .arg("generate-vless-encryption")
            .args(&args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let values: serde_yaml::Value = serde_yaml::from_slice(&output.stdout).unwrap();
        assert_eq!(values.as_mapping().unwrap().len(), 2);
        let encryption = values["encryption"].as_str().unwrap();
        let decryption = values["decryption"].as_str().unwrap();
        assert!(!String::from_utf8_lossy(&output.stderr).contains(decryption));
        assert!(encryption.starts_with("mlkem768x25519plus.native.0rtt."));
        assert!(decryption.starts_with("mlkem768x25519plus.native.600s."));
        let public_lengths: Vec<_> = encryption
            .split('.')
            .skip(3)
            .map(|s| URL_SAFE_NO_PAD.decode(s).unwrap().len())
            .collect();
        let private_lengths: Vec<_> = decryption
            .split('.')
            .skip(3)
            .map(|s| URL_SAFE_NO_PAD.decode(s).unwrap().len())
            .collect();
        assert_eq!(public_lengths, expected_public_lengths);
        assert_eq!(private_lengths, expected_private_lengths);
    }
    for args in [
        vec!["--auth", "bad"],
        vec!["--rtt", "1rtt"],
        vec!["--lifetime", "0s"],
        vec!["--mode"],
        vec!["--mode", "random", "--mode", "native"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
            .arg("generate-vless-encryption")
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn vless_encryption_rejects_invalid_startup_without_credentials_in_diagnostics() {
    use serde_json::json;
    let directory = tempfile::Builder::new()
        .prefix("vless-invalid-")
        .tempdir_in(std::env::var_os("HOME").unwrap())
        .unwrap();
    let credential = "mlkem768x25519plus.native.600s.private-key-must-not-appear";
    for protocol in [
        json!({"type": "vless", "user_id": "550e8400-e29b-41d4-a716-446655440000", "decryption": credential}),
        json!({"type": "vless", "user_id": "550e8400-e29b-41d4-a716-446655440000", "vision": true}),
        json!({"type": "vless", "user_id": "550e8400-e29b-41d4-a716-446655440000", "encryption_limits": {"max_sessions": 0}}),
    ] {
        let address = available_address();
        let config = directory.path().join("invalid.json");
        std::fs::write(
            &config,
            serde_json::to_vec(&json!([{"address": address, "protocol": protocol}])).unwrap(),
        )
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
            .arg("--no-reload")
            .arg(&config)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let diagnostic = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !diagnostic.contains("private-key-must-not-appear"),
            "{diagnostic}"
        );
        assert!(!diagnostic.contains("Servers ready"), "{diagnostic}");
        assert!(std::net::TcpListener::bind(address).is_ok());
    }
}

#[test]
fn vless_wrong_side_credentials_fail_check_and_startup() {
    use serde_json::json;
    let directory = tempfile::Builder::new()
        .prefix("vless-wrong-side-")
        .tempdir_in(std::env::var_os("HOME").unwrap())
        .unwrap();
    for server in [false, true] {
        let address = available_address();
        let mut protocol = json!({
            "type": "vless", "user_id": "550e8400-e29b-41d4-a716-446655440000",
        });
        protocol[if server { "encryption" } else { "decryption" }] =
            json!("private-key-must-not-appear");
        let config = if server {
            json!([{"address": address, "protocol": protocol}])
        } else {
            json!([{"address": address, "protocol": {"type": "socks"},
                "rules": [{"masks": "0.0.0.0/0", "action": "allow", "client_chain": {
                    "address": "127.0.0.1:443", "protocol": protocol,
                }}],
            }])
        };
        let path = directory.path().join("invalid.json");
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        for operation in ["check", "--no-reload"] {
            let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
                .arg(operation)
                .arg(&path)
                .output()
                .unwrap();
            assert!(!output.status.success());
            let diagnostic = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                diagnostic.contains("Could not parse config file"),
                "{diagnostic}"
            );
            if server {
                assert!(diagnostic.contains("VLESS server uses decryption, not encryption"));
            }
            assert!(
                !diagnostic.contains("private-key-must-not-appear"),
                "{diagnostic}"
            );
            assert!(!diagnostic.contains("Servers ready"));
            assert!(std::net::TcpListener::bind(address).is_ok());
        }
    }
}

#[test]
fn reality_mldsa_keygen_outputs_interoperable_seed_and_key() {
    use aws_lc_rs::signature::{self, KeyPair};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
        .arg("generate-reality-mldsa65-keypair")
        .output()
        .unwrap();
    assert!(output.status.success());
    let values: serde_yaml::Value = serde_yaml::from_slice(&output.stdout).unwrap();
    let seed = URL_SAFE_NO_PAD
        .decode(values["mldsa65_seed"].as_str().unwrap())
        .unwrap();
    let verify = URL_SAFE_NO_PAD
        .decode(values["mldsa65_verify"].as_str().unwrap())
        .unwrap();
    assert_eq!(seed.len(), 32);
    assert_eq!(verify.len(), 1952);
    let signing = signature::PqdsaKeyPair::from_seed(&signature::ML_DSA_65_SIGNING, &seed).unwrap();
    assert_eq!(signing.public_key().as_ref(), verify);
}

impl Process {
    fn start(path: &Path, arguments: &[&str]) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_shoes"))
            .args(["-t", "1"])
            .args(arguments)
            .arg(path)
            .env("RUST_LOG", "error")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        Self::from_child(child)
    }

    fn from_child(mut child: Child) -> Self {
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

#[cfg(unix)]
#[tokio::test]
async fn tun_worker_failure_exits_nonzero_and_releases_other_listeners() {
    use std::os::fd::OwnedFd;
    for fail_at_startup in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        let address = available_address();
        std::fs::write(&path, format!(
            "- address: '{address}'\n  protocol: {{type: socks}}\n  rules: allow-all-direct\n- device_fd: 0\n  rules: allow-all-direct\n"
        )).unwrap();
        let (peer, tun) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut peer = Some(peer);
        if fail_at_startup {
            peer.take();
        }
        let child = Command::new(env!("CARGO_BIN_EXE_shoes"))
            .args(["-t", "1"])
            .arg(&path)
            .stdin(Stdio::from(OwnedFd::from(tun)))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut process = Process::from_child(child);
        if !fail_at_startup {
            process.wait_for("Servers ready").await;
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream.write_all(&[5, 1, 0]).await.unwrap();
            let mut greeting = [0; 2];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 0]);
            peer.take();
        }
        process.wait_for("TUN device closed (EOF)").await;
        assert!(!process.exit().await.success());
        std::net::TcpListener::bind(address).unwrap();
    }
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
    configs.extend(invalid_server_protocol_configs(address));
    configs.extend(invalid_server_auth_configs(address));
    configs
}

fn invalid_server_auth_configs(address: SocketAddr) -> Vec<String> {
    use serde_json::json;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let empty = json!({"type": "trojan", "password": ""});
    let tls_target = json!({"cert": cert.cert.pem(), "key": cert.signing_key.serialize_pem(), "protocol": empty});
    let xhttp = json!({"type": "xhttp", "protocol": empty});
    let mut xhttp_tls_target = tls_target.clone();
    xhttp_tls_target["protocol"] = xhttp.clone();
    let mut protocols = vec![
        empty.clone(),
        xhttp.clone(),
        json!({"type": "tls", "default_target": xhttp_tls_target}),
        json!({"type": "snell", "cipher": "aes-128-gcm", "password": ""}),
        json!({"type": "shadowsocks", "cipher": "aes-128-gcm", "password": ""}),
        json!({"type": "trojan", "password": "do-not-log-this-secret", "shadowsocks": {"cipher": "aes-128-gcm", "password": ""}}),
        json!({"type": "anytls", "users": [{"password": "do-not-log-this-secret"}, {"password": ""}]}),
        json!({"type": "websocket", "targets": {"protocol": empty}}),
        json!({"type": "tls", "default_target": tls_target}),
        json!({"type": "tls", "tls_targets": {"localhost": tls_target}}),
        json!({"type": "tls", "reality_targets": {"localhost": {
            "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "dest": "localhost:443", "protocol": empty
        }}}),
        json!({"type": "tls", "shadowtls_targets": {"localhost": {
            "password": "do-not-log-this-secret", "handshake": {"address": "localhost:443"}, "protocol": empty
        }}}),
    ];
    for handshake in [
        json!({"address": "localhost:443"}),
        json!({"cert": cert.cert.pem(), "key": cert.signing_key.serialize_pem()}),
    ] {
        protocols.push(json!({"type": "tls", "shadowtls_targets": {"localhost": {
            "password": "", "handshake": handshake, "protocol": {"type": "socks"}
        }}}));
    }
    let mut naive = tls_target;
    naive["protocol"] = json!({"type": "naive", "users": [
        {"username": "valid", "password": "do-not-log-this-secret"},
        {"username": "invalid", "password": ""}
    ]});
    protocols.push(json!({"type": "tls", "default_target": naive}));
    for cipher in ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"] {
        for password in ["", "eA=="] {
            protocols.push(json!({"type": "shadowsocks", "cipher": cipher, "password": password}));
        }
    }
    for protocol_type in ["http", "socks", "mixed"] {
        protocols.push(json!({"type": protocol_type, "username": "user", "password": ""}));
        protocols.push(json!({"type": protocol_type, "username": "user"}));
        if protocol_type != "http" {
            protocols.push(json!({"type": protocol_type, "password": "do-not-log-this-secret"}));
            protocols.push(json!({"type": protocol_type, "username": "u".repeat(256), "password": "do-not-log-this-secret"}));
        }
    }
    let mut configs: Vec<_> = protocols
        .into_iter()
        .map(|protocol| {
            json!([{
                "address": address.to_string(), "protocol": protocol
            }])
        })
        .collect();
    for protocol in [
        xhttp,
        json!({"type": "hysteria2", "password": ""}),
        json!({"type": "tuic", "uuid": "550e8400-e29b-41d4-a716-446655440000", "password": ""}),
    ] {
        configs.push(json!([{
            "address": address.to_string(), "transport": "quic", "protocol": protocol,
            "quic_settings": {"cert": cert.cert.pem(), "key": cert.signing_key.serialize_pem()}
        }]));
    }
    configs
        .into_iter()
        .map(|config| serde_yaml::to_string(&config).unwrap())
        .collect()
}

fn invalid_server_protocol_configs(address: SocketAddr) -> Vec<String> {
    use serde_json::json;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut protocols = Vec::new();
    for inner in [
        json!({"type": "hysteria2", "password": "do-not-log-this-secret"}),
        json!({"type": "tuic", "uuid": "550e8400-e29b-41d4-a716-446655440000", "password": "do-not-log-this-secret"}),
        json!({"type": "naive", "users": [{"username": "user", "password": "do-not-log-this-secret"}]}),
    ] {
        protocols.push(inner.clone());
        protocols.push(json!({"type": "xhttp", "protocol": inner}));
        protocols.push(json!({"type": "websocket", "targets": {"protocol": inner}}));
        protocols.push(json!({"type": "tls", "shadowtls_targets": {"localhost": {
            "password": "do-not-log-this-secret", "handshake": {"address": "localhost:443"}, "protocol": inner
        }}}));
        if inner["type"] != "naive" {
            let tls_target = json!({"cert": cert.cert.pem(), "key": cert.signing_key.serialize_pem(), "protocol": inner});
            protocols.push(json!({"type": "tls", "default_target": tls_target}));
            protocols.push(json!({"type": "tls", "tls_targets": {"localhost": tls_target}}));
            protocols.push(json!({"type": "tls", "reality_targets": {"localhost": {
                "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "dest": "localhost:443", "protocol": inner
            }}}));
        }
    }
    for inner in [
        json!({"type": "trojan", "password": "do-not-log-this-secret"}),
        json!({"type": "naive", "users": [{"username": "user", "password": "do-not-log-this-secret"}]}),
    ] {
        let target = json!({"cert": cert.cert.pem(), "key": cert.signing_key.serialize_pem(), "vision": true, "protocol": inner});
        protocols.push(json!({"type": "tls", "default_target": target}));
        protocols.push(json!({"type": "tls", "tls_targets": {"localhost": target}}));
        protocols.push(json!({"type": "tls", "reality_targets": {"localhost": {
            "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "dest": "localhost:443", "vision": true, "protocol": inner
        }}}));
    }
    protocols
        .into_iter()
        .map(|protocol| {
            serde_yaml::to_string(&json!([{
                "address": address.to_string(), "protocol": protocol
            }]))
            .unwrap()
        })
        .collect()
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
        assert!(!error.contains("do-not-log-this-secret"), "{error}");
    }
}

#[test]
fn startup_rejects_invalid_server_protocols_without_panics_or_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    for config in invalid_server_protocol_configs(available_address())
        .into_iter()
        .chain(invalid_server_auth_configs(available_address()))
    {
        std::fs::write(&path, config).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
            .args(["--no-reload", "-t", "1"])
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(!error.contains("panicked"), "{error}");
        assert!(!error.contains("do-not-log-this-secret"), "{error}");
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
    let empty_dns = format!("{valid}  dns: {{servers: []}}\n");
    for option in ["--dry-run", "check"] {
        for (config, expected) in [
            (valid.as_str(), 0),
            (empty_dns.as_str(), 0),
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
async fn unsupported_quic_allowlists_fail_validation_and_start() {
    use serde_json::json;
    let groups = json!({"key_exchange_groups": ["X25519MLKEM768"]});
    let direct = json!({"protocol": {"type": "direct"}});
    let guarded_direct =
        json!({"protocol": {"type": "direct"}, "transport": "quic", "quic_settings": groups});
    let guarded_proxy = json!({"address": "127.0.0.1:443", "protocol": {"type": "portforward"}, "transport": "quic", "quic_settings": groups});
    for chain in [
        json!([guarded_direct]),
        json!([direct, guarded_proxy]),
        json!([direct, {"pool": ["guarded"]}]),
    ] {
        let config = json!([
            {"client_group": "guarded", "client_proxies": [guarded_proxy]},
            {"address": "0.0.0.0:0", "protocol": {"type": "http"}, "rules": [{"mask": "0.0.0.0/0", "action": "allow", "client_chain": chain}]}
        ]);
        let config_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(config_file.path(), serde_yaml::to_string(&config).unwrap()).unwrap();
        for mode in ["--dry-run", "--no-reload"] {
            let mut process = Process::start(config_file.path(), &[mode]);
            process.wait_for("QUIC key_exchange_groups").await;
            assert_eq!(process.exit().await.code(), Some(1));
        }
    }
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
async fn connection_budget_changes_only_with_accepted_reloads_and_counts_draining_flows() {
    async fn assert_rejected(address: SocketAddr) {
        let mut stream = TcpStream::connect(address).await.unwrap();
        let _ = stream.write_all(b"over budget").await;
        let result = timeout(Duration::from_secs(5), stream.read_u8())
            .await
            .unwrap();
        assert!(result.is_err(), "an over-budget connection was served");
    }

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let echo = shoes_test_support::test_servers::start_tcp_stream_echo_server("127.0.0.1", 0)
        .await
        .unwrap();
    let address = available_address();
    let config = |max_connections: usize| {
        format!(
            "- global_limits: {{max_connections: {max_connections}, reload_grace_secs: 60}}\n- address: '{address}'\n  protocol:\n    type: forward\n    target: '{}'\n",
            echo.local_addr()
        )
    };
    std::fs::write(&path, config(1)).unwrap();
    let mut child = Process::start(&path, &["--no-reload"]);
    child.wait_for("Servers ready").await;
    let mut draining = TcpStream::connect(address).await.unwrap();
    roundtrip(&mut draining).await;
    assert_rejected(address).await;

    // A rejected candidate's larger budget is never applied.
    std::fs::write(&path, config(2).replace("type: forward", "type: unknown")).unwrap();
    child.signal(libc::SIGHUP);
    child.wait_for("Reload rejected").await;
    assert_rejected(address).await;
    roundtrip(&mut draining).await;

    // The accepted generation's budget still counts the previous generation's flow.
    std::fs::write(&path, config(2)).unwrap();
    child.signal(libc::SIGHUP);
    child.wait_for("Servers ready").await;
    let mut current = TcpStream::connect(address).await.unwrap();
    roundtrip(&mut current).await;
    assert_rejected(address).await;
    roundtrip(&mut draining).await;

    // Closing the draining flow returns its permit.
    drop(draining);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(b"still serving").await.unwrap();
        let mut response = [0; 13];
        if timeout(Duration::from_secs(1), stream.read_exact(&mut response))
            .await
            .is_ok_and(|result| result.is_ok())
        {
            assert_eq!(&response, b"still serving");
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the drained flow's permit was not released"
        );
    }
    roundtrip(&mut current).await;
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
        timeout(Duration::from_millis(5500), async {
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

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn hard_link_updates_trigger_reload() {
    let directory = tempfile::tempdir().unwrap();
    let aliases = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let config = format!(
        "- address: '{}'\n  protocol: {{type: http}}\n",
        available_address()
    );
    std::fs::write(&path, &config).unwrap();
    let mut child = Process::start(&path, &[]);
    child.wait_for("Servers ready").await;
    for alias in [
        directory.path().join("alias.yaml"),
        aliases.path().join("alias.yaml"),
    ] {
        std::fs::hard_link(&path, &alias).unwrap();
        std::fs::write(&alias, &config).unwrap();
        child.wait_for("Servers ready").await;
    }
    child.signal(libc::SIGTERM);
    assert!(child.exit().await.success());
}

#[cfg(unix)]
#[tokio::test]
async fn quic_reload_readiness_excludes_retired_sockets() {
    use std::sync::Arc;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    let echo = shoes_test_support::test_servers::start_tcp_stream_echo_server("127.0.0.1", 0)
        .await
        .unwrap();
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let config = serde_json::json!([{
        "address": address.to_string(), "transport": "quic",
        "quic_settings": {"cert": certificate.cert.pem(), "key": certificate.signing_key.serialize_pem(), "num_endpoints": 2},
        "protocol": {"type": "forward", "target": echo.local_addr().to_string()}
    }]);
    std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
    let mut child = Process::start(&path, &["--no-reload"]);
    child.wait_for("Servers ready").await;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.cert.der().clone()).unwrap();
    let config = quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    let connect = || async {
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(config.clone());
        let connection = timeout(
            Duration::from_secs(2),
            endpoint.connect(address, "localhost").unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(b"ping").await.unwrap();
        let mut response = [0; 4];
        timeout(Duration::from_secs(2), recv.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response, b"ping");
        (endpoint, connection, send, recv)
    };
    let mut old = Vec::new();
    for _ in 0..8 {
        old.push(connect().await);
    }
    child.signal(libc::SIGHUP);
    child.wait_for("Servers ready").await;
    for _ in 0..24 {
        let (_endpoint, connection, _send, _recv) = connect().await;
        connection.close(0u32.into(), b"done");
    }
    for (_, connection, _, _) in &old {
        assert!(matches!(
            connection.close_reason(),
            Some(quinn::ConnectionError::ApplicationClosed(_))
        ));
    }
    child.signal(libc::SIGTERM);
    assert!(child.exit().await.success());
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
    let missing_directory = targets.path().join("missing-directory");
    let nested = missing_directory.join("config.yaml");
    let link = directory.path().join("replacement.yaml");
    std::os::unix::fs::symlink(&nested, &link).unwrap();
    std::fs::rename(link, &path).unwrap();
    child.wait_for("Reload rejected").await;
    std::fs::create_dir(&missing_directory).unwrap();
    child.wait_for("Reload rejected").await;
    std::fs::write(&nested, &config).unwrap();
    child.wait_for("Servers ready").await;
    child.signal(libc::SIGTERM);
    assert_eq!(child.exit().await.code(), Some(0));
}

#[cfg(unix)]
#[tokio::test]
async fn config_watch_directories_need_only_traverse_permission() {
    use std::os::unix::fs::PermissionsExt;
    struct RestorePermissions(std::path::PathBuf);
    impl Drop for RestorePermissions {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        }
    }
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let private = directory.path().join("private");
    let config_dir = private.join("config");
    std::fs::create_dir_all(&config_dir).unwrap();
    let alias = directory.path().join("alias");
    std::os::unix::fs::symlink(&config_dir, &alias).unwrap();
    let path = alias.join("config.yaml");
    let config = format!(
        "- address: '{}'\n  protocol: {{type: http}}\n",
        available_address()
    );
    std::fs::write(&path, &config).unwrap();
    for restricted in [&private, &config_dir] {
        std::fs::set_permissions(restricted, std::fs::Permissions::from_mode(0o111)).unwrap();
        let _restore = RestorePermissions(restricted.clone());
        assert!(std::fs::read_dir(restricted).is_err());
        let mut child = Process::start(&path, &[]);
        child.wait_for("Servers ready").await;
        std::fs::write(&path, &config).unwrap();
        child.wait_for("Servers ready").await;
        child.signal(libc::SIGTERM);
        assert!(child.exit().await.success());
    }
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
