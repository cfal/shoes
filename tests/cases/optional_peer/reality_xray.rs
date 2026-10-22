use std::{
    io,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};

use aws_lc_rs::{
    agreement,
    signature::{self, KeyPair},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use shoes_test_support::{
    curl::{CurlOptions, run_curl},
    process::ProcessGuard,
    test_servers::start_local_http_server,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

const USER: &str = "b85798ef-e9dc-46a4-9a87-8da4499d36d0";
const SHORT_ID: &str = "0123456789abcdef";

struct TaskGuard(JoinHandle<()>);
impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Peer {
    _guard: ProcessGuard,
    _config: tempfile::NamedTempFile,
    log: tempfile::NamedTempFile,
}

async fn start_peer(xray: bool, port: u16, config: Value) -> Peer {
    use std::io::Write;
    let mut file = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
    file.write_all(serde_json::to_string_pretty(&config).unwrap().as_bytes())
        .unwrap();
    let log = tempfile::NamedTempFile::new().unwrap();
    let binary = if xray {
        std::env::var_os("XRAY_BINARY")
            .expect("XRAY_BINARY must name the pinned Xray peer; this test never silently skips")
    } else {
        std::env::var_os("SHOES_TEST_SHOES_BIN")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_shoes").into())
    };
    let mut command = Command::new(binary);
    if xray {
        command.args(["run", "-c"]);
    } else {
        command.args(["--no-reload", "--threads", "1"]);
    }
    let child = command
        .arg(file.path())
        .env("GOMAXPROCS", "1")
        .env("RUST_LOG", "shoes=debug")
        .stdin(Stdio::null())
        .stdout(log.reopen().unwrap())
        .stderr(log.reopen().unwrap())
        .spawn()
        .unwrap();
    let peer = Peer {
        _guard: ProcessGuard::new(
            child,
            if xray {
                "xray-reality"
            } else {
                "shoes-reality"
            },
        ),
        _config: file,
        log,
    };
    timeout(Duration::from_secs(10), async {
        loop {
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "proxy listener did not become ready: {}",
            std::fs::read_to_string(peer.log.path()).unwrap_or_default()
        )
    });
    peer
}

async fn free_port() -> u16 {
    TcpListener::bind("0.0.0.0:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn start_target(hybrid: bool, padded: bool) -> (u16, TaskGuard) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["cover.test".into()]).unwrap();
    if padded {
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 55555, 1],
                vec![0; 5000],
            ));
    }
    let cert = params.self_signed(&key).unwrap();
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = if hybrid {
        vec![
            rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
            rustls::crypto::aws_lc_rs::kx_group::X25519,
        ]
    } else {
        vec![rustls::crypto::aws_lc_rs::kx_group::X25519]
    };
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap();
    config.send_tls13_tickets = 0;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let mut children = JoinSet::new();
        loop {
            tokio::select! {
                result = listener.accept() => {
                    let Ok((stream, _)) = result else { break };
                    let acceptor = acceptor.clone();
                    children.spawn(async move {
                        let _ = timeout(Duration::from_secs(5), acceptor.accept(stream)).await;
                    });
                }
                _ = children.join_next(), if !children.is_empty() => {}
            }
        }
    });
    (port, TaskGuard(task))
}

async fn read_tls_record(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0; 5];
    stream.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut bytes = vec![0; 5 + len];
    bytes[..5].copy_from_slice(&header);
    stream.read_exact(&mut bytes[5..]).await?;
    Ok(bytes)
}

fn key_shares(record: &[u8], client: bool) -> Vec<(u16, usize)> {
    let mut offset = 43;
    offset += 1 + record[offset] as usize;
    if client {
        let cipher_len = u16::from_be_bytes([record[offset], record[offset + 1]]) as usize;
        offset += 2 + cipher_len;
        offset += 1 + record[offset] as usize;
    } else {
        offset += 3;
    }
    let extensions_len = u16::from_be_bytes([record[offset], record[offset + 1]]) as usize;
    offset += 2;
    let extensions_end = offset + extensions_len;
    while offset < extensions_end {
        let id = u16::from_be_bytes([record[offset], record[offset + 1]]);
        let extension_len = u16::from_be_bytes([record[offset + 2], record[offset + 3]]) as usize;
        offset += 4;
        if id != 51 {
            offset += extension_len;
            continue;
        }
        let shares_end = offset + extension_len;
        if client {
            offset += 2;
        }
        let mut shares = Vec::new();
        while offset < shares_end {
            let group = u16::from_be_bytes([record[offset], record[offset + 1]]);
            let share_len = u16::from_be_bytes([record[offset + 2], record[offset + 3]]) as usize;
            shares.push((group, share_len));
            offset += 4 + share_len;
        }
        return shares;
    }
    panic!("key_share missing from captured hello");
}

type Capture = Arc<Mutex<Vec<(Vec<u8>, Vec<Vec<u8>>)>>>;

fn masked_server_hello(record: &[u8]) -> Vec<u8> {
    let mut masked = record.to_vec();
    let mut offset = 49 + record[43] as usize;
    while offset < record.len() {
        let id = u16::from_be_bytes([record[offset], record[offset + 1]]);
        let len = u16::from_be_bytes([record[offset + 2], record[offset + 3]]) as usize;
        if id == 51 {
            masked[offset + 8..offset + 4 + len].fill(0);
        }
        offset += 4 + len;
    }
    masked
}

async fn start_tap(upstream: u16) -> (u16, Capture, TaskGuard) {
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let captured: Capture = Arc::default();
    let output = captured.clone();
    let task = tokio::spawn(async move {
        let mut children = JoinSet::new();
        loop {
            tokio::select! {
                result = listener.accept() => {
                    let Ok((mut client, _)) = result else { break };
                    let captured = captured.clone();
                    children.spawn(async move {
                        let _ = timeout(Duration::from_secs(15), async {
                            let hello = read_tls_record(&mut client).await?;
                            let mut server = TcpStream::connect(("127.0.0.1", upstream)).await?;
                            server.write_all(&hello).await?;
                            let mut response = Vec::new();
                            for _ in 0..3 {
                                response.push(read_tls_record(&mut server).await?);
                            }
                            captured.lock().unwrap().push((hello, response.clone()));
                            client.write_all(&response.concat()).await?;
                            tokio::io::copy_bidirectional(&mut client, &mut server).await?;
                            Ok::<_, io::Error>(())
                        }).await;
                    });
                }
                _ = children.join_next(), if !children.is_empty() => {}
            }
        }
    });
    (port, output, TaskGuard(task))
}

struct Case {
    server_xray: bool,
    client_xray: bool,
    hybrid: bool,
    sign: bool,
    verify: bool,
    wrong_key: bool,
    padded: bool,
    vision: bool,
    fingerprint: &'static str,
}

impl Default for Case {
    fn default() -> Self {
        Self {
            server_xray: false,
            client_xray: false,
            hybrid: true,
            sign: false,
            verify: false,
            wrong_key: false,
            padded: true,
            vision: false,
            fingerprint: "chrome",
        }
    }
}

impl Case {
    fn server_config(
        &self,
        port: u16,
        target_port: u16,
        private_key: &str,
        signing_seed: &str,
    ) -> Value {
        let mut config = if self.server_xray {
            let flow = if self.vision { "xtls-rprx-vision" } else { "" };
            json!({
                "log": { "loglevel": "warning" },
                "inbounds": [{
                    "listen": "0.0.0.0",
                    "port": port,
                    "protocol": "vless",
                    "settings": {
                        "clients": [{ "id": USER, "flow": flow }],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "raw",
                        "security": "reality",
                        "realitySettings": {
                            "target": format!("127.0.0.1:{target_port}"),
                            "serverNames": ["cover.test"],
                            "privateKey": private_key,
                            "shortIds": [SHORT_ID]
                        }
                    }
                }],
                "outbounds": [{
                    "protocol": "freedom",
                    "settings": {
                        "finalRules": [{ "ip": ["0.0.0.0/0", "::/0"], "action": "allow" }]
                    }
                }]
            })
        } else {
            json!([{
                "address": format!("0.0.0.0:{port}"),
                "protocol": {
                    "type": "tls",
                    "reality_targets": {
                        "cover.test": {
                            "private_key": private_key,
                            "short_ids": [SHORT_ID],
                            "dest": format!("localhost:{target_port}"),
                            "vision": self.vision,
                            "protocol": { "type": "vless", "user_id": USER }
                        }
                    }
                }
            }])
        };
        if self.sign {
            if self.server_xray {
                config["inbounds"][0]["streamSettings"]["realitySettings"]["mldsa65Seed"] =
                    json!(signing_seed);
            } else {
                config[0]["protocol"]["reality_targets"]["cover.test"]["mldsa65_seed"] =
                    json!(signing_seed);
            }
        }
        config
    }

    fn client_config(
        &self,
        port: u16,
        server_port: u16,
        public_key: &str,
        verify_key: &str,
    ) -> Value {
        let mut config = if self.client_xray {
            let flow = if self.vision { "xtls-rprx-vision" } else { "" };
            json!({
                "log": { "loglevel": "warning" },
                "inbounds": [{ "listen": "0.0.0.0", "port": port, "protocol": "http" }],
                "outbounds": [{
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": "127.0.0.1",
                            "port": server_port,
                            "users": [{ "id": USER, "encryption": "none", "flow": flow }]
                        }]
                    },
                    "streamSettings": {
                        "network": "raw",
                        "security": "reality",
                        "realitySettings": {
                            "serverName": "cover.test",
                            "fingerprint": self.fingerprint,
                            "publicKey": public_key,
                            "shortId": SHORT_ID
                        }
                    }
                }]
            })
        } else {
            json!([{
                "address": format!("0.0.0.0:{port}"),
                "protocol": { "type": "http" },
                "rules": [{
                    "masks": "0.0.0.0/0",
                    "action": "allow",
                    "client_chain": {
                        "address": format!("127.0.0.1:{server_port}"),
                        "protocol": {
                            "type": "reality",
                            "public_key": public_key,
                            "short_id": SHORT_ID,
                            "sni_hostname": "cover.test",
                            "vision": self.vision,
                            "protocol": { "type": "vless", "user_id": USER }
                        }
                    }
                }]
            }])
        };
        if self.verify {
            if self.client_xray {
                config["outbounds"][0]["streamSettings"]["realitySettings"]["mldsa65Verify"] =
                    json!(verify_key);
            } else {
                config[0]["rules"][0]["client_chain"]["protocol"]["mldsa65_verify"] =
                    json!(verify_key);
            }
        }
        config
    }
}

async fn run_case(case: Case) {
    let private = [42; 32];
    let public = agreement::PrivateKey::from_private_key(&agreement::X25519, &private)
        .unwrap()
        .compute_public_key()
        .unwrap();
    let private = URL_SAFE_NO_PAD.encode(private);
    let public = URL_SAFE_NO_PAD.encode(public.as_ref());
    let seed = [7; 32];
    let signing = signature::PqdsaKeyPair::from_seed(
        &signature::ML_DSA_65_SIGNING,
        &if case.wrong_key { [8; 32] } else { seed },
    )
    .unwrap();
    let verify_key = URL_SAFE_NO_PAD.encode(signing.public_key().as_ref());
    let (target_port, _target) = start_target(case.hybrid, case.padded).await;
    let (target_port, target_captured, _target_tap) = start_tap(target_port).await;
    let app = start_local_http_server("0.0.0.0", 0).await.unwrap();
    let server_port = free_port().await;
    let server_config = case.server_config(
        server_port,
        target_port,
        &private,
        &URL_SAFE_NO_PAD.encode(seed),
    );
    let _server = start_peer(case.server_xray, server_port, server_config).await;
    let (tap_port, captured, _tap) = start_tap(server_port).await;
    let client_port = free_port().await;
    let client_config = case.client_config(client_port, tap_port, &public, &verify_key);
    let Case {
        server_xray,
        client_xray,
        hybrid,
        sign,
        verify,
        wrong_key,
        padded,
        ..
    } = case;
    let _client = start_peer(client_xray, client_port, client_config).await;
    let start = std::time::Instant::now();
    let output = run_curl(
        &format!("http://127.0.0.1:{}/bytes/204800", app.local_addr().port()),
        CurlOptions::new()
            .proxy(format!("http://127.0.0.1:{client_port}"))
            .timeout(10)
            .fail_on_http_error(true),
    )
    .await
    .unwrap();
    let expected_success = (!verify || (sign && !wrong_key)) && (!sign || padded);
    assert_eq!(
        output.status.success(),
        expected_success,
        "server_xray={server_xray} client_xray={client_xray} hybrid={hybrid} sign={sign} verify={verify} wrong_key={wrong_key} padded={padded}; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    if expected_success {
        assert_eq!(output.stdout, vec![b'X'; 204800]);
        let payload: Vec<_> = (0..204800).map(|i| (i % 251) as u8).collect();
        let echoed = run_curl(
            &format!("http://127.0.0.1:{}/echo", app.local_addr().port()),
            CurlOptions::new()
                .proxy(format!("http://127.0.0.1:{client_port}"))
                .post_data(payload.clone())
                .timeout(10)
                .fail_on_http_error(true),
        )
        .await
        .unwrap();
        assert!(
            echoed.status.success(),
            "{}",
            String::from_utf8_lossy(&echoed.stderr)
        );
        assert_eq!(echoed.stdout, payload);
        let captured = captured.lock().unwrap();
        let targets = target_captured.lock().unwrap();
        assert!(!captured.is_empty());
        for (hello, response) in captured.iter() {
            let offered: Vec<_> = key_shares(hello, true)
                .into_iter()
                .filter(|(g, _)| *g == 0x11ec || *g == 0x001d)
                .collect();
            assert_eq!(offered, [(0x11ec, 1216), (0x001d, 32)]);
            assert_eq!(
                key_shares(&response[0], false),
                if hybrid {
                    vec![(0x11ec, 1120)]
                } else {
                    vec![(0x001d, 32)]
                }
            );
            let (_, target) = targets
                .iter()
                .find(|(client, _)| client == hello)
                .expect("forwarded ClientHello capture");
            assert_eq!(
                masked_server_hello(&response[0]),
                masked_server_hello(&target[0])
            );
            assert_eq!(
                response.iter().map(Vec::len).collect::<Vec<_>>(),
                target.iter().map(Vec::len).collect::<Vec<_>>()
            );
        }
    }
    eprintln!(
        "REALITY peer case: hybrid={hybrid} mldsa={verify} elapsed={:?}",
        start.elapsed()
    );
}

#[tokio::test]
async fn reality_xray_hybrid_default_and_classical_fallback() {
    for (server_xray, client_xray) in [(true, false), (false, true), (true, true), (false, false)] {
        for hybrid in [true, false] {
            run_case(Case {
                server_xray,
                client_xray,
                hybrid,
                ..Case::default()
            })
            .await;
        }
    }
    run_case(Case {
        client_xray: true,
        fingerprint: "firefox",
        ..Case::default()
    })
    .await;
}

#[tokio::test]
async fn reality_xray_mldsa_required_and_optional() {
    for (server_xray, client_xray) in [(true, false), (false, true), (false, false)] {
        for verify in [true, false] {
            run_case(Case {
                server_xray,
                client_xray,
                sign: true,
                verify,
                ..Case::default()
            })
            .await;
        }
        run_case(Case {
            server_xray,
            client_xray,
            sign: true,
            verify: true,
            wrong_key: true,
            ..Case::default()
        })
        .await;
        run_case(Case {
            server_xray,
            client_xray,
            verify: true,
            ..Case::default()
        })
        .await;
    }
    run_case(Case {
        sign: true,
        verify: true,
        padded: false,
        ..Case::default()
    })
    .await;
}

#[tokio::test]
async fn reality_xray_vision_hybrid() {
    for (server_xray, client_xray) in [(true, false), (false, true)] {
        run_case(Case {
            server_xray,
            client_xray,
            sign: true,
            verify: true,
            vision: true,
            ..Case::default()
        })
        .await;
    }
}
