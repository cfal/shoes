use crate::{Process, available_address, reserve_address};
use serde_json::json;
use std::{process::Command, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[tokio::test]
async fn persisted_acme_retry_is_reported_once_without_contacting_the_ca() {
    use std::os::unix::fs::PermissionsExt;
    timeout(Duration::from_secs(10), async {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        let ca = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/directory", ca.local_addr().unwrap());
        let retry_at = chrono::Utc::now().timestamp() + 3600;
        let state_file = state.join("state.json");
        std::fs::write(&state_file, serde_json::to_vec(&json!({
            "directory_url": url, "domains": ["proxy.test"], "account_key": "not used until retry",
            "credentials": null, "certificate": null, "private_key": null, "order_url": null, "order_key": null, "retry_at": retry_at
        })).unwrap()).unwrap();
        std::fs::set_permissions(&state_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let path = directory.path().join("config.yaml");
        let (challenge_listener, challenge) = reserve_address();
        let (proxy_listener, proxy) = reserve_address();
        std::fs::write(&path, serde_yaml::to_string(&json!([
            {"certificate_source": "managed", "type": "acme", "domains": ["proxy.test"], "directory_url": url,
             "state_dir": state, "challenge": {"type": "http01", "listen": [challenge.to_string()]}},
            {"address": proxy.to_string(), "protocol": {"type": "socks"}}
        ])).unwrap()).unwrap();
        drop(challenge_listener);
        drop(proxy_listener);
        let child = Command::new(env!("CARGO_BIN_EXE_shoes"))
            .args(["-t", "1"]).arg(&path).env_remove("RUST_LOG")
            .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
        let mut child = Process::from_child(child);
        let marker = "ACME retry deferred until Unix time";
        loop {
            let line = child.lines.recv().await.unwrap();
            if line.contains(marker) {
                assert!(line.contains("managed") && line.contains(state.to_str().unwrap()) && line.contains(&retry_at.to_string()), "{line}");
                break;
            }
        }
        assert!(timeout(Duration::from_millis(200), ca.accept()).await.is_err());
        child.signal(libc::SIGTERM);
        assert!(child.exit().await.success());
        while let Some(line) = child.lines.recv().await {
            assert!(!line.contains(marker), "duplicate retry message: {line}");
        }
    }).await.unwrap();
}

#[tokio::test]
async fn certificate_failures_are_visible_with_default_logging() {
    timeout(Duration::from_secs(12), async {
        let directory = tempfile::tempdir().unwrap();
        let pair = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        std::fs::write(&cert, pair.cert.pem()).unwrap();
        std::fs::write(&key, pair.signing_key.serialize_pem()).unwrap();
        let ca = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/directory", ca.local_addr().unwrap());
        let mut fixture = tokio::task::JoinSet::new();
        fixture.spawn(async move {
            let (mut stream, _) = ca.accept().await.unwrap();
            let mut request = [0; 4096];
            let mut received = 0;
            while !request[..received].windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                assert!(received < request.len(), "request headers exceed fixture limit");
                let count = stream.read(&mut request[received..]).await.unwrap();
                assert_ne!(count, 0, "request ended before headers");
                received += count;
            }
            stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
        });
        let path = directory.path().join("config.yaml");
        let (challenge_listener, challenge) = reserve_address();
        let (proxy_listener, proxy) = reserve_address();
        std::fs::write(&path, serde_yaml::to_string(&json!([
            {"certificate_source": "files", "type": "files", "cert": cert, "key": key},
            {"certificate_source": "managed", "type": "acme", "domains": ["proxy.test"], "directory_url": url,
                "state_dir": directory.path().join("state"), "challenge": {"type": "http01", "listen": [challenge.to_string()]}},
            {"address": proxy.to_string(), "protocol": {"type": "tls", "default_tls_target": {
                "certificate_source": "files", "protocol": {"type": "socks"}}}}
        ])).unwrap()).unwrap();
        drop(challenge_listener);
        drop(proxy_listener);
        let child = Command::new(env!("CARGO_BIN_EXE_shoes"))
            .args(["-t", "1"]).arg(&path).env_remove("RUST_LOG")
            .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
        let mut child = Process::from_child(child);
        child.wait_for("ACME directory returned HTTP 503").await;
        std::fs::write(&key, "invalid replacement").unwrap();
        child.wait_for("Certificate source files update failed").await;
        child.signal(libc::SIGTERM);
        assert!(child.exit().await.success());
        fixture.join_next().await.unwrap().unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn file_rotation_keeps_tcp_and_quic_tunnels_and_rejects_bad_reload() {
    rotation_roundtrip(true, true).await;
}

#[tokio::test]
async fn legacy_file_references_rotate_without_triggering_config_reload() {
    rotation_roundtrip(false, false).await;
}

async fn rotation_roundtrip(named: bool, no_reload: bool) {
    timeout(Duration::from_secs(20), async {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        let cert_path = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        let first = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
        let second = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
        std::fs::write(&cert_path, first.cert.pem()).unwrap();
        std::fs::write(&key_path, first.signing_key.serialize_pem()).unwrap();
        let echo = shoes_test_support::test_servers::start_tcp_stream_echo_server("127.0.0.1", 0).await.unwrap();
        let tcp = available_address();
        let quic = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let mut config = json!([
            {"certificate_source":"shared", "type":"files", "cert":cert_path, "key":key_path},
            {"address":tcp.to_string(), "protocol":{"type":"tls", "tls_targets":{"proxy.test":{
                "certificate_source":"shared", "protocol":{"type":"forward", "target":echo.local_addr().to_string()}
            }}}},
            {"address":quic.to_string(), "transport":"quic", "quic_settings":{"certificate_source":"shared", "num_endpoints":1},
                "protocol":{"type":"forward", "target":echo.local_addr().to_string()}}
        ]);
        if !named {
            let target = config[1]["protocol"]["tls_targets"]["proxy.test"].as_object_mut().unwrap();
            target.remove("certificate_source");
            target.insert("cert".into(), json!(cert_path));
            target.insert("key".into(), json!(key_path));
            let quic = config[2]["quic_settings"].as_object_mut().unwrap();
            quic.remove("certificate_source");
            quic.insert("cert".into(), json!(cert_path));
            quic.insert("key".into(), json!(key_path));
            config.as_array_mut().unwrap().remove(0);
        }
        std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
        let mut child = Process::start(&path, if no_reload { &["--no-reload"] } else { &[] });
        child.wait_for("Servers ready").await;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(first.cert.der().clone()).unwrap();
        roots.add(second.cert.der().clone()).unwrap();
        let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions().unwrap().with_root_certificates(roots.clone()).with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
        let connect_tls = || async { connector.connect("proxy.test".try_into().unwrap(), TcpStream::connect(tcp).await.unwrap()).await.unwrap() };
        let mut old_tls = connect_tls().await;
        assert_eq!(old_tls.get_ref().1.peer_certificates().unwrap()[0], *first.cert.der());
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap());
        let old_quic = endpoint.connect(quic, "proxy.test").unwrap().await.unwrap();
        let (mut send, mut recv) = old_quic.open_bi().await.unwrap();
        send.write_all(b"before").await.unwrap();
        let mut bytes = [0; 6];
        recv.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"before");
        std::fs::write(&cert_path, second.cert.pem()).unwrap();
        tokio::time::sleep(Duration::from_millis(1300)).await;
        let unchanged = connect_tls().await;
        assert_eq!(unchanged.get_ref().1.peer_certificates().unwrap()[0], *first.cert.der());
        std::fs::write(directory.path().join("new.key"), second.signing_key.serialize_pem()).unwrap();
        std::fs::rename(directory.path().join("new.key"), &key_path).unwrap();
        let mut new_tls = timeout(Duration::from_secs(5), async {
            loop {
                let stream = connect_tls().await;
                if stream.get_ref().1.peer_certificates().unwrap()[0] == *second.cert.der() { break stream; }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await.unwrap();
        let new_quic = endpoint.connect(quic, "proxy.test").unwrap().await.unwrap();
        let peer = new_quic.peer_identity().unwrap().downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>().unwrap();
        assert_eq!(peer[0], *second.cert.der());
        assert!(old_quic.close_reason().is_none());
        for stream in [&mut old_tls, &mut new_tls] {
            stream.write_all(b"after!").await.unwrap();
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"after!");
        }
        send.write_all(b"after!").await.unwrap();
        recv.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"after!");
        if !no_reload {
            assert_no_reload(&mut child, Duration::from_millis(5500), "live rotation").await;
        }
        while let Ok(line) = child.lines.try_recv() { assert!(!line.contains("Servers ready"), "certificate rotation must not reload listeners"); }
        config[usize::from(named)]["protocol"]["tls_targets"]["proxy.test"]["certificate_source"] = json!("missing");
        std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
        child.signal(libc::SIGHUP);
        child.wait_for("Reload rejected").await;
        old_tls.write_all(b"still!").await.unwrap();
        old_tls.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"still!");
        assert!(old_quic.close_reason().is_none());
        child.signal(libc::SIGTERM);
        assert!(child.exit().await.success());
        endpoint.close(0u32.into(), b"done");
        endpoint.wait_idle().await;
        assert!(std::net::TcpListener::bind(tcp).is_ok());
        assert!(std::net::UdpSocket::bind(quic).is_ok());
    }).await.unwrap();
}

async fn assert_no_reload(child: &mut Process, duration: Duration, phase: &str) {
    assert!(
        timeout(duration, async {
            loop {
                let line = child
                    .lines
                    .recv()
                    .await
                    .expect("process exited unexpectedly");
                assert!(
                    !line.contains("Servers ready") && !line.contains("Reload rejected"),
                    "unexpected reload during {phase}: {line}"
                );
            }
        })
        .await
        .is_err()
    );
}

#[tokio::test]
async fn rejected_inbound_identities_recover_without_yaml_edits() {
    timeout(Duration::from_secs(60), async {
        for kind in ["legacy", "named-pem", "named-source"] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("config.yaml");
            let address = available_address();
            let cert_path = directory.path().join("new/cert.pem");
            let key_path = directory.path().join("new/key.pem");
            let first = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
            let second = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
            std::fs::write(&path, serde_yaml::to_string(&json!([
                {"address": address.to_string(), "protocol": {"type": "socks"}}
            ])).unwrap()).unwrap();
            let mut child = Process::start(&path, &[]);
            child.wait_for("Servers ready").await;
            let mut target = json!({"cert": cert_path, "key": key_path, "protocol": {"type": "socks"}});
            let mut config = vec![];
            match kind {
                "named-source" => {
                    config.push(json!({"certificate_source": "shared", "type": "files", "cert": cert_path, "key": key_path}));
                    target = json!({"certificate_source": "shared", "protocol": {"type": "socks"}});
                }
                "named-pem" => {
                    config.push(json!({"pem": "chain", "path": cert_path}));
                    config.push(json!({"pem": "private", "path": key_path}));
                    target["cert"] = json!("chain");
                    target["key"] = json!("private");
                }
                _ => {}
            }
            config.push(json!({"address": address.to_string(), "protocol": {"type": "tls", "default_tls_target": target}}));
            std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
            child.signal(libc::SIGHUP);
            child.wait_for("Reload rejected").await;
            let mut old = TcpStream::connect(address).await.unwrap();
            old.write_all(&[5, 1, 0]).await.unwrap();
            let mut reply = [0; 2];
            old.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [5, 0]);
            std::fs::create_dir(cert_path.parent().unwrap()).unwrap();
            std::fs::write(&cert_path, first.cert.pem()).unwrap();
            std::fs::write(&key_path, first.signing_key.serialize_pem()).unwrap();
            child.wait_for("Servers ready").await;
            let mut roots = rustls::RootCertStore::empty();
            roots.add(first.cert.der().clone()).unwrap();
            roots.add(second.cert.der().clone()).unwrap();
            let client = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
                .with_safe_default_protocol_versions().unwrap().with_root_certificates(roots).with_no_client_auth();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
            std::fs::write(&cert_path, second.cert.pem()).unwrap();
            std::fs::write(&key_path, second.signing_key.serialize_pem()).unwrap();
            timeout(Duration::from_secs(3), async {
                loop {
                    let stream = connector.connect("proxy.test".try_into().unwrap(), TcpStream::connect(address).await.unwrap()).await.unwrap();
                    if stream.get_ref().1.peer_certificates().unwrap()[0] == *second.cert.der() { break; }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }).await.unwrap();
            assert_no_reload(&mut child, Duration::from_millis(5500), kind).await;
            child.signal(libc::SIGTERM);
            assert!(child.exit().await.success());
        }
    }).await.unwrap();
}

#[tokio::test]
async fn reload_releases_retired_http01_ports_before_starting_proxy_listeners() {
    timeout(Duration::from_secs(20), async {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        let (challenge_listener, challenge) = reserve_address();
        let (proxy_listener, proxy) = reserve_address();
        let mut config = json!([
            {"certificate_source": "managed", "type": "acme", "domains": ["proxy.test"],
                "directory_url": "http://127.0.0.1:9/directory", "state_dir": directory.path().join("state"),
                "challenge": {"type": "http01", "listen": [challenge.to_string()]}},
            {"address": proxy.to_string(), "protocol": {"type": "tls", "default_tls_target": {
                "certificate_source": "managed", "protocol": {"type": "socks"}}}}
        ]);
        std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
        drop(challenge_listener);
        drop(proxy_listener);
        let mut child = Process::start(&path, &[]);
        child.wait_for("Servers ready").await;
        config[0]["challenge"] = json!({"type": "tls_alpn01"});
        config.as_array_mut().unwrap().push(json!({"address": challenge.to_string(), "protocol": {"type": "socks"}}));
        config.as_array_mut().unwrap().push(json!({"path":directory.path().join("missing/listener.sock"), "protocol":{"type":"socks"}}));
        std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
        child.signal(libc::SIGHUP);
        child.wait_for("Reload rejected; previous servers restored").await;
        let mut restored = TcpStream::connect(challenge).await.unwrap();
        restored.write_all(b"GET / HTTP/1.1\r\nHost: proxy.test\r\n\r\n").await.unwrap();
        let mut response = String::new();
        restored.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 404 "), "{response}");
        config.as_array_mut().unwrap().pop();
        std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
        child.signal(libc::SIGHUP);
        child.wait_for("Servers ready").await;
        let mut stream = TcpStream::connect(challenge).await.unwrap();
        stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0; 2];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0]);
        drop(stream);

        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        config[0]["challenge"] = json!({"type": "http01", "listen": [challenge.to_string(), occupied.local_addr().unwrap().to_string()]});
        config.as_array_mut().unwrap().pop();
        std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
        child.signal(libc::SIGHUP);
        child.wait_for("Reload rejected").await;
        let mut stream = TcpStream::connect(challenge).await.unwrap();
        stream.write_all(&[5, 1, 0]).await.unwrap();
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0], "failed deferred preparation must retain the proxy");
        drop(stream);

        config[0]["challenge"]["listen"] = json!([challenge.to_string()]);
        config.as_array_mut().unwrap().push(json!({"path":directory.path().join("missing/listener.sock"), "protocol":{"type":"socks"}}));
        std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
        child.signal(libc::SIGHUP);
        child.wait_for("Reload rejected; previous servers restored").await;
        let mut stream = TcpStream::connect(challenge).await.unwrap();
        stream.write_all(&[5, 1, 0]).await.unwrap();
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0], "failed HTTP-01 activation must restore the proxy");
        drop(stream);
        config.as_array_mut().unwrap().pop();
        std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
        child.signal(libc::SIGHUP);
        child.wait_for("Servers ready").await;
        let mut stream = TcpStream::connect(challenge).await.unwrap();
        stream.write_all(b"GET /.well-known/acme-challenge/unknown HTTP/1.1\r\nHost: proxy.test\r\n\r\n").await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 404 "), "{response}");
        child.signal(libc::SIGTERM);
        assert!(child.exit().await.success());
    }).await.unwrap();
}

#[tokio::test]
async fn unused_named_pem_rejection_recovers_from_file_creation() {
    timeout(Duration::from_secs(20), async {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        let pem = directory.path().join("new/unused.pem");
        let address = available_address();
        let mut config = json!([{"address": address.to_string(), "protocol": {"type": "socks"}}]);
        std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
        let mut child = Process::start(&path, &[]);
        child.wait_for("Servers ready").await;
        config
            .as_array_mut()
            .unwrap()
            .push(json!({"pem": "unused", "path": pem}));
        std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
        child.signal(libc::SIGHUP);
        child.wait_for("Reload rejected").await;
        std::fs::create_dir(pem.parent().unwrap()).unwrap();
        std::fs::write(&pem, "unused material").unwrap();
        child.wait_for("Servers ready").await;
        std::fs::write(&pem, "still unused").unwrap();
        assert_no_reload(
            &mut child,
            Duration::from_millis(5500),
            "unused declaration after activation",
        )
        .await;
        child.signal(libc::SIGTERM);
        assert!(child.exit().await.success());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn reload_only_pems_debounce_recover_and_stop_watching_removed_dependencies() {
    timeout(Duration::from_secs(90), async {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        let cert_path = directory.path().join("client.crt");
        let key_path = directory.path().join("client.key");
        let ca_path = directory.path().join("ca.crt");
        let shadow_cert = directory.path().join("shadow.crt");
        let shadow_key = directory.path().join("shadow.key");
        let first = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
        let second = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
        for cert in [&cert_path, &ca_path, &shadow_cert] {
            std::fs::write(cert, first.cert.pem()).unwrap();
        }
        for key in [&key_path, &shadow_key] {
            std::fs::write(key, first.signing_key.serialize_pem()).unwrap();
        }
        let mut config = json!([
            {"pem": "outbound-cert", "path": cert_path},
            {"pem": "roots", "path": ca_path},
            {"address": available_address().to_string(), "protocol": {"type": "tls",
                "default_tls_target": {"cert": first.cert.pem(), "key": first.signing_key.serialize_pem(),
                    "client_ca_certs": "roots", "protocol": {"type": "socks"}},
                "shadowtls_targets": {"shadow.test": {"password": "test",
                    "handshake": {"cert": shadow_cert, "key": shadow_key}, "protocol": {"type": "socks"}}}},
                "rules": [{"masks": "0.0.0.0/0", "action": "allow", "client_chain": [{
                    "address": "127.0.0.1:9", "protocol": {"type": "tls", "cert": "outbound-cert", "key": key_path,
                        "protocol": {"type": "socks"}}
                }]}]}
        ]);
        std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
        let mut child = Process::start(&path, &[]);
        child.wait_for("Servers ready").await;

        std::fs::write(&cert_path, second.cert.pem()).unwrap();
        assert_no_reload(&mut child, Duration::from_millis(3500), "first write debounce").await;
        std::fs::write(&key_path, second.signing_key.serialize_pem()).unwrap();
        assert_no_reload(&mut child, Duration::from_secs(4), "second write debounce").await;
        child.wait_for("Servers ready").await;

        std::fs::write(&key_path, first.signing_key.serialize_pem()).unwrap();
        child.wait_for("Reload rejected").await;
        std::fs::write(&key_path, second.signing_key.serialize_pem()).unwrap();
        child.wait_for("Servers ready").await;

        std::fs::write(&ca_path, "incomplete").unwrap();
        child.wait_for("Reload rejected").await;
        let replacement = directory.path().join("next.crt");
        std::fs::write(&replacement, second.cert.pem()).unwrap();
        std::fs::rename(&replacement, &ca_path).unwrap();
        child.wait_for("Servers ready").await;

        std::fs::write(&shadow_cert, second.cert.pem()).unwrap();
        std::fs::write(&shadow_key, second.signing_key.serialize_pem()).unwrap();
        child.wait_for("Servers ready").await;

        std::fs::remove_file(&key_path).unwrap();
        child.wait_for("Reload rejected").await;
        std::fs::write(&key_path, second.signing_key.serialize_pem()).unwrap();
        child.wait_for("Servers ready").await;

        let missing = directory.path().join("new/client.key");
        config[2]["rules"][0]["client_chain"][0]["protocol"]["key"] = json!(missing);
        std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
        child.wait_for("Reload rejected").await;
        std::fs::create_dir(missing.parent().unwrap()).unwrap();
        std::fs::write(&missing, second.signing_key.serialize_pem()).unwrap();
        child.wait_for("Servers ready").await;

        config[2]["rules"] = json!(["allow-all-direct"]);
        config.as_array_mut().unwrap().remove(0);
        std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
        child.wait_for("Servers ready").await;
        std::fs::write(&cert_path, "removed dependency").unwrap();
        std::fs::write(&missing, "removed dependency").unwrap();
        assert_no_reload(&mut child, Duration::from_millis(5500), "removed dependencies").await;
        child.signal(libc::SIGTERM);
        assert!(child.exit().await.success());

        let mut child = Process::start(&path, &["--no-reload"]);
        child.wait_for("Servers ready").await;
        std::fs::write(&ca_path, "incomplete").unwrap();
        assert_no_reload(&mut child, Duration::from_millis(5500), "disabled reload").await;
        child.signal(libc::SIGHUP);
        child.wait_for("Reload rejected").await;
        std::fs::write(&ca_path, second.cert.pem()).unwrap();
        child.signal(libc::SIGHUP);
        child.wait_for("Servers ready").await;
        child.signal(libc::SIGTERM);
        assert!(child.exit().await.success());
    }).await.unwrap();
}

#[test]
fn managed_check_has_no_network_state_or_bind_side_effects() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let state = directory.path().join("state");
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    occupied.set_nonblocking(true).unwrap();
    let challenge = occupied.local_addr().unwrap();
    let config = json!([
        {"certificate_source":"managed", "type":"acme", "domains":["proxy.test"], "state_dir":state,
            "directory_url":format!("http://{challenge}/directory"),
            "challenge":{"type":"http01", "listen":[challenge.to_string()]}},
        {"address":available_address().to_string(), "protocol":{"type":"tls", "tls_targets":{"proxy.test":{
            "certificate_source":"managed", "protocol":{"type":"socks"}
        }}}}
    ]);
    std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
    for mode in ["check", "--dry-run"] {
        let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
            .args([mode, "-t", "1"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!state.exists());
        assert_eq!(
            occupied.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}
