use crate::{Process, available_address};
use serde_json::json;
use std::{process::Command, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[tokio::test]
async fn file_rotation_keeps_tcp_and_quic_tunnels_and_rejects_bad_reload() {
    timeout(Duration::from_secs(20), async {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        let cert_path = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        let first = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
        let second = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
        std::fs::write(&cert_path, first.cert.pem()).unwrap();
        std::fs::write(&key_path, first.signing_key.serialize_pem()).unwrap();
        let tcp = available_address();
        let quic = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let echo = shoes_test_support::test_servers::start_tcp_stream_echo_server("127.0.0.1", 0).await.unwrap();
        let config = json!([
            {"certificate_source":"shared", "type":"files", "cert":cert_path, "key":key_path, "poll_interval_secs":1},
            {"address":tcp.to_string(), "protocol":{"type":"tls", "tls_targets":{"proxy.test":{
                "certificate_source":"shared", "protocol":{"type":"forward", "target":echo.local_addr().to_string()}
            }}}},
            {"address":quic.to_string(), "transport":"quic", "quic_settings":{"certificate_source":"shared", "num_endpoints":1},
                "protocol":{"type":"forward", "target":echo.local_addr().to_string()}}
        ]);
        std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
        let mut child = Process::start(&path, &["--no-reload"]);
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
        while let Ok(line) = child.lines.try_recv() { assert!(!line.contains("Servers ready"), "certificate rotation must not reload listeners"); }
        let invalid = serde_yaml::to_string(&config).unwrap().replace("certificate_source: shared", "certificate_source: missing");
        // Keep the definition's name, but break both consumers.
        let invalid = invalid.replacen("certificate_source: missing", "certificate_source: shared", 1);
        std::fs::write(&path, invalid).unwrap();
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
