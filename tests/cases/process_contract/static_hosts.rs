use crate::{Process, available_address};
use hickory_resolver::proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use serde_json::json;
use shoes_test_support::socks5::Socks5UdpAssociation;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn static_hosts_check_and_dry_run_reject_tun_collisions_without_fake_dns() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    for (ip, valid) in [("192.0.2.1", true), ("10.233.0.1", false)] {
        let config = json!([
            {"device_name": "hostscheck0", "address": "10.233.0.1",
             "netmask": "255.255.255.0", "dns_hijack": true,
             "dns": {"servers": "udp://192.0.2.53", "hosts": {"proxy.test": ip}}}
        ]);
        std::fs::write(&path, config.to_string()).unwrap();
        for mode in ["check", "--dry-run"] {
            let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_shoes"))
                .args([mode, "-t", "1"])
                .arg(&path)
                .output()
                .await
                .unwrap();
            let error = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.success(), valid, "{mode}: {error}");
            if !valid {
                assert!(
                    error.contains(
                        "static hosts address overlaps an active fake IP range or TUN endpoint"
                    ),
                    "{mode}: {error}"
                );
            }
        }
    }
}

#[tokio::test]
async fn static_hosts_preserve_proxy_sni_credentials_and_remote_destination_resolution() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        let cert = rcgen::generate_simple_self_signed(vec!["proxy.invalid".into()]).unwrap();
        let fingerprint: String = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, cert.cert.der())
            .as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
        let cert_path = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
        let trap = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let dns = format!("udp://127.0.0.1:{}", trap.local_addr().unwrap().port());
        let target = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let front = available_address();
        let proxy = available_address();
        let config = json!([
            {"address": format!("0.0.0.0:{}", front.port()),
             "protocol": {"type": "forward", "target": format!("destination.invalid:{}", target.local_addr().unwrap().port())},
             "dns": {"servers": dns, "hosts": {"proxy.invalid": ["::1", "127.0.0.1"], "destination.invalid": "192.0.2.99"}},
             "rules": [{"mask": "0.0.0.0/0", "client_chain": {
                 "address": format!("proxy.invalid:{}", proxy.port()),
                 "protocol": {"type": "tls", "verify": false, "server_fingerprints": [fingerprint],
                     "protocol": {"type": "socks", "username": "static-user", "password": "static-secret"}}
             }}]},
            {"address": format!("0.0.0.0:{}", proxy.port()),
             "protocol": {"type": "tls", "tls_targets": {"proxy.invalid": {
                 "cert": cert_path, "key": key_path,
                 "protocol": {"type": "socks", "username": "static-user", "password": "static-secret"}
             }}},
             "dns": {"servers": dns, "hosts": {"destination.invalid": "127.0.0.1"}}}
        ]);
        std::fs::write(&path, config.to_string()).unwrap();
        let mut process = Process::start(&path, &["--no-reload"]);
        process.wait_for("Servers ready").await;
        let mut stream = tokio::net::TcpStream::connect(front).await.unwrap();
        stream.write_all(b"mapped").await.unwrap();
        let (mut destination, _) = target.accept().await.unwrap();
        let mut bytes = [0; 6];
        destination.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"mapped");
        destination.write_all(b"intact").await.unwrap();
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"intact");
        assert_eq!(trap.try_recv(&mut [0; 512]).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        drop(stream);
        drop(destination);
        process.signal(libc::SIGTERM);
        assert!(process.exit().await.success());
    }).await.unwrap();
}

#[tokio::test]
async fn static_hosts_drive_ip_routing_without_upstream_queries() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        let echo = shoes_test_support::test_servers::start_tcp_stream_echo_server("0.0.0.0", 0)
            .await.unwrap();
        let trap = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let front = available_address();
        let mut config = json!([
            {"address": format!("0.0.0.0:{}", front.port()),
             "protocol": {"type": "forward", "target": "destination.invalid:443"},
             "dns": {"servers": format!("udp://127.0.0.1:{}", trap.local_addr().unwrap().port()),
                     "hosts": {"destination.invalid": "192.0.2.1"}},
             "rules": [
                 {"mask": "192.0.2.0/24", "action": "block"},
                 {"mask": "0.0.0.0/0", "override_address": format!("127.0.0.1:{}", echo.local_addr().port())}
             ]}
        ]);
        std::fs::write(&path, config.to_string()).unwrap();
        let mut process = Process::start(&path, &["--no-reload"]);
        process.wait_for("Servers ready").await;
        let mut stream = tokio::net::TcpStream::connect(front).await.unwrap();
        let _ = stream.write_all(b"denied").await;
        assert!(stream.read_u8().await.is_err());
        drop(stream);

        config[0]["dns"]["hosts"]["destination.invalid"] = json!("198.51.100.1");
        std::fs::write(&path, config.to_string()).unwrap();
        process.signal(libc::SIGHUP);
        process.wait_for("Servers ready").await;
        let mut stream = tokio::net::TcpStream::connect(front).await.unwrap();
        crate::roundtrip(&mut stream).await;
        drop(stream);
        assert_eq!(trap.try_recv(&mut [0; 512]).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        process.signal(libc::SIGTERM);
        assert!(process.exit().await.success());
    }).await.unwrap();
}

async fn query(port: u16, kind: RecordType) -> Message {
    let association = Socks5UdpAssociation::connect("127.0.0.1", port)
        .await
        .unwrap();
    let mut request = Message::query();
    request.metadata.id = 92;
    request.add_query(Query::query(
        Name::from_ascii("STATIC.invalid.").unwrap(),
        kind,
    ));
    let reply = association
        .send_to("198.18.0.1:53".parse().unwrap(), &request.to_vec().unwrap())
        .await
        .unwrap();
    let response = Message::from_vec(&reply).unwrap();
    assert_eq!(response.metadata.id, 92);
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    response
}

#[tokio::test]
async fn static_hosts_dns_reload_replaces_answers_and_rejects_invalid_candidates() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        let port = available_address().port();
        let trap = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let mut config = json!([
            {"dns_group": "shared", "dns_servers": format!("udp://127.0.0.1:{}", trap.local_addr().unwrap().port()),
             "fake_ip": true, "hosts": {"static.invalid": ["192.0.2.1", "192.0.2.2"]}},
            {"address": format!("0.0.0.0:{port}"), "protocol": {"type": "socks", "udp_enabled": true}, "dns": {"servers": "shared"}}
        ]);
        std::fs::write(&path, config.to_string()).unwrap();
        let mut process = Process::start(&path, &["--no-reload"]);
        process.wait_for("Servers ready").await;
        assert_eq!(query(port, RecordType::A).await.answers.len(), 2);
        assert!(query(port, RecordType::AAAA).await.answers.is_empty());
        config[0]["hosts"]["static.invalid"] = json!("192.0.2.3");
        std::fs::write(&path, config.to_string()).unwrap();
        process.signal(libc::SIGHUP);
        process.wait_for("Servers ready").await;
        let updated = query(port, RecordType::A).await;
        assert_eq!(updated.answers.len(), 1);
        let RData::A(ip) = updated.answers[0].data else { panic!() };
        assert_eq!(ip.0.to_string(), "192.0.2.3");

        config[0]["hosts"]["static.invalid"] = json!("198.18.0.5");
        std::fs::write(&path, config.to_string()).unwrap();
        process.signal(libc::SIGHUP);
        process.wait_for("Reload rejected").await;
        assert_eq!(query(port, RecordType::A).await.answers, updated.answers);
        assert_eq!(trap.try_recv(&mut [0; 512]).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        process.signal(libc::SIGTERM);
        assert!(process.exit().await.success());
    }).await.unwrap();
}
