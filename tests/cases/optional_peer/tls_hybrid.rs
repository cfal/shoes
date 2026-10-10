use std::{io, io::Write, process::Command, time::Duration};

use rustls::pki_types::{CertificateDer, pem::PemObject};
use serde_json::json;
use shoes_test_support::{
    certs::generate_test_cert_files, port_helper::PortHelper, process::ProcessGuard,
    test_fixture::start_shoes_server, test_servers::start_tcp_stream_echo_server,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

fn start_xray(config: serde_json::Value) -> io::Result<(ProcessGuard, tempfile::NamedTempFile)> {
    let binary = std::env::var_os("SHOES_TEST_XRAY_BIN").unwrap_or_else(|| "xray".into());
    let mut file = tempfile::NamedTempFile::new()?;
    file.write_all(config.to_string().as_bytes())?;
    file.flush()?;
    let child = Command::new(binary)
        .args(["run", "-format", "json", "-config"])
        .arg(file.path())
        .env("GOMAXPROCS", "1")
        .spawn()?;
    Ok((ProcessGuard::new(child, "xray hybrid TLS peer"), file))
}

async fn echo_through_http(port: u16, target_port: u16) -> io::Result<()> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
    stream
        .write_all(
            format!(
                "CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        headers.push(stream.read_u8().await?);
        assert!(headers.len() < 4096);
    }
    assert!(
        headers.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&headers)
    );
    let payload: Vec<_> = (0..65537).map(|i| (i % 251) as u8).collect();
    stream.write_all(&payload).await?;
    let mut response = vec![0; payload.len()];
    stream.read_exact(&mut response).await?;
    assert_eq!(payload, response);
    Ok(())
}

#[tokio::test]
async fn xray_both_native_hybrids_in_both_directions() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = async {
        let (cert_path, key_path) = generate_test_cert_files()?;
        let pem = std::fs::read(&cert_path)?;
        let cert = CertificateDer::from_pem_slice(&pem)?;
        let fingerprint = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &cert);
        let fingerprint: String = fingerprint
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
        for group in ["X25519MLKEM768", "SecP256r1MLKEM768"] {
            for shoes_is_server in [false, true] {
                let mut ports = PortHelper::new();
                let (_, server_port) = ports.get_localhost_listener_port();
                let (_, client_port) = ports.get_localhost_listener_port();
                // Xray's "unsafe" fingerprint selects native Go TLS, not a uTLS preset
                // that can override curve preferences. Certificate pinning stays enabled.
                let (shoes_config, xray_config) = if shoes_is_server {
                    (
                        json!([{
                            "address": format!("0.0.0.0:{server_port}"),
                            "protocol": {"type": "tls", "default_tls_target": {
                                "cert": cert_path.to_str().unwrap(), "key": key_path.to_str().unwrap(),
                                "key_exchange_groups": [group], "protocol": {"type": "http"}
                            }}
                        }]),
                        json!({
                            "log": {"loglevel": "warning"},
                            "inbounds": [{"listen": "0.0.0.0", "port": client_port, "protocol": "http", "settings": {}}],
                            "outbounds": [{"protocol": "http", "settings": {"servers": [{"address": "127.0.0.1", "port": server_port}]},
                                "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {
                                    "serverName": "test.local", "pinnedPeerCertSha256": fingerprint,
                                    "minVersion": "1.3", "curvePreferences": [group], "fingerprint": "unsafe"
                                }}}]
                        }),
                    )
                } else {
                    (
                        json!([{
                            "address": format!("0.0.0.0:{client_port}"), "protocol": {"type": "http"},
                            "rules": [{"mask": "0.0.0.0/0", "action": "allow", "client_chain": [{
                                "address": format!("127.0.0.1:{server_port}"),
                                "protocol": {"type": "tls", "verify": false, "server_fingerprints": [fingerprint], "sni_hostname": "test.local",
                                    "key_exchange_groups": [group], "protocol": {"type": "http"}}
                            }]}]
                        }]),
                        json!({
                            "log": {"loglevel": "warning"},
                            "inbounds": [{"listen": "0.0.0.0", "port": server_port, "protocol": "http", "settings": {},
                                "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {
                                    "minVersion": "1.3", "curvePreferences": [group],
                                    "certificates": [{"certificateFile": cert_path.to_str().unwrap(), "keyFile": key_path.to_str().unwrap()}]
                                }}}],
                            "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}]
                        }),
                    )
                };
                let _shoes = start_shoes_server(&serde_yaml::to_string(&shoes_config)?)?;
                let _xray = start_xray(xray_config)?;
                ports.wait_for_all_ports().await?;
                echo_through_http(client_port, echo.local_addr().port()).await?;
            }
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    tokio::time::timeout(Duration::from_secs(45), scenario).await?
}

#[tokio::test]
async fn singbox_hybrid_quic_tuic_and_hysteria2() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = async {
        let (cert_path, key_path) = generate_test_cert_files()?;
        let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
        for protocol in ["tuic", "hysteria2"] {
            let mut ports = PortHelper::new();
            let (_, server_port) = ports.get_quic_listener_port();
            let (_, client_port) = ports.get_localhost_listener_port();
            let uuid = "550e8400-e29b-41d4-a716-446655440000";
            let mut inner = json!({"type": protocol, "password": "hybrid-test"});
            if protocol == "tuic" {
                inner["uuid"] = uuid.into();
            }
            let shoes = json!([{
                "address": format!("0.0.0.0:{server_port}"), "transport": "quic", "protocol": inner,
                "quic_settings": {"cert": cert_path.to_str().unwrap(), "key": key_path.to_str().unwrap(),
                    "alpn_protocols": ["h3"], "num_endpoints": 1, "key_exchange_groups": ["X25519MLKEM768"]}
            }]);
            let mut outbound = json!({"type": protocol, "tag": "peer", "server": "127.0.0.1", "server_port": server_port, "password": "hybrid-test",
                "tls": {"enabled": true, "insecure": true, "alpn": ["h3"], "curve_preferences": ["X25519MLKEM768"]}});
            if protocol == "tuic" {
                outbound["uuid"] = uuid.into();
            }
            let singbox = json!({"log": {"level": "warn"}, "inbounds": [{"type": "http", "listen": "0.0.0.0", "listen_port": client_port}],
                "outbounds": [outbound], "route": {"final": "peer"}});
            let _shoes = start_shoes_server(&serde_yaml::to_string(&shoes)?)?;
            let _singbox =
                shoes_test_support::test_fixture::start_singbox_server(&singbox.to_string())?;
            ports.wait_for_all_ports().await?;
            echo_through_http(client_port, echo.local_addr().port()).await?;
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    tokio::time::timeout(Duration::from_secs(30), scenario).await?
}
