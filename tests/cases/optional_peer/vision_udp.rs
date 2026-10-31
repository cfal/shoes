use std::{path::Path, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use shoes_test_support::{
    certs::generate_test_cert_files,
    port_helper::PortHelper,
    test_fixture::{start_shoes_server, start_singbox_server},
    test_servers::{
        TlsVersion, start_tcp_stream_echo_server, start_tls_stream_echo_server,
        start_udp_echo_server_with_suffix,
    },
    vless::{VlessDestination, VlessUdpClient, parse_uuid},
};
use tokio::net::TcpStream;

const UUID: &str = "b85798ef-e9dc-46a4-9a87-8da4499d36d0";

async fn exercise(xray: bool) -> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(60), async {
        let (cert, key) = generate_test_cert_files()?;
        let cert_path: &Path = cert.as_ref();
        let key_path: &Path = key.as_ref();
        let decoy = start_tls_stream_echo_server("0.0.0.0", 0, cert_path, key_path, TlsVersion::Tls13Only).await?;
        let echo = start_udp_echo_server_with_suffix("0.0.0.0", 0, b"\x16\x03\x03").await?;
        let tcp_echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
        let private = [42; 32];
        let public = aws_lc_rs::agreement::PrivateKey::from_private_key(&aws_lc_rs::agreement::X25519, &private)
            .unwrap().compute_public_key().unwrap();
        for reality in [false, true] {
            let mut ports = PortHelper::new();
            let (_, peer_port) = ports.get_localhost_listener_port();
            let (_, shoes_port) = ports.get_localhost_listener_port();
            let (_, http_port) = ports.get_localhost_listener_port();
            let inner = json!({"type": "vless", "user_id": UUID, "udp_enabled": true});
            let outbound = if reality {
                json!({"type": "reality", "public_key": URL_SAFE_NO_PAD.encode(public.as_ref()),
                    "short_id": "0123456789abcdef", "sni_hostname": "test.local", "vision": true, "protocol": inner})
            } else {
                json!({"type": "tls", "verify": false, "sni_hostname": "test.local", "vision": true, "protocol": inner})
            };
            let mut shoes = json!([{
                "address": format!("0.0.0.0:{shoes_port}"),
                "protocol": {"type": "vless", "user_id": UUID, "udp_enabled": true},
                "rules": [{"mask": "0.0.0.0/0", "action": "allow", "client_chain": [{
                    "address": format!("127.0.0.1:{peer_port}"), "protocol": outbound
                }]}]
            }]);
            let mut http = shoes[0].clone();
            http["address"] = format!("0.0.0.0:{http_port}").into();
            http["protocol"] = json!({"type": "http"});
            shoes.as_array_mut().unwrap().push(http);
            let _peer = if xray {
                let transport = if reality {
                    json!({"network": "tcp", "security": "reality", "realitySettings": {
                        "target": format!("127.0.0.1:{}", decoy.local_addr().port()),
                        "serverNames": ["test.local"], "privateKey": URL_SAFE_NO_PAD.encode(private),
                        "shortIds": ["0123456789abcdef"]
                    }})
                } else {
                    json!({"network": "tcp", "security": "tls", "tlsSettings": {
                        "certificates": [{"certificateFile": cert_path, "keyFile": key_path}]
                    }})
                };
                super::tls_hybrid::start_xray(json!({
                    "log": {"loglevel": "warning"},
                    "inbounds": [{"listen": "0.0.0.0", "port": peer_port, "protocol": "vless",
                        "settings": {"decryption": "none", "clients": [{"id": UUID, "flow": "xtls-rprx-vision"}]},
                        "streamSettings": transport}],
                    "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}]
                }))?
            } else {
                let tls = if reality {
                    json!({"enabled": true, "server_name": "test.local", "reality": {
                        "enabled": true, "handshake": {"server": "127.0.0.1", "server_port": decoy.local_addr().port()},
                        "private_key": URL_SAFE_NO_PAD.encode(private), "short_id": ["0123456789abcdef"]
                    }})
                } else {
                    json!({"enabled": true, "certificate_path": cert_path, "key_path": key_path})
                };
                start_singbox_server(&json!({
                    "log": {"level": "warn"},
                    "inbounds": [{"type": "vless", "listen": "0.0.0.0", "listen_port": peer_port,
                        "users": [{"uuid": UUID, "flow": "xtls-rprx-vision"}], "tls": tls}],
                    "outbounds": [{"type": "direct"}]
                }).to_string())?
            };
            let _shoes = start_shoes_server(&serde_yaml::to_string(&shoes)?)?;
            ports.wait_for_all_ports().await?;
            let target = VlessDestination::Ip(([127, 0, 0, 1], echo.local_addr().port()).into());
            let mut client = VlessUdpClient::connect(TcpStream::connect(("127.0.0.1", shoes_port)).await?, parse_uuid(UUID)?, target).await?;
            let payloads = [b"one\x16".to_vec(), b"two\x16\x03\x03".to_vec(), b"embedded\x16\x03\x01\x00\x05\x01".to_vec(), vec![42; 7000]];
            for data in payloads.iter().cycle().take(12) {
                client.send_packet(data).await?;
                let mut data = data.clone();
                data.extend_from_slice(b"\x16\x03\x03");
                assert_eq!(client.recv_packet(Duration::from_secs(5)).await?, data,
                    "xray={xray}, reality={reality}");
            }
            super::tls_hybrid::echo_through_http(http_port, tcp_echo.local_addr().port()).await?;
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    }).await?
}

#[tokio::test]
async fn shoes_outbound_to_xray_tls_and_reality() -> Result<(), Box<dyn std::error::Error>> {
    exercise(true).await
}

#[tokio::test]
async fn shoes_outbound_to_sing_box_tls_and_reality() -> Result<(), Box<dyn std::error::Error>> {
    exercise(false).await
}
