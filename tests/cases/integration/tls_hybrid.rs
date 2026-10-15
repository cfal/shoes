use std::{io, sync::Arc, time::Duration};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use shoes_test_support::{port_helper::PortHelper, test_fixture::start_shoes_server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn provider(name: &str) -> Arc<rustls::crypto::CryptoProvider> {
    use rustls::crypto::aws_lc_rs::{default_provider, kx_group};
    let mut provider = default_provider();
    provider.kx_groups = vec![match name {
        "X25519MLKEM768" => kx_group::X25519MLKEM768,
        "SecP256r1MLKEM768" => kx_group::SECP256R1MLKEM768,
        "X25519" => kx_group::X25519,
        _ => unreachable!(),
    }];
    Arc::new(provider)
}

#[tokio::test]
async fn tls_server_named_and_default_targets_enforce_groups() -> io::Result<()> {
    let scenario = async {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let echo =
            shoes_test_support::test_servers::start_tcp_stream_echo_server("0.0.0.0", 0).await?;
        for group in ["X25519MLKEM768", "SecP256r1MLKEM768"] {
            for default_target in [false, true] {
                let mut ports = PortHelper::new();
                let (_, port) = ports.get_localhost_listener_port();
                let target = serde_json::json!({
                    "cert": cert.cert.pem(), "key": cert.signing_key.serialize_pem(),
                    "key_exchange_groups": [group],
                    "protocol": {"type": "forward", "target": format!("127.0.0.1:{}", echo.local_addr().port())}
                });
                let mut protocol = serde_json::json!({"type": "tls"});
                if default_target {
                    protocol["default_tls_target"] = target;
                } else {
                    protocol["tls_targets"] = serde_json::json!({"localhost": target});
                }
                let config = serde_json::json!([{"address": format!("0.0.0.0:{port}"), "protocol": protocol}]);
                let _shoes = start_shoes_server(&serde_yaml::to_string(&config).unwrap())?;
                ports.wait_for_all_ports().await?;
                for peer_group in [group, "X25519"] {
                    let provider = provider(peer_group);
                    let expected = provider.kx_groups[0].name();
                    let client = rustls::ClientConfig::builder_with_provider(provider)
                        .with_protocol_versions(&[&rustls::version::TLS13])
                        .unwrap()
                        .with_root_certificates(roots.clone())
                        .with_no_client_auth();
                    let result = tokio_rustls::TlsConnector::from(Arc::new(client))
                        .connect(
                            "localhost".try_into().unwrap(),
                            TcpStream::connect(("127.0.0.1", port)).await?,
                        )
                        .await;
                    if peer_group == "X25519" {
                        assert!(result.is_err(), "server ignored {group} allowlist");
                        continue;
                    }
                    let mut stream = result?;
                    assert_eq!(
                        stream
                            .get_ref()
                            .1
                            .negotiated_key_exchange_group()
                            .unwrap()
                            .name(),
                        expected
                    );
                    let payload = vec![0x5a; 64 * 1024];
                    stream.write_all(&payload).await?;
                    stream.flush().await?;
                    let mut response = vec![0; payload.len()];
                    stream.read_exact(&mut response).await?;
                    assert_eq!(payload, response);
                }
            }
        }
        Ok(())
    };
    tokio::time::timeout(Duration::from_secs(30), scenario).await?
}

#[tokio::test]
async fn tls_client_enforces_groups() -> io::Result<()> {
    let scenario = async {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let fingerprint = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, cert.cert.der());
        let fingerprint: String = fingerprint
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        for group in ["X25519MLKEM768", "SecP256r1MLKEM768"] {
            for peer_group in [group, "X25519"] {
                let listener = TcpListener::bind("0.0.0.0:0").await?;
                let peer_port = listener.local_addr()?.port();
                let provider = provider(peer_group);
                let expected = provider.kx_groups[0].name();
                let server = rustls::ServerConfig::builder_with_provider(provider)
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(
                        vec![CertificateDer::from_pem_slice(cert.cert.pem().as_bytes()).unwrap()],
                        PrivateKeyDer::from_pem_slice(cert.signing_key.serialize_pem().as_bytes())
                            .unwrap(),
                    )
                    .unwrap();
                let mut ports = PortHelper::new();
                let (_, port) = ports.get_localhost_listener_port();
                let config = serde_json::json!([{
                    "address": format!("0.0.0.0:{port}"),
                    "protocol": {"type": "http"},
                    "rules": [{"mask": "0.0.0.0/0", "action": "allow", "client_chain": [{
                        "address": format!("127.0.0.1:{peer_port}"),
                        "protocol": {"type": "tls", "verify": false, "server_fingerprints": [fingerprint],
                            "sni_hostname": "localhost", "key_exchange_groups": [group], "protocol": {"type": "portforward"}}
                    }]}]
                }]);
                let _shoes = start_shoes_server(&serde_yaml::to_string(&config).unwrap())?;
                ports.wait_for_all_ports().await?;
                let client = async {
                    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
                    stream
                        .write_all(b"CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: localhost\r\n\r\n")
                        .await?;
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") {
                        match stream.read_u8().await {
                            Ok(byte) => header.push(byte),
                            Err(_) if peer_group == "X25519" => return Ok(()),
                            Err(error) => return Err(error),
                        }
                        assert!(header.len() < 4096);
                    }
                    if peer_group == "X25519" {
                        assert!(!header.starts_with(b"HTTP/1.1 200"));
                        return Ok(());
                    }
                    assert!(header.starts_with(b"HTTP/1.1 200"));
                    stream.write_all(b"hybrid client").await?;
                    let mut response = [0; 13];
                    stream.read_exact(&mut response).await?;
                    assert_eq!(&response, b"hybrid client");
                    io::Result::Ok(())
                };
                let server = async {
                    let (socket, _) = listener.accept().await?;
                    let result = tokio_rustls::TlsAcceptor::from(Arc::new(server))
                        .accept(socket)
                        .await;
                    if peer_group == "X25519" {
                        assert!(result.is_err(), "client ignored {group} allowlist");
                        return Ok(());
                    }
                    let mut stream = result?;
                    assert_eq!(
                        stream
                            .get_ref()
                            .1
                            .negotiated_key_exchange_group()
                            .unwrap()
                            .name(),
                        expected
                    );
                    let mut payload = [0; 13];
                    stream.read_exact(&mut payload).await?;
                    stream.write_all(&payload).await?;
                    stream.shutdown().await?;
                    io::Result::Ok(())
                };
                tokio::try_join!(client, server)?;
            }
        }
        Ok(())
    };
    tokio::time::timeout(Duration::from_secs(30), scenario).await?
}

#[tokio::test]
async fn hybrid_quic_and_tls_udp_over_tcp() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = async {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let echo = shoes_test_support::test_servers::start_udp_echo_server("0.0.0.0", 0).await?;
        for transport in ["tcp", "quic"] {
            for group in ["X25519MLKEM768", "SecP256r1MLKEM768"] {
                let mut ports = PortHelper::new();
                let (_, server_port) = if transport == "quic" {
                    ports.get_quic_listener_port()
                } else {
                    ports.get_localhost_listener_port()
                };
                let (_, client_port) = ports.get_localhost_listener_port();
                let inner = serde_json::json!({"type": "vless", "user_id": "550e8400-e29b-41d4-a716-446655440000"});
                let server_tls = serde_json::json!({"cert": cert.cert.pem(), "key": cert.signing_key.serialize_pem(), "key_exchange_groups": [group]});
                let client_tls = serde_json::json!({"verify": false, "sni_hostname": "localhost", "key_exchange_groups": [group]});
                let mut server = serde_json::json!({"address": format!("0.0.0.0:{server_port}"), "transport": transport});
                let mut outbound = serde_json::json!({"address": format!("127.0.0.1:{server_port}"), "transport": transport});
                if transport == "quic" {
                    server["quic_settings"] = server_tls;
                    server["protocol"] = inner.clone();
                    outbound["quic_settings"] = client_tls;
                    outbound["protocol"] = inner;
                } else {
                    let mut target = server_tls;
                    target["protocol"] = inner.clone();
                    server["protocol"] =
                        serde_json::json!({"type": "tls", "default_tls_target": target});
                    let mut client = client_tls;
                    client["type"] = "tls".into();
                    client["protocol"] = inner;
                    outbound["protocol"] = client;
                }
                let config = serde_json::json!([server, {
                    "address": format!("0.0.0.0:{client_port}"), "protocol": {"type": "socks"},
                    "rules": [{"mask": "0.0.0.0/0", "action": "allow", "client_chain": [outbound]}]
                }]);
                let _shoes = start_shoes_server(&serde_yaml::to_string(&config)?)?;
                ports.wait_for_all_ports().await?;
                let association = shoes_test_support::socks5::Socks5UdpAssociation::connect(
                    "127.0.0.1",
                    client_port,
                )
                .await?;
                let target = ([127, 0, 0, 1], echo.local_addr().port()).into();
                let response = association.send_to(target, b"hybrid datagram").await?;
                assert_eq!(response, b"hybrid datagram [ECHO]");
            }
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    tokio::time::timeout(Duration::from_secs(40), scenario).await?
}
