use super::*;
use rustls::{ClientConnection, HandshakeKind, NamedGroup, ServerConnection};
use std::io::{Read, Write};

fn configured_groups(names: &str) -> TlsKeyExchangeGroups {
    if names.is_empty() {
        return TlsKeyExchangeGroups::default();
    }
    serde_yaml::from_str(&format!("[{names}]")).unwrap()
}

fn fingerprint(cert: &rcgen::Certificate) -> String {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, cert.der())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn configs(
    client_groups: &str,
    server_groups: &str,
) -> (rustls::ClientConfig, rustls::ServerConfig) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let client = try_create_client_config(
        false,
        vec![fingerprint(&cert.cert)],
        vec!["hybrid-test".into()],
        true,
        None,
        false,
        &configured_groups(client_groups),
    )
    .unwrap();
    let server = try_create_server_config(
        cert.cert.pem().as_bytes(),
        cert.signing_key.serialize_pem().as_bytes(),
        vec![],
        &["hybrid-test".into()],
        &[],
        &configured_groups(server_groups),
    )
    .unwrap();
    (client, server)
}

fn handshake(
    client: Arc<rustls::ClientConfig>,
    server: Arc<rustls::ServerConfig>,
) -> Result<(ClientConnection, ServerConnection), rustls::Error> {
    let mut client = ClientConnection::new(client, "localhost".try_into().unwrap()).unwrap();
    let mut server = ServerConnection::new(server).unwrap();
    for _ in 0..16 {
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        for fragment in wire.chunks(37) {
            server.read_tls(&mut &fragment[..]).unwrap();
            server.process_new_packets()?;
        }
        wire.clear();
        server.write_tls(&mut wire).unwrap();
        for fragment in wire.chunks(37) {
            client.read_tls(&mut &fragment[..]).unwrap();
            client.process_new_packets()?;
        }
        if !client.is_handshaking()
            && !server.is_handshaking()
            && !client.wants_write()
            && !server.wants_write()
        {
            return Ok((client, server));
        }
    }
    panic!("handshake did not converge");
}

fn assert_group(client: &ClientConnection, server: &ServerConnection, group: NamedGroup) {
    assert_eq!(
        client.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(
        server.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(
        client.negotiated_key_exchange_group().unwrap().name(),
        group
    );
    assert_eq!(
        server.negotiated_key_exchange_group().unwrap().name(),
        group
    );
    assert_eq!(client.alpn_protocol(), Some(b"hybrid-test".as_slice()));
}

#[test]
fn native_hybrids_exchange_data_and_resume_with_fresh_hybrid_keys() {
    for (name, group) in [
        ("X25519MLKEM768", NamedGroup::X25519MLKEM768),
        ("SecP256r1MLKEM768", NamedGroup::secp256r1MLKEM768),
    ] {
        let (client_config, server_config) = configs(name, name);
        assert!(!client_config.enable_early_data);
        assert_eq!(server_config.max_early_data_size, 0);
        assert!(!server_config.send_half_rtt_data);
        let client_config = Arc::new(client_config);
        let server_config = Arc::new(server_config);
        for kind in [HandshakeKind::Full, HandshakeKind::Resumed] {
            let (mut client, mut server) =
                handshake(client_config.clone(), server_config.clone()).unwrap();
            assert_group(&client, &server, group);
            assert_eq!(client.handshake_kind(), Some(kind));
            assert_eq!(server.handshake_kind(), Some(kind));
            assert!(client.early_data().is_none());
            assert!(server.early_data().is_none());
            client.writer().write_all(b"client payload").unwrap();
            let mut wire = Vec::new();
            client.write_tls(&mut wire).unwrap();
            server.read_tls(&mut wire.as_slice()).unwrap();
            server.process_new_packets().unwrap();
            let mut payload = [0; 14];
            server.reader().read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"client payload");
            server.writer().write_all(b"server payload").unwrap();
            wire.clear();
            server.write_tls(&mut wire).unwrap();
            client.read_tls(&mut wire.as_slice()).unwrap();
            client.process_new_packets().unwrap();
            client.reader().read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"server payload");
        }
    }
}

#[test]
fn hybrid_only_rejects_classical_peers_in_both_roles() {
    for hybrid in ["X25519MLKEM768", "SecP256r1MLKEM768"] {
        for classical in ["X25519", "SecP256r1", "SecP384r1"] {
            for (client, server) in [(hybrid, classical), (classical, hybrid)] {
                let (client, server) = configs(client, server);
                assert!(handshake(Arc::new(client), Arc::new(server)).is_err());
            }
        }
    }
    let (client, server) = configs("X25519MLKEM768", "SecP256r1MLKEM768");
    assert!(handshake(Arc::new(client), Arc::new(server)).is_err());
}

#[test]
fn hybrid_only_rejects_tls12_in_both_roles() {
    for hybrid in ["X25519MLKEM768", "SecP256r1MLKEM768"] {
        let (client, mut server) = configs(hybrid, "X25519");
        server = rustls::ServerConfig::builder_with_provider(server.crypto_provider().clone())
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(server.cert_resolver.clone());
        assert!(handshake(Arc::new(client), Arc::new(server)).is_err());

        let (client, server) = configs("X25519", hybrid);
        let client = rustls::ClientConfig::builder_with_provider(client.crypto_provider().clone())
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(get_disabled_verifier())
            .with_no_client_auth();
        assert!(handshake(Arc::new(client), Arc::new(server)).is_err());
    }
}

#[test]
fn explicit_order_hello_retry_and_classical_fallback() {
    let (client, server) = configs("X25519MLKEM768, SecP256r1MLKEM768", "SecP256r1MLKEM768");
    let (client, server) = handshake(Arc::new(client), Arc::new(server)).unwrap();
    assert_group(&client, &server, NamedGroup::secp256r1MLKEM768);
    assert_eq!(
        client.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
    for (client, server) in [
        ("X25519MLKEM768, X25519", "X25519"),
        ("X25519", "X25519MLKEM768, X25519"),
        ("", "X25519"),
        ("X25519", ""),
    ] {
        let (client, server) = configs(client, server);
        let (client, server) = handshake(Arc::new(client), Arc::new(server)).unwrap();
        assert_group(&client, &server, NamedGroup::X25519);
    }
}

#[test]
fn provider_selection_is_local_and_ordered() {
    let original: Vec<_> = get_crypto_provider()
        .kx_groups
        .iter()
        .map(|g| g.name())
        .collect();
    let (client, server) = configs("SecP256r1MLKEM768, X25519MLKEM768", "SecP256r1MLKEM768");
    assert_eq!(
        client
            .crypto_provider()
            .kx_groups
            .iter()
            .map(|g| g.name())
            .collect::<Vec<_>>(),
        [NamedGroup::secp256r1MLKEM768, NamedGroup::X25519MLKEM768]
    );
    assert_eq!(server.crypto_provider().kx_groups.len(), 1);
    for provider in [
        get_crypto_provider(),
        create_dns_client_config().crypto_provider().clone(),
        try_create_client_config(false, vec![], vec![], true, None, true, &Default::default())
            .unwrap()
            .crypto_provider()
            .clone(),
    ] {
        assert_eq!(
            provider
                .kx_groups
                .iter()
                .map(|g| g.name())
                .collect::<Vec<_>>(),
            original
        );
    }
}

#[test]
fn hybrid_exchange_preserves_mutual_authentication_and_pinning() {
    for group in ["X25519MLKEM768", "SecP256r1MLKEM768"] {
        let server_cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let client_cert = rcgen::generate_simple_self_signed(vec!["client".into()]).unwrap();
        for (client_auth, pin_matches, success) in [
            (true, true, true),
            (false, true, false),
            (true, false, false),
        ] {
            let client = try_create_client_config(
                false,
                vec![if pin_matches {
                    fingerprint(&server_cert.cert)
                } else {
                    "00".repeat(32)
                }],
                vec![],
                true,
                client_auth.then(|| {
                    (
                        client_cert.signing_key.serialize_pem().into_bytes(),
                        client_cert.cert.pem().into_bytes(),
                    )
                }),
                false,
                &configured_groups(group),
            )
            .unwrap();
            let server = try_create_server_config(
                server_cert.cert.pem().as_bytes(),
                server_cert.signing_key.serialize_pem().as_bytes(),
                vec![],
                &[],
                &[fingerprint(&client_cert.cert)],
                &configured_groups(group),
            )
            .unwrap();
            assert_eq!(
                handshake(Arc::new(client), Arc::new(server)).is_ok(),
                success
            );
        }
    }
}

#[test]
fn default_and_mixed_lists_preserve_tls12_compatibility() {
    for configured in ["", "X25519MLKEM768, X25519"] {
        let (client, server) = configs(configured, "X25519");
        let mut server =
            rustls::ServerConfig::builder_with_provider(server.crypto_provider().clone())
                .with_protocol_versions(&[&rustls::version::TLS12])
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(server.cert_resolver.clone());
        server.alpn_protocols = vec![b"hybrid-test".to_vec()];
        let (client, server) = handshake(Arc::new(client), Arc::new(server)).unwrap();
        assert_eq!(
            client.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_2)
        );
        assert_eq!(
            server.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_2)
        );

        let (client, server) = configs("X25519", configured);
        let mut client =
            rustls::ClientConfig::builder_with_provider(client.crypto_provider().clone())
                .with_protocol_versions(&[&rustls::version::TLS12])
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(get_disabled_verifier())
                .with_no_client_auth();
        client.alpn_protocols = vec![b"hybrid-test".to_vec()];
        let (client, server) = handshake(Arc::new(client), Arc::new(server)).unwrap();
        assert_eq!(
            client.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_2)
        );
        assert_eq!(
            server.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_2)
        );
    }
}

#[tokio::test]
async fn crypto_stream_handles_fragmented_hybrid_handshakes() {
    use crate::crypto::{CryptoConnection, CryptoTlsStream, TlsReadMode};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        for name in ["X25519MLKEM768", "SecP256r1MLKEM768"] {
            let (client, mut server) = configs(name, name);
            // Keep this tiny duplex focused on handshake fragmentation, not post-handshake tickets.
            server.send_tls13_tickets = 0;
            let client = CryptoConnection::new_rustls_client(
                ClientConnection::new(Arc::new(client), "localhost".try_into().unwrap()).unwrap(),
            );
            let server = CryptoConnection::new_rustls_server(
                ServerConnection::new(Arc::new(server)).unwrap(),
            );
            let (client_io, server_io) = tokio::io::duplex(43);
            let (mut client, mut server) = tokio::try_join!(
                CryptoTlsStream::handshake(client_io, client, TlsReadMode::Stream, &[]),
                CryptoTlsStream::handshake(server_io, server, TlsReadMode::Stream, &[]),
            )
            .unwrap();
            let send = async {
                client.write_all(b"hybrid").await.unwrap();
                client.flush().await.unwrap();
            };
            let receive = async {
                let mut data = [0; 6];
                server.read_exact(&mut data).await.unwrap();
                assert_eq!(&data, b"hybrid");
            };
            tokio::join!(send, receive);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn quic_hybrid_data_and_disjoint_group_rejection() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        for (client_name, server_name, success) in [
            ("X25519MLKEM768", "X25519MLKEM768", true),
            ("SecP256r1MLKEM768", "SecP256r1MLKEM768", true),
            ("X25519MLKEM768", "X25519", false),
            ("X25519", "SecP256r1MLKEM768", false),
            ("", "X25519", true),
        ] {
            let (client, server) = configs(client_name, server_name);
            let server = quinn::crypto::rustls::QuicServerConfig::try_from(server).unwrap();
            let server = quinn::Endpoint::server(
                quinn::ServerConfig::with_crypto(Arc::new(server)),
                "0.0.0.0:0".parse().unwrap(),
            )
            .unwrap();
            let client = {
                let config = quinn::crypto::rustls::QuicClientConfig::try_from(client).unwrap();
                let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
                endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(config)));
                endpoint
            };
            let target = (
                std::net::Ipv4Addr::LOCALHOST,
                server.local_addr().unwrap().port(),
            )
                .into();
            let connect = client.connect(target, "localhost").unwrap();
            let accept = async { server.accept().await.unwrap().await };
            let (outbound, inbound) = tokio::join!(connect, accept);
            assert_eq!(outbound.is_ok(), success);
            assert_eq!(inbound.is_ok(), success);
            if success {
                let outbound = outbound.unwrap();
                let inbound = inbound.unwrap();
                let mut send = outbound.open_uni().await.unwrap();
                send.write_all(b"quic hybrid").await.unwrap();
                send.finish().unwrap();
                let mut receive = inbound.accept_uni().await.unwrap();
                assert_eq!(receive.read_to_end(1024).await.unwrap(), b"quic hybrid");
            }
            client.close(0u32.into(), b"done");
            server.close(0u32.into(), b"done");
            client.wait_idle().await;
            server.wait_idle().await;
        }
    })
    .await
    .unwrap();
}
