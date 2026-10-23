use super::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn certificate() -> rcgen::CertifiedKey<rcgen::KeyPair> {
    rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap()
}

fn write_pair(dir: &Path, cert: &rcgen::CertifiedKey<rcgen::KeyPair>) {
    std::fs::write(dir.join("cert.pem"), cert.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), cert.signing_key.serialize_pem()).unwrap();
}

fn file_source(dir: &Path) -> Arc<Source> {
    Source::new(
        "test".into(),
        Spec::Files {
            cert: Input::File(dir.join("cert.pem")),
            key: Input::File(dir.join("key.pem")),
            interval: 1,
        },
    )
    .unwrap()
}

#[test]
fn file_updates_are_atomic_and_recover() {
    let dir = tempfile::tempdir().unwrap();
    let first = certificate();
    let second = certificate();
    write_pair(dir.path(), &first);
    let source = file_source(dir.path());
    assert!(!source.refresh_files().unwrap());
    let old = source.current().unwrap();
    std::fs::write(dir.path().join("cert.pem"), second.cert.pem()).unwrap();
    assert!(source.refresh_files().is_err());
    assert!(Arc::ptr_eq(&source.current().unwrap(), &old));
    std::fs::write(
        dir.path().join("key.pem"),
        "-----BEGIN PRIVATE KEY-----\nincomplete",
    )
    .unwrap();
    assert!(source.refresh_files().is_err());
    std::fs::remove_file(dir.path().join("key.pem")).unwrap();
    assert!(source.refresh_files().is_err());
    assert!(Arc::ptr_eq(&source.current().unwrap(), &old));
    std::fs::write(
        dir.path().join("next.key"),
        second.signing_key.serialize_pem(),
    )
    .unwrap();
    std::fs::rename(dir.path().join("next.key"), dir.path().join("key.pem")).unwrap();
    assert!(source.refresh_files().unwrap());
    assert_eq!(source.current().unwrap().cert[0], *second.cert.der());
    assert!(!source.refresh_files().unwrap());
    assert!(!format!("{source:?}").contains("PRIVATE KEY"));
}

#[cfg(unix)]
#[test]
fn symlink_replacement_and_expiry() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&b).unwrap();
    let first = certificate();
    let second = certificate();
    write_pair(&a, &first);
    write_pair(&b, &second);
    symlink(&a, dir.path().join("current")).unwrap();
    let source = file_source(&dir.path().join("current"));
    symlink(&b, dir.path().join("next")).unwrap();
    std::fs::rename(dir.path().join("next"), dir.path().join("current")).unwrap();
    assert!(source.refresh_files().unwrap());
    assert_eq!(source.current().unwrap().cert[0], *second.cert.der());
    source.material.write().as_mut().unwrap().not_after = now() - 1;
    assert!(source.current().is_none());
}

fn managed_yaml(state: &Path, challenge: &str, target: &str) -> String {
    format!(
        r#"
- certificate_source: public
  type: acme
  domains: [proxy.test]
  directory_url: http://127.0.0.1:9/directory
  state_dir: '{}'
  terms_of_service: https://ca.test/terms
  challenge: {{ {challenge} }}
- address: 127.0.0.1:18443
  protocol:
    type: tls
    tls_targets:
      proxy.test:
        {target}
        protocol: {{ type: socks }}
"#,
        state.display()
    )
}

fn compile(yaml: &str) -> io::Result<crate::config::ValidatedConfigs> {
    crate::config::create_server_configs(serde_yaml::from_str(yaml).map_err(io::Error::other)?)
}

#[test]
fn managed_validation_has_no_state_or_network_side_effects() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("not-created");
    for challenge in [
        "type: http01, listen: ['127.0.0.1:18080']",
        "type: tls_alpn01",
    ] {
        let yaml = managed_yaml(&state, challenge, "certificate_source: public");
        let validated = compile(&yaml).unwrap();
        assert_eq!(validated.certificates.len(), 1);
        assert!(validated.certificates[0].current().is_none());
        assert!(!state.exists());
    }
}

#[test]
fn managed_schema_references_and_coverage() {
    let dir = tempfile::tempdir().unwrap();
    let good = managed_yaml(dir.path(), "type: tls_alpn01", "certificate_source: public");
    for bad in [
        good.replace(
            "certificate_source: public\n        protocol",
            "certificate_source: missing\n        protocol",
        ),
        good.replace(
            "certificate_source: public\n        protocol",
            "certificate_source: public\n        cert: secret\n        protocol",
        ),
        good.replace("domains: [proxy.test]", "domains: ['*.proxy.test']"),
        good.replace("domains: [proxy.test]", "domains: [other.test]"),
        good.replace("domains: [proxy.test]", "domains: [proxy.test, proxy.test]"),
        good.replace("type: tls_alpn01", "type: dns01"),
        good.replace(
            "type: tls_alpn01",
            "type: http01, listen: ['127.0.0.1:18443']",
        ),
        good.replace("type: tls_alpn01", "type: http01, listen: []"),
        good.replace("http://127.0.0.1:9", "http://ca.test"),
        good.replace("certificate_source: public\n        protocol", "protocol"),
    ] {
        assert!(compile(&bad).is_err(), "unexpectedly accepted: {bad}");
    }
    let duplicate = format!(
        "{}\n{}",
        good,
        good.lines().skip(1).take(7).collect::<Vec<_>>().join("\n")
    );
    assert!(compile(&duplicate).is_err());
}

#[tokio::test]
async fn legacy_paths_named_pems_and_inline_remain_supported() {
    let dir = tempfile::tempdir().unwrap();
    let cert = certificate();
    write_pair(dir.path(), &cert);
    for named in [false, true] {
        let mut target = serde_yaml::to_value(serde_json::json!({
            "address": "127.0.0.1:18443", "protocol": {"type":"tls", "default_tls_target": {
                "cert": if named {"chain".to_owned()} else {dir.path().join("cert.pem").display().to_string()},
                "key": if named {"private".to_owned()} else {dir.path().join("key.pem").display().to_string()},
                "protocol": {"type":"socks"}
            }}
        })).unwrap();
        let mut values = vec![target.clone()];
        if named {
            values.push(
                serde_yaml::to_value(
                    serde_json::json!({"pem":"chain", "path": dir.path().join("cert.pem")}),
                )
                .unwrap(),
            );
            values.push(
                serde_yaml::to_value(
                    serde_json::json!({"pem":"chain-alias", "path": dir.path().join("cert.pem")}),
                )
                .unwrap(),
            );
            values.push(
                serde_yaml::to_value(
                    serde_json::json!({"pem":"private", "path": dir.path().join("key.pem")}),
                )
                .unwrap(),
            );
        }
        let configs: Vec<Config> =
            serde_yaml::from_value(serde_yaml::Value::Sequence(values)).unwrap();
        let (configs, _) = crate::config::convert_cert_paths(configs).await.unwrap();
        assert_eq!(
            crate::config::create_server_configs(configs)
                .unwrap()
                .certificates
                .len(),
            1
        );
        target["protocol"]["default_tls_target"]["cert"] =
            serde_yaml::Value::String(cert.cert.pem());
        target["protocol"]["default_tls_target"]["key"] =
            serde_yaml::Value::String(cert.signing_key.serialize_pem());
        let configs: Vec<Config> =
            serde_yaml::from_value(serde_yaml::Value::Sequence(vec![target])).unwrap();
        assert!(
            crate::config::create_server_configs(configs)
                .unwrap()
                .certificates
                .is_empty()
        );
    }
}

fn tls_base(source: &Arc<Source>, alpn: &str) -> Arc<rustls::ServerConfig> {
    Arc::new(
        crate::rustls_config_util::try_create_server_config_with_source(
            &[],
            &[],
            vec![],
            &[alpn.to_owned()],
            &[],
            &Default::default(),
            Some(source),
        )
        .unwrap(),
    )
}

fn tls_client(
    certs: &[&rcgen::CertifiedKey<rcgen::KeyPair>],
    alpn: &str,
) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert.cert.der().clone()).unwrap();
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![alpn.as_bytes().to_vec()];
    Arc::new(config)
}

#[test]
fn late_session_tickets_cannot_cross_certificate_generations() {
    let directory = tempfile::tempdir().unwrap();
    let first = certificate();
    let second = certificate();
    write_pair(directory.path(), &first);
    let source = file_source(directory.path());
    let base = tls_base(&source, "test");
    let old = source.snapshot(&base);
    write_pair(directory.path(), &second);
    source.refresh_files().unwrap();
    let current = source.snapshot(&base);
    assert!(
        old.session_storage
            .put(b"late-ticket".to_vec(), b"old-session".to_vec())
    );
    assert_eq!(
        old.session_storage.get(b"late-ticket"),
        Some(b"old-session".to_vec())
    );
    assert!(current.session_storage.get(b"late-ticket").is_none());
    assert!(
        current
            .session_storage
            .put(b"current-ticket".to_vec(), b"current-session".to_vec())
    );
    assert_eq!(
        source
            .snapshot(&base)
            .session_storage
            .get(b"current-ticket"),
        Some(b"current-session".to_vec())
    );
    source.material.write().as_mut().unwrap().not_after = now() - 1;
    assert!(!source.snapshot(&base).session_storage.can_cache());
    assert!(
        source
            .snapshot(&base)
            .session_storage
            .get(b"current-ticket")
            .is_none()
    );
}

#[tokio::test]
async fn live_tls_rotation_keeps_existing_tunnel_and_socket() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let dir = tempfile::tempdir().unwrap();
        let first = certificate();
        let second = certificate();
        write_pair(dir.path(), &first);
        let source = file_source(dir.path());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let base = tls_base(&source, "test");
        let server_source = source.clone();
        let mut servers = tokio::task::JoinSet::new();
        servers.spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let connection =
                    rustls::ServerConnection::new(server_source.snapshot(&base)).unwrap();
                connections.spawn(async move {
                    let mut stream = crate::crypto::CryptoTlsStream::handshake(
                        stream,
                        crate::crypto::TlsConnection::new(connection),
                        crate::crypto::TlsReadMode::Stream,
                        &[],
                    )
                    .await
                    .unwrap();
                    let mut bytes = [0; 4];
                    while stream.read_exact(&mut bytes).await.is_ok() {
                        stream.write_all(&bytes).await.unwrap();
                        stream.flush().await.unwrap();
                    }
                });
            }
            while connections.join_next().await.is_some() {}
        });
        let connector = tokio_rustls::TlsConnector::from(tls_client(&[&first, &second], "test"));
        let mut old = connector
            .connect(
                "proxy.test".try_into().unwrap(),
                tokio::net::TcpStream::connect(address).await.unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            old.get_ref().1.peer_certificates().unwrap()[0],
            *first.cert.der()
        );
        old.write_all(b"one!").await.unwrap();
        let mut bytes = [0; 4];
        old.read_exact(&mut bytes).await.unwrap();
        write_pair(dir.path(), &second);
        source.refresh_files().unwrap();
        let mut new = connector
            .connect(
                "proxy.test".try_into().unwrap(),
                tokio::net::TcpStream::connect(address).await.unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            new.get_ref().1.peer_certificates().unwrap()[0],
            *second.cert.der()
        );
        for stream in [&mut old, &mut new] {
            stream.write_all(b"two!").await.unwrap();
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"two!");
        }
        drop(old);
        drop(new);
        servers.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn live_quic_rotation_keeps_existing_connection_and_endpoint() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let dir = tempfile::tempdir().unwrap();
        let first = certificate();
        let second = certificate();
        write_pair(dir.path(), &first);
        let source = file_source(dir.path());
        let mut base = (*tls_base(&source, "test")).clone();
        base.max_early_data_size = u32::MAX;
        let config = quinn::ServerConfig::with_crypto(
            quic_config(Arc::new(base), Some(source.clone())).unwrap(),
        );
        let server = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let address = server.local_addr().unwrap();
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_client(
            &[&first, &second],
            "test",
        ))
        .unwrap();
        client.set_default_client_config(quinn::ClientConfig::new(Arc::new(config)));
        let first_connect = client.connect(address, "proxy.test").unwrap();
        let (old, accepted) = tokio::join!(first_connect, async {
            server.accept().await.unwrap().await
        });
        let old = old.unwrap();
        let accepted = accepted.unwrap();
        write_pair(dir.path(), &second);
        source.refresh_files().unwrap();
        let next = client.connect(address, "proxy.test").unwrap();
        let (new, next_accepted) =
            tokio::join!(next, async { server.accept().await.unwrap().await });
        let new = new.unwrap();
        let next_accepted = next_accepted.unwrap();
        let peer = new
            .peer_identity()
            .unwrap()
            .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
            .unwrap();
        assert_eq!(peer[0], *second.cert.der());
        for (outgoing, incoming) in [(&old, &accepted), (&new, &next_accepted)] {
            let mut send = outgoing.open_uni().await.unwrap();
            send.write_all(b"still connected").await.unwrap();
            send.finish().unwrap();
            let mut recv = incoming.accept_uni().await.unwrap();
            assert_eq!(recv.read_to_end(1024).await.unwrap(), b"still connected");
        }
        assert_eq!(server.local_addr().unwrap(), address);
        client.close(0u32.into(), b"done");
        server.close(0u32.into(), b"done");
        client.wait_idle().await;
        server.wait_idle().await;
    })
    .await
    .unwrap();
}
