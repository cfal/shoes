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
fn managed_directory_urls_reject_http_uri_normalization() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("not-created");
    let yaml = managed_yaml(&state, "type: tls_alpn01", "certificate_source: public");
    for directory in [
        "https://ca.test/dir ectory",
        " https://ca.test/directory",
        "https://ca.test/directory ",
        "https://ca.test/dir\tectory",
    ] {
        assert!(url::Url::parse(directory).is_ok());
        assert!(http::Request::builder().uri(directory).body(()).is_err());
        let invalid = yaml.replace(
            "http://127.0.0.1:9/directory",
            &serde_json::to_string(directory).unwrap(),
        );
        assert!(compile(&invalid).is_err(), "accepted {directory:?}");
    }
    for directory in [
        "https://ca.test/dir%20ectory",
        "http://[::1]:9000/directory",
    ] {
        let valid = yaml.replace("http://127.0.0.1:9/directory", directory);
        compile(&valid).unwrap();
    }
    assert!(!state.exists());
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

#[test]
fn source_errors_identify_schema_fields_names_and_files() {
    let dir = tempfile::tempdir().unwrap();
    let good = managed_yaml(
        &dir.path().join("state"),
        "type: tls_alpn01",
        "certificate_source: public",
    );
    for (yaml, expected) in [
        (good.replace("type: tls_alpn01", "type: http-01"), "http-01"),
        (good.replace("domains:", "domain:"), "domain"),
        (good.replace("state_dir:", "storage:"), "storage"),
        (
            good.replace(
                "certificate_source: public\n        protocol",
                "certificate_source: missing\n        protocol",
            ),
            "missing",
        ),
        (format!("{good}\n{good}"), "public"),
    ] {
        let error = compile(&yaml).err().unwrap().to_string();
        assert!(error.contains(expected), "{error}");
    }
    let ca = dir.path().join("missing-ca.pem");
    let yaml = good.replace(
        "type: acme",
        &format!("type: acme\n  ca_cert: '{}'", ca.display()),
    );
    let error = compile(&yaml).err().unwrap().to_string();
    assert!(
        error.contains("public")
            && error.contains("ca_cert")
            && error.contains(ca.to_str().unwrap()),
        "{error}"
    );

    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    let spec = Spec::Files {
        cert: Input::File(cert_path.clone()),
        key: Input::File(key_path.clone()),
    };
    let error = Source::new("@files-3".into(), spec.clone())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("@files-3")
            && error.contains("certificate file")
            && error.contains(cert_path.to_str().unwrap()),
        "{error}"
    );
    let cert = certificate();
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    let error = Source::new("@files-3".into(), spec.clone())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("private key file") && error.contains(key_path.to_str().unwrap()),
        "{error}"
    );

    let mut params = rcgen::CertificateParams::new(vec!["proxy.test".into()]).unwrap();
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2021, 1, 1);
    let expired = params.self_signed(&cert.signing_key).unwrap();
    std::fs::write(&cert_path, expired.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
    let error = Source::new("@files-3".into(), spec)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("not currently valid")
            && error.contains(cert_path.to_str().unwrap())
            && error.contains(key_path.to_str().unwrap()),
        "{error}"
    );
    assert!(!error.contains("PRIVATE KEY"));
}

#[tokio::test]
async fn state_preparation_errors_identify_source_and_storage_path() {
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("blocked");
    let state = parent.join("state");
    let yaml = managed_yaml(
        &state,
        "type: http01, listen: ['127.0.0.1:18080']",
        "certificate_source: public",
    );
    let mut validated = compile(&yaml).unwrap();
    std::fs::write(&parent, "not a directory").unwrap();
    let error = Registry::prepare(&mut validated, None)
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(
        error.contains("public")
            && error.contains("state_dir")
            && error.contains(state.to_str().unwrap()),
        "{error}"
    );
    std::fs::remove_file(&parent).unwrap();

    let Spec::Acme(config) = &validated.certificates[0].spec else {
        unreachable!()
    };
    let lock = acme::lock_state(config).unwrap();
    std::fs::write(state.join("state.json"), "PRIVATE STATE MUST NOT APPEAR").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            state.join("state.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    drop(lock);
    let error = Registry::prepare(&mut validated, None)
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(
        error.contains("public")
            && error.contains("state_dir")
            && error.contains(state.to_str().unwrap())
            && error.contains("invalid ACME durable state"),
        "{error}"
    );
    assert!(!error.contains("PRIVATE STATE"));
}

#[test]
fn source_paths_reject_pasted_secrets_before_dependency_discovery() {
    let secret = "PRIVATE KEY CONTENT MUST NOT APPEAR";
    for field in ["cert", "key", "ca_cert"] {
        for value in [
            format!("  -----BEGIN PRIVATE KEY----- {secret}"),
            format!("not-a-path\n{secret}"),
        ] {
            let mut entry = if field == "ca_cert" {
                serde_json::json!({
                    "certificate_source": "managed", "type": "acme",
                    "domains": ["proxy.test"], "directory_url": "https://ca.test/directory",
                    "state_dir": "/missing/state",
                    "challenge": {"type": "http01", "listen": ["127.0.0.1:18080"]}
                })
            } else {
                serde_json::json!({"certificate_source":"managed", "type":"files", "cert":"/missing/cert.pem", "key":"/missing/key.pem"})
            };
            entry[field] = value.into();
            let mut configs: Vec<Config> =
                serde_yaml::from_value(serde_yaml::to_value(vec![entry]).unwrap()).unwrap();
            for error in [
                crate::config::pem_candidate_dependencies(&mut configs).unwrap_err(),
                crate::config::pem_reload_dependencies(&mut configs).unwrap_err(),
                configure(&mut configs).unwrap_err(),
            ] {
                let error = error.to_string();
                assert!(
                    error.contains("managed")
                        && error.contains(field)
                        && error.contains("file path"),
                    "{error}"
                );
                assert!(!error.contains(secret), "{error}");
            }
        }
    }
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

#[tokio::test]
async fn p521_signed_chains_validate_and_rotate() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let directory = tempfile::tempdir().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let issuer = rcgen::CertifiedIssuer::self_signed(
            params,
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P521_SHA512).unwrap(),
        ).unwrap();
        let issue = || {
            let key = rcgen::KeyPair::generate().unwrap();
            let cert = rcgen::CertificateParams::new(vec!["proxy.test".into()]).unwrap()
                .signed_by(&key, &issuer).unwrap();
            (cert, key)
        };
        let (first, first_key) = issue();
        let chain = format!("{}{}", first.pem(), issuer.pem());
        // x509-parser's verifier does not cover this provider-supported algorithm.
        let (_, parsed) = x509_parser::parse_x509_certificate(first.der()).unwrap();
        let (_, root) = x509_parser::parse_x509_certificate(issuer.der()).unwrap();
        assert!(parsed.verify_signature(Some(root.public_key())).is_err());
        let cert_path = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        std::fs::write(&cert_path, &chain).unwrap();
        std::fs::write(&key_path, first_key.serialize_pem()).unwrap();
        for kind in ["inline", "legacy", "named-pem", "named-source"] {
            let mut configs = vec![];
            let mut target = serde_json::json!({"cert": cert_path, "key": key_path, "protocol": {"type": "socks"}});
            match kind {
                "inline" => {
                    target["cert"] = serde_json::json!(chain);
                    target["key"] = serde_json::json!(first_key.serialize_pem());
                }
                "named-pem" => {
                    configs.push(serde_json::json!({"pem": "chain", "path": cert_path}));
                    configs.push(serde_json::json!({"pem": "private", "path": key_path}));
                    target["cert"] = serde_json::json!("chain");
                    target["key"] = serde_json::json!("private");
                }
                "named-source" => {
                    configs.push(serde_json::json!({"certificate_source": "shared", "type": "files", "cert": cert_path, "key": key_path}));
                    target = serde_json::json!({"certificate_source": "shared", "protocol": {"type": "socks"}});
                }
                _ => {}
            }
            configs.push(serde_json::json!({"address": "127.0.0.1:18443", "protocol": {"type": "tls", "default_tls_target": target}}));
            let configs = serde_yaml::from_value(serde_yaml::to_value(configs).unwrap()).unwrap();
            let (configs, _) = crate::config::convert_cert_paths(configs).await.unwrap();
            crate::config::create_server_configs(configs).unwrap();
        }
        let source = file_source(directory.path());
        let base = tls_base(&source, "test");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(issuer.der().clone()).unwrap();
        let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions().unwrap().with_root_certificates(roots).with_no_client_auth();
        client.alpn_protocols = vec![b"test".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        for (cert, key) in [(first, first_key), issue()] {
            std::fs::write(&cert_path, format!("{}{}", cert.pem(), issuer.pem())).unwrap();
            std::fs::write(&key_path, key.serialize_pem()).unwrap();
            source.refresh_files().unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(source.snapshot(&base));
            let (client, server) = tokio::io::duplex(16 * 1024);
            let (client, server) = tokio::join!(
                connector.connect("proxy.test".try_into().unwrap(), client),
                acceptor.accept(server),
            );
            server.unwrap();
            assert_eq!(client.unwrap().get_ref().1.peer_certificates().unwrap()[0], *cert.der());
        }
    }).await.unwrap();
}

#[test]
fn rsa_signed_chain_validation_checks_order_and_acme_domains() {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let issuer = rcgen::CertifiedIssuer::self_signed(
        params,
        rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap(),
    )
    .unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(vec!["proxy.test".into()])
        .unwrap()
        .signed_by(&key, &issuer)
        .unwrap();
    let chain = format!("{}{}", leaf.pem(), issuer.pem());
    Material::parse(&chain, &key.serialize_pem(), &["proxy.test".into()]).unwrap();

    let reversed = format!("{}{}", issuer.pem(), leaf.pem());
    let error = Material::parse(&reversed, &key.serialize_pem(), &[])
        .err()
        .unwrap();
    assert_eq!(
        error.to_string(),
        "invalid certificate chain signature or order"
    );

    let error = Material::parse(
        &chain,
        &key.serialize_pem(),
        &["proxy.test".into(), "missing.test".into()],
    )
    .err()
    .unwrap();
    assert_eq!(
        error.to_string(),
        "certificate does not cover every configured ACME domain"
    );
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
