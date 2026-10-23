use super::start_from_config;
use std::{os::fd::AsRawFd, os::unix::net::UnixDatagram, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn managed_sources_release_listeners_and_storage_on_stop_and_rollback() {
    const CHILD: &str = "SHOES_FFI_CERTIFICATES_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "ffi::common::certificate_tests::managed_sources_release_listeners_and_storage_on_stop_and_rollback", "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(15), async {
            let directory = tempfile::tempdir().unwrap();
            let (_wire, tun) = UnixDatagram::pair().unwrap();
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let proxy = listener.local_addr().unwrap();
            let challenge = std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap();
            let config = serde_json::to_string(&serde_json::json!([
                {"certificate_source":"managed", "type":"acme", "domains":["proxy.test"],
                    "directory_url":"http://127.0.0.1:9/directory", "state_dir":directory.path().join("state"),
                    "challenge":{"type":"http01", "listen":[challenge.to_string()]}},
                {"device_fd":tun.as_raw_fd(), "packet_information":false, "rules":["block-all"]},
                {"address":proxy.to_string(), "protocol":{"type":"tls", "tls_targets":{"proxy.test":{
                    "certificate_source":"managed", "protocol":{"type":"socks"}
                }}}}
            ])).unwrap();
            let (_shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
            assert!(start_from_config(&config, shutdown_rx).await.is_err());
            assert!(std::net::TcpListener::bind(challenge).is_ok());
            drop(listener);

            for _ in 0..2 {
                let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
                let config = config.clone();
                let service = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                    start_from_config(&config, shutdown_rx).await
                }));
                let mut connection = loop {
                    if let Ok(connection) = tokio::net::TcpStream::connect(challenge).await {
                        break connection;
                    }
                    assert!(!service.is_finished(), "FFI startup failed");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                };
                connection.write_all(b"GET /.well-known/acme-challenge/unknown HTTP/1.1\r\nHost: proxy.test\r\n\r\n").await.unwrap();
                let mut response = String::new();
                connection.read_to_string(&mut response).await.unwrap();
                assert!(response.starts_with("HTTP/1.1 404"));
                assert!(tokio::net::TcpStream::connect(proxy).await.is_ok());
                shutdown.send(()).unwrap();
                service.await.unwrap().unwrap();
                assert!(std::net::TcpListener::bind(challenge).is_ok());
                assert!(std::net::TcpListener::bind(proxy).is_ok());
                assert!(unsafe { libc::fcntl(tun.as_raw_fd(), libc::F_GETFD) } >= 0);
            }
        }).await.unwrap();
    });
}

#[test]
fn file_watches_rotate_embedded_tls_without_restarting_the_instance() {
    const CHILD: &str = "SHOES_FFI_FILE_CERTIFICATES_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "ffi::common::certificate_tests::file_watches_rotate_embedded_tls_without_restarting_the_instance", "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(15), async {
            let directory = tempfile::tempdir().unwrap();
            let cert_path = directory.path().join("cert.pem");
            let key_path = directory.path().join("key.pem");
            let first = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
            let second = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
            std::fs::write(&cert_path, first.cert.pem()).unwrap();
            std::fs::write(&key_path, first.signing_key.serialize_pem()).unwrap();
            let (_wire, tun) = UnixDatagram::pair().unwrap();
            let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = reserved.local_addr().unwrap();
            drop(reserved);
            let config = serde_json::to_string(&serde_json::json!([
                {"certificate_source":"shared", "type":"files", "cert":cert_path, "key":key_path},
                {"device_fd":tun.as_raw_fd(), "packet_information":false, "rules":["block-all"]},
                {"address":address.to_string(), "protocol":{"type":"tls", "default_tls_target":{
                    "certificate_source":"shared", "protocol":{"type":"socks"}
                }}}
            ]))
            .unwrap();
            let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
            let service = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                start_from_config(&config, shutdown_rx).await
            }));
            while tokio::net::TcpStream::connect(address).await.is_err() {
                assert!(!service.is_finished(), "FFI startup failed");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let mut roots = rustls::RootCertStore::empty();
            roots.add(first.cert.der().clone()).unwrap();
            roots.add(second.cert.der().clone()).unwrap();
            let client = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
            let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client));
            let connect = || async {
                connector
                    .connect(
                        "proxy.test".try_into().unwrap(),
                        tokio::net::TcpStream::connect(address).await.unwrap(),
                    )
                    .await
                    .unwrap()
            };
            let mut old = connect().await;
            assert_eq!(
                old.get_ref().1.peer_certificates().unwrap()[0],
                *first.cert.der()
            );
            std::fs::write(&cert_path, second.cert.pem()).unwrap();
            std::fs::write(&key_path, second.signing_key.serialize_pem()).unwrap();
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let stream = connect().await;
                    if stream.get_ref().1.peer_certificates().unwrap()[0] == *second.cert.der() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            old.write_all(&[5, 1, 0]).await.unwrap();
            let mut response = [0; 2];
            old.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [5, 0]);
            drop(old);
            shutdown.send(()).unwrap();
            service.await.unwrap().unwrap();
            assert!(std::net::TcpListener::bind(address).is_ok());
            assert!(unsafe { libc::fcntl(tun.as_raw_fd(), libc::F_GETFD) } >= 0);
        })
        .await
        .unwrap();
    });
}
