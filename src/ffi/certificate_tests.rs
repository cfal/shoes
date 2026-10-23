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
