use std::io::{self, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

use shoes_test_support::port_helper::PortHelper;
use shoes_test_support::socks5::Socks5UdpAssociation;
use shoes_test_support::test_fixture::ProcessGuard;
use shoes_test_support::test_servers::start_tcp_stream_echo_server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

fn start_process(
    config: &str,
    reload: bool,
) -> io::Result<(ProcessGuard, tempfile::NamedTempFile, u32)> {
    let mut file = tempfile::NamedTempFile::new()?;
    file.write_all(config.as_bytes())?;
    file.flush()?;
    let binary = std::env::var_os("SHOES_TEST_SHOES_BIN")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_shoes").into());
    let mut command = Command::new(binary);
    command
        .args(["-t", "1"])
        .env("RUST_LOG", "warn")
        .env("SHOES_RELOAD_GRACE_SECS", "6")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if !reload {
        command.arg("--no-reload");
    }
    command.arg(file.path());
    let child = command.spawn()?;
    let pid = child.id();
    Ok((ProcessGuard::new(child, "lifecycle-shoes"), file, pid))
}

async fn round_trip(stream: &mut TcpStream, message: &[u8]) -> io::Result<()> {
    timeout(Duration::from_secs(2), async {
        stream.write_all(message).await?;
        let mut reply = vec![0; message.len()];
        stream.read_exact(&mut reply).await?;
        assert_eq!(reply, message);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn tcp_reload_drains_existing_connections_within_grace() -> io::Result<()> {
    let mut ports = PortHelper::new();
    let (_, proxy_port) = ports.get_localhost_listener_port();
    let (_, echo_port) = ports.get_localhost_listener_port();
    let _echo = start_tcp_stream_echo_server("0.0.0.0", echo_port).await?;
    let config = format!(
        "- address: '0.0.0.0:{proxy_port}'\n  protocol:\n    type: forward\n    target: '127.0.0.1:{echo_port}'\n"
    );
    let (_process, mut file, _) = start_process(&config, true)?;
    ports.wait_for_all_ports().await?;
    let mut existing = TcpStream::connect(("127.0.0.1", proxy_port)).await?;
    round_trip(&mut existing, b"before reload").await?;
    file.write_all(b"\n# trigger reload\n")?;
    file.flush()?;

    // Observe listener retirement rather than assuming notification timing.
    timeout(Duration::from_secs(3), async {
        while TcpStream::connect(("127.0.0.1", proxy_port)).await.is_ok() {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    round_trip(&mut existing, b"during reload").await?;
    let mut replacement = timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(stream) = TcpStream::connect(("127.0.0.1", proxy_port)).await {
                break stream;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    round_trip(&mut existing, b"after reload").await?;
    round_trip(&mut replacement, b"new generation").await?;
    let mut byte = [0];
    let closed = timeout(Duration::from_secs(5), existing.read(&mut byte)).await?;
    assert!(
        matches!(closed, Ok(0) | Err(_)),
        "old generation survived its grace deadline"
    );
    round_trip(&mut replacement, b"still active").await?;
    Ok(())
}

#[tokio::test]
async fn quic_reload_disconnects_old_connections_and_allows_reconnect()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use shoes_test_support::certs::generate_test_cert_files;
    use std::sync::Arc;

    let mut ports = PortHelper::new();
    let (_, quic_port) = ports.get_quic_listener_port();
    let (_, readiness_port) = ports.get_localhost_listener_port();
    let (_, echo_port) = ports.get_localhost_listener_port();
    let _echo = start_tcp_stream_echo_server("0.0.0.0", echo_port).await?;
    let (cert, key) = generate_test_cert_files()?;
    let config = format!(
        r#"
- address: "0.0.0.0:{quic_port}"
  transport: quic
  quic_settings:
    cert: "{}"
    key: "{}"
    num_endpoints: 2
    alpn_protocols: [reload-test]
  protocol:
    type: forward
    target: "127.0.0.1:{echo_port}"
- address: "0.0.0.0:{readiness_port}"
  protocol:
    type: forward
    target: "127.0.0.1:{echo_port}"
"#,
        cert.display(),
        key.display()
    );
    let (_process, mut file, _) = start_process(&config, true)?;
    ports.wait_for_all_ports().await?;

    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut std::io::Cursor::new(std::fs::read(&cert)?)) {
        roots.add(cert?)?;
    }
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"reload-test".to_vec()];
    let config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    ));
    let connect = || async {
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(config.clone());
        let connection = timeout(
            Duration::from_secs(3),
            endpoint
                .connect(([127, 0, 0, 1], quic_port).into(), "test.local")
                .unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        (endpoint, connection)
    };
    let mut old = Vec::new();
    for _ in 0..4 {
        let (endpoint, connection) = connect().await;
        let (mut send, mut recv) = connection.open_bi().await?;
        send.write_all(b"before").await?;
        let mut reply = [0; 6];
        timeout(Duration::from_secs(2), recv.read_exact(&mut reply)).await??;
        assert_eq!(&reply, b"before");
        old.push((endpoint, connection, send, recv));
    }
    file.write_all(b"\n# trigger QUIC reload\n")?;
    file.flush()?;
    for (_, connection, _, _) in &old {
        let closed = timeout(Duration::from_secs(2), connection.closed()).await?;
        assert!(matches!(
            closed,
            quinn::ConnectionError::ApplicationClosed(_)
        ));
    }
    drop(old);
    sleep(Duration::from_millis(3200)).await;
    for _ in 0..12 {
        let (_endpoint, connection) = connect().await;
        let (mut send, mut recv) = connection.open_bi().await?;
        send.write_all(b"after").await?;
        let mut reply = [0; 5];
        timeout(Duration::from_secs(2), recv.read_exact(&mut reply)).await??;
        assert_eq!(&reply, b"after");
        connection.close(0u32.into(), b"done");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn process_usage(pid: u32) -> io::Result<(usize, usize)> {
    let descriptors = std::fs::read_dir(format!("/proc/{pid}/fd"))?.count();
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    let resident_kib = status
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next()? == "VmRSS:")
                .then(|| fields.next()?.parse::<usize>().ok())
                .flatten()
        })
        .ok_or_else(|| io::Error::other("missing process RSS"))?;
    Ok((descriptors, resident_kib))
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn quiet_udp_association_churn_releases_descriptors_and_bounds_rss() -> io::Result<()> {
    let mut ports = PortHelper::new();
    let (_, port) = ports.get_localhost_listener_port();
    let config = format!(
        "- address: '0.0.0.0:{port}'\n  protocol:\n    type: socks\n    udp_enabled: true\n"
    );
    let (_process, _config, pid) = start_process(&config, false)?;
    ports.wait_for_all_ports().await?;
    let churn = |count| async move {
        for _ in 0..count {
            drop(Socks5UdpAssociation::connect("127.0.0.1", port).await?);
        }
        io::Result::Ok(())
    };
    timeout(Duration::from_secs(10), churn(64)).await??;
    sleep(Duration::from_millis(100)).await;
    let baseline = process_usage(pid)?;
    for _ in 0..2 {
        timeout(Duration::from_secs(20), churn(512)).await??;
        timeout(Duration::from_secs(3), async {
            while process_usage(pid)?.0 > baseline.0 + 2 {
                sleep(Duration::from_millis(20)).await;
            }
            io::Result::Ok(())
        })
        .await??;
    }
    let final_usage = process_usage(pid)?;
    eprintln!("UDP churn: warm={baseline:?}, final={final_usage:?} (FDs, RSS KiB)");
    // Allow allocator caching; the former leak retained 64 KiB and a socket per association.
    assert!(
        final_usage.1 <= baseline.1 + 16 * 1024,
        "RSS kept growing after quiet association churn"
    );
    Ok(())
}
