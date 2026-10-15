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
    start_process_with_limits(config, reload, "reload_grace_secs: 6")
}

fn start_process_with_limits(
    config: &str,
    reload: bool,
    limits: &str,
) -> io::Result<(ProcessGuard, tempfile::NamedTempFile, u32)> {
    let mut file = tempfile::NamedTempFile::new()?;
    writeln!(file, "- global_limits: {{{limits}}}")?;
    file.write_all(config.as_bytes())?;
    file.flush()?;
    let binary = std::env::var_os("SHOES_TEST_SHOES_BIN")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_shoes").into());
    let mut command = Command::new(binary);
    command
        .args(["-t", "1"])
        .env("RUST_LOG", "warn")
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
async fn default_admission_exceeds_previous_connection_and_stream_caps() -> io::Result<()> {
    let mut ports = PortHelper::new();
    let (_, proxy_port) = ports.get_localhost_listener_port();
    let (_, echo_port) = ports.get_localhost_listener_port();
    let _echo = start_tcp_stream_echo_server("0.0.0.0", echo_port).await?;
    let config = format!(
        r#"- address: '0.0.0.0:{proxy_port}'
  protocol:
    type: forward
    target: '127.0.0.1:{echo_port}'
"#
    );
    let (_process, _config, _) = start_process(&config, false)?;
    ports.wait_for_all_ports().await?;
    let mut connections = Vec::new();
    for _ in 0..520 {
        let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await?;
        round_trip(&mut stream, b"admitted").await?;
        connections.push(stream);
    }
    round_trip(&mut connections[0], b"still active").await?;
    round_trip(connections.last_mut().unwrap(), b"also active").await?;
    Ok(())
}

#[tokio::test]
async fn yaml_connection_limit_rejects_new_work_without_closing_existing_work() -> io::Result<()> {
    let mut ports = PortHelper::new();
    let (_, proxy_port) = ports.get_localhost_listener_port();
    let (_, echo_port) = ports.get_localhost_listener_port();
    let _echo = start_tcp_stream_echo_server("0.0.0.0", echo_port).await?;
    let config = format!(
        r#"- address: '0.0.0.0:{proxy_port}'
  protocol:
    type: forward
    target: '127.0.0.1:{echo_port}'
"#
    );
    let (_process, _config, _) = start_process_with_limits(&config, false, "max_connections: 2")?;
    ports.wait_for_all_ports().await?;
    // The readiness probe must relinquish its reservation before both real connections open.
    let mut connections = timeout(Duration::from_secs(3), async {
        loop {
            let mut streams = Vec::new();
            for _ in 0..2 {
                let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await?;
                if round_trip(&mut stream, b"accepted").await.is_err() {
                    break;
                }
                streams.push(stream);
            }
            if streams.len() == 2 {
                return Ok::<_, io::Error>(streams);
            }
            drop(streams);
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    let mut rejected = TcpStream::connect(("127.0.0.1", proxy_port)).await?;
    let mut byte = [0];
    let result = timeout(Duration::from_secs(2), rejected.read(&mut byte)).await?;
    assert!(matches!(result, Ok(0) | Err(_)));
    for stream in &mut connections {
        round_trip(stream, b"still active").await?;
    }
    drop(connections.pop().unwrap());
    let mut replacement = timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", proxy_port)).await
                && round_trip(&mut stream, b"replacement admitted")
                    .await
                    .is_ok()
            {
                return stream;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    round_trip(&mut connections[0], b"survivor still active").await?;
    round_trip(&mut replacement, b"replacement still active").await?;
    let result = timeout(Duration::from_secs(2), async {
        let mut rejected = TcpStream::connect(("127.0.0.1", proxy_port)).await?;
        rejected.read(&mut byte).await
    })
    .await?;
    assert!(matches!(result, Ok(0) | Err(_)));
    Ok(())
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
    let (_process, file, _) = start_process(&config, true)?;
    ports.wait_for_all_ports().await?;
    let mut existing = TcpStream::connect(("127.0.0.1", proxy_port)).await?;
    round_trip(&mut existing, b"before reload").await?;
    let reserved = std::net::TcpListener::bind("127.0.0.1:0")?;
    let replacement_port = reserved.local_addr()?.port();
    drop(reserved);
    let replacement_config = config.replace(
        &format!("0.0.0.0:{proxy_port}"),
        &format!("0.0.0.0:{replacement_port}"),
    );
    std::fs::write(
        file.path(),
        format!("- global_limits: {{reload_grace_secs: 6}}\n{replacement_config}"),
    )?;
    round_trip(&mut existing, b"during reload").await?;
    // A distinct listener identifies the new generation without requiring an outage.
    let mut replacement = timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(stream) = TcpStream::connect(("127.0.0.1", replacement_port)).await {
                break stream;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    round_trip(&mut existing, b"after reload").await?;
    round_trip(&mut replacement, b"new generation").await?;
    let mut byte = [0];
    let closed = timeout(Duration::from_secs(8), existing.read(&mut byte)).await?;
    assert!(
        matches!(closed, Ok(0) | Err(_)),
        "old generation survived its grace deadline"
    );
    round_trip(&mut replacement, b"still active").await?;
    Ok(())
}

#[tokio::test]
async fn hysteria2_control_streams_survive_small_application_caps()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use shoes_test_support::certs::generate_test_cert_files;
    use std::sync::Arc;

    let (cert, key) = generate_test_cert_files()?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut std::io::Cursor::new(std::fs::read(&cert)?)) {
        roots.add(cert?)?;
    }
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    ));

    for limit in [1, 2] {
        let mut ports = PortHelper::new();
        let (_, quic_port) = ports.get_quic_listener_port();
        let (_, readiness_port) = ports.get_localhost_listener_port();
        let config = format!(
            r#"- address: '0.0.0.0:{quic_port}'
  transport: quic
  quic_settings:
    cert: '{}'
    key: '{}'
    num_endpoints: 1
    alpn_protocols: [h3]
  protocol:
    type: hysteria2
    password: test-password
- address: '0.0.0.0:{readiness_port}'
  protocol:
    type: socks
"#,
            cert.display(),
            key.display(),
        );
        let (_process, _config, _) = start_process_with_limits(
            &config,
            false,
            &format!("max_streams_per_connection: {limit}"),
        )?;
        ports.wait_for_all_ports().await?;
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config.clone());
        let connection = timeout(
            Duration::from_secs(5),
            endpoint.connect(([127, 0, 0, 1], quic_port).into(), "test.local")?,
        )
        .await??;
        let (mut driver, mut requests) = timeout(
            Duration::from_secs(5),
            h3::client::new(h3_quinn::Connection::new(connection)),
        )
        .await??;
        let request = http::Request::builder()
            .method("POST")
            .uri("https://hysteria/auth")
            .header("Hysteria-Auth", "test-password")
            .body(())?;
        let response = timeout(Duration::from_secs(5), async {
            tokio::select! {
                result = async {
                    let mut stream = requests.send_request(request).await?;
                    stream.finish().await?;
                    stream.recv_response().await
                } => result.map_err(io::Error::other),
                error = std::future::poll_fn(|cx| driver.poll_close(cx)) => {
                    Err(io::Error::other(error))
                }
            }
        })
        .await??;
        assert_eq!(response.status().as_u16(), 233, "stream cap {limit}");
        assert_eq!(response.headers()["Hysteria-CC-RX"], "auto");
    }
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
        let closed = timeout(Duration::from_secs(6), connection.closed()).await?;
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
