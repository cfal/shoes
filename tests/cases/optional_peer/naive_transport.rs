use std::{
    cell::Cell,
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::json;
use shoes_test_support::{
    certs::generate_test_cert_files,
    port_helper::PortHelper,
    process::start_singbox_server,
    test_fixture::{start_naive_caddy_server, start_shoes_server},
    test_servers::start_tcp_stream_echo_server,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
};

use crate::http_proxy_support as support;

#[derive(Debug, Clone, Copy)]
enum Peer {
    SingBox,
    Caddy,
}

#[derive(Debug, Default)]
struct ExchangeProgress {
    uploaded: Cell<usize>,
    downloaded: Cell<usize>,
    upload_shutdown: Cell<bool>,
    response_eof: Cell<bool>,
}

#[tokio::test]
async fn singbox_naive_preserves_multiplexing_idle_and_large_transfers()
-> Result<(), Box<dyn std::error::Error>> {
    transport_compatibility(Peer::SingBox).await
}

#[tokio::test]
async fn native_caddy_naive_preserves_multiplexing_idle_and_large_transfers()
-> Result<(), Box<dyn std::error::Error>> {
    transport_compatibility(Peer::Caddy).await
}

async fn transport_compatibility(peer: Peer) -> Result<(), Box<dyn std::error::Error>> {
    let phase = Cell::new("startup");
    let exchanges: [ExchangeProgress; 4] = std::array::from_fn(|_| ExchangeProgress::default());
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(120), async {
        let (cert, key) = generate_test_cert_files()?;
        let mut ports = PortHelper::new();
        let (_, server) = ports.get_localhost_listener_port();
        let (_, entry) = ports.get_localhost_listener_port();
        let _peer = match peer {
            Peer::SingBox => start_singbox_server(&json!({
                "log": {"level": "warn"},
                "inbounds": [{"type": "naive", "listen": "0.0.0.0", "listen_port": server,
                    "users": [{"username": "user", "password": "pass"}],
                    "tls": {"enabled": true, "certificate_path": cert.to_str().unwrap(), "key_path": key.to_str().unwrap(),
                        "alpn": ["h2"]}}],
                "outbounds": [{"type": "direct"}]
            }).to_string())?,
            Peer::Caddy => start_naive_caddy_server(&json!({
                "admin": {"disabled": true},
                "apps": {
                    "http": {"servers": {"naive": {
                        "listen": [format!("0.0.0.0:{server}")],
                        "automatic_https": {"disable_redirects": true},
                        "routes": [{"handle": [{"handler": "forward_proxy",
                            "auth_credentials": [STANDARD.encode(STANDARD.encode("user:pass"))],
                            "hide_ip": true, "hide_via": true,
                            "acl": [{"subjects": ["all"], "allow": true}]}]}],
                        "tls_connection_policies": [{
                            "certificate_selection": {"any_tag": ["naive"]}, "alpn": ["h2"]}]
                    }}},
                    "tls": {"certificates": {"load_files": [{
                        "certificate": cert.to_str().unwrap(), "key": key.to_str().unwrap(), "tags": ["naive"]}]}}
                }
            }).to_string())?,
        };

        // Count carriers outside TLS, so successful requests alone cannot mask redialing.
        let listener = TcpListener::bind("0.0.0.0:0").await?;
        let carrier_port = listener.local_addr()?.port();
        let count = Arc::new(AtomicUsize::new(0));
        let mut forwarding = JoinSet::new();
        forwarding.spawn(forward_carriers(listener, server, count.clone()));
        let shoes = json!([support::relay_config(entry, carrier_port, json!({
            "type": "tls", "verify": false, "sni_hostname": "test.local", "alpn_protocols": ["h2"],
            "protocol": {"type": "naiveproxy", "username": "user", "password": "pass"}
        }))]);
        let _shoes = start_shoes_server(&serde_yaml::to_string(&shoes)?)?;
        let scenario = async {
            ports.wait_for_all_ports().await?;
            let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
            let target = format!("127.0.0.1:{}", echo.local_addr().port());
            phase.set("initial CONNECT");
            let mut first = support::connect(entry, &target).await?;
            assert_eq!(count.load(Ordering::SeqCst), 1);

            // Exceed the standard HTTP/2 proxy's 30 s + 5 s PING watchdog, which
            // Naive must not inherit, but stay below Caddy 2.11.7's 60 s body timeout.
            phase.set("active stream idle wait");
            tokio::time::sleep(Duration::from_secs(40)).await;
            phase.set("active stream after idle");
            first.write_all(b"quiet").await?;
            let mut response = [0; 5];
            first.read_exact(&mut response).await?;
            assert_eq!(&response, b"quiet");
            eprintln!(
                "{peer:?}: active stream survived idle at {:?}",
                started.elapsed()
            );
            // Concurrent preflight contention may legitimately dial a spare carrier.
            phase.set("multiplexed CONNECTs");
            let second = support::connect(entry, &target).await?;
            let third = support::connect(entry, &target).await?;
            assert_eq!(count.load(Ordering::SeqCst), 1);
            phase.set("concurrent bulk transfers and EOF");
            tokio::try_join!(
                large_exchange(first, peer, &exchanges[0]),
                large_exchange(second, peer, &exchanges[1]),
                large_exchange(third, peer, &exchanges[2])
            )?;
            eprintln!(
                "{peer:?}: concurrent bulk transfers finished at {:?}",
                started.elapsed()
            );

            phase.set("empty carrier idle wait");
            tokio::time::sleep(Duration::from_secs(40)).await;
            phase.set("CONNECT after carrier idle");
            let last = support::connect(entry, &target).await?;
            phase.set("bulk transfer and EOF after carrier idle");
            large_exchange(last, peer, &exchanges[3]).await?;
            assert_eq!(count.load(Ordering::SeqCst), 1, "idle carrier was not reused");
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        tokio::select! {
            result = scenario => result,
            result = forwarding.join_next() => {
                let error = match result.expect("carrier forwarder missing") {
                    Ok(Ok(())) => io::Error::other("carrier forwarder stopped unexpectedly"),
                    Ok(Err(error)) => io::Error::new(
                        error.kind(),
                        format!("carrier forwarder I/O failed: {error}"),
                    ),
                    Err(error) => io::Error::other(format!("carrier forwarder task failed: {error}")),
                };
                Err(error.into())
            }
        }
    })
    .await;
    if !matches!(&result, Ok(Ok(()))) {
        eprintln!("{peer:?}: phase={}, exchanges={exchanges:?}", phase.get());
    }
    result.map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "{peer:?} timed out during {} after {:?}",
                phase.get(),
                started.elapsed()
            ),
        )
    })?
}

async fn forward_carriers(
    listener: TcpListener,
    server: u16,
    count: Arc<AtomicUsize>,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            incoming = listener.accept() => {
                let (mut client, _) = incoming?;
                count.fetch_add(1, Ordering::SeqCst);
                connections.spawn(async move {
                    let mut upstream = TcpStream::connect(("127.0.0.1", server)).await?;
                    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
                    Ok::<_, io::Error>(())
                });
            }
            result = connections.join_next(), if !connections.is_empty() => {
                result.unwrap().unwrap()?;
            }
        }
    }
}

async fn large_exchange(
    mut stream: TcpStream,
    peer: Peer,
    progress: &ExchangeProgress,
) -> io::Result<()> {
    let payload: Vec<_> = (0..4 * 1024 * 1024 + 1).map(|i| (i % 251) as u8).collect();
    let (mut read, mut write) = stream.split();
    let upload = async {
        while progress.uploaded.get() < payload.len() {
            let sent = progress.uploaded.get();
            let written = write.write(&payload[sent..]).await?;
            if written == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            progress.uploaded.set(sent + written);
        }
        if matches!(peer, Peer::Caddy) {
            write.shutdown().await?;
            progress.upload_shutdown.set(true);
        }
        Ok::<_, io::Error>(())
    };
    let download = async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut received = vec![0; payload.len()];
        while progress.downloaded.get() < received.len() {
            let offset = progress.downloaded.get();
            let count = read.read(&mut received[offset..]).await?;
            if count == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            progress.downloaded.set(offset + count);
        }
        assert!(received == payload, "echo payload differs");
        Ok::<_, io::Error>(())
    };
    tokio::try_join!(upload, download)?;
    // sing-box 1.14.1 fully closes upstream TCP on upload EOF. Receive the
    // complete echo first; Caddy above still exercises early half-close draining.
    if matches!(peer, Peer::SingBox) {
        write.shutdown().await?;
        progress.upload_shutdown.set(true);
    }
    let mut trailing = [0; 1];
    assert_eq!(read.read(&mut trailing).await?, 0, "unexpected echo tail");
    progress.response_eof.set(true);
    Ok(())
}
