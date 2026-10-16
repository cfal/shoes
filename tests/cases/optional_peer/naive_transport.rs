use std::{
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

#[derive(Clone, Copy)]
enum Peer {
    SingBox,
    Caddy,
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
    tokio::time::timeout(Duration::from_secs(120), async {
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
        ports.wait_for_all_ports().await?;
        let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
        let target = format!("127.0.0.1:{}", echo.local_addr().port());
        let mut first = support::connect(entry, &target).await?;
        assert_eq!(count.load(Ordering::SeqCst), 1);

        // Exceed the standard HTTP/2 proxy's 30 s + 5 s PING watchdog, which
        // Naive must not inherit, but stay below Caddy 2.11.7's 60 s body timeout.
        tokio::time::sleep(Duration::from_secs(40)).await;
        first.write_all(b"quiet").await?;
        let mut response = [0; 5];
        first.read_exact(&mut response).await?;
        assert_eq!(&response, b"quiet");
        // Concurrent preflight contention may legitimately dial a spare carrier.
        let second = support::connect(entry, &target).await?;
        let third = support::connect(entry, &target).await?;
        assert_eq!(count.load(Ordering::SeqCst), 1);
        tokio::try_join!(large_exchange(first, peer), large_exchange(second, peer), large_exchange(third, peer))?;

        tokio::time::sleep(Duration::from_secs(40)).await;
        large_exchange(support::connect(entry, &target).await?, peer).await?;
        assert_eq!(count.load(Ordering::SeqCst), 1, "idle carrier was not reused");
        Ok::<_, Box<dyn std::error::Error>>(())
    }).await?
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

async fn large_exchange(mut stream: TcpStream, peer: Peer) -> io::Result<()> {
    let payload: Vec<_> = (0..4 * 1024 * 1024 + 1).map(|i| (i % 251) as u8).collect();
    let (mut read, mut write) = stream.split();
    let upload = async {
        write.write_all(&payload).await?;
        if matches!(peer, Peer::Caddy) {
            write.shutdown().await?;
        }
        Ok::<_, io::Error>(())
    };
    let download = async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut received = vec![0; payload.len()];
        read.read_exact(&mut received).await?;
        assert!(received == payload, "echo payload differs");
        Ok::<_, io::Error>(())
    };
    tokio::try_join!(upload, download)?;
    // sing-box 1.14.1 fully closes upstream TCP on upload EOF. Receive the
    // complete echo first; Caddy above still exercises early half-close draining.
    if matches!(peer, Peer::SingBox) {
        write.shutdown().await?;
    }
    let mut trailing = [0; 1];
    assert_eq!(read.read(&mut trailing).await?, 0, "unexpected echo tail");
    Ok(())
}
