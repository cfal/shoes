use std::{io, io::Write, process::Command, time::Duration};

use base64::{Engine, prelude::BASE64_STANDARD};
use serde_json::{Value, json};
use shoes_test_support::{
    port_helper::PortHelper,
    process::{ProcessGuard, start_singbox_server},
    socks5::Socks5UdpAssociation,
    test_fixture::start_shoes_server,
    test_servers::{start_tcp_stream_echo_server, start_udp_echo_server},
    xray,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

use crate::http_proxy_support as support;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const METHODS: [(&str, usize); 2] = [
    ("2022-blake3-aes-128-gcm", 16),
    ("2022-blake3-aes-256-gcm", 32),
];

fn keys(size: usize) -> [String; 3] {
    [0x11, 0x22, 0x33].map(|byte| BASE64_STANDARD.encode(vec![byte; size]))
}

fn client_config(port: u16, server: u16, method: &str, password: &str) -> Value {
    support::relay_config(
        port,
        server,
        json!({"type": "shadowsocks", "cipher": method, "password": password}),
    )
}

enum Shutdown {
    BeforeReply,
    AfterReply,
}

async fn check_tcp(port: u16, shutdown: Shutdown) -> io::Result<()> {
    let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
    let mut stream =
        support::connect(port, &format!("127.0.0.1:{}", echo.local_addr().port())).await?;
    match shutdown {
        Shutdown::BeforeReply => support::exchange(stream).await?,
        Shutdown::AfterReply => {
            let payload: Vec<_> = (0..131073).map(|i| (i % 251) as u8).collect();
            let mut response = vec![0; payload.len()];
            let (mut read, mut write) = stream.split();
            tokio::try_join!(write.write_all(&payload), read.read_exact(&mut response))?;
            assert!(response == payload, "TCP echo payload mismatch");
            stream.shutdown().await?;
            assert_eq!(stream.read(&mut response).await?, 0);
        }
    }

    // A target that speaks first also exercises response salt and request-salt validation.
    let listener = TcpListener::bind("0.0.0.0:0").await?;
    let target = format!("127.0.0.1:{}", listener.local_addr()?.port());
    let peer = async {
        let (mut stream, _) = listener.accept().await?;
        stream.write_all(b"banner").await?;
        let mut response = [0; 3];
        stream.read_exact(&mut response).await?;
        assert_eq!(&response, b"ack");
        stream.write_all(&response).await?;
        assert_eq!(stream.read(&mut response).await?, 0);
        stream.shutdown().await
    };
    let client = async {
        let mut stream = support::connect(port, &target).await?;
        let mut banner = [0; 6];
        stream.read_exact(&mut banner).await?;
        assert_eq!(&banner, b"banner");
        stream.write_all(b"ack").await?;
        stream.read_exact(&mut banner[..3]).await?;
        assert_eq!(&banner[..3], b"ack");
        stream.shutdown().await?;
        assert_eq!(stream.read(&mut banner).await?, 0);
        Ok::<_, io::Error>(())
    };
    tokio::try_join!(peer, client)?;
    Ok(())
}

#[tokio::test]
async fn xray_single_key_multiuser_and_ordered_identity_relay() -> TestResult {
    timeout(Duration::from_secs(60), async {
        for (method, size) in METHODS {
            let [relay_key, server_key, user_key] = keys(size);
            let mut ports = PortHelper::new();
            let (_, single) = ports.get_localhost_listener_port();
            let (_, multiuser) = ports.get_localhost_listener_port();
            let (_, relay) = ports.get_localhost_listener_port();
            let _peer = xray::start(json!({
                "log": {"loglevel": "warning"},
                "inbounds": [
                    {"listen": "0.0.0.0", "port": single, "protocol": "shadowsocks", "settings": {
                        "method": method, "password": user_key, "network": "tcp"}},
                    {"listen": "0.0.0.0", "port": multiuser, "protocol": "shadowsocks", "settings": {
                        "method": method, "password": server_key, "network": "tcp",
                        "clients": [{"password": user_key, "email": "identity-test"}]}},
                    {"listen": "0.0.0.0", "port": relay, "protocol": "shadowsocks", "settings": {
                        "method": method, "password": relay_key, "network": "tcp",
                        "clients": [{"password": server_key, "address": "127.0.0.1", "port": multiuser}]}}
                ],
                "outbounds": [{"protocol": "freedom", "settings": {
                    "finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]
                }}]
            })).await?;
            for (label, server, password) in [
                ("single key", single, user_key.clone()),
                ("multiuser", multiuser, format!("{server_key}:{user_key}")),
                ("identity relay", relay, format!("{relay_key}:{server_key}:{user_key}")),
            ] {
                eprintln!("{method}: {label}");
                let (_, entry) = ports.get_localhost_listener_port();
                let config = [client_config(entry, server, method, &password)];
                let _shoes = start_shoes_server(&serde_yaml::to_string(&config)?)?;
                ports.wait_for_all_ports().await?;
                check_tcp(entry, Shutdown::BeforeReply).await?;
            }
            for (label, server, password) in [
                ("missing server key", multiuser, user_key.clone()),
                ("wrong server key", multiuser, format!("{relay_key}:{user_key}")),
                ("wrong user key", multiuser, format!("{server_key}:{relay_key}")),
                ("reversed server/user", multiuser, format!("{user_key}:{server_key}")),
                ("unexpected identity", multiuser, format!("{server_key}:{relay_key}:{user_key}")),
                ("missing relay identity", relay, format!("{relay_key}:{user_key}")),
                ("reordered relay identities", relay, format!("{server_key}:{relay_key}:{user_key}")),
                ("wrong relay user", relay, format!("{relay_key}:{server_key}:{relay_key}")),
            ] {
                eprintln!("{method}: rejects {label}");
                let target = TcpListener::bind("0.0.0.0:0").await?;
                let (_, entry) = ports.get_localhost_listener_port();
                let config = [client_config(entry, server, method, &password)];
                let _shoes = start_shoes_server(&serde_yaml::to_string(&config)?)?;
                ports.wait_for_all_ports().await?;
                let attempt = async {
                    let mut stream = support::connect(entry, &format!("127.0.0.1:{}", target.local_addr()?.port())).await?;
                    stream.write_all(b"must not reach target").await?;
                    stream.shutdown().await?;
                    let mut byte = [0];
                    assert_eq!(stream.read(&mut byte).await?, 0);
                    Ok::<_, io::Error>(())
                };
                // A failed handshake must close or error, not merely stall without delivering data.
                let _rejection = timeout(Duration::from_secs(3), attempt).await?;
                assert!(timeout(Duration::from_millis(200), target.accept()).await.is_err());
            }
        }
        Ok(())
    }).await?
}

#[tokio::test]
async fn shadowsocks_rust_multiuser_both_aes_ciphers() -> TestResult {
    timeout(Duration::from_secs(30), async {
        for (method, size) in METHODS {
            let [_, server_key, user_key] = keys(size);
            let second_user = BASE64_STANDARD.encode(vec![0x55; size]);
            let mut ports = PortHelper::new();
            let (_, server) = ports.get_localhost_listener_port();
            let (_, entry) = ports.get_localhost_listener_port();
            let (_, second_entry) = ports.get_localhost_listener_port();
            let config = json!({"servers": [{
                "server": "0.0.0.0", "server_port": server, "method": method, "password": server_key,
                "users": [{"name": "identity-test", "password": user_key},
                    {"name": "second-user", "password": second_user}], "mode": "tcp_only"
            }], "runtime": {"mode": "single_thread"}});
            let mut file = tempfile::NamedTempFile::new()?;
            serde_json::to_writer(&mut file, &config)?;
            file.flush()?;
            let binary = std::env::var_os("SHOES_TEST_SSSERVER_BIN").unwrap_or_else(|| "ssserver".into());
            let process = Command::new(binary).arg("-c").arg(file.path()).spawn()?;
            let _peer = ProcessGuard::new(process, "ssserver");
            let configs = [
                client_config(entry, server, method, &format!("{server_key}:{user_key}")),
                client_config(second_entry, server, method, &format!("{server_key}:{second_user}")),
            ];
            let _shoes = start_shoes_server(&serde_yaml::to_string(&configs)?)?;
            ports.wait_for_all_ports().await?;
            tokio::try_join!(
                check_tcp(entry, Shutdown::BeforeReply),
                check_tcp(second_entry, Shutdown::BeforeReply)
            )?;
        }
        Ok(())
    }).await?
}

#[tokio::test]
async fn singbox_multiuser_identity_udp_over_tcp() -> TestResult {
    check_singbox_tcp_and_udp(false).await
}

#[tokio::test]
async fn singbox_multiuser_identity_after_http_proxy_hop() -> TestResult {
    check_singbox_tcp_and_udp(true).await
}

async fn check_singbox_tcp_and_udp(through_http: bool) -> TestResult {
    timeout(Duration::from_secs(30), async {
        for (method, size) in METHODS {
            let [_, server_key, user_key] = keys(size);
            let mut ports = PortHelper::new();
            let (_, server) = ports.get_localhost_listener_port();
            let (_, entry) = ports.get_localhost_listener_port();
            let _peer = start_singbox_server(
                &json!({
                    "log": {"level": "warn"},
                    "inbounds": [{"type": "shadowsocks", "listen": "0.0.0.0", "listen_port": server,
                        "method": method, "password": server_key,
                        "users": [{"name": "identity-test", "password": user_key}]}],
                    "outbounds": [{"type": "direct"}]
                })
                .to_string(),
            )?;
            let mut config =
                client_config(entry, server, method, &format!("{server_key}:{user_key}"));
            config["protocol"] = json!({"type": "mixed", "udp_enabled": true});
            config["rules"][0]["client_chain"][0]["protocol"]["udp_enabled"] = true.into();
            let mut configs = Vec::new();
            if through_http {
                let (_, hop) = ports.get_localhost_listener_port();
                configs.push(
                    json!({"address": format!("0.0.0.0:{hop}"), "protocol": {"type": "http"}}),
                );
                let chain = config["rules"][0]["client_chain"].as_array_mut().unwrap();
                chain.insert(
                    0,
                    json!({
                        "address": format!("127.0.0.1:{hop}"), "protocol": {"type": "http"}
                    }),
                );
            }
            configs.push(config);
            let _shoes = start_shoes_server(&serde_yaml::to_string(&configs)?)?;
            ports.wait_for_all_ports().await?;
            // sing-box 1.14.1 also truncates early-half-close replies without identity headers.
            check_tcp(entry, Shutdown::AfterReply).await?;
            let association = Socks5UdpAssociation::connect("127.0.0.1", entry).await?;
            for _ in 0..2 {
                let echo = start_udp_echo_server("0.0.0.0", 0).await?;
                let target = ([127, 0, 0, 1], echo.local_addr().port()).into();
                for size in [1, 4096, 8192] {
                    let payload: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
                    assert_eq!(
                        association.send_to(target, &payload).await?,
                        [payload.as_slice(), b" [ECHO]"].concat()
                    );
                }
            }
        }
        Ok(())
    })
    .await?
}
