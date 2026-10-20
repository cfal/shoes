use serde_json::json;
use shoes_test_support::{port_helper::PortHelper, test_fixture::start_shoes_server};
use std::{io, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

fn request(host: &str) -> Vec<u8> {
    format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes()
}

#[tokio::test]
async fn hysteria2_wire_ingress_sniffs_http() -> io::Result<()> {
    wire_ingress_sniffs_http("hysteria2").await
}

#[tokio::test]
async fn tuic_wire_ingress_sniffs_http() -> io::Result<()> {
    wire_ingress_sniffs_http("tuic").await
}

#[tokio::test]
async fn naive_tls_h2_wire_ingress_sniffs_http() -> io::Result<()> {
    wire_ingress_sniffs_http("naiveproxy").await
}

async fn wire_ingress_sniffs_http(protocol: &str) -> io::Result<()> {
    use shoes_test_support::certs::generate_test_cert_files;
    use shoes_test_support::process::start_singbox_server;

    timeout(Duration::from_secs(30), async {
        const UUID: &str = "0d47df7e-d210-4b76-a03d-6d0f3c8ba3d9";
        let exit = TcpListener::bind("0.0.0.0:0").await?;
        let mut ports = PortHelper::new();
        let (_, server_port) = if protocol == "naiveproxy" {
            ports.get_localhost_listener_port()
        } else {
            ports.get_quic_listener_port()
        };
        let (_, client_port) = ports.get_localhost_listener_port();
        let (cert, key) = generate_test_cert_files()?;
        let cert_path = cert.display().to_string();
        let key_path = key.display().to_string();
        let mut server = json!({
            "address": format!("0.0.0.0:{server_port}"),
            "sniff": true,
            "rules": [{"mask": "sniff.invalid", "action": "allow", "override_address": format!("127.0.0.1:{}", exit.local_addr()?.port())}],
        });
        if protocol == "naiveproxy" {
            server["protocol"] = json!({"type": "tls", "tls_targets": {"test.local": {
                "cert": cert_path, "key": key_path, "alpn_protocols": ["h2"],
                "protocol": {"type": "naiveproxy", "users": [{"name": "test", "username": "user", "password": "pass"}]},
            }}});
        } else {
            server["transport"] = "quic".into();
            server["quic_settings"] = json!({"cert": cert_path, "key": key_path, "num_endpoints": 1, "alpn_protocols": ["h3"]});
            server["protocol"] = if protocol == "hysteria2" {
                json!({"type": "hysteria2", "password": "pass"})
            } else {
                json!({"type": "tuic", "uuid": UUID, "password": "pass"})
            };
        }
        let (_server, _server_config) = start_shoes_server(&json!([server]).to_string())?;
        let (_client, _client_config) = if protocol == "naiveproxy" {
            start_shoes_server(&json!([
                {"client_group": "upstream", "client_proxies": [{
                    "address": format!("127.0.0.1:{server_port}"),
                    "protocol": {"type": "tls", "verify": false, "sni_hostname": "test.local", "alpn_protocols": ["h2"],
                        "protocol": {"type": "naiveproxy", "username": "user", "password": "pass"}},
                }]},
                {"address": format!("0.0.0.0:{client_port}"), "protocol": {"type": "http"},
                 "rules": [{"mask": "0.0.0.0/0", "client_chain": "upstream"}]},
            ]).to_string())?
        } else {
            let mut outbound = json!({
                "type": protocol, "tag": "upstream", "server": "127.0.0.1", "server_port": server_port,
                "password": "pass", "tls": {"enabled": true, "insecure": true, "server_name": "test.local", "alpn": ["h3"]},
            });
            if protocol == "tuic" {
                outbound["uuid"] = UUID.into();
                outbound["congestion_control"] = "cubic".into();
            }
            start_singbox_server(&json!({
                "log": {"level": "warn"},
                "inbounds": [{"type": "http", "listen": "0.0.0.0", "listen_port": client_port}],
                "outbounds": [outbound], "route": {"final": "upstream"},
            }).to_string())?
        };
        ports.wait_for_all_ports().await?;
        let payload = b"POST /wire HTTP/1.1\r\nHost: sniff.invalid\r\nContent-Length: 4\r\n\r\nbody";
        for split in [5, payload.len()] {
            let upstream = async {
                let (mut stream, _) = exit.accept().await?;
                let mut received = vec![0; payload.len()];
                stream.read_exact(&mut received).await?;
                assert_eq!(received, payload);
                stream.write_all(b"routed").await?;
                assert_eq!(stream.read(&mut [0]).await?, 0);
                stream.shutdown().await
            };
            let client = async {
                let mut stream = TcpStream::connect(("127.0.0.1", client_port)).await?;
                super::plain_tcp_relay::request_to(&mut stream, "http", "192.0.2.9:8080".parse().unwrap(), &payload[..split]).await?;
                stream.write_all(&payload[split..]).await?;
                let mut reply = [0; 6];
                stream.read_exact(&mut reply).await?;
                assert_eq!(&reply, b"routed");
                stream.shutdown().await?;
                assert_eq!(stream.read(&mut [0]).await?, 0);
                io::Result::Ok(())
            };
            tokio::try_join!(upstream, client)?;
        }
        Ok(())
    }).await.unwrap_or_else(|_| panic!("{protocol}/wire-ingress: timed out"))
}

#[tokio::test]
async fn late_host_after_timeout_keeps_the_fallback_route() -> io::Result<()> {
    for protocol in ["socks", "http"] {
        timeout(Duration::from_secs(10), async {
            let fallback = TcpListener::bind("0.0.0.0:0").await?;
            let hinted = TcpListener::bind("0.0.0.0:0").await?;
            let mut ports = PortHelper::new();
            let (_, port) = ports.get_localhost_listener_port();
            let config = json!([{
                "address": format!("0.0.0.0:{port}"),
                "protocol": {"type": protocol},
                "sniff": true,
                "rules": [
                    {"mask": "late.invalid", "action": "allow", "override_address": format!("127.0.0.1:{}", hinted.local_addr()?.port())},
                    {"mask": "192.0.2.9", "action": "allow", "override_address": format!("127.0.0.1:{}", fallback.local_addr()?.port())},
                ],
            }]);
            let (_process, _config) = start_shoes_server(&config.to_string())?;
            ports.wait_for_all_ports().await?;
            let partial = b"GET / HTTP/1.1\r\n";
            let tail = b"Host: late.invalid\r\n\r\nGET /later HTTP/1.1\r\nHost: late.invalid\r\n\r\n";
            let upstream = async {
                let (mut stream, _) = fallback.accept().await?;
                stream.write_all(b"ready").await?;
                let mut received = Vec::new();
                stream.read_to_end(&mut received).await?;
                assert_eq!(received, [partial.as_slice(), tail.as_slice()].concat());
                stream.write_all(b"retained").await?;
                stream.shutdown().await
            };
            let client = async {
                let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
                super::plain_tcp_relay::request_to(&mut stream, protocol, "192.0.2.9:8080".parse().unwrap(), &[]).await?;
                stream.write_all(partial).await?;
                let mut ready = [0; 5];
                stream.read_exact(&mut ready).await?;
                assert_eq!(&ready, b"ready");
                stream.write_all(tail).await?;
                stream.shutdown().await?;
                let mut reply = Vec::new();
                stream.read_to_end(&mut reply).await?;
                assert_eq!(reply, b"retained");
                io::Result::Ok(())
            };
            tokio::try_join!(upstream, client)?;
            assert!(timeout(Duration::from_millis(20), hinted.accept()).await.is_err());
            io::Result::Ok(())
        }).await.unwrap_or_else(|_| panic!("{protocol}/late-host: timed out"))?;
    }
    Ok(())
}

#[tokio::test]
async fn http_upgrade_keeps_its_route_and_replays_opaque_traffic() -> io::Result<()> {
    for protocol in ["socks", "http"] {
        timeout(Duration::from_secs(10), async {
            let first = TcpListener::bind("0.0.0.0:0").await?;
            let second = TcpListener::bind("0.0.0.0:0").await?;
            let mut ports = PortHelper::new();
            let (_, port) = ports.get_localhost_listener_port();
            let config = json!([{
                "address": format!("0.0.0.0:{port}"),
                "protocol": {"type": protocol},
                "sniff": true,
                "rules": [
                    {"mask": "a.invalid", "action": "allow", "override_address": format!("127.0.0.1:{}", first.local_addr()?.port())},
                    {"mask": "b.invalid", "action": "allow", "override_address": format!("127.0.0.1:{}", second.local_addr()?.port())},
                ],
            }]);
            let (_process, _config) = start_shoes_server(&config.to_string())?;
            ports.wait_for_all_ports().await?;
            let head = b"GET / HTTP/1.1\r\nHost: a.invalid\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n";
            let switching = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n";
            let opaque = [request("b.invalid"), vec![0, 255, 13, 10, 22, 3, 3]].concat();
            let upstream = async {
                let (mut stream, _) = first.accept().await?;
                let mut received = vec![0; head.len()];
                stream.read_exact(&mut received).await?;
                assert_eq!(received, head);
                stream.write_all(switching).await?;
                let mut received = Vec::new();
                stream.read_to_end(&mut received).await?;
                assert_eq!(received, opaque);
                stream.write_all(&received).await?;
                stream.shutdown().await
            };
            let client = async {
                let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
                super::plain_tcp_relay::request_to(&mut stream, protocol, "192.0.2.9:8080".parse().unwrap(), head).await?;
                let mut response = vec![0; switching.len()];
                stream.read_exact(&mut response).await?;
                assert_eq!(response, switching);
                stream.write_all(&opaque).await?;
                stream.shutdown().await?;
                let mut reply = Vec::new();
                stream.read_to_end(&mut reply).await?;
                assert_eq!(reply, opaque);
                io::Result::Ok(())
            };
            tokio::try_join!(upstream, client)?;
            assert!(timeout(Duration::from_millis(20), second.accept()).await.is_err());
            io::Result::Ok(())
        }).await.unwrap_or_else(|_| panic!("{protocol}/upgrade: timed out"))?;
    }
    Ok(())
}

#[tokio::test]
async fn host_changes_stay_on_one_route_but_new_connections_are_rejudged() -> io::Result<()> {
    timeout(Duration::from_secs(20), async {
        for protocol in ["http", "socks"] {
            let exit_a = TcpListener::bind("0.0.0.0:0").await?;
            let exit_b = TcpListener::bind("0.0.0.0:0").await?;
            let mut ports = PortHelper::new();
            let (_, port) = ports.get_localhost_listener_port();
            let mut rules = vec![
                json!({
                    "mask": "a.invalid",
                    "action": "allow",
                    "override_address": format!("127.0.0.1:{}", exit_a.local_addr()?.port()),
                }),
                json!({
                    "mask": "b.invalid",
                    "action": "allow",
                    "override_address": format!("127.0.0.1:{}", exit_b.local_addr()?.port()),
                }),
            ];
            rules.extend(
                (0..20).map(|i| json!({"mask": format!("unused{i}.invalid"), "action": "block"})),
            );
            let config = json!([{
                "address": format!("0.0.0.0:{port}"),
                "protocol": {"type": protocol},
                "sniff": true,
                "rules": rules,
            }]);
            let (_process, _config) = start_shoes_server(&config.to_string())?;
            ports.wait_for_all_ports().await?;
            for pipelined in [false, true] {
                let first = request("a.invalid");
                let second = request("b.invalid");
                let upstream = async {
                    let (mut stream, _) = exit_a.accept().await?;
                    for expected in [&first, &second] {
                        let mut bytes = vec![0; expected.len()];
                        stream.read_exact(&mut bytes).await?;
                        assert_eq!(&bytes, expected);
                        stream.write_all(b"ok").await?;
                    }
                    assert_eq!(stream.read(&mut [0]).await?, 0);
                    stream.shutdown().await
                };
                let client = async {
                    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
                    let payload = if pipelined {
                        [first.as_slice(), second.as_slice()].concat()
                    } else {
                        Vec::new()
                    };
                    super::plain_tcp_relay::request_to(
                        &mut stream,
                        protocol,
                        "192.0.2.9:8080".parse().unwrap(),
                        &payload,
                    )
                    .await?;
                    if !pipelined {
                        stream.write_all(&first).await?;
                    }
                    let mut reply = [0; 2];
                    stream.read_exact(&mut reply).await?;
                    assert_eq!(&reply, b"ok");
                    if !pipelined {
                        stream.write_all(&second).await?;
                    }
                    stream.read_exact(&mut reply).await?;
                    assert_eq!(&reply, b"ok");
                    stream.shutdown().await?;
                    assert_eq!(stream.read(&mut [0]).await?, 0);
                    io::Result::Ok(())
                };
                tokio::try_join!(upstream, client)?;
                assert!(
                    timeout(Duration::from_millis(20), exit_b.accept())
                        .await
                        .is_err()
                );
            }
            let bytes = request("b.invalid");
            let upstream = async {
                let (mut stream, _) = exit_b.accept().await?;
                let mut received = vec![0; bytes.len()];
                stream.read_exact(&mut received).await?;
                assert_eq!(received, bytes);
                stream.write_all(b"route b").await?;
                stream.shutdown().await
            };
            let client = async {
                let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
                super::plain_tcp_relay::request_to(
                    &mut stream,
                    protocol,
                    "192.0.2.9:8080".parse().unwrap(),
                    &bytes,
                )
                .await?;
                stream.shutdown().await?;
                let mut reply = Vec::new();
                stream.read_to_end(&mut reply).await?;
                assert_eq!(reply, b"route b");
                io::Result::Ok(())
            };
            tokio::try_join!(upstream, client)?;
            assert!(
                timeout(Duration::from_millis(20), exit_a.accept())
                    .await
                    .is_err()
            );
        }
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn forward_proxy_sniffs_rewritten_origin_form_without_changing_the_target() -> io::Result<()>
{
    timeout(Duration::from_secs(10), async {
        let target = TcpListener::bind("0.0.0.0:0").await?;
        let target_port = target.local_addr()?.port();
        let mut ports = PortHelper::new();
        let (_, port) = ports.get_localhost_listener_port();
        let config = json!([{
            "address": format!("0.0.0.0:{port}"),
            "protocol": {"type": "http"},
            "sniff": true,
            "rules": [{"mask": "sniff.invalid", "action": "allow"}],
        }]);
        let (_process, _config) = start_shoes_server(&config.to_string())?;
        ports.wait_for_all_ports().await?;
        let upstream = async {
            let (mut stream, _) = target.accept().await?;
            let expected = b"POST /path?q=1 HTTP/1.1\r\nHost: sniff.invalid\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody";
            let mut received = vec![0; expected.len()];
            stream.read_exact(&mut received).await?;
            assert_eq!(received, expected);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await?;
            stream.shutdown().await
        };
        let client = async {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
            stream
                .write_all(format!("POST http://127.0.0.1:{target_port}/path?q=1 HTTP/1.1\r\nHost: sniff.invalid\r\nConnection: keep-alive\r\nContent-Length: 4\r\n\r\nbody").as_bytes())
                .await?;
            stream.shutdown().await?;
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await?;
            assert!(reply.starts_with(b"HTTP/1.1 200 OK\r\n"));
            assert!(reply.ends_with(b"\r\n\r\nok"));
            io::Result::Ok(())
        };
        tokio::try_join!(upstream, client)?;
        Ok(())
    })
    .await?
}
