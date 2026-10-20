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
