use serde_json::{Value, json};
use shoes_test_support::certs::generate_test_cert_files;
use shoes_test_support::port_helper::PortHelper;
use shoes_test_support::socks5::Socks5UdpAssociation;
use shoes_test_support::test_fixture::{
    SingBoxCapability, generate_reality_keypair, start_shoes_server, start_singbox_server_with,
};
use shoes_test_support::test_servers::{
    start_reality_tls_template, start_tcp_stream_echo_server, start_udp_echo_server,
};
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::timeout;

const TEST_UUID: &str = "a3482e88-686a-4a58-8126-99c9034e4b09";

async fn echo_round_trip(stream: &mut TcpStream, payload: &[u8]) -> io::Result<()> {
    stream.write_all(payload).await?;
    let mut received = vec![0; payload.len()];
    stream.read_exact(&mut received).await?;
    assert_eq!(received, payload);
    Ok(())
}

async fn bulk_echo(
    mut stream: TcpStream,
    seed: u8,
    length: usize,
    read_gate: Option<oneshot::Receiver<()>>,
) -> io::Result<()> {
    let payload: Vec<_> = (0..length)
        .map(|index| (index as u8).wrapping_mul(31).wrapping_add(seed))
        .collect();
    let (mut reader, mut writer) = stream.split();
    let send = async {
        writer.write_all(&payload).await?;
        writer.shutdown().await
    };
    let receive = async {
        if let Some(gate) = read_gate {
            gate.await.map_err(io::Error::other)?;
        }
        let mut received = vec![0; payload.len()];
        reader.read_exact(&mut received).await?;
        assert_eq!(received, payload);
        assert_eq!(reader.read(&mut [0]).await?, 0);
        Ok::<_, io::Error>(())
    };
    tokio::try_join!(send, receive)?;
    Ok(())
}

#[tokio::test]
async fn sing_box_padded_single_carrier_survives_concurrent_streams()
-> Result<(), Box<dyn std::error::Error>> {
    let (cert_path, key_path) = generate_test_cert_files()?;
    let protocol = json!({
        "type": "tls",
        "tls_targets": {"test.local": {
            "cert": AsRef::<Path>::as_ref(&cert_path),
            "key": AsRef::<Path>::as_ref(&key_path),
            "protocol": {"type": "vless", "user_id": TEST_UUID, "udp_enabled": true}
        }}
    });
    let tls = json!({"enabled": true, "server_name": "test.local", "insecure": true});
    exercise_single_carrier(protocol, tls, Duration::ZERO).await
}

#[tokio::test]
async fn sing_box_reality_padded_single_carrier_survives_concurrency_and_idle()
-> Result<(), Box<dyn std::error::Error>> {
    let template = start_reality_tls_template().await?;
    let (private_key, public_key) = generate_reality_keypair();
    let short_id = "0123456789abcdef";
    let protocol = json!({
        "type": "tls",
        "reality_targets": {"localhost": {
            "private_key": private_key,
            "short_ids": [short_id],
            "dest": format!("localhost:{}", template.local_addr().port()),
            "protocol": {"type": "vless", "user_id": TEST_UUID, "udp_enabled": true}
        }}
    });
    let tls = json!({
        "enabled": true,
        "server_name": "localhost",
        "utls": {"enabled": true, "fingerprint": "chrome"},
        "reality": {"enabled": true, "public_key": public_key, "short_id": short_id}
    });
    // Exceeds Shoes' 60s idle timeout and its 10s check interval. Sing-box PINGs
    // must keep the original carrier reusable without application traffic.
    exercise_single_carrier(protocol, tls, Duration::from_secs(75)).await
}

async fn exercise_single_carrier(
    protocol: Value,
    tls: Value,
    idle: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    timeout(Duration::from_secs(60) + idle, async {
        let mut ports = PortHelper::new();
        let (_, shoes_port) = ports.get_localhost_listener_port();
        let (_, socks_port) = ports.get_localhost_listener_port();
        let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
        let udp_echo = start_udp_echo_server("0.0.0.0", 0).await?;
        let config = json!([{"address": format!("0.0.0.0:{shoes_port}"), "protocol": protocol}]);
        let (_shoes, _shoes_config) = start_shoes_server(&config.to_string())?;

        // A second carrier fails the test instead of hiding broken stream isolation.
        let listener = TcpListener::bind("0.0.0.0:0").await?;
        let carrier_port = listener.local_addr()?.port();
        let mut carrier = JoinSet::new();
        carrier.spawn(async move {
            let (mut client, _) = listener.accept().await?;
            let mut server = TcpStream::connect((Ipv4Addr::LOCALHOST, shoes_port)).await?;
            tokio::select! {
                result = tokio::io::copy_bidirectional(&mut client, &mut server) => {
                    result?;
                    Err::<(), _>(io::Error::other("mux carrier closed before the test finished"))
                }
                _ = listener.accept() => Err(io::Error::other("unexpected second mux carrier")),
            }
        });
        let singbox_config = json!({
            "log": {"level": "warn"},
            "inbounds": [{"type": "socks", "listen": "0.0.0.0", "listen_port": socks_port}],
            "outbounds": [{
                "type": "vless",
                "server": "127.0.0.1",
                "server_port": carrier_port,
                "uuid": TEST_UUID,
                "tls": tls,
                "multiplex": {
                    "enabled": true,
                    "protocol": "h2mux",
                    "max_connections": 1,
                    "padding": true
                }
            }]
        });
        let (_singbox, _singbox_config) = start_singbox_server_with(
            &singbox_config.to_string(),
            SingBoxCapability::Standard,
            &[],
        )?;
        ports.wait_for_all_ports().await?;

        let mut streams = Vec::new();
        for index in 0..5 {
            let mut stream = super::h2mux::connect_tcp_via_socks5(
                "127.0.0.1",
                socks_port,
                "127.0.0.1",
                echo.local_addr().port(),
            )
            .await?;
            echo_round_trip(&mut stream, &[index]).await?;
            streams.push(stream);
        }
        let mut interactive = streams.pop().unwrap();
        let mut abandoned = streams.pop().unwrap();
        let stalled = streams.pop().unwrap();
        socket2::SockRef::from(&stalled).set_recv_buffer_size(64 * 1024)?;
        let bulk_b = streams.pop().unwrap();
        let bulk_a = streams.pop().unwrap();
        let association = Socks5UdpAssociation::connect("127.0.0.1", socks_port).await?;
        let udp_target = (Ipv4Addr::LOCALHOST, udp_echo.local_addr().port()).into();
        let (release_reader, reader_gate) = oneshot::channel();

        let small_streams = async {
            for index in 0..16 {
                echo_round_trip(&mut interactive, &[index; 31]).await?;
                let reply = association.send_to(udp_target, &[index; 47]).await?;
                let mut expected = vec![index; 47];
                expected.extend_from_slice(b" [ECHO]");
                assert_eq!(reply, expected);
            }
            abandoned.write_all(b"cancel this stream").await?;
            socket2::SockRef::from(&abandoned).set_linger(Some(Duration::ZERO))?;
            drop(abandoned);
            release_reader.send(()).unwrap();
            Ok::<_, io::Error>(())
        };
        tokio::try_join!(
            bulk_echo(bulk_a, 17, 2 * 1024 * 1024, None),
            bulk_echo(bulk_b, 83, 2 * 1024 * 1024, None),
            bulk_echo(stalled, 149, 8 * 1024 * 1024, Some(reader_gate)),
            small_streams,
        )?;
        echo_round_trip(&mut interactive, b"surviving stream").await?;
        drop(association);
        tokio::select! {
            _ = tokio::time::sleep(idle) => {}
            result = carrier.join_next() => panic!("carrier failed while idle: {result:?}"),
        }
        echo_round_trip(&mut interactive, b"surviving stream after idle").await?;
        let mut replacement = super::h2mux::connect_tcp_via_socks5(
            "127.0.0.1",
            socks_port,
            "127.0.0.1",
            echo.local_addr().port(),
        )
        .await?;
        echo_round_trip(&mut replacement, b"new stream on the same carrier").await?;
        let association = Socks5UdpAssociation::connect("127.0.0.1", socks_port).await?;
        assert_eq!(
            association.send_to(udp_target, b"UDP after idle").await?,
            b"UDP after idle [ECHO]"
        );
        assert!(
            carrier.try_join_next().is_none(),
            "single carrier did not survive"
        );
        carrier.shutdown().await;
        Ok(())
    })
    .await?
}
