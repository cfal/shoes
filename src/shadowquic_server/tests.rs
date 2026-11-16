use super::*;
use crate::config::server::ShadowQuicUser;

fn options() -> ShadowQuicServerConfig {
    ShadowQuicServerConfig {
        users: vec![ShadowQuicUser {
            username: "alice".into(),
            password: "test-secret".into(),
        }],
        server_name: "localhost".into(),
        jls_upstream: "127.0.0.1:9".into(),
        zero_rtt: true,
        udp_enabled: true,
    }
}

struct Peer {
    client: quic::Endpoint,
    server: quic::Endpoint,
    connection: quic::Connection,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.client.close(0u32.into(), b"done");
        self.server.close(0u32.into(), b"done");
        self.task.abort();
    }
}
fn client_tls(username: &str, password: &str) -> quic::rustls::ClientConfig {
    let mut tls = quic::rustls::ClientConfig::builder_with_provider(Arc::new(
        quic::rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&quic::rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(quic::rustls::RootCertStore::empty())
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.enable_early_data = true;
    tls.jls_config = quic::rustls::jls::JlsClientConfig::new(password, username);
    tls
}

async fn peer() -> Peer {
    let server = quic::Endpoint::server(
        server_config(&options()).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let client = quic::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let tls = client_tls("alice", "test-secret");
    client.set_default_client_config(quic::ClientConfig::new(Arc::new(
        quic::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    )));
    let connect = client
        .connect(server.local_addr().unwrap(), "localhost")
        .unwrap();
    let (connection, accepted) = tokio::join!(connect, async {
        server.accept().await.unwrap().await.unwrap()
    });
    let connection = connection.unwrap();
    assert_eq!(accepted.jls_chosen_user().as_deref(), Some("alice"));
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    let selector = Arc::new(
        crate::tcp::tcp_client_handler_factory::create_test_selector(
            vec![crate::config::ResolvedRuleConfig::default()],
            resolver.clone(),
        )
        .unwrap(),
    );
    let task = tokio::spawn(async move {
        let _ = run_connection(accepted, selector, resolver, true).await;
    });
    Peer {
        client,
        server,
        connection,
        task,
    }
}

#[tokio::test]
async fn jls_tcp_and_stats_wire_contract() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = NetLocation::from_ip_addr(
            listener.local_addr().unwrap().ip(),
            listener.local_addr().unwrap().port(),
        );
        let echo = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut data = [0; 5];
            stream.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"hello");
            stream.write_all(b"reply").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let peer = peer().await;
        let (mut send, mut recv) = peer.connection.open_bi().await.unwrap();
        let mut command = vec![1];
        command.extend(crate::socks_handler::write_location_to_vec(&target).unwrap());
        command.extend(b"hello");
        send.write_all(&command).await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(100).await.unwrap(), b"reply");
        echo.await.unwrap();
        let (mut send, mut recv) = peer.connection.open_bi().await.unwrap();
        send.write_all(&[255, 0, 0, 0, 0, 0, 0, 0, 1, 0])
            .await
            .unwrap();
        send.finish().unwrap();
        let response = recv.read_to_end(100).await.unwrap();
        assert_eq!(&response[..5], &[0, 0, 0, 0, 26]);
        assert_eq!(response.len(), 31);
    })
    .await
    .unwrap();
}

async fn udp_roundtrip(stream_mode: bool) {
    tokio::time::timeout(Duration::from_secs(15), async {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = NetLocation::from_ip_addr(
            socket.local_addr().unwrap().ip(),
            socket.local_addr().unwrap().port(),
        );
        let peer = peer().await;
        let mut controls = Vec::new();
        let mut ids = std::collections::HashSet::new();
        // Both associations share one connection: outgoing IDs must be unique.
        for id in [17u16, 18] {
            let (mut control, mut response) = peer.connection.open_bi().await.unwrap();
            let mut header = vec![if stream_mode { 4 } else { 3 }, 1, 0, 0, 0, 0, 0, 0];
            control.write_all(&header).await.unwrap();
            // Send payload before the address control entry to exercise cross-stream reordering.
            let mut payload_stream = None;
            if stream_mode {
                let mut stream = peer.connection.open_uni().await.unwrap();
                header = id.to_be_bytes().to_vec();
                header.extend([0, 5]);
                header.extend(b"hello");
                stream.write_all(&header).await.unwrap();
                payload_stream = Some(stream);
            } else {
                header = id.to_be_bytes().to_vec();
                header.extend(b"hello");
                peer.connection.send_datagram(header.into()).unwrap();
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
            let mut mapping = crate::socks_handler::write_location_to_vec(&target).unwrap();
            mapping.extend(id.to_be_bytes());
            control.write_all(&mapping).await.unwrap();
            let mut data = [0; 100];
            let (n, from) = socket.recv_from(&mut data).await.unwrap();
            assert_eq!(&data[..n], b"hello");
            socket.send_to(b"reply", from).await.unwrap();
            assert_eq!(
                crate::socks_handler::read_location_direct(&mut response)
                    .await
                    .unwrap(),
                target
            );
            let reply_id = response.read_u16().await.unwrap();
            assert!(ids.insert(reply_id));
            if stream_mode {
                let mut stream = peer.connection.accept_uni().await.unwrap();
                assert_eq!(stream.read_u16().await.unwrap(), reply_id);
                assert_eq!(stream.read_u16().await.unwrap(), 5);
                let mut reply = [0; 5];
                AsyncReadExt::read_exact(&mut stream, &mut reply)
                    .await
                    .unwrap();
                assert_eq!(&reply, b"reply");
            } else {
                let reply = peer.connection.read_datagram().await.unwrap();
                assert_eq!(&reply[..2], &reply_id.to_be_bytes());
                assert_eq!(&reply[2..], b"reply");
            }
            controls.push((control, response, payload_stream));
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn jls_udp_datagram_reordering_and_multiple_associations() {
    udp_roundtrip(false).await;
}
#[tokio::test]
async fn jls_udp_stream_reordering_and_multiple_associations() {
    udp_roundtrip(true).await;
}

#[test]
fn pending_packets_are_bounded_and_expire() {
    let contexts: Contexts = Default::default();
    for id in 0..5000 {
        deliver(&contexts, id, Bytes::from(vec![0; 4096]));
    }
    let mut store = contexts.lock();
    assert!(store.pending_bytes <= 1024 * 1024);
    assert!(store.pending.len() <= 4096);
    for (time, _) in store.pending.values_mut() {
        *time -= Duration::from_secs(11);
    }
    store.expire();
    assert_eq!(store.pending_bytes, 0);
    assert!(store.pending.is_empty());
}

#[test]
fn config_rejects_missing_or_duplicate_credentials() {
    let mut config = options();
    assert!(validate(&config).is_ok());
    config.users.push(config.users[0].clone());
    assert!(validate(&config).is_err());
    config.users.clear();
    assert!(validate(&config).is_err());
    let parsed: crate::config::ServerProxyConfig = serde_json::from_value(serde_json::json!({"type":"shadowquic", "users":[{"username":"alice","password":"secret"}], "server_name":"localhost", "jls_upstream":"127.0.0.1:9"})).unwrap();
    assert!(matches!(
        parsed,
        crate::config::ServerProxyConfig::Shadowquic(_)
    ));
}

#[tokio::test]
#[ignore = "requires SHOES_SHADOWQUIC_PEER built from the reference checkout"]
async fn reference_client_interoperability() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_address = tcp.local_addr().unwrap();
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_address = udp.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let mut request = [0; 5];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"hello");
            stream.write_all(b"reply").await.unwrap();
            for _ in 0..2 {
                let (n, from) = udp.recv_from(&mut request).await.unwrap();
                assert_eq!(&request[..n], b"hello");
                udp.send_to(b"reply", from).await.unwrap();
            }
        });
        let server = quic::Endpoint::server(
            server_config(&options()).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let selector = Arc::new(
            crate::tcp::tcp_client_handler_factory::create_test_selector(
                vec![crate::config::ResolvedRuleConfig::default()],
                resolver.clone(),
            )
            .unwrap(),
        );
        let serving = tokio::spawn(async move {
            let accepted = server.accept().await.unwrap().await.unwrap();
            assert_eq!(accepted.jls_chosen_user().as_deref(), Some("alice"));
            let _ = run_connection(accepted, selector, resolver, true).await;
        });
        let output = tokio::process::Command::new(
            std::env::var_os("SHOES_SHADOWQUIC_PEER").expect("set SHOES_SHADOWQUIC_PEER"),
        )
        .args([
            address.to_string(),
            tcp_address.to_string(),
            udp_address.to_string(),
        ])
        .kill_on_drop(true)
        .output()
        .await
        .unwrap();
        serving.abort();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        echo.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn config_compilation_requires_quic_and_omits_external_certificates() {
    let example = include_str!("../../examples/shadowquic.yaml");
    let configs = serde_yaml::from_str::<Vec<crate::config::Config>>(example).unwrap();
    crate::config::compile_configs(configs).await.unwrap();
    for invalid in [
        example.replace("transport: quic", "transport: tcp"),
        example.replace("  protocol:", "  quic_settings: {}\n  protocol:"),
    ] {
        let configs = serde_yaml::from_str::<Vec<crate::config::Config>>(&invalid).unwrap();
        assert!(crate::config::compile_configs(configs).await.is_err());
    }
}

#[tokio::test]
async fn listener_retirement_releases_the_bound_socket() {
    let retirements = crate::listener_tasks::QuicRetirements::default();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let listener = retirements
        .track(async { listener::bind(server_config(&options()).unwrap(), socket).unwrap() })
        .await;
    let addr = listener.endpoint.local_addr().unwrap();
    drop(listener);
    tokio::time::timeout(Duration::from_secs(3), retirements.wait())
        .await
        .unwrap()
        .unwrap();
    std::net::UdpSocket::bind(addr).unwrap();
}

#[tokio::test]
async fn invalid_jls_credentials_never_establish_a_proxy_connection() {
    for (username, password) in [("alice", "wrong"), ("unknown", "test-secret")] {
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut config = options();
        config.jls_upstream = upstream.local_addr().unwrap().to_string();
        let server = quic::Endpoint::server(
            server_config(&config).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let client = quic::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(quic::ClientConfig::new(Arc::new(
            quic::crypto::rustls::QuicClientConfig::try_from(client_tls(username, password))
                .unwrap(),
        )));
        let connecting = client
            .connect(server.local_addr().unwrap(), "localhost")
            .unwrap();
        let handshake = async {
            let incoming = server.accept().await.unwrap();
            if let Ok(conn) = incoming.await {
                assert!(conn.jls_chosen_user().is_none());
            }
        };
        let _ = tokio::time::timeout(Duration::from_millis(300), async {
            tokio::join!(
                async {
                    assert!(connecting.await.is_err());
                },
                handshake
            );
        })
        .await;
        let mut packet = [0; 2048];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(2), upstream.recv_from(&mut packet))
                .await
                .unwrap()
                .unwrap();
        assert!(
            length >= 1200,
            "camouflage forwards the QUIC Initial to the configured upstream"
        );
        client.close(0u32.into(), b"done");
        server.close(0u32.into(), b"done");
    }
}
