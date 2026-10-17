use super::*;
use crate::async_stream::{AsyncReadMessage, AsyncWriteMessage};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{pin::Pin, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadBuf},
    net::{TcpListener, UdpSocket},
};

fn key(byte: u8) -> String {
    STANDARD.encode([byte; 32])
}
fn public(byte: u8) -> String {
    STANDARD.encode(PublicKey::from(&StaticSecret::from([byte; 32])).as_bytes())
}

fn pair_config(port: u16) -> String {
    format!(
        r#"
- wireguard: server
  private_key: '{}'
  addresses: ['10.77.0.1/32', 'fd77::1/128']
  listen: '0.0.0.0:{port}'
  peers:
    - public_key: '{}'
      pre_shared_key: '{}'
      allowed_ips: ['10.77.0.2/32', 'fd77::2/128']
  inbound:
    rules:
      - masks: ['0.0.0.0/0', '::/0']
        action: allow
- wireguard: client
  private_key: '{}'
  addresses: ['10.77.0.2/32', 'fd77::2/128']
  peers:
    - public_key: '{}'
      pre_shared_key: '{}'
      endpoint: '127.0.0.1:{port}'
      allowed_ips: ['0.0.0.0/0', '::/0']
"#,
        key(41),
        public(42),
        key(43),
        key(42),
        public(41),
        key(43)
    )
}
fn validate(yaml: &str) -> stdio::Result<ValidatedConfigs> {
    crate::config::create_server_configs(serde_yaml::from_str(yaml).map_err(stdio::Error::other)?)
}
async fn echo_servers(v6: bool) -> (SocketAddr, SocketAddr, JoinSet<()>) {
    let listener = TcpListener::bind(if v6 { "[::]:0" } else { "0.0.0.0:0" })
        .await
        .unwrap();
    let udp = UdpSocket::bind(if v6 { "[::]:0" } else { "0.0.0.0:0" })
        .await
        .unwrap();
    let ip: IpAddr = if v6 { "::1" } else { "127.0.0.1" }.parse().unwrap();
    let tcp_addr = SocketAddr::new(ip, listener.local_addr().unwrap().port());
    let udp_addr = SocketAddr::new(ip, udp.local_addr().unwrap().port());
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let mut flows = JoinSet::new();
        loop { tokio::select! {
            connection = listener.accept() => {
                let (mut stream,_) = connection.unwrap();
                flows.spawn(async move { let (mut read,mut write) = stream.split(); let _ = tokio::io::copy(&mut read,&mut write).await; });
            }
            _ = flows.join_next(), if !flows.is_empty() => {}
        }}
    });
    tasks.spawn(async move {
        let mut data = [0; 65536];
        loop {
            let (len, src) = udp.recv_from(&mut data).await.unwrap();
            udp.send_to(&data[..len], src).await.unwrap();
        }
    });
    (tcp_addr, udp_addr, tasks)
}
async fn check_echo(connector: &dyn SocketConnector, tcp: SocketAddr, udp: SocketAddr) {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let location = |addr: SocketAddr| {
        ResolvedLocation::from(NetLocation::from_ip_addr(addr.ip(), addr.port()))
    };
    let mut stream = connector.connect(&resolver, &location(tcp)).await.unwrap();
    stream.write_all(b"WireGuard TCP").await.unwrap();
    let mut data = [0; 13];
    stream.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"WireGuard TCP");
    let mut stream = connector
        .connect_udp_bidirectional(&resolver, location(udp))
        .await
        .unwrap();
    assert!(!stream.read_message_eof_on_empty());
    for bytes in [&b"WireGuard UDP"[..], &b""[..], &b"after empty"[..]] {
        futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, bytes))
            .await
            .unwrap();
        let mut data = [0; 2048];
        let mut buf = ReadBuf::new(&mut data);
        futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_read_message(cx, &mut buf))
            .await
            .unwrap();
        assert_eq!(buf.filled(), bytes);
    }
    assert!(
        futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, &[0; 1408]))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn wireguard_tcp_udp_both_families_empty_outer_and_reload_rebind() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let reservation = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        let mut configs = validate(&pair_config(port)).unwrap();
        let prepared = Prepared::new(&mut configs).await.unwrap();
        drop(reservation);
        let connector = prepared.endpoints[1].connector.clone();
        assert!(connector.handle().is_err());
        let mut dns = DnsRegistry::new();
        let mut running = Running::default();
        for _ in 0..2 {
            prepared.start(&mut dns, &mut running).await.unwrap();
            let noise = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            for data in [&b""[..], &b"malformed WireGuard"[..], &[0xff; 148][..]] {
                noise.send_to(data, ("127.0.0.1", port)).await.unwrap();
            }
            for v6 in [false, true] {
                let (tcp, udp, _echoes) = echo_servers(v6).await;
                check_echo(connector.as_ref(), tcp, udp).await;
            }
            running.stop().await;
            assert!(connector.handle().is_err());
            let _rebind = UdpSocket::bind(("0.0.0.0", port)).await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn wireguard_ipv6_outer_transport() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let reservation = std::net::UdpSocket::bind("[::]:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        let mut configs = validate(&pair_config(port)).unwrap();
        configs.wireguard_endpoints[0].listen = Some(format!("[::]:{port}").parse().unwrap());
        configs.wireguard_endpoints[1].peers[0].endpoint = Some(format!("[::1]:{port}"));
        let prepared = Prepared::new(&mut configs).await.unwrap();
        drop(reservation);
        let mut running = Running::default();
        prepared
            .start(&mut DnsRegistry::new(), &mut running)
            .await
            .unwrap();
        for v6 in [false, true] {
            let (tcp, udp, _echoes) = echo_servers(v6).await;
            check_echo(prepared.endpoints[1].connector.as_ref(), tcp, udp).await;
        }
        running.stop().await;
        std::net::UdpSocket::bind(("::", port)).unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn wireguard_ipv4_bind_selects_a_compatible_hostname_address() {
    let mut configs = validate(&pair_config(51820)).unwrap();
    configs.wireguard_endpoints[1].listen = Some("0.0.0.0:0".parse().unwrap());
    configs.wireguard_endpoints[1].peers[0].endpoint = Some("localhost:51820".into());
    let prepared = Prepared::new(&mut configs).await.unwrap();
    assert!(prepared.endpoints[1].peers[0].endpoint.unwrap().is_ipv4());
    configs.wireguard_endpoints[1].peers[0].endpoint = Some("[::1]:51820".into());
    assert!(configs.wireguard_endpoints[1].validate().is_err());
}

#[tokio::test]
async fn wireguard_references_share_a_connector_and_are_not_direct() {
    let mut configs = validate(&format!("{}\n- address: '0.0.0.0:1080'\n  protocol: {{type: socks}}\n  rules:\n    - masks: '0.0.0.0/0'\n      action: allow\n      client_chain:\n        - protocol: {{type: wireguard, endpoint: client}}\n",pair_config(10001))).unwrap();
    configs.configs.push(configs.configs[0].clone());
    let prepared = Prepared::new(&mut configs).await.unwrap();
    let expected: Arc<dyn SocketConnector> = prepared.endpoints[1].connector.clone();
    let mut first = None;
    let mut references = 0;
    configs
        .visit_clients(&mut |client| {
            if let ClientProxyConfig::Wireguard(reference) = &client.protocol {
                assert!(Arc::ptr_eq(
                    reference.connector.as_ref().unwrap(),
                    &expected
                ));
                references += 1;
                first = reference.connector.clone();
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(references, 2);
    let connector = first.unwrap();
    let chain = crate::client_proxy_chain::ClientProxyChain::new(
        vec![crate::client_proxy_chain::InitialHopEntry::Wireguard(
            connector,
        )],
        vec![],
    );
    assert!(!chain.is_direct_only());
}

#[test]
fn wireguard_validation_rejects_unsafe_or_ambiguous_configs() {
    let base = pair_config(10001);
    for invalid in [
        base.replace("  listen:", "  mtu: 9000\n  listen:"),
        base.replace("wireguard: client", "wireguard: server"),
        base.replace("['10.77.0.1/32', 'fd77::1/128']", "[]"),
        base.replace(
            "allowed_ips: ['10.77.0.2/32', 'fd77::2/128']",
            "allowed_ips: []",
        ),
        base.replace(
            "  inbound:\n    rules:\n      - masks: ['0.0.0.0/0', '::/0']\n        action: allow",
            "  inbound: {rules: []}",
        ),
        base.replace(
            &format!("public_key: '{}'", public(42)),
            &format!("public_key: '{}'", public(41)),
        ),
        format!(
            "{base}\n- address: '0.0.0.0:1080'\n  protocol: {{type: socks}}\n  rules:\n    - masks: '0.0.0.0/0'\n      client_chain:\n        - protocol: {{type: wireguard, endpoint: missing}}\n"
        ),
    ] {
        assert!(
            validate(&invalid).is_err(),
            "accepted invalid WireGuard config"
        );
    }
    let roundtrip =
        serde_yaml::to_string(&serde_yaml::from_str::<Vec<crate::config::Config>>(&base).unwrap())
            .unwrap();
    validate(&roundtrip).unwrap();
    assert!(
        !format!(
            "{:?}",
            serde_yaml::from_str::<Vec<crate::config::Config>>(&base).unwrap()
        )
        .contains(&key(41))
    );
}

#[test]
fn wireguard_dns_and_chain_constraints() {
    let base = pair_config(10001);
    let dns = |url: &str, extra: &str| {
        format!(
            "{base}\n- dns_group: tunnel\n  dns_servers:\n    - url: '{url}'\n      client_chain:\n        - protocol: {{type: wireguard, endpoint: client}}\n      {extra}\n"
        )
    };
    for url in [
        "tcp://1.1.1.1",
        "tls://1.1.1.1",
        "https://1.1.1.1/dns-query",
    ] {
        validate(&dns(url, "server_name: dns.example")).unwrap();
    }
    for url in [
        "udp://1.1.1.1",
        "h3://1.1.1.1/dns-query",
        "https://dns.example/dns-query",
    ] {
        assert!(validate(&dns(url, "")).is_err(), "accepted {url}");
    }
    assert!(validate(&dns("tcp://1.1.1.1", "bootstrap_url: udp://8.8.8.8")).is_err());
    assert!(validate(&format!("{}\n- dns_group: dependent\n  dns_servers:\n    - url: https://dns.example/dns-query\n      bootstrap_url: tunnel\n", dns("tcp://1.1.1.1", ""))).is_err());
    let rule = |chain: &str| {
        format!(
            "{base}\n- address: '0.0.0.0:1080'\n  protocol: {{type: socks}}\n  rules:\n    - masks: '0.0.0.0/0'\n      action: allow\n      client_chain: {chain}\n"
        )
    };
    for chain in [
        "[{protocol: {type: socks}, address: '127.0.0.1:1081'}, {protocol: {type: wireguard, endpoint: client}}]",
        "[{protocol: {type: tls, protocol: {type: wireguard, endpoint: client}}}]",
        "[{protocol: {type: wireguard, endpoint: client}, transport: quic}]",
        "[{protocol: {type: wireguard, endpoint: client}, address: '127.0.0.1:9'}]",
        "[{protocol: {type: wireguard, endpoint: client}, bind_interface: lo}]",
    ] {
        assert!(validate(&rule(chain)).is_err(), "accepted {chain}");
    }
    assert!(validate(&base.replace("  listen:", "  unknown: true\n  listen:")).is_err());
    assert!(validate(&base.replace("10.77.0.1/32", "invalid CIDR")).is_err());
    for example in [
        include_str!("../../examples/wireguard_client.yaml"),
        include_str!("../../examples/wireguard_server.yaml"),
    ] {
        validate(example).unwrap();
    }
}

#[test]
fn wireguard_rejects_duplicate_peers_and_cross_peer_route_overlaps() {
    let configs = validate(&pair_config(10001)).unwrap();
    let mut server = configs.wireguard_endpoints[0].clone();
    server.peers.push(server.peers[0].clone());
    assert!(server.validate().is_err());
    server.peers[1].public_key = serde_yaml::from_str(&public(44)).unwrap();
    assert!(server.validate().is_err());
    server.peers[1].allowed_ips = vec!["10.77.0.0/24".into()];
    assert!(server.validate().is_err());
    server.peers[1].allowed_ips = vec!["10.77.0.3/32".into()];
    server.validate().unwrap();
}

#[tokio::test]
async fn wireguard_inbound_loads_client_certificate_paths_before_validation() {
    let directory = tempfile::tempdir().unwrap();
    let cert_path = directory.path().join("client.crt");
    let key_path = directory.path().join("client.key");
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
    let mut config: serde_json::Value = serde_yaml::from_str(&pair_config(10001)).unwrap();
    config[0]["inbound"]["rules"][0]["client_chain"] = serde_json::json!([{
        "address":"127.0.0.1:443", "protocol": {"type":"tls", "cert":cert_path, "key":key_path, "protocol":{"type":"socks"}}
    }]);
    let configs = serde_yaml::from_str(&serde_yaml::to_string(&config).unwrap()).unwrap();
    let (configs, count) = crate::config::convert_cert_paths(configs).await.unwrap();
    assert_eq!(count, 2);
    crate::config::create_server_configs(configs).unwrap();
}

#[tokio::test]
async fn wireguard_replay_corruption_and_authenticated_endpoint_roaming() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let reservation = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        let front = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let front_port = front.local_addr().unwrap().port();
        let mut back = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let (rebind, mut commands) =
            tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<()>>(1);
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let mut outbound = [0; 65536];
            let mut inbound = [0; 65536];
            let mut client = None;
            loop {
                tokio::select! {
                    packet = front.recv_from(&mut outbound) => {
                        let (len, source) = packet.unwrap(); client = Some(source);
                        back.send_to(&outbound[..len], ("127.0.0.1",port)).await.unwrap();
                        if outbound.first() == Some(&4) && len > 32 {
                            back.send_to(&outbound[..len], ("127.0.0.1",port)).await.unwrap();
                            outbound[len-1] ^= 0x80;
                            back.send_to(&outbound[..len], ("127.0.0.1",port)).await.unwrap();
                        }
                    }
                    packet = back.recv(&mut inbound) => {
                        let len = packet.unwrap();
                        front.send_to(&inbound[..len],client.unwrap()).await.unwrap();
                    }
                    Some(done) = commands.recv() => {
                        back = UdpSocket::bind("0.0.0.0:0").await.unwrap();
                        done.send(()).unwrap();
                    }
                }
            }
        });
        let mut configs = validate(&pair_config(port)).unwrap();
        configs.wireguard_endpoints[1].peers[0].endpoint = Some(format!("127.0.0.1:{front_port}"));
        for config in &mut configs.wireguard_endpoints {
            config.peers[0].pre_shared_key = None;
        }
        let prepared = Prepared::new(&mut configs).await.unwrap();
        drop(reservation);
        let mut running = Running::default();
        prepared
            .start(&mut DnsRegistry::new(), &mut running)
            .await
            .unwrap();
        let target = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let target_addr = SocketAddr::new(
            "127.0.0.1".parse().unwrap(),
            target.local_addr().unwrap().port(),
        );
        let mut stream = prepared.endpoints[1]
            .connector
            .handle()
            .unwrap()
            .open_udp(target_addr)
            .await
            .unwrap();
        for expected in [b"before roaming", b"after  roaming"] {
            futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, expected))
                .await
                .unwrap();
            let mut data = [0; 64];
            let (len, source) = target.recv_from(&mut data).await.unwrap();
            assert_eq!(&data[..len], expected);
            target.send_to(&data[..len], source).await.unwrap();
            let mut buf = ReadBuf::new(&mut data);
            futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_read_message(cx, &mut buf))
                .await
                .unwrap();
            assert_eq!(buf.filled(), expected);
            assert!(
                tokio::time::timeout(Duration::from_millis(100), target.recv(&mut data))
                    .await
                    .is_err(),
                "replay was forwarded"
            );
            let (done, ack) = tokio::sync::oneshot::channel();
            rebind.send(done).await.unwrap();
            ack.await.unwrap();
        }
        running.stop().await;
    })
    .await
    .unwrap();
}

#[cfg(feature = "ffi")]
#[tokio::test]
async fn wireguard_outer_socket_protection_failure_prevents_binding() {
    const NAME: &str =
        "wireguard::tests::wireguard_outer_socket_protection_failure_prevents_binding";
    if std::env::var_os("SHOES_WIREGUARD_PROTECTION_TEST").is_none() {
        assert!(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", NAME])
                .env("SHOES_WIREGUARD_PROTECTION_TEST", "1")
                .status()
                .unwrap()
                .success()
        );
        return;
    }
    crate::tun::set_global_socket_protector(Arc::new(crate::tun::FnSocketProtector::new(|_| {
        Err(stdio::ErrorKind::PermissionDenied.into())
    })));
    let reservation = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let port = reservation.local_addr().unwrap().port();
    let mut configs = validate(&pair_config(port)).unwrap();
    let prepared = Prepared::new(&mut configs).await.unwrap();
    drop(reservation);
    let mut running = Running::default();
    assert_eq!(
        prepared
            .start(&mut DnsRegistry::new(), &mut running)
            .await
            .unwrap_err()
            .kind(),
        stdio::ErrorKind::PermissionDenied
    );
    running.stop().await;
    assert!(prepared.endpoints[0].connector.handle().is_err());
    std::net::UdpSocket::bind(("0.0.0.0", port)).unwrap();
}

#[tokio::test]
async fn wireguard_rejects_wrong_psk_spoofed_sources_and_unsolicited_flows() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for failure in ["psk", "source", "inbound"] {
            let reservation = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
            let port = reservation.local_addr().unwrap().port();
            let mut configs = validate(&pair_config(port)).unwrap();
            match failure {
                "psk" => {
                    configs.wireguard_endpoints[1].peers[0].pre_shared_key =
                        Some(crate::config::wireguard::WireguardKey([44; 32]))
                }
                "source" => configs.wireguard_endpoints[1].addresses = vec!["10.77.0.99/32".into()],
                "inbound" => configs.wireguard_endpoints[0].inbound = None,
                _ => unreachable!(),
            }
            let prepared = Prepared::new(&mut configs).await.unwrap();
            drop(reservation);
            let mut running = Running::default();
            prepared
                .start(&mut DnsRegistry::new(), &mut running)
                .await
                .unwrap();
            let target = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            let address = SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                target.local_addr().unwrap().port(),
            );
            let mut stream = prepared.endpoints[1]
                .connector
                .handle()
                .unwrap()
                .open_udp(address)
                .await
                .unwrap();
            for _ in 0..3 {
                futures::future::poll_fn(|cx| {
                    Pin::new(&mut stream).poll_write_message(cx, b"must not arrive")
                })
                .await
                .unwrap();
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(300), target.recv(&mut [0; 64]))
                    .await
                    .is_err(),
                "forwarded {failure}"
            );
            running.stop().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn wireguard_multiple_peers_share_a_bind_without_cross_delivering_replies() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let reservation = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        let mut configs = validate(&pair_config(port)).unwrap();
        let mut peer = configs.wireguard_endpoints[0].peers[0].clone();
        peer.public_key = serde_yaml::from_str(&public(44)).unwrap();
        peer.allowed_ips = vec!["10.77.0.3/32".into(), "fd77::3/128".into()];
        configs.wireguard_endpoints[0].peers.push(peer);
        let mut client = configs.wireguard_endpoints[1].clone();
        client.wireguard = "second-client".into();
        client.private_key = crate::config::wireguard::WireguardKey([44; 32]);
        client.addresses = vec!["10.77.0.3/32".into(), "fd77::3/128".into()];
        configs.wireguard_endpoints.push(client);
        let prepared = Prepared::new(&mut configs).await.unwrap();
        drop(reservation);
        let mut running = Running::default();
        prepared
            .start(&mut DnsRegistry::new(), &mut running)
            .await
            .unwrap();
        for v6 in [false, true] {
            let (tcp, udp, _echoes) = echo_servers(v6).await;
            tokio::join!(
                check_echo(prepared.endpoints[1].connector.as_ref(), tcp, udp),
                check_echo(prepared.endpoints[2].connector.as_ref(), tcp, udp)
            );
        }
        running.stop().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn wireguard_dns_tcp_dot_doh_use_the_tunnel_and_fail_closed_after_stop() {
    use crate::client_proxy_chain::{ClientChainGroup, ClientProxyChain, InitialHopEntry};
    use hickory_resolver::{
        config::{ConnectionConfig, NameServerConfig, ResolverConfig},
        net::runtime::RuntimeProvider,
        proto::{
            op::{Message, MessageType},
            rr::{RData, Record, rdata::A},
        },
    };
    trait TestIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
    impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> TestIo for T {}
    fn answer(bytes: &[u8]) -> Vec<u8> {
        let mut response = Message::from_vec(bytes).unwrap();
        response.metadata.message_type = MessageType::Response;
        response.add_answer(Record::from_rdata(
            response.queries[0].name().clone(),
            0,
            RData::A(A::new(192, 0, 2, 42)),
        ));
        response.to_vec().unwrap()
    }
    tokio::time::timeout(Duration::from_secs(20), async {
        let reservation = std::net::UdpSocket::bind("[::]:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        let yaml = pair_config(port)
            .replace(&format!("0.0.0.0:{port}"), &format!("[::]:{port}"))
            .replace(&format!("127.0.0.1:{port}"), &format!("[::1]:{port}"));
        let mut configs = validate(&yaml).unwrap();
        let prepared = Prepared::new(&mut configs).await.unwrap();
        drop(reservation);
        let mut dns = DnsRegistry::new();
        let mut running = Running::default();
        prepared.start(&mut dns, &mut running).await.unwrap();
        let provider = crate::dns::ProxyRuntimeProvider::with_bootstrap(
            Arc::new(ClientChainGroup::new(vec![ClientProxyChain::new(
                vec![InitialHopEntry::Wireguard(
                    prepared.endpoints[1].connector.clone(),
                )],
                vec![],
            )])),
            Arc::new(NativeResolver::new()),
            Duration::from_secs(2),
        );
        assert!(
            provider
                .bind_udp(
                    "0.0.0.0:0".parse().unwrap(),
                    "127.0.0.1:53".parse().unwrap()
                )
                .await
                .is_err()
        );
        assert!(provider.quic_binder().is_none());
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
                    .into(),
            )
            .unwrap();
        server_tls.alpn_protocols = vec![b"h2".to_vec(), b"dot".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));
        let mut servers = JoinSet::new();
        let mut resolvers = Vec::new();
        for mode in 0..3 {
            let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let acceptor = acceptor.clone();
            servers.spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream: Box<dyn TestIo> = if mode == 0 {
                    Box::new(stream)
                } else {
                    Box::new(acceptor.accept(stream).await.unwrap())
                };
                if mode == 2 {
                    let mut connection = h2::server::handshake(stream).await.unwrap();
                    let (request, mut response) = connection.accept().await.unwrap().unwrap();
                    assert_eq!(request.uri().path(), "/dns-query");
                    let mut body = request.into_body();
                    let respond = async move {
                        let mut query = Vec::new();
                        while let Some(data) = body.data().await {
                            let data = data.unwrap();
                            body.flow_control().release_capacity(data.len()).unwrap();
                            query.extend_from_slice(&data);
                        }
                        let bytes = answer(&query);
                        let mut send = response
                            .send_response(
                                http::Response::builder()
                                    .header("content-type", "application/dns-message")
                                    .header("content-length", bytes.len())
                                    .body(())
                                    .unwrap(),
                                false,
                            )
                            .unwrap();
                        send.send_data(bytes.into(), true).unwrap();
                        std::future::pending::<()>().await;
                    };
                    tokio::select! { _ = respond => {}, _ = connection.accept() => {} }
                } else {
                    let length = stream.read_u16().await.unwrap() as usize;
                    let mut query = vec![0; length];
                    stream.read_exact(&mut query).await.unwrap();
                    let bytes = answer(&query);
                    stream.write_u16(bytes.len() as u16).await.unwrap();
                    stream.write_all(&bytes).await.unwrap();
                    stream.flush().await.unwrap();
                    std::future::pending::<()>().await;
                }
            });
            let mut connection = match mode {
                0 => ConnectionConfig::tcp(),
                1 => ConnectionConfig::tls("localhost".into()),
                _ => ConnectionConfig::https("localhost".into(), Some("/dns-query".into())),
            };
            connection.port = port;
            let config = ResolverConfig::from_parts(
                None,
                vec![],
                vec![NameServerConfig::new(
                    "127.0.0.1".parse().unwrap(),
                    true,
                    vec![connection],
                )],
            );
            let tls = rustls::ClientConfig::builder()
                .with_root_certificates(roots.clone())
                .with_no_client_auth();
            let resolver =
                hickory_resolver::Resolver::builder_with_config(config, provider.clone())
                    .with_tls_config(tls)
                    .build()
                    .unwrap();
            let result = resolver.ipv4_lookup("wireguard.test.").await.unwrap();
            assert_eq!(result.answers()[0].data, RData::A(A::new(192, 0, 2, 42)));
            resolvers.push(resolver);
        }
        running.stop().await;
        for resolver in resolvers {
            assert!(resolver.ipv4_lookup("after-stop.test.").await.is_err());
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn wireguard_dns_registry_prepares_inactive_generation_handles() {
    use hickory_resolver::proto::{
        op::{Message, MessageType},
        rr::{RData, Record, rdata::A},
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        let reservation = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let dns_port = listener.local_addr().unwrap().port();
        let yaml = format!("{}\n- dns_group: tunnel\n  dns_servers:\n    - url: tcp://127.0.0.1:{dns_port}\n      ip_strategy: ipv4_only\n      client_chain:\n        - protocol: {{type: wireguard, endpoint: client}}\n", pair_config(port));
        let mut configs = validate(&yaml).unwrap();
        let prepared = Prepared::new(&mut configs).await.unwrap();
        let mut dns = crate::dns::build_dns_registry(configs.dns_groups.clone()).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(20), listener.accept()).await.is_err());
        let mut servers = JoinSet::new();
        servers.spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let length = stream.read_u16().await.unwrap() as usize;
                let mut bytes = vec![0;length];
                stream.read_exact(&mut bytes).await.unwrap();
                let mut reply = Message::from_vec(&bytes).unwrap();
                reply.metadata.message_type = MessageType::Response;
                reply.add_answer(Record::from_rdata(reply.queries[0].name().clone(), 0, RData::A(A::new(192,0,2,42))));
                let bytes = reply.to_vec().unwrap();
                stream.write_u16(bytes.len() as u16).await.unwrap();
                stream.write_all(&bytes).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        drop(reservation);
        let mut running = Running::default();
        prepared.start(&mut dns, &mut running).await.unwrap();
        for registry in [dns, crate::dns::build_dns_registry(configs.dns_groups.clone()).await.unwrap()] {
            let resolver = registry.get_by_name("tunnel").unwrap();
            let answer = resolver.resolve_location(&NetLocation::from_str("registry.test:443", None).unwrap()).await.unwrap();
            assert_eq!(answer[0], "192.0.2.42:443".parse().unwrap());
        }
        running.stop().await;
        let dns = crate::dns::build_dns_registry(configs.dns_groups).await.unwrap();
        assert!(dns.get_by_name("tunnel").unwrap().resolve_location(&NetLocation::from_str("after-stop.test:443",None).unwrap()).await.is_err());
    }).await.unwrap();
}
