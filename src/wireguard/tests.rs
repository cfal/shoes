use super::test_support as config;
use super::*;
use crate::async_stream::{AsyncReadMessage, AsyncWriteMessage};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{pin::Pin, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadBuf},
    net::{TcpListener, UdpSocket},
};

const CLIENT: usize = 0;
const SERVER: usize = 1;

fn key(byte: u8) -> String {
    STANDARD.encode([byte; 32])
}
fn public(byte: u8) -> String {
    STANDARD.encode(PublicKey::from(&StaticSecret::from([byte; 32])).as_bytes())
}

fn pair_config(port: u16) -> String {
    use serde_json::json;
    let mut server = config::server(port);
    server["rules"] = json!([{"masks": ["0.0.0.0/0", "::/0"], "action": "allow"}]);
    let mut client = config::client(port);
    client["client_group"] = json!("client");
    let mut socks = config::socks(0);
    socks["rules"][0]["client_chain"] = json!("client");
    serde_yaml::to_string(&json!([server, client, socks])).unwrap()
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
        loop {
            tokio::select! {
                connection = listener.accept() => {
                    let (mut stream, _) = connection.unwrap();
                    flows.spawn(async move {
                        let (mut read, mut write) = stream.split();
                        let _ = tokio::io::copy(&mut read, &mut write).await;
                    });
                }
                _ = flows.join_next(), if !flows.is_empty() => {}
            }
        }
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
        futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, &[0; 1408]))
            .await
            .unwrap();
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
}

async fn start_prepared(prepared: &Prepared) -> Running {
    let mut running = Running::default();
    prepared
        .start(&mut DnsRegistry::new(), &mut running)
        .await
        .unwrap();
    running
}

fn dns_answer(bytes: &[u8]) -> Vec<u8> {
    use hickory_resolver::proto::{
        op::{Message, MessageType},
        rr::{RData, Record, rdata::A},
    };
    let mut response = Message::from_vec(bytes).unwrap();
    response.metadata.message_type = MessageType::Response;
    response.add_answer(Record::from_rdata(
        response.queries[0].name().clone(),
        0,
        RData::A(A::new(192, 0, 2, 42)),
    ));
    response.to_vec().unwrap()
}

#[test]
fn canonical_socket_addresses_preserve_native_ipv6_metadata() {
    for text in [
        "127.0.0.1:443",
        "[::]:443",
        "[::192.0.2.1]:443",
        "[fe80::1%3]:443",
    ] {
        let address: SocketAddr = text.parse().unwrap();
        assert_eq!(canonical_socket_addr(address), address);
    }
    let scoped = SocketAddr::V6(std::net::SocketAddrV6::new(
        "fe80::1".parse().unwrap(),
        443,
        123,
        3,
    ));
    assert_eq!(canonical_socket_addr(scoped), scoped);
    assert_eq!(
        canonical_socket_addr("[::ffff:192.0.2.1]:443".parse().unwrap()),
        "192.0.2.1:443".parse().unwrap(),
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
        let connector = prepared.endpoints[CLIENT].connector.clone();
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
async fn wireguard_mapped_ipv4_destinations_use_the_ipv4_tunnel() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let reservation = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let mut configs = validate(&pair_config(reservation.local_addr().unwrap().port())).unwrap();
        configs.wireguard_endpoints[CLIENT].addresses = vec!["10.77.0.2/32".into()];
        configs.wireguard_endpoints[CLIENT].peers[0].allowed_ips = vec!["0.0.0.0/0".into()];
        let prepared = Prepared::new(&mut configs).await.unwrap();
        drop(reservation);
        let mut running = start_prepared(&prepared).await;
        let (tcp, udp, _echoes) = echo_servers(false).await;
        let mapped = |address: SocketAddr| {
            SocketAddr::new("::ffff:127.0.0.1".parse().unwrap(), address.port())
        };
        check_echo(
            prepared.endpoints[CLIENT].connector.as_ref(),
            mapped(tcp),
            mapped(udp),
        )
        .await;
        running.stop().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn wireguard_fake_dns_restores_tcp_and_udp_in_both_families() {
    use hickory_resolver::proto::{
        op::{Message, Query},
        rr::{Name, RData, RecordType},
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        let reservation = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let mut documents: Vec<serde_yaml::Value> =
            serde_yaml::from_str(&pair_config(reservation.local_addr().unwrap().port())).unwrap();
        let inbound: serde_yaml::Value = serde_yaml::from_str(
            r#"
dns:
  servers: udp://127.0.0.1:9
  fake_ip:
    ipv6_range: fd18::/64
rules:
  - mask: wireguard.example
    action: allow
    override_address: '127.0.0.1:0'
  - masks: ['0.0.0.0/0', '::/0']
    action: block
"#,
        )
        .unwrap();
        documents[0]["dns"] = inbound["dns"].clone();
        documents[0]["rules"] = inbound["rules"].clone();
        let mut configs = validate(&serde_yaml::to_string(&documents).unwrap()).unwrap();
        let prepared = Prepared::new(&mut configs).await.unwrap();
        let mut dns = crate::dns::build_dns_registry(configs.dns_groups.clone())
            .await
            .unwrap();
        drop(reservation);
        let mut running = Running::default();
        prepared.start(&mut dns, &mut running).await.unwrap();
        let connector = prepared.endpoints[CLIENT].connector.as_ref();
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let (tcp, udp, _echoes) = echo_servers(false).await;
        for (target, kind) in [
            ("198.18.0.1:53", RecordType::A),
            ("[fd18::1]:53", RecordType::AAAA),
        ] {
            let location = NetLocation::from_str(target, None).unwrap().into();
            let mut query = Message::query();
            query.metadata.id = 73;
            query.add_query(Query::query(
                Name::from_ascii("wireguard.example.").unwrap(),
                kind,
            ));
            let query = query.to_vec().unwrap();
            let response = if kind == RecordType::A {
                let mut stream = connector
                    .connect_udp_bidirectional(&resolver, location)
                    .await
                    .unwrap();
                futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, &query))
                    .await
                    .unwrap();
                let mut bytes = [0; 512];
                let mut buf = ReadBuf::new(&mut bytes);
                futures::future::poll_fn(|cx| {
                    Pin::new(&mut stream).poll_read_message(cx, &mut buf)
                })
                .await
                .unwrap();
                Message::from_vec(buf.filled()).unwrap()
            } else {
                let mut stream = connector.connect(&resolver, &location).await.unwrap();
                stream.write_u16(query.len() as u16).await.unwrap();
                stream.write_all(&query).await.unwrap();
                let length = stream.read_u16().await.unwrap();
                let mut bytes = vec![0; length as usize];
                stream.read_exact(&mut bytes).await.unwrap();
                Message::from_vec(&bytes).unwrap()
            };
            assert_eq!(response.metadata.id, 73);
            let ip = match response.answers[0].data {
                RData::A(ip) => IpAddr::V4(ip.0),
                RData::AAAA(ip) => IpAddr::V6(ip.0),
                _ => panic!("missing synthetic address"),
            };
            check_echo(
                connector,
                SocketAddr::new(ip, tcp.port()),
                SocketAddr::new(ip, udp.port()),
            )
            .await;
        }
        running.stop().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn wireguard_config_sniffs_literal_and_restored_targets_without_rewriting() {
    use hickory_resolver::proto::{
        op::{Message, Query},
        rr::{Name, RData, RecordType},
    };
    use serde_json::json;
    tokio::time::timeout(Duration::from_secs(15), async {
        let reservation = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let exit = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let mut documents: Vec<serde_json::Value> = serde_yaml::from_str(&pair_config(reservation.local_addr().unwrap().port())).unwrap();
        documents[0]["sniff"] = json!(true);
        documents[0]["dns"] = json!({"servers":"udp://127.0.0.1:9", "fake_ip":true});
        documents[0]["rules"] = json!([{"mask":"sniff.example", "client_chain":"exit"}]);
        documents.push(json!({"client_group":"exit", "client_proxies":[{
            "address":format!("127.0.0.1:{}", exit.local_addr().unwrap().port()), "protocol":{"type":"socks"}
        }]}));
        let mut configs = validate(&serde_yaml::to_string(&documents).unwrap()).unwrap();
        let prepared = Prepared::new(&mut configs).await.unwrap();
        let mut dns = crate::dns::build_dns_registry(configs.dns_groups.clone()).await.unwrap();
        drop(reservation);
        let mut running = Running::default();
        prepared.start(&mut dns, &mut running).await.unwrap();
        let connector = prepared.endpoints[CLIENT].connector.as_ref();
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let mut query = Message::query();
        query.metadata.id = 93;
        query.add_query(Query::query(Name::from_ascii("restored.example.").unwrap(), RecordType::A));
        let mut stream = connector.connect(&resolver, &NetLocation::from_str("198.18.0.1:53", None).unwrap().into()).await.unwrap();
        let query = query.to_vec().unwrap();
        stream.write_u16(query.len() as u16).await.unwrap();
        stream.write_all(&query).await.unwrap();
        let len = stream.read_u16().await.unwrap();
        let mut response = vec![0; len as usize];
        stream.read_exact(&mut response).await.unwrap();
        let response = Message::from_vec(&response).unwrap();
        assert_eq!(response.metadata.id, 93);
        let RData::A(ip) = response.answers[0].data else { panic!("missing synthetic address") };
        drop(stream);
        for (target, expected) in [
            (NetLocation::from_str("192.0.2.9:443", None).unwrap(), NetLocation::from_str("192.0.2.9:443", None).unwrap()),
            (NetLocation::from_ip_addr(ip.0.into(), 443), NetLocation::from_str("restored.example:443", None).unwrap()),
        ] {
            for payload in [
                crate::sniff::tests::hello(&rustls::version::TLS13, true),
                crate::sniff::tests::http_request(),
            ] {
                let upstream = async {
                    let (mut stream, _) = exit.accept().await.unwrap();
                    let mut greeting = [0; 3];
                    stream.read_exact(&mut greeting).await.unwrap();
                    assert_eq!(greeting, [5, 1, 0]);
                    stream.write_all(&[5, 0]).await.unwrap();
                    stream.read_exact(&mut greeting).await.unwrap();
                    assert_eq!(greeting, [5, 1, 0]);
                    assert_eq!(crate::socks_handler::read_location_direct(&mut stream).await.unwrap(), expected);
                    stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                    let mut bytes = vec![0; payload.len()];
                    stream.read_exact(&mut bytes).await.unwrap();
                    assert_eq!(bytes, payload);
                    stream.write_all(b"sniffed").await.unwrap();
                };
                let client = async {
                    let mut stream = connector.connect(&resolver, &target.clone().into()).await.unwrap();
                    stream.write_all(&payload).await.unwrap();
                    let mut response = [0; 7];
                    stream.read_exact(&mut response).await.unwrap();
                    assert_eq!(&response, b"sniffed");
                };
                tokio::join!(upstream, client);
            }
        }
        running.stop().await;
    }).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wireguard_concurrent_tcp_transfers_preserve_all_data() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let reservation = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let mut configs = validate(&pair_config(reservation.local_addr().unwrap().port())).unwrap();
        let prepared = Prepared::new(&mut configs).await.unwrap();
        drop(reservation);
        let mut running = start_prepared(&prepared).await;
        let (tcp, _, _echoes) = echo_servers(false).await;
        let mut flows = JoinSet::new();
        for id in 0..16u8 {
            let connector = prepared.endpoints[CLIENT].connector.clone();
            flows.spawn(async move {
                let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
                let target = NetLocation::from_ip_addr(tcp.ip(), tcp.port()).into();
                let stream = connector.connect(&resolver, &target).await.unwrap();
                let (mut read, mut write) = tokio::io::split(stream);
                let payload = vec![id; 256 * 1024];
                let mut response = vec![0; payload.len()];
                let send = async {
                    write.write_all(&payload).await.unwrap();
                    write.shutdown().await.unwrap();
                };
                let receive = async {
                    read.read_exact(&mut response).await.unwrap();
                };
                tokio::join!(send, receive);
                assert_eq!(response, payload);
            });
        }
        while let Some(result) = flows.join_next().await {
            result.unwrap();
        }
        running.stop().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn wireguard_mapped_ipv4_outer_endpoint_uses_ipv4_transport() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for listen in [
            None,
            Some("0.0.0.0:0"),
            Some("[::]:0"),
            Some("[::ffff:127.0.0.1]:0"),
        ] {
            let reservation = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
            let port = reservation.local_addr().unwrap().port();
            let mut configs = validate(&pair_config(port)).unwrap();
            let client = &mut configs.wireguard_endpoints[CLIENT];
            client.listen = listen.map(|address| address.parse().unwrap());
            client.peers[0].endpoint = Some(format!("[::ffff:127.0.0.1]:{port}"));
            let prepared = Prepared::new(&mut configs).await.unwrap();
            assert_eq!(
                prepared.endpoints[CLIENT].peers[0].endpoints,
                vec![SocketAddr::from(([127, 0, 0, 1], port))]
            );
            drop(reservation);
            let mut running = start_prepared(&prepared).await;
            let (tcp, udp, _echoes) = echo_servers(false).await;
            check_echo(prepared.endpoints[CLIENT].connector.as_ref(), tcp, udp).await;
            running.stop().await;
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
        configs.wireguard_endpoints[SERVER].listen = Some(format!("[::]:{port}").parse().unwrap());
        configs.wireguard_endpoints[CLIENT].peers[0].endpoint = Some(format!("[::1]:{port}"));
        let prepared = Prepared::new(&mut configs).await.unwrap();
        drop(reservation);
        let mut running = start_prepared(&prepared).await;
        for v6 in [false, true] {
            let (tcp, udp, _echoes) = echo_servers(v6).await;
            check_echo(prepared.endpoints[CLIENT].connector.as_ref(), tcp, udp).await;
        }
        running.stop().await;
        std::net::UdpSocket::bind(("::", port)).unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn wireguard_dual_stack_connect_falls_back_without_waiting_for_blackholed_ipv6() {
    #[derive(Debug)]
    struct DualStackResolver(Vec<SocketAddr>);
    impl Resolver for DualStackResolver {
        fn resolve_location(
            &self,
            _: &NetLocation,
        ) -> Pin<Box<dyn std::future::Future<Output = stdio::Result<Vec<SocketAddr>>> + Send>>
        {
            let addresses = self.0.clone();
            Box::pin(async move { Ok(addresses) })
        }
    }

    tokio::time::timeout(Duration::from_secs(5), async {
        let reservation = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let mut configs = validate(&pair_config(reservation.local_addr().unwrap().port())).unwrap();
        // Authenticated IPv6 packets are dropped by the remote peer's allowed_ips check.
        configs.wireguard_endpoints[SERVER].peers[0].allowed_ips = vec!["10.77.0.2/32".into()];
        let prepared = Prepared::new(&mut configs).await.unwrap();
        drop(reservation);
        let mut running = start_prepared(&prepared).await;
        let (tcp, _, _echoes) = echo_servers(false).await;
        let resolver: Arc<dyn Resolver> = Arc::new(DualStackResolver(vec![
            SocketAddr::new("::1".parse().unwrap(), tcp.port()),
            tcp,
        ]));
        let target = NetLocation::from_str(&format!("dual.test:{}", tcp.port()), None)
            .unwrap()
            .into();
        let mut stream = prepared.endpoints[CLIENT]
            .connector
            .connect(&resolver, &target)
            .await
            .unwrap();
        stream.write_all(b"fallback").await.unwrap();
        let mut response = [0; 8];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"fallback");
        drop(stream);
        running.stop().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn wireguard_bind_selects_a_compatible_hostname_address() {
    let mut configs = validate(&pair_config(51820)).unwrap();
    configs.wireguard_endpoints[CLIENT].peers[0].endpoint = Some("localhost:51820".into());
    for listen in ["0.0.0.0:0", "[::1]:0"] {
        let listen: SocketAddr = listen.parse().unwrap();
        configs.wireguard_endpoints[CLIENT].listen = Some(listen);
        let prepared = Prepared::new(&mut configs).await.unwrap();
        for endpoint in &prepared.endpoints[CLIENT].peers[0].endpoints {
            assert_eq!(endpoint.is_ipv4(), listen.is_ipv4(), "listen: {listen}");
        }
    }
}

#[tokio::test]
async fn fake_dns_guards_wireguard_peer_and_outer_proxy_hostnames() {
    use serde_json::json;
    for tun_address in [None, Some("127.0.0.1"), Some("::ffff:127.0.0.1")] {
        let tun_endpoint = tun_address.is_some();
        let mut raw: serde_json::Value = serde_yaml::from_str(&pair_config(51820)).unwrap();
        raw[1]["client_proxies"][0]["address"] = json!("localhost:51820");
        raw.as_array_mut().unwrap().push(json!({
            "dns_group":"fake", "dns_servers":"system",
            "fake_ip":{"ipv4_range":if tun_endpoint { "198.18.0.0/15" } else { "127.0.0.0/8" }}
        }));
        if let Some(address) = tun_address {
            raw.as_array_mut()
                .unwrap()
                .push(json!({"device_name":"unused", "address":address}));
        }
        let mut configs = validate(&raw.to_string()).unwrap();
        assert_eq!(
            Prepared::new(&mut configs).await.err().unwrap().kind(),
            stdio::ErrorKind::InvalidData
        );

        raw[1]["client_proxies"][0]["address"] = json!("127.0.0.1:51820");
        assert!(validate(&raw.to_string()).is_err());

        raw[1]["client_proxies"][0]["address"] = json!("192.0.2.1:51820");
        raw[1]["client_proxies"][0]["protocol"]["peer_client_chain"] = json!([{
            "address":"localhost:443", "protocol":{"type":"vless", "user_id":"b85798ef-e9dc-46a4-9a87-8da4499d36d0"}
        }]);
        let mut configs = validate(&raw.to_string()).unwrap();
        let prepared = Prepared::new(&mut configs).await.unwrap();
        let endpoint = &prepared.endpoints[CLIENT];
        let chain = endpoint.build_outer_chain().unwrap().unwrap();
        let error = chain
            .connect_udp_bidirectional(
                &endpoint.outer_resolver,
                NetLocation::from_str("192.0.2.1:51820", None)
                    .unwrap()
                    .into(),
            )
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("synthetic address"), "{error}");

        raw[3]["fake_ip"] = false.into();
        raw[1]["client_proxies"][0]["address"] = json!("localhost:51820");
        let mut configs = validate(&raw.to_string()).unwrap();
        Prepared::new(&mut configs).await.unwrap();

        let inherited = [if tun_endpoint {
            "127.0.0.1/32"
        } else {
            "127.0.0.0/8"
        }
        .parse()
        .unwrap()];
        for remove_group in [false, true] {
            let mut candidate = raw.clone();
            if remove_group {
                candidate.as_array_mut().unwrap().remove(3);
            }
            let mut configs = validate(&candidate.to_string()).unwrap();
            assert_eq!(
                Prepared::with_forbidden(&mut configs, &inherited)
                    .await
                    .err()
                    .unwrap()
                    .kind(),
                stdio::ErrorKind::InvalidData
            );
            candidate[1]["client_proxies"][0]["address"] = json!("127.0.0.1:51820");
            let mut configs = validate(&candidate.to_string()).unwrap();
            assert_eq!(
                Prepared::with_forbidden(&mut configs, &inherited)
                    .await
                    .err()
                    .unwrap()
                    .kind(),
                stdio::ErrorKind::InvalidInput
            );
            candidate[1]["client_proxies"][0]["address"] = json!("192.0.2.1:51820");
            let mut configs = validate(&candidate.to_string()).unwrap();
            let prepared = Prepared::with_forbidden(&mut configs, &inherited)
                .await
                .unwrap();
            assert!(
                prepared.endpoints[CLIENT]
                    .outer_resolver
                    .resolve_location(&NetLocation::from_str("localhost:443", None).unwrap())
                    .await
                    .is_err()
            );
            candidate[1]["client_proxies"][0]["protocol"]["peer_client_chain"][0]["address"] =
                json!("127.0.0.1:443");
            let mut configs = validate(&candidate.to_string()).unwrap();
            assert_eq!(
                Prepared::with_forbidden(&mut configs, &inherited)
                    .await
                    .err()
                    .unwrap()
                    .kind(),
                stdio::ErrorKind::InvalidInput
            );
        }
    }
}

#[test]
fn fake_dns_rejects_unbracketed_wireguard_literals() {
    use serde_json::json;
    for endpoint in ["::ffff:198.18.0.5:51820", "2001:2::5:51820"] {
        let mut raw: serde_json::Value = serde_yaml::from_str(&pair_config(51820)).unwrap();
        raw[1]["client_proxies"][0]["address"] = json!(endpoint);
        raw.as_array_mut().unwrap().push(json!({
            "dns_group":"fake", "dns_servers":"system",
            "fake_ip":{"ipv6_range":"2001:2::/48"}
        }));
        let error = validate(&raw.to_string()).err().unwrap();
        assert_eq!(error.kind(), stdio::ErrorKind::InvalidInput);
        assert!(
            error.to_string().contains("WireGuard endpoint overlaps"),
            "{error}"
        );
        raw[3]["fake_ip"] = false.into();
        validate(&raw.to_string()).unwrap();
    }
}

#[tokio::test]
async fn wireguard_ipv4_fallback_selects_a_compatible_resolved_peer() {
    let mut configs = validate(&pair_config(51820)).unwrap();
    let mut prepared = Prepared::new(&mut configs).await.unwrap();
    let (udp, released, local) =
        io::Factory::new(Some("0.0.0.0:0".parse().unwrap()), None).unwrap();
    assert!(local.is_ipv4());
    let ipv6: SocketAddr = "[::1]:51820".parse().unwrap();
    let ipv4: SocketAddr = "127.0.0.1:51820".parse().unwrap();
    let client = &mut prepared.endpoints[CLIENT];
    assert!(client.config.listen.is_none());
    client.peers[0].endpoints = vec![ipv6, ipv4];
    assert_eq!(
        client.peers_for_socket(None).unwrap()[0].endpoint,
        Some(ipv6)
    );
    assert_eq!(
        client.peers_for_socket(Some(local)).unwrap()[0].endpoint,
        Some(ipv4)
    );
    assert_eq!(client.peers[0].endpoints, vec![ipv6, ipv4]);
    client.peers[0].endpoints = vec![ipv6];
    assert_eq!(
        client.peers_for_socket(Some(local)).unwrap_err().kind(),
        stdio::ErrorKind::AddrNotAvailable,
    );
    assert!(
        prepared.endpoints[SERVER]
            .peers_for_socket(Some(local))
            .unwrap()[0]
            .endpoint
            .is_none()
    );
    drop(udp);
    released.await.unwrap();
}

#[test]
fn wireguard_bind_validates_peer_address_families() {
    let mut configs = validate(&pair_config(51820)).unwrap();
    let client = &mut configs.wireguard_endpoints[CLIENT];
    for (listen, endpoint, compatible) in [
        ("0.0.0.0:0", "[::1]:51820", false),
        ("[::1]:0", "127.0.0.1:51820", false),
        ("[::1]:0", "[::ffff:127.0.0.1]:51820", false),
        ("[::ffff:127.0.0.1]:0", "[::ffff:127.0.0.1]:51820", true),
        ("[::ffff:127.0.0.1]:0", "[::1]:51820", false),
        ("[::]:0", "[::1]:51820", true),
        ("[::]:0", "127.0.0.1:51820", true),
    ] {
        client.listen = Some(listen.parse().unwrap());
        client.peers[0].endpoint = Some(endpoint.into());
        assert_eq!(
            client.validate().is_ok(),
            compatible,
            "listen: {listen}, endpoint: {endpoint}"
        );
    }
}

#[tokio::test]
async fn wireguard_copied_clients_share_a_connector_only_within_their_generation() {
    use serde_json::{Value, json};
    let mut raw: Value = serde_yaml::from_str(&pair_config(10001)).unwrap();
    let mut duplicate = raw[1].clone();
    duplicate["client_group"] = json!("copy");
    raw[2]["rules"][0]["client_chain"] = json!([{"pool": [
        "client", "copy", raw[1]["client_proxies"][0],
    ]}]);
    raw.as_array_mut().unwrap().push(duplicate);
    let mut configs = validate(&serde_yaml::to_string(&raw).unwrap()).unwrap();
    let prepared = Prepared::new(&mut configs).await.unwrap();
    assert_eq!(prepared.endpoints.len(), 2);
    let expected: Arc<dyn SocketConnector> = prepared.endpoints[CLIENT].connector.clone();
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
    assert_eq!(references, 3);
    let next = Prepared::new(&mut configs).await.unwrap();
    let next_connector: Arc<dyn SocketConnector> = next.endpoints[CLIENT].connector.clone();
    assert!(!Arc::ptr_eq(&expected, &next_connector));
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
    use serde_json::{Value, json};
    let base = pair_config(10001);
    for (pointer, value) in [
        ("/0/protocol/mtu", json!(9000)),
        ("/0/protocol/addresses", json!([])),
        ("/0/protocol/addresses", json!(["255.255.255.255/32"])),
        ("/0/protocol/addresses", json!(["::ffff:10.77.0.9/128"])),
        ("/0/protocol/peers/0/allowed_ips", json!([])),
        ("/0/protocol/peers/0/public_key", json!(public(41))),
        ("/0/rules", json!([])),
        ("/0/rules", Value::Null),
        ("/1/client_proxies/0/address", json!("127.0.0.1:0")),
        ("/1/client_proxies/0/protocol/addresses", json!([])),
        ("/1/client_proxies/0/protocol/allowed_ips", json!([])),
    ] {
        let mut invalid: Value = serde_yaml::from_str(&base).unwrap();
        if pointer.ends_with("/mtu") {
            invalid[0]["protocol"]["mtu"] = value;
        } else {
            *invalid.pointer_mut(pointer).unwrap() = value;
        }
        assert!(
            validate(&serde_yaml::to_string(&invalid).unwrap()).is_err(),
            "accepted invalid WireGuard config at {pointer}"
        );
    }
    let mut missing_rules: Value = serde_yaml::from_str(&base).unwrap();
    missing_rules[0].as_object_mut().unwrap().remove("rules");
    assert!(validate(&serde_yaml::to_string(&missing_rules).unwrap()).is_err());
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
fn wireguard_rejects_non_contributory_peer_keys() {
    let mut low_order = [0; 32];
    low_order[0] = 1;
    let mut minus_one = [0xff; 32];
    minus_one[0] = 0xec;
    minus_one[31] = 0x7f;
    for bytes in [[0; 32], low_order, minus_one] {
        let mut configs = validate(&pair_config(51820)).unwrap();
        let endpoint = &mut configs.wireguard_endpoints[CLIENT];
        endpoint.peers[0].public_key = crate::config::wireguard::WireguardKey(bytes);
        for psk in [Some(crate::config::wireguard::WireguardKey([7; 32])), None] {
            endpoint.peers[0].pre_shared_key = psk;
            let error = endpoint.validate().unwrap_err().to_string();
            assert!(error.contains("non-contributory"));
            assert!(!error.contains(&STANDARD.encode(bytes)));
        }
    }
}

#[test]
fn wireguard_dns_and_chain_constraints() {
    let base = pair_config(10001);
    let dns = |url: &str, extra: &str| {
        format!(
            "{base}\n- dns_group: tunnel\n  dns_servers:\n    - url: '{url}'\n      client_chain: client\n      {extra}\n"
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
    use serde_json::{Value, json};
    let mut raw: Value = serde_yaml::from_str(&base).unwrap();
    raw[2]["rules"][0]["client_chain"] = json!([
        {"address": "127.0.0.1:1081", "protocol": {"type": "socks"}}, "client",
    ]);
    let error = validate(&serde_yaml::to_string(&raw).unwrap())
        .err()
        .unwrap();
    assert!(error.to_string().contains("hop 0"));
    let client_protocol = raw[1]["client_proxies"][0]["protocol"].clone();
    raw[2]["rules"][0]["client_chain"] = json!([{
        "address": "127.0.0.1:443", "protocol": {"type": "tls", "protocol": client_protocol},
    }]);
    assert!(validate(&serde_yaml::to_string(&raw).unwrap()).is_err());
    assert!(validate(&base.replace("10.77.0.1/32", "invalid CIDR")).is_err());
    for example in [
        include_str!("../../examples/wireguard_client.yaml"),
        include_str!("../../examples/wireguard_server.yaml"),
        include_str!("../../examples/wireguard_outer_chain.yaml"),
        include_str!("../../examples/wireguard_proxied_server.yaml"),
    ] {
        validate(example).unwrap();
    }
}

#[test]
fn wireguard_rejects_duplicate_peers_and_cross_peer_route_overlaps() {
    let configs = validate(&pair_config(10001)).unwrap();
    let mut server = configs.wireguard_endpoints[SERVER].clone();
    server.peers.push(server.peers[0].clone());
    assert!(server.validate().is_err());
    server.peers[1].public_key = serde_yaml::from_str(&public(44)).unwrap();
    assert!(server.validate().is_err());
    server.peers[1].allowed_ips = vec!["10.77.0.0/24".into()];
    assert!(server.validate().is_err());
    server.peers[1].allowed_ips = vec!["10.77.0.3/32".into()];
    server.validate().unwrap();
}

#[test]
fn wireguard_outer_chain_validation_and_roundtrip() {
    use serde_json::json;
    let base: serde_json::Value = serde_yaml::from_str(&pair_config(51820)).unwrap();
    let direct = json!({"protocol": {"type": "direct"}});
    let check = |value: &serde_json::Value| validate(&serde_yaml::to_string(value).unwrap());
    let mut valid = base.clone();
    valid[1]["client_proxies"][0]["protocol"]["peer_client_chain"] = json!([direct]);
    check(&valid).unwrap();
    let raw: Vec<crate::config::Config> =
        serde_yaml::from_str(&serde_yaml::to_string(&valid).unwrap()).unwrap();
    validate(&serde_yaml::to_string(&raw).unwrap()).unwrap();
    for (field, value) in [
        ("listen", json!("0.0.0.0:0")),
        ("peer_client_chain", json!([])),
        ("peer_client_chain", json!("missing-group")),
        (
            "peer_client_chain",
            json!([{"protocol": {"type": "wireguard", "endpoint": "missing"}}]),
        ),
    ] {
        let mut invalid = valid.clone();
        invalid[1]["client_proxies"][0]["protocol"][field] = value;
        assert!(check(&invalid).is_err(), "accepted {field}");
    }
    let mut bound = valid.clone();
    bound[1]["client_proxies"][0]["bind_interface"] = json!("lo");
    assert!(check(&bound).is_err());
    let mut missing_peer = valid.clone();
    missing_peer[1]["client_proxies"][0]
        .as_object_mut()
        .unwrap()
        .remove("address");
    assert!(check(&missing_peer).is_err());

    let mut nested = base.clone();
    let mut carrier = base[1].clone();
    carrier["client_group"] = json!("carrier");
    carrier["client_proxies"][0]["address"] = json!("127.0.0.1:51821");
    nested.as_array_mut().unwrap().push(carrier);
    nested[1]["client_proxies"][0]["protocol"]["mtu"] = json!(1280);
    nested[1]["client_proxies"][0]["protocol"]["peer_client_chain"] = json!("carrier");
    nested.as_array_mut().unwrap().reverse();
    let sorted = check(&nested).unwrap();
    assert_eq!(
        sorted.wireguard_endpoints[0].peers[0].endpoint.as_deref(),
        Some("127.0.0.1:51821")
    );
    assert_eq!(
        sorted.wireguard_endpoints[1].peers[0].endpoint.as_deref(),
        Some("127.0.0.1:51820")
    );
    nested[2]["client_proxies"][0]["protocol"]["mtu"] = json!(1408);
    assert!(check(&nested).err().unwrap().to_string().contains("MTU"));

    let cycle_chain = |group| {
        json!([
            group,
            {"address": "127.0.0.1:443", "protocol": config::vless_protocol()},
        ])
    };
    let mut cyclic = valid.clone();
    cyclic[1]["client_proxies"][0]["protocol"]["peer_client_chain"] = cycle_chain("client");
    assert!(
        check(&cyclic)
            .err()
            .unwrap()
            .to_string()
            .contains("Circular dependency")
    );
    let mut carrier = base[1].clone();
    carrier["client_group"] = json!("carrier");
    carrier["client_proxies"][0]["protocol"]["peer_client_chain"] = cycle_chain("client");
    cyclic.as_array_mut().unwrap().push(carrier);
    cyclic[1]["client_proxies"][0]["protocol"]["peer_client_chain"] = cycle_chain("carrier");
    assert!(
        check(&cyclic)
            .err()
            .unwrap()
            .to_string()
            .contains("Circular dependency")
    );
    cyclic[1]["client_proxies"][0]["protocol"]["peer_client_chain"][0] =
        json!({"pool": [direct, "carrier"]});
    assert!(
        check(&cyclic)
            .err()
            .unwrap()
            .to_string()
            .contains("Circular dependency")
    );

    valid[1]["client_proxies"][0]["protocol"]["peer_client_chain"] = json!("outer");
    valid
        .as_array_mut()
        .unwrap()
        .push(json!({"client_group": "outer", "client_proxies": [direct]}));
    check(&valid).unwrap();
}

#[tokio::test]
async fn wireguard_outer_chain_requires_udp_before_starting() {
    for protocol in [
        "{type: socks}",
        "{type: trojan, password: test}",
        "{type: vless, user_id: b85798ef-e9dc-46a4-9a87-8da4499d36d0, udp_enabled: false}",
    ] {
        let mut raw: serde_json::Value = serde_yaml::from_str(&pair_config(51820)).unwrap();
        raw[1]["client_proxies"][0]["protocol"]["peer_client_chain"] = serde_yaml::from_str(
            &format!("[{{address: 'unresolvable.invalid:9', protocol: {protocol}}}]"),
        )
        .unwrap();
        let error = validate(&serde_yaml::to_string(&raw).unwrap())
            .err()
            .unwrap();
        assert!(error.to_string().contains("does not support UDP"));
        let mut configs = validate(&pair_config(51820)).unwrap();
        configs.wireguard_endpoints[CLIENT].peer_client_chain = Some(
            serde_yaml::from_str(&format!(
                "[{{address: '127.0.0.1:9', protocol: {protocol}}}]"
            ))
            .unwrap(),
        );
        let error = Prepared::new(&mut configs).await.err().unwrap();
        assert!(error.to_string().contains("does not support UDP"));
    }
    let mut configs = validate(&pair_config(51820)).unwrap();
    configs.wireguard_endpoints[CLIENT].peer_client_chain = Some(
        serde_yaml::from_str(
            r#"
      - address: '127.0.0.1:9'
        protocol: {type: socks}
      - pool:
          - address: '127.0.0.1:10'
            protocol: {type: socks}
          - address: '127.0.0.1:11'
            protocol: {type: vless, user_id: b85798ef-e9dc-46a4-9a87-8da4499d36d0}
    "#,
        )
        .unwrap(),
    );
    Prepared::new(&mut configs).await.unwrap();
}

#[tokio::test]
async fn wireguard_nested_outer_chain_and_reload() {
    use serde_json::{Value, json};
    // Concurrent harness forks can retain even CLOEXEC sockets until exec completes.
    if std::env::var_os("SHOES_WIREGUARD_NESTED_RELOAD_CHILD").is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "wireguard::tests::wireguard_nested_outer_chain_and_reload",
                "--nocapture",
            ])
            .env("SHOES_WIREGUARD_NESTED_RELOAD_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    tokio::time::timeout(Duration::from_secs(30), async {
        let carrier_port = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let inner_port = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let mut carrier: Vec<Value> =
            serde_yaml::from_str(&pair_config(carrier_port.local_addr().unwrap().port())).unwrap();
        carrier[1]["client_group"] = json!("carrier-client");
        carrier[2]["rules"][0]["client_chain"] = json!("carrier-client");
        let mut inner: Vec<Value> =
            serde_yaml::from_str(&pair_config(inner_port.local_addr().unwrap().port())).unwrap();
        inner[1]["client_proxies"][0]["protocol"]["mtu"] = json!(1280);
        inner[1]["client_proxies"][0]["protocol"]["peer_client_chain"] = json!("carrier-client");
        inner.extend(carrier);
        let mut configs = validate(&serde_yaml::to_string(&inner).unwrap()).unwrap();
        let prepared = Prepared::new(&mut configs).await.unwrap();
        let find = |port| {
            prepared
                .endpoints
                .iter()
                .find(|endpoint| {
                    endpoint.config.peers[0].endpoint == Some(format!("127.0.0.1:{port}"))
                })
                .unwrap()
        };
        let client = find(inner_port.local_addr().unwrap().port());
        let carrier = find(carrier_port.local_addr().unwrap().port());
        assert!(Arc::strong_count(&carrier.connector) > 1);
        drop((carrier_port, inner_port));
        let mut running = Running::default();
        for _ in 0..2 {
            prepared
                .start(&mut DnsRegistry::new(), &mut running)
                .await
                .unwrap();
            for ipv6 in [false, true] {
                let (tcp, udp, _servers) = echo_servers(ipv6).await;
                check_echo(client.connector.as_ref(), tcp, udp).await;
            }
            running.stop().await;
            assert!(client.connector.handle().is_err());
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn wireguard_detoured_endpoint_keeps_encrypted_peers_separate() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let first = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let second = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let mut configs = validate(&pair_config(first.local_addr().unwrap().port())).unwrap();
        let mut other_server = configs.wireguard_endpoints[SERVER].clone();
        other_server.id = "other-server".into();
        other_server.private_key = crate::config::wireguard::WireguardKey([44; 32]);
        other_server.listen = Some(second.local_addr().unwrap());
        other_server.inbound.as_mut().unwrap().rules = serde_yaml::from_str(
            "[{masks: '198.18.0.2/32', action: allow, override_address: '127.0.0.1:0'}]",
        )
        .unwrap();
        for selection in other_server.inbound.as_mut().unwrap().rules.iter_mut() {
            let crate::config::ConfigSelection::Config(rule) = selection else {
                panic!("expected an inline rule")
            };
            rule.compile(&mut crate::rules::Compiler::default())
                .unwrap();
        }
        let client = &mut configs.wireguard_endpoints[CLIENT];
        client.peer_client_chain = Some(crate::config::ClientChain::default());
        client.peers[0].allowed_ips = vec!["127.0.0.1/32".into()];
        let mut other_peer = client.peers[0].clone();
        other_peer.public_key = serde_yaml::from_str(&public(44)).unwrap();
        other_peer.endpoint = Some(format!("127.0.0.1:{}", second.local_addr().unwrap().port()));
        other_peer.allowed_ips = vec!["198.18.0.2/32".into()];
        client.peers.push(other_peer);
        configs.wireguard_endpoints.push(other_server);
        let prepared = Prepared::new(&mut configs).await.unwrap();
        drop((first, second));
        let mut running = start_prepared(&prepared).await;
        let (tcp, udp, _servers) = echo_servers(false).await;
        let second_ip = "198.18.0.2".parse().unwrap();
        let connector = prepared.endpoints[CLIENT].connector.as_ref();
        tokio::join!(
            check_echo(connector, tcp, udp),
            check_echo(
                connector,
                SocketAddr::new(second_ip, tcp.port()),
                SocketAddr::new(second_ip, udp.port())
            ),
        );
        running.stop().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn wireguard_chains_load_client_certificate_paths_before_validation() {
    use serde_json::{Value, json};
    let directory = tempfile::tempdir().unwrap();
    let cert_path = directory.path().join("client.crt");
    let key_path = directory.path().join("client.key");
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
    let mut config: serde_json::Value = serde_yaml::from_str(&pair_config(10001)).unwrap();
    let chain = serde_json::json!([{
        "address":"127.0.0.1:443", "protocol": {"type":"tls", "cert":cert_path, "key":key_path, "protocol":{"type":"vless", "user_id":"b85798ef-e9dc-46a4-9a87-8da4499d36d0"}}
    }]);
    for outer in [false, true] {
        if outer {
            config[1]["client_proxies"][0]["protocol"]["peer_client_chain"] = chain.clone();
        } else {
            config[0]["rules"][0]["client_chain"] = chain.clone();
        }
        let configs = serde_yaml::from_str(&serde_yaml::to_string(&config).unwrap()).unwrap();
        let (configs, count) = crate::config::convert_cert_paths(configs).await.unwrap();
        assert_eq!(count, 2);
        crate::config::create_server_configs(configs).unwrap();
        config = serde_yaml::from_str(&pair_config(10001)).unwrap();
    }
    let mut carrier = config[1]["client_proxies"][0].clone();
    carrier["address"] = json!("127.0.0.1:10002");
    carrier["protocol"]["peer_client_chain"] = chain;
    let mut nested = config[1]["client_proxies"][0].clone();
    nested["protocol"]["mtu"] = json!(1280);
    nested["protocol"]["peer_client_chain"] = json!([carrier]);
    let rule = json!({"masks": "0.0.0.0/0", "action": "allow", "client_chain": [nested]});
    let dns = json!({"url": "tcp://192.0.2.53", "client_chain": [nested]});
    for roots in [
        json!([
            {"dns_group": "tunnel", "dns_servers": [dns]},
            {"address": "0.0.0.0:1080", "protocol": {"type": "socks"}, "dns": {"servers": "tunnel"}},
        ]),
        json!([{"address": "0.0.0.0:1080", "protocol": {"type": "socks"}, "dns": {"servers": [dns]}}]),
        json!([{"device_fd": 7, "rules": [rule]}]),
    ] {
        let raw: Vec<crate::config::Config> =
            serde_yaml::from_str(&serde_yaml::to_string(&roots).unwrap()).unwrap();
        let (raw, count) = crate::config::convert_cert_paths(raw).await.unwrap();
        assert_eq!(count, 2);
        assert_eq!(
            crate::config::create_server_configs(raw)
                .unwrap()
                .wireguard_endpoints
                .len(),
            2
        );
    }
    let raw: Vec<crate::config::Config> = serde_yaml::from_str(
        &serde_yaml::to_string(&json!([
            {"rule_group": "tunnel", "rules": [rule]},
            {"address": "0.0.0.0:1080", "protocol": {"type": "socks"}, "rules": "tunnel"},
        ]))
        .unwrap(),
    )
    .unwrap();
    let (raw, count) = crate::config::convert_cert_paths(raw).await.unwrap();
    assert_eq!(count, 2);
    assert_eq!(
        crate::config::create_server_configs(raw)
            .unwrap()
            .wireguard_endpoints
            .len(),
        2
    );

    let mut server: Value = config[0].clone();
    server.as_object_mut().unwrap().remove("address");
    server["protocol"]["mtu"] = json!(1280);
    server["protocol"]["peers"][0]["endpoint"] = json!("127.0.0.1:10003");
    server["protocol"]["peers"][0]["persistent_keepalive"] = json!(1);
    server["protocol"]["peer_client_chain"] = json!([carrier]);
    let raw = serde_yaml::from_str(&serde_yaml::to_string(&json!([server])).unwrap()).unwrap();
    let (raw, count) = crate::config::convert_cert_paths(raw).await.unwrap();
    assert_eq!(count, 2);
    assert_eq!(
        crate::config::create_server_configs(raw)
            .unwrap()
            .wireguard_endpoints
            .len(),
        2
    );
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
        configs.wireguard_endpoints[CLIENT].peers[0].endpoint =
            Some(format!("127.0.0.1:{front_port}"));
        for config in &mut configs.wireguard_endpoints {
            config.peers[0].pre_shared_key = None;
        }
        let prepared = Prepared::new(&mut configs).await.unwrap();
        drop(reservation);
        let mut running = start_prepared(&prepared).await;
        let target = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let target_addr = SocketAddr::new(
            "127.0.0.1".parse().unwrap(),
            target.local_addr().unwrap().port(),
        );
        let mut stream = prepared.endpoints[CLIENT]
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
    assert!(prepared.endpoints[SERVER].connector.handle().is_err());
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
                    configs.wireguard_endpoints[CLIENT].peers[0].pre_shared_key =
                        Some(crate::config::wireguard::WireguardKey([44; 32]))
                }
                "source" => {
                    configs.wireguard_endpoints[CLIENT].addresses = vec!["10.77.0.99/32".into()]
                }
                "inbound" => configs.wireguard_endpoints[SERVER].inbound = None,
                _ => unreachable!(),
            }
            let prepared = Prepared::new(&mut configs).await.unwrap();
            drop(reservation);
            let mut running = start_prepared(&prepared).await;
            let target = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            let address = SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                target.local_addr().unwrap().port(),
            );
            let mut stream = prepared.endpoints[CLIENT]
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
        let mut peer = configs.wireguard_endpoints[SERVER].peers[0].clone();
        peer.public_key = serde_yaml::from_str(&public(44)).unwrap();
        peer.allowed_ips = vec!["10.77.0.3/32".into(), "fd77::3/128".into()];
        configs.wireguard_endpoints[SERVER].peers.push(peer);
        let mut client = configs.wireguard_endpoints[CLIENT].clone();
        client.id = "second-client".into();
        client.private_key = crate::config::wireguard::WireguardKey([44; 32]);
        client.addresses = vec!["10.77.0.3/32".into(), "fd77::3/128".into()];
        configs.wireguard_endpoints.push(client);
        let prepared = Prepared::new(&mut configs).await.unwrap();
        drop(reservation);
        let mut running = start_prepared(&prepared).await;
        for v6 in [false, true] {
            let (tcp, udp, _echoes) = echo_servers(v6).await;
            tokio::join!(
                check_echo(prepared.endpoints[CLIENT].connector.as_ref(), tcp, udp),
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
        proto::rr::{RData, rdata::A},
    };
    trait TestIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
    impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> TestIo for T {}
    tokio::time::timeout(Duration::from_secs(20), async {
        let reservation = std::net::UdpSocket::bind("[::]:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        let mut raw: serde_json::Value = serde_yaml::from_str(&pair_config(port)).unwrap();
        raw[0]["address"] = serde_json::json!(format!("[::]:{port}"));
        raw[1]["client_proxies"][0]["address"] = serde_json::json!(format!("[::1]:{port}"));
        let mut configs = validate(&serde_yaml::to_string(&raw).unwrap()).unwrap();
        let prepared = Prepared::new(&mut configs).await.unwrap();
        drop(reservation);
        let mut dns = DnsRegistry::new();
        let mut running = Running::default();
        prepared.start(&mut dns, &mut running).await.unwrap();
        let provider = crate::dns::ProxyRuntimeProvider::with_bootstrap(
            Arc::new(ClientChainGroup::new(vec![ClientProxyChain::new(
                vec![InitialHopEntry::Wireguard(
                    prepared.endpoints[CLIENT].connector.clone(),
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
                        let bytes = dns_answer(&query);
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
                    let bytes = dns_answer(&query);
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
async fn wireguard_unused_dns_groups_do_not_contact_peers() {
    use serde_json::json;

    tokio::time::timeout(Duration::from_secs(10), async {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut client = config::client(peer.local_addr().unwrap().port());
        client["client_proxies"][0]["protocol"]["persistent_keepalive"] = json!(1);
        let mut raw = json!([
            client,
            {"dns_group": "tunnel", "dns_servers": [{"url": "tcp://192.0.2.53", "client_chain": "wg"}]},
            {"address": "0.0.0.0:1080", "protocol": {"type": "socks"}},
        ]);
        let mut configs = validate(&serde_yaml::to_string(&raw).unwrap()).unwrap();
        assert!(configs.wireguard_endpoints.is_empty());
        let prepared = Prepared::new(&mut configs).await.unwrap();
        let mut dns = crate::dns::build_dns_registry(configs.dns_groups).await.unwrap();
        let mut running = Running::default();
        prepared.start(&mut dns, &mut running).await.unwrap();
        let mut packet = [0; 2048];
        assert!(
            tokio::time::timeout(Duration::from_millis(1100), peer.recv(&mut packet))
                .await
                .is_err()
        );
        running.stop().await;

        raw[2]["dns"] = json!({"servers": "tunnel"});
        let mut configs = validate(&serde_yaml::to_string(&raw).unwrap()).unwrap();
        let prepared = Prepared::new(&mut configs).await.unwrap();
        let mut dns = crate::dns::build_dns_registry(configs.dns_groups).await.unwrap();
        prepared.start(&mut dns, &mut running).await.unwrap();
        let length = tokio::time::timeout(Duration::from_secs(3), peer.recv(&mut packet))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(length, 148);
        assert_eq!(&packet[..4], &[1, 0, 0, 0]);
        running.stop().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn wireguard_dns_registry_prepares_inactive_generation_handles() {
    use serde_json::json;

    tokio::time::timeout(Duration::from_secs(10), async {
        let reservation = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let dns_port = listener.local_addr().unwrap().port();
        let mut raw: serde_json::Value = serde_yaml::from_str(&pair_config(port)).unwrap();
        raw[2]["dns"] = json!({"servers": "tunnel"});
        raw.as_array_mut().unwrap().push(json!({
            "dns_group": "tunnel",
            "dns_servers": [{
                "url": format!("tcp://127.0.0.1:{dns_port}"),
                "ip_strategy": "ipv4_only",
                "client_chain": "client",
            }],
        }));
        let mut configs = validate(&serde_yaml::to_string(&raw).unwrap()).unwrap();
        let prepared = Prepared::new(&mut configs).await.unwrap();
        let mut dns = crate::dns::build_dns_registry(configs.dns_groups.clone())
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
        let mut servers = JoinSet::new();
        servers.spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let length = stream.read_u16().await.unwrap() as usize;
                let mut bytes = vec![0; length];
                stream.read_exact(&mut bytes).await.unwrap();
                let bytes = dns_answer(&bytes);
                stream.write_u16(bytes.len() as u16).await.unwrap();
                stream.write_all(&bytes).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        drop(reservation);
        let mut running = Running::default();
        prepared.start(&mut dns, &mut running).await.unwrap();
        for registry in [
            dns,
            crate::dns::build_dns_registry(configs.dns_groups.clone())
                .await
                .unwrap(),
        ] {
            let resolver = registry.get_by_name("tunnel").unwrap();
            let answer = resolver
                .resolve_location(&NetLocation::from_str("registry.test:443", None).unwrap())
                .await
                .unwrap();
            assert_eq!(answer[0], "192.0.2.42:443".parse().unwrap());
        }
        running.stop().await;
        let dns = crate::dns::build_dns_registry(configs.dns_groups)
            .await
            .unwrap();
        assert!(
            dns.get_by_name("tunnel")
                .unwrap()
                .resolve_location(&NetLocation::from_str("after-stop.test:443", None).unwrap())
                .await
                .is_err()
        );
    })
    .await
    .unwrap();
}
