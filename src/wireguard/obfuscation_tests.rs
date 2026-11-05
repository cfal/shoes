use super::tests::{CLIENT, check_echo, echo_servers, pair_config, start_prepared, validate};
use super::*;
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

fn with_amnezia(config: &str, server: &Value, client: &Value) -> String {
    let mut parsed: Vec<Value> = serde_yaml::from_str(config).unwrap();
    parsed[0]["protocol"]["amnezia"] = server.clone();
    parsed[1]["client_chains"][0]["protocol"]["amnezia"] = client.clone();
    serde_yaml::to_string(&parsed).unwrap()
}

fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn amnezia_pair_carries_tcp_and_udp_per_version() {
    for version in ["2.0", "3.0", "3.1"] {
        tokio::time::timeout(Duration::from_secs(30), async {
            let profile = super::test_support::amnezia_profile(version);
            let yaml = with_amnezia(&pair_config(free_port()), &profile, &profile);
            let mut configs = validate(&yaml).unwrap();
            let prepared = Prepared::new(&mut configs).await.unwrap();
            let mut running = start_prepared(&prepared).await;
            for ipv6 in [false, true] {
                let (tcp, udp, _servers) = echo_servers(ipv6).await;
                check_echo(prepared.endpoints[CLIENT].connector.as_ref(), tcp, udp).await;
            }
            running.stop().await;
        })
        .await
        .unwrap_or_else(|_| panic!("amnezia {version} pair timed out"));
    }
}

#[tokio::test]
async fn amnezia_mismatch_does_not_handshake() {
    let server = super::test_support::amnezia_profile("2.0");
    let mut client = server.clone();
    client["h1"] = json!("100200-100300");
    let yaml = with_amnezia(&pair_config(free_port()), &server, &client);
    let mut configs = validate(&yaml).unwrap();
    let prepared = Prepared::new(&mut configs).await.unwrap();
    let mut running = start_prepared(&prepared).await;
    let (tcp, _udp, _servers) = echo_servers(false).await;
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let location = ResolvedLocation::from(NetLocation::from_ip_addr(tcp.ip(), tcp.port()));
    let connected = tokio::time::timeout(
        Duration::from_secs(3),
        prepared.endpoints[CLIENT]
            .connector
            .connect(&resolver, &location),
    )
    .await;
    assert!(
        !matches!(connected, Ok(Ok(_))),
        "mismatched Amnezia settings must not connect"
    );
    running.stop().await;
}

#[tokio::test]
async fn plain_client_cannot_reach_amnezia_server() {
    let server = super::test_support::amnezia_profile("2.0");
    let mut parsed: Vec<Value> = serde_yaml::from_str(&pair_config(free_port())).unwrap();
    parsed[0]["protocol"]["amnezia"] = server;
    let mut configs = validate(&serde_yaml::to_string(&parsed).unwrap()).unwrap();
    let prepared = Prepared::new(&mut configs).await.unwrap();
    let mut running = start_prepared(&prepared).await;
    let (tcp, _udp, _servers) = echo_servers(false).await;
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let location = ResolvedLocation::from(NetLocation::from_ip_addr(tcp.ip(), tcp.port()));
    let connected = tokio::time::timeout(
        Duration::from_secs(3),
        prepared.endpoints[CLIENT]
            .connector
            .connect(&resolver, &location),
    )
    .await;
    assert!(
        !matches!(connected, Ok(Ok(_))),
        "a plain client must not reach an Amnezia server"
    );
    running.stop().await;
}

#[tokio::test]
async fn amnezia_pair_through_peer_client_chain() {
    if std::env::var_os("SHOES_WIREGUARD_AMNEZIA_CHAIN_CHILD").is_none() {
        shoes_test_support::isolated::run_isolated(
            "wireguard::obfuscation_tests::amnezia_pair_through_peer_client_chain",
            "SHOES_WIREGUARD_AMNEZIA_CHAIN_CHILD",
            "1",
        );
        return;
    }
    tokio::time::timeout(Duration::from_secs(30), async {
        let carrier_port = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let inner_port = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let mut carrier: Vec<Value> =
            serde_yaml::from_str(&pair_config(carrier_port.local_addr().unwrap().port())).unwrap();
        carrier[1]["client_group"] = json!("carrier-client");
        carrier[2]["rules"][0]["client_chain"] = json!("carrier-client");
        let profile = super::test_support::amnezia_profile("3.1");
        let mut inner: Vec<Value> =
            serde_yaml::from_str(&pair_config(inner_port.local_addr().unwrap().port())).unwrap();
        inner[0]["protocol"]["amnezia"] = profile.clone();
        inner[1]["client_chains"][0]["protocol"]["amnezia"] = profile;
        inner[1]["client_chains"][0]["protocol"]["mtu"] = json!(1280);
        carrier[1]["client_chains"][0]["protocol"]["mtu"] = json!(1420);
        inner[1]["client_chains"][0]["protocol"]["peer_client_chain"] = json!("carrier-client");
        inner.extend(carrier);
        let mut configs = validate(&serde_yaml::to_string(&inner).unwrap()).unwrap();
        let prepared = Prepared::new(&mut configs).await.unwrap();
        let client = prepared
            .endpoints
            .iter()
            .find(|endpoint| {
                endpoint.config.peers[0].endpoint
                    == Some(format!(
                        "127.0.0.1:{}",
                        inner_port.local_addr().unwrap().port()
                    ))
            })
            .unwrap();
        drop((carrier_port, inner_port));
        let mut running = start_prepared(&prepared).await;
        for ipv6 in [false, true] {
            let (tcp, udp, _servers) = echo_servers(ipv6).await;
            check_echo(client.connector.as_ref(), tcp, udp).await;
        }
        running.stop().await;
    })
    .await
    .unwrap();
}

#[test]
fn carrier_mtu_check_counts_amnezia_overhead() {
    // Plain inner MTU 1280 needs a 1360 carrier; the carrier is set 22 bytes above that.
    let config = |s4: Option<u32>| {
        let mut inner = super::test_support::client(1);
        inner["client_chains"][0]["protocol"]["mtu"] = json!(1280);
        inner["client_chains"][0]["protocol"]["peer_client_chain"] = json!("carrier");
        if let Some(s4) = s4 {
            let mut profile = super::test_support::amnezia_profile("2.0");
            profile["s4"] = json!(s4);
            inner["client_chains"][0]["protocol"]["amnezia"] = profile;
        }
        let mut carrier = super::test_support::client(2);
        carrier["client_group"] = json!("carrier");
        carrier["client_chains"][0]["protocol"]["mtu"] = json!(1382);
        let socks = super::test_support::socks(0);
        serde_yaml::to_string(&json!([inner, carrier, socks])).unwrap()
    };
    validate(&config(None)).unwrap();
    validate(&config(Some(22))).unwrap();
    let error = validate(&config(Some(23)))
        .err()
        .expect("s4 23 is too large");
    assert!(error.to_string().contains("carrier MTU >= 1383"), "{error}");
}

/// An inner device over a WireGuard carrier, with the given `amnezia` overrides.
fn carried_config(carrier_mtu: u32, overrides: serde_json::Value) -> String {
    let mut inner = super::test_support::client(1);
    inner["client_chains"][0]["protocol"]["mtu"] = json!(1280);
    inner["client_chains"][0]["protocol"]["peer_client_chain"] = json!("carrier");
    let mut profile = super::test_support::amnezia_profile("3.0");
    for (key, value) in overrides.as_object().unwrap() {
        profile[key] = value.clone();
    }
    inner["client_chains"][0]["protocol"]["amnezia"] = profile;
    let mut carrier = super::test_support::client(2);
    carrier["client_group"] = json!("carrier");
    carrier["client_chains"][0]["protocol"]["mtu"] = json!(carrier_mtu);
    let socks = super::test_support::socks(0);
    serde_yaml::to_string(&json!([inner, carrier, socks])).unwrap()
}

#[test]
fn carrier_mtu_check_does_not_count_content_padding() {
    // The fork never pads a packet past the tunnel MTU, so only `s4` needs room: 1280 + 80 + 22.
    validate(&carried_config(
        1382,
        json!({"s4": 22, "content_padding_addition": "0-100"}),
    ))
    .unwrap();
    let error = validate(&carried_config(
        1382,
        json!({"s4": 23, "content_padding_addition": "0-100"}),
    ))
    .err()
    .expect("s4 23 is too large");
    assert!(error.to_string().contains("carrier MTU >= 1383"), "{error}");
}

#[test]
fn carrier_mtu_check_reports_huge_padding_without_overflow() {
    // 1280 + 80 + 64200 does not fit in u16; the check must still reject it.
    let error = validate(&carried_config(1420, json!({"s4": 64200})))
        .err()
        .expect("s4 64200 cannot fit any carrier");
    assert!(
        error.to_string().contains("carrier MTU >= 65560"),
        "{error}"
    );
}

const MASKINGS: [&str; 3] = ["none", "stun", "media"];

fn phobos_config(masking: &str) -> gotatun::phobos::PhobosConfig {
    let mut config = gotatun::phobos::PhobosConfig::new(PHOBOS_KEY.as_bytes()).unwrap();
    assert!(config.set("masking", masking).unwrap());
    config
}

const PHOBOS_KEY: &str = "shoes-phobos-test-key";

#[test]
fn phobos_codec_round_trips_between_two_codecs() {
    use gotatun::phobos::{PhobosCodec, Unwrapped};
    let source: SocketAddr = "127.0.0.1:40000".parse().unwrap();
    let mut initiation = vec![0u8; 148];
    initiation[0] = 1;
    for (index, byte) in initiation.iter_mut().enumerate().skip(4) {
        *byte = index as u8;
    }
    for masking in MASKINGS {
        let mut client = PhobosCodec::new(phobos_config(masking)).unwrap();
        let mut relay = PhobosCodec::new(phobos_config(masking)).unwrap();
        for _ in 0..3 {
            let mut framed = Vec::new();
            client.wrap(&initiation, &mut framed).unwrap();
            match relay.unwrap(&mut framed, source) {
                Unwrapped::WireGuard(bytes) => assert_eq!(bytes, &initiation[..], "{masking}"),
                other => panic!("{masking}: initiation came back as {other:?}"),
            }
        }
    }
}

/// A Phobos server stand-in: unframes the client's datagrams for a plain WireGuard server.
///
/// Like a Phobos server, it forwards nothing from an address that has not sent an initiation.
async fn phobos_relay(config: gotatun::phobos::PhobosConfig, server: SocketAddr) -> PhobosRelay {
    use gotatun::phobos::{PhobosCodec, Unwrapped};
    let outside = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let inside = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = outside.local_addr().unwrap();
    let initiated = Arc::new(parking_lot::Mutex::new(HashSet::new()));
    let gated = Arc::new(AtomicUsize::new(0));
    let (sources, dropped) = (initiated.clone(), gated.clone());
    let task = tokio::spawn(async move {
        let mut codec = PhobosCodec::new(config).unwrap();
        let mut client = None;
        let mut from_client = vec![0; 65536];
        let mut from_server = vec![0; 65536];
        let mut framed = Vec::new();
        loop {
            tokio::select! {
                received = outside.recv_from(&mut from_client) => {
                    let (len, source) = received.unwrap();
                    match codec.unwrap(&mut from_client[..len], source) {
                        Unwrapped::WireGuard(bytes) => {
                            if bytes[0] == 1 {
                                sources.lock().insert(source);
                            }
                            if sources.lock().contains(&source) {
                                client = Some(source);
                                inside.send_to(bytes, server).await.unwrap();
                            } else {
                                dropped.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                        Unwrapped::Reply(reply) => {
                            outside.send_to(&reply, source).await.unwrap();
                        }
                        Unwrapped::Drop => {}
                    }
                }
                received = inside.recv_from(&mut from_server) => {
                    let (len, _) = received.unwrap();
                    let Some(client) = client else { continue };
                    if let Some(preamble) = codec.wrap(&from_server[..len], &mut framed).unwrap() {
                        outside.send_to(&preamble, client).await.unwrap();
                    }
                    outside.send_to(&framed, client).await.unwrap();
                }
            }
        }
    });
    PhobosRelay {
        address,
        task,
        initiated,
        gated,
    }
}

struct PhobosRelay {
    address: SocketAddr,
    task: tokio::task::JoinHandle<()>,
    /// Sources that sent an initiation; only these are forwarded.
    initiated: Arc<parking_lot::Mutex<HashSet<SocketAddr>>>,
    /// Datagrams dropped because their source had not sent an initiation.
    gated: Arc<AtomicUsize>,
}

#[tokio::test]
async fn phobos_client_through_gated_relay_per_masking() {
    for masking in MASKINGS {
        tokio::time::timeout(Duration::from_secs(30), async {
            let server_port = free_port();
            let relay = phobos_relay(
                phobos_config(masking),
                format!("127.0.0.1:{server_port}").parse().unwrap(),
            )
            .await;
            let mut parsed: Vec<Value> = serde_yaml::from_str(&pair_config(server_port)).unwrap();
            let protocol = &mut parsed[1]["client_chains"][0];
            protocol["address"] = json!(relay.address.to_string());
            protocol["protocol"]["phobos"] = json!({"key": PHOBOS_KEY, "masking": masking});
            let mut configs = validate(&serde_yaml::to_string(&parsed).unwrap()).unwrap();
            let prepared = Prepared::new(&mut configs).await.unwrap();
            let mut running = start_prepared(&prepared).await;
            let (tcp, udp, _servers) = echo_servers(false).await;
            check_echo(prepared.endpoints[CLIENT].connector.as_ref(), tcp, udp).await;
            running.stop().await;
            relay.task.abort();
        })
        .await
        .unwrap_or_else(|_| panic!("phobos {masking} through the relay timed out"));
    }
}

#[tokio::test]
async fn phobos_relay_drops_without_initiation() {
    use gotatun::phobos::PhobosCodec;
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay = phobos_relay(phobos_config("none"), server.local_addr().unwrap()).await;
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut codec = PhobosCodec::new(phobos_config("none")).unwrap();
    let mut transport = vec![0u8; 64];
    transport[0] = 4;
    let mut initiation = vec![0u8; 148];
    initiation[0] = 1;
    let mut framed = Vec::new();
    // Datagrams on loopback arrive in order, so the first one forwarded shows what was gated.
    for message in [&transport, &initiation, &transport] {
        codec.wrap(message, &mut framed).unwrap();
        client.send_to(&framed, relay.address).await.unwrap();
    }
    let mut buffer = [0; 2048];
    for expected in [&initiation, &transport] {
        let (len, _) = tokio::time::timeout(Duration::from_secs(5), server.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..len], &expected[..]);
    }
    assert_eq!(relay.gated.load(Ordering::SeqCst), 1);
    relay.task.abort();
}

/// A VLESS UDP stand-in for a `peer_client_chain` hop. Each association gets its own UDP
/// socket, so a reconnect reaches the Phobos relay from a new source port. `kick` ends every
/// open association, which the detour sees as EOF and redials.
struct VlessCarrier {
    address: SocketAddr,
    associations: Arc<parking_lot::Mutex<tokio::task::JoinSet<()>>>,
    accepted: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl VlessCarrier {
    const USER_ID: &str = "b85798ef-e9dc-46a4-9a87-8da4499d36d0";

    async fn start() -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let associations = Arc::new(parking_lot::Mutex::new(tokio::task::JoinSet::new()));
        let accepted = Arc::new(AtomicUsize::new(0));
        let (spawned, counted) = (associations.clone(), accepted.clone());
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                counted.fetch_add(1, Ordering::SeqCst);
                spawned.lock().spawn(async move {
                    // version, user id, addon length 0, command UDP, port, type 1, IPv4.
                    let mut header = [0; 26];
                    stream.read_exact(&mut header).await.unwrap();
                    assert_eq!((header[18], header[21]), (2, 1), "IPv4 UDP request");
                    let port = u16::from_be_bytes([header[19], header[20]]);
                    let ip =
                        std::net::Ipv4Addr::new(header[22], header[23], header[24], header[25]);
                    let target = SocketAddr::from((ip, port));
                    stream.write_all(&[0, 0]).await.unwrap();
                    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    let (mut read, mut write) = stream.into_split();
                    let mut datagram = vec![0; 65536];
                    let mut length = [0; 2];
                    loop {
                        tokio::select! {
                            received = read.read_exact(&mut length) => {
                                if received.is_err() {
                                    return;
                                }
                                let len = u16::from_be_bytes(length) as usize;
                                let mut payload = vec![0; len];
                                if read.read_exact(&mut payload).await.is_err() {
                                    return;
                                }
                                let _ = udp.send_to(&payload, target).await;
                            }
                            received = udp.recv_from(&mut datagram) => {
                                let (len, _) = received.unwrap();
                                let mut frame = (len as u16).to_be_bytes().to_vec();
                                frame.extend_from_slice(&datagram[..len]);
                                if write.write_all(&frame).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });
        Self {
            address,
            associations,
            accepted,
            task,
        }
    }

    fn kick(&self) {
        self.associations.lock().abort_all();
    }
}

/// A detour reconnect changes the source the Phobos server sees. The relay's gate then drops
/// the new source until it sends an initiation, which only `address_changed()` asks for at
/// once; without it WireGuard stays silent for about 15 s before retrying the handshake.
#[tokio::test]
async fn phobos_detour_reconnect_recovers_without_waiting_for_rekey() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let server_port = free_port();
        let relay = phobos_relay(
            phobos_config("stun"),
            format!("127.0.0.1:{server_port}").parse().unwrap(),
        )
        .await;
        let carrier = VlessCarrier::start().await;
        let mut parsed: Vec<Value> = serde_yaml::from_str(&pair_config(server_port)).unwrap();
        let protocol = &mut parsed[1]["client_chains"][0];
        protocol["address"] = json!(relay.address.to_string());
        protocol["protocol"]["phobos"] = json!({"key": PHOBOS_KEY, "masking": "stun"});
        protocol["protocol"]["peer_client_chain"] = json!([{
            "address": carrier.address.to_string(),
            "protocol": {"type": "vless", "user_id": VlessCarrier::USER_ID},
        }]);
        let mut configs = validate(&serde_yaml::to_string(&parsed).unwrap()).unwrap();
        let prepared = Prepared::new(&mut configs).await.unwrap();
        let mut running = start_prepared(&prepared).await;
        let connector = prepared.endpoints[CLIENT].connector.as_ref();
        let (tcp, udp, _servers) = echo_servers(false).await;
        check_echo(connector, tcp, udp).await;
        assert_eq!(carrier.accepted.load(Ordering::SeqCst), 1);
        assert_eq!(relay.initiated.lock().len(), 1);

        carrier.kick();
        tokio::time::timeout(Duration::from_secs(5), check_echo(connector, tcp, udp))
            .await
            .expect("Phobos must recover from a detour reconnect without waiting for a rekey");
        assert_eq!(carrier.accepted.load(Ordering::SeqCst), 2);
        assert_eq!(
            relay.initiated.lock().len(),
            2,
            "the reconnect must reach the relay from a new source that sent an initiation"
        );
        running.stop().await;
        carrier.task.abort();
        relay.task.abort();
    })
    .await
    .unwrap();
}
