use super::tests::{CLIENT, check_echo, echo_servers, pair_config, start_prepared, validate};
use super::*;
use serde_json::{Value, json};
use std::time::Duration;

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
