use serde_json::json;
use shoes_test_support::certs::generate_test_cert_files;
use shoes_test_support::port_helper::PortHelper;
use shoes_test_support::socks5::{
    Socks5UdpAssociation, SocksDestination, decode_udp_datagram, encode_udp_datagram,
};
use shoes_test_support::test_fixture::{start_shoes_server, start_singbox_server};
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

const UUID: &str = "a3482e88-686a-4a58-8126-99c9034e4b09";
const STUN: &[u8] = &[
    0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const DTLS: &[u8] = &[22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 42];
type TestResult = Result<(), Box<dyn std::error::Error>>;

enum Carrier {
    AnyTls,
    H2Mux,
}

async fn exchange(
    association: &Socks5UdpAssociation,
    target: SocketAddr,
    outbound: &UdpSocket,
    payload: &[u8],
    fixed: bool,
) -> io::Result<SocketAddr> {
    let round_trip = async {
        let request = encode_udp_datagram(&SocksDestination::Ip(target), payload)?;
        association
            .socket()
            .send_to(&request, association.relay_addr())
            .await?;
        let mut reply = [0; 4096];
        let (length, source) = timeout(
            Duration::from_secs(10),
            association.socket().recv_from(&mut reply),
        )
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
        assert_eq!(source, association.relay_addr());
        assert_eq!(decode_udp_datagram(&reply[..length])?, payload);
        // Fixed replies carry no address; sing-box's AnyTLS adapter reports the carrier address.
        if !fixed {
            assert_eq!(&reply[..length], request);
        }
        Ok::<_, io::Error>(())
    };
    let echo = async {
        let mut bytes = [0; 4096];
        let (length, source) = outbound.recv_from(&mut bytes).await?;
        assert_eq!(&bytes[..length], payload);
        outbound.send_to(payload, source).await?;
        Ok::<_, io::Error>(source)
    };
    let ((), source) = tokio::try_join!(round_trip, echo)?;
    Ok(source)
}

async fn check_protocol_routes(carrier: Carrier, fixed: bool) -> TestResult {
    timeout(Duration::from_secs(30), async {
        let mut ports = PortHelper::new();
        let (_, shoes_port) = ports.get_localhost_listener_port();
        let (_, socks_port) = ports.get_localhost_listener_port();
        let requested = UdpSocket::bind("0.0.0.0:0").await?;
        let routed = UdpSocket::bind("0.0.0.0:0").await?;
        let target = SocketAddr::from(([127, 0, 0, 1], requested.local_addr()?.port()));
        let (cert, key) = generate_test_cert_files()?;
        let (server_protocol, mut outbound) = match carrier {
            Carrier::AnyTls => (
                json!({"type": "anytls", "users": [{"name": "test", "password": "test"}]}),
                json!({"type": "anytls", "password": "test"}),
            ),
            Carrier::H2Mux => (
                json!({"type": "vless", "user_id": UUID, "udp_enabled": true}),
                json!({
                    "type": "vless", "uuid": UUID,
                    "multiplex": {"enabled": true, "protocol": "h2mux", "max_connections": 1}
                }),
            ),
        };
        let shoes_config = json!([{
            "address": format!("0.0.0.0:{shoes_port}"),
            "protocol": {
                "type": "tls",
                "tls_targets": {"test.local": {
                    "cert": AsRef::<Path>::as_ref(&cert),
                    "key": AsRef::<Path>::as_ref(&key),
                    "protocol": server_protocol
                }}
            },
            "rules": [
                {
                    "conditions": {"all": [{"network": "udp"}, {"protocol": ["stun", "dtls"]}]},
                    "action": "allow",
                    "override_address": format!("127.0.0.1:{}", routed.local_addr()?.port())
                },
                {"conditions": {"any_destination": true}, "action": "block"}
            ]
        }]);
        outbound["tag"] = json!("proxy");
        outbound["server"] = json!("127.0.0.1");
        outbound["server_port"] = json!(shoes_port);
        outbound["tls"] = json!({"enabled": true, "insecure": true, "server_name": "test.local"});
        let singbox_config = json!({
            "log": {"level": "warn"},
            "inbounds": [{"type": "socks", "listen": "0.0.0.0", "listen_port": socks_port}],
            "outbounds": [outbound],
            // udp_connect selects fixed-target UoT/h2mux rather than packet-address mode.
            "route": {"rules": [{"action": "route", "outbound": "proxy", "udp_connect": fixed}]}
        });
        let (_shoes, _shoes_config) = start_shoes_server(&shoes_config.to_string())?;
        let (_singbox, _singbox_config) = start_singbox_server(&singbox_config.to_string())?;
        ports.wait_for_all_ports().await?;

        for initial in [STUN, DTLS] {
            let allowed = Socks5UdpAssociation::connect("127.0.0.1", socks_port).await?;
            let peer = exchange(&allowed, target, &routed, initial, fixed).await?;
            for payload in [b"media".as_slice(), STUN, DTLS] {
                assert_eq!(exchange(&allowed, target, &routed, payload, fixed).await?, peer);
            }
            let blocked = Socks5UdpAssociation::connect("127.0.0.1", socks_port).await?;
            let mut routed_bytes = [0; 4096];
            let mut requested_bytes = [0; 4096];
            tokio::select! {
                result = blocked.send_to_with_timeout(
                    SocksDestination::Ip(target), b"not a protocol", Duration::from_secs(1),
                ) => assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut),
                result = routed.recv_from(&mut routed_bytes) => panic!("blocked datagram reached routed socket: {result:?}"),
                result = requested.recv_from(&mut requested_bytes) => panic!("datagram bypassed routing: {result:?}"),
            }
            assert_eq!(
                exchange(&allowed, target, &routed, b"media after rejected sibling", fixed).await?,
                peer
            );
            assert_eq!(
                requested.try_recv_from(&mut requested_bytes).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            assert_eq!(
                routed.try_recv_from(&mut routed_bytes).unwrap_err().kind(),
                io::ErrorKind::WouldBlock,
                "unexpected replay or rejected datagram"
            );
        }
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn anytls_fixed_udp_classifies_and_pins_routes() -> TestResult {
    check_protocol_routes(Carrier::AnyTls, true).await
}

#[tokio::test]
async fn anytls_packet_udp_classifies_and_pins_routes() -> TestResult {
    check_protocol_routes(Carrier::AnyTls, false).await
}

#[tokio::test]
async fn h2mux_fixed_udp_classifies_and_pins_routes() -> TestResult {
    check_protocol_routes(Carrier::H2Mux, true).await
}

#[tokio::test]
async fn h2mux_packet_udp_classifies_and_pins_routes() -> TestResult {
    check_protocol_routes(Carrier::H2Mux, false).await
}
