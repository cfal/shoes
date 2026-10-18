use super::support::{Pair, target};
use serde_json::json;
use shoes_test_support::{
    socks5::Socks5UdpAssociation,
    wireguard::{EchoTargets, connect},
};
use std::{io, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::timeout,
};

#[tokio::test]
async fn denied_routes_families_and_unavailable_peers_never_reach_local_targets() -> io::Result<()>
{
    timeout(Duration::from_secs(180), async {
        for failure in ["rule", "route", "family", "peer", "inbound"] {
            for ipv6 in [false, true] {
                let bind = if ipv6 { "[::]:0" } else { "0.0.0.0:0" };
                let protected_tcp = TcpListener::bind(bind).await?;
                let protected_udp = UdpSocket::bind(bind).await?;
                let ip = if ipv6 { "::1" } else { "127.0.0.1" }.parse().unwrap();
                let tcp = SocketAddr::new(ip, protected_tcp.local_addr()?.port());
                let udp = SocketAddr::new(ip, protected_udp.local_addr()?.port());
                let blackhole = UdpSocket::bind("0.0.0.0:0").await?;
                let pair = Pair::start(false, |server, client| match failure {
                    "rule" => server["rules"].as_array_mut().unwrap().insert(0, json!({
                        "masks": [tcp.to_string(), udp.to_string()], "action": "block",
                    })),
                    "route" => client["client_proxies"][0]["protocol"]["allowed_ips"] = json!(["10.77.0.1/32", "fd77::1/128"]),
                    "family" => client["client_proxies"][0]["protocol"]["addresses"] = if ipv6 { json!(["10.77.0.2/32"]) } else { json!(["fd77::2/128"]) },
                    "peer" => client["client_proxies"][0]["address"] = json!(blackhole.local_addr().unwrap().to_string()),
                    "inbound" => server["rules"] = json!("block-all"),
                    _ => unreachable!(),
                }).await?;
                if failure == "rule" {
                    EchoTargets::new(ipv6).await?.check(pair.entry, Some(target(ipv6, 0).ip())).await?;
                }
                // Both targets are reachable without the tunnel, making fallback observable.
                let direct = tokio::net::TcpStream::connect(tcp).await?;
                let _accepted = protected_tcp.accept().await?;
                drop(direct);
                let probe = UdpSocket::bind(bind).await?;
                probe.send_to(b"control", udp).await?;
                protected_udp.recv_from(&mut [0; 64]).await?;
                let association = Socks5UdpAssociation::connect("127.0.0.1", pair.entry).await?;
                let attempt = async {
                    let deadline = if matches!(failure, "peer" | "inbound") {
                        Duration::from_secs(35)
                    } else {
                        Duration::from_secs(3)
                    };
                    // Waiting through the handshake deadline also catches delayed fallback.
                    let result = timeout(deadline, connect(pair.entry, tcp)).await.expect("TCP admission did not terminate");
                    if let Ok(mut stream) = result {
                        let _ = stream.write_all(b"forbidden").await;
                        assert!(!matches!(timeout(Duration::from_millis(750), stream.read(&mut [0; 16])).await, Ok(Ok(1..))), "{failure}, ipv6={ipv6}");
                    }
                    assert!(timeout(Duration::from_millis(750), association.send_to(udp, b"forbidden")).await.is_err());
                    io::Result::Ok(())
                };
                let mut buffer = [0; 64];
                tokio::select! {
                    result = attempt => result?,
                    result = protected_tcp.accept() => panic!("TCP leaked: {failure}, ipv6={ipv6}: {result:?}"),
                    result = protected_udp.recv_from(&mut buffer) => panic!("UDP leaked: {failure}, ipv6={ipv6}: {result:?}"),
                }
            }
        }
        Ok(())
    }).await?
}
