use super::support::{Pair, exchange, target};
use serde_json::json;
use shoes_test_support::{
    socks5::{Socks5UdpAssociation, SocksDestination},
    test_servers::{start_tcp_stream_echo_server, start_udp_response_server},
    wireguard::connect,
};
use std::{io, time::Duration};
use tokio::time::timeout;

#[tokio::test]
async fn udp_boundaries_asymmetric_mtu_and_oversized_responses_preserve_the_flow() -> io::Result<()>
{
    timeout(Duration::from_secs(45), async {
        for detour in [false, true] {
            for ipv6 in [false, true] {
                for (server_mtu, client_mtu) in [(1280, 1420), (1420, 1280)] {
                    let pair = Pair::start(detour, |server, client| {
                        server["protocol"]["mtu"] = json!(server_mtu);
                        client["client_proxies"][0]["protocol"]["mtu"] = json!(client_mtu);
                    }).await?;
                    let echo = start_udp_response_server(if ipv6 { "::" } else { "0.0.0.0" }, 0, |data, _| {
                        if data == b"oversized response" { vec![0xab; 1500] } else { data.to_vec() }
                    }).await?;
                    let destination = target(ipv6, echo.local_addr().port());
                    let ready = start_tcp_stream_echo_server(if ipv6 { "::" } else { "0.0.0.0" }, 0).await?;
                    let mut tcp = connect(pair.entry, target(ipv6, ready.local_addr().port())).await?;
                    exchange(&mut tcp, b"ready").await?;
                    let association = Socks5UdpAssociation::connect("127.0.0.1", pair.entry).await?;
                    let overhead = if ipv6 { 48 } else { 28 };
                    let maximum = server_mtu.min(client_mtu) - overhead;
                    // Empty SOCKS datagrams are discarded before reaching WireGuard; raw TUN tests cover them.
                    for size in [1, maximum - 1, maximum] {
                        let payload = vec![0x5a; size];
                        eprintln!("datagram: detour={detour}, ipv6={ipv6}, mtu={server_mtu}/{client_mtu}, size={size}");
                        let response = association.send_to(destination, &payload).await?;
                        assert_eq!(response, payload);
                    }
                    for payload in [vec![0xff; maximum + 1], b"oversized response".to_vec(), vec![0xff; 1500]] {
                        let error = association.send_to_with_timeout(SocksDestination::Ip(destination), &payload, Duration::from_millis(250)).await.unwrap_err();
                        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                        assert_eq!(association.send_to(destination, b"after drop").await?, b"after drop");
                    }
                }
            }
        }
        Ok(())
    }).await?
}
