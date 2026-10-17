use crate::wireguard_support as config;
use serde_json::json;
use shoes_test_support::{
    port_helper::PortHelper, test_fixture::start_shoes_server, wireguard::EchoTargets,
};

#[tokio::test]
async fn wireguard_server_client_tcp_udp_and_stream_chain() -> std::io::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let reservation = std::net::UdpSocket::bind("0.0.0.0:0")?;
        let port = reservation.local_addr()?.port();
        let mut ports = PortHelper::new();
        let (_, proxy) = ports.get_localhost_listener_port();
        let protocol = config::vless_protocol();
        let server = json!([
            config::server(port),
            {"address": format!("0.0.0.0:{proxy}"), "protocol": protocol}
        ]);
        drop(reservation);
        let _server = start_shoes_server(&serde_yaml::to_string(&server).unwrap())?;
        for chain in [false, true] {
            let (_, entry) = ports.get_localhost_listener_port();
            let mut entry_config = config::socks(entry);
            if chain {
                entry_config["rules"][0]["client_chain"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"address": format!("127.0.0.1:{proxy}"), "protocol": protocol}));
            }
            let _client = start_shoes_server(
                &serde_yaml::to_string(&json!([config::client(port), entry_config])).unwrap(),
            )?;
            ports.wait_for_all_ports().await?;
            for ipv6 in [false, true] {
                EchoTargets::new(ipv6).await?.check(entry, None).await?;
            }
        }
        Ok(())
    })
    .await?
}
