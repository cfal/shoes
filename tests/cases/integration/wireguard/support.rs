use crate::wireguard_support as config;
use serde_json::{Value, json};
use shoes_test_support::{
    port_helper::PortHelper,
    test_fixture::{ProcessGuard, start_shoes_server},
};
use std::{io, net::SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub type Process = (ProcessGuard, tempfile::NamedTempFile);

pub fn start(configs: &Value) -> io::Result<Process> {
    start_shoes_server(&serde_yaml::to_string(configs).unwrap())
}

pub fn target(ipv6: bool, port: u16) -> SocketAddr {
    SocketAddr::new(
        if ipv6 { "fd88::1" } else { "198.18.0.1" }.parse().unwrap(),
        port,
    )
}

pub struct Pair {
    pub entry: u16,
    _processes: Vec<Process>,
}

impl Pair {
    pub async fn start(
        detour: bool,
        configure: impl FnOnce(&mut Value, &mut Value),
    ) -> io::Result<Self> {
        let reservation = std::net::UdpSocket::bind("0.0.0.0:0")?;
        let port = reservation.local_addr()?.port();
        let mut ports = PortHelper::new();
        let (_, entry) = ports.get_localhost_listener_port();
        let mut server = config::server(port);
        let mut client = config::client(port);
        let mut servers = Vec::new();
        if detour {
            let (_, outer) = ports.get_localhost_listener_port();
            let protocol = config::vless_protocol();
            client["client_proxies"][0]["address"] = json!(format!("192.0.2.200:{port}"));
            client["client_proxies"][0]["protocol"]["peer_client_chain"] = json!([{
                "address": format!("127.0.0.1:{outer}"), "protocol": protocol,
            }]);
            servers.push(json!({
                "address": format!("0.0.0.0:{outer}"), "protocol": protocol,
                "rules": [{"masks": "192.0.2.200/32", "action": "allow", "override_address": "127.0.0.1:0"}],
            }));
        }
        configure(&mut server, &mut client);
        servers.push(server);
        drop(reservation);
        let server = start(&json!(servers))?;
        let client = start(&json!([client, config::socks(entry)]))?;
        ports.wait_for_all_ports().await?;
        Ok(Self {
            entry,
            _processes: vec![client, server],
        })
    }
}

pub async fn exchange(stream: &mut tokio::net::TcpStream, bytes: &[u8]) -> io::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        stream.write_all(bytes).await?;
        let mut reply = vec![0; bytes.len()];
        stream.read_exact(&mut reply).await?;
        assert_eq!(reply, bytes);
        io::Result::Ok(())
    })
    .await?
}

// Bounded WireGuard queues may drop datagrams under load or during a handshake.
pub async fn udp_echo(
    association: &shoes_test_support::socks5::Socks5UdpAssociation,
    destination: SocketAddr,
    payload: &[u8],
) -> io::Result<()> {
    use shoes_test_support::socks5::SocksDestination;
    use std::time::Duration;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match association
                .send_to_with_timeout(
                    SocksDestination::Ip(destination),
                    payload,
                    Duration::from_millis(250),
                )
                .await
            {
                Ok(reply) => {
                    assert_eq!(reply, payload);
                    return Ok(());
                }
                Err(error) if error.kind() == io::ErrorKind::TimedOut => {}
                Err(error) => return Err(error),
            }
        }
    })
    .await?
}
