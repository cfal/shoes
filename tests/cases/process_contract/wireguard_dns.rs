use crate::{Process, wireguard_support as config};
use hickory_resolver::proto::{
    op::{Message, MessageType},
    rr::{RData, Record, rdata::A},
};
use serde_json::json;
use shoes_test_support::{
    port_helper::PortHelper,
    socks5::{Socks5UdpAssociation, SocksDestination},
    wireguard::EchoTargets,
};
use std::{io, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
    task::JoinSet,
    time::timeout,
};

struct DnsPeer {
    port: u16,
    queries: mpsc::UnboundedReceiver<String>,
    closed: mpsc::UnboundedReceiver<Vec<String>>,
    task: tokio_util::task::AbortOnDropHandle<()>,
}

async fn serve_dns_connection(
    mut stream: TcpStream,
    queries: mpsc::UnboundedSender<String>,
    closed: mpsc::UnboundedSender<Vec<String>>,
) {
    let mut names = Vec::new();
    while let Ok(length) = stream.read_u16().await {
        let mut bytes = vec![0; length as usize];
        if stream.read_exact(&mut bytes).await.is_err() {
            break;
        }
        let mut message = Message::from_vec(&bytes).unwrap();
        let name = message.queries[0].name().to_string();
        queries.send(name.clone()).unwrap();
        names.push(name);
        message.metadata.message_type = MessageType::Response;
        message.add_answer(Record::from_rdata(
            message.queries[0].name().clone(),
            0,
            RData::A(A::new(198, 18, 0, 1)),
        ));
        let bytes = message.to_vec().unwrap();
        if stream.write_u16(bytes.len() as u16).await.is_err()
            || stream.write_all(&bytes).await.is_err()
        {
            break;
        }
    }
    let _ = closed.send(names);
}

impl DnsPeer {
    async fn start() -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let (query_tx, query_rx) = mpsc::unbounded_channel();
        let (closed_tx, closed_rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        connections.spawn(serve_dns_connection(
                            stream,
                            query_tx.clone(),
                            closed_tx.clone(),
                        ));
                    }
                    result = connections.join_next(), if !connections.is_empty() => {
                        result.unwrap().unwrap();
                    }
                }
            }
        });
        Ok(Self {
            port,
            queries: query_rx,
            closed: closed_rx,
            task: tokio_util::task::AbortOnDropHandle::new(task),
        })
    }

    async fn wait_closed(&mut self, query: &str) -> io::Result<()> {
        timeout(Duration::from_secs(5), async {
            loop {
                let names = self.closed.recv().await.expect("DNS responder stopped");
                if names.iter().any(|name| name == query) {
                    break;
                }
            }
        })
        .await?;
        Ok(())
    }
}

#[tokio::test]
async fn wireguard_dns_reload_uses_the_new_resolver_and_outages_never_bypass_the_tunnel()
-> io::Result<()> {
    timeout(Duration::from_secs(60), async {
        let mut old_dns = DnsPeer::start().await?;
        let mut new_dns = DnsPeer::start().await?;
        let forbidden_tcp = TcpListener::bind(("::1", new_dns.port)).await?;
        let forbidden_udp = UdpSocket::bind(("::1", new_dns.port)).await?;
        let reservation = std::net::UdpSocket::bind("0.0.0.0:0")?;
        let port = reservation.local_addr()?.port();
        let mut ports = PortHelper::new();
        let (_, entry) = ports.get_localhost_listener_port();
        let directory = tempfile::tempdir()?;
        let server_path = directory.path().join("server.yaml");
        let client_path = directory.path().join("client.yaml");
        let mut server_config = config::server(port);
        server_config["rules"].as_array_mut().unwrap().insert(
            0,
            json!({
                "masks": "::1/128",
                "action": "allow",
                "override_address": "127.0.0.1:0",
            }),
        );
        std::fs::write(
            &server_path,
            serde_yaml::to_string(&json!([server_config])).unwrap(),
        )?;
        let mut socks = config::socks(entry);
        socks["dns"] = json!({"servers": "tunneled"});
        let client_config = |dns_port| {
            json!([
                config::client(port),
                socks,
                {
                    "dns_group": "tunneled",
                    "dns_servers": [{
                        "url": format!("tcp://[::1]:{dns_port}"),
                        "ip_strategy": "ipv4_only",
                        "timeout_secs": 1,
                        "connect_timeout_secs": 1,
                        "attempts": 1,
                        "client_chain": "wg",
                    }],
                },
            ])
        };
        std::fs::write(
            &client_path,
            serde_yaml::to_string(&client_config(old_dns.port)).unwrap(),
        )?;
        drop(reservation);
        let mut server = Process::start(&server_path, &["--no-reload"]);
        let mut client = Process::start(&client_path, &["--no-reload"]);
        server.wait_for("Servers ready").await;
        client.wait_for("Servers ready").await;
        let echo = EchoTargets::new(false).await?;
        let association = Socks5UdpAssociation::connect("127.0.0.1", entry).await?;
        assert_eq!(
            association
                .send_to_hostname("before.wireguard.test", echo.udp().port(), b"before")
                .await?,
            b"before"
        );
        assert_eq!(old_dns.queries.recv().await.unwrap(), "before.wireguard.test.");
        drop(association);

        std::fs::write(
            &client_path,
            serde_yaml::to_string(&client_config(new_dns.port)).unwrap(),
        )?;
        client.signal(libc::SIGHUP);
        client.wait_for("Servers ready").await;
        let association = Socks5UdpAssociation::connect("127.0.0.1", entry).await?;
        assert_eq!(
            association
                .send_to_hostname("after.wireguard.test", echo.udp().port(), b"after")
                .await?,
            b"after"
        );
        assert_eq!(new_dns.queries.recv().await.unwrap(), "after.wireguard.test.");
        server.signal(libc::SIGTERM);
        assert!(server.exit().await.success());
        old_dns.wait_closed("before.wireguard.test.").await?;
        new_dns.wait_closed("after.wireguard.test.").await?;

        let denied = association.send_to_with_timeout(
            SocksDestination::Hostname("outage.wireguard.test".into(), echo.udp().port()),
            b"no bypass",
            Duration::from_secs(3),
        );
        let mut bytes = [0; 2048];
        tokio::select! {
            reply = denied => assert_eq!(reply.unwrap_err().kind(), io::ErrorKind::TimedOut),
            _ = forbidden_tcp.accept() => panic!("DNS connected directly instead of using WireGuard"),
            _ = forbidden_udp.recv_from(&mut bytes) => panic!("DNS fell back to direct UDP"),
        }
        assert!(
            timeout(Duration::from_millis(100), forbidden_tcp.accept())
                .await
                .is_err()
        );

        server = Process::start(&server_path, &["--no-reload"]);
        server.wait_for("Servers ready").await;
        client.signal(libc::SIGHUP);
        client.wait_for("Servers ready").await;
        let association = Socks5UdpAssociation::connect("127.0.0.1", entry).await?;
        assert_eq!(
            association
                .send_to_hostname("restored.wireguard.test", echo.udp().port(), b"restored")
                .await?,
            b"restored"
        );
        assert_eq!(new_dns.queries.recv().await.unwrap(), "restored.wireguard.test.");
        client.signal(libc::SIGTERM);
        assert!(client.exit().await.success());
        server.signal(libc::SIGTERM);
        assert!(server.exit().await.success());
        new_dns.wait_closed("restored.wireguard.test.").await?;
        assert!(!old_dns.task.is_finished());
        assert!(!new_dns.task.is_finished());
        Ok(())
    })
    .await?
}
