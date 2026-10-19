use hickory_resolver::proto::op::{Edns, Message, Query, ResponseCode};
use hickory_resolver::proto::rr::rdata::opt::EdnsOption;
use hickory_resolver::proto::rr::{Name, RData, RecordType};
use shoes_test_support::port_helper::PortHelper;
use shoes_test_support::test_fixture::start_shoes_server;
use std::{io, net::SocketAddrV4, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

fn hello() -> Vec<u8> {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    let mut client =
        rustls::ClientConnection::new(Arc::new(config), "sniff.invalid".try_into().unwrap())
            .unwrap();
    let mut bytes = Vec::new();
    client.write_tls(&mut bytes).unwrap();
    bytes
}

fn dns_query(id: u16, max_frame: bool) -> Vec<u8> {
    let mut query = Message::query();
    query.metadata.id = id;
    query.add_query(Query::query(
        Name::from_ascii("restored.invalid.").unwrap(),
        RecordType::A,
    ));
    if max_frame {
        let mut edns = Edns::new();
        edns.options_mut().insert(EdnsOption::Unknown(12, vec![]));
        query.edns = Some(edns);
        let padding = u16::MAX as usize - query.to_vec().unwrap().len();
        let options = query.edns.as_mut().unwrap().options_mut();
        options.remove(12.into());
        options.insert(EdnsOption::Unknown(12, vec![0; padding]));
    }
    let payload = query.to_vec().unwrap();
    if max_frame {
        assert_eq!(payload.len(), 65_535);
    }
    let mut framed = (payload.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&payload);
    framed
}

#[tokio::test]
async fn fake_dns_sniff_routes_without_rewriting_restored_targets() -> io::Result<()> {
    use super::plain_tcp_relay::{request_to, send_request_to};

    timeout(Duration::from_secs(30), async {
        for protocol in ["socks", "http"] {
            for (sniff, tls, pipelined) in [
                (false, true, true),
                (true, true, true),
                (true, true, false),
                (true, false, true),
                (true, false, false),
            ] {
                let exit = TcpListener::bind("0.0.0.0:0").await?;
                let exit_port = exit.local_addr()?.port();
                let real_dns = UdpSocket::bind("0.0.0.0:0").await?;
                let dns_port = real_dns.local_addr()?.port();
                let mut ports = PortHelper::new();
                let (_, port) = ports.get_localhost_listener_port();
                let (restored_action, sniff_action) = if sniff && tls {
                    ("action: block", "client_chain: exit")
                } else {
                    ("client_chain: exit", "action: block")
                };
                let (_process, _config) = start_shoes_server(&format!(
                    r#"
- client_group: exit
  client_proxies:
    - address: '127.0.0.1:{exit_port}'
      protocol: {{type: socks}}
- address: '0.0.0.0:{port}'
  protocol: {{type: {protocol}}}
  sniff: {sniff}
  dns:
    fake_ip: {{ipv4_range: '198.18.0.0/24', max_entries: 64}}
    servers: 'udp://127.0.0.1:{dns_port}'
  rules:
    - masks: '0.0.0.0/0:53'
      action: block
    - masks: restored.invalid
      {restored_action}
    - masks: sniff.invalid
      {sniff_action}
    - masks: '0.0.0.0/0'
      action: block
"#
                ))?;
                ports.wait_for_all_ports().await?;

                let unknown: SocketAddrV4 = "198.18.0.250:443".parse().unwrap();
                for prefix in [Vec::new(), hello()] {
                    let mut client = TcpStream::connect(("127.0.0.1", port)).await?;
                    send_request_to(&mut client, protocol, unknown, &prefix).await?;
                    let mut reply = Vec::new();
                    let result = client.read_to_end(&mut reply).await;
                    if let Err(error) = result {
                        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
                    }
                    assert!(
                        reply.is_empty(),
                        "unknown fake address received an optimistic reply"
                    );
                }

                // The same unknown address at port 53 must dispatch locally before restoration or rules.
                let mut dns = TcpStream::connect(("127.0.0.1", port)).await?;
                request_to(
                    &mut dns,
                    protocol,
                    SocketAddrV4::new(*unknown.ip(), 53),
                    &[],
                )
                .await?;
                let first = dns_query(41, false);
                dns.write_all(&first[..1]).await?;
                for chunk in first[1..].chunks(3) {
                    dns.write_all(chunk).await?;
                }
                dns.write_all(&dns_query(42, true)).await?;
                let mut fake_ip = None;
                for id in [41, 42] {
                    let length = dns.read_u16().await?;
                    let mut response = vec![0; length as usize];
                    dns.read_exact(&mut response).await?;
                    let response = Message::from_vec(&response).map_err(io::Error::other)?;
                    assert_eq!(response.metadata.id, id);
                    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
                    assert_eq!(response.answers.len(), 1);
                    let RData::A(ip) = &response.answers[0].data else {
                        panic!("missing synthesized A record")
                    };
                    assert_eq!(ip.0.octets()[..2], [198, 18]);
                    if let Some(previous) = fake_ip {
                        assert_eq!(previous, ip.0);
                    }
                    fake_ip = Some(ip.0);
                }
                dns.shutdown().await?;
                let fake_target = SocketAddrV4::new(fake_ip.unwrap(), 443);
                let payload = if tls { hello() } else { b"not TLS".to_vec() };
                let expected = payload.clone();
                let upstream = async {
                    let (mut socket, _) = exit.accept().await?;
                    let mut greeting = [0; 3];
                    socket.read_exact(&mut greeting).await?;
                    assert_eq!(greeting, [5, 1, 0]);
                    socket.write_all(&[5, 0]).await?;
                    let mut header = [0; 4];
                    socket.read_exact(&mut header).await?;
                    assert_eq!(header, [5, 1, 0, 3]);
                    let length = socket.read_u8().await?;
                    let mut hostname = vec![0; length as usize];
                    socket.read_exact(&mut hostname).await?;
                    assert_eq!(hostname, b"restored.invalid");
                    assert_eq!(socket.read_u16().await?, 443);
                    socket
                        .write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00greeting")
                        .await?;
                    let mut received = Vec::new();
                    socket.read_to_end(&mut received).await?;
                    assert_eq!(received, expected);
                    socket.write_all(b"after half-close").await?;
                    socket.shutdown().await
                };
                let client = async {
                    let mut client = TcpStream::connect(("127.0.0.1", port)).await?;
                    request_to(
                        &mut client,
                        protocol,
                        fake_target,
                        if pipelined { &payload } else { &[] },
                    )
                    .await?;
                    if !pipelined {
                        client.write_all(&payload).await?;
                    }
                    client.shutdown().await?;
                    let mut response = Vec::new();
                    client.read_to_end(&mut response).await?;
                    assert_eq!(response, b"greetingafter half-close");
                    io::Result::Ok(())
                };
                tokio::try_join!(upstream, client)?;
                assert!(
                    timeout(Duration::from_millis(20), real_dns.recv(&mut [0; 512]))
                        .await
                        .is_err()
                );
            }
        }
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn listener_config_enables_route_only_sniffing_for_gated_and_pipelined_clients()
-> io::Result<()> {
    timeout(Duration::from_secs(30), async {
        for protocol in ["socks", "http"] {
            for (sniff, pipelined) in [(None, false), (Some(false), false), (Some(true), false), (Some(true), true)] {
                let target = TcpListener::bind("0.0.0.0:0").await?;
                let target_port = target.local_addr()?.port();
                let mut ports = PortHelper::new();
                let (_, port) = ports.get_localhost_listener_port();
                let setting = sniff.map(|value| format!("  sniff: {value}\n")).unwrap_or_default();
                let (_process, _config) = start_shoes_server(&format!(
                    "- address: '0.0.0.0:{port}'\n  protocol: {{type: {protocol}}}\n{setting}  rules:\n    - masks: sniff.invalid\n      action: allow\n",
                ))?;
                ports.wait_for_all_ports().await?;
                let bytes = hello();
                let mut client = TcpStream::connect(("127.0.0.1", port)).await?;
                let result = super::plain_tcp_relay::request(
                    &mut client, protocol, target_port, if pipelined { &bytes } else { &[] },
                ).await;
                if sniff != Some(true) {
                    assert!(result.is_err(), "disabled sniff unexpectedly matched a hostname rule");
                    assert!(timeout(Duration::from_millis(20), target.accept()).await.is_err());
                    continue;
                }
                result?;
                if !pipelined { client.write_all(&bytes).await?; }
                client.write_all(b"tail").await?;
                client.shutdown().await?;
                let (mut upstream, _) = target.accept().await?;
                let mut received = Vec::new();
                upstream.read_to_end(&mut received).await?;
                let mut expected = bytes;
                expected.extend_from_slice(b"tail");
                assert_eq!(received, expected);
                upstream.write_all(b"after half-close").await?;
                upstream.shutdown().await?;
                let mut response = Vec::new();
                client.read_to_end(&mut response).await?;
                assert_eq!(response, b"after half-close");
            }
        }
        Ok(())
    }).await?
}
