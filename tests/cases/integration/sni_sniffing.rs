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
    hello_with_sni(true)
}

fn hello_with_sni(sni: bool) -> Vec<u8> {
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    config.enable_sni = sni;
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
async fn nested_tls_connect_inherits_fake_dns_and_sniff_but_uses_child_rules() -> io::Result<()> {
    use serde_json::json;
    timeout(Duration::from_secs(20), async {
        let cert = rcgen::generate_simple_self_signed(vec!["outer.example".into(), "sniff.invalid".into()]).map_err(io::Error::other)?;
        let files = tempfile::tempdir()?;
        let cert_path = files.path().join("cert.pem");
        let key_path = files.path().join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem())?;
        std::fs::write(&key_path, cert.signing_key.serialize_pem())?;
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).map_err(io::Error::other)?;
        let client_tls = rustls::ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions().unwrap()
            .with_root_certificates(roots).with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls));
        let server_tls = rustls::ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap()
            .with_no_client_auth().with_single_cert(vec![cert.cert.der().clone()], rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into()).map_err(io::Error::other)?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));
        for fake in [false, true] {
            let exit = TcpListener::bind("0.0.0.0:0").await?;
            let mut ports = PortHelper::new();
            let (_, port) = ports.get_localhost_listener_port();
            let config = json!([
                {"client_group":"exit", "client_proxies":[{"address":format!("127.0.0.1:{}", exit.local_addr()?.port()), "protocol":{"type":"socks"}}]},
                {"address":format!("0.0.0.0:{port}"), "sniff":true,
                 "dns":{"fake_ip":fake, "servers":"udp://127.0.0.1:9"},
                 "rules":[{"mask":"0.0.0.0/0", "action":"block"}],
                 "protocol":{"type":"tls", "tls_targets":{"outer.example":{
                     "cert":cert_path, "key":key_path, "protocol":{"type":"http"},
                     "override_rules":[{"mask":"sniff.invalid", "client_chain":"exit"}]
                 }}}}
            ]);
            let (_process, _config) = start_shoes_server(&config.to_string())?;
            ports.wait_for_all_ports().await?;
            let target = if fake {
                let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
                let mut dns = connector.connect("outer.example".try_into().unwrap(), tcp).await?;
                dns.write_all(b"CONNECT dns.invalid:53 HTTP/1.1\r\nHost: dns.invalid:53\r\n\r\n").await?;
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") { headers.push(dns.read_u8().await?); }
                assert!(headers.starts_with(b"HTTP/1.1 200"));
                dns.write_all(&dns_query(88, false)).await?;
                let length = dns.read_u16().await?;
                let mut bytes = vec![0; length as usize];
                dns.read_exact(&mut bytes).await?;
                let reply = Message::from_vec(&bytes).map_err(io::Error::other)?;
                assert_eq!(reply.metadata.id, 88);
                let RData::A(ip) = reply.answers[0].data else { panic!("missing fake address") };
                dns.shutdown().await?;
                format!("{}:443", ip.0)
            } else { "192.0.2.9:443".into() };
            let upstream = async {
                let (mut stream, _) = exit.accept().await?;
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting).await?;
                assert_eq!(greeting, [5, 1, 0]);
                stream.write_all(&[5, 0]).await?;
                let mut header = [0; 4];
                stream.read_exact(&mut header).await?;
                assert_eq!(&header[..3], &[5, 1, 0]);
                if fake {
                    assert_eq!(header[3], 3);
                    let len = stream.read_u8().await?;
                    let mut name = vec![0; len as usize];
                    stream.read_exact(&mut name).await?;
                    assert_eq!(name, b"restored.invalid");
                } else {
                    assert_eq!(header[3], 1);
                    let mut ip = [0; 4];
                    stream.read_exact(&mut ip).await?;
                    assert_eq!(ip, [192, 0, 2, 9]);
                }
                assert_eq!(stream.read_u16().await?, 443);
                stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                let mut tls = acceptor.accept(stream).await?;
                assert_eq!(tls.get_ref().1.server_name(), Some("sniff.invalid"));
                let mut payload = [0; 12];
                tls.read_exact(&mut payload).await?;
                assert_eq!(&payload, b"nested hello");
                tls.write_all(b"nested reply").await?;
                tls.shutdown().await
            };
            let client = async {
                let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
                let mut outer = connector.connect("outer.example".try_into().unwrap(), tcp).await?;
                outer.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes()).await?;
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") { headers.push(outer.read_u8().await?); }
                assert!(headers.starts_with(b"HTTP/1.1 200"));
                let mut inner = connector.connect("sniff.invalid".try_into().unwrap(), outer).await?;
                inner.write_all(b"nested hello").await?;
                let mut response = [0; 12];
                inner.read_exact(&mut response).await?;
                assert_eq!(&response, b"nested reply");
                inner.shutdown().await
            };
            tokio::try_join!(upstream, client)?;
        }
        Ok(())
    }).await?
}

#[tokio::test]
async fn fake_dns_sniff_routes_without_rewriting_restored_targets() -> io::Result<()> {
    use super::plain_tcp_relay::{request_to, send_request_to};

    timeout(Duration::from_secs(30), async {
        for protocol in ["socks", "http"] {
            for (sniff, kind, pipelined) in [
                (false, "tls", true),
                (true, "tls", true),
                (true, "tls", false),
                (true, "plain", true),
                (true, "plain", false),
                (true, "no-sni", true),
                (true, "no-sni", false),
                (true, "partial", false),
                (true, "server-first", false),
                (true, "supplied-hostname", false),
            ] {
                let exit = TcpListener::bind("0.0.0.0:0").await?;
                let exit_port = exit.local_addr()?.port();
                let real_dns = UdpSocket::bind("0.0.0.0:0").await?;
                let dns_port = real_dns.local_addr()?.port();
                let mut ports = PortHelper::new();
                let (_, port) = ports.get_localhost_listener_port();
                let (restored_action, sniff_action) = if sniff && kind == "tls" {
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
                let payload = match kind {
                    "tls" | "supplied-hostname" => hello(),
                    "no-sni" => hello_with_sni(false),
                    "partial" => hello()[..5].to_vec(),
                    _ => b"not TLS".to_vec(),
                };
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
                    if kind == "supplied-hostname" {
                        if protocol == "http" {
                            client.write_all(b"CONNECT restored.invalid:443 HTTP/1.1\r\nHost: restored.invalid:443\r\n\r\n").await?;
                            let mut headers = Vec::new();
                            while !headers.ends_with(b"\r\n\r\n") {
                                headers.push(client.read_u8().await?);
                            }
                            assert!(headers.starts_with(b"HTTP/1.1 200"));
                        } else {
                            client.write_all(&[5, 1, 0]).await?;
                            let mut method = [0; 2];
                            client.read_exact(&mut method).await?;
                            assert_eq!(method, [5, 0]);
                            client.write_all(b"\x05\x01\x00\x03\x10restored.invalid\x01\xbb").await?;
                            let mut reply = [0; 10];
                            client.read_exact(&mut reply).await?;
                            assert_eq!(&reply[..4], &[5, 0, 0, 1]);
                        }
                    } else {
                        request_to(
                            &mut client,
                            protocol,
                            fake_target,
                            if pipelined { &payload } else { &[] },
                        )
                        .await?;
                    }
                    if !pipelined && kind != "server-first" {
                        client.write_all(&payload).await?;
                    }
                    let mut response = Vec::new();
                    if matches!(kind, "server-first" | "partial") {
                        response.resize(8, 0);
                        client.read_exact(&mut response).await?;
                        assert_eq!(response, b"greeting");
                        if kind == "server-first" {
                            client.write_all(&payload).await?;
                        }
                    }
                    client.shutdown().await?;
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
