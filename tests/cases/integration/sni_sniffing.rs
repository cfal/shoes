use shoes_test_support::port_helper::PortHelper;
use shoes_test_support::test_fixture::start_shoes_server;
use std::{io, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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
