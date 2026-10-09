use bytes::Bytes;
use shoes_test_support::port_helper::PortHelper;
use shoes_test_support::test_fixture::start_shoes_server;
use shoes_test_support::test_servers::start_tcp_eof_echo_server;
use shoes_test_support::vless::parse_uuid;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::timeout;

const TEST_UUID: &str = "a3482e88-686a-4a58-8126-99c9034e4b09";

#[tokio::test]
async fn first_response_survives_one_byte_credit() -> Result<(), Box<dyn std::error::Error>> {
    timeout(Duration::from_secs(30), async {
        let mut ports = PortHelper::new();
        let (_, shoes_port) = ports.get_localhost_listener_port();
        let echo = start_tcp_eof_echo_server("0.0.0.0", 0).await?;
        let config = format!(
            r#"- address: '0.0.0.0:{shoes_port}'
  protocol:
    type: vless
    user_id: '{TEST_UUID}'
"#
        );
        let (_shoes, _config) = start_shoes_server(&config)?;
        ports.wait_for_all_ports().await?;

        let mut transport = TcpStream::connect((Ipv4Addr::LOCALHOST, shoes_port)).await?;
        let hostname = b"sp.mux.sing-box.arpa";
        let mut request = vec![0];
        request.extend_from_slice(&parse_uuid(TEST_UUID)?);
        request.extend_from_slice(&[0, 1]); // No addons, TCP CONNECT.
        request.extend_from_slice(&444u16.to_be_bytes());
        request.extend_from_slice(&[2, hostname.len() as u8]);
        request.extend_from_slice(hostname);
        request.extend_from_slice(&[0, 2]); // Unpadded sing-mux v0, h2mux.
        transport.write_all(&request).await?;
        let mut vless_response = [0; 2];
        transport.read_exact(&mut vless_response).await?;
        assert_eq!(vless_response, [0, 0]);

        let (mut sender, connection) = h2::client::Builder::new()
            .initial_window_size(1)
            .handshake(transport)
            .await?;
        let mut drivers = JoinSet::new();
        drivers.spawn(connection);

        // A second stream verifies that completing the first leaves the carrier reusable.
        for payload in [b"first response".as_slice(), b"same carrier, next stream"] {
            let (response, mut body) = sender.send_request(
                http::Request::builder()
                    .uri("https://localhost/")
                    .body(())?,
                false,
            )?;
            let mut data = vec![0, 0, 1]; // TCP flags, SOCKS IPv4 destination.
            data.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
            data.extend_from_slice(&echo.local_addr().port().to_be_bytes());
            data.extend_from_slice(payload);
            body.send_data(Bytes::from(data), true)?;

            let mut response = response.await?.into_body();
            let status = response.data().await.ok_or("missing mux status")??;
            assert_eq!(&status[..], &[0]);
            response.flow_control().release_capacity(1)?;
            let mut received = Vec::new();
            while let Some(chunk) = response.data().await {
                let chunk = chunk?;
                response.flow_control().release_capacity(chunk.len())?;
                received.extend_from_slice(&chunk);
            }
            let mut expected = payload.to_vec();
            expected.extend_from_slice(b" [ECHO]");
            assert_eq!(received, expected);
        }
        drivers.shutdown().await;
        Ok(())
    })
    .await?
}
