use super::test_io::H2Writes;
use super::*;
use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::h2mux::{MUX_DESTINATION_HOST, MUX_DESTINATION_PORT};
use crate::socks_handler::SocksTcpClientHandler;
use crate::tcp::tcp_handler::TcpClientHandler;
use crate::uuid_util::parse_uuid;
use shoes_test_support::port_helper::PortHelper;
use shoes_test_support::test_fixture::{SingBoxCapability, start_singbox_server_with};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

const TEST_UUID: &str = "a3482e88-686a-4a58-8126-99c9034e4b09";

async fn open_stream(
    socks_port: u16,
    destination: &NetLocation,
) -> io::Result<Box<dyn AsyncStream>> {
    let transport = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, socks_port)).await?;
    let result = SocksTcpClientHandler::new(None)
        .setup_client_tcp_stream(Box::new(transport), destination.clone().into())
        .await?;
    assert!(result.early_data.is_none());
    Ok(result.client_stream)
}

async fn echo(stream: &mut Box<dyn AsyncStream>, payload: &[u8]) -> io::Result<()> {
    stream.write_all(payload).await?;
    stream.flush().await?;
    let mut response = vec![0; payload.len()];
    stream.read_exact(&mut response).await?;
    assert_eq!(response, payload);
    Ok(())
}

async fn finish(stream: &mut Box<dyn AsyncStream>) -> io::Result<()> {
    stream.shutdown().await?;
    assert_eq!(stream.read(&mut [0]).await?, 0);
    Ok(())
}

// The endpoint uses Shoes' mux codecs and stream handling but owns the h2 driver
// so it can request graceful retirement without a production test hook.
async fn serve_carrier(
    mut transport: TcpStream,
    carrier_id: usize,
    destination: NetLocation,
    streams: mpsc::Sender<usize>,
    mut retire: Option<oneshot::Receiver<()>>,
    writes: H2Writes,
) -> io::Result<()> {
    let hostname = MUX_DESTINATION_HOST.as_bytes();
    let mut expected = vec![0];
    expected.extend_from_slice(&parse_uuid(TEST_UUID).unwrap());
    expected.extend_from_slice(&[0, 1]);
    expected.extend_from_slice(&MUX_DESTINATION_PORT.to_be_bytes());
    expected.extend_from_slice(&[2, hostname.len() as u8]);
    expected.extend_from_slice(hostname);
    let mut header = vec![0; expected.len()];
    transport.read_exact(&mut header).await?;
    assert_eq!(header, expected);
    transport.write_all(&[0, 0]).await?;
    assert_eq!(
        SessionRequest::decode(&mut transport).await?,
        SessionRequest::new(MuxProtocol::H2Mux, true)
    );
    let mut connection = h2::server::handshake(writes.wrap(H2MuxPaddingStream::new(transport)))
        .await
        .map_err(io::Error::other)?;
    let (inbound_tx, mut inbound_rx) = mpsc::channel::<InboundStream>(8);
    let slots = Arc::new(crate::resources::Budget::new(None));
    let mut tasks = JoinSet::new();
    let mut retiring = false;
    loop {
        tokio::select! {
            command = async { retire.as_mut().unwrap().await }, if retire.is_some() => {
                command.map_err(io::Error::other)?;
                retire = None;
                retiring = true;
                connection.graceful_shutdown();
            }
            request = connection.accept() => {
                let Some(request) = request else { break };
                let (request, respond) = match request {
                    Ok(request) => request,
                    // sing-mux closes on the first GOAWAY without draining the
                    // following PING, which can reset TCP on the server side.
                    Err(error) if retiring && error.get_io().is_some_and(|error| matches!(
                        error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                    )) => break,
                    Err(error) => return Err(io::Error::other(error)),
                };
                tasks.spawn(H2MuxServerSession::handle_stream(
                    request, respond, inbound_tx.clone(), slots.clone(),
                ));
            }
            inbound = inbound_rx.recv() => {
                let mut inbound = inbound.unwrap();
                assert_eq!(inbound.request.destination, destination);
                assert!(!inbound.request.is_udp());
                streams.send(carrier_id).await.map_err(io::Error::other)?;
                tasks.spawn(async move {
                    let mut data = [0; 8192];
                    loop {
                        let length = inbound.stream.read(&mut data).await?;
                        if length == 0 {
                            return inbound.stream.shutdown().await;
                        }
                        inbound.stream.write_all(&data[..length]).await?;
                        inbound.stream.flush().await?;
                    }
                });
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                result.unwrap().map_err(io::Error::other)??;
            }
        }
    }
    while let Some(result) = tasks.join_next().await {
        result.map_err(io::Error::other)??;
    }
    Ok(())
}

#[tokio::test]
async fn sing_box_padded_goaway_replaces_and_reuses_carrier()
-> Result<(), Box<dyn std::error::Error>> {
    timeout(Duration::from_secs(30), async {
        let listener = TcpListener::bind("0.0.0.0:0").await?;
        let carrier_port = listener.local_addr()?.port();
        let mut ports = PortHelper::new();
        let (_, socks_port) = ports.get_localhost_listener_port();
        let destination = NetLocation::from_str("echo.test:1234", None)?;
        let config = serde_json::json!({
            "log": {"level": "warn"},
            "inbounds": [{"type": "socks", "listen": "0.0.0.0", "listen_port": socks_port}],
            "outbounds": [{
                "type": "vless", "server": "127.0.0.1", "server_port": carrier_port,
                "uuid": TEST_UUID,
                "multiplex": {
                    "enabled": true, "protocol": "h2mux", "max_connections": 1, "padding": true
                }
            }]
        });
        let (_singbox, _config) =
            start_singbox_server_with(&config.to_string(), SingBoxCapability::Standard, &[])?;
        ports.wait_for_all_ports().await?;

        let (retire_tx, retire_rx) = oneshot::channel();
        let (streams_tx, mut streams_rx) = mpsc::channel(8);
        let (closed_tx, mut closed_rx) = mpsc::channel(2);
        let server_destination = destination.clone();
        let first_writes = H2Writes::default();
        let captured_writes = first_writes.clone();
        let mut server = JoinSet::<io::Result<()>>::new();
        server.spawn(async move {
            let mut sessions = JoinSet::new();
            let mut retire_rx = Some(retire_rx);
            let mut carriers = 0;
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (transport, _) = accepted?;
                        let id = carriers;
                        carriers += 1;
                        assert!(carriers <= 2, "unexpected third carrier");
                        let destination = server_destination.clone();
                        let streams = streams_tx.clone();
                        let retire = retire_rx.take();
                        let writes = if id == 0 { captured_writes.clone() } else { H2Writes::default() };
                        sessions.spawn(async move {
                            serve_carrier(transport, id, destination, streams, retire, writes).await?;
                            Ok::<_, io::Error>(id)
                        });
                    }
                    result = sessions.join_next(), if !sessions.is_empty() => {
                        let id = result.unwrap().map_err(io::Error::other)??;
                        closed_tx.send(id).await.map_err(io::Error::other)?;
                    }
                }
            }
        });

        let mut original = open_stream(socks_port, &destination).await?;
        echo(&mut original, b"before GOAWAY").await?;
        assert_eq!(streams_rx.recv().await, Some(0));
        // sing-mux closes the entire carrier on GOAWAY, so completed work is
        // retired before checking recovery. Active-stream draining is tested
        // separately with an h2 peer that supports it.
        finish(&mut original).await?;
        retire_tx.send(()).unwrap();
        let closed = closed_rx.recv().await;
        if closed.is_none() {
            panic!("endpoint failed: {:?}", server.join_next().await);
        }
        assert_eq!(closed, Some(0));
        first_writes.assert_graceful_goaway();

        let mut replacement = open_stream(socks_port, &destination).await?;
        echo(&mut replacement, b"replacement carrier").await?;
        assert_eq!(streams_rx.recv().await, Some(1));
        echo(
            &mut replacement,
            b"replacement survives old carrier closure",
        )
        .await?;
        let mut reused = open_stream(socks_port, &destination).await?;
        echo(&mut reused, b"reuse replacement carrier").await?;
        assert_eq!(streams_rx.recv().await, Some(1));
        finish(&mut replacement).await?;
        finish(&mut reused).await?;
        assert!(server.try_join_next().is_none(), "endpoint failed");
        server.shutdown().await;
        Ok(())
    })
    .await?
}
