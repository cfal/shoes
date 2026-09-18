//! Direct VLESS XUDP session and framing regressions.

use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::time::Duration;

use shoes_test_support as common;
use tempfile::NamedTempFile;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use common::process::ProcessGuard;
use common::test_fixture::{TEST_UUID, start_shoes_server};
use common::test_servers::{TestServer, start_udp_echo_server_with_suffix};
use common::vless::{
    VlessDestination, XUDP_OPTION_DATA, XUDP_OPTION_ERROR, XUDP_STATUS_END, XUDP_STATUS_KEEP,
    XUDP_STATUS_KEEPALIVE, XUDP_STATUS_NEW, XudpClient, XudpFrame, parse_uuid,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

async fn start_xudp_client() -> TestResult<(XudpClient<TcpStream>, ProcessGuard, NamedTempFile)> {
    let mut ports = common::port_helper::PortHelper::new();
    let (ip, port) = ports.get_listener_port();
    let config = format!(
        r#"
- address: "{ip}:{port}"
  protocol:
    type: vless
    user_id: "{TEST_UUID}"
    udp_enabled: true
"#
    );
    let (guard, config_file) = start_shoes_server(&config)?;
    ports.wait_for_all_ports().await?;
    let stream = TcpStream::connect((ip.as_str(), port)).await?;
    let client = XudpClient::connect(stream, parse_uuid(TEST_UUID)?).await?;
    Ok((client, guard, config_file))
}

async fn start_echo(suffix: &[u8]) -> TestResult<TestServer> {
    Ok(start_udp_echo_server_with_suffix("127.0.0.1", 0, suffix).await?)
}

fn new_frame(session_id: u16, destination: SocketAddr, payload: &[u8]) -> XudpFrame {
    XudpFrame {
        session_id,
        status: XUDP_STATUS_NEW,
        options: XUDP_OPTION_DATA,
        destination: Some(VlessDestination::Ip(destination)),
        payload: Some(payload.to_vec()),
    }
}

fn keep_frame(session_id: u16, payload: &[u8]) -> XudpFrame {
    XudpFrame {
        session_id,
        status: XUDP_STATUS_KEEP,
        options: XUDP_OPTION_DATA,
        destination: None,
        payload: Some(payload.to_vec()),
    }
}

fn targeted_keep_frame(session_id: u16, destination: SocketAddr, payload: &[u8]) -> XudpFrame {
    XudpFrame {
        session_id,
        status: XUDP_STATUS_KEEP,
        options: XUDP_OPTION_DATA,
        destination: Some(VlessDestination::Ip(destination)),
        payload: Some(payload.to_vec()),
    }
}

fn control_frame(session_id: u16, status: u8, options: u8, payload: Option<&[u8]>) -> XudpFrame {
    XudpFrame {
        session_id,
        status,
        options,
        destination: None,
        payload: payload.map(<[u8]>::to_vec),
    }
}

async fn expect_data(
    client: &mut XudpClient<TcpStream>,
    session_id: u16,
    destination: SocketAddr,
    payload: &[u8],
) -> TestResult {
    let response = client.recv_frame(Duration::from_secs(5)).await?;
    assert_eq!(response.session_id, session_id);
    assert_eq!(response.status, XUDP_STATUS_KEEP);
    assert_eq!(response.options, XUDP_OPTION_DATA);
    assert_eq!(
        response.destination,
        Some(VlessDestination::Ip(destination))
    );
    assert_eq!(response.payload.as_deref(), Some(payload));
    Ok(())
}

async fn receive_udp(socket: &UdpSocket, expected: &[u8]) -> TestResult<SocketAddr> {
    let mut buffer = [0; 65_536];
    let (length, peer) = timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await??;
    assert_eq!(&buffer[..length], expected);
    Ok(peer)
}

async fn expect_no_frame(client: &mut XudpClient<TcpStream>) -> TestResult {
    let error = client
        .recv_frame(Duration::from_millis(200))
        .await
        .expect_err("received an unexpected XUDP frame");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    Ok(())
}

#[tokio::test]
async fn session_end_is_isolated_from_other_sessions() -> TestResult {
    let socket_a = UdpSocket::bind("127.0.0.1:0").await?;
    let echo_b = start_echo(b" [B]").await?;
    let destination_a = socket_a.local_addr()?;
    let destination_b = echo_b.local_addr();
    let (mut client, _shoes, _config) = start_xudp_client().await?;

    client
        .send_frame(&new_frame(10, destination_a, b"establish-a"))
        .await?;
    let peer_a = receive_udp(&socket_a, b"establish-a").await?;
    socket_a.send_to(b"a-ready", peer_a).await?;
    expect_data(&mut client, 10, destination_a, b"a-ready").await?;

    client
        .send_frame(&new_frame(20, destination_b, b"establish-b"))
        .await?;
    expect_data(&mut client, 20, destination_b, b"establish-b [B]").await?;

    client
        .send_frame(&control_frame(10, XUDP_STATUS_END, 0, None))
        .await?;
    client.send_frame(&keep_frame(10, b"stale-a")).await?;
    client.send_frame(&keep_frame(20, b"live-b")).await?;
    expect_data(&mut client, 20, destination_b, b"live-b [B]").await?;

    let mut buffer = [0; 64];
    assert!(
        timeout(Duration::from_millis(200), socket_a.recv_from(&mut buffer))
            .await
            .is_err(),
        "closed session traffic reached its former destination"
    );

    socket_a.send_to(b"late-a", peer_a).await?;
    client
        .send_frame(&new_frame(10, destination_b, b"reopened"))
        .await?;
    expect_data(&mut client, 10, destination_b, b"reopened [B]").await?;
    client
        .send_frame(&keep_frame(10, b"new-generation"))
        .await?;
    expect_data(&mut client, 10, destination_b, b"new-generation [B]").await?;
    expect_no_frame(&mut client).await?;
    Ok(())
}

#[tokio::test]
async fn one_wire_session_routes_each_packet_to_its_destination() -> TestResult {
    let echo_a = start_echo(b" [A]").await?;
    let echo_b = start_echo(b" [B]").await?;
    let destination_a = echo_a.local_addr();
    let destination_b = echo_b.local_addr();
    let (mut client, _shoes, _config) = start_xudp_client().await?;

    client
        .send_frame(&new_frame(0, destination_a, b"new-a"))
        .await?;
    expect_data(&mut client, 0, destination_a, b"new-a [A]").await?;

    client
        .send_frame(&targeted_keep_frame(0, destination_b, b"target-b"))
        .await?;
    expect_data(&mut client, 0, destination_b, b"target-b [B]").await?;

    client.send_frame(&keep_frame(0, b"default-a")).await?;
    expect_data(&mut client, 0, destination_a, b"default-a [A]").await?;

    client
        .send_frame(&targeted_keep_frame(0, destination_b, b"again-b"))
        .await?;
    expect_data(&mut client, 0, destination_b, b"again-b [B]").await?;
    Ok(())
}

#[tokio::test]
async fn control_only_new_establishes_the_default_destination() -> TestResult {
    let echo_a = start_echo(b" [A]").await?;
    let echo_b = start_echo(b" [B]").await?;
    let destination_a = echo_a.local_addr();
    let destination_b = echo_b.local_addr();
    let (mut client, _shoes, _config) = start_xudp_client().await?;

    client
        .send_frame(&XudpFrame {
            session_id: 17,
            status: XUDP_STATUS_NEW,
            options: 0,
            destination: Some(VlessDestination::Ip(destination_a)),
            payload: None,
        })
        .await?;
    client
        .send_frame(&targeted_keep_frame(17, destination_b, b"target-b"))
        .await?;
    expect_data(&mut client, 17, destination_b, b"target-b [B]").await?;

    client.send_frame(&keep_frame(17, b"default-a")).await?;
    expect_data(&mut client, 17, destination_a, b"default-a [A]").await?;
    Ok(())
}

#[tokio::test]
async fn duplicate_new_replaces_the_previous_session_generation() -> TestResult {
    let socket_a = UdpSocket::bind("127.0.0.1:0").await?;
    let echo_b = start_echo(b" [B]").await?;
    let destination_a = socket_a.local_addr()?;
    let destination_b = echo_b.local_addr();
    let (mut client, _shoes, _config) = start_xudp_client().await?;

    client
        .send_frame(&new_frame(10, destination_a, b"old-generation"))
        .await?;
    let peer_a = receive_udp(&socket_a, b"old-generation").await?;

    client
        .send_frame(&new_frame(10, destination_b, b"replacement"))
        .await?;
    expect_data(&mut client, 10, destination_b, b"replacement [B]").await?;

    socket_a.send_to(b"late-old-generation", peer_a).await?;
    client.send_frame(&keep_frame(10, b"still-b")).await?;
    expect_data(&mut client, 10, destination_b, b"still-b [B]").await?;
    expect_no_frame(&mut client).await?;
    Ok(())
}

#[tokio::test]
async fn keepalive_frames_preserve_following_frame_boundaries() -> TestResult {
    let echo = start_echo(b" [ECHO]").await?;
    let destination = echo.local_addr();
    let (mut client, _shoes, _config) = start_xudp_client().await?;

    client
        .send_frame(&new_frame(1, destination, b"initial"))
        .await?;
    expect_data(&mut client, 1, destination, b"initial [ECHO]").await?;

    client
        .send_frame(&control_frame(1, XUDP_STATUS_KEEPALIVE, 0, None))
        .await?;
    client
        .send_frame(&control_frame(
            1,
            XUDP_STATUS_KEEPALIVE,
            XUDP_OPTION_DATA,
            Some(b"discarded-control-data"),
        ))
        .await?;
    client.send_frame(&keep_frame(1, b"after")).await?;
    expect_data(&mut client, 1, destination, b"after [ECHO]").await?;
    Ok(())
}

#[tokio::test]
async fn error_end_is_isolated_from_other_sessions() -> TestResult {
    let echo_a = start_echo(b" [A]").await?;
    let echo_b = start_echo(b" [B]").await?;
    let destination_a = echo_a.local_addr();
    let destination_b = echo_b.local_addr();
    let (mut client, _shoes, _config) = start_xudp_client().await?;

    client
        .send_frame(&new_frame(1, destination_a, b"session-a"))
        .await?;
    expect_data(&mut client, 1, destination_a, b"session-a [A]").await?;
    client
        .send_frame(&new_frame(2, destination_b, b"session-b"))
        .await?;
    expect_data(&mut client, 2, destination_b, b"session-b [B]").await?;

    client
        .send_frame(&control_frame(1, XUDP_STATUS_END, XUDP_OPTION_ERROR, None))
        .await?;
    client.send_frame(&keep_frame(2, b"still-open")).await?;
    expect_data(&mut client, 2, destination_b, b"still-open [B]").await?;
    Ok(())
}

#[tokio::test]
async fn realistic_large_datagrams_round_trip_without_framing_drift() -> TestResult {
    let echo = start_echo(b"").await?;
    let destination = echo.local_addr();
    let (mut client, _shoes, _config) = start_xudp_client().await?;

    for (index, size) in [1024, 3072, 6144].into_iter().enumerate() {
        let payload: Vec<u8> = (0..size).map(|offset| (offset % 251) as u8).collect();
        let frame = if index == 0 {
            new_frame(7, destination, &payload)
        } else {
            keep_frame(7, &payload)
        };
        client.send_frame(&frame).await?;
        expect_data(&mut client, 7, destination, &payload).await?;
    }

    client.send_frame(&keep_frame(7, b"sentinel")).await?;
    expect_data(&mut client, 7, destination, b"sentinel").await?;
    Ok(())
}

#[tokio::test]
async fn ipv6_destination_round_trips() -> TestResult {
    let echo = start_udp_echo_server_with_suffix("::1", 0, b" [IPV6]").await?;
    let destination = echo.local_addr();
    let (mut client, _shoes, _config) = start_xudp_client().await?;

    client
        .send_frame(&new_frame(6, destination, b"ipv6"))
        .await?;
    expect_data(&mut client, 6, destination, b"ipv6 [IPV6]").await?;
    Ok(())
}

#[tokio::test]
async fn unknown_session_does_not_poison_a_valid_session() -> TestResult {
    let echo = start_echo(b" [ECHO]").await?;
    let destination = echo.local_addr();
    let (mut client, _shoes, _config) = start_xudp_client().await?;

    client
        .send_frame(&new_frame(1, destination, b"initial"))
        .await?;
    expect_data(&mut client, 1, destination, b"initial [ECHO]").await?;

    client
        .send_frame(&keep_frame(999, b"unknown-session"))
        .await?;
    client.send_frame(&keep_frame(1, b"valid-session")).await?;
    expect_data(&mut client, 1, destination, b"valid-session [ECHO]").await?;
    Ok(())
}

#[tokio::test]
async fn one_connection_multiplexes_explicit_session_ids() -> TestResult {
    let echoes = [
        start_echo(b" [A]").await?,
        start_echo(b" [B]").await?,
        start_echo(b" [C]").await?,
    ];
    let sessions = [
        (
            11,
            echoes[0].local_addr(),
            b"first-a".as_slice(),
            b"first-a [A]".as_slice(),
        ),
        (
            22,
            echoes[1].local_addr(),
            b"first-b".as_slice(),
            b"first-b [B]".as_slice(),
        ),
        (
            33,
            echoes[2].local_addr(),
            b"first-c".as_slice(),
            b"first-c [C]".as_slice(),
        ),
    ];
    let (mut client, _shoes, _config) = start_xudp_client().await?;

    for (session_id, destination, request, _) in sessions {
        client
            .send_frame(&new_frame(session_id, destination, request))
            .await?;
    }
    let mut received = HashMap::new();
    for _ in sessions {
        let frame = client.recv_frame(Duration::from_secs(5)).await?;
        received.insert(frame.session_id, (frame.destination, frame.payload));
    }
    for (session_id, destination, _, expected) in sessions {
        assert_eq!(
            received.remove(&session_id),
            Some((
                Some(VlessDestination::Ip(destination)),
                Some(expected.to_vec())
            ))
        );
    }
    assert!(received.is_empty());

    for (session_id, _, _, _) in sessions.into_iter().rev() {
        let payload = format!("again-{session_id}");
        client
            .send_frame(&keep_frame(session_id, payload.as_bytes()))
            .await?;
    }
    let expected = HashMap::from([
        (11, b"again-11 [A]".to_vec()),
        (22, b"again-22 [B]".to_vec()),
        (33, b"again-33 [C]".to_vec()),
    ]);
    let mut received = HashMap::new();
    for _ in sessions {
        let frame = client.recv_frame(Duration::from_secs(5)).await?;
        received.insert(frame.session_id, frame.payload.unwrap());
    }
    assert_eq!(received, expected);
    Ok(())
}
