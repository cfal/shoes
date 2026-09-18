/// Integration tests for SOCKS5 UDP ASSOCIATE (RFC 1928)
///
/// Test Architecture:
/// ==================
/// These tests verify that shoes correctly implements native SOCKS5 UDP ASSOCIATE.
/// Unlike UoT tests which tunnel UDP over TCP, UDP ASSOCIATE uses a real UDP socket.
///
/// Key Protocol Points:
/// 1. Client establishes TCP connection and sends CMD=0x03 (UDP ASSOCIATE)
/// 2. Server binds UDP socket and returns BND.ADDR:BND.PORT in response
/// 3. Client sends/receives UDP packets through the relay
/// 4. UDP relay terminates when TCP connection closes
///
/// Test Categories:
/// ================
/// 1. Basic functionality - single packet, response verification
/// 2. Multiple packets - many packets through same association
/// 3. Multi-destination - packets to different targets through same relay
/// 4. TCP close behavior - verify UDP relay terminates correctly
/// 5. Multiple associations - multiple concurrent UDP relays
/// 6. Error handling - disabled UDP, auth failures
/// 7. Edge cases - various packet sizes, domain addresses
use shoes_test_support as common;

use common::port_helper::PortHelper;
use common::socks5::{
    Socks5UdpAssociation, SocksDestination, decode_udp_datagram, encode_udp_datagram,
    send_udp_datagram,
};
use common::test_fixture::start_shoes_server;
use common::test_servers::{start_udp_echo_server, start_udp_echo_server_with_suffix};

use std::collections::HashSet;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

// BASIC FUNCTIONALITY TESTS

/// Test basic UDP ASSOCIATE - single packet echo
#[tokio::test]
async fn test_udp_associate_basic() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!(
        "[TEST] Basic UDP ASSOCIATE: shoes={}, echo={}",
        shoes_port, udp_echo_port
    );

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    let shoes_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: socks
    udp_enabled: true
"#,
        shoes_ip, shoes_port
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(200)).await;

    let association = Socks5UdpAssociation::connect(&shoes_ip, shoes_port).await?;
    let target = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    let response = association.send_to(target, b"Hello UDP!").await?;
    eprintln!(
        "[TEST] Got response, length: {}, bytes: {:02x?}",
        response.len(),
        &response[..std::cmp::min(50, response.len())]
    );
    eprintln!("[TEST] Response: {}", String::from_utf8_lossy(&response));
    assert_eq!(response, b"Hello UDP! [ECHO]");

    eprintln!("[TEST] Basic UDP ASSOCIATE test PASSED");
    Ok(())
}

/// Test UDP ASSOCIATE with authentication
#[tokio::test]
async fn test_udp_associate_with_auth() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!("[TEST] UDP ASSOCIATE with auth");

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    let shoes_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: socks
    username: testuser
    password: testpass123
    udp_enabled: true
"#,
        shoes_ip, shoes_port
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(200)).await;

    let association = Socks5UdpAssociation::connect_with_password(
        &shoes_ip,
        shoes_port,
        "testuser",
        "testpass123",
    )
    .await?;
    let target = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    let response = association.send_to(target, b"Auth test!").await?;
    assert_eq!(response, b"Auth test! [ECHO]");

    eprintln!("[TEST] UDP ASSOCIATE with auth test PASSED");
    Ok(())
}

// MULTIPLE PACKETS TESTS

/// Test many packets through same UDP association
#[tokio::test]
async fn test_udp_associate_many_packets() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!("[TEST] Many packets through UDP ASSOCIATE");

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    let shoes_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: socks
    udp_enabled: true
"#,
        shoes_ip, shoes_port
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(200)).await;

    let association = Socks5UdpAssociation::connect(&shoes_ip, shoes_port).await?;
    let target = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    // Send 50 packets
    for i in 0..50 {
        let msg = format!("Packet-{:04}", i);
        let response = association.send_to(target, msg.as_bytes()).await?;
        assert_eq!(response, [msg.as_bytes(), b" [ECHO]"].concat());

        if i % 10 == 0 {
            eprintln!("[TEST] Packet {} OK", i);
        }
    }

    eprintln!("[TEST] Many packets test PASSED (50 packets)");
    Ok(())
}

/// Test rapid-fire packets (stress test)
#[tokio::test]
async fn test_udp_associate_rapid_fire() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!("[TEST] Rapid-fire UDP packets");

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    let shoes_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: socks
    udp_enabled: true
"#,
        shoes_ip, shoes_port
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(200)).await;

    let association = Socks5UdpAssociation::connect(&shoes_ip, shoes_port).await?;
    let target = SocksDestination::Ip(format!("{udp_echo_ip}:{udp_echo_port}").parse()?);

    // Send packets as fast as possible, then collect responses
    let mut pending: HashSet<Vec<u8>> = (0..20)
        .map(|i| format!("RAPID-{i:04} [ECHO]").into_bytes())
        .collect();

    for i in 0..20 {
        let request = encode_udp_datagram(&target, format!("RAPID-{i:04}").as_bytes())?;
        let sent = association
            .socket()
            .send_to(&request, association.relay_addr())
            .await?;
        assert_eq!(sent, request.len());
    }

    let mut response_buf = vec![0u8; 65536];
    timeout(Duration::from_secs(5), async {
        while !pending.is_empty() {
            let (length, source) = association.socket().recv_from(&mut response_buf).await?;
            if source != association.relay_addr() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "SOCKS5 UDP response came from {source}, expected {}",
                        association.relay_addr()
                    ),
                ));
            }
            let payload = decode_udp_datagram(&response_buf[..length])?;
            if !pending.remove(payload) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected or duplicate rapid response: {payload:?}"),
                ));
            }
        }
        Ok::<(), io::Error>(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "rapid responses timed out"))??;
    assert!(pending.is_empty());

    eprintln!("[TEST] Rapid-fire test PASSED");
    Ok(())
}

// MULTI-DESTINATION TESTS

/// Test sending to multiple destinations through same relay
#[tokio::test]
async fn test_udp_associate_multi_destination()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_listener_port();
    let (udp_echo_ip1, udp_echo_port1) = port_helper.get_port();
    let (udp_echo_ip2, udp_echo_port2) = port_helper.get_port();
    let (udp_echo_ip3, udp_echo_port3) = port_helper.get_port();

    eprintln!("[TEST] Multi-destination UDP ASSOCIATE");

    let _echo_server1 =
        start_udp_echo_server_with_suffix(&udp_echo_ip1, udp_echo_port1, b" [SERVER-1]").await?;
    let _echo_server2 =
        start_udp_echo_server_with_suffix(&udp_echo_ip2, udp_echo_port2, b" [SERVER-2]").await?;
    let _echo_server3 =
        start_udp_echo_server_with_suffix(&udp_echo_ip3, udp_echo_port3, b" [SERVER-3]").await?;

    let shoes_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: socks
    udp_enabled: true
"#,
        shoes_ip, shoes_port
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(200)).await;

    let association = Socks5UdpAssociation::connect(&shoes_ip, shoes_port).await?;

    // Send to each destination and verify responses come from correct server
    let targets = [
        (
            format!("{udp_echo_ip1}:{udp_echo_port1}").parse()?,
            ("Server1", b" [SERVER-1]".as_slice()),
        ),
        (
            format!("{udp_echo_ip2}:{udp_echo_port2}").parse()?,
            ("Server2", b" [SERVER-2]".as_slice()),
        ),
        (
            format!("{udp_echo_ip3}:{udp_echo_port3}").parse()?,
            ("Server3", b" [SERVER-3]".as_slice()),
        ),
    ];

    for (target, (name, suffix)) in &targets {
        let msg = format!("Hello {}", name);
        let response = association.send_to(*target, msg.as_bytes()).await?;
        assert_eq!(response, [msg.as_bytes(), *suffix].concat());
        eprintln!("[TEST] {} responded correctly", name);
    }

    // Interleave packets to different destinations
    for i in 0..5 {
        for (target, (name, suffix)) in &targets {
            let msg = format!("{}-round-{}", name, i);
            let response = association.send_to(*target, msg.as_bytes()).await?;
            assert_eq!(response, [msg.as_bytes(), *suffix].concat());
        }
    }

    eprintln!("[TEST] Multi-destination test PASSED");
    Ok(())
}

// TCP CLOSE BEHAVIOR TESTS (CRITICAL)

/// Test that UDP relay terminates when TCP connection closes
#[tokio::test]
async fn test_udp_associate_tcp_close_terminates_relay()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!("[TEST] TCP close terminates UDP relay");

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    let shoes_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: socks
    udp_enabled: true
"#,
        shoes_ip, shoes_port
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(200)).await;

    let association = Socks5UdpAssociation::connect(&shoes_ip, shoes_port).await?;
    let target = SocksDestination::Ip(format!("{udp_echo_ip}:{udp_echo_port}").parse()?);

    // Verify UDP works before TCP close
    let response = association
        .send_to_with_timeout(target.clone(), b"Before close", Duration::from_secs(5))
        .await?;
    assert_eq!(response, b"Before close [ECHO]");
    eprintln!("[TEST] UDP works before TCP close");

    let (socket, relay) = association.close_control();
    eprintln!("[TEST] TCP connection dropped");

    // Give server time to detect the close
    sleep(Duration::from_millis(500)).await;

    // UDP should no longer work - the relay should be terminated
    // We expect this to timeout or fail
    let result = send_udp_datagram(
        &socket,
        relay,
        &target,
        b"After close",
        Duration::from_millis(500),
    )
    .await;

    // The result should be an error (timeout) since the relay is gone
    let error =
        result.expect_err("UDP relay remained available after its control connection closed");
    assert!(
        matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::ConnectionRefused
        ),
        "unexpected error after closing UDP relay control connection: {error}"
    );
    eprintln!("[TEST] UDP correctly fails after TCP close");

    eprintln!("[TEST] TCP close terminates relay test PASSED");
    Ok(())
}

/// Test that we can create a new association after closing the previous one
#[tokio::test]
async fn test_udp_associate_reestablish_after_close()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!("[TEST] Re-establish UDP ASSOCIATE after close");

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    let shoes_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: socks
    udp_enabled: true
"#,
        shoes_ip, shoes_port
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(200)).await;

    let target = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    // First association
    {
        let association = Socks5UdpAssociation::connect(&shoes_ip, shoes_port).await?;
        let response = association.send_to(target, b"First").await?;
        assert_eq!(response, b"First [ECHO]");
        eprintln!("[TEST] First association works");
        // tcp drops here
    }

    sleep(Duration::from_millis(300)).await;

    // Second association (should get a new port)
    {
        let association = Socks5UdpAssociation::connect(&shoes_ip, shoes_port).await?;
        let response = association.send_to(target, b"Second").await?;
        assert_eq!(response, b"Second [ECHO]");
        eprintln!("[TEST] Second association works");
    }

    eprintln!("[TEST] Re-establish after close test PASSED");
    Ok(())
}

// MULTIPLE CONCURRENT ASSOCIATIONS TESTS

/// Test multiple concurrent UDP associations
#[tokio::test]
async fn test_udp_associate_multiple_concurrent()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!("[TEST] Multiple concurrent UDP associations");

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    let shoes_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: socks
    udp_enabled: true
"#,
        shoes_ip, shoes_port
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(200)).await;

    let target = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    // Create multiple associations, each with its own UDP socket
    let num_associations = 5;
    let mut associations = Vec::new();

    for i in 0..num_associations {
        let association = Socks5UdpAssociation::connect(&shoes_ip, shoes_port).await?;
        eprintln!(
            "[TEST] Created association {} at {}",
            i,
            association.relay_addr()
        );
        associations.push((association, i));
    }

    // Verify all associations work independently
    for (association, id) in &associations {
        let msg = format!("Association-{}", id);
        let response = association.send_to(target, msg.as_bytes()).await?;
        assert_eq!(response, [msg.as_bytes(), b" [ECHO]"].concat());
    }

    eprintln!(
        "[TEST] All {} associations work independently",
        num_associations
    );

    // Close some associations and verify others still work
    drop(associations.remove(0));
    drop(associations.remove(0));
    sleep(Duration::from_millis(200)).await;

    for (association, id) in &associations {
        let msg = format!("StillAlive-{}", id);
        let response = association.send_to(target, msg.as_bytes()).await?;
        assert_eq!(response, [msg.as_bytes(), b" [ECHO]"].concat());
    }

    eprintln!("[TEST] Remaining associations still work after others closed");
    eprintln!("[TEST] Multiple concurrent associations test PASSED");
    Ok(())
}

// ERROR HANDLING TESTS

/// Test that UDP ASSOCIATE is rejected when udp_enabled is false
#[tokio::test]
async fn test_udp_associate_disabled() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_listener_port();

    eprintln!("[TEST] UDP ASSOCIATE disabled");

    // Explicitly disable UDP
    let shoes_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: socks
    udp_enabled: false
"#,
        shoes_ip, shoes_port
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    port_helper.wait_for_all_ports().await?;

    // UDP ASSOCIATE should fail with command not supported (0x07)
    let error = Socks5UdpAssociation::connect(&shoes_ip, shoes_port)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
    assert!(
        error.to_string().contains("code 0x07"),
        "unexpected UDP ASSOCIATE rejection: {error}"
    );

    eprintln!("[TEST] UDP ASSOCIATE disabled test PASSED");
    Ok(())
}

/// Test wrong authentication fails
#[tokio::test]
async fn test_udp_associate_wrong_auth() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_listener_port();

    eprintln!("[TEST] Wrong authentication");

    let shoes_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: socks
    username: correctuser
    password: correctpass
    udp_enabled: true
"#,
        shoes_ip, shoes_port
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    port_helper.wait_for_all_ports().await?;

    let mut control = TcpStream::connect((shoes_ip.as_str(), shoes_port)).await?;
    control.write_all(&[5, 1, 2]).await?;

    let mut greeting = [0; 2];
    timeout(Duration::from_secs(5), control.read_exact(&mut greeting)).await??;
    assert_eq!(greeting, [5, 2]);

    let username = b"wronguser";
    let password = b"wrongpass";
    let mut auth_request = Vec::with_capacity(username.len() + password.len() + 3);
    auth_request.extend_from_slice(&[1, username.len() as u8]);
    auth_request.extend_from_slice(username);
    auth_request.push(password.len() as u8);
    auth_request.extend_from_slice(password);
    control.write_all(&auth_request).await?;

    let mut response = [0; 1];
    match timeout(Duration::from_secs(5), control.read(&mut response))
        .await
        .expect("server did not close the connection after rejecting credentials")
    {
        Ok(0) => {}
        Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
        Ok(length) => panic!(
            "server leaked an authentication response: {:02x?}",
            &response[..length]
        ),
        Err(error) => panic!("unexpected authentication rejection error: {error}"),
    }

    let _association = timeout(
        Duration::from_secs(5),
        Socks5UdpAssociation::connect_with_password(
            &shoes_ip,
            shoes_port,
            "correctuser",
            "correctpass",
        ),
    )
    .await
    .expect("server stopped accepting connections after rejecting credentials")?;

    eprintln!("[TEST] Wrong authentication test PASSED");
    Ok(())
}

// EDGE CASE TESTS

/// Test various UDP packet sizes
#[tokio::test]
async fn test_udp_associate_various_sizes() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!("[TEST] Various UDP packet sizes");

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    let shoes_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: socks
    udp_enabled: true
"#,
        shoes_ip, shoes_port
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(200)).await;

    let association = Socks5UdpAssociation::connect(&shoes_ip, shoes_port).await?;
    let target = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    // Test various sizes from tiny to large
    let sizes = [1, 10, 100, 500, 1000, 2000, 4000, 8000, 16000, 32000];

    for &size in &sizes {
        let payload: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let response = association.send_to(target, &payload).await?;

        assert_eq!(response, [payload.as_slice(), b" [ECHO]"].concat());
        eprintln!("[TEST] {} bytes OK", size);
    }

    eprintln!("[TEST] Various sizes test PASSED");
    Ok(())
}

/// Test empty payload handling
/// Empty UDP payloads are silently skipped, and subsequent packets remain usable.
#[tokio::test]
async fn test_udp_associate_empty_payload() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!("[TEST] Empty UDP payload");

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    let shoes_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: socks
    udp_enabled: true
"#,
        shoes_ip, shoes_port
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(200)).await;

    let association = Socks5UdpAssociation::connect(&shoes_ip, shoes_port).await?;
    let target = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    // Send an empty payload before verifying the association with a nonempty packet.
    association
        .send_to_with_timeout(
            SocksDestination::Ip(target),
            b"",
            Duration::from_millis(200),
        )
        .await
        .ok();

    // Small delay to let the empty packet be processed
    sleep(Duration::from_millis(50)).await;

    // Send a real packet - relay should still work
    let response = association.send_to(target, b"after_empty").await?;
    assert_eq!(response, b"after_empty [ECHO]");

    eprintln!("[TEST] Empty payload test PASSED");
    Ok(())
}

// MIXED PROTOCOL TESTS

/// Test UDP ASSOCIATE through mixed HTTP+SOCKS5 server
#[tokio::test]
async fn test_mixed_server_udp_associate() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut port_helper = PortHelper::new();
    let (shoes_ip, shoes_port) = port_helper.get_listener_port();
    let (udp_echo_ip, udp_echo_port) = port_helper.get_port();

    eprintln!("[TEST] Mixed server UDP ASSOCIATE");

    let _echo_server = start_udp_echo_server(&udp_echo_ip, udp_echo_port).await?;

    let shoes_config = format!(
        r#"
- address: "{}:{}"
  protocol:
    type: mixed
    udp_enabled: true
"#,
        shoes_ip, shoes_port
    );
    let (_shoes_guard, _shoes_cfg) = start_shoes_server(&shoes_config)?;

    port_helper.wait_for_all_ports().await?;
    sleep(Duration::from_millis(200)).await;

    // SOCKS5 through mixed server should work
    let association = Socks5UdpAssociation::connect(&shoes_ip, shoes_port).await?;
    let target = format!("{udp_echo_ip}:{udp_echo_port}").parse()?;

    let response = association.send_to(target, b"Mixed server!").await?;
    assert_eq!(response, b"Mixed server! [ECHO]");

    eprintln!("[TEST] Mixed server UDP ASSOCIATE test PASSED");
    Ok(())
}
