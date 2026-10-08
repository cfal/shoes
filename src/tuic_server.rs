use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str;
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::io::AsyncWriteExt;

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use log::{debug, error};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::copy_bidirectional::copy_bidirectional_with_sizes;
use crate::quic_stream::QuicStream;
use crate::resolver::Resolver;
use crate::routing::udp_relay::UdpRelay;
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_server::setup_client_tcp_stream;
use crate::udp_fragments::UdpFragments;
use crate::util::write_all;

const COMMAND_TYPE_AUTHENTICATE: u8 = 0x00;
const COMMAND_TYPE_CONNECT: u8 = 0x01;
const COMMAND_TYPE_PACKET: u8 = 0x02;
const COMMAND_TYPE_DISSOCIATE: u8 = 0x03;
const COMMAND_TYPE_HEARTBEAT: u8 = 0x04;

// hostname case: type (1) + hostname length (1) + hostname bytes (255) + port (2)
const MAX_ADDRESS_BYTES_LEN: usize = 1 + 1 + 255 + 2;
const MAX_HEADER_LEN: usize = 2 + 2 + 1 + 1 + 2 + MAX_ADDRESS_BYTES_LEN;

const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Authentication timeout - close connection if client doesn't authenticate within this time.
/// Default is 3 seconds per sing-box reference implementation.
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);

/// Heartbeat interval - server sends heartbeat datagrams to client at this interval.
/// Default is 10 seconds per sing-box reference implementation.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

type UdpSessionMap = Arc<UdpState>;

struct UdpState {
    sessions: DashMap<u16, Arc<UdpSession>>,
    fragments: parking_lot::Mutex<UdpFragments<(u16, u16)>>,
    slots: Arc<crate::resources::Budget>,
}

impl UdpState {
    fn new() -> Self {
        Self {
            sessions: DashMap::new(),
            fragments: parking_lot::Mutex::new(UdpFragments::new()),
            slots: Arc::new(crate::resources::Budget::new(
                crate::resources::limits().max_udp_destinations,
            )),
        }
    }
}

async fn process_connection(
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    uuid: Arc<[u8]>,
    password: Arc<str>,
    conn: quinn::Connecting,
    zero_rtt_handshake: bool,
) -> std::io::Result<()> {
    // Accept the incoming connection. When 0-RTT is enabled, use into_0rtt() to
    // allow 0.5-RTT data transmission before the handshake fully completes.
    // This reduces latency at the cost of some security (0-RTT data is vulnerable
    // to replay attacks, though for incoming server connections it's 0.5-RTT which
    // is safer but still shouldn't be used for client-authenticated data).
    let connection = if zero_rtt_handshake {
        // For incoming connections, into_0rtt() always succeeds per quinn docs
        let (connection, _zero_rtt_accepted) = conn
            .into_0rtt()
            .map_err(|_| std::io::Error::other("failed to enable 0-RTT"))?;
        connection
    } else {
        conn.await?
    };

    // Authentication with timeout - per sing-box reference, default 3 seconds.
    // This prevents malicious clients from holding connections open without authenticating.
    match timeout(AUTH_TIMEOUT, auth_connection(&connection, &uuid, &password)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            connection.close(0u32.into(), b"auth failed");
            return Err(e);
        }
        Err(_elapsed) => {
            error!("Authentication timeout");
            connection.close(0u32.into(), b"auth timeout");
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "authentication timeout",
            ));
        }
    }

    // Create a cancellation token for the entire connection lifecycle.
    // When cancelled, all spawned tasks (UDP sessions, cleanup task, heartbeat) will terminate gracefully.
    let cancel_token = CancellationToken::new();
    let _cancel_on_drop = cancel_token.clone().drop_guard();

    // this allows for:
    // 1. multiple threads can read different sessions concurrently
    // 2. multiple threads can modify different sessions concurrently
    // 3. the outer write lock is only needed for adding/removing sessions
    let udp_session_map = Arc::new(UdpState::new());

    // Clone what we need for each loop before creating async blocks
    let heartbeat_connection = connection.clone();
    let heartbeat_cancel_token = cancel_token.clone();

    let bi_connection = connection.clone();
    let bi_client_proxy_selector = client_proxy_selector.clone();
    let bi_resolver = resolver.clone();

    let uni_connection = connection.clone();
    let uni_client_proxy_selector = client_proxy_selector.clone();
    let uni_resolver = resolver.clone();
    let uni_udp_session_map = udp_session_map.clone();
    let uni_cancel_token = cancel_token.clone();

    let datagram_connection = connection.clone();
    let datagram_cancel_token = cancel_token.clone();

    // Use try_join! to run all loops concurrently within the same task, like Quinn's perf example.
    // This reduces task count and avoids spawning separate tasks for the main loops.
    let heartbeat_loop = run_heartbeat_loop(heartbeat_connection, heartbeat_cancel_token);

    let bi_loop = run_bidirectional_loop(bi_connection, bi_client_proxy_selector, bi_resolver);

    let uni_loop = run_unidirectional_loop(
        uni_connection,
        uni_client_proxy_selector,
        uni_resolver,
        uni_udp_session_map,
        uni_cancel_token,
    );

    let datagram_loop = run_datagram_loop(
        datagram_connection,
        client_proxy_selector,
        resolver,
        udp_session_map,
        datagram_cancel_token,
    );

    let result = tokio::try_join!(heartbeat_loop, bi_loop, uni_loop, datagram_loop);

    // Cancel all remaining tasks (UDP session loops, cleanup task, heartbeat)
    cancel_token.cancel();

    // Per sing-box reference (service.go:382-398), close connection on error
    if let Err(ref e) = result {
        error!("Connection failed: {e}");
        connection.close(0u32.into(), b"");
    }

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Sends periodic heartbeat datagrams to the client to maintain connection liveness.
/// Per sing-box reference implementation (service.go:366-380).
/// Returns an error if heartbeat fails, which will cause the connection to close.
async fn run_heartbeat_loop(
    connection: quinn::Connection,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
    // Skip the first immediate tick
    interval.tick().await;

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                return Ok(());
            }
            _ = interval.tick() => {
                // Send heartbeat datagram: [version, command_heartbeat]
                let heartbeat = bytes::Bytes::from_static(&[5, COMMAND_TYPE_HEARTBEAT]);
                if let Err(e) = connection.send_datagram(heartbeat) {
                    // Per sing-box reference, heartbeat failure should close the connection
                    return Err(std::io::Error::other(format!("heartbeat failed: {e}")));
                }
            }
        }
    }
}

async fn auth_connection(
    connection: &quinn::Connection,
    uuid: &[u8],
    password: &str,
) -> std::io::Result<()> {
    let mut expected_token_bytes = [0u8; 32];
    connection
        .export_keying_material(
            &mut expected_token_bytes,
            uuid.as_ref(),
            password.as_bytes(),
        )
        .map_err(|e| std::io::Error::other(format!("Failed to export keying material: {e:?}")))?;

    // Loop until we receive an AUTH command.
    // Other commands (like DISSOCIATE) may arrive on uni streams before AUTH.
    // We discard non-AUTH streams and wait for the next one.
    // The outer timeout in process_connection ensures we don't wait forever.
    loop {
        let mut recv_stream = connection.accept_uni().await?;
        let mut stream_reader = StreamReader::new_with_buffer_size(80);
        let tuic_version = stream_reader.read_u8(&mut recv_stream).await?;
        if tuic_version != 5 {
            return Err(std::io::Error::other(format!(
                "invalid tuic version: {tuic_version}"
            )));
        }
        let command_type = stream_reader.read_u8(&mut recv_stream).await?;

        if command_type != COMMAND_TYPE_AUTHENTICATE {
            // Not an AUTH command - discard this stream and wait for the next one.
            debug!("Received command type {command_type} before auth, waiting for auth command");
            continue;
        }

        let credentials = stream_reader.read_slice(&mut recv_stream, 48).await?;
        let authenticated =
            credentials[..16].ct_eq(uuid) & credentials[16..].ct_eq(&expected_token_bytes);
        if !bool::from(authenticated) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "incorrect credentials",
            ));
        }

        return Ok(());
    }
}

async fn run_bidirectional_loop(
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            result = connection.accept_bi() => result,
            _ = tasks.join_next(), if !tasks.is_empty() => continue,
        };
        let (send_stream, recv_stream) = match accepted {
            Ok(s) => s,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                break;
            }
            Err(quinn::ConnectionError::ConnectionClosed(_)) => {
                break;
            }
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "failed to accept bidirectional stream: {e}"
                )));
            }
        };

        let conn = connection.clone();
        if crate::resources::limits()
            .max_streams_per_connection
            .is_some_and(|limit| tasks.len() >= limit)
        {
            continue;
        }
        let Some(permit) = crate::resources::try_stream() else {
            continue;
        };
        let client_proxy_selector = client_proxy_selector.clone();
        let resolver = resolver.clone();
        tasks.spawn(async move {
            let _permit = permit;
            match process_tcp_stream(client_proxy_selector, resolver, send_stream, recv_stream)
                .await
            {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                    // Per official TUIC reference (handle_stream.rs:127-135),
                    // header parsing errors close the connection
                    error!("Error parsing TCP stream header, closing connection: {e}");
                    conn.close(0u32.into(), b"");
                }
                Err(e) => {
                    // TCP proxying errors are just logged (handle_task.rs:238-246)
                    error!("Error processing TCP stream: {e}");
                }
            }
        });
    }
    Ok(())
}

async fn read_address(
    recv: &mut quinn::RecvStream,
    stream_reader: &mut StreamReader,
) -> std::io::Result<Option<NetLocation>> {
    let address_type = stream_reader.read_u8(recv).await?;
    let address = match address_type {
        0xff => {
            return Ok(None);
        }
        0x00 => {
            let address_len = stream_reader.read_u8(recv).await? as usize;
            let address_bytes = stream_reader.read_slice(recv, address_len).await?;
            let address_str = str::from_utf8(address_bytes).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid address: {e}"),
                )
            })?;
            // Although this is supposed to be a hostname, some clients will pass
            // ipv4 and ipv6 addresses as well, so parse it rather than directly
            // using Address:Hostname enum.
            Address::from(address_str)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?
        }
        0x01 => {
            let ipv4_bytes = stream_reader.read_slice(recv, 4).await?;
            let ipv4_addr =
                Ipv4Addr::new(ipv4_bytes[0], ipv4_bytes[1], ipv4_bytes[2], ipv4_bytes[3]);
            Address::Ipv4(ipv4_addr)
        }
        0x02 => {
            let ipv6_bytes = stream_reader.read_slice(recv, 16).await?;
            let ipv6_bytes: [u8; 16] = ipv6_bytes.try_into().unwrap();
            let ipv6_addr = Ipv6Addr::from(ipv6_bytes);
            Address::Ipv6(ipv6_addr)
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid address type: {address_type}"),
            ));
        }
    };

    let port = stream_reader.read_u16_be(recv).await?;

    Ok(Some(NetLocation::new(address, port)))
}

fn serialize_address(location: &NetLocation) -> Vec<u8> {
    let mut address_bytes = match location.address() {
        Address::Hostname(hostname) => {
            let mut res = Vec::with_capacity(1 + 1 + hostname.len() + 2);
            res.push(0x00); // address type
            let hostname_bytes = hostname.as_bytes();
            res.push(hostname_bytes.len() as u8);
            res.extend_from_slice(hostname_bytes);
            res
        }
        Address::Ipv4(ipv4) => {
            let mut res = Vec::with_capacity(1 + 4 + 2);
            res.push(0x01); // address type
            res.extend_from_slice(&ipv4.octets());
            res
        }
        Address::Ipv6(ipv6) => {
            let mut res = Vec::with_capacity(1 + 16 + 2);
            res.push(0x02); // address type
            res.extend_from_slice(&ipv6.octets());
            res
        }
    };

    address_bytes.extend_from_slice(&location.port().to_be_bytes());

    address_bytes
}

fn serialize_socket_addr(addr: &SocketAddr) -> Vec<u8> {
    let mut res = match addr {
        SocketAddr::V4(addr_v4) => {
            let mut res = Vec::with_capacity(1 + 4 + 2);
            res.push(0x01); // address type for IPv4
            res.extend_from_slice(&addr_v4.ip().octets());
            res
        }
        SocketAddr::V6(addr_v6) => {
            let mut res = Vec::with_capacity(1 + 16 + 2);
            res.push(0x02); // address type for IPv6
            res.extend_from_slice(&addr_v6.ip().octets());
            res
        }
    };

    res.extend_from_slice(&addr.port().to_be_bytes());
    res
}

async fn process_tcp_stream(
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> std::io::Result<()> {
    let mut stream_reader = StreamReader::new_with_buffer_size(1024);
    let tuic_version = stream_reader.read_u8(&mut recv).await?;
    if tuic_version != 5 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid tuic version: {tuic_version}"),
        ));
    }
    let command_type = stream_reader.read_u8(&mut recv).await?;
    if command_type != COMMAND_TYPE_CONNECT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid command type: {command_type}"),
        ));
    }

    let remote_location = read_address(&mut recv, &mut stream_reader)
        .await?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "empty address"))?;

    let mut server_stream: Box<dyn AsyncStream> = Box::new(QuicStream::from(send, recv));
    let setup_client_stream_future = timeout(
        Duration::from_secs(60),
        setup_client_tcp_stream(client_proxy_selector, resolver, remote_location.clone()),
    );

    let crate::tcp::tcp_handler::TcpClientSetupResult {
        mut client_stream,
        early_data,
    } = match setup_client_stream_future.await {
        Ok(Ok(Some(s))) => s,
        Ok(Ok(None)) => {
            // Must have been blocked.
            crate::util::shutdown_stream(&mut server_stream).await;
            return Ok(());
        }
        Ok(Err(e)) => {
            crate::util::shutdown_stream(&mut server_stream).await;
            return Err(std::io::Error::new(
                e.kind(),
                format!("failed to setup client stream to {remote_location}: {e}"),
            ));
        }
        Err(elapsed) => {
            crate::util::shutdown_stream(&mut server_stream).await;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("client setup to {remote_location} timed out: {elapsed}"),
            ));
        }
    };

    crate::util::timeout_stream_setup(async {
        if let Some(data) = early_data {
            write_all(&mut server_stream, &data).await?;
            server_stream.flush().await?;
        }
        let unparsed_data = stream_reader.unparsed_data();
        if !unparsed_data.is_empty() {
            write_all(&mut client_stream, unparsed_data).await?;
            client_stream.flush().await?;
        }
        Ok(())
    })
    .await?;
    drop(stream_reader);

    // Use 32KB buffers to match reference implementations
    let copy_result = copy_bidirectional_with_sizes(
        &mut server_stream,
        &mut client_stream,
        false, // no need to flush since it's QUIC
        false,
        32768,
        32768,
    )
    .await;

    futures::join!(
        crate::util::shutdown_stream(&mut server_stream),
        crate::util::shutdown_stream(&mut client_stream),
    );

    copy_result?;
    Ok(())
}

struct UdpSession {
    send_socket: Arc<UdpRelay>,
    pinned_location: Option<NetLocation>,
    // Cancellation token for this session's background task
    cancel_token: CancellationToken,
    task: Option<tokio::task::AbortHandle>,
    _permit: Option<crate::resources::BudgetPermit>,
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        self.cancel_token.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

impl UdpSession {
    #[allow(clippy::too_many_arguments)]
    fn start_with_send_stream(
        assoc_id: u16,
        connection: quinn::Connection,
        client_socket: Arc<UdpRelay>,
        override_local_write_location: Option<NetLocation>,
        pinned_location: Option<NetLocation>,
        parent_cancel_token: &CancellationToken,
        permit: crate::resources::BudgetPermit,
    ) -> Self {
        // Create a child token so this session is cancelled when the parent (connection) is cancelled
        let session_cancel_token = parent_cancel_token.child_token();

        let mut session = UdpSession {
            send_socket: client_socket.clone(),
            pinned_location,
            cancel_token: session_cancel_token.clone(),
            task: None,
            _permit: Some(permit),
        };

        session.task = Some(
            tokio::spawn(async move {
                if let Err(e) = run_udp_remote_to_local_stream_loop(
                    assoc_id,
                    connection,
                    client_socket,
                    override_local_write_location,
                    session_cancel_token,
                )
                .await
                {
                    error!("UDP remote-to-local write loop ended with error: {e}");
                }
            })
            .abort_handle(),
        );

        session
    }

    #[allow(clippy::too_many_arguments)]
    fn start_with_datagram(
        assoc_id: u16,
        connection: quinn::Connection,
        client_socket: Arc<UdpRelay>,
        override_local_write_location: Option<NetLocation>,
        pinned_location: Option<NetLocation>,
        parent_cancel_token: &CancellationToken,
        permit: crate::resources::BudgetPermit,
    ) -> Self {
        // Create a child token so this session is cancelled when the parent (connection) is cancelled
        let session_cancel_token = parent_cancel_token.child_token();

        let mut session = UdpSession {
            send_socket: client_socket.clone(),
            pinned_location,
            cancel_token: session_cancel_token.clone(),
            task: None,
            _permit: Some(permit),
        };

        session.task = Some(
            tokio::spawn(async move {
                if let Err(e) = run_udp_remote_to_local_datagram_loop(
                    assoc_id,
                    connection,
                    client_socket,
                    override_local_write_location,
                    session_cancel_token,
                )
                .await
                {
                    error!("UDP remote-to-local write loop ended with error: {e}");
                }
            })
            .abort_handle(),
        );

        session
    }
}

async fn run_udp_remote_to_local_stream_loop(
    assoc_id: u16,
    connection: quinn::Connection,
    socket: Arc<UdpRelay>,
    override_local_write_address: Option<NetLocation>,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let original_address_bytes: Option<Bytes> =
        override_local_write_address.map(|a| serialize_address(&a).into());

    let mut next_packet_id: u16 = 0;
    let mut loop_count: u8 = 0;

    loop {
        let (payload, src_addr) = tokio::select! {
            _ = cancel_token.cancelled() => return Ok(()),
            result = socket.recv() => result?,
        };
        let payload_len = payload.len();

        // Yield periodically to allow quinn's internal tasks to run (keepalives, ACKs, etc.)
        loop_count = loop_count.wrapping_add(1);
        if loop_count == 0 {
            tokio::task::yield_now().await;
        }

        let packet_id = next_packet_id;
        next_packet_id = next_packet_id.wrapping_add(1);

        let address_bytes = match original_address_bytes {
            Some(ref a) => a.clone(),
            None => serialize_socket_addr(&src_addr).into(),
        };

        let mut frame = BytesMut::with_capacity(MAX_HEADER_LEN + payload_len);
        frame.extend_from_slice(&[5, COMMAND_TYPE_PACKET]);
        frame.extend_from_slice(&assoc_id.to_be_bytes());
        frame.extend_from_slice(&packet_id.to_be_bytes());
        frame.extend_from_slice(&[1, 0]);
        frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
        frame.extend_from_slice(&address_bytes);
        frame.extend_from_slice(&payload);
        let mut send_stream = connection.open_uni().await?;
        write_all(&mut send_stream, &frame).await?;
        send_stream.finish()?;
    }
}

async fn run_udp_remote_to_local_datagram_loop(
    assoc_id: u16,
    connection: quinn::Connection,
    client_socket: Arc<UdpRelay>,
    override_local_write_location: Option<NetLocation>,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    use bytes::BufMut;

    let max_datagram_size = connection
        .max_datagram_size()
        .ok_or_else(|| std::io::Error::other("datagram not supported by remote endpoint"))?;

    let original_address_bytes: Option<Bytes> =
        override_local_write_location.map(|a| serialize_address(&a).into());

    let mut next_packet_id: u16 = 0;
    let mut loop_count: u8 = 0;

    loop {
        let (payload, src_addr) = tokio::select! {
            _ = cancel_token.cancelled() => return Ok(()),
            result = client_socket.recv() => result?,
        };
        let payload_len = payload.len();

        // Yield periodically to allow quinn's internal tasks to run (keepalives, ACKs, etc.)
        loop_count = loop_count.wrapping_add(1);
        if loop_count == 0 {
            tokio::task::yield_now().await;
        }

        let packet_id = next_packet_id;
        next_packet_id = next_packet_id.wrapping_add(1);

        let address_bytes: Bytes = match &original_address_bytes {
            Some(a) => a.clone(),
            None => serialize_socket_addr(&src_addr).into(),
        };
        let address_bytes_len = address_bytes.len();

        // Header format:
        // tuic_version (1 byte) + command_type (1 byte)
        // + assoc_id (2 bytes) + packet_id (2 bytes)
        // + frag_total (1 byte) + frag_id (1 byte)
        // + payload_size (2 bytes) + address_bytes
        let header_overhead = 1 + 1 + 2 + 2 + 1 + 1 + 2 + address_bytes_len;

        if header_overhead + payload_len <= max_datagram_size {
            let mut datagram = BytesMut::with_capacity(header_overhead + payload_len);
            datagram.put_u8(5); // tuic version
            datagram.put_u8(COMMAND_TYPE_PACKET); // command type
            datagram.extend_from_slice(&assoc_id.to_be_bytes());
            datagram.extend_from_slice(&packet_id.to_be_bytes());
            datagram.put_u8(1); // frag_total = 1
            datagram.put_u8(0); // frag_id = 0
            datagram.extend_from_slice(&(payload_len as u16).to_be_bytes());
            datagram.extend_from_slice(&address_bytes);
            datagram.extend_from_slice(&payload);

            connection
                .send_datagram(datagram.freeze())
                .map_err(|e| std::io::Error::other(format!("Failed to send datagram: {e}")))?;
        } else {
            // Calculate header sizes for first fragment and subsequent fragments.
            let first_overhead = header_overhead; // full address included in the first fragment
            let other_overhead = 1 + 1 + 2 + 2 + 1 + 1 + 2 + 1; // 0xff marker instead of full address
            if max_datagram_size <= first_overhead || max_datagram_size <= other_overhead {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "QUIC datagram cannot fit UDP header",
                ));
            }
            let first_capacity = max_datagram_size - first_overhead;
            let other_capacity = max_datagram_size - other_overhead;

            let remaining = payload_len.saturating_sub(first_capacity);
            let additional_fragments = remaining.div_ceil(other_capacity);
            let fragment_count = u8::try_from(1 + additional_fragments).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "too many UDP fragments")
            })? as usize;

            let mut offset = 0;
            for fragment_id in 0..fragment_count {
                let (fragment_payload_len, header_size) = if fragment_id == 0 {
                    let len = std::cmp::min(first_capacity, payload_len);
                    (len, first_overhead)
                } else {
                    let len = std::cmp::min(other_capacity, payload_len - offset);
                    (len, other_overhead)
                };

                let mut datagram = BytesMut::with_capacity(header_size + fragment_payload_len);
                datagram.extend_from_slice(&[5, COMMAND_TYPE_PACKET]);
                datagram.extend_from_slice(&assoc_id.to_be_bytes());
                datagram.extend_from_slice(&packet_id.to_be_bytes());
                datagram.extend_from_slice(&[fragment_count as u8, fragment_id as u8]);
                datagram.extend_from_slice(&(fragment_payload_len as u16).to_be_bytes());
                if fragment_id == 0 {
                    datagram.extend_from_slice(&address_bytes);
                } else {
                    datagram.put_u8(0xff);
                }
                datagram.extend_from_slice(&payload[offset..offset + fragment_payload_len]);
                connection.send_datagram(datagram.freeze()).map_err(|e| {
                    std::io::Error::other(format!(
                        "Failed to send datagram fragment {fragment_id}: {e}"
                    ))
                })?;
                offset += fragment_payload_len;
            }
        }
    }
}
async fn run_unidirectional_loop(
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    udp_session_map: UdpSessionMap,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let mut tasks = JoinSet::new();
    // Spawn a cleanup task for UDP sessions that terminates when connection closes
    let cleanup_session_map = udp_session_map.clone();
    let cleanup_cancel_token = cancel_token.clone();
    tasks.spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = cleanup_cancel_token.cancelled() => {
                    break;
                }
                _ = interval.tick() => {
                    cleanup_session_map.fragments.lock().expire();
                    cleanup_session_map.sessions.retain(|assoc_id, session| {
                        if session.send_socket.idle_for() > IDLE_TIMEOUT {
                            // Cancel the session's background task before removing
                            session.cancel_token.cancel();
                            debug!("Removing inactive UDP session {assoc_id}");
                            false
                        } else {
                            true
                        }
                    });
                }
            }
        }
    });

    loop {
        let accepted = tokio::select! {
            result = connection.accept_uni() => result,
            _ = tasks.join_next(), if !tasks.is_empty() => continue,
        };
        let recv_stream = match accepted {
            Ok(recv_stream) => recv_stream,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                break;
            }
            Err(quinn::ConnectionError::ConnectionClosed(_)) => {
                break;
            }
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "failed to accept unidirectional stream: {e}"
                )));
            }
        };

        if crate::resources::limits()
            .max_streams_per_connection
            .is_some_and(|limit| tasks.len() > limit)
        {
            continue;
        }
        let Some(permit) = crate::resources::try_stream() else {
            continue;
        };
        let connection = connection.clone();
        let client_proxy_selector = client_proxy_selector.clone();
        let resolver = resolver.clone();
        let udp_session_map = udp_session_map.clone();
        let cancel_token = cancel_token.clone();
        tasks.spawn(async move {
            let _permit = permit;
            // Per TUIC protocol, each uni stream carries exactly ONE command.
            // The reference implementation (handle_stream.rs) handles one task per stream.
            match timeout(
                Duration::from_secs(30),
                process_uni_stream(
                    &connection,
                    client_proxy_selector,
                    resolver,
                    recv_stream,
                    udp_session_map,
                    cancel_token,
                ),
            )
            .await
            .unwrap_or_else(|_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "TUIC command timed out",
                ))
            }) {
                Ok(()) => {}
                Err(e) => {
                    // Per official TUIC reference (handle_stream.rs:70-78),
                    // uni stream errors close the connection
                    error!("Error processing uni stream, closing connection: {e}");
                    connection.close(0u32.into(), b"");
                }
            }
        });
    }
    Ok(())
}

/// Process a single uni stream command. Per TUIC protocol, each uni stream
/// carries exactly one command (PACKET or DISSOCIATE on server side).
async fn process_uni_stream(
    connection: &quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    mut recv_stream: quinn::RecvStream,
    udp_session_map: UdpSessionMap,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let mut stream_reader = StreamReader::new_with_buffer_size(MAX_HEADER_LEN + 65535);

    let tuic_version = stream_reader.read_u8(&mut recv_stream).await?;
    if tuic_version != 5 {
        return Err(std::io::Error::other(format!(
            "invalid tuic version: {tuic_version}"
        )));
    }
    let command_type = stream_reader.read_u8(&mut recv_stream).await?;

    if command_type == COMMAND_TYPE_DISSOCIATE {
        let assoc_id = stream_reader.read_u16_be(&mut recv_stream).await?;
        // Remove and cancel the session's background task.
        // Per official TUIC Rust reference (handle_task.rs:154-165).
        if let Some((_, session)) = udp_session_map.sessions.remove(&assoc_id) {
            session.cancel_token.cancel();
        }
        // Session not found is normal - it may have already timed out or been closed
        return Ok(());
    }

    if command_type != COMMAND_TYPE_PACKET {
        return Err(std::io::Error::other(format!(
            "invalid uni stream command type: {command_type}"
        )));
    }

    // PACKET command - read the packet data
    let assoc_id = stream_reader.read_u16_be(&mut recv_stream).await?;
    let packet_id = stream_reader.read_u16_be(&mut recv_stream).await?;
    let frag_total = stream_reader.read_u8(&mut recv_stream).await?;
    let frag_id = stream_reader.read_u8(&mut recv_stream).await?;
    let payload_size = stream_reader.read_u16_be(&mut recv_stream).await?;
    let remote_location = read_address(&mut recv_stream, &mut stream_reader).await?;

    let payload_fragment = stream_reader
        .read_slice(&mut recv_stream, payload_size as usize)
        .await?;

    process_udp_packet(
        connection,
        &client_proxy_selector,
        &resolver,
        &udp_session_map,
        assoc_id,
        packet_id,
        frag_total,
        frag_id,
        remote_location,
        payload_fragment,
        true,
        &cancel_token,
    )
    .await
}

// TODO: fix too many arguments warning
#[allow(clippy::too_many_arguments)]
#[inline]
async fn process_udp_packet(
    connection: &quinn::Connection,
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    udp_session_map: &UdpSessionMap,
    assoc_id: u16,
    packet_id: u16,
    frag_total: u8,
    frag_id: u8,
    remote_location: Option<NetLocation>,
    payload_fragment: &[u8],
    is_uni_stream: bool,
    cancel_token: &CancellationToken,
) -> std::io::Result<()> {
    let Some((remote_location, payload)) = udp_session_map.fragments.lock().push(
        (assoc_id, packet_id),
        frag_total,
        frag_id,
        remote_location,
        payload_fragment,
    )?
    else {
        return Ok(());
    };
    if crate::resources::limits()
        .max_udp_destinations
        .is_some_and(|limit| udp_session_map.sessions.len() >= limit)
        && !udp_session_map.sessions.contains_key(&assoc_id)
    {
        return Ok(());
    }

    let existing = udp_session_map
        .sessions
        .get(&assoc_id)
        .map(|entry| Arc::clone(entry.value()));
    let session = {
        match existing {
            Some(s) => s,
            None => {
                let permit = udp_session_map.slots.acquire(1).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "TUIC UDP session limit reached",
                    )
                })?;
                let action = client_proxy_selector
                    .judge(remote_location.clone().into(), resolver)
                    .await;

                let (_chain_group, updated_location) = match action {
                    Ok(ConnectDecision::Allow {
                        chain_group,
                        remote_location,
                    }) => (chain_group, remote_location),
                    Ok(ConnectDecision::Block) => {
                        return Err(std::io::Error::other(format!(
                            "Blocked UDP forward to {remote_location}"
                        )));
                    }
                    Err(e) => {
                        return Err(std::io::Error::other(format!(
                            "Failed to judge UDP forward to {remote_location}: {e}"
                        )));
                    }
                };

                let pinned_location = if remote_location.address().hostname().is_some()
                    || updated_location.location() != &remote_location
                {
                    Some(remote_location.clone())
                } else {
                    None
                };
                let client_socket = UdpRelay::new(client_proxy_selector.clone(), resolver.clone())?;

                let session = if is_uni_stream {
                    UdpSession::start_with_send_stream(
                        assoc_id,
                        connection.clone(),
                        Arc::new(client_socket),
                        pinned_location.clone(),
                        pinned_location,
                        cancel_token,
                        permit,
                    )
                } else {
                    UdpSession::start_with_datagram(
                        assoc_id,
                        connection.clone(),
                        Arc::new(client_socket),
                        pinned_location.clone(),
                        pinned_location,
                        cancel_token,
                        permit,
                    )
                };

                // it's possible that the session is already on the map since we last checked.
                // TODO: why is there no way to get a Ref<_> from an Entry<_>? see if we can
                // do better than converting into a RefMut<_> and then downgrading.
                match udp_session_map.sessions.entry(assoc_id) {
                    dashmap::mapref::entry::Entry::Occupied(entry) => entry.get().clone(),
                    dashmap::mapref::entry::Entry::Vacant(entry) => {
                        let session = Arc::new(session);
                        entry.insert(session.clone());
                        session
                    }
                }
            }
        }
    };

    let target = session.pinned_location.clone().unwrap_or(remote_location);
    if let Err(e) = session.send_socket.send_to(payload, target) {
        error!("Failed to forward UDP payload for session {assoc_id}: {e}");
        udp_session_map
            .sessions
            .remove_if(&assoc_id, |_, current| Arc::ptr_eq(current, &session));
    }
    Ok(())
}

struct UdpPacket<'a> {
    assoc_id: u16,
    packet_id: u16,
    frag_total: u8,
    frag_id: u8,
    remote_location: Option<NetLocation>,
    payload_fragment: &'a [u8],
}

fn parse_udp_packet(data: &[u8]) -> std::io::Result<UdpPacket<'_>> {
    let data_len = data.len();
    if data_len < 11 {
        return Err(std::io::Error::other("decode UDP message: too short"));
    }

    let assoc_id = u16::from_be_bytes([data[2], data[3]]);
    let packet_id = u16::from_be_bytes([data[4], data[5]]);
    let frag_total = data[6];
    let frag_id = data[7];
    let payload_size = u16::from_be_bytes([data[8], data[9]]) as usize;

    let address_type = data[10];

    let (remote_location, offset) = match address_type {
        0xff => (None, 11),
        0x00 => {
            if data_len < 14 {
                return Err(std::io::Error::other(
                    "decode UDP message: hostname too short",
                ));
            }
            let address_len = data[11] as usize;
            if data_len < 12 + address_len + 2 + payload_size {
                return Err(std::io::Error::other(
                    "decode UDP message: truncated hostname",
                ));
            }
            let address_bytes = &data[12..12 + address_len];
            let address_str = str::from_utf8(address_bytes).map_err(|e| {
                std::io::Error::other(format!("decode UDP message: invalid UTF-8: {e}"))
            })?;
            // Although this is supposed to be a hostname, some clients will pass
            // ipv4 and ipv6 addresses as well, so parse it rather than directly
            // using Address:Hostname enum.
            let address = Address::from(address_str).map_err(|e| {
                std::io::Error::other(format!("decode UDP message: invalid address: {e}"))
            })?;
            let port = u16::from_be_bytes([data[12 + address_len], data[12 + address_len + 1]]);
            (Some(NetLocation::new(address, port)), 12 + address_len + 2)
        }
        0x01 => {
            if data_len < 17 + payload_size {
                return Err(std::io::Error::other("decode UDP message: IPv4 too short"));
            }
            let ipv4_addr = Ipv4Addr::new(data[11], data[12], data[13], data[14]);
            let port = u16::from_be_bytes([data[15], data[16]]);
            (Some(NetLocation::new(Address::Ipv4(ipv4_addr), port)), 17)
        }
        0x02 => {
            if data_len < 29 + payload_size {
                return Err(std::io::Error::other("decode UDP message: IPv6 too short"));
            }
            let ipv6_bytes: [u8; 16] = data[11..27].try_into().unwrap();
            let ipv6_addr = Ipv6Addr::from(ipv6_bytes);
            let port = u16::from_be_bytes([data[27], data[28]]);
            (Some(NetLocation::new(Address::Ipv6(ipv6_addr), port)), 29)
        }
        _ => {
            return Err(std::io::Error::other(format!(
                "decode UDP message: invalid address type: {address_type}"
            )));
        }
    };

    if frag_total == 0 || frag_id >= frag_total {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid TUIC fragment index",
        ));
    }
    let payload_fragment = data.get(offset..offset + payload_size).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "truncated TUIC UDP payload",
        )
    })?;

    Ok(UdpPacket {
        assoc_id,
        packet_id,
        frag_total,
        frag_id,
        remote_location,
        payload_fragment,
    })
}

async fn run_datagram_loop(
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    udp_session_map: UdpSessionMap,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    loop {
        let data = connection
            .read_datagram()
            .await
            .map_err(|err| std::io::Error::other(format!("failed to read datagram: {err}")))?;

        // Per official TUIC reference (handle_stream.rs:172-180), protocol errors close the connection
        if data.len() < 2 {
            return Err(std::io::Error::other("invalid message: too short"));
        }

        let tuic_version = data[0];
        if tuic_version != 5 {
            return Err(std::io::Error::other(format!(
                "unknown version: {tuic_version}"
            )));
        }

        let command_type = data[1];
        if command_type == COMMAND_TYPE_HEARTBEAT {
            continue;
        } else if command_type != COMMAND_TYPE_PACKET {
            return Err(std::io::Error::other(format!(
                "unknown command: {command_type}"
            )));
        }

        let UdpPacket {
            assoc_id,
            packet_id,
            frag_total,
            frag_id,
            remote_location,
            payload_fragment,
        } = parse_udp_packet(&data)?;

        if let Err(e) = process_udp_packet(
            &connection,
            &client_proxy_selector,
            &resolver,
            &udp_session_map,
            assoc_id,
            packet_id,
            frag_total,
            frag_id,
            remote_location,
            payload_fragment,
            false,
            &cancel_token,
        )
        .await
        {
            error!("Failed to process datagram UDP packet: {e}");
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn start_tuic_server(
    bind_address: SocketAddr,
    quic_server_config: Arc<quinn::crypto::rustls::QuicServerConfig>,
    uuid: Arc<[u8]>,
    password: Arc<str>,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    num_endpoints: usize,
    zero_rtt_handshake: bool,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let mut join_handles = vec![];
    let mut server_config = quinn::ServerConfig::with_crypto(quic_server_config);

    let memory_bytes = crate::resources::configure_quic(&mut server_config, 4096, 4096);
    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        .max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()))
        .keep_alive_interval(Some(Duration::from_secs(15)))
        // MTU settings per official TUIC reference
        .initial_mtu(1200)
        .min_mtu(1200)
        // Enable MTU discovery for larger packets on capable networks
        .mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()))
        // Enable GSO (Generic Segmentation Offload) for better throughput
        .enable_segmentation_offload(true)
        // Lower initial RTT estimate for faster initial window growth
        .initial_rtt(Duration::from_millis(100));

    for endpoint in crate::listener_tasks::QuicListener::bind_all(
        bind_address,
        server_config,
        num_endpoints,
        memory_bytes,
    )? {
        let resolver = resolver.clone();
        let client_proxy_selector = client_proxy_selector.clone();
        let uuid = uuid.clone();
        let password = password.clone();
        let join_handle = tokio::spawn(async move {
            let mut tasks = crate::listener_tasks::ListenerTasks::immediate();
            loop {
                let conn = tokio::select! {
                    conn = endpoint.accept() => conn,
                    _ = tasks.join_next(), if !tasks.is_empty() => continue,
                };
                let Some(conn) = conn else { break };
                let Some(permit) =
                    crate::resources::try_connection(Some(conn.remote_address().ip()))
                else {
                    conn.refuse();
                    continue;
                };
                let conn = match conn.accept() {
                    Ok(conn) => conn,
                    Err(e) => {
                        debug!("QUIC accept failed: {e}");
                        continue;
                    }
                };
                let cloned_selector = client_proxy_selector.clone();
                let cloned_resolver = resolver.clone();
                let uuid = uuid.clone();
                let password = password.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(e) = process_connection(
                        cloned_selector,
                        cloned_resolver,
                        uuid,
                        password,
                        conn,
                        zero_rtt_handshake,
                    )
                    .await
                    {
                        error!("Connection ended with error: {e}");
                    }
                });
            }
        });
        join_handles.push(join_handle);
    }

    Ok(join_handles)
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    #[test]
    fn truncated_payload_with_absent_address_is_rejected() {
        assert!(parse_udp_packet(&[5, 2, 0, 1, 0, 1, 2, 1, 0, 1, 0xff]).is_err());
        let mut packet = vec![5, 2, 0, 1, 0, 1, 1, 0, 0, 3, 1, 127, 0, 0, 1, 0, 53];
        packet.extend_from_slice(b"dns");
        assert_eq!(parse_udp_packet(&packet).unwrap().payload_fragment, b"dns");
        for len in 0..packet.len() {
            assert!(parse_udp_packet(&packet[..len]).is_err());
        }
        for count in [0, 1, 2, 255] {
            for id in 0..=255 {
                packet[6] = count;
                packet[7] = id;
                assert_eq!(parse_udp_packet(&packet).is_ok(), count != 0 && id < count);
            }
        }
    }

    #[tokio::test]
    async fn map_removal_releases_reply_task() {
        let socket = Arc::new(
            UdpRelay::new(
                Arc::new(ClientProxySelector::new(Vec::new())),
                Arc::new(crate::resolver::NativeResolver::new()),
            )
            .unwrap(),
        );
        let weak = Arc::downgrade(&socket);
        let token = CancellationToken::new();
        let task_socket = socket.clone();
        let task = tokio::spawn(async move {
            let _socket = task_socket;
            std::future::pending::<()>().await;
        });
        let session = Arc::new(UdpSession {
            send_socket: socket,
            pinned_location: None,
            cancel_token: token.clone(),
            task: Some(task.abort_handle()),
            _permit: None,
        });
        let map: UdpSessionMap = Arc::new(UdpState::new());
        map.sessions.insert(1, session);
        let snapshot = map
            .sessions
            .get(&1)
            .map(|entry| entry.value().clone())
            .unwrap();
        map.sessions.remove(&1);
        assert!(!token.is_cancelled());
        drop(snapshot);
        assert!(token.is_cancelled());
        let _ = task.await;
        assert!(weak.upgrade().is_none());
    }
}
