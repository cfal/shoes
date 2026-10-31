use futures::FutureExt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

use bytes::BytesMut;
use dashmap::DashMap;
use log::{debug, error};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::copy_bidirectional::copy_bidirectional_with_sizes;
use crate::resolver::Resolver;
use crate::routing::udp_relay::UdpRelay;
use crate::stream_reader::StreamReader;
use crate::tcp::ingress::PreparedTcp;
use crate::udp_fragments::UdpFragments;
use crate::util::write_all;

mod pre_auth;

const COMMAND_TYPE_AUTHENTICATE: u8 = 0x00;
const COMMAND_TYPE_CONNECT: u8 = 0x01;
const COMMAND_TYPE_PACKET: u8 = 0x02;
const COMMAND_TYPE_DISSOCIATE: u8 = 0x03;
const COMMAND_TYPE_HEARTBEAT: u8 = 0x04;

// hostname case: type (1) + hostname length (1) + hostname bytes (255) + port (2)
const MAX_ADDRESS_BYTES_LEN: usize = 1 + 1 + 255 + 2;
const MAX_HEADER_LEN: usize = 2 + 2 + 2 + 1 + 1 + 2 + MAX_ADDRESS_BYTES_LEN;

const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Authentication timeout - close connection if client doesn't authenticate within this time.
/// Default is 3 seconds per sing-box reference implementation.
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);
const UNI_STREAM_WINDOW: u32 = 4096;

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
    pre_auth_settings: pre_auth::Settings,
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
    let pending_commands = match timeout(
        AUTH_TIMEOUT,
        pre_auth::authenticate(&connection, &uuid, &password, pre_auth_settings),
    )
    .await
    {
        Ok(Ok(pending)) => pending,
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
    };

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

    let bi_loop = run_bidirectional_loop(
        bi_connection,
        bi_client_proxy_selector,
        bi_resolver,
        pending_commands.bi,
    );

    let uni_loop = run_unidirectional_loop(
        uni_connection,
        uni_client_proxy_selector,
        uni_resolver,
        uni_udp_session_map,
        uni_cancel_token,
        pending_commands.uni,
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

async fn run_bidirectional_loop(
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    pending: Vec<pre_auth::BiReader>,
) -> std::io::Result<()> {
    let mut tasks = JoinSet::new();
    let mut pending = pending.into_iter();
    loop {
        let reader = if let Some(reader) = pending.next() {
            reader
        } else {
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

            let stream =
                pre_auth::BufferedBi::new(send_stream, recv_stream, connection.remote_address());
            futures::future::ready(Ok(Some(stream))).boxed()
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
            let result = async {
                let Some(stream) = reader.await? else {
                    return Ok(());
                };
                process_tcp_stream(client_proxy_selector, resolver, stream.into_stream()).await
            }
            .await;
            match result {
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

async fn read_address<R: tokio::io::AsyncRead + Unpin>(
    recv: &mut R,
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

async fn process_tcp_stream(
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    mut stream: Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    let mut stream_reader = StreamReader::new_with_buffer_size(1024);
    let tuic_version = stream_reader.read_u8(&mut stream).await?;
    if tuic_version != 5 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid tuic version: {tuic_version}"),
        ));
    }
    let command_type = stream_reader.read_u8(&mut stream).await?;
    if command_type != COMMAND_TYPE_CONNECT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid command type: {command_type}"),
        ));
    }

    let remote_location = read_address(&mut stream, &mut stream_reader)
        .await?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "empty address"))?;

    relay_tcp_stream(
        stream,
        remote_location,
        stream_reader.into_unparsed_data(),
        client_proxy_selector,
        resolver,
    )
    .await
}

async fn relay_tcp_stream(
    mut server_stream: Box<dyn AsyncStream>,
    remote_location: NetLocation,
    initial_data: Vec<u8>,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()> {
    let setup_client_stream_future = async {
        let route = timeout(Duration::from_secs(60), async {
            let prepared = PreparedTcp::new(
                &client_proxy_selector,
                remote_location.clone(),
                initial_data,
            )?
            .with_source(server_stream.peer_addr());
            prepared
                .route(&mut server_stream, &client_proxy_selector, &resolver)
                .await
        })
        .await?;
        match route {
            Ok(route) => timeout(Duration::from_secs(60), route.connect(&resolver)).await,
            Err(error) => Ok(Err(error)),
        }
    };

    let routed = match setup_client_stream_future.await {
        Ok(Ok(routed)) => routed,
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
    drop(client_proxy_selector);
    drop(resolver);
    let Some(crate::tcp::tcp_handler::TcpClientSetupResult {
        mut client_stream,
        early_data,
    }) = routed.setup
    else {
        crate::util::shutdown_stream(&mut server_stream).await;
        return Ok(());
    };

    let flow = client_stream.flow().cloned();
    crate::control::tracked_stream::during_flow(
        flow.as_deref(),
        crate::util::timeout_stream_setup(async {
            if let Some(data) = early_data {
                write_all(&mut server_stream, &data).await?;
                server_stream.flush().await?;
            }
            if !routed.prefix.is_empty() {
                write_all(&mut client_stream, &routed.prefix).await?;
                client_stream.flush().await?;
            }
            Ok(())
        }),
    )
    .await?;
    drop(routed.prefix);

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

    crate::util::shutdown_stream_pair(&mut server_stream, &mut client_stream).await;

    copy_result?;
    Ok(())
}

struct UdpSession {
    send_socket: Arc<UdpRelay>,
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
    fn start(
        assoc_id: u16,
        connection: quinn::Connection,
        client_socket: Arc<UdpRelay>,
        is_uni_stream: bool,
        parent_cancel_token: &CancellationToken,
        permit: crate::resources::BudgetPermit,
    ) -> Self {
        // Create a child token so this session is cancelled when the parent (connection) is cancelled
        let session_cancel_token = parent_cancel_token.child_token();

        let mut session = UdpSession {
            send_socket: client_socket.clone(),
            cancel_token: session_cancel_token.clone(),
            task: None,
            _permit: Some(permit),
        };

        session.task = Some(
            tokio::spawn(async move {
                let result = if is_uni_stream {
                    run_udp_remote_to_local_stream_loop(
                        assoc_id,
                        connection,
                        client_socket,
                        session_cancel_token,
                    )
                    .await
                } else {
                    run_udp_remote_to_local_datagram_loop(
                        assoc_id,
                        connection,
                        client_socket,
                        session_cancel_token,
                    )
                    .await
                };
                if let Err(e) = result {
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
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
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

        let address_bytes = serialize_address(&src_addr);

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
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    use bytes::BufMut;

    let max_datagram_size = connection
        .max_datagram_size()
        .ok_or_else(|| std::io::Error::other("datagram not supported by remote endpoint"))?;

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

        let address_bytes = serialize_address(&src_addr);
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
    pending_commands: Vec<pre_auth::UniReader>,
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

    let mut pending_commands = pending_commands.into_iter();
    loop {
        let reader = if let Some(pending) = pending_commands.next() {
            pending
        } else {
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

            pre_auth::read_uni_stream(recv_stream).boxed()
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
                    reader,
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
    reader: pre_auth::UniReader,
    udp_session_map: UdpSessionMap,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let Some(command) = reader.await? else {
        return Ok(());
    };
    let pre_auth::UniCommand::Data(data) = command else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "duplicate TUIC authentication",
        ));
    };
    let command_type = data[1];

    if command_type == COMMAND_TYPE_DISSOCIATE {
        let assoc_id = u16::from_be_bytes([data[2], data[3]]);
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

    let packet = parse_udp_packet(&data)?;

    process_udp_packet(
        connection,
        &client_proxy_selector,
        &resolver,
        &udp_session_map,
        packet,
        true,
        &cancel_token,
    )
    .await
}

#[inline]
async fn process_udp_packet(
    connection: &quinn::Connection,
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    udp_session_map: &UdpSessionMap,
    packet: UdpPacket<'_>,
    is_uni_stream: bool,
    cancel_token: &CancellationToken,
) -> std::io::Result<()> {
    let UdpPacket {
        assoc_id,
        packet_id,
        frag_total,
        frag_id,
        remote_location,
        payload_fragment,
    } = packet;
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
                let client_socket = UdpRelay::new(
                    client_proxy_selector.clone(),
                    resolver.clone(),
                    Some(connection.remote_address()),
                )?;

                let session = UdpSession::start(
                    assoc_id,
                    connection.clone(),
                    Arc::new(client_socket),
                    is_uni_stream,
                    cancel_token,
                    permit,
                );

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

    if let Err(e) = session.send_socket.send_to(payload, remote_location) {
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

        let packet = parse_udp_packet(&data)?;

        if let Err(e) = process_udp_packet(
            &connection,
            &client_proxy_selector,
            &resolver,
            &udp_session_map,
            packet,
            false,
            &cancel_token,
        )
        .await
        {
            error!("Failed to process datagram UDP packet: {e}");
        }
    }
}

fn configure_transport(
    server_config: &mut quinn::ServerConfig,
    limits: crate::config::GlobalLimits,
) -> (usize, pre_auth::Settings) {
    let settings = pre_auth::Settings::new(limits);
    let memory_bytes = crate::resources::configure_quic_with_limits(
        server_config,
        4096,
        UNI_STREAM_WINDOW,
        limits,
    );
    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        // AUTH has its own transport slot, even when application admission is one stream.
        .max_concurrent_uni_streams(((settings.uni_streams + 1) as u32).into())
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
    (memory_bytes, settings)
}

#[allow(clippy::too_many_arguments)]
pub async fn start_tuic_server(
    bind_address: SocketAddr,
    quic_server_config: Arc<dyn quinn::crypto::ServerConfig>,
    uuid: Arc<[u8]>,
    password: Arc<str>,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    num_endpoints: usize,
    zero_rtt_handshake: bool,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let mut join_handles = vec![];
    let mut server_config = quinn::ServerConfig::with_crypto(quic_server_config);

    let (memory_bytes, pre_auth_settings) =
        configure_transport(&mut server_config, crate::resources::limits());

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
                        pre_auth_settings,
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

    #[tokio::test]
    async fn udp_session_keeps_first_reply_mode_and_releases_real_tasks() {
        timeout(Duration::from_secs(10), async {
            for initial_stream_mode in [false, true] {
                let (server, client) = crate::quic_endpoint::test_endpoints_with_config(|config| {
                    configure_transport(config, crate::config::GlobalLimits::default());
                });
                let (peer, connection) = tokio::join!(
                    client
                        .connect(server.local_addr().unwrap(), "localhost")
                        .unwrap(),
                    async { server.accept().await.unwrap().await },
                );
                let peer = peer.unwrap();
                let connection = connection.unwrap();
                let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
                let selector = Arc::new(
                    crate::tcp::tcp_client_handler_factory::create_test_selector(
                        vec![crate::config::RuleConfig::default()],
                        resolver.clone(),
                    )
                    .unwrap(),
                );
                let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let target = socket.local_addr().unwrap();
                let destination = NetLocation::from_ip_addr(target.ip(), target.port());
                let map = Arc::new(UdpState::new());
                let parent = CancellationToken::new();
                for generation in 0..2 {
                    let first_mode = initial_stream_mode ^ (generation != 0);
                    for (index, receive_mode) in [first_mode, !first_mode].into_iter().enumerate() {
                        let payload = [generation, index as u8, 42];
                        process_udp_packet(
                            &connection,
                            &selector,
                            &resolver,
                            &map,
                            UdpPacket {
                                assoc_id: 7,
                                packet_id: index as u16,
                                frag_total: 1,
                                frag_id: 0,
                                remote_location: Some(destination.clone()),
                                payload_fragment: &payload,
                            },
                            receive_mode,
                            &parent,
                        )
                        .await
                        .unwrap();
                        let mut request = [0; 64];
                        let (length, source) = socket.recv_from(&mut request).await.unwrap();
                        assert_eq!(&request[..length], &payload);
                        socket.send_to(&payload, source).await.unwrap();
                        let (stream_mode, wire) = tokio::select! {
                            stream = peer.accept_uni() => (true, stream.unwrap().read_to_end(1024).await.unwrap()),
                            data = peer.read_datagram() => (false, data.unwrap().to_vec()),
                        };
                        assert_eq!(stream_mode, first_mode);
                        let reply = parse_udp_packet(&wire).unwrap();
                        assert_eq!(reply.assoc_id, 7);
                        assert_eq!(reply.remote_location, Some(destination.clone()));
                        assert_eq!(reply.payload_fragment, payload);
                        assert_eq!(map.sessions.len(), 1);
                        assert_eq!(map.slots.snapshot().active, 1);
                    }
                    let (relay, task, child) = {
                        let entry = map.sessions.get(&7).unwrap();
                        (
                            Arc::downgrade(&entry.send_socket),
                            entry.task.clone().unwrap(),
                            entry.cancel_token.clone(),
                        )
                    };
                    if generation == 1 {
                        parent.cancel();
                        while !task.is_finished() {
                            tokio::task::yield_now().await;
                        }
                    }
                    map.sessions.remove(&7);
                    while relay.upgrade().is_some() || !task.is_finished() {
                        tokio::task::yield_now().await;
                    }
                    assert!(child.is_cancelled());
                    assert_eq!(map.slots.snapshot().active, 0);
                }
                connection.close(0u32.into(), b"done");
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn fake_dns_adapter_contract() {
        use crate::tcp::ingress::tests::FakeTcpCase;
        use tokio::io::AsyncReadExt;
        timeout(Duration::from_secs(10), async {
            for case in [
                FakeTcpCase::Dns,
                FakeTcpCase::Tls,
                FakeTcpCase::Http,
                FakeTcpCase::Plain,
                FakeTcpCase::Unknown,
            ] {
                let mut tasks = JoinSet::new();
                let (selector, resolver, target, payload) = case.fixture(&mut tasks).await;
                let split = payload.len().min(5);
                let prefix = payload[..split].to_vec();
                let (server, mut peer) = tokio::io::duplex(8192);
                tasks.spawn(async move {
                    let result =
                        relay_tcp_stream(Box::new(server), target, prefix, selector, resolver)
                            .await;
                    assert_eq!(result.is_err(), case == FakeTcpCase::Unknown);
                });
                peer.write_all(&payload[split..]).await.unwrap();
                peer.shutdown().await.unwrap();
                let mut reply = Vec::new();
                peer.read_to_end(&mut reply).await.unwrap();
                if case == FakeTcpCase::Unknown {
                    assert!(reply.is_empty());
                } else {
                    case.assert_reply(&reply);
                }
                while let Some(result) = tasks.join_next().await {
                    result.unwrap();
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn sniff_replays_header_tail_without_an_ack_frame() {
        use tokio::io::AsyncReadExt;
        timeout(Duration::from_secs(5), async {
            let mut tasks = JoinSet::new();
            let hello = crate::sniff::tests::hello(&rustls::version::TLS13, true);
            let (selector, resolver) =
                crate::tcp::ingress::tests::socks_target(hello.clone(), &mut tasks).await;
            let target = NetLocation::from_str(crate::tcp::ingress::tests::TARGET, None).unwrap();
            let (server, mut peer) = tokio::io::duplex(8192);
            let prefix = hello[..5].to_vec();
            tasks.spawn(async move {
                relay_tcp_stream(Box::new(server), target, prefix, selector, resolver)
                    .await
                    .unwrap();
            });
            peer.write_all(&hello[5..]).await.unwrap();
            peer.shutdown().await.unwrap();
            let mut response = Vec::new();
            peer.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"greetinglater");
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        })
        .await
        .unwrap();
    }

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
                None,
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

#[cfg(test)]
mod auth_tests {
    use super::*;
    use crate::tcp::tcp_client_handler_factory::create_test_selector;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const UUID: [u8; 16] = [0x55; 16];
    const PASSWORD: &str = "tuic-password";

    struct Peer {
        connection: quinn::Connection,
        server: tokio::task::JoinHandle<std::io::Result<()>>,
        _endpoints: (quinn::Endpoint, quinn::Endpoint),
    }

    async fn connect(selector: Arc<ClientProxySelector>) -> Peer {
        connect_with_resolver(selector, Arc::new(crate::resolver::NativeResolver::new())).await
    }

    async fn connect_with_resolver(
        selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Peer {
        connect_with_limits(selector, resolver, crate::resources::limits()).await
    }

    async fn connect_with_limits(
        selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
        limits: crate::config::GlobalLimits,
    ) -> Peer {
        let mut settings = pre_auth::Settings::new(limits);
        let (server, client) = crate::quic_endpoint::test_endpoints_with_config(|config| {
            settings = configure_transport(config, limits).1;
        });
        let address = server.local_addr().unwrap();
        let accepting = server.clone();
        let server_task = tokio::spawn(async move {
            let incoming = accepting.accept().await.unwrap();
            process_connection(
                selector,
                resolver,
                Arc::from(UUID.as_slice()),
                PASSWORD.into(),
                incoming.accept().unwrap(),
                false,
                settings,
            )
            .await
        });
        let connection = client.connect(address, "localhost").unwrap().await.unwrap();
        Peer {
            connection,
            server: server_task,
            _endpoints: (server, client),
        }
    }

    async fn send_uni(connection: &quinn::Connection, bytes: &[u8]) {
        let mut stream = connection.open_uni().await.unwrap();
        stream.write_all(bytes).await.unwrap();
        stream.finish().unwrap();
    }

    fn authenticate_command(connection: &quinn::Connection, password: &str) -> Vec<u8> {
        let mut token = [0; 32];
        connection
            .export_keying_material(&mut token, &UUID, password.as_bytes())
            .unwrap();
        let mut command = vec![5, COMMAND_TYPE_AUTHENTICATE];
        command.extend_from_slice(&UUID);
        command.extend_from_slice(&token);
        command
    }

    fn packet(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![5, COMMAND_TYPE_PACKET, 0, 1, 0, 1, 1, 0];
        bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&serialize_address(&NetLocation::from_ip_addr(
            target.ip(),
            target.port(),
        )));
        bytes.extend_from_slice(payload);
        bytes
    }

    async fn direct_peer(limits: crate::config::GlobalLimits) -> Peer {
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let selector = Arc::new(
            create_test_selector(vec![crate::config::RuleConfig::default()], resolver.clone())
                .unwrap(),
        );
        connect_with_limits(selector, resolver, limits).await
    }

    async fn tcp_roundtrip(peer: &Peer) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (mut send, mut recv) = peer.connection.open_bi().await.unwrap();
        let mut request = vec![5, COMMAND_TYPE_CONNECT];
        let address = listener.local_addr().unwrap();
        request.extend_from_slice(&serialize_address(&NetLocation::from_ip_addr(
            address.ip(),
            address.port(),
        )));
        request.extend_from_slice(b"hello");
        send.write_all(&request).await.unwrap();
        send.finish().unwrap();
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut data = Vec::new();
        socket.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"hello");
        socket.write_all(&data).await.unwrap();
        socket.shutdown().await.unwrap();
        assert_eq!(recv.read_to_end(1024).await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn largest_early_packets_release_receive_credit_without_fin() {
        timeout(Duration::from_secs(20), async {
            for stream_window in [16384, 65536] {
                for limit in [Some(1), Some(4), None] {
                    for bind in ["127.0.0.1:0", "[::1]:0"] {
                        let socket = tokio::net::UdpSocket::bind(bind).await.unwrap();
                        let peer = direct_peer(crate::config::GlobalLimits {
                            max_streams_per_connection: limit,
                            quic_receive_window: 65536,
                            quic_stream_window: stream_window,
                            ..Default::default()
                        })
                        .await;
                        let payload = vec![0x71; 65507];
                        let command = packet(socket.local_addr().unwrap(), &payload);
                        let mut early = peer.connection.open_uni().await.unwrap();
                        early.write_all(&command).await.unwrap();
                        // Complete framed commands release credit without requiring a FIN.
                        assert_eq!(early.stopped().await.unwrap(), Some(0u32.into()));
                        let mut received = vec![0; 65535];
                        assert!(
                            timeout(Duration::from_millis(20), socket.recv(&mut received))
                                .await
                                .is_err()
                        );
                        let mut auth = peer.connection.open_uni().await.unwrap();
                        auth.write_all(&authenticate_command(&peer.connection, PASSWORD))
                            .await
                            .unwrap();
                        let len = socket.recv(&mut received).await.unwrap();
                        assert_eq!(&received[..len], &payload);
                        tcp_roundtrip(&peer).await;
                        peer.connection.close(0u32.into(), b"done");
                        let _ = peer.server.await;
                    }
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn delayed_auth_is_not_evicted_by_higher_stream_ids() {
        timeout(Duration::from_secs(10), async {
            for limit in [1, 2] {
                for prefix_len in [0, 1] {
                    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    let peer = direct_peer(crate::config::GlobalLimits {
                        max_streams_per_connection: Some(limit),
                        quic_receive_window: 65536,
                        quic_stream_window: 16384,
                        ..Default::default()
                    })
                    .await;
                    let command = authenticate_command(&peer.connection, PASSWORD);
                    let mut auth = peer.connection.open_uni().await.unwrap();
                    auth.write_all(&command[..prefix_len]).await.unwrap();
                    let mut partials = Vec::new();
                    for _ in 1..limit {
                        partials.push(peer.connection.open_uni().await.unwrap());
                    }
                    let mut data = peer.connection.open_uni().await.unwrap();
                    data.write_all(&packet(socket.local_addr().unwrap(), b"reordered"))
                        .await
                        .unwrap();
                    // A higher stream ID implicitly opens earlier streams before their bytes arrive.
                    assert_eq!(data.stopped().await.unwrap(), Some(0u32.into()));
                    auth.write_all(&command[prefix_len..]).await.unwrap();
                    let mut response = [0; 32];
                    let len = socket.recv(&mut response).await.unwrap();
                    assert_eq!(&response[..len], b"reordered");
                    tcp_roundtrip(&peer).await;
                    peer.connection.close(0u32.into(), b"done");
                    let _ = peer.server.await;
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn stalled_headers_and_split_auth_keep_a_control_slot() {
        timeout(Duration::from_secs(15), async {
            for limit in [1, 4] {
                for auth_first in [false, true] {
                    let peer = direct_peer(crate::config::GlobalLimits {
                        max_streams_per_connection: Some(limit),
                        quic_receive_window: 65536,
                        quic_stream_window: 16384,
                        ..Default::default()
                    })
                    .await;
                    let mut auth = if auth_first {
                        let mut auth = peer.connection.open_uni().await.unwrap();
                        auth.write_all(&[5, COMMAND_TYPE_AUTHENTICATE])
                            .await
                            .unwrap();
                        Some(auth)
                    } else {
                        None
                    };
                    let mut stalled = if !auth_first || limit > 1 {
                        let mut stream = peer.connection.open_uni().await.unwrap();
                        stream.write_all(&[5]).await.unwrap();
                        Some(stream)
                    } else {
                        None
                    };
                    if auth_first {
                        for id in 0..8 {
                            send_uni(&peer.connection, &[5, COMMAND_TYPE_DISSOCIATE, 0, id]).await;
                        }
                        auth.as_mut()
                            .unwrap()
                            .write_all(&authenticate_command(&peer.connection, PASSWORD)[2..])
                            .await
                            .unwrap();
                    } else {
                        send_uni(
                            &peer.connection,
                            &authenticate_command(&peer.connection, PASSWORD),
                        )
                        .await;
                    }
                    tcp_roundtrip(&peer).await;
                    if let Some(stream) = &mut stalled {
                        let _ = stream.reset(0u32.into());
                    }
                    peer.connection.close(0u32.into(), b"done");
                    let _ = peer.server.await;
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn early_tcp_returns_credit_and_rejects_whole_streams_on_overflow() {
        timeout(Duration::from_secs(15), async {
            for (overflow, finish_early) in [(false, false), (false, true), (true, false)] {
                let peer = direct_peer(crate::config::GlobalLimits {
                    max_streams_per_connection: Some(1),
                    quic_receive_window: 65536,
                    quic_stream_window: 16384,
                    ..Default::default()
                })
                .await;
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let target = listener.local_addr().unwrap();
                let (mut send, mut recv) = peer.connection.open_bi().await.unwrap();
                let payload = vec![42; if overflow { 100000 } else { 65536 }];
                let mut request = vec![5, COMMAND_TYPE_CONNECT];
                request.extend_from_slice(&serialize_address(&NetLocation::from_ip_addr(
                    target.ip(),
                    target.port(),
                )));
                request.extend_from_slice(&payload);
                let write = send.write_all(&request).await;
                if overflow {
                    let _ = write;
                    assert_eq!(send.stopped().await.unwrap(), Some(0u32.into()));
                } else {
                    write.unwrap();
                    if finish_early {
                        send.finish().unwrap();
                    }
                }
                assert!(
                    timeout(Duration::from_millis(20), listener.accept())
                        .await
                        .is_err()
                );
                send_uni(
                    &peer.connection,
                    &authenticate_command(&peer.connection, PASSWORD),
                )
                .await;
                if overflow {
                    assert!(
                        timeout(Duration::from_secs(1), recv.read_to_end(100))
                            .await
                            .expect("overflow stream must reset")
                            .is_err()
                    );
                    assert!(
                        timeout(Duration::from_millis(20), listener.accept())
                            .await
                            .is_err()
                    );
                } else {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    if !finish_early {
                        send.finish().unwrap();
                    }
                    let echo = tokio::spawn(async move {
                        let mut data = Vec::new();
                        socket.read_to_end(&mut data).await.unwrap();
                        assert_eq!(data, payload);
                        socket.write_all(&data).await.unwrap();
                        socket.shutdown().await.unwrap();
                    });
                    assert_eq!(recv.read_to_end(100000).await.unwrap(), vec![42; 65536]);
                    echo.await.unwrap();
                }
                // STOP_SENDING returns data credit; the sender must reset to release its slot.
                drop(send);
                timeout(Duration::from_secs(2), tcp_roundtrip(&peer))
                    .await
                    .expect("subsequent TCP stream must work");
                peer.connection.close(0u32.into(), b"done");
                let _ = peer.server.await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn early_udp_streams_wait_for_auth_and_keep_each_destination() {
        #[derive(Debug)]
        struct LocalResolver;
        impl Resolver for LocalResolver {
            fn resolve_location(&self, location: &NetLocation) -> crate::resolver::ResolveFuture {
                let port = location.port();
                Box::pin(async move { Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))]) })
            }
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            for stream_mode in [true, false] {
                let first = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let second = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let resolver: Arc<dyn Resolver> = Arc::new(LocalResolver);
                let peer = connect_with_resolver(
                    Arc::new(
                        create_test_selector(
                            vec![crate::config::RuleConfig::default()],
                            resolver.clone(),
                        )
                        .unwrap(),
                    ),
                    resolver,
                )
                .await;
                let packet = |target: &NetLocation, id: u16| {
                    let mut bytes = vec![5, COMMAND_TYPE_PACKET, 0, 1];
                    bytes.extend_from_slice(&id.to_be_bytes());
                    bytes.extend_from_slice(&[1, 0, 0, 5]);
                    bytes.extend_from_slice(&serialize_address(target));
                    bytes.extend_from_slice(b"hello");
                    bytes
                };
                let first_target = NetLocation::new(
                    Address::Hostname("localhost".into()),
                    first.local_addr().unwrap().port(),
                );
                let bytes = packet(&first_target, 1);
                if stream_mode {
                    send_uni(&peer.connection, &bytes).await;
                } else {
                    peer.connection.send_datagram(bytes.into()).unwrap();
                }
                let mut buf = [0; 32];
                assert!(
                    timeout(Duration::from_millis(50), first.recv_from(&mut buf))
                        .await
                        .is_err()
                );
                send_uni(
                    &peer.connection,
                    &authenticate_command(&peer.connection, PASSWORD),
                )
                .await;
                for (index, socket) in [&first, &second].into_iter().enumerate() {
                    if index == 1 {
                        let target = NetLocation::from_ip_addr(
                            socket.local_addr().unwrap().ip(),
                            socket.local_addr().unwrap().port(),
                        );
                        let bytes = packet(&target, 2);
                        if stream_mode {
                            send_uni(&peer.connection, &bytes).await;
                        } else {
                            peer.connection.send_datagram(bytes.into()).unwrap();
                        }
                    }
                    let (count, from) = socket.recv_from(&mut buf).await.unwrap();
                    assert_eq!(&buf[..count], b"hello");
                    socket.send_to(b"reply", from).await.unwrap();
                    let response = if stream_mode {
                        peer.connection
                            .accept_uni()
                            .await
                            .unwrap()
                            .read_to_end(1024)
                            .await
                            .unwrap()
                    } else {
                        loop {
                            let data = peer.connection.read_datagram().await.unwrap();
                            if data.get(1) == Some(&COMMAND_TYPE_PACKET) {
                                break data.to_vec();
                            }
                        }
                    };
                    let parsed = parse_udp_packet(&response).unwrap();
                    assert_eq!(parsed.payload_fragment, b"reply");
                    assert_eq!(
                        parsed.remote_location.unwrap().port(),
                        socket.local_addr().unwrap().port()
                    );
                }
                peer.connection.close(0u32.into(), b"done");
                let _ = peer.server.await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn authenticated_clients_can_connect_after_earlier_commands() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = echo.local_addr().unwrap().port();
            let echo_task = tokio::spawn(async move {
                let (mut socket, _) = echo.accept().await.unwrap();
                let mut request = [0; 5];
                socket.read_exact(&mut request).await.unwrap();
                socket.write_all(&request).await.unwrap();
                socket.shutdown().await.unwrap();
            });
            let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
            let peer = connect(Arc::new(
                create_test_selector(vec![crate::config::RuleConfig::default()], resolver).unwrap(),
            ))
            .await;

            // Commands may precede authentication and are dispatched only after it succeeds.
            let mut partial = peer.connection.open_uni().await.unwrap();
            partial.write_all(&[5]).await.unwrap();
            send_uni(&peer.connection, &[5, COMMAND_TYPE_DISSOCIATE, 0, 1]).await;
            send_uni(
                &peer.connection,
                &authenticate_command(&peer.connection, PASSWORD),
            )
            .await;

            let (mut send, mut recv) = peer.connection.open_bi().await.unwrap();
            let mut connect = vec![5, COMMAND_TYPE_CONNECT, 0x01, 127, 0, 0, 1];
            connect.extend_from_slice(&port.to_be_bytes());
            connect.extend_from_slice(b"hello");
            send.write_all(&connect).await.unwrap();
            send.finish().unwrap();
            assert_eq!(recv.read_to_end(1024).await.unwrap(), b"hello");
            partial
                .write_all(&[COMMAND_TYPE_DISSOCIATE, 0, 2])
                .await
                .unwrap();
            partial.finish().unwrap();
            echo_task.await.unwrap();
            assert!(!peer.server.is_finished());
            peer.connection.close(0u32.into(), b"done");
            let _ = peer.server.await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn packet_before_auth_is_retained_without_pre_auth_dispatch() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let echo = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
            let target = NetLocation::from_str(
                &format!("127.0.0.1:{}", echo.local_addr().unwrap().port()),
                None,
            )
            .unwrap();
            let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
            let peer = connect(Arc::new(
                create_test_selector(vec![crate::config::RuleConfig::default()], resolver).unwrap(),
            ))
            .await;
            let mut packet = vec![5, COMMAND_TYPE_PACKET, 0, 7, 0, 9, 1, 0, 0, 5];
            packet.extend_from_slice(&serialize_address(&target));
            packet.extend_from_slice(b"first");
            send_uni(&peer.connection, &packet).await;
            let mut buffer = [0; 64];
            assert!(
                tokio::time::timeout(Duration::from_millis(50), echo.recv_from(&mut buffer))
                    .await
                    .is_err()
            );
            send_uni(
                &peer.connection,
                &authenticate_command(&peer.connection, PASSWORD),
            )
            .await;
            let (length, remote) = echo.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], b"first");
            echo.send_to(b"reply", remote).await.unwrap();
            let mut receive = peer.connection.accept_uni().await.unwrap();
            let response = receive.read_to_end(1024).await.unwrap();
            assert!(response.ends_with(b"reply"));
            peer.connection.close(0u32.into(), b"done");
            let _ = peer.server.await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn rejected_authentication_closes_the_connection() {
        tokio::time::timeout(Duration::from_secs(10), async {
            for (case, version, uuid, password) in [
                ("wrong uuid", 5, [0x66; 16], PASSWORD),
                ("wrong password", 5, UUID, "wrong-password"),
                ("unsupported version", 4, UUID, PASSWORD),
            ] {
                let peer = connect(Arc::new(ClientProxySelector::new(Vec::new()))).await;
                // The token always binds UUID, so a wrong UUID is sent with a valid token.
                let mut command = authenticate_command(&peer.connection, password);
                command[0] = version;
                command[2..18].copy_from_slice(&uuid);
                send_uni(&peer.connection, &command).await;
                match peer.connection.closed().await {
                    quinn::ConnectionError::ApplicationClosed(close) => {
                        assert_eq!(&close.reason[..], b"auth failed", "{case}");
                    }
                    other => panic!("{case}: unexpected close {other:?}"),
                }
                assert!(peer.server.await.unwrap().is_err(), "{case}");
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn pre_auth_pressure_and_cleanup_release_stream_permits() {
        if std::env::var_os("SHOES_TUIC_PRESSURE_CHILD").is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tuic_server::auth_tests::pre_auth_pressure_and_cleanup_release_stream_permits",
                    "--quiet",
                ])
                .env("SHOES_TUIC_PRESSURE_CHILD", "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed;"));
            return;
        }
        crate::resources::configure(crate::config::GlobalLimits {
            max_streams: Some(3),
            max_streams_per_connection: Some(4),
            ..Default::default()
        })
        .unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                timeout(Duration::from_secs(15), async {
                    let configured = crate::resources::limits();
                    crate::resources::configure(crate::config::GlobalLimits {
                        max_streams: Some(1),
                        ..configured
                    })
                    .unwrap();
                    let unauthenticated = direct_peer(crate::resources::limits()).await;
                    send_uni(
                        &unauthenticated.connection,
                        &[5, COMMAND_TYPE_DISSOCIATE, 0, 1],
                    )
                    .await;
                    while crate::resources::snapshot().quic_buffer_bytes.active == 0 {
                        tokio::task::yield_now().await;
                    }
                    assert_eq!(crate::resources::snapshot().streams.active, 0);
                    let authenticated = direct_peer(crate::resources::limits()).await;
                    send_uni(
                        &authenticated.connection,
                        &authenticate_command(&authenticated.connection, PASSWORD),
                    )
                    .await;
                    tcp_roundtrip(&authenticated).await;
                    authenticated.connection.close(0u32.into(), b"done");
                    let _ = authenticated.server.await;
                    unauthenticated.server.abort();
                    let _ = unauthenticated.server.await;
                    assert_eq!(crate::resources::snapshot().quic_buffer_bytes.active, 0);
                    crate::resources::configure(configured).unwrap();

                    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    let peer = direct_peer(crate::config::GlobalLimits {
                        quic_receive_window: 131072,
                        ..configured
                    })
                    .await;
                    crate::resources::configure(crate::config::GlobalLimits {
                        quic_receive_window: 65536,
                        ..configured
                    })
                    .unwrap();
                    let payload = vec![42; 40000];
                    for _ in 0..2 {
                        let mut stream = peer.connection.open_uni().await.unwrap();
                        stream
                            .write_all(&packet(socket.local_addr().unwrap(), &payload))
                            .await
                            .unwrap();
                        assert_eq!(stream.stopped().await.unwrap(), Some(0u32.into()));
                    }
                    // Existing listeners retain their staging allowance across a window reload.
                    assert_eq!(crate::resources::snapshot().quic_buffer_bytes.active, 80034);
                    send_uni(
                        &peer.connection,
                        &authenticate_command(&peer.connection, PASSWORD),
                    )
                    .await;
                    let mut response = vec![0; 65535];
                    for _ in 0..2 {
                        let len = socket.recv(&mut response).await.unwrap();
                        assert_eq!(&response[..len], &payload);
                    }
                    peer.connection.close(0u32.into(), b"done");
                    let _ = peer.server.await;
                    assert_eq!(crate::resources::snapshot().quic_buffer_bytes.active, 0);

                    let peer = direct_peer(configured).await;
                    let rejected = crate::resources::snapshot().quic_buffer_bytes.rejected;
                    crate::resources::configure(crate::config::GlobalLimits {
                        quic_memory_bytes: Some(1),
                        ..configured
                    })
                    .unwrap();
                    let mut early = peer.connection.open_uni().await.unwrap();
                    early
                        .write_all(&packet(socket.local_addr().unwrap(), b"denied"))
                        .await
                        .unwrap();
                    assert_eq!(early.stopped().await.unwrap(), Some(0u32.into()));
                    assert!(crate::resources::snapshot().quic_buffer_bytes.rejected > rejected);
                    assert_eq!(crate::resources::snapshot().quic_buffer_bytes.active, 0);
                    send_uni(
                        &peer.connection,
                        &authenticate_command(&peer.connection, PASSWORD),
                    )
                    .await;
                    tcp_roundtrip(&peer).await;
                    assert!(
                        timeout(Duration::from_millis(20), socket.recv(&mut response))
                            .await
                            .is_err()
                    );
                    peer.connection.close(0u32.into(), b"done");
                    let _ = peer.server.await;
                    crate::resources::configure(configured).unwrap();

                    for case in [
                        "success",
                        "invalid",
                        "timeout",
                        "cancel",
                        "truncated",
                        "peer_close",
                    ] {
                        let peer = direct_peer(crate::resources::limits()).await;
                        let mut stalled = peer.connection.open_uni().await.unwrap();
                        stalled.write_all(&[5]).await.unwrap();
                        for id in 0..8 {
                            send_uni(&peer.connection, &[5, COMMAND_TYPE_DISSOCIATE, 0, id]).await;
                        }
                        timeout(Duration::from_secs(1), async {
                            while crate::resources::snapshot().quic_buffer_bytes.active == 0 {
                                tokio::task::yield_now().await;
                            }
                        })
                        .await
                        .unwrap();
                        let mut bodies = None;
                        if case != "success" {
                            let mut partial = peer.connection.open_uni().await.unwrap();
                            partial
                                .write_all(&[5, 2, 0, 1, 0, 1, 1, 0, 255, 255, 0xff])
                                .await
                                .unwrap();
                            let (mut send, recv) = peer.connection.open_bi().await.unwrap();
                            send.write_all(&[5, COMMAND_TYPE_CONNECT]).await.unwrap();
                            while crate::resources::snapshot().quic_buffer_bytes.active
                                < 65546 + 4096
                            {
                                tokio::task::yield_now().await;
                            }
                            bodies = Some((partial, send, recv));
                        }
                        assert_eq!(crate::resources::snapshot().streams.active, 0);
                        match case {
                            "success" | "invalid" => {
                                let password = if case == "success" { PASSWORD } else { "wrong" };
                                send_uni(
                                    &peer.connection,
                                    &authenticate_command(&peer.connection, password),
                                )
                                .await;
                            }
                            "cancel" => peer.server.abort(),
                            "truncated" => send_uni(&peer.connection, &[5]).await,
                            "peer_close" => peer.connection.close(0u32.into(), b"done"),
                            _ => {}
                        }
                        if case == "success" {
                            tcp_roundtrip(&peer).await;
                            timeout(Duration::from_secs(1), async {
                                while crate::resources::snapshot().streams.active != 0 {
                                    tokio::task::yield_now().await;
                                }
                            })
                            .await
                            .unwrap();
                            assert!(!peer.server.is_finished());
                            peer.connection.close(0u32.into(), b"done");
                        }
                        let _ = peer.server.await;
                        drop(bodies);
                        assert_eq!(crate::resources::snapshot().streams.active, 0, "{case}");
                        assert_eq!(
                            crate::resources::snapshot().quic_buffer_bytes.active,
                            0,
                            "{case}"
                        );
                        assert!(crate::resources::snapshot().streams.peak <= 3, "{case}");
                        assert!(crate::resources::try_stream().is_some());
                    }
                })
                .await
                .unwrap();
            });
    }
}
