use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::str;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use log::{debug, error};
use lru::LruCache;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::copy_bidirectional::copy_bidirectional_with_sizes;
use crate::quic_stream::QuicStream;
use crate::resolver::{Resolver, resolve_single_address};
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_server::setup_client_tcp_stream;
use crate::util::{allocate_vec, write_all};

const COMMAND_TYPE_AUTHENTICATE: u8 = 0x00;
const COMMAND_TYPE_CONNECT: u8 = 0x01;
const COMMAND_TYPE_PACKET: u8 = 0x02;
const COMMAND_TYPE_DISSOCIATE: u8 = 0x03;
const COMMAND_TYPE_HEARTBEAT: u8 = 0x04;

// hostname case: type (1) + hostname length (1) + hostname bytes (255) + port (2)
const MAX_ADDRESS_BYTES_LEN: usize = 1 + 1 + 255 + 2;
const MAX_HEADER_LEN: usize = 2 + 2 + 1 + 1 + 2 + MAX_ADDRESS_BYTES_LEN;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum number of fragmented packets to track per connection.
/// Old entries are automatically evicted when this limit is reached.
const MAX_FRAGMENT_CACHE_SIZE: usize = 256;

/// Authentication timeout - close connection if client doesn't authenticate within this time.
/// Default is 3 seconds per sing-box reference implementation.
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);

/// Heartbeat interval - server sends heartbeat datagrams to client at this interval.
/// Default is 10 seconds per sing-box reference implementation.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

type UdpSessionMap = Arc<DashMap<u16, UdpSession>>;

async fn process_connection(
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    uuid: &'static [u8],
    password: &'static str,
    conn: quinn::Incoming,
    zero_rtt_handshake: bool,
) -> std::io::Result<()> {
    // Accept the incoming connection. When 0-RTT is enabled, use into_0rtt() to
    // allow 0.5-RTT data transmission before the handshake fully completes.
    // This reduces latency at the cost of some security (0-RTT data is vulnerable
    // to replay attacks, though for incoming server connections it's 0.5-RTT which
    // is safer but still shouldn't be used for client-authenticated data).
    let connection = if zero_rtt_handshake {
        let connecting = conn.accept().map_err(std::io::Error::other)?;
        // For incoming connections, into_0rtt() always succeeds per quinn docs
        let (connection, _zero_rtt_accepted) = connecting
            .into_0rtt()
            .map_err(|_| std::io::Error::other("failed to enable 0-RTT"))?;
        connection
    } else {
        conn.await?
    };

    // Authentication with timeout - per sing-box reference, default 3 seconds.
    // This prevents malicious clients from holding connections open without authenticating.
    match timeout(AUTH_TIMEOUT, auth_connection(&connection, uuid, password)).await {
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

    // this allows for:
    // 1. multiple threads can read different sessions concurrently
    // 2. multiple threads can modify different sessions concurrently
    // 3. the outer write lock is only needed for adding/removing sessions
    let udp_session_map = Arc::new(DashMap::new());

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
    uuid: &'static [u8],
    password: &'static str,
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

        let specified_uuid = stream_reader.read_slice(&mut recv_stream, 16).await?;
        if specified_uuid != uuid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("incorrect uuid: {specified_uuid:?}"),
            ));
        }
        let token_bytes = stream_reader.read_slice(&mut recv_stream, 32).await?;
        if token_bytes != expected_token_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "incorrect token",
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
    loop {
        let (send_stream, recv_stream) = match connection.accept_bi().await {
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
        let client_proxy_selector = client_proxy_selector.clone();
        let resolver = resolver.clone();
        tokio::spawn(async move {
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
        setup_client_tcp_stream(
            &mut server_stream,
            client_proxy_selector,
            resolver,
            remote_location.clone(),
        ),
    );

    let mut client_stream = match setup_client_stream_future.await {
        Ok(Ok(Some(s))) => s,
        Ok(Ok(None)) => {
            // Must have been blocked.
            let _ = server_stream.shutdown().await;
            return Ok(());
        }
        Ok(Err(e)) => {
            let _ = server_stream.shutdown().await;
            return Err(std::io::Error::new(
                e.kind(),
                format!("failed to setup client stream to {remote_location}: {e}"),
            ));
        }
        Err(elapsed) => {
            let _ = server_stream.shutdown().await;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("client setup to {remote_location} timed out: {elapsed}"),
            ));
        }
    };

    let unparsed_data = stream_reader.unparsed_data();
    let client_requires_flush = if unparsed_data.is_empty() {
        false
    } else {
        write_all(&mut client_stream, unparsed_data).await?;
        true
    };
    drop(stream_reader);

    // Use 32KB buffers to match reference implementations
    let copy_result = copy_bidirectional_with_sizes(
        &mut server_stream,
        &mut client_stream,
        false, // no need to flush since it's QUIC
        client_requires_flush,
        32768,
        32768,
    )
    .await;

    let (_, _) = futures::join!(server_stream.shutdown(), client_stream.shutdown());

    copy_result?;
    Ok(())
}

struct UdpSession {
    send_socket: Arc<UdpSocket>,
    // we cache the last location in case of mid-session address changes, and
    // don't want to have to call ClientProxySelector::judge on every packet.
    last_location: NetLocation,
    last_socket_addr: SocketAddr,
    override_remote_write_address: Option<SocketAddr>,
    last_activity: std::time::Instant,
    // Cancellation token for this session's background task
    cancel_token: CancellationToken,
}

struct FragmentedPacket {
    fragment_count: u8,
    fragment_received: u8,
    packet_len: usize,
    received: Vec<Option<Bytes>>,
    remote_location: Option<NetLocation>,
}

impl UdpSession {
    #[allow(clippy::too_many_arguments)]
    fn start_with_send_stream(
        assoc_id: u16,
        send_stream: quinn::SendStream,
        client_socket: Arc<UdpSocket>,
        initial_location: NetLocation,
        initial_socket_addr: SocketAddr,
        override_local_write_location: Option<NetLocation>,
        override_remote_write_address: Option<SocketAddr>,
        parent_cancel_token: &CancellationToken,
    ) -> Self {
        // Create a child token so this session is cancelled when the parent (connection) is cancelled
        let session_cancel_token = parent_cancel_token.child_token();

        let session = UdpSession {
            send_socket: client_socket.clone(),
            last_location: initial_location,
            last_socket_addr: initial_socket_addr,
            override_remote_write_address,
            last_activity: std::time::Instant::now(),
            cancel_token: session_cancel_token.clone(),
        };

        tokio::spawn(async move {
            if let Err(e) = run_udp_remote_to_local_stream_loop(
                assoc_id,
                send_stream,
                client_socket,
                override_local_write_location,
                session_cancel_token,
            )
            .await
            {
                error!("UDP remote-to-local write loop ended with error: {e}");
            }
        });

        session
    }

    #[allow(clippy::too_many_arguments)]
    fn start_with_datagram(
        assoc_id: u16,
        connection: quinn::Connection,
        client_socket: Arc<UdpSocket>,
        initial_location: NetLocation,
        initial_socket_addr: SocketAddr,
        override_local_write_location: Option<NetLocation>,
        override_remote_write_address: Option<SocketAddr>,
        parent_cancel_token: &CancellationToken,
    ) -> Self {
        // Create a child token so this session is cancelled when the parent (connection) is cancelled
        let session_cancel_token = parent_cancel_token.child_token();

        let session = UdpSession {
            send_socket: client_socket.clone(),
            last_location: initial_location,
            last_socket_addr: initial_socket_addr,
            override_remote_write_address,
            last_activity: std::time::Instant::now(),
            cancel_token: session_cancel_token.clone(),
        };

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
        });

        session
    }

    #[inline]
    async fn resolve_address(
        &self,
        location: &NetLocation,
        client_proxy_selector: &Arc<ClientProxySelector>,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<(SocketAddr, bool)> {
        let (addr, is_updated) = match self.override_remote_write_address {
            Some(addr) => (addr, false),
            None => {
                if location == &self.last_location {
                    (self.last_socket_addr, false)
                } else {
                    let action = client_proxy_selector
                        .judge(location.clone().into(), resolver)
                        .await?;

                    let updated_location = match action {
                        ConnectDecision::Allow {
                            chain_group: _,
                            remote_location,
                        } => remote_location,
                        ConnectDecision::Block => {
                            return Err(std::io::Error::other(format!(
                                "Blocked UDP forward to {location}"
                            )));
                        }
                    };
                    let updated_address =
                        match resolve_single_address(resolver, updated_location.location()).await {
                            Ok(s) => s,
                            Err(e) => {
                                error!("Failed to resolve updated remote location {location}: {e}");
                                return Err(e);
                            }
                        };

                    (updated_address, true)
                }
            }
        };

        Ok((addr, is_updated))
    }

    fn update_last_location(&mut self, location: NetLocation, socket_addr: SocketAddr) {
        self.last_location = location;
        self.last_socket_addr = socket_addr;
    }
}

async fn run_udp_remote_to_local_stream_loop(
    assoc_id: u16,
    mut send_stream: quinn::SendStream,
    socket: Arc<UdpSocket>,
    override_local_write_address: Option<NetLocation>,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let original_address_bytes: Option<Bytes> =
        override_local_write_address.map(|a| serialize_address(&a).into());

    let mut next_packet_id: u16 = 0;
    let mut buf = allocate_vec(MAX_HEADER_LEN + 65535).into_boxed_slice();
    let mut loop_count: u8 = 0;

    loop {
        let (payload_len, src_addr) = match socket.try_recv_from(&mut buf[MAX_HEADER_LEN..]) {
            Ok(res) => res,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Use select! to allow cancellation while waiting for socket to be readable
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        return Ok(());
                    }
                    result = socket.readable() => {
                        result?;
                        continue;
                    }
                }
            }
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "failed to receive from UDP socket: {e}"
                )));
            }
        };

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

        let address_bytes_len = address_bytes.len();

        // assoc_id(2) + packet_id(2) + fragment total(1) + fragment id(1) + payload size (2) + address bytes
        let header_len = 2 + 2 + 1 + 1 + 2 + address_bytes_len;

        let start_offset = MAX_HEADER_LEN - header_len;
        let end_offset = MAX_HEADER_LEN + payload_len;

        buf[start_offset] = (assoc_id >> 8) as u8;
        buf[start_offset + 1] = assoc_id as u8;
        buf[start_offset + 2] = (packet_id >> 8) as u8;
        buf[start_offset + 3] = packet_id as u8;
        buf[start_offset + 4] = 1;
        buf[start_offset + 5] = 0;
        buf[start_offset + 6] = (payload_len >> 8) as u8;
        buf[start_offset + 7] = payload_len as u8;
        buf[start_offset + 8..start_offset + 8 + address_bytes_len].copy_from_slice(&address_bytes);

        let mut i = start_offset;
        while i < end_offset {
            let count = send_stream
                .write(&buf[i..end_offset])
                .await
                .map_err(std::io::Error::other)?;
            i += count;
        }
    }
}

async fn run_udp_remote_to_local_datagram_loop(
    assoc_id: u16,
    connection: quinn::Connection,
    client_socket: Arc<UdpSocket>,
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
    let mut buf = allocate_vec(65535).into_boxed_slice();
    let mut loop_count: u8 = 0;

    loop {
        let (payload_len, src_addr) = match client_socket.try_recv_from(&mut buf) {
            Ok(res) => res,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Use select! to allow cancellation while waiting for socket to be readable
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        return Ok(());
                    }
                    result = client_socket.readable() => {
                        result?;
                        continue;
                    }
                }
            }
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "failed to receive from UDP socket: {e}"
                )));
            }
        };

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
            datagram.extend_from_slice(&buf[..payload_len]);

            connection
                .send_datagram(datagram.freeze())
                .map_err(|e| std::io::Error::other(format!("Failed to send datagram: {e}")))?;
        } else {
            // Calculate header sizes for first fragment and subsequent fragments.
            let first_overhead = header_overhead; // full address included in the first fragment
            let other_overhead = 1 + 1 + 2 + 2 + 1 + 1 + 2 + 1; // 0xff marker instead of full address
            let first_capacity = max_datagram_size - first_overhead;
            let other_capacity = max_datagram_size - other_overhead;

            let remaining = payload_len.saturating_sub(first_capacity);
            let additional_fragments = remaining.div_ceil(other_capacity);
            let fragment_count = 1 + additional_fragments;

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
                datagram.extend_from_slice(&buf[offset..offset + fragment_payload_len]);
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
    // Spawn a cleanup task for UDP sessions that terminates when connection closes
    let cleanup_session_map = udp_session_map.clone();
    let cleanup_cancel_token = cancel_token.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
        loop {
            tokio::select! {
                _ = cleanup_cancel_token.cancelled() => {
                    break;
                }
                _ = interval.tick() => {
                    cleanup_session_map.retain(|assoc_id, session| {
                        if session.last_activity.elapsed() > IDLE_TIMEOUT {
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
        let recv_stream = match connection.accept_uni().await {
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

        let connection = connection.clone();
        let client_proxy_selector = client_proxy_selector.clone();
        let resolver = resolver.clone();
        let udp_session_map = udp_session_map.clone();
        let cancel_token = cancel_token.clone();
        tokio::spawn(async move {
            // Per TUIC protocol, each uni stream carries exactly ONE command.
            // The reference implementation (handle_stream.rs) handles one task per stream.
            match process_uni_stream(
                &connection,
                client_proxy_selector,
                resolver,
                recv_stream,
                udp_session_map,
                cancel_token,
            )
            .await
            {
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
        if let Some((_, session)) = udp_session_map.remove(&assoc_id) {
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

    // For uni stream packets, we need per-connection fragment reassembly.
    // Since each stream is one packet, fragments come on separate streams.
    // We use the connection-level udp_session_map for this.
    // Note: Fragment reassembly for uni streams is handled at the session level.
    // For simplicity, we only support non-fragmented packets on uni streams for now,
    // or let process_udp_packet handle it with a temporary fragment cache.
    let mut fragments: LruCache<u16, FragmentedPacket> =
        LruCache::new(NonZeroUsize::new(MAX_FRAGMENT_CACHE_SIZE).unwrap());

    process_udp_packet(
        connection,
        &client_proxy_selector,
        &resolver,
        &udp_session_map,
        &mut fragments,
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
    fragments: &mut LruCache<u16, FragmentedPacket>,
    assoc_id: u16,
    packet_id: u16,
    frag_total: u8,
    frag_id: u8,
    remote_location: Option<NetLocation>,
    payload_fragment: &[u8],
    is_uni_stream: bool,
    cancel_token: &CancellationToken,
) -> std::io::Result<()> {
    if frag_total == 0 {
        return Err(std::io::Error::other(
            "Ignoring packet with empty fragment total",
        ));
    }

    // Bounds check: frag_id must be less than frag_total to avoid panic
    // Per sing-box reference (packet.go:394)
    if frag_id >= frag_total {
        return Err(std::io::Error::other(format!(
            "Invalid fragment id {frag_id} >= total {frag_total}"
        )));
    }

    let session = {
        match udp_session_map.get(&assoc_id) {
            Some(s) => s,
            None => {
                // TODO: it's possible that a new session starts with a fragmented packet, and we
                // receive this initial packet out of order so there's no address.
                if remote_location.is_none() {
                    return Err(std::io::Error::other(
                        "Ignoring packet with unknown session and empty address",
                    ));
                }

                let remote_location = remote_location.clone().unwrap();

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

                let resolved_address = resolve_single_address(resolver, updated_location.location())
                    .await
                    .map_err(|e| {
                        std::io::Error::other(format!(
                            "Failed to resolve initial remote location {}: {e}",
                            updated_location.location()
                        ))
                    })?;

                let (override_remote_write_address, override_local_write_location) =
                    if resolved_address.to_string() != remote_location.to_string() {
                        (Some(resolved_address), Some(remote_location.clone()))
                    } else {
                        // since we don't replace addresses, support the case where a future
                        // address is ipv6
                        (None, None)
                    };

                // Use IPv6 dual-stack socket for direct UDP
                let client_socket = crate::socket_util::new_udp_socket(true, None)?;

                let session = if is_uni_stream {
                    // TODO: should we only have a single send stream?
                    let send_stream = connection.open_uni().await?;

                    UdpSession::start_with_send_stream(
                        assoc_id,
                        send_stream,
                        Arc::new(client_socket),
                        remote_location,
                        resolved_address,
                        override_local_write_location,
                        override_remote_write_address,
                        cancel_token,
                    )
                } else {
                    UdpSession::start_with_datagram(
                        assoc_id,
                        connection.clone(),
                        Arc::new(client_socket),
                        remote_location,
                        resolved_address,
                        override_local_write_location,
                        override_remote_write_address,
                        cancel_token,
                    )
                };

                // it's possible that the session is already on the map since we last checked.
                // TODO: why is there no way to get a Ref<_> from an Entry<_>? see if we can
                // do better than converting into a RefMut<_> and then downgrading.
                match udp_session_map.entry(assoc_id) {
                    dashmap::mapref::entry::Entry::Occupied(entry) => entry.into_ref().downgrade(),
                    dashmap::mapref::entry::Entry::Vacant(entry) => {
                        entry.insert_entry(session).into_ref().downgrade()
                    }
                }
            }
        }
    };

    if frag_total == 1 {
        if remote_location.is_none() {
            return Err(std::io::Error::other(
                "Ignoring packet with single fragment and no address",
            ));
        }
        let remote_location = remote_location.as_ref().unwrap();

        let (socket_addr, is_updated) = session
            .resolve_address(remote_location, client_proxy_selector, resolver)
            .await
            .map_err(|e| {
                std::io::Error::other(format!(
                    "Failed to resolve remote location {remote_location}: {e}"
                ))
            })?;

        if let Err(e) = session
            .send_socket
            .send_to(payload_fragment, socket_addr)
            .await
        {
            error!("Failed to forward UDP payload for session {assoc_id}: {e}");
            drop(session);
            udp_session_map.remove(&assoc_id);
            return Ok(());
        }

        drop(session);
        if let Some(mut session) = udp_session_map.get_mut(&assoc_id) {
            session.last_activity = std::time::Instant::now();
            if is_updated {
                session.update_last_location(remote_location.clone(), socket_addr);
            }
        }
    } else {
        let is_new = !fragments.contains(&packet_id);

        if is_new {
            // Insert new fragmented packet entry
            fragments.put(
                packet_id,
                FragmentedPacket {
                    fragment_count: frag_total,
                    fragment_received: 0,
                    packet_len: 0,
                    received: vec![None; frag_total as usize],
                    remote_location: remote_location.clone(),
                },
            );
        }

        let packet = match fragments.get_mut(&packet_id) {
            Some(p) => p,
            None => {
                // This shouldn't happen since we just inserted it
                return Err(std::io::Error::other("Fragment cache error"));
            }
        };

        if is_new && frag_id == 0 && packet.remote_location.is_none() {
            if remote_location.is_none() {
                fragments.pop(&packet_id);
                return Err(std::io::Error::other(format!(
                    "Ignoring packet with empty first fragment address for session {assoc_id}"
                )));
            }
            packet.remote_location = remote_location.clone();
        }

        if packet.fragment_count != frag_total {
            fragments.pop(&packet_id);
            return Err(std::io::Error::other(format!(
                "Mismatched fragment count for session {assoc_id} packet {packet_id}"
            )));
        }
        if packet.received[frag_id as usize].is_some() {
            fragments.pop(&packet_id);
            return Err(std::io::Error::other(format!(
                "Duplicate fragment for session {assoc_id} packet {packet_id}"
            )));
        }

        packet.fragment_received += 1;
        packet.packet_len += payload_fragment.len();
        packet.received[frag_id as usize] = Some(payload_fragment.to_vec().into());

        if packet.fragment_received != packet.fragment_count {
            return Ok(());
        }

        // All fragments received - remove from cache and process
        let FragmentedPacket {
            remote_location,
            received,
            packet_len,
            ..
        } = fragments.pop(&packet_id).unwrap();

        let remote_location = remote_location.unwrap();

        let (socket_addr, is_updated) = session
            .resolve_address(&remote_location, client_proxy_selector, resolver)
            .await
            .map_err(|e| {
                std::io::Error::other(format!(
                    "Failed to resolve remote location {remote_location}: {e}"
                ))
            })?;

        let mut complete_payload = Vec::with_capacity(packet_len);
        for frag in received.iter() {
            complete_payload.extend_from_slice(frag.as_ref().unwrap());
        }

        if let Err(e) = session
            .send_socket
            .send_to(&complete_payload, socket_addr)
            .await
        {
            error!("Failed to forward UDP payload for session {assoc_id}: {e}");
            drop(session);
            udp_session_map.remove(&assoc_id);
            return Ok(());
        }

        drop(session);
        if let Some(mut session) = udp_session_map.get_mut(&assoc_id) {
            session.last_activity = std::time::Instant::now();
            if is_updated {
                session.update_last_location(remote_location.clone(), socket_addr);
            }
        }
    }

    Ok(())
}

async fn run_datagram_loop(
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    udp_session_map: UdpSessionMap,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    // Use LRU cache for fragment reassembly to prevent unbounded memory growth.
    let mut fragments: LruCache<u16, FragmentedPacket> =
        LruCache::new(NonZeroUsize::new(MAX_FRAGMENT_CACHE_SIZE).unwrap());
    let mut last_cleanup = std::time::Instant::now();

    loop {
        let now = std::time::Instant::now();
        if (now - last_cleanup) > CLEANUP_INTERVAL {
            udp_session_map.retain(|assoc_id, session| {
                if session.last_activity.elapsed() > IDLE_TIMEOUT {
                    // Cancel the session's background task before removing
                    session.cancel_token.cancel();
                    debug!("Removing inactive UDP session {assoc_id}");
                    false
                } else {
                    true
                }
            });
            last_cleanup = now;
        }

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

        let payload_fragment = &data[offset..offset + payload_size];

        if let Err(e) = process_udp_packet(
            &connection,
            &client_proxy_selector,
            &resolver,
            &udp_session_map,
            &mut fragments,
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
    uuid: &'static [u8],
    password: &'static str,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    num_endpoints: usize,
    zero_rtt_handshake: bool,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let mut join_handles = vec![];
    for _ in 0..num_endpoints {
        let quic_server_config = quic_server_config.clone();
        let resolver = resolver.clone();
        let client_proxy_selector = client_proxy_selector.clone();

        let join_handle = tokio::spawn(async move {
            let mut server_config = quinn::ServerConfig::with_crypto(quic_server_config);

            Arc::get_mut(&mut server_config.transport)
                .unwrap()
                .max_concurrent_bidi_streams(4096_u32.into())
                .max_concurrent_uni_streams(4096_u32.into())
                .max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()))
                .keep_alive_interval(Some(Duration::from_secs(15)))
                .send_window(16 * 1024 * 1024)
                .receive_window((20u32 * 1024 * 1024).into())
                .stream_receive_window((8u32 * 1024 * 1024).into())
                // MTU settings per official TUIC reference
                .initial_mtu(1200)
                .min_mtu(1200)
                // Enable MTU discovery for larger packets on capable networks
                .mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()))
                // Enable GSO (Generic Segmentation Offload) for better throughput
                .enable_segmentation_offload(true)
                // Lower initial RTT estimate for faster initial window growth
                .initial_rtt(Duration::from_millis(100));

            // Use 7.5MB socket buffers for high-throughput QUIC (8.625MB on BSD for 15% kernel overhead)
            // https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes
            let socket2_socket = crate::socket_util::new_socket2_udp_socket_with_buffer_size(
                bind_address.is_ipv6(),
                None,
                Some(bind_address),
                true,
                Some(8_625_000),
            )
            .unwrap();

            let endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(server_config),
                socket2_socket.into(),
                Arc::new(quinn::TokioRuntime),
            )
            .unwrap();

            while let Some(conn) = endpoint.accept().await {
                let cloned_selector = client_proxy_selector.clone();
                let cloned_resolver = resolver.clone();
                tokio::spawn(async move {
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
