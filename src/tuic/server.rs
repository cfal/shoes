use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::str;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use log::{debug, error};
use lru::LruCache;
use parking_lot::Mutex;
use subtle::ConstantTimeEq;
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
use crate::quic_transport::{
    QuicListenerSettings, QuicTransportParams, effective_mtu, start_quic_listeners,
};
use crate::resolver::{Resolver, resolve_single_address};
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_forward::setup_client_tcp_stream;
use crate::util::{allocate_vec, write_all};

use super::frame::{
    COMMAND_TYPE_AUTHENTICATE, COMMAND_TYPE_CONNECT, COMMAND_TYPE_DISSOCIATE,
    COMMAND_TYPE_HEARTBEAT, COMMAND_TYPE_PACKET, MAX_HEADER_LEN, TUIC_VERSION,
    encode_packet_header_with_address, read_address, serialize_address, serialize_socket_addr,
};

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

/// Connection-level UDP fragment reassembly cache, keyed by (assoc_id, packet_id).
///
/// TUIC carries one fragment per uni stream, and uni streams are handled by
/// concurrent tasks, so the cache must be shared and synchronized rather than
/// living on the stack of a single stream handler (a fresh per-stream cache could
/// never reassemble a multi-fragment packet). Keying on both ids also prevents two
/// associations that happen to pick the same 16-bit packet id from colliding. The
/// mutex is only ever held across synchronous LRU operations, never an `.await`.
type FragmentCache = Arc<Mutex<LruCache<(u16, u16), FragmentedPacket>>>;

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
        let connecting = conn
            .accept()
            .map_err(|e| std::io::Error::other(format!("QUIC accept failed: {e}")))?;
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

    // One fragment cache shared by the uni-stream tasks and the datagram loop, so a
    // multi-fragment packet reassembles regardless of which relay mode carries it.
    let fragments: FragmentCache = Arc::new(Mutex::new(LruCache::new(
        NonZeroUsize::new(MAX_FRAGMENT_CACHE_SIZE).unwrap(),
    )));

    let uni_connection = connection.clone();
    let uni_client_proxy_selector = client_proxy_selector.clone();
    let uni_resolver = resolver.clone();
    let uni_udp_session_map = udp_session_map.clone();
    let uni_cancel_token = cancel_token.clone();
    let uni_fragments = fragments.clone();

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
        uni_fragments,
        uni_cancel_token,
    );

    let datagram_loop = run_datagram_loop(
        datagram_connection,
        client_proxy_selector,
        resolver,
        udp_session_map,
        fragments,
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
///
/// A failed send just stops the heartbeat; it must not close the connection.
/// The TUIC spec defines heartbeats as client-only, so a peer that negotiated
/// `max_datagram_frame_size = 0` (datagrams disabled) rejects every send here.
/// Propagating that into the connection's `try_join!` would tear down an
/// otherwise healthy connection roughly one interval in. QUIC's own keep-alive
/// and the real stream/datagram loops carry liveness regardless.
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
                    debug!("TUIC heartbeat send failed, stopping heartbeat: {e}");
                    return Ok(());
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
        if tuic_version != TUIC_VERSION {
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
        let uuid_match = specified_uuid.ct_eq(uuid);

        let token_bytes = stream_reader.read_slice(&mut recv_stream, 32).await?;
        let token_match = token_bytes.ct_eq(&expected_token_bytes);

        // Constant time, and both are read and compared before either is
        // judged, so the reply says nothing about which half was wrong. The
        // token is derived from the password, so a byte-by-byte timing signal
        // on it is a signal on the password.
        if (uuid_match & token_match).unwrap_u8() == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "TUIC authentication failed",
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

async fn process_tcp_stream(
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> std::io::Result<()> {
    let mut stream_reader = StreamReader::new_with_buffer_size(1024);
    let tuic_version = stream_reader.read_u8(&mut recv).await?;
    if tuic_version != TUIC_VERSION {
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
            remote_location.clone().into(),
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
    fn start_with_uni_streams(
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

/// Send replies to the client over unidirectional streams.
///
/// One stream per packet, each carrying a complete `Packet` command including
/// the version and type bytes. This used to hold a single stream open for the
/// association and write bare packet bodies onto it, which is not a command at
/// all — our own receiving side would have rejected it, and so would every
/// other implementation. The reference does it this way too: see `packet_quic`
/// in EAimTY/tuic, `tuic-quinn/src/lib.rs`.
async fn run_udp_remote_to_local_stream_loop(
    assoc_id: u16,
    connection: quinn::Connection,
    socket: Arc<UdpSocket>,
    override_local_write_address: Option<NetLocation>,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let original_address_bytes: Option<Bytes> =
        override_local_write_address.map(|a| serialize_address(&a).into());

    let mut next_packet_id: u16 = 0;
    let mut buf = allocate_vec(65535).into_boxed_slice();
    let mut loop_count: u8 = 0;
    // Cache the serialized reply source address; it is constant for the common
    // single-peer flow, so the steady state is a refcount bump rather than a
    // serialize_socket_addr allocation per packet. Unused when there is an override.
    let mut cached_src: Option<(SocketAddr, Bytes)> = None;

    loop {
        let (payload_len, src_addr) = match socket.try_recv_from(&mut buf) {
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
            None => {
                if cached_src.as_ref().is_none_or(|(a, _)| *a != src_addr) {
                    cached_src = Some((src_addr, serialize_socket_addr(&src_addr).into()));
                }
                cached_src.as_ref().unwrap().1.clone()
            }
        };

        let mut packet = encode_packet_header_with_address(
            assoc_id,
            packet_id,
            1,
            0,
            payload_len as u16,
            &address_bytes,
        );
        packet.extend_from_slice(&buf[..payload_len]);

        let mut send_stream = connection
            .open_uni()
            .await
            .map_err(|e| std::io::Error::other(format!("failed to open a TUIC uni stream: {e}")))?;
        send_stream
            .write_all(&packet)
            .await
            .map_err(|e| std::io::Error::other(format!("TUIC stream write failed: {e}")))?;
        send_stream
            .finish()
            .map_err(|e| std::io::Error::other(format!("TUIC stream finish failed: {e}")))?;
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
    // Cache the serialized reply source address; it is constant for the common
    // single-peer flow, so the steady state is a refcount bump rather than a
    // serialize_socket_addr allocation per packet. Unused when there is an override.
    let mut cached_src: Option<(SocketAddr, Bytes)> = None;

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
            None => {
                if cached_src.as_ref().is_none_or(|(a, _)| *a != src_addr) {
                    cached_src = Some((src_addr, serialize_socket_addr(&src_addr).into()));
                }
                cached_src.as_ref().unwrap().1.clone()
            }
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
    fragments: FragmentCache,
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
        let fragments = fragments.clone();
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
                fragments,
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
    fragments: FragmentCache,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let mut stream_reader = StreamReader::new_with_buffer_size(MAX_HEADER_LEN + 65535);

    let tuic_version = stream_reader.read_u8(&mut recv_stream).await?;
    if tuic_version != TUIC_VERSION {
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

    // Fragments arrive on separate uni streams, so reassembly uses the shared
    // connection-level cache rather than a per-stream one that could never complete.
    process_udp_packet(
        connection,
        &client_proxy_selector,
        &resolver,
        &udp_session_map,
        &fragments,
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
    fragments: &FragmentCache,
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

                let resolved_address =
                    resolve_single_address(resolver, updated_location.location())
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
                    UdpSession::start_with_uni_streams(
                        assoc_id,
                        connection.clone(),
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

        // send_socket is dual-stack IPv6, so an IPv4 target must be sent as an
        // IPv4-mapped address (a bare v4 destination fails with EINVAL on macOS/BSD).
        let socket_addr = crate::socket_util::dual_stack_dest(socket_addr);
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
        // Reassembly touches only the shared cache and is fully synchronous, so the
        // lock is taken here and released before any `.await` below. The block yields
        // the completed packet, or `None` while fragments are still outstanding.
        let key = (assoc_id, packet_id);
        let assembled: Option<(NetLocation, Vec<u8>)> = {
            let mut cache = fragments.lock();

            if !cache.contains(&key) {
                // Insert new fragmented packet entry
                cache.put(
                    key,
                    FragmentedPacket {
                        fragment_count: frag_total,
                        fragment_received: 0,
                        packet_len: 0,
                        received: vec![None; frag_total as usize],
                        remote_location: remote_location.clone(),
                    },
                );
            }

            let packet = match cache.get_mut(&key) {
                Some(p) => p,
                None => {
                    // This shouldn't happen since we just inserted it
                    return Err(std::io::Error::other("Fragment cache error"));
                }
            };

            // The address rides only on the first fragment; adopt it whenever fragment 0
            // arrives (which may be after a later fragment created the entry).
            if frag_id == 0 && packet.remote_location.is_none() {
                if remote_location.is_none() {
                    cache.pop(&key);
                    return Err(std::io::Error::other(format!(
                        "Ignoring packet with empty first fragment address for session {assoc_id}"
                    )));
                }
                packet.remote_location = remote_location.clone();
            }

            if packet.fragment_count != frag_total {
                cache.pop(&key);
                return Err(std::io::Error::other(format!(
                    "Mismatched fragment count for session {assoc_id} packet {packet_id}"
                )));
            }
            if packet.received[frag_id as usize].is_some() {
                cache.pop(&key);
                return Err(std::io::Error::other(format!(
                    "Duplicate fragment for session {assoc_id} packet {packet_id}"
                )));
            }

            packet.fragment_received += 1;
            packet.packet_len += payload_fragment.len();
            packet.received[frag_id as usize] = Some(payload_fragment.to_vec().into());

            if packet.fragment_received != packet.fragment_count {
                None
            } else {
                // All fragments received - remove from cache and assemble.
                let FragmentedPacket {
                    remote_location,
                    received,
                    packet_len,
                    ..
                } = cache.pop(&key).unwrap();
                let remote_location = match remote_location {
                    Some(loc) => loc,
                    None => {
                        return Err(std::io::Error::other(format!(
                            "Reassembled packet for session {assoc_id} has no address"
                        )));
                    }
                };
                let mut complete_payload = Vec::with_capacity(packet_len);
                for frag in received.iter() {
                    complete_payload.extend_from_slice(frag.as_ref().unwrap());
                }
                Some((remote_location, complete_payload))
            }
        };

        let (remote_location, complete_payload) = match assembled {
            Some(assembled) => assembled,
            None => return Ok(()),
        };

        let (socket_addr, is_updated) = session
            .resolve_address(&remote_location, client_proxy_selector, resolver)
            .await
            .map_err(|e| {
                std::io::Error::other(format!(
                    "Failed to resolve remote location {remote_location}: {e}"
                ))
            })?;

        // send_socket is dual-stack IPv6, so an IPv4 target must be sent as an
        // IPv4-mapped address (a bare v4 destination fails with EINVAL on macOS/BSD).
        let socket_addr = crate::socket_util::dual_stack_dest(socket_addr);
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
    fragments: FragmentCache,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
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
        if tuic_version != TUIC_VERSION {
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

        // offset + payload_size is validated per address-type above for 0x00/0x01/0x02,
        // but the 0xff (no-address) arm sets offset without a length check. Validate
        // uniformly here so a peer cannot claim a payload_size past the datagram end.
        if data_len < offset + payload_size {
            return Err(std::io::Error::other(
                "decode UDP message: payload larger than datagram",
            ));
        }
        let payload_fragment = &data[offset..offset + payload_size];

        if let Err(e) = process_udp_packet(
            &connection,
            &client_proxy_selector,
            &resolver,
            &udp_session_map,
            &fragments,
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

pub async fn start_tuic_server(
    listener: QuicListenerSettings,
    uuid: &'static [u8],
    password: &'static str,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    zero_rtt_handshake: bool,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let params = QuicTransportParams {
        max_concurrent_bidi_streams: 4096,
        // The `quic` UDP relay mode carries every packet fragment on its own
        // client-opened uni stream, so this has to be generous.
        max_concurrent_uni_streams: 4096,
        max_idle_timeout: Duration::from_secs(60),
        keep_alive_interval: Duration::from_secs(15),
        // MTU per the official TUIC reference, less whatever an obfuscator
        // takes out of every datagram.
        mtu: effective_mtu(listener.obfs.as_ref().map(|o| o.overhead())),
        enable_segmentation_offload: listener.obfs.is_none(),
    };

    start_quic_listeners(listener, params, move |conn| {
        let client_proxy_selector = client_proxy_selector.clone();
        let resolver = resolver.clone();
        async move {
            process_connection(
                client_proxy_selector,
                resolver,
                uuid,
                password,
                conn,
                zero_rtt_handshake,
            )
            .await
        }
    })
}
