use lru::LruCache;
use std::collections::hash_map::Entry;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::str;
use std::sync::Arc;
use std::time::Duration;

use crate::hysteria2_protocol::{
    header, tcp_status, AUTH_HOST, AUTH_PATH, FRAME_TYPE_TCP_REQUEST,
    STATUS_AUTH_OK,
};

use bytes::{Bytes, BytesMut};
use log::{debug, error, warn};
use rand::distr::Alphanumeric;
use rand::{Rng, RngCore};
use rustc_hash::FxHashMap;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

/// Maximum number of fragmented packets to track per session.
/// Old entries are automatically evicted when this limit is reached.
const MAX_FRAGMENT_CACHE_SIZE: usize = 256;

/// Authentication timeout - close connection if client doesn't authenticate within this time.
/// Default is 3 seconds per sing-box reference implementation.
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);

/// HTTP/3 error code for normal closure.
/// Per official hysteria reference: https://github.com/apernet/hysteria/blob/master/core/server/server.go#L20
const CLOSE_ERR_CODE_OK: u32 = 0x100; // HTTP3 ErrCodeNoError

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::copy_bidirectional::copy_bidirectional_with_sizes;
use crate::quic_stream::QuicStream;
use crate::resolver::{Resolver, ResolverCache};
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_server::setup_client_tcp_stream;
use crate::util::allocate_vec;

async fn process_connection(
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    password: &'static str,
    conn: quinn::Incoming,
    udp_enabled: bool,
) -> std::io::Result<()> {
    let connection = conn.await?;

    // Create a cancellation token for the entire connection lifecycle.
    // When cancelled, all spawned tasks (UDP sessions) will terminate gracefully.
    let cancel_token = CancellationToken::new();

    // we unfortunately need to keep the h3 connection around because it closes the underlying
    // connection on drop, see
    // https://github.com/hyperium/h3/blob/dbf2523d26e115f096b66cdd8a6f68127a17a156/h3/src/server/connection.rs#L427
    //
    // we keep this function waiting for the tcp and udp tasks both to finish before dropping,
    // instead of passing the connection to one of the two loops, incase one finishes first.
    let h3_quinn_connection = h3_quinn::Connection::new(connection.clone());

    let mut h3_conn: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
        h3::server::Connection::new(h3_quinn_connection)
            .await
            .map_err(std::io::Error::other)?;

    // Per sing-box reference, authentication timeout is 3 seconds
    match timeout(
        AUTH_TIMEOUT,
        auth_connection(&mut h3_conn, password, udp_enabled),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            connection.close(CLOSE_ERR_CODE_OK.into(), b"auth failed");
            return Err(e);
        }
        Err(_elapsed) => {
            error!("Authentication timeout");
            connection.close(CLOSE_ERR_CODE_OK.into(), b"auth timeout");
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "authentication timeout",
            ));
        }
    }

    let udp_connection = connection.clone();
    let udp_client_proxy_selector = client_proxy_selector.clone();
    let udp_resolver = resolver.clone();
    let udp_cancel_token = cancel_token.clone();

    let uni_connection = connection.clone();

    // Use try_join! to run all loops concurrently within the same task, like Quinn's perf example.
    // This reduces task count and avoids spawning separate tasks for the main loops.
    let udp_loop = async {
        if udp_enabled {
            run_udp_local_to_remote_loop(
                udp_connection,
                udp_client_proxy_selector,
                udp_resolver,
                udp_cancel_token,
            )
            .await
        } else {
            Ok(())
        }
    };

    let uni_loop = async {
        // Depending on the client, unidirectional streams could still be sent, accept and drop.
        loop {
            match uni_connection.accept_uni().await {
                Ok(mut recv_stream) => {
                    let _ = recv_stream.stop(0u32.into());
                }
                Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
                Err(quinn::ConnectionError::ConnectionClosed(_)) => break,
                Err(e) => {
                    return Err(std::io::Error::other(format!(
                        "unidirectional loop error: {e}"
                    )));
                }
            }
        }
        Ok(())
    };

    let tcp_connection = connection.clone();
    let tcp_loop = run_tcp_loop(tcp_connection, client_proxy_selector, resolver);

    let result = tokio::try_join!(udp_loop, uni_loop, tcp_loop);

    cancel_token.cancel();

    // Per sing-box reference (service.go:277-293), close connection on error
    if let Err(ref e) = result {
        error!("Connection failed: {e}");
        connection.close(CLOSE_ERR_CODE_OK.into(), b"");
    }

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

fn validate_auth_request<T>(req: http::Request<T>, password: &str) -> std::io::Result<()> {
    // Check HTTP method (similar to official implementation)
    if req.method() != http::Method::POST {
        return Err(std::io::Error::other(format!(
            "unexpected method: {}",
            req.method()
        )));
    }

    // Check URI path
    if req.uri().path() != AUTH_PATH {
        return Err(std::io::Error::other(format!(
            "unexpected uri path: {}",
            req.uri().path()
        )));
    }

    let headers = req.headers();

    // Check Host header (optional per HTTP/3 spec, but recommended)
    if let Some(host) = headers.get(http::header::HOST) {
        let host_str = host.to_str().map_err(std::io::Error::other)?;
        if host_str != AUTH_HOST {
            return Err(std::io::Error::other(format!(
                "unexpected host: {}",
                host_str
            )));
        }
    }

    // Check Hysteria-Auth header
    let auth_value = match headers.get(header::AUTH) {
        Some(h) => h,
        None => {
            return Err(std::io::Error::other("missing auth header"));
        }
    };
    let auth_str = auth_value.to_str().map_err(std::io::Error::other)?;
    if auth_str != password {
        return Err(std::io::Error::other(format!(
            "incorrect auth password: {auth_str}"
        )));
    }

    Ok(())
}

fn generate_ascii_string() -> String {
    let mut rng = rand::rng();
    let length = rng.random_range(1..80);
    rng.sample_iter(Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

async fn auth_connection(
    h3_conn: &mut h3::server::Connection<h3_quinn::Connection, bytes::Bytes>,
    password: &str,
    udp_enabled: bool,
) -> std::io::Result<()> {
    loop {
        match h3_conn.accept().await.map_err(std::io::Error::other)? {
            Some(resolver) => {
                let (req, mut stream) = resolver.resolve_request().await.map_err(|err| {
                    std::io::Error::other(format!("Failed to resolve request: {err}"))
                })?;
                match validate_auth_request(req, password) {
                    Ok(()) => {
                        let resp = http::Response::builder()
                            .status(http::status::StatusCode::from_u16(STATUS_AUTH_OK).unwrap())
                            .header(header::UDP, if udp_enabled { "true" } else { "false" })
                            .header(header::CC_RX, "0")
                            .header(header::PADDING, generate_ascii_string())
                            .body(())
                            .unwrap();

                        stream
                            .send_response(resp)
                            .await
                            .map_err(std::io::Error::other)?;

                        stream.finish().await.map_err(std::io::Error::other)?;

                        return Ok(());
                    }
                    Err(e) => {
                        error!("Received non-hysteria2 auth http3 request: {e}");
                        let resp = http::Response::builder()
                            .status(http::status::StatusCode::NOT_FOUND)
                            .body(())
                            .unwrap();
                        stream
                            .send_response(resp)
                            .await
                            .map_err(std::io::Error::other)?;
                        stream.finish().await.map_err(std::io::Error::other)?;
                    }
                }
            }
            // indicating no more streams to be received
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "no streams",
                ));
            }
        }
    }
}

struct UdpSession {
    fragments: LruCache<u16, FragmentedPacket>,
    send_socket: Arc<UdpSocket>,
    // we cache the last location in case of mid-session address changes, and
    // don't want to have to call ClientProxySelector::judge on every packet.
    last_location: NetLocation,
    last_socket_addr: SocketAddr,
    override_remote_write_address: Option<SocketAddr>,
    last_activity: std::time::Instant,
    cancel_token: CancellationToken,
}

struct FragmentedPacket {
    fragment_count: u8,
    fragment_received: u8,
    packet_len: usize,
    received: Vec<Option<Bytes>>,
    remote_location: NetLocation,
}

impl UdpSession {
    // TODO: remove this function completely and inline?
    #[allow(clippy::too_many_arguments)]
    fn start(
        session_id: u32,
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
            fragments: LruCache::new(NonZeroUsize::new(MAX_FRAGMENT_CACHE_SIZE).unwrap()),
            send_socket: client_socket.clone(),
            last_location: initial_location,
            last_socket_addr: initial_socket_addr,
            override_remote_write_address,
            last_activity: std::time::Instant::now(),
            cancel_token: session_cancel_token.clone(),
        };

        tokio::spawn(async move {
            if let Err(e) = run_udp_remote_to_local_loop(
                session_id,
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
}

async fn run_udp_remote_to_local_loop(
    session_id: u32,
    connection: quinn::Connection,
    socket: Arc<UdpSocket>,
    override_local_write_address: Option<NetLocation>,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let max_datagram_size = connection
        .max_datagram_size()
        .ok_or_else(|| std::io::Error::other("datagram not supported by remote endpoint"))?;

    let original_address_bytes: Option<(Bytes, Bytes)> = match override_local_write_address {
        Some(a) => {
            let address_bytes: Bytes = a.to_string().into_bytes().into();
            let address_len = address_bytes.len();
            let address_len_bytes = encode_varint(address_len as u64)?;
            Some((address_bytes, address_len_bytes.into()))
        }
        None => None,
    };

    let mut next_packet_id: u16 = 0;
    let mut buf = allocate_vec(65535);
    let mut loop_count: u8 = 0;

    loop {
        let (payload_len, src_addr) = match socket.try_recv_from(&mut buf) {
            Ok(res) => res,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
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
        // This prevents starvation during heavy UDP traffic.
        loop_count = loop_count.wrapping_add(1);
        if loop_count == 0 {
            tokio::task::yield_now().await;
        }

        let packet_id = next_packet_id;
        next_packet_id = next_packet_id.wrapping_add(1);

        let (address_bytes, address_len_bytes) = match original_address_bytes {
            Some((ref a, ref b)) => (a.clone(), b.clone()),
            None => {
                let address_bytes: Bytes = src_addr.to_string().into_bytes().into();
                // no need to do a length check since this is a socket address and an IP.
                let address_len = address_bytes.len();
                let address_len_bytes = encode_varint(address_len as u64)?.into();
                (address_bytes, address_len_bytes)
            }
        };

        // session_id(4) + packet_id(2) + fragment id(1) + fragment count(1) + address length varint + address bytes
        let header_overhead = 4 + 2 + 1 + 1 + address_len_bytes.len() + address_bytes.len();

        assert!(
            max_datagram_size > header_overhead,
            "max datagram size ({max_datagram_size}) is smaller than header overhead ({header_overhead})"
        );

        if header_overhead + payload_len <= max_datagram_size {
            let mut datagram = BytesMut::with_capacity(header_overhead + payload_len);
            datagram.extend_from_slice(&session_id.to_be_bytes());
            datagram.extend_from_slice(&packet_id.to_be_bytes());
            // fragment id = 0, fragment count = 0
            datagram.extend_from_slice(&[0, 1]);
            datagram.extend_from_slice(&address_len_bytes);
            datagram.extend_from_slice(&address_bytes);
            datagram.extend_from_slice(&buf[..payload_len]);

            connection
                .send_datagram(datagram.freeze())
                .map_err(|e| std::io::Error::other(format!("Failed to send datagram: {e}")))?;
        } else {
            let available_payload = max_datagram_size - header_overhead;
            let fragment_count = payload_len.div_ceil(available_payload) as u8;
            for fragment_id in 0..fragment_count {
                let start = (fragment_id as usize) * available_payload;
                let end = std::cmp::min(start + available_payload, payload_len);
                let mut datagram = BytesMut::with_capacity(header_overhead + (end - start));
                datagram.extend_from_slice(&session_id.to_be_bytes());
                datagram.extend_from_slice(&packet_id.to_be_bytes());
                datagram.extend_from_slice(&[fragment_id, fragment_count]);
                datagram.extend_from_slice(&address_len_bytes);
                datagram.extend_from_slice(&address_bytes);
                datagram.extend_from_slice(&buf[start..end]);

                connection.send_datagram(datagram.freeze()).map_err(|e| {
                    std::io::Error::other(format!(
                        "Failed to send datagram fragment {fragment_id}: {e}"
                    ))
                })?;
            }
        }
    }
}

async fn run_udp_local_to_remote_loop(
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let mut resolver_cache = ResolverCache::new(resolver.clone());
    let mut sessions: FxHashMap<u32, UdpSession> = FxHashMap::default();
    let mut last_cleanup = std::time::Instant::now();

    // Match reference implementation defaults for UDP session management
    const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
    const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

    loop {
        let now = std::time::Instant::now();
        if (now - last_cleanup) > CLEANUP_INTERVAL {
            sessions.retain(|session_id, session| {
                if session.last_activity.elapsed() > IDLE_TIMEOUT {
                    // Cancel the session's background task before removing
                    session.cancel_token.cancel();
                    debug!("Removing inactive UDP session {session_id}");
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

        // Per official hysteria reference (server.go:332-353), parse errors are ignored
        // and we continue waiting for the next message. Only connection errors are fatal.
        if data.len() < 9 {
            debug!("Ignoring short datagram (len={})", data.len());
            continue;
        }
        let session_id = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let packet_id = u16::from_be_bytes(data[4..6].try_into().unwrap());
        let fragment_id = data[6];
        let fragment_count = data[7];

        let (address_len, next_index) = {
            let first_byte = data[8];
            let length_indicator = first_byte >> 6;
            let mut value: u64 = (first_byte & 0b00111111) as u64;
            let num_bytes = match length_indicator {
                0 => 1,
                1 => 2,
                2 => 4,
                3 => 8,
                _ => {
                    // impossible since we only have 2 bits
                    unreachable!();
                }
            };
            let mut next_index = 9;
            if num_bytes > 1 {
                let remaining = &data[9..9 + (num_bytes - 1)];
                for byte in remaining {
                    value <<= 8;
                    value |= *byte as u64;
                }
                next_index += num_bytes - 1;
            }
            (value as usize, next_index)
        };

        if address_len == 0 {
            debug!("Ignoring packet with empty address");
            continue;
        }

        if address_len > 2048 {
            debug!("Ignoring packet with address length {address_len}");
            continue;
        }

        if data.len() < next_index + address_len {
            debug!("Ignoring datagram with truncated address");
            continue;
        }
        let address_bytes = &data[next_index..next_index + address_len];
        let payload_fragment = data.slice(next_index + address_len..);

        let addr_str = match str::from_utf8(address_bytes) {
            Ok(s) => s,
            Err(e) => {
                debug!("Invalid UTF-8 in address: {e}");
                continue;
            }
        };

        let remote_location = match NetLocation::from_str(addr_str, None) {
            Ok(loc) => loc,
            Err(e) => {
                debug!("Failed to parse address '{addr_str}': {e}");
                continue;
            }
        };

        let mut session_entry = sessions.entry(session_id);
        let session = match session_entry {
            Entry::Vacant(entry) => {
                let action = client_proxy_selector
                    .judge(remote_location.clone(), &resolver)
                    .await;

                let (_chain_group, updated_location) = match action {
                    Ok(ConnectDecision::Allow {
                        chain_group,
                        remote_location,
                    }) => (chain_group, remote_location),
                    Ok(ConnectDecision::Block) => {
                        warn!("Blocked UDP forward to {remote_location}");
                        continue;
                    }
                    Err(e) => {
                        error!("Failed to judge UDP forward to {remote_location}: {e}");
                        continue;
                    }
                };

                // the remote location specified at the beginning of a session is assumed
                // to be the remote location for the entire session iif it does not match
                // the resolved address, as per the official client - which is only if
                // it's a hostname. in our case, we also have to handle when the remote
                // location is replaced by a different location in the rules.
                //
                // it's possible that when we receive packets on the client socket,
                // it could be the resolved hostname versus what was initially provided,
                // and we need to write datagrams back to the user using their provided
                // address so that they know where it's from.
                //
                // it would be much simpler to always replace, or never, but we stick to
                // the official client behavior for now.
                //
                // ref: https://github.com/apernet/hysteria/blob/5520bcc405ee11a47c164c75bae5c40fc2b1d99d/core/server/udp.go#L137

                let resolved_address = match resolver_cache
                    .resolve_location(&updated_location)
                    .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to resolve initial remote location {remote_location}: {e}");
                        continue;
                    }
                };

                let (override_remote_write_address, override_local_write_location) =
                    if resolved_address.to_string() != remote_location.to_string() {
                        (Some(resolved_address), Some(remote_location.clone()))
                    } else {
                        (None, None)
                    };

                // even if the remote location is ipv4, a future location could be ipv6.
                // TODO: the configured client socket is for the current remote_location, but
                // the remote_location could be changed later on with a different client_socket
                // configuration.
                // Use IPv6 dual-stack socket for direct UDP
                let client_socket = crate::socket_util::new_udp_socket(true, None)?;

                let session = UdpSession::start(
                    session_id,
                    connection.clone(),
                    Arc::new(client_socket),
                    remote_location.clone(),
                    resolved_address,
                    override_local_write_location,
                    override_remote_write_address,
                    &cancel_token,
                );
                entry.insert(session)
            }
            Entry::Occupied(ref mut entry) => entry.get_mut(),
        };

        let (complete_payload, remote_location) = if fragment_count == 0 {
            error!("Ignoring empty UDP fragment for session {session_id}");
            continue;
        } else if fragment_count == 1 {
            (payload_fragment, remote_location)
        } else {
            let is_new = !session.fragments.contains(&packet_id);

            if is_new {
                session.fragments.put(
                    packet_id,
                    FragmentedPacket {
                        fragment_count,
                        fragment_received: 0,
                        packet_len: 0,
                        received: vec![None; fragment_count as usize],
                        remote_location: remote_location.clone(),
                    },
                );
            }

            let entry = match session.fragments.get_mut(&packet_id) {
                Some(e) => e,
                None => {
                    // This shouldn't happen since we just inserted it
                    error!("Fragment cache error for session {session_id}");
                    continue;
                }
            };

            if entry.fragment_count != fragment_count {
                session.fragments.pop(&packet_id);
                error!("Mismatched fragment count for session {session_id} packet {packet_id}");
                continue;
            }
            if entry.received[fragment_id as usize].is_some() {
                session.fragments.pop(&packet_id);
                error!("Duplicate fragment for session {session_id} packet {packet_id}");
                continue;
            }
            entry.fragment_received += 1;
            entry.packet_len += payload_fragment.len();
            entry.received[fragment_id as usize] = Some(payload_fragment);

            if entry.fragment_received != entry.fragment_count {
                continue;
            }

            // All fragments received - remove from cache and process
            let FragmentedPacket {
                remote_location: initial_location,
                received,
                packet_len,
                ..
            } = session.fragments.pop(&packet_id).unwrap();
            let mut complete_payload = BytesMut::with_capacity(packet_len);
            for frag in received.iter() {
                complete_payload.extend_from_slice(frag.as_ref().unwrap());
            }
            (complete_payload.freeze(), initial_location)
        };

        let socket_addr = match session.override_remote_write_address {
            Some(addr) => addr,
            None => {
                if remote_location == session.last_location {
                    session.last_socket_addr
                } else {
                    warn!(
                        "Location changed during ongoing UDP session: {}",
                        remote_location.clone()
                    );
                    let action = client_proxy_selector
                        .judge(remote_location.clone(), &resolver)
                        .await;
                    let updated_location = match action {
                        Ok(ConnectDecision::Allow {
                            chain_group: _,
                            remote_location,
                        }) => remote_location,
                        Ok(ConnectDecision::Block) => {
                            warn!("Blocked UDP forward to {remote_location}");
                            continue;
                        }
                        Err(e) => {
                            error!("Failed to judge UDP forward to {remote_location}: {e}");
                            continue;
                        }
                    };
                    let updated_socket_addr = match resolver_cache
                        .resolve_location(&updated_location)
                        .await
                    {
                        Ok(s) => s,
                        Err(e) => {
                            error!(
                                "Failed to resolve updated remote location {updated_location}: {e}"
                            );
                            continue;
                        }
                    };
                    session.last_location = updated_location;
                    session.last_socket_addr = updated_socket_addr;
                    updated_socket_addr
                }
            }
        };

        if let Err(e) = session
            .send_socket
            .send_to(&complete_payload, socket_addr)
            .await
        {
            error!("Failed to forward UDP payload for session {session_id}: {e}");
            sessions.remove(&session_id);
        }
    }
}

async fn run_tcp_loop(
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

        let client_proxy_selector = client_proxy_selector.clone();
        let resolver = resolver.clone();
        tokio::spawn(async move {
            if let Err(e) =
                process_tcp_stream(client_proxy_selector, resolver, send_stream, recv_stream).await
            {
                error!("Failed to process streams: {e}");
            }
        });
    }
    Ok(())
}

async fn handle_tcp_header(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
) -> std::io::Result<(NetLocation, StreamReader)> {
    let mut stream_reader = StreamReader::new_with_buffer_size(8192);

    // Read the TCP request frame type as a QUIC varint per protocol spec.
    // The value 0x401 can be encoded in multiple valid ways (e.g., [0x44, 0x01] as 2-byte form).
    let tcp_request_id = read_varint(recv, &mut stream_reader).await?;
    if tcp_request_id != FRAME_TYPE_TCP_REQUEST {
        return Err(std::io::Error::other(format!(
            "invalid tcp request id: expected {:#x}, got {:#x}",
            FRAME_TYPE_TCP_REQUEST, tcp_request_id
        )));
    }

    // max lengths from https://github.com/apernet/hysteria/blob/5520bcc405ee11a47c164c75bae5c40fc2b1d99d/core/internal/protocol/proxy.go#L19
    let address_len = read_varint(recv, &mut stream_reader).await?;
    if address_len > 2048 {
        return Err(std::io::Error::other("invalid address length"));
    }
    let address_bytes = stream_reader.read_slice(recv, address_len as usize).await?;
    let address = std::str::from_utf8(address_bytes).map_err(std::io::Error::other)?;
    let remote_location = NetLocation::from_str(address, None)?;

    let padding_len = read_varint(recv, &mut stream_reader).await?;
    if padding_len > 4096 {
        return Err(std::io::Error::other("invalid padding length"));
    }
    stream_reader.read_slice(recv, padding_len as usize).await?;

    let response_bytes = {
        // [uint8] Status (0x00 = OK, 0x01 = Error)
        // [varint] Message length
        // [bytes] Message string
        // [varint] Padding length
        // [bytes] Random padding

        let mut rng = rand::rng();

        // only use the lower 6 bits so that the varint always fits in a single u8
        let padding_len = rng.random_range(0..=63);

        // first 3 bytes of status = 0x0, message length = 0, padding length
        let mut response_bytes = allocate_vec(3 + (padding_len as usize));
        response_bytes[0] = tcp_status::OK;
        response_bytes[1] = 0;
        response_bytes[2] = padding_len;
        rng.fill_bytes(&mut response_bytes[3..]);

        response_bytes
    };

    let len = response_bytes.len();
    let mut i = 0;
    while i < len {
        let count = send
            .write(&response_bytes[i..len])
            .await
            .map_err(std::io::Error::other)?;
        i += count;
    }

    Ok((remote_location, stream_reader))
}

async fn process_tcp_stream(
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> std::io::Result<()> {
    let (remote_location, stream_reader) = match handle_tcp_header(&mut send, &mut recv).await {
        Ok(res) => res,
        Err(e) => {
            let _ = send.shutdown().await;
            return Err(e);
        }
    };

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
        let len = unparsed_data.len();
        let mut i = 0;
        while i < len {
            let count = client_stream
                .write(&unparsed_data[i..len])
                .await
                .map_err(std::io::Error::other)?;
            i += count;
        }
        true
    };
    drop(stream_reader);

    // Use 32KB buffers to match hysteria2/sing-box reference implementations
    let copy_result = copy_bidirectional_with_sizes(
        &mut server_stream,
        &mut client_stream,
        // no need to flush even through we wrote this response since it's quic
        false,
        client_requires_flush,
        32768,
        32768,
    )
    .await;

    let (_, _) = futures::join!(server_stream.shutdown(), client_stream.shutdown());

    copy_result?;
    Ok(())
}

#[inline]
fn encode_varint(value: u64) -> std::io::Result<Box<[u8]>> {
    if value <= 0b00111111 {
        Ok(Box::new([value as u8]))
    } else if value < (1 << 14) {
        let mut bytes = (value as u16).to_be_bytes();
        bytes[0] |= 0b01000000;
        Ok(Box::new(bytes))
    } else if value < (1 << 30) {
        let mut bytes = (value as u32).to_be_bytes();
        bytes[0] |= 0b10000000;
        Ok(Box::new(bytes))
    } else if value < (1 << 62) {
        let mut bytes = value.to_be_bytes();
        bytes[0] |= 0b11000000;
        Ok(Box::new(bytes))
    } else {
        Err(std::io::Error::other("value too large to encode as varint"))
    }
}

async fn read_varint(
    recv: &mut quinn::RecvStream,
    stream_reader: &mut StreamReader,
) -> std::io::Result<u64> {
    let first_byte = stream_reader.read_u8(recv).await?;

    let length = first_byte >> 6;
    let mut value: u64 = (first_byte & 0b00111111) as u64;

    let num_bytes = match length {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => {
            // impossible since we only have 2 bits
            panic!("invalid num bytes value");
        }
    };

    if num_bytes > 1 {
        let remaining_bytes = stream_reader.read_slice(recv, num_bytes - 1).await?;
        for byte in remaining_bytes {
            value <<= 8; // Shift left by 8 bits for each subsequent byte
            value |= *byte as u64; // Add the next byte
        }
    }

    Ok(value)
}

pub async fn start_hysteria2_server(
    bind_address: SocketAddr,
    quic_server_config: Arc<quinn::crypto::rustls::QuicServerConfig>,
    hysteria2_password: &'static str,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    num_endpoints: usize,
    udp_enabled: bool,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let mut join_handles = vec![];
    for _ in 0..num_endpoints {
        let quic_server_config = quic_server_config.clone();
        let resolver = resolver.clone();
        let client_proxy_selector = client_proxy_selector.clone();

        let join_handle = tokio::spawn(async move {
            let mut server_config = quinn::ServerConfig::with_crypto(quic_server_config);

            // values estimated from https://github.com/apernet/hysteria/blob/5520bcc405ee11a47c164c75bae5c40fc2b1d99d/core/server/config.go#L16
            Arc::get_mut(&mut server_config.transport)
                .unwrap()
                .max_concurrent_bidi_streams(4096_u32.into())
                // required for HTTP/3 QPACK updates
                .max_concurrent_uni_streams(1024_u32.into())
                .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()))
                .keep_alive_interval(Some(Duration::from_secs(10)))
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
                        hysteria2_password,
                        conn,
                        udp_enabled,
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
mod tests {
    use super::*;
    use crate::hysteria2_protocol::{
        header, tcp_status, AUTH_HOST, AUTH_PATH, FRAME_TYPE_TCP_REQUEST, STATUS_AUTH_OK,
    };

    // Helper function to decode a QUIC varint
    fn test_decode_varint(data: &[u8]) -> std::io::Result<(u64, usize)> {
        if data.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "incomplete varint",
            ));
        }

        let first_byte = data[0];
        let length_indicator = first_byte >> 6;
        let mut value: u64 = (first_byte & 0b00111111) as u64;

        let num_bytes = match length_indicator {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => 8,
            _ => unreachable!(),
        };

        if data.len() < num_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("incomplete varint: have {} bytes, need {}", data.len(), num_bytes),
            ));
        }

        if num_bytes > 1 {
            for byte in &data[1..num_bytes] {
                value <<= 8;
                value |= *byte as u64;
            }
        }

        Ok((value, num_bytes))
    }

    #[test]
    fn test_validate_auth_request_valid() {
        // Test a valid authentication request
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(AUTH_PATH)
            .header(http::header::HOST, AUTH_HOST)
            .header(header::AUTH, "test_password")
            .body(())
            .unwrap();

        let result = validate_auth_request(req, "test_password");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_auth_request_wrong_method() {
        // Test request with wrong method
        let req = http::Request::builder()
            .method(http::Method::GET)
            .uri(AUTH_PATH)
            .header(http::header::HOST, AUTH_HOST)
            .header(header::AUTH, "test_password")
            .body(())
            .unwrap();

        let result = validate_auth_request(req, "test_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_auth_request_wrong_path() {
        // Test request with wrong path
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("/wrong")
            .header(http::header::HOST, AUTH_HOST)
            .header(header::AUTH, "test_password")
            .body(())
            .unwrap();

        let result = validate_auth_request(req, "test_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_auth_request_wrong_host() {
        // Test request with wrong host
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(AUTH_PATH)
            .header(http::header::HOST, "wrong.com")
            .header(header::AUTH, "test_password")
            .body(())
            .unwrap();

        let result = validate_auth_request(req, "test_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_auth_request_missing_header() {
        // Test request without auth header
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(AUTH_PATH)
            .header(http::header::HOST, AUTH_HOST)
            .body(())
            .unwrap();

        let result = validate_auth_request(req, "test_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_auth_request_wrong_password() {
        // Test request with wrong password
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(AUTH_PATH)
            .header(http::header::HOST, AUTH_HOST)
            .header(header::AUTH, "wrong_password")
            .body(())
            .unwrap();

        let result = validate_auth_request(req, "test_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_auth_request_without_host() {
        // Test request without Host header (should still pass validation since Host is optional)
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(AUTH_PATH)
            .header(header::AUTH, "test_password")
            .body(())
            .unwrap();

        let result = validate_auth_request(req, "test_password");
        // Should pass because Host header check is optional
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_auth_request_with_empty_password() {
        // Test with empty password - should succeed
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(AUTH_PATH)
            .header(http::header::HOST, AUTH_HOST)
            .header(header::AUTH, "")
            .body(())
            .unwrap();

        let result = validate_auth_request(req, "");
        assert!(result.is_ok());

        // Test with wrong password - should fail
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(AUTH_PATH)
            .header(http::header::HOST, AUTH_HOST)
            .header(header::AUTH, "")
            .body(())
            .unwrap();

        let result = validate_auth_request(req, "test_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_varint_boundary_values() {
        // Test values at each encoding boundary
        let boundary_tests = vec![
            (0, 1),           // Minimum, single byte
            (63, 1),          // Max single byte
            (64, 2),          // Min two-byte
            (16383, 2),       // Max two-byte
            (16384, 4),       // Min four-byte
            (1073741823, 4),  // Max four-byte
            (1073741824, 8),  // Min eight-byte
        ];

        for (value, expected_bytes) in boundary_tests {
            let encoded = encode_varint(value).unwrap();
            assert_eq!(
                encoded.len(),
                expected_bytes,
                "Value {} should encode to {} bytes",
                value,
                expected_bytes
            );
        }
    }

    #[test]
    fn test_varint_max_value() {
        // Test maximum encodable value (2^62 - 1)
        let max_value = (1u64 << 62) - 1;
        let encoded = encode_varint(max_value).unwrap();
        assert_eq!(encoded.len(), 8);
        let (decoded, _) = test_decode_varint(&encoded).unwrap();
        assert_eq!(decoded, max_value);
    }

    #[test]
    fn test_varint_too_large() {
        // Value exceeding 62 bits should fail
        let result = encode_varint(1u64 << 62);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_ascii_string_properties() {
        // Test various properties of generated ASCII strings
        for _ in 0..50 {
            let s = generate_ascii_string();
            // Length should be in [1, 79]
            assert!(s.len() >= 1 && s.len() < 80);
            // Should be valid ASCII
            assert!(s.is_ascii());
            // Should contain only printable ASCII characters
            assert!(s.chars().all(|c| c >= ' ' && c <= '~'));
        }
    }

    #[test]
    fn test_generate_ascii_string_uniqueness() {
        // Generate multiple strings and verify they're likely unique
        let mut strings = std::collections::HashSet::new();
        for _ in 0..100 {
            let s = generate_ascii_string();
            strings.insert(s);
        }
        // With 100 random strings of length 1-79, extremely unlikely to have duplicates
        assert!(strings.len() > 95, "Should have mostly unique strings");
    }
}
