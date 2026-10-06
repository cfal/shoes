use std::collections::hash_map::Entry;
use std::net::SocketAddr;
use std::str;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use log::{debug, error, warn};
use rand::distr::Alphanumeric;
use rand::{Rng, RngExt};
use rustc_hash::FxHashMap;
use tokio::io::AsyncWriteExt;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

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
use crate::resolver::Resolver;
use crate::routing::udp_relay::UdpRelay;
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_server::setup_client_tcp_stream;
use crate::udp_fragments::UdpFragments;
use crate::util::allocate_vec;

async fn process_connection(
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    password: Arc<str>,
    conn: quinn::Connecting,
    udp_enabled: bool,
) -> std::io::Result<()> {
    let connection = conn.await?;

    // Create a cancellation token for the entire connection lifecycle.
    // When cancelled, all spawned tasks (UDP sessions) will terminate gracefully.
    let cancel_token = CancellationToken::new();
    let _cancel_on_drop = cancel_token.clone().drop_guard();

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
            .map_err(|e| std::io::Error::other(format!("H3 connection setup failed: {e}")))?;

    // Per sing-box reference, authentication timeout is 3 seconds
    match timeout(
        AUTH_TIMEOUT,
        auth_connection(&mut h3_conn, &password, udp_enabled),
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
    if req.uri() != "https://hysteria/auth" {
        return Err(std::io::Error::other(format!(
            "unexpected uri: {}",
            req.uri()
        )));
    }
    if req.method() != "POST" {
        return Err(std::io::Error::other(format!(
            "unexpected method: {}",
            req.method()
        )));
    }

    let headers = req.headers();
    let auth_value = match headers.get("hysteria-auth") {
        Some(h) => h,
        None => {
            return Err(std::io::Error::other("missing auth header"));
        }
    };
    let auth_str = auth_value
        .to_str()
        .map_err(|e| std::io::Error::other(format!("invalid auth header value: {e}")))?;
    if auth_str != password {
        return Err(std::io::Error::other("incorrect auth password"));
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
        match h3_conn
            .accept()
            .await
            .map_err(|e| std::io::Error::other(format!("H3 accept failed: {e}")))?
        {
            Some(resolver) => {
                let (req, mut stream) = resolver.resolve_request().await.map_err(|err| {
                    std::io::Error::other(format!("Failed to resolve request: {err}"))
                })?;
                match validate_auth_request(req, password) {
                    Ok(()) => {
                        let resp = http::Response::builder()
                            .status(http::status::StatusCode::from_u16(233).unwrap())
                            .header("Hysteria-UDP", if udp_enabled { "true" } else { "false" })
                            .header("Hysteria-CC-RX", "0")
                            .header("Hysteria-Padding", generate_ascii_string())
                            .body(())
                            .unwrap();

                        stream.send_response(resp).await.map_err(|e| {
                            std::io::Error::other(format!("failed to send auth response: {e}"))
                        })?;

                        stream.finish().await.map_err(|e| {
                            std::io::Error::other(format!("failed to finish auth stream: {e}"))
                        })?;

                        return Ok(());
                    }
                    Err(e) => {
                        error!("Received non-hysteria2 auth http3 request: {e}");
                        let resp = http::Response::builder()
                            .status(http::status::StatusCode::NOT_FOUND)
                            .body(())
                            .unwrap();
                        stream.send_response(resp).await.map_err(|e| {
                            std::io::Error::other(format!("failed to send reject response: {e}"))
                        })?;
                        stream.finish().await.map_err(|e| {
                            std::io::Error::other(format!("failed to finish reject stream: {e}"))
                        })?;
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
    send_socket: Arc<UdpRelay>,
    pinned_location: Option<NetLocation>,
    cancel_token: CancellationToken,
    task: Option<tokio::task::AbortHandle>,
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
    // TODO: remove this function completely and inline?
    #[allow(clippy::too_many_arguments)]
    fn start(
        session_id: u32,
        connection: quinn::Connection,
        client_socket: Arc<UdpRelay>,
        override_local_write_location: Option<NetLocation>,
        pinned_location: Option<NetLocation>,
        parent_cancel_token: &CancellationToken,
    ) -> Self {
        // Create a child token so this session is cancelled when the parent (connection) is cancelled
        let session_cancel_token = parent_cancel_token.child_token();

        let mut session = UdpSession {
            send_socket: client_socket.clone(),
            pinned_location,
            cancel_token: session_cancel_token.clone(),
            task: None,
        };

        session.task = Some(
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
            })
            .abort_handle(),
        );

        session
    }
}

async fn run_udp_remote_to_local_loop(
    session_id: u32,
    connection: quinn::Connection,
    socket: Arc<UdpRelay>,
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
    let mut loop_count: u8 = 0;

    loop {
        let (payload, src_addr) = tokio::select! {
            _ = cancel_token.cancelled() => return Ok(()),
            result = socket.recv() => result?,
        };
        let payload_len = payload.len();

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

        if max_datagram_size <= header_overhead {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "QUIC datagram cannot fit UDP header",
            ));
        }

        if header_overhead + payload_len <= max_datagram_size {
            let mut datagram = BytesMut::with_capacity(header_overhead + payload_len);
            datagram.extend_from_slice(&session_id.to_be_bytes());
            datagram.extend_from_slice(&packet_id.to_be_bytes());
            // fragment id = 0, fragment count = 0
            datagram.extend_from_slice(&[0, 1]);
            datagram.extend_from_slice(&address_len_bytes);
            datagram.extend_from_slice(&address_bytes);
            datagram.extend_from_slice(&payload);

            connection
                .send_datagram(datagram.freeze())
                .map_err(|e| std::io::Error::other(format!("Failed to send datagram: {e}")))?;
        } else {
            let available_payload = max_datagram_size - header_overhead;
            let fragment_count =
                u8::try_from(payload_len.div_ceil(available_payload)).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "too many UDP fragments")
                })?;
            for fragment_id in 0..fragment_count {
                let start = (fragment_id as usize) * available_payload;
                let end = std::cmp::min(start + available_payload, payload_len);
                let mut datagram = BytesMut::with_capacity(header_overhead + (end - start));
                datagram.extend_from_slice(&session_id.to_be_bytes());
                datagram.extend_from_slice(&packet_id.to_be_bytes());
                datagram.extend_from_slice(&[fragment_id, fragment_count]);
                datagram.extend_from_slice(&address_len_bytes);
                datagram.extend_from_slice(&address_bytes);
                datagram.extend_from_slice(&payload[start..end]);

                connection.send_datagram(datagram.freeze()).map_err(|e| {
                    std::io::Error::other(format!(
                        "Failed to send datagram fragment {fragment_id}: {e}"
                    ))
                })?;
            }
        }
    }
}

struct UdpPacket<'a> {
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    location: NetLocation,
    payload: &'a [u8],
}

fn parse_udp_packet(data: &[u8]) -> std::io::Result<UdpPacket<'_>> {
    let invalid = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid Hysteria UDP datagram",
        )
    };
    if data.len() < 9 || data[7] == 0 || data[6] >= data[7] {
        return Err(invalid());
    }
    let length = 1usize << (data[8] >> 6);
    let encoded = data.get(8..8 + length).ok_or_else(invalid)?;
    let address_len = encoded[1..]
        .iter()
        .fold((encoded[0] & 63) as u64, |value, byte| {
            (value << 8) | *byte as u64
        });
    if address_len == 0 || address_len > 2048 {
        return Err(invalid());
    }
    let end = 8 + length + address_len as usize;
    let address = data.get(8 + length..end).ok_or_else(invalid)?;
    let location = NetLocation::from_str(str::from_utf8(address).map_err(|_| invalid())?, None)?;
    Ok(UdpPacket {
        session_id: u32::from_be_bytes(data[..4].try_into().unwrap()),
        packet_id: u16::from_be_bytes(data[4..6].try_into().unwrap()),
        fragment_id: data[6],
        fragment_count: data[7],
        location,
        payload: &data[end..],
    })
}

async fn run_udp_local_to_remote_loop(
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let mut sessions: FxHashMap<u32, UdpSession> = FxHashMap::default();
    let mut fragments = UdpFragments::new();
    let mut cleanup = tokio::time::interval(Duration::from_secs(1));
    const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

    loop {
        let data = tokio::select! {
            _ = cancel_token.cancelled() => return Ok(()),
            _ = cleanup.tick() => {
                fragments.expire();
                sessions.retain(|_, session| session.send_socket.idle_for() < IDLE_TIMEOUT);
                continue;
            }
            data = connection.read_datagram() => data.map_err(|err| std::io::Error::other(format!("failed to read datagram: {err}")))?,
        };
        let packet = match parse_udp_packet(&data) {
            Ok(packet) => packet,
            Err(e) => {
                debug!("Ignoring invalid Hysteria UDP datagram: {e}");
                continue;
            }
        };
        let session_id = packet.session_id;
        let (remote_location, complete_payload) = match fragments.push(
            (session_id, packet.packet_id),
            packet.fragment_count,
            packet.fragment_id,
            Some(packet.location),
            packet.payload,
        ) {
            Ok(Some(packet)) => packet,
            Ok(None) => continue,
            Err(e) => {
                debug!("Ignoring invalid Hysteria fragments: {e}");
                continue;
            }
        };
        if crate::resources::limits()
            .max_udp_destinations
            .is_some_and(|limit| sessions.len() >= limit)
            && !sessions.contains_key(&session_id)
        {
            continue;
        }

        let mut session_entry = sessions.entry(session_id);
        let session = match session_entry {
            Entry::Vacant(entry) => {
                let action = client_proxy_selector
                    .judge(remote_location.clone().into(), &resolver)
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

                let pinned_location = if remote_location.address().hostname().is_some()
                    || updated_location.location() != &remote_location
                {
                    Some(remote_location.clone())
                } else {
                    None
                };
                let Ok(client_socket) =
                    UdpRelay::new(client_proxy_selector.clone(), resolver.clone())
                else {
                    continue;
                };

                let session = UdpSession::start(
                    session_id,
                    connection.clone(),
                    Arc::new(client_socket),
                    pinned_location.clone(),
                    pinned_location,
                    &cancel_token,
                );
                entry.insert(session)
            }
            Entry::Occupied(ref mut entry) => entry.get_mut(),
        };

        let target = session.pinned_location.clone().unwrap_or(remote_location);
        if let Err(e) = session.send_socket.send_to(complete_payload, target) {
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
            if let Err(e) =
                process_tcp_stream(client_proxy_selector, resolver, send_stream, recv_stream).await
            {
                error!("Failed to process streams: {e}");
            }
        });
    }
    Ok(())
}

/// TCP request frame type constant from Hysteria2 protocol.
/// See: https://github.com/apernet/hysteria/blob/master/core/internal/protocol/proxy.go#L15
const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

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
    let address = std::str::from_utf8(address_bytes)
        .map_err(|e| std::io::Error::other(format!("invalid address encoding: {e}")))?;
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
        response_bytes[0] = 0;
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
            .map_err(|e| std::io::Error::other(format!("H3 stream write failed: {e}")))?;
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
                .map_err(|e| std::io::Error::other(format!("H3 stream write failed: {e}")))?;
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

    futures::join!(
        crate::util::shutdown_stream(&mut server_stream),
        crate::util::shutdown_stream(&mut client_stream),
    );

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
    hysteria2_password: Arc<str>,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    num_endpoints: usize,
    udp_enabled: bool,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let mut join_handles = vec![];
    let mut server_config = quinn::ServerConfig::with_crypto(quic_server_config);

    let memory_bytes = crate::resources::configure_quic(&mut server_config, 4096, 1024);
    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        // HTTP/3 control and QPACK streams are independent of application stream limits.
        .max_concurrent_uni_streams(1024u32.into())
        .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()))
        .keep_alive_interval(Some(Duration::from_secs(10)))
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
        let hysteria2_password = hysteria2_password.clone();
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
                let hysteria2_password = hysteria2_password.clone();
                tasks.spawn(async move {
                    let _permit = permit;
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
mod datagram_tests {
    use super::*;

    #[test]
    fn truncated_varints_and_fragment_indices_never_panic() {
        for first in [0x00, 0x40, 0x80, 0xc0] {
            let mut packet = vec![0; 9];
            packet[7] = 1;
            packet[8] = first;
            assert!(parse_udp_packet(&packet).is_err());
        }
        let address = b"127.0.0.1:53";
        let mut packet = vec![0, 0, 0, 1, 0, 1, 0, 1, address.len() as u8];
        packet.extend_from_slice(address);
        packet.extend_from_slice(b"payload");
        assert_eq!(parse_udp_packet(&packet).unwrap().payload, b"payload");
        for len in 0..packet.len() {
            let _ = parse_udp_packet(&packet[..len]);
        }
        for count in [0, 1, 2, 255] {
            for id in 0..=255 {
                packet[6] = id;
                packet[7] = count;
                assert_eq!(parse_udp_packet(&packet).is_ok(), count != 0 && id < count);
            }
        }
    }
}
