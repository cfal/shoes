use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use log::{error, warn};
use rand::{Rng, RngCore};
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::copy_bidirectional::copy_bidirectional_with_sizes;
use crate::line_reader::LineReader;
use crate::quic_stream::QuicStream;
use crate::resolver::{NativeResolver, Resolver, ResolverCache};
use crate::socket_util::new_socket2_udp_socket;
use crate::tcp_client_connector::TcpClientConnector;
use crate::tcp_server::setup_client_stream;
use crate::util::allocate_vec;

async fn process_connection(
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    resolver: Arc<dyn Resolver>,
    password: &'static str,
    conn: quinn::Incoming,
    udp_enabled: bool,
) -> std::io::Result<()> {
    let connection = conn.await?;

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
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
    auth_connection(&mut h3_conn, password, udp_enabled).await?;

    let mut join_handles = vec![];
    if udp_enabled {
        let connection = connection.clone();
        let client_proxy_selector = client_proxy_selector.clone();
        let resolver = resolver.clone();
        join_handles.push(tokio::spawn(async move {
            if let Err(e) =
                run_udp_local_to_remote_loop(connection, client_proxy_selector, resolver).await
            {
                error!("UDP local-to-remote write loop ended with error: {}", e);
            }
        }));
    }

    // depending on the client, unidirectional streams could still be sent, accept and drop.
    {
        let connection = connection.clone();
        join_handles.push(tokio::spawn(async move {
            loop {
                match connection.accept_uni().await {
                    Ok(mut recv_stream) => {
                        let _ = recv_stream.stop(0u32.into());
                    }
                    Err(e) => {
                        error!("Unidirectional loop ended with error: {}", e);
                        break;
                    }
                }
            }
        }));
    }
    join_handles.push(tokio::spawn(async move {
        if let Err(e) = run_tcp_loop(connection, client_proxy_selector, resolver).await {
            error!("TCP loop ended with error: {}", e);
        }
    }));

    for join_handle in join_handles {
        join_handle.await?;
    }

    Ok(())
}

fn validate_auth_request<T>(req: http::Request<T>, password: &str) -> std::io::Result<()> {
    if req.uri() != "https://hysteria/auth" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("unexpected uri: {}", req.uri()),
        ));
    }
    if req.method() != "POST" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("unexpected method: {}", req.method()),
        ));
    }

    let headers = req.headers();
    let auth_value = match headers.get("hysteria-auth") {
        Some(h) => h,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "missing auth header",
            ));
        }
    };
    let auth_str = auth_value
        .to_str()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
    if auth_str != password {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("incorrect auth password: {}", auth_str),
        ));
    }

    Ok(())
}

fn generate_ascii_string() -> String {
    let mut rng = rand::thread_rng();
    let length = rng.gen_range(1..80);
    rng.sample_iter(&rand::distributions::Alphanumeric)
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
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?
        {
            Some((req, mut stream)) => match validate_auth_request(req, password) {
                Ok(()) => {
                    let resp = http::Response::builder()
                        .status(http::status::StatusCode::from_u16(233).unwrap())
                        .header("Hysteria-UDP", if udp_enabled { "true" } else { "false" })
                        .header("Hysteria-CC-RX", "0")
                        .header("Hysteria-Padding", generate_ascii_string())
                        .body(())
                        .unwrap();

                    stream
                        .send_response(resp)
                        .await
                        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

                    stream
                        .finish()
                        .await
                        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

                    return Ok(());
                }
                Err(e) => {
                    error!("Received non-hysteria2 auth http3 request: {}", e);
                    let resp = http::Response::builder()
                        .status(http::status::StatusCode::NOT_FOUND)
                        .body(())
                        .unwrap();
                    stream
                        .send_response(resp)
                        .await
                        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
                    stream
                        .finish()
                        .await
                        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
                }
            },
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
    fragments: HashMap<u16, FragmentedPacket>,
    send_socket: Arc<UdpSocket>,
    // we cache the last location in case of mid-session address changes, and
    // don't want to have to call ClientProxySelector::judge on every packet.
    last_location: NetLocation,
    last_socket_addr: SocketAddr,
    override_remote_write_address: Option<SocketAddr>,
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
    fn start(
        session_id: u32,
        connection: quinn::Connection,
        client_socket: Arc<UdpSocket>,
        initial_location: NetLocation,
        initial_socket_addr: SocketAddr,
        override_local_write_location: Option<NetLocation>,
        override_remote_write_address: Option<SocketAddr>,
    ) -> Self {
        let session = UdpSession {
            fragments: HashMap::new(),
            send_socket: client_socket.clone(),
            last_location: initial_location,
            last_socket_addr: initial_socket_addr,
            override_remote_write_address,
        };

        tokio::spawn(async move {
            if let Err(e) = run_udp_remote_to_local_loop(
                session_id,
                connection,
                client_socket,
                override_local_write_location,
            )
            .await
            {
                error!("UDP remote-to-local write loop ended with error: {}", e);
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
) -> std::io::Result<()> {
    let max_datagram_size = connection.max_datagram_size().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            "datagram not supported by remote endpoint",
        )
    })?;

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
    let mut buf = [0u8; 65535];

    loop {
        let (payload_len, src_addr) = match socket.try_recv_from(&mut buf) {
            Ok(res) => res,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                socket.readable().await?;
                continue;
            }
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to receive from UDP socket: {}", e),
                ));
            }
        };

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
            "max datagram size ({}) is smaller than header overhead ({})",
            max_datagram_size,
            header_overhead
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

            connection.send_datagram(datagram.freeze()).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to send datagram: {}", e),
                )
            })?;
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
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to send datagram fragment {}: {}", fragment_id, e),
                    )
                })?;
            }
        }
    }
}

async fn run_udp_local_to_remote_loop(
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()> {
    let mut resolver_cache = ResolverCache::new(resolver.clone());
    let mut sessions: HashMap<u32, UdpSession> = HashMap::new();

    loop {
        let data = connection.read_datagram().await.map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed to read datagram: {}", err),
            )
        })?;
        if data.len() < 9 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "datagram length too short",
            ));
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
                    panic!("invalid num bytes value");
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
            error!("Ignoring packet with empty address");
            continue;
        }

        if address_len > 2048 {
            error!("Ignoring packet with address length {}", address_len);
            continue;
        }

        if data.len() < next_index + address_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "invalid address length",
            ));
        }
        let address_bytes = &data[next_index..next_index + address_len];
        let payload_fragment = data.slice(next_index + address_len..);

        let addr_str = match str::from_utf8(address_bytes) {
            Ok(s) => s,
            Err(e) => {
                error!("Invalid UTF-8 in address: {}", e);
                continue;
            }
        };

        let remote_location = match NetLocation::from_str(addr_str, None) {
            Ok(loc) => loc,
            Err(e) => {
                error!("Failed to parse remote location from {}: {}", addr_str, e);
                continue;
            }
        };

        let mut session_entry = sessions.entry(session_id);
        let session = match session_entry {
            Entry::Vacant(entry) => {
                let action = client_proxy_selector
                    .judge(remote_location.clone(), &resolver)
                    .await;

                let (client_proxy, updated_location) = match action {
                    Ok(ConnectDecision::Allow {
                        client_proxy,
                        remote_location,
                    }) => (client_proxy, remote_location),
                    Ok(ConnectDecision::Block) => {
                        warn!("Blocked UDP forward to {}", remote_location);
                        continue;
                    }
                    Err(e) => {
                        error!("Failed to judge UDP forward to {}: {}", remote_location, e);
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

                let resolved_address =
                    match resolver_cache.resolve_location(&updated_location).await {
                        Ok(s) => s,
                        Err(e) => {
                            error!(
                                "Failed to resolve initial remote location {}: {}",
                                remote_location, e
                            );
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
                let client_socket = client_proxy.configure_udp_socket(true)?;

                let session = UdpSession::start(
                    session_id,
                    connection.clone(),
                    Arc::new(client_socket),
                    remote_location.clone(),
                    resolved_address,
                    override_local_write_location,
                    override_remote_write_address,
                );
                entry.insert(session)
            }
            Entry::Occupied(ref mut entry) => entry.get_mut(),
        };

        let (complete_payload, remote_location) = if fragment_count == 0 {
            error!("Ignoring empty UDP fragment for session {}", session_id);
            continue;
        } else if fragment_count == 1 {
            (payload_fragment, remote_location)
        } else {
            let entry =
                session
                    .fragments
                    .entry(packet_id)
                    .or_insert_with(move || FragmentedPacket {
                        fragment_count,
                        fragment_received: 0,
                        packet_len: 0,
                        received: vec![None; fragment_count as usize],
                        remote_location,
                    });
            if entry.fragment_count != fragment_count {
                session.fragments.remove(&packet_id).unwrap();
                error!(
                    "Mismatched fragment count for session {} packet {}",
                    session_id, packet_id
                );
                continue;
            }
            if entry.received[fragment_id as usize].is_some() {
                session.fragments.remove(&packet_id).unwrap();
                error!(
                    "Duplicate fragment for session {} packet {}",
                    session_id, packet_id
                );
                continue;
            }
            entry.fragment_received += 1;
            entry.packet_len += payload_fragment.len();
            entry.received[fragment_id as usize] = Some(payload_fragment);

            if entry.fragment_received != entry.fragment_count {
                continue;
            }

            let FragmentedPacket {
                remote_location: initial_location,
                received,
                packet_len,
                ..
            } = session.fragments.remove(&packet_id).unwrap();
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
                            client_proxy: _,
                            remote_location,
                        }) => remote_location,
                        Ok(ConnectDecision::Block) => {
                            warn!("Blocked UDP forward to {}", remote_location);
                            continue;
                        }
                        Err(e) => {
                            error!("Failed to judge UDP forward to {}: {}", remote_location, e);
                            continue;
                        }
                    };
                    let updated_socket_addr =
                        match resolver_cache.resolve_location(&updated_location).await {
                            Ok(s) => s,
                            Err(e) => {
                                error!(
                                    "Failed to resolve updated remote location {}: {}",
                                    updated_location, e
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
            error!(
                "Failed to forward UDP payload for session {}: {}",
                session_id, e
            );
        }
    }
}

async fn run_tcp_loop(
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
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
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to accept bidirectional stream: {}", e),
                ));
            }
        };

        let client_proxy_selector = client_proxy_selector.clone();
        let resolver = resolver.clone();
        tokio::spawn(async move {
            if let Err(e) =
                process_tcp_stream(client_proxy_selector, resolver, send_stream, recv_stream).await
            {
                error!("Failed to process streams: {}", e);
            }
        });
    }
    Ok(())
}

async fn handle_tcp_header(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
) -> std::io::Result<(NetLocation, LineReader)> {
    let mut line_reader = LineReader::new_with_buffer_size(8192);

    // the tcp request id is a varint with value 0x401, which is encoded as [0x44, 0x01]
    let tcp_request_id = line_reader.read_slice(recv, 2).await?;
    if tcp_request_id[0] != 0x44 || tcp_request_id[1] != 0x01 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "invalid tcp request id",
        ));
    }

    // max lengths from https://github.com/apernet/hysteria/blob/5520bcc405ee11a47c164c75bae5c40fc2b1d99d/core/internal/protocol/proxy.go#L19
    let address_len = read_varint(recv, &mut line_reader).await?;
    if address_len > 2048 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "invalid address length",
        ));
    }
    let address_bytes = line_reader.read_slice(recv, address_len as usize).await?;
    let address = std::str::from_utf8(address_bytes)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
    let remote_location = NetLocation::from_str(address, None)?;

    let padding_len = read_varint(recv, &mut line_reader).await?;
    if padding_len > 4096 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "invalid padding length",
        ));
    }
    line_reader.read_slice(recv, padding_len as usize).await?;

    let response_bytes = {
        // [uint8] Status (0x00 = OK, 0x01 = Error)
        // [varint] Message length
        // [bytes] Message string
        // [varint] Padding length
        // [bytes] Random padding

        let mut rng = rand::thread_rng();

        // only use the lower 6 bits so that the varint always fits in a single u8
        let padding_len = rng.gen_range(0..=63);

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
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
        i += count;
    }

    Ok((remote_location, line_reader))
}

async fn process_tcp_stream(
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    resolver: Arc<dyn Resolver>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> std::io::Result<()> {
    let (remote_location, line_reader) = match handle_tcp_header(&mut send, &mut recv).await {
        Ok(res) => res,
        Err(e) => {
            let _ = send.shutdown().await;
            return Err(e);
        }
    };

    let mut server_stream: Box<dyn AsyncStream> = Box::new(QuicStream::from(send, recv));

    let setup_client_stream_future = timeout(
        Duration::from_secs(60),
        setup_client_stream(
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
                format!(
                    "failed to setup client stream to {}: {}",
                    remote_location, e
                ),
            ));
        }
        Err(elapsed) => {
            let _ = server_stream.shutdown().await;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("client setup to {} timed out: {}", remote_location, elapsed),
            ));
        }
    };

    let unparsed_data = line_reader.unparsed_data();
    let client_requires_flush = if unparsed_data.is_empty() {
        false
    } else {
        let len = unparsed_data.len();
        let mut i = 0;
        while i < len {
            let count = client_stream
                .write(&unparsed_data[i..len])
                .await
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
            i += count;
        }
        true
    };
    drop(line_reader);

    // unlike tokio's implementation, we read as much as possible to fill up the
    // buffer size before sending. reduce the buffer sizes compared to tcp -> tcp.
    // also see https://www.privateoctopus.com/2023/12/12/quic-performance.html
    let copy_result = copy_bidirectional_with_sizes(
        &mut server_stream,
        &mut client_stream,
        // no need to flush even through we wrote this response since it's quic
        false,
        client_requires_flush,
        // quic -> tcp
        8192,
        // tcp -> quic
        16384,
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
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "value too large to encode as varint",
        ))
    }
}

async fn read_varint(
    recv: &mut quinn::RecvStream,
    line_reader: &mut LineReader,
) -> std::io::Result<u64> {
    let first_byte = line_reader.read_u8(recv).await?;

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
        let remaining_bytes = line_reader.read_slice(recv, num_bytes - 1).await?;
        for byte in remaining_bytes {
            value <<= 8; // Shift left by 8 bits for each subsequent byte
            value |= *byte as u64; // Add the next byte
        }
    }

    Ok(value)
}

pub async fn run_hysteria2_server(
    bind_address: SocketAddr,
    server_config: Arc<rustls::ServerConfig>,
    password: String,
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    num_endpoints: usize,
    udp_enabled: bool,
) -> std::io::Result<()> {
    // TODO: hash password instead of passing directly
    let hysteria2_password: &'static str = Box::leak(password.into_boxed_str());

    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());

    let quic_server_config: quinn::crypto::rustls::QuicServerConfig = server_config
        .try_into()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    let quic_server_config = Arc::new(quic_server_config);

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
                // required for HTTP/3 QPACK updates
                .max_concurrent_uni_streams(1024_u32.into())
                .keep_alive_interval(Some(Duration::from_secs(15)))
                .max_idle_timeout(Some(Duration::from_secs(120).try_into().unwrap()));

            let socket2_socket =
                new_socket2_udp_socket(bind_address.is_ipv6(), None, Some(bind_address), true)
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
                        error!("Connection ended with error: {}", e);
                    }
                });
            }
        });
        join_handles.push(join_handle);
    }

    for join_handle in join_handles {
        join_handle.await?;
    }
    Ok(())
}
