use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use log::error;
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
use crate::thread_util::get_num_threads;
use crate::udp_multi_message_stream::UdpMultiMessageStream;
use crate::util::allocate_vec;

const MAX_QUIC_ENDPOINTS: usize = 4;

async fn process_hysteria2_connection(
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    resolver: Arc<dyn Resolver>,
    password: &'static str,
    conn: quinn::Incoming,
) -> std::io::Result<()> {
    let connection = conn.await?;

    // we unfortunately need to keep the h3 connection around because it closes the underlying
    // connection on drop, see
    // https://github.com/hyperium/h3/blob/dbf2523d26e115f096b66cdd8a6f68127a17a156/h3/src/server/connection.rs#L427
    let h3_quinn_connection = h3_quinn::Connection::new(connection.clone());
    let mut h3_conn: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
        h3::server::Connection::new(h3_quinn_connection)
            .await
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
    auth_hysteria2_connection(&mut h3_conn, password).await?;

    {
        let connection = connection.clone();
        let client_proxy_selector = client_proxy_selector.clone();
        let resolver = resolver.clone();
        tokio::spawn(run_hysteria2_udp_read_loop(
            connection,
            client_proxy_selector,
            resolver,
        ));
    }

    tokio::spawn(run_hysteria2_tcp_loop(
        h3_conn,
        connection,
        client_proxy_selector,
        resolver,
    ));

    Ok(())
}

fn validate_auth_request<T>(req: http::Request<T>, password: &str) -> std::io::Result<()> {
    if req.uri() != "https://hysteria/auth" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "invalid uri",
        ));
    }
    if req.method() != "POST" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "invalid method",
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
            "missing host header",
        ));
    }

    Ok(())
}

async fn auth_hysteria2_connection(
    h3_conn: &mut h3::server::Connection<h3_quinn::Connection, bytes::Bytes>,
    password: &str,
) -> std::io::Result<()> {
    loop {
        match h3_conn
            .accept()
            .await
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?
        {
            Some((req, mut stream)) => {
                match validate_auth_request(req, password) {
                    Ok(()) => {
                        let resp = http::Response::builder()
                            .status(http::status::StatusCode::from_u16(233).unwrap())
                            .header("Hysteria-UDP", "true")
                            .header("Hysteria-CC-RX", "0")
                            // TODO: randomize padding
                            .header("Hysteria-Padding", "test")
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
    fragments: HashMap<u16, FragmentedPacket>,
    tx: tokio::sync::mpsc::Sender<UdpMessage>,
}

struct UdpMessage {
    payload: Bytes,
    remote_location: NetLocation,
}

struct FragmentedPacket {
    fragment_count: u8,
    fragment_received: u8,
    packet_len: usize,
    received: Vec<Option<Bytes>>,
    remote_location: NetLocation,
}

impl UdpSession {
    fn start(
        session_id: u32,
        connection: quinn::Connection,
        client_sockets: Vec<Arc<UdpSocket>>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(40);

        let session = UdpSession {
            fragments: HashMap::new(),
            tx,
        };

        let send_socket = client_sockets.first().unwrap().clone();

        // Spawn a dedicated worker task to drain the outgoing UDP message queue.
        let resolver_cache = ResolverCache::new(resolver.clone());
        tokio::spawn(async move {
            if let Err(e) =
                run_hysteria2_udp_remote_write_loop(session_id, send_socket, rx, resolver_cache)
                    .await
            {
                error!("UDP remote write loop ended with error: {}", e);
            }
        });

        let client_stream = UdpMultiMessageStream::new(client_sockets, resolver);
        tokio::spawn(async move {
            if let Err(e) =
                run_hysteria2_udp_local_write_loop(session_id, connection, client_stream).await
            {
                error!("UDP local write loop ended with error: {}", e);
            }
        });

        session
    }
}

async fn run_hysteria2_udp_remote_write_loop(
    session_id: u32,
    socket: Arc<UdpSocket>,
    mut rx: tokio::sync::mpsc::Receiver<UdpMessage>,
    mut resolver_cache: ResolverCache,
) -> std::io::Result<()> {
    let mut last_location = NetLocation::UNSPECIFIED;
    let mut last_socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

    while let Some(UdpMessage {
        remote_location,
        payload,
    }) = rx.recv().await
    {
        if remote_location != last_location {
            let socket_addr = match resolver_cache.resolve_location(&remote_location).await {
                Ok(socket_addr) => socket_addr,
                Err(e) => {
                    error!(
                        "Failed to resolve remote location {}: {}",
                        remote_location, e
                    );
                    continue;
                }
            };
            last_location = remote_location;
            last_socket_addr = socket_addr;
        };

        socket
            .send_to(&payload, &last_socket_addr)
            .await
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "Failed to forward UDP payload for session {}: {}",
                        session_id, e
                    ),
                )
            })?;
    }

    Ok(())
}

async fn run_hysteria2_udp_local_write_loop(
    session_id: u32,
    connection: quinn::Connection,
    mut socket: UdpMultiMessageStream,
) -> std::io::Result<()> {
    let max_datagram_size = connection.max_datagram_size().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            "datagram not supported by remote endpoint",
        )
    })?;

    let mut next_packet_id: u16 = 0;
    let mut buf = [0u8; 65535];

    loop {
        let (len, src_addr) = socket.read_sourced_message(&mut buf).await?;

        let packet_id = next_packet_id;
        next_packet_id = next_packet_id.wrapping_add(1);
        let addr_str = src_addr.to_string();
        let header_overhead = 4 + 2 + 1 + 1 + 1 + addr_str.len(); // session_id(4) + packet_id(2) + fragment id(1) + fragment count(1) + address length(1) + address bytes
        if header_overhead + len <= max_datagram_size {
            let mut datagram = BytesMut::with_capacity(header_overhead + len);
            datagram.extend_from_slice(&session_id.to_be_bytes());
            datagram.extend_from_slice(&packet_id.to_be_bytes());
            // fragment id = 0, fragment count = 0, address length
            datagram.extend_from_slice(&[0, 1, addr_str.len() as u8]);
            datagram.extend_from_slice(addr_str.as_bytes());
            datagram.extend_from_slice(&buf[..len]);

            connection.send_datagram(datagram.freeze()).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to send datagram: {}", e),
                )
            })?;
        } else {
            // Fragment the UDP packet since it exceeds max datagram size.
            assert!(max_datagram_size > header_overhead);

            let available_payload = max_datagram_size - header_overhead;
            let fragment_count = len.div_ceil(available_payload) as u8;
            for fragment_id in 0..fragment_count {
                let start = (fragment_id as usize) * available_payload;
                let end = std::cmp::min(start + available_payload, len);
                let mut datagram = BytesMut::with_capacity(header_overhead + (end - start));
                datagram.extend_from_slice(&session_id.to_be_bytes());
                datagram.extend_from_slice(&packet_id.to_be_bytes());
                datagram.extend_from_slice(&[fragment_id, fragment_count, addr_str.len() as u8]);
                datagram.extend_from_slice(addr_str.as_bytes());
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

async fn run_hysteria2_udp_read_loop(
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()> {
    let action = client_proxy_selector.default_decision();
    let client_proxy = match action {
        ConnectDecision::Allow {
            client_proxy,
            remote_location: _,
        } => client_proxy,
        ConnectDecision::Block => {
            return Ok(());
        }
    };

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
            let length_indicator = (first_byte >> 6) & 0b11;
            let mut value: u64 = (first_byte & 0b00111111) as u64;
            let num_bytes = match length_indicator {
                0 => 1,
                1 => 2,
                2 => 4,
                3 => 8,
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "invalid num bytes value",
                    ))
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
                let client_sockets = client_proxy.configure_reuse_udp_sockets(true, 2)?;
                let client_sockets = client_sockets.into_iter().map(Arc::new).collect::<Vec<_>>();
                let session = UdpSession::start(
                    session_id,
                    connection.clone(),
                    client_sockets,
                    resolver.clone(),
                );
                entry.insert(session)
            }
            Entry::Occupied(ref mut entry) => entry.get_mut(),
        };

        if fragment_count == 0 {
            error!("Ignoring empty UDP fragment for session {}", session_id);
            continue;
        } else if fragment_count == 1 {
            session
                .tx
                .send(UdpMessage {
                    payload: payload_fragment,
                    remote_location,
                })
                .await
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "Failed to queue UDP payload for session {}: {}",
                            session_id, e
                        ),
                    )
                })?;
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

            if entry.fragment_received == entry.fragment_count {
                let FragmentedPacket {
                    remote_location,
                    received,
                    packet_len,
                    ..
                } = session.fragments.remove(&packet_id).unwrap();
                let mut complete_payload = BytesMut::with_capacity(packet_len);
                for frag in received.into_iter() {
                    complete_payload.extend(frag.unwrap());
                }
                session
                    .tx
                    .send(UdpMessage {
                        payload: complete_payload.freeze(),
                        remote_location,
                    })
                    .await
                    .map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!(
                                "Failed to queue reassembled UDP payload for session {}: {}",
                                session_id, e
                            ),
                        )
                    })?;
            }
        }
    }
}
async fn run_hysteria2_tcp_loop(
    // unused, but needs to be kept in scope, see above.
    _h3_conn: h3::server::Connection<h3_quinn::Connection, bytes::Bytes>,
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
            if let Err(e) = process_hysteria2_tcp_stream(
                client_proxy_selector,
                resolver,
                send_stream,
                recv_stream,
            )
            .await
            {
                error!("Failed to process streams: {}", e);
            }
        });
    }
    Ok(())
}

async fn process_hysteria2_tcp_stream(
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    resolver: Arc<dyn Resolver>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> std::io::Result<()> {
    let mut line_reader = LineReader::new_with_buffer_size(8192);

    let tcp_request_id = read_varint(&mut recv, &mut line_reader).await?;
    if tcp_request_id != 0x401 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "invalid tcp request id",
        ));
    }

    // max lengths from https://github.com/apernet/hysteria/blob/5520bcc405ee11a47c164c75bae5c40fc2b1d99d/core/internal/protocol/proxy.go#L19
    let address_length = read_varint(&mut recv, &mut line_reader).await?;
    if address_length > 2048 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "invalid address length",
        ));
    }
    let address_bytes = line_reader
        .read_slice(&mut recv, address_length as usize)
        .await?;
    let address = std::str::from_utf8(address_bytes)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
    let remote_location = NetLocation::from_str(address, None)?;

    let padding_length = read_varint(&mut recv, &mut line_reader).await?;
    if padding_length > 4096 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "invalid padding length",
        ));
    }
    line_reader
        .read_slice(&mut recv, padding_length as usize)
        .await?;

    {
        let response_bytes = {
            // [uint8] Status (0x00 = OK, 0x01 = Error)
            // [varint] Message length
            // [bytes] Message string
            // [varint] Padding length
            // [bytes] Random padding

            let mut rng = rand::thread_rng();

            // only use the lower 6 bits so that the varint always fits in a single u8
            let padding_length = rng.gen_range(0..=63);

            // first 3 bytes of status = 0x0, message length = 0, padding length
            let mut response_bytes = allocate_vec(3 + (padding_length as usize));
            response_bytes[0] = 0;
            response_bytes[1] = 0;
            response_bytes[2] = padding_length;
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
    }

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
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "invalid num bytes value",
            ))
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
) -> std::io::Result<()> {
    // TODO: hash password instead of passing directly
    let hysteria2_password: &'static str = Box::leak(password.into_boxed_str());

    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());

    let quic_server_config: quinn::crypto::rustls::QuicServerConfig = server_config
        .try_into()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    let quic_server_config = Arc::new(quic_server_config);

    let endpoints_len = std::cmp::min(get_num_threads(), MAX_QUIC_ENDPOINTS);
    let mut join_handles = vec![];
    for _ in 0..endpoints_len {
        let quic_server_config = quic_server_config.clone();
        let resolver = resolver.clone();
        let client_proxy_selector = client_proxy_selector.clone();

        let join_handle = tokio::spawn(async move {
            let server_config = quinn::ServerConfig::with_crypto(quic_server_config);

            // TODO: consider setting transport config
            // Previously we set server_config.transport, but that seems to break when testing
            // against the hysteria2 client:
            //   Arc::get_mut(&mut server_config.transport)
            //     .unwrap()
            //     .max_concurrent_bidi_streams(1024_u32.into())
            //     .max_concurrent_uni_streams(0_u8.into())
            //     .keep_alive_interval(Some(Duration::from_secs(15)))
            //     .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
            //

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
                    if let Err(e) = process_hysteria2_connection(
                        cloned_selector,
                        cloned_resolver,
                        hysteria2_password,
                        conn,
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
