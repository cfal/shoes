use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use futures::{pin_mut, select, FutureExt};
use log::error;
use tokio::io::AsyncWriteExt;
use tokio::sync::Notify;
use tokio::time::timeout;

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::copy_bidirectional::copy_bidirectional;
use crate::quic_stream::QuicStream;
use crate::resolver::{NativeResolver, Resolver};
use crate::tcp_client_connector::TcpClientConnector;
use crate::tcp_server::setup_client_stream;
use crate::thread_util::get_num_threads;
use crate::udp_direct_message_stream::UdpDirectMessageStream;

const MAX_QUIC_ENDPOINTS: usize = 32;

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

    let udp_future = {
        let connection = connection.clone();
        let client_proxy_selector = client_proxy_selector.clone();
        let resolver = resolver.clone();
        run_hysteria2_udp_read_loop(connection, client_proxy_selector, resolver)
    };

    let tcp_future = run_hysteria2_tcp_loop(connection, client_proxy_selector, resolver);

    // Pin the futures since select! requires them to be pinned
    pin_mut!(udp_future);
    pin_mut!(tcp_future);

    select! {
        tcp_result = tcp_future.fuse() => tcp_result,
        udp_result = udp_future.fuse() => udp_result,
    }
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
    socket: UdpDirectMessageStream,
    cancel_notify: Arc<Notify>,
    fragments: HashMap<u16, FragmentedPacket>,
}

struct FragmentedPacket {
    fragment_count: u8,
    received: Vec<Option<Vec<u8>>>,
    header: Option<(String, NetLocation)>,
}

impl UdpSession {
    fn start(
        session_id: u32,
        connection: quinn::Connection,
        socket: UdpDirectMessageStream,
    ) -> Self {
        let notify = Arc::new(Notify::new());
        let session = UdpSession {
            socket: socket.clone(),
            fragments: HashMap::new(),
            cancel_notify: notify.clone(),
        };

        tokio::spawn(async move {
            if let Err(e) =
                run_hysteria2_udp_write_loop(session_id, connection, socket, notify).await
            {
                error!("Failed to write UDP loop: {}", e);
            }
        });
        session
    }
}

async fn run_hysteria2_udp_write_loop(
    session_id: u32,
    connection: quinn::Connection,
    socket: UdpDirectMessageStream,
    cancel_notify: Arc<Notify>,
) -> std::io::Result<()> {
    let max_datagram_size = connection.max_datagram_size().unwrap();
    let session_id = session_id;
    let mut next_packet_id: u16 = 0;

    let mut buf = [0u8; 65535];
    loop {
        match socket.read_sourced_message(&mut buf).await {
            Ok((len, src_addr)) => {
                let packet_id = next_packet_id;
                next_packet_id = next_packet_id.wrapping_add(1);
                let addr_str = src_addr.to_string();
                let header_overhead = 4 + 2 + 1 + 1 + 1 + addr_str.len(); // session_id(4) + packet_id(2) + fragment id(1) + fragment count(1) + address length(1) + address bytes
                if header_overhead + len <= max_datagram_size {
                    let mut datagram = BytesMut::with_capacity(header_overhead + len);
                    //let mut datagram = Vec::with_capacity(header_overhead + len);
                    datagram.extend_from_slice(&session_id.to_be_bytes());
                    datagram.extend_from_slice(&packet_id.to_be_bytes());
                    // fragment id = 0, fragment count = 0, address length
                    datagram.extend_from_slice(&[0, 1, addr_str.len() as u8]);
                    datagram.extend_from_slice(addr_str.as_bytes());
                    datagram.extend_from_slice(&buf[..len]);
                    if let Err(e) = connection.send_datagram(datagram.freeze()) {
                        error!("Failed to send UDP response datagram: {}", e);
                    }
                } else {
                    // Fragment the UDP packet since it exceeds max datagram size.
                    let available_payload = max_datagram_size - header_overhead;
                    if available_payload == 0 {
                        error!(
                            "Max datagram size {} is too small for header overhead: {}",
                            max_datagram_size, header_overhead
                        );
                        continue;
                    }
                    let fragment_count = ((len + available_payload - 1) / available_payload) as u8;
                    for fragment_id in 0..fragment_count {
                        let start = (fragment_id as usize) * available_payload;
                        let end = std::cmp::min(start + available_payload, len);
                        let mut datagram = BytesMut::with_capacity(header_overhead + (end - start));
                        datagram.extend_from_slice(&session_id.to_be_bytes());
                        datagram.extend_from_slice(&packet_id.to_be_bytes());
                        datagram.extend_from_slice(&[
                            fragment_id,
                            fragment_count,
                            addr_str.len() as u8,
                        ]);
                        datagram.extend_from_slice(addr_str.as_bytes());
                        datagram.extend_from_slice(&buf[start..end]);
                        if let Err(e) = connection.send_datagram(datagram.freeze()) {
                            error!(
                                "Failed to send UDP fragment {} for packet {}: {}",
                                fragment_id, packet_id, e
                            );
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to read UDP message from socket: {}", e);
                break;
            }
        }
    }

    Ok(())
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
        // TODO: stop initializing the read loop if it's blocked
        ConnectDecision::Block => futures::future::pending().await,
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
                std::io::ErrorKind::Other,
                "udp data length too short",
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
        let payload_fragment = data[next_index + address_len..].to_vec();

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
                let client_socket = client_proxy.configure_udp_socket()?;
                // because of the AsyncWriteTargetedMessage trait, which requires &mut self,
                // we can'e UdpDirectMessageStream in an Arc and use it repeatedly, so
                // clone here.
                let client_stream = UdpDirectMessageStream::new(client_socket, resolver.clone());
                let session = UdpSession::start(session_id, connection.clone(), client_stream);
                entry.insert(session)
            }
            Entry::Occupied(ref mut entry) => entry.get_mut(),
        };

        if fragment_count == 1 {
            // Forward UDP payload asynchronously to improve performance.
            let remote_location_clone = remote_location.clone();
            let mut socket_clone = session.socket.clone();
            let session_id_copy = session_id;
            tokio::spawn(async move {
                if let Err(e) = socket_clone
                    .write_targeted_message(&payload_fragment, &remote_location_clone)
                    .await
                {
                    error!(
                        "Failed to forward UDP payload for session {}: {}",
                        session_id_copy, e
                    );
                }
            });
        } else {
            let entry = session
                .fragments
                .entry(packet_id)
                .or_insert_with(|| FragmentedPacket {
                    fragment_count,
                    received: vec![None; fragment_count as usize],
                    header: Some((addr_str.to_string(), remote_location.clone())),
                });
            if entry.fragment_count != fragment_count {
                error!(
                    "Mismatched fragment count for session {} packet {}",
                    session_id, packet_id
                );
                continue;
            }
            if entry.header.is_none() {
                entry.header = Some((addr_str.to_string(), remote_location.clone()));
            }
            entry.received[fragment_id as usize] = Some(payload_fragment);
            if entry.received.iter().all(|frag| frag.is_some()) {
                let capacity: usize = entry
                    .received
                    .iter()
                    .filter_map(|frag| frag.as_ref().map(|f| f.len()))
                    .sum();
                let mut complete_payload = Vec::with_capacity(capacity);
                for frag in &entry.received {
                    complete_payload.extend(frag.as_ref().unwrap());
                }
                let complete_payload_final = complete_payload;
                let mut socket_clone = session.socket.clone();
                let session_id_copy = session_id;
                tokio::spawn(async move {
                    if let Err(e) = socket_clone
                        .write_targeted_message(&complete_payload_final, &remote_location)
                        .await
                    {
                        error!(
                            "Failed to forward reassembled UDP payload for session {}: {}",
                            session_id_copy, e
                        );
                    }
                });
                session.fragments.remove(&packet_id);
            }
        }
    }
}
async fn run_hysteria2_tcp_loop(
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()> {
    loop {
        let (send_stream, recv_stream) = match connection.accept_bi().await {
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                // TODO: should this be an error?
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Connection closed",
                ));
            }
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to accept bidirectional stream: {}", e),
                ));
            }
            Ok(s) => s,
        };
        let cloned_selector = client_proxy_selector.clone();
        let cloned_resolver = resolver.clone();
        tokio::spawn(async move {
            if let Err(e) = process_hysteria2_tcp_stream(
                cloned_selector,
                cloned_resolver,
                send_stream,
                recv_stream,
            )
            .await
            {
                error!("Failed to process streams: {}", e);
            }
        });
    }
}

async fn process_hysteria2_tcp_stream(
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    resolver: Arc<dyn Resolver>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> std::io::Result<()> {
    // TODO: read_exact is shown as non-cancellable, switch to a state machine?
    let tcp_request_id = read_varint(&mut recv).await?;
    if tcp_request_id != 0x401 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "invalid tcp request id",
        ));
    }
    let address_length = read_varint(&mut recv).await?;
    let mut address_bytes = vec![0u8; address_length as usize];
    recv.read_exact(&mut address_bytes)
        .await
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
    let padding_length = read_varint(&mut recv).await?;
    // TODO: this could be big, don't allocate
    let mut padding_bytes = vec![0u8; padding_length as usize];
    recv.read_exact(&mut padding_bytes)
        .await
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    let address = std::string::String::from_utf8(address_bytes)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
    let remote_location = NetLocation::from_str(&address, None)?;

    // TODO: add message or padding
    // [uint8] Status (0x00 = OK, 0x01 = Error)
    // [varint] Message length
    // [bytes] Message string
    // [varint] Padding length
    // [bytes] Random padding
    send.write_all(&[0u8, 0u8, 0u8])
        .await
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

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

    let server_need_initial_flush = false;
    let client_need_initial_flush = false;
    let copy_result = copy_bidirectional(
        &mut server_stream,
        &mut client_stream,
        server_need_initial_flush,
        client_need_initial_flush,
    )
    .await;

    let (_, _) = futures::join!(server_stream.shutdown(), client_stream.shutdown());

    copy_result?;
    Ok(())
}

async fn read_varint(recv: &mut quinn::RecvStream) -> std::io::Result<u64> {
    let mut first_byte = [0u8];
    recv.read_exact(&mut first_byte)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    let length = (first_byte[0] >> 6) & 0b11; // Get top two bits
    let mut value: u64 = (first_byte[0] & 0b00111111) as u64; // Remaining bits of the first byte

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
        let mut remaining_bytes = vec![0u8; num_bytes - 1];
        recv.read_exact(&mut remaining_bytes).await.map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to read remaining bytes: {}", e),
            )
        })?;

        for byte in remaining_bytes {
            value <<= 8; // Shift left by 8 bits for each subsequent byte
            value |= byte as u64; // Add the next byte
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
        let bind_address = bind_address.clone();
        let resolver = resolver.clone();
        let client_proxy_selector = client_proxy_selector.clone();

        let join_handle = tokio::spawn(async move {
            let server_config = quinn::ServerConfig::with_crypto(quic_server_config);

            // Previously we set server_config.transport, but that seems to break when testing
            // against the hysteria2 client:
            //   Arc::get_mut(&mut server_config.transport)
            //     .unwrap()
            //     .max_concurrent_bidi_streams(1024_u32.into())
            //     .max_concurrent_uni_streams(0_u8.into())
            //     .keep_alive_interval(Some(Duration::from_secs(15)))
            //     .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
            //

            let socket = {
                let socket2_socket = socket2::Socket::new(
                    socket2::Domain::for_address(bind_address),
                    socket2::Type::DGRAM,
                    Some(socket2::Protocol::UDP),
                )
                .unwrap();

                socket2_socket.set_nonblocking(true).unwrap();
                // We need to set SO_REUSEPORT firt before binding, else we will get "Address
                // already in use" errors.
                socket2_socket.set_reuse_port(true).unwrap();

                socket2_socket.bind(&bind_address.into()).unwrap();

                socket2_socket.into()
            };

            let endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(server_config),
                socket,
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
        join_handle.await.unwrap();
    }
    Ok(())
}
