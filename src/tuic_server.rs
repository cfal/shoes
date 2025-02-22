use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use log::{error, warn};
use rand::{Rng, RngCore};
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::copy_bidirectional::copy_bidirectional_with_sizes;
use crate::line_reader::LineReader;
use crate::quic_stream::QuicStream;
use crate::resolver::{resolve_single_address, NativeResolver, Resolver, ResolverCache};
use crate::socket_util::new_socket2_udp_socket;
use crate::tcp_client_connector::TcpClientConnector;
use crate::tcp_server::setup_client_stream;
use crate::util::{allocate_vec, parse_uuid};

const COMMAND_TYPE_AUTHENTICATE: u8 = 0x00;
const COMMAND_TYPE_CONNECT: u8 = 0x01;
const COMMAND_TYPE_PACKET: u8 = 0x02;
const COMMAND_TYPE_DISSOCIATE: u8 = 0x03;
const COMMAND_TYPE_HEARTBEAT: u8 = 0x04;

async fn process_connection(
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    resolver: Arc<dyn Resolver>,
    uuid: &'static [u8],
    password: &'static str,
    conn: quinn::Incoming,
) -> std::io::Result<()> {
    let connection = conn.await?;

    auth_connection(&connection, uuid, password).await?;

    // this allows for:
    // 1. multiple threads can read different sessions concurrently
    // 2. multiple threads can modify different sessions concurrently
    // 3. the outer write lock is only needed for adding/removing sessions
    let udp_session_map = Arc::new(DashMap::new());

    let mut join_handles = vec![];
    {
        let connection = connection.clone();
        let client_proxy_selector = client_proxy_selector.clone();
        let resolver = resolver.clone();
        join_handles.push(tokio::spawn(async move {
            if let Err(e) =
                run_bidirectional_loop(connection, client_proxy_selector, resolver).await
            {
                error!("Bidirectional loop ended with error: {}", e);
            }
        }));
    }

    {
        let connection = connection.clone();
        let client_proxy_selector = client_proxy_selector.clone();
        let resolver = resolver.clone();
        let udp_session_map = udp_session_map.clone();
        join_handles.push(tokio::spawn(async move {
            if let Err(e) = run_unidirectional_loop(
                connection,
                client_proxy_selector,
                resolver,
                udp_session_map,
            )
            .await
            {
                error!("Bidirectional loop ended with error: {}", e);
            }
        }));
    }

    {
        join_handles.push(tokio::spawn(async move {
            if let Err(e) =
                run_datagram_loop(connection, client_proxy_selector, resolver, udp_session_map)
                    .await
            {
                error!("Bidirectional loop ended with error: {}", e);
            }
        }));
    }

    for join_handle in join_handles {
        join_handle.await?;
    }

    Ok(())
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
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to export keying material: {:?}", e),
            )
        })?;

    let mut recv_stream = connection.accept_uni().await?;
    let mut line_reader = LineReader::new_with_buffer_size(80);
    let tuic_version = line_reader.read_u8(&mut recv_stream).await?;
    if tuic_version != 5 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("invalid tuic version: {}", tuic_version),
        ));
    }
    let command_type = line_reader.read_u8(&mut recv_stream).await?;
    if command_type != COMMAND_TYPE_AUTHENTICATE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("invalid command type: {}", command_type),
        ));
    }
    let specified_uuid = line_reader.read_slice(&mut recv_stream, 16).await?;
    if specified_uuid != uuid {
        // TODO: pretty print
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("incorrect uuid: {:?}", specified_uuid),
        ));
    }
    let token_bytes = line_reader.read_slice(&mut recv_stream, 32).await?;
    if token_bytes != expected_token_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("incorrect token"),
        ));
    }

    Ok(())
}

async fn run_bidirectional_loop(
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
                error!("Error processing TCP stream: {}", e);
            }
        });
    }
    Ok(())
}

async fn read_address(
    recv: &mut quinn::RecvStream,
    line_reader: &mut LineReader,
) -> std::io::Result<Option<NetLocation>> {
    let address_type = line_reader.read_u8(recv).await?;
    let address = match address_type {
        0xff => {
            return Ok(None);
        }
        0x00 => {
            let address_len = line_reader.read_u8(recv).await? as usize;
            let address_bytes = line_reader.read_slice(recv, address_len).await?;
            let address_str = String::from_utf8(address_bytes.to_vec()).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid address: {}", e),
                )
            })?;
            Address::Hostname(address_str)
        }
        0x01 => {
            let ipv4_bytes = line_reader.read_slice(recv, 4).await?;
            let ipv4_addr =
                Ipv4Addr::new(ipv4_bytes[0], ipv4_bytes[1], ipv4_bytes[2], ipv4_bytes[3]);
            Address::Ipv4(ipv4_addr)
        }
        0x02 => {
            let ipv6_bytes = line_reader.read_slice(recv, 16).await?;
            let ipv6_bytes: [u8; 16] = ipv6_bytes.try_into().unwrap();
            let ipv6_addr = Ipv6Addr::from(ipv6_bytes);
            Address::Ipv6(ipv6_addr)
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("invalid address type: {}", address_type),
            ));
        }
    };

    let port = line_reader.read_u16_be(recv).await?;

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
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    resolver: Arc<dyn Resolver>,
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> std::io::Result<()> {
    let mut line_reader = LineReader::new_with_buffer_size(1024);
    let tuic_version = line_reader.read_u8(&mut recv).await?;
    if tuic_version != 5 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("invalid tuic version: {}", tuic_version),
        ));
    }
    let command_type = line_reader.read_u8(&mut recv).await?;
    if command_type != COMMAND_TYPE_CONNECT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("invalid command type: {}", command_type),
        ));
    }

    let remote_location = read_address(&mut recv, &mut line_reader)
        .await?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "empty address"))?;

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

type UdpSessionMap = Arc<DashMap<u16, UdpSession>>;

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
    remote_location: Option<NetLocation>,
}

impl UdpSession {
    // TODO: remove this function completely and inline?
    fn start(
        assoc_id: u16,
        send_stream: quinn::SendStream,
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
            if let Err(e) = run_udp_remote_to_local_stream_loop(
                assoc_id,
                send_stream,
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

    #[inline]
    async fn resolve_address(
        &self,
        location: &NetLocation,
        client_proxy_selector: &Arc<ClientProxySelector<TcpClientConnector>>,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<(SocketAddr, bool)> {
        let (addr, is_updated) = match self.override_remote_write_address {
            Some(addr) => (addr, false),
            None => {
                if location == &self.last_location {
                    (self.last_socket_addr, false)
                } else {
                    let action = client_proxy_selector
                        .judge(location.clone(), &resolver)
                        .await?;

                    let updated_location = match action {
                        ConnectDecision::Allow {
                            client_proxy: _,
                            remote_location,
                        } => remote_location,
                        ConnectDecision::Block => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("Blocked UDP forward to {}", location),
                            ));
                        }
                    };
                    let updated_address =
                        match resolve_single_address(&resolver, &updated_location).await {
                            Ok(s) => s,
                            Err(e) => {
                                error!(
                                    "Failed to resolve updated remote location {}: {}",
                                    location, e
                                );
                                return Err(e);
                            }
                        };

                    (updated_address, true)
                }
            }
        };

        Ok((addr, is_updated))
    }
}

async fn run_udp_remote_to_local_stream_loop(
    assoc_id: u16,
    mut send_stream: quinn::SendStream,
    socket: Arc<UdpSocket>,
    override_local_write_address: Option<NetLocation>,
) -> std::io::Result<()> {
    let original_address_bytes: Option<Bytes> =
        override_local_write_address.map(|a| serialize_address(&a).into());

    // hostname case: type (1) + hostname length (1) + hostname bytes (255) + port (2)
    const MAX_ADDRESS_BYTES_LEN: usize = 1 + 1 + 255 + 2;
    const MAX_HEADER_LEN: usize = 2 + 2 + 1 + 1 + 2 + MAX_ADDRESS_BYTES_LEN;

    let mut next_packet_id: u16 = 0;
    let mut buf = [0u8; MAX_HEADER_LEN + 65535];

    loop {
        let (payload_len, src_addr) = match socket.try_recv_from(&mut buf[MAX_HEADER_LEN..]) {
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
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
            i += count;
        }
    }
}

async fn run_unidirectional_loop(
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    resolver: Arc<dyn Resolver>,
    udp_session_map: UdpSessionMap,
) -> std::io::Result<()> {
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
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to accept unidirectional stream: {}", e),
                ));
            }
        };

        let connection = connection.clone();
        let client_proxy_selector = client_proxy_selector.clone();
        let resolver = resolver.clone();
        let udp_session_map = udp_session_map.clone();
        tokio::spawn(async move {
            if let Err(e) = process_udp_recv_stream(
                connection,
                client_proxy_selector,
                resolver,
                recv_stream,
                udp_session_map,
            )
            .await
            {
                error!("Error processing UDP stream: {}", e);
            }
        });
    }
    std::future::pending::<()>().await;
    Ok(())
}

async fn process_udp_recv_stream(
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    resolver: Arc<dyn Resolver>,
    mut recv_stream: quinn::RecvStream,
    udp_session_map: UdpSessionMap,
) -> std::io::Result<()> {
    let mut line_reader = LineReader::new_with_buffer_size(65535);
    loop {
        let tuic_version = line_reader.read_u8(&mut recv_stream).await?;
        if tuic_version != 5 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("invalid tuic version: {}", tuic_version),
            ));
        }
        let command_type = line_reader.read_u8(&mut recv_stream).await?;
        if command_type == COMMAND_TYPE_HEARTBEAT {
            continue;
        } else if command_type == COMMAND_TYPE_DISSOCIATE {
            let assoc_id = line_reader.read_u16_be(&mut recv_stream).await?;
            let removed_session = udp_session_map.remove(&assoc_id);
            if removed_session.is_none() {
                error!("UDP session {} not found to dissociate", assoc_id);
                continue;
            }
        } else if command_type != COMMAND_TYPE_PACKET {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("invalid UDP stream command type: {}", command_type),
            ));
        }

        let assoc_id = line_reader.read_u16_be(&mut recv_stream).await?;
        let packet_id = line_reader.read_u16_be(&mut recv_stream).await?;
        let frag_total = line_reader.read_u8(&mut recv_stream).await?;
        let frag_id = line_reader.read_u8(&mut recv_stream).await?;
        let payload_size = line_reader.read_u16_be(&mut recv_stream).await?;
        let remote_location = read_address(&mut recv_stream, &mut line_reader).await?;

        let payload_fragment = line_reader
            .read_slice(&mut recv_stream, payload_size as usize)
            .await?;

        let session = match udp_session_map.get(&assoc_id) {
            Some(s) => s,
            None => {
                // TODO: it's possible that a new session starts with a fragmented packet, and we
                // receive this initial packet out of order so there's no address.
                if remote_location.is_none() {
                    warn!("Ignoring packet with unknown session and empty address");
                    continue;
                }

                let remote_location = remote_location.clone().unwrap();

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

                let resolved_address =
                    match resolve_single_address(&resolver, &updated_location).await {
                        Ok(s) => s,
                        Err(e) => {
                            error!(
                                "Failed to resolve initial remote location {}: {}",
                                updated_location, e
                            );
                            continue;
                        }
                    };

                let (override_remote_write_address, override_local_write_location) =
                    if resolved_address.to_string() != remote_location.to_string() {
                        (Some(resolved_address), Some(remote_location.clone()))
                    } else {
                        // since we don't replace addresses, support the case where a future
                        // address is ipv6
                        (None, None)
                    };

                let client_socket = client_proxy.configure_udp_socket(true)?;

                // TODO: should we only have a single send stream?
                let send_stream = connection.open_uni().await?;

                let session = UdpSession::start(
                    assoc_id,
                    send_stream,
                    Arc::new(client_socket),
                    remote_location,
                    resolved_address,
                    override_local_write_location,
                    override_remote_write_address,
                );

                // it's possible that the session is already on the map since we last checked.
                match udp_session_map.get(&assoc_id) {
                    Some(session) => session,
                    None => {
                        // TODO: is there a better way to do this?
                        udp_session_map.insert(assoc_id, session);
                        udp_session_map.get(&assoc_id).unwrap()
                    }
                }
            }
        };

        if frag_total == 0 {
            error!("Ignoring packet with empty fragment total");
            continue;
        } else if frag_total == 1 {
            if remote_location.is_none() {
                warn!("Ignoring packet with single fragment and no address");
                continue;
            }
            let remote_location = remote_location.as_ref().unwrap();

            let (socket_addr, is_updated) = match session
                .resolve_address(&remote_location, &client_proxy_selector, &resolver)
                .await
            {
                Ok(res) => res,
                Err(e) => {
                    error!(
                        "Failed to resolve remote location {}: {}",
                        remote_location, e
                    );
                    continue;
                }
            };

            if let Err(e) = session
                .send_socket
                .send_to(&payload_fragment, socket_addr)
                .await
            {
                error!(
                    "Failed to forward UDP payload for session {}: {}",
                    assoc_id, e
                );
            }

            if is_updated {
                drop(session);
                let mut session = udp_session_map.get_mut(&assoc_id).unwrap();
                session.last_location = remote_location.clone();
                session.last_socket_addr = socket_addr;
            }
        } else {
            drop(session);

            let mut session = udp_session_map.get_mut(&assoc_id).unwrap();

            let (mut entry, is_new) = match session.fragments.entry(packet_id) {
                Entry::Occupied(entry) => (entry, false),
                Entry::Vacant(v) => (
                    v.insert_entry(FragmentedPacket {
                        fragment_count: frag_total,
                        fragment_received: 0,
                        packet_len: 0,
                        received: vec![None; frag_total as usize],
                        remote_location: remote_location.clone(),
                    }),
                    true,
                ),
            };

            let packet = entry.get_mut();

            if is_new && frag_id == 0 && packet.remote_location.is_none() {
                if remote_location.is_none() {
                    entry.remove();
                    error!(
                        "Ignoring packet with empty first fragment address for session {}",
                        assoc_id
                    );
                    continue;
                }
                packet.remote_location = remote_location.clone();
            }

            if packet.fragment_count != frag_total {
                entry.remove();
                error!(
                    "Mismatched fragment count for session {} packet {}",
                    assoc_id, packet_id
                );
                continue;
            }
            if packet.received[frag_id as usize].is_some() {
                entry.remove();
                error!(
                    "Duplicate fragment for session {} packet {}",
                    assoc_id, packet_id
                );
                continue;
            }

            packet.fragment_received += 1;
            packet.packet_len += payload_fragment.len();
            packet.received[frag_id as usize] = Some(payload_fragment.to_vec().into());

            if packet.fragment_received != packet.fragment_count {
                continue;
            }

            let FragmentedPacket {
                remote_location,
                received,
                packet_len,
                ..
            } = entry.remove();

            let remote_location = remote_location.unwrap();

            let (socket_addr, is_updated) = match session
                .resolve_address(&remote_location, &client_proxy_selector, &resolver)
                .await
            {
                Ok(res) => res,
                Err(e) => {
                    error!(
                        "Failed to resolve remote location {}: {}",
                        remote_location, e
                    );
                    continue;
                }
            };

            if is_updated {
                session.last_location = remote_location.clone();
                session.last_socket_addr = socket_addr;
            }

            let mut complete_payload = Vec::with_capacity(packet_len);
            for frag in received.iter() {
                complete_payload.extend_from_slice(frag.as_ref().unwrap());
            }

            if let Err(e) = session
                .send_socket
                .send_to(&payload_fragment, socket_addr)
                .await
            {
                error!(
                    "Failed to forward UDP payload for session {}: {}",
                    assoc_id, e
                );
            }
        }
    }
}

async fn run_datagram_loop(
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    resolver: Arc<dyn Resolver>,
    udp_session_map: UdpSessionMap,
) -> std::io::Result<()> {
    // TODO
    std::future::pending::<()>().await;
    Ok(())
}

pub async fn run_tuic_server(
    bind_address: SocketAddr,
    server_config: Arc<rustls::ServerConfig>,
    uuid: String,
    password: String,
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    num_endpoints: usize,
) -> std::io::Result<()> {
    let uuid: &'static [u8] = Box::leak(parse_uuid(&uuid)?.into_boxed_slice());
    let password: &'static str = Box::leak(password.into_boxed_str());

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
                .max_concurrent_uni_streams(4096_u32.into())
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
                    if let Err(e) =
                        process_connection(cloned_selector, cloned_resolver, uuid, password, conn)
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
