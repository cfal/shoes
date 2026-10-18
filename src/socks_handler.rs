use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::OnceLock;

use async_trait::async_trait;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::resolver::Resolver;
use crate::routing::{ServerStream, run_udp_routing};
use crate::socks5_udp_relay::Socks5UdpRelayStream;
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};
use crate::uot::{UOT_V1_MAGIC_ADDRESS, UOT_V2_MAGIC_ADDRESS, UotV1ServerStream, UotV2Stream};
use crate::util::write_all;

pub const VER_SOCKS5: u8 = 0x05;
pub const VER_AUTH: u8 = 0x01;

pub const METHOD_NONE: u8 = 0x00;
pub const METHOD_USERNAME: u8 = 0x02;
pub const METHOD_INVALID: u8 = 0xff;

pub const ADDR_TYPE_IPV4: u8 = 0x01;
pub const ADDR_TYPE_DOMAIN_NAME: u8 = 0x03;
pub const ADDR_TYPE_IPV6: u8 = 0x04;

pub const RESULT_SUCCESS: u8 = 0x0;

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

// SOCKS5 reply codes
pub const REPLY_SUCCESS: u8 = 0x00;
pub const REPLY_GENERAL_FAILURE: u8 = 0x01;
pub const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;

#[derive(Debug)]
pub struct SocksTcpServerHandler {
    auth_info: Option<(String, String)>,
    /// Enable UDP functionality (UDP ASSOCIATE and UDP-over-TCP)
    udp_enabled: bool,
    /// IP address to bind UDP sockets on (same as TCP server)
    bind_ip: IpAddr,
    /// Proxy selector for outbound connections
    proxy_selector: Arc<ClientProxySelector>,
    /// DNS resolver
    resolver: Arc<dyn Resolver>,
}

impl SocksTcpServerHandler {
    /// Create a new SOCKS5 server handler.
    ///
    /// # Arguments
    /// * `auth_info` - Optional username/password for authentication
    /// * `udp_enabled` - Enable UDP functionality (UDP ASSOCIATE and UDP-over-TCP)
    /// * `bind_ip` - IP address to bind UDP sockets on (should match TCP server)
    /// * `proxy_selector` - Proxy selector for outbound connections
    /// * `resolver` - DNS resolver
    pub fn new(
        auth_info: Option<(String, String)>,
        udp_enabled: bool,
        bind_ip: IpAddr,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        Self {
            auth_info,
            udp_enabled,
            bind_ip,
            proxy_selector,
            resolver,
        }
    }
}

#[async_trait]
impl TcpServerHandler for SocksTcpServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let stream_reader = StreamReader::new_with_buffer_size(400);
        let udp_bind_ip = if self.udp_enabled {
            Some(self.bind_ip)
        } else {
            None
        };
        setup_socks_server_stream_inner(
            self.auth_info.as_ref(),
            udp_bind_ip,
            &self.proxy_selector,
            &self.resolver,
            server_stream,
            stream_reader,
        )
        .await
    }
}

/// Core SOCKS5 server setup logic.
/// Can be called from SocksTcpServerHandler or MixedTcpServerHandler.
///
/// Takes ownership of `server_stream` and returns it in the result.
///
/// # Arguments
/// * `auth_info` - Optional username/password for authentication
/// * `udp_bind_ip` - If Some, UDP is enabled and this is the IP to bind UDP sockets on
/// * `proxy_selector` - Proxy selector for outbound connections (only cloned if UDP request)
/// * `resolver` - DNS resolver (only cloned if UDP request)
/// * `server_stream` - The client TCP stream
/// * `stream_reader` - Stream reader for parsing
pub async fn setup_socks_server_stream_inner(
    auth_info: Option<&(String, String)>,
    udp_bind_ip: Option<IpAddr>,
    proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    mut server_stream: Box<dyn AsyncStream>,
    mut stream_reader: StreamReader,
) -> std::io::Result<TcpServerSetupResult> {
    let socks_version = stream_reader.read_u8(&mut server_stream).await?;
    if socks_version != VER_SOCKS5 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Unsupported SOCKS version: {socks_version}"),
        ));
    }

    let method_len = stream_reader.read_u8(&mut server_stream).await? as usize;
    if method_len < 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid method length: {method_len}"),
        ));
    }

    let methods = stream_reader
        .read_slice(&mut server_stream, method_len)
        .await?;

    let supported_method = if auth_info.is_some() {
        METHOD_USERNAME
    } else {
        METHOD_NONE
    };

    if !methods.contains(&supported_method) {
        // TODO: consider writing response: [VER_SOCKS5, METHOD_INVALID]
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Supported SOCKS method not found",
        ));
    }

    write_all(&mut server_stream, &[VER_SOCKS5, supported_method]).await?;
    // Clients may wait for each reply before sending more, so replies cannot wait for
    // the final flush.
    server_stream.flush().await?;

    if let Some((target_username, target_password)) = auth_info {
        let auth_version = stream_reader.read_u8(&mut server_stream).await?;
        if auth_version != VER_AUTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unsupported SOCKS auth version",
            ));
        }

        let username_len = stream_reader.read_u8(&mut server_stream).await? as usize;
        if username_len == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unsupported SOCKS username length",
            ));
        }

        let username = stream_reader
            .read_slice(&mut server_stream, username_len)
            .await?;
        // Copy to owned buffer to release the borrow on stream_reader
        let username_bytes = username.to_vec();

        let password_len = stream_reader.read_u8(&mut server_stream).await? as usize;
        if password_len == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unsupported SOCKS password length",
            ));
        }

        let password = stream_reader
            .read_slice(&mut server_stream, password_len)
            .await?;

        // Use constant-time comparison to prevent timing attacks.
        // Both username and password are compared together to avoid leaking
        // which one is incorrect.
        let username_match = target_username.as_bytes().ct_eq(&username_bytes);
        let password_match = target_password.as_bytes().ct_eq(password);

        if username_match.unwrap_u8() == 0 || password_match.unwrap_u8() == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "SOCKS authentication failed",
            ));
        }

        write_all(&mut server_stream, &[VER_AUTH, RESULT_SUCCESS]).await?;
        server_stream.flush().await?;
    }

    let connection_request = stream_reader.read_slice(&mut server_stream, 3).await?;
    if connection_request[0] != VER_SOCKS5 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid SOCKS version: {}", connection_request[0]),
        ));
    }

    if connection_request[1] == CMD_UDP_ASSOCIATE {
        let bind_ip = match udp_bind_ip {
            Some(ip) => ip,
            None => {
                let response = build_error_response(REPLY_COMMAND_NOT_SUPPORTED);
                write_all(&mut server_stream, &response).await?;
                server_stream.flush().await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "UDP ASSOCIATE not enabled",
                ));
            }
        };
        return handle_udp_associate(
            bind_ip,
            proxy_selector,
            resolver,
            server_stream,
            &mut stream_reader,
        )
        .await;
    }

    if connection_request[1] != CMD_CONNECT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid command code: {}", connection_request[1]),
        ));
    }

    if connection_request[2] != 0x0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid reserved bit",
        ));
    }

    static SUCCESS_RESPONSE: OnceLock<Box<[u8]>> = OnceLock::new();

    let connection_success_response = SUCCESS_RESPONSE.get_or_init(|| {
        let mut response_bytes = vec![VER_SOCKS5, RESULT_SUCCESS, 0];
        let mut location_vec = write_location_to_vec(&NetLocation::new(
            Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
            65535,
        ));
        response_bytes.append(&mut location_vec);
        response_bytes.into_boxed_slice()
    });

    let location = read_location(&mut server_stream, &mut stream_reader).await?;

    // Checks for UDP-over-TCP (UoT) magic addresses.
    if let Address::Hostname(host) = location.address() {
        if host == UOT_V1_MAGIC_ADDRESS {
            if udp_bind_ip.is_none() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "UDP-over-TCP not enabled",
                ));
            }

            // UoT V1: Multi-destination UDP (ATYP + address + port + length + data per packet).
            write_all(&mut server_stream, connection_success_response).await?;
            server_stream.flush().await?;

            let mut uot_stream = UotV1ServerStream::new_uot(server_stream);

            // Feeds unparsed data since first UoT packet might be in same TCP segment.
            let unparsed_data = stream_reader.unparsed_data();
            if !unparsed_data.is_empty() {
                log::debug!(
                    "SOCKS UoT V1: feeding {} bytes of initial data",
                    unparsed_data.len()
                );
                uot_stream.feed_initial_data(unparsed_data);
            }

            return Ok(TcpServerSetupResult::MultiDirectionalUdp {
                stream: Box::new(uot_stream),
                need_initial_flush: false,
                proxy_selector: proxy_selector.clone(),
            });
        } else if host == UOT_V2_MAGIC_ADDRESS {
            if udp_bind_ip.is_none() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "UDP-over-TCP not enabled",
                ));
            }

            // UoT V2: Request format is isConnect(u8) + ATYP + address + port.
            write_all(&mut server_stream, connection_success_response).await?;
            server_stream.flush().await?;

            let is_connect = stream_reader.read_u8(&mut server_stream).await?;
            log::debug!("SOCKS UoT V2: is_connect = {}", is_connect);

            let destination = read_location(&mut server_stream, &mut stream_reader).await?;
            log::debug!("SOCKS UoT V2: destination = {:?}", destination);

            if is_connect == 1 {
                // V2 Connect mode: Single destination, length-prefixed packets only
                let unparsed_data = stream_reader.unparsed_data();
                let mut uot_v2_stream = UotV2Stream::new(server_stream);
                if !unparsed_data.is_empty() {
                    uot_v2_stream.feed_initial_read_data(unparsed_data)?;
                }

                return Ok(TcpServerSetupResult::BidirectionalUdp {
                    remote_location: destination,
                    stream: Box::new(uot_v2_stream),
                    need_initial_flush: false,
                    proxy_selector: proxy_selector.clone(),
                });
            } else {
                // V2 Non-connect mode: Same as V1 (multi-destination)
                let mut uot_stream = UotV1ServerStream::new_uot(server_stream);

                let unparsed_data = stream_reader.unparsed_data();
                if !unparsed_data.is_empty() {
                    log::debug!(
                        "SOCKS UoT V2 non-connect: feeding {} bytes of initial data",
                        unparsed_data.len()
                    );
                    uot_stream.feed_initial_data(unparsed_data);
                }

                return Ok(TcpServerSetupResult::MultiDirectionalUdp {
                    stream: Box::new(uot_stream),
                    need_initial_flush: false,
                    proxy_selector: proxy_selector.clone(),
                });
            }
        }
    }

    Ok(TcpServerSetupResult::TcpForward {
        remote_location: location,
        stream: server_stream,
        need_initial_flush: true,
        connection_success_response: Some(connection_success_response.to_vec().into_boxed_slice()),
        initial_remote_data: stream_reader.unparsed_data_owned(),
        proxy_selector: proxy_selector.clone(),
    })
}

/// Handle SOCKS5 UDP ASSOCIATE command.
///
/// Takes ownership of `server_stream` for use in the spawned UDP relay task.
async fn handle_udp_associate(
    bind_ip: IpAddr,
    proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    mut server_stream: Box<dyn AsyncStream>,
    stream_reader: &mut StreamReader,
) -> std::io::Result<TcpServerSetupResult> {
    // NAT and some clients make this hint differ from the actual UDP source.
    let _client_hint = read_location(&mut server_stream, stream_reader).await?;

    // Uses 2MB buffer to prevent packet drops during bursts.
    const UDP_BUFFER_SIZE: usize = 2 * 1024 * 1024;
    let udp_bind_addr = SocketAddr::new(bind_ip, 0);
    let udp_socket: std::net::UdpSocket =
        match crate::socket_util::new_socket2_udp_socket_with_buffer_size(
            bind_ip.is_ipv6(),
            None,
            Some(udp_bind_addr),
            false,
            Some(UDP_BUFFER_SIZE),
        ) {
            Ok(s) => s.into(),
            Err(e) => {
                log::error!("Failed to bind UDP socket: {}", e);
                let response = build_error_response(REPLY_GENERAL_FAILURE);
                write_all(&mut server_stream, &response).await?;
                server_stream.flush().await?;
                return Err(e);
            }
        };
    let udp_socket = tokio::net::UdpSocket::from_std(udp_socket)?;

    let bound_addr = udp_socket.local_addr()?;
    log::info!("SOCKS5 UDP ASSOCIATE: bound UDP relay at {}", bound_addr);

    let response = build_udp_associate_response(bound_addr);
    write_all(&mut server_stream, &response).await?;
    server_stream.flush().await?;

    let relay_stream = Socks5UdpRelayStream::new(udp_socket);
    let proxy_selector = proxy_selector.clone();
    let resolver = resolver.clone();

    Ok(TcpServerSetupResult::Session(Box::pin(async move {
        if let Err(e) =
            run_udp_associate(server_stream, relay_stream, proxy_selector, resolver).await
        {
            log::debug!("SOCKS5 UDP ASSOCIATE ended: {}", e);
        }
    })))
}

/// Build a SOCKS5 error response.
fn build_error_response(reply_code: u8) -> Vec<u8> {
    vec![
        VER_SOCKS5,
        reply_code,
        0x00, // RSV
        ADDR_TYPE_IPV4,
        0,
        0,
        0,
        0, // 0.0.0.0
        0,
        0, // port 0
    ]
}

/// Build a SOCKS5 UDP ASSOCIATE success response.
fn build_udp_associate_response(bound_addr: SocketAddr) -> Vec<u8> {
    let mut response = vec![VER_SOCKS5, REPLY_SUCCESS, 0x00];

    match bound_addr {
        SocketAddr::V4(v4) => {
            response.push(ADDR_TYPE_IPV4);
            response.extend_from_slice(&v4.ip().octets());
            response.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            response.push(ADDR_TYPE_IPV6);
            response.extend_from_slice(&v6.ip().octets());
            response.extend_from_slice(&v6.port().to_be_bytes());
        }
    }

    response
}

/// Run the UDP ASSOCIATE relay.
///
/// This function:
/// 1. Uses per-destination routing for UDP packets
/// 2. Monitors the TCP connection for termination
///
/// When the TCP connection closes, the UDP relay is terminated.
async fn run_udp_associate(
    mut tcp_stream: Box<dyn AsyncStream>,
    relay_stream: Socks5UdpRelayStream,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()> {
    let server_stream: Box<dyn crate::async_stream::AsyncTargetedMessageStream> =
        Box::new(relay_stream);

    // Runs per-destination routing in parallel with TCP monitoring.
    tokio::select! {
        result = run_udp_routing(ServerStream::Targeted(server_stream), proxy_selector, resolver, false) => {
            result
        }
        _ = monitor_tcp_close(&mut tcp_stream) => {
            log::debug!("SOCKS5 UDP ASSOCIATE: TCP connection closed, terminating relay");
            Ok(())
        }
    }
}

/// Monitor the TCP connection for closure.
///
/// Per RFC 1928, the UDP association terminates when the TCP connection closes.
/// We read and discard any data until EOF or error.
async fn monitor_tcp_close(stream: &mut Box<dyn AsyncStream>) -> std::io::Result<()> {
    let mut buf = [0u8; 1024];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => return Ok(()),  // EOF
            Ok(_) => continue,       // Discard data
            Err(_) => return Ok(()), // Error = close
        }
    }
}

#[derive(Debug)]
pub struct SocksTcpClientHandler {
    method: u8,
    auth_request: Option<Vec<u8>>,
}

impl SocksTcpClientHandler {
    pub fn new(auth_info: Option<(String, String)>) -> Self {
        let auth_request = auth_info.map(|(username, password)| {
            let mut request = vec![VER_AUTH, username.len() as u8];
            request.extend_from_slice(username.as_bytes());
            request.push(password.len() as u8);
            request.extend_from_slice(password.as_bytes());
            request
        });

        Self {
            method: if auth_request.is_some() {
                METHOD_USERNAME
            } else {
                METHOD_NONE
            },
            auth_request,
        }
    }
}

#[async_trait]
impl TcpClientHandler for SocksTcpClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        // Each request waits for the previous reply. RFC 1928 only sends the request once
        // method negotiation completes, and some servers (eg. Cloudflare WARP) drop bytes
        // that arrive early.
        write_all(&mut client_stream, &[VER_SOCKS5, 1, self.method]).await?;
        client_stream.flush().await?;

        let mut stream_reader = StreamReader::new_with_buffer_size(400);

        let socks_version = stream_reader.read_u8(&mut client_stream).await?;
        if socks_version != VER_SOCKS5 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Unsupported SOCKS version: {socks_version}"),
            ));
        }

        let auth_method = stream_reader.read_u8(&mut client_stream).await?;
        if auth_method == METHOD_INVALID {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "SOCKS server rejected auth method",
            ));
        }
        if auth_method != self.method {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("SOCKS server selected auth method {auth_method}, which was not offered"),
            ));
        }

        if let Some(auth_request) = &self.auth_request {
            write_all(&mut client_stream, auth_request).await?;
            client_stream.flush().await?;

            let auth_version = stream_reader.read_u8(&mut client_stream).await?;
            if auth_version != VER_AUTH {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Unsupported SOCKS auth version",
                ));
            }

            let auth_result = stream_reader.read_u8(&mut client_stream).await?;
            if auth_result != RESULT_SUCCESS {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("SOCKS server authentication failed: error {auth_result}"),
                ));
            }
        }

        let mut connect_request = vec![
            VER_SOCKS5,
            CMD_CONNECT,
            0x0, // reserved
        ];
        connect_request.extend(write_location_to_vec(remote_location.location()));
        write_all(&mut client_stream, &connect_request).await?;
        client_stream.flush().await?;

        let socks_version = stream_reader.read_u8(&mut client_stream).await?;
        if socks_version != VER_SOCKS5 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Unsupported SOCKS version: {socks_version}"),
            ));
        }

        let connect_response = stream_reader.read_u8(&mut client_stream).await?;
        if connect_response != RESULT_SUCCESS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("SOCKS server connect command failed: error {connect_response}"),
            ));
        }

        let reserved = stream_reader.read_u8(&mut client_stream).await?;
        if reserved != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "SOCKS server responded with invalid reserved bit",
            ));
        }

        // Read the final location part of the connect response.
        read_location(&mut client_stream, &mut stream_reader).await?;

        let early_data = stream_reader.unparsed_data();
        let early_data = if early_data.is_empty() {
            None
        } else {
            Some(early_data.to_vec())
        };

        Ok(TcpClientSetupResult {
            client_stream,
            early_data,
        })
    }
}

pub async fn read_location<T: AsyncReadExt + Unpin>(
    stream: &mut T,
    stream_reader: &mut StreamReader,
) -> std::io::Result<NetLocation> {
    let address_type = stream_reader.read_u8(stream).await?;
    match address_type {
        ADDR_TYPE_IPV4 => {
            let address_bytes = stream_reader.read_slice(stream, 6).await?;

            let v4addr = Ipv4Addr::new(
                address_bytes[0],
                address_bytes[1],
                address_bytes[2],
                address_bytes[3],
            );

            let port = u16::from_be_bytes(address_bytes[4..6].try_into().unwrap());

            Ok(NetLocation::new(Address::Ipv4(v4addr), port))
        }
        ADDR_TYPE_IPV6 => {
            let address_bytes = stream_reader.read_slice(stream, 18).await?;

            let v6addr = std::net::Ipv6Addr::new(
                u16::from_be_bytes(address_bytes[0..2].try_into().unwrap()),
                u16::from_be_bytes(address_bytes[2..4].try_into().unwrap()),
                u16::from_be_bytes(address_bytes[4..6].try_into().unwrap()),
                u16::from_be_bytes(address_bytes[6..8].try_into().unwrap()),
                u16::from_be_bytes(address_bytes[8..10].try_into().unwrap()),
                u16::from_be_bytes(address_bytes[10..12].try_into().unwrap()),
                u16::from_be_bytes(address_bytes[12..14].try_into().unwrap()),
                u16::from_be_bytes(address_bytes[14..16].try_into().unwrap()),
            );

            let port = u16::from_be_bytes(address_bytes[16..18].try_into().unwrap());

            Ok(NetLocation::new(Address::Ipv6(v6addr), port))
        }
        ADDR_TYPE_DOMAIN_NAME => {
            let address_len = stream_reader.read_u8(stream).await? as usize;

            let address_bytes = stream_reader.read_slice(stream, address_len + 2).await?;

            let address_str = match std::str::from_utf8(&address_bytes[0..address_len]) {
                Ok(s) => s,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Failed to decode address: {e}"),
                    ));
                }
            };

            let port = u16::from_be_bytes(
                address_bytes[address_len..address_len + 2]
                    .try_into()
                    .unwrap(),
            );

            // Parses as Address since some clients pass IP addresses as hostnames.
            Ok(NetLocation::new(Address::from(address_str)?, port))
        }

        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Unknown address type: {address_type}"),
        )),
    }
}

/// Read a SOCKS5-format address directly from an AsyncRead stream.
///
/// This is a simpler version of `read_location` that doesn't use `StreamReader`.
/// Use this when the protocol has its own framing (e.g., H2 streams, AnyTLS frames).
///
/// SOCKS5 address format (also used in UoT V2 Request header):
/// - 0x01: IPv4 (4 bytes) + port (2 bytes)
/// - 0x03: Domain (1 byte len + domain) + port (2 bytes)
/// - 0x04: IPv6 (16 bytes) + port (2 bytes)
pub async fn read_location_direct<T: AsyncReadExt + Unpin>(
    stream: &mut T,
) -> std::io::Result<NetLocation> {
    let mut addr_type = [0u8; 1];
    stream.read_exact(&mut addr_type).await?;

    match addr_type[0] {
        ADDR_TYPE_IPV4 => {
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await?;
            let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok(NetLocation::new(Address::Ipv4(addr), port))
        }
        ADDR_TYPE_IPV6 => {
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await?;
            let addr = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&buf[0..16]).unwrap());
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Ok(NetLocation::new(Address::Ipv6(addr), port))
        }
        ADDR_TYPE_DOMAIN_NAME => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let domain_len = len[0] as usize;

            let mut buf = vec![0u8; domain_len + 2];
            stream.read_exact(&mut buf).await?;

            let domain = std::str::from_utf8(&buf[..domain_len]).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid domain encoding: {e}"),
                )
            })?;
            let port = u16::from_be_bytes([buf[domain_len], buf[domain_len + 1]]);

            // Parse as Address to handle IP literals passed as domain
            Ok(NetLocation::new(Address::from(domain)?, port))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Unknown address type: {}", addr_type[0]),
        )),
    }
}

pub fn write_location_to_vec(location: &NetLocation) -> Vec<u8> {
    let (address, port) = location.components();
    let mut vec = match address {
        Address::Ipv4(v4addr) => {
            let mut vec = Vec::with_capacity(7);
            vec.push(ADDR_TYPE_IPV4);
            vec.extend_from_slice(&v4addr.octets());
            vec
        }
        Address::Ipv6(v6addr) => {
            let mut vec = Vec::with_capacity(19);
            vec.push(ADDR_TYPE_IPV6);
            vec.extend_from_slice(&v6addr.octets());
            vec
        }
        Address::Hostname(domain_name) => {
            let domain_name_bytes = domain_name.as_bytes();
            let mut vec = Vec::with_capacity(4 + domain_name_bytes.len());
            vec.push(ADDR_TYPE_DOMAIN_NAME);
            vec.push(domain_name_bytes.len() as u8);
            vec.extend_from_slice(domain_name_bytes);
            vec
        }
    };

    vec.push((port >> 8) as u8);
    vec.push((port & 0xff) as u8);
    vec
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_stream::test_streams::FlushGatedStream;
    use crate::resolver::NativeResolver;
    use std::io;
    use std::time::Duration;
    use tokio::io::DuplexStream;

    /// RFC 1929 request carrying `credentials()`.
    const AUTH_REQUEST: &[u8] = b"\x01\x04user\x04pass";
    /// CONNECT request for `destination()`.
    const CONNECT_REQUEST: &[u8] = b"\x05\x01\x00\x03\x0bexample.com\x01\xbb";
    /// CONNECT success reply with bound address 127.0.0.1:0.
    const CONNECT_REPLY: &[u8] = b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00";

    fn credentials() -> Option<(String, String)> {
        Some(("user".to_string(), "pass".to_string()))
    }

    fn destination() -> NetLocation {
        NetLocation::from_str("example.com:443", None).unwrap()
    }

    fn server_handler(auth_info: Option<(String, String)>) -> SocksTcpServerHandler {
        SocksTcpServerHandler::new(
            auth_info,
            false,
            "0.0.0.0".parse().unwrap(),
            Arc::new(ClientProxySelector::new(vec![])),
            Arc::new(NativeResolver::new()),
        )
    }

    /// Fails the test instead of hanging when a handshake step stalls.
    async fn bounded<F: std::future::Future>(future: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(1), future)
            .await
            .expect("handshake step stalled")
    }

    async fn read_bytes(stream: &mut DuplexStream, len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        bounded(stream.read_exact(&mut bytes)).await.unwrap();
        bytes
    }

    #[tokio::test]
    async fn server_flushes_each_negotiation_reply() {
        for auth_info in [None, credentials()] {
            let with_auth = auth_info.is_some();
            let (mut client, server_stream) = tokio::io::duplex(1024);
            let setup = tokio::spawn(async move {
                server_handler(auth_info)
                    .setup_server_stream(Box::new(FlushGatedStream::new(server_stream)))
                    .await
            });

            let method = if with_auth {
                METHOD_USERNAME
            } else {
                METHOD_NONE
            };
            client.write_all(&[VER_SOCKS5, 1, method]).await.unwrap();
            assert_eq!(read_bytes(&mut client, 2).await, [VER_SOCKS5, method]);
            if with_auth {
                client.write_all(AUTH_REQUEST).await.unwrap();
                assert_eq!(read_bytes(&mut client, 2).await, [VER_AUTH, RESULT_SUCCESS]);
            }
            client.write_all(CONNECT_REQUEST).await.unwrap();

            let TcpServerSetupResult::TcpForward {
                remote_location, ..
            } = bounded(setup).await.unwrap().unwrap()
            else {
                panic!("expected TCP forwarding");
            };
            assert_eq!(remote_location, destination());
        }
    }

    #[tokio::test]
    async fn server_flushes_command_not_supported_reply() {
        let (mut client, server_stream) = tokio::io::duplex(1024);
        let setup = tokio::spawn(async move {
            server_handler(None)
                .setup_server_stream(Box::new(FlushGatedStream::new(server_stream)))
                .await
        });

        client
            .write_all(&[VER_SOCKS5, 1, METHOD_NONE])
            .await
            .unwrap();
        read_bytes(&mut client, 2).await;
        client
            .write_all(&[VER_SOCKS5, CMD_UDP_ASSOCIATE, 0])
            .await
            .unwrap();
        assert_eq!(
            read_bytes(&mut client, 10).await,
            build_error_response(REPLY_COMMAND_NOT_SUPPORTED)
        );
        let error = bounded(setup).await.unwrap().err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[tokio::test]
    async fn server_flushes_udp_bind_failure_reply() {
        // Binding the UDP relay to TEST-NET-1 fails unless the host assigns it or allows
        // non-local binds.
        if std::net::UdpSocket::bind("192.0.2.1:0").is_ok() {
            eprintln!("skipping: 192.0.2.1 is bindable on this host");
            return;
        }

        let (mut client, server_stream) = tokio::io::duplex(1024);
        let setup = tokio::spawn(async move {
            SocksTcpServerHandler::new(
                None,
                true,
                "192.0.2.1".parse().unwrap(),
                Arc::new(ClientProxySelector::new(vec![])),
                Arc::new(NativeResolver::new()),
            )
            .setup_server_stream(Box::new(FlushGatedStream::new(server_stream)))
            .await
        });

        client
            .write_all(&[VER_SOCKS5, 1, METHOD_NONE])
            .await
            .unwrap();
        read_bytes(&mut client, 2).await;
        client
            .write_all(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
            .await
            .unwrap();
        assert_eq!(
            read_bytes(&mut client, 10).await,
            build_error_response(REPLY_GENERAL_FAILURE)
        );
        assert!(bounded(setup).await.unwrap().is_err());
    }

    fn spawn_client(
        auth_info: Option<(String, String)>,
        stream: Box<dyn AsyncStream>,
    ) -> tokio::task::JoinHandle<io::Result<TcpClientSetupResult>> {
        tokio::spawn(async move {
            SocksTcpClientHandler::new(auth_info)
                .setup_client_tcp_stream(stream, destination().into())
                .await
        })
    }

    async fn assert_nothing_sent(stream: &mut DuplexStream) {
        let mut byte = [0; 1];
        let read = tokio::time::timeout(Duration::from_millis(50), stream.read(&mut byte)).await;
        assert!(read.is_err(), "client sent data before the previous reply");
    }

    #[tokio::test]
    async fn client_waits_for_each_negotiation_reply() {
        for auth_info in [None, credentials()] {
            let with_auth = auth_info.is_some();
            let (client_stream, mut server) = tokio::io::duplex(1024);
            let setup = spawn_client(auth_info, Box::new(client_stream));

            let method = if with_auth {
                METHOD_USERNAME
            } else {
                METHOD_NONE
            };
            assert_eq!(read_bytes(&mut server, 3).await, [VER_SOCKS5, 1, method]);
            assert_nothing_sent(&mut server).await;
            server.write_all(&[VER_SOCKS5, method]).await.unwrap();

            if with_auth {
                assert_eq!(
                    read_bytes(&mut server, AUTH_REQUEST.len()).await,
                    AUTH_REQUEST
                );
                assert_nothing_sent(&mut server).await;
                server.write_all(&[VER_AUTH, RESULT_SUCCESS]).await.unwrap();
            }

            assert_eq!(
                read_bytes(&mut server, CONNECT_REQUEST.len()).await,
                CONNECT_REQUEST
            );
            // Bytes after the CONNECT reply belong to the tunnel.
            server
                .write_all(&[CONNECT_REPLY, b"banner"].concat())
                .await
                .unwrap();

            let result = bounded(setup).await.unwrap().unwrap();
            assert_eq!(result.early_data.as_deref(), Some(&b"banner"[..]));
        }
    }

    #[tokio::test]
    async fn client_rejects_unoffered_methods_without_sending_more() {
        for (auth_info, selected_method) in [
            (None, METHOD_INVALID),
            (None, METHOD_USERNAME),
            (credentials(), METHOD_INVALID),
            (credentials(), METHOD_NONE),
        ] {
            let (client_stream, mut server) = tokio::io::duplex(1024);
            let setup = spawn_client(auth_info, Box::new(client_stream));

            read_bytes(&mut server, 3).await;
            server
                .write_all(&[VER_SOCKS5, selected_method])
                .await
                .unwrap();

            let error = bounded(setup).await.unwrap().err().unwrap();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            let mut rest = Vec::new();
            bounded(server.read_to_end(&mut rest)).await.unwrap();
            assert!(rest.is_empty());
        }
    }

    #[tokio::test]
    async fn client_stops_after_rejected_credentials() {
        let (client_stream, mut server) = tokio::io::duplex(1024);
        let setup = spawn_client(credentials(), Box::new(client_stream));

        read_bytes(&mut server, 3).await;
        server
            .write_all(&[VER_SOCKS5, METHOD_USERNAME])
            .await
            .unwrap();
        read_bytes(&mut server, AUTH_REQUEST.len()).await;
        server.write_all(&[VER_AUTH, 0x01]).await.unwrap();

        let error = bounded(setup).await.unwrap().err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let mut rest = Vec::new();
        bounded(server.read_to_end(&mut rest)).await.unwrap();
        assert!(
            rest.is_empty(),
            "client sent CONNECT after failed authentication"
        );
    }

    #[tokio::test]
    async fn client_reads_replies_split_across_writes() {
        let (client_stream, mut server) = tokio::io::duplex(1024);
        let setup = spawn_client(credentials(), Box::new(client_stream));

        for (request_len, reply) in [
            (3, &[VER_SOCKS5, METHOD_USERNAME][..]),
            (AUTH_REQUEST.len(), &[VER_AUTH, RESULT_SUCCESS][..]),
            (CONNECT_REQUEST.len(), CONNECT_REPLY),
        ] {
            read_bytes(&mut server, request_len).await;
            for byte in reply {
                server.write_all(&[*byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        }

        let result = bounded(setup).await.unwrap().unwrap();
        assert!(result.early_data.is_none());
    }

    #[tokio::test]
    async fn client_and_server_handshake_over_flush_gated_transport() {
        for auth_info in [None, credentials()] {
            let (client_stream, server_stream) = tokio::io::duplex(1024);
            let client = spawn_client(
                auth_info.clone(),
                Box::new(FlushGatedStream::new(client_stream)),
            );
            let handler = server_handler(auth_info);
            let server =
                handler.setup_server_stream(Box::new(FlushGatedStream::new(server_stream)));

            let TcpServerSetupResult::TcpForward {
                remote_location,
                stream: mut tunnel,
                connection_success_response: Some(response),
                ..
            } = bounded(server).await.unwrap()
            else {
                panic!("expected TCP forwarding with a deferred CONNECT reply");
            };
            assert_eq!(remote_location, destination());

            // The TCP server sends the CONNECT reply once the upstream connection is set up.
            tunnel.write_all(&response).await.unwrap();
            tunnel.flush().await.unwrap();
            let result = bounded(client).await.unwrap().unwrap();
            assert!(result.early_data.is_none());
        }
    }
}
