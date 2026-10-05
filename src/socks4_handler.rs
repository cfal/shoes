use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use memchr::memchr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::resolver::Resolver;
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};
use crate::util::write_all;

const VER_SOCKS4: u8 = 0x04;

const CMD_CONNECT: u8 = 0x01;
const CMD_BIND: u8 = 0x02;

const VER_REPLY: u8 = 0x00;

const CD_GRANTED: u8 = 0x5A;
const CD_REJECTED: u8 = 0x5B;

const MAX_VAR_SIZE: u8 = 255;

#[derive(Debug)]
pub struct Socks4TcpServerHandler {
    /// Enable DNS functionality (SOCKS4a)
    dns_enabled: bool,
    /// Proxy selector for outbound connections
    proxy_selector: Arc<ClientProxySelector>,
}

impl Socks4TcpServerHandler {
    /// Create a new SOCKS4 server handler.
    ///
    /// # Arguments
    /// * `dns_enabled` - Enable DNS functionality (SOCKS4a)
    /// * `proxy_selector` - Proxy selector for outbound connections
    pub fn new(dns_enabled: bool, proxy_selector: Arc<ClientProxySelector>) -> Self {
        Self {
            dns_enabled,
            proxy_selector,
        }
    }
}

#[async_trait]
impl TcpServerHandler for Socks4TcpServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let stream_reader = StreamReader::new_with_buffer_size(400);
        socks4_server_stream_inner(
            self.dns_enabled,
            &self.proxy_selector,
            server_stream,
            stream_reader,
        )
        .await
    }
}

/// Core SOCKS4 server logic.
/// Can be called from Socks4TcpServerHandler or MixedTcpServerHandler.
///
/// Takes ownership of `server_stream` and returns it in the result.
///
/// # Arguments
/// * `dns_enabled` - Enable DNS functionality (SOCKS4a)
/// * `proxy_selector` - Proxy selector for outbound connections (only cloned if UDP request)
/// * `server_stream` - The client TCP stream
/// * `stream_reader` - Stream reader for parsing
async fn socks4_server_stream_inner(
    dns_enabled: bool,
    proxy_selector: &Arc<ClientProxySelector>,
    mut server_stream: Box<dyn AsyncStream>,
    mut stream_reader: StreamReader,
) -> std::io::Result<TcpServerSetupResult> {
    let socks_version = stream_reader.read_u8(&mut server_stream).await?;
    if socks_version != VER_SOCKS4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Unsupported SOCKS version: {socks_version}"),
        ));
    }

    let command_code = stream_reader.read_u8(&mut server_stream).await?;
    if command_code == CMD_BIND {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Unsupported command: BIND",
        ));
    }
    if command_code != CMD_CONNECT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid command code: {}", command_code),
        ));
    }

    static SUCCESS_RESPONSE: OnceLock<Box<[u8]>> = OnceLock::new();

    let connection_success_response = SUCCESS_RESPONSE.get_or_init(|| {
        let mut response_bytes = vec![VER_REPLY, CD_GRANTED];
        let mut location_vec = write_location_to_vec(&NetLocation::UNSPECIFIED);
        response_bytes.append(&mut location_vec);
        response_bytes.into_boxed_slice()
    });

    let address_bytes = stream_reader.read_slice(&mut server_stream, 6).await?;

    let port = u16::from_be_bytes(address_bytes[0..2].try_into().unwrap());
    let v4addr = Ipv4Addr::new(
        address_bytes[2],
        address_bytes[3],
        address_bytes[4],
        address_bytes[5],
    );

    let _ = read_var_bytes(&mut stream_reader, &mut server_stream).await?;

    let octets = &v4addr.octets(); // unstable: v4addr.as_octets()
    let address = if octets[0] == 0 && octets[1] == 0 && octets[2] == 0 && octets[3] != 0 {
        if !dns_enabled {
            static ERROR_RESPONSE: OnceLock<Box<[u8]>> = OnceLock::new();

            let response = ERROR_RESPONSE.get_or_init(|| {
                let mut response_bytes = vec![VER_REPLY, CD_REJECTED];
                let mut location_vec = write_location_to_vec(&NetLocation::UNSPECIFIED);
                response_bytes.append(&mut location_vec);
                response_bytes.into_boxed_slice()
            });

            write_all(&mut server_stream, &response).await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "DNS not enabled",
            ));
        }

        let domain = read_var(&mut stream_reader, &mut server_stream).await?;
        Address::from(domain)?
    } else {
        Address::Ipv4(v4addr)
    };
    let location = NetLocation::new(address, port);

    Ok(TcpServerSetupResult::TcpForward {
        remote_location: location,
        stream: server_stream,
        need_initial_flush: true,
        connection_success_response: Some(connection_success_response.to_vec().into_boxed_slice()),
        initial_remote_data: stream_reader.unparsed_data_owned(),
        proxy_selector: proxy_selector.clone(),
    })
}

#[derive(Debug)]
pub struct Socks4TcpClientHandler {
    resolver: Option<Arc<dyn Resolver>>,
}

impl Socks4TcpClientHandler {
    pub fn new(resolver: Option<Arc<dyn Resolver>>) -> Self {
        Self { resolver }
    }
}

#[async_trait]
impl TcpClientHandler for Socks4TcpClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let mut request_bytes = vec![VER_SOCKS4, CMD_CONNECT];

        let mut maybe_domain = None;
        let v4addr = match resolved_ipv4(&remote_location) {
            // Short circuit if already resolved to IPv4.
            Some(ip) => ip,
            None => match self.resolver {
                Some(ref resolver) => {
                    match resolve_ipv4(resolver, remote_location.location()).await? {
                        Some(ip) => ip,
                        None => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "Invalid address type: IPv6",
                            ));
                        }
                    }
                }
                None => {
                    // Not pre resolved to IPv4 and no resolver available, must be SOCKS4a request.
                    maybe_domain = Some(remote_location.location().address().to_string());
                    Ipv4Addr::new(0, 0, 0, 1)
                }
            },
        };
        let location = NetLocation::new(Address::Ipv4(v4addr), remote_location.port());
        let mut location_vec = write_location_to_vec(&location);

        request_bytes.append(&mut location_vec);
        request_bytes.push(b'\0');

        if let Some(domain) = maybe_domain {
            // SOCKS4a domain name, must be NULL-terminated.
            request_bytes.extend_from_slice(domain.as_bytes());
            request_bytes.push(b'\0');
        }

        write_all(&mut client_stream, &request_bytes).await?;
        client_stream.flush().await?;

        let mut stream_reader = StreamReader::new_with_buffer_size(8);

        let reply_version = stream_reader.read_u8(&mut client_stream).await?;
        if reply_version != VER_REPLY {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid reply version: {reply_version}"),
            ));
        }

        let connect_response = stream_reader.read_u8(&mut client_stream).await?;
        if connect_response != CD_GRANTED {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("SOCKS4 server connect command failed: error {connect_response}"),
            ));
        }

        let _ = stream_reader.read_slice(&mut client_stream, 6).await?;

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

fn resolved_ipv4(resolved_location: &ResolvedLocation) -> Option<Ipv4Addr> {
    if let Some(resolved_addr) = resolved_location.resolved_addr() {
        if let IpAddr::V4(ip) = resolved_addr.ip() {
            return Some(ip);
        }
    }

    if let Address::Ipv4(ip) = resolved_location.location().address() {
        return Some(*ip);
    }

    None
}

async fn resolve_ipv4(
    resolver: &Arc<dyn Resolver>,
    location: &NetLocation,
) -> std::io::Result<Option<Ipv4Addr>> {
    let socket_addrs = resolver.resolve_location(location).await?;

    for socket_addr in socket_addrs {
        if let IpAddr::V4(ip) = socket_addr.ip() {
            return Ok(Some(ip));
        }
    }

    Ok(None)
}

async fn read_var_bytes<'a, T: AsyncReadExt + Unpin>(
    reader: &'a mut StreamReader,
    stream: &mut T,
) -> std::io::Result<&'a [u8]> {
    loop {
        let buf = reader.unparsed_data();

        if let Some(pos) = memchr(b'\0', buf) {
            let bytes = reader.read_slice(stream, pos + 1).await?;
            // Strips NULL.
            return Ok(&bytes[..pos]);
        }

        if buf.len() > MAX_VAR_SIZE as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Variable length field exceeds allowed size",
            ));
        }

        let peek_len = buf.len().saturating_add(1);
        let _ = reader.peek_slice(stream, peek_len).await?;
    }
}

async fn read_var<'a, T: AsyncReadExt + Unpin>(
    reader: &'a mut StreamReader,
    stream: &mut T,
) -> std::io::Result<&'a str> {
    let bytes = read_var_bytes(reader, stream).await?;
    std::str::from_utf8(bytes).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to decode utf8: {e}"),
        )
    })
}

fn write_location_to_vec(location: &NetLocation) -> Vec<u8> {
    let (address, port) = location.components();
    let mut vec = Vec::with_capacity(6);

    vec.push((port >> 8) as u8);
    vec.push((port & 0xff) as u8);

    match address {
        Address::Ipv4(v4addr) => vec.extend_from_slice(&v4addr.octets()),
        _ => unreachable!(),
    };
    vec
}
