use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncStream;
use crate::option_util::NoneOrOne;
use crate::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};
use crate::util::allocate_vec;

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

#[derive(Debug)]
pub struct SocksTcpServerHandler {
    auth_info: Option<(String, String)>,
}

impl SocksTcpServerHandler {
    pub fn new(auth_info: Option<(String, String)>) -> Self {
        Self { auth_info }
    }
}

#[async_trait]
impl TcpServerHandler for SocksTcpServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let mut data = [0u8; 2];
        server_stream.read_exact(&mut data).await?;

        if data[0] != VER_SOCKS5 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Unsupported SOCKS version: {}", data[0]),
            ));
        }

        let method_len = data[1] as usize;
        if method_len < 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid method length: {}", method_len),
            ));
        }

        let mut methods = allocate_vec(method_len);
        server_stream.read_exact(&mut methods).await?;

        let supported_method = if self.auth_info.is_some() {
            METHOD_USERNAME
        } else {
            METHOD_NONE
        };

        if !methods
            .into_iter()
            .any(move |method| method == supported_method)
        {
            // TODO: consider writing response: [VER_SOCKS5, METHOD_INVALID]
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Supported SOCKS method not found",
            ));
        }

        // Write response: [VER_SOCKS5, <selected method>]
        data[1] = supported_method;
        server_stream.write_all(&data).await?;

        if let Some((target_username, target_password)) = self.auth_info.as_ref() {
            server_stream.read_exact(&mut data).await?;
            if data[0] != VER_AUTH {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Unsupported SOCKS auth version",
                ));
            }

            let username_len = data[1] as usize;
            if username_len == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Unsupported SOCKS username length",
                ));
            }

            let mut username = allocate_vec(username_len);
            server_stream.read_exact(&mut username).await?;

            server_stream.read_exact(&mut data[0..1]).await?;

            let password_len = data[0] as usize;
            if password_len == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Unsupported SOCKS password length",
                ));
            }

            let mut password = allocate_vec(password_len);
            server_stream.read_exact(&mut password).await?;

            let username_str = match std::str::from_utf8(&username) {
                Ok(s) => s,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Failed to decode username: {}", e),
                    ));
                }
            };
            let password_str = match std::str::from_utf8(&password) {
                Ok(s) => s,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Failed to decode password: {}", e),
                    ));
                }
            };

            if target_username != username_str || target_password != password_str {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Incorrect username or password provided",
                ));
            }

            data[0] = VER_AUTH;
            data[1] = RESULT_SUCCESS;
            server_stream.write_all(&data).await?;
        }

        let mut connection_request = [0u8; 3];
        server_stream.read_exact(&mut connection_request).await?;
        if connection_request[0] != VER_SOCKS5 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid SOCKS version: {}", connection_request[0]),
            ));
        }

        if connection_request[1] == CMD_UDP_ASSOCIATE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "UDP associate command is not supported",
            ));
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

        let location = read_location(&mut server_stream).await?;

        Ok(TcpServerSetupResult::TcpForward {
            remote_location: location,
            stream: server_stream,
            need_initial_flush: true,
            connection_success_response: Some(
                connection_success_response.to_vec().into_boxed_slice(),
            ),
            initial_remote_data: None,
            override_proxy_provider: NoneOrOne::Unspecified,
        })
    }
}

#[derive(Debug)]
pub struct SocksTcpClientHandler {
    prefix_data: Vec<u8>,
    has_auth: bool,
}

impl SocksTcpClientHandler {
    pub fn new(auth_info: Option<(String, String)>) -> Self {
        let mut data = vec![
            VER_SOCKS5,
            1, // number of methods,
            if auth_info.is_some() {
                METHOD_USERNAME
            } else {
                METHOD_NONE
            },
        ];
        if let Some((username, password)) = auth_info.as_ref() {
            data.extend(&[VER_AUTH, username.len() as u8]);
            data.extend_from_slice(username.as_bytes());
            data.push(password.len() as u8);
            data.extend_from_slice(password.as_bytes());
        }
        data.extend(&[
            VER_SOCKS5,
            CMD_CONNECT,
            0x0, // reserved
        ]);

        Self {
            prefix_data: data,
            has_auth: auth_info.is_some(),
        }
    }
}

#[async_trait]
impl TcpClientHandler for SocksTcpClientHandler {
    async fn setup_client_stream(
        &self,
        _server_stream: &mut Box<dyn AsyncStream>,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: NetLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        client_stream.write_all(&self.prefix_data).await?;
        write_location(&mut client_stream, &remote_location).await?;
        client_stream.flush().await?;

        let mut data = [0u8; 2];

        // read server choice response on auth method
        client_stream.read_exact(&mut data).await?;
        if data[1] == METHOD_INVALID {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "SOCKS server rejected auth method",
            ));
        }

        if self.has_auth {
            // read auth response
            client_stream.read_exact(&mut data).await?;
            if data[1] != RESULT_SUCCESS {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("SOCKS server authentication failed: error {}", data[1]),
                ));
            }
        }

        let mut connect_response_prefix = [0u8; 3];
        client_stream
            .read_exact(&mut connect_response_prefix)
            .await?;
        if connect_response_prefix[1] != RESULT_SUCCESS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "SOCKS server connect command failed: error {}",
                    connect_response_prefix[1]
                ),
            ));
        }

        // Read the final location part of the connect response.
        read_location(&mut client_stream).await?;

        Ok(TcpClientSetupResult { client_stream })
    }
}

pub async fn read_location<T: AsyncReadExt + Unpin>(
    stream: &mut T,
) -> std::io::Result<NetLocation> {
    let mut data = [0u8; 1];

    stream.read_exact(&mut data).await?;

    let address_type = data[0];

    match address_type {
        ADDR_TYPE_IPV4 => {
            let mut address_bytes = [0u8; 6];
            stream.read_exact(&mut address_bytes).await?;

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
            let mut address_bytes = [0u8; 18];
            stream.read_exact(&mut address_bytes).await?;

            let v6addr = Ipv6Addr::new(
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
            stream.read_exact(&mut data).await?;
            let address_len = data[0] as usize;

            let mut address_bytes = allocate_vec(address_len + 2);
            stream.read_exact(&mut address_bytes).await?;

            let address_str = match std::str::from_utf8(&address_bytes[0..address_len]) {
                Ok(s) => s,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Failed to decode address: {}", e),
                    ));
                }
            };

            let port = u16::from_be_bytes(
                address_bytes[address_len..address_len + 2]
                    .try_into()
                    .unwrap(),
            );

            // Although this is supposed to be a hostname, some clients will pass
            // ipv4 and ipv6 addresses as well, so parse it rather than directly
            // using Address:Hostname enum.
            Ok(NetLocation::new(Address::from(address_str)?, port))
        }

        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Unknown address type: {}", address_type),
        )),
    }
}

pub async fn write_location(
    stream: &mut Box<dyn AsyncStream>,
    location: &NetLocation,
) -> std::io::Result<()> {
    let (address, port) = location.components();
    let mut data = [0u8; 1];
    match address {
        Address::Ipv4(v4addr) => {
            data[0] = ADDR_TYPE_IPV4;
            stream.write_all(&data).await?;
            stream.write_all(&v4addr.octets()).await?;
        }
        Address::Ipv6(v6addr) => {
            data[0] = ADDR_TYPE_IPV6;
            stream.write_all(&data).await?;
            stream.write_all(&v6addr.octets()).await?;
        }
        Address::Hostname(domain_name) => {
            data[0] = ADDR_TYPE_DOMAIN_NAME;
            stream.write_all(&data).await?;

            let domain_name_bytes = domain_name.as_bytes();
            data[0] = domain_name_bytes.len() as u8;
            stream.write_all(&data).await?;
            stream.write_all(domain_name_bytes).await?;
        }
    }

    let port_bytes = [(port >> 8) as u8, (port & 0xff) as u8];
    stream.write_all(&port_bytes).await?;

    Ok(())
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
