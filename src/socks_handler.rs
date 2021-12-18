use std::net::{Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::address::{Address, Location};
use crate::async_stream::AsyncStream;
use crate::protocol_handler::{
    ClientSetupResult, ServerSetupResult, TcpClientHandler, TcpServerHandler,
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
    ) -> std::io::Result<ServerSetupResult> {
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

        if methods
            .into_iter()
            .find(move |method| *method == supported_method)
            .is_none()
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

        // Normally, the location is read first before we reply with success
        // and the bind location.
        connection_request[1] = RESULT_SUCCESS;
        server_stream.write_all(&connection_request).await?;

        // Because we only return the location to the caller, we don't get a chance to populate it
        // with the correct bound address.
        // TODO: Consider amending the TcpHandler trait to allow returning a vector to
        // write to the server stream after connection to the remote location is successful.
        write_location(
            &mut server_stream,
            &Location::new(Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 65535),
        )
        .await?;

        let location = read_location(&mut server_stream).await?;

        Ok(ServerSetupResult {
            server_stream,
            remote_location: location,
            override_proxy_provider: None,
            initial_remote_data: None,
        })
    }
}

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
        remote_location: Location,
    ) -> std::io::Result<ClientSetupResult> {
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

        Ok(ClientSetupResult { client_stream })
    }
}

pub async fn read_location(stream: &mut Box<dyn AsyncStream>) -> std::io::Result<Location> {
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

            Ok(Location::new(Address::Ipv4(v4addr), port))
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

            Ok(Location::new(Address::Ipv6(v6addr), port))
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
            Ok(Location::new(Address::from(address_str)?, port))
        }

        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Unknown address type: {}", address_type),
        )),
    }
}

pub async fn write_location(
    stream: &mut Box<dyn AsyncStream>,
    location: &Location,
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

pub fn read_location_from_vec(data: &[u8]) -> std::io::Result<(Location, usize)> {
    let address_type = data[0];

    match address_type {
        ADDR_TYPE_IPV4 => {
            let v4addr = Ipv4Addr::new(data[1], data[2], data[3], data[4]);

            let port = u16::from_be_bytes(data[5..7].try_into().unwrap());

            Ok((Location::new(Address::Ipv4(v4addr), port), 1 + 4 + 2))
        }
        ADDR_TYPE_IPV6 => {
            let v6addr = Ipv6Addr::new(
                u16::from_be_bytes(data[1..3].try_into().unwrap()),
                u16::from_be_bytes(data[3..5].try_into().unwrap()),
                u16::from_be_bytes(data[5..7].try_into().unwrap()),
                u16::from_be_bytes(data[7..9].try_into().unwrap()),
                u16::from_be_bytes(data[9..11].try_into().unwrap()),
                u16::from_be_bytes(data[11..13].try_into().unwrap()),
                u16::from_be_bytes(data[13..15].try_into().unwrap()),
                u16::from_be_bytes(data[15..17].try_into().unwrap()),
            );

            let port = u16::from_be_bytes(data[17..19].try_into().unwrap());

            Ok((Location::new(Address::Ipv6(v6addr), port), 1 + 16 + 2))
        }
        ADDR_TYPE_DOMAIN_NAME => {
            let address_len = data[1] as usize;

            let address_str = match std::str::from_utf8(&data[2..address_len + 2]) {
                Ok(s) => s,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Failed to decode address: {}", e),
                    ));
                }
            };

            let port =
                u16::from_be_bytes(data[address_len + 2..address_len + 4].try_into().unwrap());

            // Although this is supposed to be a hostname, some clients will pass
            // ipv4 and ipv6 addresses as well, so parse it rather than directly
            // using Address:Hostname enum.
            Ok((
                Location::new(Address::from(address_str)?, port),
                1 + 1 + address_len + 2,
            ))
        }

        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Unknown address type: {}", address_type),
        )),
    }
}
