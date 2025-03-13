use std::net::{Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use log::info;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncStream;
use crate::option_util::NoneOrOne;
use crate::stream_reader::StreamReader;
use crate::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};
use crate::util::{allocate_vec, parse_uuid, write_all};
use crate::vless_message_stream::VlessMessageStream;

#[derive(Debug)]
pub struct VlessTcpServerHandler {
    user_id: Box<[u8]>,
    udp_enabled: bool,
}

impl VlessTcpServerHandler {
    pub fn new(user_id: &str, udp_enabled: bool) -> Self {
        Self {
            user_id: parse_uuid(user_id).unwrap().into_boxed_slice(),
            udp_enabled,
        }
    }
}

const SERVER_RESPONSE_HEADER: &[u8] = &[
    0u8, // version
    0u8, // addons length
];

#[async_trait]
impl TcpServerHandler for VlessTcpServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        // this needs to be less than `read_buf` size in VlessMessageStream so that
        // feed_initial_data can handle the unparsed data.
        let mut stream_reader = StreamReader::new_with_buffer_size(800);

        let client_version = stream_reader.read_u8(&mut server_stream).await?;
        if client_version != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "invalid client protocol version, expected 0, got {}",
                    client_version
                ),
            ));
        }

        let target_id = stream_reader.read_slice(&mut server_stream, 16).await?;
        for (b1, b2) in self.user_id.iter().zip(target_id.iter()) {
            if b1 != b2 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Unknown user id",
                ));
            }
        }

        let addon_length = stream_reader.read_u8(&mut server_stream).await?;
        if addon_length > 0 {
            stream_reader
                .read_slice(&mut server_stream, addon_length as usize)
                .await?;
        }

        let instruction = stream_reader.read_u8(&mut server_stream).await?;
        let is_udp = match instruction {
            1 => {
                // tcp
                false
            }
            2 => {
                if !self.udp_enabled {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "UDP not enabled",
                    ));
                }
                true
            }
            unknown_protocol_type => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Unknown requested protocol: {}", unknown_protocol_type),
                ));
            }
        };

        let port = stream_reader.read_u16_be(&mut server_stream).await?;

        let address_type = stream_reader.read_u8(&mut server_stream).await?;
        let remote_location = match address_type {
            1 => {
                // 4 byte ipv4 address
                let address_bytes = stream_reader.read_slice(&mut server_stream, 4).await?;
                let v4addr = Ipv4Addr::new(
                    address_bytes[0],
                    address_bytes[1],
                    address_bytes[2],
                    address_bytes[3],
                );
                NetLocation::new(Address::Ipv4(v4addr), port)
            }
            2 => {
                // domain name
                let domain_name_len = stream_reader.read_u8(&mut server_stream).await?;
                let domain_name_bytes = stream_reader
                    .read_slice(&mut server_stream, domain_name_len as usize)
                    .await?;

                let address_str = match std::str::from_utf8(domain_name_bytes) {
                    Ok(s) => s,
                    Err(e) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("Failed to decode address: {}", e),
                        ));
                    }
                };

                // Although this is supposed to be a hostname, some clients will pass
                // ipv4 and ipv6 addresses as well, so parse it rather than directly
                // using Address:Hostname enum.
                NetLocation::new(Address::from(address_str)?, port)
            }
            3 => {
                // 16 byte ipv6 address
                let address_bytes = stream_reader.read_slice(&mut server_stream, 16).await?;
                let v6addr = Ipv6Addr::new(
                    ((address_bytes[0] as u16) << 8) | (address_bytes[1] as u16),
                    ((address_bytes[2] as u16) << 8) | (address_bytes[3] as u16),
                    ((address_bytes[4] as u16) << 8) | (address_bytes[5] as u16),
                    ((address_bytes[6] as u16) << 8) | (address_bytes[7] as u16),
                    ((address_bytes[8] as u16) << 8) | (address_bytes[9] as u16),
                    ((address_bytes[10] as u16) << 8) | (address_bytes[11] as u16),
                    ((address_bytes[12] as u16) << 8) | (address_bytes[13] as u16),
                    ((address_bytes[14] as u16) << 8) | (address_bytes[15] as u16),
                );

                NetLocation::new(Address::Ipv6(v6addr), port)
            }
            invalid_type => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid address type: {}", invalid_type),
                ));
            }
        };

        let unparsed_data = stream_reader.unparsed_data();

        if !is_udp {
            Ok(TcpServerSetupResult::TcpForward {
                remote_location,
                stream: server_stream,
                need_initial_flush: false,
                connection_success_response: Some(
                    SERVER_RESPONSE_HEADER.to_vec().into_boxed_slice(),
                ),
                initial_remote_data: if unparsed_data.is_empty() {
                    None
                } else {
                    Some(unparsed_data.to_vec().into_boxed_slice())
                },
                override_proxy_provider: NoneOrOne::Unspecified,
            })
        } else {
            write_all(&mut server_stream, SERVER_RESPONSE_HEADER).await?;

            let mut vless_stream = VlessMessageStream::new(server_stream);
            if !unparsed_data.is_empty() {
                vless_stream.feed_initial_read_data(unparsed_data)?;
            }

            Ok(TcpServerSetupResult::BidirectionalUdp {
                remote_location,
                stream: Box::new(vless_stream),
                // don't flush and write the server response with the initial data.
                need_initial_flush: false,
                override_proxy_provider: NoneOrOne::Unspecified,
            })
        }
    }
}

#[derive(Debug)]
pub struct VlessTcpClientHandler {
    user_id: Box<[u8]>,
}

impl VlessTcpClientHandler {
    pub fn new(user_id: &str) -> Self {
        Self {
            user_id: parse_uuid(user_id).unwrap().into_boxed_slice(),
        }
    }
}

#[async_trait]
impl TcpClientHandler for VlessTcpClientHandler {
    async fn setup_client_stream(
        &self,
        _server_stream: &mut Box<dyn AsyncStream>,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: NetLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        // version + user id + header addon length + command + port + address type
        let mut header_bytes = [0u8; 1 + 16 + 1 + 1 + 2 + 1];

        // version 0 is fine, no need to write.
        header_bytes[1..17].copy_from_slice(&self.user_id);

        // header addon length of 0 is fine, no need to write.
        // tcp
        header_bytes[18] = 1;

        let (remote_address, remote_port) = remote_location.unwrap_components();
        header_bytes[19] = (remote_port >> 8) as u8;
        header_bytes[20] = (remote_port & 0xff) as u8;

        match remote_address {
            Address::Ipv4(v4addr) => {
                header_bytes[21] = 1;
                write_all(&mut client_stream, &header_bytes).await?;

                let address_bytes = v4addr.octets();
                write_all(&mut client_stream, &address_bytes).await?;
            }
            Address::Ipv6(v6addr) => {
                header_bytes[21] = 3;
                write_all(&mut client_stream, &header_bytes).await?;

                let address_bytes = v6addr.octets();
                write_all(&mut client_stream, &address_bytes).await?;
            }
            Address::Hostname(hostname) => {
                if hostname.len() > 255 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Hostname is too long: {}", hostname),
                    ));
                }

                header_bytes[21] = 2;
                write_all(&mut client_stream, &header_bytes).await?;

                let hostname_len_byte: [u8; 1] = [hostname.len() as u8];
                write_all(&mut client_stream, &hostname_len_byte).await?;

                let hostname_bytes = hostname.into_bytes();
                write_all(&mut client_stream, &hostname_bytes).await?;
            }
        }
        client_stream.flush().await?;

        // TODO: remove read_exact, used buffered writes above.
        let mut response_header = [0u8; 2];
        client_stream.read_exact(&mut response_header).await?;

        if response_header[0] != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "invalid server protocol version, expected 0, got {}",
                    response_header[0]
                ),
            ));
        }

        let addon_length = response_header[1];
        if addon_length > 0 {
            read_addons(&mut client_stream, addon_length).await?;
        }

        Ok(TcpClientSetupResult { client_stream })
    }
}

fn read_varint(data: &[u8]) -> std::io::Result<(u64, usize)> {
    let mut cursor = 0usize;
    let mut length = 0u64;
    loop {
        let byte = data[cursor];
        if (byte & 0b10000000) != 0 {
            length = (length << 8) | ((byte ^ 0b10000000) as u64);
        } else {
            length = (length << 8) | (byte as u64);
            return Ok((length, cursor + 1));
        }
        if cursor == 7 || cursor == data.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Varint is too long",
            ));
        }
        cursor += 1;
    }
}

async fn read_addons(stream: &mut Box<dyn AsyncStream>, addon_length: u8) -> std::io::Result<()> {
    let mut addon_bytes = allocate_vec(addon_length as usize).into_boxed_slice();
    stream.read_exact(&mut addon_bytes).await?;

    let mut addon_cursor = 0;
    let (flow_length, bytes_used) = read_varint(&addon_bytes)?;
    addon_cursor += bytes_used;

    let flow_bytes = &addon_bytes[addon_cursor..addon_cursor + flow_length as usize];
    addon_cursor += flow_length as usize;

    let (seed_length, bytes_used) = read_varint(&addon_bytes[addon_cursor..])?;
    addon_cursor += bytes_used;
    let seed_bytes = &addon_bytes[addon_cursor..addon_cursor + seed_length as usize];
    addon_cursor += seed_length as usize;

    if addon_cursor as u8 != addon_length {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "Did not consume all addon bytes, cursor is at {}, length is {}",
                addon_cursor, addon_length
            ),
        ));
    }

    info!(
        "Read addon bytes: flow: {:?}, seed: {:?}",
        &flow_bytes, &seed_bytes
    );

    Ok(())
}
