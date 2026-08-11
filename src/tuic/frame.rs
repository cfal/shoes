//! TUIC v5 frame codec, shared by the server and the client.
//!
//! Layouts are from the upstream specification (EAimTY/tuic, SPEC.md). Every
//! command is `[u8 version][u8 type][type-specific data]`, and every field is
//! big endian.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str;

use crate::address::{Address, NetLocation};
use crate::stream_reader::StreamReader;

/// TUIC protocol version.
pub const TUIC_VERSION: u8 = 0x05;

pub const COMMAND_TYPE_AUTHENTICATE: u8 = 0x00;
pub const COMMAND_TYPE_CONNECT: u8 = 0x01;
pub const COMMAND_TYPE_PACKET: u8 = 0x02;
pub const COMMAND_TYPE_DISSOCIATE: u8 = 0x03;
pub const COMMAND_TYPE_HEARTBEAT: u8 = 0x04;

// hostname case: type (1) + hostname length (1) + hostname bytes (255) + port (2)
pub const MAX_ADDRESS_BYTES_LEN: usize = 1 + 1 + 255 + 2;
pub const MAX_HEADER_LEN: usize = 2 + 2 + 1 + 1 + 2 + MAX_ADDRESS_BYTES_LEN;

pub async fn read_address(
    recv: &mut quinn::RecvStream,
    stream_reader: &mut StreamReader,
) -> std::io::Result<Option<NetLocation>> {
    let address_type = stream_reader.read_u8(recv).await?;
    let address = match address_type {
        0xff => {
            return Ok(None);
        }
        0x00 => {
            let address_len = stream_reader.read_u8(recv).await? as usize;
            let address_bytes = stream_reader.read_slice(recv, address_len).await?;
            let address_str = str::from_utf8(address_bytes).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid address: {e}"),
                )
            })?;
            // Although this is supposed to be a hostname, some clients will pass
            // ipv4 and ipv6 addresses as well, so parse it rather than directly
            // using Address:Hostname enum.
            Address::from(address_str)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?
        }
        0x01 => {
            let ipv4_bytes = stream_reader.read_slice(recv, 4).await?;
            let ipv4_addr =
                Ipv4Addr::new(ipv4_bytes[0], ipv4_bytes[1], ipv4_bytes[2], ipv4_bytes[3]);
            Address::Ipv4(ipv4_addr)
        }
        0x02 => {
            let ipv6_bytes = stream_reader.read_slice(recv, 16).await?;
            let ipv6_bytes: [u8; 16] = ipv6_bytes.try_into().unwrap();
            let ipv6_addr = Ipv6Addr::from(ipv6_bytes);
            Address::Ipv6(ipv6_addr)
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid address type: {address_type}"),
            ));
        }
    };

    let port = stream_reader.read_u16_be(recv).await?;

    Ok(Some(NetLocation::new(address, port)))
}

pub fn serialize_address(location: &NetLocation) -> Vec<u8> {
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

pub fn serialize_socket_addr(addr: &SocketAddr) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_address_hostname() {
        let loc = NetLocation::new(Address::Hostname("example.com".to_string()), 443);
        assert_eq!(
            serialize_address(&loc),
            [&[0x00u8, 11][..], b"example.com", &[0x01, 0xbb][..]].concat()
        );
    }

    #[test]
    fn test_serialize_address_ipv4() {
        let loc = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 80);
        assert_eq!(serialize_address(&loc), vec![0x01, 1, 2, 3, 4, 0x00, 0x50]);
    }

    #[test]
    fn test_serialize_address_ipv6() {
        let loc = NetLocation::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 80);
        let mut expected = vec![0x02u8];
        expected.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        expected.extend_from_slice(&80u16.to_be_bytes());
        assert_eq!(serialize_address(&loc), expected);
    }

    #[test]
    fn test_serialize_address_max_length_hostname() {
        let hostname = "a".repeat(255);
        let loc = NetLocation::new(Address::Hostname(hostname), 1);
        let encoded = serialize_address(&loc);
        assert_eq!(encoded[0], 0x00);
        assert_eq!(encoded[1], 255);
        assert_eq!(encoded.len(), MAX_ADDRESS_BYTES_LEN);
    }

    #[test]
    fn test_command_type_values() {
        assert_eq!(COMMAND_TYPE_AUTHENTICATE, 0x00);
        assert_eq!(COMMAND_TYPE_CONNECT, 0x01);
        assert_eq!(COMMAND_TYPE_PACKET, 0x02);
        assert_eq!(COMMAND_TYPE_DISSOCIATE, 0x03);
        assert_eq!(COMMAND_TYPE_HEARTBEAT, 0x04);
        assert_eq!(TUIC_VERSION, 0x05);
    }
}
