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

/// Address type byte meaning "no address", used on fragments after the first.
pub const ADDRESS_TYPE_NONE: u8 = 0xff;

fn command(command_type: u8, capacity: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + capacity);
    out.push(TUIC_VERSION);
    out.push(command_type);
    out
}

/// `Authenticate`: `[16-byte UUID][32-byte token]`.
pub fn encode_authenticate(uuid: &[u8; 16], token: &[u8; 32]) -> Vec<u8> {
    let mut out = command(COMMAND_TYPE_AUTHENTICATE, 48);
    out.extend_from_slice(uuid);
    out.extend_from_slice(token);
    out
}

/// `Connect`: `[address]`. The server never answers it.
pub fn encode_connect(target: &NetLocation) -> Vec<u8> {
    let mut out = command(COMMAND_TYPE_CONNECT, MAX_ADDRESS_BYTES_LEN);
    out.extend_from_slice(&serialize_address(target));
    out
}

/// `Packet`: `[u16 assoc][u16 pkt][u8 frag total][u8 frag id][u16 size][address]`.
///
/// `target` is None for every fragment after the first, which the specification
/// encodes as address type 0xff.
pub fn encode_packet_header(
    assoc_id: u16,
    packet_id: u16,
    fragment_total: u8,
    fragment_id: u8,
    size: u16,
    target: Option<&NetLocation>,
) -> Vec<u8> {
    let mut out = command(COMMAND_TYPE_PACKET, MAX_HEADER_LEN);
    out.extend_from_slice(&assoc_id.to_be_bytes());
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.push(fragment_total);
    out.push(fragment_id);
    out.extend_from_slice(&size.to_be_bytes());
    match target {
        Some(target) => out.extend_from_slice(&serialize_address(target)),
        None => out.push(ADDRESS_TYPE_NONE),
    }
    out
}

/// `Dissociate`: `[u16 assoc]`.
pub fn encode_dissociate(assoc_id: u16) -> Vec<u8> {
    let mut out = command(COMMAND_TYPE_DISSOCIATE, 2);
    out.extend_from_slice(&assoc_id.to_be_bytes());
    out
}

/// `Heartbeat`: no payload.
pub fn encode_heartbeat() -> Vec<u8> {
    command(COMMAND_TYPE_HEARTBEAT, 0)
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

    #[test]
    fn test_authenticate_layout() {
        let uuid = [0xabu8; 16];
        let token = [0xcdu8; 32];
        let command = encode_authenticate(&uuid, &token);
        assert_eq!(command[0], TUIC_VERSION);
        assert_eq!(command[1], COMMAND_TYPE_AUTHENTICATE);
        assert_eq!(&command[2..18], &uuid);
        assert_eq!(&command[18..50], &token);
        assert_eq!(command.len(), 50);
    }

    #[test]
    fn test_connect_layout() {
        let loc = NetLocation::new(Address::Hostname("example.com".to_string()), 443);
        let command = encode_connect(&loc);
        assert_eq!(command[0], TUIC_VERSION);
        assert_eq!(command[1], COMMAND_TYPE_CONNECT);
        assert_eq!(&command[2..], &serialize_address(&loc)[..]);
    }

    #[test]
    fn test_packet_header_layout() {
        let loc = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 53);
        let header = encode_packet_header(7, 9, 3, 1, 1200, Some(&loc));
        assert_eq!(header[0], TUIC_VERSION);
        assert_eq!(header[1], COMMAND_TYPE_PACKET);
        assert_eq!(&header[2..4], &7u16.to_be_bytes());
        assert_eq!(&header[4..6], &9u16.to_be_bytes());
        assert_eq!(header[6], 3, "fragment total");
        assert_eq!(header[7], 1, "fragment id");
        assert_eq!(&header[8..10], &1200u16.to_be_bytes());
        assert_eq!(&header[10..], &serialize_address(&loc)[..]);
    }

    #[test]
    fn test_packet_header_uses_the_none_address_for_later_fragments() {
        let header = encode_packet_header(7, 9, 3, 2, 100, None);
        assert_eq!(header[10], ADDRESS_TYPE_NONE);
        assert_eq!(header.len(), 11);
    }

    #[test]
    fn test_dissociate_layout() {
        assert_eq!(
            encode_dissociate(7),
            vec![TUIC_VERSION, COMMAND_TYPE_DISSOCIATE, 0x00, 0x07]
        );
    }

    #[test]
    fn test_heartbeat_layout() {
        assert_eq!(
            encode_heartbeat(),
            vec![TUIC_VERSION, COMMAND_TYPE_HEARTBEAT]
        );
    }
}
