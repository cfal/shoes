//! SOCKS-style packet address parsing for h2mux `packet_addr` streams.
//!
//! sing-mux encodes per-packet destinations with `SocksaddrSerializer`, using:
//! - 0x01: IPv4 (4 bytes)
//! - 0x03: Domain (1 byte length + domain string)
//! - 0x04: IPv6 (16 bytes)

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::address::{Address, NetLocation};

/// SOCKS5 ATYP values used by sing-mux `packet_addr`.
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

/// Parse a SOCKS packet address (ATYP + address + port).
/// Returns Ok(Some((NetLocation, bytes consumed))) on success.
/// Returns Ok(None) if data is truncated (need more data).
/// Returns Err for invalid data (unknown ATYP, invalid UTF-8).
#[inline]
pub fn parse_socks_packet_address(data: &[u8]) -> std::io::Result<Option<(NetLocation, usize)>> {
    if data.is_empty() {
        return Ok(None);
    }

    let atyp = data[0];
    match atyp {
        ATYP_IPV4 => {
            if data.len() < 7 {
                return Ok(None);
            }
            let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok(Some((NetLocation::new(Address::Ipv4(ip), port), 7)))
        }
        ATYP_IPV6 => {
            if data.len() < 19 {
                return Ok(None);
            }
            let ip_bytes: [u8; 16] = data[1..17].try_into().unwrap();
            let ip = Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok(Some((NetLocation::new(Address::Ipv6(ip), port), 19)))
        }
        ATYP_DOMAIN => {
            if data.len() < 2 {
                return Ok(None);
            }
            let domain_len = data[1] as usize;
            let total_len = 1 + 1 + domain_len + 2;
            if data.len() < total_len {
                return Ok(None);
            }
            let domain = std::str::from_utf8(&data[2..2 + domain_len])
                .map_err(|e| std::io::Error::other(format!("invalid domain: {e}")))?;
            let port = u16::from_be_bytes([data[2 + domain_len], data[3 + domain_len]]);
            Ok(Some((
                NetLocation::new(Address::Hostname(domain.to_string()), port),
                total_len,
            )))
        }
        _ => Err(std::io::Error::other(format!(
            "unknown SOCKS packet ATYP: {atyp}"
        ))),
    }
}

/// Write a SOCKS packet address (ATYP + address + port) from SocketAddr.
/// Returns number of bytes written.
#[inline]
pub fn write_socks_packet_address(buf: &mut [u8], addr: &SocketAddr) -> usize {
    match addr {
        SocketAddr::V4(v4) => {
            buf[0] = ATYP_IPV4;
            buf[1..5].copy_from_slice(&v4.ip().octets());
            buf[5..7].copy_from_slice(&v4.port().to_be_bytes());
            7
        }
        SocketAddr::V6(v6) => {
            buf[0] = ATYP_IPV6;
            buf[1..17].copy_from_slice(&v6.ip().octets());
            buf[17..19].copy_from_slice(&v6.port().to_be_bytes());
            19
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_socks_ipv4_address() {
        let data = [ATYP_IPV4, 192, 168, 1, 1, 0x1F, 0x90];
        let (location, len) = parse_socks_packet_address(&data).unwrap().unwrap();
        assert_eq!(len, 7);
        assert_eq!(location.port(), 8080);
        match location.address() {
            Address::Ipv4(ip) => assert_eq!(*ip, Ipv4Addr::new(192, 168, 1, 1)),
            _ => panic!("expected IPv4"),
        }
    }

    #[test]
    fn test_parse_socks_ipv6_address() {
        let mut data = vec![ATYP_IPV6];
        data.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        data.extend_from_slice(&443u16.to_be_bytes());

        let (location, len) = parse_socks_packet_address(&data).unwrap().unwrap();
        assert_eq!(len, 19);
        assert_eq!(location.port(), 443);
        match location.address() {
            Address::Ipv6(ip) => assert_eq!(*ip, Ipv6Addr::LOCALHOST),
            _ => panic!("expected IPv6"),
        }
    }

    #[test]
    fn test_parse_socks_domain_address() {
        let domain = b"example.com";
        let mut data = vec![ATYP_DOMAIN, domain.len() as u8];
        data.extend_from_slice(domain);
        data.extend_from_slice(&53u16.to_be_bytes());

        let (location, len) = parse_socks_packet_address(&data).unwrap().unwrap();
        assert_eq!(len, 1 + 1 + domain.len() + 2);
        assert_eq!(location.port(), 53);
        match location.address() {
            Address::Hostname(h) => assert_eq!(h, "example.com"),
            _ => panic!("expected hostname"),
        }
    }

    #[test]
    fn test_parse_socks_rejects_uot_atyp_values() {
        for atyp in [0x00_u8, 0x02_u8] {
            assert!(parse_socks_packet_address(&[atyp, 1, 2, 3, 4, 5, 6, 7]).is_err());
        }
    }

    #[test]
    fn test_write_socks_ipv4_address() {
        let addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let mut buf = [0u8; 32];
        let len = write_socks_packet_address(&mut buf, &addr);
        assert_eq!(len, 7);
        assert_eq!(buf[0], ATYP_IPV4);
        assert_eq!(&buf[1..5], &[192, 168, 1, 1]);
        assert_eq!(&buf[5..7], &0x1F90u16.to_be_bytes());
    }

    #[test]
    fn test_write_socks_ipv6_address() {
        let addr: SocketAddr = "[::1]:443".parse().unwrap();
        let mut buf = [0u8; 32];
        let len = write_socks_packet_address(&mut buf, &addr);
        assert_eq!(len, 19);
        assert_eq!(buf[0], ATYP_IPV6);
        assert_eq!(&buf[1..17], &Ipv6Addr::LOCALHOST.octets());
        assert_eq!(&buf[17..19], &443u16.to_be_bytes());
    }
}
