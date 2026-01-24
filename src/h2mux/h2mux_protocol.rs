//! H2MUX protocol encoding and decoding
//!
//! This module handles the session-level and stream-level protocol framing.

use std::io;

use bytes::{Buf, BufMut, BytesMut};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::address::{Address, NetLocation};
use crate::util::write_all;

use super::MuxProtocol;

// Protocol version constants
pub const VERSION_0: u8 = 0; // No padding
pub const VERSION_1: u8 = 1; // With padding support

// Stream flags
pub const FLAG_UDP: u16 = 0x0001;
pub const FLAG_ADDR: u16 = 0x0002; // Per-packet addressing for UDP

// Response status
pub const STATUS_SUCCESS: u8 = 0;
pub const STATUS_ERROR: u8 = 1;

// Padding constants
pub const MIN_PADDING: u16 = 256;
pub const MAX_PADDING: u16 = 767;

/// Session request from client
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRequest {
    pub version: u8,
    pub protocol: MuxProtocol,
    pub padding: bool,
}

impl SessionRequest {
    pub fn new(protocol: MuxProtocol, padding: bool) -> Self {
        Self {
            version: if padding { VERSION_1 } else { VERSION_0 },
            protocol,
            padding,
        }
    }

    /// Encode session request to bytes
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(256);
        buf.put_u8(self.version);
        buf.put_u8(self.protocol as u8);

        if self.version >= VERSION_1 {
            buf.put_u8(self.padding as u8);
            if self.padding {
                let padding_len = rand::rng().random_range(MIN_PADDING..=MAX_PADDING);
                buf.put_u16(padding_len);
                buf.put_bytes(0, padding_len as usize);
            }
        }
        buf
    }

    /// Decode session request from reader
    pub async fn decode<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        let version = reader.read_u8().await?;
        if version > VERSION_1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported mux version: {}", version),
            ));
        }

        let protocol_byte = reader.read_u8().await?;
        let protocol = MuxProtocol::from_u8(protocol_byte).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported mux protocol: {}", protocol_byte),
            )
        })?;

        let mut padding = false;
        if version == VERSION_1 {
            padding = reader.read_u8().await? != 0;
            if padding {
                let padding_len = reader.read_u16().await?;
                // Skip padding bytes
                let mut skip_buf = vec![0u8; padding_len as usize];
                reader.read_exact(&mut skip_buf).await?;
            }
        }

        Ok(Self {
            version,
            protocol,
            padding,
        })
    }

    /// Write session request to writer
    pub async fn write<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        let encoded = self.encode();
        write_all(writer, &encoded).await?;
        writer.flush().await
    }
}

/// Stream request (destination addressing)
#[derive(Debug, Clone)]
pub struct StreamRequest {
    /// Network type: "tcp" or "udp"
    pub network: String,
    /// Destination address
    pub destination: NetLocation,
    /// Per-packet addressing for UDP
    pub packet_addr: bool,
}

impl StreamRequest {
    pub fn tcp(destination: NetLocation) -> Self {
        Self {
            network: "tcp".to_string(),
            destination,
            packet_addr: false,
        }
    }

    pub fn udp(destination: NetLocation, packet_addr: bool) -> Self {
        Self {
            network: "udp".to_string(),
            destination,
            packet_addr,
        }
    }

    /// Check if this is a UDP stream
    pub fn is_udp(&self) -> bool {
        self.network == "udp"
    }

    /// Encode stream request to bytes
    pub fn encode(&self) -> io::Result<BytesMut> {
        let mut buf = BytesMut::with_capacity(64);

        let mut flags: u16 = 0;
        if self.network == "udp" {
            flags |= FLAG_UDP;
        }
        if self.packet_addr {
            flags |= FLAG_ADDR;
        }

        buf.put_u16(flags);
        encode_socks_address(&mut buf, &self.destination)?;
        Ok(buf)
    }

    /// Decode stream request from reader
    pub async fn decode_async<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        let flags = reader.read_u16().await?;
        let destination = decode_socks_address_async(reader).await?;

        let network = if flags & FLAG_UDP != 0 {
            "udp".to_string()
        } else {
            "tcp".to_string()
        };
        let packet_addr = flags & FLAG_ADDR != 0;

        Ok(Self {
            network,
            destination,
            packet_addr,
        })
    }
}

/// Stream response (status).
/// Reserved for future client-side response parsing.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct StreamResponse {
    pub status: u8,
    pub message: Option<String>,
}

#[allow(dead_code)]
impl StreamResponse {
    pub fn success() -> Self {
        Self {
            status: STATUS_SUCCESS,
            message: None,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            status: STATUS_ERROR,
            message: Some(message.into()),
        }
    }

    pub fn is_success(&self) -> bool {
        self.status == STATUS_SUCCESS
    }

    /// Encode stream response to bytes
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(64);
        buf.put_u8(self.status);

        if self.status == STATUS_ERROR {
            if let Some(ref msg) = self.message {
                let len = msg.len();
                if len < 128 {
                    buf.put_u8(len as u8);
                } else {
                    buf.put_u8((len & 0x7F) as u8 | 0x80);
                    buf.put_u8((len >> 7) as u8);
                }
                buf.put_slice(msg.as_bytes());
            } else {
                buf.put_u8(0);
            }
        }
        buf
    }

    /// Decode stream response from reader
    pub async fn decode<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        let status = reader.read_u8().await?;

        let message = if status == STATUS_ERROR {
            let len = read_varint(reader).await?;
            if len > 0 {
                let mut msg_buf = vec![0u8; len];
                reader.read_exact(&mut msg_buf).await?;
                Some(String::from_utf8_lossy(&msg_buf).to_string())
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self { status, message })
    }
}

/// Encode a NetLocation to SOCKS5 address format.
/// Returns error if hostname exceeds 255 bytes.
pub fn encode_socks_address(buf: &mut BytesMut, location: &NetLocation) -> io::Result<()> {
    match location.address() {
        Address::Ipv4(ip) => {
            buf.put_u8(0x01);
            buf.put_slice(&ip.octets());
        }
        Address::Ipv6(ip) => {
            buf.put_u8(0x04);
            buf.put_slice(&ip.octets());
        }
        Address::Hostname(host) => {
            let host_bytes = host.as_bytes();
            if host_bytes.len() > 255 {
                // Truncate hostname in error message to avoid huge logs
                let preview = std::str::from_utf8(&host_bytes[..64.min(host_bytes.len())])
                    .unwrap_or("<invalid utf8>");
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "hostname too long: {} bytes (max 255): {}...",
                        host_bytes.len(),
                        preview
                    ),
                ));
            }
            buf.put_u8(0x03);
            buf.put_u8(host_bytes.len() as u8);
            buf.put_slice(host_bytes);
        }
    }
    buf.put_u16(location.port());
    Ok(())
}

/// Decode a SOCKS5 address from bytes.
/// Reserved for synchronous parsing paths.
#[allow(dead_code)]
pub fn decode_socks_address(data: &mut &[u8]) -> io::Result<NetLocation> {
    if data.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "address too short",
        ));
    }

    let addr_type = data.get_u8();
    let address = match addr_type {
        0x01 => {
            // IPv4
            if data.len() < 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "IPv4 address too short",
                ));
            }
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&data[..4]);
            data.advance(4);
            Address::Ipv4(std::net::Ipv4Addr::from(octets))
        }
        0x03 => {
            // Domain
            if data.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "domain length missing",
                ));
            }
            let len = data.get_u8() as usize;
            if data.len() < len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "domain too short",
                ));
            }
            let domain = String::from_utf8_lossy(&data[..len]).to_string();
            data.advance(len);
            Address::Hostname(domain)
        }
        0x04 => {
            // IPv6
            if data.len() < 16 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "IPv6 address too short",
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[..16]);
            data.advance(16);
            Address::Ipv6(std::net::Ipv6Addr::from(octets))
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown address type: {}", addr_type),
            ));
        }
    };

    if data.len() < 2 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "port missing"));
    }
    let port = data.get_u16();

    Ok(NetLocation::new(address, port))
}

/// Decode a SOCKS5 address from async reader
pub async fn decode_socks_address_async<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<NetLocation> {
    let addr_type = reader.read_u8().await?;
    let address = match addr_type {
        0x01 => {
            // IPv4
            let mut octets = [0u8; 4];
            reader.read_exact(&mut octets).await?;
            Address::Ipv4(std::net::Ipv4Addr::from(octets))
        }
        0x03 => {
            // Domain
            let len = reader.read_u8().await? as usize;
            let mut domain_buf = vec![0u8; len];
            reader.read_exact(&mut domain_buf).await?;
            Address::Hostname(String::from_utf8_lossy(&domain_buf).to_string())
        }
        0x04 => {
            // IPv6
            let mut octets = [0u8; 16];
            reader.read_exact(&mut octets).await?;
            Address::Ipv6(std::net::Ipv6Addr::from(octets))
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown address type: {}", addr_type),
            ));
        }
    };

    let port = reader.read_u16().await?;
    Ok(NetLocation::new(address, port))
}

/// Read a varint from reader.
/// Used by StreamResponse::decode.
#[allow(dead_code)]
async fn read_varint<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<usize> {
    let mut result: usize = 0;
    let mut shift = 0;

    loop {
        let byte = reader.read_u8().await?;
        result |= ((byte & 0x7F) as usize) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "varint too long",
            ));
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_request_encode_decode_v0() {
        let req = SessionRequest {
            version: VERSION_0,
            protocol: MuxProtocol::H2Mux,
            padding: false,
        };
        let encoded = req.encode();
        assert_eq!(encoded.len(), 2);
        assert_eq!(encoded[0], VERSION_0);
        assert_eq!(encoded[1], MuxProtocol::H2Mux as u8);
    }

    #[test]
    fn test_session_request_encode_v1_no_padding() {
        let req = SessionRequest {
            version: VERSION_1,
            protocol: MuxProtocol::H2Mux,
            padding: false,
        };
        let encoded = req.encode();
        assert_eq!(encoded.len(), 3);
        assert_eq!(encoded[0], VERSION_1);
        assert_eq!(encoded[1], MuxProtocol::H2Mux as u8);
        assert_eq!(encoded[2], 0); // padding disabled
    }

    #[test]
    fn test_session_request_encode_v1_with_padding() {
        let req = SessionRequest {
            version: VERSION_1,
            protocol: MuxProtocol::H2Mux,
            padding: true,
        };
        let encoded = req.encode();
        assert!(encoded.len() >= 5); // version + protocol + padding_flag + padding_len
        assert_eq!(encoded[0], VERSION_1);
        assert_eq!(encoded[1], MuxProtocol::H2Mux as u8);
        assert_eq!(encoded[2], 1); // padding enabled
    }

    #[tokio::test]
    async fn test_stream_request_tcp() {
        let dest = NetLocation::new(Address::Hostname("example.com".to_string()), 443);
        let req = StreamRequest::tcp(dest.clone());
        let encoded = req.encode().unwrap();

        let mut cursor = std::io::Cursor::new(encoded);
        let decoded = StreamRequest::decode_async(&mut cursor).await.unwrap();
        assert_eq!(decoded.network, "tcp");
        assert!(!decoded.packet_addr);
        assert_eq!(decoded.destination.port(), 443);
    }

    #[tokio::test]
    async fn test_stream_request_udp() {
        let dest = NetLocation::new(Address::Ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)), 53);
        let req = StreamRequest::udp(dest, true);
        let encoded = req.encode().unwrap();

        let mut cursor = std::io::Cursor::new(encoded);
        let decoded = StreamRequest::decode_async(&mut cursor).await.unwrap();
        assert_eq!(decoded.network, "udp");
        assert!(decoded.packet_addr);
        assert_eq!(decoded.destination.port(), 53);
    }

    #[test]
    fn test_stream_response_success() {
        let resp = StreamResponse::success();
        let encoded = resp.encode();
        assert_eq!(encoded.len(), 1);
        assert_eq!(encoded[0], STATUS_SUCCESS);
    }

    #[test]
    fn test_stream_response_error() {
        let resp = StreamResponse::error("connection refused");
        let encoded = resp.encode();
        assert_eq!(encoded[0], STATUS_ERROR);
        // Check that message is encoded
        assert!(encoded.len() > 2);
    }

    #[tokio::test]
    async fn test_stream_response_error_roundtrip() {
        let message = "connection refused by server";
        let resp = StreamResponse::error(message);
        let encoded = resp.encode();

        let mut cursor = std::io::Cursor::new(encoded);
        let decoded = StreamResponse::decode(&mut cursor).await.unwrap();

        assert_eq!(decoded.status, STATUS_ERROR);
        assert_eq!(decoded.message.as_deref(), Some(message));
    }

    #[tokio::test]
    async fn test_stream_response_error_long_message() {
        // Message > 128 chars to test multi-byte varint encoding
        let message = "x".repeat(200);
        let resp = StreamResponse::error(&message);
        let encoded = resp.encode();

        // Verify varint is multi-byte (message len 200 requires 2 bytes)
        assert!(encoded[1] & 0x80 != 0, "varint should be multi-byte for len > 127");

        let mut cursor = std::io::Cursor::new(encoded);
        let decoded = StreamResponse::decode(&mut cursor).await.unwrap();

        assert_eq!(decoded.status, STATUS_ERROR);
        assert_eq!(decoded.message.as_deref(), Some(message.as_str()));
    }

    #[tokio::test]
    async fn test_stream_response_success_roundtrip() {
        let resp = StreamResponse::success();
        let encoded = resp.encode();

        let mut cursor = std::io::Cursor::new(encoded);
        let decoded = StreamResponse::decode(&mut cursor).await.unwrap();

        assert_eq!(decoded.status, STATUS_SUCCESS);
        assert!(decoded.message.is_none());
    }

    #[test]
    fn test_encode_socks_address_ipv4() {
        let loc = NetLocation::new(Address::Ipv4(std::net::Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let mut buf = BytesMut::new();
        encode_socks_address(&mut buf, &loc).unwrap();

        assert_eq!(buf[0], 0x01); // IPv4 type
        assert_eq!(&buf[1..5], &[192, 168, 1, 1]);
        assert_eq!(&buf[5..7], &[0x1F, 0x90]); // 8080 in BE
    }

    #[test]
    fn test_encode_socks_address_hostname() {
        let loc = NetLocation::new(Address::Hostname("test.com".to_string()), 443);
        let mut buf = BytesMut::new();
        encode_socks_address(&mut buf, &loc).unwrap();

        assert_eq!(buf[0], 0x03); // Domain type
        assert_eq!(buf[1], 8); // Length
        assert_eq!(&buf[2..10], b"test.com");
    }

    #[test]
    fn test_encode_socks_address_hostname_too_long() {
        let long_hostname = "a".repeat(256);
        let loc = NetLocation::new(Address::Hostname(long_hostname), 443);
        let mut buf = BytesMut::new();
        let result = encode_socks_address(&mut buf, &loc);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("hostname too long"));
    }

    #[test]
    fn test_decode_socks_address_ipv4() {
        let data = [0x01, 127, 0, 0, 1, 0x1F, 0x90]; // 127.0.0.1:8080
        let mut slice = &data[..];
        let loc = decode_socks_address(&mut slice).unwrap();

        assert!(matches!(loc.address(), Address::Ipv4(ip) if ip.octets() == [127, 0, 0, 1]));
        assert_eq!(loc.port(), 8080);
    }

    #[test]
    fn test_decode_socks_address_ipv6() {
        let mut data = vec![0x04]; // IPv6 type
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // ::1
        data.extend_from_slice(&[0x00, 0x50]); // port 80

        let mut slice = &data[..];
        let loc = decode_socks_address(&mut slice).unwrap();

        assert!(matches!(loc.address(), Address::Ipv6(_)));
        assert_eq!(loc.port(), 80);
    }
}
