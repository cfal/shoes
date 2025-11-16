//! UDP-over-TCP V1 stream implementation
//!
//! V1 Packet format (each packet has full address):
//! ```text
//! | ATYP | address  | port  | length | data     |
//! | u8   | variable | u16be | u16be  | variable |
//! ```

use futures::ready;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::address::{Address, NetLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncPing, AsyncReadTargetedMessage, AsyncShutdownMessage, AsyncStream,
    AsyncTargetedMessageStream, AsyncWriteSourcedMessage,
};
use crate::slide_buffer::SlideBuffer;

/// ATYP values for UoT (different from SOCKS5!)
const ATYP_IPV4: u8 = 0x00;
const ATYP_IPV6: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;

/// Buffer size for reading/writing UoT packets
const BUFFER_SIZE: usize = 65535;

/// UoT V1 stream for multi-destination UDP packets
///
/// Each packet includes the full destination address, making it suitable
/// for applications that send UDP packets to multiple destinations.
///
/// This stream wraps an `AsyncStream` (raw byte stream) and handles
/// UoT packet framing internally.
pub struct UotV1Stream {
    stream: Box<dyn AsyncStream>,

    /// Buffer for reading - accumulates bytes until we have a complete packet
    read_buf: SlideBuffer,

    /// Buffer for writing - holds a complete packet before sending
    write_buf: [u8; BUFFER_SIZE],
    write_buf_len: usize,
    write_buf_sent: usize,

    is_eof: bool,
}

impl UotV1Stream {
    pub fn new(stream: Box<dyn AsyncStream>) -> Self {
        Self {
            stream,
            read_buf: SlideBuffer::new(BUFFER_SIZE),
            write_buf: [0u8; BUFFER_SIZE],
            write_buf_len: 0,
            write_buf_sent: 0,
            is_eof: false,
        }
    }

    /// Feed initial data that was read before the stream was created.
    /// This is needed when the first UoT packet arrives in the same TCP segment
    /// as the magic address header.
    pub fn feed_initial_data(&mut self, data: &[u8]) {
        if !data.is_empty() {
            let len = data.len().min(self.read_buf.remaining_capacity());
            self.read_buf.extend_from_slice(&data[..len]);
        }
    }

    /// Try to parse a complete UoT packet from the read buffer.
    /// Returns Some((location, payload_start, payload_len)) if a complete packet is available.
    fn try_parse_packet(&self) -> Option<(NetLocation, usize, usize)> {
        let data = self.read_buf.as_slice();
        if data.is_empty() {
            return None;
        }

        // Parse address to determine header length
        let (location, addr_len) = parse_uot_address(data).ok()?;

        // Need at least addr_len + 2 (length prefix) bytes
        if data.len() < addr_len + 2 {
            return None;
        }

        // Read length prefix
        let payload_len = u16::from_be_bytes([data[addr_len], data[addr_len + 1]]) as usize;
        let payload_start = addr_len + 2;
        let total_len = payload_start + payload_len;

        // Check if we have the complete packet
        if data.len() < total_len {
            return None;
        }

        Some((location, payload_start, payload_len))
    }
}

/// Parse UoT address format (ATYP + address + port)
/// Returns (NetLocation, bytes consumed)
fn parse_uot_address(data: &[u8]) -> std::io::Result<(NetLocation, usize)> {
    if data.is_empty() {
        return Err(std::io::Error::other("empty UoT address"));
    }

    let atyp = data[0];
    match atyp {
        ATYP_IPV4 => {
            // ATYP(1) + IPv4(4) + Port(2) = 7 bytes
            if data.len() < 7 {
                return Err(std::io::Error::other("UoT IPv4 address truncated"));
            }
            let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok((NetLocation::new(Address::Ipv4(ip), port), 7))
        }
        ATYP_IPV6 => {
            // ATYP(1) + IPv6(16) + Port(2) = 19 bytes
            if data.len() < 19 {
                return Err(std::io::Error::other("UoT IPv6 address truncated"));
            }
            let ip_bytes: [u8; 16] = data[1..17].try_into().unwrap();
            let ip = Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok((NetLocation::new(Address::Ipv6(ip), port), 19))
        }
        ATYP_DOMAIN => {
            // ATYP(1) + DomainLen(1) + Domain(variable) + Port(2)
            if data.len() < 2 {
                return Err(std::io::Error::other("UoT domain length truncated"));
            }
            let domain_len = data[1] as usize;
            let total_len = 1 + 1 + domain_len + 2; // ATYP + len + domain + port
            if data.len() < total_len {
                return Err(std::io::Error::other("UoT domain address truncated"));
            }
            let domain = std::str::from_utf8(&data[2..2 + domain_len])
                .map_err(|e| std::io::Error::other(format!("invalid domain: {e}")))?;
            let port = u16::from_be_bytes([data[2 + domain_len], data[3 + domain_len]]);
            Ok((
                NetLocation::new(Address::Hostname(domain.to_string()), port),
                total_len,
            ))
        }
        _ => Err(std::io::Error::other(format!("unknown UoT ATYP: {atyp}"))),
    }
}

/// Write UoT address format (ATYP + address + port)
/// Returns number of bytes written
fn write_uot_address(buf: &mut [u8], addr: &SocketAddr) -> usize {
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

impl AsyncReadTargetedMessage for UotV1Stream {
    fn poll_read_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>> {
        let this = self.get_mut();

        if this.is_eof {
            return Poll::Ready(Ok(NetLocation::UNSPECIFIED));
        }

        loop {
            // Try to parse a complete packet from buffered data
            if let Some((location, payload_start, payload_len)) = this.try_parse_packet() {
                let data = this.read_buf.as_slice();
                buf.put_slice(&data[payload_start..payload_start + payload_len]);

                // Consume the entire packet from the buffer
                let total_consumed = payload_start + payload_len;
                this.read_buf.consume(total_consumed);

                return Poll::Ready(Ok(location));
            }

            // Need more data - compact buffer if needed
            this.read_buf.maybe_compact(4096);

            if this.read_buf.remaining_capacity() == 0 {
                return Poll::Ready(Err(std::io::Error::other(
                    "UoT read buffer full but no complete packet",
                )));
            }

            // Read more data from the underlying stream
            let write_slice = this.read_buf.write_slice();
            let mut read_buf = ReadBuf::new(write_slice);

            match Pin::new(&mut this.stream).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let bytes_read = read_buf.filled().len();
                    if bytes_read == 0 {
                        this.is_eof = true;
                        return Poll::Ready(Ok(NetLocation::UNSPECIFIED));
                    }
                    this.read_buf.advance_write(bytes_read);
                    // Loop to try parsing again
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWriteSourcedMessage for UotV1Stream {
    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // If there's pending data to send, flush it first
        while this.write_buf_sent < this.write_buf_len {
            let remaining = &this.write_buf[this.write_buf_sent..this.write_buf_len];
            match Pin::new(&mut this.stream).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    this.write_buf_sent += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Reset write buffer
        this.write_buf_len = 0;
        this.write_buf_sent = 0;

        // Calculate required space: address + length(2) + payload
        let addr_len = match source {
            SocketAddr::V4(_) => 7,  // ATYP + IPv4(4) + Port(2)
            SocketAddr::V6(_) => 19, // ATYP + IPv6(16) + Port(2)
        };
        let total_len = addr_len + 2 + buf.len();

        if total_len > this.write_buf.len() {
            return Poll::Ready(Err(std::io::Error::other(format!(
                "UoT packet too large: {total_len} > {}",
                this.write_buf.len()
            ))));
        }

        // Write UoT address format
        let offset = write_uot_address(&mut this.write_buf, source);

        // Write length prefix (u16be)
        let len_bytes = (buf.len() as u16).to_be_bytes();
        this.write_buf[offset..offset + 2].copy_from_slice(&len_bytes);
        let data_start = offset + 2;

        // Write payload
        this.write_buf[data_start..data_start + buf.len()].copy_from_slice(buf);
        this.write_buf_len = data_start + buf.len();

        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for UotV1Stream {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Flush any pending write data
        while this.write_buf_sent < this.write_buf_len {
            let remaining = &this.write_buf[this.write_buf_sent..this.write_buf_len];
            match Pin::new(&mut this.stream).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    this.write_buf_sent += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        this.write_buf_len = 0;
        this.write_buf_sent = 0;

        // Flush the underlying stream
        Pin::new(&mut this.stream).poll_flush(cx)
    }
}

impl AsyncShutdownMessage for UotV1Stream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.get_mut();
        ready!(Pin::new(&mut this).poll_flush_message(cx))?;
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

impl AsyncPing for UotV1Stream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncTargetedMessageStream for UotV1Stream {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uot_ipv4_address() {
        // ATYP=0x00, IP=192.168.1.1, Port=8080
        let data = [0x00, 192, 168, 1, 1, 0x1F, 0x90];
        let (location, len) = parse_uot_address(&data).unwrap();
        assert_eq!(len, 7);
        assert_eq!(location.port(), 8080);
        match location.address() {
            Address::Ipv4(ip) => assert_eq!(*ip, Ipv4Addr::new(192, 168, 1, 1)),
            _ => panic!("expected IPv4"),
        }
    }

    #[test]
    fn test_parse_uot_ipv6_address() {
        // ATYP=0x01, IP=::1, Port=443
        let mut data = vec![ATYP_IPV6];
        data.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        data.extend_from_slice(&443u16.to_be_bytes());

        let (location, len) = parse_uot_address(&data).unwrap();
        assert_eq!(len, 19);
        assert_eq!(location.port(), 443);
        match location.address() {
            Address::Ipv6(ip) => assert_eq!(*ip, Ipv6Addr::LOCALHOST),
            _ => panic!("expected IPv6"),
        }
    }

    #[test]
    fn test_parse_uot_domain_address() {
        // ATYP=0x02, Domain="example.com", Port=53
        let domain = b"example.com";
        let mut data = vec![ATYP_DOMAIN, domain.len() as u8];
        data.extend_from_slice(domain);
        data.extend_from_slice(&53u16.to_be_bytes());

        let (location, len) = parse_uot_address(&data).unwrap();
        assert_eq!(len, 1 + 1 + domain.len() + 2);
        assert_eq!(location.port(), 53);
        match location.address() {
            Address::Hostname(h) => assert_eq!(h, "example.com"),
            _ => panic!("expected hostname"),
        }
    }

    #[test]
    fn test_write_uot_ipv4_address() {
        let addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let mut buf = [0u8; 32];
        let len = write_uot_address(&mut buf, &addr);
        assert_eq!(len, 7);
        assert_eq!(buf[0], ATYP_IPV4);
        assert_eq!(&buf[1..5], &[192, 168, 1, 1]);
        assert_eq!(&buf[5..7], &0x1F90u16.to_be_bytes());
    }

    #[test]
    fn test_write_uot_ipv6_address() {
        let addr: SocketAddr = "[::1]:443".parse().unwrap();
        let mut buf = [0u8; 32];
        let len = write_uot_address(&mut buf, &addr);
        assert_eq!(len, 19);
        assert_eq!(buf[0], ATYP_IPV6);
        assert_eq!(&buf[1..17], &Ipv6Addr::LOCALHOST.octets());
        assert_eq!(&buf[17..19], &443u16.to_be_bytes());
    }
}
