//! SOCKS5 UDP relay implementation.
//!
//! This module provides UDP relay functionality for SOCKS5 UDP ASSOCIATE.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::ready;
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::address::{Address, NetLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncPing, AsyncReadTargetedMessage, AsyncShutdownMessage,
    AsyncTargetedMessageStream, AsyncWriteSourcedMessage,
};
use crate::socks_handler::{ADDR_TYPE_DOMAIN_NAME, ADDR_TYPE_IPV4, ADDR_TYPE_IPV6};

/// Minimum SOCKS5 UDP header size: RSV(2) + FRAG(1) + ATYP(1) + min_addr(4 for IPv4) + PORT(2) = 10
const MIN_HEADER_SIZE: usize = 10;

/// Maximum UDP packet size
const MAX_UDP_SIZE: usize = 65535;

/// Parse a SOCKS5 UDP packet header, returning the target location and payload slice.
///
/// Packet format:
/// ```text
/// +------+------+------+----------+----------+----------+
/// | RSV  | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +------+------+------+----------+----------+----------+
/// |  2   |  1   |  1   | Variable |    2     | Variable |
/// +------+------+------+----------+----------+----------+
/// ```
pub fn parse_socks5_udp_packet(data: &[u8]) -> std::io::Result<(NetLocation, &[u8])> {
    if data.len() < MIN_HEADER_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("SOCKS5 UDP packet too short: {} bytes", data.len()),
        ));
    }

    // RSV must be 0x0000
    if data[0] != 0 || data[1] != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SOCKS5 UDP packet has non-zero reserved bytes",
        ));
    }

    // FRAG must be 0 (we don't support fragmentation)
    let frag = data[2];
    if frag != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("SOCKS5 UDP fragmentation not supported (frag={})", frag),
        ));
    }

    let atyp = data[3];
    let (address, header_len) = match atyp {
        ADDR_TYPE_IPV4 => {
            // 4 bytes for IPv4 + 2 bytes for port
            if data.len() < 4 + 4 + 2 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "SOCKS5 UDP packet too short for IPv4 address",
                ));
            }
            let addr = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            let port = u16::from_be_bytes([data[8], data[9]]);
            (NetLocation::new(Address::Ipv4(addr), port), 10)
        }
        ADDR_TYPE_IPV6 => {
            // 16 bytes for IPv6 + 2 bytes for port
            if data.len() < 4 + 16 + 2 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "SOCKS5 UDP packet too short for IPv6 address",
                ));
            }
            let addr = Ipv6Addr::new(
                u16::from_be_bytes([data[4], data[5]]),
                u16::from_be_bytes([data[6], data[7]]),
                u16::from_be_bytes([data[8], data[9]]),
                u16::from_be_bytes([data[10], data[11]]),
                u16::from_be_bytes([data[12], data[13]]),
                u16::from_be_bytes([data[14], data[15]]),
                u16::from_be_bytes([data[16], data[17]]),
                u16::from_be_bytes([data[18], data[19]]),
            );
            let port = u16::from_be_bytes([data[20], data[21]]);
            (NetLocation::new(Address::Ipv6(addr), port), 22)
        }
        ADDR_TYPE_DOMAIN_NAME => {
            // 1 byte length + domain + 2 bytes port
            if data.len() < 5 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "SOCKS5 UDP packet too short for domain length",
                ));
            }
            let domain_len = data[4] as usize;
            let header_len = 4 + 1 + domain_len + 2;
            if data.len() < header_len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "SOCKS5 UDP packet too short for domain (need {}, have {})",
                        header_len,
                        data.len()
                    ),
                ));
            }
            let domain = std::str::from_utf8(&data[5..5 + domain_len]).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid UTF-8 in domain name: {}", e),
                )
            })?;
            let port_offset = 5 + domain_len;
            let port = u16::from_be_bytes([data[port_offset], data[port_offset + 1]]);
            (
                NetLocation::new(Address::Hostname(domain.to_string()), port),
                header_len,
            )
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unknown SOCKS5 address type: {}", atyp),
            ));
        }
    };

    Ok((address, &data[header_len..]))
}

/// Encode a SOCKS5 UDP packet with the given source address and payload.
///
/// Returns the complete packet ready to send to the client.
pub fn encode_socks5_udp_packet(source: &NetLocation, payload: &[u8]) -> Vec<u8> {
    let (address, port) = source.components();

    let addr_size = match address {
        Address::Ipv4(_) => 1 + 4,               // ATYP + 4 bytes
        Address::Ipv6(_) => 1 + 16,              // ATYP + 16 bytes
        Address::Hostname(h) => 1 + 1 + h.len(), // ATYP + len + domain
    };
    let header_size = 2 + 1 + addr_size + 2; // RSV + FRAG + addr + PORT
    let mut packet = Vec::with_capacity(header_size + payload.len());

    packet.extend_from_slice(&[0, 0, 0]); // RSV + FRAG

    match address {
        Address::Ipv4(addr) => {
            packet.push(ADDR_TYPE_IPV4);
            packet.extend_from_slice(&addr.octets());
        }
        Address::Ipv6(addr) => {
            packet.push(ADDR_TYPE_IPV6);
            packet.extend_from_slice(&addr.octets());
        }
        Address::Hostname(domain) => {
            packet.push(ADDR_TYPE_DOMAIN_NAME);
            packet.push(domain.len() as u8);
            packet.extend_from_slice(domain.as_bytes());
        }
    }

    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend_from_slice(payload);

    packet
}

/// SOCKS5 UDP relay stream.
///
/// This stream wraps a UDP socket and handles SOCKS5 UDP packet framing.
/// It implements `AsyncTargetedMessageStream` for use with the proxy chain.
///
/// - Reading: Receives SOCKS5-framed UDP packets from the client, parses the header,
///   and returns the payload with the target address.
/// - Writing: Takes a payload and source address, encodes it as a SOCKS5 UDP packet,
///   and sends it to the client.
pub struct Socks5UdpRelayStream {
    socket: Arc<UdpSocket>,
    /// The client's UDP address, learned from the first received packet.
    client_addr: Option<SocketAddr>,
    /// Receiver for incoming packets from the socket reader task.
    receiver: mpsc::Receiver<(Box<[u8]>, SocketAddr)>,
    /// Handle to the socket reader task.
    reader_task: Option<tokio::task::JoinHandle<()>>,
}

impl Socks5UdpRelayStream {
    /// Create a new SOCKS5 UDP relay stream.
    ///
    /// # Arguments
    /// * `socket` - The bound UDP socket for the relay
    pub fn new(socket: UdpSocket) -> Self {
        let socket = Arc::new(socket);
        let local_addr = socket.local_addr().ok();
        log::debug!(
            "SOCKS5 UDP relay: creating Socks5UdpRelayStream at {:?}",
            local_addr
        );
        let (tx, rx) = mpsc::channel(64);
        let recv_socket = socket.clone();
        let reader_task = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_SIZE];
            loop {
                match recv_socket.recv_from(&mut buf).await {
                    Ok((n, from_addr)) => {
                        log::debug!("SOCKS5 UDP relay: received {} bytes from {}", n, from_addr);
                        let packet = buf[..n].to_vec().into_boxed_slice();
                        if tx.send((packet, from_addr)).await.is_err() {
                            // Channel closed, stop reading
                            log::debug!("SOCKS5 UDP relay: channel closed, stopping reader");
                            break;
                        }
                    }
                    Err(e) => {
                        log::debug!("SOCKS5 UDP relay recv error: {}", e);
                        break;
                    }
                }
            }
        });

        Self {
            socket,
            client_addr: None,
            receiver: rx,
            reader_task: Some(reader_task),
        }
    }
}

impl AsyncReadTargetedMessage for Socks5UdpRelayStream {
    fn poll_read_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>> {
        let this = self.get_mut();

        match Pin::new(&mut this.receiver).poll_recv(cx) {
            Poll::Ready(Some((packet, from_addr))) => {
                // Learn/verify client address
                if let Some(expected) = this.client_addr {
                    if from_addr != expected {
                        // Packet from unexpected source, ignore
                        log::debug!(
                            "SOCKS5 UDP relay: ignoring packet from {} (expected {})",
                            from_addr,
                            expected
                        );
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                } else {
                    // Learn client address from first packet
                    log::debug!("SOCKS5 UDP relay: learned client address: {}", from_addr);
                    this.client_addr = Some(from_addr);
                }

                match parse_socks5_udp_packet(&packet) {
                    Ok((target, payload)) => {
                        log::debug!(
                            "SOCKS5 UDP relay: parsed packet, target={}, payload_len={}",
                            target,
                            payload.len()
                        );
                        // Skip empty payloads - the copy loop interprets 0-byte reads as EOF
                        if payload.is_empty() {
                            log::debug!("SOCKS5 UDP relay: skipping empty payload");
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        if payload.len() > buf.remaining() {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!(
                                    "UDP payload too large: {} > {}",
                                    payload.len(),
                                    buf.remaining()
                                ),
                            )));
                        }
                        buf.put_slice(payload);
                        Poll::Ready(Ok(target))
                    }
                    Err(e) => {
                        log::debug!("SOCKS5 UDP relay: failed to parse packet: {}", e);
                        // Try to get another packet
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
            }
            Poll::Ready(None) => {
                log::debug!("SOCKS5 UDP relay: channel closed (receiver got None)");
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "UDP relay channel closed",
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWriteSourcedMessage for Socks5UdpRelayStream {
    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        let client_addr = match this.client_addr {
            Some(addr) => addr,
            None => {
                log::debug!("SOCKS5 UDP relay: cannot write, no client address learned yet");
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "No client address learned yet",
                )));
            }
        };

        // Convert SocketAddr to NetLocation for encoding.
        // Handle IPv4-mapped IPv6 addresses (::ffff:w.x.y.z) by converting back to IPv4.
        let source_ip = source.ip();
        let address = match source_ip {
            IpAddr::V4(v4) => Address::Ipv4(v4),
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    Address::Ipv4(v4)
                } else {
                    Address::Ipv6(v6)
                }
            }
        };
        let source_location = NetLocation::new(address, source.port());
        let packet = encode_socks5_udp_packet(&source_location, buf);

        log::debug!(
            "SOCKS5 UDP relay: sending {} byte response from {} to client {}",
            packet.len(),
            source_location,
            client_addr
        );

        ready!(this.socket.poll_send_to(cx, &packet, client_addr))?;
        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for Socks5UdpRelayStream {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        // UDP doesn't need flushing
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for Socks5UdpRelayStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Some(handle) = this.reader_task.take() {
            handle.abort();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for Socks5UdpRelayStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncTargetedMessageStream for Socks5UdpRelayStream {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_packet() {
        // RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + PORT(2) + DATA
        let packet = [
            0x00, 0x00, // RSV
            0x00, // FRAG
            0x01, // ATYP = IPv4
            0x08, 0x08, 0x08, 0x08, // 8.8.8.8
            0x00, 0x35, // port 53
            0x48, 0x65, 0x6c, 0x6c, 0x6f, // "Hello"
        ];

        let (location, payload) = parse_socks5_udp_packet(&packet).unwrap();
        assert_eq!(
            location.address(),
            &Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8))
        );
        assert_eq!(location.port(), 53);
        assert_eq!(payload, b"Hello");
    }

    #[test]
    fn test_parse_ipv6_packet() {
        // RSV(2) + FRAG(1) + ATYP(1) + IPv6(16) + PORT(2) + DATA
        let mut packet = vec![
            0x00, 0x00, // RSV
            0x00, // FRAG
            0x04, // ATYP = IPv6
        ];
        // 2001:4860:4860::8888
        packet.extend_from_slice(&[
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x88, 0x88,
        ]);
        packet.extend_from_slice(&[0x00, 0x35]); // port 53
        packet.extend_from_slice(b"Hello");

        let (location, payload) = parse_socks5_udp_packet(&packet).unwrap();
        assert!(matches!(location.address(), Address::Ipv6(_)));
        assert_eq!(location.port(), 53);
        assert_eq!(payload, b"Hello");
    }

    #[test]
    fn test_parse_domain_packet() {
        // RSV(2) + FRAG(1) + ATYP(1) + LEN(1) + DOMAIN + PORT(2) + DATA
        let mut packet = vec![
            0x00, 0x00, // RSV
            0x00, // FRAG
            0x03, // ATYP = domain
            0x0b, // length = 11
        ];
        packet.extend_from_slice(b"example.com");
        packet.extend_from_slice(&[0x00, 0x50]); // port 80
        packet.extend_from_slice(b"GET /");

        let (location, payload) = parse_socks5_udp_packet(&packet).unwrap();
        assert_eq!(
            location.address(),
            &Address::Hostname("example.com".to_string())
        );
        assert_eq!(location.port(), 80);
        assert_eq!(payload, b"GET /");
    }

    #[test]
    fn test_encode_ipv4_packet() {
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        let packet = encode_socks5_udp_packet(&location, b"Hello");

        // Verify by parsing it back
        let (parsed_loc, payload) = parse_socks5_udp_packet(&packet).unwrap();
        assert_eq!(parsed_loc.address(), location.address());
        assert_eq!(parsed_loc.port(), location.port());
        assert_eq!(payload, b"Hello");
    }

    #[test]
    fn test_roundtrip_domain() {
        let location = NetLocation::new(Address::Hostname("dns.google".to_string()), 443);
        let original_payload = b"test data";
        let packet = encode_socks5_udp_packet(&location, original_payload);

        let (parsed_loc, payload) = parse_socks5_udp_packet(&packet).unwrap();
        assert_eq!(parsed_loc.address(), location.address());
        assert_eq!(parsed_loc.port(), location.port());
        assert_eq!(payload, original_payload);
    }

    #[test]
    fn test_reject_fragmented() {
        let packet = [
            0x00, 0x00, // RSV
            0x01, // FRAG = 1 (fragmented!)
            0x01, // ATYP = IPv4
            0x08, 0x08, 0x08, 0x08, 0x00, 0x35, 0x48, 0x65, 0x6c, 0x6c, 0x6f,
        ];

        let result = parse_socks5_udp_packet(&packet);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("fragmentation"));
    }

    #[test]
    fn test_reject_bad_reserved() {
        let packet = [
            0x00, 0x01, // RSV = bad!
            0x00, 0x01, 0x08, 0x08, 0x08, 0x08, 0x00, 0x35,
        ];

        let result = parse_socks5_udp_packet(&packet);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("reserved"));
    }
}
