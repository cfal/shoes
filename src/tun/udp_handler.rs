//! UDP Handler for direct packet processing.
//!
//! This module handles UDP packets directly without going through smoltcp,
//! since UDP is stateless and doesn't benefit from smoltcp's TCP state machine.
//!
//! We use smoltcp's wire types for parsing and etherparse for building packets.

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use etherparse::PacketBuilder;
use futures::{Sink, Stream, ready};
use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv6Packet, UdpPacket};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

pub type PacketBuffer = Vec<u8>;

/// UDP message: (payload, local_addr, remote_addr)
pub type UdpMessage = (Vec<u8>, SocketAddr, SocketAddr);

/// UDP handler for reading/writing UDP packets from/to TUN.
pub struct UdpHandler {
    /// Receiver for UDP packets from TUN
    from_tun_rx: UnboundedReceiver<PacketBuffer>,
    /// Sender for UDP packets to TUN
    to_tun_tx: UnboundedSender<PacketBuffer>,
}

impl UdpHandler {
    /// Create a new UDP handler.
    pub fn new(
        from_tun_rx: UnboundedReceiver<PacketBuffer>,
        to_tun_tx: UnboundedSender<PacketBuffer>,
    ) -> Self {
        Self {
            from_tun_rx,
            to_tun_tx,
        }
    }

    /// Split into read and write halves.
    pub fn split(self) -> (UdpReader, UdpWriter) {
        (
            UdpReader {
                from_tun_rx: self.from_tun_rx,
            },
            UdpWriter {
                to_tun_tx: self.to_tun_tx,
            },
        )
    }
}

/// Read half for receiving UDP packets.
pub struct UdpReader {
    from_tun_rx: UnboundedReceiver<PacketBuffer>,
}

/// Write half for sending UDP packets.
pub struct UdpWriter {
    to_tun_tx: UnboundedSender<PacketBuffer>,
}

impl Stream for UdpReader {
    type Item = UdpMessage;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match ready!(self.from_tun_rx.poll_recv(cx)) {
                Some(packet) => {
                    if let Some(msg) = parse_udp_packet(&packet) {
                        return Poll::Ready(Some(msg));
                    }
                    // Invalid packet, try next
                    continue;
                }
                None => return Poll::Ready(None),
            }
        }
    }
}

impl Sink<UdpMessage> for UdpWriter {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Unbounded channel is always ready
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: UdpMessage) -> Result<(), Self::Error> {
        let (payload, src_addr, dst_addr) = item;
        let packet = build_udp_packet(&payload, src_addr, dst_addr)?;
        self.to_tun_tx
            .send(packet)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "channel closed"))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

/// Parse a raw IP packet containing UDP data.
fn parse_udp_packet(packet: &[u8]) -> Option<UdpMessage> {
    if packet.is_empty() {
        return None;
    }

    // Determine IP version from first nibble
    let version = packet[0] >> 4;

    match version {
        4 => parse_ipv4_udp(packet),
        6 => parse_ipv6_udp(packet),
        _ => None,
    }
}

fn parse_ipv4_udp(packet: &[u8]) -> Option<UdpMessage> {
    let ip_packet = Ipv4Packet::new_checked(packet).ok()?;

    if ip_packet.next_header() != IpProtocol::Udp {
        return None;
    }

    let src_ip = ip_packet.src_addr();
    let dst_ip = ip_packet.dst_addr();
    let payload = ip_packet.payload();

    let udp_packet = UdpPacket::new_checked(payload).ok()?;
    let src_port = udp_packet.src_port();
    let dst_port = udp_packet.dst_port();

    let src_addr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            src_ip.octets()[0],
            src_ip.octets()[1],
            src_ip.octets()[2],
            src_ip.octets()[3],
        )),
        src_port,
    );
    let dst_addr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            dst_ip.octets()[0],
            dst_ip.octets()[1],
            dst_ip.octets()[2],
            dst_ip.octets()[3],
        )),
        dst_port,
    );

    Some((udp_packet.payload().to_vec(), src_addr, dst_addr))
}

fn parse_ipv6_udp(packet: &[u8]) -> Option<UdpMessage> {
    let ip_packet = Ipv6Packet::new_checked(packet).ok()?;

    if ip_packet.next_header() != IpProtocol::Udp {
        return None;
    }

    let src_ip = ip_packet.src_addr();
    let dst_ip = ip_packet.dst_addr();
    let payload = ip_packet.payload();

    let udp_packet = UdpPacket::new_checked(payload).ok()?;
    let src_port = udp_packet.src_port();
    let dst_port = udp_packet.dst_port();

    let src_addr = SocketAddr::new(
        std::net::IpAddr::V6(std::net::Ipv6Addr::from(src_ip.octets())),
        src_port,
    );
    let dst_addr = SocketAddr::new(
        std::net::IpAddr::V6(std::net::Ipv6Addr::from(dst_ip.octets())),
        dst_port,
    );

    Some((udp_packet.payload().to_vec(), src_addr, dst_addr))
}

/// Build a raw IP packet containing UDP data.
pub fn build_udp_packet(
    payload: &[u8],
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
) -> io::Result<PacketBuffer> {
    match (src_addr, dst_addr) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
            let builder = PacketBuilder::ipv4(
                src.ip().octets(),
                dst.ip().octets(),
                20, // TTL
            )
            .udp(src.port(), dst.port());

            let mut packet = Vec::with_capacity(builder.size(payload.len()));
            builder
                .write(&mut packet, payload)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            Ok(packet)
        }
        (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
            let builder = PacketBuilder::ipv6(
                src.ip().octets(),
                dst.ip().octets(),
                20, // Hop limit
            )
            .udp(src.port(), dst.port());

            let mut packet = Vec::with_capacity(builder.size(payload.len()));
            builder
                .write(&mut packet, payload)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            Ok(packet)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "IP version mismatch between source and destination",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_parse_ipv4_udp() {
        let payload = b"hello world";
        let src = "192.168.1.1:12345".parse().unwrap();
        let dst = "10.0.0.1:80".parse().unwrap();

        let packet = build_udp_packet(payload, src, dst).unwrap();
        let (parsed_payload, parsed_src, parsed_dst) = parse_udp_packet(&packet).unwrap();

        assert_eq!(parsed_payload, payload);
        assert_eq!(parsed_src, src);
        assert_eq!(parsed_dst, dst);
    }

    #[test]
    fn test_build_and_parse_ipv6_udp() {
        let payload = b"hello ipv6";
        let src: SocketAddr = "[2001:db8::1]:12345".parse().unwrap();
        let dst: SocketAddr = "[2001:db8::2]:80".parse().unwrap();

        let packet = build_udp_packet(payload, src, dst).unwrap();
        let (parsed_payload, parsed_src, parsed_dst) = parse_udp_packet(&packet).unwrap();

        assert_eq!(parsed_payload, payload);
        assert_eq!(parsed_src, src);
        assert_eq!(parsed_dst, dst);
    }
}
