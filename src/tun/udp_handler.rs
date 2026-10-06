//! UDP Handler for direct packet processing.
//!
//! This module handles UDP packets directly without going through smoltcp,
//! since UDP is stateless and doesn't benefit from smoltcp's TCP state machine.
//!
//! We use smoltcp's wire types for parsing and etherparse for building packets.

use std::{
    io,
    net::SocketAddr,
    ops::Range,
    pin::Pin,
    task::{Context, Poll},
};

use etherparse::PacketBuilder;
use futures::{Sink, Stream, ready};
use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv6Packet, UdpPacket};
use tokio::sync::mpsc::{Receiver, Sender, error::TrySendError};

use super::packet::PacketBuffer;
use super::wake::Wake;

/// UDP message: (payload, local_addr, remote_addr)
pub type UdpMessage = (PacketBuffer, SocketAddr, SocketAddr);

/// UDP handler for reading/writing UDP packets from/to TUN.
pub struct UdpHandler {
    /// Receiver for UDP packets from TUN
    from_tun_rx: Receiver<PacketBuffer>,
    /// Sender for UDP packets to TUN
    to_tun_tx: Sender<PacketBuffer>,
    wake: Wake,
}

impl UdpHandler {
    /// Create a new UDP handler.
    pub fn new(
        from_tun_rx: Receiver<PacketBuffer>,
        to_tun_tx: Sender<PacketBuffer>,
        wake: Wake,
    ) -> Self {
        Self {
            from_tun_rx,
            to_tun_tx,
            wake,
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
                wake: self.wake,
            },
        )
    }
}

/// Read half for receiving UDP packets.
pub struct UdpReader {
    from_tun_rx: Receiver<PacketBuffer>,
}

/// Write half for sending UDP packets.
pub struct UdpWriter {
    to_tun_tx: Sender<PacketBuffer>,
    wake: Wake,
}

impl UdpWriter {
    /// UDP is lossy: saturation drops a packet rather than retaining unbounded data.
    pub fn send_sync(&self, message: UdpMessage) -> io::Result<()> {
        let (payload, src_addr, dst_addr) = message;
        let packet = build_udp_packet(&payload, src_addr, dst_addr)?;
        match self.to_tun_tx.try_send(packet) {
            Ok(()) => {
                self.wake.notify();
                Ok(())
            }
            Err(TrySendError::Full(_)) => Ok(()),
            Err(TrySendError::Closed(_)) => {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "channel closed"))
            }
        }
    }
}

impl Stream for UdpReader {
    type Item = UdpMessage;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        while let Some(packet) = ready!(self.from_tun_rx.poll_recv(cx)) {
            if let Some(message) = parse_udp_packet(packet) {
                return Poll::Ready(Some(message));
            }
        }
        Poll::Ready(None)
    }
}

impl Sink<UdpMessage> for UdpWriter {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Saturated UDP output drops packets.
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: UdpMessage) -> Result<(), Self::Error> {
        self.send_sync(item)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

/// Parse a raw IP packet containing UDP data.
fn parse_udp_packet(mut packet: PacketBuffer) -> Option<UdpMessage> {
    let (range, src, dst) = match packet.first()? >> 4 {
        4 => parse_ipv4_udp(&packet),
        6 => parse_ipv6_udp(&packet),
        _ => None,
    }?;
    packet.retain_range(range);
    Some((packet, src, dst))
}

fn parse_ipv4_udp(packet: &[u8]) -> Option<(Range<usize>, SocketAddr, SocketAddr)> {
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

    let start = usize::from(ip_packet.header_len()) + 8;
    Some((
        start..start + udp_packet.payload().len(),
        src_addr,
        dst_addr,
    ))
}

fn parse_ipv6_udp(packet: &[u8]) -> Option<(Range<usize>, SocketAddr, SocketAddr)> {
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

    let start = 40 + 8;
    Some((
        start..start + udp_packet.payload().len(),
        src_addr,
        dst_addr,
    ))
}

/// Build a raw IP packet containing UDP data.
pub fn build_udp_packet(
    payload: &[u8],
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
) -> io::Result<PacketBuffer> {
    let builder = match (src_addr, dst_addr) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
            PacketBuilder::ipv4(
                src.ip().octets(),
                dst.ip().octets(),
                20, // TTL
            )
            .udp(src.port(), dst.port())
        }
        (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
            PacketBuilder::ipv6(
                src.ip().octets(),
                dst.ip().octets(),
                20, // Hop limit
            )
            .udp(src.port(), dst.port())
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IP version mismatch between source and destination",
            ));
        }
    };
    let packet_len = builder.size(payload.len());
    let mut packet = PacketBuffer::with_capacity(packet_len);
    packet.resize(packet_len);
    builder
        .write(&mut &mut packet[..], payload)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_skips_invalid_packets_before_pending_delivery_and_eof() {
        let (sender, from_tun_rx) = tokio::sync::mpsc::channel(2);
        let mut reader = UdpReader { from_tun_rx };
        let mut cx = Context::from_waker(std::task::Waker::noop());

        sender
            .try_send(PacketBuffer::copy_from_slice(&[0]))
            .unwrap();
        assert!(Pin::new(&mut reader).poll_next(&mut cx).is_pending());

        let src = "192.0.2.1:1234".parse().unwrap();
        let dst = "198.51.100.1:53".parse().unwrap();
        sender
            .try_send(PacketBuffer::copy_from_slice(&[0]))
            .unwrap();
        sender
            .try_send(build_udp_packet(b"payload", src, dst).unwrap())
            .unwrap();
        let Poll::Ready(Some((payload, actual_src, actual_dst))) =
            Pin::new(&mut reader).poll_next(&mut cx)
        else {
            panic!("queued UDP packet was not delivered");
        };
        assert_eq!(&*payload, b"payload");
        assert_eq!((actual_src, actual_dst), (src, dst));

        sender
            .try_send(PacketBuffer::copy_from_slice(&[0]))
            .unwrap();
        drop(sender);
        assert!(matches!(
            Pin::new(&mut reader).poll_next(&mut cx),
            Poll::Ready(None)
        ));
    }

    #[test]
    fn payload_ranges_preserve_ipv4_options_and_ignore_padding() {
        let src = "192.0.2.1:1234".parse().unwrap();
        let dst = "198.51.100.1:53".parse().unwrap();
        let mut bytes = build_udp_packet(b"payload", src, dst).unwrap().to_vec();
        bytes.splice(20..20, [0; 4]);
        bytes.extend_from_slice(b"padding");
        let length = bytes.len();
        let mut ip = Ipv4Packet::new_unchecked(&mut bytes);
        ip.set_header_len(24);
        ip.set_total_len(length as u16);
        ip.fill_checksum();
        let packet = PacketBuffer::copy_from_slice(&bytes);
        let pointer = packet.as_ptr();
        let (payload, actual_src, actual_dst) = parse_udp_packet(packet).unwrap();
        assert_eq!(payload.as_ptr(), pointer.wrapping_add(32));
        assert_eq!(&*payload, b"payload");
        assert_eq!((actual_src, actual_dst), (src, dst));
    }

    #[test]
    fn empty_udp_payloads_keep_addresses_for_both_families() {
        for (src, dst) in [
            ("192.0.2.1:1234", "198.51.100.1:53"),
            ("[2001:db8::1]:1234", "[2001:db8::2]:53"),
        ] {
            let (src, dst) = (src.parse().unwrap(), dst.parse().unwrap());
            let packet = build_udp_packet(b"", src, dst).unwrap();
            let (payload, actual_src, actual_dst) = parse_udp_packet(packet).unwrap();
            assert!(payload.is_empty());
            assert_eq!((actual_src, actual_dst), (src, dst));
        }
    }

    #[test]
    fn malformed_udp_lengths_do_not_create_payload_views() {
        let src = "192.0.2.1:1234".parse().unwrap();
        let dst = "198.51.100.1:53".parse().unwrap();
        for length in [7, 12] {
            let mut packet = build_udp_packet(b"abc", src, dst).unwrap();
            UdpPacket::new_unchecked(&mut packet[20..]).set_len(length);
            assert!(parse_udp_packet(packet).is_none());
        }
    }

    #[test]
    fn only_successful_response_enqueues_notify_the_stack() {
        use std::os::{fd::AsRawFd, unix::net::UnixStream};
        use std::time::Duration;
        use tokio::sync::mpsc;

        let (_peer, tun) = UnixStream::pair().unwrap();
        let (wake, mut receiver) = Wake::new().unwrap();
        let (_, input) = mpsc::channel(1);
        let (output, queued) = mpsc::channel(1);
        let (_, writer) = UdpHandler::new(input, output, wake).split();
        let message = || {
            (
                PacketBuffer::copy_from_slice(b"reply"),
                "1.1.1.1:53".parse().unwrap(),
                "10.0.0.2:1000".parse().unwrap(),
            )
        };
        writer.send_sync(message()).unwrap();
        assert!(
            receiver
                .wait(tun.as_raw_fd(), Some(Duration::ZERO))
                .unwrap()
        );
        receiver.drain().unwrap();
        writer.send_sync(message()).unwrap();
        assert_eq!(queued.len(), 1);
        assert!(
            !receiver
                .wait(tun.as_raw_fd(), Some(Duration::ZERO))
                .unwrap()
        );
        drop(queued);
        assert_eq!(
            writer.send_sync(message()).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert!(
            !receiver
                .wait(tun.as_raw_fd(), Some(Duration::ZERO))
                .unwrap()
        );
    }

    #[test]
    fn test_build_and_parse_ipv4_udp() {
        let payload = b"hello world";
        let src = "192.168.1.1:12345".parse().unwrap();
        let dst = "10.0.0.1:80".parse().unwrap();

        let packet = build_udp_packet(payload, src, dst).unwrap();
        let (parsed_payload, parsed_src, parsed_dst) = parse_udp_packet(packet).unwrap();

        assert_eq!(&*parsed_payload, payload);
        assert_eq!(parsed_src, src);
        assert_eq!(parsed_dst, dst);
    }

    #[test]
    fn test_build_and_parse_ipv6_udp() {
        let payload = b"hello ipv6";
        let src: SocketAddr = "[2001:db8::1]:12345".parse().unwrap();
        let dst: SocketAddr = "[2001:db8::2]:80".parse().unwrap();

        let packet = build_udp_packet(payload, src, dst).unwrap();
        let (parsed_payload, parsed_src, parsed_dst) = parse_udp_packet(packet).unwrap();

        assert_eq!(&*parsed_payload, payload);
        assert_eq!(parsed_src, src);
        assert_eq!(parsed_dst, dst);
    }
}
