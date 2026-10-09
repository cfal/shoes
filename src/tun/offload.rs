use std::{io, num::NonZeroU16};

use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket, checksum};

pub(super) const HEADER_LEN: usize = 10;
pub(super) const MAX_PACKET_LEN: usize = u16::MAX as usize;

const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
const VIRTIO_NET_HDR_F_DATA_VALID: u8 = 2;
const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
const TCP_CHECKSUM_OFFSET: u16 = 16;

#[cfg(target_os = "linux")]
pub(super) fn configure(fd: std::os::fd::RawFd) -> io::Result<()> {
    let size: libc::c_int = HEADER_LEN as _;
    let little_endian: libc::c_int = 1;
    // TUNSETOFFLOAD controls kernel-to-userspace traffic, not GSO writes.
    // Keep reads segmented and checksummed by the kernel.
    if unsafe { libc::ioctl(fd, libc::TUNSETVNETHDRSZ, &size) } < 0
        || unsafe { libc::ioctl(fd, libc::TUNSETVNETLE, &little_endian) } < 0
        || unsafe { libc::ioctl(fd, libc::TUNSETOFFLOAD, 0 as libc::c_ulong) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut actual: libc::c_int = 0;
    if unsafe { libc::ioctl(fd, libc::TUNGETVNETHDRSZ, &mut actual) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if actual != size {
        return Err(invalid("unexpected TUN virtio header size"));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(super) fn validate_rx(frame: &[u8], mtu: usize) -> io::Result<()> {
    if frame.len() <= HEADER_LEN || frame.len() > HEADER_LEN + mtu {
        return Err(invalid("invalid TUN virtio packet length"));
    }
    // DATA_VALID is harmless, but partial checksums and receive GSO were not negotiated.
    if frame[0] & !VIRTIO_NET_HDR_F_DATA_VALID != 0 || frame[1] != VIRTIO_NET_HDR_GSO_NONE {
        return Err(invalid("unexpected TUN receive offload"));
    }
    Ok(())
}

pub(super) fn tx_header(
    packet: &mut [u8],
    segment_size: Option<NonZeroU16>,
) -> io::Result<[u8; HEADER_LEN]> {
    let mut header = [0; HEADER_LEN];
    if packet.is_empty() || packet.len() > MAX_PACKET_LEN {
        return Err(invalid("invalid TUN offload packet length"));
    }
    let (transport_offset, protocol, source, destination) = match packet[0] >> 4 {
        4 => {
            let ip =
                Ipv4Packet::new_checked(&*packet).map_err(|_| invalid("invalid IPv4 packet"))?;
            if usize::from(ip.total_len()) != packet.len()
                || ip.more_frags()
                || ip.frag_offset() != 0
            {
                return Err(invalid("invalid IPv4 offload length or fragmentation"));
            }
            (
                usize::from(ip.header_len()),
                ip.next_header(),
                IpAddress::Ipv4(ip.src_addr()),
                IpAddress::Ipv4(ip.dst_addr()),
            )
        }
        6 if segment_size.is_none() => {
            let ip =
                Ipv6Packet::new_checked(&*packet).map_err(|_| invalid("invalid IPv6 packet"))?;
            if usize::from(ip.payload_len()) + 40 != packet.len() {
                return Err(invalid("invalid IPv6 offload length"));
            }
            (
                40,
                ip.next_header(),
                IpAddress::Ipv6(ip.src_addr()),
                IpAddress::Ipv6(ip.dst_addr()),
            )
        }
        _ => return Err(invalid("unsupported IP version for TUN segmentation")),
    };
    if protocol != IpProtocol::Tcp {
        if segment_size.is_some() {
            return Err(invalid("segmentation metadata on non-TCP packet"));
        }
        return Ok(header);
    }
    let tcp_len = packet.len() - transport_offset;
    let mut tcp = TcpPacket::new_checked(&mut packet[transport_offset..])
        .map_err(|_| invalid("invalid TCP packet"))?;
    let headers_len = transport_offset + usize::from(tcp.header_len());
    tcp.set_checksum(checksum::pseudo_header(
        &source,
        &destination,
        IpProtocol::Tcp,
        tcp_len as u32,
    ));
    header[0] = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    header[6..8].copy_from_slice(&(transport_offset as u16).to_le_bytes());
    header[8..10].copy_from_slice(&TCP_CHECKSUM_OFFSET.to_le_bytes());
    if let Some(size) = segment_size {
        if headers_len + usize::from(size.get()) >= packet.len() {
            return Err(invalid("segmentation metadata without multiple segments"));
        }
        header[1] = VIRTIO_NET_HDR_GSO_TCPV4;
        header[2..4].copy_from_slice(&(headers_len as u16).to_le_bytes());
        header[4..6].copy_from_slice(&size.get().to_le_bytes());
    }
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn negotiation_failure_preserves_descriptor_ownership() {
        use std::os::fd::AsRawFd;
        let (peer, device) = std::os::unix::net::UnixDatagram::pair().unwrap();
        assert!(configure(device.as_raw_fd()).is_err());
        peer.send(b"intact").unwrap();
        let mut data = [0; 16];
        let n = device.recv(&mut data).unwrap();
        assert_eq!(&data[..n], b"intact");
    }

    fn finish_checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        for chunk in bytes.chunks(2) {
            sum += u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]) as u32;
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn partial_checksums_match_independent_packet_builder() {
        for ipv6 in [false, true] {
            for length in [0, 1, 1200, 4097, 60_001] {
                let builder = if ipv6 {
                    etherparse::PacketBuilder::ipv6([0x21; 16], [0x43; 16], 64)
                } else {
                    etherparse::PacketBuilder::ipv4([192, 0, 2, 1], [198, 51, 100, 2], 64)
                };
                let data: Vec<_> = (0..length).map(|i| (i ^ (i >> 8)) as u8).collect();
                let mut packet = Vec::new();
                builder
                    .tcp(1001, 443, u32::MAX - 20, 65535)
                    .ack(87)
                    .psh()
                    .options(&[etherparse::TcpOptionElement::Timestamp(17, 23)])
                    .unwrap()
                    .write(&mut packet, &data)
                    .unwrap();
                let start = if ipv6 { 40 } else { 20 };
                let expected =
                    u16::from_be_bytes(packet[start + 16..start + 18].try_into().unwrap());
                let segment = if !ipv6 && length > 1460 {
                    NonZeroU16::new(1460)
                } else {
                    None
                };
                let header = tx_header(&mut packet, segment).unwrap();
                assert_eq!(header[0], 1);
                assert_eq!(
                    u16::from_le_bytes(header[6..8].try_into().unwrap()) as usize,
                    start
                );
                assert_eq!(u16::from_le_bytes(header[8..10].try_into().unwrap()), 16);
                assert_eq!(finish_checksum(&packet[start..]), expected);
                assert_eq!(header[1], u8::from(segment.is_some()));
                if segment.is_some() {
                    assert_eq!(u16::from_le_bytes(header[4..6].try_into().unwrap()), 1460);
                    assert_eq!(
                        u16::from_le_bytes(header[2..4].try_into().unwrap()) as usize,
                        start + 32
                    );
                }
            }
        }
    }

    #[test]
    fn receive_headers_reject_unnegotiated_offload_and_truncation() {
        for length in 0..=HEADER_LEN {
            assert!(validate_rx(&vec![0; length], 1500).is_err());
        }
        let mut frame = vec![0; HEADER_LEN + 1500];
        validate_rx(&frame, 1500).unwrap();
        frame[0] = 2;
        validate_rx(&frame, 1500).unwrap();
        for flag in [1, 3, 4, 128] {
            frame[0] = flag;
            assert!(validate_rx(&frame, 1500).is_err());
        }
        frame[0] = 0;
        for kind in [1, 3, 4, 5, 129] {
            frame[1] = kind;
            assert!(validate_rx(&frame, 1500).is_err());
        }
        frame[1] = 0;
        frame.push(0);
        assert!(validate_rx(&frame, 1500).is_err());
    }

    #[test]
    fn non_tcp_packets_keep_software_checksums_and_zero_headers() {
        let mut packet = Vec::new();
        etherparse::PacketBuilder::ipv4([192, 0, 2, 1], [198, 51, 100, 2], 64)
            .udp(1001, 53)
            .write(&mut packet, b"dns")
            .unwrap();
        let original = packet.clone();
        assert_eq!(tx_header(&mut packet, None).unwrap(), [0; HEADER_LEN]);
        assert_eq!(packet, original);
        assert!(tx_header(&mut packet, NonZeroU16::new(1)).is_err());
    }

    #[test]
    fn malformed_transmit_packets_are_rejected() {
        for length in 0..40 {
            assert!(tx_header(&mut vec![0x45; length], NonZeroU16::new(1460)).is_err());
        }
        assert!(tx_header(&mut vec![0; MAX_PACKET_LEN + 1], None).is_err());
        let mut packet = Vec::new();
        etherparse::PacketBuilder::ipv6([0x21; 16], [0x43; 16], 64)
            .tcp(1001, 443, 17, 65535)
            .write(&mut packet, &[0; 2000])
            .unwrap();
        assert!(tx_header(&mut packet, NonZeroU16::new(1460)).is_err());
        packet[52] = 0;
        assert!(tx_header(&mut packet, None).is_err());
    }
}
