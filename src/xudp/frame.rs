// XUDP frame protocol implementation
// Protocol-agnostic UDP multiplexing used by VLESS and VMess

use bytes::{Buf, BufMut, BytesMut};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::address::{Address, NetLocation};

/// XUDP session status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionStatus {
    New = 0x01,       // Create new session
    Keep = 0x02,      // Continue session
    End = 0x03,       // Close session
    KeepAlive = 0x04, // Heartbeat
}

impl TryFrom<u8> for SessionStatus {
    type Error = std::io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(SessionStatus::New),
            0x02 => Ok(SessionStatus::Keep),
            0x03 => Ok(SessionStatus::End),
            0x04 => Ok(SessionStatus::KeepAlive),
            other => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid session status: {}", other),
            )),
        }
    }
}

/// XUDP frame options (bitmask)
#[derive(Debug, Clone, Copy)]
pub struct FrameOption(u8);

impl FrameOption {
    pub const DATA: u8 = 0x01;
    pub const ERROR: u8 = 0x02;

    pub fn new() -> Self {
        Self(0)
    }

    pub fn with_data(mut self) -> Self {
        self.0 |= Self::DATA;
        self
    }

    pub fn has_data(&self) -> bool {
        (self.0 & Self::DATA) != 0
    }

    pub fn has_error(&self) -> bool {
        (self.0 & Self::ERROR) != 0
    }

    pub fn raw(&self) -> u8 {
        self.0
    }
}

impl Default for FrameOption {
    fn default() -> Self {
        Self::new()
    }
}

impl From<u8> for FrameOption {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

/// Target network type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TargetNetwork {
    Tcp = 0x01,
    Udp = 0x02,
}

impl TryFrom<u8> for TargetNetwork {
    type Error = std::io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(TargetNetwork::Tcp),
            0x02 => Ok(TargetNetwork::Udp),
            other => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid network type: {}", other),
            )),
        }
    }
}

/// XUDP frame metadata
#[derive(Debug)]
pub struct FrameMetadata {
    pub session_id: u16,
    pub status: SessionStatus,
    pub option: FrameOption,
    pub target: Option<NetLocation>,
    pub network: Option<TargetNetwork>,
}

impl FrameMetadata {
    /// Encode frame metadata to bytes
    pub fn encode(&self, buf: &mut BytesMut) -> std::io::Result<()> {
        // Reserve space for length (will fill in at end)
        let length_pos = buf.len();
        buf.put_u16(0);

        let metadata_start = buf.len();

        // Session ID
        buf.put_u16(self.session_id);

        // Status and Option
        buf.put_u8(self.status as u8);
        buf.put_u8(self.option.raw());

        // For New status or Keep+UDP: write destination
        if self.status == SessionStatus::New {
            let network = self.network.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "network required for SessionStatusNew",
                )
            })?;
            buf.put_u8(network as u8);

            let target = self.target.as_ref().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "target required for SessionStatusNew",
                )
            })?;

            // Port
            buf.put_u16(target.port());

            // Address
            encode_address(buf, target.address())?;
        } else if matches!(self.status, SessionStatus::Keep)
            && matches!(self.network, Some(TargetNetwork::Udp))
        {
            // For Keep frames with UDP, include destination
            buf.put_u8(TargetNetwork::Udp as u8);

            let target = self.target.as_ref().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "target required for Keep+UDP",
                )
            })?;

            buf.put_u16(target.port());
            encode_address(buf, target.address())?;
        }

        // Calculate and write length
        let metadata_len = buf.len() - metadata_start;
        let length_bytes = &mut buf[length_pos..length_pos + 2];
        length_bytes.copy_from_slice(&(metadata_len as u16).to_be_bytes());

        Ok(())
    }

    /// Decode frame metadata from bytes
    pub fn decode(buf: &mut BytesMut) -> std::io::Result<Option<Self>> {
        // Need at least length field
        if buf.len() < 2 {
            log::debug!(
                "[XUDP DECODE] Buffer too short for length field: {} bytes",
                buf.len()
            );
            return Ok(None);
        }

        let metadata_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        log::debug!(
            "[XUDP DECODE] metadata_len={}, buf.len()={}, need={}",
            metadata_len,
            buf.len(),
            2 + metadata_len
        );

        // Need complete metadata
        if buf.len() < 2 + metadata_len {
            log::debug!("[XUDP DECODE] Incomplete metadata, need more data");
            return Ok(None);
        }

        // Skip length field
        buf.advance(2);

        if metadata_len < 4 {
            log::error!(
                "[XUDP DECODE] Metadata too short: {} (buffer was {} bytes, first 8 bytes: {:?})",
                metadata_len,
                buf.len() + 2,
                &buf[..std::cmp::min(8, buf.len())]
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("metadata too short: {}", metadata_len),
            ));
        }

        // Track how many metadata bytes we consume
        let metadata_start = buf.len();

        let session_id = buf.get_u16();
        let status = SessionStatus::try_from(buf.get_u8())?;
        let option = FrameOption::from(buf.get_u8());

        let mut network = None;
        let mut target = None;

        // Calculate remaining metadata bytes (after session_id, status, option = 4 bytes)
        let remaining_metadata = metadata_len.saturating_sub(4);

        // Parse destination for New or Keep+UDP
        // Check remaining_metadata > 0 to know if there's address data
        if remaining_metadata > 0
            && (status == SessionStatus::New
                || (status == SessionStatus::Keep && buf.remaining() > 0 && buf[0] == 0x02))
        {
            let net_byte = buf.get_u8();
            network = Some(TargetNetwork::try_from(net_byte)?);

            let port = buf.get_u16();
            let address = decode_address(buf)?;
            target = Some(NetLocation::new(address, port));
        }

        // Consume any remaining metadata bytes we didn't parse
        let consumed = metadata_start - buf.len();
        let unconsumed = metadata_len.saturating_sub(consumed);
        if unconsumed > 0 {
            log::debug!(
                "[XUDP DECODE] Skipping {} unconsumed metadata bytes (GlobalID or padding)",
                unconsumed
            );
            buf.advance(unconsumed);
        }

        Ok(Some(FrameMetadata {
            session_id,
            status,
            option,
            target,
            network,
        }))
    }
}

/// Encode address to buffer (VLESS address format)
fn encode_address(buf: &mut BytesMut, address: &Address) -> std::io::Result<()> {
    match address {
        Address::Ipv4(v4) => {
            buf.put_u8(0x01);
            buf.put_slice(&v4.octets());
        }
        Address::Hostname(hostname) => {
            if hostname.len() > 255 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "hostname too long",
                ));
            }
            buf.put_u8(0x02);
            buf.put_u8(hostname.len() as u8);
            buf.put_slice(hostname.as_bytes());
        }
        Address::Ipv6(v6) => {
            buf.put_u8(0x03);
            buf.put_slice(&v6.octets());
        }
    }
    Ok(())
}

/// Decode address from buffer (VLESS address format)
fn decode_address(buf: &mut BytesMut) -> std::io::Result<Address> {
    if buf.remaining() < 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "incomplete address type",
        ));
    }

    let addr_type = buf.get_u8();
    match addr_type {
        0x01 => {
            // IPv4
            if buf.remaining() < 4 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "incomplete IPv4 address",
                ));
            }
            let mut octets = [0u8; 4];
            buf.copy_to_slice(&mut octets);
            Ok(Address::Ipv4(Ipv4Addr::from(octets)))
        }
        0x02 => {
            // Hostname
            if buf.remaining() < 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "incomplete hostname length",
                ));
            }
            let len = buf.get_u8() as usize;
            if buf.remaining() < len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "incomplete hostname",
                ));
            }
            let hostname_bytes = buf.copy_to_bytes(len);
            let hostname = std::str::from_utf8(&hostname_bytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            Ok(Address::from(hostname)?)
        }
        0x03 => {
            // IPv6
            if buf.remaining() < 16 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "incomplete IPv6 address",
                ));
            }
            let mut octets = [0u8; 16];
            buf.copy_to_slice(&mut octets);
            Ok(Address::Ipv6(Ipv6Addr::from(octets)))
        }
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid address type: {}", other),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==========================================================================
    // Basic encode/decode tests
    // ==========================================================================

    #[test]
    fn test_encode_decode_new_frame_udp() {
        let metadata = FrameMetadata {
            session_id: 42,
            status: SessionStatus::New,
            option: FrameOption::new().with_data(),
            target: Some(NetLocation::new(
                Address::Ipv4("1.1.1.1".parse().unwrap()),
                53,
            )),
            network: Some(TargetNetwork::Udp),
        };

        let mut buf = BytesMut::new();
        metadata.encode(&mut buf).unwrap();

        let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.session_id, 42);
        assert_eq!(decoded.status, SessionStatus::New);
        assert!(decoded.option.has_data());
        assert_eq!(decoded.network, Some(TargetNetwork::Udp));
        assert!(decoded.target.is_some());
        let target = decoded.target.unwrap();
        assert_eq!(target.port(), 53);
    }

    #[test]
    fn test_encode_decode_keep_frame_udp() {
        let metadata = FrameMetadata {
            session_id: 100,
            status: SessionStatus::Keep,
            option: FrameOption::new().with_data(),
            target: Some(NetLocation::new(
                Address::Ipv4("8.8.8.8".parse().unwrap()),
                53,
            )),
            network: Some(TargetNetwork::Udp),
        };

        let mut buf = BytesMut::new();
        metadata.encode(&mut buf).unwrap();

        let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.session_id, 100);
        assert_eq!(decoded.status, SessionStatus::Keep);
        assert!(decoded.option.has_data());
        assert_eq!(decoded.network, Some(TargetNetwork::Udp));
    }

    #[test]
    fn test_encode_decode_end_frame() {
        let metadata = FrameMetadata {
            session_id: 50,
            status: SessionStatus::End,
            option: FrameOption::new(),
            target: None,
            network: None,
        };

        let mut buf = BytesMut::new();
        metadata.encode(&mut buf).unwrap();

        let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.session_id, 50);
        assert_eq!(decoded.status, SessionStatus::End);
        assert!(!decoded.option.has_data());
    }

    #[test]
    fn test_encode_decode_hostname() {
        let metadata = FrameMetadata {
            session_id: 1,
            status: SessionStatus::New,
            option: FrameOption::new(),
            target: Some(NetLocation::new(
                Address::Hostname("example.com".to_string()),
                443,
            )),
            network: Some(TargetNetwork::Tcp),
        };

        let mut buf = BytesMut::new();
        metadata.encode(&mut buf).unwrap();

        let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.session_id, 1);
        let target = decoded.target.unwrap();
        assert_eq!(target.port(), 443);
        match target.address() {
            Address::Hostname(h) => assert_eq!(h, "example.com"),
            _ => panic!("expected hostname"),
        }
    }

    /// Test decoding a frame with extra metadata bytes (GlobalID simulation)
    /// Xray-core appends 8-byte GlobalID for UDP session continuity.
    /// We skip these bytes like sing-box
    #[test]
    fn test_decode_frame_with_globalid_extra_bytes() {
        let mut buf = BytesMut::new();

        // Manually construct a frame with GlobalID (8 extra bytes)
        // Format: length(2) + session_id(2) + status(1) + option(1) + network(1) + port(2) + addr_type(1) + ipv4(4) + GlobalID(8)
        let metadata_len: u16 = 4 + 1 + 2 + 1 + 4 + 8; // 20 bytes
        buf.put_u16(metadata_len);
        buf.put_u16(123); // session_id
        buf.put_u8(0x01); // SessionStatus::New
        buf.put_u8(0x01); // FrameOption::DATA
        buf.put_u8(0x02); // TargetNetwork::Udp
        buf.put_u16(53); // port
        buf.put_u8(0x01); // address type: IPv4
        buf.put_slice(&[8, 8, 8, 8]); // 8.8.8.8
        buf.put_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // GlobalID (8 bytes)

        let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.session_id, 123);
        assert_eq!(decoded.status, SessionStatus::New);
        assert!(decoded.option.has_data());
        assert_eq!(decoded.network, Some(TargetNetwork::Udp));
        let target = decoded.target.unwrap();
        assert_eq!(target.port(), 53);
        assert_eq!(target.address(), &Address::Ipv4("8.8.8.8".parse().unwrap()));

        // Buffer should be fully consumed
        assert_eq!(buf.len(), 0, "Buffer should be fully consumed after decode");
    }

    /// Test Keep frame without destination (TCP keep)
    /// This is a minimal Keep frame with just session_id + status + option
    #[test]
    fn test_decode_keep_frame_tcp_no_destination() {
        let mut buf = BytesMut::new();

        // Minimal Keep frame: length(2) + session_id(2) + status(1) + option(1) = 4 bytes metadata
        buf.put_u16(4); // metadata length
        buf.put_u16(42); // session_id
        buf.put_u8(0x02); // SessionStatus::Keep
        buf.put_u8(0x01); // FrameOption::DATA

        let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.session_id, 42);
        assert_eq!(decoded.status, SessionStatus::Keep);
        assert!(decoded.option.has_data());
        assert!(decoded.network.is_none(), "TCP Keep should have no network");
        assert!(
            decoded.target.is_none(),
            "TCP Keep should have no destination"
        );
        assert_eq!(buf.len(), 0);
    }

    /// Test Keep frame with UDP destination change
    /// Per Xray-core: Keep frames CAN have destination if network byte is 0x02 (UDP)
    #[test]
    fn test_decode_keep_frame_udp_with_destination() {
        let mut buf = BytesMut::new();

        // Keep+UDP frame with destination
        // Format: length(2) + session_id(2) + status(1) + option(1) + network(1) + port(2) + addr_type(1) + ipv4(4)
        let metadata_len: u16 = 4 + 1 + 2 + 1 + 4; // 12 bytes
        buf.put_u16(metadata_len);
        buf.put_u16(99); // session_id
        buf.put_u8(0x02); // SessionStatus::Keep
        buf.put_u8(0x01); // FrameOption::DATA
        buf.put_u8(0x02); // TargetNetwork::Udp - this triggers destination parsing
        buf.put_u16(1234); // port
        buf.put_u8(0x01); // address type: IPv4
        buf.put_slice(&[192, 168, 1, 1]); // 192.168.1.1

        let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.session_id, 99);
        assert_eq!(decoded.status, SessionStatus::Keep);
        assert_eq!(decoded.network, Some(TargetNetwork::Udp));
        let target = decoded.target.unwrap();
        assert_eq!(target.port(), 1234);
        assert_eq!(buf.len(), 0);
    }

    /// Test Keep frame where first byte after header is NOT 0x02 (not UDP)
    /// Should NOT parse destination even if there's extra data
    #[test]
    fn test_decode_keep_frame_non_udp_extra_bytes() {
        let mut buf = BytesMut::new();

        // Keep frame where network byte is 0x01 (TCP) - should NOT parse destination
        let metadata_len: u16 = 4 + 1 + 2 + 1 + 4; // 12 bytes total
        buf.put_u16(metadata_len);
        buf.put_u16(50); // session_id
        buf.put_u8(0x02); // SessionStatus::Keep
        buf.put_u8(0x01); // FrameOption::DATA
        buf.put_u8(0x01); // TargetNetwork::Tcp (NOT UDP!)
        buf.put_u16(443); // port (should be skipped)
        buf.put_u8(0x01); // address type
        buf.put_slice(&[1, 2, 3, 4]); // address (should be skipped)

        let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.session_id, 50);
        assert_eq!(decoded.status, SessionStatus::Keep);
        // Network and target should be None because first byte wasn't 0x02
        assert!(
            decoded.network.is_none(),
            "Keep+TCP should not parse network"
        );
        assert!(
            decoded.target.is_none(),
            "Keep+TCP should not parse destination"
        );
        // Extra bytes should be consumed/skipped
        assert_eq!(buf.len(), 0, "Extra bytes should be consumed");
    }

    /// Test KeepAlive frame (status 0x04)
    #[test]
    fn test_decode_keepalive_frame() {
        let mut buf = BytesMut::new();

        buf.put_u16(4); // metadata length
        buf.put_u16(1); // session_id
        buf.put_u8(0x04); // SessionStatus::KeepAlive
        buf.put_u8(0x00); // no options

        let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.session_id, 1);
        assert_eq!(decoded.status, SessionStatus::KeepAlive);
        assert!(!decoded.option.has_data());
        assert!(!decoded.option.has_error());
        assert_eq!(buf.len(), 0);
    }

    /// Test End frame with ERROR option
    #[test]
    fn test_decode_end_frame_with_error() {
        let mut buf = BytesMut::new();

        buf.put_u16(4); // metadata length
        buf.put_u16(77); // session_id
        buf.put_u8(0x03); // SessionStatus::End
        buf.put_u8(0x02); // FrameOption::ERROR

        let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.session_id, 77);
        assert_eq!(decoded.status, SessionStatus::End);
        assert!(!decoded.option.has_data());
        assert!(decoded.option.has_error());
        assert_eq!(buf.len(), 0);
    }

    /// Test IPv6 destination
    #[test]
    fn test_decode_new_frame_ipv6() {
        let mut buf = BytesMut::new();

        // New frame with IPv6 destination
        let metadata_len: u16 = 4 + 1 + 2 + 1 + 16; // 24 bytes
        buf.put_u16(metadata_len);
        buf.put_u16(200); // session_id
        buf.put_u8(0x01); // SessionStatus::New
        buf.put_u8(0x01); // FrameOption::DATA
        buf.put_u8(0x02); // TargetNetwork::Udp
        buf.put_u16(53); // port
        buf.put_u8(0x03); // address type: IPv6
        buf.put_slice(&[
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
        ]); // 2001:4860:4860::8888

        let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.session_id, 200);
        let target = decoded.target.unwrap();
        assert_eq!(target.port(), 53);
        match target.address() {
            Address::Ipv6(v6) => {
                assert_eq!(v6.to_string(), "2001:4860:4860::8888");
            }
            _ => panic!("expected IPv6"),
        }
        assert_eq!(buf.len(), 0);
    }

    // ==========================================================================
    // Error handling tests
    // ==========================================================================

    /// Test incomplete buffer (not enough for length field)
    #[test]
    fn test_decode_incomplete_length() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x00); // Only 1 byte, need 2 for length

        let result = FrameMetadata::decode(&mut buf).unwrap();
        assert!(result.is_none(), "Should return None for incomplete length");
        assert_eq!(buf.len(), 1, "Buffer should not be consumed");
    }

    /// Test incomplete metadata (length says more than available)
    #[test]
    fn test_decode_incomplete_metadata() {
        let mut buf = BytesMut::new();
        buf.put_u16(10); // metadata length = 10
        buf.put_u16(1); // session_id
        // Only 2 bytes of metadata, but length says 10

        let result = FrameMetadata::decode(&mut buf).unwrap();
        assert!(
            result.is_none(),
            "Should return None for incomplete metadata"
        );
    }

    /// Test metadata too short (less than 4 bytes)
    #[test]
    fn test_decode_metadata_too_short() {
        let mut buf = BytesMut::new();
        buf.put_u16(2); // metadata length = 2 (too short, need at least 4)
        buf.put_u16(1); // only 2 bytes of metadata

        let result = FrameMetadata::decode(&mut buf);
        assert!(result.is_err(), "Should error on metadata too short");
    }

    /// Test invalid session status
    #[test]
    fn test_decode_invalid_session_status() {
        let mut buf = BytesMut::new();
        buf.put_u16(4); // metadata length
        buf.put_u16(1); // session_id
        buf.put_u8(0x99); // Invalid status!
        buf.put_u8(0x00); // option

        let result = FrameMetadata::decode(&mut buf);
        assert!(result.is_err(), "Should error on invalid session status");
    }

    /// Test invalid network type in New frame
    #[test]
    fn test_decode_invalid_network_type() {
        let mut buf = BytesMut::new();
        let metadata_len: u16 = 4 + 1 + 2 + 1 + 4;
        buf.put_u16(metadata_len);
        buf.put_u16(1); // session_id
        buf.put_u8(0x01); // SessionStatus::New
        buf.put_u8(0x01); // FrameOption::DATA
        buf.put_u8(0x99); // Invalid network type!
        buf.put_u16(53); // port
        buf.put_u8(0x01); // address type
        buf.put_slice(&[1, 2, 3, 4]);

        let result = FrameMetadata::decode(&mut buf);
        assert!(result.is_err(), "Should error on invalid network type");
    }

    /// Test invalid address type
    #[test]
    fn test_decode_invalid_address_type() {
        let mut buf = BytesMut::new();
        let metadata_len: u16 = 4 + 1 + 2 + 1 + 4;
        buf.put_u16(metadata_len);
        buf.put_u16(1); // session_id
        buf.put_u8(0x01); // SessionStatus::New
        buf.put_u8(0x01); // FrameOption::DATA
        buf.put_u8(0x02); // TargetNetwork::Udp
        buf.put_u16(53); // port
        buf.put_u8(0x99); // Invalid address type!
        buf.put_slice(&[1, 2, 3, 4]);

        let result = FrameMetadata::decode(&mut buf);
        assert!(result.is_err(), "Should error on invalid address type");
    }

    #[test]
    fn test_frame_format_compatibility() {
        let mut buf = BytesMut::new();

        // Xray-core format for New+UDP:
        // 2 bytes - length (of metadata after this field)
        // 2 bytes - session id
        // 1 byte - status
        // 1 byte - option
        // 1 byte - network
        // 2 bytes - port
        // n bytes - address (1 byte type + address bytes)

        let metadata_len: u16 = 2 + 1 + 1 + 1 + 2 + 1 + 4; // = 12
        buf.put_u16(metadata_len);
        buf.put_u16(0x0001); // session_id = 1
        buf.put_u8(0x01); // SessionStatusNew
        buf.put_u8(0x01); // OptionData
        buf.put_u8(0x02); // TargetNetworkUDP
        buf.put_u16(443); // port (big-endian)
        buf.put_u8(0x01); // AddressTypeIPv4
        buf.put_slice(&[93, 184, 216, 34]); // 93.184.216.34 (example.com)

        let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();

        assert_eq!(decoded.session_id, 1);
        assert_eq!(decoded.status, SessionStatus::New);
        assert!(decoded.option.has_data());
        assert!(!decoded.option.has_error());
        assert_eq!(decoded.network, Some(TargetNetwork::Udp));

        let target = decoded.target.unwrap();
        assert_eq!(target.port(), 443);
        assert_eq!(
            target.address(),
            &Address::Ipv4("93.184.216.34".parse().unwrap())
        );
    }

    /// Test domain name encoding
    #[test]
    fn test_domain_format() {
        let mut buf = BytesMut::new();

        let domain = "dns.google";
        let metadata_len: u16 = 4 + 1 + 2 + 1 + 1 + domain.len() as u16; // 19
        buf.put_u16(metadata_len);
        buf.put_u16(5); // session_id
        buf.put_u8(0x01); // SessionStatusNew
        buf.put_u8(0x01); // OptionData
        buf.put_u8(0x02); // TargetNetworkUDP
        buf.put_u16(853); // DNS over TLS port
        buf.put_u8(0x02); // AddressTypeDomain
        buf.put_u8(domain.len() as u8);
        buf.put_slice(domain.as_bytes());

        let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
        let target = decoded.target.unwrap();
        assert_eq!(target.port(), 853);
        match target.address() {
            Address::Hostname(h) => assert_eq!(h, "dns.google"),
            _ => panic!("expected hostname"),
        }
    }

    /// Test that our encoder produces Xray-compatible output
    #[test]
    fn test_encode_xray_compatible() {
        let metadata = FrameMetadata {
            session_id: 100,
            status: SessionStatus::New,
            option: FrameOption::new().with_data(),
            target: Some(NetLocation::new(
                Address::Ipv4("1.1.1.1".parse().unwrap()),
                53,
            )),
            network: Some(TargetNetwork::Udp),
        };

        let mut buf = BytesMut::new();
        metadata.encode(&mut buf).unwrap();

        // Verify the wire format
        assert_eq!(buf[0..2], [0x00, 0x0c]); // length = 12 (big-endian)
        assert_eq!(buf[2..4], [0x00, 0x64]); // session_id = 100 (big-endian)
        assert_eq!(buf[4], 0x01); // SessionStatusNew
        assert_eq!(buf[5], 0x01); // OptionData
        assert_eq!(buf[6], 0x02); // TargetNetworkUDP
        assert_eq!(buf[7..9], [0x00, 0x35]); // port = 53 (big-endian)
        assert_eq!(buf[9], 0x01); // AddressTypeIPv4
        assert_eq!(buf[10..14], [1, 1, 1, 1]); // 1.1.1.1
    }

    /// Test maximum session ID (u16::MAX)
    #[test]
    fn test_max_session_id() {
        let mut buf = BytesMut::new();
        buf.put_u16(4);
        buf.put_u16(0xFFFF); // max session_id
        buf.put_u8(0x02); // Keep
        buf.put_u8(0x00);

        let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.session_id, 65535);
    }

    /// Test both DATA and ERROR options set
    #[test]
    fn test_data_and_error_options() {
        let mut buf = BytesMut::new();
        buf.put_u16(4);
        buf.put_u16(1);
        buf.put_u8(0x03); // End
        buf.put_u8(0x03); // DATA | ERROR

        let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
        assert!(decoded.option.has_data());
        assert!(decoded.option.has_error());
    }
}
