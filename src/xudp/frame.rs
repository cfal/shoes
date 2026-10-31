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
        let Some(metadata_len) = decode_metadata_len(buf)? else {
            log::debug!(
                "[XUDP DECODE] Buffer too short for length field: {} bytes",
                buf.len()
            );
            return Ok(None);
        };
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

        // Address parsing must not consume payload or a coalesced next frame.
        let mut metadata = buf.split_to(metadata_len);

        let session_id = metadata.get_u16();
        let status = SessionStatus::try_from(metadata.get_u8())?;
        let option = FrameOption::from(metadata.get_u8());

        let mut network = None;
        let mut target = None;

        // Parse destination for New or Keep+UDP
        if !metadata.is_empty()
            && (status == SessionStatus::New
                || (status == SessionStatus::Keep && metadata[0] == 0x02))
        {
            let net_byte = metadata.get_u8();
            network = Some(TargetNetwork::try_from(net_byte)?);

            if metadata.remaining() < 2 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "truncated XUDP destination port",
                ));
            }
            let port = metadata.get_u16();
            let address = decode_address(&mut metadata)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            target = Some(NetLocation::new(address, port));
        }

        let unconsumed = metadata.len();
        if unconsumed > 0 {
            log::debug!(
                "[XUDP DECODE] Skipping {} unconsumed metadata bytes (GlobalID or padding)",
                unconsumed
            );
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

fn decode_metadata_len(buf: &[u8]) -> std::io::Result<Option<usize>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let metadata_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if !(4..=512).contains(&metadata_len) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "XUDP metadata length outside 4..=512",
        ));
    }
    Ok(Some(metadata_len))
}

pub(crate) fn decode_frame(
    buf: &mut BytesMut,
) -> std::io::Result<Option<(FrameMetadata, BytesMut)>> {
    let Some(metadata_len) = decode_metadata_len(buf)? else {
        return Ok(None);
    };
    let metadata_end = 2 + metadata_len;
    if buf.len() < metadata_end {
        return Ok(None);
    }
    // The option byte follows the length, session ID, and status fields.
    let has_data = buf[5] & FrameOption::DATA != 0;
    let data_len = if has_data {
        let payload_start = metadata_end + 2;
        if buf.len() < payload_start {
            return Ok(None);
        }
        let length = u16::from_be_bytes([buf[metadata_end], buf[metadata_end + 1]]) as usize;
        if buf.len() < payload_start + length {
            return Ok(None);
        }
        length
    } else {
        0
    };
    let metadata = FrameMetadata::decode(buf)?.expect("complete metadata");
    if has_data {
        buf.advance(2);
    }
    Ok(Some((metadata, buf.split_to(data_len))))
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
mod tests;
