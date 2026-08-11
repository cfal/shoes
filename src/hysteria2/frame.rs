//! Hysteria2 frame codec, shared by the server and the client.

use crate::stream_reader::StreamReader;

/// TCP request frame type constant from the Hysteria2 protocol.
/// See: https://github.com/apernet/hysteria/blob/master/core/internal/protocol/proxy.go#L15
pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

/// Maximum address length accepted in a TCP request or a datagram header.
/// See: https://github.com/apernet/hysteria/blob/5520bcc405ee11a47c164c75bae5c40fc2b1d99d/core/internal/protocol/proxy.go#L19
pub const MAX_ADDRESS_LEN: u64 = 2048;

/// Maximum padding length accepted in a TCP request.
pub const MAX_PADDING_LEN: u64 = 4096;

#[inline]
pub fn encode_varint(value: u64) -> std::io::Result<Box<[u8]>> {
    if value <= 0b00111111 {
        Ok(Box::new([value as u8]))
    } else if value < (1 << 14) {
        let mut bytes = (value as u16).to_be_bytes();
        bytes[0] |= 0b01000000;
        Ok(Box::new(bytes))
    } else if value < (1 << 30) {
        let mut bytes = (value as u32).to_be_bytes();
        bytes[0] |= 0b10000000;
        Ok(Box::new(bytes))
    } else if value < (1 << 62) {
        let mut bytes = value.to_be_bytes();
        bytes[0] |= 0b11000000;
        Ok(Box::new(bytes))
    } else {
        Err(std::io::Error::other("value too large to encode as varint"))
    }
}

pub async fn read_varint(
    recv: &mut quinn::RecvStream,
    stream_reader: &mut StreamReader,
) -> std::io::Result<u64> {
    let first_byte = stream_reader.read_u8(recv).await?;

    let length = first_byte >> 6;
    let mut value: u64 = (first_byte & 0b00111111) as u64;

    let num_bytes = match length {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => {
            // impossible since we only have 2 bits
            panic!("invalid num bytes value");
        }
    };

    if num_bytes > 1 {
        let remaining_bytes = stream_reader.read_slice(recv, num_bytes - 1).await?;
        for byte in remaining_bytes {
            value <<= 8; // Shift left by 8 bits for each subsequent byte
            value |= *byte as u64; // Add the next byte
        }
    }

    Ok(value)
}

/// Decode a QUIC varint from the front of a slice.
///
/// Returns the value and the number of bytes consumed, or None when the slice
/// is shorter than the encoding announces. Used on the datagram path, which has
/// the whole packet in memory rather than a stream to await on.
pub fn decode_varint_slice(data: &[u8]) -> Option<(u64, usize)> {
    let first_byte = *data.first()?;
    let num_bytes = match first_byte >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    if data.len() < num_bytes {
        return None;
    }
    let mut value = (first_byte & 0b0011_1111) as u64;
    for byte in &data[1..num_bytes] {
        value <<= 8;
        value |= *byte as u64;
    }
    Some((value, num_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_varint_widths() {
        assert_eq!(&*encode_varint(0).unwrap(), &[0x00]);
        assert_eq!(&*encode_varint(63).unwrap(), &[0x3f]);
        assert_eq!(&*encode_varint(64).unwrap(), &[0x40, 0x40]);
        // The TCP request frame type. 1025 does not fit the one-byte form.
        assert_eq!(&*encode_varint(0x401).unwrap(), &[0x44, 0x01]);
        assert_eq!(&*encode_varint(16383).unwrap(), &[0x7f, 0xff]);
        assert_eq!(&*encode_varint(16384).unwrap(), &[0x80, 0x00, 0x40, 0x00]);
    }

    #[test]
    fn test_encode_varint_rejects_too_large() {
        assert!(encode_varint(1u64 << 62).is_err());
    }

    #[test]
    fn test_decode_varint_slice_round_trip() {
        for value in [0u64, 1, 63, 64, 1025, 16383, 16384, 1 << 29, 1 << 30] {
            let encoded = encode_varint(value).unwrap();
            let (decoded, consumed) = decode_varint_slice(&encoded).unwrap();
            assert_eq!(decoded, value, "value {value}");
            assert_eq!(consumed, encoded.len(), "value {value}");
        }
    }

    #[test]
    fn test_decode_varint_slice_needs_more_data() {
        // A four-byte form with only two bytes present.
        assert!(decode_varint_slice(&[0x80, 0x00]).is_none());
        assert!(decode_varint_slice(&[]).is_none());
    }
}
