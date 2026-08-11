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

/// Upper bound on padding we generate ourselves. The protocol allows up to
/// MAX_PADDING_LEN; there is no reason to send more than a token amount.
pub const MAX_GENERATED_PADDING: usize = 64;

/// Largest response message we will buffer. The protocol does not bound it, but
/// a peer that claims megabytes is not one we want to allocate for.
const MAX_RESPONSE_MESSAGE: u64 = 4096;

/// Encode a TCP proxy request.
///
/// `[varint 0x401][varint addr len][addr][varint pad len][pad]`
pub fn encode_tcp_request(address: &str, padding: &[u8]) -> std::io::Result<Vec<u8>> {
    if address.len() as u64 > MAX_ADDRESS_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "address is {} bytes, over the {MAX_ADDRESS_LEN} byte limit",
                address.len()
            ),
        ));
    }
    if padding.len() as u64 > MAX_PADDING_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "padding is over the protocol limit",
        ));
    }

    let mut out = Vec::with_capacity(2 + 2 + address.len() + 2 + padding.len());
    out.extend_from_slice(&encode_varint(FRAME_TYPE_TCP_REQUEST)?);
    out.extend_from_slice(&encode_varint(address.len() as u64)?);
    out.extend_from_slice(address.as_bytes());
    out.extend_from_slice(&encode_varint(padding.len() as u64)?);
    out.extend_from_slice(padding);
    Ok(out)
}

/// Random padding for a request, of the same shape the server generates.
pub fn random_padding() -> Vec<u8> {
    use rand::{Rng, RngExt};
    let mut rng = rand::rng();
    let len = rng.random_range(0..=MAX_GENERATED_PADDING);
    let mut padding = vec![0u8; len];
    rng.fill_bytes(&mut padding);
    padding
}

/// Parse a TCP response.
///
/// `[u8 status][varint msg len][msg][varint pad len][pad]`
///
/// Returns `Ok(None)` when `data` does not yet hold a whole response, so the
/// caller can read more; the response arrives on a stream and a short read is
/// normal rather than an error. The inner `Result` is the server's verdict:
/// `Ok(())` for status 0, `Err(message)` otherwise.
#[allow(clippy::type_complexity)]
pub fn parse_tcp_response(data: &[u8]) -> std::io::Result<Option<(Result<(), String>, usize)>> {
    let Some(&status) = data.first() else {
        return Ok(None);
    };
    let mut offset = 1;

    let Some((message_len, consumed)) = decode_varint_slice(&data[offset..]) else {
        return Ok(None);
    };
    if message_len > MAX_RESPONSE_MESSAGE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("response message length {message_len} is implausible"),
        ));
    }
    offset += consumed;

    let message_end = offset + message_len as usize;
    if data.len() < message_end {
        return Ok(None);
    }
    let message = String::from_utf8_lossy(&data[offset..message_end]).into_owned();
    offset = message_end;

    let Some((padding_len, consumed)) = decode_varint_slice(&data[offset..]) else {
        return Ok(None);
    };
    if padding_len > MAX_PADDING_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("response padding length {padding_len} is over the protocol limit"),
        ));
    }
    offset += consumed;

    let padding_end = offset + padding_len as usize;
    if data.len() < padding_end {
        return Ok(None);
    }

    let verdict = if status == 0 { Ok(()) } else { Err(message) };
    Ok(Some((verdict, padding_end)))
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

    #[test]
    fn test_tcp_request_layout() {
        let request = encode_tcp_request("example.com:443", &[]).unwrap();
        assert_eq!(&request[..2], &[0x44, 0x01], "frame type varint");
        assert_eq!(request[2], 15, "address length varint");
        assert_eq!(&request[3..18], b"example.com:443");
        assert_eq!(request[18], 0, "padding length varint");
        assert_eq!(request.len(), 19);
    }

    #[test]
    fn test_tcp_request_with_padding() {
        let padding = [0x41u8; 30];
        let request = encode_tcp_request("a:1", &padding).unwrap();
        assert_eq!(request[request.len() - 31], 30, "padding length varint");
        assert_eq!(&request[request.len() - 30..], &padding);
    }

    #[test]
    fn test_tcp_request_rejects_oversized_address() {
        let address = format!("{}:1", "a".repeat(2048));
        assert!(encode_tcp_request(&address, &[]).is_err());
    }

    #[test]
    fn test_parse_tcp_response_ok() {
        // status 0, empty message, 2 bytes of padding
        let bytes = [0x00, 0x00, 0x02, 0xaa, 0xbb];
        let (result, consumed) = parse_tcp_response(&bytes).unwrap().unwrap();
        assert!(result.is_ok());
        assert_eq!(consumed, 5);
    }

    #[test]
    fn test_parse_tcp_response_error_carries_the_message() {
        let message = b"no such host";
        let mut bytes = vec![0x01, message.len() as u8];
        bytes.extend_from_slice(message);
        bytes.push(0x00);
        let (result, consumed) = parse_tcp_response(&bytes).unwrap().unwrap();
        assert_eq!(result.unwrap_err(), "no such host");
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn test_parse_tcp_response_leaves_trailing_bytes_to_the_caller() {
        // A response immediately followed by the target's first reply bytes.
        let mut bytes = vec![0x00, 0x00, 0x00];
        bytes.extend_from_slice(b"HTTP/1.1 200 OK");
        let (result, consumed) = parse_tcp_response(&bytes).unwrap().unwrap();
        assert!(result.is_ok());
        assert_eq!(consumed, 3, "only the response itself is consumed");
        assert_eq!(&bytes[consumed..], b"HTTP/1.1 200 OK");
    }

    #[test]
    fn test_parse_tcp_response_needs_more_data() {
        assert!(parse_tcp_response(&[]).unwrap().is_none());
        assert!(parse_tcp_response(&[0x00]).unwrap().is_none());
        // message length says 4 but only 2 bytes follow
        assert!(
            parse_tcp_response(&[0x00, 0x04, b'a', b'b'])
                .unwrap()
                .is_none()
        );
        // message complete, padding length announced but its bytes are missing
        assert!(
            parse_tcp_response(&[0x00, 0x00, 0x04, 0xaa])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_parse_tcp_response_rejects_absurd_lengths() {
        // A four-byte varint announcing 1 MiB of message.
        let bytes = [0x00, 0x80, 0x10, 0x00, 0x00];
        assert!(parse_tcp_response(&bytes).is_err());
    }

    #[test]
    fn test_random_padding_is_within_bounds() {
        for _ in 0..64 {
            assert!(random_padding().len() <= MAX_GENERATED_PADDING);
        }
    }
}
