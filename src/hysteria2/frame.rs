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

/// The message a successful response carries, as the reference sends it
/// (`core/server/server.go:322`). We sent an empty one, which parses and says
/// nothing.
pub const CONNECTED_MESSAGE: &str = "Connected";

/// Encode a TCP response.
///
/// `[u8 status][varint msg len][msg][varint pad len][pad]`
///
/// `Err(message)` is the server declining, and the message is the reason. It is
/// truncated rather than refused if it is somehow over the limit: a response
/// that says too little is recoverable for the client, and one that never
/// arrives is not.
pub fn encode_tcp_response(outcome: Result<(), &str>, padding: &[u8]) -> std::io::Result<Vec<u8>> {
    let (status, message) = match outcome {
        Ok(()) => (0u8, CONNECTED_MESSAGE),
        Err(message) => (1u8, message),
    };

    let mut end = message.len().min(MAX_RESPONSE_MESSAGE as usize);
    while end > 0 && !message.is_char_boundary(end) {
        end -= 1;
    }
    let message = &message[..end];

    if padding.len() as u64 > MAX_PADDING_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "padding is over the protocol limit",
        ));
    }

    let mut out = Vec::with_capacity(1 + 2 + message.len() + 2 + padding.len());
    out.push(status);
    out.extend_from_slice(&encode_varint(message.len() as u64)?);
    out.extend_from_slice(message.as_bytes());
    out.extend_from_slice(&encode_varint(padding.len() as u64)?);
    out.extend_from_slice(padding);
    Ok(out)
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

/// A parsed Hysteria2 UDP datagram.
pub struct Datagram<'a> {
    /// Read by the connection's demultiplexer before the rest of the header is
    /// touched, so a session that has already been routed one has no use for
    /// it. Parsed anyway: it is the first field of the wire format, and a
    /// parser that skipped it would be documenting the format wrongly.
    #[allow(dead_code)]
    pub session_id: u32,
    pub packet_id: u16,
    pub fragment_id: u8,
    pub fragment_count: u8,
    /// On a reply this is the source the packet came from. A session is bound
    /// to one target and AsyncMessageStream has nowhere to carry a source, so
    /// the client does not use it — but parsing it is not optional, because
    /// its length is what locates the payload.
    #[allow(dead_code)]
    pub address: &'a str,
    pub payload: &'a [u8],
}

/// `[u32 session][u16 packet][u8 frag id][u8 frag count][varint addr len][addr]`
fn encode_datagram_header(
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    address: &str,
) -> std::io::Result<Vec<u8>> {
    if address.is_empty() || address.len() as u64 > MAX_ADDRESS_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("address length {} is not encodable", address.len()),
        ));
    }
    let mut out = Vec::with_capacity(8 + 2 + address.len());
    out.extend_from_slice(&session_id.to_be_bytes());
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.push(fragment_id);
    out.push(fragment_count);
    out.extend_from_slice(&encode_varint(address.len() as u64)?);
    out.extend_from_slice(address.as_bytes());
    Ok(out)
}

/// Parse a datagram.
///
/// Returns None for anything malformed. A stray packet is dropped rather than
/// raised as an error, which is how the server treats them too: a datagram
/// channel carries whatever the network delivers.
pub fn parse_datagram(data: &[u8]) -> Option<Datagram<'_>> {
    if data.len() < 9 {
        return None;
    }
    let session_id = u32::from_be_bytes(data[0..4].try_into().ok()?);
    let packet_id = u16::from_be_bytes(data[4..6].try_into().ok()?);
    let fragment_id = data[6];
    let fragment_count = data[7];

    let (address_len, consumed) = decode_varint_slice(&data[8..])?;
    if address_len == 0 || address_len > MAX_ADDRESS_LEN {
        return None;
    }
    let address_start = 8 + consumed;
    let address_end = address_start.checked_add(address_len as usize)?;
    if data.len() < address_end {
        return None;
    }
    let address = std::str::from_utf8(&data[address_start..address_end]).ok()?;

    Some(Datagram {
        session_id,
        packet_id,
        fragment_id,
        fragment_count,
        address,
        payload: &data[address_end..],
    })
}

/// Split one UDP payload into datagrams no larger than `max_datagram`.
///
/// Every fragment repeats the address, because the protocol puts it in each
/// datagram header rather than only in the first.
pub fn build_datagrams(
    session_id: u32,
    packet_id: u16,
    address: &str,
    payload: &[u8],
    max_datagram: usize,
) -> std::io::Result<Vec<Vec<u8>>> {
    let header_len = encode_datagram_header(session_id, packet_id, 0, 1, address)?.len();
    let capacity = max_datagram
        .checked_sub(header_len)
        .filter(|c| *c > 0)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "datagram limit of {max_datagram} is smaller than a {header_len} byte header"
                ),
            )
        })?;

    let fragment_count = payload.len().div_ceil(capacity).max(1);
    if fragment_count > u8::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "payload of {} bytes needs {fragment_count} fragments, over the 255 the protocol allows",
                payload.len()
            ),
        ));
    }

    let mut datagrams = Vec::with_capacity(fragment_count);
    for (index, chunk) in payload.chunks(capacity).enumerate() {
        let mut datagram = encode_datagram_header(
            session_id,
            packet_id,
            index as u8,
            fragment_count as u8,
            address,
        )?;
        datagram.extend_from_slice(chunk);
        datagrams.push(datagram);
    }
    // An empty payload still has to travel: a zero-length UDP packet is a
    // packet, and chunks() yields nothing for it.
    if datagrams.is_empty() {
        datagrams.push(encode_datagram_header(
            session_id, packet_id, 0, 1, address,
        )?);
    }
    Ok(datagrams)
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

    /// Exact bytes, not a round trip through our own parser. An encoder and a
    /// parser that share a misreading agree with each other and with nothing
    /// else, which is how most of the Hysteria2 conformance list came to exist.
    #[test]
    fn test_a_successful_response_is_the_bytes_upstream_sends() {
        assert_eq!(
            encode_tcp_response(Ok(()), &[]).unwrap(),
            b"\x00\x09Connected\x00",
            "status 0, a 9-byte message, no padding"
        );
    }

    #[test]
    fn test_a_refusal_carries_status_one_and_its_reason() {
        assert_eq!(
            encode_tcp_response(Err("no such host"), &[0xaa]).unwrap(),
            b"\x01\x0cno such host\x01\xaa"
        );
    }

    /// A message over the limit must not cost the client its response: without
    /// a status byte it has nothing to act on at all.
    #[test]
    fn test_an_overlong_message_is_truncated_rather_than_refused() {
        let long = "e".repeat(MAX_RESPONSE_MESSAGE as usize + 10);
        let encoded = encode_tcp_response(Err(&long), &[]).unwrap();
        let (verdict, consumed) = parse_tcp_response(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(
            verdict.unwrap_err().len(),
            MAX_RESPONSE_MESSAGE as usize,
            "the message must be cut to the limit, not dropped"
        );
    }

    /// The limit is a byte count and messages are UTF-8, so the cut has to land
    /// on a character boundary. A split character would reach the client as a
    /// replacement character in place of the last letter of the reason.
    #[test]
    fn test_truncation_does_not_split_a_character() {
        // Three bytes each, so the limit falls inside the 1366th one.
        let long = "☃".repeat(2000);
        let encoded = encode_tcp_response(Err(&long), &[]).unwrap();
        let (verdict, _) = parse_tcp_response(&encoded).unwrap().unwrap();
        let message = verdict.unwrap_err();

        assert_eq!(message.len(), MAX_RESPONSE_MESSAGE as usize / 3 * 3);
        assert!(
            message.chars().all(|c| c == '☃'),
            "a split character would have arrived as U+FFFD"
        );
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

    #[test]
    fn test_datagram_header_layout() {
        let header = encode_datagram_header(0xdeadbeef, 0x1234, 1, 3, "example.com:53").unwrap();
        assert_eq!(&header[0..4], &0xdeadbeefu32.to_be_bytes());
        assert_eq!(&header[4..6], &0x1234u16.to_be_bytes());
        assert_eq!(header[6], 1, "fragment id");
        assert_eq!(header[7], 3, "fragment count");
        assert_eq!(header[8], 14, "address length varint");
        assert_eq!(&header[9..], b"example.com:53");
    }

    #[test]
    fn test_parse_datagram_round_trip() {
        let datagrams = build_datagrams(7, 9, "1.2.3.4:53", b"payload", 1200).unwrap();
        assert_eq!(datagrams.len(), 1);
        let parsed = parse_datagram(&datagrams[0]).unwrap();
        assert_eq!(parsed.session_id, 7);
        assert_eq!(parsed.packet_id, 9);
        assert_eq!(parsed.fragment_id, 0);
        assert_eq!(parsed.fragment_count, 1);
        assert_eq!(parsed.address, "1.2.3.4:53");
        assert_eq!(parsed.payload, b"payload");
    }

    #[test]
    fn test_parse_datagram_rejects_truncated_input() {
        assert!(parse_datagram(&[0u8; 8]).is_none());
        // Announces a 200-byte address that is not there.
        let mut packet = vec![0u8; 8];
        packet.push(0x40);
        packet.push(200);
        assert!(parse_datagram(&packet).is_none());
    }

    #[test]
    fn test_parse_datagram_rejects_empty_address() {
        let mut packet = vec![0u8; 8];
        packet.push(0x00); // address length 0
        assert!(parse_datagram(&packet).is_none());
    }

    #[test]
    fn test_fragmentation_splits_and_reassembles() {
        let payload: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let datagrams = build_datagrams(1, 2, "a:1", &payload, 1200).unwrap();
        assert!(datagrams.len() > 1);
        assert!(datagrams.iter().all(|d| d.len() <= 1200));

        for (index, datagram) in datagrams.iter().enumerate() {
            let parsed = parse_datagram(datagram).unwrap();
            assert_eq!(parsed.fragment_id as usize, index);
            assert_eq!(parsed.fragment_count as usize, datagrams.len());
            assert_eq!(parsed.address, "a:1", "every fragment repeats the address");
        }

        let rebuilt: Vec<u8> = datagrams
            .iter()
            .flat_map(|d| parse_datagram(d).unwrap().payload.to_vec())
            .collect();
        assert_eq!(rebuilt, payload);
    }

    #[test]
    fn test_an_empty_payload_still_produces_a_datagram() {
        let datagrams = build_datagrams(1, 2, "a:1", &[], 1200).unwrap();
        assert_eq!(datagrams.len(), 1);
        assert!(parse_datagram(&datagrams[0]).unwrap().payload.is_empty());
    }

    #[test]
    fn test_fragmentation_refuses_more_than_255_fragments() {
        let payload = vec![0u8; 100_000];
        assert!(build_datagrams(1, 2, "a:1", &payload, 200).is_err());
    }

    #[test]
    fn test_fragmentation_refuses_a_limit_below_the_header() {
        assert!(build_datagrams(1, 2, "a:1", b"x", 4).is_err());
    }
}
