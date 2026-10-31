use bytes::{BufMut, Bytes, BytesMut};
use rand::RngExt;

// Padding parameters
const LONG_PADDING_MIN: usize = 900;
const LONG_PADDING_RANDOM_MAX: usize = 500;
const SHORT_PADDING_RANDOM_MAX: usize = 256;
const MAX_PADDING_SIZE: usize = 8171; // buf.Size - 21

pub fn pad_with_uuid_and_command(data: &[u8], uuid: &[u8; 16], command: u8, is_tls: bool) -> Bytes {
    pad(data, Some(uuid), command, is_tls)
}
//
pub fn pad_with_command(data: &[u8], command: u8, is_tls: bool) -> Bytes {
    pad(data, None, command, is_tls)
}

fn pad(data: &[u8], mut uuid: Option<&[u8; 16]>, command: u8, is_tls: bool) -> Bytes {
    let mut output = BytesMut::new();
    if data.is_empty() {
        pad_one(&mut output, data, uuid, command, is_tls);
    } else {
        let mut chunks = data.chunks(MAX_PADDING_SIZE).peekable();
        while let Some(chunk) = chunks.next() {
            // Only the final frame may end padding or switch to DIRECT.
            let command = if chunks.peek().is_some() { 0 } else { command };
            pad_one(&mut output, chunk, uuid.take(), command, is_tls);
        }
    }
    output.freeze()
}

fn pad_one(output: &mut BytesMut, data: &[u8], uuid: Option<&[u8; 16]>, command: u8, is_tls: bool) {
    let content_len = data.len() as u16;
    let padding_len = calculate_padding_length(data.len(), is_tls);

    let uuid_len = if uuid.is_some() { 16 } else { 0 };
    let total_size = uuid_len + 1 + 2 + 2 + data.len() + padding_len;

    output.reserve(total_size);

    if let Some(uuid) = uuid {
        output.put_slice(uuid);
    }

    output.put_u8(command);
    output.put_u16(content_len);
    output.put_u16(padding_len as u16);
    output.put_slice(data);

    // Write random padding
    if padding_len > 0 {
        let padding_start = output.len();
        output.resize(padding_start + padding_len, 0);
        rand::rng().fill(&mut output[padding_start..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_frames_preserve_payload_uuid_and_final_command() {
        for size in [0, 8171, 8172, 65535, 65536, 150000] {
            for command in [0, 1, 2] {
                for uuid in [None, Some([9; 16])] {
                    let data: Vec<_> = (0..size).map(|i| i as u8).collect();
                    let wire = pad(&data, uuid.as_ref(), command, true);
                    let mut cursor = if let Some(uuid) = uuid {
                        assert_eq!(wire[..16], uuid);
                        16
                    } else {
                        0
                    };
                    let mut decoded = Vec::new();
                    while cursor < wire.len() {
                        let frame_command = wire[cursor];
                        let len = u16::from_be_bytes([wire[cursor + 1], wire[cursor + 2]]) as usize;
                        let padding =
                            u16::from_be_bytes([wire[cursor + 3], wire[cursor + 4]]) as usize;
                        assert!(len + padding <= MAX_PADDING_SIZE);
                        decoded.extend_from_slice(&wire[cursor + 5..cursor + 5 + len]);
                        cursor += 5 + len + padding;
                        assert_eq!(
                            frame_command,
                            if cursor == wire.len() { command } else { 0 }
                        );
                    }
                    assert_eq!(decoded, data);
                }
            }
        }
    }
}

/// Calculate padding length based on content size and TLS detection
fn calculate_padding_length(content_len: usize, is_tls: bool) -> usize {
    let mut rng = rand::rng();

    // Calculate maximum allowable padding (avoid overflow)
    // Matches Xray-core logic: buf.Size - 21 - contentLen
    // MAX_PADDING_SIZE is already (buf.Size - 21), so we only subtract content_len
    let max_allowable = MAX_PADDING_SIZE.saturating_sub(content_len);

    if is_tls && content_len < LONG_PADDING_MIN {
        // Long padding for TLS handshake phase
        let random_part = rng.random_range(0..LONG_PADDING_RANDOM_MAX);
        let padding = LONG_PADDING_MIN
            .saturating_sub(content_len)
            .saturating_add(random_part);
        std::cmp::min(padding, max_allowable)
    } else {
        // Short random padding
        let padding = rng.random_range(0..SHORT_PADDING_RANDOM_MAX);
        std::cmp::min(padding, max_allowable)
    }
}
