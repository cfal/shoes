use bytes::{BufMut, Bytes, BytesMut};
use rand::Rng;

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

fn pad(data: &[u8], uuid: Option<&[u8; 16]>, command: u8, is_tls: bool) -> Bytes {
    let content_len = data.len() as u16;
    let padding_len = calculate_padding_length(content_len as usize, is_tls);

    let uuid_len = if uuid.is_some() { 16 } else { 0 };
    let total_size = uuid_len + 1 + 2 + 2 + data.len() + padding_len;

    let mut output = BytesMut::with_capacity(total_size);

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

    output.freeze()
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
