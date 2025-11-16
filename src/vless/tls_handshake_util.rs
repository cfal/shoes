/// Utilities for detecting TLS handshake patterns in Vision protocol
///
/// These functions search for TLS handshake patterns to identify where the actual
/// TLS data begins in buffers that may contain protocol headers (e.g., VLESS headers).
/// Minimum bytes needed for a complete TLS handshake pattern
/// Pattern: [0x16, 0x03, 0x01-0x03, ?, ?, 0x01|0x02] = 6 bytes
pub const MIN_TLS_HANDSHAKE_PATTERN_LEN: usize = 6;

/// Search for TLS handshake pattern using SIMD-optimized memchr
///
/// Returns Some(offset) if pattern found, None otherwise
///
/// Pattern: [0x16, 0x03, 0x01-0x03, ?, ?, 0x01|0x02]
/// - Byte 0: 0x16 (Handshake record type)
/// - Byte 1: 0x03 (TLS version major)
/// - Byte 2: 0x01-0x03 (TLS version minor: 1.0, 1.1, 1.2, or 1.3 compat)
/// - Bytes 3-4: [any] (Record length)
/// - Byte 5: 0x01 or 0x02 (ClientHello or ServerHello)
use memchr::memmem;

pub fn find_tls_handshake_start(data: &[u8]) -> Option<usize> {
    if data.len() < MIN_TLS_HANDSHAKE_PATTERN_LEN {
        return None;
    }

    // Use SIMD-optimized search for the 2-byte prefix [0x16, 0x03]
    // This is much faster than naive byte-by-byte scanning
    let finder = memmem::Finder::new(&[0x16, 0x03]);

    let mut pos = 0;
    while let Some(offset) = finder.find(&data[pos..]) {
        let absolute_offset = pos + offset;

        // Check if we have enough bytes for full pattern
        if absolute_offset + MIN_TLS_HANDSHAKE_PATTERN_LEN > data.len() {
            return None;
        }

        // Verify remaining bytes manually
        let candidate = &data[absolute_offset..];
        if (candidate[2] >= 0x01 && candidate[2] <= 0x03) // TLS minor version
            && (candidate[5] == 0x01 || candidate[5] == 0x02)
        // ClientHello or ServerHello
        {
            return Some(absolute_offset);
        }

        // Not a match, continue searching after this position
        pos = absolute_offset + 1;
    }

    None
}

/// Optimized suffix matching using decision tree based on last byte
///
/// Returns the length of suffix to keep (0-5 bytes)
///
/// Uses a decision tree: checks the last byte first to narrow down possibilities,
/// then validates from longest to shortest match for that last byte.
///
/// This is used to minimize buffering when searching for TLS patterns - if the data
/// doesn't end with a potential pattern prefix, we can flush it immediately.
///
/// If the data is shorter than the maximum pattern length (5 bytes), returns the
/// full buffer length since we can't make assumptions about partial data.
pub fn get_partial_tls_pattern_suffix_len(data: &[u8]) -> usize {
    if data.is_empty() {
        return 0;
    }

    let len = data.len();

    // If buffer is smaller than max pattern length, return full length
    // We can't make assumptions about what might grow into a pattern
    if len <= 5 {
        return len;
    }
    let last = data[len - 1];

    match last {
        // Last byte is 0x16 - can only be position 0 of pattern
        0x16 => {
            // Pattern: [0x16, ...]
            // Only need to check 1-byte suffix
            1
        }

        // Last byte is 0x03 - could be position 1 (major version) or 2 (minor version)
        0x03 => {
            // Check longest first (3-byte), fall back to 2-byte
            if len >= 3 && data[len - 3] == 0x16 && data[len - 2] == 0x03 {
                3 // [0x16, 0x03, 0x03]
            } else if len >= 2 && data[len - 2] == 0x16 {
                2 // [0x16, 0x03]
            } else {
                0
            }
        }

        // Last byte is 0x01 or 0x02 - could be position 2 (minor version if 0x01)
        // or position 3/4 (length bytes - wildcard) or position 5 (handshake type)
        0x01 | 0x02 => {
            // Check from longest to shortest: 5-byte → 4-byte → 3-byte
            if len >= 5
                && data[len - 5] == 0x16
                && data[len - 4] == 0x03
                && (data[len - 3] >= 0x01 && data[len - 3] <= 0x03)
            {
                5 // [0x16, 0x03, 0x01-0x03, ?, 0x01/0x02]
            } else if len >= 4
                && data[len - 4] == 0x16
                && data[len - 3] == 0x03
                && (data[len - 2] >= 0x01 && data[len - 2] <= 0x03)
            {
                4 // [0x16, 0x03, 0x01-0x03, 0x01/0x02]
            } else if len >= 3 && data[len - 3] == 0x16 && data[len - 2] == 0x03 && last == 0x01 {
                // Only valid if last byte is 0x01 (valid minor version)
                // 0x02 is ServerHello handshake type, not minor version
                3 // [0x16, 0x03, 0x01]
            } else {
                0
            }
        }

        // Any other byte - can only be in wildcard length field (position 3 or 4)
        _ => {
            // Check 5-byte, then 4-byte
            if len >= 5
                && data[len - 5] == 0x16
                && data[len - 4] == 0x03
                && (data[len - 3] >= 0x01 && data[len - 3] <= 0x03)
            {
                5 // [0x16, 0x03, 0x01-0x03, ?, last]
            } else if len >= 4
                && data[len - 4] == 0x16
                && data[len - 3] == 0x03
                && (data[len - 2] >= 0x01 && data[len - 2] <= 0x03)
            {
                4 // [0x16, 0x03, 0x01-0x03, last]
            } else {
                0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_tls_handshake_clienthello() {
        // TLS 1.3 ClientHello: [0x16, 0x03, 0x03, length_bytes, 0x01]
        let data = vec![0x16, 0x03, 0x03, 0x00, 0x10, 0x01];
        assert_eq!(find_tls_handshake_start(&data), Some(0));
    }

    #[test]
    fn test_find_tls_handshake_serverhello() {
        // TLS 1.3 ServerHello: [0x16, 0x03, 0x03, length_bytes, 0x02]
        let data = vec![0x16, 0x03, 0x03, 0x00, 0x10, 0x02];
        assert_eq!(find_tls_handshake_start(&data), Some(0));
    }

    #[test]
    fn test_find_tls_handshake_with_prefix() {
        // VLESS header (26 bytes) + TLS ClientHello
        let mut data = vec![0x00; 26]; // VLESS header
        data.extend_from_slice(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01]); // TLS 1.0 ClientHello
        assert_eq!(find_tls_handshake_start(&data), Some(26));
    }

    #[test]
    fn test_find_tls_handshake_not_found() {
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert_eq!(find_tls_handshake_start(&data), None);
    }

    #[test]
    fn test_find_tls_handshake_too_short() {
        let data = vec![0x16, 0x03, 0x03];
        assert_eq!(find_tls_handshake_start(&data), None);
    }

    #[test]
    fn test_suffix_len_no_pattern() {
        // Small buffer (≤ 5 bytes) returns full length
        let data = vec![0x00, 0x01, 0x02, 0x03];
        assert_eq!(get_partial_tls_pattern_suffix_len(&data), 4);
    }

    #[test]
    fn test_suffix_len_single_byte() {
        // Small buffer (≤ 5 bytes) returns full length
        let data = vec![0x00, 0x01, 0x16];
        assert_eq!(get_partial_tls_pattern_suffix_len(&data), 3);
    }

    #[test]
    fn test_suffix_len_two_bytes() {
        // Small buffer (≤ 5 bytes) returns full length
        let data = vec![0x00, 0x01, 0x16, 0x03];
        assert_eq!(get_partial_tls_pattern_suffix_len(&data), 4);
    }

    #[test]
    fn test_suffix_len_three_bytes() {
        // Small buffer (≤ 5 bytes) returns full length
        let data = vec![0x00, 0x16, 0x03, 0x01];
        assert_eq!(get_partial_tls_pattern_suffix_len(&data), 4);
    }

    #[test]
    fn test_suffix_len_five_bytes() {
        // Exactly 5 bytes, returns full length
        let data = vec![0x16, 0x03, 0x03, 0xAB, 0x01];
        assert_eq!(get_partial_tls_pattern_suffix_len(&data), 5);
    }

    #[test]
    fn test_suffix_len_false_positive() {
        // Exactly 5 bytes, returns full length (even if not valid pattern)
        let data = vec![0x16, 0x03, 0x04, 0x00, 0x01]; // 0x04 is not valid TLS minor version
        assert_eq!(get_partial_tls_pattern_suffix_len(&data), 5);
    }

    #[test]
    fn test_suffix_len_large_buffer_no_pattern() {
        // Large buffer (> 5 bytes) with no pattern at end
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert_eq!(get_partial_tls_pattern_suffix_len(&data), 0);
    }

    #[test]
    fn test_suffix_len_large_buffer_with_pattern() {
        // Large buffer (> 5 bytes) ending with partial pattern
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x16, 0x03];
        assert_eq!(get_partial_tls_pattern_suffix_len(&data), 2);
    }
}
