/// Utilities for detecting TLS handshake patterns in Vision protocol
///
/// These functions search for TLS handshake patterns to identify where the actual
/// TLS data begins in buffers that may contain protocol headers (e.g., VLESS headers).
use memchr::memmem;

/// Minimum bytes needed for a complete TLS handshake pattern
/// Pattern: [0x16, 0x03, 0x01-0x03, ?, ?, 0x01|0x02] = 6 bytes
pub const MIN_TLS_HANDSHAKE_PATTERN_LEN: usize = 6;

/// Check if the given data could be a valid TLS handshake prefix (starting from position 0)
///
/// Returns true if the data could grow into a valid TLS handshake pattern.
/// This is used to avoid buffering data that can never become TLS.
///
/// Valid prefixes:
/// - `[0x16]` - handshake record type
/// - `[0x16, 0x03]` - with major version
/// - `[0x16, 0x03, 0x01-0x03]` - with valid minor version
/// - `[0x16, 0x03, 0x01-0x03, X]` - with one length byte
/// - `[0x16, 0x03, 0x01-0x03, X, Y]` - with both length bytes
fn is_valid_tls_handshake_prefix(data: &[u8]) -> bool {
    if data.is_empty() {
        return true; // Empty could become anything
    }

    // Byte 0 must be 0x16 (Handshake record type)
    if data[0] != 0x16 {
        return false;
    }

    if data.len() >= 2 {
        // Byte 1 must be 0x03 (TLS major version)
        if data[1] != 0x03 {
            return false;
        }
    }

    if data.len() >= 3 {
        // Byte 2 must be 0x01, 0x02, or 0x03 (TLS minor version)
        if !(0x01..=0x03).contains(&data[2]) {
            return false;
        }
    }

    // Bytes 3-4 are length (any value is valid)
    // Byte 5 would be handshake type (0x01 or 0x02) but we don't check that for prefixes

    true
}

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

/// Find the longest suffix (up to 5 bytes) that could be a valid TLS handshake prefix.
///
/// Returns 0 if no suffix could be a valid TLS prefix (safe to flush entire buffer).
/// Returns 1-5 if a suffix of that length could grow into a valid TLS handshake.
///
/// This is used to minimize buffering - we can flush bytes that definitely
/// aren't part of a TLS pattern while keeping potential pattern starts.
pub fn find_potential_tls_suffix_len(data: &[u8]) -> usize {
    let len = data.len();
    if len == 0 {
        return 0;
    }

    let max_suffix = std::cmp::min(len, 5);

    // Check from longest suffix to shortest
    for suffix_len in (1..=max_suffix).rev() {
        let suffix = &data[len - suffix_len..];
        if is_valid_tls_handshake_prefix(suffix) {
            return suffix_len;
        }
    }

    0
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

    // Tests for find_potential_tls_suffix_len

    #[test]
    fn test_suffix_no_tls_bytes() {
        // No 0x16 in buffer - nothing could be TLS
        let data = vec![0x00, 0x01, 0x02, 0x03];
        assert_eq!(find_potential_tls_suffix_len(&data), 0);
    }

    #[test]
    fn test_suffix_single_0x16() {
        // Ends with 0x16 - valid 1-byte TLS prefix
        let data = vec![0x00, 0x01, 0x16];
        assert_eq!(find_potential_tls_suffix_len(&data), 1);
    }

    #[test]
    fn test_suffix_two_byte_prefix() {
        // Ends with [0x16, 0x03] - valid 2-byte TLS prefix
        let data = vec![0x00, 0x01, 0x16, 0x03];
        assert_eq!(find_potential_tls_suffix_len(&data), 2);
    }

    #[test]
    fn test_suffix_three_byte_prefix() {
        // Ends with [0x16, 0x03, 0x01] - valid 3-byte TLS prefix
        let data = vec![0x00, 0x16, 0x03, 0x01];
        assert_eq!(find_potential_tls_suffix_len(&data), 3);
    }

    #[test]
    fn test_suffix_valid_five_byte_prefix() {
        // Valid 5-byte TLS prefix
        let data = vec![0x16, 0x03, 0x03, 0xAB, 0x01];
        assert_eq!(find_potential_tls_suffix_len(&data), 5);
    }

    #[test]
    fn test_suffix_invalid_minor_version() {
        // [0x16, 0x03, 0x04, ...] - 0x04 is NOT valid minor version
        // No valid TLS prefix in this buffer
        let data = vec![0x16, 0x03, 0x04, 0x00, 0x01];
        assert_eq!(find_potential_tls_suffix_len(&data), 0);
    }

    #[test]
    fn test_suffix_large_buffer_no_pattern() {
        // Large buffer with no 0x16
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert_eq!(find_potential_tls_suffix_len(&data), 0);
    }

    #[test]
    fn test_suffix_large_buffer_with_pattern() {
        // Large buffer ending with [0x16, 0x03]
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x16, 0x03];
        assert_eq!(find_potential_tls_suffix_len(&data), 2);
    }

    // New tests for edge cases discovered during bug fix

    #[test]
    fn test_chunked_terminator_not_buffered() {
        // The HTTP chunked terminator "0\r\n\r\n" - clearly not TLS
        let data = vec![0x30, 0x0d, 0x0a, 0x0d, 0x0a];
        assert_eq!(find_potential_tls_suffix_len(&data), 0);
    }

    #[test]
    fn test_0x16_as_length_byte() {
        // [0x16, 0x03, 0x03, 0x16] - 0x16 at position 3 is a length byte (valid)
        // This was a bug in the decision tree approach
        let data = vec![0x00, 0x16, 0x03, 0x03, 0x16];
        assert_eq!(find_potential_tls_suffix_len(&data), 4);
    }

    #[test]
    fn test_0x03_as_length_byte() {
        // [0x16, 0x03, 0x01, 0x03] - 0x03 at position 3 is a length byte (valid)
        let data = vec![0x00, 0x16, 0x03, 0x01, 0x03];
        assert_eq!(find_potential_tls_suffix_len(&data), 4);
    }

    #[test]
    fn test_multiple_0x16_finds_longest_valid() {
        // Multiple 0x16 bytes - should find longest valid suffix
        // Earlier pattern was invalidated, suffix [0x16, 0x03] is valid
        let data = vec![0x16, 0x03, 0x03, 0xAB, 0x16, 0x03];
        assert_eq!(find_potential_tls_suffix_len(&data), 2);
    }

    #[test]
    fn test_single_0x16_at_end_of_large_buffer() {
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x16];
        assert_eq!(find_potential_tls_suffix_len(&data), 1);
    }

    #[test]
    fn test_five_byte_prefix_with_0x16_length() {
        // 5-byte prefix where both length bytes happen to be 0x16
        let data = vec![0x00, 0x16, 0x03, 0x03, 0x16, 0x16];
        assert_eq!(find_potential_tls_suffix_len(&data), 5);
    }

    #[test]
    fn test_empty_buffer() {
        let data: Vec<u8> = vec![];
        assert_eq!(find_potential_tls_suffix_len(&data), 0);
    }

    #[test]
    fn test_prefix_validation() {
        // Test is_valid_tls_handshake_prefix directly
        assert!(is_valid_tls_handshake_prefix(&[0x16]));
        assert!(is_valid_tls_handshake_prefix(&[0x16, 0x03]));
        assert!(is_valid_tls_handshake_prefix(&[0x16, 0x03, 0x01]));
        assert!(is_valid_tls_handshake_prefix(&[0x16, 0x03, 0x02]));
        assert!(is_valid_tls_handshake_prefix(&[0x16, 0x03, 0x03]));
        assert!(is_valid_tls_handshake_prefix(&[0x16, 0x03, 0x03, 0xFF]));
        assert!(is_valid_tls_handshake_prefix(&[
            0x16, 0x03, 0x03, 0xFF, 0xFF
        ]));

        // Invalid prefixes
        assert!(!is_valid_tls_handshake_prefix(&[0x17])); // wrong record type
        assert!(!is_valid_tls_handshake_prefix(&[0x16, 0x04])); // wrong major version
        assert!(!is_valid_tls_handshake_prefix(&[0x16, 0x03, 0x00])); // wrong minor version
        assert!(!is_valid_tls_handshake_prefix(&[0x16, 0x03, 0x04])); // wrong minor version
    }
}
