// TLS constants and utilities for REALITY client/server implementations

use std::io::{self, Error, ErrorKind};

// TLS ContentType values
pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14;
pub const CONTENT_TYPE_ALERT: u8 = 0x15;
pub const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
pub const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

// TLS alert levels and descriptions
pub const ALERT_LEVEL_WARNING: u8 = 0x01;
pub const ALERT_DESC_CLOSE_NOTIFY: u8 = 0x00;

// TLS 1.2 version bytes (0x03, 0x03) used in TLS 1.3 record layer for compatibility
pub const VERSION_TLS_1_2_MAJOR: u8 = 0x03;
pub const VERSION_TLS_1_2_MINOR: u8 = 0x03;

// TLS 1.3 handshake message types
pub const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 2;
pub const HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: u8 = 8;
pub const HANDSHAKE_TYPE_CERTIFICATE: u8 = 11;
pub const HANDSHAKE_TYPE_CERTIFICATE_VERIFY: u8 = 15;
pub const HANDSHAKE_TYPE_FINISHED: u8 = 20;

// TLS 1.3 record size limits per RFC 8446
//
// The TLS record header's `length` field specifies the size of the ENCRYPTED payload.
// Per RFC 8446, the TLS 1.3 limit is stricter than TLS 1.2:
//
// - TLS 1.3: Plaintext limit = 16,384 bytes (2^14)
//   Encryption overhead allowance = 256 bytes
//   Ciphertext limit = 16,384 + 256 = 16,640 bytes
//
// - TLS 1.2: Plaintext limit = 16,384 bytes (2^14)
//   Encryption overhead allowance = 2,048 bytes
//   Ciphertext limit = 16,384 + 2,048 = 18,432 bytes
//
// REALITY uses TLS 1.3, so we MUST use the TLS 1.3 limit. Using the larger
// TLS 1.2 limit causes "record overflow" errors in libraries like utls.

/// Maximum TLS 1.3 ciphertext payload size (16,640 bytes)
pub const MAX_TLS_CIPHERTEXT_LEN: usize = 16384 + 256;

/// Maximum plaintext payload size for a single TLS 1.3 record
///
/// RFC 8446 Section 5.1: "The record layer fragments information blocks into
/// TLSPlaintext records carrying data in chunks of 2^14 bytes or less."
///
/// This is the hard limit enforced by TLS implementations.
/// The 256-byte allowance in MAX_TLS_CIPHERTEXT_LEN is for:
/// - AEAD tag (16 bytes for AES-GCM)
/// - Content type byte (1 byte)
/// - Optional padding (up to 239 bytes)
///
/// We MUST NOT exceed 16384 bytes of actual plaintext per record, or clients
/// will reject with "record overflow" error.
pub const MAX_TLS_PLAINTEXT_LEN: usize = 16384;

/// TLS record header size (ContentType + ProtocolVersion + Length)
pub const TLS_RECORD_HEADER_SIZE: usize = 5;

/// Maximum TLS record size (ciphertext + header)
pub const TLS_MAX_RECORD_SIZE: usize = MAX_TLS_CIPHERTEXT_LEN + TLS_RECORD_HEADER_SIZE;

/// Buffer capacity for ciphertext read (2x TLS max record for safety)
pub const CIPHERTEXT_READ_BUF_CAPACITY: usize = TLS_MAX_RECORD_SIZE * 2;

/// Buffer capacity for plaintext read
pub const PLAINTEXT_READ_BUF_CAPACITY: usize = TLS_MAX_RECORD_SIZE * 2;

/// Buffer capacity for outgoing data (matches rustls DEFAULT_BUFFER_LIMIT)
///
/// This controls the size of both the plaintext write buffer (pre-encryption)
/// and ciphertext write buffer (post-encryption). rustls uses 64KB for both.
pub const OUTGOING_BUFFER_LIMIT: usize = 64 * 1024;

/// Strip TLS 1.3 content type trailer from decrypted plaintext slice.
///
/// TLS 1.3 format: content || type_byte
/// Returns (content_type, valid_content_length) without modifying the slice.
///
/// This is the zero-allocation version for use with in-place decryption.
/// NOTE: Does NOT strip padding zeros - our implementation doesn't add padding.
#[inline]
pub fn strip_content_type_slice(plaintext: &[u8]) -> io::Result<(u8, usize)> {
    if plaintext.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "Empty plaintext"));
    }

    // No padding in our implementation
    let content_type = plaintext[plaintext.len() - 1];

    if content_type != CONTENT_TYPE_HANDSHAKE
        && content_type != CONTENT_TYPE_APPLICATION_DATA
        && content_type != CONTENT_TYPE_ALERT
    {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Invalid content type: 0x{:02x}", content_type),
        ));
    }

    Ok((content_type, plaintext.len() - 1))
}

/// Strip TLS 1.3 content type trailer from decrypted plaintext.
///
/// TLS 1.3 format: content || type_byte
/// Returns the actual content type and modifies plaintext to contain only content.
///
/// NOTE: This function does NOT strip padding zeros. Our REALITY implementation
/// does not add padding, so stripping zeros could corrupt data that legitimately
/// ends with zero bytes. Use `strip_content_type_with_padding` for messages from
/// external implementations that may use padding.
///
/// Only used by tests - the hot path uses `strip_content_type_slice` for zero-allocation.
#[cfg(test)]
pub fn strip_content_type(plaintext: &mut Vec<u8>) -> io::Result<u8> {
    let (content_type, valid_len) = strip_content_type_slice(plaintext)?;
    plaintext.truncate(valid_len);
    Ok(content_type)
}

/// Strip TLS 1.3 content type trailer and padding from decrypted plaintext.
///
/// TLS 1.3 format: content || type_byte || padding_zeros
/// Returns the actual content type and modifies plaintext to contain only content.
///
/// Use this for messages from external TLS implementations (e.g., sing-box) that
/// may add optional padding per RFC 8446 Section 5.4.
pub fn strip_content_type_with_padding(plaintext: &mut Vec<u8>) -> io::Result<u8> {
    if plaintext.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "Empty plaintext"));
    }

    // Remove trailing zeros (padding) per RFC 8446 Section 5.4
    while !plaintext.is_empty() && *plaintext.last().unwrap() == 0 {
        plaintext.pop();
    }

    if plaintext.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "Plaintext is all zeros"));
    }

    let content_type = plaintext.pop().unwrap();

    if content_type != CONTENT_TYPE_HANDSHAKE
        && content_type != CONTENT_TYPE_APPLICATION_DATA
        && content_type != CONTENT_TYPE_ALERT
    {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Invalid content type: 0x{:02x}", content_type),
        ));
    }

    Ok(content_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_content_type_app_data() {
        let mut plaintext = vec![0x01, 0x02, 0x03, CONTENT_TYPE_APPLICATION_DATA];
        let ct = strip_content_type(&mut plaintext).unwrap();
        assert_eq!(ct, CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(plaintext, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_strip_content_type_handshake() {
        let mut plaintext = vec![0xAA, 0xBB, CONTENT_TYPE_HANDSHAKE];
        let ct = strip_content_type(&mut plaintext).unwrap();
        assert_eq!(ct, CONTENT_TYPE_HANDSHAKE);
        assert_eq!(plaintext, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_strip_content_type_alert() {
        let mut plaintext = vec![0x01, 0x00, CONTENT_TYPE_ALERT];
        let ct = strip_content_type(&mut plaintext).unwrap();
        assert_eq!(ct, CONTENT_TYPE_ALERT);
        assert_eq!(plaintext, vec![0x01, 0x00]);
    }

    #[test]
    fn test_strip_content_type_preserves_zeros() {
        // Trailing zeros in data should be preserved (not treated as padding)
        let mut plaintext = vec![0x01, 0x00, 0x00, CONTENT_TYPE_APPLICATION_DATA];
        let ct = strip_content_type(&mut plaintext).unwrap();
        assert_eq!(ct, CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(plaintext, vec![0x01, 0x00, 0x00]);
    }

    #[test]
    fn test_strip_content_type_empty() {
        let mut plaintext = Vec::new();
        assert!(strip_content_type(&mut plaintext).is_err());
    }

    #[test]
    fn test_strip_content_type_invalid() {
        let mut plaintext = vec![0x01, 0xFF]; // 0xFF is invalid
        assert!(strip_content_type(&mut plaintext).is_err());
    }

    #[test]
    fn test_strip_with_padding_no_padding() {
        let mut plaintext = vec![0x01, 0x02, CONTENT_TYPE_APPLICATION_DATA];
        let ct = strip_content_type_with_padding(&mut plaintext).unwrap();
        assert_eq!(ct, CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(plaintext, vec![0x01, 0x02]);
    }

    #[test]
    fn test_strip_with_padding_strips_zeros() {
        // TLS 1.3 format: content || type || padding
        let mut plaintext = vec![0x01, 0x02, CONTENT_TYPE_HANDSHAKE, 0x00, 0x00, 0x00];
        let ct = strip_content_type_with_padding(&mut plaintext).unwrap();
        assert_eq!(ct, CONTENT_TYPE_HANDSHAKE);
        assert_eq!(plaintext, vec![0x01, 0x02]);
    }

    #[test]
    fn test_strip_with_padding_empty() {
        let mut plaintext = Vec::new();
        assert!(strip_content_type_with_padding(&mut plaintext).is_err());
    }

    #[test]
    fn test_strip_with_padding_all_zeros() {
        let mut plaintext = vec![0x00, 0x00, 0x00];
        assert!(strip_content_type_with_padding(&mut plaintext).is_err());
    }

    #[test]
    fn test_strip_with_padding_invalid_type() {
        let mut plaintext = vec![0x01, 0xFF, 0x00]; // 0xFF with padding
        assert!(strip_content_type_with_padding(&mut plaintext).is_err());
    }
}
