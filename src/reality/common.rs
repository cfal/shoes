// Common constants and helpers shared between REALITY client and server implementations
//
// This module provides:
// - TLS constants (content types, alert codes, version bytes, handshake types)
// - Close notify alert construction

use super::reality_aead::encrypt_tls13_record;
use std::io;

// TLS ContentType values
pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14;
pub const CONTENT_TYPE_ALERT: u8 = 0x15;
pub const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
pub const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

// TLS alert levels and descriptions
pub const ALERT_LEVEL_WARNING: u8 = 0x01;
pub const ALERT_DESC_CLOSE_NOTIFY: u8 = 0x00;

// TLS version bytes (used on wire for compatibility)
// TLS 1.2 version bytes: 0x03, 0x03
// Used in TLS 1.3 for compatibility (appears in record layer)
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

/// Build an encrypted close_notify alert for TLS 1.3
///
/// In TLS 1.3, alerts must be encrypted like application data.
pub fn build_close_notify_alert(key: &[u8], iv: &[u8], seq_num: u64) -> io::Result<Vec<u8>> {
    // Build alert message: level(1) + description(0) + ContentType
    let alert_with_type = vec![
        ALERT_LEVEL_WARNING,
        ALERT_DESC_CLOSE_NOTIFY,
        CONTENT_TYPE_ALERT, // ContentType byte for TLS 1.3
    ];

    // Build TLS header with correct ciphertext length
    let ciphertext_len = (alert_with_type.len() + 16) as u16; // plaintext + tag
    let mut tls_header = [
        CONTENT_TYPE_APPLICATION_DATA,
        VERSION_TLS_1_2_MAJOR,
        VERSION_TLS_1_2_MINOR,
        0x00,
        0x00, // Length will be set
    ];
    tls_header[3..5].copy_from_slice(&ciphertext_len.to_be_bytes());

    // Encrypt the alert
    let ciphertext = encrypt_tls13_record(key, iv, seq_num, &alert_with_type, &tls_header)?;

    // Build complete TLS record
    let mut record = Vec::with_capacity(5 + ciphertext.len());
    record.push(CONTENT_TYPE_APPLICATION_DATA);
    record.push(VERSION_TLS_1_2_MAJOR);
    record.push(VERSION_TLS_1_2_MINOR);
    record.push(((ciphertext.len() >> 8) & 0xff) as u8);
    record.push((ciphertext.len() & 0xff) as u8);
    record.extend_from_slice(&ciphertext);

    Ok(record)
}
