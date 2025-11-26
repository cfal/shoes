// TLS 1.3 record encryption with automatic fragmentation
//
// Handles encrypting plaintext into TLS records, automatically splitting
// large data into multiple records to stay within TLS 1.3 size limits.

use std::io;

use super::common::{
    CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_HANDSHAKE, MAX_TLS_CIPHERTEXT_LEN,
    MAX_TLS_PLAINTEXT_LEN, TLS_RECORD_HEADER_SIZE, increment_seq,
};
use super::reality_aead::encrypt_tls13_record;
use super::reality_cipher_suite::CipherSuite;

/// Encrypt plaintext into TLS 1.3 records with CipherSuite, fragmenting if necessary.
#[inline]
pub fn encrypt_plaintext_to_records(
    cipher_suite: CipherSuite,
    plaintext: &mut Vec<u8>,
    app_write_key: &[u8],
    app_write_iv: &[u8],
    write_seq: &mut u64,
    ciphertext_buf: &mut Vec<u8>,
) -> io::Result<()> {
    if plaintext.is_empty() {
        return Ok(());
    }

    // Fast path: single record (most common case, ~16KB or less)
    if plaintext.len() <= MAX_TLS_PLAINTEXT_LEN {
        encrypt_single_record(
            cipher_suite,
            plaintext,
            app_write_key,
            app_write_iv,
            write_seq,
            ciphertext_buf,
        )?;
        plaintext.clear();
        return Ok(());
    }

    // Slow path: fragment into multiple records
    let total_len = plaintext.len();
    let num_records = total_len.div_ceil(MAX_TLS_PLAINTEXT_LEN);
    log::debug!(
        "REALITY: Fragmenting {} bytes into {} TLS records (max {} bytes/record)",
        total_len,
        num_records,
        MAX_TLS_PLAINTEXT_LEN
    );

    let mut offset = 0;
    while offset < plaintext.len() {
        let chunk_end = (offset + MAX_TLS_PLAINTEXT_LEN).min(plaintext.len());
        let chunk = &plaintext[offset..chunk_end];

        encrypt_chunk_with_type(
            cipher_suite,
            chunk,
            app_write_key,
            app_write_iv,
            write_seq,
            ciphertext_buf,
            CONTENT_TYPE_APPLICATION_DATA,
        )?;
        offset = chunk_end;
    }

    plaintext.clear();
    Ok(())
}

#[inline]
fn encrypt_single_record(
    cipher_suite: CipherSuite,
    plaintext: &mut Vec<u8>,
    app_write_key: &[u8],
    app_write_iv: &[u8],
    write_seq: &mut u64,
    ciphertext_buf: &mut Vec<u8>,
) -> io::Result<()> {
    let mut plaintext_with_type = std::mem::take(plaintext);
    plaintext_with_type.push(CONTENT_TYPE_APPLICATION_DATA);

    let ciphertext_len = (plaintext_with_type.len() + 16) as u16;

    let tls_header: [u8; TLS_RECORD_HEADER_SIZE] = [
        CONTENT_TYPE_APPLICATION_DATA,
        0x03,
        0x03,
        (ciphertext_len >> 8) as u8,
        (ciphertext_len & 0xff) as u8,
    ];

    let ciphertext = encrypt_tls13_record(
        cipher_suite,
        app_write_key,
        app_write_iv,
        *write_seq,
        &plaintext_with_type,
        &tls_header,
    )?;

    increment_seq(write_seq)?;

    ciphertext_buf.reserve(TLS_RECORD_HEADER_SIZE + ciphertext.len());
    ciphertext_buf.extend_from_slice(&tls_header);
    ciphertext_buf.extend_from_slice(&ciphertext);

    *plaintext = plaintext_with_type;

    Ok(())
}

#[inline]
fn encrypt_chunk_with_type(
    cipher_suite: CipherSuite,
    chunk: &[u8],
    key: &[u8],
    iv: &[u8],
    write_seq: &mut u64,
    ciphertext_buf: &mut Vec<u8>,
    inner_content_type: u8,
) -> io::Result<()> {
    let mut plaintext_with_type = Vec::with_capacity(chunk.len() + 1);
    plaintext_with_type.extend_from_slice(chunk);
    plaintext_with_type.push(inner_content_type);

    let ciphertext_len = (plaintext_with_type.len() + 16) as u16;

    debug_assert!(
        (ciphertext_len as usize) <= MAX_TLS_CIPHERTEXT_LEN,
        "BUG: ciphertext_len {} exceeds MAX_TLS_CIPHERTEXT_LEN {}",
        ciphertext_len,
        MAX_TLS_CIPHERTEXT_LEN
    );

    let tls_header: [u8; TLS_RECORD_HEADER_SIZE] = [
        CONTENT_TYPE_APPLICATION_DATA,
        0x03,
        0x03,
        (ciphertext_len >> 8) as u8,
        (ciphertext_len & 0xff) as u8,
    ];

    let ciphertext = encrypt_tls13_record(
        cipher_suite,
        key,
        iv,
        *write_seq,
        &plaintext_with_type,
        &tls_header,
    )?;

    increment_seq(write_seq)?;

    ciphertext_buf.reserve(TLS_RECORD_HEADER_SIZE + ciphertext.len());
    ciphertext_buf.extend_from_slice(&tls_header);
    ciphertext_buf.extend_from_slice(&ciphertext);

    Ok(())
}

/// Encrypt handshake data into TLS 1.3 records with CipherSuite, fragmenting if necessary.
#[inline]
pub fn encrypt_handshake_to_records(
    cipher_suite: CipherSuite,
    handshake_data: &[u8],
    key: &[u8],
    iv: &[u8],
    write_seq: &mut u64,
    ciphertext_buf: &mut Vec<u8>,
) -> io::Result<()> {
    if handshake_data.is_empty() {
        return Ok(());
    }

    if handshake_data.len() <= MAX_TLS_PLAINTEXT_LEN {
        encrypt_chunk_with_type(
            cipher_suite,
            handshake_data,
            key,
            iv,
            write_seq,
            ciphertext_buf,
            CONTENT_TYPE_HANDSHAKE,
        )?;
    } else {
        let total_len = handshake_data.len();
        let num_records = total_len.div_ceil(MAX_TLS_PLAINTEXT_LEN);
        log::debug!(
            "REALITY: Fragmenting {} bytes of handshake data into {} TLS records (max {} bytes/record)",
            total_len,
            num_records,
            MAX_TLS_PLAINTEXT_LEN
        );

        let mut offset = 0;
        while offset < handshake_data.len() {
            let chunk_end = (offset + MAX_TLS_PLAINTEXT_LEN).min(handshake_data.len());
            let chunk = &handshake_data[offset..chunk_end];

            encrypt_chunk_with_type(
                cipher_suite,
                chunk,
                key,
                iv,
                write_seq,
                ciphertext_buf,
                CONTENT_TYPE_HANDSHAKE,
            )?;
            offset = chunk_end;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::common::{CIPHERTEXT_READ_BUF_CAPACITY, TLS_MAX_RECORD_SIZE};

    const CS: CipherSuite = CipherSuite::AES_128_GCM_SHA256;

    #[test]
    fn test_constants() {
        // Verify constants match expected TLS 1.3 values
        assert_eq!(MAX_TLS_CIPHERTEXT_LEN, 16640); // TLS 1.3 limit: 16384 + 256
        assert_eq!(MAX_TLS_PLAINTEXT_LEN, 16384); // RFC 8446: 2^14 bytes max plaintext
        assert_eq!(TLS_RECORD_HEADER_SIZE, 5);
        assert_eq!(TLS_MAX_RECORD_SIZE, 16645); // 16640 + 5
        assert_eq!(CIPHERTEXT_READ_BUF_CAPACITY, 33290); // 2 * TLS_MAX_RECORD_SIZE
    }

    #[test]
    fn test_encrypt_empty_plaintext() {
        let mut plaintext = Vec::new();
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_plaintext_to_records(
            CS,
            &mut plaintext,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert!(ciphertext_buf.is_empty());
        assert_eq!(seq, 0); // No records encrypted
    }

    #[test]
    fn test_encrypt_small_plaintext_single_record() {
        let mut plaintext = vec![0x41u8; 100]; // 100 bytes of 'A'
        let key = [0x01u8; 16];
        let iv = [0x02u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_plaintext_to_records(
            CS,
            &mut plaintext,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert!(plaintext.is_empty()); // Should be cleared

        // Should have one record: header(5) + plaintext(100) + content_type(1) + tag(16)
        let expected_len = TLS_RECORD_HEADER_SIZE + 100 + 1 + 16;
        assert_eq!(ciphertext_buf.len(), expected_len);
        assert_eq!(seq, 1); // One record encrypted

        // Verify TLS header
        assert_eq!(ciphertext_buf[0], CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(ciphertext_buf[1], 0x03);
        assert_eq!(ciphertext_buf[2], 0x03);
        let record_len = u16::from_be_bytes([ciphertext_buf[3], ciphertext_buf[4]]) as usize;
        assert_eq!(record_len, 100 + 1 + 16);
    }

    #[test]
    fn test_encrypt_max_single_record() {
        // Test exactly at the boundary - should still be single record
        let mut plaintext = vec![0x42u8; MAX_TLS_PLAINTEXT_LEN];
        let key = [0x03u8; 16];
        let iv = [0x04u8; 12];
        let mut seq = 5u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_plaintext_to_records(
            CS,
            &mut plaintext,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert!(plaintext.is_empty());

        // Should have one record
        let expected_len = TLS_RECORD_HEADER_SIZE + MAX_TLS_PLAINTEXT_LEN + 1 + 16;
        assert_eq!(ciphertext_buf.len(), expected_len);
        assert_eq!(seq, 6); // One record encrypted
    }

    #[test]
    fn test_encrypt_fragmentation_two_records() {
        // One byte over the limit - should produce two records
        let mut plaintext = vec![0x43u8; MAX_TLS_PLAINTEXT_LEN + 1];
        let key = [0x05u8; 16];
        let iv = [0x06u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_plaintext_to_records(
            CS,
            &mut plaintext,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert!(plaintext.is_empty());
        assert_eq!(seq, 2); // Two records encrypted

        // First record: full MAX_TLS_PLAINTEXT_LEN
        let first_record_len = TLS_RECORD_HEADER_SIZE + MAX_TLS_PLAINTEXT_LEN + 1 + 16;
        // Second record: 1 byte
        let second_record_len = TLS_RECORD_HEADER_SIZE + 1 + 1 + 16;
        assert_eq!(ciphertext_buf.len(), first_record_len + second_record_len);

        // Verify first record header
        assert_eq!(ciphertext_buf[0], CONTENT_TYPE_APPLICATION_DATA);
        let first_payload_len = u16::from_be_bytes([ciphertext_buf[3], ciphertext_buf[4]]) as usize;
        assert_eq!(first_payload_len, MAX_TLS_PLAINTEXT_LEN + 1 + 16);

        // Verify second record header
        let second_header_offset = first_record_len;
        assert_eq!(
            ciphertext_buf[second_header_offset],
            CONTENT_TYPE_APPLICATION_DATA
        );
        let second_payload_len = u16::from_be_bytes([
            ciphertext_buf[second_header_offset + 3],
            ciphertext_buf[second_header_offset + 4],
        ]) as usize;
        assert_eq!(second_payload_len, 1 + 1 + 16);
    }

    #[test]
    fn test_encrypt_fragmentation_multiple_records() {
        // Test 3x the max size - should produce 3 records
        let size = MAX_TLS_PLAINTEXT_LEN * 3;
        let mut plaintext = vec![0x44u8; size];
        let key = [0x07u8; 16];
        let iv = [0x08u8; 12];
        let mut seq = 10u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_plaintext_to_records(
            CS,
            &mut plaintext,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert!(plaintext.is_empty());
        assert_eq!(seq, 13); // Three records encrypted

        // Each record: header(5) + MAX_TLS_PLAINTEXT_LEN + content_type(1) + tag(16)
        let record_len = TLS_RECORD_HEADER_SIZE + MAX_TLS_PLAINTEXT_LEN + 1 + 16;
        assert_eq!(ciphertext_buf.len(), record_len * 3);
    }

    #[test]
    fn test_encrypt_fragmentation_uneven_split() {
        // Test size that doesn't divide evenly
        let size = MAX_TLS_PLAINTEXT_LEN * 2 + 1000;
        let mut plaintext = vec![0x45u8; size];
        let key = [0x09u8; 16];
        let iv = [0x0Au8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_plaintext_to_records(
            CS,
            &mut plaintext,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert!(plaintext.is_empty());
        assert_eq!(seq, 3); // Three records

        // Two full records + one partial
        let full_record_len = TLS_RECORD_HEADER_SIZE + MAX_TLS_PLAINTEXT_LEN + 1 + 16;
        let partial_record_len = TLS_RECORD_HEADER_SIZE + 1000 + 1 + 16;
        assert_eq!(
            ciphertext_buf.len(),
            full_record_len * 2 + partial_record_len
        );
    }

    #[test]
    fn test_sequence_number_increments() {
        let key = [0x0Bu8; 16];
        let iv = [0x0Cu8; 12];
        let mut seq = 100u64;
        let mut ciphertext_buf = Vec::new();

        // First call with small data
        let mut plaintext1 = vec![0x46u8; 50];
        encrypt_plaintext_to_records(
            CS,
            &mut plaintext1,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        )
        .unwrap();
        assert_eq!(seq, 101);

        // Second call with data requiring fragmentation
        let mut plaintext2 = vec![0x47u8; MAX_TLS_PLAINTEXT_LEN + 500];
        encrypt_plaintext_to_records(
            CS,
            &mut plaintext2,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        )
        .unwrap();
        assert_eq!(seq, 103); // Two more records
    }

    #[test]
    fn test_ciphertext_buf_appends() {
        let key = [0x0Du8; 16];
        let iv = [0x0Eu8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        // Pre-populate buffer
        ciphertext_buf.extend_from_slice(b"existing data");
        let initial_len = ciphertext_buf.len();

        let mut plaintext = vec![0x48u8; 100];
        encrypt_plaintext_to_records(CS, &mut plaintext, &key, &iv, &mut seq, &mut ciphertext_buf)
            .unwrap();

        // Should append, not overwrite
        assert!(ciphertext_buf.len() > initial_len);
        assert_eq!(&ciphertext_buf[..initial_len], b"existing data");
    }

    #[test]
    fn test_encrypt_single_byte() {
        // Minimum non-empty plaintext
        let mut plaintext = vec![0x42u8; 1];
        let key = [0x0Fu8; 16];
        let iv = [0x10u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_plaintext_to_records(
            CS,
            &mut plaintext,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert!(plaintext.is_empty());
        assert_eq!(seq, 1);

        // header(5) + plaintext(1) + content_type(1) + tag(16) = 23
        assert_eq!(ciphertext_buf.len(), 23);
    }

    #[test]
    fn test_encrypt_boundary_minus_one() {
        // One byte below the limit - should still be single record (fast path)
        let mut plaintext = vec![0x49u8; MAX_TLS_PLAINTEXT_LEN - 1];
        let key = [0x11u8; 16];
        let iv = [0x12u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_plaintext_to_records(
            CS,
            &mut plaintext,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert!(plaintext.is_empty());
        assert_eq!(seq, 1); // Still single record

        let expected_len = TLS_RECORD_HEADER_SIZE + (MAX_TLS_PLAINTEXT_LEN - 1) + 1 + 16;
        assert_eq!(ciphertext_buf.len(), expected_len);
    }

    #[test]
    fn test_encrypt_large_500kb() {
        // 500KB = 512000 bytes, requires 32 records (512000 / 16384 = 31.25)
        let size = 512000;
        let expected_records = (size + MAX_TLS_PLAINTEXT_LEN - 1) / MAX_TLS_PLAINTEXT_LEN;
        assert_eq!(expected_records, 32); // Verify our math

        let mut plaintext = vec![0x4Au8; size];
        let key = [0x13u8; 16];
        let iv = [0x14u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_plaintext_to_records(
            CS,
            &mut plaintext,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert!(plaintext.is_empty());
        assert_eq!(seq, 32); // 32 records

        // 31 full records + 1 partial
        let full_records = 31;
        let last_record_plaintext = size - (full_records * MAX_TLS_PLAINTEXT_LEN);
        let full_record_len = TLS_RECORD_HEADER_SIZE + MAX_TLS_PLAINTEXT_LEN + 1 + 16;
        let last_record_len = TLS_RECORD_HEADER_SIZE + last_record_plaintext + 1 + 16;
        let expected_total = full_records * full_record_len + last_record_len;
        assert_eq!(ciphertext_buf.len(), expected_total);
    }

    #[test]
    fn test_sequence_number_high_values() {
        // Test with sequence number near u64::MAX to ensure no overflow issues
        let key = [0x15u8; 16];
        let iv = [0x16u8; 12];
        let mut seq = u64::MAX - 5;
        let mut ciphertext_buf = Vec::new();

        // Small data - single record
        let mut plaintext = vec![0x4Bu8; 100];
        let result = encrypt_plaintext_to_records(
            CS,
            &mut plaintext,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert_eq!(seq, u64::MAX - 4);

        // Another small record
        let mut plaintext2 = vec![0x4Cu8; 100];
        let result2 = encrypt_plaintext_to_records(
            CS,
            &mut plaintext2,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result2.is_ok());
        assert_eq!(seq, u64::MAX - 3);
    }

    #[test]
    fn test_record_headers_valid() {
        // Verify all record headers in a fragmented output are valid TLS 1.3 headers
        let size = MAX_TLS_PLAINTEXT_LEN * 3 + 100; // 3 full + 1 partial = 4 records
        let mut plaintext = vec![0x4Du8; size];
        let key = [0x17u8; 16];
        let iv = [0x18u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        encrypt_plaintext_to_records(CS, &mut plaintext, &key, &iv, &mut seq, &mut ciphertext_buf)
            .unwrap();
        assert_eq!(seq, 4);

        // Parse and verify each record header
        let mut offset = 0;
        for i in 0..4 {
            assert!(
                offset + 5 <= ciphertext_buf.len(),
                "Record {} header incomplete",
                i
            );

            // Content type should be application_data (0x17)
            assert_eq!(
                ciphertext_buf[offset], 0x17,
                "Record {} wrong content type",
                i
            );

            // Version should be TLS 1.2 (0x0303) for compatibility
            assert_eq!(
                ciphertext_buf[offset + 1],
                0x03,
                "Record {} wrong version major",
                i
            );
            assert_eq!(
                ciphertext_buf[offset + 2],
                0x03,
                "Record {} wrong version minor",
                i
            );

            // Length field
            let record_len =
                u16::from_be_bytes([ciphertext_buf[offset + 3], ciphertext_buf[offset + 4]])
                    as usize;

            // Record length must not exceed TLS 1.3 limit
            assert!(
                record_len <= MAX_TLS_CIPHERTEXT_LEN,
                "Record {} length {} exceeds TLS 1.3 limit {}",
                i,
                record_len,
                MAX_TLS_CIPHERTEXT_LEN
            );

            offset += 5 + record_len;
        }

        // Should have consumed exactly all data
        assert_eq!(offset, ciphertext_buf.len(), "Unexpected trailing data");
    }

    // ==================== Additional app data edge case tests ====================

    #[test]
    fn test_app_data_different_keys_produce_different_output() {
        let key1 = [0x50u8; 16];
        let key2 = [0x51u8; 16];
        let iv = [0x52u8; 12];

        let mut data1 = vec![0xAAu8; 100];
        let mut data2 = vec![0xAAu8; 100];
        let mut seq1 = 0u64;
        let mut seq2 = 0u64;
        let mut buf1 = Vec::new();
        let mut buf2 = Vec::new();

        encrypt_plaintext_to_records(CS, &mut data1, &key1, &iv, &mut seq1, &mut buf1).unwrap();
        encrypt_plaintext_to_records(CS, &mut data2, &key2, &iv, &mut seq2, &mut buf2).unwrap();

        assert_eq!(buf1.len(), buf2.len());
        assert_ne!(buf1, buf2); // Different keys = different ciphertext
    }

    #[test]
    fn test_app_data_different_ivs_produce_different_output() {
        let key = [0x53u8; 16];
        let iv1 = [0x54u8; 12];
        let iv2 = [0x55u8; 12];

        let mut data1 = vec![0xBBu8; 100];
        let mut data2 = vec![0xBBu8; 100];
        let mut seq1 = 0u64;
        let mut seq2 = 0u64;
        let mut buf1 = Vec::new();
        let mut buf2 = Vec::new();

        encrypt_plaintext_to_records(CS, &mut data1, &key, &iv1, &mut seq1, &mut buf1).unwrap();
        encrypt_plaintext_to_records(CS, &mut data2, &key, &iv2, &mut seq2, &mut buf2).unwrap();

        assert_eq!(buf1.len(), buf2.len());
        assert_ne!(buf1, buf2); // Different IVs = different ciphertext
    }

    #[test]
    fn test_app_data_different_seq_produce_different_output() {
        let key = [0x56u8; 16];
        let iv = [0x57u8; 12];

        let mut data1 = vec![0xCCu8; 100];
        let mut data2 = vec![0xCCu8; 100];
        let mut seq1 = 0u64;
        let mut seq2 = 50u64;
        let mut buf1 = Vec::new();
        let mut buf2 = Vec::new();

        encrypt_plaintext_to_records(CS, &mut data1, &key, &iv, &mut seq1, &mut buf1).unwrap();
        encrypt_plaintext_to_records(CS, &mut data2, &key, &iv, &mut seq2, &mut buf2).unwrap();

        assert_eq!(buf1.len(), buf2.len());
        assert_ne!(buf1, buf2); // Different seq = different nonce = different ciphertext
    }

    #[test]
    fn test_app_data_exactly_double_limit() {
        let mut plaintext = vec![0xDDu8; MAX_TLS_PLAINTEXT_LEN * 2];
        let key = [0x58u8; 16];
        let iv = [0x59u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        encrypt_plaintext_to_records(CS, &mut plaintext, &key, &iv, &mut seq, &mut ciphertext_buf)
            .unwrap();
        assert!(plaintext.is_empty());
        assert_eq!(seq, 2);

        // Both records: header(5) + plaintext + content_type(1) + tag(16)
        let expected_len = 2 * (TLS_RECORD_HEADER_SIZE + MAX_TLS_PLAINTEXT_LEN + 1 + 16);
        assert_eq!(ciphertext_buf.len(), expected_len);
    }

    #[test]
    fn test_app_data_exactly_triple_limit() {
        let mut plaintext = vec![0xEEu8; MAX_TLS_PLAINTEXT_LEN * 3];
        let key = [0x5Au8; 16];
        let iv = [0x5Bu8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        encrypt_plaintext_to_records(CS, &mut plaintext, &key, &iv, &mut seq, &mut ciphertext_buf)
            .unwrap();
        assert!(plaintext.is_empty());
        assert_eq!(seq, 3);

        // Three records: header(5) + plaintext + content_type(1) + tag(16)
        let expected_len = 3 * (TLS_RECORD_HEADER_SIZE + MAX_TLS_PLAINTEXT_LEN + 1 + 16);
        assert_eq!(ciphertext_buf.len(), expected_len);
    }

    #[test]
    fn test_app_data_256kb_stress() {
        let size = 256 * 1024;
        let expected_records = (size + MAX_TLS_PLAINTEXT_LEN - 1) / MAX_TLS_PLAINTEXT_LEN;
        assert_eq!(expected_records, 16);

        let mut plaintext = vec![0xFFu8; size];
        let key = [0x5Cu8; 16];
        let iv = [0x5Du8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        encrypt_plaintext_to_records(CS, &mut plaintext, &key, &iv, &mut seq, &mut ciphertext_buf)
            .unwrap();
        assert!(plaintext.is_empty());
        assert_eq!(seq, 16);

        // Verify all records valid
        let mut offset = 0;
        let mut count = 0;
        while offset < ciphertext_buf.len() {
            let record_len =
                u16::from_be_bytes([ciphertext_buf[offset + 3], ciphertext_buf[offset + 4]])
                    as usize;
            assert!(record_len <= MAX_TLS_CIPHERTEXT_LEN);
            offset += 5 + record_len;
            count += 1;
        }
        assert_eq!(count, 16);
    }

    #[test]
    fn test_app_data_preserves_structure() {
        // Verify total plaintext reconstructable from records
        let mut plaintext = vec![0x11u8; 20000];
        let key = [0x5Eu8; 16];
        let iv = [0x5Fu8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        encrypt_plaintext_to_records(CS, &mut plaintext, &key, &iv, &mut seq, &mut ciphertext_buf)
            .unwrap();

        let mut offset = 0;
        let mut total_plaintext = 0;
        while offset < ciphertext_buf.len() {
            let record_len =
                u16::from_be_bytes([ciphertext_buf[offset + 3], ciphertext_buf[offset + 4]])
                    as usize;
            total_plaintext += record_len - 16 - 1; // minus tag and content type
            offset += 5 + record_len;
        }
        assert_eq!(total_plaintext, 20000);
    }

    #[test]
    fn test_app_data_small_prime_sizes() {
        for &size in &[17usize, 31, 127, 251, 509, 1021, 2039, 4093, 8191] {
            let mut plaintext = vec![0x22u8; size];
            let key = [0x60u8; 16];
            let iv = [0x61u8; 12];
            let mut seq = 0u64;
            let mut ciphertext_buf = Vec::new();

            encrypt_plaintext_to_records(
                CS,
                &mut plaintext,
                &key,
                &iv,
                &mut seq,
                &mut ciphertext_buf,
            )
            .unwrap();
            assert!(plaintext.is_empty());
            assert_eq!(seq, 1, "Size {} should be single record", size);

            let record_len = u16::from_be_bytes([ciphertext_buf[3], ciphertext_buf[4]]) as usize;
            assert_eq!(record_len, size + 1 + 16);
        }
    }

    #[test]
    fn test_app_data_near_boundary_primes() {
        let primes = [16619, 16631, 16633, 16649];
        for &size in &primes {
            let mut plaintext = vec![0x33u8; size];
            let key = [0x62u8; 16];
            let iv = [0x63u8; 12];
            let mut seq = 0u64;
            let mut ciphertext_buf = Vec::new();

            encrypt_plaintext_to_records(
                CS,
                &mut plaintext,
                &key,
                &iv,
                &mut seq,
                &mut ciphertext_buf,
            )
            .unwrap();
            assert!(plaintext.is_empty());

            let expected_records = if size <= MAX_TLS_PLAINTEXT_LEN { 1 } else { 2 };
            assert_eq!(
                seq, expected_records,
                "Wrong record count for size {}",
                size
            );
        }
    }

    #[test]
    fn test_app_data_multiple_calls_accumulate() {
        let key = [0x64u8; 16];
        let iv = [0x65u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        let mut data1 = vec![0x44u8; 1000];
        encrypt_plaintext_to_records(CS, &mut data1, &key, &iv, &mut seq, &mut ciphertext_buf)
            .unwrap();
        let len1 = ciphertext_buf.len();
        assert_eq!(seq, 1);

        let mut data2 = vec![0x55u8; MAX_TLS_PLAINTEXT_LEN + 500];
        encrypt_plaintext_to_records(CS, &mut data2, &key, &iv, &mut seq, &mut ciphertext_buf)
            .unwrap();
        assert!(ciphertext_buf.len() > len1);
        assert_eq!(seq, 3); // 1 + 2 more
    }

    #[test]
    fn test_app_data_high_sequence_fragmentation() {
        let key = [0x66u8; 16];
        let iv = [0x67u8; 12];
        let mut seq = u64::MAX - 5;
        let mut ciphertext_buf = Vec::new();

        // Fragmentation at high seq numbers
        let mut plaintext = vec![0x66u8; MAX_TLS_PLAINTEXT_LEN + 100];
        encrypt_plaintext_to_records(CS, &mut plaintext, &key, &iv, &mut seq, &mut ciphertext_buf)
            .unwrap();
        assert_eq!(seq, u64::MAX - 3); // 2 records
    }

    #[test]
    fn test_app_data_boundary_exactly_at_limit() {
        let mut plaintext = vec![0x77u8; MAX_TLS_PLAINTEXT_LEN];
        let key = [0x68u8; 16];
        let iv = [0x69u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        encrypt_plaintext_to_records(CS, &mut plaintext, &key, &iv, &mut seq, &mut ciphertext_buf)
            .unwrap();
        assert_eq!(seq, 1);

        // Record length = plaintext + content_type(1) + tag(16)
        let record_len = u16::from_be_bytes([ciphertext_buf[3], ciphertext_buf[4]]) as usize;
        assert_eq!(record_len, MAX_TLS_PLAINTEXT_LEN + 1 + 16);
    }

    #[test]
    fn test_app_data_boundary_one_over() {
        let mut plaintext = vec![0x88u8; MAX_TLS_PLAINTEXT_LEN + 1];
        let key = [0x6Au8; 16];
        let iv = [0x6Bu8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        encrypt_plaintext_to_records(CS, &mut plaintext, &key, &iv, &mut seq, &mut ciphertext_buf)
            .unwrap();
        assert_eq!(seq, 2);

        // First at max: plaintext + content_type(1) + tag(16)
        let first_len = u16::from_be_bytes([ciphertext_buf[3], ciphertext_buf[4]]) as usize;
        assert_eq!(first_len, MAX_TLS_PLAINTEXT_LEN + 1 + 16);

        // Second has 1 byte
        let second_offset = 5 + first_len;
        let second_len = u16::from_be_bytes([
            ciphertext_buf[second_offset + 3],
            ciphertext_buf[second_offset + 4],
        ]) as usize;
        assert_eq!(second_len, 1 + 1 + 16);
    }

    // ==================== Handshake encryption tests ====================

    #[test]
    fn test_handshake_encrypt_empty() {
        let handshake_data: &[u8] = &[];
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_handshake_to_records(
            CS,
            handshake_data,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert!(ciphertext_buf.is_empty());
        assert_eq!(seq, 0); // No records encrypted
    }

    #[test]
    fn test_handshake_encrypt_small_single_record() {
        // Typical small handshake (EncryptedExtensions + small cert + CV + Finished)
        let handshake_data = vec![0x16u8; 500];
        let key = [0x01u8; 16];
        let iv = [0x02u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_handshake_to_records(
            CS,
            &handshake_data,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert_eq!(seq, 1); // One record encrypted

        // Should have one record: header(5) + handshake(500) + content_type(1) + tag(16)
        let expected_len = TLS_RECORD_HEADER_SIZE + 500 + 1 + 16;
        assert_eq!(ciphertext_buf.len(), expected_len);

        // Verify TLS header - outer type is ApplicationData (0x17)
        assert_eq!(ciphertext_buf[0], CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(ciphertext_buf[1], 0x03);
        assert_eq!(ciphertext_buf[2], 0x03);
        let record_len = u16::from_be_bytes([ciphertext_buf[3], ciphertext_buf[4]]) as usize;
        assert_eq!(record_len, 500 + 1 + 16);
    }

    #[test]
    fn test_handshake_encrypt_max_single_record() {
        // Exactly at the boundary - should still be single record
        let handshake_data = vec![0x16u8; MAX_TLS_PLAINTEXT_LEN];
        let key = [0x03u8; 16];
        let iv = [0x04u8; 12];
        let mut seq = 5u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_handshake_to_records(
            CS,
            &handshake_data,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert_eq!(seq, 6); // One record encrypted

        let expected_len = TLS_RECORD_HEADER_SIZE + MAX_TLS_PLAINTEXT_LEN + 1 + 16;
        assert_eq!(ciphertext_buf.len(), expected_len);
    }

    #[test]
    fn test_handshake_encrypt_fragmentation_two_records() {
        // One byte over the limit - should produce two records
        let handshake_data = vec![0x16u8; MAX_TLS_PLAINTEXT_LEN + 1];
        let key = [0x05u8; 16];
        let iv = [0x06u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_handshake_to_records(
            CS,
            &handshake_data,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert_eq!(seq, 2); // Two records encrypted

        // First record: full MAX_TLS_PLAINTEXT_LEN
        let first_record_len = TLS_RECORD_HEADER_SIZE + MAX_TLS_PLAINTEXT_LEN + 1 + 16;
        // Second record: 1 byte
        let second_record_len = TLS_RECORD_HEADER_SIZE + 1 + 1 + 16;
        assert_eq!(ciphertext_buf.len(), first_record_len + second_record_len);
    }

    #[test]
    fn test_handshake_encrypt_large_certificate() {
        // Simulate a large certificate chain (e.g., 20KB)
        // This is a realistic scenario that would cause record overflow without fragmentation
        let handshake_data = vec![0x16u8; 20000];
        let key = [0x07u8; 16];
        let iv = [0x08u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_handshake_to_records(
            CS,
            &handshake_data,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert_eq!(seq, 2); // Should be 2 records (20000 / 16384 = 1.2)

        // Verify all records are valid
        let mut offset = 0;
        for i in 0..2 {
            assert!(
                offset + 5 <= ciphertext_buf.len(),
                "Record {} header incomplete",
                i
            );

            // Outer type is ApplicationData (0x17)
            assert_eq!(ciphertext_buf[offset], CONTENT_TYPE_APPLICATION_DATA);
            assert_eq!(ciphertext_buf[offset + 1], 0x03);
            assert_eq!(ciphertext_buf[offset + 2], 0x03);

            let record_len =
                u16::from_be_bytes([ciphertext_buf[offset + 3], ciphertext_buf[offset + 4]])
                    as usize;

            // Record length must not exceed TLS 1.3 limit
            assert!(
                record_len <= MAX_TLS_CIPHERTEXT_LEN,
                "Record {} length {} exceeds TLS 1.3 limit {}",
                i,
                record_len,
                MAX_TLS_CIPHERTEXT_LEN
            );

            offset += 5 + record_len;
        }
        assert_eq!(offset, ciphertext_buf.len());
    }

    #[test]
    fn test_handshake_encrypt_very_large_certificate_chain() {
        // Simulate a very large certificate chain (e.g., 50KB - 3+ records)
        let handshake_data = vec![0x16u8; 50000];
        let key = [0x09u8; 16];
        let iv = [0x0Au8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_handshake_to_records(
            CS,
            &handshake_data,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());

        // 50000 / 16384 = 3.01 -> 4 records
        let expected_records = (50000 + MAX_TLS_PLAINTEXT_LEN - 1) / MAX_TLS_PLAINTEXT_LEN;
        assert_eq!(expected_records, 4);
        assert_eq!(seq, 4);

        // Verify all records
        let mut offset = 0;
        let mut record_count = 0;
        while offset < ciphertext_buf.len() {
            assert!(offset + 5 <= ciphertext_buf.len());

            let record_len =
                u16::from_be_bytes([ciphertext_buf[offset + 3], ciphertext_buf[offset + 4]])
                    as usize;

            assert!(record_len <= MAX_TLS_CIPHERTEXT_LEN);
            offset += 5 + record_len;
            record_count += 1;
        }
        assert_eq!(record_count, 4);
    }

    #[test]
    fn test_handshake_sequence_number_increments() {
        let key = [0x0Bu8; 16];
        let iv = [0x0Cu8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        // First handshake - single record
        let handshake1 = vec![0x16u8; 1000];
        encrypt_handshake_to_records(CS, &handshake1, &key, &iv, &mut seq, &mut ciphertext_buf)
            .unwrap();
        assert_eq!(seq, 1);

        // Second handshake - requires fragmentation
        let handshake2 = vec![0x16u8; MAX_TLS_PLAINTEXT_LEN + 5000];
        encrypt_handshake_to_records(CS, &handshake2, &key, &iv, &mut seq, &mut ciphertext_buf)
            .unwrap();
        assert_eq!(seq, 3); // 1 + 2 more records
    }

    #[test]
    fn test_handshake_realistic_sizes() {
        // Test with realistic handshake message sizes
        // EncryptedExtensions: ~50 bytes
        // Certificate (typical): ~2-3KB
        // CertificateVerify: ~200 bytes
        // Finished: ~36 bytes
        // Total: ~3KB - should fit in one record
        let typical_handshake = vec![0x16u8; 3000];
        let key = [0x0Du8; 16];
        let iv = [0x0Eu8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_handshake_to_records(
            CS,
            &typical_handshake,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert_eq!(seq, 1); // Single record for typical handshake
    }

    #[test]
    fn test_handshake_realistic_large_cert_chain() {
        // Large certificate chain scenario:
        // EncryptedExtensions: ~50 bytes
        // Certificate (with chain): ~15KB
        // CertificateVerify: ~200 bytes
        // Finished: ~36 bytes
        // Total: ~15.3KB - should fit in one record
        let large_cert_handshake = vec![0x16u8; 15300];
        let key = [0x0Fu8; 16];
        let iv = [0x10u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_handshake_to_records(
            CS,
            &large_cert_handshake,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert_eq!(seq, 1); // Still fits in one record (15300 < 16384)
    }

    #[test]
    fn test_handshake_realistic_very_large_cert_chain() {
        // Very large certificate chain scenario:
        // EncryptedExtensions: ~50 bytes
        // Certificate (with long chain + extensions): ~18KB
        // CertificateVerify: ~200 bytes
        // Finished: ~36 bytes
        // Total: ~18.3KB - requires 2 records
        let very_large_handshake = vec![0x16u8; 18300];
        let key = [0x11u8; 16];
        let iv = [0x12u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_handshake_to_records(
            CS,
            &very_large_handshake,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert_eq!(seq, 2); // Requires 2 records (18300 > 16384)
    }

    #[test]
    fn test_handshake_boundary_exactly_at_limit() {
        // Test exactly at MAX_TLS_PLAINTEXT_LEN (16384 bytes)
        let handshake_data = vec![0x16u8; MAX_TLS_PLAINTEXT_LEN];
        let key = [0x13u8; 16];
        let iv = [0x14u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_handshake_to_records(
            CS,
            &handshake_data,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert_eq!(seq, 1); // Exactly one record

        // Verify the ciphertext length: plaintext + content_type(1) + tag(16)
        let record_len = u16::from_be_bytes([ciphertext_buf[3], ciphertext_buf[4]]) as usize;
        assert_eq!(record_len, MAX_TLS_PLAINTEXT_LEN + 1 + 16);
    }

    #[test]
    fn test_handshake_boundary_one_over_limit() {
        // Test one byte over MAX_TLS_PLAINTEXT_LEN (16385 bytes)
        let handshake_data = vec![0x16u8; MAX_TLS_PLAINTEXT_LEN + 1];
        let key = [0x15u8; 16];
        let iv = [0x16u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_handshake_to_records(
            CS,
            &handshake_data,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert_eq!(seq, 2); // Requires two records

        // First record at max: plaintext + content_type(1) + tag(16)
        let first_record_len = u16::from_be_bytes([ciphertext_buf[3], ciphertext_buf[4]]) as usize;
        assert_eq!(first_record_len, MAX_TLS_PLAINTEXT_LEN + 1 + 16);

        // Second record should have just 1 byte of payload
        let second_offset = 5 + first_record_len;
        let second_record_len = u16::from_be_bytes([
            ciphertext_buf[second_offset + 3],
            ciphertext_buf[second_offset + 4],
        ]) as usize;
        assert_eq!(second_record_len, 1 + 1 + 16); // 1 byte + content_type + tag
    }

    #[test]
    fn test_handshake_single_byte() {
        let handshake_data = vec![0x16u8; 1];
        let key = [0x17u8; 16];
        let iv = [0x18u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_handshake_to_records(
            CS,
            &handshake_data,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert_eq!(seq, 1);

        // header(5) + handshake(1) + content_type(1) + tag(16) = 23
        assert_eq!(ciphertext_buf.len(), 23);
    }

    #[test]
    fn test_handshake_record_headers_all_valid() {
        // Test that all fragmented records have valid headers
        let size = MAX_TLS_PLAINTEXT_LEN * 3 + 100;
        let handshake_data = vec![0x16u8; size];
        let key = [0x19u8; 16];
        let iv = [0x1Au8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        encrypt_handshake_to_records(
            CS,
            &handshake_data,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        )
        .unwrap();
        assert_eq!(seq, 4); // 3 full + 1 partial

        let mut offset = 0;
        for i in 0..4 {
            // Outer content type is ApplicationData (0x17)
            assert_eq!(
                ciphertext_buf[offset], CONTENT_TYPE_APPLICATION_DATA,
                "Record {} has wrong outer content type",
                i
            );

            // Version is TLS 1.2 (0x0303)
            assert_eq!(ciphertext_buf[offset + 1], 0x03);
            assert_eq!(ciphertext_buf[offset + 2], 0x03);

            let record_len =
                u16::from_be_bytes([ciphertext_buf[offset + 3], ciphertext_buf[offset + 4]])
                    as usize;

            // All records must be within TLS 1.3 limit
            assert!(
                record_len <= MAX_TLS_CIPHERTEXT_LEN,
                "Record {} length {} exceeds limit",
                i,
                record_len
            );

            offset += 5 + record_len;
        }
        assert_eq!(offset, ciphertext_buf.len());
    }

    // ==================== Additional edge case tests ====================

    #[test]
    fn test_handshake_high_sequence_numbers() {
        // Test with sequence numbers near u64::MAX
        let key = [0x1Bu8; 16];
        let iv = [0x1Cu8; 12];
        let mut seq = u64::MAX - 10;
        let mut ciphertext_buf = Vec::new();

        // Single record
        let handshake1 = vec![0x16u8; 1000];
        encrypt_handshake_to_records(CS, &handshake1, &key, &iv, &mut seq, &mut ciphertext_buf)
            .unwrap();
        assert_eq!(seq, u64::MAX - 9);

        // Two records (fragmentation at high seq)
        let handshake2 = vec![0x16u8; MAX_TLS_PLAINTEXT_LEN + 100];
        encrypt_handshake_to_records(CS, &handshake2, &key, &iv, &mut seq, &mut ciphertext_buf)
            .unwrap();
        assert_eq!(seq, u64::MAX - 7); // 2 more records
    }

    #[test]
    fn test_handshake_appends_to_existing_buffer() {
        let key = [0x1Du8; 16];
        let iv = [0x1Eu8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        // Pre-populate buffer (simulating ServerHello already written)
        ciphertext_buf.extend_from_slice(b"existing server hello data");
        let initial_len = ciphertext_buf.len();

        let handshake = vec![0x16u8; 500];
        encrypt_handshake_to_records(CS, &handshake, &key, &iv, &mut seq, &mut ciphertext_buf)
            .unwrap();

        // Should append, not overwrite
        assert!(ciphertext_buf.len() > initial_len);
        assert_eq!(
            &ciphertext_buf[..initial_len],
            b"existing server hello data"
        );
    }

    #[test]
    fn test_handshake_multiple_calls_accumulate() {
        // Simulating how the server might send multiple handshake batches
        let key = [0x1Fu8; 16];
        let iv = [0x20u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        // First batch (e.g., just EE + Cert)
        let batch1 = vec![0x16u8; 5000];
        encrypt_handshake_to_records(CS, &batch1, &key, &iv, &mut seq, &mut ciphertext_buf)
            .unwrap();
        let len_after_batch1 = ciphertext_buf.len();
        assert_eq!(seq, 1);

        // Second batch (e.g., CV + Finished) - note seq continues
        let batch2 = vec![0x16u8; 300];
        encrypt_handshake_to_records(CS, &batch2, &key, &iv, &mut seq, &mut ciphertext_buf)
            .unwrap();
        assert!(ciphertext_buf.len() > len_after_batch1);
        assert_eq!(seq, 2);
    }

    #[test]
    fn test_handshake_boundary_minus_one() {
        // Test one byte below the limit (16622 bytes)
        let handshake_data = vec![0x16u8; MAX_TLS_PLAINTEXT_LEN - 1];
        let key = [0x21u8; 16];
        let iv = [0x22u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_handshake_to_records(
            CS,
            &handshake_data,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert_eq!(seq, 1); // Still single record (fast path)

        let expected_len = TLS_RECORD_HEADER_SIZE + (MAX_TLS_PLAINTEXT_LEN - 1) + 1 + 16;
        assert_eq!(ciphertext_buf.len(), expected_len);
    }

    #[test]
    fn test_handshake_exactly_double_limit() {
        // Test exactly 2x the limit (32768 bytes) - should produce exactly 2 full records
        let handshake_data = vec![0x16u8; MAX_TLS_PLAINTEXT_LEN * 2];
        let key = [0x23u8; 16];
        let iv = [0x24u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_handshake_to_records(
            CS,
            &handshake_data,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert_eq!(seq, 2);

        // Both records: header(5) + plaintext + content_type(1) + tag(16)
        let expected_len = 2 * (TLS_RECORD_HEADER_SIZE + MAX_TLS_PLAINTEXT_LEN + 1 + 16);
        assert_eq!(ciphertext_buf.len(), expected_len);
    }

    #[test]
    fn test_handshake_exactly_triple_limit() {
        // Test exactly 3x the limit (49152 bytes)
        let handshake_data = vec![0x16u8; MAX_TLS_PLAINTEXT_LEN * 3];
        let key = [0x25u8; 16];
        let iv = [0x26u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_handshake_to_records(
            CS,
            &handshake_data,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert_eq!(seq, 3);

        // Three records: header(5) + plaintext + content_type(1) + tag(16)
        let expected_len = 3 * (TLS_RECORD_HEADER_SIZE + MAX_TLS_PLAINTEXT_LEN + 1 + 16);
        assert_eq!(ciphertext_buf.len(), expected_len);
    }

    #[test]
    fn test_handshake_different_keys_produce_different_output() {
        let handshake = vec![0x16u8; 100];
        let iv = [0x27u8; 12];
        let mut seq1 = 0u64;
        let mut seq2 = 0u64;

        let key1 = [0x28u8; 16];
        let key2 = [0x29u8; 16];

        let mut buf1 = Vec::new();
        let mut buf2 = Vec::new();

        encrypt_handshake_to_records(CS, &handshake, &key1, &iv, &mut seq1, &mut buf1).unwrap();
        encrypt_handshake_to_records(CS, &handshake, &key2, &iv, &mut seq2, &mut buf2).unwrap();

        // Same structure but different ciphertext
        assert_eq!(buf1.len(), buf2.len());
        assert_ne!(buf1, buf2); // Different keys = different ciphertext
    }

    #[test]
    fn test_handshake_different_ivs_produce_different_output() {
        let handshake = vec![0x16u8; 100];
        let key = [0x2Au8; 16];
        let mut seq1 = 0u64;
        let mut seq2 = 0u64;

        let iv1 = [0x2Bu8; 12];
        let iv2 = [0x2Cu8; 12];

        let mut buf1 = Vec::new();
        let mut buf2 = Vec::new();

        encrypt_handshake_to_records(CS, &handshake, &key, &iv1, &mut seq1, &mut buf1).unwrap();
        encrypt_handshake_to_records(CS, &handshake, &key, &iv2, &mut seq2, &mut buf2).unwrap();

        assert_eq!(buf1.len(), buf2.len());
        assert_ne!(buf1, buf2); // Different IVs = different ciphertext
    }

    #[test]
    fn test_handshake_different_sequence_numbers_produce_different_output() {
        let handshake = vec![0x16u8; 100];
        let key = [0x2Du8; 16];
        let iv = [0x2Eu8; 12];

        let mut seq1 = 0u64;
        let mut seq2 = 100u64;

        let mut buf1 = Vec::new();
        let mut buf2 = Vec::new();

        encrypt_handshake_to_records(CS, &handshake, &key, &iv, &mut seq1, &mut buf1).unwrap();
        encrypt_handshake_to_records(CS, &handshake, &key, &iv, &mut seq2, &mut buf2).unwrap();

        assert_eq!(buf1.len(), buf2.len());
        assert_ne!(buf1, buf2); // Different seq = different nonce = different ciphertext
    }

    #[test]
    fn test_plaintext_and_handshake_produce_different_inner_content_type() {
        // While we can't directly inspect the encrypted inner content type,
        // we can verify that the same plaintext encrypted as app data vs handshake
        // produces different ciphertext (due to different content type byte)
        let data = vec![0xAAu8; 100];
        let key = [0x2Fu8; 16];
        let iv = [0x30u8; 12];

        let mut seq1 = 0u64;
        let mut seq2 = 0u64;

        let mut app_buf = Vec::new();
        let mut hs_buf = Vec::new();

        let mut app_data = data.clone();
        encrypt_plaintext_to_records(CS, &mut app_data, &key, &iv, &mut seq1, &mut app_buf)
            .unwrap();
        encrypt_handshake_to_records(CS, &data, &key, &iv, &mut seq2, &mut hs_buf).unwrap();

        // Same size but different content (inner content type differs)
        assert_eq!(app_buf.len(), hs_buf.len());
        assert_ne!(app_buf, hs_buf);
    }

    #[test]
    fn test_handshake_256kb_stress_test() {
        // 256KB handshake data (extreme case)
        let size = 256 * 1024;
        let expected_records = (size + MAX_TLS_PLAINTEXT_LEN - 1) / MAX_TLS_PLAINTEXT_LEN;
        assert_eq!(expected_records, 16); // 262144 / 16384 = 15.77 -> 16

        let handshake_data = vec![0x16u8; size];
        let key = [0x31u8; 16];
        let iv = [0x32u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        let result = encrypt_handshake_to_records(
            CS,
            &handshake_data,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        );
        assert!(result.is_ok());
        assert_eq!(seq, 16);

        // Verify all records
        let mut offset = 0;
        let mut count = 0;
        while offset < ciphertext_buf.len() {
            let record_len =
                u16::from_be_bytes([ciphertext_buf[offset + 3], ciphertext_buf[offset + 4]])
                    as usize;
            assert!(record_len <= MAX_TLS_CIPHERTEXT_LEN);
            offset += 5 + record_len;
            count += 1;
        }
        assert_eq!(count, 16);
        assert_eq!(offset, ciphertext_buf.len());
    }

    #[test]
    fn test_app_data_and_handshake_same_fragmentation_boundaries() {
        // Both app data and handshake should fragment at the same boundaries
        let size = MAX_TLS_PLAINTEXT_LEN + 1;
        let key = [0x33u8; 16];
        let iv = [0x34u8; 12];

        let mut app_seq = 0u64;
        let mut hs_seq = 0u64;
        let mut app_buf = Vec::new();
        let mut hs_buf = Vec::new();

        let mut app_data = vec![0xBBu8; size];
        let hs_data = vec![0xCCu8; size];

        encrypt_plaintext_to_records(CS, &mut app_data, &key, &iv, &mut app_seq, &mut app_buf)
            .unwrap();
        encrypt_handshake_to_records(CS, &hs_data, &key, &iv, &mut hs_seq, &mut hs_buf).unwrap();

        // Both should produce exactly 2 records
        assert_eq!(app_seq, 2);
        assert_eq!(hs_seq, 2);

        // Same total size
        assert_eq!(app_buf.len(), hs_buf.len());
    }

    #[test]
    fn test_handshake_preserves_data_integrity_structure() {
        // Verify that the record structure allows proper parsing
        let handshake_data = vec![0x16u8; 20000]; // 2 records
        let key = [0x35u8; 16];
        let iv = [0x36u8; 12];
        let mut seq = 0u64;
        let mut ciphertext_buf = Vec::new();

        encrypt_handshake_to_records(
            CS,
            &handshake_data,
            &key,
            &iv,
            &mut seq,
            &mut ciphertext_buf,
        )
        .unwrap();

        // Parse records and verify total plaintext size matches
        let mut offset = 0;
        let mut total_plaintext = 0;
        while offset < ciphertext_buf.len() {
            let record_len =
                u16::from_be_bytes([ciphertext_buf[offset + 3], ciphertext_buf[offset + 4]])
                    as usize;

            // Plaintext size = record_len - 16 (tag) - 1 (content type)
            total_plaintext += record_len - 16 - 1;
            offset += 5 + record_len;
        }

        assert_eq!(total_plaintext, 20000);
    }

    #[test]
    fn test_small_prime_sized_handshake() {
        // Test with prime-number sizes to catch off-by-one errors
        for &size in &[17usize, 31, 127, 251, 509, 1021, 2039, 4093, 8191] {
            let handshake_data = vec![0x16u8; size];
            let key = [0x37u8; 16];
            let iv = [0x38u8; 12];
            let mut seq = 0u64;
            let mut ciphertext_buf = Vec::new();

            let result = encrypt_handshake_to_records(
                CS,
                &handshake_data,
                &key,
                &iv,
                &mut seq,
                &mut ciphertext_buf,
            );
            assert!(result.is_ok(), "Failed for size {}", size);
            assert_eq!(seq, 1, "Size {} should be single record", size);

            let record_len = u16::from_be_bytes([ciphertext_buf[3], ciphertext_buf[4]]) as usize;
            assert_eq!(record_len, size + 1 + 16);
        }
    }

    #[test]
    fn test_handshake_near_boundary_prime_sizes() {
        // Prime numbers near the boundary
        let near_boundary_primes = [16619, 16631, 16633, 16649];

        for &size in &near_boundary_primes {
            let handshake_data = vec![0x16u8; size];
            let key = [0x39u8; 16];
            let iv = [0x3Au8; 12];
            let mut seq = 0u64;
            let mut ciphertext_buf = Vec::new();

            let result = encrypt_handshake_to_records(
                CS,
                &handshake_data,
                &key,
                &iv,
                &mut seq,
                &mut ciphertext_buf,
            );
            assert!(result.is_ok(), "Failed for size {}", size);

            let expected_records = if size <= MAX_TLS_PLAINTEXT_LEN { 1 } else { 2 };
            assert_eq!(
                seq, expected_records,
                "Wrong record count for size {}",
                size
            );
        }
    }
}
