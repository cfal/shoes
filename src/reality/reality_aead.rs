// TLS 1.3 Encryption/Decryption Helpers
//
// AES-GCM encryption for TLS 1.3 records using aws-lc-rs

use super::common::{
    CONTENT_TYPE_ALERT, CONTENT_TYPE_APPLICATION_DATA, VERSION_TLS_1_2_MAJOR, VERSION_TLS_1_2_MINOR,
};
use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use std::io::{Error, ErrorKind, Result};

/// Encrypt TLS 1.3 record using AES-128-GCM
///
/// # Arguments
/// * `key` - AES key (16 bytes for AES-128)
/// * `iv` - Base IV (12 bytes)
/// * `sequence_number` - TLS record sequence number
/// * `plaintext` - Plaintext data (including ContentType trailer)
/// * `additional_data` - TLS record header for AEAD
///
/// # Returns
/// Ciphertext with authentication tag appended
pub fn encrypt_tls13_record(
    key: &[u8],
    iv: &[u8],
    sequence_number: u64,
    plaintext: &[u8],
    additional_data: &[u8],
) -> Result<Vec<u8>> {
    if key.len() != 16 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Invalid key length: {} (expected 16)", key.len()),
        ));
    }
    if iv.len() != 12 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Invalid IV length: {} (expected 12)", iv.len()),
        ));
    }

    // Construct nonce: IV XOR sequence_number
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(iv);

    // XOR the last 8 bytes with the sequence number
    let seq_bytes = sequence_number.to_be_bytes();
    for i in 0..8 {
        nonce_bytes[4 + i] ^= seq_bytes[i];
    }

    // Create key and nonce for aws-lc-rs
    let unbound_key = UnboundKey::new(&AES_128_GCM, key)
        .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("Invalid key: {:?}", e)))?;
    let sealing_key = LessSafeKey::new(unbound_key);

    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("Invalid nonce: {:?}", e)))?;

    let aad = Aad::from(additional_data);

    // Note: The caller is responsible for adding the ContentType byte to plaintext
    // For handshake: plaintext = handshake_msg || 0x16
    // For app data: plaintext = app_data || 0x17
    let mut in_out = plaintext.to_vec();

    sealing_key
        .seal_in_place_append_tag(nonce, aad, &mut in_out)
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidData,
                format!("Encryption failed: {:?}", e),
            )
        })?;

    Ok(in_out)
}

/// Decrypt TLS 1.3 record using AES-128-GCM
///
/// # Arguments
/// * `key` - AES key (16 bytes for AES-128)
/// * `iv` - Base IV (12 bytes)
/// * `sequence_number` - TLS record sequence number
/// * `ciphertext` - Ciphertext with authentication tag
/// * `additional_data` - TLS record header for AEAD
///
/// # Returns
/// Plaintext data (including ContentType trailer)
pub fn decrypt_tls13_record(
    key: &[u8],
    iv: &[u8],
    sequence_number: u64,
    ciphertext: &[u8],
    additional_data: &[u8],
) -> Result<Vec<u8>> {
    if key.len() != 16 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Invalid key length: {} (expected 16)", key.len()),
        ));
    }
    if iv.len() != 12 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Invalid IV length: {} (expected 12)", iv.len()),
        ));
    }

    // Construct nonce: IV XOR sequence_number
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(iv);

    // XOR the last 8 bytes with the sequence number
    let seq_bytes = sequence_number.to_be_bytes();
    for i in 0..8 {
        nonce_bytes[4 + i] ^= seq_bytes[i];
    }

    // Create key and nonce for aws-lc-rs
    let unbound_key = UnboundKey::new(&AES_128_GCM, key)
        .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("Invalid key: {:?}", e)))?;
    let opening_key = LessSafeKey::new(unbound_key);

    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("Invalid nonce: {:?}", e)))?;

    let aad = Aad::from(additional_data);

    // aws-lc-rs requires in-place decryption
    let mut in_out = ciphertext.to_vec();
    let plaintext = opening_key
        .open_in_place(nonce, aad, &mut in_out)
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidData,
                format!("Decryption failed: {:?}", e),
            )
        })?;

    Ok(plaintext.to_vec())
}

/// Decrypt TLS 1.3 handshake message
///
/// Decrypts and extracts handshake message, removing ContentType trailer
pub fn decrypt_handshake_message(
    key: &[u8],
    iv: &[u8],
    sequence_number: u64,
    ciphertext: &[u8],
    record_length: u16,
) -> Result<Vec<u8>> {
    // Additional data for decryption
    let mut additional_data = Vec::new();
    additional_data.push(0x17); // ApplicationData
    additional_data.extend_from_slice(&[VERSION_TLS_1_2_MAJOR, VERSION_TLS_1_2_MINOR]); // TLS 1.2
    additional_data.extend_from_slice(&record_length.to_be_bytes());

    let mut plaintext =
        decrypt_tls13_record(key, iv, sequence_number, ciphertext, &additional_data)?;

    // Remove ContentType trailer
    if plaintext.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "Empty plaintext"));
    }

    // TLS 1.3 has format: content | type_byte | padding (zeros)
    // We need to find the type byte by removing trailing zeros first

    // Remove trailing zeros (padding)
    while !plaintext.is_empty() && plaintext[plaintext.len() - 1] == 0 {
        plaintext.pop();
    }

    if plaintext.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "Plaintext is all zeros"));
    }

    // Now the last byte should be the content type
    let content_type = plaintext.pop().unwrap();

    if content_type != 0x16
        && content_type != CONTENT_TYPE_APPLICATION_DATA
        && content_type != CONTENT_TYPE_ALERT
    {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Invalid content type: 0x{:02x}", content_type),
        ));
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_record() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = b"Hello, TLS 1.3!";
        let aad = b"additional data";

        let ciphertext = encrypt_tls13_record(&key, &iv, 0, plaintext, aad).unwrap();

        let decrypted = decrypt_tls13_record(&key, &iv, 0, &ciphertext, aad).unwrap();

        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_roundtrip_handshake() {
        let key = vec![0x11u8; 16];
        let iv = vec![0x22u8; 12];
        let handshake_msg = vec![0x33u8; 50];

        // Manually encrypt like encrypt_handshake_to_records does
        let mut plaintext = handshake_msg.clone();
        plaintext.push(0x16); // ContentType: Handshake

        let ciphertext_length = (plaintext.len() + 16) as u16;
        let aad: [u8; 5] = [
            0x17, // ApplicationData
            0x03,
            0x03, // TLS 1.2
            (ciphertext_length >> 8) as u8,
            (ciphertext_length & 0xff) as u8,
        ];

        let ciphertext = encrypt_tls13_record(&key, &iv, 0, &plaintext, &aad).unwrap();

        let decrypted =
            decrypt_handshake_message(&key, &iv, 0, &ciphertext, ciphertext_length).unwrap();

        assert_eq!(decrypted, handshake_msg);
    }

    #[test]
    fn test_encrypt_with_sequence_number() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = b"Test with sequence";
        let aad = b"aad";

        // Test that different sequence numbers produce different ciphertexts
        let cipher1 = encrypt_tls13_record(&key, &iv, 1, plaintext, aad).unwrap();
        let cipher2 = encrypt_tls13_record(&key, &iv, 2, plaintext, aad).unwrap();
        let cipher3 = encrypt_tls13_record(&key, &iv, 100, plaintext, aad).unwrap();

        // Ciphertexts should all be different
        assert_ne!(cipher1, cipher2);
        assert_ne!(cipher2, cipher3);
        assert_ne!(cipher1, cipher3);

        // But they should all decrypt correctly
        let decrypt1 = decrypt_tls13_record(&key, &iv, 1, &cipher1, aad).unwrap();
        let decrypt2 = decrypt_tls13_record(&key, &iv, 2, &cipher2, aad).unwrap();
        let decrypt3 = decrypt_tls13_record(&key, &iv, 100, &cipher3, aad).unwrap();

        assert_eq!(decrypt1, plaintext);
        assert_eq!(decrypt2, plaintext);
        assert_eq!(decrypt3, plaintext);
    }

    #[test]
    fn test_decrypt_with_wrong_sequence_number() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = b"Test sequence";
        let aad = b"aad";

        let ciphertext = encrypt_tls13_record(&key, &iv, 5, plaintext, aad).unwrap();

        // Decrypting with wrong sequence number should fail
        let result = decrypt_tls13_record(&key, &iv, 6, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_wrong_aad() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = b"Test AAD";
        let aad = b"correct aad";
        let wrong_aad = b"wrong aad";

        let ciphertext = encrypt_tls13_record(&key, &iv, 0, plaintext, aad).unwrap();

        // Decrypting with wrong AAD should fail
        let result = decrypt_tls13_record(&key, &iv, 0, &ciphertext, wrong_aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_invalid_key_length() {
        let invalid_key = vec![0x42u8; 15]; // Wrong length (not 16)
        let iv = vec![0x99u8; 12];
        let plaintext = b"Test";
        let aad = b"aad";

        let result = encrypt_tls13_record(&invalid_key, &iv, 0, plaintext, aad);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn test_encrypt_invalid_iv_length() {
        let key = vec![0x42u8; 16];
        let invalid_iv = vec![0x99u8; 11]; // Wrong length (not 12)
        let plaintext = b"Test";
        let aad = b"aad";

        let result = encrypt_tls13_record(&key, &invalid_iv, 0, plaintext, aad);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn test_decrypt_corrupted_ciphertext() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = b"Test corruption";
        let aad = b"aad";

        let mut ciphertext = encrypt_tls13_record(&key, &iv, 0, plaintext, aad).unwrap();

        // Corrupt the ciphertext
        ciphertext[5] ^= 0xFF;

        let result = decrypt_tls13_record(&key, &iv, 0, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_empty_plaintext() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = b"";
        let aad = b"aad";

        let ciphertext = encrypt_tls13_record(&key, &iv, 0, plaintext, aad).unwrap();

        // Should still produce a ciphertext with auth tag
        assert!(ciphertext.len() >= 16); // At least the auth tag

        let decrypted = decrypt_tls13_record(&key, &iv, 0, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_plaintext() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = vec![0xAB; 16384]; // 16KB
        let aad = b"aad";

        let ciphertext = encrypt_tls13_record(&key, &iv, 42, &plaintext, aad).unwrap();
        let decrypted = decrypt_tls13_record(&key, &iv, 42, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
