// TLS 1.3 AEAD encryption/decryption using aws-lc-rs.
// Record framing is handled by reality_records.rs.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
use std::io::{self, Error, ErrorKind};

use super::common::strip_content_type_with_padding;
use super::reality_cipher_suite::CipherSuite;

/// AEAD key for TLS 1.3 encryption/decryption.
///
/// Wraps aws-lc-rs LessSafeKey and provides a cleaner API.
/// Create once per connection direction and reuse for all records.
pub struct AeadKey(LessSafeKey);

impl AeadKey {
    /// Create a new AEAD key from raw key bytes.
    pub fn new(cipher_suite: CipherSuite, key: &[u8]) -> io::Result<Self> {
        let algorithm = cipher_suite.algorithm();
        let expected_len = cipher_suite.key_len();

        if key.len() != expected_len {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "Invalid key length for {:?}: {} (expected {})",
                    cipher_suite,
                    key.len(),
                    expected_len
                ),
            ));
        }

        let unbound = UnboundKey::new(algorithm, key)
            .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("Invalid key: {:?}", e)))?;

        Ok(Self(LessSafeKey::new(unbound)))
    }

    /// Encrypt in-place, appending 16-byte auth tag.
    ///
    /// The buffer is modified: plaintext -> ciphertext || tag
    #[inline]
    pub fn seal_in_place(
        &self,
        buf: &mut Vec<u8>,
        iv: &[u8],
        seq: u64,
        aad: &[u8],
    ) -> io::Result<()> {
        let nonce = Self::make_nonce(iv, seq)?;
        self.0
            .seal_in_place_append_tag(nonce, Aad::from(aad), buf)
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("Encryption failed: {:?}", e),
                )
            })
    }

    /// Encrypt with copy, returning new Vec containing ciphertext || tag.
    ///
    /// Use this for small buffers where allocation overhead doesn't matter.
    #[inline]
    #[cfg_attr(not(test), allow(dead_code))] // Used by test helpers
    pub fn seal(&self, plaintext: &[u8], iv: &[u8], seq: u64, aad: &[u8]) -> io::Result<Vec<u8>> {
        let mut buf = plaintext.to_vec();
        self.seal_in_place(&mut buf, iv, seq, aad)?;
        Ok(buf)
    }

    /// Decrypt in-place on a mutable slice, returning the plaintext portion.
    ///
    /// This is the zero-allocation decryption API. The slice is decrypted in-place
    /// and a sub-slice containing only the plaintext (without the auth tag) is returned.
    ///
    /// # Arguments
    /// * `buf` - Mutable slice containing ciphertext + auth tag
    /// * `iv` - 12-byte IV/nonce base
    /// * `seq` - Sequence number to XOR with IV
    /// * `aad` - Additional authenticated data
    ///
    /// # Returns
    /// Sub-slice of `buf` containing only the decrypted plaintext
    #[inline]
    pub fn open_in_place_slice<'a>(
        &self,
        buf: &'a mut [u8],
        iv: &[u8],
        seq: u64,
        aad: &[u8],
    ) -> io::Result<&'a mut [u8]> {
        let nonce = Self::make_nonce(iv, seq)?;
        self.0
            .open_in_place(nonce, Aad::from(aad), buf)
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("Decryption failed: {:?}", e),
                )
            })
    }

    /// Decrypt with copy, returning new Vec containing plaintext.
    ///
    /// Used for handshake decryption and tests where allocation is acceptable.
    #[inline]
    pub fn open(&self, ciphertext: &[u8], iv: &[u8], seq: u64, aad: &[u8]) -> io::Result<Vec<u8>> {
        let mut buf = ciphertext.to_vec();
        let plaintext = self.open_in_place_slice(&mut buf, iv, seq, aad)?;
        let plaintext_len = plaintext.len();
        buf.truncate(plaintext_len);
        Ok(buf)
    }

    /// Construct TLS 1.3 nonce: IV XOR sequence_number
    fn make_nonce(iv: &[u8], seq: u64) -> io::Result<Nonce> {
        if iv.len() != 12 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Invalid IV length: {} (expected 12)", iv.len()),
            ));
        }

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(iv);

        // XOR last 8 bytes with sequence number (big-endian)
        let seq_bytes = seq.to_be_bytes();
        for i in 0..8 {
            nonce_bytes[4 + i] ^= seq_bytes[i];
        }

        Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("Invalid nonce: {:?}", e)))
    }
}

/// Decrypt a TLS 1.3 handshake message.
///
/// Builds the AAD from the record length and decrypts.
/// Returns plaintext with content type trailer stripped.
pub fn decrypt_handshake_message(
    cipher_suite: CipherSuite,
    key: &[u8],
    iv: &[u8],
    seq: u64,
    ciphertext: &[u8],
    record_len: u16,
) -> io::Result<Vec<u8>> {
    // Build AAD: TLS record header
    let aad = [
        0x17, // ApplicationData
        0x03,
        0x03, // TLS 1.2 version
        (record_len >> 8) as u8,
        (record_len & 0xff) as u8,
    ];

    let aead_key = AeadKey::new(cipher_suite, key)?;
    let mut plaintext = aead_key.open(ciphertext, iv, seq, &aad)?;

    // Strip content type and optional padding (external implementations may pad)
    let _ = strip_content_type_with_padding(&mut plaintext)?;

    Ok(plaintext)
}

#[cfg(test)]
pub(crate) fn encrypt_tls13_record(
    cipher_suite: CipherSuite,
    key: &[u8],
    iv: &[u8],
    seq: u64,
    plaintext: &[u8],
    aad: &[u8],
) -> io::Result<Vec<u8>> {
    AeadKey::new(cipher_suite, key)?.seal(plaintext, iv, seq, aad)
}

#[cfg(test)]
pub(crate) fn decrypt_tls13_record(
    cipher_suite: CipherSuite,
    key: &[u8],
    iv: &[u8],
    seq: u64,
    ciphertext: &[u8],
    aad: &[u8],
) -> io::Result<Vec<u8>> {
    AeadKey::new(cipher_suite, key)?.open(ciphertext, iv, seq, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CS: CipherSuite = CipherSuite::AES_128_GCM_SHA256;

    #[test]
    fn test_encrypt_decrypt_record() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = b"Hello, TLS 1.3!";
        let aad = b"additional data";

        let ciphertext = encrypt_tls13_record(CS, &key, &iv, 0, plaintext, aad).unwrap();

        let decrypted = decrypt_tls13_record(CS, &key, &iv, 0, &ciphertext, aad).unwrap();

        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_aead_key_seal_open() {
        let key = AeadKey::new(CS, &[0x42u8; 16]).unwrap();
        let iv = [0x99u8; 12];
        let plaintext = b"Test message";
        let aad = b"aad";

        let ciphertext = key.seal(plaintext, &iv, 0, aad).unwrap();
        let decrypted = key.open(&ciphertext, &iv, 0, aad).unwrap();

        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_aead_key_in_place() {
        let key = AeadKey::new(CS, &[0x42u8; 16]).unwrap();
        let iv = [0x99u8; 12];
        let plaintext = b"Test in-place";
        let aad = b"aad";

        let mut buf = plaintext.to_vec();
        key.seal_in_place(&mut buf, &iv, 0, aad).unwrap();

        // buf now contains ciphertext + tag
        assert_eq!(buf.len(), plaintext.len() + 16);

        let decrypted = key.open_in_place_slice(&mut buf, &iv, 0, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_with_sequence_number() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = b"Test with sequence";
        let aad = b"aad";

        // Test that different sequence numbers produce different ciphertexts
        let cipher1 = encrypt_tls13_record(CS, &key, &iv, 1, plaintext, aad).unwrap();
        let cipher2 = encrypt_tls13_record(CS, &key, &iv, 2, plaintext, aad).unwrap();
        let cipher3 = encrypt_tls13_record(CS, &key, &iv, 100, plaintext, aad).unwrap();

        // Ciphertexts should all be different
        assert_ne!(cipher1, cipher2);
        assert_ne!(cipher2, cipher3);
        assert_ne!(cipher1, cipher3);

        // But they should all decrypt correctly
        let decrypt1 = decrypt_tls13_record(CS, &key, &iv, 1, &cipher1, aad).unwrap();
        let decrypt2 = decrypt_tls13_record(CS, &key, &iv, 2, &cipher2, aad).unwrap();
        let decrypt3 = decrypt_tls13_record(CS, &key, &iv, 100, &cipher3, aad).unwrap();

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

        let ciphertext = encrypt_tls13_record(CS, &key, &iv, 5, plaintext, aad).unwrap();

        // Decrypting with wrong sequence number should fail
        let result = decrypt_tls13_record(CS, &key, &iv, 6, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_wrong_aad() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = b"Test AAD";
        let aad = b"correct aad";
        let wrong_aad = b"wrong aad";

        let ciphertext = encrypt_tls13_record(CS, &key, &iv, 0, plaintext, aad).unwrap();

        // Decrypting with wrong AAD should fail
        let result = decrypt_tls13_record(CS, &key, &iv, 0, &ciphertext, wrong_aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_invalid_key_length() {
        let invalid_key = vec![0x42u8; 15]; // Wrong length (not 16)
        let iv = vec![0x99u8; 12];
        let plaintext = b"Test";
        let aad = b"aad";

        let result = encrypt_tls13_record(CS, &invalid_key, &iv, 0, plaintext, aad);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn test_encrypt_invalid_iv_length() {
        let key = vec![0x42u8; 16];
        let invalid_iv = vec![0x99u8; 11]; // Wrong length (not 12)
        let plaintext = b"Test";
        let aad = b"aad";

        let result = encrypt_tls13_record(CS, &key, &invalid_iv, 0, plaintext, aad);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn test_decrypt_corrupted_ciphertext() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = b"Test corruption";
        let aad = b"aad";

        let mut ciphertext = encrypt_tls13_record(CS, &key, &iv, 0, plaintext, aad).unwrap();

        // Corrupt the ciphertext
        ciphertext[5] ^= 0xFF;

        let result = decrypt_tls13_record(CS, &key, &iv, 0, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_empty_plaintext() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = b"";
        let aad = b"aad";

        let ciphertext = encrypt_tls13_record(CS, &key, &iv, 0, plaintext, aad).unwrap();

        // Should still produce a ciphertext with auth tag
        assert!(ciphertext.len() >= 16); // At least the auth tag

        let decrypted = decrypt_tls13_record(CS, &key, &iv, 0, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_plaintext() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = vec![0xAB; 16384]; // 16KB
        let aad = b"aad";

        let ciphertext = encrypt_tls13_record(CS, &key, &iv, 42, &plaintext, aad).unwrap();
        let decrypted = decrypt_tls13_record(CS, &key, &iv, 42, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_handshake_message() {
        use super::decrypt_handshake_message;
        use crate::reality::common::CONTENT_TYPE_HANDSHAKE;

        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let handshake_msg = vec![0xABu8; 100]; // Simulated handshake message

        // Build plaintext: handshake_msg || content_type
        let mut plaintext_with_type = handshake_msg.clone();
        plaintext_with_type.push(CONTENT_TYPE_HANDSHAKE);

        // Calculate ciphertext length for AAD
        let ciphertext_len = (plaintext_with_type.len() + 16) as u16;

        // Build AAD (TLS record header)
        let aad = [
            0x17, // ApplicationData
            0x03,
            0x03, // TLS 1.2 version
            (ciphertext_len >> 8) as u8,
            (ciphertext_len & 0xff) as u8,
        ];

        // Encrypt
        let ciphertext =
            encrypt_tls13_record(CS, &key, &iv, 0, &plaintext_with_type, &aad).unwrap();

        // Decrypt using decrypt_handshake_message
        let decrypted =
            decrypt_handshake_message(CS, &key, &iv, 0, &ciphertext, ciphertext_len).unwrap();

        assert_eq!(decrypted, handshake_msg);
    }

    #[test]
    fn test_decrypt_handshake_message_with_padding() {
        use super::decrypt_handshake_message;
        use crate::reality::common::CONTENT_TYPE_HANDSHAKE;

        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let handshake_msg = vec![0xCDu8; 50];

        // Build plaintext with padding: handshake_msg || content_type || padding_zeros
        let mut plaintext_with_type_and_padding = handshake_msg.clone();
        plaintext_with_type_and_padding.push(CONTENT_TYPE_HANDSHAKE);
        plaintext_with_type_and_padding.extend_from_slice(&[0x00, 0x00, 0x00]); // 3 bytes padding

        let ciphertext_len = (plaintext_with_type_and_padding.len() + 16) as u16;

        let aad = [
            0x17,
            0x03,
            0x03,
            (ciphertext_len >> 8) as u8,
            (ciphertext_len & 0xff) as u8,
        ];

        let ciphertext =
            encrypt_tls13_record(CS, &key, &iv, 0, &plaintext_with_type_and_padding, &aad).unwrap();

        // Padding should be stripped
        let decrypted =
            decrypt_handshake_message(CS, &key, &iv, 0, &ciphertext, ciphertext_len).unwrap();

        assert_eq!(decrypted, handshake_msg);
    }
}
