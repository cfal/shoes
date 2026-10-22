use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::agreement;
use aws_lc_rs::hkdf::{HKDF_SHA256, Salt};

/// Custom error type for REALITY cryptographic operations
#[derive(Debug)]
pub enum CryptoError {
    InvalidNonceLength,
    EncryptionFailed,
    DecryptionFailed,
    EcdhFailed,
    HkdfFailed,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidNonceLength => write!(f, "Invalid nonce length"),
            CryptoError::EncryptionFailed => write!(f, "Encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "Decryption failed"),
            CryptoError::EcdhFailed => write!(f, "ECDH key exchange failed"),
            CryptoError::HkdfFailed => write!(f, "HKDF derivation failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<CryptoError> for std::io::Error {
    fn from(err: CryptoError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string())
    }
}

/// Performs X25519 ECDH key exchange
///
/// # Arguments
/// * `private_key` - 32-byte X25519 private key
/// * `public_key` - 32-byte X25519 public key
///
/// # Returns
/// 32-byte shared secret
pub fn perform_ecdh(
    private_key: &[u8; 32],
    public_key: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    // Create private key from raw bytes
    let my_private_key = agreement::PrivateKey::from_private_key(&agreement::X25519, private_key)
        .map_err(|_| CryptoError::EcdhFailed)?;

    // Compute public key from private key (not used, but verifies key is valid)
    let _my_public_key = my_private_key
        .compute_public_key()
        .map_err(|_| CryptoError::EcdhFailed)?;

    // Create unparsed public key
    let peer_public_key =
        agreement::UnparsedPublicKey::new(&agreement::X25519, public_key.as_ref());

    // Perform ECDH
    let mut shared_secret = [0u8; 32];
    agreement::agree(
        &my_private_key,
        peer_public_key,
        CryptoError::EcdhFailed,
        |key_material| {
            shared_secret.copy_from_slice(key_material);
            Ok(())
        },
    )?;

    Ok(shared_secret)
}

/// Derives authentication key using HKDF-SHA256
///
/// # Arguments
/// * `shared_secret` - 32-byte shared secret from ECDH
/// * `salt` - Salt bytes (must be exactly 20 bytes, from ClientHello.Random[0..20])
/// * `info` - Context string (should be b"REALITY")
///
/// # Returns
/// 32-byte derived authentication key
///
/// # Panics
/// Panics if salt is not exactly 20 bytes.
pub fn derive_auth_key(
    shared_secret: &[u8; 32],
    salt: &[u8],
    info: &[u8],
) -> Result<[u8; 32], CryptoError> {
    debug_assert_eq!(salt.len(), 20, "salt must be exactly 20 bytes");
    let salt = Salt::new(HKDF_SHA256, salt);
    let prk = salt.extract(shared_secret);
    let info_pieces = [info];
    let okm = prk
        .expand(&info_pieces, HKDF_SHA256)
        .map_err(|_| CryptoError::HkdfFailed)?;
    let mut auth_key = [0u8; 32];
    okm.fill(&mut auth_key)
        .map_err(|_| CryptoError::HkdfFailed)?;
    Ok(auth_key)
}

/// Encrypts SessionId using AES-256-GCM
///
/// # Arguments
/// * `plaintext` - 16-byte plaintext (first 16 bytes of SessionId)
/// * `auth_key` - 32-byte authentication key
/// * `nonce` - 12-byte nonce (ClientHello.Random[20..32])
/// * `aad` - Additional authenticated data (entire ClientHello)
///
/// # Returns
/// 32-byte result (16 bytes ciphertext + 16 bytes GCM tag)
///
/// # Panics
/// Panics if nonce is not exactly 12 bytes.
pub fn encrypt_session_id(
    plaintext: &[u8; 16],
    auth_key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
) -> Result<[u8; 32], CryptoError> {
    debug_assert_eq!(nonce.len(), 12, "nonce must be exactly 12 bytes");
    let unbound_key =
        UnboundKey::new(&AES_256_GCM, auth_key).map_err(|_| CryptoError::EncryptionFailed)?;
    let sealing_key = LessSafeKey::new(unbound_key);

    let nonce_obj =
        Nonce::try_assume_unique_for_key(nonce).map_err(|_| CryptoError::InvalidNonceLength)?;

    let aad_obj = Aad::from(aad);

    // aws-lc-rs requires in-place encryption
    let mut in_out = zeroize::Zeroizing::new(plaintext.to_vec());
    sealing_key
        .seal_in_place_append_tag(nonce_obj, aad_obj, &mut *in_out)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    if in_out.len() != 32 {
        return Err(CryptoError::EncryptionFailed);
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(&in_out);
    Ok(result)
}

/// Decrypts SessionId using AES-256-GCM
///
/// # Arguments
/// * `ciphertext_and_tag` - 32-byte encrypted data (16 ciphertext + 16 tag)
/// * `auth_key` - 32-byte authentication key
/// * `nonce` - 12-byte nonce (ClientHello.Random[20..32])
/// * `aad` - Additional authenticated data (entire ClientHello)
///
/// # Returns
/// 16-byte decrypted plaintext
///
/// # Panics
/// Panics if nonce is not exactly 12 bytes.
pub fn decrypt_session_id(
    ciphertext_and_tag: &[u8; 32],
    auth_key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
) -> Result<[u8; 16], CryptoError> {
    debug_assert_eq!(nonce.len(), 12, "nonce must be exactly 12 bytes");
    let unbound_key =
        UnboundKey::new(&AES_256_GCM, auth_key).map_err(|_| CryptoError::DecryptionFailed)?;
    let opening_key = LessSafeKey::new(unbound_key);

    let nonce_obj =
        Nonce::try_assume_unique_for_key(nonce).map_err(|_| CryptoError::InvalidNonceLength)?;

    let aad_obj = Aad::from(aad);

    // aws-lc-rs requires in-place decryption
    let mut in_out = zeroize::Zeroizing::new(ciphertext_and_tag.to_vec());
    let plaintext = opening_key
        .open_in_place(nonce_obj, aad_obj, &mut in_out)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    if plaintext.len() != 16 {
        return Err(CryptoError::DecryptionFailed);
    }

    let mut result = [0u8; 16];
    result.copy_from_slice(plaintext);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdh() {
        // Test vectors
        let private_key_a = [1u8; 32];
        let private_key_b = [2u8; 32];

        // Compute public keys using aws-lc-rs
        let priv_a =
            agreement::PrivateKey::from_private_key(&agreement::X25519, &private_key_a).unwrap();
        let pub_a = priv_a.compute_public_key().unwrap();

        let priv_b =
            agreement::PrivateKey::from_private_key(&agreement::X25519, &private_key_b).unwrap();
        let pub_b = priv_b.compute_public_key().unwrap();

        let shared_a = perform_ecdh(&private_key_a, pub_b.as_ref().try_into().unwrap()).unwrap();
        let shared_b = perform_ecdh(&private_key_b, pub_a.as_ref().try_into().unwrap()).unwrap();
        assert_eq!(shared_a, shared_b);
        assert_ne!(shared_a, [0; 32]);
        assert!(matches!(
            perform_ecdh(&private_key_a, &[0; 32]),
            Err(CryptoError::EcdhFailed)
        ));
    }

    #[test]
    fn test_session_id_encryption_preserves_structure() {
        // Create session ID with known values
        let version = [1, 8, 1];
        let timestamp = 1234567890u32;
        let short_id = [0xAB; 8];

        let mut plaintext = [0; 16];
        plaintext[..3].copy_from_slice(&version);
        plaintext[4..8].copy_from_slice(&timestamp.to_be_bytes());
        plaintext[8..].copy_from_slice(&short_id);

        // Perform ECDH
        let client_private = [0x01; 32];
        let server_public = [0x02; 32];
        let shared_secret = perform_ecdh(&client_private, &server_public).unwrap();

        // Derive auth key
        let salt = [0x03; 20];
        let auth_key = derive_auth_key(&shared_secret, &salt, b"REALITY").unwrap();

        let nonce = [0x04; 12];
        let aad = b"test additional authenticated data";

        let encrypted = encrypt_session_id(&plaintext, &auth_key, &nonce, aad).unwrap();

        // Decrypt session ID
        let decrypted = decrypt_session_id(&encrypted, &auth_key, &nonce, aad).unwrap();

        // Verify we can recover the structure
        assert_eq!(decrypted[0], version[0]);
        assert_eq!(decrypted[1], version[1]);
        assert_eq!(decrypted[2], version[2]);
        assert_eq!(decrypted[3], 0); // reserved

        let recovered_timestamp =
            u32::from_be_bytes([decrypted[4], decrypted[5], decrypted[6], decrypted[7]]);
        assert_eq!(recovered_timestamp, timestamp);

        assert_eq!(&decrypted[8..16], &short_id[..]);
    }

    #[test]
    fn test_hkdf() {
        let shared_secret = [0x42u8; 32];
        let salt = [0x43u8; 20];
        let info = b"REALITY";

        let auth_key = derive_auth_key(&shared_secret, &salt, info).unwrap();

        // Verify length
        assert_eq!(auth_key.len(), 32);

        // Verify deterministic
        let auth_key2 = derive_auth_key(&shared_secret, &salt, info).unwrap();
        assert_eq!(auth_key, auth_key2);

        // Verify different salt produces different key
        let salt2 = [0x44u8; 20];
        let auth_key3 = derive_auth_key(&shared_secret, &salt2, info).unwrap();
        assert_ne!(auth_key, auth_key3);
    }

    #[test]
    fn test_aes_gcm_roundtrip() {
        let plaintext = [0x55u8; 16];
        let auth_key = [0x66u8; 32];
        let nonce = [0x77u8; 12];
        let aad = b"additional authenticated data";

        let encrypted = encrypt_session_id(&plaintext, &auth_key, &nonce, aad).unwrap();
        assert_eq!(encrypted.len(), 32);

        let decrypted = decrypt_session_id(&encrypted, &auth_key, &nonce, aad).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_aes_gcm_wrong_key_fails() {
        let plaintext = [0x55u8; 16];
        let auth_key = [0x66u8; 32];
        let wrong_key = [0x67u8; 32];
        let nonce = [0x77u8; 12];
        let aad = b"additional authenticated data";

        let encrypted = encrypt_session_id(&plaintext, &auth_key, &nonce, aad).unwrap();

        let result = decrypt_session_id(&encrypted, &wrong_key, &nonce, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_wrong_aad_fails() {
        let plaintext = [0x55u8; 16];
        let auth_key = [0x66u8; 32];
        let nonce = [0x77u8; 12];
        let aad = b"additional authenticated data";
        let wrong_aad = b"wrong additional authenticated data";

        let encrypted = encrypt_session_id(&plaintext, &auth_key, &nonce, aad).unwrap();

        let result = decrypt_session_id(&encrypted, &auth_key, &nonce, wrong_aad);
        assert!(result.is_err());
    }
}
