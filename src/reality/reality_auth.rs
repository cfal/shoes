use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use aws_lc_rs::agreement;
use aws_lc_rs::hkdf::{Salt, HKDF_SHA256};

#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

/// Custom error type for REALITY cryptographic operations
#[derive(Debug)]
pub enum CryptoError {
    InvalidKeyLength,
    InvalidNonceLength,
    InvalidCiphertextLength,
    EncryptionFailed,
    DecryptionFailed,
    EcdhFailed,
    HkdfFailed,
    CertificateGenerationFailed(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidKeyLength => write!(f, "Invalid key length"),
            CryptoError::InvalidNonceLength => write!(f, "Invalid nonce length"),
            CryptoError::InvalidCiphertextLength => write!(f, "Invalid ciphertext length"),
            CryptoError::EncryptionFailed => write!(f, "Encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "Decryption failed"),
            CryptoError::EcdhFailed => write!(f, "ECDH key exchange failed"),
            CryptoError::HkdfFailed => write!(f, "HKDF derivation failed"),
            CryptoError::CertificateGenerationFailed(e) => {
                write!(f, "Certificate generation failed: {}", e)
            }
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
    let mut in_out = plaintext.to_vec();
    sealing_key
        .seal_in_place_append_tag(nonce_obj, aad_obj, &mut in_out)
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
    let mut in_out = ciphertext_and_tag.to_vec();
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
/// Creates a REALITY SessionId (test helper)
fn create_session_id(version: [u8; 3], timestamp: u32, short_id: &[u8; 8]) -> [u8; 32] {
    let mut session_id = [0u8; 32];
    session_id[0] = version[0]; // Major version
    session_id[1] = version[1]; // Minor version
    session_id[2] = version[2]; // Patch version
                                // session_id[3] = 0 (reserved)
    session_id[4..8].copy_from_slice(&timestamp.to_be_bytes());
    session_id[8..16].copy_from_slice(short_id);
    // session_id[16..32] remain zeros
    session_id
}

#[cfg(test)]
/// Gets current Unix timestamp (test helper)
fn get_current_timestamp() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as u32
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

        // Perform ECDH both ways
        let mut shared_a_bytes = [0u8; 32];
        agreement::agree(
            &priv_a,
            &agreement::UnparsedPublicKey::new(&agreement::X25519, pub_b.as_ref()),
            (),
            |key_material| {
                shared_a_bytes.copy_from_slice(key_material);
                Ok(())
            },
        )
        .unwrap();

        let mut shared_b_bytes = [0u8; 32];
        agreement::agree(
            &priv_b,
            &agreement::UnparsedPublicKey::new(&agreement::X25519, pub_a.as_ref()),
            (),
            |key_material| {
                shared_b_bytes.copy_from_slice(key_material);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(shared_a_bytes, shared_b_bytes);
    }

    #[test]
    fn test_session_id_structure() {
        // Test that session ID has the correct structure
        let version = [1, 8, 1]; // major, minor, patch
        let timestamp = get_current_timestamp();
        let short_id = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];

        let session_id = create_session_id(version, timestamp, &short_id);

        // Verify structure
        assert_eq!(session_id[0], 1); // version major
        assert_eq!(session_id[1], 8); // version minor
        assert_eq!(session_id[2], 1); // version patch
        assert_eq!(session_id[3], 0); // reserved

        // Verify timestamp
        let extracted_timestamp =
            u32::from_be_bytes([session_id[4], session_id[5], session_id[6], session_id[7]]);
        assert_eq!(extracted_timestamp, timestamp);

        // Verify short_id
        assert_eq!(&session_id[8..16], &short_id[..]);

        // Verify remaining bytes are zero
        for i in 16..32 {
            assert_eq!(session_id[i], 0);
        }
    }

    #[test]
    fn test_version_comparison() {
        // Test version comparison logic (same as used in reality_server_handler.rs)
        let v1_8_1 = [1u8, 8, 1];
        let v1_8_0 = [1u8, 8, 0];
        let v1_9_0 = [1u8, 9, 0];
        let v2_0_0 = [2u8, 0, 0];

        assert!(v1_8_0 < v1_8_1);
        assert!(v1_8_1 < v1_9_0);
        assert!(v1_9_0 < v2_0_0);
        assert!(v1_8_1 > v1_8_0);
    }

    #[test]
    fn test_timestamp_validation_logic() {
        // Test the timestamp validation logic used in reality_server_handler.rs
        let now = get_current_timestamp();

        // Test within bounds (60 seconds = 60000 milliseconds)
        let max_diff_ms = 60000u64;
        let max_diff_secs = max_diff_ms / 1000;

        // Current time - should pass
        let diff = now.abs_diff(now);
        assert!((diff as u64) <= max_diff_secs);

        // 30 seconds ago - should pass
        let past_timestamp = now - 30;
        let diff = now.abs_diff(past_timestamp);
        assert!((diff as u64) <= max_diff_secs);

        // 30 seconds future - should pass
        let future_timestamp = now + 30;
        let diff = now.abs_diff(future_timestamp);
        assert!((diff as u64) <= max_diff_secs);

        // 2 minutes ago - should fail
        let old_timestamp = now.saturating_sub(120);
        let diff = now.abs_diff(old_timestamp);
        assert!((diff as u64) > max_diff_secs);

        // 2 minutes future - should fail
        let future_timestamp = now + 120;
        let diff = now.abs_diff(future_timestamp);
        assert!((diff as u64) > max_diff_secs);
    }

    #[test]
    fn test_session_id_encryption_preserves_structure() {
        // Create session ID with known values
        let version = [1, 8, 1];
        let timestamp = 1234567890u32;
        let short_id = [0xAB; 8];

        let session_id = create_session_id(version, timestamp, &short_id);

        // Perform ECDH
        let client_private = [0x01; 32];
        let server_public = [0x02; 32];
        let shared_secret = perform_ecdh(&client_private, &server_public).unwrap();

        // Derive auth key
        let salt = [0x03; 20];
        let auth_key = derive_auth_key(&shared_secret, &salt, b"REALITY").unwrap();

        // Encrypt session ID (first 16 bytes)
        let plaintext: [u8; 16] = session_id[0..16].try_into().unwrap();
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

    #[test]
    fn test_create_session_id() {
        let version = [1, 8, 1];
        let timestamp = 1234567890u32;
        let short_id = [0xAB; 8];

        let session_id = create_session_id(version, timestamp, &short_id);

        assert_eq!(session_id[0], 1);
        assert_eq!(session_id[1], 8);
        assert_eq!(session_id[2], 1);
        assert_eq!(session_id[3], 0);

        let ts = u32::from_be_bytes([session_id[4], session_id[5], session_id[6], session_id[7]]);
        assert_eq!(ts, timestamp);

        assert_eq!(&session_id[8..16], &short_id[..]);

        // Verify remaining bytes are zeros
        for i in 16..32 {
            assert_eq!(session_id[i], 0);
        }
    }

    #[test]
    fn test_validation_scenarios() {
        println!("\n=== REALITY Validation Test Scenarios ===\n");

        // Scenario 1: Version validation
        println!("Scenario 1: Version Validation");
        println!("  Client version: [1, 8, 1]");
        println!("  Min version: [1, 8, 0]");
        println!("  Max version: [1, 9, 0]");
        println!("  Expected: PASS ✓");

        let client_version = [1u8, 8, 1];
        let min_version = [1u8, 8, 0];
        let max_version = [1u8, 9, 0];
        assert!(client_version >= min_version);
        assert!(client_version <= max_version);

        // Scenario 2: Version below minimum
        println!("\nScenario 2: Version Below Minimum");
        println!("  Client version: [1, 7, 5]");
        println!("  Min version: [1, 8, 0]");
        println!("  Expected: FAIL ✗");

        let old_client_version = [1u8, 7, 5];
        assert!(old_client_version < min_version);

        // Scenario 3: Version above maximum
        println!("\nScenario 3: Version Above Maximum");
        println!("  Client version: [2, 0, 0]");
        println!("  Max version: [1, 9, 0]");
        println!("  Expected: FAIL ✗");

        let new_client_version = [2u8, 0, 0];
        assert!(new_client_version > max_version);

        // Scenario 4: Timestamp validation (within bounds)
        println!("\nScenario 4: Timestamp Within Bounds");
        let now = get_current_timestamp();
        let client_timestamp = now - 30; // 30 seconds ago
        let max_diff_ms = 60000u64; // 60 seconds

        let diff = now.abs_diff(client_timestamp);
        println!("  Server time: {}", now);
        println!("  Client time: {} (30 seconds ago)", client_timestamp);
        println!("  Max allowed: {} seconds", max_diff_ms / 1000);
        println!("  Actual diff: {} seconds", diff);
        println!("  Expected: PASS ✓");
        assert!((diff as u64) <= (max_diff_ms / 1000));

        // Scenario 5: Timestamp validation (out of bounds)
        println!("\nScenario 5: Timestamp Out of Bounds");
        let old_timestamp = now - 120; // 2 minutes ago
        let diff = now.abs_diff(old_timestamp);
        println!("  Server time: {}", now);
        println!("  Client time: {} (2 minutes ago)", old_timestamp);
        println!("  Max allowed: {} seconds", max_diff_ms / 1000);
        println!("  Actual diff: {} seconds", diff);
        println!("  Expected: FAIL ✗");
        assert!((diff as u64) > (max_diff_ms / 1000));

        // Scenario 6: Future timestamp validation
        println!("\nScenario 6: Future Timestamp Validation");
        let future_timestamp = now + 45; // 45 seconds in future
        let diff = now.abs_diff(future_timestamp);
        println!("  Server time: {}", now);
        println!("  Client time: {} (45 seconds in future)", future_timestamp);
        println!("  Max allowed: {} seconds", max_diff_ms / 1000);
        println!("  Actual diff: {} seconds", diff);
        println!("  Expected: PASS ✓");
        assert!((diff as u64) <= (max_diff_ms / 1000));

        println!("\n=== All Validation Scenarios Passed ===\n");
    }
}
