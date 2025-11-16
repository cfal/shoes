// TLS 1.3 Key Schedule Implementation
//
// Implements RFC 8446 key derivation for TLS 1.3
// Using HKDF-SHA256 for all key derivation operations

use aws_lc_rs::digest;
use std::io::{Error, ErrorKind, Result};

/// Intermediate TLS 1.3 keys (handshake secrets + master secret)
/// Used for two-phase key derivation where application secrets
/// must be derived after server Finished message
#[derive(Debug, Clone)]
pub struct Tls13HandshakeKeys {
    /// Client handshake traffic secret
    pub client_handshake_traffic_secret: Vec<u8>,
    /// Server handshake traffic secret
    pub server_handshake_traffic_secret: Vec<u8>,
    /// Master secret (for deriving application secrets later)
    pub master_secret: Vec<u8>,
}

/// HKDF-Expand implementation using HMAC-SHA256 directly
/// This follows RFC 5869 Section 2.3
pub fn hkdf_expand_sha256(prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
    use aws_lc_rs::hmac;

    const HASH_LEN: usize = 32; // SHA256 output length
    let n = length.div_ceil(HASH_LEN); // Number of iterations

    if n > 255 {
        return Err(Error::new(ErrorKind::InvalidData, "HKDF output too long"));
    }

    let mut output = Vec::new();
    let mut prev = Vec::new();

    for i in 1..=n {
        let key = hmac::Key::new(hmac::HMAC_SHA256, prk);
        let mut ctx = hmac::Context::with_key(&key);

        log::debug!(
            "HKDF iteration {}: prev_len={}, info_len={}",
            i,
            prev.len(),
            info.len()
        );

        ctx.update(&prev);
        ctx.update(info);
        ctx.update(&[i as u8]);
        let tag = ctx.sign();

        log::debug!(
            "HKDF iteration {}: output={:02x?}",
            i,
            &tag.as_ref()[..tag.as_ref().len().min(16)]
        );

        prev = tag.as_ref().to_vec();
        output.extend_from_slice(tag.as_ref());
    }

    output.truncate(length);
    Ok(output)
}

/// HKDF-Expand-Label as defined in RFC 8446 Section 7.1
fn hkdf_expand_label(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>> {
    log::debug!(
        "DEBUG hkdf_expand_label: secret len={}, label={:?}, context len={}, length={}",
        secret.len(),
        std::str::from_utf8(label).unwrap_or("<binary>"),
        context.len(),
        length
    );
    // HkdfLabel structure:
    // struct {
    //     uint16 length = Length;
    //     opaque label<7..255> = "tls13 " + Label;
    //     opaque context<0..255> = Context;
    // } HkdfLabel;

    let mut hkdf_label = Vec::new();

    // Length (2 bytes, big-endian)
    hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());

    // Label length and content
    let full_label = format!("tls13 {}", std::str::from_utf8(label).unwrap());
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(full_label.as_bytes());

    // Context length and content
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    log::debug!("HKDF_LABEL_BYTES: {:02x?}", hkdf_label);

    // Use our helper function
    hkdf_expand_sha256(secret, &hkdf_label, length)
}

/// Derive-Secret as defined in RFC 8446 Section 7.1
fn derive_secret(secret: &[u8], label: &[u8], messages_hash: &[u8]) -> Result<Vec<u8>> {
    hkdf_expand_label(secret, label, messages_hash, 32)
}

/// HKDF-Extract operation
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    // Use hmac directly for extract operation since aws-lc-rs doesn't expose PRK bytes
    use aws_lc_rs::hmac;
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let tag = hmac::sign(&key, ikm);
    tag.as_ref().to_vec()
}

/// Derive TLS 1.3 handshake keys and master secret (Phase 1)
///
/// This function derives handshake traffic secrets and the master secret,
/// but NOT the application traffic secrets. Application secrets must be
/// derived separately after the server Finished message is sent (Phase 2).
///
/// # Arguments
/// * `shared_secret` - ECDH shared secret (32 bytes for X25519)
/// * `client_hello_hash` - SHA256 hash of ClientHello (32 bytes)
/// * `server_hello_hash` - SHA256 hash of ClientHello...ServerHello (32 bytes)
///
/// # Returns
/// Handshake traffic secrets and master secret
pub fn derive_handshake_keys(
    shared_secret: &[u8],
    client_hello_hash: &[u8],
    server_hello_hash: &[u8],
) -> Result<Tls13HandshakeKeys> {
    // Validate input lengths
    if shared_secret.len() != 32 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "Invalid shared_secret length: {} (expected 32)",
                shared_secret.len()
            ),
        ));
    }
    if client_hello_hash.len() != 32 || server_hello_hash.len() != 32 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "All hashes must be 32 bytes (SHA256)",
        ));
    }

    log::debug!("TLS13 DEBUG: Deriving handshake keys (Phase 1)...");

    // 1. Early Secret = HKDF-Extract(salt=0, IKM=0)
    let zero_salt = vec![0u8; 32];
    let early_secret = hkdf_extract(&zero_salt, &zero_salt);

    // 2. Derive-Secret(., "derived", "")
    let mut empty_ctx = digest::Context::new(&digest::SHA256);
    empty_ctx.update(b"");
    let empty_hash = empty_ctx.finish();
    let derived_secret = derive_secret(&early_secret, b"derived", empty_hash.as_ref())?;

    // 3. Handshake Secret = HKDF-Extract(salt=derived_secret, IKM=shared_secret)
    let handshake_secret = hkdf_extract(&derived_secret, shared_secret);

    // 4. Client Handshake Traffic Secret
    let client_handshake_traffic_secret =
        derive_secret(&handshake_secret, b"c hs traffic", server_hello_hash)?;

    // 5. Server Handshake Traffic Secret
    let server_handshake_traffic_secret =
        derive_secret(&handshake_secret, b"s hs traffic", server_hello_hash)?;

    // 6. Derive-Secret(., "derived", "")
    let mut empty_ctx_2 = digest::Context::new(&digest::SHA256);
    empty_ctx_2.update(b"");
    let empty_hash_2 = empty_ctx_2.finish();
    let derived_secret_2 = derive_secret(&handshake_secret, b"derived", empty_hash_2.as_ref())?;

    // 7. Master Secret = HKDF-Extract(salt=derived_secret, IKM=0)
    let master_secret = hkdf_extract(&derived_secret_2, &zero_salt);

    log::debug!("  master_secret: {:?}", &master_secret[..8]);

    Ok(Tls13HandshakeKeys {
        client_handshake_traffic_secret,
        server_handshake_traffic_secret,
        master_secret,
    })
}

/// Derive TLS 1.3 application traffic secrets (Phase 2)
///
/// This function must be called AFTER the server Finished message is sent,
/// with a transcript hash that includes the Finished message.
///
/// # Arguments
/// * `master_secret` - Master secret from Phase 1
/// * `handshake_hash` - SHA256 hash including server Finished (32 bytes)
///
/// # Returns
/// (client_application_traffic_secret, server_application_traffic_secret)
pub fn derive_application_secrets(
    master_secret: &[u8],
    handshake_hash: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    if master_secret.len() != 32 || handshake_hash.len() != 32 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Master secret and handshake hash must be 32 bytes",
        ));
    }

    log::debug!("TLS13 DEBUG: Deriving application secrets (Phase 2)...");
    log::info!(
        "  handshake_hash (with Finished): {:?}",
        &handshake_hash[..8]
    );

    // Client Application Traffic Secret
    let client_application_traffic_secret =
        derive_secret(master_secret, b"c ap traffic", handshake_hash)?;

    log::debug!(
        "  client_app_traffic: {:?}",
        &client_application_traffic_secret[..8]
    );
    log::info!(
        "DERIVE_APP_SECRETS: ClientAppSecret(full)={:02x?}",
        client_application_traffic_secret
    );

    // Server Application Traffic Secret
    let server_application_traffic_secret =
        derive_secret(master_secret, b"s ap traffic", handshake_hash)?;

    log::debug!(
        "  server_app_traffic: {:?}",
        &server_application_traffic_secret[..8]
    );
    log::info!(
        "DERIVE_APP_SECRETS: ServerAppSecret(full)={:02x?}",
        server_application_traffic_secret
    );

    Ok((
        client_application_traffic_secret,
        server_application_traffic_secret,
    ))
}

/// Derive traffic keys and IV from traffic secret
///
/// # Arguments
/// * `traffic_secret` - Traffic secret (32 bytes)
/// * `cipher_suite` - TLS cipher suite (e.g., 0x1301 for TLS_AES_128_GCM_SHA256)
///
/// # Returns
/// (key, iv) tuple for AES-GCM
pub fn derive_traffic_keys(traffic_secret: &[u8], cipher_suite: u16) -> Result<(Vec<u8>, Vec<u8>)> {
    // For TLS_AES_128_GCM_SHA256 (0x1301):
    // - key_length = 16 bytes
    // - iv_length = 12 bytes

    let (key_length, iv_length) = match cipher_suite {
        0x1301 => (16, 12), // TLS_AES_128_GCM_SHA256
        0x1302 => (32, 12), // TLS_AES_256_GCM_SHA384
        0x1303 => (32, 12), // TLS_CHACHA20_POLY1305_SHA256
        _ => {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Unsupported cipher suite: 0x{:04x}", cipher_suite),
            ))
        }
    };

    log::debug!(
        "TRAFFIC_KEY_DERIVE: cipher_suite=0x{:04x}, key_len={}, iv_len={}",
        cipher_suite,
        key_length,
        iv_length
    );
    log::debug!("TRAFFIC_KEY_DERIVE: traffic_secret={:02x?}", traffic_secret);

    // key = HKDF-Expand-Label(Secret, "key", "", key_length)
    let key = hkdf_expand_label(traffic_secret, b"key", b"", key_length)?;

    // iv = HKDF-Expand-Label(Secret, "iv", "", iv_length)
    let iv = hkdf_expand_label(traffic_secret, b"iv", b"", iv_length)?;

    log::info!("TRAFFIC_KEY_DERIVE: key={:02x?}", key);
    log::info!("TRAFFIC_KEY_DERIVE: iv={:02x?}", iv);

    Ok((key, iv))
}

/// Compute "Finished" verify data
///
/// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
/// verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context))
pub fn compute_finished_verify_data(base_key: &[u8], handshake_hash: &[u8]) -> Result<Vec<u8>> {
    use aws_lc_rs::hmac;

    // finished_key = HKDF-Expand-Label(BaseKey, "finished", "", 32)
    let finished_key = hkdf_expand_label(base_key, b"finished", b"", 32)?;

    // verify_data = HMAC(finished_key, handshake_hash)
    let key = hmac::Key::new(hmac::HMAC_SHA256, &finished_key);
    let tag = hmac::sign(&key, handshake_hash);
    let verify_data = tag.as_ref().to_vec();

    Ok(verify_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from RFC 5869 Appendix A
    #[test]
    fn test_hkdf_expand_sha256_rfc_vector() {
        // Test Case 1 from RFC 5869 (simplified - using extracted PRK directly)
        let prk = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        let result = hkdf_expand_sha256(&prk, &info, 42).unwrap();
        assert_eq!(result.len(), 42);

        // Check first few bytes match expected pattern
        assert_eq!(result[0], 0x3c);
        assert_eq!(result[1], 0xb2);
        assert_eq!(result[2], 0x5f);
    }

    #[test]
    fn test_hkdf_expand_sha256_empty_info() {
        let prk = vec![0x42u8; 32];
        let result = hkdf_expand_sha256(&prk, &[], 16);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 16);
    }

    #[test]
    fn test_hkdf_expand_sha256_max_length() {
        let prk = vec![0x42u8; 32];
        let info = b"test info";

        // Maximum output length is 255 * hash_len (32 for SHA256) = 8160 bytes
        let result = hkdf_expand_sha256(&prk, info, 8160);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 8160);

        // Should fail for length > 8160
        let result = hkdf_expand_sha256(&prk, info, 8161);
        assert!(result.is_err());
    }

    #[test]
    fn test_hkdf_expand_label() {
        let secret = vec![0x42u8; 32];
        let result = hkdf_expand_label(&secret, b"test", b"", 16);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 16);
    }

    #[test]
    fn test_hkdf_expand_label_with_context() {
        let secret = vec![0x42u8; 32];
        let context = vec![0x11u8; 32];
        let result = hkdf_expand_label(&secret, b"finished", &context, 32);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.len(), 32);

        // Result should be deterministic
        let result2 = hkdf_expand_label(&secret, b"finished", &context, 32).unwrap();
        assert_eq!(output, result2);
    }

    #[test]
    fn test_hkdf_extract() {
        let salt = vec![0x11u8; 32];
        let ikm = vec![0x22u8; 32];

        let result1 = hkdf_extract(&salt, &ikm);
        assert_eq!(result1.len(), 32); // SHA256 output length

        // Should be deterministic
        let result2 = hkdf_extract(&salt, &ikm);
        assert_eq!(result1, result2);

        // Different input should give different output
        let ikm2 = vec![0x33u8; 32];
        let result3 = hkdf_extract(&salt, &ikm2);
        assert_ne!(result1, result3);
    }

    #[test]
    fn test_derive_traffic_keys() {
        let traffic_secret = vec![0x99u8; 32];

        // Test TLS_AES_128_GCM_SHA256
        let result = derive_traffic_keys(&traffic_secret, 0x1301);
        assert!(result.is_ok());
        let (key, iv) = result.unwrap();
        assert_eq!(key.len(), 16);
        assert_eq!(iv.len(), 12);
    }

    #[test]
    fn test_compute_finished_verify_data() {
        let base_key = vec![0xAAu8; 32];
        let handshake_hash = vec![0xBBu8; 32];

        let result = compute_finished_verify_data(&base_key, &handshake_hash);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }
}
