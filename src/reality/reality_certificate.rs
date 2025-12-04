use aws_lc_rs::hmac;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use rcgen::SignatureAlgorithm;
use std::io::{Error, ErrorKind, Result};

/// A signing key that computes HMAC-SHA512(auth_key, public_key) as the "signature".
///
/// This implements rcgen's SigningKey trait but ignores the TBS (to-be-signed) data,
/// instead computing the REALITY HMAC. This allows rcgen to place our HMAC directly
/// into the certificate signature field.
struct HmacSigningKey {
    /// The HMAC key derived from auth_key
    hmac_key: hmac::Key,
    /// The Ed25519 public key bytes (32 bytes)
    public_key: [u8; 32],
}

impl rcgen::SigningKey for HmacSigningKey {
    fn sign(&self, _msg: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
        // Ignore the TBS data - compute HMAC-SHA512(auth_key, public_key)
        let tag = hmac::sign(&self.hmac_key, &self.public_key);
        Ok(tag.as_ref().to_vec())
    }
}

impl rcgen::PublicKeyData for HmacSigningKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &rcgen::PKCS_ED25519
    }
}

/// Generate HMAC-signed Ed25519 certificate.
///
/// This creates a minimal X.509 certificate where:
/// - The public key is a real Ed25519 public key
/// - The signature is HMAC-SHA512(auth_key, public_key) instead of a real signature
///
/// The returned Ed25519KeyPair is used for:
/// 1. Its public key goes in the certificate (and HMAC is computed over it)
/// 2. Its private key signs the CertificateVerify message during TLS handshake
///
/// The client verifies both the HMAC and the CertificateVerify signature.
///
/// Returns the certificate (call `.der()` to get DER bytes) and the signing keypair.
pub fn generate_hmac_certificate(
    auth_key: &[u8; 32],
    hostname: &str,
) -> Result<(rcgen::Certificate, Ed25519KeyPair)> {
    // Keypair is needed for CertificateVerify signing
    let ed25519_keypair = Ed25519KeyPair::generate()
        .map_err(|_| Error::other("Failed to generate Ed25519 keypair"))?;

    let public_key: [u8; 32] = ed25519_keypair
        .public_key()
        .as_ref()
        .try_into()
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Ed25519 public key is not 32 bytes"))?;

    let hmac_key = HmacSigningKey {
        hmac_key: hmac::Key::new(hmac::HMAC_SHA512, auth_key),
        public_key,
    };

    // Create minimal certificate params matching reference implementation
    let mut params = rcgen::CertificateParams::default();
    // Reference impl doesn't have a hostname, but we set it anyway
    params.subject_alt_names =
        vec![rcgen::SanType::DnsName(hostname.try_into().map_err(
            |_| Error::new(ErrorKind::InvalidInput, "Invalid hostname"),
        )?)];
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.serial_number = Some(rcgen::SerialNumber::from(vec![0u8]));

    let cert = params
        .self_signed(&hmac_key)
        .map_err(|e| Error::other(format!("Failed to create certificate: {e}")))?;

    log::debug!(
        "REALITY: Generated HMAC certificate ({} bytes)",
        cert.der().len()
    );

    Ok((cert, ed25519_keypair))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::KeyPair;

    /// Find the signature bytes in a DER-encoded certificate.
    /// Returns the offset where the 64-byte Ed25519 signature starts.
    fn find_signature_offset(cert_der: &[u8]) -> Option<usize> {
        // The signature is the last BIT STRING in the certificate DER
        // For Ed25519, it's always 64 bytes
        // BIT STRING tag = 0x03
        // Length = 0x41 (65 bytes: 1 byte unused bits + 64 bytes signature)
        for i in (0..cert_der.len().saturating_sub(66)).rev() {
            if cert_der[i] == 0x03 && cert_der[i + 1] == 0x41 && cert_der[i + 2] == 0x00 {
                return Some(i + 3); // Skip tag, length, unused bits
            }
        }
        None
    }

    #[test]
    fn test_generate_hmac_certificate() {
        let auth_key = [42u8; 32];
        let result = generate_hmac_certificate(&auth_key, "test.example.com");

        assert!(result.is_ok());

        let (cert, _signing_key) = result.unwrap();
        let cert_der = cert.der();

        // Certificate should be a reasonable size
        assert!(cert_der.len() > 100);
        assert!(cert_der.len() < 1000);

        // Should start with SEQUENCE tag
        assert_eq!(cert_der[0], 0x30);
    }

    #[test]
    fn test_hmac_placed_at_correct_offset() {
        // This test verifies that our HmacSigningKey places the HMAC bytes
        // at exactly the same location that find_signature_offset() identifies.

        let auth_key = [0x42u8; 32];

        let (cert, signing_key) = generate_hmac_certificate(&auth_key, "test.example.com").unwrap();
        let cert_der = cert.der();

        // Find where the signature should be
        let sig_offset =
            find_signature_offset(cert_der).expect("Should find signature offset in certificate");

        // Compute what the HMAC should be
        let public_key_bytes = signing_key.public_key().as_ref();
        let key = hmac::Key::new(hmac::HMAC_SHA512, &auth_key);
        let expected_hmac = hmac::sign(&key, public_key_bytes);

        // Extract the signature bytes from the certificate
        let actual_signature = &cert_der[sig_offset..sig_offset + 64];

        // They should match exactly
        assert_eq!(
            actual_signature,
            expected_hmac.as_ref(),
            "HMAC signature should be placed at the correct offset in the certificate"
        );
    }

    #[test]
    fn test_different_keys_produce_different_hmacs() {
        let auth_key = [99u8; 32];

        let (cert1, key1) = generate_hmac_certificate(&auth_key, "test.example.com").unwrap();
        let (cert2, key2) = generate_hmac_certificate(&auth_key, "test.example.com").unwrap();
        let cert1_der = cert1.der();
        let cert2_der = cert2.der();

        // Different Ed25519 keys (random generation)
        assert_ne!(
            key1.public_key().as_ref(),
            key2.public_key().as_ref(),
            "Each call should generate a new random keypair"
        );

        // Different certificates (different public keys -> different HMACs)
        assert_ne!(cert1_der.as_ref(), cert2_der.as_ref());

        // But both should have valid HMAC signatures
        let sig_offset1 = find_signature_offset(cert1_der).unwrap();
        let sig_offset2 = find_signature_offset(cert2_der).unwrap();

        // Verify HMAC for cert1
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA512, &auth_key);
        let expected1 = hmac::sign(&hmac_key, key1.public_key().as_ref());
        assert_eq!(
            &cert1_der[sig_offset1..sig_offset1 + 64],
            expected1.as_ref()
        );

        // Verify HMAC for cert2
        let expected2 = hmac::sign(&hmac_key, key2.public_key().as_ref());
        assert_eq!(
            &cert2_der[sig_offset2..sig_offset2 + 64],
            expected2.as_ref()
        );
    }

    #[test]
    fn test_signature_offset_consistent() {
        // Generate multiple certificates and verify the signature is always
        // at the same relative position (since cert structure is identical)
        let auth_key = [0xABu8; 32];

        let mut offsets = Vec::new();
        let mut sizes = Vec::new();

        for _ in 0..5 {
            let (cert, _) = generate_hmac_certificate(&auth_key, "example.com").unwrap();
            let cert_der = cert.der();
            let offset = find_signature_offset(cert_der).unwrap();
            offsets.push(offset);
            sizes.push(cert_der.len());
        }

        // All certificates should have the same size
        assert!(
            sizes.iter().all(|&s| s == sizes[0]),
            "All certificates should have identical size: {:?}",
            sizes
        );

        // All signatures should be at the same offset
        assert!(
            offsets.iter().all(|&o| o == offsets[0]),
            "All signatures should be at the same offset: {:?}",
            offsets
        );
    }
}
