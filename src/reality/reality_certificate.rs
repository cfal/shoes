use aws_lc_rs::hmac;
use aws_lc_rs::signature::Ed25519KeyPair;
use std::io::{Error, ErrorKind, Result};

/// Generate a template Ed25519 certificate for the given hostname
fn generate_template_cert(hostname: &str) -> (Vec<u8>, Ed25519KeyPair) {
    // Generate Ed25519 keypair using rcgen
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .expect("Failed to generate Ed25519 key pair");

    // Generate a minimal self-signed certificate using rcgen with Ed25519
    let params = rcgen::CertificateParams::new(vec![hostname.to_string()])
        .expect("Failed to create certificate params");

    // Create self-signed certificate
    let cert = params
        .self_signed(&key_pair)
        .expect("Failed to create self-signed certificate");

    let cert_der = cert.der().to_vec();

    // Create the Ed25519KeyPair from the PKCS#8 document
    let signing_key = Ed25519KeyPair::from_pkcs8(key_pair.serialized_der())
        .expect("Failed to parse generated key");

    use aws_lc_rs::signature::KeyPair;
    let public_key_bytes = signing_key.public_key().as_ref();

    log::debug!(
        "REALITY DEBUG: Generated template certificate ({} bytes) for {}",
        cert_der.len(),
        hostname
    );
    log::debug!(
        "REALITY DEBUG: Using public key: {:?}",
        &public_key_bytes[..16.min(public_key_bytes.len())]
    );

    // Debug: print last 70 bytes to see signature structure
    if cert_der.len() > 70 {
        log::debug!(
            "REALITY DEBUG: Last 70 bytes: {:?}",
            &cert_der[cert_der.len() - 70..]
        );
    }

    (cert_der, signing_key)
}

/// Generate HMAC-signed Ed25519 certificate
///
/// This follows the uTLS approach:
/// 1. Generate a certificate for the destination hostname
/// 2. Replace the signature (last 64 bytes) with HMAC-SHA512(auth_key, ed25519_public_key)
///
/// This is NOT a cryptographically valid certificate!
pub fn generate_hmac_certificate(
    auth_key: &[u8; 32],
    hostname: &str,
) -> Result<(Vec<u8>, Ed25519KeyPair)> {
    // Generate a new certificate for the destination hostname
    let (cert_der, signing_key) = generate_template_cert(hostname);

    log::debug!(
        "REALITY DEBUG: Using template certificate ({} bytes)",
        cert_der.len()
    );

    // Extract the Ed25519 public key from the signing key
    use aws_lc_rs::signature::KeyPair;
    let public_key_bytes = signing_key.public_key().as_ref();

    // Replace signature with HMAC
    let cert_with_hmac = replace_signature_with_hmac(cert_der, auth_key, public_key_bytes)?;

    log::debug!("REALITY DEBUG: Replaced signature with HMAC");

    // Return the HMAC-signed certificate with the signing key
    Ok((cert_with_hmac, signing_key))
}

/// Replace the certificate signature with HMAC-SHA512(auth_key, ed25519_public_key)
fn replace_signature_with_hmac(
    mut cert_der: Vec<u8>,
    auth_key: &[u8; 32],
    public_key_bytes: &[u8],
) -> Result<Vec<u8>> {
    // The signature is the last BIT STRING in the certificate DER
    // For Ed25519, it's always 64 bytes

    // Find the signature BIT STRING tag
    // It should be near the end of the certificate
    // BIT STRING tag = 0x03
    // Length = 0x41 (65 bytes: 1 byte unused bits + 64 bytes signature)

    // Search backwards for BIT STRING tag
    let mut sig_offset = None;
    for i in (0..cert_der.len().saturating_sub(66)).rev() {
        if cert_der[i] == 0x03 && cert_der[i + 1] == 0x41 && cert_der[i + 2] == 0x00 {
            // Found it!
            sig_offset = Some(i + 3); // Skip tag, length, unused bits
            break;
        }
    }

    let sig_offset = sig_offset.ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            "Could not find signature in certificate DER",
        )
    })?;

    if sig_offset + 64 > cert_der.len() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Invalid signature offset",
        ));
    }

    // Compute HMAC-SHA512(auth_key, ed25519_public_key)
    let key = hmac::Key::new(hmac::HMAC_SHA512, auth_key);
    let tag = hmac::sign(&key, public_key_bytes);
    let hmac_bytes = tag.as_ref();

    // Replace signature bytes with HMAC
    cert_der[sig_offset..sig_offset + 64].copy_from_slice(hmac_bytes);

    log::debug!(
        "REALITY DEBUG: HMAC signature (first 16 bytes): {:?}",
        &hmac_bytes[..16]
    );

    Ok(cert_der)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_hmac_certificate() {
        let auth_key = [42u8; 32];
        let hostname = "test.example.com";
        let result = generate_hmac_certificate(&auth_key, hostname);

        assert!(result.is_ok());

        let (cert_der, _signing_key) = result.unwrap();

        // Certificate should be a reasonable size (few hundred bytes)
        assert!(cert_der.len() > 100);
        assert!(cert_der.len() < 1000);

        // Should start with SEQUENCE tag
        assert_eq!(cert_der[0], 0x30);
    }

    #[test]
    fn test_hmac_signature_deterministic() {
        let auth_key = [99u8; 32];
        let hostname = "test.example.com";

        let (cert1, key1) = generate_hmac_certificate(&auth_key, hostname).unwrap();
        use aws_lc_rs::signature::KeyPair;
        let public_key1 = key1.public_key().as_ref().to_vec();

        // Generate another certificate with same auth_key
        let (cert2, key2) = generate_hmac_certificate(&auth_key, hostname).unwrap();
        let public_key2 = key2.public_key().as_ref().to_vec();

        // Different Ed25519 keys (random generation)
        assert_ne!(public_key1, public_key2);

        // But certificates should have different signatures
        // (because they're based on different public keys)
        assert_ne!(cert1, cert2);
    }
}
