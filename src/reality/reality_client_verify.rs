// REALITY client certificate verification
//
// This module handles HMAC verification of REALITY server certificates.
// In REALITY protocol, the server embeds HMAC-SHA512(auth_key, ed25519_public_key)
// in the signature field of the certificate.

use std::io;

use aws_lc_rs::hmac;
use subtle::ConstantTimeEq;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

/// Extract the DER-encoded certificate from a TLS 1.3 Certificate message
///
/// Certificate message structure:
/// - certificate_request_context (1 byte length + data)
/// - certificate_list length (3 bytes)
/// - For each certificate entry:
///   - cert_data length (3 bytes)
///   - cert_data (DER-encoded X.509 certificate)
///   - extensions length (2 bytes)
///   - extensions data
///
#[inline]
pub fn extract_certificate_der(certificate_message: &[u8]) -> io::Result<&[u8]> {
    // Skip handshake header (type + 3-byte length)
    if certificate_message.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Certificate message too short",
        ));
    }

    let mut pos = 4; // Skip handshake header

    // certificate_request_context length (1 byte)
    if pos >= certificate_message.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Certificate message truncated at context length",
        ));
    }
    let context_len = certificate_message[pos] as usize;
    pos += 1 + context_len;

    // certificate_list length (3 bytes)
    if pos + 3 > certificate_message.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Certificate message truncated at list length",
        ));
    }
    let _list_len = u32::from_be_bytes([
        0,
        certificate_message[pos],
        certificate_message[pos + 1],
        certificate_message[pos + 2],
    ]) as usize;
    pos += 3;

    // First certificate entry: cert_data length (3 bytes)
    if pos + 3 > certificate_message.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Certificate message truncated at cert length",
        ));
    }
    let cert_len = u32::from_be_bytes([
        0,
        certificate_message[pos],
        certificate_message[pos + 1],
        certificate_message[pos + 2],
    ]) as usize;
    pos += 3;

    // Extract the DER-encoded certificate
    if pos + cert_len > certificate_message.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Certificate message truncated at cert data",
        ));
    }

    Ok(&certificate_message[pos..pos + cert_len])
}

/// Verify the HMAC signature embedded in the REALITY certificate
///
/// In REALITY protocol, the server embeds HMAC-SHA512(auth_key, ed25519_public_key)
/// in the signature field of the certificate. We compare the first 32 bytes.
///
/// Uses proper X.509 parsing via x509-parser crate for robust extraction.
#[inline]
pub fn verify_certificate_hmac(cert_der: &[u8], auth_key: &[u8; 32]) -> io::Result<()> {
    // Parse the X.509 certificate properly
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to parse X.509 certificate: {}", e),
        )
    })?;

    // Extract the public key from SubjectPublicKeyInfo
    let spki = cert.public_key();
    let pubkey_data: &[u8] = &spki.subject_public_key.data;
    let signature: &[u8] = &cert.signature_value.data;

    log::debug!(
        "REALITY CLIENT: Parsed certificate - pubkey len={}, sig len={}",
        pubkey_data.len(),
        signature.len()
    );

    // Verify this is an Ed25519 public key (32 bytes)
    if pubkey_data.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Expected Ed25519 public key (32 bytes), got {} bytes",
                pubkey_data.len()
            ),
        ));
    }

    // Verify signature is long enough (should be 64 bytes for Ed25519, containing HMAC-SHA512)
    if signature.len() < 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Signature too short for HMAC verification: {} bytes",
                signature.len()
            ),
        ));
    }

    // Compute expected HMAC: HMAC-SHA512(auth_key, ed25519_public_key)
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA512, auth_key);
    let hmac_tag = hmac::sign(&hmac_key, pubkey_data);
    let expected_signature = &hmac_tag.as_ref()[..32]; // First 32 bytes

    log::debug!(
        "REALITY CLIENT: HMAC verification - ed25519_pubkey={:02x?}",
        pubkey_data
    );
    log::debug!(
        "REALITY CLIENT: HMAC verification - expected_sig={:02x?}",
        expected_signature
    );
    log::debug!(
        "REALITY CLIENT: HMAC verification - actual_sig={:02x?}",
        &signature[..32]
    );

    // Compare first 32 bytes of signature with expected HMAC using constant-time comparison
    // to prevent timing attacks that could leak information about the expected signature
    if expected_signature.ct_eq(&signature[..32]).unwrap_u8() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Certificate HMAC verification failed - signature mismatch",
        ));
    }

    log::info!("REALITY CLIENT: Certificate HMAC verified successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::KeyPair;

    /// Test certificate extraction with a properly formatted TLS 1.3 Certificate message
    #[test]
    fn test_extract_certificate_der_valid() {
        // Build a minimal TLS 1.3 Certificate message:
        // Handshake header: type (0x0b) + 3-byte length
        // certificate_request_context: 1 byte length (0) + no data
        // certificate_list: 3 byte length + entries
        // First entry: 3 byte cert length + cert data + 2 byte extensions length (0)

        let cert_data = b"fake_certificate_der_data";
        let cert_len = cert_data.len();

        // Build certificate entry: cert_len (3 bytes) + cert + extensions_len (2 bytes)
        let entry_len = 3 + cert_len + 2;

        // Build certificate_list: list_len (3 bytes) + entry
        let list_len = entry_len;

        // Build message body: context_len (1) + list_len (3) + entry
        let body_len = 1 + 3 + entry_len;

        let mut message = Vec::new();
        // Handshake type (Certificate = 0x0b)
        message.push(0x0b);
        // Handshake length (3 bytes, big-endian)
        message.push(((body_len >> 16) & 0xff) as u8);
        message.push(((body_len >> 8) & 0xff) as u8);
        message.push((body_len & 0xff) as u8);
        // certificate_request_context length = 0
        message.push(0x00);
        // certificate_list length (3 bytes)
        message.push(((list_len >> 16) & 0xff) as u8);
        message.push(((list_len >> 8) & 0xff) as u8);
        message.push((list_len & 0xff) as u8);
        // First certificate: cert_data length (3 bytes)
        message.push(((cert_len >> 16) & 0xff) as u8);
        message.push(((cert_len >> 8) & 0xff) as u8);
        message.push((cert_len & 0xff) as u8);
        // cert_data
        message.extend_from_slice(cert_data);
        // extensions length = 0
        message.push(0x00);
        message.push(0x00);

        let result = extract_certificate_der(&message);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), cert_data);
    }

    /// Test certificate extraction with message too short
    #[test]
    fn test_extract_certificate_der_too_short() {
        let message = vec![0x0b, 0x00, 0x00]; // Only 3 bytes, need at least 4
        let result = extract_certificate_der(&message);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    /// Test certificate extraction with truncated context
    #[test]
    fn test_extract_certificate_der_truncated_context() {
        // Handshake header but no body
        let message = vec![0x0b, 0x00, 0x00, 0x10]; // Claims 16 bytes but none present
        let result = extract_certificate_der(&message);
        assert!(result.is_err());
    }

    /// Test HMAC verification with a real Ed25519 certificate
    #[test]
    fn test_verify_certificate_hmac_with_real_cert() {
        // Generate a real Ed25519 certificate using rcgen
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .expect("Failed to generate Ed25519 key pair");

        let params = rcgen::CertificateParams::new(vec!["test.example.com".to_string()])
            .expect("Failed to create certificate params");

        let cert = params
            .self_signed(&key_pair)
            .expect("Failed to create self-signed certificate");

        let mut cert_der = cert.der().to_vec();

        // Get the public key
        let signing_key =
            aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(key_pair.serialized_der())
                .expect("Failed to parse key");
        let public_key_bytes = signing_key.public_key().as_ref();

        // Parse the certificate to find where the signature actually is
        let (_, parsed_cert) =
            X509Certificate::from_der(&cert_der).expect("Failed to parse certificate");
        let sig_offset =
            parsed_cert.signature_value.data.as_ptr() as usize - cert_der.as_ptr() as usize;

        // Create auth_key and compute HMAC
        let auth_key = [0x42u8; 32];
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA512, &auth_key);
        let hmac_tag = hmac::sign(&hmac_key, public_key_bytes);

        // Replace the signature bytes at the correct offset
        cert_der[sig_offset..sig_offset + 64].copy_from_slice(hmac_tag.as_ref());

        // Now verify
        let result = verify_certificate_hmac(&cert_der, &auth_key);
        assert!(result.is_ok(), "HMAC verification should succeed");
    }

    /// Test HMAC verification with invalid signature
    #[test]
    fn test_verify_certificate_hmac_invalid_signature() {
        // Generate a real Ed25519 certificate but don't modify the signature
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .expect("Failed to generate Ed25519 key pair");

        let params = rcgen::CertificateParams::new(vec!["test.example.com".to_string()])
            .expect("Failed to create certificate params");

        let cert = params
            .self_signed(&key_pair)
            .expect("Failed to create self-signed certificate");

        let cert_der = cert.der().to_vec();
        let auth_key = [0x42u8; 32];

        // This should fail because the signature is a real Ed25519 signature, not HMAC
        let result = verify_certificate_hmac(&cert_der, &auth_key);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    /// Test HMAC verification with invalid certificate DER
    #[test]
    fn test_verify_certificate_hmac_invalid_der() {
        let auth_key = [0x11u8; 32];
        let invalid_der = vec![0x30, 0x00]; // Empty SEQUENCE, not a valid certificate

        let result = verify_certificate_hmac(&invalid_der, &auth_key);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
}
