// REALITY certificate verification (HMAC and CertificateVerify)

use std::io;

use aws_lc_rs::hmac;
use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
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

    let mut pos = 4;

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
/// in the signature field of the certificate.
///
/// Uses x509-parser for robust extraction.
#[inline]
pub fn verify_certificate_hmac(cert_der: &[u8], auth_key: &[u8; 32]) -> io::Result<()> {
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to parse X.509 certificate: {}", e),
        )
    })?;

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

    // Verify signature is exactly 64 bytes (HMAC-SHA512 output)
    if signature.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Expected 64-byte signature for HMAC-SHA512 verification, got {} bytes",
                signature.len()
            ),
        ));
    }

    // Compute expected HMAC: HMAC-SHA512(auth_key, ed25519_public_key)
    // Reference: sing-box reality_client.go lines 273-275
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA512, auth_key);
    let hmac_tag = hmac::sign(&hmac_key, pubkey_data);
    let expected_signature = hmac_tag.as_ref(); // Full 64 bytes

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
        signature
    );

    // Compare full 64-byte signature with expected HMAC using constant-time comparison
    // to prevent timing attacks that could leak information about the expected signature
    if expected_signature.ct_eq(signature).unwrap_u8() == 0 {
        // HMAC mismatch - the certificate is not signed by a REALITY server.
        // Possible causes:
        // 1. Connection intercepted/MITM (received real certificate from target site)
        // 2. ISP traffic hijacking/redirection
        // 3. Misconfigured server (wrong keys)
        // 4. Connection to wrong server
        // Note: Unlike Xray-core, we don't fall back to X.509 validation and spider crawling.
        log::warn!(
            "REALITY CLIENT: Certificate HMAC mismatch - not a REALITY server (possible MITM or misconfiguration)"
        );
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Certificate HMAC verification failed - not a REALITY-signed certificate",
        ));
    }

    log::debug!("REALITY CLIENT: Certificate HMAC verified successfully");
    Ok(())
}

/// Extract the Ed25519 public key from a DER-encoded certificate
///
/// Returns the 32-byte Ed25519 public key.
#[inline]
pub fn extract_ed25519_public_key(cert_der: &[u8]) -> io::Result<[u8; 32]> {
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to parse X.509 certificate: {}", e),
        )
    })?;

    let spki = cert.public_key();
    let pubkey_data: &[u8] = &spki.subject_public_key.data;

    if pubkey_data.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Expected Ed25519 public key (32 bytes), got {} bytes",
                pubkey_data.len()
            ),
        ));
    }

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(pubkey_data);
    Ok(public_key)
}

/// Parse CertificateVerify message and extract the signature
///
/// CertificateVerify structure:
/// - handshake_type (1 byte) = 0x0f
/// - length (3 bytes)
/// - signature_algorithm (2 bytes)
/// - signature_length (2 bytes)
/// - signature (variable)
///
/// Returns the signature bytes.
#[inline]
pub fn extract_certificate_verify_signature(cert_verify_message: &[u8]) -> io::Result<Vec<u8>> {
    // Minimum: 1 (type) + 3 (len) + 2 (alg) + 2 (sig len) + 64 (ed25519 sig) = 72
    if cert_verify_message.len() < 72 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "CertificateVerify message too short: {} bytes",
                cert_verify_message.len()
            ),
        ));
    }

    if cert_verify_message[0] != 0x0f {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Expected CertificateVerify type (0x0f), got 0x{:02x}",
                cert_verify_message[0]
            ),
        ));
    }

    // Skip handshake header (4 bytes)
    let pos = 4;

    // Signature algorithm (2 bytes)
    let sig_alg = u16::from_be_bytes([cert_verify_message[pos], cert_verify_message[pos + 1]]);

    // We only support Ed25519 (0x0807)
    if sig_alg != 0x0807 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Unsupported signature algorithm: 0x{:04x}, expected Ed25519 (0x0807)",
                sig_alg
            ),
        ));
    }

    // Signature length (2 bytes)
    let sig_len =
        u16::from_be_bytes([cert_verify_message[pos + 2], cert_verify_message[pos + 3]]) as usize;

    // Ed25519 signatures are always 64 bytes
    if sig_len != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid Ed25519 signature length: {}, expected 64", sig_len),
        ));
    }

    // Extract signature
    let sig_start = pos + 4;
    if sig_start + sig_len > cert_verify_message.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CertificateVerify message truncated",
        ));
    }

    Ok(cert_verify_message[sig_start..sig_start + sig_len].to_vec())
}

/// Verify the CertificateVerify signature
///
/// This verifies that the server holds the private key corresponding to the
/// public key in the certificate. The signature is over:
///   64 spaces + "TLS 1.3, server CertificateVerify\0" + transcript_hash
///
/// # Arguments
/// * `public_key` - The Ed25519 public key from the certificate (32 bytes)
/// * `signature` - The signature from CertificateVerify message (64 bytes)
/// * `transcript_hash` - Hash of handshake messages up to (but not including) CertificateVerify
#[inline]
pub fn verify_certificate_verify_signature(
    public_key: &[u8; 32],
    signature: &[u8],
    transcript_hash: &[u8],
) -> io::Result<()> {
    if signature.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid signature length: {}, expected 64", signature.len()),
        ));
    }

    // Construct the signed content per RFC 8446 Section 4.4.3:
    // "  " * 64 + context_string + 0x00 + content
    let mut signed_content = Vec::with_capacity(64 + 34 + transcript_hash.len());
    signed_content.extend_from_slice(&[0x20u8; 64]); // 64 spaces
    signed_content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    signed_content.push(0x00);
    signed_content.extend_from_slice(transcript_hash);

    // Verify the Ed25519 signature
    let public_key = UnparsedPublicKey::new(&ED25519, public_key);
    public_key.verify(&signed_content, signature).map_err(|_| {
        log::warn!("REALITY CLIENT: CertificateVerify signature verification failed");
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "CertificateVerify signature verification failed",
        )
    })?;

    log::debug!("REALITY CLIENT: CertificateVerify signature verified successfully");
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

    /// Test extracting Ed25519 public key from certificate
    #[test]
    fn test_extract_ed25519_public_key() {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .expect("Failed to generate Ed25519 key pair");

        let params = rcgen::CertificateParams::new(vec!["test.example.com".to_string()])
            .expect("Failed to create certificate params");

        let cert = params
            .self_signed(&key_pair)
            .expect("Failed to create self-signed certificate");

        let cert_der = cert.der().to_vec();

        // Extract the public key
        let result = extract_ed25519_public_key(&cert_der);
        assert!(result.is_ok());

        let public_key = result.unwrap();
        assert_eq!(public_key.len(), 32);

        // Verify it matches the original key
        let signing_key =
            aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(key_pair.serialized_der())
                .expect("Failed to parse key");
        assert_eq!(public_key, signing_key.public_key().as_ref());
    }

    /// Test extracting signature from CertificateVerify message
    #[test]
    fn test_extract_certificate_verify_signature() {
        // Build a CertificateVerify message:
        // - type (1 byte) = 0x0f
        // - length (3 bytes)
        // - signature_algorithm (2 bytes) = 0x0807 (Ed25519)
        // - signature_length (2 bytes) = 64
        // - signature (64 bytes)

        let signature = [0xABu8; 64];
        let payload_len = 2 + 2 + 64; // sig_alg + sig_len + sig

        let mut message = Vec::new();
        message.push(0x0f); // CertificateVerify type
        message.push(0x00);
        message.push(0x00);
        message.push(payload_len as u8);
        message.push(0x08); // Ed25519 algorithm
        message.push(0x07);
        message.push(0x00); // Signature length
        message.push(0x40); // 64
        message.extend_from_slice(&signature);

        let result = extract_certificate_verify_signature(&message);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), signature.to_vec());
    }

    /// Test CertificateVerify extraction with wrong message type
    #[test]
    fn test_extract_certificate_verify_wrong_type() {
        let mut message = vec![0x0b; 72]; // Certificate type instead of CertificateVerify
        message[4] = 0x08;
        message[5] = 0x07;
        message[6] = 0x00;
        message[7] = 0x40;

        let result = extract_certificate_verify_signature(&message);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Expected CertificateVerify type")
        );
    }

    /// Test CertificateVerify extraction with unsupported algorithm
    #[test]
    fn test_extract_certificate_verify_unsupported_algorithm() {
        let mut message = vec![0x00; 72];
        message[0] = 0x0f; // CertificateVerify type
        message[4] = 0x04; // RSA-PKCS1-SHA256 instead of Ed25519
        message[5] = 0x01;

        let result = extract_certificate_verify_signature(&message);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unsupported signature algorithm")
        );
    }

    /// Test CertificateVerify extraction with message too short
    #[test]
    fn test_extract_certificate_verify_too_short() {
        let message = vec![0x0f; 10]; // Too short

        let result = extract_certificate_verify_signature(&message);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    /// Test full CertificateVerify signature verification
    #[test]
    fn test_verify_certificate_verify_signature_valid() {
        // Generate an Ed25519 key pair
        let key_pair = aws_lc_rs::signature::Ed25519KeyPair::generate()
            .expect("Failed to generate Ed25519 key pair");

        let public_key: [u8; 32] = key_pair.public_key().as_ref().try_into().unwrap();

        // Create a fake transcript hash
        let transcript_hash = [0x42u8; 32];

        // Construct the signed content per RFC 8446 Section 4.4.3
        let mut signed_content = Vec::new();
        signed_content.extend_from_slice(&[0x20u8; 64]); // 64 spaces
        signed_content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        signed_content.push(0x00);
        signed_content.extend_from_slice(&transcript_hash);

        // Sign it
        let signature = key_pair.sign(&signed_content);

        // Verify
        let result =
            verify_certificate_verify_signature(&public_key, signature.as_ref(), &transcript_hash);
        assert!(result.is_ok(), "Signature verification should succeed");
    }

    /// Test CertificateVerify verification with wrong public key
    #[test]
    fn test_verify_certificate_verify_signature_wrong_key() {
        // Generate two different key pairs
        let key_pair1 = aws_lc_rs::signature::Ed25519KeyPair::generate()
            .expect("Failed to generate Ed25519 key pair");
        let key_pair2 = aws_lc_rs::signature::Ed25519KeyPair::generate()
            .expect("Failed to generate Ed25519 key pair");

        let public_key2: [u8; 32] = key_pair2.public_key().as_ref().try_into().unwrap();

        let transcript_hash = [0x42u8; 32];

        // Construct and sign with key_pair1
        let mut signed_content = Vec::new();
        signed_content.extend_from_slice(&[0x20u8; 64]);
        signed_content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        signed_content.push(0x00);
        signed_content.extend_from_slice(&transcript_hash);

        let signature = key_pair1.sign(&signed_content);

        // Try to verify with key_pair2's public key - should fail
        let result =
            verify_certificate_verify_signature(&public_key2, signature.as_ref(), &transcript_hash);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    /// Test CertificateVerify verification with wrong transcript hash
    #[test]
    fn test_verify_certificate_verify_signature_wrong_transcript() {
        let key_pair = aws_lc_rs::signature::Ed25519KeyPair::generate()
            .expect("Failed to generate Ed25519 key pair");

        let public_key: [u8; 32] = key_pair.public_key().as_ref().try_into().unwrap();

        let transcript_hash1 = [0x42u8; 32];
        let transcript_hash2 = [0x43u8; 32]; // Different hash

        // Sign with transcript_hash1
        let mut signed_content = Vec::new();
        signed_content.extend_from_slice(&[0x20u8; 64]);
        signed_content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        signed_content.push(0x00);
        signed_content.extend_from_slice(&transcript_hash1);

        let signature = key_pair.sign(&signed_content);

        // Try to verify with transcript_hash2 - should fail
        let result =
            verify_certificate_verify_signature(&public_key, signature.as_ref(), &transcript_hash2);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    /// Test CertificateVerify verification with invalid signature length
    #[test]
    fn test_verify_certificate_verify_signature_invalid_length() {
        let public_key = [0x00u8; 32];
        let transcript_hash = [0x42u8; 32];
        let invalid_signature = [0x00u8; 32]; // Should be 64 bytes

        let result =
            verify_certificate_verify_signature(&public_key, &invalid_signature, &transcript_hash);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    /// Test end-to-end: generate certificate, create CertificateVerify, verify it
    #[test]
    fn test_certificate_verify_end_to_end() {
        use aws_lc_rs::digest;

        // Generate Ed25519 key pair
        let key_pair = aws_lc_rs::signature::Ed25519KeyPair::generate()
            .expect("Failed to generate Ed25519 key pair");

        let public_key: [u8; 32] = key_pair.public_key().as_ref().try_into().unwrap();

        // Simulate a transcript hash (in real life, this would be hash of handshake messages)
        let fake_client_hello = b"ClientHello data here";
        let fake_server_hello = b"ServerHello data here";
        let fake_encrypted_extensions = b"EncryptedExtensions here";
        let fake_certificate = b"Certificate message here";

        let mut transcript = digest::Context::new(&digest::SHA256);
        transcript.update(fake_client_hello);
        transcript.update(fake_server_hello);
        transcript.update(fake_encrypted_extensions);
        transcript.update(fake_certificate);
        let transcript_hash = transcript.finish();

        // Create CertificateVerify message (simulating server)
        let mut signed_content = Vec::new();
        signed_content.extend_from_slice(&[0x20u8; 64]);
        signed_content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        signed_content.push(0x00);
        signed_content.extend_from_slice(transcript_hash.as_ref());

        let signature = key_pair.sign(&signed_content);

        // Build CertificateVerify message
        let payload_len = 2 + 2 + 64;
        let mut cv_message = Vec::new();
        cv_message.push(0x0f); // type
        cv_message.push(0x00);
        cv_message.push(0x00);
        cv_message.push(payload_len as u8);
        cv_message.push(0x08); // Ed25519
        cv_message.push(0x07);
        cv_message.push(0x00); // sig len
        cv_message.push(0x40);
        cv_message.extend_from_slice(signature.as_ref());

        // Client side: extract and verify
        let extracted_sig =
            extract_certificate_verify_signature(&cv_message).expect("Failed to extract signature");

        let result = verify_certificate_verify_signature(
            &public_key,
            &extracted_sig,
            transcript_hash.as_ref(),
        );
        assert!(
            result.is_ok(),
            "End-to-end CertificateVerify verification should succeed"
        );
    }
}
