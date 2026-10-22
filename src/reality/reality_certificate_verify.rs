// REALITY certificate authentication (HMAC and optional ML-DSA)

use std::io;

use aws_lc_rs::hmac;
use subtle::ConstantTimeEq;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

pub fn verify_certificate_mldsa(
    cert_der: &[u8],
    auth_key: &[u8; 32],
    hellos: &[u8],
    verify_key: &super::reality_mldsa::VerifyKey,
) -> io::Result<()> {
    let (remaining, cert) = X509Certificate::from_der(cert_der)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid REALITY certificate"))?;
    if !remaining.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Trailing certificate bytes",
        ));
    }
    // OID 0.0 encodes as one zero byte; the parser displays it as "0".
    let mut signatures = cert
        .extensions()
        .iter()
        .filter(|ext| ext.oid.as_bytes() == [0]);
    let ext = signatures.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "REALITY ML-DSA-65 signature required",
        )
    })?;
    if signatures.next().is_some() || ext.critical {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Invalid REALITY ML-DSA-65 extension",
        ));
    }
    let public = ed25519_public_key(&cert)?;
    let message = super::reality_mldsa::certificate_message(auth_key, &public, &[hellos]);
    super::reality_mldsa::verify(verify_key, &message, ext.value)
}

/// Verifies the certificate HMAC and returns the authenticated Ed25519 public key.
///
/// In REALITY protocol, the server embeds HMAC-SHA512(auth_key, ed25519_public_key)
/// in the signature field of the certificate.
///
/// Uses x509-parser for robust extraction.
#[inline]
pub fn verify_certificate_hmac(cert_der: &[u8], auth_key: &[u8; 32]) -> io::Result<[u8; 32]> {
    let (remaining, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to parse X.509 certificate: {}", e),
        )
    })?;

    if !remaining.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Trailing certificate bytes",
        ));
    }
    let spki = cert.public_key();
    let pubkey_data: &[u8] = &spki.subject_public_key.data;
    let signature: &[u8] = &cert.signature_value.data;

    log::debug!(
        "REALITY CLIENT: Parsed certificate - pubkey len={}, sig len={}",
        pubkey_data.len(),
        signature.len()
    );

    let public_key = ed25519_public_key(&cert)?;

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
    Ok(public_key)
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

    ed25519_public_key(&cert)
}

fn ed25519_public_key(cert: &X509Certificate<'_>) -> io::Result<[u8; 32]> {
    let spki = cert.public_key();
    let pubkey_data: &[u8] = &spki.subject_public_key.data;

    if pubkey_data.len() != 32 || spki.algorithm.algorithm.to_id_string() != "1.3.101.112" {
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

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::KeyPair;

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
        let authenticated_key = verify_certificate_hmac(&cert_der, &auth_key).unwrap();
        assert_eq!(authenticated_key, public_key_bytes);
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
}
