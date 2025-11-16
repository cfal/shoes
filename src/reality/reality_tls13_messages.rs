// TLS 1.3 Message Construction
//
// Construct TLS 1.3 handshake messages for REALITY protocol

use super::common::{
    HANDSHAKE_TYPE_CERTIFICATE, HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
    HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, HANDSHAKE_TYPE_FINISHED, HANDSHAKE_TYPE_SERVER_HELLO,
    VERSION_TLS_1_2_MAJOR, VERSION_TLS_1_2_MINOR,
};
use aws_lc_rs::signature::Ed25519KeyPair;
use std::io::Result;

/// Construct ServerHello message
///
/// # Arguments
/// * `server_random` - 32 bytes of server random
/// * `session_id` - Session ID from ClientHello (for compatibility)
/// * `cipher_suite` - Selected cipher suite (e.g., 0x1301)
/// * `key_share_data` - Server's X25519 public key (32 bytes)
pub fn construct_server_hello(
    server_random: &[u8; 32],
    session_id: &[u8],
    cipher_suite: u16,
    key_share_data: &[u8],
) -> Result<Vec<u8>> {
    let mut server_hello = Vec::new();

    // ServerHello structure:
    // - handshake_type (1 byte) = 2
    // - length (3 bytes)
    // - version (2 bytes) = 0x0303 (TLS 1.2 for compatibility)
    // - random (32 bytes)
    // - session_id_length (1 byte)
    // - session_id (variable)
    // - cipher_suite (2 bytes)
    // - compression_method (1 byte) = 0
    // - extensions_length (2 bytes)
    // - extensions (variable)

    let mut payload = Vec::new();

    // Version: 0x0303 (TLS 1.2 for compatibility)
    payload.extend_from_slice(&[VERSION_TLS_1_2_MAJOR, VERSION_TLS_1_2_MINOR]);

    // Random (32 bytes)
    payload.extend_from_slice(server_random);

    // Session ID
    payload.push(session_id.len() as u8);
    payload.extend_from_slice(session_id);

    // Cipher suite
    payload.extend_from_slice(&cipher_suite.to_be_bytes());

    // Compression method = 0
    payload.push(0x00);

    // Extensions
    let mut extensions = Vec::new();

    // supported_versions extension (type=43)
    extensions.extend_from_slice(&[0x00, 0x2b]); // type = 43
    extensions.extend_from_slice(&[0x00, 0x02]); // length = 2
    extensions.extend_from_slice(&[0x03, 0x04]); // TLS 1.3

    // key_share extension (type=51)
    let key_share_length = 2 + 2 + key_share_data.len(); // group + length + data
    extensions.extend_from_slice(&[0x00, 0x33]); // type = 51
    extensions.extend_from_slice(&(key_share_length as u16).to_be_bytes());
    extensions.extend_from_slice(&[0x00, 0x1d]); // group = X25519 (0x001d)
    extensions.extend_from_slice(&(key_share_data.len() as u16).to_be_bytes());
    extensions.extend_from_slice(key_share_data);

    // Extensions length
    payload.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    payload.extend_from_slice(&extensions);

    // Handshake header
    server_hello.push(HANDSHAKE_TYPE_SERVER_HELLO);

    // Payload length (3 bytes, big-endian)
    let length_bytes = [
        ((payload.len() >> 16) & 0xff) as u8,
        ((payload.len() >> 8) & 0xff) as u8,
        (payload.len() & 0xff) as u8,
    ];
    server_hello.extend_from_slice(&length_bytes);
    server_hello.extend_from_slice(&payload);

    Ok(server_hello)
}

/// Construct EncryptedExtensions message
pub fn construct_encrypted_extensions() -> Result<Vec<u8>> {
    let mut encrypted_extensions = Vec::new();

    // EncryptedExtensions structure:
    // - handshake_type (1 byte) = 8
    // - length (3 bytes)
    // - extensions_length (2 bytes)
    // - extensions (variable, usually empty for minimal setup)

    encrypted_extensions.push(HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS);

    // Empty extensions for minimal setup
    let extensions_length: u16 = 0;
    let payload_length = 2; // Just the extensions_length field

    // Payload length (3 bytes)
    encrypted_extensions.extend_from_slice(&[0x00, 0x00, payload_length as u8]);

    // Extensions length (2 bytes)
    encrypted_extensions.extend_from_slice(&extensions_length.to_be_bytes());

    Ok(encrypted_extensions)
}

/// Construct Certificate message with HMAC-signed Ed25519 certificate
///
/// # Arguments
/// * `cert_der` - DER-encoded certificate (with HMAC signature)
pub fn construct_certificate(cert_der: &[u8]) -> Result<Vec<u8>> {
    let mut certificate = Vec::new();

    // Certificate structure:
    // - handshake_type (1 byte) = 11
    // - length (3 bytes)
    // - certificate_request_context (1 byte length + data, usually empty)
    // - certificate_list (3 bytes length + entries)
    //   - certificate_entry:
    //     - cert_data (3 bytes length + DER)
    //     - extensions (2 bytes length, usually empty)

    let mut payload = Vec::new();

    // Certificate request context (empty for server certificates)
    payload.push(0x00);

    // Certificate list
    let mut cert_list = Vec::new();

    // Certificate entry
    // Cert data length (3 bytes)
    cert_list.extend_from_slice(&[
        ((cert_der.len() >> 16) & 0xff) as u8,
        ((cert_der.len() >> 8) & 0xff) as u8,
        (cert_der.len() & 0xff) as u8,
    ]);
    cert_list.extend_from_slice(cert_der);

    // Extensions (empty)
    cert_list.extend_from_slice(&[0x00, 0x00]);

    // Certificate list length (3 bytes)
    payload.extend_from_slice(&[
        ((cert_list.len() >> 16) & 0xff) as u8,
        ((cert_list.len() >> 8) & 0xff) as u8,
        (cert_list.len() & 0xff) as u8,
    ]);
    payload.extend_from_slice(&cert_list);

    // Handshake header
    certificate.push(HANDSHAKE_TYPE_CERTIFICATE);

    // Payload length (3 bytes)
    certificate.extend_from_slice(&[
        ((payload.len() >> 16) & 0xff) as u8,
        ((payload.len() >> 8) & 0xff) as u8,
        (payload.len() & 0xff) as u8,
    ]);
    certificate.extend_from_slice(&payload);

    Ok(certificate)
}

/// Construct CertificateVerify message
///
/// # Arguments
/// * `signing_key` - Ed25519 signing key
/// * `handshake_hash` - SHA256 hash of all handshake messages up to this point
pub fn construct_certificate_verify(
    signing_key: &Ed25519KeyPair,
    handshake_hash: &[u8],
) -> Result<Vec<u8>> {
    let mut certificate_verify = Vec::new();

    // CertificateVerify structure:
    // - handshake_type (1 byte) = 15
    // - length (3 bytes)
    // - signature_algorithm (2 bytes) = 0x0807 for Ed25519
    // - signature (2 bytes length + data)

    // Construct the signed content
    // TLS 1.3 uses a specific prefix for CertificateVerify:
    // "  " * 64 + "TLS 1.3, server CertificateVerify" + 0x00 + handshake_hash
    let mut signed_content = Vec::new();
    signed_content.extend_from_slice(&[0x20u8; 64]); // 64 spaces
    signed_content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    signed_content.push(0x00);
    signed_content.extend_from_slice(handshake_hash);

    // Sign the content
    let signature = signing_key.sign(&signed_content);
    let signature_bytes = signature.as_ref();

    let mut payload = Vec::new();

    // Signature algorithm: Ed25519 (0x0807)
    payload.extend_from_slice(&[0x08, 0x07]);

    // Signature length and data
    payload.extend_from_slice(&(signature_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(signature_bytes);

    // Handshake header
    certificate_verify.push(HANDSHAKE_TYPE_CERTIFICATE_VERIFY);

    // Payload length (3 bytes)
    certificate_verify.extend_from_slice(&[
        ((payload.len() >> 16) & 0xff) as u8,
        ((payload.len() >> 8) & 0xff) as u8,
        (payload.len() & 0xff) as u8,
    ]);
    certificate_verify.extend_from_slice(&payload);

    Ok(certificate_verify)
}

/// Construct Finished message
///
/// # Arguments
/// * `verify_data` - HMAC of handshake transcript (32 bytes for SHA256)
pub fn construct_finished(verify_data: &[u8]) -> Result<Vec<u8>> {
    let mut finished = Vec::new();

    // Finished structure:
    // - handshake_type (1 byte) = 20
    // - length (3 bytes)
    // - verify_data (variable, 32 bytes for SHA256)

    finished.push(HANDSHAKE_TYPE_FINISHED);

    // Payload length (3 bytes)
    finished.extend_from_slice(&[
        ((verify_data.len() >> 16) & 0xff) as u8,
        ((verify_data.len() >> 8) & 0xff) as u8,
        (verify_data.len() & 0xff) as u8,
    ]);

    finished.extend_from_slice(verify_data);

    Ok(finished)
}

/// Write TLS record header
///
/// Construct TLS 1.3 ClientHello message
///
/// Returns handshake message bytes (without record header)
pub fn construct_client_hello(
    client_random: &[u8; 32],
    session_id: &[u8; 32],
    client_public_key: &[u8],
    server_name: &str,
) -> Result<Vec<u8>> {
    let mut hello = Vec::with_capacity(512);

    // Handshake message type: ClientHello (0x01)
    hello.push(0x01);

    // Placeholder for handshake message length (3 bytes)
    let length_offset = hello.len();
    hello.extend_from_slice(&[0u8; 3]);

    // TLS version: 3.3 (TLS 1.2 for compatibility)
    hello.extend_from_slice(&[VERSION_TLS_1_2_MAJOR, VERSION_TLS_1_2_MINOR]);

    // Client random (32 bytes)
    hello.extend_from_slice(client_random);

    // Session ID length (1 byte) + Session ID (32 bytes)
    hello.push(32);
    hello.extend_from_slice(session_id);

    // Cipher suites
    // Support only TLS_AES_128_GCM_SHA256 (0x1301)
    hello.extend_from_slice(&[0x00, 0x02]); // Cipher suites length: 2 bytes
    hello.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256

    // Compression methods (1 method: null)
    hello.extend_from_slice(&[0x01, 0x00]);

    // Extensions
    let extensions_offset = hello.len();
    hello.extend_from_slice(&[0u8; 2]); // Placeholder for extensions length

    let mut extensions = Vec::new();

    // 1. server_name extension (type 0)
    {
        let server_name_bytes = server_name.as_bytes();
        let server_name_len = server_name_bytes.len();

        extensions.extend_from_slice(&[0x00, 0x00]); // Extension type: server_name
        let ext_len = 5 + server_name_len;
        extensions.extend_from_slice(&(ext_len as u16).to_be_bytes()); // Extension length
        extensions.extend_from_slice(&((server_name_len + 3) as u16).to_be_bytes()); // Server name list length
        extensions.push(0x00); // Name type: host_name
        extensions.extend_from_slice(&(server_name_len as u16).to_be_bytes()); // Name length
        extensions.extend_from_slice(server_name_bytes); // Server name
    }

    // 2. supported_versions extension (type 43)
    {
        extensions.extend_from_slice(&[0x00, 0x2b]); // Extension type: supported_versions
        extensions.extend_from_slice(&[0x00, 0x03]); // Extension length: 3
        extensions.push(0x02); // Supported versions length: 2
        extensions.extend_from_slice(&[0x03, 0x04]); // TLS 1.3
    }

    // 3. supported_groups extension (type 10)
    {
        extensions.extend_from_slice(&[0x00, 0x0a]); // Extension type: supported_groups
        extensions.extend_from_slice(&[0x00, 0x04]); // Extension length: 4
        extensions.extend_from_slice(&[0x00, 0x02]); // Supported groups length: 2
        extensions.extend_from_slice(&[0x00, 0x1d]); // x25519
    }

    // 4. key_share extension (type 51)
    {
        extensions.extend_from_slice(&[0x00, 0x33]); // Extension type: key_share
        let key_share_len = 2 + 4 + client_public_key.len();
        extensions.extend_from_slice(&(key_share_len as u16).to_be_bytes()); // Extension length
        let key_share_list_len = 4 + client_public_key.len();
        extensions.extend_from_slice(&(key_share_list_len as u16).to_be_bytes()); // Key share list length
        extensions.extend_from_slice(&[0x00, 0x1d]); // Group: x25519
        extensions.extend_from_slice(&(client_public_key.len() as u16).to_be_bytes()); // Key length
        extensions.extend_from_slice(client_public_key); // Public key
    }

    // 5. signature_algorithms extension (type 13)
    {
        extensions.extend_from_slice(&[0x00, 0x0d]); // Extension type: signature_algorithms
        extensions.extend_from_slice(&[0x00, 0x04]); // Extension length: 4
        extensions.extend_from_slice(&[0x00, 0x02]); // Signature algorithms length: 2
        extensions.extend_from_slice(&[0x08, 0x07]); // ed25519
    }

    // Write extensions length
    let extensions_length = extensions.len();
    hello[extensions_offset..extensions_offset + 2]
        .copy_from_slice(&(extensions_length as u16).to_be_bytes());

    // Append extensions
    hello.extend_from_slice(&extensions);

    // Write handshake message length
    let message_length = hello.len() - 4; // Exclude type (1) and length (3)
    hello[length_offset..length_offset + 3]
        .copy_from_slice(&(message_length as u32).to_be_bytes()[1..]);

    Ok(hello)
}

/// # Arguments
/// * `record_type` - TLS record type (0x16 for Handshake, 0x17 for ApplicationData)
/// * `length` - Length of record payload
pub fn write_record_header(record_type: u8, length: u16) -> Vec<u8> {
    let mut header = Vec::new();
    header.push(record_type);
    header.extend_from_slice(&[VERSION_TLS_1_2_MAJOR, VERSION_TLS_1_2_MINOR]); // Version: TLS 1.2
    header.extend_from_slice(&length.to_be_bytes());
    header
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::common::CONTENT_TYPE_HANDSHAKE;

    #[test]
    fn test_construct_server_hello() {
        let server_random = [0x42u8; 32];
        let session_id = vec![0x99u8; 32];
        let cipher_suite = 0x1301; // TLS_AES_128_GCM_SHA256
        let key_share = vec![0xAAu8; 32];

        let result = construct_server_hello(&server_random, &session_id, cipher_suite, &key_share);

        assert!(result.is_ok());
        let msg = result.unwrap();
        assert_eq!(msg[0], HANDSHAKE_TYPE_SERVER_HELLO);
    }

    #[test]
    fn test_construct_encrypted_extensions() {
        let result = construct_encrypted_extensions();
        assert!(result.is_ok());
        let msg = result.unwrap();
        assert_eq!(msg[0], HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS);
    }

    #[test]
    fn test_construct_certificate() {
        let cert_der = vec![0xBBu8; 100];
        let result = construct_certificate(&cert_der);
        assert!(result.is_ok());
        let msg = result.unwrap();
        assert_eq!(msg[0], HANDSHAKE_TYPE_CERTIFICATE);
    }

    #[test]
    fn test_construct_finished() {
        let verify_data = vec![0xCCu8; 32];
        let result = construct_finished(&verify_data);
        assert!(result.is_ok());
        let msg = result.unwrap();
        assert_eq!(msg[0], HANDSHAKE_TYPE_FINISHED);
        assert_eq!(msg.len(), 1 + 3 + 32); // type + length + verify_data
    }

    #[test]
    fn test_write_record_header() {
        let header = write_record_header(CONTENT_TYPE_HANDSHAKE, 100);
        assert_eq!(header.len(), 5);
        assert_eq!(header[0], 0x16); // Handshake
        assert_eq!(header[1], 0x03); // TLS 1.2
        assert_eq!(header[2], 0x03);
        assert_eq!(u16::from_be_bytes([header[3], header[4]]), 100);
    }
}
