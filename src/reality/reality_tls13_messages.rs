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
/// * `cert` - Certificate from rcgen (takes ownership to avoid allocation)
pub fn construct_certificate(cert: rcgen::Certificate) -> Result<Vec<u8>> {
    let cert_der = cert.der();

    // Certificate structure:
    // - handshake_type (1 byte) = 11
    // - length (3 bytes)
    // - certificate_request_context (1 byte length + data, usually empty)
    // - certificate_list (3 bytes length + entries)
    //   - certificate_entry:
    //     - cert_data (3 bytes length + DER)
    //     - extensions (2 bytes length, usually empty)

    // Pre-calculate sizes to allocate exact capacity
    // cert_list = 3 (len) + cert_der.len() + 2 (extensions)
    let cert_list_len = 3 + cert_der.len() + 2;
    // payload = 1 (context) + 3 (list len) + cert_list_len
    let payload_len = 1 + 3 + cert_list_len;
    // total = 1 (type) + 3 (payload len) + payload_len
    let total_len = 1 + 3 + payload_len;

    let mut certificate = Vec::with_capacity(total_len);

    // Handshake header
    certificate.push(HANDSHAKE_TYPE_CERTIFICATE);

    // Payload length (3 bytes)
    certificate.extend_from_slice(&[
        ((payload_len >> 16) & 0xff) as u8,
        ((payload_len >> 8) & 0xff) as u8,
        (payload_len & 0xff) as u8,
    ]);

    // Certificate request context (empty for server certificates)
    certificate.push(0x00);

    // Certificate list length (3 bytes)
    certificate.extend_from_slice(&[
        ((cert_list_len >> 16) & 0xff) as u8,
        ((cert_list_len >> 8) & 0xff) as u8,
        (cert_list_len & 0xff) as u8,
    ]);

    // Certificate entry - cert data length (3 bytes)
    certificate.extend_from_slice(&[
        ((cert_der.len() >> 16) & 0xff) as u8,
        ((cert_der.len() >> 8) & 0xff) as u8,
        (cert_der.len() & 0xff) as u8,
    ]);

    // Certificate DER data
    certificate.extend_from_slice(cert_der);

    // Extensions (empty)
    certificate.extend_from_slice(&[0x00, 0x00]);

    Ok(certificate)
}

/// Construct CertificateVerify message
///
/// # Arguments
/// * `signing_key` - Ed25519 signing key
/// * `handshake_hash` - Hash of all handshake messages up to this point (32 or 48 bytes depending on cipher suite)
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

/// Default ALPN protocols for REALITY client (matches browser fingerprints)
pub const DEFAULT_ALPN_PROTOCOLS: &[&str] = &["h2", "http/1.1"];

const CHROME_TLS12_COMPAT_CIPHER_SUITES: &[u16] = &[
    0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
    0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
    0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
    0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
];

const GREASE_VALUES: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

fn grease_value(client_random: &[u8; 32], domain_separator: usize) -> u16 {
    GREASE_VALUES[(client_random[0] as usize + domain_separator) % GREASE_VALUES.len()]
}

#[cfg(test)]
fn is_grease_value(value: u16) -> bool {
    GREASE_VALUES.contains(&value)
}

fn chrome_like_cipher_suites(client_random: &[u8; 32], configured_suites: &[u16]) -> Vec<u16> {
    let mut suites =
        Vec::with_capacity(1 + configured_suites.len() + CHROME_TLS12_COMPAT_CIPHER_SUITES.len());
    suites.push(grease_value(client_random, 0));

    for &suite in configured_suites
        .iter()
        .chain(CHROME_TLS12_COMPAT_CIPHER_SUITES.iter())
    {
        if !suites.contains(&suite) {
            suites.push(suite);
        }
    }

    suites
}

/// Construct TLS 1.3 ClientHello message
///
/// Returns handshake message bytes (without record header)
///
/// # Arguments
/// * `client_random` - 32 bytes client random
/// * `session_id` - 32 bytes session ID
/// * `client_public_key` - X25519 public key bytes
/// * `server_name` - SNI hostname
/// * `cipher_suites` - TLS 1.3 cipher suite IDs to include before browser-style fallback suites
/// * `alpn_protocols` - ALPN protocols to offer (e.g., &["h2", "http/1.1"])
pub fn construct_client_hello(
    client_random: &[u8; 32],
    session_id: &[u8; 32],
    client_public_key: &[u8],
    server_name: &str,
    cipher_suites: &[u16],
    alpn_protocols: &[&str],
) -> Result<Vec<u8>> {
    let mut hello = Vec::with_capacity(512);
    let offered_cipher_suites = chrome_like_cipher_suites(client_random, cipher_suites);
    let cipher_suite_grease = offered_cipher_suites[0];
    let supported_group_grease = grease_value(client_random, 1);
    let extension_grease = grease_value(client_random, 2);

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
    let cipher_suites_len = (offered_cipher_suites.len() * 2) as u16;
    hello.extend_from_slice(&cipher_suites_len.to_be_bytes());
    for &suite in &offered_cipher_suites {
        hello.extend_from_slice(&suite.to_be_bytes());
    }

    // Compression methods (1 method: null)
    hello.extend_from_slice(&[0x01, 0x00]);

    // Extensions
    let extensions_offset = hello.len();
    hello.extend_from_slice(&[0u8; 2]); // Placeholder for extensions length

    let mut extensions = Vec::new();

    // GREASE extension. The empty body is ignored by compliant peers and makes the
    // default ClientHello less trivially distinguishable from modern browsers.
    {
        extensions.extend_from_slice(&extension_grease.to_be_bytes());
        extensions.extend_from_slice(&[0x00, 0x00]);
    }

    // server_name extension (type 0)
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

    // supported_versions extension (type 43)
    {
        extensions.extend_from_slice(&[0x00, 0x2b]); // Extension type: supported_versions
        extensions.extend_from_slice(&[0x00, 0x07]); // Extension length: 7
        extensions.push(0x06); // Supported versions length: 6
        extensions.extend_from_slice(&cipher_suite_grease.to_be_bytes());
        extensions.extend_from_slice(&[0x03, 0x04]); // TLS 1.3
        extensions.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    }

    // supported_groups extension (type 10)
    {
        extensions.extend_from_slice(&[0x00, 0x0a]); // Extension type: supported_groups
        extensions.extend_from_slice(&[0x00, 0x0a]); // Extension length: 10
        extensions.extend_from_slice(&[0x00, 0x08]); // Supported groups length: 8
        extensions.extend_from_slice(&supported_group_grease.to_be_bytes());
        extensions.extend_from_slice(&[0x00, 0x1d]); // x25519
        extensions.extend_from_slice(&[0x00, 0x17]); // secp256r1
        extensions.extend_from_slice(&[0x00, 0x18]); // secp384r1
    }

    // key_share extension (type 51)
    {
        extensions.extend_from_slice(&[0x00, 0x33]); // Extension type: key_share
        let grease_key_share_len = 1usize;
        let key_share_len = 2 + 4 + grease_key_share_len + 4 + client_public_key.len();
        extensions.extend_from_slice(&(key_share_len as u16).to_be_bytes()); // Extension length
        let key_share_list_len = 4 + grease_key_share_len + 4 + client_public_key.len();
        extensions.extend_from_slice(&(key_share_list_len as u16).to_be_bytes()); // Key share list length
        extensions.extend_from_slice(&supported_group_grease.to_be_bytes()); // GREASE group
        extensions.extend_from_slice(&(grease_key_share_len as u16).to_be_bytes());
        extensions.push(0x00);
        extensions.extend_from_slice(&[0x00, 0x1d]); // Group: x25519
        extensions.extend_from_slice(&(client_public_key.len() as u16).to_be_bytes()); // Key length
        extensions.extend_from_slice(client_public_key); // Public key
    }

    // signature_algorithms extension (type 13)
    // Matches the Chrome 133 uTLS fingerprints used by Xray-core and sing-box.
    // https://github.com/refraction-networking/utls/blob/aa6edf4b11af82e110eea845bb2983d30138d651/u_parrots.go#L935-L944
    // https://github.com/metacubex/utls/blob/cf49b0864331e156689feec6363ef9bf518a5ac7/u_parrots.go#L925-L934
    {
        extensions.extend_from_slice(&[0x00, 0x0d]); // Extension type: signature_algorithms
        extensions.extend_from_slice(&[0x00, 0x12]); // Extension length: 18
        extensions.extend_from_slice(&[0x00, 0x10]); // Signature algorithms length: 16
        extensions.extend_from_slice(&[0x04, 0x03]); // ecdsa_secp256r1_sha256
        extensions.extend_from_slice(&[0x08, 0x04]); // rsa_pss_rsae_sha256
        extensions.extend_from_slice(&[0x04, 0x01]); // rsa_pkcs1_sha256
        extensions.extend_from_slice(&[0x05, 0x03]); // ecdsa_secp384r1_sha384
        extensions.extend_from_slice(&[0x08, 0x05]); // rsa_pss_rsae_sha384
        extensions.extend_from_slice(&[0x05, 0x01]); // rsa_pkcs1_sha384
        extensions.extend_from_slice(&[0x08, 0x06]); // rsa_pss_rsae_sha512
        extensions.extend_from_slice(&[0x06, 0x01]); // rsa_pkcs1_sha512
    }

    // ALPN extension (type 16)
    if !alpn_protocols.is_empty() {
        extensions.extend_from_slice(&[0x00, 0x10]); // Extension type: ALPN (16)

        // Calculate total length of protocol list
        let protocols_list_len: usize = alpn_protocols
            .iter()
            .map(|p| 1 + p.len()) // 1 byte length prefix + protocol bytes
            .sum();

        // Extension length = 2 (list length field) + protocols_list_len
        let ext_len = 2 + protocols_list_len;
        extensions.extend_from_slice(&(ext_len as u16).to_be_bytes());

        // Protocol list length
        extensions.extend_from_slice(&(protocols_list_len as u16).to_be_bytes());

        // Each protocol: 1 byte length + protocol string
        for protocol in alpn_protocols {
            extensions.push(protocol.len() as u8);
            extensions.extend_from_slice(protocol.as_bytes());
        }
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

/// Write TLS record header
///
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
    use std::collections::HashMap;

    fn parse_client_hello(hello: &[u8]) -> (Vec<u16>, HashMap<u16, Vec<u8>>) {
        let mut offset = 1 + 3 + 2 + 32;
        let session_id_len = hello[offset] as usize;
        offset += 1 + session_id_len;

        let cipher_suites_len = u16::from_be_bytes([hello[offset], hello[offset + 1]]) as usize;
        offset += 2;
        let cipher_suites = hello[offset..offset + cipher_suites_len]
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect();
        offset += cipher_suites_len;

        let compression_methods_len = hello[offset] as usize;
        offset += 1 + compression_methods_len;

        let extensions_len = u16::from_be_bytes([hello[offset], hello[offset + 1]]) as usize;
        offset += 2;
        let extensions_end = offset + extensions_len;

        let mut extensions = HashMap::new();
        while offset < extensions_end {
            let extension_type = u16::from_be_bytes([hello[offset], hello[offset + 1]]);
            let extension_len = u16::from_be_bytes([hello[offset + 2], hello[offset + 3]]) as usize;
            offset += 4;
            extensions.insert(
                extension_type,
                hello[offset..offset + extension_len].to_vec(),
            );
            offset += extension_len;
        }

        (cipher_suites, extensions)
    }

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
        use crate::reality::reality_certificate::generate_hmac_certificate;
        let auth_key = [0x42u8; 32];
        let (cert, _) = generate_hmac_certificate(&auth_key, "test.example.com").unwrap();
        let result = construct_certificate(cert);
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

    #[test]
    fn test_client_hello_signature_algorithms_match_chrome_utls() {
        let client_random = [0u8; 32];
        let session_id = [0u8; 32];
        let client_public_key = [0u8; 32];

        let hello = construct_client_hello(
            &client_random,
            &session_id,
            &client_public_key,
            "example.com",
            &[0x1301],
            &["h2"],
        )
        .unwrap();

        let (_cipher_suites, extensions) = parse_client_hello(&hello);
        let signature_algorithms = extensions.get(&0x000d).map(Vec::as_slice);

        let extension = signature_algorithms.expect("missing signature_algorithms extension");
        assert_eq!(u16::from_be_bytes([extension[0], extension[1]]), 16);
        assert_eq!(
            &extension[2..],
            &[
                0x04, 0x03, // ecdsa_secp256r1_sha256
                0x08, 0x04, // rsa_pss_rsae_sha256
                0x04, 0x01, // rsa_pkcs1_sha256
                0x05, 0x03, // ecdsa_secp384r1_sha384
                0x08, 0x05, // rsa_pss_rsae_sha384
                0x05, 0x01, // rsa_pkcs1_sha384
                0x08, 0x06, // rsa_pss_rsae_sha512
                0x06, 0x01, // rsa_pkcs1_sha512
            ]
        );
    }

    #[test]
    fn test_client_hello_default_cipher_suites_are_chrome_like() {
        let client_random = [0u8; 32];
        let session_id = [0u8; 32];
        let client_public_key = [0u8; 32];

        let hello = construct_client_hello(
            &client_random,
            &session_id,
            &client_public_key,
            "example.com",
            &[0x1301, 0x1302, 0x1303],
            DEFAULT_ALPN_PROTOCOLS,
        )
        .unwrap();

        let (cipher_suites, _extensions) = parse_client_hello(&hello);
        assert!(is_grease_value(cipher_suites[0]));
        assert!(cipher_suites.contains(&0x1301));
        assert!(cipher_suites.contains(&0x1302));
        assert!(cipher_suites.contains(&0x1303));
        assert!(cipher_suites.contains(&0xc02b));
        assert!(cipher_suites.contains(&0xc02f));
        assert!(cipher_suites.contains(&0xcca9));
        assert!(cipher_suites.contains(&0x002f));
    }

    #[test]
    fn test_client_hello_default_extensions_cover_browser_groups_and_grease() {
        let client_random = [0u8; 32];
        let session_id = [0u8; 32];
        let client_public_key = [0x42u8; 32];

        let hello = construct_client_hello(
            &client_random,
            &session_id,
            &client_public_key,
            "example.com",
            &[0x1301, 0x1302, 0x1303],
            DEFAULT_ALPN_PROTOCOLS,
        )
        .unwrap();

        let (_cipher_suites, extensions) = parse_client_hello(&hello);
        assert!(
            extensions
                .keys()
                .any(|extension| is_grease_value(*extension))
        );
        assert!(extensions.contains_key(&0x0000)); // server_name
        assert!(extensions.contains_key(&0x000a)); // supported_groups
        assert!(extensions.contains_key(&0x000d)); // signature_algorithms
        assert!(extensions.contains_key(&0x0010)); // alpn
        assert!(extensions.contains_key(&0x002b)); // supported_versions
        assert!(extensions.contains_key(&0x0033)); // key_share

        let supported_groups = extensions.get(&0x000a).expect("missing supported_groups");
        assert_eq!(
            u16::from_be_bytes([supported_groups[0], supported_groups[1]]),
            8
        );
        let groups: Vec<u16> = supported_groups[2..]
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect();
        assert!(is_grease_value(groups[0]));
        assert!(groups.contains(&0x001d)); // x25519
        assert!(groups.contains(&0x0017)); // secp256r1
        assert!(groups.contains(&0x0018)); // secp384r1

        let supported_versions = extensions.get(&0x002b).expect("missing supported_versions");
        assert_eq!(supported_versions[0], 6);
        let versions: Vec<u16> = supported_versions[1..]
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect();
        assert!(is_grease_value(versions[0]));
        assert!(versions.contains(&0x0304)); // TLS 1.3
        assert!(versions.contains(&0x0303)); // TLS 1.2

        let key_share = extensions.get(&0x0033).expect("missing key_share");
        let list_len = u16::from_be_bytes([key_share[0], key_share[1]]) as usize;
        assert_eq!(list_len, key_share.len() - 2);
        let first_group = u16::from_be_bytes([key_share[2], key_share[3]]);
        let first_key_len = u16::from_be_bytes([key_share[4], key_share[5]]) as usize;
        assert!(is_grease_value(first_group));
        assert_eq!(first_key_len, 1);

        let x25519_offset = 6 + first_key_len;
        assert_eq!(
            u16::from_be_bytes([key_share[x25519_offset], key_share[x25519_offset + 1]]),
            0x001d
        );
        assert_eq!(
            u16::from_be_bytes([key_share[x25519_offset + 2], key_share[x25519_offset + 3]]),
            32
        );
        assert_eq!(
            &key_share[x25519_offset + 4..x25519_offset + 36],
            &client_public_key
        );
    }
}
