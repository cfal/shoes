use aws_lc_rs::{
    agreement,
    rand::{SecureRandom, SystemRandom},
};
use base64::engine::{Engine as _, general_purpose::URL_SAFE_NO_PAD};

use super::reality_cipher_suite::CipherSuite;
use crate::buf_reader::BufReader;

/// Decodes a base64url-encoded public key
pub fn decode_public_key(encoded: &str) -> Result<[u8; 32], std::io::Error> {
    let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid base64: {}", e),
        )
    })?;

    if decoded.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid public key length: {} (expected 32)", decoded.len()),
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

/// Decodes a base64url-encoded private key
pub fn decode_private_key(encoded: &str) -> Result<[u8; 32], std::io::Error> {
    let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid base64: {}", e),
        )
    })?;

    if decoded.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Invalid private key length: {} (expected 32)",
                decoded.len()
            ),
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

/// Decodes a hex-encoded short ID with zero-padding
///
/// Short IDs can be 0-16 hex characters (0-8 bytes).
/// If shorter than 16 characters, they are left-padded with zeros.
pub fn decode_short_id(hex: &str) -> Result<[u8; 8], std::io::Error> {
    if hex.len() > 16 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Short ID too long: {} (max 16 hex chars)", hex.len()),
        ));
    }

    // Left-pad with zeros to make 16 chars
    let padded = format!("{:0>16}", hex);

    let mut short_id = [0u8; 8];
    decode_hex_to_slice(&padded, &mut short_id).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid hex: {}", e),
        )
    })?;

    Ok(short_id)
}

/// Decode hex string to byte slice
fn decode_hex_to_slice(hex: &str, output: &mut [u8]) -> Result<(), &'static str> {
    if hex.len() != output.len() * 2 {
        return Err("Invalid hex length");
    }

    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let high = hex_char_to_value(chunk[0])?;
        let low = hex_char_to_value(chunk[1])?;
        output[i] = (high << 4) | low;
    }

    Ok(())
}

/// Convert hex character to its numeric value
fn hex_char_to_value(c: u8) -> Result<u8, &'static str> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err("Invalid hex character"),
    }
}

/// Extracts ClientRandom from ClientHello
///
/// ClientHello structure (simplified):
/// - TLS Header: 5 bytes
/// - Handshake Type: 1 byte
/// - Length: 3 bytes
/// - Protocol Version: 2 bytes
/// - ClientRandom: 32 bytes (starts at offset 11)
pub fn extract_client_random(client_hello: &[u8]) -> Result<[u8; 32], std::io::Error> {
    const TLS_HEADER_LEN: usize = 5;
    const HANDSHAKE_HEADER_LEN: usize = 4; // type(1) + length(3)
    const PROTOCOL_VERSION_LEN: usize = 2;
    const RANDOM_OFFSET: usize = TLS_HEADER_LEN + HANDSHAKE_HEADER_LEN + PROTOCOL_VERSION_LEN;

    if client_hello.len() < RANDOM_OFFSET + 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ClientHello too short to extract random",
        ));
    }

    let mut random = [0u8; 32];
    random.copy_from_slice(&client_hello[RANDOM_OFFSET..RANDOM_OFFSET + 32]);
    Ok(random)
}

/// Extracts SessionId slice from ClientHello without allocation
///
/// SessionId comes after ClientRandom and has a 1-byte length prefix.
/// Returns a slice pointing into the original buffer.
pub fn extract_session_id_slice(client_hello: &[u8]) -> Result<&[u8], std::io::Error> {
    const TLS_HEADER_LEN: usize = 5;
    const HANDSHAKE_HEADER_LEN: usize = 4;
    const PROTOCOL_VERSION_LEN: usize = 2;
    const RANDOM_LEN: usize = 32;
    const SESSION_ID_LEN_OFFSET: usize =
        TLS_HEADER_LEN + HANDSHAKE_HEADER_LEN + PROTOCOL_VERSION_LEN + RANDOM_LEN;

    if client_hello.len() < SESSION_ID_LEN_OFFSET + 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ClientHello too short to extract session ID",
        ));
    }

    let session_id_len = client_hello[SESSION_ID_LEN_OFFSET] as usize;

    if client_hello.len() < SESSION_ID_LEN_OFFSET + 1 + session_id_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ClientHello session ID extends past end",
        ));
    }

    Ok(&client_hello[SESSION_ID_LEN_OFFSET + 1..SESSION_ID_LEN_OFFSET + 1 + session_id_len])
}

/// Extracts X25519 public key from ClientHello KeyShare extension
///
/// This parses the TLS 1.3 extensions to find the KeyShare extension
/// and extracts the X25519 public key (group 0x001d).
pub fn extract_client_public_key(client_hello: &[u8]) -> Result<[u8; 32], std::io::Error> {
    const TLS_HEADER_LEN: usize = 5;

    if client_hello.len() < TLS_HEADER_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ClientHello too short",
        ));
    }

    let mut reader = BufReader::new(&client_hello[TLS_HEADER_LEN..]);

    // Parse handshake header
    let _handshake_type = reader.read_u8()?;
    let _handshake_len = reader.read_u24_be()?;
    let _protocol_version = reader.read_u16_be()?;

    // Skip random
    reader.skip(32)?;

    // Read session ID
    let session_id_len = reader.read_u8()? as usize;
    reader.skip(session_id_len)?;

    // Read cipher suites
    let cipher_suites_len = reader.read_u16_be()? as usize;
    reader.skip(cipher_suites_len)?;

    // Read compression methods
    let compression_len = reader.read_u8()? as usize;
    reader.skip(compression_len)?;

    // Parse extensions
    let extensions_len = reader.read_u16_be()? as usize;
    let extensions_start = reader.position();
    let extensions_end = extensions_start + extensions_len;

    while reader.position() < extensions_end {
        let ext_type = reader.read_u16_be()?;
        let ext_len = reader.read_u16_be()? as usize;

        if ext_type == 51 {
            // KeyShare extension (0x0033)
            return parse_keyshare_extension(reader.read_slice(ext_len)?);
        } else {
            reader.skip(ext_len)?;
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "KeyShare extension not found in ClientHello",
    ))
}

/// Parses the KeyShare extension to extract X25519 public key
fn parse_keyshare_extension(data: &[u8]) -> Result<[u8; 32], std::io::Error> {
    let mut reader = BufReader::new(data);

    // KeyShare extension format (client):
    // - Client Key Share Length: 2 bytes
    // - Key Share Entries (repeated):
    //   - Group: 2 bytes
    //   - Key Exchange Length: 2 bytes
    //   - Key Exchange Data: variable

    let _client_shares_len = reader.read_u16_be()?;

    // Find X25519 key share (group 0x001d = 29)
    loop {
        // Check if we have at least 4 bytes for group and length
        if reader.position() + 4 > data.len() {
            break;
        }

        let group = reader.read_u16_be()?;
        let key_len = reader.read_u16_be()? as usize;

        if reader.position() + key_len > data.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "KeyShare entry extends past end",
            ));
        }

        if group == 0x001d {
            // X25519
            if key_len != 32 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid X25519 key length: {}", key_len),
                ));
            }

            let key_bytes = reader.read_slice(32)?;
            let mut key = [0u8; 32];
            key.copy_from_slice(key_bytes);
            return Ok(key);
        } else {
            reader.skip(key_len)?;
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "X25519 key share not found in KeyShare extension",
    ))
}

/// Extract server's X25519 public key from ServerHello message
///
/// This parses the TLS 1.3 ServerHello to find the KeyShare extension
/// and extracts the X25519 public key (group 0x001d).
pub fn extract_server_public_key(server_hello: &[u8]) -> Result<[u8; 32], std::io::Error> {
    const TLS_HEADER_LEN: usize = 5;

    if server_hello.len() < TLS_HEADER_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ServerHello too short",
        ));
    }

    let mut reader = BufReader::new(&server_hello[TLS_HEADER_LEN..]);

    // Parse handshake header
    let _handshake_type = reader.read_u8()?;
    let _handshake_len = reader.read_u24_be()?;
    let _protocol_version = reader.read_u16_be()?;

    // Skip random
    reader.skip(32)?;

    // Read session ID (ServerHello can echo it back)
    let session_id_len = reader.read_u8()? as usize;
    reader.skip(session_id_len)?;

    // Read cipher suite (single 2-byte value in ServerHello)
    reader.skip(2)?;

    // Read compression method (single byte in ServerHello)
    reader.skip(1)?;

    // Parse extensions
    let extensions_len = reader.read_u16_be()? as usize;
    let extensions_start = reader.position();
    let extensions_end = extensions_start + extensions_len;

    while reader.position() < extensions_end {
        let ext_type = reader.read_u16_be()?;
        let ext_len = reader.read_u16_be()? as usize;

        if ext_type == 51 {
            // KeyShare extension (0x0033)
            return parse_server_keyshare_extension(reader.read_slice(ext_len)?);
        } else {
            reader.skip(ext_len)?;
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "KeyShare extension not found in ServerHello",
    ))
}

/// Parses the ServerHello KeyShare extension to extract X25519 public key
fn parse_server_keyshare_extension(data: &[u8]) -> Result<[u8; 32], std::io::Error> {
    let mut reader = BufReader::new(data);

    // ServerHello KeyShare extension format:
    // - Group: 2 bytes
    // - Key Exchange Length: 2 bytes
    // - Key Exchange Data: variable

    let group = reader.read_u16_be()?;
    let key_len = reader.read_u16_be()? as usize;

    if group == 29 {
        // X25519
        if key_len != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid X25519 key length: {}", key_len),
            ));
        }

        let key_bytes = reader.read_slice(32)?;
        let mut key = [0u8; 32];
        key.copy_from_slice(key_bytes);
        return Ok(key);
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "X25519 key share not found in ServerHello KeyShare extension",
    ))
}

/// Extract the cipher suite selected by the server from ServerHello message
///
/// This parses the TLS 1.3 ServerHello to find the cipher suite.
/// ServerHello contains a single cipher suite (the server's choice).
pub fn extract_server_cipher_suite(server_hello: &[u8]) -> Result<u16, std::io::Error> {
    const TLS_HEADER_LEN: usize = 5;

    if server_hello.len() < TLS_HEADER_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ServerHello too short",
        ));
    }

    let mut reader = BufReader::new(&server_hello[TLS_HEADER_LEN..]);

    // Parse handshake header
    let _handshake_type = reader.read_u8()?;
    let _handshake_len = reader.read_u24_be()?;
    let _protocol_version = reader.read_u16_be()?;

    // Skip random (32 bytes)
    reader.skip(32)?;

    // Read session ID (ServerHello can echo it back)
    let session_id_len = reader.read_u8()? as usize;
    reader.skip(session_id_len)?;

    // Read cipher suite (single 2-byte value in ServerHello)
    let cipher_suite = reader.read_u16_be()?;

    Ok(cipher_suite)
}

/// Extracts cipher suites offered by client from ClientHello
///
/// Returns a Vec of cipher suite IDs in the order they appear in the ClientHello.
pub fn extract_client_cipher_suites(client_hello: &[u8]) -> Result<Vec<u16>, std::io::Error> {
    const TLS_HEADER_LEN: usize = 5;

    if client_hello.len() < TLS_HEADER_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ClientHello too short",
        ));
    }

    let mut reader = BufReader::new(&client_hello[TLS_HEADER_LEN..]);

    // Parse handshake header
    let _handshake_type = reader.read_u8()?;
    let _handshake_len = reader.read_u24_be()?;
    let _protocol_version = reader.read_u16_be()?;

    // Skip random (32 bytes)
    reader.skip(32)?;

    // Skip session ID
    let session_id_len = reader.read_u8()? as usize;
    reader.skip(session_id_len)?;

    // Read cipher suites
    let cipher_suites_len = reader.read_u16_be()? as usize;
    if !cipher_suites_len.is_multiple_of(2) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid cipher suites length (not even)",
        ));
    }

    let cipher_suites_data = reader.read_slice(cipher_suites_len)?;
    let mut cipher_suites = Vec::with_capacity(cipher_suites_len / 2);

    for chunk in cipher_suites_data.chunks(2) {
        let suite = u16::from_be_bytes([chunk[0], chunk[1]]);
        cipher_suites.push(suite);
    }

    Ok(cipher_suites)
}

/// Negotiate cipher suite between server preferences and client offers (CipherSuite version)
///
/// Returns the first CipherSuite from server_preferences that the client supports,
/// or None if no common cipher suite is found.
pub fn negotiate_cipher_suite(
    server_preferences: &[CipherSuite],
    client_cipher_suite_ids: &[u16],
) -> Option<CipherSuite> {
    for server_suite in server_preferences {
        if client_cipher_suite_ids.contains(&server_suite.id()) {
            return Some(*server_suite);
        }
    }
    None
}

pub fn generate_keypair() -> std::io::Result<(String, String)> {
    // Step 1: Generate 32 random bytes for private key
    let rng = SystemRandom::new();
    let mut private_key_bytes = [0u8; 32];
    rng.fill(&mut private_key_bytes)
        .map_err(|_| std::io::Error::other("RNG failed"))?;

    // Step 2: Create X25519 private key from the random bytes
    let private_key =
        agreement::PrivateKey::from_private_key(&agreement::X25519, &private_key_bytes)
            .map_err(|_| std::io::Error::other("Failed to create X25519 key"))?;

    // Step 3: Derive public key from private key
    let public_key_bytes = private_key
        .compute_public_key()
        .map_err(|_| std::io::Error::other("Failed to compute public key"))?;

    // Step 4: Encode both keys as base64url (no padding)
    let private_key_b64 = URL_SAFE_NO_PAD.encode(private_key_bytes);
    let public_key_b64 = URL_SAFE_NO_PAD.encode(public_key_bytes.as_ref());

    Ok((private_key_b64, public_key_b64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_short_id() {
        // Full 16-char hex
        let short_id = decode_short_id("0123456789abcdef").unwrap();
        assert_eq!(short_id, [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);

        // Partial hex (should be zero-padded on left)
        let short_id2 = decode_short_id("abcdef").unwrap();
        assert_eq!(short_id2, [0x00, 0x00, 0x00, 0x00, 0x00, 0xab, 0xcd, 0xef]);

        // Empty (all zeros)
        let short_id3 = decode_short_id("").unwrap();
        assert_eq!(short_id3, [0; 8]);

        // Too long should error
        let result = decode_short_id("0123456789abcdef0");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_client_random() {
        // Create a minimal ClientHello with random
        let mut client_hello = vec![0u8; 100];

        // TLS Header
        client_hello[0] = 0x16; // Handshake
        client_hello[1] = 0x03; // Version major
        client_hello[2] = 0x03; // Version minor (TLS 1.2)

        // Handshake header
        client_hello[5] = 0x01; // ClientHello type

        // Protocol version in handshake
        client_hello[9] = 0x03; // Major
        client_hello[10] = 0x03; // Minor

        // ClientRandom starts at offset 11
        for i in 0..32 {
            client_hello[11 + i] = (i + 1) as u8;
        }

        let random = extract_client_random(&client_hello).unwrap();
        for i in 0..32 {
            assert_eq!(random[i], (i + 1) as u8);
        }
    }

    #[test]
    fn test_decode_public_key() {
        use base64::engine::{Engine as _, general_purpose::URL_SAFE_NO_PAD};

        // Valid 32-byte key
        let key_bytes = [0x42u8; 32];
        let encoded = URL_SAFE_NO_PAD.encode(&key_bytes);
        let decoded = decode_public_key(&encoded).unwrap();
        assert_eq!(decoded, key_bytes);

        // Invalid length
        let short_key = [0x42u8; 16];
        let encoded_short = URL_SAFE_NO_PAD.encode(&short_key);
        assert!(decode_public_key(&encoded_short).is_err());

        // Invalid base64
        assert!(decode_public_key("not-valid-base64!!!").is_err());
    }
}
