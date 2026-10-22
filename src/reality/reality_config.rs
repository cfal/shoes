use aws_lc_rs::agreement;
use base64::engine::{Engine as _, general_purpose::URL_SAFE_NO_PAD};
use rand::Rng;

pub(crate) fn parse_server_name(
    name: &str,
) -> std::io::Result<rustls::pki_types::ServerName<'static>> {
    match rustls::pki_types::ServerName::try_from(name.to_owned()) {
        Ok(name @ rustls::pki_types::ServerName::DnsName(_)) => Ok(name),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "REALITY requires a valid DNS server name",
        )),
    }
}

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
/// If shorter than 16 characters, they are right-padded with zeros.
pub fn decode_short_id(hex: &str) -> Result<[u8; 8], std::io::Error> {
    if hex.len() > 16 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Short ID too long: {} (max 16 hex chars)", hex.len()),
        ));
    }

    // Right-pad with zeros to make 16 chars (compatible with other REALITY clients)
    let padded = format!("{:0<16}", hex);

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

pub fn generate_keypair() -> std::io::Result<(String, String)> {
    // Generate 32 random bytes for private key
    let mut private_key_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut private_key_bytes);

    // Create X25519 private key from the random bytes
    let private_key =
        agreement::PrivateKey::from_private_key(&agreement::X25519, &private_key_bytes)
            .map_err(|_| std::io::Error::other("Failed to create X25519 key"))?;

    // Derive public key from private key
    let public_key_bytes = private_key
        .compute_public_key()
        .map_err(|_| std::io::Error::other("Failed to compute public key"))?;

    // Encode both keys as base64url (no padding)
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

        // Partial hex (should be zero-padded on right)
        let short_id2 = decode_short_id("abcdef").unwrap();
        assert_eq!(short_id2, [0xab, 0xcd, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // Empty (all zeros)
        let short_id3 = decode_short_id("").unwrap();
        assert_eq!(short_id3, [0; 8]);

        // Too long should error
        let result = decode_short_id("0123456789abcdef0");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_public_key() {
        use base64::engine::{Engine as _, general_purpose::URL_SAFE_NO_PAD};

        // Valid 32-byte key
        let key_bytes = [0x42u8; 32];
        let encoded = URL_SAFE_NO_PAD.encode(key_bytes);
        let decoded = decode_public_key(&encoded).unwrap();
        assert_eq!(decoded, key_bytes);

        // Invalid length
        let short_key = [0x42u8; 16];
        let encoded_short = URL_SAFE_NO_PAD.encode(short_key);
        assert!(decode_public_key(&encoded_short).is_err());

        // Invalid base64
        assert!(decode_public_key("not-valid-base64!!!").is_err());
    }
}
