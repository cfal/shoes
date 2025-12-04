use std::fmt::Write;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};

/// Parse a UUID v4 string (with or without dashes) into 16 bytes.
/// Validates that the UUID has version 4 and RFC 4122 variant.
#[inline]
pub fn parse_uuid(uuid_str: &str) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(16);
    let mut first_nibble: Option<u8> = None;
    for &c in uuid_str.as_bytes() {
        let hex = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            b'-' => continue,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid uuid: {uuid_str}"),
                ));
            }
        };
        if let Some(first) = first_nibble.take() {
            bytes.push((first << 4) | hex);
        } else {
            first_nibble = Some(hex);
        }
    }
    if first_nibble.is_some() || bytes.len() != 16 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid uuid: {uuid_str}"),
        ));
    }

    // Validate version 4: upper nibble of byte 6 must be 4
    if (bytes[6] >> 4) != 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("UUID is not version 4: {uuid_str}"),
        ));
    }

    // Validate variant (RFC 4122): upper 2 bits of byte 8 must be 10
    if (bytes[8] >> 6) != 2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("UUID does not have RFC 4122 variant: {uuid_str}"),
        ));
    }

    Ok(bytes)
}

/// Generate a random UUID v4 and return it as a formatted string.
#[inline]
pub fn generate_uuid() -> String {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes).expect("RNG failed");

    // Set version (4) in bits 12-15 of byte 6
    bytes[6] = (bytes[6] & 0x0f) | 0x40;

    // Set variant (RFC 4122) in bits 6-7 of byte 8
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    let mut s = String::with_capacity(36);
    for (i, &b) in bytes.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            s.push('-');
        }
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_uuid_format() {
        let uuid = generate_uuid();
        // Check format: 8-4-4-4-12
        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid.chars().nth(8), Some('-'));
        assert_eq!(uuid.chars().nth(13), Some('-'));
        assert_eq!(uuid.chars().nth(18), Some('-'));
        assert_eq!(uuid.chars().nth(23), Some('-'));

        // Check version (4) at position 14
        assert_eq!(uuid.chars().nth(14), Some('4'));

        // Check variant at position 19 (must be 8, 9, a, or b)
        let variant_char = uuid.chars().nth(19).unwrap();
        assert!(
            variant_char == '8'
                || variant_char == '9'
                || variant_char == 'a'
                || variant_char == 'b'
        );
    }

    #[test]
    fn test_generate_uuid_roundtrip() {
        let uuid = generate_uuid();
        let bytes = parse_uuid(&uuid).unwrap();
        assert_eq!(bytes.len(), 16);

        // Verify version nibble
        assert_eq!(bytes[6] >> 4, 4);

        // Verify variant bits
        assert_eq!(bytes[8] >> 6, 2);
    }

    #[test]
    fn test_parse_uuid_with_dashes() {
        // Valid v4 UUID (version=4, variant=10xx)
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let bytes = parse_uuid(uuid).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], 0x55);
        assert_eq!(bytes[1], 0x0e);
    }

    #[test]
    fn test_parse_uuid_without_dashes() {
        // Valid v4 UUID (version=4, variant=10xx)
        let uuid = "550e8400e29b41d4a716446655440000";
        let bytes = parse_uuid(uuid).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], 0x55);
        assert_eq!(bytes[1], 0x0e);
    }

    #[test]
    fn test_parse_uuid_rejects_non_v4() {
        // Version 1 UUID (version nibble = 1)
        let uuid = "550e8400-e29b-11d4-a716-446655440000";
        assert!(parse_uuid(uuid).is_err());
    }

    #[test]
    fn test_parse_uuid_rejects_wrong_variant() {
        // Wrong variant (upper 2 bits of byte 8 = 11 instead of 10)
        let uuid = "550e8400-e29b-41d4-c716-446655440000";
        assert!(parse_uuid(uuid).is_err());
    }
}
