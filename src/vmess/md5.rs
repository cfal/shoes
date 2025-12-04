use md5::{Digest, Md5};

#[inline]
pub fn compute_md5(data: &[u8]) -> [u8; 16] {
    let mut context = Md5::new();
    md5::Digest::update(&mut context, data);
    context.finalize().into()
}

#[inline]
pub fn create_chacha_key(data: &[u8]) -> [u8; 32] {
    let mut ret = [0u8; 32];
    let mut context = Md5::new();
    md5::Digest::update(&mut context, data);
    context.finalize_into_reset((&mut ret[0..16]).into());
    md5::Digest::update(&mut context, &ret[0..16]);
    context.finalize_into((&mut ret[16..]).into());
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_md5_empty() {
        let result = compute_md5(b"");
        // MD5 of empty string: d41d8cd98f00b204e9800998ecf8427e
        assert_eq!(
            result,
            [
                0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
                0x42, 0x7e
            ]
        );
    }

    #[test]
    fn test_compute_md5_hello() {
        let result = compute_md5(b"hello");
        // MD5 of "hello": 5d41402abc4b2a76b9719d911017c592
        assert_eq!(
            result,
            [
                0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76, 0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17,
                0xc5, 0x92
            ]
        );
    }

    #[test]
    fn test_compute_md5_vmess_user_id() {
        // Test with VMess-style user ID + magic string
        // This is used to derive the instruction key
        let user_id = b"test-user-id";
        let magic = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
        let mut combined = Vec::new();
        combined.extend_from_slice(user_id);
        combined.extend_from_slice(magic);
        let result = compute_md5(&combined);
        // Verify it produces a valid 16-byte key
        assert_eq!(result.len(), 16);
        // Verify non-trivial output
        assert_ne!(result, [0u8; 16]);
    }

    #[test]
    fn test_create_chacha_key_from_16_bytes() {
        // Test ChaCha key derivation from 16-byte input (typical VMess key)
        let input = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let result = create_chacha_key(&input);
        // Verify it produces a 32-byte key
        assert_eq!(result.len(), 32);
        // First 16 bytes should be MD5(input)
        assert_eq!(&result[0..16], &compute_md5(&input));
        // Second 16 bytes should be MD5(first_16_bytes)
        assert_eq!(&result[16..32], &compute_md5(&result[0..16]));
    }

    #[test]
    fn test_create_chacha_key_deterministic() {
        // Same input should always produce same output
        let input = b"test-key-material";
        let result1 = create_chacha_key(input);
        let result2 = create_chacha_key(input);
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_create_chacha_key_different_inputs() {
        // Different inputs should produce different outputs
        let result1 = create_chacha_key(b"key1");
        let result2 = create_chacha_key(b"key2");
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_create_chacha_key_empty() {
        // Even empty input should produce valid 32-byte key
        let result = create_chacha_key(b"");
        assert_eq!(result.len(), 32);
        // MD5 of empty string for first 16 bytes
        assert_eq!(
            &result[0..16],
            &[
                0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
                0x42, 0x7e
            ]
        );
    }

    #[test]
    fn test_create_chacha_key_matches_sing_vmess() {
        // Test vector that matches sing-vmess GenerateChacha20Poly1305Key behavior
        // sing-vmess does: md5.Sum(key) for first 16, md5.Sum(first16) for second 16
        let key = [0u8; 16];
        let result = create_chacha_key(&key);
        // Verify the structure: result = MD5(key) || MD5(MD5(key))
        let first_half = compute_md5(&key);
        let second_half = compute_md5(&first_half);
        assert_eq!(&result[0..16], &first_half);
        assert_eq!(&result[16..32], &second_half);
    }
}
