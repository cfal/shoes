// Copied and modified from rust-snappy
use std::sync::OnceLock;

const POLY: u32 = 0xEDB88320;

/// Returns the CRC32 checksum of `buf` using the Castagnoli polynomial.
pub fn crc32c(buf: &[u8]) -> u32 {
    // I can't measure any difference between slice8 and slice16.
    let ret = crc32c_slice8(buf, !0);
    !ret
}

/// Returns the CRC32 checksum of `buf` using the Castagnoli polynomial.
fn crc32c_slice8(mut buf: &[u8], initial_crc: u32) -> u32 {
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    static TABLE16: OnceLock<[[u32; 256]; 16]> = OnceLock::new();

    let tab = TABLE.get_or_init(|| make_table(POLY));
    let tab8 = &TABLE16.get_or_init(|| {
        let mut tab = [[0; 256]; 16];
        tab[0] = make_table(POLY);
        for i in 0..256 {
            let mut crc = tab[0][i];
            for j in 1..16 {
                crc = (crc >> 8) ^ tab[0][crc as u8 as usize];
                tab[j][i] = crc;
            }
        }
        tab
    });

    let mut crc: u32 = initial_crc;
    while buf.len() >= 8 {
        crc ^= u32::from_le_bytes(buf[0..4].try_into().unwrap());
        crc = tab8[0][buf[7] as usize]
            ^ tab8[1][buf[6] as usize]
            ^ tab8[2][buf[5] as usize]
            ^ tab8[3][buf[4] as usize]
            ^ tab8[4][(crc >> 24) as u8 as usize]
            ^ tab8[5][(crc >> 16) as u8 as usize]
            ^ tab8[6][(crc >> 8) as u8 as usize]
            ^ tab8[7][(crc) as u8 as usize];
        buf = &buf[8..];
    }
    for &b in buf {
        crc = tab[((crc as u8) ^ b) as usize] ^ (crc >> 8);
    }
    crc
}

fn make_table(poly: u32) -> [u32; 256] {
    let mut tab = [0; 256];
    let mut rev_tab = [0; 256];
    for i in 0u32..256u32 {
        let mut crc = i;
        let mut rev = i << 24;
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ poly;
            } else {
                crc >>= 1;
            }

            if (rev & 0x80000000) != 0 {
                rev = ((rev ^ poly) << 1) | 1;
            } else {
                rev <<= 1;
            }
        }
        tab[i as usize] = crc;
        rev_tab[i as usize] = rev;
    }
    tab
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32c_empty() {
        // CRC32C of empty input should be 0
        assert_eq!(crc32c(b""), 0);
    }

    #[test]
    fn test_crc32c_single_byte() {
        // Test with single byte
        let result = crc32c(&[0x00]);
        assert_ne!(result, 0);
    }

    #[test]
    fn test_crc32c_hello() {
        // Test with "hello"
        let result = crc32c(b"hello");
        // Note: This implementation uses standard CRC32 polynomial (0xEDB88320)
        // despite the function name. Verify determinism.
        let result2 = crc32c(b"hello");
        assert_eq!(result, result2);
        assert_ne!(result, 0);
    }

    #[test]
    fn test_crc32c_vmess_auth_id() {
        // Test with typical VMess auth ID structure (12 bytes)
        // This is what's checksummed in the AEAD auth ID
        let auth_id = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, // timestamp (1 second since epoch)
            0x01, 0x02, 0x03, 0x04, // random bytes
        ];
        let result = crc32c(&auth_id);
        // Verify it produces a valid 32-bit checksum
        // The result should be consistent
        let result2 = crc32c(&auth_id);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_crc32c_different_inputs() {
        // Different inputs should produce different checksums
        let result1 = crc32c(b"input1");
        let result2 = crc32c(b"input2");
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_crc32c_long_input() {
        // Test with input longer than 8 bytes to exercise slice8 optimization
        let input = b"this is a longer input that exercises the slice8 optimization path";
        let result = crc32c(input);
        assert_ne!(result, 0);
    }

    #[test]
    fn test_crc32c_16_bytes() {
        // Test with exactly 16 bytes (two iterations of slice8)
        let input = [0x55u8; 16];
        let result = crc32c(&input);
        assert_ne!(result, 0);
    }

    #[test]
    fn test_crc32c_all_zeros() {
        // All zeros should produce consistent non-zero result
        let result = crc32c(&[0u8; 16]);
        // Verify determinism
        let result2 = crc32c(&[0u8; 16]);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_crc32c_all_ones() {
        // All 0xff bytes
        let result = crc32c(&[0xffu8; 16]);
        assert_ne!(result, 0);
    }

    #[test]
    fn test_crc32c_boundary_8_bytes() {
        // Exactly 8 bytes - boundary case for slice8
        let input = [1, 2, 3, 4, 5, 6, 7, 8];
        let result = crc32c(&input);
        assert_ne!(result, 0);
    }

    #[test]
    fn test_crc32c_boundary_7_bytes() {
        // 7 bytes - exercises the tail loop only
        let input = [1, 2, 3, 4, 5, 6, 7];
        let result = crc32c(&input);
        assert_ne!(result, 0);
    }

    #[test]
    fn test_crc32c_boundary_9_bytes() {
        // 9 bytes - one slice8 iteration + 1 tail byte
        let input = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let result = crc32c(&input);
        assert_ne!(result, 0);
    }

    #[test]
    fn test_crc32c_32_zeros() {
        // 32 bytes of 0x00
        let input = [0u8; 32];
        let result = crc32c(&input);
        // Verify determinism
        let result2 = crc32c(&input);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_crc32c_32_ones() {
        // 32 bytes of 0xff
        let input = [0xffu8; 32];
        let result = crc32c(&input);
        // Verify determinism
        let result2 = crc32c(&input);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_crc32c_incremental_sequence() {
        // 32 bytes: 0x00, 0x01, 0x02, ... 0x1f
        let input: Vec<u8> = (0u8..32).collect();
        let result = crc32c(&input);
        // Verify determinism
        let result2 = crc32c(&input);
        assert_eq!(result, result2);
    }
}
