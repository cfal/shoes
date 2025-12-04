pub struct Fnv1aHasher(u32);

const FNV_PRIME: u32 = 16777619;

impl Fnv1aHasher {
    pub fn new() -> Self {
        Self(0x811c9dc5)
    }

    pub fn write(&mut self, data: &[u8]) {
        let mut hash = self.0;
        for byte in data.iter() {
            hash ^= *byte as u32;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        self.0 = hash;
    }

    pub fn finish(self) -> u32 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fnv1a_empty() {
        let hasher = Fnv1aHasher::new();
        // FNV1a offset basis for empty input
        assert_eq!(hasher.finish(), 0x811c9dc5);
    }

    #[test]
    fn test_fnv1a_single_byte() {
        let mut hasher = Fnv1aHasher::new();
        hasher.write(&[0x00]);
        // 0x811c9dc5 ^ 0x00 = 0x811c9dc5, then * 16777619 = 0x050c5d1f
        assert_eq!(hasher.finish(), 0x050c5d1f);
    }

    #[test]
    fn test_fnv1a_hello() {
        // Standard FNV-1a test vector for "hello"
        let mut hasher = Fnv1aHasher::new();
        hasher.write(b"hello");
        assert_eq!(hasher.finish(), 0x4f9f2cab);
    }

    #[test]
    fn test_fnv1a_incremental() {
        // Test that incremental hashing produces same result as single call
        let mut hasher1 = Fnv1aHasher::new();
        hasher1.write(b"hello world");

        let mut hasher2 = Fnv1aHasher::new();
        hasher2.write(b"hello");
        hasher2.write(b" ");
        hasher2.write(b"world");

        assert_eq!(hasher1.finish(), hasher2.finish());
    }

    #[test]
    fn test_fnv1a_vmess_header_format() {
        // Test with typical VMess header-like data
        let mut hasher = Fnv1aHasher::new();
        let header_data = [
            1u8, // version
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // IV (partial)
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // IV (rest)
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // Key (partial)
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, // Key (rest)
        ];
        hasher.write(&header_data);
        let hash = hasher.finish();
        // Just verify it produces a consistent result
        assert_ne!(hash, 0);
        assert_ne!(hash, 0x811c9dc5);
    }

    #[test]
    fn test_fnv1a_all_zeros() {
        let mut hasher = Fnv1aHasher::new();
        hasher.write(&[0u8; 16]);
        // Verify consistent output for all zeros
        let hash = hasher.finish();
        // Verify determinism - same input produces same output
        let mut hasher2 = Fnv1aHasher::new();
        hasher2.write(&[0u8; 16]);
        assert_eq!(hash, hasher2.finish());
    }

    #[test]
    fn test_fnv1a_all_ones() {
        let mut hasher = Fnv1aHasher::new();
        hasher.write(&[0xff; 16]);
        let hash = hasher.finish();
        // Verify determinism - same input produces same output
        let mut hasher2 = Fnv1aHasher::new();
        hasher2.write(&[0xff; 16]);
        assert_eq!(hash, hasher2.finish());
    }
}
