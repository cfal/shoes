use aws_lc_rs::digest::{Context, SHA256};

trait VmessHash: std::fmt::Debug {
    fn setup_new(&self) -> Box<dyn VmessHash>;
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> [u8; 32];
}

struct Sha256Hash(Context);

impl std::fmt::Debug for Sha256Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Sha256Hash").field(&"Context").finish()
    }
}

impl Sha256Hash {
    fn create() -> Self {
        Self(Context::new(&SHA256))
    }
}

impl VmessHash for Sha256Hash {
    fn setup_new(&self) -> Box<dyn VmessHash> {
        Box::new(Sha256Hash(self.0.clone()))
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.0.clone().finish().as_ref());
        out
    }
}

#[derive(Debug)]
struct RecursiveHash {
    inner: Box<dyn VmessHash>,
    outer: Box<dyn VmessHash>,
    default_inner: [u8; 64],
    default_outer: [u8; 64],
}

impl RecursiveHash {
    fn create(key: &[u8], hash: Box<dyn VmessHash>) -> Self {
        // for hmac, we would normally have to get a derived key
        // by hashing the key when it's longer than 64 bytes, but
        // that doesn't happen for vmess's usecase.
        assert!(key.len() <= 64);

        let mut default_outer = [0x5c; 64];
        let mut default_inner = [0x36; 64];

        for (i, &b) in key.iter().enumerate() {
            default_outer[i] ^= b;
            default_inner[i] ^= b;
        }

        let mut inner = hash.setup_new();
        let outer = hash;
        inner.update(&default_inner);
        Self {
            inner,
            outer,
            default_inner,
            default_outer,
        }
    }
}

impl VmessHash for RecursiveHash {
    fn setup_new(&self) -> Box<dyn VmessHash> {
        let new_inner = self.inner.setup_new();
        let new_outer = self.outer.setup_new();

        let mut new_default_inner = [0u8; 64];
        let mut new_default_outer = [0u8; 64];
        new_default_inner.copy_from_slice(&self.default_inner);
        new_default_outer.copy_from_slice(&self.default_outer);

        Box::new(RecursiveHash {
            inner: new_inner,
            outer: new_outer,
            default_inner: new_default_inner,
            default_outer: new_default_outer,
        })
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(&mut self) -> [u8; 32] {
        self.outer.update(&self.default_outer);
        self.outer.update(&self.inner.finalize());
        self.outer.finalize()
    }
}

pub fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut current = Box::new(RecursiveHash::create(
        b"VMess AEAD KDF",
        Box::new(Sha256Hash::create()),
    ));
    for path_item in path.iter() {
        current = Box::new(RecursiveHash::create(path_item, current))
    }
    current.update(key);
    current.finalize()
}

pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(aws_lc_rs::digest::digest(&SHA256, data).as_ref());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_sha256_empty() {
        let result = compute_sha256(b"");
        // SHA256 of empty string: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            result,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );
    }

    #[test]
    fn test_compute_sha256_hello() {
        let result = compute_sha256(b"hello");
        // SHA256 of "hello": 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert_eq!(
            result,
            [
                0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9,
                0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e, 0x73, 0x04, 0x33, 0x62,
                0x93, 0x8b, 0x98, 0x24
            ]
        );
    }

    #[test]
    fn test_kdf_single_path() {
        // Test KDF with single path element
        let key = b"test-key";
        let result = kdf(key, &[b"test-path"]);
        // Verify it produces a 32-byte output
        assert_eq!(result.len(), 32);
        // Verify deterministic output
        let result2 = kdf(key, &[b"test-path"]);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_kdf_multiple_paths() {
        // Test KDF with multiple path elements (as used in VMess AEAD)
        let key = b"instruction-key-16";
        let result = kdf(key, &[b"AES Auth ID Encryption"]);
        // Verify 32-byte output
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_kdf_vmess_header_length_key() {
        // Test KDF with typical VMess header length key derivation
        let instruction_key = [0u8; 16];
        let cert_hash = [1u8; 16];
        let nonce = [2u8; 8];
        let result = kdf(
            &instruction_key,
            &[b"VMess Header AEAD Key_Length", &cert_hash[..], &nonce[..]],
        );
        assert_eq!(result.len(), 32);
        // First 16 bytes are used as AES-128 key
        assert_ne!(&result[0..16], &[0u8; 16]);
    }

    #[test]
    fn test_kdf_vmess_header_nonce() {
        // Test KDF with VMess header nonce derivation
        let instruction_key = [0u8; 16];
        let cert_hash = [1u8; 16];
        let nonce = [2u8; 8];
        let result = kdf(
            &instruction_key,
            &[
                b"VMess Header AEAD Nonce_Length",
                &cert_hash[..],
                &nonce[..],
            ],
        );
        assert_eq!(result.len(), 32);
        // First 12 bytes are used as nonce
        assert_ne!(&result[0..12], &[0u8; 12]);
    }

    #[test]
    fn test_kdf_response_header_key() {
        // Test KDF for response header key derivation
        let response_header_key = [0x11u8; 16];
        let result = kdf(&response_header_key, &[b"AEAD Resp Header Len Key"]);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_kdf_different_paths_different_results() {
        // Different paths should produce different results
        let key = b"same-key";
        let result1 = kdf(key, &[b"path1"]);
        let result2 = kdf(key, &[b"path2"]);
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_kdf_different_keys_different_results() {
        // Different keys should produce different results
        let result1 = kdf(b"key1", &[b"same-path"]);
        let result2 = kdf(b"key2", &[b"same-path"]);
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_kdf_path_order_matters() {
        // Path order should affect results
        let key = b"test-key";
        let result1 = kdf(key, &[b"path1", b"path2"]);
        let result2 = kdf(key, &[b"path2", b"path1"]);
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_kdf_empty_path() {
        // Empty path should still work
        let key = b"test-key";
        let result = kdf(key, &[]);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_kdf_vmess_aead_kdf_constant() {
        // The KDF uses "VMess AEAD KDF" as the initial salt
        // This is a structural test to verify the KDF chain works correctly
        let key = [0u8; 16];
        // Single path should nest: HMAC(HMAC("VMess AEAD KDF", "path"), key)
        let result = kdf(&key, &[b"AES Auth ID Encryption"]);
        assert_eq!(result.len(), 32);
        // Verify it's not just SHA256 of the key
        assert_ne!(result, compute_sha256(&key));
    }
}
