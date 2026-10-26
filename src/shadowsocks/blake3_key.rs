use super::shadowsocks_key::ShadowsocksKey;
use crate::util::allocate_vec;

#[derive(Clone)]
pub struct Blake3Key {
    key_bytes: Box<[u8]>,
    session_key_len: usize,
    identity_keys: Vec<Box<[u8]>>,
}

impl std::fmt::Debug for Blake3Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Blake3Key")
            .field("session_key_len", &self.session_key_len)
            .field("identity_count", &self.identity_keys.len())
            .finish_non_exhaustive()
    }
}

impl Blake3Key {
    pub fn new(key_bytes: Box<[u8]>, session_key_len: usize) -> Self {
        Self {
            key_bytes,
            session_key_len,
            identity_keys: Vec::new(),
        }
    }

    pub fn with_identity_keys(mut self, identity_keys: Vec<Box<[u8]>>) -> Self {
        self.identity_keys = identity_keys;
        self
    }
}

const CONTEXT_STR: &str = "shadowsocks 2022 session subkey";

impl ShadowsocksKey for Blake3Key {
    fn create_identity_headers(&self, salt: &[u8]) -> std::io::Result<Vec<u8>> {
        use aws_lc_rs::cipher::{
            AES_128, AES_256, EncryptingKey, EncryptionContext, UnboundCipherKey,
        };

        let mut headers = Vec::new();
        for (identity, next) in self.identity_keys.iter().zip(
            self.identity_keys
                .iter()
                .skip(1)
                .chain(std::iter::once(&self.key_bytes)),
        ) {
            let algorithm = match self.session_key_len {
                16 => &AES_128,
                32 => &AES_256,
                _ => {
                    return Err(std::io::Error::other(
                        "Invalid Shadowsocks identity key length",
                    ));
                }
            };
            let mut hasher = blake3::Hasher::new_derive_key("shadowsocks 2022 identity subkey");
            hasher.update(identity);
            hasher.update(salt);
            let subkey = hasher.finalize();
            let key = UnboundCipherKey::new(algorithm, &subkey.as_bytes()[..self.session_key_len])
                .and_then(EncryptingKey::ecb)
                .map_err(|_| {
                    std::io::Error::other("Failed to initialize Shadowsocks identity cipher")
                })?;
            let mut block = [0; 16];
            block.copy_from_slice(&blake3::hash(next).as_bytes()[..16]);
            key.less_safe_encrypt(&mut block, EncryptionContext::None)
                .map_err(|_| {
                    std::io::Error::other("Failed to encrypt Shadowsocks identity header")
                })?;
            headers.extend_from_slice(&block);
        }
        Ok(headers)
    }

    fn create_session_key(&self, salt: &[u8]) -> Box<[u8]> {
        let salt_len = salt.len();
        // both are 16 for aes-128-gcm, and both are 32 for aes-256-gcm
        assert!(self.key_bytes.len() == salt_len);

        let mut key_material = allocate_vec(salt_len * 2);
        key_material[0..salt_len].copy_from_slice(&self.key_bytes);
        key_material[salt_len..].copy_from_slice(salt);

        let mut hasher = blake3::Hasher::new_derive_key(CONTEXT_STR);
        hasher.update(&key_material);
        let mut output_reader = hasher.finalize_xof();

        let mut session_key = allocate_vec(self.session_key_len);
        output_reader.fill(&mut session_key);

        session_key.into_boxed_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_headers_match_xray_vectors() {
        // Generated with Xray's BLAKE3 derivation and Go crypto/aes, not this encoder.
        for (size, expected) in [
            (
                16,
                "42b9d61c1a91c5589aed68ebaef26f8e72286fd37f16ad7da6a9bb5c5d7b6062",
            ),
            (
                32,
                "f6b9f20ad975af89ed9cfc5bd7a4febc76b1ac3902d8e75b3d93e94e8cc714bd",
            ),
        ] {
            let key = Blake3Key::new(vec![0x33; size].into_boxed_slice(), size);
            let salt = vec![0x44; size];
            assert!(key.create_identity_headers(&salt).unwrap().is_empty());
            let session_key = key.create_session_key(&salt);
            let key = key.with_identity_keys(vec![
                vec![0x11; size].into_boxed_slice(),
                vec![0x22; size].into_boxed_slice(),
            ]);
            let headers = key.create_identity_headers(&salt).unwrap();
            let hex = headers
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(hex, expected);
            assert_eq!(key.create_session_key(&salt), session_key);
            assert_ne!(
                key.create_identity_headers(&vec![0x55; size]).unwrap(),
                headers
            );
            assert!(!format!("{key:?}").contains("key_bytes"));
        }
    }
}
