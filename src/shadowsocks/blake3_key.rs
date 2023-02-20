use super::shadowsocks_key::ShadowsocksKey;
use crate::util::allocate_vec;

#[derive(Debug, Clone)]
pub struct Blake3Key {
    key_bytes: Box<[u8]>,
    session_key_len: usize,
}

impl Blake3Key {
    pub fn new(key_bytes: Box<[u8]>, session_key_len: usize) -> Self {
        Self {
            key_bytes,
            session_key_len,
        }
    }
}

const CONTEXT_STR: &str = "shadowsocks 2022 session subkey";

impl ShadowsocksKey for Blake3Key {
    fn create_session_key(&self, salt: &[u8]) -> Box<[u8]> {
        let salt_len = salt.len();
        // both are 16 for aes-128-gcm, and both are 32 for aes-32-gcm
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
