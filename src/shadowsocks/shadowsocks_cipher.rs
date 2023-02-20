use ring::aead::{Algorithm, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};

use super::aead_util::TAG_LEN;

#[derive(Debug)]
pub struct ShadowsocksCipher {
    algorithm: &'static Algorithm,
    salt_len: usize,
}

impl ShadowsocksCipher {
    fn chacha20_ietf_poly1305() -> Self {
        Self::new(&CHACHA20_POLY1305, 32)
    }

    fn aes_256_gcm() -> Self {
        Self::new(&AES_256_GCM, 32)
    }

    fn aes_128_gcm() -> Self {
        Self::new(&AES_128_GCM, 16)
    }

    fn new(algorithm: &'static Algorithm, salt_len: usize) -> Self {
        if algorithm.tag_len() != TAG_LEN {
            panic!("Unexpected tag length: {}", algorithm.tag_len());
        }
        Self {
            algorithm,
            salt_len,
        }
    }

    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }

    pub fn salt_len(&self) -> usize {
        self.salt_len
    }
}

impl From<&str> for ShadowsocksCipher {
    fn from(name: &str) -> Self {
        match name {
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => {
                ShadowsocksCipher::chacha20_ietf_poly1305()
            }
            "aes-256-gcm" => ShadowsocksCipher::aes_256_gcm(),
            "aes-128-gcm" => ShadowsocksCipher::aes_128_gcm(),
            _ => {
                panic!("Unknown cipher: {}", name);
            }
        }
    }
}
