// TODO: investigate using SIV variants for nonce reuse resistance
use aws_lc_rs::aead::{AES_128_GCM, AES_256_GCM, Algorithm, CHACHA20_POLY1305};

use super::aead_util::TAG_LEN;

#[derive(Debug, Clone, Copy)]
pub struct ShadowsocksCipher {
    algorithm: &'static Algorithm,
    salt_len: usize,
    name: &'static str,
}

impl ShadowsocksCipher {
    fn chacha20_ietf_poly1305() -> Self {
        Self::new(&CHACHA20_POLY1305, 32, "chacha20-ietf-poly1305")
    }

    fn aes_256_gcm() -> Self {
        Self::new(&AES_256_GCM, 32, "aes-256-gcm")
    }

    fn aes_128_gcm() -> Self {
        Self::new(&AES_128_GCM, 16, "aes-128-gcm")
    }

    fn new(algorithm: &'static Algorithm, salt_len: usize, name: &'static str) -> Self {
        if algorithm.tag_len() != TAG_LEN {
            panic!("Unexpected tag length: {}", algorithm.tag_len());
        }
        Self {
            algorithm,
            salt_len,
            name,
        }
    }

    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }

    pub fn salt_len(&self) -> usize {
        self.salt_len
    }

    pub fn key_len(&self) -> usize {
        self.algorithm.key_len()
    }

    pub fn name(&self) -> &'static str {
        self.name
    }
}

impl TryFrom<&str> for ShadowsocksCipher {
    type Error = std::io::Error;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        match name {
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => {
                Ok(ShadowsocksCipher::chacha20_ietf_poly1305())
            }
            "aes-256-gcm" => Ok(ShadowsocksCipher::aes_256_gcm()),
            "aes-128-gcm" => Ok(ShadowsocksCipher::aes_128_gcm()),
            _ => Err(std::io::Error::other(format!("Unknown cipher: {name}"))),
        }
    }
}
