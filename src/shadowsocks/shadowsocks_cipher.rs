use md5::{Digest, Md5};
use ring::aead::{
    Algorithm, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_128_GCM,
    AES_256_GCM, CHACHA20_POLY1305,
};
use ring::error::Unspecified;

use super::aead_util::{create_session_key, TAG_LEN};
use super::shadowsocks_stream::ShadowsocksStream;
use crate::async_stream::AsyncStream;

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
}

impl ShadowsocksCipher {
    pub fn get_key_bytes(&self, key: &str) -> Box<[u8]> {
        // TODO: This is the same as openssl::pkcs5::bytes_to_key.
        // Is it possible not to depend on the md5 crate when openssl is enabled?
        let cipher_key_len = self.algorithm.key_len();
        let key = key.as_bytes();
        let mut ret = vec![];
        let mut context = Md5::new();
        loop {
            context.update(key);
            let digest: [u8; 16] = context.finalize().into();
            ret.extend(digest.iter());
            if ret.len() >= cipher_key_len {
                break;
            }
            context = Md5::new();
            context.update(&digest);
        }
        ret.truncate(cipher_key_len);
        ret.into_boxed_slice()
    }

    pub fn create_cipher_stream(
        &self,
        key: &[u8],
        stream: Box<dyn AsyncStream>,
    ) -> Box<dyn AsyncStream> {
        Box::new(ShadowsocksStream::new(
            self.algorithm,
            stream,
            key,
            self.salt_len,
        )) as Box<dyn AsyncStream>
    }

    pub fn salt_len(&self) -> usize {
        self.salt_len
    }

    pub fn create_udp_opening_key(
        &self,
        key: &[u8],
        salt: &[u8],
    ) -> ring::aead::OpeningKey<ZeroNonceSequence> {
        let session_key = create_session_key(key, salt);
        let unbound_key = UnboundKey::new(self.algorithm, &session_key).unwrap();
        OpeningKey::new(unbound_key, ZeroNonceSequence {})
    }

    pub fn create_udp_sealing_key(
        &self,
        key: &[u8],
        salt: &[u8],
    ) -> ring::aead::SealingKey<ZeroNonceSequence> {
        let session_key = create_session_key(key, salt);
        let sealing_key = UnboundKey::new(self.algorithm, &session_key).unwrap();
        SealingKey::new(sealing_key, ZeroNonceSequence {})
    }
}

pub struct ZeroNonceSequence;
impl NonceSequence for ZeroNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        Ok(Nonce::assume_unique_for_key([0u8; 12]))
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
