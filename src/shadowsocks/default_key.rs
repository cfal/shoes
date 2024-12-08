use md5::{Digest, Md5};

use super::shadowsocks_key::ShadowsocksKey;
use crate::util::allocate_vec;

#[derive(Debug, Clone)]
pub struct DefaultKey {
    key_bytes: Box<[u8]>,
    key_len: usize,
}

impl DefaultKey {
    pub fn new(password: &str, key_len: usize) -> Self {
        Self {
            key_bytes: get_key_bytes(password, key_len),
            key_len,
        }
    }
}

const SS_SUBKEY_INFO: &[&[u8]] = &[b"ss-subkey"];

struct SliceKeyType<'a>(&'a [u8]);

impl aws_lc_rs::hkdf::KeyType for SliceKeyType<'_> {
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl ShadowsocksKey for DefaultKey {
    fn create_session_key(&self, salt: &[u8]) -> Box<[u8]> {
        let mut session_key = allocate_vec(self.key_len);
        aws_lc_rs::hkdf::Salt::new(aws_lc_rs::hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt)
            .extract(&self.key_bytes)
            .expand(SS_SUBKEY_INFO, SliceKeyType(&self.key_bytes))
            .unwrap()
            .fill(&mut session_key)
            .unwrap();
        session_key.into_boxed_slice()
    }
}

fn get_key_bytes(key: &str, cipher_key_len: usize) -> Box<[u8]> {
    // TODO: This is the same as openssl::pkcs5::bytes_to_key.
    // Is it possible not to depend on the md5 crate when openssl is enabled?
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
        context.update(digest);
    }
    ret.truncate(cipher_key_len);
    ret.into_boxed_slice()
}
