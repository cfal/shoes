use crate::util::allocate_vec;

pub const TAG_LEN: usize = 16;

struct SliceKeyType<'a>(&'a [u8]);

impl ring::hkdf::KeyType for SliceKeyType<'_> {
    fn len(&self) -> usize {
        self.0.len()
    }
}

const SS_SUBKEY_INFO: &[&[u8]] = &[b"ss-subkey"];

pub fn create_session_key(key: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut session_key = allocate_vec(key.len());
    ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt)
        .extract(key)
        .expand(SS_SUBKEY_INFO, SliceKeyType(&key))
        .unwrap()
        .fill(&mut session_key)
        .unwrap();
    session_key
}
