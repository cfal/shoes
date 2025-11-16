use md5::{Digest, Md5};

#[inline]
pub fn compute_md5(data: &[u8]) -> [u8; 16] {
    let mut context = Md5::new();
    md5::Digest::update(&mut context, data);
    context.finalize().into()
}

#[inline]
pub fn create_chacha_key(data: &[u8]) -> [u8; 32] {
    let mut ret = [0u8; 32];
    let mut context = Md5::new();
    md5::Digest::update(&mut context, data);
    context.finalize_into_reset((&mut ret[0..16]).into());
    md5::Digest::update(&mut context, &ret[0..16]);
    context.finalize_into((&mut ret[16..]).into());
    ret
}
