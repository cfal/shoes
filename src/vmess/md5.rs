use generic_array::GenericArray;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};

#[inline]
pub fn compute_md5(data: &[u8]) -> [u8; 16] {
    let mut context = Md5::new();
    md5::Digest::update(&mut context, data);
    context.finalize().into()
}

#[inline]
pub fn compute_md5_repeating(data: &[u8], data_times: usize) -> [u8; 16] {
    let mut context = Md5::new();
    for _ in 0..data_times {
        md5::Digest::update(&mut context, data);
    }
    context.finalize().into()
}

#[inline]
pub fn create_chacha_key(data: &[u8]) -> [u8; 32] {
    let mut ret = [0u8; 32];
    let mut context = Md5::new();
    md5::Digest::update(&mut context, data);
    context.finalize_into_reset(GenericArray::from_mut_slice(&mut ret[0..16]));
    md5::Digest::update(&mut context, &ret[0..16]);
    context.finalize_into(GenericArray::from_mut_slice(&mut ret[16..]));
    ret
}

type HmacMd5 = Hmac<Md5>;

#[inline]
pub fn compute_hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = HmacMd5::new_from_slice(key).unwrap();
    Mac::update(&mut mac, data);
    mac.finalize().into_bytes().into()
}
