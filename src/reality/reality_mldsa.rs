use std::io;
use std::sync::Arc;

use aws_lc_rs::{
    hmac,
    signature::{self, KeyPair, PqdsaKeyPair},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::Rng;

pub const VERIFY_KEY_LEN: usize = 1952;
pub const SIGNATURE_LEN: usize = 3309;
pub type VerifyKey = Arc<[u8; VERIFY_KEY_LEN]>;

fn decode<const N: usize>(encoded: &str, message: &'static str) -> io::Result<[u8; N]> {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, message))
}

pub fn decode_mldsa65_seed(encoded: &str) -> io::Result<[u8; 32]> {
    decode(
        encoded,
        "ML-DSA-65 seed must be 32 bytes encoded as unpadded base64url",
    )
}

pub fn decode_mldsa65_verify(encoded: &str) -> io::Result<VerifyKey> {
    decode(
        encoded,
        "ML-DSA-65 verification key must be 1952 bytes encoded as unpadded base64url",
    )
    .map(Arc::new)
}

pub fn mldsa65_signing_key(encoded: &str) -> io::Result<Arc<PqdsaKeyPair>> {
    let seed = decode_mldsa65_seed(encoded)?;
    PqdsaKeyPair::from_seed(&signature::ML_DSA_65_SIGNING, &seed)
        .map(Arc::new)
        .map_err(|_| io::Error::other("ML-DSA-65 key expansion failed"))
}

pub fn generate_mldsa65_keypair() -> io::Result<(String, String)> {
    let mut seed = [0; 32];
    rand::rng().fill_bytes(&mut seed);
    let encoded_seed = URL_SAFE_NO_PAD.encode(seed);
    let key = mldsa65_signing_key(&encoded_seed)?;
    Ok((
        encoded_seed,
        URL_SAFE_NO_PAD.encode(key.public_key().as_ref()),
    ))
}

// Matches REALITY's HMAC state continued with both on-wire handshake hellos.
pub fn certificate_message(auth_key: &[u8; 32], public_key: &[u8], hellos: &[&[u8]]) -> [u8; 64] {
    let key = hmac::Key::new(hmac::HMAC_SHA512, auth_key);
    let mut mac = hmac::Context::with_key(&key);
    mac.update(public_key);
    for hello in hellos {
        mac.update(hello);
    }
    mac.sign().as_ref().try_into().unwrap()
}

pub fn sign(key: &PqdsaKeyPair, message: &[u8]) -> io::Result<Vec<u8>> {
    let mut signature = vec![0; SIGNATURE_LEN];
    let length = key
        .sign(message, &mut signature)
        .map_err(|_| io::Error::other("ML-DSA-65 signing failed"))?;
    if length != SIGNATURE_LEN {
        return Err(io::Error::other("Unexpected ML-DSA-65 signature length"));
    }
    Ok(signature)
}

pub fn verify(key: &VerifyKey, message: &[u8], sig: &[u8]) -> io::Result<()> {
    if sig.len() != SIGNATURE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Invalid REALITY ML-DSA-65 signature length",
        ));
    }
    signature::UnparsedPublicKey::new(&signature::ML_DSA_65, key.as_slice())
        .verify(message, sig)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "REALITY ML-DSA-65 verification failed",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_key_encoding_is_strict() {
        for invalid in ["", "not base64!", "AA", "AAAA="] {
            assert!(decode_mldsa65_seed(invalid).is_err());
            assert!(decode_mldsa65_verify(invalid).is_err());
        }
        let (seed, verify) = generate_mldsa65_keypair().unwrap();
        let key = mldsa65_signing_key(&seed).unwrap();
        assert_eq!(
            key.public_key().as_ref(),
            decode_mldsa65_verify(&verify).unwrap().as_slice()
        );
    }

    #[test]
    fn transcript_and_key_are_bound() {
        let (seed, encoded) = generate_mldsa65_keypair().unwrap();
        let key = mldsa65_signing_key(&seed).unwrap();
        let verify_key = decode_mldsa65_verify(&encoded).unwrap();
        let message = certificate_message(&[1; 32], &[2; 32], &[b"client", b"server"]);
        let signature = sign(&key, &message).unwrap();
        verify(&verify_key, &message, &signature).unwrap();
        for altered in [
            certificate_message(&[3; 32], &[2; 32], &[b"client", b"server"]),
            certificate_message(&[1; 32], &[3; 32], &[b"client", b"server"]),
            certificate_message(&[1; 32], &[2; 32], &[b"Client", b"server"]),
            certificate_message(&[1; 32], &[2; 32], &[b"client", b"Server"]),
        ] {
            assert!(verify(&verify_key, &altered, &signature).is_err());
        }
        let (_, wrong) = generate_mldsa65_keypair().unwrap();
        assert!(
            verify(
                &decode_mldsa65_verify(&wrong).unwrap(),
                &message,
                &signature
            )
            .is_err()
        );
        assert!(verify(&verify_key, &message, &signature[..SIGNATURE_LEN - 1]).is_err());
    }
}
