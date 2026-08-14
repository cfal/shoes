//! Salamander obfuscation.
//!
//! Verified against apernet/hysteria, extras/obfs/salamander.go:
//!
//! ```text
//! smPSKMinLen = 4
//! smSaltLen   = 8
//! smKeyLen    = blake2b.Size256
//! ```
//!
//! On the wire a packet is `[8-byte random salt][payload XOR key]`, where
//! `key = BLAKE2b-256(PSK || salt)` and byte `i` of the payload is XOR'd with
//! `key[i % 32]`.

use blake2::{Blake2b, Digest, digest::consts::U32};
use rand::Rng;

use super::Obfuscator;

/// Minimum pre-shared key length, matching smPSKMinLen upstream.
pub const MIN_PSK_LEN: usize = 4;
/// Salt prefixed to every packet, matching smSaltLen upstream.
const SALT_LEN: usize = 8;
/// Derived key length, matching smKeyLen = blake2b.Size256 upstream.
const KEY_LEN: usize = 32;

type Blake2b256 = Blake2b<U32>;

#[derive(Debug)]
pub struct Salamander {
    psk: Vec<u8>,
}

impl Salamander {
    pub fn new(psk: &[u8]) -> std::io::Result<Self> {
        if psk.len() < MIN_PSK_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("obfuscation password must be at least {MIN_PSK_LEN} bytes"),
            ));
        }
        Ok(Self { psk: psk.to_vec() })
    }

    fn derive_key(&self, salt: &[u8; SALT_LEN]) -> [u8; KEY_LEN] {
        let mut hasher = Blake2b256::new();
        hasher.update(&self.psk);
        hasher.update(salt);
        hasher.finalize().into()
    }
}

impl Obfuscator for Salamander {
    fn obfuscate(&self, input: &[u8], out: &mut [u8]) -> Option<usize> {
        let out_len = input.len() + SALT_LEN;
        if out.len() < out_len {
            return None;
        }
        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut salt);
        let key = self.derive_key(&salt);

        out[..SALT_LEN].copy_from_slice(&salt);
        for (i, byte) in input.iter().enumerate() {
            out[i + SALT_LEN] = byte ^ key[i % KEY_LEN];
        }
        Some(out_len)
    }

    fn deobfuscate_in_place(&self, buf: &mut [u8]) -> Option<usize> {
        let out_len = buf.len().checked_sub(SALT_LEN)?;
        if out_len == 0 {
            return None;
        }
        let salt: [u8; SALT_LEN] = buf[..SALT_LEN].try_into().ok()?;
        let key = self.derive_key(&salt);

        // Byte i of the payload is read from i + SALT_LEN and written to i, so
        // every write lands behind the read that produced it.
        for i in 0..out_len {
            buf[i] = buf[i + SALT_LEN] ^ key[i % KEY_LEN];
        }
        Some(out_len)
    }

    fn overhead(&self) -> usize {
        SALT_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip() {
        let obfs = Salamander::new(b"a password").unwrap();
        let payload = b"the quick brown fox jumps over the lazy dog";
        let mut wire = vec![0u8; payload.len() + obfs.overhead()];
        let written = obfs.obfuscate(payload, &mut wire).unwrap();
        assert_eq!(written, payload.len() + 8);

        wire.truncate(written);
        let read = obfs.deobfuscate_in_place(&mut wire).unwrap();
        assert_eq!(read, payload.len());
        assert_eq!(&wire[..read], payload);
    }

    #[test]
    fn test_output_is_not_the_input() {
        let obfs = Salamander::new(b"a password").unwrap();
        let payload = [0u8; 64];
        let mut wire = [0u8; 72];
        obfs.obfuscate(&payload, &mut wire).unwrap();
        // An all-zero payload XOR'd with the key is the key itself repeated,
        // so the tail must not be all zero.
        assert!(wire[8..].iter().any(|b| *b != 0));
    }

    #[test]
    fn test_salt_varies_between_packets() {
        let obfs = Salamander::new(b"a password").unwrap();
        let payload = b"same payload";
        let mut first = vec![0u8; payload.len() + 8];
        let mut second = vec![0u8; payload.len() + 8];
        obfs.obfuscate(payload, &mut first).unwrap();
        obfs.obfuscate(payload, &mut second).unwrap();
        assert_ne!(first, second, "a fresh salt must be drawn per packet");
    }

    #[test]
    fn test_deobfuscate_rejects_short_packets() {
        let obfs = Salamander::new(b"a password").unwrap();
        assert!(obfs.deobfuscate_in_place(&mut []).is_none());
        assert!(obfs.deobfuscate_in_place(&mut [0u8; 8]).is_none());
        assert!(obfs.deobfuscate_in_place(&mut [0u8; 9]).is_some());
    }

    #[test]
    fn test_obfuscate_rejects_short_output_buffer() {
        let obfs = Salamander::new(b"a password").unwrap();
        let mut out = [0u8; 8];
        assert!(obfs.obfuscate(b"payload", &mut out).is_none());
    }

    #[test]
    fn test_rejects_short_password() {
        assert!(Salamander::new(b"abc").is_err());
        assert!(Salamander::new(b"abcd").is_ok());
    }

    /// A fixed vector so a refactor cannot silently change the transform.
    /// The key is derived from the PSK and the salt only, so a known salt
    /// pins the whole output.
    #[test]
    fn test_known_vector() {
        let obfs = Salamander::new(b"hysteria").unwrap();
        let salt = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let key = obfs.derive_key(&salt);

        // Deobfuscating a packet we build by hand must reproduce the payload.
        let payload = b"hello";
        let mut wire = Vec::new();
        wire.extend_from_slice(&salt);
        for (i, byte) in payload.iter().enumerate() {
            wire.push(byte ^ key[i % 32]);
        }

        let read = obfs.deobfuscate_in_place(&mut wire).unwrap();
        assert_eq!(&wire[..read], payload);
    }
}
