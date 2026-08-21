//! mieru key derivation and the direction-scoped cipher.

use std::num::NonZeroU32;

use aws_lc_rs::{digest, pbkdf2};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::Rng;

use crate::mieru::{NONCE_LEN, TAG_LEN};

/// Bytes of the nonce hashed to produce the user hint.
/// `pkg/cipher/api.go:35` — NoncePrefixLenForUserHint.
const NONCE_HINT_PREFIX_LEN: usize = 16;

/// Bytes at the end of the nonce replaced by the hint.
const NONCE_HINT_SUFFIX_LEN: usize = 4;

/// PBKDF2 iterations. `pkg/cipher/keygen.go:32` — "This is part of mieru
/// protocol. This value should not be changed."
const KEY_ITERATIONS: u32 = 64;

/// The salt changes every 2 minutes. `pkg/cipher/keygen.go:37`.
pub const KEY_REFRESH_INTERVAL_SECS: u64 = 120;

/// Derived key length in bytes.
pub const KEY_LEN: usize = 32;

/// `hashedPassword = SHA-256(password ‖ 0x00 ‖ username)`.
/// `pkg/cipher/api.go:149`.
pub fn hash_password(password: &[u8], username: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(password.len() + 1 + username.len());
    input.extend_from_slice(password);
    input.push(0x00);
    input.extend_from_slice(username);
    let digest = digest::digest(&digest::SHA256, &input);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// Round to the nearest 2-minute boundary, matching Go's `Time.Round`, which
/// rounds half away from zero. `pkg/cipher/keygen.go:57`.
pub fn round_to_interval(unix_secs: u64) -> u64 {
    let interval = KEY_REFRESH_INTERVAL_SECS;
    let remainder = unix_secs % interval;
    if remainder * 2 >= interval {
        unix_secs - remainder + interval
    } else {
        unix_secs - remainder
    }
}

/// `timeSalt = SHA-256(be64(roundedUnixSeconds))`. `pkg/cipher/keygen.go:64-69`.
pub fn time_salt(rounded_unix_secs: u64) -> [u8; 32] {
    let digest = digest::digest(&digest::SHA256, &rounded_unix_secs.to_be_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// The full derivation: hashed password, time salt, PBKDF2.
pub fn derive_key(password: &[u8], username: &[u8], rounded_unix_secs: u64) -> [u8; KEY_LEN] {
    let hashed = hash_password(password, username);
    let salt = time_salt(rounded_unix_secs);
    let mut key = [0u8; KEY_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(KEY_ITERATIONS).expect("the iteration count is a non-zero literal"),
        &salt,
        &hashed,
        &mut key,
    );
    key
}

/// Increment the nonce by one, big-endian from the last byte.
/// `pkg/cipher/cipher.go:359`.
pub fn increment_nonce(nonce: &mut [u8; NONCE_LEN]) {
    for byte in nonce.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

/// Replace the last 4 bytes with the first 4 bytes of
/// `SHA-256(username ‖ nonce[0..16])`, so a server can find the user without
/// trying every key. `pkg/cipher/cipher.go:380-396`.
pub fn apply_user_hint(nonce: &mut [u8; NONCE_LEN], username: &[u8]) {
    let mut input = Vec::with_capacity(username.len() + NONCE_HINT_PREFIX_LEN);
    input.extend_from_slice(username);
    input.extend_from_slice(&nonce[..NONCE_HINT_PREFIX_LEN]);
    let digest = digest::digest(&digest::SHA256, &input);
    nonce[NONCE_LEN - NONCE_HINT_SUFFIX_LEN..]
        .copy_from_slice(&digest.as_ref()[..NONCE_HINT_SUFFIX_LEN]);
}

/// One direction of a mieru stream.
///
/// The nonce is implicit: it travels once, in the first segment of the
/// direction, and both ends increment their own copy on every operation
/// afterwards. Each direction therefore owns its own cipher, and nothing is
/// shared between tasks.
pub struct DirectionCipher {
    aead: XChaCha20Poly1305,
    username: Vec<u8>,
    nonce: Option<[u8; NONCE_LEN]>,
}

impl std::fmt::Debug for DirectionCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No key, no username, no nonce: this type is all secret.
        f.debug_struct("DirectionCipher").finish_non_exhaustive()
    }
}

impl DirectionCipher {
    pub fn new(key: &[u8; KEY_LEN], username: &[u8]) -> Self {
        Self {
            aead: XChaCha20Poly1305::new(key.into()),
            username: username.to_vec(),
            nonce: None,
        }
    }

    /// Bytes on the wire for a sealed message of `plaintext_len`, accounting
    /// for the nonce the first message of a direction carries.
    pub fn sealed_len(&self, plaintext_len: usize) -> usize {
        let nonce = if self.nonce.is_none() { NONCE_LEN } else { 0 };
        nonce + plaintext_len + TAG_LEN
    }

    /// A copy that can be advanced speculatively and either committed or
    /// discarded. Decoding a segment needs this because a short read must not
    /// advance the nonce.
    pub fn clone_state(&self) -> Self {
        Self {
            aead: self.aead.clone(),
            username: self.username.clone(),
            nonce: self.nonce,
        }
    }

    /// Encrypt one message. The first call prepends the nonce.
    pub fn seal(&mut self, plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
        let first = self.nonce.is_none();
        let nonce = match self.nonce.as_mut() {
            Some(nonce) => {
                increment_nonce(nonce);
                *nonce
            }
            None => {
                let mut nonce = [0u8; NONCE_LEN];
                rand::rng().fill_bytes(&mut nonce);
                apply_user_hint(&mut nonce, &self.username);
                self.nonce = Some(nonce);
                nonce
            }
        };

        let ciphertext = self
            .aead
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: b"",
                },
            )
            .map_err(|_| std::io::Error::other("mieru encryption failed"))?;

        if first {
            let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&ciphertext);
            Ok(out)
        } else {
            Ok(ciphertext)
        }
    }

    /// Decrypt one message. The first call consumes the leading nonce.
    pub fn open(&mut self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        let (nonce, ciphertext) = match self.nonce.as_mut() {
            Some(nonce) => {
                increment_nonce(nonce);
                (*nonce, data)
            }
            None => {
                if data.len() < NONCE_LEN + TAG_LEN {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "mieru segment is too short to carry a nonce",
                    ));
                }
                let mut nonce = [0u8; NONCE_LEN];
                nonce.copy_from_slice(&data[..NONCE_LEN]);
                self.nonce = Some(nonce);
                (nonce, &data[NONCE_LEN..])
            }
        };

        self.aead
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: b"",
                },
            )
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "mieru decryption failed: wrong password, or the stream desynchronised",
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mieru::NONCE_LEN;

    #[test]
    fn test_nonce_increments_from_the_last_byte() {
        let mut nonce = [0u8; NONCE_LEN];
        increment_nonce(&mut nonce);
        assert_eq!(nonce[NONCE_LEN - 1], 1);
        assert_eq!(nonce[0], 0);
    }

    /// The carry is the part that is easy to get wrong, and getting it wrong
    /// desynchronises a stream only after 256 segments.
    #[test]
    fn test_nonce_carries_across_a_full_byte() {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[NONCE_LEN - 1] = 0xff;
        increment_nonce(&mut nonce);
        assert_eq!(nonce[NONCE_LEN - 1], 0);
        assert_eq!(nonce[NONCE_LEN - 2], 1);
    }

    #[test]
    fn test_nonce_wraps_from_all_ones_to_all_zeros() {
        let mut nonce = [0xffu8; NONCE_LEN];
        increment_nonce(&mut nonce);
        assert_eq!(nonce, [0u8; NONCE_LEN]);
    }

    #[test]
    fn test_user_hint_overwrites_the_last_four_bytes() {
        let mut nonce = [7u8; NONCE_LEN];
        let before = nonce;
        apply_user_hint(&mut nonce, b"alice");
        assert_eq!(nonce[..NONCE_LEN - 4], before[..NONCE_LEN - 4]);
        assert_ne!(nonce[NONCE_LEN - 4..], before[NONCE_LEN - 4..]);
    }

    #[test]
    fn test_user_hint_is_stable_for_the_same_user_and_prefix() {
        let mut a = [3u8; NONCE_LEN];
        let mut b = [3u8; NONCE_LEN];
        apply_user_hint(&mut a, b"alice");
        apply_user_hint(&mut b, b"alice");
        assert_eq!(a, b);
        let mut c = [3u8; NONCE_LEN];
        apply_user_hint(&mut c, b"bob");
        assert_ne!(a, c);
    }

    #[test]
    fn test_a_cipher_pair_round_trips_several_segments() {
        let key = derive_key(b"password", b"user", 120);
        let mut sender = DirectionCipher::new(&key, b"user");
        let mut receiver = DirectionCipher::new(&key, b"user");

        // The first encryption emits the nonce; the receiver adopts it.
        let first = sender.seal(b"one").unwrap();
        assert_eq!(first.len(), NONCE_LEN + 3 + TAG_LEN);
        assert_eq!(receiver.open(&first).unwrap(), b"one");

        // Subsequent ones do not carry it.
        let second = sender.seal(b"two").unwrap();
        assert_eq!(second.len(), 3 + TAG_LEN);
        assert_eq!(receiver.open(&second).unwrap(), b"two");

        let third = sender.seal(b"three").unwrap();
        assert_eq!(receiver.open(&third).unwrap(), b"three");
    }

    /// Skipping one segment must not silently decode the next: that is what
    /// makes a desynchronised stream detectable rather than corrupt.
    #[test]
    fn test_a_skipped_segment_breaks_the_stream() {
        let key = derive_key(b"password", b"user", 120);
        let mut sender = DirectionCipher::new(&key, b"user");
        let mut receiver = DirectionCipher::new(&key, b"user");

        let first = sender.seal(b"one").unwrap();
        receiver.open(&first).unwrap();
        let _skipped = sender.seal(b"two").unwrap();
        let third = sender.seal(b"three").unwrap();
        assert!(receiver.open(&third).is_err());
    }

    #[test]
    fn test_a_wrong_key_fails_to_open() {
        let key = derive_key(b"password", b"user", 120);
        let wrong = derive_key(b"wrong", b"user", 120);
        let mut sender = DirectionCipher::new(&key, b"user");
        let mut receiver = DirectionCipher::new(&wrong, b"user");
        let sealed = sender.seal(b"payload").unwrap();
        assert!(receiver.open(&sealed).is_err());
    }

    #[test]
    fn test_hash_password_separates_with_a_zero_byte() {
        // "ab" + username "c" must differ from "a" + username "bc": the 0x00
        // separator is what stops the two from colliding.
        assert_ne!(hash_password(b"ab", b"c"), hash_password(b"a", b"bc"));
    }

    #[test]
    fn test_rounding_goes_to_the_nearest_boundary() {
        assert_eq!(round_to_interval(0), 0);
        assert_eq!(round_to_interval(59), 0);
        // Exactly half rounds away from zero, as Go's Time.Round does.
        assert_eq!(round_to_interval(60), 120);
        assert_eq!(round_to_interval(119), 120);
        assert_eq!(round_to_interval(120), 120);
        assert_eq!(round_to_interval(121), 120);
    }

    #[test]
    fn test_the_key_depends_on_every_input() {
        let base = derive_key(b"password", b"user", 120);
        assert_ne!(derive_key(b"other", b"user", 120), base);
        assert_ne!(derive_key(b"password", b"other", 120), base);
        assert_ne!(derive_key(b"password", b"user", 240), base);
    }

    #[test]
    fn test_the_key_is_stable_within_one_interval() {
        // Every second inside a 2-minute window rounds to the same salt, which
        // is what lets a client and a server agree without exact clocks.
        let a = derive_key(b"password", b"user", round_to_interval(1000));
        let b = derive_key(b"password", b"user", round_to_interval(1010));
        assert_eq!(a, b);
    }
}
