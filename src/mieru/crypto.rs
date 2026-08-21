//! mieru key derivation and the direction-scoped cipher.

use std::num::NonZeroU32;

use aws_lc_rs::{digest, pbkdf2};

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

#[cfg(test)]
mod tests {
    use super::*;

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
