# mieru Client Outbound Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** shoes can route traffic through a mieru server over mieru's TCP transport, for both TCP and UDP destinations.

**Architecture:** mieru over TCP is a protocol over a stream, so it becomes a `TcpClientHandler` and composes with shoes' existing chain model. A `MieruStream` wraps the underlying stream and frames segments inline in `poll_read`/`poll_write`; socks5 runs inside that session. Five modules under `src/mieru/`, each with one responsibility: crypto, metadata, padding, frame, stream, plus the handler.

**Tech Stack:** Rust, tokio, `chacha20poly1305` (XChaCha20-Poly1305, already in the graph via awgtun), `aws-lc-rs` (PBKDF2, SHA-256), `subtle` (constant-time comparison).

**Spec:** `docs/superpowers/specs/2026-08-20-mieru-client-outbound-design.md`

---

## Before you start

Read the spec. Then read `AGENTS.md` — it is the working agreement for this
repository and this plan assumes it. The parts that matter most here:

- **The verification gate.** Every task ends with it:
  ```bash
  cargo fmt --all
  cargo clippy --locked --lib --bins --tests -- -D warnings
  cargo test --lib
  ```
  The full gate (bins, integration tests, both FFI configurations) runs before
  the final commit of the feature.
- **Prove a new test can fail.** Write the test first, watch it fail for the
  reason you expect. When a test covers a specific defect, reintroduce the
  defect afterwards and confirm exactly that test goes red.
- **Both crate roots.** A new top-level module must be declared in `src/lib.rs`
  *and* `src/main.rs`, and a module declared before it has a consumer is dead
  code that `-D warnings` rejects. Task 1 handles this deliberately.
- **No secrets in logs or errors.**

Reference implementation, for checking wire details:
`git clone --depth 1 https://github.com/enfein/mieru /tmp/mieru`. The spec cites
file and line for every claim; verify against the source rather than trusting
this plan's prose.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `src/mieru/mod.rs` | Module declarations, shared constants, the public `MieruTcpHandler` re-export |
| `src/mieru/crypto.rs` | Key derivation (SHA-256 → PBKDF2), `DirectionCipher` owning one implicit nonce, user hint |
| `src/mieru/metadata.rs` | The 32-byte metadata formats: encode, parse, protocol-type constants |
| `src/mieru/padding.rs` | Both padding strategies and their length bounds |
| `src/mieru/frame.rs` | Segment codec: assemble and parse the byte layout |
| `src/mieru/stream.rs` | `MieruStream: AsyncStream` — session state machine, fragmentation |
| `src/mieru/client.rs` | `TcpClientHandler`, socks5 inside the session, UDP encapsulation |
| `src/mieru/testing.rs` | `#[cfg(test)]` scripted peer: encodes the bytes a server would send |
| `src/config/types/client.rs` | The `Mieru` config variant |
| `src/config/validate.rs` | Loud rejection of every unimplemented option |
| `src/tcp/tcp_client_handler_factory.rs` | Dispatch to the handler |

---

### Task 1: Module skeleton and constants

**Files:**
- Create: `src/mieru/mod.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `src/mieru/mod.rs`:

```rust
//! The mieru proxy protocol, client side.
//!
//! Wire format verified against enfein/mieru at b9bbc41; see
//! docs/superpowers/specs/2026-08-20-mieru-client-outbound-design.md for the
//! citation table.

/// Nonce size of XChaCha20-Poly1305. `pkg/cipher/api.go:31`.
pub const NONCE_LEN: usize = 24;

/// AEAD tag size. `pkg/cipher/api.go:32`.
pub const TAG_LEN: usize = 16;

/// Fixed metadata size. `docs/protocol.md`, "Metadata Format".
pub const METADATA_LEN: usize = 32;

/// Largest application fragment in one segment. `docs/protocol.md`,
/// "TCP Segment Rules".
pub const MAX_FRAGMENT_LEN: usize = 32768;

/// Largest padding at any position over TCP. `pkg/protocol/padding.go:95`
/// returns 255 for StreamTransport.
pub const MAX_PADDING_LEN: usize = 255;

#[cfg(test)]
mod tests {
    use super::*;

    /// The overhead of a segment carrying a payload: metadata plus its tag,
    /// plus the payload's tag. `pkg/protocol/underlay_stream.go:41` defines
    /// streamOverhead as MetadataLength + DefaultOverhead*2.
    #[test]
    fn test_stream_overhead_matches_upstream() {
        assert_eq!(METADATA_LEN + TAG_LEN * 2, 64);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib mieru`
Expected: FAIL — the module is not declared, so the test does not exist:
`0 tests` or a compile error about an unknown module.

- [ ] **Step 3: Declare the module in the library root only**

In `src/lib.rs`, add in alphabetical position (after `mod logging;`, before
`mod mixed_handler;`):

```rust
pub mod mieru;
```

Do **not** add it to `src/main.rs` yet. `src/lib.rs` carries a crate-wide
`#![allow(dead_code)]`, so the library tolerates a module with no consumer;
`src/main.rs` does not, and would fail the gate until Task 8 wires the handler
in. This is the trap AGENTS.md describes under "The dual crate roots".

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --lib mieru`
Expected: PASS, `1 passed`.

- [ ] **Step 5: Run the gate and commit**

```bash
cargo fmt --all
cargo clippy --locked --lib --bins --tests -- -D warnings
cargo test --lib
git add src/mieru/mod.rs src/lib.rs
git commit -m "mieru: module skeleton and wire constants"
```

---

### Task 2: Key derivation

**Files:**
- Create: `src/mieru/crypto.rs`
- Modify: `src/mieru/mod.rs`

- [ ] **Step 1: Write the failing test**

Create `src/mieru/crypto.rs`:

```rust
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib mieru::crypto`
Expected: FAIL — `src/mieru/crypto.rs` is not declared as a module, so the
tests do not run.

- [ ] **Step 3: Declare the module**

In `src/mieru/mod.rs`, above the constants:

```rust
pub mod crypto;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib mieru::crypto`
Expected: PASS, `4 passed`.

- [ ] **Step 5: Mutation-check the rounding**

Temporarily change `if remainder * 2 >= interval` to `if remainder * 2 > interval`.
Run: `cargo test --lib mieru::crypto`
Expected: `test_rounding_goes_to_the_nearest_boundary` FAILS on the
`round_to_interval(60)` assertion, and nothing else fails. Revert the change.

- [ ] **Step 6: Run the gate and commit**

```bash
cargo fmt --all
cargo clippy --locked --lib --bins --tests -- -D warnings
cargo test --lib
git add src/mieru/crypto.rs src/mieru/mod.rs
git commit -m "mieru: key derivation from password, username and time"
```

---

### Task 3: The direction-scoped cipher

**Files:**
- Modify: `src/mieru/crypto.rs`

- [ ] **Step 1: Write the failing test**

Append to the `tests` module in `src/mieru/crypto.rs`:

```rust
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
```

Add to the imports at the top of the test module:

```rust
    use crate::mieru::NONCE_LEN;
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib mieru::crypto`
Expected: FAIL to compile — `increment_nonce`, `apply_user_hint` and
`DirectionCipher` are not defined.

- [ ] **Step 3: Write the implementation**

Add to `src/mieru/crypto.rs`, above the `tests` module:

```rust
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngExt;

use crate::mieru::{NONCE_LEN, TAG_LEN};

/// Bytes of the nonce hashed to produce the user hint.
/// `pkg/cipher/api.go:35` — NoncePrefixLenForUserHint.
const NONCE_HINT_PREFIX_LEN: usize = 16;

/// Bytes at the end of the nonce replaced by the hint.
const NONCE_HINT_SUFFIX_LEN: usize = 4;

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
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: b"" })
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
            .decrypt(XNonce::from_slice(&nonce), Payload { msg: ciphertext, aad: b"" })
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "mieru decryption failed: wrong password, or the stream desynchronised",
                )
            })
    }
}
```

- [ ] **Step 4: Add the dependency**

`chacha20poly1305` is already in the lockfile through awgtun, but shoes does
not depend on it directly. In `Cargo.toml`, under `[dependencies]`, in
alphabetical position after `chrono`:

```toml
chacha20poly1305 = "0.10"
```

Pin the major rather than using `"*"`: AGENTS.md records that a wildcard let
`digest` flip majors mid-release and break the build.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib mieru::crypto`
Expected: PASS, `12 passed`.

- [ ] **Step 6: Mutation-check the nonce increment**

Temporarily change `for byte in nonce.iter_mut().rev()` to
`for byte in nonce.iter_mut()`.
Run: `cargo test --lib mieru::crypto`
Expected: `test_nonce_increments_from_the_last_byte` and
`test_nonce_carries_across_a_full_byte` FAIL; the round-trip tests still pass,
because both ends make the same mistake — which is exactly why the byte-level
tests exist. Revert.

- [ ] **Step 7: Run the gate and commit**

```bash
cargo fmt --all
cargo clippy --locked --lib --bins --tests -- -D warnings
cargo test --lib
git add src/mieru/crypto.rs Cargo.toml Cargo.lock
git commit -m "mieru: the direction-scoped cipher and its implicit nonce"
```

---

### Task 4: Metadata

**Files:**
- Create: `src/mieru/metadata.rs`
- Modify: `src/mieru/mod.rs`

- [ ] **Step 1: Write the failing test**

Create `src/mieru/metadata.rs`:

```rust
//! The 32-byte segment metadata. `docs/protocol.md`, "Metadata Format".

use crate::mieru::METADATA_LEN;

/// Protocol type values. `docs/protocol.md`.
pub const OPEN_SESSION_REQUEST: u8 = 2;
pub const OPEN_SESSION_RESPONSE: u8 = 3;
pub const CLOSE_SESSION_REQUEST: u8 = 4;
pub const CLOSE_SESSION_RESPONSE: u8 = 5;
pub const DATA_CLIENT_TO_SERVER: u8 = 6;
pub const DATA_SERVER_TO_CLIENT: u8 = 7;
pub const ACK_CLIENT_TO_SERVER: u8 = 8;
pub const ACK_SERVER_TO_CLIENT: u8 = 9;
/// The low-entropy extension. Recognised so it can be refused; never produced.
pub const DATA_CLIENT_TO_SERVER_LOW_ENTROPY: u8 = 10;
pub const DATA_SERVER_TO_CLIENT_LOW_ENTROPY: u8 = 11;

/// Session metadata: protocol types 2 through 5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMetadata {
    pub protocol: u8,
    pub timestamp_minutes: u32,
    pub session_id: u32,
    pub seq: u32,
    pub status: u8,
    pub payload_len: u16,
    pub suffix_len: u8,
}

/// Data metadata: protocol types 6 through 9.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataMetadata {
    pub protocol: u8,
    pub timestamp_minutes: u32,
    pub session_id: u32,
    pub seq: u32,
    pub unack_seq: u32,
    pub window_size: u16,
    pub fragment: u8,
    pub prefix_len: u8,
    pub payload_len: u16,
    pub suffix_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Metadata {
    Session(SessionMetadata),
    Data(DataMetadata),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_metadata_round_trips() {
        let original = SessionMetadata {
            protocol: OPEN_SESSION_REQUEST,
            timestamp_minutes: 0x0a0b0c0d,
            session_id: 0x11223344,
            seq: 0x55667788,
            status: 0,
            payload_len: 1024,
            suffix_len: 7,
        };
        let encoded = encode_session(&original);
        assert_eq!(encoded.len(), METADATA_LEN);
        match parse(&encoded).unwrap() {
            Metadata::Session(parsed) => assert_eq!(parsed, original),
            other => panic!("expected session metadata, got {other:?}"),
        }
    }

    #[test]
    fn test_data_metadata_round_trips() {
        let original = DataMetadata {
            protocol: DATA_CLIENT_TO_SERVER,
            timestamp_minutes: 42,
            session_id: 7,
            seq: 9,
            unack_seq: 3,
            window_size: 512,
            fragment: 2,
            prefix_len: 11,
            payload_len: 4096,
            suffix_len: 13,
        };
        let encoded = encode_data(&original);
        assert_eq!(encoded.len(), METADATA_LEN);
        match parse(&encoded).unwrap() {
            Metadata::Data(parsed) => assert_eq!(parsed, original),
            other => panic!("expected data metadata, got {other:?}"),
        }
    }

    /// Field offsets are the thing a reimplementation gets wrong, so pin the
    /// first bytes of a known encoding rather than only round-tripping.
    #[test]
    fn test_session_field_offsets() {
        let encoded = encode_session(&SessionMetadata {
            protocol: OPEN_SESSION_REQUEST,
            timestamp_minutes: 0x01020304,
            session_id: 0x05060708,
            seq: 0x090a0b0c,
            status: 0x0d,
            payload_len: 0x0e0f,
            suffix_len: 0x10,
        });
        assert_eq!(encoded[0], 2, "protocol type is byte 0");
        assert_eq!(&encoded[2..6], &[1, 2, 3, 4], "timestamp is big-endian at 2");
        assert_eq!(&encoded[6..10], &[5, 6, 7, 8], "session id at 6");
        assert_eq!(&encoded[10..14], &[9, 10, 11, 12], "sequence at 10");
        assert_eq!(encoded[14], 0x0d, "status at 14");
        assert_eq!(&encoded[15..17], &[0x0e, 0x0f], "payload length at 15");
        assert_eq!(encoded[17], 0x10, "suffix length at 17");
    }

    #[test]
    fn test_data_field_offsets() {
        let encoded = encode_data(&DataMetadata {
            protocol: DATA_CLIENT_TO_SERVER,
            timestamp_minutes: 0x01020304,
            session_id: 0x05060708,
            seq: 0x090a0b0c,
            unack_seq: 0x0d0e0f10,
            window_size: 0x1112,
            fragment: 0x13,
            prefix_len: 0x14,
            payload_len: 0x1516,
            suffix_len: 0x17,
        });
        assert_eq!(encoded[0], 6);
        assert_eq!(&encoded[2..6], &[1, 2, 3, 4]);
        assert_eq!(&encoded[6..10], &[5, 6, 7, 8]);
        assert_eq!(&encoded[10..14], &[9, 10, 11, 12]);
        assert_eq!(&encoded[14..18], &[0x0d, 0x0e, 0x0f, 0x10], "unack at 14");
        assert_eq!(&encoded[18..20], &[0x11, 0x12], "window at 18");
        assert_eq!(encoded[20], 0x13, "fragment at 20");
        assert_eq!(encoded[21], 0x14, "prefix length at 21");
        assert_eq!(&encoded[22..24], &[0x15, 0x16], "payload length at 22");
        assert_eq!(encoded[24], 0x17, "suffix length at 24");
    }

    #[test]
    fn test_low_entropy_types_are_refused() {
        let mut encoded = [0u8; METADATA_LEN];
        encoded[0] = DATA_CLIENT_TO_SERVER_LOW_ENTROPY;
        let err = parse(&encoded).unwrap_err();
        assert!(err.to_string().contains("low entropy"), "{err}");

        encoded[0] = DATA_SERVER_TO_CLIENT_LOW_ENTROPY;
        assert!(parse(&encoded).is_err());
    }

    #[test]
    fn test_unknown_protocol_type_is_refused() {
        let mut encoded = [0u8; METADATA_LEN];
        encoded[0] = 99;
        assert!(parse(&encoded).is_err());
    }

    #[test]
    fn test_short_input_is_refused() {
        assert!(parse(&[0u8; METADATA_LEN - 1]).is_err());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib mieru::metadata`
Expected: FAIL to compile — `encode_session`, `encode_data` and `parse` are not
defined, and the module is not declared.

- [ ] **Step 3: Write the implementation**

Add to `src/mieru/metadata.rs`, above the `tests` module:

```rust
pub fn encode_session(meta: &SessionMetadata) -> [u8; METADATA_LEN] {
    let mut out = [0u8; METADATA_LEN];
    out[0] = meta.protocol;
    // out[1] is unused.
    out[2..6].copy_from_slice(&meta.timestamp_minutes.to_be_bytes());
    out[6..10].copy_from_slice(&meta.session_id.to_be_bytes());
    out[10..14].copy_from_slice(&meta.seq.to_be_bytes());
    out[14] = meta.status;
    out[15..17].copy_from_slice(&meta.payload_len.to_be_bytes());
    out[17] = meta.suffix_len;
    // out[18..32] is unused.
    out
}

pub fn encode_data(meta: &DataMetadata) -> [u8; METADATA_LEN] {
    let mut out = [0u8; METADATA_LEN];
    out[0] = meta.protocol;
    // out[1] is unused.
    out[2..6].copy_from_slice(&meta.timestamp_minutes.to_be_bytes());
    out[6..10].copy_from_slice(&meta.session_id.to_be_bytes());
    out[10..14].copy_from_slice(&meta.seq.to_be_bytes());
    out[14..18].copy_from_slice(&meta.unack_seq.to_be_bytes());
    out[18..20].copy_from_slice(&meta.window_size.to_be_bytes());
    out[20] = meta.fragment;
    out[21] = meta.prefix_len;
    out[22..24].copy_from_slice(&meta.payload_len.to_be_bytes());
    out[24] = meta.suffix_len;
    // out[25..32] is unused.
    out
}

pub fn parse(input: &[u8]) -> std::io::Result<Metadata> {
    if input.len() < METADATA_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("mieru metadata is {} bytes, want {METADATA_LEN}", input.len()),
        ));
    }
    let be32 = |at: usize| u32::from_be_bytes([input[at], input[at + 1], input[at + 2], input[at + 3]]);
    let be16 = |at: usize| u16::from_be_bytes([input[at], input[at + 1]]);

    match input[0] {
        protocol @ (OPEN_SESSION_REQUEST | OPEN_SESSION_RESPONSE | CLOSE_SESSION_REQUEST
        | CLOSE_SESSION_RESPONSE) => Ok(Metadata::Session(SessionMetadata {
            protocol,
            timestamp_minutes: be32(2),
            session_id: be32(6),
            seq: be32(10),
            status: input[14],
            payload_len: be16(15),
            suffix_len: input[17],
        })),
        protocol @ (DATA_CLIENT_TO_SERVER | DATA_SERVER_TO_CLIENT | ACK_CLIENT_TO_SERVER
        | ACK_SERVER_TO_CLIENT) => Ok(Metadata::Data(DataMetadata {
            protocol,
            timestamp_minutes: be32(2),
            session_id: be32(6),
            seq: be32(10),
            unack_seq: be32(14),
            window_size: be16(18),
            fragment: input[20],
            prefix_len: input[21],
            payload_len: be16(22),
            suffix_len: input[24],
        })),
        DATA_CLIENT_TO_SERVER_LOW_ENTROPY | DATA_SERVER_TO_CLIENT_LOW_ENTROPY => {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the peer used mieru's low entropy extension, which this client does not implement",
            ))
        }
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown mieru protocol type {other}"),
        )),
    }
}
```

Declare the module in `src/mieru/mod.rs`:

```rust
pub mod metadata;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib mieru::metadata`
Expected: PASS, `7 passed`.

- [ ] **Step 5: Mutation-check an offset**

Temporarily change `out[14..18]` to `out[13..17]` in `encode_data`.
Run: `cargo test --lib mieru::metadata`
Expected: `test_data_field_offsets` FAILS. `test_data_metadata_round_trips` may
still pass, because encode and parse would disagree — which is the point of
pinning offsets separately. Revert.

- [ ] **Step 6: Run the gate and commit**

```bash
cargo fmt --all
cargo clippy --locked --lib --bins --tests -- -D warnings
cargo test --lib
git add src/mieru/metadata.rs src/mieru/mod.rs
git commit -m "mieru: segment metadata codec"
```

---

### Task 5: Padding

**Files:**
- Create: `src/mieru/padding.rs`
- Modify: `src/mieru/mod.rs`

The spec's parity policy applies here: both strategies and their length
distributions are reproduced exactly, but the per-user strategy choice is
seeded from the username alone rather than borrowing mieru's application
version string.

- [ ] **Step 1: Write the failing test**

Create `src/mieru/padding.rs`:

```rust
//! Segment padding. `pkg/protocol/padding.go`.
//!
//! Two strategies, chosen once per connection from the username. Upstream
//! seeds that choice with its own application version string and derives the
//! ASCII run length from the hostname, so byte-for-byte parity with "the" Go
//! client is not a thing that exists. This reproduces both distributions and
//! seeds independently; see the spec's "Traffic-pattern parity".

use aws_lc_rs::digest;
use rand::Rng;

use crate::mieru::MAX_PADDING_LEN;

/// Target probability for the rarer bit. `pkg/protocol/padding.go:31`.
const TARGET_BIT_PROBABILITY: f64 = 0.325;

/// The ASCII run length is drawn from `24 + [0, 17)`.
/// `pkg/protocol/padding.go:30`.
const ASCII_RUN_BASE: usize = 24;
const ASCII_RUN_SPREAD: usize = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingStrategy {
    Ascii,
    Entropy,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strategy_is_stable_for_a_username() {
        let first = PaddingStrategy::for_user(b"alice");
        for _ in 0..10 {
            assert_eq!(PaddingStrategy::for_user(b"alice"), first);
        }
    }

    /// Both strategies must be reachable, or half the parity work is dead.
    #[test]
    fn test_both_strategies_occur_across_usernames() {
        let mut seen_ascii = false;
        let mut seen_entropy = false;
        for i in 0..200u32 {
            match PaddingStrategy::for_user(format!("user{i}").as_bytes()) {
                PaddingStrategy::Ascii => seen_ascii = true,
                PaddingStrategy::Entropy => seen_entropy = true,
            }
        }
        assert!(seen_ascii && seen_entropy);
    }

    #[test]
    fn test_ascii_padding_stays_within_bounds() {
        for _ in 0..100 {
            let padding = build_ascii_padding(MAX_PADDING_LEN);
            assert!(padding.len() <= MAX_PADDING_LEN);
            assert!(padding.len() >= ASCII_RUN_BASE);
        }
    }

    #[test]
    fn test_ascii_padding_contains_a_printable_run() {
        for _ in 0..100 {
            let padding = build_ascii_padding(MAX_PADDING_LEN);
            let longest = longest_printable_run(&padding);
            assert!(
                longest >= ASCII_RUN_BASE,
                "longest printable run was {longest}, want at least {ASCII_RUN_BASE}"
            );
        }
    }

    #[test]
    fn test_ascii_padding_handles_a_tiny_budget() {
        // maxLen below the run length must not panic; the run is clamped.
        let padding = build_ascii_padding(4);
        assert!(padding.len() <= 4);
    }

    #[test]
    fn test_entropy_padding_stays_within_bounds() {
        let existing = [0u8; 100];
        for _ in 0..100 {
            let padding = build_entropy_padding(MAX_PADDING_LEN, &existing);
            assert!(padding.len() <= MAX_PADDING_LEN);
        }
    }

    /// Entropy padding exists to pull the bit distribution toward the target.
    /// Feed it all-zero data and the padding must contain ones.
    #[test]
    fn test_entropy_padding_balances_a_skewed_input() {
        let existing = [0u8; 200];
        let padding = build_entropy_padding(MAX_PADDING_LEN, &existing);
        assert!(!padding.is_empty(), "all-zero data needs padding to balance");
        let ones: u32 = padding.iter().map(|b| b.count_ones()).sum();
        assert!(ones > 0, "the padding must carry the rarer bit");
    }

    fn longest_printable_run(data: &[u8]) -> usize {
        let mut longest = 0;
        let mut current = 0;
        for byte in data {
            if (0x20..=0x7e).contains(byte) {
                current += 1;
                longest = longest.max(current);
            } else {
                current = 0;
            }
        }
        longest
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib mieru::padding`
Expected: FAIL to compile — `for_user`, `build_ascii_padding` and
`build_entropy_padding` are not defined.

- [ ] **Step 3: Write the implementation**

Add to `src/mieru/padding.rs`, above the `tests` module:

```rust
impl PaddingStrategy {
    /// Choose the strategy for a user. Stable for a given username, so a
    /// deployment's traffic keeps one shape rather than alternating.
    pub fn for_user(username: &[u8]) -> Self {
        let digest = digest::digest(&digest::SHA256, username);
        if digest.as_ref()[0] & 1 == 0 {
            PaddingStrategy::Ascii
        } else {
            PaddingStrategy::Entropy
        }
    }

    /// Build padding of at most `max_len` bytes for this strategy.
    ///
    /// `existing` is the segment content the entropy strategy balances
    /// against; the ASCII strategy ignores it.
    pub fn build(&self, max_len: usize, existing: &[u8]) -> Vec<u8> {
        match self {
            PaddingStrategy::Ascii => build_ascii_padding(max_len),
            PaddingStrategy::Entropy => build_entropy_padding(max_len, existing),
        }
    }
}

/// Random bytes with one run forced into printable ASCII, so a segment carries
/// a plausible run of text. `pkg/protocol/padding.go:138-155`.
pub fn build_ascii_padding(max_len: usize) -> Vec<u8> {
    if max_len == 0 {
        return Vec::new();
    }
    let run_len = (ASCII_RUN_BASE + rand::rng().random_range(0..ASCII_RUN_SPREAD)).min(max_len);
    let len = rand::rng().random_range(run_len..=max_len);

    let mut padding = vec![0u8; len];
    rand::rng().fill_bytes(&mut padding);

    let begin = if len > run_len {
        rand::rng().random_range(0..len - run_len)
    } else {
        0
    };
    for byte in &mut padding[begin..begin + run_len] {
        // 0x20..=0x7e is the printable range upstream uses.
        *byte = 0x20 + (*byte % (0x7e - 0x20 + 1));
    }
    padding
}

/// Padding sized so the rarer bit reaches the target probability across the
/// segment. `pkg/protocol/padding.go:156-190`.
pub fn build_entropy_padding(max_len: usize, existing: &[u8]) -> Vec<u8> {
    if max_len == 0 {
        return Vec::new();
    }
    let total_bits = existing.len() * 8;
    let ones: usize = existing.iter().map(|b| b.count_ones() as usize).sum();
    let zeros = total_bits - ones;
    let rarer_count = ones.min(zeros);
    let rarer_bit_is_one = ones <= zeros;

    // Solve rarer = target * (existing + padding) for padding, in bits.
    let needed_bits = (rarer_count as f64 / TARGET_BIT_PROBABILITY) - total_bits as f64;
    let needed_bytes = if needed_bits <= 0.0 {
        0
    } else {
        (needed_bits.ceil() as usize).div_ceil(8)
    };

    let len = if needed_bytes >= max_len {
        max_len
    } else {
        rand::rng().random_range(needed_bytes..=max_len)
    };
    if len == 0 {
        return Vec::new();
    }

    // Fill with the rarer bit so the padding moves the distribution the way
    // the calculation assumed.
    let mut padding = vec![if rarer_bit_is_one { 0xff } else { 0x00 }; len];
    // Perturb a fraction of the bytes so the padding is not a constant run.
    let perturb = len / 4;
    for _ in 0..perturb {
        let at = rand::rng().random_range(0..len);
        padding[at] = rand::rng().random();
    }
    padding
}
```

Add to the imports at the top of the file:

```rust
use rand::RngExt;
```

Declare the module in `src/mieru/mod.rs`:

```rust
pub mod padding;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib mieru::padding`
Expected: PASS, `7 passed`.

- [ ] **Step 5: Mutation-check the printable run**

Temporarily comment out the loop that forces the printable range.
Run: `cargo test --lib mieru::padding`
Expected: `test_ascii_padding_contains_a_printable_run` FAILS. Revert.

- [ ] **Step 6: Run the gate and commit**

```bash
cargo fmt --all
cargo clippy --locked --lib --bins --tests -- -D warnings
cargo test --lib
git add src/mieru/padding.rs src/mieru/mod.rs
git commit -m "mieru: both padding strategies"
```

---

### Task 6: Segment codec

**Files:**
- Create: `src/mieru/frame.rs`
- Modify: `src/mieru/mod.rs`

A segment is
`[padding 0][nonce?][encrypted metadata][tag][padding 1][encrypted payload][tag][padding 2]`.
Over TCP, `padding 0` is not used by the client — upstream emits it only where
a segment needs a leading adjustment, and the receiver locates the metadata by
its fixed position. This codec therefore writes `prefix_len` and `suffix_len`
padding only, which is what the metadata fields describe.

- [ ] **Step 1: Write the failing test**

Create `src/mieru/frame.rs`:

```rust
//! Segment assembly and parsing. `docs/protocol.md`, "Segment Format".

use crate::mieru::crypto::DirectionCipher;
use crate::mieru::metadata::{self, DataMetadata, Metadata, SessionMetadata};
use crate::mieru::padding::PaddingStrategy;
use crate::mieru::{MAX_PADDING_LEN, METADATA_LEN, TAG_LEN};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mieru::crypto::derive_key;
    use crate::mieru::metadata::{DATA_CLIENT_TO_SERVER, OPEN_SESSION_REQUEST};

    fn cipher_pair() -> (DirectionCipher, DirectionCipher) {
        let key = derive_key(b"password", b"user", 120);
        (
            DirectionCipher::new(&key, b"user"),
            DirectionCipher::new(&key, b"user"),
        )
    }

    #[test]
    fn test_a_session_segment_round_trips() {
        let (mut sender, mut receiver) = cipher_pair();
        let meta = SessionMetadata {
            protocol: OPEN_SESSION_REQUEST,
            timestamp_minutes: 5,
            session_id: 99,
            seq: 0,
            status: 0,
            payload_len: 0,
            suffix_len: 0,
        };

        let wire = encode_session_segment(&mut sender, &meta, PaddingStrategy::Ascii).unwrap();
        let (parsed, payload, consumed) = decode_segment(&mut receiver, &wire).unwrap().unwrap();
        assert_eq!(consumed, wire.len());
        assert!(payload.is_empty());
        match parsed {
            Metadata::Session(session) => {
                assert_eq!(session.protocol, OPEN_SESSION_REQUEST);
                assert_eq!(session.session_id, 99);
            }
            other => panic!("expected session metadata, got {other:?}"),
        }
    }

    #[test]
    fn test_a_data_segment_round_trips_with_its_payload() {
        let (mut sender, mut receiver) = cipher_pair();
        let body = b"the quick brown fox";

        let wire =
            encode_data_segment(&mut sender, 99, 1, body, PaddingStrategy::Ascii).unwrap();
        let (parsed, payload, consumed) = decode_segment(&mut receiver, &wire).unwrap().unwrap();
        assert_eq!(consumed, wire.len());
        assert_eq!(payload, body);
        match parsed {
            Metadata::Data(data) => {
                assert_eq!(data.protocol, DATA_CLIENT_TO_SERVER);
                assert_eq!(data.payload_len as usize, body.len());
            }
            other => panic!("expected data metadata, got {other:?}"),
        }
    }

    #[test]
    fn test_both_padding_strategies_produce_decodable_segments() {
        for strategy in [PaddingStrategy::Ascii, PaddingStrategy::Entropy] {
            let (mut sender, mut receiver) = cipher_pair();
            let wire = encode_data_segment(&mut sender, 1, 0, b"payload", strategy).unwrap();
            let (_, payload, _) = decode_segment(&mut receiver, &wire).unwrap().unwrap();
            assert_eq!(payload, b"payload", "strategy {strategy:?} did not round trip");
        }
    }

    /// A partial segment must ask for more rather than erroring: this is the
    /// case that happens constantly on a real socket.
    #[test]
    fn test_an_incomplete_segment_returns_none() {
        let (mut sender, mut receiver) = cipher_pair();
        let wire = encode_data_segment(&mut sender, 1, 0, b"payload", PaddingStrategy::Ascii).unwrap();
        for cut in 1..wire.len() {
            let mut probe = DirectionCipher::new(&derive_key(b"password", b"user", 120), b"user");
            assert!(
                decode_segment(&mut probe, &wire[..cut]).unwrap().is_none(),
                "a {cut}-byte prefix should be incomplete"
            );
        }
        // The whole thing decodes.
        assert!(decode_segment(&mut receiver, &wire).unwrap().is_some());
    }

    #[test]
    fn test_two_segments_decode_in_sequence() {
        let (mut sender, mut receiver) = cipher_pair();
        let mut wire = encode_data_segment(&mut sender, 1, 0, b"first", PaddingStrategy::Ascii).unwrap();
        wire.extend_from_slice(
            &encode_data_segment(&mut sender, 1, 1, b"second", PaddingStrategy::Ascii).unwrap(),
        );

        let (_, first, consumed) = decode_segment(&mut receiver, &wire).unwrap().unwrap();
        assert_eq!(first, b"first");
        let (_, second, _) = decode_segment(&mut receiver, &wire[consumed..]).unwrap().unwrap();
        assert_eq!(second, b"second");
    }

    #[test]
    fn test_a_corrupted_tag_is_rejected() {
        let (mut sender, mut receiver) = cipher_pair();
        let mut wire = encode_data_segment(&mut sender, 1, 0, b"payload", PaddingStrategy::Ascii).unwrap();
        let last = wire.len() - 1;
        wire[last] ^= 0xff;
        // The corruption lands in the trailing padding, which is not
        // authenticated, so flip a metadata byte instead.
        let mut wire2 = encode_data_segment(&mut sender, 1, 1, b"payload", PaddingStrategy::Ascii).unwrap();
        wire2[0] ^= 0xff;
        let mut probe = DirectionCipher::new(&derive_key(b"password", b"user", 120), b"user");
        assert!(decode_segment(&mut probe, &wire2).is_err());
        let _ = receiver;
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib mieru::frame`
Expected: FAIL to compile — `encode_session_segment`, `encode_data_segment` and
`decode_segment` are not defined.

- [ ] **Step 3: Write the implementation**

Add to `src/mieru/frame.rs`, above the `tests` module:

```rust
/// Assemble a session segment: encrypted metadata, then trailing padding.
pub fn encode_session_segment(
    cipher: &mut DirectionCipher,
    meta: &SessionMetadata,
    strategy: PaddingStrategy,
) -> std::io::Result<Vec<u8>> {
    let mut meta = meta.clone();
    let suffix = strategy.build(MAX_PADDING_LEN, &[]);
    meta.suffix_len = suffix.len() as u8;

    let sealed = cipher.seal(&metadata::encode_session(&meta))?;
    let mut out = Vec::with_capacity(sealed.len() + suffix.len());
    out.extend_from_slice(&sealed);
    out.extend_from_slice(&suffix);
    Ok(out)
}

/// Assemble a data segment: encrypted metadata, prefix padding, encrypted
/// payload, trailing padding.
pub fn encode_data_segment(
    cipher: &mut DirectionCipher,
    session_id: u32,
    seq: u32,
    payload: &[u8],
    strategy: PaddingStrategy,
) -> std::io::Result<Vec<u8>> {
    let prefix = strategy.build(MAX_PADDING_LEN, payload);
    let suffix = strategy.build(MAX_PADDING_LEN, payload);

    let meta = DataMetadata {
        protocol: metadata::DATA_CLIENT_TO_SERVER,
        // Minutes since the epoch, as the format requires. A wrong value here
        // does not break decoding; the peer uses it for its own bookkeeping.
        timestamp_minutes: current_timestamp_minutes(),
        session_id,
        seq,
        // Carried because the format has the fields; over TCP neither end
        // acts on them. See the spec, "Metadata".
        unack_seq: 0,
        window_size: 0,
        fragment: 0,
        prefix_len: prefix.len() as u8,
        payload_len: payload.len() as u16,
        suffix_len: suffix.len() as u8,
    };

    let sealed_meta = cipher.seal(&metadata::encode_data(&meta))?;
    let sealed_payload = cipher.seal(payload)?;

    let mut out =
        Vec::with_capacity(sealed_meta.len() + prefix.len() + sealed_payload.len() + suffix.len());
    out.extend_from_slice(&sealed_meta);
    out.extend_from_slice(&prefix);
    out.extend_from_slice(&sealed_payload);
    out.extend_from_slice(&suffix);
    Ok(out)
}

/// Minutes since the Unix epoch, saturating rather than panicking on a broken
/// clock: this field is bookkeeping, not authentication.
fn current_timestamp_minutes() -> u32 {
    let secs = crate::util::unix_time_secs().unwrap_or(0);
    (secs / 60) as u32
}

/// Try to decode one segment from the front of `input`.
///
/// Returns `Ok(None)` when more bytes are needed — the ordinary case on a
/// socket — and consumes nothing from the cipher in that case, so the caller
/// can retry with more data.
#[allow(clippy::type_complexity)]
pub fn decode_segment(
    cipher: &mut DirectionCipher,
    input: &[u8],
) -> std::io::Result<Option<(Metadata, Vec<u8>, usize)>> {
    // Peek at how many bytes the metadata will occupy without disturbing the
    // cipher: the first segment of a direction carries a nonce, later ones do
    // not.
    let meta_len = cipher.sealed_len(METADATA_LEN);
    if input.len() < meta_len {
        return Ok(None);
    }

    // Decode metadata against a clone, so a short segment leaves the real
    // cipher's nonce untouched.
    let mut probe = cipher.clone_state();
    let plaintext = probe.open(&input[..meta_len])?;
    let meta = metadata::parse(&plaintext)?;

    let (prefix_len, payload_len, suffix_len) = match &meta {
        Metadata::Session(session) => (0usize, session.payload_len as usize, session.suffix_len as usize),
        Metadata::Data(data) => (
            data.prefix_len as usize,
            data.payload_len as usize,
            data.suffix_len as usize,
        ),
    };

    let sealed_payload_len = if payload_len > 0 { payload_len + TAG_LEN } else { 0 };
    let total = meta_len + prefix_len + sealed_payload_len + suffix_len;
    if input.len() < total {
        return Ok(None);
    }

    // The segment is complete: commit the metadata decryption to the real
    // cipher and decrypt the payload.
    *cipher = probe;
    let payload = if sealed_payload_len > 0 {
        let at = meta_len + prefix_len;
        cipher.open(&input[at..at + sealed_payload_len])?
    } else {
        Vec::new()
    };

    Ok(Some((meta, payload, total)))
}
```

- [ ] **Step 4: Add the two cipher helpers this needs**

In `src/mieru/crypto.rs`, add to `impl DirectionCipher`:

```rust
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
```

Declare the module in `src/mieru/mod.rs`:

```rust
pub mod frame;
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib mieru::frame`
Expected: PASS, `6 passed`.

- [ ] **Step 6: Mutation-check the incomplete-segment path**

Temporarily change `if input.len() < total` to `if input.len() < meta_len`.
Run: `cargo test --lib mieru::frame`
Expected: `test_an_incomplete_segment_returns_none` FAILS. Revert.

- [ ] **Step 7: Run the gate and commit**

```bash
cargo fmt --all
cargo clippy --locked --lib --bins --tests -- -D warnings
cargo test --lib
git add src/mieru/frame.rs src/mieru/crypto.rs src/mieru/mod.rs
git commit -m "mieru: segment codec"
```

---

### Task 7: The session stream

**Files:**
- Create: `src/mieru/stream.rs`
- Create: `src/mieru/testing.rs`
- Modify: `src/mieru/mod.rs`

- [ ] **Step 1: Write the scripted peer**

Create `src/mieru/testing.rs`:

```rust
//! A scripted mieru peer for tests.
//!
//! This encodes, with this crate's own codec, the bytes a mieru server would
//! send. It is a byte generator, not a server: no user table, no salt window,
//! no quota. What it cannot catch is a shared misreading of the specification
//! — see "What stays unverified" in the spec.

use crate::mieru::crypto::{DirectionCipher, derive_key, round_to_interval};
use crate::mieru::frame::{encode_data_segment, encode_session_segment};
use crate::mieru::metadata::{OPEN_SESSION_RESPONSE, SessionMetadata};
use crate::mieru::padding::PaddingStrategy;

pub const TEST_USERNAME: &[u8] = b"testuser";
pub const TEST_PASSWORD: &[u8] = b"testpassword";

/// The server side of a mieru conversation, as bytes.
pub struct ScriptedPeer {
    pub send: DirectionCipher,
    pub recv: DirectionCipher,
}

impl ScriptedPeer {
    pub fn new(unix_secs: u64) -> Self {
        let key = derive_key(TEST_PASSWORD, TEST_USERNAME, round_to_interval(unix_secs));
        Self {
            send: DirectionCipher::new(&key, TEST_USERNAME),
            recv: DirectionCipher::new(&key, TEST_USERNAME),
        }
    }

    /// The `openSessionResponse` a server answers a request with.
    pub fn open_session_response(&mut self, session_id: u32) -> Vec<u8> {
        encode_session_segment(
            &mut self.send,
            &SessionMetadata {
                protocol: OPEN_SESSION_RESPONSE,
                timestamp_minutes: 0,
                session_id,
                seq: 0,
                status: 0,
                payload_len: 0,
                suffix_len: 0,
            },
            PaddingStrategy::Ascii,
        )
        .expect("encoding an open session response")
    }

    /// A data segment carrying `payload` toward the client.
    pub fn data(&mut self, session_id: u32, seq: u32, payload: &[u8]) -> Vec<u8> {
        encode_data_segment(&mut self.send, session_id, seq, payload, PaddingStrategy::Ascii)
            .expect("encoding a data segment")
    }
}
```

Declare it in `src/mieru/mod.rs`:

```rust
#[cfg(test)]
pub mod testing;
```

- [ ] **Step 2: Write the failing test for the stream**

Create `src/mieru/stream.rs`:

```rust
//! `MieruStream` — one mieru session as an `AsyncStream`.
//!
//! Over TCP the session has no ARQ: `pkg/protocol/session.go:1144-1148` makes
//! ACK handling a no-op for StreamTransport, and TCP already provides ordering
//! and retransmission. So this is framing plus an open/close state machine.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::AsyncStream;
use crate::mieru::MAX_FRAGMENT_LEN;
use crate::mieru::crypto::DirectionCipher;
use crate::mieru::frame::{decode_segment, encode_data_segment};
use crate::mieru::metadata::Metadata;
use crate::mieru::padding::PaddingStrategy;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mieru::testing::{ScriptedPeer, TEST_PASSWORD, TEST_USERNAME};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Connect a MieruStream to a scripted peer over a loopback socket and
    /// return both ends of the conversation.
    async fn connect() -> (MieruStream, tokio::net::TcpStream, ScriptedPeer) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move {
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            MieruStream::open(Box::new(tcp), TEST_PASSWORD, TEST_USERNAME, 1000).await
        });

        let (mut server_tcp, _) = listener.accept().await.unwrap();
        let mut peer = ScriptedPeer::new(1000);

        // Read the client's openSessionRequest, then answer it.
        let mut buf = vec![0u8; 4096];
        let n = server_tcp.read(&mut buf).await.unwrap();
        let (meta, _, _) = decode_segment(&mut peer.recv, &buf[..n]).unwrap().unwrap();
        assert!(matches!(meta, Metadata::Session(_)), "first segment opens the session");

        let response = peer.open_session_response(1);
        server_tcp.write_all(&response).await.unwrap();

        (client.await.unwrap().unwrap(), server_tcp, peer)
    }

    #[tokio::test]
    async fn test_open_completes_the_session_handshake() {
        let (_stream, _server, _peer) = connect().await;
    }

    #[tokio::test]
    async fn test_written_data_arrives_as_a_data_segment() {
        let (mut stream, mut server, mut peer) = connect().await;
        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = server.read(&mut buf).await.unwrap();
        let (_, payload, _) = decode_segment(&mut peer.recv, &buf[..n]).unwrap().unwrap();
        assert_eq!(payload, b"hello");
    }

    #[tokio::test]
    async fn test_a_data_segment_is_readable_as_bytes() {
        let (mut stream, mut server, mut peer) = connect().await;
        let segment = peer.data(1, 1, b"from the server");
        server.write_all(&segment).await.unwrap();

        let mut buf = [0u8; 15];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"from the server");
    }

    #[tokio::test]
    async fn test_a_payload_larger_than_one_fragment_is_split() {
        let (mut stream, mut server, mut peer) = connect().await;
        let payload: Vec<u8> = (0..MAX_FRAGMENT_LEN + 1000).map(|i| i as u8).collect();
        let sent = payload.clone();
        tokio::spawn(async move {
            stream.write_all(&sent).await.unwrap();
            stream.flush().await.unwrap();
        });

        let mut received = Vec::new();
        let mut pending = Vec::new();
        let mut buf = vec![0u8; 65536];
        while received.len() < payload.len() {
            let n = server.read(&mut buf).await.unwrap();
            assert!(n > 0, "the server end closed early");
            pending.extend_from_slice(&buf[..n]);
            while let Some((_, body, consumed)) = decode_segment(&mut peer.recv, &pending).unwrap() {
                received.extend_from_slice(&body);
                pending.drain(..consumed);
            }
        }
        assert_eq!(received, payload);
    }

    /// A segment split across two reads must not be mis-decoded, and must not
    /// advance the nonce twice.
    #[tokio::test]
    async fn test_a_segment_split_across_reads_reassembles() {
        let (mut stream, mut server, mut peer) = connect().await;
        let segment = peer.data(1, 1, b"split me");
        let (first, second) = segment.split_at(segment.len() / 2);
        server.write_all(first).await.unwrap();
        server.flush().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        server.write_all(second).await.unwrap();

        let mut buf = [0u8; 8];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"split me");
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test --lib mieru::stream`
Expected: FAIL to compile — `MieruStream` is not defined.

- [ ] **Step 4: Write the implementation**

Add to `src/mieru/stream.rs`, above the `tests` module:

```rust
use crate::mieru::crypto::{derive_key, round_to_interval};
use crate::mieru::metadata::{OPEN_SESSION_REQUEST, SessionMetadata};
use crate::mieru::frame::encode_session_segment;
use crate::util::write_all;

/// How many bytes to buffer while looking for a segment boundary. A segment
/// is at most metadata, two paddings and a full fragment.
const READ_BUFFER_LEN: usize = MAX_FRAGMENT_LEN + 1024;

pub struct MieruStream {
    inner: Box<dyn AsyncStream>,
    send: DirectionCipher,
    recv: DirectionCipher,
    strategy: PaddingStrategy,
    session_id: u32,
    next_seq: u32,

    /// Bytes read from the socket that have not yet formed a whole segment.
    pending: Vec<u8>,
    /// Decoded payload the caller has not yet read.
    ready: Vec<u8>,
    ready_at: usize,

    /// Bytes staged for the socket by `poll_write`.
    outgoing: Vec<u8>,
    outgoing_at: usize,
}

impl std::fmt::Debug for MieruStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MieruStream")
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

impl MieruStream {
    /// Derive the key, open a session and wait for the server's response.
    pub async fn open(
        mut inner: Box<dyn AsyncStream>,
        password: &[u8],
        username: &[u8],
        unix_secs: u64,
    ) -> std::io::Result<Self> {
        let key = derive_key(password, username, round_to_interval(unix_secs));
        let mut send = DirectionCipher::new(&key, username);
        let mut recv = DirectionCipher::new(&key, username);
        let strategy = PaddingStrategy::for_user(username);

        // Session ids are the peer's bookkeeping; any value works as long as
        // it is consistent for the connection.
        let session_id: u32 = rand::rng().random();

        let request = encode_session_segment(
            &mut send,
            &SessionMetadata {
                protocol: OPEN_SESSION_REQUEST,
                timestamp_minutes: 0,
                session_id,
                seq: 0,
                status: 0,
                payload_len: 0,
                suffix_len: 0,
            },
            strategy,
        )?;
        write_all(&mut inner, &request).await?;
        inner.flush().await?;

        // Await the response before returning, so a wrong password surfaces
        // here rather than on the first read.
        let mut pending = Vec::new();
        let mut buf = vec![0u8; 4096];
        loop {
            let n = inner.read(&mut buf).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "the mieru server closed the connection before answering the session request",
                ));
            }
            pending.extend_from_slice(&buf[..n]);
            if let Some((meta, _, consumed)) = decode_segment(&mut recv, &pending)? {
                match meta {
                    Metadata::Session(_) => {
                        pending.drain(..consumed);
                        break;
                    }
                    Metadata::Data(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "the mieru server sent data before opening the session",
                        ));
                    }
                }
            }
        }

        Ok(Self {
            inner,
            send,
            recv,
            strategy,
            session_id,
            next_seq: 1,
            pending,
            ready: Vec::new(),
            ready_at: 0,
            outgoing: Vec::new(),
            outgoing_at: 0,
        })
    }

    /// Move any complete segment out of `pending` and into `ready`.
    fn drain_pending(&mut self) -> std::io::Result<bool> {
        let mut progressed = false;
        while let Some((meta, payload, consumed)) = decode_segment(&mut self.recv, &self.pending)? {
            self.pending.drain(..consumed);
            progressed = true;
            match meta {
                Metadata::Data(_) => {
                    if !payload.is_empty() {
                        self.ready.extend_from_slice(&payload);
                    }
                }
                // A close request ends the stream; the caller sees EOF once
                // ready is drained.
                Metadata::Session(_) => {}
            }
        }
        Ok(progressed)
    }
}

impl AsyncRead for MieruStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        loop {
            // Hand back anything already decoded.
            if this.ready_at < this.ready.len() {
                let available = &this.ready[this.ready_at..];
                let n = available.len().min(buf.remaining());
                buf.put_slice(&available[..n]);
                this.ready_at += n;
                if this.ready_at == this.ready.len() {
                    this.ready.clear();
                    this.ready_at = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // Read more from the socket.
            let mut chunk = [0u8; 8192];
            let mut chunk_buf = ReadBuf::new(&mut chunk);
            match Pin::new(&mut this.inner).poll_read(cx, &mut chunk_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = chunk_buf.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    if this.pending.len() + filled.len() > READ_BUFFER_LEN {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "mieru segment exceeded the maximum size",
                        )));
                    }
                    this.pending.extend_from_slice(filled);
                    this.drain_pending()?;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for MieruStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        // Finish any staged bytes first, so a segment is never interleaved.
        while this.outgoing_at < this.outgoing.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.outgoing[this.outgoing_at..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "mieru transport accepted no bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => this.outgoing_at += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        this.outgoing.clear();
        this.outgoing_at = 0;

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let take = buf.len().min(MAX_FRAGMENT_LEN);
        let segment = encode_data_segment(
            &mut this.send,
            this.session_id,
            this.next_seq,
            &buf[..take],
            this.strategy,
        )?;
        this.next_seq = this.next_seq.wrapping_add(1);
        this.outgoing = segment;
        this.outgoing_at = 0;

        // Push what we can now; the rest goes out on the next call.
        while this.outgoing_at < this.outgoing.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.outgoing[this.outgoing_at..]) {
                Poll::Ready(Ok(0)) => break,
                Poll::Ready(Ok(n)) => this.outgoing_at += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => break,
            }
        }

        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while this.outgoing_at < this.outgoing.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.outgoing[this.outgoing_at..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "mieru transport accepted no bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => this.outgoing_at += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        this.outgoing.clear();
        this.outgoing_at = 0;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl AsyncStream for MieruStream {}
```

Add these imports at the top of `src/mieru/stream.rs`:

```rust
use rand::{Rng, RngExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
```

Declare the module in `src/mieru/mod.rs`:

```rust
pub mod stream;
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib mieru::stream`
Expected: PASS, `5 passed`.

- [ ] **Step 6: Mutation-check the fragment split**

Temporarily change `let take = buf.len().min(MAX_FRAGMENT_LEN);` to
`let take = buf.len();`.
Run: `cargo test --lib mieru::stream`
Expected: `test_a_payload_larger_than_one_fragment_is_split` FAILS — the
`payload_len` field is a `u16` and a 33768-byte payload truncates. Revert.

- [ ] **Step 7: Run the gate and commit**

```bash
cargo fmt --all
cargo clippy --locked --lib --bins --tests -- -D warnings
cargo test --lib
git add src/mieru/stream.rs src/mieru/testing.rs src/mieru/mod.rs
git commit -m "mieru: the session stream"
```

---

### Task 8: The client handler and config

**Files:**
- Create: `src/mieru/client.rs`
- Modify: `src/mieru/mod.rs`, `src/main.rs`, `src/config/types/client.rs`, `src/tcp/tcp_client_handler_factory.rs`

- [ ] **Step 1: Write the failing test**

Create `src/mieru/client.rs`:

```rust
//! The mieru client handler: a session, with socks5 inside it.

use async_trait::async_trait;

use crate::address::ResolvedLocation;
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::mieru::stream::MieruStream;
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};

/// The marker bytes framing a UDP datagram inside the session.
/// `docs/protocol.md`, "UDP Associate Encapsulation".
const UDP_MARKER_START: u8 = 0x00;
const UDP_MARKER_END: u8 = 0xff;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_encapsulation_frames_a_datagram() {
        let framed = encapsulate_udp(b"payload");
        assert_eq!(framed[0], UDP_MARKER_START);
        assert_eq!(&framed[1..3], &7u16.to_be_bytes());
        assert_eq!(&framed[3..10], b"payload");
        assert_eq!(framed[10], UDP_MARKER_END);
        assert_eq!(framed.len(), 1 + 2 + 7 + 1);
    }

    #[test]
    fn test_udp_decapsulation_round_trips() {
        let framed = encapsulate_udp(b"round trip");
        let (payload, consumed) = decapsulate_udp(&framed).unwrap().unwrap();
        assert_eq!(payload, b"round trip");
        assert_eq!(consumed, framed.len());
    }

    #[test]
    fn test_udp_decapsulation_waits_for_the_whole_datagram() {
        let framed = encapsulate_udp(b"incomplete");
        for cut in 0..framed.len() {
            assert!(
                decapsulate_udp(&framed[..cut]).unwrap().is_none(),
                "a {cut}-byte prefix is incomplete"
            );
        }
    }

    #[test]
    fn test_udp_decapsulation_rejects_bad_markers() {
        let mut framed = encapsulate_udp(b"payload");
        framed[0] = 0x01;
        assert!(decapsulate_udp(&framed).is_err());

        let mut framed = encapsulate_udp(b"payload");
        let last = framed.len() - 1;
        framed[last] = 0x00;
        assert!(decapsulate_udp(&framed).is_err());
    }

    #[test]
    fn test_a_datagram_too_large_to_frame_is_refused() {
        let oversized = vec![0u8; u16::MAX as usize + 1];
        assert!(try_encapsulate_udp(&oversized).is_err());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib mieru::client`
Expected: FAIL to compile — `encapsulate_udp`, `decapsulate_udp` and
`try_encapsulate_udp` are not defined.

- [ ] **Step 3: Write the UDP encapsulation**

Add to `src/mieru/client.rs`, above the `tests` module:

```rust
/// Frame a datagram as `[0x00][u16 len][data][0xff]`, preserving the packet
/// boundary a stream would otherwise lose.
pub fn try_encapsulate_udp(payload: &[u8]) -> std::io::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "UDP datagram of {} bytes exceeds the {} the encapsulation allows",
                payload.len(),
                u16::MAX
            ),
        ));
    }
    let mut out = Vec::with_capacity(1 + 2 + payload.len() + 1);
    out.push(UDP_MARKER_START);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out.push(UDP_MARKER_END);
    Ok(out)
}

#[cfg(test)]
fn encapsulate_udp(payload: &[u8]) -> Vec<u8> {
    try_encapsulate_udp(payload).expect("the test payload fits")
}

/// Recover one datagram. `Ok(None)` means more bytes are needed.
#[allow(clippy::type_complexity)]
pub fn decapsulate_udp(input: &[u8]) -> std::io::Result<Option<(Vec<u8>, usize)>> {
    if input.len() < 3 {
        return Ok(None);
    }
    if input[0] != UDP_MARKER_START {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "mieru UDP encapsulation has a wrong start marker",
        ));
    }
    let len = u16::from_be_bytes([input[1], input[2]]) as usize;
    let total = 1 + 2 + len + 1;
    if input.len() < total {
        return Ok(None);
    }
    if input[total - 1] != UDP_MARKER_END {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "mieru UDP encapsulation has a wrong end marker",
        ));
    }
    Ok(Some((input[3..3 + len].to_vec(), total)))
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib mieru::client`
Expected: PASS, `5 passed`.

- [ ] **Step 5: Write the handler**

Append to `src/mieru/client.rs`, above the `tests` module:

```rust
/// The mieru client handler.
///
/// A connection is one mieru session carrying one socks5 request, which is
/// what `MULTIPLEXING_OFF` looks like on the wire.
#[derive(Debug)]
pub struct MieruTcpHandler {
    username: Vec<u8>,
    password: Vec<u8>,
}

impl MieruTcpHandler {
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.as_bytes().to_vec(),
            password: password.as_bytes().to_vec(),
        }
    }

    async fn open_session(
        &self,
        client_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<MieruStream> {
        let now = crate::util::unix_time_secs().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "mieru derives its key from the current time, and this clock is unusable: {e}"
                ),
            )
        })?;
        MieruStream::open(client_stream, &self.password, &self.username, now).await
    }
}

#[async_trait]
impl TcpClientHandler for MieruTcpHandler {
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let mut session = self.open_session(client_stream).await?;
        crate::socks_handler::write_socks5_connect_request(
            &mut session,
            &remote_location.into_location(),
        )
        .await?;
        Ok(TcpClientSetupResult {
            client_stream: Box::new(session) as Box<dyn AsyncStream>,
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        true
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        let mut session = self.open_session(client_stream).await?;
        crate::socks_handler::write_socks5_udp_associate_request(
            &mut session,
            &target.into_location(),
        )
        .await?;
        Ok(Box::new(MieruUdpStream::new(session)))
    }
}
```

**Note for the implementer:** `write_socks5_connect_request` and
`write_socks5_udp_associate_request` may not exist under those names in
`src/socks_handler.rs`. Before writing this, run
`grep -n "pub async fn\|pub fn" src/socks_handler.rs` and use the existing
client-side request helpers. If the file has no reusable helper — the socks5
code may be server-only — write the request encoder in `src/mieru/client.rs`
instead: a socks5 request is `[0x05][cmd][0x00][addr_type][addr][u16 port]`,
with `cmd` 0x01 for CONNECT and 0x03 for UDP ASSOCIATE, and the reply is
`[0x05][status][0x00][addr_type][addr][u16 port]` where status 0x00 is success.
`src/socks5_udp_relay.rs` already encodes and parses socks5 addresses; reuse it.

- [ ] **Step 6: Write `MieruUdpStream`**

This wraps the session as an `AsyncMessageStream`, applying the encapsulation
from Step 3. Append to `src/mieru/client.rs`:

```rust
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::ReadBuf;

use crate::async_stream::{
    AsyncFlushMessage, AsyncPing, AsyncReadMessage, AsyncShutdownMessage, AsyncWriteMessage,
};

/// A mieru session carrying socks5 UDP-associate traffic.
pub struct MieruUdpStream {
    session: MieruStream,
    pending: Vec<u8>,
}

impl std::fmt::Debug for MieruUdpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MieruUdpStream").finish_non_exhaustive()
    }
}

impl MieruUdpStream {
    pub fn new(session: MieruStream) -> Self {
        Self {
            session,
            pending: Vec::new(),
        }
    }
}

impl AsyncReadMessage for MieruUdpStream {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if let Some((payload, consumed)) = decapsulate_udp(&this.pending)? {
                this.pending.drain(..consumed);
                if payload.len() > buf.remaining() {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "mieru UDP datagram is larger than the read buffer",
                    )));
                }
                buf.put_slice(&payload);
                return Poll::Ready(Ok(()));
            }

            let mut chunk = [0u8; 8192];
            let mut chunk_buf = ReadBuf::new(&mut chunk);
            match Pin::new(&mut this.session).poll_read(cx, &mut chunk_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = chunk_buf.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    this.pending.extend_from_slice(filled);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWriteMessage for MieruUdpStream {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let framed = try_encapsulate_udp(buf)?;
        match Pin::new(&mut this.session).poll_write(cx, &framed) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncFlushMessage for MieruUdpStream {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.session).poll_flush(cx)
    }
}

impl AsyncShutdownMessage for MieruUdpStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.session).poll_shutdown(cx)
    }
}

impl AsyncPing for MieruUdpStream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncMessageStream for MieruUdpStream {}
```

Add at the top of the file:

```rust
use tokio::io::{AsyncRead, AsyncWrite};
```

Declare the module in `src/mieru/mod.rs`:

```rust
pub mod client;

pub use client::MieruTcpHandler;
```

- [ ] **Step 7: Add the config variant**

In `src/config/types/client.rs`, add to the `ClientProxyConfig` enum after the
`Trojan` variant:

```rust
    Mieru {
        username: String,
        password: Redacted<String>,
    },
```

And in the name function alongside `ClientProxyConfig::Trojan { .. } => "Trojan",`:

```rust
            ClientProxyConfig::Mieru { .. } => "mieru",
```

- [ ] **Step 8: Wire the factory**

In `src/tcp/tcp_client_handler_factory.rs`, add a match arm alongside the
`Trojan` one:

```rust
        ClientProxyConfig::Mieru { username, password } => {
            Box::new(crate::mieru::MieruTcpHandler::new(&username, password.expose()))
        }
```

- [ ] **Step 9: Declare the module in the binary root**

Now that the binary uses `crate::mieru`, add to `src/main.rs` in alphabetical
position (after `mod logging;`, before `mod mixed_handler;`):

```rust
mod mieru;
```

- [ ] **Step 10: Write the config test**

Add to the tests module in `src/config/types/client.rs`:

```rust
    #[test]
    fn test_mieru_client_config_parses() {
        let config: ClientConfig = serde_yaml::from_str(
            "
address: example.com:8080
protocol:
  type: mieru
  username: alice
  password: hunter2
",
        )
        .unwrap();
        match config.protocol {
            ClientProxyConfig::Mieru { username, password } => {
                assert_eq!(username, "alice");
                assert_eq!(password.expose(), "hunter2");
            }
            other => panic!("expected mieru, got {other:?}"),
        }
    }

    #[test]
    fn test_mieru_password_is_redacted_in_debug_output() {
        let config: ClientConfig = serde_yaml::from_str(
            "
address: example.com:8080
protocol:
  type: mieru
  username: alice
  password: hunter2
",
        )
        .unwrap();
        let debug = format!("{:?}", config);
        assert!(!debug.contains("hunter2"), "the password leaked into Debug: {debug}");
    }
```

- [ ] **Step 11: Run everything**

Run: `cargo test --lib mieru`
Expected: PASS, all mieru tests.

Run: `cargo test --lib config`
Expected: PASS, including the two new config tests.

- [ ] **Step 12: Run the gate and commit**

```bash
cargo fmt --all
cargo clippy --locked --lib --bins --tests -- -D warnings
cargo test --lib
cargo test --bins
git add src/mieru/ src/main.rs src/config/types/client.rs src/tcp/tcp_client_handler_factory.rs
git commit -m "mieru: client handler, config and factory wiring"
```

---

### Task 9: Loud config rejections

**Files:**
- Modify: `src/config/validate.rs`

The spec requires every unimplemented option a user could plausibly write to be
rejected by name rather than ignored. Since the `Mieru` config variant defines
only `username` and `password`, serde's `deny_unknown_fields` already rejects
the others — but the error says "unknown field", which tells a user their
config is malformed rather than that shoes has not implemented the feature.

- [ ] **Step 1: Write the failing test**

Add to the tests module in `src/config/validate.rs`:

```rust
    #[tokio::test]
    async fn test_mieru_rejects_the_udp_transport_by_name() {
        let yaml = "
address: example.com:8080
protocol:
  type: mieru
  username: alice
  password: hunter2
  transport: udp
";
        let err = serde_yaml::from_str::<ClientConfig>(yaml).unwrap_err().to_string();
        assert!(
            err.contains("transport"),
            "the error should name the field the user wrote: {err}"
        );
    }
```

- [ ] **Step 2: Run the test to verify it fails or passes for the wrong reason**

Run: `cargo test --lib config::validate::tests::test_mieru_rejects`
Expected: The test may already PASS through serde's unknown-field error. Read
the message. If it says only "unknown field `transport`", that is the outcome
this task improves on.

- [ ] **Step 3: Add explicit fields that are rejected with a real explanation**

In `src/config/types/client.rs`, extend the variant:

```rust
    Mieru {
        username: String,
        password: Redacted<String>,
        /// mieru's UDP transport, which this client does not implement.
        /// Accepted by the parser so validation can explain why, rather than
        /// reporting an unknown field.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transport: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        multiplexing: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        low_entropy: Option<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port_range: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        handshake_mode: Option<String>,
    },
```

Update the factory arm in `src/tcp/tcp_client_handler_factory.rs` to destructure
the new fields:

```rust
        ClientProxyConfig::Mieru {
            username, password, ..
        } => Box::new(crate::mieru::MieruTcpHandler::new(&username, password.expose())),
```

- [ ] **Step 4: Add the validation**

In `src/config/validate.rs`, in the function that validates client configs —
find it with `grep -n "ClientProxyConfig::" src/config/validate.rs` and follow
the existing pattern, for example the TUIC `zero_rtt_handshake` rejection near
line 1026 — add:

```rust
        ClientProxyConfig::Mieru {
            transport,
            multiplexing,
            low_entropy,
            port_range,
            handshake_mode,
            ..
        } => {
            let unimplemented: [(&str, bool); 5] = [
                (
                    "transport: mieru's UDP transport needs its reliability layer, which this client does not implement. Use the TCP transport, which upstream recommends anyway.",
                    transport.as_deref().is_some_and(|t| !t.eq_ignore_ascii_case("tcp")),
                ),
                (
                    "multiplexing: this client opens one session per connection, equivalent to mieru's MULTIPLEXING_OFF.",
                    multiplexing.as_deref().is_some_and(|m| !m.eq_ignore_ascii_case("off")),
                ),
                (
                    "low_entropy: the low entropy encoding is not implemented.",
                    low_entropy.is_some_and(|mode| mode != 0),
                ),
                (
                    "port_range: this client connects to a single port per endpoint.",
                    port_range.is_some(),
                ),
                (
                    "handshake_mode: only the standard 1-RTT handshake is implemented.",
                    handshake_mode
                        .as_deref()
                        .is_some_and(|m| !m.eq_ignore_ascii_case("standard")),
                ),
            ];
            for (message, rejected) in unimplemented {
                if rejected {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("The mieru client outbound does not support {message}"),
                    ));
                }
            }
        }
```

- [ ] **Step 5: Replace the test with one that checks the real message**

Replace the test from Step 1 with:

```rust
    #[tokio::test]
    async fn test_mieru_rejects_every_unimplemented_option() {
        for (field, value) in [
            ("transport", "udp"),
            ("multiplexing", "high"),
            ("low_entropy", "1"),
            ("port_range", "8000-9000"),
            ("handshake_mode", "no_wait"),
        ] {
            let yaml = format!(
                "
address: example.com:8080
protocol:
  type: mieru
  username: alice
  password: hunter2
  {field}: {value}
"
            );
            let config: ClientConfig = serde_yaml::from_str(&yaml)
                .unwrap_or_else(|e| panic!("{field} should parse so validation can explain: {e}"));
            let err = validate_client_config(&config)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains(field),
                "rejecting {field} should name it: {err}"
            );
            assert!(
                err.contains("does not support"),
                "rejecting {field} should explain, not just refuse: {err}"
            );
        }
    }

    #[tokio::test]
    async fn test_mieru_accepts_the_implemented_settings() {
        let yaml = "
address: example.com:8080
protocol:
  type: mieru
  username: alice
  password: hunter2
  transport: tcp
  multiplexing: off
  low_entropy: 0
";
        let config: ClientConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(validate_client_config(&config).is_ok());
    }
```

**Note for the implementer:** `validate_client_config` is a placeholder for
whatever the real entry point is. Find it with
`grep -n "fn validate.*client" src/config/validate.rs` and call that, matching
the signature the neighbouring tests use.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test --lib config::validate::tests::test_mieru`
Expected: PASS, `2 passed`.

- [ ] **Step 7: Run the gate and commit**

```bash
cargo fmt --all
cargo clippy --locked --lib --bins --tests -- -D warnings
cargo test --lib
git add src/config/types/client.rs src/config/validate.rs src/tcp/tcp_client_handler_factory.rs
git commit -m "mieru: reject unimplemented options by name"
```

---

### Task 10: Documentation, example and CI

**Files:**
- Modify: `CONFIG.md`, `README.md`, `ROADMAP.md`, `.github/workflows/build.yml`
- Create: `examples/mieru_client.yaml`

- [ ] **Step 1: Write the example config**

Create `examples/mieru_client.yaml`:

```yaml
# Route everything through a mieru server.
#
# mieru derives its encryption key from the current time, rounded to two
# minutes, so the client and the server clocks must agree to within about four
# minutes. A device whose clock has not synchronised cannot authenticate.
- address: 0.0.0.0:1080
  protocol: socks
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_proxies:
        - address: mieru.example.com:8080
          protocol:
            type: mieru
            username: alice
            password: hunter2
```

- [ ] **Step 2: Verify the example parses**

```bash
cargo run --bin shoes -- --dry-run examples/mieru_client.yaml
```

Expected: exits 0 and prints the parsed configuration.

- [ ] **Step 3: Add it to the CI dry-run list**

In `.github/workflows/build.yml`, in the `Smoke test binary` step, add
`mieru_client` to the `for cfg in ...` list:

```yaml
          for cfg in socks_basic multi_hop_chain tun_vpn tun_fake_ip amneziawg_client sniff \
                     hysteria2_client tuic_client mieru_client; do
```

- [ ] **Step 4: Document the protocol in CONFIG.md**

Find the client protocol section — `grep -n "^### Trojan\|^#### Trojan" CONFIG.md`
— and add an entry in the same shape as its neighbours:

```markdown
#### mieru

A client outbound for the [mieru](https://github.com/enfein/mieru) protocol,
over mieru's TCP transport.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `username` | string | required | The mieru user name. Part of the key derivation, so it must match the server. |
| `password` | string | required | The mieru password. |

The key is derived from the current time rounded to two minutes, so the client
and server clocks must agree to within about four minutes.

Not implemented, and rejected with an explanation if configured: mieru's UDP
transport, session multiplexing, the low entropy encoding, port ranges, and the
0-RTT handshake mode. UDP destinations still work — mieru carries socks5
UDP-associate inside its TCP session.
```

- [ ] **Step 5: Add the protocol to the README list**

Find the client protocol list — `grep -n "Trojan" README.md` — and add mieru to
it in the same style as its neighbours.

- [ ] **Step 6: Record the unverified interoperability in ROADMAP.md**

The spec requires this. Add to `ROADMAP.md`, under a heading that fits the
file's structure:

```markdown
### mieru: not yet verified against a real server

The mieru client outbound is tested against a scripted peer built from this
repository's own codec, which cannot detect a shared misreading of the
specification: encode a field wrongly, decode it wrongly to match, and every
test passes. It has not completed a round trip against upstream's `mita`
server or a real deployment, so it must not be described as working until
someone runs one. Implementing a mieru server here would close this
permanently by turning the scripted peer into a real interoperability test.
```

- [ ] **Step 7: Run the full gate**

```bash
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --locked --lib --bins --tests -- -D warnings
cargo clippy --locked --features ffi --lib --tests -- -D warnings
cargo clippy --locked --features ffi --bins -- -D warnings
cargo test --lib
cargo test --bins
cargo test --test '*'
```

Expected: all green.

- [ ] **Step 8: Commit**

```bash
git add CONFIG.md README.md ROADMAP.md examples/mieru_client.yaml .github/workflows/build.yml
git commit -m "mieru: document the outbound and record what is unverified"
```

---

## After the plan

The feature is complete but **not verified against a real mieru server**. Task
10 Step 6 records this in `ROADMAP.md` and it is the honest state to ship in.

To close it, run upstream's server and dial it:

```bash
git clone --depth 1 https://github.com/enfein/mieru /tmp/mieru
cd /tmp/mieru && make   # produces the mita server and mieru client binaries
```

Configure `mita` with a user matching `examples/mieru_client.yaml`, start it,
point shoes at it, and fetch a page through the socks5 listener. If it works,
remove the ROADMAP entry and say so in the commit. If it does not, the failure
is a specification misreading and the fix belongs in whichever codec module got
the field wrong — the scripted peer will need the same correction, since it
shares the codec.
