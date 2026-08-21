//! A scripted mieru peer for tests.
//!
//! This encodes, with this crate's own codec, the bytes a mieru server would
//! send. It is a byte generator, not a server: no user table, no salt window,
//! no quota. What it cannot catch is a shared misreading of the specification
//! — encode a field wrongly, decode it wrongly to match, and every test here
//! passes. See "What stays unverified" in the design document.

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
        encode_data_segment(&mut self.send, session_id, seq, payload)
            .expect("encoding a data segment")
    }
}
