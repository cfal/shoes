//! Segment assembly and parsing. `docs/protocol.md`, "Segment Format".
//!
//! A segment is
//! `[padding 0][nonce?][encrypted metadata][tag][padding 1][encrypted payload][tag][padding 2]`.
//! The client does not emit `padding 0`: the receiver locates the metadata by
//! its fixed position, and the metadata's own `prefix_len` and `suffix_len`
//! describe the two paddings this codec writes.

use crate::mieru::crypto::DirectionCipher;
use crate::mieru::metadata::{self, DataMetadata, Metadata, SessionMetadata};
use crate::mieru::padding::{PaddingStrategy, build_data_padding};
use rand::Rng;

use crate::mieru::{MAX_PADDING_LEN, METADATA_LEN, TAG_LEN};

/// What a segment costs before payload and padding: the metadata, its tag and
/// the payload's tag. `pkg/protocol/underlay_stream.go:41`.
const STREAM_OVERHEAD: usize = METADATA_LEN + TAG_LEN * 2;

/// Assemble a session segment: encrypted metadata, then trailing padding.
pub fn encode_session_segment(
    cipher: &mut DirectionCipher,
    meta: &SessionMetadata,
    strategy: PaddingStrategy,
) -> std::io::Result<Vec<u8>> {
    // This encoder writes metadata and padding only. A non-zero payload_len
    // would describe a payload that never reaches the wire, and the peer would
    // sit waiting for bytes that are not coming.
    if meta.payload_len != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "a mieru session segment carries no payload, so payload_len must be zero",
        ));
    }
    let mut meta = meta.clone();
    // The entropy strategy balances against the bytes that will precede the
    // padding. Those are ciphertext, so upstream models them with random data
    // of the right length rather than the real thing
    // (`buildRecommendedPaddingOpts`, `pkg/protocol/padding.go:108-134`).
    // Passing an empty slice instead makes every bit count zero, and the
    // calculation degenerates into a near-constant run of 0xFF.
    let mut preceding = vec![0u8; STREAM_OVERHEAD + meta.payload_len as usize];
    rand::rng().fill_bytes(&mut preceding);
    let suffix = strategy.build(MAX_PADDING_LEN, &preceding);
    meta.suffix_len = suffix.len() as u8;
    // Upstream stamps this in sessionStruct.Marshal and its Unmarshal rejects
    // anything more than one minute from its own clock
    // (`pkg/protocol/metadata.go:150,170`). A caller-supplied value would be
    // stale by the time it reached the wire, so the encoder owns the field.
    meta.timestamp_minutes = current_timestamp_minutes()?;

    let sealed = cipher.seal(&metadata::encode_session(&meta))?;
    let mut out = Vec::with_capacity(sealed.len() + suffix.len());
    out.extend_from_slice(&sealed);
    out.extend_from_slice(&suffix);
    Ok(out)
}

/// Assemble a data segment: encrypted metadata, prefix padding, encrypted
/// payload, trailing padding.
///
/// The padding here is not the per-user strategy: upstream pads data and ack
/// segments with plain random bytes of uniform length, and reserves the
/// strategy for session segments (`pkg/protocol/underlay_stream.go:672`).
/// Applying the strategy to every packet would give the traffic a constant
/// shape, which is the opposite of what padding is for.
pub fn encode_data_segment(
    cipher: &mut DirectionCipher,
    session_id: u32,
    seq: u32,
    payload: &[u8],
) -> std::io::Result<Vec<u8>> {
    let prefix = build_data_padding(MAX_PADDING_LEN);
    let suffix = build_data_padding(MAX_PADDING_LEN);

    let meta = DataMetadata {
        protocol: metadata::DATA_CLIENT_TO_SERVER,
        // Minutes since the epoch. The peer checks this against its own clock
        // and drops the segment if it is off by more than a minute
        // (`dataAckStruct.Unmarshal`, `pkg/protocol/metadata.go:261`).
        timestamp_minutes: current_timestamp_minutes()?,
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
    // An empty payload gets no second encryption, so the receiver must not
    // look for a tag that was never written.
    let sealed_payload = if payload.is_empty() {
        Vec::new()
    } else {
        cipher.seal(payload)?
    };

    let mut out =
        Vec::with_capacity(sealed_meta.len() + prefix.len() + sealed_payload.len() + suffix.len());
    out.extend_from_slice(&sealed_meta);
    out.extend_from_slice(&prefix);
    out.extend_from_slice(&sealed_payload);
    out.extend_from_slice(&suffix);
    Ok(out)
}

/// Minutes since the Unix epoch.
///
/// Both `sessionStruct.Unmarshal` and `dataAckStruct.Unmarshal` reject a
/// timestamp more than a minute from the peer's own clock
/// (`pkg/protocol/metadata.go:171,261`), so this is not bookkeeping the peer
/// shrugs off. Falling back to zero would put every segment outside that
/// window and the server would drop the lot with no hint as to why; failing
/// here names the clock instead.
fn current_timestamp_minutes() -> std::io::Result<u32> {
    let secs = crate::util::unix_time_secs().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "mieru stamps every segment with the current time, and this clock is unusable: {e}"
            ),
        )
    })?;
    Ok((secs / 60) as u32)
}

/// Try to decode one segment from the front of `input`.
///
/// Returns `Ok(None)` when more bytes are needed — the ordinary case on a
/// socket. Crucially it consumes nothing from the cipher in that case: the
/// nonce advances only once the whole segment is present, so a segment split
/// across reads reassembles instead of desynchronising the stream.
#[allow(clippy::type_complexity)]
pub fn decode_segment(
    cipher: &mut DirectionCipher,
    input: &[u8],
) -> std::io::Result<Option<(Metadata, Vec<u8>, usize)>> {
    // How many bytes the metadata occupies: the first segment of a direction
    // carries a nonce, later ones do not.
    let meta_len = cipher.sealed_len(METADATA_LEN);
    if input.len() < meta_len {
        return Ok(None);
    }

    // Decrypt against a clone, so a short segment leaves the real cipher's
    // nonce untouched.
    let mut probe = cipher.clone_state();
    let plaintext = probe.open(&input[..meta_len])?;
    let meta = metadata::parse(&plaintext)?;

    let (prefix_len, payload_len, suffix_len) = match &meta {
        Metadata::Session(session) => (
            0usize,
            session.payload_len as usize,
            session.suffix_len as usize,
        ),
        Metadata::Data(data) => (
            data.prefix_len as usize,
            data.payload_len as usize,
            data.suffix_len as usize,
        ),
    };

    let sealed_payload_len = if payload_len > 0 {
        payload_len + TAG_LEN
    } else {
        0
    };
    let total = meta_len + prefix_len + sealed_payload_len + suffix_len;
    if input.len() < total {
        return Ok(None);
    }

    // The segment is complete: commit the metadata decryption, then decrypt
    // the payload with the same cipher so the nonces stay in step.
    *cipher = probe;
    let payload = if sealed_payload_len > 0 {
        let at = meta_len + prefix_len;
        cipher.open(&input[at..at + sealed_payload_len])?
    } else {
        Vec::new()
    };

    Ok(Some((meta, payload, total)))
}

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

        let wire = encode_data_segment(&mut sender, 99, 1, body).unwrap();
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
            let wire = encode_data_segment(&mut sender, 1, 0, b"payload").unwrap();
            let (_, payload, _) = decode_segment(&mut receiver, &wire).unwrap().unwrap();
            assert_eq!(
                payload, b"payload",
                "strategy {strategy:?} did not round trip"
            );
        }
    }

    /// A partial segment must ask for more rather than erroring, and must not
    /// advance the nonce: this is the case that happens constantly on a real
    /// socket, and getting it wrong desynchronises the stream silently.
    #[test]
    fn test_an_incomplete_segment_returns_none_without_advancing() {
        let (mut sender, mut receiver) = cipher_pair();
        let wire = encode_data_segment(&mut sender, 1, 0, b"payload").unwrap();

        // Feed every prefix to the same receiver. None may consume anything.
        for cut in 1..wire.len() {
            assert!(
                decode_segment(&mut receiver, &wire[..cut])
                    .unwrap()
                    .is_none(),
                "a {cut}-byte prefix should be incomplete"
            );
        }
        // After all those attempts the whole segment still decodes, which it
        // could not if a partial attempt had advanced the nonce.
        let (_, payload, _) = decode_segment(&mut receiver, &wire).unwrap().unwrap();
        assert_eq!(payload, b"payload");
    }

    /// A session segment is metadata plus padding; nothing writes a payload.
    /// Announcing one would leave the peer waiting on bytes that never come,
    /// so the encoder refuses rather than emitting a segment that lies.
    #[test]
    fn test_a_session_segment_refuses_to_announce_a_payload() {
        let (mut cipher, _) = cipher_pair();
        let err = encode_session_segment(
            &mut cipher,
            &SessionMetadata {
                protocol: OPEN_SESSION_REQUEST,
                timestamp_minutes: 0,
                session_id: 7,
                seq: 0,
                status: 0,
                payload_len: 16,
                suffix_len: 0,
            },
            PaddingStrategy::Ascii,
        )
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_two_segments_decode_in_sequence() {
        let (mut sender, mut receiver) = cipher_pair();
        let mut wire = encode_data_segment(&mut sender, 1, 0, b"first").unwrap();
        wire.extend_from_slice(&encode_data_segment(&mut sender, 1, 1, b"second").unwrap());

        let (_, first, consumed) = decode_segment(&mut receiver, &wire).unwrap().unwrap();
        assert_eq!(first, b"first");
        let (_, second, _) = decode_segment(&mut receiver, &wire[consumed..])
            .unwrap()
            .unwrap();
        assert_eq!(second, b"second");
    }

    #[test]
    fn test_a_corrupted_metadata_byte_is_rejected() {
        let (mut sender, mut receiver) = cipher_pair();
        let mut wire = encode_data_segment(&mut sender, 1, 0, b"payload").unwrap();
        // Flip a byte inside the encrypted metadata, past the nonce.
        wire[crate::mieru::NONCE_LEN + 1] ^= 0xff;
        assert!(decode_segment(&mut receiver, &wire).is_err());
    }

    /// Upstream rejects a session segment whose timestamp is more than a
    /// minute from its own clock, so a zero here means the handshake dies
    /// before the server answers. The encoder owns the field; a caller cannot
    /// leave it unset.
    #[test]
    fn test_a_session_segment_carries_the_current_timestamp() {
        let (mut sender, mut receiver) = cipher_pair();
        let now_minutes = (crate::util::unix_time_secs().unwrap() / 60) as u32;

        let wire = encode_session_segment(
            &mut sender,
            &SessionMetadata {
                protocol: OPEN_SESSION_REQUEST,
                // Deliberately zero: the encoder must overwrite it.
                timestamp_minutes: 0,
                session_id: 1,
                seq: 0,
                status: 0,
                payload_len: 0,
                suffix_len: 0,
            },
            PaddingStrategy::Ascii,
        )
        .unwrap();

        let (parsed, _, _) = decode_segment(&mut receiver, &wire).unwrap().unwrap();
        let Metadata::Session(session) = parsed else {
            panic!("expected session metadata")
        };
        assert!(
            session.timestamp_minutes.abs_diff(now_minutes) <= 1,
            "timestamp {} is not within a minute of {now_minutes}",
            session.timestamp_minutes
        );
    }

    /// Data segments stamp it too, and did so before this was fixed for the
    /// session path - so pin both rather than assuming they share a code path.
    #[test]
    fn test_a_data_segment_carries_the_current_timestamp() {
        let (mut sender, mut receiver) = cipher_pair();
        let now_minutes = (crate::util::unix_time_secs().unwrap() / 60) as u32;

        let wire = encode_data_segment(&mut sender, 1, 0, b"x").unwrap();
        let (parsed, _, _) = decode_segment(&mut receiver, &wire).unwrap().unwrap();
        let Metadata::Data(data) = parsed else {
            panic!("expected data metadata")
        };
        assert!(data.timestamp_minutes.abs_diff(now_minutes) <= 1);
    }

    #[test]
    fn test_an_empty_payload_segment_carries_no_payload_tag() {
        let (mut sender, mut receiver) = cipher_pair();
        let wire = encode_data_segment(&mut sender, 1, 0, b"").unwrap();
        let (_, payload, consumed) = decode_segment(&mut receiver, &wire).unwrap().unwrap();
        assert!(payload.is_empty());
        assert_eq!(consumed, wire.len());
    }
}
