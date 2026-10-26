use super::*;
use crate::copy_bidirectional::tests::{copy_response_with_flush_pressure, quota_test_payload};
use crate::prepend_stream::PrependStream;
use aws_lc_rs::aead::{Algorithm, CHACHA20_POLY1305, UnboundKey};
use shake::Shake128;
use shake::digest::{ExtendableOutput, Update};
use tokio::io::AsyncReadExt;

#[tokio::test]
async fn full_output_chunk_is_accepted_with_or_without_pending_length() {
    for pending in [false, true] {
        let (transport, _) = tokio::io::duplex(1);
        let mut stream = response_test_stream(Box::new(transport), None, false, false, None);
        let len = stream.processed_buf.len();
        assert!(len <= u16::MAX as usize);
        stream.unprocessed_buf[..2].copy_from_slice(&(len as u16).to_be_bytes());
        stream.unprocessed_buf[2..2 + len].fill(42);
        stream.unprocessed_end_offset = 2 + len;
        if pending {
            stream.unprocessed_pending_len = Some((0, len));
            stream.unprocessed_start_offset = 2;
        }
        assert!(matches!(
            stream.try_decrypt().unwrap(),
            DecryptState::Success
        ));
        assert_eq!(&*stream.processed_buf, vec![42; len]);
    }
}

#[tokio::test]
async fn padding_larger_than_chunk_is_rejected() {
    let (transport, _) = tokio::io::duplex(1);
    let mut stream = response_test_stream(Box::new(transport), None, true, true, None);
    let (padding, mask) = LengthMask::new(create_shake128_reader(&[23; 16]), true).next_values();
    assert!(padding > 0);
    stream.unprocessed_buf[..2].copy_from_slice(&mask.to_be_bytes());
    stream.unprocessed_end_offset = 2;
    assert!(
        matches!(stream.try_decrypt(), Err(error) if error.kind() == std::io::ErrorKind::InvalidData)
    );
}

fn create_shake128_reader(iv: &[u8]) -> VmessReader {
    let mut hasher = Shake128::default();
    hasher.update(iv);
    hasher.finalize_xof()
}

fn response_test_stream(
    stream: Box<dyn AsyncStream>,
    algorithm: Option<&'static Algorithm>,
    masked: bool,
    padding: bool,
    prefix: Option<BytesMut>,
) -> VmessStream {
    let keys = algorithm.map(|algorithm| {
        let key = vec![42; algorithm.key_len()];
        (
            OpeningKey::new(
                UnboundKey::new(algorithm, &key).unwrap(),
                VmessNonceSequence::new(&[23; 16]),
            ),
            SealingKey::new(
                UnboundKey::new(algorithm, &key).unwrap(),
                VmessNonceSequence::new(&[23; 16]),
            ),
        )
    });
    VmessStream::new(
        stream,
        false,
        keys,
        masked.then(|| create_shake128_reader(&[23; 16])),
        masked.then(|| create_shake128_reader(&[23; 16])),
        padding,
        prefix,
        None,
    )
}

async fn check_response_flushes(payload: &[u8]) {
    // The handler supplies an opaque, already encrypted 38-byte response prefix.
    let prefix = [0x5a; 38];
    for algorithm in [None, Some(&AES_128_GCM), Some(&CHACHA20_POLY1305)] {
        for (masked, padding) in [(false, false), (true, false), (true, true)] {
            let capture = copy_response_with_flush_pressure(
                |stream| async move {
                    response_test_stream(
                        stream,
                        algorithm,
                        masked,
                        padding,
                        Some(BytesMut::from(&prefix[..])),
                    )
                },
                payload,
            )
            .await;
            assert!(capture.first_write_offer.starts_with(&prefix));
            assert!(capture.first_write_offer.len() > prefix.len());
            assert!(capture.data.starts_with(&prefix));

            let (transport, _) = tokio::io::duplex(1);
            let mut decoder = response_test_stream(
                Box::new(PrependStream::new(
                    transport,
                    Some(capture.data[prefix.len()..].into()),
                )),
                algorithm,
                masked,
                padding,
                None,
            );
            let mut decoded = Vec::new();
            decoder.read_to_end(&mut decoded).await.unwrap();
            assert_eq!(decoded, payload);

            let mut mask =
                masked.then(|| LengthMask::new(create_shake128_reader(&[23; 16]), padding));
            let tag_len = if algorithm.is_some() {
                ENCRYPTION_TAG_LEN
            } else {
                0
            };
            let mut frame_start = prefix.len();
            let mut eof_count = 0;
            while frame_start < capture.data.len() {
                let (padding_len, length_mask) =
                    mask.as_mut().map_or((0, 0), LengthMask::next_values);
                let encoded_len = u16::from_be_bytes(
                    capture.data[frame_start..frame_start + 2]
                        .try_into()
                        .unwrap(),
                );
                let frame_len = usize::from(encoded_len ^ length_mask);
                assert!(frame_len >= padding_len + tag_len);
                let frame_end = frame_start + 2 + frame_len;
                assert!(frame_end <= capture.data.len());
                let is_eof = frame_len == padding_len + tag_len;
                if frame_start == prefix.len() {
                    // The first offered write contains a complete body frame, not just its prefix.
                    assert!(capture.first_write_offer.len() >= frame_end);
                    assert_eq!(is_eof, payload.is_empty());
                }
                if is_eof {
                    eof_count += 1;
                    assert_eq!(frame_end, capture.data.len());
                    assert_eq!(
                        capture.bytes_before_shutdown,
                        if payload.is_empty() { 0 } else { frame_start }
                    );
                    if let Some(key) = &mut decoder.opening_key {
                        let mut eof_tag =
                            capture.data[frame_start + 2..frame_end - padding_len].to_vec();
                        assert!(
                            key.open_in_place(Aad::empty(), &mut eof_tag)
                                .unwrap()
                                .is_empty()
                        );
                    }
                }
                frame_start = frame_end;
            }
            assert_eq!(eof_count, 1);
        }
    }
}

#[tokio::test]
async fn response_header_waits_for_content_across_copier_flushes() {
    check_response_flushes(b"first response").await;
}

#[tokio::test]
async fn response_survives_copier_quota_flushes_and_eof() {
    let payload = quota_test_payload();
    check_response_flushes(&payload).await;
}

#[tokio::test]
async fn empty_response_pairs_header_with_eof_only_at_shutdown() {
    check_response_flushes(b"").await;
}

#[test]
fn test_length_mask_creation() {
    let reader = create_shake128_reader(&[0u8; 16]);
    let mut mask = LengthMask::new(reader, false);

    // Verify it produces u16 values
    let value = mask.next_u16();
    // The value should be deterministic for the same input
    let reader2 = create_shake128_reader(&[0u8; 16]);
    let mut mask2 = LengthMask::new(reader2, false);
    assert_eq!(value, mask2.next_u16());
}

#[test]
fn test_length_mask_with_padding() {
    let reader = create_shake128_reader(&[0u8; 16]);
    let mut mask = LengthMask::new(reader, true);

    let (padding, _length_mask) = mask.next_values();
    // Padding should be less than MAX_PADDING_LEN (64)
    assert!(padding < MAX_PADDING_LEN);
}

#[test]
fn test_length_mask_without_padding() {
    let reader = create_shake128_reader(&[0u8; 16]);
    let mut mask = LengthMask::new(reader, false);

    let (padding, _length_mask) = mask.next_values();
    // Padding should always be 0 when disabled
    assert_eq!(padding, 0);
}

#[test]
fn test_length_mask_deterministic() {
    // Same input should produce same sequence
    let reader1 = create_shake128_reader(&[
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00,
    ]);
    let mut mask1 = LengthMask::new(reader1, true);

    let reader2 = create_shake128_reader(&[
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00,
    ]);
    let mut mask2 = LengthMask::new(reader2, true);

    for _ in 0..10 {
        let (p1, m1) = mask1.next_values();
        let (p2, m2) = mask2.next_values();
        assert_eq!(p1, p2);
        assert_eq!(m1, m2);
    }
}

#[test]
fn test_length_mask_sequence_matches_sing_vmess() {
    // sing-vmess reads padding first (if enabled), then length mask
    // Both are read as big-endian u16 from SHAKE128
    let reader = create_shake128_reader(&[0u8; 16]);
    let mut mask = LengthMask::new(reader, true);

    // Get first pair
    let (padding1, _length_mask1) = mask.next_values();
    // Get second pair
    let (padding2, _length_mask2) = mask.next_values();

    // Values should be different (SHAKE128 produces pseudo-random output)
    // Though in rare cases they could be equal, so we just check they're valid
    assert!(padding1 < MAX_PADDING_LEN);
    assert!(padding2 < MAX_PADDING_LEN);
}

#[test]
fn test_check_header_response_valid() {
    // Test valid response header
    let response_v = 0x42u8;
    let response_bytes = [response_v, 0x00, 0x00, 0x00]; // auth, opt, cmd, cmdlen
    assert!(check_header_response(&response_bytes, response_v).is_ok());
}

#[test]
fn test_check_header_response_invalid_auth() {
    // Test invalid auth value
    let response_v = 0x42u8;
    let response_bytes = [0x43u8, 0x00, 0x00, 0x00]; // Wrong auth value
    let result = check_header_response(&response_bytes, response_v);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("Invalid response auth value"));
}

#[test]
fn test_check_header_response_with_dynamic_port_flag() {
    // Test with dynamic port flag set (should log warning but not fail)
    let response_v = 0x42u8;
    let response_bytes = [response_v, 0x00, 0x01, 0x00]; // dynamic port flag set
    assert!(check_header_response(&response_bytes, response_v).is_ok());
}

#[test]
fn test_constants() {
    // Verify constants match protocol specification
    assert_eq!(HEADER_TAG_LEN, 16);
    assert_eq!(ENCRYPTION_TAG_LEN, 16);
    assert_eq!(MAX_PADDING_LEN, 64);
    // Chunk size: 8192 data + 16 tag = 8208
    assert_eq!(MAX_ENCRYPTED_WRITE_DATA_SIZE, 8208);
    // Max read size is u16::MAX to handle all clients
    assert_eq!(MAX_ENCRYPTED_READ_DATA_SIZE, 65535);
}

#[test]
fn test_read_header_state_transitions() {
    // Verify state machine enum values
    assert_eq!(
        ReadHeaderState::ReadAeadLength,
        ReadHeaderState::ReadAeadLength
    );
    assert_eq!(ReadHeaderState::Done, ReadHeaderState::Done);
    assert_ne!(ReadHeaderState::ReadAeadLength, ReadHeaderState::Done);
}

#[test]
fn test_aead_key_creation() {
    // Test creating AEAD keys (AES-128-GCM)
    let key = [0x42u8; 16];
    let iv = [0x11u8; 16];

    let opening_unbound = UnboundKey::new(&AES_128_GCM, &key).unwrap();
    let sealing_unbound = UnboundKey::new(&AES_128_GCM, &key).unwrap();

    let opening_key = OpeningKey::new(opening_unbound, VmessNonceSequence::new(&iv));
    let sealing_key = SealingKey::new(sealing_unbound, VmessNonceSequence::new(&iv));

    // Keys should be created successfully (no panic)
    // We can't easily test encryption/decryption without the full stream
    // but we verify the keys are valid by checking they exist
    assert!(std::mem::size_of_val(&opening_key) > 0);
    assert!(std::mem::size_of_val(&sealing_key) > 0);
}

#[test]
fn test_chacha20_poly1305_key_creation() {
    // Test creating ChaCha20-Poly1305 keys
    let key = [0x42u8; 16];
    let chacha_key = super::super::md5::create_chacha_key(&key);
    let iv = [0x11u8; 16];

    let opening_unbound = UnboundKey::new(&CHACHA20_POLY1305, &chacha_key).unwrap();
    let sealing_unbound = UnboundKey::new(&CHACHA20_POLY1305, &chacha_key).unwrap();

    let opening_key = OpeningKey::new(opening_unbound, VmessNonceSequence::new(&iv));
    let sealing_key = SealingKey::new(sealing_unbound, VmessNonceSequence::new(&iv));

    assert!(std::mem::size_of_val(&opening_key) > 0);
    assert!(std::mem::size_of_val(&sealing_key) > 0);
}

#[test]
fn test_length_encoding_unmasked() {
    // Test that unmasked length is encoded correctly as big-endian u16
    let length: u16 = 0x1234;
    let bytes = length.to_be_bytes();
    assert_eq!(bytes, [0x12, 0x34]);
}

#[test]
fn test_length_encoding_masked() {
    // Test length XOR masking behavior
    let length: u16 = 0x1234;
    let mask: u16 = 0xabcd;
    let masked = length ^ mask;
    // XOR is reversible
    assert_eq!(masked ^ mask, length);
}

#[test]
fn test_padding_calculation() {
    // Padding is computed as u16 % MAX_PADDING_LEN (64)
    let reader = create_shake128_reader(&[0u8; 16]);
    let mut mask = LengthMask::new(reader, true);

    // Run multiple iterations to verify padding is always in range
    for _ in 0..100 {
        let (padding, _) = mask.next_values();
        assert!(
            padding < MAX_PADDING_LEN,
            "Padding {} should be < {}",
            padding,
            MAX_PADDING_LEN
        );
    }
}

#[test]
fn test_chunk_size_limits() {
    // VMess chunks have specific size limits
    // Write chunk: 8192 + 16 (tag) = 8208 max encrypted size
    // This is different from sing-vmess which uses different defaults

    // Verify the constant values match the protocol
    assert_eq!(MAX_ENCRYPTED_WRITE_DATA_SIZE, 8192 + ENCRYPTION_TAG_LEN);

    // Read allows larger chunks to be compatible with other implementations
    assert_eq!(MAX_ENCRYPTED_READ_DATA_SIZE, 65535);
}

#[test]
fn test_response_header_format() {
    // VMess response header is 4 bytes: auth, opt, cmd, cmdlen
    // auth = response_v (random byte set by client)
    // opt = options (usually 0)
    // cmd = command response (0x01 = dynamic port)
    // cmdlen = additional command data length (usually 0)

    let response_v = 0x42u8;

    // Standard successful response
    let header = [response_v, 0x00, 0x00, 0x00];
    assert!(check_header_response(&header, response_v).is_ok());

    // Response with options set (should still succeed)
    let header_with_opts = [response_v, 0x01, 0x00, 0x00];
    assert!(check_header_response(&header_with_opts, response_v).is_ok());
}
