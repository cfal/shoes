use super::{parse_server_hello, parse_validated_server_hello};

const TLS13_VERSION: &[u8] = b"\x00\x2b\x00\x02\x03\x04";

fn server_hello(session_id_len: u8, extensions: Option<&[u8]>) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[42; 32]);
    body.push(session_id_len);
    body.extend(std::iter::repeat_n(7, usize::from(session_id_len)));
    body.extend_from_slice(&[0x13, 0x01, 0]);
    if let Some(extensions) = extensions {
        body.extend_from_slice(&u16::try_from(extensions.len()).unwrap().to_be_bytes());
        body.extend_from_slice(extensions);
    }
    let mut frame = vec![0x16, 3, 3];
    frame.extend_from_slice(&u16::try_from(4 + body.len()).unwrap().to_be_bytes());
    frame.push(2);
    frame.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
    frame.extend_from_slice(&body);
    frame
}

#[test]
fn parses_tls12_and_tls13_with_variable_session_ids() {
    for session_id_len in [0, 1, 32] {
        for (extensions, expected_tls13) in [
            (None, false),
            (Some(b"".as_slice()), false),
            (Some(TLS13_VERSION), true),
        ] {
            let frame = server_hello(session_id_len, extensions);
            let parsed = parse_server_hello(&frame).unwrap();
            assert_eq!(parsed.server_random, [42; 32]);
            assert_eq!(parsed.session_id_len, session_id_len);
            assert_eq!(parsed.cipher_suite, 0x1301);
            assert_eq!(parsed.is_tls13, expected_tls13);
            assert_eq!(
                parse_validated_server_hello(&frame).is_ok(),
                parsed.is_tls13 && session_id_len == 32
            );
        }
    }
}

#[test]
fn coalesced_handshakes_do_not_extend_server_hello() {
    for (extensions, expected_tls13) in [
        (None, false),
        (Some(b"".as_slice()), false),
        (Some(TLS13_VERSION), true),
    ] {
        let mut frame = server_hello(32, extensions);
        // A second handshake containing a version-like byte sequence must be ignored.
        frame.extend_from_slice(&[11, 0, 0, 6]);
        frame.extend_from_slice(TLS13_VERSION);
        let record_len = u16::try_from(frame.len() - 5).unwrap();
        frame[3..5].copy_from_slice(&record_len.to_be_bytes());
        let parsed = parse_server_hello(&frame).unwrap();
        assert_eq!(parsed.is_tls13, expected_tls13);
    }
}

#[test]
fn declared_handshake_body_bounds_every_field() {
    for session_id_len in [0, 1, 32] {
        let valid = server_hello(session_id_len, Some(TLS13_VERSION));
        let minimum_body_len = 38 + usize::from(session_id_len);
        for body_len in 0..valid.len() - 9 {
            let mut frame = valid.clone();
            frame[6..9].copy_from_slice(&u32::try_from(body_len).unwrap().to_be_bytes()[1..]);
            let parsed = parse_server_hello(&frame);
            if body_len == minimum_body_len {
                // TLS 1.2 permits a ServerHello with no extensions vector.
                assert!(!parsed.unwrap().is_tls13);
            } else {
                assert!(
                    parsed.is_err(),
                    "session_id_len={session_id_len}, body_len={body_len}"
                );
            }
        }
        for frame_len in 0..valid.len() {
            assert!(parse_server_hello(&valid[..frame_len]).is_err());
        }
    }
}

#[test]
fn extensions_must_fill_the_declared_body_and_contain_complete_entries() {
    let valid = server_hello(32, Some(TLS13_VERSION));
    for extension_len in 0..=TLS13_VERSION.len() + 1 {
        let mut frame = valid.clone();
        frame[79..81].copy_from_slice(&u16::try_from(extension_len).unwrap().to_be_bytes());
        assert_eq!(
            parse_server_hello(&frame).is_ok(),
            extension_len == TLS13_VERSION.len(),
            "extension_len={extension_len}"
        );
    }
    for extensions in [
        b"\x00\x2b\x00".as_slice(),
        b"\x00\x2b\x00\x01\x03".as_slice(),
        b"\x00\x2b\x00\x02\x03".as_slice(),
        b"\xfa\xfa\x00\x02\x03".as_slice(),
    ] {
        assert!(parse_server_hello(&server_hello(32, Some(extensions))).is_err());
    }
}
