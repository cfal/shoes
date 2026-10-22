use std::io::{self, BufRead, Read, Write};
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::Mutex;

use super::reality_key_exchange::RealityGroup;
use super::reality_pq_tests::{configs, separate_target_records, target_records};
use super::*;

#[derive(Debug, Default)]
struct Secrets(Mutex<std::collections::HashMap<String, Vec<u8>>>);

#[test]
fn interleaved_connections_do_not_share_authentication_state() {
    let pending: Vec<_> = (0..4).map(|_| pending_pair(Arc::default(), true)).collect();
    for (mut client, mut server, flight) in pending {
        feed_reality_client_connection(&mut client, &flight.concat()).unwrap();
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        feed_reality_server_connection(&mut server, &wire).unwrap();
        assert!(!client.is_handshaking() && !server.is_handshaking());
    }
}

#[test]
fn real_target_certificate_never_authenticates_reality() {
    let (cc, _) = configs(CipherSuite::AES_128_GCM_SHA256);
    let cert = rcgen::generate_simple_self_signed(vec!["cover.test".into()]).unwrap();
    let config = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let mut server = rustls::ServerConnection::new(Arc::new(config)).unwrap();
    let mut client = RealityClientConnection::new(cc).unwrap();
    let mut wire = Vec::new();
    client.write_tls(&mut wire).unwrap();
    let mut input = wire.as_slice();
    while !input.is_empty() {
        server.read_tls(&mut input).unwrap();
        server.process_new_packets().unwrap();
    }
    wire.clear();
    server.write_tls(&mut wire).unwrap();
    assert_eq!(
        feed_reality_client_connection(&mut client, &wire)
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(client.is_handshaking() && !client.wants_write());
}

impl rustls::KeyLog for Secrets {
    fn log(&self, label: &str, _: &[u8], secret: &[u8]) {
        self.0.lock().insert(label.into(), secret.to_vec());
    }
}

fn records(wire: &[u8]) -> Vec<Bytes> {
    let mut deframer = crate::crypto::tls_deframer::TlsDeframer::new();
    deframer.feed(wire);
    let records = deframer.next_records().unwrap();
    assert_eq!(deframer.pending_bytes(), 0);
    records
}

fn pending_pair(
    secrets: Arc<Secrets>,
    omit_ed25519: bool,
) -> (RealityClientConnection, RealityServerConnection, Vec<Bytes>) {
    let (cc, sc) = configs(CipherSuite::AES_128_GCM_SHA256);
    let crypto = reality_rustls::provider(&cc.cipher_suites);
    let mut schemes = crypto.signature_verification_algorithms.supported_schemes();
    if omit_ed25519 {
        schemes.retain(|scheme| *scheme != rustls::SignatureScheme::ED25519);
    }
    let mut client = RealityClientConnection::with_options(cc, crypto, schemes, secrets).unwrap();
    let mut server = RealityServerConnection::new(sc).unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    server.validate_client_hello(&hello).unwrap();
    let target = separate_target_records(
        RealityGroup::X25519MlKem768,
        CipherSuite::AES_128_GCM_SHA256,
        &hello[44..76],
    );
    server.build_server_response(&target).unwrap();
    let mut wire = Vec::new();
    server.write_tls(&mut wire).unwrap();
    (client, server, records(&wire))
}

fn mutate_record(
    record: &Bytes,
    secret: &[u8],
    seq: u64,
    change: impl FnOnce(&mut Vec<u8>),
) -> Vec<u8> {
    use aws_lc_rs::{aead, hkdf};
    struct Length(usize);
    impl hkdf::KeyType for Length {
        fn len(&self) -> usize {
            self.0
        }
    }
    let expand = |label: &[u8], len: usize| {
        let mut info = (len as u16).to_be_bytes().to_vec();
        info.push((6 + label.len()) as u8);
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label);
        info.push(0);
        let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);
        let mut output = vec![0; len];
        prk.expand(&[&info], Length(len))
            .unwrap()
            .fill(&mut output)
            .unwrap();
        output
    };
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, &expand(b"key", 16)).unwrap(),
    );
    let mut nonce: [u8; 12] = expand(b"iv", 12).try_into().unwrap();
    for (byte, sequence) in nonce[4..].iter_mut().zip(seq.to_be_bytes()) {
        *byte ^= sequence;
    }
    let mut plaintext = record[5..].to_vec();
    let len = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(&record[..5]),
            &mut plaintext,
        )
        .unwrap()
        .len();
    plaintext.truncate(len);
    let original_len = plaintext.len();
    change(&mut plaintext);
    assert_eq!(plaintext.len(), original_len);
    let mut output = record[..5].to_vec();
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(&record[..5]),
        &mut plaintext,
    )
    .unwrap();
    output.extend_from_slice(&plaintext);
    output
}

#[test]
fn authenticated_unadvertised_ed25519_and_key_updates() {
    let (mut client, mut server, flight) = pending_pair(Arc::default(), true);
    feed_reality_client_connection(&mut client, &flight.concat()).unwrap();
    let mut wire = Vec::new();
    client.write_tls(&mut wire).unwrap();
    feed_reality_server_connection(&mut server, &wire).unwrap();
    assert!(!client.is_handshaking() && !server.is_handshaking());
    for _ in 0..3 {
        client.transport.refresh_traffic_keys().unwrap();
        client.writer().write_all(b"updated client").unwrap();
        wire.clear();
        client.write_tls(&mut wire).unwrap();
        feed_reality_server_connection(&mut server, &wire).unwrap();
        let mut data = [0; 14];
        server.reader().read_exact(&mut data).unwrap();
        assert_eq!(&data, b"updated client");
        server.transport.refresh_traffic_keys().unwrap();
        server.writer().write_all(b"updated server").unwrap();
        wire.clear();
        server.write_tls(&mut wire).unwrap();
        feed_reality_client_connection(&mut client, &wire).unwrap();
        client.reader().read_exact(&mut data).unwrap();
        assert_eq!(&data, b"updated server");
    }
}

#[test]
fn certificate_verify_and_server_finished_must_verify() {
    // Re-encrypt corrupted plaintext with valid AEAD tags: this tests signature/Finished validation.
    for (index, kind) in [
        (3, io::ErrorKind::PermissionDenied),
        (4, io::ErrorKind::PermissionDenied),
        (5, io::ErrorKind::InvalidData),
    ] {
        let secrets = Arc::new(Secrets::default());
        let (mut client, _, flight) = pending_pair(secrets.clone(), true);
        for record in &flight[..index] {
            feed_reality_client_connection(&mut client, record).unwrap();
        }
        let secret = secrets.0.lock()["SERVER_HANDSHAKE_TRAFFIC_SECRET"].clone();
        let bad = mutate_record(&flight[index], &secret, (index - 2) as u64, |plaintext| {
            let offset = if index == 3 {
                let len =
                    u32::from_be_bytes([0, plaintext[8], plaintext[9], plaintext[10]]) as usize;
                11 + len - 1
            } else {
                8
            };
            plaintext[offset] ^= 1;
        });
        let mutated_flight = [bad, flight[index + 1..].concat()].concat();
        let error = feed_reality_client_connection(&mut client, &mutated_flight).unwrap_err();
        assert_eq!(error.kind(), kind);
        assert!(client.is_handshaking());
        assert!(client.reader().fill_buf().is_err());
        assert!(client.writer().write(b"forbidden").is_err());
        let mut output = Vec::new();
        assert_eq!(client.write_tls(&mut output).unwrap(), 0);
        assert!(output.is_empty());
        assert!(client.process_new_packets().is_err());
    }
}

#[test]
fn authentication_policy_and_client_share_variants() {
    for case in [
        "valid",
        "plain-only",
        "hybrid-only",
        "short-id",
        "static-key",
        "minimum",
        "maximum",
        "timestamp",
        "tampered-hello",
    ] {
        let (mut cc, mut sc) = configs(CipherSuite::AES_128_GCM_SHA256);
        match case {
            "short-id" => cc.short_id = [2; 8],
            "static-key" => sc.private_key = [43; 32],
            "minimum" => sc.min_client_version = Some([1, 8, 1]),
            "maximum" => sc.max_client_version = Some([1, 7, 9]),
            _ => {}
        }
        let mut crypto = reality_rustls::provider(&cc.cipher_suites);
        if case == "plain-only" {
            crypto.kx_groups.remove(0);
        }
        if case == "hybrid-only" {
            crypto.kx_groups.pop();
        }
        let schemes = crypto.signature_verification_algorithms.supported_schemes();
        let mut client = RealityClientConnection::with_options(
            cc,
            crypto,
            schemes,
            Arc::new(rustls::NoKeyLog {}),
        )
        .unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        if case == "tampered-hello" {
            hello[11] ^= 1;
        }
        if case == "timestamp" {
            use super::reality_auth::{derive_auth_key, encrypt_session_id, perform_ecdh};
            let shares = super::reality_key_exchange::extract_client_key_shares(&hello).unwrap();
            let shared =
                perform_ecdh(&sc.private_key, shares.authentication_public_key().unwrap()).unwrap();
            let auth = derive_auth_key(&shared, &hello[11..31], b"REALITY").unwrap();
            let mut aad = hello[5..].to_vec();
            aad[39..71].fill(0);
            let mut payload = [0; 16];
            payload[..3].copy_from_slice(&[1, 8, 0]);
            payload[8..].fill(1);
            let session = encrypt_session_id(&payload, &auth, &hello[31..43], &aad).unwrap();
            hello[44..76].copy_from_slice(&session);
            sc.max_time_diff = Some(60_000);
        }
        let mut server = RealityServerConnection::new(sc).unwrap();
        let result = server.validate_client_hello(&hello);
        if matches!(case, "valid" | "plain-only" | "hybrid-only") {
            result.unwrap();
            let group = if case == "plain-only" {
                RealityGroup::X25519
            } else {
                RealityGroup::X25519MlKem768
            };
            server
                .build_server_response(&target_records(
                    group,
                    CipherSuite::AES_128_GCM_SHA256,
                    &hello[44..76],
                ))
                .unwrap();
            let mut flight = Vec::new();
            server.write_tls(&mut flight).unwrap();
            feed_reality_client_connection(&mut client, &flight).unwrap();
            flight.clear();
            client.write_tls(&mut flight).unwrap();
            feed_reality_server_connection(&mut server, &flight).unwrap();
            assert!(!server.is_handshaking());
        } else {
            assert_eq!(
                result.unwrap_err().kind(),
                io::ErrorKind::PermissionDenied,
                "{case}"
            );
            assert!(!server.wants_write());
        }
    }
}

#[test]
fn rejected_client_finished_never_completes_handshake() {
    let secrets = Arc::new(Secrets::default());
    let (mut client, mut server, flight) = pending_pair(secrets.clone(), false);
    feed_reality_client_connection(&mut client, &flight.concat()).unwrap();
    let mut wire = Vec::new();
    client.write_tls(&mut wire).unwrap();
    let secret = secrets.0.lock()["CLIENT_HANDSHAKE_TRAFFIC_SECRET"].clone();
    for record in records(&wire) {
        if record[0] == 20 {
            feed_reality_server_connection(&mut server, &record).unwrap();
            continue;
        }
        let bad = mutate_record(&record, &secret, 0, |plaintext| plaintext[4] ^= 1);
        let error = feed_reality_server_connection(&mut server, &bad).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(server.is_handshaking());
        assert!(server.reader().fill_buf().is_err());
        assert!(server.writer().write(b"forbidden").is_err());
        assert!(!server.wants_write());
    }
}

#[test]
fn server_hello_must_echo_session_and_select_offered_cipher() {
    for offset in [44, 76] {
        let (mut client, _, flight) = pending_pair(Arc::default(), false);
        let mut hello = flight[0].to_vec();
        hello[offset] ^= 1;
        assert!(feed_reality_client_connection(&mut client, &hello).is_err());
        assert!(client.is_handshaking());
        assert!(!client.wants_write());
    }
}

#[test]
fn target_selection_is_an_allowlist_not_local_preference() {
    for allowed in [false, true] {
        let (mut cc, mut sc) = configs(CipherSuite::AES_128_GCM_SHA256);
        cc.cipher_suites = DEFAULT_CIPHER_SUITES.to_vec();
        if allowed {
            sc.cipher_suites = cc.cipher_suites.clone();
        }
        let mut client = RealityClientConnection::new(cc).unwrap();
        let mut server = RealityServerConnection::new(sc).unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        server.validate_client_hello(&hello).unwrap();
        let target = target_records(
            RealityGroup::X25519,
            CipherSuite::AES_256_GCM_SHA384,
            &hello[44..76],
        );
        let result = server.build_server_response(&target);
        if allowed {
            result.unwrap();
            let mut wire = Vec::new();
            server.write_tls(&mut wire).unwrap();
            // This fixture has supported_versions before key_share; preserve every byte preceding the share.
            assert_eq!(&wire[..90], &target[0][..90]);
            feed_reality_client_connection(&mut client, &wire).unwrap();
            assert!(!client.is_handshaking());
        } else {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
            assert!(!server.wants_write());
        }
    }
}

#[test]
fn rejected_templates_never_queue_synthetic_output() {
    for case in [
        "ccs",
        "version",
        "type",
        "length",
        "short",
        "extra",
        "session",
        "unknown-extension",
    ] {
        let (cc, sc) = configs(CipherSuite::AES_128_GCM_SHA256);
        let mut client = RealityClientConnection::new(cc).unwrap();
        let mut server = RealityServerConnection::new(sc).unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        server.validate_client_hello(&hello).unwrap();
        let mut target = separate_target_records(
            RealityGroup::X25519,
            CipherSuite::AES_128_GCM_SHA256,
            &hello[44..76],
        );
        let (index, offset) = match case {
            "ccs" => (1, 5),
            "version" => (2, 2),
            "type" => (2, 0),
            "length" => (3, 4),
            "session" => (0, 44),
            "unknown-extension" => (0, 81),
            "short" => {
                target[3] = Bytes::from_static(&[
                    23, 3, 3, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]);
                (3, 5)
            }
            "extra" => {
                target.extend([target[5].clone(), target[5].clone()]);
                (7, 5)
            }
            _ => unreachable!(),
        };
        let mut bad = target[index].to_vec();
        bad[offset] ^= 1;
        target[index] = bad.into();
        assert_eq!(
            server.build_server_response(&target).unwrap_err().kind(),
            io::ErrorKind::Unsupported,
            "{case}"
        );
        let mut output = Vec::new();
        server.write_tls(&mut output).unwrap();
        assert!(output.is_empty(), "{case}");
    }
}

#[test]
fn authenticated_non_contributory_tls_share_forwards_before_commit() {
    use super::reality_auth::{derive_auth_key, encrypt_session_id, perform_ecdh};
    let (cc, sc) = configs(CipherSuite::AES_128_GCM_SHA256);
    let mut client = RealityClientConnection::new(cc).unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    let shares = super::reality_key_exchange::extract_client_key_shares(&hello).unwrap();
    let shared =
        perform_ecdh(&sc.private_key, shares.authentication_public_key().unwrap()).unwrap();
    let auth = derive_auth_key(&shared, &hello[11..31], b"REALITY").unwrap();
    let hybrid = shares.hybrid.unwrap();
    let position = hello
        .windows(hybrid.len())
        .position(|bytes| bytes == hybrid.as_slice())
        .unwrap();
    hello[position + 1184..position + 1216].fill(0);
    let mut aad = hello[5..].to_vec();
    aad[39..71].fill(0);
    let mut payload = [0; 16];
    payload[..3].copy_from_slice(&[1, 8, 0]);
    payload[8..].fill(1);
    let session = encrypt_session_id(&payload, &auth, &hello[31..43], &aad).unwrap();
    hello[44..76].copy_from_slice(&session);
    let mut server = RealityServerConnection::new(sc).unwrap();
    server.validate_client_hello(&hello).unwrap();
    let result = server.build_server_response(&target_records(
        RealityGroup::X25519MlKem768,
        CipherSuite::AES_128_GCM_SHA256,
        &session,
    ));
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
    assert!(!server.wants_write());
}
