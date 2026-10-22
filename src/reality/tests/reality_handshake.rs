use std::io::{self, BufRead, Read, Write};
use std::sync::Arc;

use crate::crypto::TlsConnection;
use bytes::Bytes;
use parking_lot::Mutex;

use super::reality_fixtures::{
    configs, established_pair, handshake, separate_target_records, target_records,
    target_with_unknown_extension, write_record_header,
};
use crate::reality::reality_hello::{RealityGroup, extract_client_key_shares};
use crate::reality::{CipherSuite, DEFAULT_CIPHER_SUITES, reality_rustls_adapter};

#[derive(Debug, Default)]
struct Secrets(Mutex<std::collections::HashMap<String, Vec<u8>>>);

#[test]
fn provider_preserves_cipher_defaults_order_and_duplicates() {
    for suites in [
        Vec::new(),
        vec![
            CipherSuite::CHACHA20_POLY1305_SHA256,
            CipherSuite::AES_256_GCM_SHA384,
        ],
        vec![CipherSuite::AES_128_GCM_SHA256; 2],
    ] {
        let provider = reality_rustls_adapter::provider(&suites);
        let expected = if suites.is_empty() {
            DEFAULT_CIPHER_SUITES
        } else {
            &suites
        };
        assert_eq!(
            provider
                .cipher_suites
                .iter()
                .map(|suite| u16::from(suite.suite()))
                .collect::<Vec<_>>(),
            expected.iter().map(CipherSuite::id).collect::<Vec<_>>()
        );
    }
}

#[test]
fn interleaved_connections_do_not_share_authentication_state() {
    let pending: Vec<_> = (0..4).map(|_| pending_pair(Arc::default(), true)).collect();
    for (mut client, mut server, flight) in pending {
        client.feed(&flight.concat()).unwrap();
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        server.feed(&wire).unwrap();
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
    let mut client = cc.create_connection().unwrap();
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
        client.feed(&wire).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(client.is_handshaking() && !client.wants_write());
}

#[test]
fn authenticated_hellos_longer_than_one_record_reach_rustls() {
    use crate::reality::reality_auth::{derive_auth_key, encrypt_session_id, perform_ecdh};
    let (cc, sc) = configs(CipherSuite::AES_128_GCM_SHA256);
    let mut client = cc.create_connection().unwrap();
    let mut records = Vec::new();
    client.write_tls(&mut records).unwrap();
    // Pad the hello past 16 KiB, as a client could after reassembly, and authenticate it again.
    let mut padding = vec![0xff, 0xa5, 0x45, 0x00];
    padding.resize(4 + 0x4500, 0);
    let records = crate::sniff::tests::extend_hello(records, &padding);
    // Rejoin the records into the single record that reassembly produces.
    let mut hello = crate::sniff::tests::records(&records, u16::MAX.into());
    let message_len = usize::from(u16::from_be_bytes([hello[3], hello[4]]));
    assert_eq!(hello.len(), 5 + message_len);
    assert!(message_len > 16384);
    let shares = extract_client_key_shares(&hello).unwrap();
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

    let mut server = sc
        .authenticate_client_hello(&hello)
        .unwrap()
        .into_connection(&target_records(
            RealityGroup::X25519MlKem768,
            CipherSuite::AES_128_GCM_SHA256,
            &hello[44..76],
        ))
        .unwrap();
    let mut flight = Vec::new();
    server.write_tls(&mut flight).unwrap();
    assert!(!flight.is_empty());
}

#[test]
fn ordinary_tls_client_hello_is_denied() {
    let (_, sc) = configs(CipherSuite::AES_128_GCM_SHA256);
    let config = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let mut client =
        rustls::ClientConnection::new(Arc::new(config), "cover.test".try_into().unwrap()).unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    assert_eq!(
        sc.authenticate_client_hello(&hello).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
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
) -> (TlsConnection, TlsConnection, Vec<Bytes>) {
    let (cc, sc) = configs(CipherSuite::AES_128_GCM_SHA256);
    let crypto = reality_rustls_adapter::provider(&cc.cipher_suites);
    let mut schemes = crypto.signature_verification_algorithms.supported_schemes();
    if omit_ed25519 {
        schemes.retain(|scheme| *scheme != rustls::SignatureScheme::ED25519);
    }
    let mut client = cc
        .create_connection_with_options(crypto, schemes, secrets)
        .unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    let authenticated = sc.authenticate_client_hello(&hello).unwrap();
    let target = separate_target_records(
        RealityGroup::X25519MlKem768,
        CipherSuite::AES_128_GCM_SHA256,
        &hello[44..76],
    );
    let mut server = authenticated.into_connection(&target).unwrap();
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
    client.feed(&flight.concat()).unwrap();
    let mut wire = Vec::new();
    client.write_tls(&mut wire).unwrap();
    server.feed(&wire).unwrap();
    assert!(!client.is_handshaking() && !server.is_handshaking());
    for _ in 0..3 {
        client.refresh_traffic_keys().unwrap();
        client.writer().write_all(b"updated client").unwrap();
        wire.clear();
        client.write_tls(&mut wire).unwrap();
        server.feed(&wire).unwrap();
        let mut data = [0; 14];
        server.reader().read_exact(&mut data).unwrap();
        assert_eq!(&data, b"updated client");
        server.refresh_traffic_keys().unwrap();
        server.writer().write_all(b"updated server").unwrap();
        wire.clear();
        server.write_tls(&mut wire).unwrap();
        client.feed(&wire).unwrap();
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
            client.feed(record).unwrap();
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
        let error = client.feed(&mutated_flight).unwrap_err();
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
fn client_hello_carries_authenticated_reality_metadata() {
    use crate::reality::reality_auth::{decrypt_session_id, derive_auth_key, perform_ecdh};

    let (mut cc, mut sc) = configs(CipherSuite::AES_128_GCM_SHA256);
    let short_id = [1, 2, 3, 4, 5, 6, 7, 8];
    cc.short_id = short_id;
    sc.short_ids = vec![[0; 8], short_id, [255; 8]];
    sc.min_client_version = Some([1, 8, 0]);
    sc.max_client_version = Some([1, 8, 0]);
    sc.max_time_diff = Some(60_000);

    let mut client = cc.create_connection().unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    let shares = extract_client_key_shares(&hello).unwrap();
    let shared =
        perform_ecdh(&sc.private_key, shares.authentication_public_key().unwrap()).unwrap();
    let auth = derive_auth_key(&shared, &hello[11..31], b"REALITY").unwrap();
    assert_eq!(hello[43], 32);
    let session = hello[44..76].try_into().unwrap();
    let mut aad = hello[5..].to_vec();
    aad[39..71].fill(0);
    let metadata = decrypt_session_id(session, &auth, &hello[31..43], &aad).unwrap();
    assert_eq!(metadata[..4], [1, 8, 0, 0]);
    assert_eq!(metadata[8..], short_id);
    sc.authenticate_client_hello(&hello).unwrap();
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
        let mut crypto = reality_rustls_adapter::provider(&cc.cipher_suites);
        if case == "plain-only" {
            crypto.kx_groups.remove(0);
        }
        if case == "hybrid-only" {
            crypto.kx_groups.pop();
        }
        let schemes = crypto.signature_verification_algorithms.supported_schemes();
        let mut client = cc
            .create_connection_with_options(crypto, schemes, Arc::new(rustls::NoKeyLog {}))
            .unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        if case == "tampered-hello" {
            hello[11] ^= 1;
        }
        if case == "timestamp" {
            use crate::reality::reality_auth::{derive_auth_key, encrypt_session_id, perform_ecdh};
            let shares = extract_client_key_shares(&hello).unwrap();
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
        let result = sc.authenticate_client_hello(&hello);
        if matches!(case, "valid" | "plain-only" | "hybrid-only") {
            let authenticated = result.unwrap();
            let group = if case == "plain-only" {
                RealityGroup::X25519
            } else {
                RealityGroup::X25519MlKem768
            };
            let mut server = authenticated
                .into_connection(&target_records(
                    group,
                    CipherSuite::AES_128_GCM_SHA256,
                    &hello[44..76],
                ))
                .unwrap();
            let mut flight = Vec::new();
            server.write_tls(&mut flight).unwrap();
            client.feed(&flight).unwrap();
            flight.clear();
            client.write_tls(&mut flight).unwrap();
            server.feed(&flight).unwrap();
            assert!(!server.is_handshaking());
        } else {
            assert_eq!(
                result.unwrap_err().kind(),
                io::ErrorKind::PermissionDenied,
                "{case}"
            );
        }
    }
}

#[test]
fn rejected_client_finished_never_completes_handshake() {
    let secrets = Arc::new(Secrets::default());
    let (mut client, mut server, flight) = pending_pair(secrets.clone(), false);
    client.feed(&flight.concat()).unwrap();
    let mut wire = Vec::new();
    client.write_tls(&mut wire).unwrap();
    let secret = secrets.0.lock()["CLIENT_HANDSHAKE_TRAFFIC_SECRET"].clone();
    for record in records(&wire) {
        if record[0] == 20 {
            server.feed(&record).unwrap();
            continue;
        }
        let bad = mutate_record(&record, &secret, 0, |plaintext| plaintext[4] ^= 1);
        let error = server.feed(&bad).unwrap_err();
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
        assert!(client.feed(&hello).is_err());
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
        let mut client = cc.create_connection().unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        let authenticated = sc.authenticate_client_hello(&hello).unwrap();
        let target = target_records(
            RealityGroup::X25519,
            CipherSuite::AES_256_GCM_SHA384,
            &hello[44..76],
        );
        let result = authenticated.into_connection(&target);
        if allowed {
            let mut server = result.unwrap();
            let mut wire = Vec::new();
            server.write_tls(&mut wire).unwrap();
            // This fixture has supported_versions before key_share; preserve every byte preceding the share.
            assert_eq!(&wire[..90], &target[0][..90]);
            client.feed(&wire).unwrap();
            assert!(!client.is_handshaking());
        } else {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
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
        let mut client = cc.create_connection().unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        let authenticated = sc.authenticate_client_hello(&hello).unwrap();
        let mut target = separate_target_records(
            RealityGroup::X25519,
            CipherSuite::AES_128_GCM_SHA256,
            &hello[44..76],
        );
        let mutation = match case {
            "ccs" => Some((1, 5)),
            "version" => Some((2, 2)),
            "type" => Some((2, 0)),
            "length" => Some((3, 4)),
            "session" => Some((0, 44)),
            "unknown-extension" => {
                target[0] = target_with_unknown_extension(&target[0]);
                None
            }
            "short" => {
                target[3] = Bytes::from_static(&[
                    23, 3, 3, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]);
                Some((3, 5))
            }
            "extra" => {
                target.extend([target[5].clone(), target[5].clone()]);
                Some((7, 5))
            }
            _ => unreachable!(),
        };
        if let Some((index, offset)) = mutation {
            let mut bad = target[index].to_vec();
            bad[offset] ^= 1;
            target[index] = bad.into();
        }
        assert_eq!(
            authenticated.into_connection(&target).unwrap_err().kind(),
            io::ErrorKind::Unsupported,
            "{case}"
        );
    }
}

#[test]
fn authenticated_invalid_tls_shares_forward_before_commit() {
    use crate::reality::reality_auth::{derive_auth_key, encrypt_session_id, perform_ecdh};
    let (cc, sc) = configs(CipherSuite::AES_128_GCM_SHA256);
    let mut client = cc.create_connection().unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    let shares = extract_client_key_shares(&hello).unwrap();
    let shared =
        perform_ecdh(&sc.private_key, shares.authentication_public_key().unwrap()).unwrap();
    let auth = derive_auth_key(&shared, &hello[11..31], b"REALITY").unwrap();
    let hybrid = shares.hybrid.unwrap();
    let position = hello
        .windows(hybrid.len())
        .position(|bytes| bytes == hybrid.as_slice())
        .unwrap();
    for invalid_mlkem in [false, true] {
        let mut hello = hello.clone();
        if invalid_mlkem {
            hello[position..position + 1184].fill(255);
        } else {
            hello[position + 1184..position + 1216].fill(0);
        }
        let mut aad = hello[5..].to_vec();
        aad[39..71].fill(0);
        let mut payload = [0; 16];
        payload[..3].copy_from_slice(&[1, 8, 0]);
        payload[8..].fill(1);
        let session = encrypt_session_id(&payload, &auth, &hello[31..43], &aad).unwrap();
        hello[44..76].copy_from_slice(&session);
        let authenticated = sc.clone().authenticate_client_hello(&hello).unwrap();
        let result = authenticated.into_connection(&target_records(
            RealityGroup::X25519MlKem768,
            CipherSuite::AES_128_GCM_SHA256,
            &session,
        ));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
    }
}

#[test]
fn tcp_eof_without_close_notify_is_not_clean_tls_eof() {
    let (mut client, mut server) = established_pair();
    client.writer().write_all(b"request").unwrap();
    server.writer().write_all(b"response").unwrap();
    let mut wire = Vec::new();
    client.write_tls(&mut wire).unwrap();
    server.feed(&wire).unwrap();
    wire.clear();
    server.write_tls(&mut wire).unwrap();
    client.feed(&wire).unwrap();
    assert_eq!(client.read_tls(&mut io::empty()).unwrap(), 0);
    assert_eq!(server.read_tls(&mut io::empty()).unwrap(), 0);
    let mut response = [0; 8];
    client.reader().read_exact(&mut response).unwrap();
    assert_eq!(&response, b"response");
    let mut request = [0; 7];
    server.reader().read_exact(&mut request).unwrap();
    assert_eq!(&request, b"request");
    assert_eq!(
        client.reader().read(&mut response).unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    assert_eq!(
        server.reader().read(&mut request).unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[test]
fn reality_separate_and_observed_trailing_record_without_mldsa() {
    for &cipher in DEFAULT_CIPHER_SUITES {
        for group in [RealityGroup::X25519, RealityGroup::X25519MlKem768] {
            let (cc, sc) = configs(cipher);
            handshake(cc, sc, group, separate_target_records, 1);
            let (cc, sc) = configs(cipher);
            handshake(
                cc,
                sc,
                group,
                |group, cipher, session| {
                    let mut records = separate_target_records(group, cipher, session);
                    let mut trailing = write_record_header(23, 59);
                    trailing.resize(64, 0);
                    records.push(trailing.into());
                    records
                },
                17,
            );
        }
    }
}
