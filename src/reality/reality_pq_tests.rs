use std::io::{Read, Write};

use crate::crypto::TlsConnection;
use aws_lc_rs::agreement;
use bytes::Bytes;

use super::reality_key_exchange::{RealityGroup, extract_client_key_shares};
use super::test_tls::{construct_server_hello, write_record_header};
use super::*;

fn public_key(private: &[u8; 32]) -> [u8; 32] {
    agreement::PrivateKey::from_private_key(&agreement::X25519, private)
        .unwrap()
        .compute_public_key()
        .unwrap()
        .as_ref()
        .try_into()
        .unwrap()
}

pub(super) fn configs(cipher: CipherSuite) -> (RealityClientConfig, RealityServerConfig) {
    let private = [42; 32];
    (
        RealityClientConfig {
            mldsa65_verify: None,
            public_key: public_key(&private),
            short_id: [1; 8],
            server_name: "cover.test".try_into().unwrap(),
            cipher_suites: vec![cipher],
        },
        RealityServerConfig {
            mldsa65_key: None,
            private_key: private,
            short_ids: vec![[1; 8]],
            dest: crate::address::NetLocation::from_str("cover.test:443", None).unwrap(),
            max_time_diff: None,
            min_client_version: None,
            max_client_version: None,
            cipher_suites: vec![cipher],
        },
    )
}

pub(super) fn target_records(
    group: RealityGroup,
    cipher: CipherSuite,
    session: &[u8],
) -> Vec<Bytes> {
    let hello = construct_server_hello(
        &[3; 32],
        session,
        cipher.id(),
        group,
        &vec![0; group.share_len(false)],
    )
    .unwrap();
    let mut record = write_record_header(22, hello.len() as u16);
    record.extend_from_slice(&hello);
    let mut encrypted = write_record_header(23, 6000);
    encrypted.resize(6005, 0);
    vec![
        record.into(),
        Bytes::from_static(&[20, 3, 3, 0, 1, 1]),
        encrypted.into(),
    ]
}

pub(crate) fn default_target_records(session: &[u8]) -> Vec<Bytes> {
    target_records(
        RealityGroup::X25519MlKem768,
        CipherSuite::AES_128_GCM_SHA256,
        session,
    )
}

pub(super) fn separate_target_records(
    group: RealityGroup,
    cipher: CipherSuite,
    session: &[u8],
) -> Vec<Bytes> {
    let mut records = target_records(group, cipher, session);
    records.truncate(2);
    for payload_len in [32, 4096, 128, 96] {
        let mut record = write_record_header(23, payload_len);
        record.resize(5 + payload_len as usize, 0);
        records.push(record.into());
    }
    records
}

pub(super) fn target_with_unknown_extension(record: &Bytes) -> Bytes {
    let mut hello = record.to_vec();
    let extensions_offset = 47 + usize::from(hello[43]);
    let extensions_len =
        u16::from_be_bytes([hello[extensions_offset], hello[extensions_offset + 1]]);
    hello.extend_from_slice(&[0xfe, 0x30, 0, 0]);
    hello[extensions_offset..extensions_offset + 2]
        .copy_from_slice(&(extensions_len + 4).to_be_bytes());
    let record_len = (hello.len() - 5) as u16;
    hello[3..5].copy_from_slice(&record_len.to_be_bytes());
    let message_len = (hello.len() - 9) as u32;
    hello[6..9].copy_from_slice(&message_len.to_be_bytes()[1..]);
    assert!(
        crate::shadow_tls::parse_server_hello(&hello)
            .unwrap()
            .is_tls13
    );
    super::reality_key_exchange::validate_server_key_share(&hello).unwrap();
    hello.into()
}

fn handshake(
    client_config: RealityClientConfig,
    server_config: RealityServerConfig,
    group: RealityGroup,
    make_target_records: fn(RealityGroup, CipherSuite, &[u8]) -> Vec<Bytes>,
    fragment: usize,
) -> (TlsConnection, TlsConnection) {
    let cipher = client_config.cipher_suites[0];
    let mut client = client_config.create_connection().unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    let shares = extract_client_key_shares(&hello).unwrap();
    assert!(shares.hybrid.is_some());
    assert!(shares.x25519.is_some());
    let authenticated = server_config.authenticate_client_hello(&hello).unwrap();
    let target = make_target_records(group, cipher, &hello[44..76]);
    let mut server = authenticated.into_connection(&target).unwrap();
    let mut response = Vec::new();
    server.write_tls(&mut response).unwrap();
    let mut deframer = crate::crypto::tls_deframer::TlsDeframer::new();
    deframer.feed(&response);
    let records = deframer.next_records().unwrap();
    assert_eq!(records.len(), target.len());
    for (actual, expected) in records.iter().zip(&target) {
        assert_eq!(actual.len(), expected.len());
    }
    let share_start = target[0].len() - group.share_len(false);
    assert_eq!(&records[0][..share_start], &target[0][..share_start]);
    for chunk in response.chunks(fragment) {
        client.feed(chunk).unwrap();
    }
    let mut finished = Vec::new();
    client.write_tls(&mut finished).unwrap();
    for chunk in finished.chunks(fragment) {
        server.feed(chunk).unwrap();
    }
    assert!(!client.is_handshaking());
    assert!(!server.is_handshaking());
    assert_eq!(
        client.negotiated_group(),
        Some(rustls::NamedGroup::from(group as u16))
    );
    assert_eq!(
        server.negotiated_group(),
        Some(rustls::NamedGroup::from(group as u16))
    );
    (client, server)
}

pub(crate) fn established_pair() -> (TlsConnection, TlsConnection) {
    let (client, server) = configs(CipherSuite::AES_128_GCM_SHA256);
    handshake(
        client,
        server,
        RealityGroup::X25519MlKem768,
        target_records,
        37,
    )
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

#[test]
fn reality_pq_handshake_and_data_all_suites() {
    for &cipher in DEFAULT_CIPHER_SUITES {
        for group in [RealityGroup::X25519MlKem768, RealityGroup::X25519] {
            let (cc, sc) = configs(cipher);
            let (mut client, mut server) = handshake(cc, sc, group, target_records, 37);
            let expected = vec![17; 200_000];
            let mut wire = Vec::new();
            for chunk in expected.chunks(8192) {
                client.writer().write_all(chunk).unwrap();
                while client.wants_write() {
                    client.write_tls(&mut wire).unwrap();
                }
            }
            let mut actual = Vec::new();
            for chunk in wire.chunks(1024) {
                server.feed(chunk).unwrap();
                let mut buffer = [0; 16384];
                loop {
                    match server.reader().read(&mut buffer) {
                        Ok(0) => break,
                        Ok(n) => actual.extend_from_slice(&buffer[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => panic!("{e}"),
                    }
                }
            }
            assert_eq!(actual, expected);
            server.writer().write_all(b"response").unwrap();
            wire.clear();
            server.write_tls(&mut wire).unwrap();
            client.feed(&wire).unwrap();
            let mut response = [0; 8];
            client.reader().read_exact(&mut response).unwrap();
            assert_eq!(&response, b"response");
            client.send_close_notify();
            wire.clear();
            client.write_tls(&mut wire).unwrap();
            server.feed(&wire).unwrap();
            assert_eq!(server.reader().read(&mut response).unwrap(), 0);
        }
    }
}

#[test]
fn reality_pq_mldsa_optional_and_required() {
    let (seed, verify) = generate_mldsa65_keypair().unwrap();
    let signer = mldsa65_signing_key(&seed).unwrap();
    let key = decode_mldsa65_verify(&verify).unwrap();
    for &cipher in DEFAULT_CIPHER_SUITES {
        for group in [RealityGroup::X25519MlKem768, RealityGroup::X25519] {
            for required in [false, true] {
                let (mut cc, mut sc) = configs(cipher);
                sc.mldsa65_key = Some(signer.clone());
                cc.mldsa65_verify = required.then(|| key.clone());
                handshake(cc.clone(), sc.clone(), group, target_records, 19);
                handshake(cc, sc, group, separate_target_records, 19);
            }
        }
    }
}

#[test]
fn reality_pq_mldsa_required_fails_closed() {
    let (seed, verify) = generate_mldsa65_keypair().unwrap();
    let (_, wrong) = generate_mldsa65_keypair().unwrap();
    for sign in [false, true] {
        let (mut cc, mut sc) = configs(CipherSuite::AES_128_GCM_SHA256);
        cc.mldsa65_verify =
            Some(decode_mldsa65_verify(if sign { &wrong } else { &verify }).unwrap());
        sc.mldsa65_key = sign.then(|| mldsa65_signing_key(&seed).unwrap());
        let mut client = cc.create_connection().unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        let authenticated = sc.authenticate_client_hello(&hello).unwrap();
        let mut server = authenticated
            .into_connection(&default_target_records(&hello[44..76]))
            .unwrap();
        let mut flight = Vec::new();
        server.write_tls(&mut flight).unwrap();
        assert_eq!(
            client.feed(&flight).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert!(client.is_handshaking());
        let _ = client.writer().write(b"forbidden");
        let mut output = Vec::new();
        client.write_tls(&mut output).unwrap();
        assert!(output.is_empty());
    }
}

#[test]
fn reality_pq_mldsa_small_target_does_not_emit_synthetic_bytes() {
    let (cc, mut sc) = configs(CipherSuite::AES_128_GCM_SHA256);
    let (seed, _) = generate_mldsa65_keypair().unwrap();
    sc.mldsa65_key = Some(mldsa65_signing_key(&seed).unwrap());
    let mut client = cc.create_connection().unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    let authenticated = sc.authenticate_client_hello(&hello).unwrap();
    let mut records = default_target_records(&hello[44..76]);
    let mut small = write_record_header(23, 595);
    small.resize(600, 0);
    records[2] = small.into();
    let error = authenticated.into_connection(&records).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    assert_eq!(
        error.to_string(),
        "Unsupported REALITY target or insufficient capacity"
    );
}

#[test]
fn reality_pq_mldsa_separate_records_each_require_capacity() {
    let (seed, _) = generate_mldsa65_keypair().unwrap();
    let signer = mldsa65_signing_key(&seed).unwrap();
    for &cipher in DEFAULT_CIPHER_SUITES {
        for small_record in 2..6 {
            let (cc, mut sc) = configs(cipher);
            sc.mldsa65_key = Some(signer.clone());
            let mut client = cc.create_connection().unwrap();
            let mut hello = Vec::new();
            client.write_tls(&mut hello).unwrap();
            let authenticated = sc.authenticate_client_hello(&hello).unwrap();
            let mut records =
                separate_target_records(RealityGroup::X25519MlKem768, cipher, &hello[44..76]);
            let mut small = write_record_header(23, 17);
            small.resize(22, 0);
            records[small_record] = small.into();
            let error = authenticated.into_connection(&records).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
            assert_eq!(
                error.to_string(),
                "Unsupported REALITY target or insufficient capacity"
            );
        }
    }
}
