use std::io::{Read, Write};

use crate::reality::reality_hello::RealityGroup;
use crate::reality::{
    CipherSuite, DEFAULT_CIPHER_SUITES, decode_mldsa65_verify, generate_mldsa65_keypair,
    mldsa65_signing_key,
};

use super::reality_fixtures::{
    configs, default_target_records, handshake, separate_target_records, target_records,
    write_record_header,
};

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
