//! Shared REALITY connection and independent target-wire fixtures.

use aws_lc_rs::agreement;
use bytes::Bytes;

use crate::crypto::TlsConnection;
use crate::reality::reality_hello::{
    RealityGroup, extract_client_key_shares, validate_server_key_share,
};
use crate::reality::{CipherSuite, RealityClientConfig, RealityServerConfig};

pub(in crate::reality) fn construct_server_hello(
    random: &[u8; 32],
    session: &[u8],
    cipher: u16,
    group: RealityGroup,
    key_share: &[u8],
) -> std::io::Result<Vec<u8>> {
    if key_share.len() != group.share_len(false) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid server key share size",
        ));
    }
    let mut hello = vec![2, 0, 0, 0, 3, 3];
    hello.extend_from_slice(random);
    hello.push(session.len() as u8);
    hello.extend_from_slice(session);
    hello.extend_from_slice(&cipher.to_be_bytes());
    hello.push(0);

    let mut extensions = vec![0, 43, 0, 2, 3, 4];
    extensions.extend_from_slice(&[0, 51]);
    extensions.extend_from_slice(&((4 + key_share.len()) as u16).to_be_bytes());
    extensions.extend_from_slice(&(group as u16).to_be_bytes());
    extensions.extend_from_slice(&(key_share.len() as u16).to_be_bytes());
    extensions.extend_from_slice(key_share);
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);

    let length = (hello.len() - 4) as u32;
    hello[1..4].copy_from_slice(&length.to_be_bytes()[1..]);
    Ok(hello)
}

pub(in crate::reality) fn write_record_header(record_type: u8, length: u16) -> Vec<u8> {
    let mut header = vec![record_type, 3, 3];
    header.extend_from_slice(&length.to_be_bytes());
    header
}

fn public_key(private: &[u8; 32]) -> [u8; 32] {
    agreement::PrivateKey::from_private_key(&agreement::X25519, private)
        .unwrap()
        .compute_public_key()
        .unwrap()
        .as_ref()
        .try_into()
        .unwrap()
}

pub(in crate::reality) fn configs(
    cipher: CipherSuite,
) -> (RealityClientConfig, RealityServerConfig) {
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

pub(in crate::reality) fn target_records(
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

pub(in crate::reality) fn separate_target_records(
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

pub(in crate::reality) fn target_with_unknown_extension(record: &Bytes) -> Bytes {
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
    validate_server_key_share(&hello).unwrap();
    hello.into()
}

pub(super) fn handshake(
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
