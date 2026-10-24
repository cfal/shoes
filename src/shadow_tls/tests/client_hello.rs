use super::*;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
    let mut bytes = kind.to_be_bytes().to_vec();
    bytes.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(data);
    bytes
}

fn server_name(name_type: u8, name: &[u8]) -> Vec<u8> {
    let mut entry = vec![name_type];
    entry.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
    entry.extend_from_slice(name);
    let mut list = u16::try_from(entry.len()).unwrap().to_be_bytes().to_vec();
    list.extend_from_slice(&entry);
    extension(TLS_EXT_SERVER_NAME, &list)
}

fn supported_versions(versions: &[[u8; 2]]) -> Vec<u8> {
    let mut list = vec![u8::try_from(versions.len() * 2).unwrap()];
    list.extend(versions.iter().flatten());
    extension(TLS_EXT_SUPPORTED_VERSIONS, &list)
}

fn handshake_body(session_id: &[u8], extensions: &[u8]) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0x11; 32]);
    body.push(u8::try_from(session_id.len()).unwrap());
    body.extend_from_slice(session_id);
    body.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
    body.extend_from_slice(&u16::try_from(extensions.len()).unwrap().to_be_bytes());
    body.extend_from_slice(extensions);
    body
}

fn record(handshake_type: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = vec![CONTENT_TYPE_HANDSHAKE, 3, 1];
    frame.extend_from_slice(&u16::try_from(4 + body.len()).unwrap().to_be_bytes());
    frame.push(handshake_type);
    frame.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
    frame.extend_from_slice(body);
    frame
}

fn client_hello(session_id: &[u8], extensions: &[u8]) -> Vec<u8> {
    record(
        HANDSHAKE_TYPE_CLIENT_HELLO,
        &handshake_body(session_id, extensions),
    )
}

/// A stream that yields `bytes` and then EOF.
async fn stream_of(bytes: &[u8]) -> Box<dyn AsyncStream> {
    let (io, mut peer) = tokio::io::duplex(TLS_FRAME_MAX_LEN);
    peer.write_all(bytes).await.unwrap();
    peer.shutdown().await.unwrap();
    Box::new(io)
}

async fn parse(bytes: &[u8]) -> std::io::Result<ParsedClientHello> {
    let mut stream = stream_of(bytes).await;
    tokio::time::timeout(Duration::from_secs(2), read_client_hello(&mut stream))
        .await
        .expect("ClientHello parsing must not wait beyond the supplied bytes")
}

#[tokio::test]
async fn rustls_hello_exposes_sni_tls13_and_the_session_id_digest() {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    let mut client =
        rustls::ClientConnection::new(Arc::new(config), "camouflage.example".try_into().unwrap())
            .unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();

    let parsed = parse(&hello).await.unwrap();
    assert_eq!(parsed.client_hello_frame, hello);
    assert_eq!(
        parsed.requested_server_name.as_deref(),
        Some("camouflage.example")
    );
    assert!(parsed.supports_tls13);
    let digest = parsed
        .parsed_digest
        .expect("rustls sends a 32-byte session id");
    assert_eq!(
        digest.client_hello_digest_end_index - digest.client_hello_digest_start_index,
        4
    );
    assert_eq!(
        &hello[digest.client_hello_digest_start_index..digest.client_hello_digest_end_index],
        digest.client_hello_digest.as_slice()
    );
}

#[tokio::test]
async fn only_32_byte_session_ids_carry_a_digest() {
    for len in [0, 1, 16, 31] {
        let parsed = parse(&client_hello(&vec![7; len], &[])).await.unwrap();
        assert!(parsed.parsed_digest.is_none(), "session id length {len}");
    }
    let session_id: Vec<u8> = (0..32).collect();
    let hello = client_hello(&session_id, &[]);
    let digest = parse(&hello).await.unwrap().parsed_digest.unwrap();
    assert_eq!(digest.client_hello_digest, [28, 29, 30, 31]);
    assert_eq!(
        &hello[digest.client_hello_digest_start_index..digest.client_hello_digest_end_index],
        &[28, 29, 30, 31]
    );
}

#[tokio::test]
async fn tls13_support_requires_the_supported_versions_entry() {
    for (versions, tls13) in [
        (vec![[3, 3]], false),
        (vec![[3, 3], [3, 4]], true),
        (vec![[3, 4]], true),
        (vec![], false),
    ] {
        let parsed = parse(&client_hello(&[], &supported_versions(&versions)))
            .await
            .unwrap();
        assert_eq!(parsed.supports_tls13, tls13, "{versions:?}");
        assert_eq!(parsed.requested_server_name, None);
    }
}

#[tokio::test]
async fn bytes_after_the_hello_remain_readable() {
    let mut bytes = client_hello(&[], &server_name(0, b"front.example"));
    bytes.extend_from_slice(b"early application bytes");
    let mut stream = stream_of(&bytes).await;
    let mut parsed = read_client_hello(&mut stream).await.unwrap();
    assert_eq!(
        parsed.requested_server_name.as_deref(),
        Some("front.example")
    );
    let remaining = parsed
        .client_reader
        .read_slice(&mut stream, b"early application bytes".len())
        .await
        .unwrap();
    assert_eq!(remaining, b"early application bytes");
}

#[tokio::test]
async fn malformed_hellos_are_rejected() {
    let valid = client_hello(&[7; 32], &server_name(0, b"front.example"));
    let mut wrong_content_type = valid.clone();
    wrong_content_type[0] = 0x17;
    let mut overstated_message_length = valid.clone();
    overstated_message_length[8] += 1;
    let mut tls11_hello = valid.clone();
    tls11_hello[10] = 2;
    let mut sslv3_hello = valid.clone();
    sslv3_hello[10] = 0;
    let mut overstated_extensions = handshake_body(&[], &server_name(0, b"x"));
    let extensions_len_offset = overstated_extensions.len() - server_name(0, b"x").len() - 2;
    overstated_extensions[extensions_len_offset + 1] += 1;

    let mut duplicate_names = server_name(0, b"a.example");
    duplicate_names.extend(server_name(0, b"b.example"));
    let mut odd_versions = vec![3, 3, 3, 4, 3];
    odd_versions.insert(0, u8::try_from(odd_versions.len()).unwrap());
    let mut short_session_id = vec![3, 3];
    short_session_id.extend_from_slice(&[0x11; 32]);
    short_session_id.extend_from_slice(&[32, 1, 2, 3]);
    let set_extension_len = |mut bytes: Vec<u8>, len: usize| {
        bytes[2..4].copy_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
        bytes
    };
    let name = server_name(0, b"front.example");
    let name_overrun = set_extension_len(name.clone(), name.len() - 4 - 4);
    let mut name_trailing = name.clone();
    name_trailing.push(0);
    let name_trailing = set_extension_len(name_trailing, name.len() - 4 + 1);
    let mut versions_overrun = extension(TLS_EXT_SUPPORTED_VERSIONS, &[4, 3, 4]);
    versions_overrun.extend(extension(0xff01, &[0]));
    let mut versions_trailing = supported_versions(&[[3, 4]]);
    versions_trailing.push(0);
    let versions_trailing = set_extension_len(versions_trailing, 4);

    let cases = [
        ("wrong content type", wrong_content_type),
        ("wrong handshake type", record(2, &handshake_body(&[], &[]))),
        ("overstated message length", overstated_message_length),
        ("TLS 1.1 client version", tls11_hello),
        ("SSL 3.0 client version", sslv3_hello),
        (
            "extensions overrun the hello",
            record(HANDSHAKE_TYPE_CLIENT_HELLO, &overstated_extensions),
        ),
        (
            "duplicate server names",
            client_hello(&[], &duplicate_names),
        ),
        (
            "non-hostname server name",
            client_hello(&[], &server_name(1, b"front.example")),
        ),
        (
            "non-UTF-8 server name",
            client_hello(&[], &server_name(0, &[0xff, 0xfe])),
        ),
        (
            "odd supported_versions length",
            client_hello(&[], &extension(TLS_EXT_SUPPORTED_VERSIONS, &odd_versions)),
        ),
        (
            "session id overruns the hello",
            record(HANDSHAKE_TYPE_CLIENT_HELLO, &short_session_id),
        ),
        (
            "server name overruns its extension",
            client_hello(&[], &name_overrun),
        ),
        (
            "server name extension with trailing bytes",
            client_hello(&[], &name_trailing),
        ),
        (
            "empty server name list",
            client_hello(&[], &extension(TLS_EXT_SERVER_NAME, &[0, 0])),
        ),
        (
            "supported_versions overruns its extension",
            client_hello(&[], &versions_overrun),
        ),
        (
            "supported_versions with trailing bytes",
            client_hello(&[], &versions_trailing),
        ),
    ];
    for (name, bytes) in cases {
        assert!(parse(&bytes).await.is_err(), "{name} was accepted");
    }
}

#[tokio::test]
async fn truncated_records_are_rejected_at_eof() {
    let hello = client_hello(&[7; 32], &server_name(0, b"front.example"));
    for len in [0, 1, TLS_HEADER_LEN, TLS_HEADER_LEN + 1, hello.len() - 1] {
        assert!(parse(&hello[..len]).await.is_err(), "{len}-byte prefix");
    }
}

#[tokio::test]
async fn hellos_split_across_records_are_reassembled() {
    let hello = crate::sniff::tests::hello(&rustls::version::TLS13, true);
    for chunk in [1, 2, 3, 4, 137] {
        let split = crate::sniff::tests::records(&hello, chunk);
        let parsed = parse(&split).await.unwrap();
        assert_eq!(parsed.client_hello_frame, split, "chunk={chunk}");
        assert_eq!(parsed.client_hello_record, hello, "chunk={chunk}");
        assert_eq!(
            parsed.requested_server_name.as_deref(),
            Some("sniff.example")
        );
        assert!(parsed.supports_tls13);
        // ShadowTLS authenticates its digest within a single record.
        assert!(parsed.parsed_digest.is_none(), "chunk={chunk}");
    }
}

#[tokio::test]
async fn alpn_selection_survives_fragmented_client_hellos() {
    for (protocols, acme) in [
        (b"\x00\x0b\x0aacme-tls/1".as_slice(), true),
        (b"\x00\x03\x02h2".as_slice(), false),
    ] {
        let mut extensions = server_name(0, b"proxy.example");
        extensions.extend(extension(TLS_EXT_ALPN, protocols));
        extensions.extend(supported_versions(&[[3, 4]]));
        let hello = client_hello(&[7; 32], &extensions);
        for chunk in [1, 3, 137] {
            let split = crate::sniff::tests::records(&hello, chunk);
            let parsed = parse(&split).await.unwrap();
            assert_eq!(parsed.acme_alpn, acme);
            assert_eq!(
                parsed.requested_server_name.as_deref(),
                Some("proxy.example")
            );
            assert!(parsed.supports_tls13);
            assert_eq!(parsed.client_hello_frame, split);
            assert_eq!(parsed.client_hello_record, hello);
        }
    }
}

#[tokio::test]
async fn malformed_or_mixed_acme_alpn_retains_normal_dispatch() {
    let alpn = extension(TLS_EXT_ALPN, b"\x00\x0b\x0aacme-tls/1");
    let mut duplicate = alpn.clone();
    duplicate.extend(alpn);
    for extensions in [
        duplicate,
        extension(TLS_EXT_ALPN, b"\x00\x0e\x0aacme-tls/1\x02h2"),
        extension(TLS_EXT_ALPN, b"\x00\x04\x02h2"),
        extension(TLS_EXT_ALPN, b"\x00\x02\x02h"),
        extension(TLS_EXT_ALPN, b"\x00\x01\x00"),
    ] {
        assert!(
            !parse(&client_hello(&[], &extensions))
                .await
                .unwrap()
                .acme_alpn
        );
    }
}

#[tokio::test]
async fn invalid_record_framing_is_rejected() {
    let hello = crate::sniff::tests::hello(&rustls::version::TLS13, true);
    let split = crate::sniff::tests::records(&hello, 100);
    let mut interleaved = split[..105].to_vec();
    interleaved.extend_from_slice(&[0x14, 3, 3, 0, 1, 1]);
    interleaved.extend_from_slice(&split[105..]);
    let mut empty_record = split[..105].to_vec();
    empty_record.extend_from_slice(&[CONTENT_TYPE_HANDSHAKE, 3, 1, 0, 0]);
    empty_record.extend_from_slice(&split[105..]);
    let mut trailing = hello.clone();
    trailing.push(HANDSHAKE_TYPE_CLIENT_HELLO);
    let record_len = u16::from_be_bytes([trailing[3], trailing[4]]) + 1;
    trailing[3..5].copy_from_slice(&record_len.to_be_bytes());
    for (name, bytes) in [
        ("non-handshake record inside the hello", interleaved),
        ("empty handshake record", empty_record),
        ("handshake data after the hello", trailing),
        (
            "hello longer than one record can carry",
            vec![CONTENT_TYPE_HANDSHAKE, 3, 1, 0, 4, 1, 1, 0, 0],
        ),
    ] {
        let Err(error) = parse(&bytes).await else {
            panic!("{name} was accepted");
        };
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::InvalidData,
            "{name}: {error}"
        );
    }
}
