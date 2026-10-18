use super::*;
use crate::vless::vision_pad::pad_with_uuid_and_command;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::time::{Duration, timeout};

type LegacyVision = VisionStream<CryptoTlsStream<DuplexStream>>;

pub(super) const APPLICATION: &[u8] = b"\x17\x03\x03\x00\x03app";
const CHANGE_CIPHER_SPEC: &[u8] = b"\x14\x03\x03\x00\x01\x01";
pub(super) const TLS13_VERSION: &[u8] = b"\x00\x2b\x00\x02\x03\x04";

fn record(content_type: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![content_type, 3, 3];
    bytes.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

pub(super) fn client_hello() -> Vec<u8> {
    let (mut client, _) = new_connections(Backend::Tls13);
    let mut flight = Vec::new();
    client.write_tls(&mut flight).unwrap();
    flight
}

pub(super) fn server_hello(cipher: u16, session_id_len: u8, extensions: &[u8]) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[42; 32]);
    body.push(session_id_len);
    body.extend(std::iter::repeat_n(7, usize::from(session_id_len)));
    body.extend_from_slice(&cipher.to_be_bytes());
    body.push(0);
    body.extend_from_slice(&u16::try_from(extensions.len()).unwrap().to_be_bytes());
    body.extend_from_slice(extensions);
    let mut handshake = vec![2];
    handshake.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);
    record(0x16, &handshake)
}

fn decrypt_output(peer: &mut CryptoConnection, ciphertext: &[u8]) -> Vec<u8> {
    use std::io::Read;

    feed_and_process_crypto_connection(peer, ciphertext).unwrap();
    let mut plaintext = Vec::new();
    if let Err(error) = peer.reader().read_to_end(&mut plaintext) {
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }
    plaintext
}

async fn pair(backend: Backend) -> (LegacyVision, LegacyVision) {
    // Independent matrix cases must not inherit an exhausted cooperative budget.
    tokio::task::yield_now().await;
    let (client, server) = connection_pair(backend);
    let (left, right) = tokio::io::duplex(65536);
    (
        VisionStream::new_client(
            CryptoTlsStream::new(left, client, Some(TlsDeframer::new())),
            [7; 16],
        )
        .unwrap(),
        VisionStream::new_server(
            CryptoTlsStream::new(right, server, Some(TlsDeframer::new())),
            [7; 16],
            b"",
        )
        .unwrap(),
    )
}

pub(super) async fn transfer<S: VisionTransport>(
    sender: &mut VisionStream<S>,
    receiver: &mut VisionStream<S>,
    data: &[u8],
) {
    timeout(Duration::from_secs(2), async {
        sender.write_all(data).await.unwrap();
        sender.flush().await.unwrap();
        let mut received = vec![0; data.len()];
        receiver.read_exact(&mut received).await.unwrap();
        assert_eq!(received, data);
    })
    .await
    .expect("Vision transfer stalled");
}

fn assert_padding(client: &LegacyVision, server: &LegacyVision) {
    for stream in [client, server] {
        assert_eq!(stream.read_mode, VisionMode::PaddingTls);
        assert_eq!(stream.write_mode, VisionMode::PaddingTls);
        assert!(!stream.pending_tls_mode_switch);
    }
}

fn assert_terminal_write<S: VisionTransport>(stream: &VisionStream<S>, direct: bool) {
    if direct {
        assert_eq!(stream.write_mode, VisionMode::Direct);
        assert!(!stream.pending_tls_mode_switch);
    } else {
        // END stays pending until the next write, even after a flush.
        assert_eq!(stream.write_mode, VisionMode::PaddingTls);
        assert!(stream.pending_tls_mode_switch);
    }
}

pub(super) async fn assert_decision<S: VisionTransport>(
    client: &mut VisionStream<S>,
    server: &mut VisionStream<S>,
    direct: bool,
    server_first: bool,
) {
    assert_eq!(
        client.filter.supports_xtls(),
        direct,
        "client: {:?}",
        client.filter
    );
    assert_eq!(
        server.filter.supports_xtls(),
        direct,
        "server: {:?}",
        server.filter
    );
    let expected = if direct {
        VisionMode::Direct
    } else {
        VisionMode::Tls
    };
    let (first, second) = if server_first {
        (server, client)
    } else {
        (client, server)
    };
    transfer(first, second, APPLICATION).await;
    assert_terminal_write(first, direct);
    assert_eq!(second.read_mode, expected);
    assert_eq!(first.read_mode, VisionMode::PaddingTls);
    assert_eq!(second.write_mode, VisionMode::PaddingTls);
    transfer(second, first, APPLICATION).await;
    assert_terminal_write(second, direct);
    for stream in [&*first, &*second] {
        assert_eq!(stream.read_mode, expected);
    }
    // The receiver must follow the on-wire command, not merely the sender's local state.
    transfer(first, second, b"payload after padding stops").await;
    transfer(second, first, b"reverse payload after padding stops").await;
    assert_eq!(first.write_mode, expected);
    assert_eq!(second.write_mode, expected);
}

#[tokio::test]
async fn legacy_direct_requires_tls13_and_a_supported_cipher() {
    let cases = [
        (0x1301, TLS13_VERSION, true),
        (0x1302, TLS13_VERSION, true),
        (0x1303, TLS13_VERSION, true),
        (0x1304, TLS13_VERSION, true),
        (0x1305, TLS13_VERSION, false),
        (0xc02f, TLS13_VERSION, false),
        (0x1306, TLS13_VERSION, false),
        (0x0a0a, TLS13_VERSION, false),
        (0xc02f, b"".as_slice(), false),
        (0x1301, b"".as_slice(), false),
        (0x1301, b"\x00\x2b\x00\x02\x03\x03".as_slice(), false),
    ];
    for backend in BACKENDS {
        for (cipher, extensions, direct) in cases {
            for server_first in [false, true] {
                eprintln!(
                    "{backend:?}, cipher={cipher:#06x}, extensions={extensions:?}, server_first={server_first}"
                );
                let (mut client, mut server) = pair(backend).await;
                transfer(&mut client, &mut server, &client_hello()).await;
                assert!(!client.filter.supports_xtls());
                assert!(!server.filter.supports_xtls());
                transfer(
                    &mut server,
                    &mut client,
                    &server_hello(cipher, 32, extensions),
                )
                .await;
                assert_eq!(client.filter.supports_xtls(), direct);
                assert_eq!(server.filter.supports_xtls(), direct);
                // ServerHello and compatibility CCS alone must not end padding.
                transfer(&mut server, &mut client, CHANGE_CIPHER_SPEC).await;
                assert_padding(&client, &server);
                assert_decision(&mut client, &mut server, direct, server_first).await;
            }
        }
    }
}

#[tokio::test]
async fn legacy_direct_parses_session_ids_and_extension_boundaries() {
    let unknown = b"\xfa\xfa\x00\x07\x00\x2b\x00\x02\x03\x04\x00";
    for backend in BACKENDS {
        for session_id_len in [0, 1, 32] {
            for (extensions, direct) in [
                (TLS13_VERSION.to_vec(), true),
                ([unknown.as_slice(), TLS13_VERSION].concat(), true),
                ([TLS13_VERSION, unknown.as_slice()].concat(), true),
                (unknown.to_vec(), false),
            ] {
                eprintln!(
                    "{backend:?}, session_id_len={session_id_len}, extensions={extensions:?}"
                );
                let (mut client, mut server) = pair(backend).await;
                transfer(&mut client, &mut server, &client_hello()).await;
                transfer(
                    &mut server,
                    &mut client,
                    &server_hello(0x1301, session_id_len, &extensions),
                )
                .await;
                assert_padding(&client, &server);
                assert_decision(&mut client, &mut server, direct, false).await;
            }
        }
    }
}

#[tokio::test]
async fn legacy_malformed_server_hello_never_enables_direct() {
    let valid = server_hello(0x1301, 32, TLS13_VERSION);
    let mut long_handshake = valid.clone();
    long_handshake[6..9].copy_from_slice(&[0, 1, 0]);
    let mut short_handshake = valid.clone();
    short_handshake[6..9].copy_from_slice(&[0, 0, 2]);
    let mut long_extensions = valid.clone();
    long_extensions[79..81].copy_from_slice(&100u16.to_be_bytes());
    let mut short_extensions = valid.clone();
    short_extensions[79..81].copy_from_slice(&0u16.to_be_bytes());
    let mut retry = valid.clone();
    retry[11..43].copy_from_slice(&[
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8,
        0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8,
        0x33, 0x9c,
    ]);
    let cases = [
        ("short hello", record(0x16, &[2, 0, 0, 2, 3, 3])),
        ("handshake length", long_handshake),
        ("undersized handshake length", short_handshake),
        ("session ID length", server_hello(0x1301, 33, TLS13_VERSION)),
        ("extensions length", long_extensions),
        ("trailing data after extensions", short_extensions),
        (
            "truncated extension header",
            server_hello(0x1301, 32, &[0, 43, 0]),
        ),
        (
            "short selected version",
            server_hello(0x1301, 32, &[0, 43, 0, 1, 3]),
        ),
        (
            "truncated selected version",
            server_hello(0x1301, 32, &[0, 43, 0, 2, 3]),
        ),
        ("HelloRetryRequest", retry),
    ];
    for backend in BACKENDS {
        for (name, hello) in &cases {
            eprintln!("{backend:?}, {name}");
            assert!(
                crate::shadow_tls::parse_server_hello(hello).is_err(),
                "{name}"
            );
            let (mut client, mut server) = pair(backend).await;
            transfer(&mut client, &mut server, &client_hello()).await;
            transfer(&mut server, &mut client, hello).await;
            assert!(!client.filter.supports_xtls());
            assert!(!server.filter.supports_xtls());
            assert_padding(&client, &server);
            assert_decision(&mut client, &mut server, false, false).await;
        }
    }
}

#[tokio::test]
async fn legacy_server_hello_write_splits_preserve_the_decision() {
    for backend in BACKENDS {
        for (cipher, direct) in [(0x1301, true), (0x1305, false)] {
            let hello = server_hello(cipher, 32, TLS13_VERSION);
            for split in 1..hello.len() {
                eprintln!("{backend:?}, cipher={cipher:#06x}, split={split}");
                let (mut client, mut server) = pair(backend).await;
                transfer(&mut client, &mut server, &client_hello()).await;
                server.write_all(&hello[..split]).await.unwrap();
                server.flush().await.unwrap();
                assert!(!server.filter.supports_xtls());
                let mut byte = [0];
                let mut buf = ReadBuf::new(&mut byte);
                assert!(
                    Pin::new(&mut client)
                        .poll_read(&mut Context::from_waker(noop_waker_ref()), &mut buf)
                        .is_pending()
                );
                assert!(buf.filled().is_empty());
                assert_padding(&client, &server);
                server.write_all(&hello[split..]).await.unwrap();
                server.flush().await.unwrap();
                let mut received = vec![0; hello.len()];
                timeout(Duration::from_secs(2), client.read_exact(&mut received))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(received, hello);
                assert_padding(&client, &server);
                assert_decision(&mut client, &mut server, direct, false).await;
            }
        }
    }
}

#[tokio::test]
async fn legacy_server_hello_across_incoming_vision_frames_preserves_the_decision() {
    for backend in BACKENDS {
        for (cipher, direct) in [(0x1301, true), (0x1305, false)] {
            let hello = server_hello(cipher, 32, TLS13_VERSION);
            for split in 1..hello.len() {
                eprintln!("incoming {backend:?}, cipher={cipher:#06x}, split={split}");
                tokio::task::yield_now().await;
                let (session, mut peer) = connection_pair(backend);
                let (io, mut wire) = tokio::io::duplex(65536);
                let mut client = VisionStream::new_client(
                    CryptoTlsStream::new(io, session, Some(TlsDeframer::new())),
                    [7; 16],
                )
                .unwrap();
                let request = client_hello();
                client.write_all(&request).await.unwrap();
                client.flush().await.unwrap();
                for (index, fragment) in [&hello[..split], &hello[split..]].into_iter().enumerate()
                {
                    let mut padded = Vec::new();
                    if index == 0 {
                        padded.extend_from_slice(&[0, 0]);
                        padded.extend_from_slice(&[7; 16]);
                    }
                    padded.push(COMMAND_CONTINUE);
                    padded.extend_from_slice(&u16::try_from(fragment.len()).unwrap().to_be_bytes());
                    padded.extend_from_slice(&[0, 0]);
                    padded.extend_from_slice(fragment);
                    wire.write_all(&encrypt(&mut peer, &padded)).await.unwrap();
                    let mut received = vec![0; fragment.len()];
                    timeout(Duration::from_secs(2), client.read_exact(&mut received))
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(received, fragment);
                    assert_eq!(client.filter.supports_xtls(), index == 1 && direct);
                    assert_eq!(client.read_mode, VisionMode::PaddingTls);
                    assert_eq!(client.write_mode, VisionMode::PaddingTls);
                }
                client.write_all(APPLICATION).await.unwrap();
                client.flush().await.unwrap();
                assert_terminal_write(&client, direct);

                let mut ciphertext = Vec::new();
                loop {
                    let mut scratch = [0; 4096];
                    let mut buf = ReadBuf::new(&mut scratch);
                    match Pin::new(&mut wire)
                        .poll_read(&mut Context::from_waker(noop_waker_ref()), &mut buf)
                    {
                        Poll::Ready(Ok(())) => {
                            assert!(!buf.filled().is_empty());
                            ciphertext.extend_from_slice(buf.filled());
                        }
                        Poll::Pending => break,
                        Poll::Ready(Err(error)) => panic!("{error}"),
                    }
                }
                let plaintext = decrypt_output(&mut peer, &ciphertext);
                let decoded = VisionUnpadder::new([7; 16]).unpad(&plaintext).unwrap();
                let command = if direct {
                    UnpadCommand::Direct
                } else {
                    UnpadCommand::End
                };
                assert_eq!(decoded.command, Some(command));
                assert_eq!(decoded.content, [request.as_slice(), APPLICATION].concat());
            }
        }
    }
}

#[tokio::test]
async fn legacy_incomplete_handshake_records_never_enable_direct() {
    let hello = server_hello(0x1301, 32, TLS13_VERSION);
    let handshake = &hello[5..];
    for backend in BACKENDS {
        for split in [1, 4, 40, handshake.len() - 1] {
            let (mut client, mut server) = pair(backend).await;
            transfer(&mut client, &mut server, &client_hello()).await;
            // Separate TLS records are not the same as splitting one record across writes.
            let records = [
                record(0x16, &handshake[..split]),
                record(0x16, &handshake[split..]),
            ]
            .concat();
            transfer(&mut server, &mut client, &records).await;
            assert_padding(&client, &server);
            assert_decision(&mut client, &mut server, false, false).await;
        }
    }
}

#[tokio::test]
async fn legacy_application_splits_and_coalesced_tail_preserve_the_decision() {
    for backend in BACKENDS {
        for (cipher, direct) in [(0x1301, true), (0x1305, false)] {
            for server_first in [false, true] {
                for split in 1..APPLICATION.len() {
                    eprintln!(
                        "{backend:?}, cipher={cipher:#06x}, server_first={server_first}, split={split}"
                    );
                    let (mut client, mut server) = pair(backend).await;
                    transfer(&mut client, &mut server, &client_hello()).await;
                    transfer(
                        &mut server,
                        &mut client,
                        &server_hello(cipher, 32, TLS13_VERSION),
                    )
                    .await;
                    let expected = if direct {
                        VisionMode::Direct
                    } else {
                        VisionMode::Tls
                    };
                    let (sender, receiver) = if server_first {
                        (&mut server, &mut client)
                    } else {
                        (&mut client, &mut server)
                    };
                    sender.write_all(&APPLICATION[..split]).await.unwrap();
                    sender.flush().await.unwrap();
                    assert_eq!(sender.write_mode, VisionMode::PaddingTls);
                    assert!(!sender.pending_tls_mode_switch);
                    let tail = b"coalesced bytes after application record";
                    let rest = [&APPLICATION[split..], tail].concat();
                    sender.write_all(&rest).await.unwrap();
                    sender.flush().await.unwrap();
                    let mut received = vec![0; APPLICATION.len() + tail.len()];
                    timeout(Duration::from_secs(2), receiver.read_exact(&mut received))
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(received, [APPLICATION, tail].concat());
                    assert_eq!(sender.write_mode, expected);
                    assert_eq!(receiver.read_mode, expected);
                    transfer(receiver, sender, APPLICATION).await;
                    assert_terminal_write(receiver, direct);
                    assert_eq!(sender.read_mode, expected);
                    transfer(receiver, sender, b"reverse tail").await;
                    assert_eq!(receiver.write_mode, expected);
                }
            }
        }
    }
}

#[tokio::test]
async fn legacy_filter_budget_does_not_enable_direct_after_end() {
    let handshake = record(0x16, &[11, 0, 0, 0]);
    for backend in BACKENDS {
        for extra_records in [6, 7] {
            let (mut client, mut server) = pair(backend).await;
            transfer(&mut client, &mut server, &client_hello()).await;
            for _ in 0..extra_records {
                transfer(&mut server, &mut client, &handshake).await;
            }
            transfer(
                &mut server,
                &mut client,
                &server_hello(0x1301, 32, TLS13_VERSION),
            )
            .await;
            if extra_records == 6 {
                assert_decision(&mut client, &mut server, true, false).await;
            } else {
                assert_eq!(server.write_mode, VisionMode::Tls);
                assert_eq!(client.read_mode, VisionMode::Tls);
                assert!(!server.filter.supports_xtls());
                assert!(!client.filter.supports_xtls());
                transfer(&mut client, &mut server, APPLICATION).await;
                assert_terminal_write(&client, false);
                assert_eq!(server.read_mode, VisionMode::Tls);
                transfer(&mut client, &mut server, b"still encrypted").await;
                assert_eq!(client.write_mode, VisionMode::Tls);
                transfer(&mut server, &mut client, APPLICATION).await;
                assert_eq!(server.write_mode, VisionMode::Tls);
                assert_eq!(client.read_mode, VisionMode::Tls);
            }
        }
    }
}

#[tokio::test]
async fn legacy_client_hello_alone_never_enables_direct() {
    for backend in BACKENDS {
        let (mut client, mut server) = pair(backend).await;
        transfer(&mut client, &mut server, &client_hello()).await;
        assert_padding(&client, &server);
        transfer(&mut client, &mut server, APPLICATION).await;
        assert_terminal_write(&client, false);
        assert_eq!(server.read_mode, VisionMode::Tls);
        transfer(&mut client, &mut server, b"still encrypted").await;
        assert_eq!(client.write_mode, VisionMode::Tls);
    }
}

#[test]
fn legacy_pending_hello_write_preserves_decision_and_resubmitted_tail() {
    use std::io::Read;

    for backend in BACKENDS {
        for is_server in [false, true] {
            for (cipher, direct) in [(0x1301, true), (0x1305, false)] {
                let server_hello = server_hello(cipher, 32, TLS13_VERSION);
                let hello = if is_server {
                    server_hello.clone()
                } else {
                    client_hello()
                };
                let tail = [APPLICATION, b"post-transition bytes"].concat();
                for retained in [0, 3, hello.len() - 1] {
                    for coalesced in [0, 3, tail.len()] {
                        eprintln!(
                            "{backend:?}, server={is_server}, cipher={cipher:#06x}, retained={retained}, coalesced={coalesced}"
                        );
                        let (client, server) = connection_pair(backend);
                        let (session, mut peer) = if is_server {
                            (server, client)
                        } else {
                            (client, server)
                        };
                        let reads = if is_server {
                            VecDeque::new()
                        } else {
                            let mut response = vec![0, 0];
                            response.extend_from_slice(&pad_with_uuid_and_command(
                                &server_hello,
                                &[7; 16],
                                COMMAND_CONTINUE,
                                true,
                            ));
                            VecDeque::from([encrypt(&mut peer, &response).into()])
                        };
                        let gate = Arc::new(std::sync::Mutex::new(WriteGate::default()));
                        let io = GatedIo {
                            input: ScriptedIo { reads },
                            gate: gate.clone(),
                        };
                        let tls = CryptoTlsStream::new(io, session, Some(TlsDeframer::new()));
                        let mut stream = if is_server {
                            let mut stream = VisionStream::new_server(tls, [7; 16], b"").unwrap();
                            // The gate targets the hello record, not the initial response header.
                            stream.vless_response_to_send = false;
                            stream
                        } else {
                            VisionStream::new_client(tls, [7; 16]).unwrap()
                        };
                        let mut cx = Context::from_waker(noop_waker_ref());
                        if retained != 0 {
                            assert!(
                                matches!(Pin::new(&mut stream).poll_write(&mut cx, &hello[..retained]),
                                Poll::Ready(Ok(n)) if n == retained)
                            );
                        }
                        gate.lock().unwrap().blocked = true;
                        let input = [&hello[retained..], &tail[..coalesced]].concat();
                        assert!(matches!(Pin::new(&mut stream).poll_write(&mut cx, &input),
                            Poll::Ready(Ok(n)) if n == hello.len() - retained));
                        assert_eq!(stream.inner_write_deframer.pending_bytes(), 0);
                        assert!(gate.lock().unwrap().output.is_empty());
                        assert!(
                            Pin::new(&mut stream)
                                .poll_write(&mut cx, &tail)
                                .is_pending()
                        );
                        gate.lock().unwrap().blocked = false;
                        assert!(matches!(
                            Pin::new(&mut stream).poll_flush(&mut cx),
                            Poll::Ready(Ok(()))
                        ));
                        if !is_server {
                            assert_buffered_reads(&mut stream, &server_hello);
                        }
                        assert_eq!(stream.filter.supports_xtls(), direct);
                        assert!(matches!(Pin::new(&mut stream).poll_write(&mut cx, &tail),
                            Poll::Ready(Ok(n)) if n == APPLICATION.len()));
                        assert!(matches!(
                            Pin::new(&mut stream).poll_flush(&mut cx),
                            Poll::Ready(Ok(()))
                        ));
                        assert_terminal_write(&stream, direct);

                        let ciphertext = std::mem::take(&mut gate.lock().unwrap().output);
                        let plaintext = decrypt_output(&mut peer, &ciphertext);
                        let decoded = VisionUnpadder::new([7; 16]).unpad(&plaintext).unwrap();
                        assert_eq!(decoded.content, [hello.as_slice(), APPLICATION].concat());
                        let command = if direct {
                            UnpadCommand::Direct
                        } else {
                            UnpadCommand::End
                        };
                        assert_eq!(decoded.command, Some(command));

                        let raw_tail = &tail[APPLICATION.len()..];
                        assert!(
                            matches!(Pin::new(&mut stream).poll_write(&mut cx, raw_tail),
                            Poll::Ready(Ok(n)) if n == raw_tail.len())
                        );
                        assert!(matches!(
                            Pin::new(&mut stream).poll_flush(&mut cx),
                            Poll::Ready(Ok(()))
                        ));
                        let output = std::mem::take(&mut gate.lock().unwrap().output);
                        if direct {
                            assert_eq!(output, raw_tail);
                        } else {
                            assert_eq!(stream.write_mode, VisionMode::Tls);
                            feed_and_process_crypto_connection(&mut peer, &output).unwrap();
                            let mut received = vec![0; raw_tail.len()];
                            peer.reader().read_exact(&mut received).unwrap();
                            assert_eq!(received, raw_tail);
                        }
                    }
                }
            }
        }
    }
}
