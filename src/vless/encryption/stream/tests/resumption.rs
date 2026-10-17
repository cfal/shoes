use super::*;
use crate::vless::encryption::crypto::TAG_LEN;

fn ticket(number: u8) -> Arc<ClientSession> {
    Arc::new(ClientSession {
        ticket: [number; 16],
        pfs: Zeroizing::new([number; 64]),
        expires_at: Instant::now() + Duration::from_secs(60),
    })
}

fn resumed(inner: Scripted) -> (EncryptionStream<Scripted>, Arc<ClientSessionCache>) {
    let cache = Arc::new(ClientSessionCache::default());
    let used = ticket(1);
    cache.publish(used.clone(), Instant::now());
    let mut stream = stream(inner, true, false);
    stream.initial = InitialRead::Resumed {
        random: [0; 16],
        filled: 0,
    };
    stream
        .set_client_prefix(
            b"resume prefix".to_vec(),
            ResumeGuard {
                cache: cache.clone(),
                used,
            },
        )
        .unwrap();
    (stream, cache)
}

#[tokio::test]
async fn resumed_first_record_failures_invalidate_only_the_used_ticket() {
    let mut aead = Aead::new(&[9; 16], &[7; 96], Cipher::Aes256Gcm).unwrap();
    let record = aead.seal_record(b"data", &[7; 96]).unwrap();
    let mut tampered = record.clone();
    *tampered.last_mut().unwrap() ^= 1;
    for wire in [
        vec![],
        vec![9; 15],
        [vec![9; 16], vec![0; 5]].concat(),
        [vec![9; 16], record[..8].to_vec()].concat(),
        [vec![9; 16], tampered].concat(),
    ] {
        for replace in [false, true] {
            let (mut stream, cache) = resumed(Scripted {
                input: wire.clone().into(),
                eof: true,
                ..Default::default()
            });
            let new = ticket(2);
            if replace {
                cache.publish(new.clone(), Instant::now());
            }
            assert!(stream.read_u8().await.is_err());
            let current = cache.snapshot(Instant::now());
            if replace {
                assert!(Arc::ptr_eq(&current.unwrap(), &new));
            } else {
                assert!(current.is_none());
            }
        }
    }
    for flush in [false, true] {
        let (mut stream, cache) = resumed(Scripted {
            fail_write: !flush,
            fail_flush: flush,
            ..Default::default()
        });
        assert!(stream.flush().await.is_err());
        assert!(cache.snapshot(Instant::now()).is_none());
    }
}

#[tokio::test]
async fn resumed_authentication_disarms_guard_and_drop_does_not_invalidate() {
    let (stream, cache) = resumed(Scripted::default());
    drop(stream);
    assert!(cache.snapshot(Instant::now()).is_some());
    let mut aead = Aead::new(&[9; 16], &[7; 96], Cipher::Aes256Gcm).unwrap();
    let record = aead.seal_record(b"data", &[7; 96]).unwrap();
    let (mut stream, cache) = resumed(Scripted {
        input: [vec![9; 16], record, vec![0; 5]].concat().into(),
        eof: true,
        ..Default::default()
    });
    let mut data = [0; 4];
    stream.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"data");
    assert!(stream.resume.is_none());
    assert!(stream.read_u8().await.is_err());
    assert!(cache.snapshot(Instant::now()).is_some());
}

#[tokio::test]
async fn resumed_prefix_shares_first_scalar_or_vectored_record_write() {
    for masked in [false, true] {
        for vectored in [false, true] {
            let (mut client, _) = resumed(Scripted::default());
            let prefix = client.output.to_vec();
            if masked {
                client.write_mask = Some(HeaderMask::new(&[7; 96], &[8; 16], 0).unwrap());
            }
            let n = if vectored {
                client
                    .write_vectored(&[io::IoSlice::new(b""), io::IoSlice::new(b"first")])
                    .await
            } else {
                client.write(b"first").await
            };
            assert_eq!(n.unwrap(), 5);
            assert_eq!(
                client.inner.write_sizes,
                [prefix.len() + HEADER_LEN + 5 + TAG_LEN]
            );
            client.write_all(b"second").await.unwrap();
            client.flush().await.unwrap();
            assert_eq!(client.inner.write_sizes.len(), 2);
            assert_eq!(&client.inner.output[..prefix.len()], &prefix);
            let mut peer = stream(
                Scripted {
                    input: client.inner.output[prefix.len()..].to_vec().into(),
                    eof: true,
                    ..Default::default()
                },
                false,
                masked,
            );
            let mut plaintext = Vec::new();
            peer.read_to_end(&mut plaintext).await.unwrap();
            assert_eq!(plaintext, b"firstsecond");
        }
    }
}

#[tokio::test]
async fn resumed_prefix_accepts_only_one_record_while_output_is_blocked() {
    for writable_bytes in [0, 3, b"resume prefix".len() + 2] {
        let (mut client, _) = resumed(Scripted {
            writable_bytes: Some(writable_bytes),
            ..Default::default()
        });
        let prefix_len = client.output.len();
        let mut cx = Context::from_waker(noop_waker_ref());
        let first = vec![42; WRITE_PLAINTEXT_MAX];
        assert!(matches!(
            Pin::new(&mut client).poll_write(&mut cx, &first),
            Poll::Ready(Ok(WRITE_PLAINTEXT_MAX))
        ));
        let queued = client.output.clone();
        assert_eq!(
            queued.len(),
            prefix_len + HEADER_LEN + first.len() + TAG_LEN - writable_bytes
        );
        assert!(
            Pin::new(&mut client)
                .poll_write(&mut cx, b"cancelled")
                .is_pending()
        );
        assert_eq!(client.output, queued);
        client.inner.writable_bytes = None;
        client.write_all(b"replacement").await.unwrap();
        client.flush().await.unwrap();
        let mut peer = stream_from_wire(client.inner.output[prefix_len..].to_vec());
        let mut plaintext = Vec::new();
        peer.read_to_end(&mut plaintext).await.unwrap();
        assert_eq!(plaintext, [first.as_slice(), b"replacement"].concat());
    }
}

#[tokio::test]
async fn resumed_prefix_drain_failure_acknowledges_first_record_and_latches_error() {
    let (mut client, cache) = resumed(Scripted {
        fail_write: true,
        ..Default::default()
    });
    assert_eq!(client.write(b"first").await.unwrap(), 5);
    let queued = client.output.clone();
    assert_eq!(
        client.write(b"second").await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(
        client.flush().await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(client.output, queued);
    assert!(client.inner.output.is_empty());
    assert!(cache.snapshot(Instant::now()).is_none());
}

#[tokio::test]
async fn explicit_prefix_drain_and_direct_record_preserve_output_order() {
    for direct in [false, true] {
        let (mut client, _) = resumed(Scripted {
            writable_bytes: Some(3),
            ..Default::default()
        });
        let prefix_len = client.output.len();
        let mut cx = Context::from_waker(noop_waker_ref());
        if direct {
            client.start_raw_write(b"final").unwrap();
        } else {
            assert!(Pin::new(&mut client).poll_flush(&mut cx).is_pending());
        }
        assert!(
            Pin::new(&mut client)
                .poll_write(&mut cx, b"later")
                .is_pending()
        );
        client.inner.writable_bytes = None;
        client.write_all(b"later").await.unwrap();
        client.flush().await.unwrap();
        assert_eq!(&client.inner.output[..prefix_len], b"resume prefix");
        let mut peer = stream_from_wire(client.inner.output[prefix_len..].to_vec());
        if direct {
            let mut final_record = [0; 5];
            peer.read_exact(&mut final_record).await.unwrap();
            assert_eq!(&final_record, b"final");
            peer.start_raw_read().unwrap();
        }
        let mut plaintext = Vec::new();
        peer.read_to_end(&mut plaintext).await.unwrap();
        assert_eq!(plaintext, b"later");
    }
}

#[tokio::test]
async fn client_flush_sends_prefix_but_server_flush_waits_for_a_record() {
    let (mut client, _) = resumed(Scripted::default());
    client.flush().await.unwrap();
    assert_eq!(client.inner.output, b"resume prefix");
    client.flush().await.unwrap();
    assert_eq!(client.inner.output, b"resume prefix");
    assert_eq!(client.inner.write_sizes, [b"resume prefix".len()]);
    client.write_all(b"request").await.unwrap();
    assert_eq!(
        client.inner.write_sizes,
        [b"resume prefix".len(), HEADER_LEN + 7 + TAG_LEN]
    );
    let mut server = stream(Scripted::default(), false, false);
    server.set_server_random([9; 16]);
    server.flush().await.unwrap();
    assert!(server.inner.output.is_empty());
    server.write_all(b"response").await.unwrap();
    server.flush().await.unwrap();
    assert_eq!(&server.inner.output[..16], &[9; 16]);
    let mut data = Vec::new();
    stream_from_wire(server.inner.output[16..].to_vec())
        .read_to_end(&mut data)
        .await
        .unwrap();
    assert_eq!(data, b"response");
    let mut server = stream(Scripted::default(), false, false);
    server.set_server_random([9; 16]);
    server.shutdown().await.unwrap();
    assert!(server.inner.output.is_empty());
}

#[tokio::test(start_paused = true)]
async fn blocked_flush_and_shutdown_help_padding_and_surface_its_deadline() {
    for shutdown in [false, true] {
        let (mut stream, padding, record) = pending_padding(Scripted {
            block_flush: !shutdown,
            block_shutdown: shutdown,
            ..Default::default()
        });
        stream.inner.input.extend(&padding[..8]);
        let mut cx = Context::from_waker(noop_waker_ref());
        let result = if shutdown {
            Pin::new(&mut stream).poll_shutdown(&mut cx)
        } else {
            Pin::new(&mut stream).poll_flush(&mut cx)
        };
        assert!(result.is_pending());
        assert!(matches!(&stream.initial, InitialRead::Fresh(p) if p.filled == 8));
        stream.inner.input.extend(&padding[8..]);
        stream.inner.input.extend(&record);
        let result = if shutdown {
            Pin::new(&mut stream).poll_shutdown(&mut cx)
        } else {
            Pin::new(&mut stream).poll_flush(&mut cx)
        };
        assert!(result.is_pending());
        assert!(matches!(stream.initial, InitialRead::Records));
        assert_eq!(stream.inner.input.len(), record.len());

        let (mut stream, _, _) = pending_padding(Scripted {
            block_flush: !shutdown,
            block_shutdown: shutdown,
            ..Default::default()
        });
        let result = if shutdown {
            Pin::new(&mut stream).poll_shutdown(&mut cx)
        } else {
            Pin::new(&mut stream).poll_flush(&mut cx)
        };
        assert!(result.is_pending());
        tokio::time::advance(Duration::from_secs(61)).await;
        let result = if shutdown {
            Pin::new(&mut stream).poll_shutdown(&mut cx)
        } else {
            Pin::new(&mut stream).poll_flush(&mut cx)
        };
        assert!(matches!(result, Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::TimedOut));
    }
}
