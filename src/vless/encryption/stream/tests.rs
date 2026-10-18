use super::*;
use crate::vless::encryption::crypto::Cipher;
use futures::task::noop_waker_ref;
use std::{collections::VecDeque, task::Waker, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod liveness;
mod resumption;

#[tokio::test]
async fn maximum_native_record_keeps_direct_command_in_second_vision_read_and_raw_tail() {
    use crate::vless::vision_stream::VisionStream;
    for masked in [false, true] {
        for cipher in [Cipher::Aes256Gcm, Cipher::ChaCha20Poly1305] {
            let first = vec![41; 9000];
            let second = vec![42; 7596];
            let mut plain = vec![0, 0];
            plain.extend_from_slice(&[7; 16]);
            plain.push(0);
            plain.extend_from_slice(&(first.len() as u16).to_be_bytes());
            plain.extend_from_slice(&[0, 0]);
            plain.extend_from_slice(&first);
            plain.push(2);
            plain.extend_from_slice(&(second.len() as u16).to_be_bytes());
            plain.extend_from_slice(&[0, 0]);
            plain.extend_from_slice(&second);
            assert_eq!(plain.len(), 16624);
            let mut peer = Aead::new(b"context", &[7; 96], cipher).unwrap();
            let mut wire = peer.seal_record(&plain, &[7; 96]).unwrap();
            wire.extend_from_slice(b"\x17\x03\x03\x00\x04tail");
            if masked {
                HeaderMask::new(&[7; 96], &[8; 16], 0)
                    .unwrap()
                    .apply_write(&mut wire)
                    .unwrap();
            }
            let mut stream = stream(
                Scripted {
                    input: wire.into(),
                    eof: true,
                    ..Default::default()
                },
                true,
                masked,
            );
            stream.read_aead = Some(Aead::new(b"context", &[7; 96], cipher).unwrap());
            let mut vision = VisionStream::new_client(stream, [7; 16]).unwrap();
            let mut received = Vec::new();
            vision.read_to_end(&mut received).await.unwrap();
            assert_eq!(
                received,
                [first, second, b"\x17\x03\x03\x00\x04tail".to_vec()].concat()
            );
        }
    }
}

#[derive(Default)]
struct Scripted {
    input: VecDeque<u8>,
    output: Vec<u8>,
    write_sizes: Vec<usize>,
    writable_bytes: Option<usize>,
    block_write: bool,
    fail_write: bool,
    fail_read: bool,
    fail_flush: bool,
    block_flush: bool,
    block_shutdown: bool,
    eof: bool,
    read_waker: Option<Waker>,
    flushes: usize,
}

impl AsyncRead for Scripted {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.fail_read {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        if this.input.is_empty() && !this.eof {
            this.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        while buf.remaining() != 0 {
            let Some(byte) = this.input.pop_front() else {
                break;
            };
            buf.put_slice(&[byte]);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Scripted {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.fail_write {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if this.block_write {
            return Poll::Pending;
        }
        let n = this
            .writable_bytes
            .map_or(buf.len(), |limit| buf.len().min(limit));
        if n == 0 && !buf.is_empty() {
            return Poll::Pending;
        }
        if let Some(remaining) = &mut this.writable_bytes {
            *remaining -= n;
        }
        this.write_sizes.push(n);
        this.output.extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.flushes += 1;
        if this.fail_flush {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if this.block_flush {
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.block_shutdown {
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for Scripted {
    fn supports_ping(&self) -> bool {
        true
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(true))
    }
}
impl AsyncStream for Scripted {}

fn stream<S: AsyncStream>(inner: S, client: bool, masked: bool) -> EncryptionStream<S> {
    let keys = StreamKeys {
        united: Zeroizing::new([7; 96]),
        write_aead: Aead::new(b"context", &[7; 96], Cipher::Aes256Gcm).unwrap(),
        read_aead: Some(Aead::new(b"context", &[7; 96], Cipher::Aes256Gcm).unwrap()),
        write_mask: masked.then(|| HeaderMask::new(&[7; 96], &[8; 16], 0).unwrap()),
        read_mask: masked.then(|| HeaderMask::new(&[7; 96], &[8; 16], 0).unwrap()),
        random_mode: masked,
    };
    EncryptionStream::new(inner, client, keys, InitialRead::Records)
}

fn pending_padding<S: AsyncStream>(inner: S) -> (EncryptionStream<S>, Vec<u8>, Vec<u8>) {
    pending_padding_with_response(inner, b"response")
}

fn pending_padding_with_response<S: AsyncStream>(
    inner: S,
    response: &[u8],
) -> (EncryptionStream<S>, Vec<u8>, Vec<u8>) {
    let mut stream = stream(inner, true, false);
    let mut peer = Aead::new(b"context", &[7; 96], Cipher::Aes256Gcm).unwrap();
    let padding = peer.seal(&[0; 48], &[]).unwrap();
    let record = peer.seal_record(response, &[7; 96]).unwrap();
    stream.initial = InitialRead::Fresh(FreshPadding::new(
        vec![0; padding.len()],
        0,
        None,
        Instant::now() + Duration::from_secs(60),
    ));
    (stream, padding, record)
}

#[test]
fn required_stream_bounds() {
    fn assert_stream<S: AsyncStream>() {}
    assert_stream::<EncryptionStream<Box<dyn AsyncStream>>>();
    assert_stream::<
        crate::vless::vision_stream::VisionStream<EncryptionStream<Box<dyn AsyncStream>>>,
    >();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn native_splice_requires_both_direct_directions_drained_unmasked_tcp() {
    for masked in [false, true] {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (client, accepted) = tokio::join!(
            tokio::net::TcpStream::connect(("127.0.0.1", port)),
            listener.accept(),
        );
        let (_peer, _) = accepted.unwrap();
        let mut stream = stream(client.unwrap(), true, masked);
        assert!(stream.plain_tcp().is_none());
        stream.start_raw_read().unwrap();
        assert!(stream.plain_tcp().is_none());
        stream.start_raw_write(b"final").unwrap();
        assert!(stream.plain_tcp().is_none());
        stream.flush().await.unwrap();
        assert_eq!(stream.plain_tcp().is_some(), !masked);
        stream.plaintext.extend_from_slice(b"preread");
        assert!(stream.plain_tcp().is_none());
        stream.read_exact(&mut [0; 7]).await.unwrap();
        assert_eq!(stream.plain_tcp().is_some(), !masked);
        stream.shutdown().await.unwrap();
        assert!(stream.plain_tcp().is_none());
    }
}

#[tokio::test]
async fn acknowledged_ciphertext_is_not_reencrypted_after_cancelled_pending_write() {
    let mut stream = stream(
        Scripted {
            block_write: true,
            ..Default::default()
        },
        true,
        false,
    );
    let mut cx = Context::from_waker(noop_waker_ref());
    assert!(matches!(
        Pin::new(&mut stream).poll_write(&mut cx, b"first"),
        Poll::Ready(Ok(5))
    ));
    let queued = stream.output.clone();
    assert!(
        Pin::new(&mut stream)
            .poll_write(&mut cx, b"cancelled")
            .is_pending()
    );
    assert_eq!(stream.output, queued);
    stream.inner.block_write = false;
    assert!(matches!(
        Pin::new(&mut stream).poll_write(&mut cx, b"replacement"),
        Poll::Ready(Ok(11))
    ));
    let mut peer = stream_from_wire(stream.inner.output);
    let mut plaintext = Vec::new();
    peer.read_to_end(&mut plaintext).await.unwrap();
    assert_eq!(plaintext, b"firstreplacement");
}

fn stream_from_wire(wire: Vec<u8>) -> EncryptionStream<Scripted> {
    stream(
        Scripted {
            input: wire.into(),
            eof: true,
            ..Default::default()
        },
        false,
        false,
    )
}

#[tokio::test]
async fn post_acceptance_write_failure_preserves_readable_input() {
    let mut peer = Aead::new(b"context", &[7; 96], Cipher::Aes256Gcm).unwrap();
    let wire = peer.seal_record(b"still readable", &[7; 96]).unwrap();
    let mut stream = stream(
        Scripted {
            input: wire.into(),
            fail_write: true,
            ..Default::default()
        },
        true,
        false,
    );
    assert_eq!(stream.write(b"accepted").await.unwrap(), 8);
    assert_eq!(
        stream.write(b"later").await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(
        stream.flush().await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    let mut response = [0; 14];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"still readable");
}

#[tokio::test]
async fn records_reject_truncation_and_tampering_without_exposing_plaintext() {
    let mut peer = Aead::new(b"context", &[7; 96], Cipher::Aes256Gcm).unwrap();
    let wire = peer.seal_record(b"secret", &[7; 96]).unwrap();
    for length in 1..wire.len() {
        let mut stream = stream_from_wire(wire[..length].to_vec());
        let mut result = Vec::new();
        assert_eq!(
            stream.read_to_end(&mut result).await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert!(result.is_empty());
    }
    let mut corrupt = wire;
    *corrupt.last_mut().unwrap() ^= 1;
    let mut stream = stream_from_wire(corrupt);
    let mut result = Vec::new();
    assert_eq!(
        stream.read_to_end(&mut result).await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert!(result.is_empty());
    assert!(stream.write(b"cannot continue").await.is_err());
}

#[tokio::test]
async fn direct_read_keeps_current_plaintext_before_opaque_tail() {
    for masked in [false, true] {
        let mut sender = stream(Scripted::default(), false, masked);
        sender.write_all(&vec![0x42; 16000]).await.unwrap();
        sender.start_raw_write(b"end").unwrap();
        sender.write_all(b"\x17\x03\x03\x00\x04tail").await.unwrap();
        sender.flush().await.unwrap();
        let mut receiver = stream(
            Scripted {
                input: sender.inner.output.into(),
                eof: true,
                ..Default::default()
            },
            true,
            masked,
        );
        let mut prefix = vec![0; 16000 + 1];
        receiver.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix[..16000], &[0x42; 16000]);
        assert_eq!(prefix[16000], b'e');
        receiver.start_raw_read().unwrap();
        let mut tail = Vec::new();
        receiver.read_to_end(&mut tail).await.unwrap();
        assert_eq!(tail, b"nd\x17\x03\x03\x00\x04tail");
    }
}

#[tokio::test]
async fn direct_read_failure_is_terminal_even_if_transport_recovers() {
    for masked in [false, true] {
        let mut stream = stream(
            Scripted {
                fail_read: true,
                ..Default::default()
            },
            true,
            masked,
        );
        stream.start_raw_read().unwrap();
        assert_eq!(
            stream.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
        stream.inner.fail_read = false;
        stream.inner.input.push_back(42);
        assert_eq!(
            stream.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
        assert_eq!(
            stream.write(b"output").await.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
        assert_eq!(stream.inner.input.len(), 1);
    }
}

#[tokio::test]
async fn resumed_server_rejects_empty_direct_flight_without_losing_random() {
    for masked in [false, true] {
        let mut stream = stream(Scripted::default(), false, masked);
        stream.set_server_random([8; 16]);
        if masked {
            stream.write_mask = Some(HeaderMask::new(&[7; 96], &[8; 16], 16).unwrap());
        }
        assert!(stream.start_raw_write(&[]).is_err());
        assert!(!stream.write_raw);
        assert_eq!(stream.server_random, Some([8; 16]));
        assert!(stream.output.is_empty());
        stream.start_raw_write(b"final").unwrap();
        stream.flush().await.unwrap();
        assert_eq!(&stream.inner.output[..16], &[8; 16]);
        let mut record = stream.inner.output[16..].to_vec();
        if masked {
            HeaderMask::new(&[7; 96], &[8; 16], 0)
                .unwrap()
                .apply_read(&mut record)
                .unwrap();
        }
        let mut peer = stream_from_wire(record);
        let mut final_plaintext = Vec::new();
        peer.read_to_end(&mut final_plaintext).await.unwrap();
        assert_eq!(final_plaintext, b"final");
    }
}

#[tokio::test(start_paused = true)]
async fn every_output_entry_enforces_deadline_even_without_backpressure() {
    for operation in 0..6 {
        let (mut stream, _, _) = pending_padding(Scripted::default());
        stream.write_all(b"before deadline").await.unwrap();
        tokio::time::advance(Duration::from_secs(61)).await;
        let mut cx = Context::from_waker(noop_waker_ref());
        let result = match operation {
            0 => Pin::new(&mut stream)
                .poll_write(&mut cx, b"after")
                .map_ok(|_| ()),
            1 => Pin::new(&mut stream)
                .poll_write_vectored(
                    &mut cx,
                    &[io::IoSlice::new(&[]), io::IoSlice::new(b"after")],
                )
                .map_ok(|_| ()),
            2 => Pin::new(&mut stream).poll_flush(&mut cx),
            3 => Pin::new(&mut stream).poll_shutdown(&mut cx),
            4 => Pin::new(&mut stream)
                .poll_write_ping(&mut cx)
                .map_ok(|_| ()),
            _ => stream.poll_drain_encrypted(&mut cx),
        };
        assert!(matches!(result, Poll::Ready(Err(ref e)) if e.kind() == io::ErrorKind::TimedOut));
        assert_eq!(
            stream.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }
}

#[tokio::test(start_paused = true)]
async fn available_padding_wins_at_expiry_and_never_returns_false_eof() {
    let (mut stream, padding, record) = pending_padding(Scripted::default());
    tokio::time::advance(Duration::from_secs(61)).await;
    stream.inner.input.extend(padding);
    stream.inner.input.extend(record);
    stream.write_all(b"allowed").await.unwrap();
    let mut response = [0; 8];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"response");
}

#[tokio::test]
async fn drain_assists_padding_but_does_not_read_records_or_flush() {
    let (mut stream, padding, record) = pending_padding(Scripted {
        block_write: true,
        ..Default::default()
    });
    stream.write_all(b"request").await.unwrap();
    stream.inner.input.extend(padding);
    stream.inner.input.extend(&record);
    let mut cx = Context::from_waker(noop_waker_ref());
    assert!(stream.poll_drain_encrypted(&mut cx).is_pending());
    assert!(matches!(stream.initial, InitialRead::Records));
    assert_eq!(stream.inner.input.len(), record.len());
    assert_eq!(stream.inner.flushes, 0);
}
