use super::*;
use crate::vless::vision_stream::{VisionStream, VisionWriteErrorPolicy};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::oneshot;

fn pending_vision(
    io: tokio::io::DuplexStream,
) -> (
    VisionStream<EncryptionStream<tokio::io::DuplexStream>>,
    Vec<u8>,
) {
    let mut response = vec![0, 0];
    response.extend_from_slice(&[9; 16]);
    response.extend_from_slice(b"\x02\x00\x08\x00\x00response");
    let (stream, padding, record) = pending_padding_with_response(io, &response);
    let stream = VisionStream::new_client(stream, [9; 16])
        .unwrap()
        .with_write_error_policy(VisionWriteErrorPolicy::AcknowledgeAccepted);
    (stream, [padding, record].concat())
}

async fn observe_pending<F: Future>(
    future: F,
    signal: oneshot::Sender<()>,
    polls: Arc<AtomicUsize>,
) -> F::Output {
    tokio::pin!(future);
    let mut signal = Some(signal);
    futures::future::poll_fn(|cx| {
        polls.fetch_add(1, Ordering::SeqCst);
        let result = future.as_mut().poll(cx);
        if result.is_pending()
            && let Some(signal) = signal.take()
        {
            let _ = signal.send(());
        }
        result
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn cancelled_helping_writer_cannot_strand_reader_readiness_or_deadline() {
    for expire in [false, true] {
        let (io, mut peer) = tokio::io::duplex(16);
        let (stream, padding, record) = pending_padding(io);
        let (mut reader, mut writer) = tokio::io::split(stream);
        let (read_tx, read_rx) = oneshot::channel();
        let read_polls = Arc::new(AtomicUsize::new(0));
        let read_task = tokio::spawn(async move {
            let mut bytes = [0; 8];
            observe_pending(reader.read_exact(&mut bytes), read_tx, read_polls).await?;
            Ok::<_, io::Error>(bytes)
        });
        read_rx.await.unwrap();
        let (write_tx, write_rx) = oneshot::channel();
        let write_task = tokio::spawn(async move {
            observe_pending(writer.write_all(&vec![42; 16384]), write_tx, Arc::default()).await
        });
        write_rx.await.unwrap();
        write_task.abort();
        assert!(write_task.await.unwrap_err().is_cancelled());
        if expire {
            tokio::time::advance(Duration::from_secs(61)).await;
            assert_eq!(
                read_task.await.unwrap().unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
        } else {
            peer.write_all(&[padding, record].concat()).await.unwrap();
            assert_eq!(&read_task.await.unwrap().unwrap(), b"response");
        }
    }
}

#[tokio::test(start_paused = true)]
async fn cancelled_last_reader_cannot_strand_writer_at_deadline() {
    let (io, mut peer) = tokio::io::duplex(16);
    let (stream, padding, _) = pending_padding(io);
    peer.write_all(&padding[..8]).await.unwrap();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (write_tx, write_rx) = oneshot::channel();
    let write_task = tokio::spawn(async move {
        observe_pending(writer.write_all(&vec![42; 16384]), write_tx, Arc::default()).await
    });
    write_rx.await.unwrap();
    let (read_tx, read_rx) = oneshot::channel();
    let read_task = tokio::spawn(async move {
        observe_pending(reader.read(&mut [0; 8]), read_tx, Arc::default()).await
    });
    read_rx.await.unwrap();
    read_task.abort();
    assert!(read_task.await.unwrap_err().is_cancelled());
    tokio::time::advance(Duration::from_secs(61)).await;
    assert_eq!(
        write_task.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
}

#[tokio::test(start_paused = true)]
async fn pending_padding_does_not_spin_and_transition_keeps_both_halves_live() {
    let (io, mut peer) = tokio::io::duplex(16);
    let (stream, padding, record) = pending_padding(io);
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (read_tx, read_rx) = oneshot::channel();
    let read_polls = Arc::new(AtomicUsize::new(0));
    let rp = read_polls.clone();
    let read_task = tokio::spawn(async move {
        let mut bytes = [0; 8];
        observe_pending(reader.read_exact(&mut bytes), read_tx, rp).await?;
        Ok::<_, io::Error>(bytes)
    });
    read_rx.await.unwrap();
    let (write_tx, write_rx) = oneshot::channel();
    let write_polls = Arc::new(AtomicUsize::new(0));
    let wp = write_polls.clone();
    let write_task = tokio::spawn(async move {
        observe_pending(writer.write_all(&vec![42; 16384]), write_tx, wp).await?;
        writer.flush().await
    });
    write_rx.await.unwrap();
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    let before = read_polls.load(Ordering::SeqCst) + write_polls.load(Ordering::SeqCst);
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        before,
        read_polls.load(Ordering::SeqCst) + write_polls.load(Ordering::SeqCst)
    );
    let (mut r, mut w) = tokio::io::split(&mut peer);
    let ((), bytes) = tokio::join!(
        async {
            w.write_all(&[padding, record].concat()).await.unwrap();
        },
        async {
            let mut bytes = vec![0; 16384 + 2 * 21];
            r.read_exact(&mut bytes).await.unwrap();
            bytes
        }
    );
    assert_eq!(&read_task.await.unwrap().unwrap(), b"response");
    write_task.await.unwrap().unwrap();
    let mut decoded = Vec::new();
    stream_from_wire(bytes)
        .read_to_end(&mut decoded)
        .await
        .unwrap();
    assert_eq!(decoded, vec![42; 16384]);
}

#[tokio::test(start_paused = true)]
async fn native_vision_split_cancellation_preserves_readiness_and_deadline_wakes() {
    for cancel_reader in [false, true] {
        for expire in [false, true] {
            if cancel_reader && !expire {
                continue;
            }
            let (io, mut peer) = tokio::io::duplex(16);
            let (stream, response) = pending_vision(io);
            let (mut reader, mut writer) = tokio::io::split(stream);
            let (read_tx, read_rx) = oneshot::channel();
            let (write_tx, write_rx) = oneshot::channel();
            let reader_future = async move {
                let mut bytes = [0; 8];
                observe_pending(reader.read_exact(&mut bytes), read_tx, Arc::default()).await?;
                Ok::<_, io::Error>(bytes)
            };
            let writer_future = async move {
                observe_pending(
                    async {
                        writer.write_all(&vec![42; 16384]).await?;
                        writer.flush().await
                    },
                    write_tx,
                    Arc::default(),
                )
                .await
            };
            let (read_task, write_task) = if cancel_reader {
                let writer = tokio::spawn(writer_future);
                write_rx.await.unwrap();
                let reader = tokio::spawn(reader_future);
                read_rx.await.unwrap();
                (reader, writer)
            } else {
                let reader = tokio::spawn(reader_future);
                read_rx.await.unwrap();
                let writer = tokio::spawn(writer_future);
                write_rx.await.unwrap();
                (reader, writer)
            };
            if cancel_reader {
                read_task.abort();
                assert!(read_task.await.unwrap_err().is_cancelled());
                tokio::time::advance(Duration::from_secs(61)).await;
                assert_eq!(
                    write_task.await.unwrap().unwrap_err().kind(),
                    io::ErrorKind::TimedOut
                );
            } else {
                write_task.abort();
                assert!(write_task.await.unwrap_err().is_cancelled());
                if expire {
                    tokio::time::advance(Duration::from_secs(61)).await;
                    assert_eq!(
                        read_task.await.unwrap().unwrap_err().kind(),
                        io::ErrorKind::TimedOut
                    );
                } else {
                    peer.write_all(&response).await.unwrap();
                    assert_eq!(&read_task.await.unwrap().unwrap(), b"response");
                }
            }
        }
    }
}

#[tokio::test]
async fn write_only_native_vision_drains_fresh_padding_then_reads_direct() {
    let (io, mut peer) = tokio::io::duplex(16);
    let (mut stream, response) = pending_vision(io);
    tokio::time::timeout(Duration::from_secs(2), async {
        let client = async {
            stream.write_all(&vec![42; 16384]).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut bytes = [0; 8];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"response");
            let mut raw = [0; 9];
            stream.read_exact(&mut raw).await.unwrap();
            assert_eq!(&raw, b"\x17\x03\x03\x00\x04tail");
        };
        let server = async {
            // No request reads until all fresh padding is sent: reference ordering.
            peer.write_all(&response[..64]).await.unwrap();
            let (mut reader, mut writer) = tokio::io::split(&mut peer);
            let (wire, ()) = tokio::join!(
                async {
                    let mut wire = Vec::new();
                    reader.read_to_end(&mut wire).await.unwrap();
                    wire
                },
                async {
                    writer.write_all(&response[64..]).await.unwrap();
                    writer.write_all(b"\x17\x03\x03\x00\x04tail").await.unwrap();
                }
            );
            let mut server =
                VisionStream::new_server(stream_from_wire(wire), [9; 16], &[]).unwrap();
            let mut request = Vec::new();
            server.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, vec![42; 16384]);
        };
        tokio::join!(client, server);
    })
    .await
    .unwrap();
}
