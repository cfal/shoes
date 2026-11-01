use super::*;
use crate::async_stream::AsyncShutdownMessageExt;
use futures::{future::poll_fn, poll};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
use tokio::time::timeout;

async fn read(stream: &mut VlessMessageStream<DuplexStream>, capacity: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0; capacity];
    let mut buffer = ReadBuf::new(&mut bytes);
    timeout(
        Duration::from_secs(5),
        poll_fn(|cx| Pin::new(&mut *stream).poll_read_message(cx, &mut buffer)),
    )
    .await
    .expect("message read stalled")?;
    Ok(buffer.filled().to_vec())
}

async fn write(stream: &mut VlessMessageStream<DuplexStream>, bytes: &[u8]) -> Result<()> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_write_message(cx, bytes)).await
}

#[tokio::test]
async fn fragmented_header_and_body_preserve_coalesced_next_message() {
    timeout(Duration::from_secs(5), async {
        let wire = b"\x00\x03abc\x00\x02de";
        for split in 1..5 {
            let (io, mut peer) = duplex(32);
            let mut stream = VlessMessageStream::new(io);
            peer.write_all(&wire[..split]).await.unwrap();
            let mut receiving = Box::pin(read(&mut stream, 8));
            assert!(poll!(&mut receiving).is_pending(), "split={split}");
            peer.write_all(&wire[split..]).await.unwrap();
            assert_eq!(receiving.await.unwrap(), b"abc", "split={split}");
            assert_eq!(read(&mut stream, 8).await.unwrap(), b"de");
            peer.shutdown().await.unwrap();
            assert!(read(&mut stream, 8).await.unwrap().is_empty());
            assert!(read(&mut stream, 8).await.unwrap().is_empty());
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn truncated_header_or_body_reports_unexpected_eof() {
    timeout(Duration::from_secs(5), async {
        let wire = b"\x00\x03abc";
        for end in 1..wire.len() {
            let (io, mut peer) = duplex(32);
            let mut stream = VlessMessageStream::new(io);
            peer.write_all(&wire[..end]).await.unwrap();
            peer.shutdown().await.unwrap();
            assert_eq!(
                read(&mut stream, 8).await.unwrap_err().kind(),
                ErrorKind::UnexpectedEof,
                "truncation={end}"
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn insufficient_remaining_capacity_preserves_message_for_retry() {
    let (io, _peer) = duplex(1);
    let mut stream = VlessMessageStream::new(io);
    stream
        .feed_initial_read_data(b"\x00\x03abc\x00\x01z")
        .unwrap();
    let mut bytes = [0; 4];
    let mut buffer = ReadBuf::new(&mut bytes);
    buffer.put_slice(b"xy");
    let result = poll!(poll_fn(
        |cx| Pin::new(&mut stream).poll_read_message(cx, &mut buffer)
    ));
    assert!(matches!(result, Poll::Ready(Err(_))));
    assert_eq!(buffer.filled(), b"xy");
    assert_eq!(read(&mut stream, 3).await.unwrap(), b"abc");
    assert_eq!(read(&mut stream, 1).await.unwrap(), b"z");
}

#[tokio::test]
async fn initial_data_limit_rejects_without_overwriting_buffered_frame() {
    let (io, _peer) = duplex(1);
    let mut stream = VlessMessageStream::new(io);
    let mut wire = vec![0xff, 0xff];
    wire.extend((0..65535).map(|index| index as u8));
    stream.feed_initial_read_data(&wire).unwrap();
    assert!(stream.feed_initial_read_data(&vec![0; 65538]).is_err());
    assert_eq!(read(&mut stream, 65535).await.unwrap(), wire[2..]);
}

#[tokio::test]
async fn oversized_write_does_not_poison_maximum_frame_or_following_message() {
    timeout(Duration::from_secs(5), async {
        let (io, mut peer) = duplex(7);
        let mut stream = VlessMessageStream::new(io);
        let payload: Vec<_> = (0..65535).map(|index| index as u8).collect();
        assert_eq!(
            write(&mut stream, &vec![0; 65536])
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput
        );
        let ((), bytes) = tokio::join!(
            async {
                write(&mut stream, &payload).await.unwrap();
                write(&mut stream, b"next").await.unwrap();
                stream.shutdown_message().await.unwrap();
            },
            async {
                let mut bytes = Vec::new();
                peer.read_to_end(&mut bytes).await.unwrap();
                bytes
            }
        );
        let mut expected = vec![0xff, 0xff];
        expected.extend_from_slice(&payload);
        expected.extend_from_slice(b"\x00\x04next");
        assert_eq!(bytes, expected);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_backpressured_write_resumes_without_duplication_and_shutdown_flushes() {
    timeout(Duration::from_secs(5), async {
        let (io, mut peer) = duplex(1);
        let mut stream = VlessMessageStream::new(io);
        write(&mut stream, b"abc").await.unwrap();
        let mut pending = Box::pin(write(&mut stream, b"de"));
        assert!(poll!(&mut pending).is_pending());
        drop(pending);
        let ((), bytes) = tokio::join!(
            async {
                write(&mut stream, b"de").await.unwrap();
                stream.shutdown_message().await.unwrap();
            },
            async {
                let mut bytes = Vec::new();
                peer.read_to_end(&mut bytes).await.unwrap();
                bytes
            }
        );
        assert_eq!(bytes, b"\x00\x03abc\x00\x02de");
    })
    .await
    .unwrap();
}
