use super::*;
use std::collections::VecDeque;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn test_generate_padding_header() {
    let header = generate_padding_header(20);
    assert_eq!(header.len(), 20);
    // All characters should be from NONINDEX_CHARS (first 16 chars use indices 0-15, rest use index 16 = 'X')
    assert!(header.chars().all(|c| NONINDEX_CHARS.contains(&(c as u8))));
    // For headers > 16 chars, the last 4 should be 'X'
    assert!(header.chars().skip(16).all(|c| c == 'X'));
}

#[test]
fn test_padding_type_parse() {
    let types = parse_padding_type_request("1, 0");
    assert_eq!(types, vec![PaddingType::Variant1, PaddingType::None]);
}

#[test]
fn test_padding_type_from_u8() {
    assert_eq!(PaddingType::from_u8(0), Some(PaddingType::None));
    assert_eq!(PaddingType::from_u8(1), Some(PaddingType::Variant1));
    assert_eq!(PaddingType::from_u8(2), None);
}

/// Helper to manually encode a padded frame for testing.
/// Format: [payload_len_be16][padding_len_u8][payload][padding_zeros]
fn encode_test_frame(payload: &[u8], padding_len: u8) -> Vec<u8> {
    let payload_len = payload.len() as u16;
    let mut frame = Vec::with_capacity(3 + payload.len() + padding_len as usize);
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.push(padding_len);
    frame.extend_from_slice(payload);
    frame.extend(std::iter::repeat_n(0u8, padding_len as usize));
    frame
}

#[test]
fn test_frame_encoding_format() {
    // Verify our test helper matches expected format
    let frame = encode_test_frame(b"hello", 10);
    assert_eq!(frame.len(), 3 + 5 + 10); // header + payload + padding
    assert_eq!(&frame[0..2], &[0x00, 0x05]); // payload_len = 5 (big-endian)
    assert_eq!(frame[2], 10); // padding_len
    assert_eq!(&frame[3..8], b"hello"); // payload
    assert!(frame[8..].iter().all(|&b| b == 0)); // padding zeros
}

#[test]
fn test_frame_encoding_empty_payload() {
    // Pure padding frame (payload_len = 0)
    let frame = encode_test_frame(b"", 50);
    assert_eq!(frame.len(), 3 + 50);
    assert_eq!(&frame[0..2], &[0x00, 0x00]); // payload_len = 0
    assert_eq!(frame[2], 50); // padding_len
}

#[test]
fn test_frame_encoding_max_payload() {
    // Maximum payload size
    let payload = vec![0xAB; MAX_PAYLOAD_SIZE];
    let frame = encode_test_frame(&payload, 0);
    assert_eq!(frame.len(), 3 + MAX_PAYLOAD_SIZE);
    assert_eq!(&frame[0..2], &[0xFF, 0xFF]); // payload_len = 65535
}

/// A mock async stream that returns pre-defined chunks of data.
/// Useful for testing partial reads and specific data patterns.
struct MockStream {
    /// Data chunks to return on each read
    read_chunks: VecDeque<Vec<u8>>,
    /// Data written to the stream
    written: Vec<u8>,
}

impl MockStream {
    fn new(chunks: Vec<Vec<u8>>) -> Self {
        Self {
            read_chunks: chunks.into(),
            written: Vec::new(),
        }
    }

    fn from_data(data: Vec<u8>) -> Self {
        Self::new(vec![data])
    }
}

impl AsyncRead for MockStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(chunk) = self.read_chunks.pop_front() {
            let to_copy = chunk.len().min(buf.remaining());
            buf.put_slice(&chunk[..to_copy]);
            // If we didn't use the whole chunk, put the rest back
            if to_copy < chunk.len() {
                self.read_chunks.push_front(chunk[to_copy..].to_vec());
            }
            Poll::Ready(Ok(()))
        } else {
            // EOF
            Poll::Ready(Ok(()))
        }
    }
}

impl AsyncWrite for MockStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.written.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Unpin for MockStream {}

impl AsyncPing for MockStream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for MockStream {}

#[test]
fn buffered_write_is_acknowledged_before_flush() {
    let payload = [42; 512];
    for completed_frames in [0, NUM_FIRST_PADDINGS - 1] {
        let mut stream = NaivePaddingStream::new(
            MockStream::new(vec![]),
            PaddingDirection::Server,
            PaddingType::Variant1,
        );
        stream.num_written_frames = completed_frames;
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, &payload),
            Poll::Ready(Ok(512))
        ));
        assert!(stream.write_start < stream.write_end);
        assert!(matches!(
            Pin::new(&mut stream).poll_flush(&mut cx),
            Poll::Ready(Ok(()))
        ));
        let wire = stream.inner.written.clone();
        assert!(matches!(
            Pin::new(&mut stream).poll_flush(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(stream.inner.written, wire);
        assert_eq!(stream.num_written_frames, completed_frames + 1);
    }
}

#[tokio::test]
async fn cancelled_write_does_not_consume_replacement_after_flush() {
    for completed_frames in [0, NUM_FIRST_PADDINGS - 1] {
        let (inner, mut peer) = tokio::io::duplex(7);
        let mut stream =
            NaivePaddingStream::new(inner, PaddingDirection::Server, PaddingType::Variant1);
        stream.num_written_frames = completed_frames;
        let payload = [42; 512];
        assert!(matches!(
            futures::poll!(std::pin::pin!(stream.write(&payload))),
            Poll::Ready(Ok(512))
        ));
        assert!(futures::poll!(std::pin::pin!(stream.write(b"cancelled"))).is_pending());
        assert!(futures::poll!(std::pin::pin!(stream.flush())).is_pending());

        let mut wire = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::try_join!(
                async {
                    stream.flush().await?;
                    assert_eq!(stream.num_written_frames, completed_frames + 1);
                    assert_eq!(stream.write(b"x").await?, 1);
                    stream.shutdown().await
                },
                peer.read_to_end(&mut wire),
            )
        })
        .await
        .unwrap()
        .unwrap();

        let mut reader = NaivePaddingStream::new(
            MockStream::from_data(wire),
            PaddingDirection::Client,
            PaddingType::Variant1,
        );
        reader.num_read_frames = completed_frames;
        let mut received = Vec::new();
        reader.read_to_end(&mut received).await.unwrap();
        let mut expected = payload.to_vec();
        expected.push(b'x');
        assert_eq!(received, expected);
    }
}

#[tokio::test]
async fn batched_flushes_do_not_duplicate_pending_naive_frames() {
    let payload: Vec<u8> = (0..65536u32).flat_map(u32::to_be_bytes).collect();
    let mut source = MockStream::from_data(payload.clone());
    let mut writer = NaivePaddingStream::new(
        MockStream::new(vec![]),
        PaddingDirection::Server,
        PaddingType::Variant1,
    );
    crate::copy_bidirectional::copy_bidirectional_with_sizes(
        &mut source,
        &mut writer,
        false,
        false,
        512,
        512,
    )
    .await
    .unwrap();
    let mut reader = NaivePaddingStream::new(
        MockStream::from_data(writer.inner.written),
        PaddingDirection::Client,
        PaddingType::Variant1,
    );
    let mut received = Vec::new();
    reader.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, payload);
}

#[tokio::test]
async fn test_read_single_padded_frame() {
    let payload = b"hello world";
    let frame = encode_test_frame(payload, 20);
    let mock = MockStream::from_data(frame);

    let mut stream = NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::Variant1);

    let mut buf = vec![0u8; 100];
    let n = stream.read(&mut buf).await.unwrap();

    assert_eq!(n, payload.len());
    assert_eq!(&buf[..n], payload);
}

#[tokio::test]
async fn test_read_multiple_padded_frames() {
    // Create 3 frames with different payloads
    let payloads = [b"frame1".as_slice(), b"frame2", b"frame3"];
    let mut data = Vec::new();
    for payload in &payloads {
        data.extend(encode_test_frame(payload, 10));
    }

    let mock = MockStream::from_data(data);
    let mut stream = NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::Variant1);

    for expected in &payloads {
        let mut buf = vec![0u8; 100];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], *expected);
    }
}

#[tokio::test]
async fn test_read_pure_padding_frame_skipped() {
    // Create: pure_padding_frame + real_frame
    // The pure padding frame should be skipped automatically
    let mut data = Vec::new();
    data.extend(encode_test_frame(b"", 50)); // Pure padding (payload_len = 0)
    data.extend(encode_test_frame(b"real data", 10)); // Real frame

    let mock = MockStream::from_data(data);
    let mut stream = NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::Variant1);

    let mut buf = vec![0u8; 100];
    let n = stream.read(&mut buf).await.unwrap();

    // Should get "real data", skipping the pure padding frame
    assert_eq!(&buf[..n], b"real data");
}

#[tokio::test]
async fn test_read_partial_frame_header() {
    // Split the frame header across two reads
    let payload = b"test payload";
    let frame = encode_test_frame(payload, 5);

    // Split: first 2 bytes, then the rest
    let chunk1 = frame[..2].to_vec();
    let chunk2 = frame[2..].to_vec();

    let mock = MockStream::new(vec![chunk1, chunk2]);
    let mut stream = NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::Variant1);

    let mut buf = vec![0u8; 100];
    let n = stream.read(&mut buf).await.unwrap();

    assert_eq!(&buf[..n], payload);
}

#[tokio::test]
async fn test_read_partial_frame_payload() {
    // Split the frame payload across two reads
    // Reference implementation streams partial payload as it arrives
    let payload = b"split payload data";
    let frame = encode_test_frame(payload, 5);

    // Split after header + half payload
    let split_point = 3 + payload.len() / 2;
    let chunk1 = frame[..split_point].to_vec();
    let chunk2 = frame[split_point..].to_vec();

    let mock = MockStream::new(vec![chunk1, chunk2]);
    let mut stream = NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::Variant1);

    // Read all data (may take multiple reads due to streaming)
    let mut result = Vec::new();
    loop {
        let mut buf = vec![0u8; 100];
        let n = stream.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        result.extend_from_slice(&buf[..n]);
        if result.len() >= payload.len() {
            break;
        }
    }

    assert_eq!(result, payload);
}

#[tokio::test]
async fn test_read_transition_to_raw_mode() {
    // Create exactly 8 padded frames + raw data
    // This tests the bug fix for leftover data in read_buffer
    let mut data = Vec::new();

    // 8 padded frames
    for i in 0..NUM_FIRST_PADDINGS {
        let payload = format!("frame{}", i);
        data.extend(encode_test_frame(payload.as_bytes(), 5));
    }

    // Raw data after the padded frames
    let raw_data = b"raw data after padding";
    data.extend_from_slice(raw_data);

    let mock = MockStream::from_data(data);
    let mut stream = NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::Variant1);

    // Read all 8 padded frames
    for i in 0..NUM_FIRST_PADDINGS {
        let mut buf = vec![0u8; 100];
        let n = stream.read(&mut buf).await.unwrap();
        let expected = format!("frame{}", i);
        assert_eq!(&buf[..n], expected.as_bytes(), "frame {} mismatch", i);
    }

    // Now read the raw data (should transition to pass-through mode)
    let mut buf = vec![0u8; 100];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], raw_data, "raw data after transition was lost!");
}

#[tokio::test]
async fn test_read_transition_with_coalesced_data() {
    // This is the specific bug scenario:
    // Last padded frame and raw data arrive in the same TCP read
    let mut data = Vec::new();

    // First 7 frames (will be read separately)
    for i in 0..7 {
        let payload = format!("f{}", i);
        data.extend(encode_test_frame(payload.as_bytes(), 3));
    }

    let first_7_frames = data.clone();
    data.clear();

    // Frame 8 + raw data (coalesced in same read)
    data.extend(encode_test_frame(b"f7", 3));
    data.extend_from_slice(b"RAWDATA");

    // Provide as two chunks: first 7 frames, then frame8+raw
    let mock = MockStream::new(vec![first_7_frames, data]);
    let mut stream = NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::Variant1);

    // Read all 8 padded frames
    for i in 0..8 {
        let mut buf = vec![0u8; 100];
        let n = stream.read(&mut buf).await.unwrap();
        let expected = format!("f{}", i);
        assert_eq!(&buf[..n], expected.as_bytes());
    }

    // The raw data must not be lost!
    let mut buf = vec![0u8; 100];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"RAWDATA", "coalesced raw data was lost!");
}

#[tokio::test]
async fn test_read_transition_after_pure_padding_frame() {
    // Bug test: if frame 8 is pure padding (payload_len=0), we must still
    // transition to raw mode correctly and not try to parse raw data as a frame.
    let mut data = Vec::new();

    // 7 frames with payload
    for i in 0..7 {
        let payload = format!("f{}", i);
        data.extend(encode_test_frame(payload.as_bytes(), 3));
    }

    // Frame 8 is PURE PADDING (payload_len = 0)
    data.extend(encode_test_frame(b"", 50));

    // Raw data immediately after (would be misinterpreted as frame header if buggy)
    data.extend_from_slice(b"RAWDATA");

    let mock = MockStream::from_data(data);
    let mut stream = NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::Variant1);

    // Read first 7 frames
    for i in 0..7 {
        let mut buf = vec![0u8; 100];
        let n = stream.read(&mut buf).await.unwrap();
        let expected = format!("f{}", i);
        assert_eq!(&buf[..n], expected.as_bytes(), "frame {} mismatch", i);
    }

    // Frame 8 is pure padding - this read should skip it and return raw data
    // (or return empty and next read returns raw data)
    let mut result = Vec::new();
    loop {
        let mut buf = vec![0u8; 100];
        let n = stream.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        result.extend_from_slice(&buf[..n]);
        if result == b"RAWDATA" {
            break;
        }
    }

    assert_eq!(
        result, b"RAWDATA",
        "raw data after pure padding frame 8 was corrupted!"
    );
}

#[tokio::test]
async fn test_write_adds_padding_header() {
    let mock = MockStream::new(vec![]);
    let mut stream = NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::Variant1);

    let payload = b"test write";
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();

    // Check the written data has a valid frame header
    let written = &stream.inner.written;
    assert!(written.len() >= 3 + payload.len());

    // Parse header
    let payload_len = u16::from_be_bytes([written[0], written[1]]) as usize;
    let padding_len = written[2] as usize;

    assert_eq!(payload_len, payload.len());
    assert_eq!(&written[3..3 + payload_len], payload);
    assert_eq!(written.len(), 3 + payload_len + padding_len);
}

#[tokio::test]
async fn test_write_transition_to_raw_mode() {
    let mock = MockStream::new(vec![]);
    let mut stream = NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::Variant1);

    // Write 8 padded frames
    for i in 0..NUM_FIRST_PADDINGS {
        let payload = format!("w{}", i);
        stream.write_all(payload.as_bytes()).await.unwrap();
    }

    // Mark where padded frames end
    let padded_end = stream.inner.written.len();

    // Write raw data (should not have padding header)
    let raw_payload = b"raw write data";
    stream.write_all(raw_payload).await.unwrap();

    // The raw data should be written directly without header
    let raw_written = &stream.inner.written[padded_end..];
    assert_eq!(raw_written, raw_payload);
}

#[tokio::test]
async fn test_write_frame_count_tracking() {
    let mock = MockStream::new(vec![]);
    let mut stream = NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::Variant1);

    assert_eq!(stream.num_written_frames, 0);

    for i in 0..5 {
        stream.write_all(b"x").await.unwrap();
        assert_eq!(stream.num_written_frames, i + 1);
    }
}

#[tokio::test]
async fn test_server_padding_bias_for_small_payloads() {
    // Server should bias towards larger padding for small payloads (< 100 bytes)
    // We can't test the exact random values, but we can verify the logic exists
    let mock = MockStream::new(vec![]);
    let mut stream = NaivePaddingStream::new(mock, PaddingDirection::Server, PaddingType::Variant1);

    // Write a small payload
    let small_payload = b"tiny";
    stream.write_all(small_payload).await.unwrap();

    // Parse the written frame
    let written = &stream.inner.written;
    let padding_len = written[2] as usize;

    // For server with small payload, padding should be biased high
    // min_padding = 255 - payload_len = 255 - 4 = 251
    // So padding should be >= 251
    assert!(
        padding_len >= (MAX_PADDING_SIZE as usize).saturating_sub(small_payload.len()),
        "server padding for small payload should be biased high, got {}",
        padding_len
    );
}

#[tokio::test]
async fn test_padding_type_none_passthrough() {
    // With PaddingType::None, data should pass through unchanged
    let test_data = b"passthrough data";
    let mock = MockStream::from_data(test_data.to_vec());
    let mut stream = NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::None);

    let mut buf = vec![0u8; 100];
    let n = stream.read(&mut buf).await.unwrap();

    assert_eq!(&buf[..n], test_data);
}

#[tokio::test]
async fn test_read_eof_handling() {
    // Empty stream should return EOF (0 bytes)
    let mock = MockStream::new(vec![]);
    let mut stream = NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::Variant1);

    let mut buf = vec![0u8; 100];
    let n = stream.read(&mut buf).await.unwrap();

    assert_eq!(n, 0);
}
