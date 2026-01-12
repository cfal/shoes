use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};
use crate::util::allocate_vec;

/// Number of frames to pad in each direction
pub const NUM_FIRST_PADDINGS: usize = 8;

/// Maximum padding size per frame
pub const MAX_PADDING_SIZE: u8 = 255;

/// Padding frame header size (2 bytes payload length + 1 byte padding length)
pub const PADDING_HEADER_SIZE: usize = 3;

/// Maximum payload size (limited by 2-byte length field)
pub const MAX_PAYLOAD_SIZE: usize = 65535;

/// Maximum frame size including header and padding
const MAX_FRAME_SIZE: usize = PADDING_HEADER_SIZE + MAX_PAYLOAD_SIZE + MAX_PADDING_SIZE as usize;

/// Characters that won't be Huffman-coded efficiently by HPACK (>= 8 bits)
/// These are the first 17 ASCII printable chars with Huffman code length >= 8
/// from RFC 7541 Appendix B, matching the reference naiveproxy implementation.
/// Order: !"#$&'()*+,;<>?@X
pub const NONINDEX_CHARS: &[u8] = b"!\"#$&'()*+,;<>?@X";

/// Padding type negotiation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingType {
    /// No padding
    None = 0,
    /// Variant 1: 3-byte header (payload_len_be16 + padding_len_u8)
    Variant1 = 1,
}

impl PaddingType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(PaddingType::None),
            1 => Some(PaddingType::Variant1),
            _ => None,
        }
    }
}

/// Direction of the connection (kept for API compatibility).
/// Note: Padding behavior is now uniform for both directions per NaiveProxy spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingDirection {
    /// Client side
    Client,
    /// Server side
    Server,
}

/// Generate a random padding header value for HTTP headers.
/// Uses characters that won't be Huffman-coded efficiently by HPACK.
/// Matches the reference naiveproxy FillNonindexHeaderValue implementation.
pub fn generate_padding_header(len: usize) -> String {
    let mut rng = rand::rng();
    let mut buf = Vec::with_capacity(len);

    // First 16 chars use 4 bits of entropy each to select from first 16 chars
    for _ in 0..len.min(16) {
        let idx = rng.random_range(0..16);
        buf.push(NONINDEX_CHARS[idx]);
    }

    // Remaining chars use the 17th character (index 16 = 'X')
    for _ in 16..len {
        buf.push(NONINDEX_CHARS[16]); // 'X'
    }

    // Safe because NONINDEX_CHARS are all ASCII
    String::from_utf8(buf).unwrap()
}

/// Parse Padding-Type-Request header value.
/// Returns list of supported types in preference order.
pub fn parse_padding_type_request(value: &str) -> Vec<PaddingType> {
    value
        .split(',')
        .filter_map(|s| s.trim().parse::<u8>().ok())
        .filter_map(PaddingType::from_u8)
        .collect()
}

/// Threshold for small payload bias on server side
const SMALL_PAYLOAD_THRESHOLD: usize = 100;
/// Threshold for medium payload fragmentation (lower bound)
const MEDIUM_PAYLOAD_LOW: usize = 400;
/// Threshold for medium payload fragmentation (upper bound)
const MEDIUM_PAYLOAD_HIGH: usize = 1024;
/// Minimum fragment size for server-side write fragmentation
const FRAGMENT_SIZE_MIN: usize = 200;
/// Maximum fragment size for server-side write fragmentation
const FRAGMENT_SIZE_MAX: usize = 300;

/// Wrapper stream that applies NaiveProxy padding.
///
/// Pads the first 8 reads and writes in each direction to obscure
/// traffic fingerprints from initial handshakes.
///
/// Memory-optimized: decodes directly into user buffer without intermediate storage.
pub struct NaivePaddingStream<S> {
    inner: S,
    padding_type: PaddingType,
    direction: PaddingDirection,
    /// Number of frames read so far
    num_read_frames: usize,
    /// Number of frames written so far
    num_written_frames: usize,
    /// Pre-allocated buffer for incoming frame data
    read_buffer: Box<[u8]>,
    read_buffer_start: usize,
    read_buffer_end: usize,
    /// Current frame state: (payload_len, padding_len, payload_delivered)
    /// payload_delivered tracks how many payload bytes have been copied to user
    current_frame: Option<(usize, usize, usize)>,
    /// Pre-allocated buffer for encoded frame writes
    write_buffer: Box<[u8]>,
    write_start: usize,
    write_end: usize,
    /// Original payload length for current write (to return correct count)
    write_payload_len: usize,
}

impl<S> NaivePaddingStream<S> {
    pub fn new(inner: S, direction: PaddingDirection, padding_type: PaddingType) -> Self {
        // Pre-allocate buffers sized for maximum frame
        let read_buffer = allocate_vec(MAX_FRAME_SIZE).into_boxed_slice();
        let write_buffer = allocate_vec(MAX_FRAME_SIZE).into_boxed_slice();

        Self {
            inner,
            padding_type,
            direction,
            num_read_frames: 0,
            num_written_frames: 0,
            read_buffer,
            read_buffer_start: 0,
            read_buffer_end: 0,
            current_frame: None,
            write_buffer,
            write_start: 0,
            write_end: 0,
            write_payload_len: 0,
        }
    }

    /// Return buffered data to user, reset buffer if empty. Returns bytes copied.
    #[inline]
    fn drain_read_buffer(&mut self, buf: &mut ReadBuf<'_>) -> usize {
        let available = self.read_buffer_end - self.read_buffer_start;
        let to_copy = available.min(buf.remaining());
        buf.put_slice(&self.read_buffer[self.read_buffer_start..self.read_buffer_start + to_copy]);
        self.read_buffer_start += to_copy;
        if self.read_buffer_start >= self.read_buffer_end {
            self.read_buffer_start = 0;
            self.read_buffer_end = 0;
        }
        to_copy
    }

    /// Reset buffer offsets if buffer is empty.
    #[inline]
    fn maybe_reset_read_buffer(&mut self) {
        if self.read_buffer_start == self.read_buffer_end {
            self.read_buffer_start = 0;
            self.read_buffer_end = 0;
        }
    }

    /// Check if we should still be padding reads
    #[inline]
    fn should_pad_reads(&self) -> bool {
        self.padding_type != PaddingType::None && self.num_read_frames < NUM_FIRST_PADDINGS
    }

    /// Check if we should still be padding writes
    #[inline]
    fn should_pad_writes(&self) -> bool {
        self.padding_type != PaddingType::None && self.num_written_frames < NUM_FIRST_PADDINGS
    }

    /// Generate random padding size for a write.
    /// Server-side biases padding towards larger values for small payloads
    /// to prevent fingerprinting of small response packets.
    fn generate_padding_size(&self, payload_len: usize) -> u8 {
        let mut rng = rand::rng();

        if self.direction == PaddingDirection::Server && payload_len < SMALL_PAYLOAD_THRESHOLD {
            // For small payloads on server side, bias towards larger padding
            // Range: [255 - payload_len, 255]
            let min_padding = (MAX_PADDING_SIZE as usize).saturating_sub(payload_len);
            rng.random_range(min_padding as u8..=MAX_PADDING_SIZE)
        } else {
            // Uniform distribution for client or larger payloads
            rng.random_range(0..=MAX_PADDING_SIZE)
        }
    }

    /// Compute fragment limit for server-side write fragmentation.
    /// Returns 0 if no fragmentation needed, otherwise returns the max bytes to write.
    fn compute_fragment_limit(&self, payload_len: usize, remaining: usize) -> usize {
        if self.direction == PaddingDirection::Server
            && payload_len > MEDIUM_PAYLOAD_LOW
            && payload_len < MEDIUM_PAYLOAD_HIGH
        {
            // Fragment medium-sized server writes to 200-300 bytes
            let limit = rand::rng().random_range(FRAGMENT_SIZE_MIN..=FRAGMENT_SIZE_MAX);
            remaining.min(limit)
        } else {
            remaining
        }
    }

    /// Encode a payload into the write buffer as a padded frame.
    fn encode_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Payload too large: {} > {}",
                    payload.len(),
                    MAX_PAYLOAD_SIZE
                ),
            ));
        }

        let padding_size = self.generate_padding_size(payload.len());
        let payload_len = payload.len() as u16;
        let frame_size = PADDING_HEADER_SIZE + payload.len() + padding_size as usize;

        // Write header: payload_len (2 bytes BE) + padding_size (1 byte)
        self.write_buffer[0] = (payload_len >> 8) as u8;
        self.write_buffer[1] = (payload_len & 0xff) as u8;
        self.write_buffer[2] = padding_size;

        // Write payload
        self.write_buffer[PADDING_HEADER_SIZE..PADDING_HEADER_SIZE + payload.len()]
            .copy_from_slice(payload);

        // Write padding (zeros)
        let padding_start = PADDING_HEADER_SIZE + payload.len();
        self.write_buffer[padding_start..padding_start + padding_size as usize].fill(0);

        self.write_start = 0;
        self.write_end = frame_size;
        self.write_payload_len = payload.len();

        Ok(())
    }

    /// Reset read buffer offset by moving remaining data to the front.
    #[inline]
    fn reset_read_buffer_offset(&mut self) {
        if self.read_buffer_start > 0 && self.read_buffer_end > self.read_buffer_start {
            self.read_buffer
                .copy_within(self.read_buffer_start..self.read_buffer_end, 0);
            self.read_buffer_end -= self.read_buffer_start;
            self.read_buffer_start = 0;
        } else if self.read_buffer_start == self.read_buffer_end {
            self.read_buffer_start = 0;
            self.read_buffer_end = 0;
        }
    }

    /// Try to decode payload directly into user's buffer.
    /// Returns the number of bytes written to buf, or None if more data needed.
    /// Streams partial payload as it becomes available (matching reference implementation).
    #[inline]
    fn try_decode_to_buf(&mut self, buf: &mut ReadBuf<'_>) -> Option<usize> {
        let available = self.read_buffer_end - self.read_buffer_start;

        // Get or parse current frame state
        let (payload_len, padding_len, payload_delivered) = match self.current_frame {
            Some((pl, pd, delivered)) => (pl, pd, delivered),
            None => {
                // Need to parse header first
                if available < PADDING_HEADER_SIZE {
                    return None;
                }

                let payload_len = u16::from_be_bytes([
                    self.read_buffer[self.read_buffer_start],
                    self.read_buffer[self.read_buffer_start + 1],
                ]) as usize;
                let padding_len = self.read_buffer[self.read_buffer_start + 2] as usize;

                self.read_buffer_start += PADDING_HEADER_SIZE;
                self.current_frame = Some((payload_len, padding_len, 0));

                (payload_len, padding_len, 0)
            }
        };

        let payload_remaining = payload_len - payload_delivered;
        let available = self.read_buffer_end - self.read_buffer_start;

        // If we still need payload bytes
        if payload_remaining > 0 {
            // Check if we have data to deliver
            if available == 0 {
                return None; // Need more data from stream
            }
            // Note: can_deliver > 0 guaranteed because poll_read checks buf.remaining() > 0
            let can_deliver = payload_remaining.min(available).min(buf.remaining());

            buf.put_slice(
                &self.read_buffer[self.read_buffer_start..self.read_buffer_start + can_deliver],
            );
            self.read_buffer_start += can_deliver;

            let new_delivered = payload_delivered + can_deliver;
            if new_delivered < payload_len {
                // More payload to deliver later
                self.current_frame = Some((payload_len, padding_len, new_delivered));
                return Some(can_deliver);
            }

            // Payload complete, now skip padding
            let available = self.read_buffer_end - self.read_buffer_start;
            if available < padding_len {
                // Need more data to skip padding
                self.current_frame = Some((payload_len, padding_len, new_delivered));
                return Some(can_deliver);
            }

            // Skip padding and complete frame
            self.read_buffer_start += padding_len;
            self.current_frame = None;
            self.num_read_frames += 1;
            self.maybe_reset_read_buffer();
            return Some(can_deliver);
        }

        // Payload already delivered, just need to skip padding
        if available < padding_len {
            return None;
        }

        self.read_buffer_start += padding_len;
        self.current_frame = None;
        self.num_read_frames += 1;
        self.maybe_reset_read_buffer();

        // Frame complete but no data delivered this call (was a pure padding frame)
        Some(0)
    }
}

impl<S: AsyncWrite + Unpin> NaivePaddingStream<S> {
    /// Write buffered frame data to inner stream with fragmentation support.
    /// Returns Ok(Some(payload_len)) when frame is complete, Ok(None) if partial.
    fn poll_write_buffered(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<usize>>> {
        let remaining = self.write_end - self.write_start;
        if remaining == 0 {
            return Poll::Ready(Ok(Some(self.write_payload_len)));
        }

        let fragment_limit = self.compute_fragment_limit(self.write_payload_len, remaining);
        let to_write = &self.write_buffer[self.write_start..self.write_start + fragment_limit];

        match Pin::new(&mut self.inner).poll_write(cx, to_write) {
            Poll::Ready(Ok(n)) => {
                self.write_start += n;
                if self.write_start >= self.write_end {
                    self.num_written_frames += 1;
                    Poll::Ready(Ok(Some(self.write_payload_len)))
                } else {
                    Poll::Ready(Ok(None))
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for NaivePaddingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;

        // Handle zero-size buffer to avoid infinite loop
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        if !this.should_pad_reads() {
            // Return leftover buffered data from padding phase before switching to passthrough
            if this.read_buffer_end > this.read_buffer_start {
                this.drain_read_buffer(buf);
                return Poll::Ready(Ok(()));
            }
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }

        // Decode frames directly into user's buffer
        loop {
            if let Some(n) = this.try_decode_to_buf(buf) {
                if n > 0 {
                    return Poll::Ready(Ok(()));
                }
                // n == 0 means pure padding frame was skipped.
                // Re-check if we've finished padding phase before continuing.
                if !this.should_pad_reads() {
                    // Transitioned to raw mode - return any buffered data
                    if this.read_buffer_end > this.read_buffer_start {
                        this.drain_read_buffer(buf);
                        return Poll::Ready(Ok(()));
                    }
                    return Pin::new(&mut this.inner).poll_read(cx, buf);
                }
                continue;
            }

            // Need more data
            if this.read_buffer_end >= this.read_buffer.len() {
                this.reset_read_buffer_offset();
            }

            let read_slice = &mut this.read_buffer[this.read_buffer_end..];
            let mut temp_read_buf = ReadBuf::new(read_slice);

            match Pin::new(&mut this.inner).poll_read(cx, &mut temp_read_buf) {
                Poll::Ready(Ok(())) => {
                    let filled_len = temp_read_buf.filled().len();
                    if filled_len == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    this.read_buffer_end += filled_len;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Maximum payload size per padded frame (matches reference 64KB buffer minus overhead)
const MAX_PAYLOAD_PER_FRAME: usize = 64 * 1024 - PADDING_HEADER_SIZE - MAX_PADDING_SIZE as usize;

impl<S: AsyncWrite + Unpin> AsyncWrite for NaivePaddingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;

        if !this.should_pad_writes() {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        // Finish writing buffered frame data first
        if this.write_start < this.write_end {
            match this.poll_write_buffered(cx) {
                Poll::Ready(Ok(Some(payload_len))) => return Poll::Ready(Ok(payload_len)),
                Poll::Ready(Ok(None)) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let payload = if buf.len() > MAX_PAYLOAD_PER_FRAME {
            &buf[..MAX_PAYLOAD_PER_FRAME]
        } else {
            buf
        };

        this.encode_frame(payload)?;

        match this.poll_write_buffered(cx) {
            Poll::Ready(Ok(Some(payload_len))) => Poll::Ready(Ok(payload_len)),
            Poll::Ready(Ok(None)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;

        // Complete any pending buffered write first
        while this.write_start < this.write_end {
            match this.poll_write_buffered(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;

        // Complete any pending buffered write first
        while this.write_start < this.write_end {
            match this.poll_write_buffered(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncPing> AsyncPing for NaivePaddingStream<S> {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        // Cannot safely implement ping through padding layer
        Poll::Ready(Ok(false))
    }
}

impl<S: AsyncStream> AsyncStream for NaivePaddingStream<S> {}

#[cfg(test)]
mod tests {
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
        frame.extend(std::iter::repeat(0u8).take(padding_len as usize));
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
        assert_eq!(frame.len(), 3 + 0 + 50);
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

    #[tokio::test]
    async fn test_read_single_padded_frame() {
        let payload = b"hello world";
        let frame = encode_test_frame(payload, 20);
        let mock = MockStream::from_data(frame);

        let mut stream =
            NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::Variant1);

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
        let mut stream =
            NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::Variant1);

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
        let mut stream =
            NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::Variant1);

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
        let mut stream =
            NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::Variant1);

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
        let mut stream =
            NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::Variant1);

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
        let mut stream =
            NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::Variant1);

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
        let mut stream =
            NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::Variant1);

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
        let mut stream =
            NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::Variant1);

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

        assert_eq!(result, b"RAWDATA", "raw data after pure padding frame 8 was corrupted!");
    }

    #[tokio::test]
    async fn test_write_adds_padding_header() {
        let mock = MockStream::new(vec![]);
        let mut stream =
            NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::Variant1);

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
        let mut stream =
            NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::Variant1);

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
        let mut stream =
            NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::Variant1);

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
        let mut stream =
            NaivePaddingStream::new(mock, PaddingDirection::Server, PaddingType::Variant1);

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
        let mut stream =
            NaivePaddingStream::new(mock, PaddingDirection::Client, PaddingType::Variant1);

        let mut buf = vec![0u8; 100];
        let n = stream.read(&mut buf).await.unwrap();

        assert_eq!(n, 0);
    }
}
