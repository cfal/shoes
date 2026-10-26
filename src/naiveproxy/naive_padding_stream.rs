use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use rand::RngExt;
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
    /// Payload length used to choose the current frame's fragment size
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
    /// Writes at most one fragment of the buffered frame.
    fn poll_write_buffered(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let remaining = self.write_end - self.write_start;
        if remaining == 0 {
            return Poll::Ready(Ok(()));
        }

        let fragment_limit = self.compute_fragment_limit(self.write_payload_len, remaining);
        let to_write = &self.write_buffer[self.write_start..self.write_start + fragment_limit];

        let written = ready!(Pin::new(&mut self.inner).poll_write(cx, to_write))?;
        if written == 0 {
            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
        }
        self.write_start += written;
        if self.write_start == self.write_end {
            self.num_written_frames += 1;
        }
        Poll::Ready(Ok(()))
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

        if this.write_start < this.write_end {
            ready!(this.poll_write_buffered(cx))?;
            if this.write_start < this.write_end {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }

        if !this.should_pad_writes() {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        let payload = &buf[..buf.len().min(MAX_PAYLOAD_PER_FRAME)];
        this.encode_frame(payload)?;
        if let Poll::Ready(Err(error)) = this.poll_write_buffered(cx) {
            this.write_end = 0;
            return Poll::Ready(Err(error));
        }
        // Owned input is accepted even when its encoded frame still needs draining.
        Poll::Ready(Ok(payload.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;

        // Complete any pending buffered write first
        while this.write_start < this.write_end {
            ready!(this.poll_write_buffered(cx))?;
        }

        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;

        // Complete any pending buffered write first
        while this.write_start < this.write_end {
            ready!(this.poll_write_buffered(cx))?;
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

impl<S: AsyncStream> AsyncStream for NaivePaddingStream<S> {
    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.peer_addr()
    }
}

#[cfg(test)]
mod tests;
