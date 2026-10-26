use bytes::{Bytes, BytesMut};
use futures::ready;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

/// TLS record header size (ContentType + ProtocolVersion + Length)
const TLS_RECORD_HEADER_SIZE: usize = 5;

/// Maximum TLS ciphertext payload size per RFC specifications
///
/// The TLS record header's `length` field specifies the size of the ENCRYPTED payload (ciphertext).
/// Per RFC 8446 (TLS 1.3) and RFC 5246 (TLS 1.2), the limits are:
///
/// - TLS 1.3: Plaintext limit = 16,384 bytes (2^14)
///   Encryption overhead allowance = 256 bytes
///   Ciphertext limit = 16,384 + 256 = 16,640 bytes
///
/// - TLS 1.2: Plaintext limit = 16,384 bytes (2^14)
///   Encryption overhead allowance = 2,048 bytes
///   Ciphertext limit = 16,384 + 2,048 = 18,432 bytes
///
/// We use the TLS 1.2 limit for maximum compatibility with both protocol versions.
/// See /shoes/VISION_TLS_RECORD_SIZE.md for detailed analysis and RFC references.
const MAX_TLS_CIPHERTEXT_LEN: usize = 16384 + 2048; // 18,432 bytes (TLS 1.2 limit)

/// Maximum TLS record size (ciphertext + header)
pub const TLS_MAX_RECORD_SIZE: usize = MAX_TLS_CIPHERTEXT_LEN + TLS_RECORD_HEADER_SIZE;

/// TLS protocol versions we expect (0x0303 = TLS 1.2 for compatibility)
const TLS_PROTOCOL_VERSION_MAJOR: u8 = 0x03;
const TLS_PROTOCOL_VERSION_MINOR_MIN: u8 = 0x01;
const TLS_PROTOCOL_VERSION_MINOR_MAX: u8 = 0x03;

/// Deframer that reassembles TLS records from partial reads/writes
///
/// ```ignore
/// let mut deframer = TlsDeframer::new();
///
/// // Feed data as it arrives (may be partial)
/// deframer.feed(&chunk1);
/// deframer.feed(&chunk2);
///
/// // Extract complete records
/// while let Some(record) = deframer.next_record()? {
///     process_tls_record(record);
/// }
/// ```
#[derive(Debug, PartialEq)]
pub struct TlsDeframer {
    /// Buffer holding partial TLS record data
    buffer: BytesMut,

    /// Current parsing state
    state: DeframerState,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum DeframerState {
    /// Waiting for or reading the 5-byte TLS record header
    ReadingHeader,

    /// Reading payload of known length
    /// Stores the expected payload length
    ReadingPayload { payload_len: usize },
}

impl TlsDeframer {
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(TLS_MAX_RECORD_SIZE),
            state: DeframerState::ReadingHeader,
        }
    }

    /// Feed data into the deframer
    ///
    /// This data may contain partial TLS records, complete records, or multiple records.
    /// Call `next_record()` after feeding to extract complete records.
    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Extract the next complete TLS record if available
    ///
    /// This method automatically advances the internal buffer after extracting the record.
    ///
    /// Returns:
    /// - `Ok(Some(Bytes))` if a complete record is available (zero-copy slice)
    /// - `Ok(None)` if more data is needed
    /// - `Err(...)` if the data is malformed
    pub fn next_record(&mut self) -> io::Result<Option<Bytes>> {
        loop {
            match self.state {
                DeframerState::ReadingHeader => {
                    // Need at least 5 bytes for header
                    if self.buffer.len() < TLS_RECORD_HEADER_SIZE {
                        return Ok(None);
                    }

                    // Parse TLS record header
                    let content_type = self.buffer[0];
                    let version_major = self.buffer[1];
                    let version_minor = self.buffer[2];
                    let payload_len = u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize;

                    // Validate protocol version (should be 0x03XX for TLS 1.x)
                    // Accept TLS 1.0 (0x0301), TLS 1.1 (0x0302), TLS 1.2 (0x0303), and TLS 1.3 (0x0303)
                    // TLS 1.3 uses 0x0303 in the record layer for backwards compatibility
                    if version_major != TLS_PROTOCOL_VERSION_MAJOR
                        || !(TLS_PROTOCOL_VERSION_MINOR_MIN..=TLS_PROTOCOL_VERSION_MINOR_MAX)
                            .contains(&version_minor)
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "Invalid TLS protocol version: 0x{:02x}{:02x} (expected 0x0301 to 0x0303)",
                                version_major, version_minor
                            ),
                        ));
                    }

                    // Validate ciphertext payload length
                    // The `payload_len` from the TLS record header specifies encrypted data size.
                    // TLS 1.2 allows up to 18,432 bytes (16,384 plaintext + 2,048 overhead).
                    if payload_len > MAX_TLS_CIPHERTEXT_LEN {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "TLS record ciphertext length {} exceeds maximum {} (TLS 1.2 limit)",
                                payload_len, MAX_TLS_CIPHERTEXT_LEN
                            ),
                        ));
                    }

                    // Validate content type (basic sanity check)
                    // Valid types: 0x14-0x18 (ChangeCipherSpec, Alert, Handshake, Application Data, Heartbeat)
                    if !(0x14..=0x18).contains(&content_type) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Invalid TLS content type: 0x{:02x}", content_type),
                        ));
                    }

                    // Transition to reading payload
                    self.state = DeframerState::ReadingPayload { payload_len };
                }

                DeframerState::ReadingPayload { payload_len } => {
                    let total_len = TLS_RECORD_HEADER_SIZE + payload_len;

                    // Check if we have the complete record
                    if self.buffer.len() < total_len {
                        return Ok(None);
                    }

                    // We have a complete record! Extract it using split_to for zero-copy.
                    // BytesMut::split_to() returns a Bytes object that shares the underlying
                    // buffer without copying, and advances the BytesMut past the split point.
                    let record = self.buffer.split_to(total_len).freeze();

                    // Reset state for next record
                    self.state = DeframerState::ReadingHeader;

                    return Ok(Some(record));
                }
            }
        }
    }

    pub fn poll_read_record<IO: AsyncRead + Unpin + ?Sized>(
        &mut self,
        io: &mut IO,
        cx: &mut Context<'_>,
        scratch: &mut [u8],
        read_ahead: bool,
    ) -> Poll<io::Result<Option<Bytes>>> {
        loop {
            if let Some(record) = self.next_record()? {
                return Poll::Ready(Ok(Some(record)));
            }

            let read_len = if read_ahead {
                scratch.len()
            } else {
                // Finish seeded input at a record boundary before returning to backend reads.
                let record_len = match self.state {
                    DeframerState::ReadingHeader => TLS_RECORD_HEADER_SIZE,
                    DeframerState::ReadingPayload { payload_len } => {
                        TLS_RECORD_HEADER_SIZE + payload_len
                    }
                };
                scratch.len().min(record_len - self.buffer.len())
            };
            let mut buf = ReadBuf::new(&mut scratch[..read_len]);
            ready!(Pin::new(&mut *io).poll_read(cx, &mut buf))?;
            if buf.filled().is_empty() {
                return if self.pending_bytes() == 0 {
                    Poll::Ready(Ok(None))
                } else {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "EOF inside a TLS record",
                    )))
                };
            }
            self.feed(buf.filled());
        }
    }

    /// Get the number of bytes currently buffered
    pub fn pending_bytes(&self) -> usize {
        self.buffer.len()
    }

    /// Extract all available complete TLS records
    ///
    /// This is equivalent to calling `next_record()` repeatedly until it returns `Ok(None)`,
    /// but more convenient when you want to process all available records at once.
    ///
    /// Returns a vector of all complete records that can be extracted from the current buffer.
    /// If no complete records are available, returns an empty vector.
    ///
    /// Returns:
    /// - `Ok(Vec<Bytes>)` containing all available complete records (may be empty)
    /// - `Err(...)` if any record is malformed
    pub fn next_records(&mut self) -> io::Result<Vec<Bytes>> {
        let mut records = Vec::new();

        while let Some(record) = self.next_record()? {
            records.push(record);
        }

        Ok(records)
    }

    /// Consume the deframer and return all remaining buffered data
    pub fn into_remaining_data(self) -> Bytes {
        self.buffer.freeze()
    }

    pub fn remaining_data(&self) -> &[u8] {
        &self.buffer
    }

    /// Clear all buffered data
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.state = DeframerState::ReadingHeader;
    }

    pub fn deallocate(&mut self) {
        drop(std::mem::take(&mut self.buffer));
    }
}

impl Default for TlsDeframer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
