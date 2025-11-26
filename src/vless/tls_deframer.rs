use bytes::{Bytes, BytesMut};
use std::io;

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
mod tests {
    use super::*;

    /// Helper to create a TLS record with given content type and payload
    fn make_tls_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut record = Vec::new();
        record.push(content_type);
        record.push(0x03); // Version major
        record.push(0x03); // Version minor
        let len = payload.len() as u16;
        record.extend_from_slice(&len.to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    #[test]
    fn test_single_complete_packet() {
        let mut deframer = TlsDeframer::new();

        let payload = b"Hello, TLS!";
        let record = make_tls_record(0x17, payload); // Application Data

        deframer.feed(&record);

        let read_record = deframer.next_record().unwrap();
        assert!(read_record.is_some());
        let read_record = read_record.unwrap();
        assert_eq!(read_record, &record[..]);

        // Verify no more packets
        assert!(deframer.next_record().unwrap().is_none());
    }

    #[test]
    fn test_partial_packet_split_header() {
        let mut deframer = TlsDeframer::new();

        let payload = b"Partial header test";
        let record = make_tls_record(0x16, payload); // Handshake

        // Feed first 3 bytes (partial header)
        deframer.feed(&record[..3]);
        assert!(deframer.next_record().unwrap().is_none());

        // Feed rest of header
        deframer.feed(&record[3..5]);
        assert!(deframer.next_record().unwrap().is_none());

        // Feed payload
        deframer.feed(&record[5..]);
        let extracted_record = deframer.next_record().unwrap();
        assert!(extracted_record.is_some());
        assert_eq!(extracted_record.unwrap(), &record[..]);
    }

    #[test]
    fn test_partial_packet_split_payload() {
        let mut deframer = TlsDeframer::new();

        let payload = vec![0x42; 100]; // 100 bytes of 0x42
        let record = make_tls_record(0x17, &payload);

        // Feed header + half payload
        let split_point = 5 + 50;
        deframer.feed(&record[..split_point]);
        assert!(deframer.next_record().unwrap().is_none());

        // Feed rest of payload
        deframer.feed(&record[split_point..]);
        let extracted_record = deframer.next_record().unwrap();
        assert!(extracted_record.is_some());
        assert_eq!(extracted_record.unwrap(), &record[..]);
    }

    #[test]
    fn test_multiple_packets_at_once() {
        let mut deframer = TlsDeframer::new();

        let record1 = make_tls_record(0x16, b"First");
        let record2 = make_tls_record(0x17, b"Second");
        let record3 = make_tls_record(0x16, b"Third");

        // Feed all three at once
        let mut combined = Vec::new();
        combined.extend_from_slice(&record1);
        combined.extend_from_slice(&record2);
        combined.extend_from_slice(&record3);

        deframer.feed(&combined);

        // Extract all three (automatically consumed)
        let rec1 = deframer.next_record().unwrap().unwrap();
        assert_eq!(rec1, &record1[..]);

        let rec2 = deframer.next_record().unwrap().unwrap();
        assert_eq!(rec2, &record2[..]);

        let rec3 = deframer.next_record().unwrap().unwrap();
        assert_eq!(rec3, &record3[..]);

        assert!(deframer.next_record().unwrap().is_none());
    }

    #[test]
    fn test_multiple_packets_partial_boundary() {
        let mut deframer = TlsDeframer::new();

        let record1 = make_tls_record(0x16, b"Record One");
        let record2 = make_tls_record(0x17, b"Record Two");

        let mut combined = Vec::new();
        combined.extend_from_slice(&record1);
        combined.extend_from_slice(&record2);

        // Feed up to middle of second record
        let split = record1.len() + 8;
        deframer.feed(&combined[..split]);

        // Should get first record (automatically consumed)
        let rec1 = deframer.next_record().unwrap().unwrap();
        assert_eq!(rec1, &record1[..]);

        // Second record not complete yet
        assert!(deframer.next_record().unwrap().is_none());

        // Feed rest
        deframer.feed(&combined[split..]);
        let rec2 = deframer.next_record().unwrap().unwrap();
        assert_eq!(rec2, &record2[..]);
    }

    #[test]
    fn test_tls10_accepted() {
        let mut deframer = TlsDeframer::new();

        let mut record = vec![0x16, 0x03, 0x01, 0x00, 0x05]; // TLS 1.0
        record.extend_from_slice(b"Hello");

        deframer.feed(&record);

        let result = deframer.next_record();
        assert!(result.is_ok());
        assert_eq!(result.unwrap().unwrap(), &record[..]);
    }

    #[test]
    fn test_invalid_protocol_version() {
        let mut deframer = TlsDeframer::new();

        let mut record = vec![0x16, 0x02, 0x00, 0x00, 0x05]; // SSL 2.0 (invalid)
        record.extend_from_slice(b"Hello");

        deframer.feed(&record);

        let result = deframer.next_record();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid TLS protocol version")
        );
    }

    #[test]
    fn test_invalid_content_type() {
        let mut deframer = TlsDeframer::new();

        let mut record = vec![0xFF, 0x03, 0x03, 0x00, 0x05]; // Invalid content type
        record.extend_from_slice(b"Hello");

        deframer.feed(&record);

        let result = deframer.next_record();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid TLS content type")
        );
    }

    #[test]
    fn test_excessive_payload_length() {
        let mut deframer = TlsDeframer::new();

        // Payload length > 18432 (TLS 1.2 max ciphertext)
        let record = vec![0x17, 0x03, 0x03, 0xFF, 0xFF]; // 65535 bytes

        deframer.feed(&record);

        let result = deframer.next_record();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
    }

    #[test]
    fn test_byte_by_byte_feed() {
        let mut deframer = TlsDeframer::new();

        let record = make_tls_record(0x16, b"Byte by byte");

        // Feed one byte at a time
        for byte in &record[..record.len() - 1] {
            deframer.feed(&[*byte]);
            assert!(deframer.next_record().unwrap().is_none());
        }

        // Feed last byte
        deframer.feed(&[record[record.len() - 1]]);
        let extracted_record = deframer.next_record().unwrap().unwrap();
        assert_eq!(extracted_record, &record[..]);
    }

    #[test]
    fn test_clear() {
        let mut deframer = TlsDeframer::new();

        let record = make_tls_record(0x16, b"Test");
        deframer.feed(&record[..3]); // Partial

        assert_eq!(deframer.pending_bytes(), 3);

        deframer.clear();

        assert_eq!(deframer.pending_bytes(), 0);
        assert!(deframer.next_record().unwrap().is_none());
    }

    #[test]
    fn test_empty_payload() {
        let mut deframer = TlsDeframer::new();

        let record = make_tls_record(0x16, b""); // Empty payload

        deframer.feed(&record);

        let extracted_record = deframer.next_record().unwrap().unwrap();
        assert_eq!(extracted_record.len(), 5); // Just the header
        assert_eq!(extracted_record, &record[..]);
    }

    #[test]
    fn test_max_size_payload() {
        let mut deframer = TlsDeframer::new();

        // Test with maximum TLS 1.2 ciphertext size (18,432 bytes)
        let payload = vec![0xAA; 18432];
        let record = make_tls_record(0x17, &payload);

        deframer.feed(&record);

        let extracted_record = deframer.next_record().unwrap().unwrap();
        assert_eq!(extracted_record, &record[..]);
    }

    #[test]
    fn test_reuse_after_consume() {
        let mut deframer = TlsDeframer::new();

        let record1 = make_tls_record(0x16, b"First");
        let record2 = make_tls_record(0x17, b"Second");

        // First packet (automatically consumed)
        deframer.feed(&record1);
        let rec1 = deframer.next_record().unwrap().unwrap();
        assert_eq!(rec1, &record1[..]);

        // Second packet (automatically consumed)
        deframer.feed(&record2);
        let rec2 = deframer.next_record().unwrap().unwrap();
        assert_eq!(rec2, &record2[..]);

        assert_eq!(deframer.pending_bytes(), 0);
    }

    #[test]
    fn test_next_records_empty() {
        let mut deframer = TlsDeframer::new();

        let records = deframer.next_records().unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn test_next_records_single() {
        let mut deframer = TlsDeframer::new();

        let record = make_tls_record(0x16, b"Single");
        deframer.feed(&record);

        let records = deframer.next_records().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], &record[..]);
    }

    #[test]
    fn test_next_records_multiple() {
        let mut deframer = TlsDeframer::new();

        let record1 = make_tls_record(0x16, b"First");
        let record2 = make_tls_record(0x17, b"Second");
        let record3 = make_tls_record(0x16, b"Third");

        let mut combined = Vec::new();
        combined.extend_from_slice(&record1);
        combined.extend_from_slice(&record2);
        combined.extend_from_slice(&record3);

        deframer.feed(&combined);

        let records = deframer.next_records().unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0], &record1[..]);
        assert_eq!(records[1], &record2[..]);
        assert_eq!(records[2], &record3[..]);

        assert_eq!(deframer.pending_bytes(), 0);
    }

    #[test]
    fn test_next_records_partial_remaining() {
        let mut deframer = TlsDeframer::new();

        let record1 = make_tls_record(0x16, b"Complete");
        let record2 = make_tls_record(0x17, b"Incomplete");

        let mut combined = Vec::new();
        combined.extend_from_slice(&record1);
        combined.extend_from_slice(&record2[..10]); // Only partial second record

        deframer.feed(&combined);

        let records = deframer.next_records().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], &record1[..]);

        // Should still have partial data
        assert_eq!(deframer.pending_bytes(), 10);
    }

    #[test]
    fn test_next_records_error_propagation() {
        let mut deframer = TlsDeframer::new();

        // Invalid record with bad content type
        let mut bad_record = vec![0xFF, 0x03, 0x03, 0x00, 0x05];
        bad_record.extend_from_slice(b"Hello");

        deframer.feed(&bad_record);

        let result = deframer.next_records();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid TLS content type")
        );
    }

    #[test]
    fn test_next_records_mixed_complete_and_partial() {
        let mut deframer = TlsDeframer::new();

        let record1 = make_tls_record(0x16, b"First");
        let record2 = make_tls_record(0x17, b"Second");

        // Feed first complete record and partial second
        deframer.feed(&record1);
        deframer.feed(&record2[..8]);

        let records = deframer.next_records().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], &record1[..]);

        // Complete the second record
        deframer.feed(&record2[8..]);

        let records = deframer.next_records().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], &record2[..]);
    }
}
