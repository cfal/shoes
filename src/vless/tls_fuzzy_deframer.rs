/// Fuzzy TLS deframer that can handle unknown prefixes before TLS data
///
/// This deframer wraps TlsDeframer and adds the ability to:
/// 1. Search for TLS handshake patterns in buffers that may contain protocol headers
/// 2. Proactively return unknown prefix bytes that cannot be part of TLS patterns
/// 3. Minimize buffering by discarding non-TLS prefixes as soon as possible
///
/// The deframer operates in two states:
/// - **Searching**: Looking for the TLS handshake pattern [0x16, 0x03, 0x01-0x03, ?, ?, 0x01|0x02]
///   - Returns UnknownPrefix for bytes that cannot be part of the pattern
///   - Keeps minimal suffix that might complete into a pattern (max 5 bytes)
/// - **Deframing**: Found TLS pattern, now extracting complete TLS records
///   - Delegates to inner TlsDeframer for standard TLS record parsing
///
/// This is used in VLESS Vision protocol when chaining proxies, where the inner TLS data
/// may be prefixed with VLESS protocol headers from intermediate proxies.
use bytes::{Bytes, BytesMut};
use std::io;

use super::tls_deframer::TlsDeframer;
use super::tls_handshake_util::{
    MIN_TLS_HANDSHAKE_PATTERN_LEN, find_tls_handshake_start, get_partial_tls_pattern_suffix_len,
};

/// Result of attempting to extract data from the fuzzy deframer
#[derive(Debug, PartialEq)]
pub enum DeframeResult {
    /// Complete TLS record extracted
    TlsRecord(Bytes),

    /// Unknown prefix bytes that were skipped
    /// Returned proactively as soon as we know bytes aren't part of TLS pattern
    UnknownPrefix(Bytes),

    /// Need more data (waiting for complete record or more pattern bytes)
    NeedData,
}

/// Fuzzy TLS deframer that can skip unknown prefixes before TLS data
pub struct FuzzyTlsDeframer {
    /// Underlying TLS deframer (only used in Deframing state)
    inner: TlsDeframer,

    /// Search buffer (only used in Searching state)
    search_buffer: BytesMut,

    /// Current state
    state: FuzzyState,

    /// Total prefix bytes discarded (for logging)
    total_prefix_bytes: usize,
}

#[derive(Debug, PartialEq)]
enum FuzzyState {
    /// Searching for TLS handshake pattern
    Searching,

    /// Found TLS pattern, now in normal deframing mode
    Deframing,
}

impl FuzzyTlsDeframer {
    pub fn new() -> Self {
        Self {
            inner: TlsDeframer::new(),
            search_buffer: BytesMut::new(),
            state: FuzzyState::Searching,
            total_prefix_bytes: 0,
        }
    }

    /// Feed data into the deframer
    ///
    /// Data may contain protocol headers, partial TLS patterns, or complete TLS records.
    /// Call `next_record()` after feeding to extract available data.
    pub fn feed(&mut self, data: &[u8]) {
        match self.state {
            FuzzyState::Searching => {
                // Just accumulate in search buffer
                // Don't optimize here - let next_record() handle it for proper accounting
                self.search_buffer.extend_from_slice(data);
            }
            FuzzyState::Deframing => {
                // Normal mode, feed directly to inner deframer
                self.inner.feed(data);
            }
        }
    }

    /// Extract the next available data
    ///
    /// Returns:
    /// - `TlsRecord`: A complete TLS record (in Deframing state)
    /// - `UnknownPrefix`: Bytes that cannot be part of TLS pattern (in Searching state)
    /// - `IncompleteRecord`: Need more data
    ///
    /// This method should be called in a loop until it returns `IncompleteRecord`.
    pub fn next_record(&mut self) -> io::Result<DeframeResult> {
        loop {
            match self.state {
                FuzzyState::Searching => {
                    if self.search_buffer.is_empty() {
                        return Ok(DeframeResult::NeedData);
                    }

                    // Try to find complete TLS pattern (need at least 6 bytes)
                    if self.search_buffer.len() >= MIN_TLS_HANDSHAKE_PATTERN_LEN {
                        if let Some(offset) = find_tls_handshake_start(&self.search_buffer) {
                            // Found complete pattern!

                            if offset > 0 {
                                // There's a prefix before the TLS pattern
                                // Extract it and return as UnknownPrefix
                                let prefix = self.search_buffer.split_to(offset).freeze();
                                self.total_prefix_bytes += prefix.len();

                                // Feed remaining data (TLS) to inner deframer
                                self.inner.feed(&self.search_buffer);
                                self.search_buffer.clear();

                                // Transition to Deframing state
                                self.state = FuzzyState::Deframing;

                                log::debug!(
                                    "FuzzyTlsDeframer: Found TLS pattern after {} byte prefix (total {} bytes discarded), transitioned to Deframing",
                                    prefix.len(),
                                    self.total_prefix_bytes
                                );

                                return Ok(DeframeResult::UnknownPrefix(prefix));
                            } else {
                                // offset == 0, pattern at start, no prefix
                                self.inner.feed(&self.search_buffer);
                                self.search_buffer.clear();
                                self.state = FuzzyState::Deframing;

                                log::debug!(
                                    "FuzzyTlsDeframer: Found TLS pattern at offset 0 (total {} bytes discarded), transitioned to Deframing",
                                    self.total_prefix_bytes
                                );

                                // Continue loop to try extracting a record from inner
                                continue;
                            }
                        } else {
                            // No complete pattern found, but we have enough bytes to check
                            // Check if we can discard some prefix bytes
                            let suffix_len =
                                get_partial_tls_pattern_suffix_len(&self.search_buffer);

                            // Only discard if suffix is shorter than buffer
                            // This means we have definite non-pattern bytes at the start
                            if suffix_len < self.search_buffer.len() {
                                let prefix_len = self.search_buffer.len() - suffix_len;
                                let prefix = self.search_buffer.split_to(prefix_len).freeze();
                                self.total_prefix_bytes += prefix.len();

                                log::debug!(
                                    "FuzzyTlsDeframer: Returning {} byte UnknownPrefix (total {} bytes discarded, kept {} suffix bytes)",
                                    prefix.len(),
                                    self.total_prefix_bytes,
                                    suffix_len
                                );

                                return Ok(DeframeResult::UnknownPrefix(prefix));
                            }
                        }
                    }

                    // Either:
                    // - Buffer too small (< 6 bytes) - need more data to check for complete pattern
                    // - Buffer >= 6, no complete pattern, entire buffer might be partial pattern
                    // Need more data in all cases
                    return Ok(DeframeResult::NeedData);
                }
                FuzzyState::Deframing => {
                    // Already in deframing mode, delegate to inner
                    match self.inner.next_record()? {
                        Some(record) => return Ok(DeframeResult::TlsRecord(record)),
                        None => return Ok(DeframeResult::NeedData),
                    }
                }
            }
        }
    }

    /// Get the number of bytes currently buffered
    pub fn pending_bytes(&self) -> usize {
        match self.state {
            FuzzyState::Searching => self.search_buffer.len(),
            FuzzyState::Deframing => self.inner.pending_bytes(),
        }
    }

    /// Get a reference to remaining buffered data
    pub fn remaining_data(&self) -> &[u8] {
        match self.state {
            FuzzyState::Searching => &self.search_buffer,
            FuzzyState::Deframing => self.inner.remaining_data(),
        }
    }

    /// Clear all buffered data and reset to searching state
    pub fn clear(&mut self) {
        self.search_buffer.clear();
        self.inner.clear();
        self.state = FuzzyState::Searching;
        self.total_prefix_bytes = 0;
    }

    /// Deallocate buffers
    pub fn deallocate(&mut self) {
        self.search_buffer = BytesMut::new();
        self.inner.deallocate();
    }
}

impl Default for FuzzyTlsDeframer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a TLS record with given content type and payload
    /// For Handshake records (0x16), prepends handshake type to payload
    fn make_tls_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut record = Vec::new();
        record.push(content_type);
        record.push(0x03); // Version major
        record.push(0x03); // Version minor

        // For Handshake records, prepend handshake type (0x01 = ClientHello)
        if content_type == 0x16 {
            let total_len = 1 + payload.len(); // handshake type byte + payload
            record.extend_from_slice(&(total_len as u16).to_be_bytes());
            record.push(0x01); // ClientHello handshake type
            record.extend_from_slice(payload);
        } else {
            let len = payload.len() as u16;
            record.extend_from_slice(&len.to_be_bytes());
            record.extend_from_slice(payload);
        }

        record
    }

    #[test]
    fn test_no_prefix_complete_record() {
        let mut deframer = FuzzyTlsDeframer::new();

        // TLS record with no prefix
        let record = make_tls_record(0x16, b"Hello");
        deframer.feed(&record);

        // Should immediately transition to Deframing and return the record
        match deframer.next_record().unwrap() {
            DeframeResult::TlsRecord(r) => assert_eq!(r, &record[..]),
            other => panic!("Expected TlsRecord, got {:?}", other),
        }
    }

    #[test]
    fn test_prefix_then_complete_record() {
        let mut deframer = FuzzyTlsDeframer::new();

        // VLESS-like prefix (26 bytes of zeros) + TLS record
        let mut data = vec![0x00; 26];
        let record = make_tls_record(0x16, b"Hello");
        data.extend_from_slice(&record);

        deframer.feed(&data);

        // First call should return the prefix
        match deframer.next_record().unwrap() {
            DeframeResult::UnknownPrefix(prefix) => assert_eq!(prefix.len(), 26),
            other => panic!("Expected UnknownPrefix, got {:?}", other),
        }

        // Second call should return the TLS record
        match deframer.next_record().unwrap() {
            DeframeResult::TlsRecord(r) => assert_eq!(r, &record[..]),
            other => panic!("Expected TlsRecord, got {:?}", other),
        }

        // Third call should return incomplete
        match deframer.next_record().unwrap() {
            DeframeResult::NeedData => {}
            other => panic!("Expected IncompleteRecord, got {:?}", other),
        }
    }

    #[test]
    fn test_small_prefix_not_returned_immediately() {
        let mut deframer = FuzzyTlsDeframer::new();

        // Small prefix (3 bytes) that doesn't match any partial pattern
        deframer.feed(&[0x00, 0x01, 0x02]);

        // Should wait for more data (buffer <= MAX_PARTIAL_SUFFIX_LEN)
        match deframer.next_record().unwrap() {
            DeframeResult::NeedData => {}
            other => panic!("Expected IncompleteRecord, got {:?}", other),
        }

        assert_eq!(deframer.pending_bytes(), 3);
    }

    #[test]
    fn test_large_prefix_returned_proactively() {
        let mut deframer = FuzzyTlsDeframer::new();

        // Large prefix (10 bytes) with no partial pattern at end
        deframer.feed(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]);

        // Should return prefix, keeping nothing (suffix_len = 0)
        match deframer.next_record().unwrap() {
            DeframeResult::UnknownPrefix(prefix) => assert_eq!(prefix.len(), 10),
            other => panic!("Expected UnknownPrefix, got {:?}", other),
        }

        assert_eq!(deframer.pending_bytes(), 0);
    }

    #[test]
    fn test_prefix_with_partial_pattern_suffix() {
        let mut deframer = FuzzyTlsDeframer::new();

        // 10 bytes of junk + partial TLS pattern [0x16, 0x03]
        deframer.feed(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x16, 0x03,
        ]);

        // Should return 10 bytes as prefix, keep [0x16, 0x03] as potential pattern
        match deframer.next_record().unwrap() {
            DeframeResult::UnknownPrefix(prefix) => assert_eq!(prefix.len(), 10),
            other => panic!("Expected UnknownPrefix, got {:?}", other),
        }

        assert_eq!(deframer.pending_bytes(), 2);

        // Now feed the rest of the pattern
        deframer.feed(&[0x01, 0x00, 0x05, 0x01, b'H', b'e', b'l', b'l', b'o']);

        // Should get the complete TLS record
        match deframer.next_record().unwrap() {
            DeframeResult::TlsRecord(r) => {
                assert_eq!(r[0], 0x16); // Handshake
                assert_eq!(r.len(), 5 + 5); // header + payload
            }
            other => panic!("Expected TlsRecord, got {:?}", other),
        }
    }

    #[test]
    fn test_partial_pattern_alone_not_discarded() {
        let mut deframer = FuzzyTlsDeframer::new();

        // Just a partial pattern [0x16, 0x03]
        deframer.feed(&[0x16, 0x03]);

        // Should wait for more data, not discard
        match deframer.next_record().unwrap() {
            DeframeResult::NeedData => {}
            other => panic!("Expected IncompleteRecord, got {:?}", other),
        }

        assert_eq!(deframer.pending_bytes(), 2);
    }

    #[test]
    fn test_multiple_records_after_prefix() {
        let mut deframer = FuzzyTlsDeframer::new();

        // Prefix + two TLS records
        let mut data = vec![0x00; 26];
        let record1 = make_tls_record(0x16, b"First");
        let record2 = make_tls_record(0x17, b"Second");
        data.extend_from_slice(&record1);
        data.extend_from_slice(&record2);

        deframer.feed(&data);

        // Get prefix
        match deframer.next_record().unwrap() {
            DeframeResult::UnknownPrefix(prefix) => assert_eq!(prefix.len(), 26),
            other => panic!("Expected UnknownPrefix, got {:?}", other),
        }

        // Get first record
        match deframer.next_record().unwrap() {
            DeframeResult::TlsRecord(r) => assert_eq!(r, &record1[..]),
            other => panic!("Expected TlsRecord, got {:?}", other),
        }

        // Get second record
        match deframer.next_record().unwrap() {
            DeframeResult::TlsRecord(r) => assert_eq!(r, &record2[..]),
            other => panic!("Expected TlsRecord, got {:?}", other),
        }

        // No more data
        match deframer.next_record().unwrap() {
            DeframeResult::NeedData => {}
            other => panic!("Expected IncompleteRecord, got {:?}", other),
        }
    }

    #[test]
    fn test_split_feed_across_pattern() {
        let mut deframer = FuzzyTlsDeframer::new();

        // Feed prefix + partial pattern in first call
        deframer.feed(&[0x00, 0x01, 0x02, 0x16, 0x03]);

        // Buffer too small, wait for more
        match deframer.next_record().unwrap() {
            DeframeResult::NeedData => {}
            other => panic!("Expected IncompleteRecord, got {:?}", other),
        }

        // Feed rest of pattern + record
        deframer.feed(&[0x01, 0x00, 0x05, 0x01, b'H', b'e', b'l', b'l', b'o']);

        // Now should get prefix
        match deframer.next_record().unwrap() {
            DeframeResult::UnknownPrefix(prefix) => assert_eq!(prefix.len(), 3),
            other => panic!("Expected UnknownPrefix, got {:?}", other),
        }

        // Then the record
        match deframer.next_record().unwrap() {
            DeframeResult::TlsRecord(_) => {}
            other => panic!("Expected TlsRecord, got {:?}", other),
        }
    }

    #[test]
    fn test_pending_bytes_accounting() {
        let mut deframer = FuzzyTlsDeframer::new();

        assert_eq!(deframer.pending_bytes(), 0);

        // Feed some data
        deframer.feed(&[0x00, 0x01, 0x02]);
        assert_eq!(deframer.pending_bytes(), 3);

        // Feed more to exceed threshold
        deframer.feed(&[0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(deframer.pending_bytes(), 9);

        // Extract prefix
        match deframer.next_record().unwrap() {
            DeframeResult::UnknownPrefix(prefix) => assert_eq!(prefix.len(), 9),
            _ => panic!("Expected UnknownPrefix"),
        }

        assert_eq!(deframer.pending_bytes(), 0);
    }

    #[test]
    fn test_pending_bytes_during_state_transition() {
        let mut deframer = FuzzyTlsDeframer::new();

        // Feed prefix + complete TLS record
        let mut data = vec![0x00; 26]; // VLESS prefix
        let record = make_tls_record(0x16, b"Test");
        data.extend_from_slice(&record);

        deframer.feed(&data);

        // Before extracting anything, pending_bytes should be full buffer
        assert_eq!(deframer.pending_bytes(), 26 + record.len());

        // Extract prefix (state transitions to Deframing, TLS data fed to inner)
        match deframer.next_record().unwrap() {
            DeframeResult::UnknownPrefix(prefix) => {
                assert_eq!(prefix.len(), 26);
            }
            other => panic!("Expected UnknownPrefix, got {:?}", other),
        }

        // After extracting prefix, pending_bytes should show TLS record length
        // (TLS data is now in inner deframer)
        assert_eq!(deframer.pending_bytes(), record.len());

        // Extract the TLS record
        match deframer.next_record().unwrap() {
            DeframeResult::TlsRecord(r) => assert_eq!(r.len(), record.len()),
            other => panic!("Expected TlsRecord, got {:?}", other),
        }

        // After extracting record, buffer should be empty
        assert_eq!(deframer.pending_bytes(), 0);
    }

    #[test]
    fn test_clear() {
        let mut deframer = FuzzyTlsDeframer::new();

        deframer.feed(&[0x00, 0x01, 0x02]);
        assert_eq!(deframer.pending_bytes(), 3);

        deframer.clear();
        assert_eq!(deframer.pending_bytes(), 0);
        assert_eq!(deframer.state, FuzzyState::Searching);
    }

    #[test]
    fn test_false_tls_pattern_continues_search() {
        let mut deframer = FuzzyTlsDeframer::new();

        // Data with [0x16, 0x03] but not a valid TLS pattern (wrong minor version)
        // Pattern needs: [0x16, 0x03, 0x01-0x03, ?, ?, 0x01|0x02]
        let data = vec![0x00, 0x01, 0x16, 0x03, 0x04, 0x00, 0x00, 0x01]; // 0x04 is invalid minor version

        deframer.feed(&data);

        // Should return as prefix since pattern search fails
        match deframer.next_record().unwrap() {
            DeframeResult::UnknownPrefix(prefix) => assert_eq!(prefix.len(), 8),
            other => panic!("Expected UnknownPrefix, got {:?}", other),
        }

        assert_eq!(deframer.state, FuzzyState::Searching);
    }
}
