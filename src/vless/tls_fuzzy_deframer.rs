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

use super::tls_handshake_util::{
    MIN_TLS_HANDSHAKE_PATTERN_LEN, find_potential_tls_suffix_len, find_tls_handshake_start,
};
use crate::crypto::tls_deframer::TlsDeframer;

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
                    if self.search_buffer.len() >= MIN_TLS_HANDSHAKE_PATTERN_LEN
                        && let Some(offset) = find_tls_handshake_start(&self.search_buffer)
                    {
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
                    }

                    // Check if we can discard some prefix bytes that definitely aren't TLS.
                    // This works for both small (<6) and large (>=6) buffers.
                    let suffix_len = find_potential_tls_suffix_len(&self.search_buffer);

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

                    // Buffer might be a valid TLS prefix, need more data
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

    /// Discards buffered bytes for resubmission without forgetting recognized TLS framing.
    pub fn discard_buffered(&mut self) {
        self.search_buffer.clear();
        self.inner.clear();
    }

    /// Clear all buffered data and reset to searching state
    pub fn clear(&mut self) {
        self.discard_buffered();
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
mod tests;
