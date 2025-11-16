//! Zero-allocation sliding buffer for streaming data
//!
//! This module provides a fixed-capacity sliding buffer optimized for
//! streaming protocols where data is written at one end and read from another.
//! Unlike a true ring buffer, this uses a linear layout with lazy compaction
//! via `copy_within()`, which is optimal for use cases requiring contiguous
//! slices (like TLS record processing).
//!
//! # Design Rationale
//!
//! A true ring buffer wraps around, but that creates non-contiguous data
//! regions which require either two-slice APIs or copies for consumers
//! expecting `&[u8]`. Since TLS encryption/decryption functions need
//! contiguous slices, this linear design with lazy compaction is more
//! efficient for our use case.

use std::io::{BufRead, Read};

/// A fixed-capacity sliding buffer with zero-allocation read/write operations.
///
/// This buffer maintains start and end offsets into a pre-allocated storage,
/// allowing efficient append and consume operations without allocating.
/// When the write end approaches capacity, `compact()` or `maybe_compact()`
/// can be used to move remaining data to the front using `copy_within()`.
///
/// # Example
/// ```ignore
/// let mut buf = SlideBuffer::new(1024);
/// buf.extend_from_slice(b"hello");
/// assert_eq!(buf.as_slice(), b"hello");
/// buf.consume(2);
/// assert_eq!(buf.as_slice(), b"llo");
/// ```
pub struct SlideBuffer {
    /// Pre-allocated buffer storage
    data: Box<[u8]>,
    /// Start offset of valid data (inclusive)
    start: usize,
    /// End offset of valid data (exclusive)
    end: usize,
}

impl SlideBuffer {
    /// Create a new slide buffer with the specified capacity.
    ///
    /// The buffer is allocated once and reused for all operations.
    #[inline]
    pub fn new(capacity: usize) -> Self {
        Self {
            data: vec![0u8; capacity].into_boxed_slice(),
            start: 0,
            end: 0,
        }
    }

    /// Returns the number of bytes currently stored in the buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Returns the remaining space available for writing.
    ///
    /// This is the space at the end of the buffer. To reclaim space
    /// consumed from the front, call `compact()`.
    #[inline]
    pub fn remaining_capacity(&self) -> usize {
        self.data.len() - self.end
    }

    /// Get a slice of the readable data.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.data[self.start..self.end]
    }

    /// Get a mutable slice for writing new data at the end.
    ///
    /// Returns the writable portion at the end of the buffer.
    /// After writing, call `advance_write(n)` to mark bytes as written.
    ///
    /// # Example
    /// ```ignore
    /// let mut buf = SlideBuffer::new(1024);
    /// let write_buf = buf.write_slice();
    /// write_buf[..5].copy_from_slice(b"hello");
    /// buf.advance_write(5);
    /// ```
    #[inline]
    pub fn write_slice(&mut self) -> &mut [u8] {
        &mut self.data[self.end..]
    }

    /// Extend the buffer with data from a slice.
    ///
    /// # Panics
    /// Panics in debug mode if there isn't enough capacity.
    #[inline]
    pub fn extend_from_slice(&mut self, data: &[u8]) {
        debug_assert!(
            self.remaining_capacity() >= data.len(),
            "SlideBuffer overflow: need {} bytes, have {}",
            data.len(),
            self.remaining_capacity()
        );
        let end = self.end;
        self.data[end..end + data.len()].copy_from_slice(data);
        self.end += data.len();
    }

    /// Mark n bytes as written (after writing to `write_slice()`).
    #[inline]
    pub fn advance_write(&mut self, n: usize) {
        debug_assert!(
            self.end + n <= self.data.len(),
            "SlideBuffer advance_write overflow: end={}, n={}, capacity={}",
            self.end,
            n,
            self.data.len()
        );
        self.end += n;
    }

    /// Consume n bytes from the front of the buffer.
    ///
    /// # Panics
    /// Panics in debug mode if n exceeds the available data.
    #[inline]
    pub fn consume(&mut self, n: usize) {
        debug_assert!(
            n <= self.len(),
            "SlideBuffer consume underflow: n={}, len={}",
            n,
            self.len()
        );
        self.start += n;

        // Reset offsets if buffer is now empty
        if self.start >= self.end {
            self.start = 0;
            self.end = 0;
        }
    }

    /// Compact the buffer by moving data to the front.
    ///
    /// This reclaims the space that was consumed from the front,
    /// making it available for writing at the end.
    /// Uses `copy_within()` which is optimized by the compiler.
    #[inline]
    pub fn compact(&mut self) {
        if self.start > 0 && self.start < self.end {
            self.data.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        } else if self.start >= self.end {
            self.start = 0;
            self.end = 0;
        }
    }

    /// Compact only if we've consumed more than the threshold.
    ///
    /// This amortizes the cost of compaction over many operations,
    /// avoiding unnecessary copies when little space would be reclaimed.
    #[inline]
    pub fn maybe_compact(&mut self, threshold: usize) {
        if self.start > threshold {
            self.compact();
        }
    }

    /// Returns a two-byte value at the given offset as big-endian u16.
    #[inline]
    pub fn get_u16_be(&self, offset: usize) -> Option<u16> {
        if offset + 2 <= self.len() {
            let idx = self.start + offset;
            Some(u16::from_be_bytes([self.data[idx], self.data[idx + 1]]))
        } else {
            None
        }
    }
}

impl Read for SlideBuffer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let available = self.len();
        if available == 0 {
            return Ok(0);
        }
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&self.data[self.start..self.start + to_read]);
        self.consume(to_read);
        Ok(to_read)
    }
}

impl BufRead for SlideBuffer {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        Ok(self.as_slice())
    }

    fn consume(&mut self, amt: usize) {
        SlideBuffer::consume(self, amt);
    }
}

// Implement indexing for convenient access
impl std::ops::Index<usize> for SlideBuffer {
    type Output = u8;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.data[self.start + index]
    }
}

impl std::ops::Index<std::ops::Range<usize>> for SlideBuffer {
    type Output = [u8];

    #[inline]
    fn index(&self, range: std::ops::Range<usize>) -> &Self::Output {
        &self.data[self.start + range.start..self.start + range.end]
    }
}

impl std::ops::Index<std::ops::RangeFrom<usize>> for SlideBuffer {
    type Output = [u8];

    #[inline]
    fn index(&self, range: std::ops::RangeFrom<usize>) -> &Self::Output {
        &self.data[self.start + range.start..self.end]
    }
}

impl std::ops::Index<std::ops::RangeTo<usize>> for SlideBuffer {
    type Output = [u8];

    #[inline]
    fn index(&self, range: std::ops::RangeTo<usize>) -> &Self::Output {
        &self.data[self.start..self.start + range.end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_buffer() {
        let buf = SlideBuffer::new(1024);
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.remaining_capacity(), 1024);
    }

    #[test]
    fn test_extend_from_slice() {
        let mut buf = SlideBuffer::new(1024);
        buf.extend_from_slice(b"hello");
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.as_slice(), b"hello");
        assert_eq!(buf.remaining_capacity(), 1024 - 5);
    }

    #[test]
    fn test_consume() {
        let mut buf = SlideBuffer::new(1024);
        buf.extend_from_slice(b"hello world");
        buf.consume(6);
        assert_eq!(buf.as_slice(), b"world");
        assert_eq!(buf.len(), 5);
    }

    #[test]
    fn test_consume_all_resets() {
        let mut buf = SlideBuffer::new(1024);
        buf.extend_from_slice(b"hello");
        buf.consume(5);
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.remaining_capacity(), 1024);
    }

    #[test]
    fn test_compact() {
        let mut buf = SlideBuffer::new(1024);
        buf.extend_from_slice(b"hello world");
        buf.consume(6);
        assert_eq!(buf.remaining_capacity(), 1024 - 11);

        buf.compact();
        assert_eq!(buf.as_slice(), b"world");
        assert_eq!(buf.remaining_capacity(), 1024 - 5);
    }

    #[test]
    fn test_maybe_compact() {
        let mut buf = SlideBuffer::new(1024);
        buf.extend_from_slice(b"0123456789"); // 10 bytes
        buf.consume(5);

        // Threshold not met
        buf.maybe_compact(10);
        assert_eq!(buf.remaining_capacity(), 1024 - 10);

        // Threshold met
        buf.maybe_compact(4);
        assert_eq!(buf.remaining_capacity(), 1024 - 5);
    }

    #[test]
    fn test_write_slice() {
        let mut buf = SlideBuffer::new(1024);
        let write_buf = buf.write_slice();
        write_buf[..5].copy_from_slice(b"hello");
        buf.advance_write(5);

        assert_eq!(buf.as_slice(), b"hello");
        assert_eq!(buf.len(), 5);
    }

    #[test]
    fn test_read_trait() {
        let mut buf = SlideBuffer::new(1024);
        buf.extend_from_slice(b"hello world");

        let mut output = [0u8; 5];
        let n = buf.read(&mut output).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&output, b"hello");

        let n = buf.read(&mut output).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&output, b" worl");

        let n = buf.read(&mut output).unwrap();
        assert_eq!(n, 1);
        assert_eq!(&output[..1], b"d");
    }

    #[test]
    fn test_bufread_trait() {
        let mut buf = SlideBuffer::new(1024);
        buf.extend_from_slice(b"hello world");

        {
            let slice = buf.fill_buf().unwrap();
            assert_eq!(slice, b"hello world");
        }

        buf.consume(6);

        {
            let slice = buf.fill_buf().unwrap();
            assert_eq!(slice, b"world");
        }
    }

    #[test]
    fn test_indexing() {
        let mut buf = SlideBuffer::new(1024);
        buf.extend_from_slice(b"hello world");

        assert_eq!(buf[0], b'h');
        assert_eq!(buf[6], b'w');
        assert_eq!(&buf[0..5], b"hello");
        assert_eq!(&buf[6..], b"world");
        assert_eq!(&buf[..5], b"hello");
    }

    #[test]
    fn test_indexing_after_consume() {
        let mut buf = SlideBuffer::new(1024);
        buf.extend_from_slice(b"hello world");
        buf.consume(6);

        assert_eq!(buf[0], b'w');
        assert_eq!(&buf[0..5], b"world");
    }

    #[test]
    fn test_get_u16_be() {
        let mut buf = SlideBuffer::new(1024);
        buf.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);

        assert_eq!(buf.get_u16_be(0), Some(0x1234));
        assert_eq!(buf.get_u16_be(2), Some(0x5678));
        assert_eq!(buf.get_u16_be(3), None);
    }

    #[test]
    fn test_multiple_extend_consume_cycles() {
        let mut buf = SlideBuffer::new(100);

        for i in 0..10 {
            buf.extend_from_slice(b"0123456789");
            assert_eq!(buf.len(), 10);
            buf.consume(10);
            assert_eq!(buf.len(), 0);
            assert_eq!(buf.remaining_capacity(), 100, "iteration {} failed", i);
        }
    }

    #[test]
    fn test_partial_consume_and_extend() {
        let mut buf = SlideBuffer::new(100);

        buf.extend_from_slice(b"hello world"); // 11 bytes
        buf.consume(6); // consume "hello "

        buf.extend_from_slice(b"!!!"); // add "!!!"
        assert_eq!(buf.as_slice(), b"world!!!");

        buf.compact();
        assert_eq!(buf.as_slice(), b"world!!!");
        assert_eq!(buf.remaining_capacity(), 100 - 8);
    }
}
