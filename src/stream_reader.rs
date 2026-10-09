use memchr::memchr;
use tokio::io::AsyncReadExt;

use crate::util::allocate_vec;

const DEFAULT_BUFFER_SIZE: usize = 32768;
const ERROR_ON_BARE_LF: bool = true;

pub struct StreamReader {
    buf: Box<[u8]>,
    start_offset: usize,
    end_offset: usize,
}

impl StreamReader {
    pub fn new() -> Self {
        Self::new_with_buffer_size(DEFAULT_BUFFER_SIZE)
    }

    pub fn new_with_buffer_size(buffer_size: usize) -> Self {
        // The buffer_size also determines the maximum line length that can be read.
        Self {
            buf: allocate_vec(buffer_size).into_boxed_slice(),
            start_offset: 0usize,
            end_offset: 0usize,
        }
    }

    fn reset_buf_offset(&mut self) {
        if self.start_offset == 0 {
            return;
        }
        self.buf.copy_within(self.start_offset..self.end_offset, 0);
        self.end_offset -= self.start_offset;
        self.start_offset = 0;
    }

    pub async fn read_line_bytes<T: AsyncReadExt + Unpin>(
        &mut self,
        stream: &mut T,
    ) -> std::io::Result<&mut [u8]> {
        let mut search_start_offset = self.start_offset;
        loop {
            let search_end_offset = self.end_offset;
            match memchr(b'\n', &self.buf[search_start_offset..search_end_offset]) {
                Some(pos) => {
                    let newline_pos = search_start_offset + pos;
                    if newline_pos == self.start_offset || self.buf[newline_pos - 1] != b'\r' {
                        if ERROR_ON_BARE_LF {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "Line is not terminated by CRLF",
                            ));
                        } else {
                            search_start_offset = newline_pos + 1;
                            continue;
                        }
                    }
                    // Strips CRLF.
                    let line = &mut self.buf[self.start_offset..newline_pos - 1];
                    let new_start_offset = newline_pos + 1;
                    if new_start_offset == search_end_offset {
                        self.start_offset = 0;
                        self.end_offset = 0;
                    } else {
                        self.start_offset = new_start_offset;
                    }
                    return Ok(line);
                }
                None => {
                    // There are no more newlines.
                    let previous_start_offset = self.start_offset;

                    self.read(stream).await?;

                    // Only searches through new data.
                    if previous_start_offset != self.start_offset {
                        // Can only move to zero when reset_buf_offset is called.
                        assert!(self.start_offset == 0);
                        search_start_offset = search_end_offset - previous_start_offset;
                    } else {
                        search_start_offset = search_end_offset;
                    }
                }
            }
        }
    }

    pub async fn read_line<T: AsyncReadExt + Unpin>(
        &mut self,
        stream: &mut T,
    ) -> std::io::Result<&str> {
        let line_bytes = self.read_line_bytes(stream).await?;
        std::str::from_utf8(line_bytes).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to decode utf8: {e}"),
            )
        })
    }

    pub async fn read_u8<T: AsyncReadExt + Unpin>(
        &mut self,
        stream: &mut T,
    ) -> std::io::Result<u8> {
        while self.end_offset - self.start_offset < 1 {
            self.read(stream).await?;
        }
        let value = self.buf[self.start_offset];
        let new_start_offset = self.start_offset + 1;
        if new_start_offset == self.end_offset {
            self.start_offset = 0;
            self.end_offset = 0;
        } else {
            self.start_offset = new_start_offset;
        }
        Ok(value)
    }

    /// Peek at the first byte without consuming it.
    /// Ensures at least 1 byte is buffered, then returns it.
    pub async fn peek_u8<T: AsyncReadExt + Unpin>(
        &mut self,
        stream: &mut T,
    ) -> std::io::Result<u8> {
        while self.end_offset - self.start_offset < 1 {
            self.read(stream).await?;
        }
        // Returns the byte without advancing start_offset.
        Ok(self.buf[self.start_offset])
    }

    /// Peek at the first `len` bytes without consuming them.
    /// Ensures at least `len` bytes are buffered, then returns a reference to them.
    pub async fn peek_slice<T: AsyncReadExt + Unpin + ?Sized>(
        &mut self,
        stream: &mut T,
        len: usize,
    ) -> std::io::Result<&[u8]> {
        if len > self.buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Requested length {} exceeds buffer size {}",
                    len,
                    self.buf.len()
                ),
            ));
        }
        while self.end_offset - self.start_offset < len {
            self.read(stream).await?;
        }
        // Returns the slice without advancing start_offset.
        Ok(&self.buf[self.start_offset..self.start_offset + len])
    }

    /// Consume (skip) `len` bytes that were previously peeked.
    /// This advances the read position without returning any data.
    pub fn consume(&mut self, len: usize) {
        let new_start_offset = self.start_offset + len;
        debug_assert!(new_start_offset <= self.end_offset);
        if new_start_offset == self.end_offset {
            self.start_offset = 0;
            self.end_offset = 0;
        } else {
            self.start_offset = new_start_offset;
        }
    }

    pub async fn read_u16_be<T: AsyncReadExt + Unpin>(
        &mut self,
        stream: &mut T,
    ) -> std::io::Result<u16> {
        while self.end_offset - self.start_offset < 2 {
            self.read(stream).await?;
        }
        let value =
            u16::from_be_bytes([self.buf[self.start_offset], self.buf[self.start_offset + 1]]);
        let new_start_offset = self.start_offset + 2;
        if new_start_offset == self.end_offset {
            self.start_offset = 0;
            self.end_offset = 0;
        } else {
            self.start_offset = new_start_offset;
        }
        Ok(value)
    }

    pub async fn read_slice<T: AsyncReadExt + Unpin + ?Sized>(
        &mut self,
        stream: &mut T,
        len: usize,
    ) -> std::io::Result<&[u8]> {
        if len > self.buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Requested length {} exceeds buffer size {}",
                    len,
                    self.buf.len()
                ),
            ));
        }
        while self.end_offset - self.start_offset < len {
            self.read(stream).await?;
        }
        let slice = &self.buf[self.start_offset..self.start_offset + len];
        let new_start_offset = self.start_offset + len;
        if new_start_offset == self.end_offset {
            self.start_offset = 0;
            self.end_offset = 0;
        } else {
            self.start_offset = new_start_offset;
        }
        Ok(slice)
    }

    pub async fn read_slice_into<T: AsyncReadExt + Unpin>(
        &mut self,
        stream: &mut T,
        buf: &mut [u8],
    ) -> std::io::Result<()> {
        let slice = self.read_slice(stream, buf.len()).await?;
        buf.copy_from_slice(slice);
        Ok(())
    }

    pub fn unparsed_data(&self) -> &[u8] {
        &self.buf[self.start_offset..self.end_offset]
    }

    pub fn unparsed_data_owned(&self) -> Option<Box<[u8]>> {
        let unparsed_data = self.unparsed_data();
        if unparsed_data.is_empty() {
            None
        } else {
            Some(unparsed_data.to_vec().into_boxed_slice())
        }
    }

    async fn read<T: AsyncReadExt + Unpin + ?Sized>(
        &mut self,
        stream: &mut T,
    ) -> std::io::Result<()> {
        // Returns immediately after a single read() call to support blocking I/O.
        if self.is_cache_full() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "cache is full",
            ));
        }

        // Clears the offset to make space for the next read.
        self.reset_buf_offset();

        loop {
            match stream.read(&mut self.buf[self.end_offset..]).await {
                Ok(len) => {
                    if len == 0 {
                        // EOF
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionAborted,
                            "EOF while reading",
                        ));
                    }
                    self.end_offset += len;
                    return Ok(());
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }

    fn is_cache_full(&self) -> bool {
        self.start_offset == 0 && self.end_offset == self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};

    #[tokio::test]
    async fn split_crlf_preserves_following_lines_and_payload() {
        let (mut writer, mut stream) = tokio::io::duplex(64);
        let mut reader = StreamReader::new_with_buffer_size(32);
        writer.write_all(b"first\r").await.unwrap();
        let mut line = Box::pin(reader.read_line(&mut stream));
        assert!(futures::poll!(&mut line).is_pending());
        drop(line);
        writer.write_all(b"\nsecond\r\npayload").await.unwrap();
        assert_eq!(reader.read_line(&mut stream).await.unwrap(), "first");
        assert_eq!(reader.read_line(&mut stream).await.unwrap(), "second");
        assert_eq!(reader.unparsed_data(), b"payload");
    }

    #[tokio::test]
    async fn cancelled_line_read_preserves_compacted_input() {
        let (mut writer, mut stream) = tokio::io::duplex(16);
        let mut reader = StreamReader::new_with_buffer_size(8);
        writer.write_all(b"ab\r\ncdef").await.unwrap();
        assert_eq!(reader.read_line(&mut stream).await.unwrap(), "ab");
        assert_eq!(reader.start_offset, 4);

        let mut line = Box::pin(reader.read_line(&mut stream));
        assert!(futures::poll!(&mut line).is_pending());
        drop(line);
        assert_eq!(reader.start_offset, 0);
        assert_eq!(reader.unparsed_data(), b"cdef");

        writer.write_all(b"\r\n!").await.unwrap();
        assert_eq!(reader.read_line(&mut stream).await.unwrap(), "cdef");
        assert_eq!(reader.unparsed_data(), b"!");
        assert_eq!(reader.read_u8(&mut stream).await.unwrap(), b'!');
        assert!(reader.unparsed_data_owned().is_none());
    }

    #[tokio::test]
    async fn peek_consume_and_owned_snapshots_preserve_offsets() {
        let mut stream = &b"\x01\x02\x03ABtail"[..];
        let mut reader = StreamReader::new_with_buffer_size(16);
        for _ in 0..2 {
            assert_eq!(reader.peek_u8(&mut stream).await.unwrap(), 1);
            assert_eq!(reader.peek_slice(&mut stream, 3).await.unwrap(), [1, 2, 3]);
        }
        reader.consume(1);
        assert_eq!(reader.read_u16_be(&mut stream).await.unwrap(), 0x0203);
        assert_eq!(reader.read_slice(&mut stream, 2).await.unwrap(), b"AB");
        let snapshot = reader.unparsed_data_owned().unwrap();
        let mut tail = [0; 4];
        reader
            .read_slice_into(&mut stream, &mut tail)
            .await
            .unwrap();
        assert_eq!(&tail, b"tail");
        assert_eq!(&*snapshot, b"tail");
        assert!(reader.unparsed_data().is_empty());
        assert!(reader.unparsed_data_owned().is_none());
        assert!(reader.peek_slice(&mut stream, 0).await.unwrap().is_empty());
        assert!(reader.read_slice(&mut stream, 0).await.unwrap().is_empty());
        assert_eq!(
            reader.read_u8(&mut stream).await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
    }

    #[tokio::test]
    async fn bounded_lines_and_slices_report_exact_error_kinds() {
        let mut reader = StreamReader::new_with_buffer_size(8);
        assert_eq!(
            reader.read_line(&mut &b"123456\r\n"[..]).await.unwrap(),
            "123456"
        );
        for (input, kind) in [
            (&b"12345678"[..], io::ErrorKind::ConnectionAborted),
            (&b"1234567\r\n"[..], io::ErrorKind::ConnectionAborted),
            (&b"untermin"[..], io::ErrorKind::ConnectionAborted),
            (&b"abc"[..], io::ErrorKind::ConnectionAborted),
            (&b"abc\n"[..], io::ErrorKind::InvalidData),
            (&b"\n"[..], io::ErrorKind::InvalidData),
            (&b"\xff\r\n"[..], io::ErrorKind::InvalidData),
        ] {
            let mut reader = StreamReader::new_with_buffer_size(8);
            let mut stream = input;
            assert_eq!(
                reader.read_line(&mut stream).await.unwrap_err().kind(),
                kind,
                "input: {input:?}"
            );
        }
        let mut reader = StreamReader::new_with_buffer_size(4);
        let mut input = &b"test"[..];
        assert_eq!(
            reader.peek_slice(&mut input, 5).await.unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            reader.read_slice(&mut input, 5).await.unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(input, b"test");
        assert_eq!(reader.read_slice(&mut input, 4).await.unwrap(), b"test");
        let mut reader = StreamReader::new_with_buffer_size(4);
        assert_eq!(
            reader.read_line_bytes(&mut &b"\xff\r\n"[..]).await.unwrap(),
            [255]
        );
        assert_eq!(reader.read_line(&mut &b"\r\n"[..]).await.unwrap(), "");
    }

    struct FailingRead {
        error: Option<io::ErrorKind>,
        remaining: &'static [u8],
    }

    impl AsyncRead for FailingRead {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(error) = self.error.take() {
                return Poll::Ready(Err(error.into()));
            }
            Pin::new(&mut self.remaining).poll_read(cx, buf)
        }
    }

    #[tokio::test]
    async fn interrupted_reads_retry_and_other_errors_propagate() {
        for kind in [io::ErrorKind::Interrupted, io::ErrorKind::ConnectionReset] {
            let mut reader = StreamReader::new();
            let mut stream = FailingRead {
                error: Some(kind),
                remaining: b"line\r\n",
            };
            if kind != io::ErrorKind::Interrupted {
                assert_eq!(
                    reader.read_line(&mut stream).await.unwrap_err().kind(),
                    kind
                );
            }
            assert_eq!(reader.read_line(&mut stream).await.unwrap(), "line");
        }
    }
}
