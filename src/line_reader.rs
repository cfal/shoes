use memchr::memchr;
use tokio::io::AsyncReadExt;

use crate::util::allocate_vec;

const DEFAULT_BUFFER_SIZE: usize = 32768;

pub struct LineReader {
    buf: Box<[u8]>,
    start_offset: usize,
    end_offset: usize,
}

impl LineReader {
    pub fn new() -> Self {
        Self::new_with_buffer_size(DEFAULT_BUFFER_SIZE)
    }

    pub fn new_with_buffer_size(buffer_size: usize) -> Self {
        // note that `buffer_size` also represents the maximum line length that can be read.
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
        mut stream: T,
    ) -> std::io::Result<&mut [u8]> {
        loop {
            match memchr(b'\n', &self.buf[self.start_offset..self.end_offset]) {
                Some(pos) => {
                    let newline_pos = self.start_offset + pos;
                    let line = if newline_pos > 0 && self.buf[newline_pos - 1] == b'\r' {
                        &mut self.buf[self.start_offset..newline_pos - 1]
                    } else {
                        &mut self.buf[self.start_offset..newline_pos]
                    };
                    let new_start_offset = newline_pos + 1;
                    if new_start_offset == self.end_offset {
                        self.start_offset = 0;
                        self.end_offset = 0;
                    } else {
                        self.start_offset = new_start_offset;
                    }
                    return Ok(line);
                }
                None => {
                    // There are no more newlines.
                    self.read(&mut stream).await?;
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
                format!("Failed to decode utf8: {}", e),
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

    pub async fn read_slice<T: AsyncReadExt + Unpin>(
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

    async fn read<T: AsyncReadExt + Unpin>(&mut self, stream: &mut T) -> std::io::Result<()> {
        // Note that read() needs to work for blocking I/O. So we need to return
        // immediately after a single read() call.
        if self.is_cache_full() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "cache is full",
            ));
        }

        // Clear the offset so there's space for the next line.
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
