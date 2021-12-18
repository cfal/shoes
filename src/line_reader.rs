use memchr::memchr;
use tokio::io::AsyncReadExt;

use crate::async_stream::AsyncStream;
use crate::util::allocate_vec;

const BUFFER_SIZE: usize = 32768;

pub struct LineReader {
    buf: Box<[u8]>,
    start_offset: usize,
    end_offset: usize,
}

impl LineReader {
    pub fn new() -> Self {
        Self {
            buf: allocate_vec(BUFFER_SIZE).into_boxed_slice(),
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

    pub async fn read_line_bytes(
        &mut self,
        stream: &mut Box<dyn AsyncStream>,
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
                    // There are no more newlines. Clear the offset so there's space
                    // for the next line.
                    self.reset_buf_offset();
                    self.read(stream).await?;
                }
            }
        }
    }

    pub async fn read_line(&mut self, stream: &mut Box<dyn AsyncStream>) -> std::io::Result<&str> {
        let line_bytes = self.read_line_bytes(stream).await?;
        std::str::from_utf8(line_bytes).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to decode utf8: {}", e),
            )
        })
    }

    pub fn unparsed_data(&self) -> &[u8] {
        &self.buf[self.start_offset..self.end_offset]
    }

    async fn read(&mut self, stream: &mut Box<dyn AsyncStream>) -> std::io::Result<()> {
        // Note that read() needs to work for blocking I/O. So we need to return
        // immediately after a single read() call.
        if self.is_cache_full() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "cache is full",
            ));
        }

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
                    if self.end_offset == BUFFER_SIZE {
                        // We did reset_buf_offset before the read, so checking
                        // end_offset is enough to know that cache is full.
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionAborted,
                            "cache is full",
                        ));
                    } else {
                        return Ok(());
                    }
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
        self.start_offset == 0 && self.end_offset == BUFFER_SIZE
    }
}
