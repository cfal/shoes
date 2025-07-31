/// Read slices similar to std::io::Cursor with byteorder extension
pub struct BufReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> BufReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn is_consumed(&self) -> bool {
        self.pos == self.buf.len()
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn read_u8(&mut self) -> std::io::Result<u8> {
        if self.pos >= self.buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Read past end of buffer",
            ));
        }
        let value = self.buf[self.pos];
        self.pos += 1;
        Ok(value)
    }

    pub fn read_u16_be(&mut self) -> std::io::Result<u16> {
        if self.pos + 1 >= self.buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Read past end of buffer",
            ));
        }
        let value = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(value)
    }

    pub fn read_u24_be(&mut self) -> std::io::Result<u32> {
        if self.pos + 2 >= self.buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Read past end of buffer",
            ));
        }
        let value = u32::from_be_bytes([
            0,
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
        ]);
        self.pos += 3;
        Ok(value)
    }

    pub fn read_slice(&mut self, len: usize) -> std::io::Result<&[u8]> {
        if self.pos + len > self.buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Read past end of buffer",
            ));
        }
        let slice = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    pub fn read_str(&mut self, len: usize) -> std::io::Result<&str> {
        let slice = self.read_slice(len)?;
        std::str::from_utf8(slice).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid UTF-8 sequence: {e}"),
            )
        })
    }

    pub fn skip(&mut self, amount: usize) -> std::io::Result<()> {
        if self.pos + amount > self.buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Read past end of buffer",
            ));
        }
        self.pos += amount;
        Ok(())
    }
}
