use std::io::{self, BufRead, Read, Write};

pub struct RealityReader<'a> {
    inner: Option<rustls::Reader<'a>>,
    failed: Option<io::ErrorKind>,
}

impl<'a> RealityReader<'a> {
    pub(super) fn new(inner: Option<rustls::Reader<'a>>, failed: Option<io::ErrorKind>) -> Self {
        Self { inner, failed }
    }
}

impl Read for RealityReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner
            .as_mut()
            .ok_or(self.failed.unwrap_or(io::ErrorKind::WouldBlock))?
            .read(buffer)
    }
}

impl BufRead for RealityReader<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.inner
            .as_mut()
            .ok_or(self.failed.unwrap_or(io::ErrorKind::WouldBlock))?
            .fill_buf()
    }

    fn consume(&mut self, amount: usize) {
        if let Some(reader) = &mut self.inner {
            reader.consume(amount);
        }
    }
}

pub struct RealityWriter<'a> {
    inner: Option<rustls::Writer<'a>>,
    failed: Option<io::ErrorKind>,
}

impl<'a> RealityWriter<'a> {
    pub(super) fn new(inner: Option<rustls::Writer<'a>>, failed: Option<io::ErrorKind>) -> Self {
        Self { inner, failed }
    }
}

impl Write for RealityWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.inner
            .as_mut()
            .ok_or(self.failed.unwrap_or(io::ErrorKind::WouldBlock))?
            .write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(kind) = self.failed {
            return Err(kind.into());
        }
        self.inner.as_mut().map_or(Ok(()), Write::flush)
    }
}
