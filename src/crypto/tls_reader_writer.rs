use std::io::{self, BufRead, IoSlice, Read, Write};

pub struct TlsReader<'a> {
    inner: Option<rustls::Reader<'a>>,
    failed: Option<io::ErrorKind>,
}

impl<'a> TlsReader<'a> {
    pub(super) fn new(inner: Option<rustls::Reader<'a>>, failed: Option<io::ErrorKind>) -> Self {
        Self { inner, failed }
    }
}

impl Read for TlsReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner
            .as_mut()
            .ok_or(self.failed.unwrap_or(io::ErrorKind::WouldBlock))?
            .read(buffer)
    }
}

impl BufRead for TlsReader<'_> {
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

pub struct TlsWriter<'a> {
    inner: Option<rustls::Writer<'a>>,
    failed: Option<io::ErrorKind>,
    vectored: bool,
}

impl<'a> TlsWriter<'a> {
    pub(super) fn new(
        inner: Option<rustls::Writer<'a>>,
        failed: Option<io::ErrorKind>,
        vectored: bool,
    ) -> Self {
        Self {
            inner,
            failed,
            vectored,
        }
    }
}

impl Write for TlsWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.inner
            .as_mut()
            .ok_or(self.failed.unwrap_or(io::ErrorKind::WouldBlock))?
            .write(buffer)
    }

    fn write_vectored(&mut self, buffers: &[IoSlice<'_>]) -> io::Result<usize> {
        // Preserve REALITY's first-nonempty-buffer contract under backpressure.
        if !self.vectored {
            let first = buffers.iter().find(|buffer| !buffer.is_empty());
            return self.write(first.map_or(&[], |buffer| buffer));
        }
        self.inner
            .as_mut()
            .ok_or(self.failed.unwrap_or(io::ErrorKind::WouldBlock))?
            .write_vectored(buffers)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(kind) = self.failed {
            return Err(kind.into());
        }
        self.inner.as_mut().map_or(Ok(()), Write::flush)
    }
}
