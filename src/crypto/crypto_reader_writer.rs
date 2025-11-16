// Reader and Writer types for crypto connections
//
// These types provide a consistent API for reading decrypted plaintext
// and writing plaintext to be encrypted, working with both rustls and REALITY.

use std::io::{self, BufRead, Read, Write};

use crate::reality::{RealityReader, RealityWriter};

/// Unified reader that works with both Rustls and REALITY connections
pub enum CryptoReader<'a> {
    Rustls(rustls::Reader<'a>),
    Reality(RealityReader<'a>),
}

impl<'a> Read for CryptoReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            CryptoReader::Rustls(reader) => reader.read(buf),
            CryptoReader::Reality(reader) => reader.read(buf),
        }
    }
}

impl<'a> BufRead for CryptoReader<'a> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self {
            CryptoReader::Rustls(reader) => reader.fill_buf(),
            CryptoReader::Reality(reader) => reader.fill_buf(),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            CryptoReader::Rustls(reader) => reader.consume(amt),
            CryptoReader::Reality(reader) => reader.consume(amt),
        }
    }
}

/// Unified writer that works with both Rustls and REALITY connections
pub enum CryptoWriter<'a> {
    Rustls(rustls::Writer<'a>),
    Reality(RealityWriter<'a>),
}

impl<'a> Write for CryptoWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            CryptoWriter::Rustls(writer) => writer.write(buf),
            CryptoWriter::Reality(writer) => writer.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            CryptoWriter::Rustls(writer) => writer.flush(),
            CryptoWriter::Reality(writer) => writer.flush(),
        }
    }
}
