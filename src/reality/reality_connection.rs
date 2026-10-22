use std::io::{self, Read, Write};

use super::reality_io_state::RealityIoState;
#[cfg(test)]
use super::reality_key_exchange::RealityGroup;
use super::reality_reader_writer::{RealityReader, RealityWriter};
#[cfg(test)]
use super::reality_rustls::group;
use super::reality_rustls::io_error;

#[derive(Default)]
pub(super) struct RealityTransport {
    pub(super) inner: Option<rustls::Connection>,
    pub(super) prefix: bytes::Bytes,
    failed: Option<io::ErrorKind>,
}

impl RealityTransport {
    pub(super) fn new(mut connection: rustls::Connection) -> Self {
        connection.set_buffer_limit(Some(super::common::OUTGOING_BUFFER_LIMIT));
        Self {
            inner: Some(connection),
            prefix: bytes::Bytes::new(),
            failed: None,
        }
    }

    pub(super) fn read_tls(&mut self, rd: &mut dyn Read) -> io::Result<usize> {
        if let Some(kind) = self.failed {
            return Err(kind.into());
        }
        self.inner
            .as_mut()
            .ok_or(io::ErrorKind::WouldBlock)?
            .read_tls(rd)
    }

    pub(super) fn process_new_packets(&mut self) -> io::Result<RealityIoState> {
        if let Some(kind) = self.failed {
            return Err(kind.into());
        }
        let Some(connection) = &mut self.inner else {
            return Ok(RealityIoState::new(0));
        };
        match connection.process_new_packets() {
            Ok(state) => Ok(RealityIoState::new(state.plaintext_bytes_to_read())),
            Err(error) => {
                let error = io_error(error);
                self.failed = Some(error.kind());
                // Never expose queued plaintext or a TLS alert after failed REALITY authentication.
                self.inner = None;
                self.prefix = bytes::Bytes::new();
                Err(error)
            }
        }
    }

    pub(super) fn feed(&mut self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            if self.read_tls(&mut data)? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "REALITY TLS input made no progress",
                ));
            }
            self.process_new_packets()?;
        }
        Ok(())
    }

    pub(super) fn write_tls(&mut self, wr: &mut dyn Write) -> io::Result<usize> {
        if !self.prefix.is_empty() {
            let written = wr.write(&self.prefix)?;
            let _ = self.prefix.split_to(written);
            return Ok(written);
        }
        self.inner
            .as_mut()
            .map_or(Ok(0), |connection| connection.write_tls(wr))
    }

    pub(super) fn reader(&mut self) -> RealityReader<'_> {
        let available = self
            .inner
            .as_mut()
            .filter(|connection| !connection.is_handshaking());
        RealityReader::new(available.map(|connection| connection.reader()), self.failed)
    }

    pub(super) fn writer(&mut self) -> RealityWriter<'_> {
        let available = self
            .inner
            .as_mut()
            .filter(|connection| !connection.is_handshaking());
        RealityWriter::new(available.map(|connection| connection.writer()), self.failed)
    }

    pub(super) fn wants_write(&self) -> bool {
        !self.prefix.is_empty()
            || self
                .inner
                .as_ref()
                .is_some_and(|connection| connection.wants_write())
    }
    pub(super) fn wants_read(&self) -> bool {
        self.failed.is_none()
            && self
                .inner
                .as_ref()
                .is_none_or(|connection| connection.wants_read())
    }
    pub(super) fn is_handshaking(&self) -> bool {
        self.inner
            .as_ref()
            .is_none_or(|connection| connection.is_handshaking())
    }
    #[cfg(test)]
    pub(super) fn negotiated_group(&self) -> Option<RealityGroup> {
        self.inner
            .as_ref()?
            .negotiated_key_exchange_group()
            .and_then(|kx| group(kx.name()))
    }
    pub(super) fn send_close_notify(&mut self) {
        if let Some(connection) = &mut self.inner {
            connection.send_close_notify();
        }
    }

    #[cfg(test)]
    pub(super) fn refresh_traffic_keys(&mut self) -> io::Result<()> {
        self.inner
            .as_mut()
            .ok_or(io::ErrorKind::NotConnected)?
            .refresh_traffic_keys()
            .map_err(io_error)
    }
}

macro_rules! delegate_tls {
    () => {
        pub fn read_tls(&mut self, reader: &mut dyn std::io::Read) -> std::io::Result<usize> {
            self.transport.read_tls(reader)
        }
        pub fn write_tls(&mut self, writer: &mut dyn std::io::Write) -> std::io::Result<usize> {
            self.transport.write_tls(writer)
        }
        pub fn process_new_packets(
            &mut self,
        ) -> std::io::Result<super::reality_io_state::RealityIoState> {
            self.transport.process_new_packets()
        }
        pub fn reader(&mut self) -> super::reality_reader_writer::RealityReader<'_> {
            self.transport.reader()
        }
        pub fn writer(&mut self) -> super::reality_reader_writer::RealityWriter<'_> {
            self.transport.writer()
        }
        pub fn wants_write(&self) -> bool {
            self.transport.wants_write()
        }
        pub fn wants_read(&self) -> bool {
            self.transport.wants_read()
        }
        pub fn is_handshaking(&self) -> bool {
            self.transport.is_handshaking()
        }
        #[cfg(test)]
        pub fn negotiated_group(&self) -> Option<super::reality_key_exchange::RealityGroup> {
            self.transport.negotiated_group()
        }
        pub fn send_close_notify(&mut self) {
            self.transport.send_close_notify();
        }
    };
}
pub(super) use delegate_tls;
