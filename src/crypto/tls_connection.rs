use std::io::{self, Read, Write};

use bytes::Bytes;

use super::tls_reader_writer::{TlsReader, TlsWriter};

/// A rustls connection with REALITY plaintext gating and staged-output handling.
#[derive(Debug)]
pub struct TlsConnection {
    inner: Option<rustls::Connection>,
    server: bool,
    reality: bool,
    prefix: Bytes,
    failed: Option<io::ErrorKind>,
}

impl TlsConnection {
    pub fn new(connection: impl Into<rustls::Connection>) -> Self {
        let connection = connection.into();
        Self {
            server: matches!(connection, rustls::Connection::Server(_)),
            inner: Some(connection),
            reality: false,
            prefix: Bytes::new(),
            failed: None,
        }
    }

    pub(crate) fn new_reality(connection: impl Into<rustls::Connection>) -> Self {
        let mut connection = Self::new(connection);
        connection.reality = true;
        connection
    }

    pub(crate) fn set_staged_output(&mut self, wire: Bytes) {
        self.prefix = wire;
    }

    pub fn is_server(&self) -> bool {
        self.server
    }

    pub fn is_client(&self) -> bool {
        !self.server
    }

    pub fn is_reality(&self) -> bool {
        self.reality
    }

    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        if self.reality {
            None
        } else {
            self.inner.as_ref()?.alpn_protocol()
        }
    }

    pub fn negotiated_group(&self) -> Option<rustls::NamedGroup> {
        self.inner
            .as_ref()?
            .negotiated_key_exchange_group()
            .map(|group| group.name())
    }

    pub fn read_tls(&mut self, reader: &mut dyn Read) -> io::Result<usize> {
        self.inner
            .as_mut()
            .ok_or(self.failed.unwrap_or(io::ErrorKind::WouldBlock))?
            .read_tls(reader)
    }

    pub fn process_new_packets(&mut self) -> io::Result<usize> {
        let connection = self
            .inner
            .as_mut()
            .ok_or(self.failed.unwrap_or(io::ErrorKind::WouldBlock))?;
        match connection.process_new_packets() {
            Ok(state) => Ok(state.plaintext_bytes_to_read()),
            Err(error) if self.reality => {
                let error = tls_error(error);
                self.failed = Some(error.kind());
                // A failed REALITY connection must expose neither plaintext nor queued alerts.
                self.inner = None;
                self.prefix = Bytes::new();
                Err(error)
            }
            Err(error) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "rustls {} error processing new packets: {:?}",
                    if self.server { "server" } else { "client" },
                    error
                ),
            )),
        }
    }

    pub fn feed(&mut self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            if self.read_tls(&mut data)? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TLS input made no progress",
                ));
            }
            self.process_new_packets()?;
        }
        Ok(())
    }

    pub fn write_tls(&mut self, writer: &mut dyn Write) -> io::Result<usize> {
        if !self.prefix.is_empty() {
            let written = writer.write(&self.prefix)?;
            let _ = self.prefix.split_to(written);
            return Ok(written);
        }
        self.inner
            .as_mut()
            .map_or(Ok(0), |connection| connection.write_tls(writer))
    }

    pub fn reader(&mut self) -> TlsReader<'_> {
        let connection = self
            .inner
            .as_mut()
            .filter(|connection| !self.reality || !connection.is_handshaking());
        TlsReader::new(
            connection.map(|connection| connection.reader()),
            self.failed,
        )
    }

    pub fn writer(&mut self) -> TlsWriter<'_> {
        let connection = self
            .inner
            .as_mut()
            .filter(|connection| !self.reality || !connection.is_handshaking());
        TlsWriter::new(
            connection.map(|connection| connection.writer()),
            self.failed,
            !self.reality,
        )
    }

    pub fn wants_write(&self) -> bool {
        !self.prefix.is_empty()
            || self
                .inner
                .as_ref()
                .is_some_and(|connection| connection.wants_write())
    }

    pub fn wants_read(&self) -> bool {
        self.inner
            .as_ref()
            .is_some_and(|connection| connection.wants_read())
    }

    pub fn is_handshaking(&self) -> bool {
        self.inner
            .as_ref()
            .is_none_or(|connection| connection.is_handshaking())
    }

    pub fn send_close_notify(&mut self) {
        if let Some(connection) = &mut self.inner {
            connection.send_close_notify();
        }
    }

    #[cfg(test)]
    pub fn refresh_traffic_keys(&mut self) -> io::Result<()> {
        self.inner
            .as_mut()
            .ok_or(io::ErrorKind::NotConnected)?
            .refresh_traffic_keys()
            .map_err(tls_error)
    }
}

pub(crate) fn tls_error(error: rustls::Error) -> io::Error {
    let kind = match &error {
        rustls::Error::InvalidCertificate(_) => io::ErrorKind::PermissionDenied,
        rustls::Error::PeerIncompatible(rustls::PeerIncompatible::RealityUnsupported) => {
            io::ErrorKind::Unsupported
        }
        rustls::Error::FailedToGetCurrentTime
        | rustls::Error::FailedToGetRandomBytes
        | rustls::Error::General(_) => io::ErrorKind::Other,
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn client() -> rustls::ClientConnection {
        let config =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();
        rustls::ClientConnection::new(Arc::new(config), "cover.test".try_into().unwrap()).unwrap()
    }

    #[test]
    fn only_reality_blocks_plaintext_until_authenticated() {
        for reality in [false, true] {
            let mut connection = if reality {
                TlsConnection::new_reality(client())
            } else {
                TlsConnection::new(client())
            };
            assert!(connection.is_client());
            assert!(!connection.is_server());
            assert_eq!(connection.is_reality(), reality);
            assert!(connection.is_handshaking());
            let result = connection.writer().write(b"pending");
            if reality {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
            } else {
                assert_eq!(result.unwrap(), 7);
            }
        }
        let (client, server) = crate::reality::established_pair();
        assert!(client.is_client() && server.is_server());
        assert!(client.is_reality() && server.is_reality());
        assert!(client.alpn_protocol().is_none() && server.alpn_protocol().is_none());
    }

    #[test]
    fn reality_failure_discards_output_but_ordinary_tls_keeps_alerts() {
        for reality in [false, true] {
            let mut connection = if reality {
                let mut connection = TlsConnection::new_reality(client());
                connection.set_staged_output(Bytes::from_static(b"staged"));
                connection
            } else {
                TlsConnection::new(client())
            };
            let error = connection.feed(&[23, 3, 3, 0, 1, 0]).unwrap_err();
            let mut output = Vec::new();
            while connection.wants_write() {
                assert!(connection.write_tls(&mut output).unwrap() > 0);
            }
            if reality {
                assert!(output.is_empty());
                assert!(!connection.wants_read());
                assert_eq!(
                    connection.process_new_packets().unwrap_err().kind(),
                    error.kind()
                );
                assert_eq!(
                    connection.read_tls(&mut io::empty()).unwrap_err().kind(),
                    error.kind()
                );
                assert_eq!(
                    connection.reader().read(&mut [0]).unwrap_err().kind(),
                    error.kind()
                );
                assert_eq!(
                    connection.writer().write(b"forbidden").unwrap_err().kind(),
                    error.kind()
                );
                assert!(connection.is_handshaking() && connection.is_client());
            } else {
                let mut records = crate::crypto::tls_deframer::TlsDeframer::new();
                records.feed(&output);
                assert!(
                    records
                        .next_records()
                        .unwrap()
                        .iter()
                        .any(|record| record[0] == 21)
                );
            }
        }
    }

    #[test]
    fn staged_prefix_drains_before_queued_rustls_records() {
        let mut connection = TlsConnection::new_reality(client());
        connection.set_staged_output(Bytes::from_static(&[1, 2, 3]));
        let mut first = [0; 2];
        assert_eq!(connection.write_tls(&mut first.as_mut_slice()).unwrap(), 2);
        assert_eq!(first, [1, 2]);
        let mut rest = Vec::new();
        assert_eq!(connection.write_tls(&mut rest).unwrap(), 1);
        assert_eq!(rest, [3]);
        assert!(connection.wants_write());
        rest.clear();
        assert!(connection.write_tls(&mut rest).unwrap() > 0);
        assert_eq!(rest[0], 22);
    }
}
