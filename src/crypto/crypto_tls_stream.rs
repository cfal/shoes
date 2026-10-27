//! Owns TLS input, handshake state, and output across protocol transitions.

use bytes::{Buf, Bytes};
use futures::ready;
use std::io::{self, BufRead, Write};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::TlsConnection;
use super::tls_deframer::TlsDeframer;
use crate::async_stream::{AsyncPing, AsyncStream};
use crate::sync_adapter::{SyncReadAdapter, SyncWriteAdapter};

/// Select before any handshake input reaches the crypto backend.
#[derive(Clone, Copy)]
pub enum TlsReadMode {
    Stream,
    PreserveRecords,
}

enum TlsInput {
    Stream,
    Records {
        deframer: TlsDeframer,
        preserve: bool,
    },
    Raw(Bytes),
}

/// TLS connection state machine (mirrors tokio-rustls TlsState)
///
/// Tracks read and write shutdown states independently to handle
/// half-closed connections correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsState {
    /// Normal operation - both read and write are open
    Stream,
    /// Read side has been shut down (received close_notify or EOF)
    ReadShutdown,
    /// Write side has been shut down (sent close_notify)
    WriteShutdown,
    /// Both sides have been shut down
    FullyShutdown,
}

impl TlsState {
    /// Transition to read shutdown state
    #[inline]
    pub fn shutdown_read(&mut self) {
        *self = match *self {
            Self::WriteShutdown | Self::FullyShutdown => Self::FullyShutdown,
            _ => Self::ReadShutdown,
        };
    }

    /// Transition to write shutdown state
    #[inline]
    pub fn shutdown_write(&mut self) {
        *self = match *self {
            Self::ReadShutdown | Self::FullyShutdown => Self::FullyShutdown,
            _ => Self::WriteShutdown,
        };
    }

    /// Check if the connection is readable
    #[inline]
    pub fn readable(&self) -> bool {
        !matches!(*self, Self::ReadShutdown | Self::FullyShutdown)
    }

    /// Check if the connection is writeable
    #[inline]
    pub fn writeable(&self) -> bool {
        !matches!(*self, Self::WriteShutdown | Self::FullyShutdown)
    }
}

pub struct CryptoTlsStream<IO> {
    io: IO,
    pub(super) session: TlsConnection,
    state: TlsState,
    need_flush: bool,
    input: TlsInput,
    write_raw: bool,
    raw_write_prefix: Option<Bytes>,
}

impl<IO: AsyncStream> CryptoTlsStream<IO> {
    pub async fn handshake(
        io: IO,
        session: TlsConnection,
        mode: TlsReadMode,
        preread: &[u8],
    ) -> io::Result<Self> {
        let preserve = matches!(mode, TlsReadMode::PreserveRecords);
        let input = if preserve || !preread.is_empty() {
            let mut deframer = TlsDeframer::new();
            deframer.feed(preread);
            TlsInput::Records { deframer, preserve }
        } else {
            TlsInput::Stream
        };
        let mut stream = Self::with_input(io, session, input);
        super::crypto_handshake::perform_crypto_handshake(&mut stream).await?;
        Ok(stream)
    }

    fn with_input(io: IO, session: TlsConnection, input: TlsInput) -> Self {
        Self {
            io,
            session,
            state: TlsState::Stream,
            need_flush: false,
            input,
            write_raw: false,
            raw_write_prefix: None,
        }
    }

    #[cfg(test)]
    pub fn new(io: IO, session: TlsConnection, deframer: Option<TlsDeframer>) -> Self {
        assert!(!session.is_handshaking());
        let input = match deframer {
            Some(deframer) => TlsInput::Records {
                deframer,
                preserve: true,
            },
            None => TlsInput::Stream,
        };
        Self::with_input(io, session, input)
    }

    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.session.alpn_protocol()
    }

    pub fn negotiated_group(&self) -> Option<rustls::NamedGroup> {
        self.session.negotiated_group()
    }

    pub fn is_reality(&self) -> bool {
        self.session.is_reality()
    }

    pub fn is_server(&self) -> bool {
        self.session.is_server()
    }

    pub fn is_client(&self) -> bool {
        self.session.is_client()
    }

    pub fn require_record_framing(&self) -> io::Result<()> {
        match self.input {
            TlsInput::Records { preserve: true, .. } => Ok(()),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Vision requires record-preserving TLS input from handshake start",
            )),
        }
    }

    /// Once handoff is ruled out, drain seeded records without reading ahead, then
    /// return to allocation-free backend reads at the next buffered boundary.
    pub fn allow_streaming_reads(&mut self) {
        if let TlsInput::Records { preserve, .. } = &mut self.input {
            *preserve = false;
        }
        self.release_empty_deframer();
    }

    fn release_empty_deframer(&mut self) {
        if matches!(&self.input, TlsInput::Records { deframer, preserve: false }
            if deframer.pending_bytes() == 0)
        {
            self.input = TlsInput::Stream;
        }
    }

    fn take_plaintext(&mut self) -> io::Result<Vec<u8>> {
        let mut plaintext = Vec::new();
        let mut reader = self.session.reader();
        loop {
            match reader.fill_buf() {
                Ok([]) => break,
                Ok(bytes) => {
                    plaintext.extend_from_slice(bytes);
                    let len = bytes.len();
                    reader.consume(len);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        Ok(plaintext)
    }

    /// Session plaintext precedes the opaque transport tail, even if DIRECT was
    /// parsed from a small caller buffer in the middle of a decrypted record.
    pub fn start_raw_read(&mut self) -> io::Result<()> {
        self.require_record_framing()?;
        let mut pending = self.take_plaintext()?;
        let TlsInput::Records { deframer, .. } =
            std::mem::replace(&mut self.input, TlsInput::Stream)
        else {
            unreachable!()
        };
        pending.extend_from_slice(&deframer.into_remaining_data());
        self.input = TlsInput::Raw(pending.into());
        Ok(())
    }

    pub fn start_raw_write(&mut self, mut final_plaintext: &[u8]) -> io::Result<()> {
        if self.write_raw {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS output has already switched to raw mode",
            ));
        }

        // Freeze the final TLS flight before reads can queue alerts or KeyUpdate
        // responses. Reads remain independent while this prefix drains and flushes.
        let mut prefix = Vec::new();
        loop {
            while self.session.wants_write() {
                if self.session.write_tls(&mut prefix)? == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
            }
            if final_plaintext.is_empty() {
                break;
            }
            let written = self.session.writer().write(final_plaintext)?;
            if written == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            final_plaintext = &final_plaintext[written..];
            self.session.writer().flush()?;
        }
        self.raw_write_prefix = Some(prefix.into());
        self.write_raw = true;
        Ok(())
    }

    pub(super) fn poll_receive_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let n = match &mut self.input {
            TlsInput::Stream => {
                let mut adapter = SyncReadAdapter {
                    io: &mut self.io,
                    cx,
                };
                match self.session.read_tls(&mut adapter) {
                    Ok(n) => n,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        return Poll::Pending;
                    }
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
            TlsInput::Records { deframer, preserve } => {
                let mut scratch = [0; 4096];
                let record =
                    ready!(deframer.poll_read_record(&mut self.io, cx, &mut scratch, *preserve))?;
                self.release_empty_deframer();
                match record {
                    Some(record) => {
                        self.session
                            .feed(&record)
                            .map_err(|error| self.packet_error(error))?;
                        record.len()
                    }
                    // rustls must see physical EOF to report missing close_notify.
                    None => self.session.read_tls(&mut io::empty())?,
                }
            }
            TlsInput::Raw(_) => unreachable!("raw input bypasses TLS"),
        };
        if n != 0 {
            let plaintext_len = self
                .session
                .process_new_packets()
                .map_err(|error| self.packet_error(error))?;
            log::trace!("TLS received {n} bytes, {plaintext_len} plaintext bytes available");
        }
        Poll::Ready(Ok(n))
    }

    fn packet_error(&self, error: io::Error) -> io::Error {
        if !self.session.is_reality() {
            return error;
        }
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "reality {} error processing new packets: {:?}",
                if self.session.is_server() {
                    "server"
                } else {
                    "client"
                },
                error
            ),
        )
    }

    fn poll_write_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut adapter = SyncWriteAdapter {
            io: &mut self.io,
            cx,
        };
        match self.session.write_tls(&mut adapter) {
            Ok(n) => {
                self.need_flush |= n != 0;
                Poll::Ready(Ok(n))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    pub fn poll_drain_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The peer no longer accepts TLS records once this direction is raw.
        if let Some(prefix) = &mut self.raw_write_prefix {
            while !prefix.is_empty() {
                let written = ready!(Pin::new(&mut self.io).poll_write(cx, prefix))?;
                if written == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                prefix.advance(written);
                self.need_flush = true;
            }
        } else if !self.write_raw {
            while self.session.wants_write() {
                if ready!(self.poll_write_tls(cx))? == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<IO: AsyncStream> AsyncRead for CryptoTlsStream<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 || !this.state.readable() {
            return Poll::Ready(Ok(()));
        }
        if let TlsInput::Raw(pending) = &mut this.input {
            if !pending.is_empty() {
                let len = buf.remaining().min(pending.len());
                buf.put_slice(&pending[..len]);
                pending.advance(len);
                return Poll::Ready(Ok(()));
            }
            return Pin::new(&mut this.io).poll_read(cx, buf);
        }

        loop {
            // Deliver plaintext before consuming another outer record. DIRECT may
            // be in these bytes, with opaque data immediately after that record.
            let mut reader = this.session.reader();
            match reader.fill_buf() {
                Ok(available) if !available.is_empty() => {
                    let len = buf.remaining().min(available.len());
                    buf.put_slice(&available[..len]);
                    reader.consume(len);
                    return Poll::Ready(Ok(()));
                }
                Ok(_) => {
                    this.state.shutdown_read();
                    return Poll::Ready(Ok(()));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Poll::Ready(Err(error)),
            }
            // Service post-handshake responses without blocking readable plaintext
            // on output backpressure. Both I/O directions register their wakers.
            if let Poll::Ready(Err(error)) = Pin::new(&mut *this).poll_flush(cx) {
                return Poll::Ready(Err(error));
            }
            if let Err(error) = ready!(this.poll_receive_tls(cx)) {
                let _ = this.poll_drain_tls(cx);
                return Poll::Ready(Err(error));
            }
        }
    }
}

impl<IO: AsyncStream> AsyncWrite for CryptoTlsStream<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.state.writeable() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write side is shut down",
            )));
        }
        if self.write_raw {
            if self.raw_write_prefix.is_some() {
                ready!(self.as_mut().poll_flush(cx))?;
            }
            return Pin::new(&mut self.io).poll_write(cx, buf);
        }

        let mut pos = 0;
        while pos < buf.len() {
            pos += self.session.writer().write(&buf[pos..])?;
            match self.poll_drain_tls(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending if pos == 0 => return Poll::Pending,
                Poll::Pending => return Poll::Ready(Ok(pos)),
            }
        }
        Poll::Ready(Ok(pos))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if !self.state.writeable() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write side is shut down",
            )));
        }
        if self.write_raw {
            if self.raw_write_prefix.is_some() {
                ready!(self.as_mut().poll_flush(cx))?;
            }
            return Pin::new(&mut self.io).poll_write_vectored(cx, bufs);
        }
        if bufs.iter().all(|buf| buf.is_empty()) {
            return Poll::Ready(Ok(0));
        }

        loop {
            let written = self.session.writer().write_vectored(bufs)?;
            let pending = match self.poll_drain_tls(cx) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => false,
                Poll::Pending => true,
            };
            if written > 0 {
                return Poll::Ready(Ok(written));
            }
            if pending {
                return Poll::Pending;
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        if self.write_raw {
            self.io.is_write_vectored()
        } else {
            !self.session.is_reality()
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_raw {
            ready!(self.poll_drain_tls(cx))?;
            ready!(Pin::new(&mut self.io).poll_flush(cx))?;
            self.raw_write_prefix = None;
            self.need_flush = false;
            return Poll::Ready(Ok(()));
        }
        self.session.writer().flush()?;
        ready!(self.poll_drain_tls(cx))?;
        if self.need_flush {
            ready!(Pin::new(&mut self.io).poll_flush(cx))?;
            self.need_flush = false;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.write_raw {
            if self.state.writeable() {
                self.session.send_close_notify();
                self.state.shutdown_write();
            }
            // A failed ordinary TLS session still has output to send before writer.flush fails.
            ready!(self.poll_drain_tls(cx))?;
            ready!(self.as_mut().poll_flush(cx))?;
        } else {
            ready!(self.as_mut().poll_flush(cx))?;
            self.state.shutdown_write();
        }
        match Pin::new(&mut self.io).poll_shutdown(cx) {
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::NotConnected => {
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

impl<IO: AsyncStream> AsyncPing for CryptoTlsStream<IO> {
    fn supports_ping(&self) -> bool {
        self.io.supports_ping()
    }

    fn poll_write_ping(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let written = ready!(Pin::new(&mut self.io).poll_write_ping(cx))?;
        self.need_flush |= written;
        Poll::Ready(Ok(written))
    }
}

impl<IO: AsyncStream> AsyncStream for CryptoTlsStream<IO> {
    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.io.peer_addr()
    }
    #[cfg(target_os = "linux")]
    fn plain_tcp(&self) -> Option<&tokio::net::TcpStream> {
        if self.state != TlsState::Stream
            || !matches!(&self.input, TlsInput::Raw(pending) if pending.is_empty())
            || !self.write_raw
            || self.raw_write_prefix.is_some()
            || self.need_flush
        {
            return None;
        }
        self.io.plain_tcp()
    }
}

#[cfg(test)]
mod tests;
