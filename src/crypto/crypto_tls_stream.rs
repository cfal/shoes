// CryptoTlsStream: Async wrapper around Connection enum
//
// This provides AsyncRead + AsyncWrite for the Connection enum,
// allowing it to work with tokio-based async code.
//
// Based on VisionStream's TLS mode logic (non-padded), which itself
// is adapted from tokio-rustls.

use std::io::{self, BufRead, Write};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::crypto_connection::CryptoConnection;
use crate::async_stream::{AsyncPing, AsyncStream};
use crate::sync_adapter::{SyncReadAdapter, SyncWriteAdapter};

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

/// Async stream wrapper for Connection enum
///
/// This combines a Connection (rustls or REALITY) with an async I/O stream,
/// providing AsyncRead + AsyncWrite interface.
pub struct CryptoTlsStream<IO> {
    /// The underlying async I/O stream (e.g., TcpStream)
    io: IO,
    /// The crypto connection (rustls or REALITY)
    session: CryptoConnection,
    /// Connection state machine for tracking shutdown
    state: TlsState,
    /// Whether a flush is pending (tokio-rustls pattern)
    need_flush: bool,
}

impl<IO> CryptoTlsStream<IO>
where
    IO: AsyncStream,
{
    /// Create a new CryptoTlsStream
    pub fn new(io: IO, session: CryptoConnection) -> Self {
        CryptoTlsStream {
            io,
            session,
            state: TlsState::Stream,
            need_flush: false,
        }
    }

    /// Extract the underlying I/O stream and crypto session
    ///
    /// This consumes the CryptoTlsStream and returns its components.
    /// Useful for scenarios like Vision that need direct access to both.
    pub fn into_inner(self) -> (IO, CryptoConnection) {
        (self.io, self.session)
    }

    /// Write TLS data directly to the underlying stream
    ///
    /// Returns Poll::Ready(Ok(n)) with bytes written, or Poll::Pending if would block.
    fn write_tls_direct(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut adapter = SyncWriteAdapter {
            io: &mut self.io,
            cx,
        };
        match self.session.write_tls(&mut adapter) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    /// Drain all pending TLS writes to the underlying stream
    ///
    /// Note: This is used for best-effort draining (e.g., sending alerts on error).
    /// WriteZero is not treated as fatal here since the caller may want to continue
    /// even if some writes fail.
    fn drain_all_writes(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.session.wants_write() {
            match self.write_tls_direct(cx) {
                Poll::Ready(Ok(0)) => {
                    // WriteZero - can't make progress, but not fatal for drain
                    break;
                }
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Complete handshake if needed
    fn complete_handshake_if_needed(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.session.is_handshaking() {
            // Write any pending TLS data
            match self.drain_all_writes(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }

            // Read more data for handshake
            let mut adapter = SyncReadAdapter {
                io: &mut self.io,
                cx,
            };
            match self.session.read_tls(&mut adapter) {
                Ok(0) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "EOF during handshake",
                    )));
                }
                Ok(_) => {
                    // Process the data
                    self.session.process_new_packets()?;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return Poll::Pending;
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl<IO> AsyncRead for CryptoTlsStream<IO>
where
    IO: AsyncStream,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // If read side is shut down, return EOF immediately
        if !this.state.readable() {
            return Poll::Ready(Ok(()));
        }

        // Complete handshake first if needed
        if this.session.is_handshaking() {
            match this.complete_handshake_if_needed(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Track whether we did any I/O that returned Pending
        let mut io_pending = false;
        let mut eof = false;

        // Read from TCP while the session wants more data (tokio-rustls pattern)
        while this.state.readable() && this.session.wants_read() {
            let mut adapter = SyncReadAdapter {
                io: &mut this.io,
                cx,
            };
            match this.session.read_tls(&mut adapter) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(_) => {
                    // Process encrypted data - try to send alerts on error
                    if let Err(e) = this.session.process_new_packets() {
                        // Try last-gasp write to send any pending TLS alerts (tokio-rustls pattern)
                        let _ = this.drain_all_writes(cx);
                        return Poll::Ready(Err(e));
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    io_pending = true;
                    break;
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        // Try to get decrypted data from session buffer
        let mut reader = this.session.reader();
        match reader.fill_buf() {
            Ok(available) if !available.is_empty() => {
                // Copy directly from session buffer to user buffer
                let len = buf.remaining().min(available.len());
                buf.put_slice(&available[..len]);
                reader.consume(len);
                Poll::Ready(Ok(()))
            }
            Ok(_) => {
                // Empty buffer - check various conditions
                if eof {
                    // Mark read side as shut down
                    this.state.shutdown_read();
                    Poll::Ready(Ok(()))
                } else if io_pending {
                    Poll::Pending
                } else {
                    // Edge case: wants_read() returned false but no data available.
                    // Wake ourselves to retry (tokio-rustls pattern to prevent hangs).
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if !io_pending {
                    // If wants_read() is satisfied, rustls will not return WouldBlock.
                    // But if it does, we can try again. Wake ourselves to prevent hang.
                    // Tokio's cooperative budget will prevent infinite wakeup.
                    cx.waker().wake_by_ref();
                }
                Poll::Pending
            }
            Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                // Connection aborted - mark read side as shut down
                this.state.shutdown_read();
                Poll::Ready(Err(e))
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl<IO> AsyncWrite for CryptoTlsStream<IO>
where
    IO: AsyncStream,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Check if write side is shut down
        if !self.state.writeable() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write side is shut down",
            )));
        }

        // Complete handshake first if needed
        if self.session.is_handshaking() {
            match self.complete_handshake_if_needed(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let mut pos = 0;

        while pos < buf.len() {
            let mut would_block = false;

            // Write plaintext to session
            match self.session.writer().write(&buf[pos..]) {
                Ok(n) => pos += n,
                Err(e) => return Poll::Ready(Err(e)),
            };

            // Drain TLS output to TCP stream
            while self.session.wants_write() {
                match self.write_tls_direct(cx) {
                    Poll::Ready(Ok(0)) => {
                        // WriteZero: underlying socket can't accept data
                        return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                    }
                    Poll::Pending => {
                        would_block = true;
                        self.need_flush = true; // Mark that we have pending data
                        break;
                    }
                    Poll::Ready(Ok(_)) => {
                        self.need_flush = true; // Mark that we wrote something
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }

            return match (pos, would_block) {
                (0, true) => Poll::Pending,
                (n, true) => Poll::Ready(Ok(n)), // Partial write
                (_, false) => continue,          // Keep writing
            };
        }

        Poll::Ready(Ok(pos))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flush the session writer first (tokio-rustls pattern)
        // This ensures any buffered plaintext is moved to the TLS output buffer
        self.session.writer().flush()?;

        // Drain all pending TLS writes
        while self.session.wants_write() {
            match self.write_tls_direct(cx) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(_)) => {
                    self.need_flush = true;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Flush underlying stream if we have pending data
        if self.need_flush {
            match Pin::new(&mut self.io).poll_flush(cx) {
                Poll::Ready(Ok(())) => {
                    self.need_flush = false;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // 1. First drain any pending application data (before sending close_notify)
        //    This is important because REALITY's write_tls() does lazy encryption -
        //    plaintext is encrypted when write_tls() is called, not when written to
        //    the session. If we send close_notify first, it would be queued before
        //    the application data gets encrypted, resulting in wrong wire order.
        while self.session.wants_write() {
            match self.write_tls_direct(cx) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // 2. Send close_notify once (when write side is still open)
        if self.state.writeable() {
            self.session.send_close_notify();
            self.state.shutdown_write();
        }

        // 3. Drain the close_notify alert
        while self.session.wants_write() {
            match self.write_tls_direct(cx) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // 4. Shutdown underlying stream - ignore NotConnected errors (tokio-rustls pattern)
        match Pin::new(&mut self.io).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::NotConnected => {
                // When trying to shutdown, not being connected is fine
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<IO> AsyncPing for CryptoTlsStream<IO>
where
    IO: AsyncStream,
{
    fn supports_ping(&self) -> bool {
        self.io.supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.io).poll_write_ping(cx)
    }
}

// Implement AsyncStream blanket trait
impl<IO> crate::async_stream::AsyncStream for CryptoTlsStream<IO> where IO: AsyncStream {}
