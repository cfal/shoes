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
use crate::sync_adapter::{SyncReadAdapter, SyncWriteAdapter};

/// Async stream wrapper for Connection enum
///
/// This combines a Connection (rustls or REALITY) with an async I/O stream,
/// providing AsyncRead + AsyncWrite interface.
pub struct CryptoTlsStream<IO> {
    /// The underlying async I/O stream (e.g., TcpStream)
    io: IO,
    /// The crypto connection (rustls or REALITY)
    session: CryptoConnection,
    /// Whether we've hit EOF when reading
    is_read_eof: bool,
}

impl<IO> CryptoTlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Create a new CryptoTlsStream
    pub fn new(io: IO, session: CryptoConnection) -> Self {
        CryptoTlsStream {
            io,
            session,
            is_read_eof: false,
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
    fn drain_all_writes(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.session.wants_write() {
            match self.write_tls_direct(cx) {
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
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Check if session already has decrypted data available
        {
            let mut reader = this.session.reader();
            match reader.fill_buf() {
                Ok(available) if !available.is_empty() => {
                    // Copy directly from session buffer to user buffer
                    let len = buf.remaining().min(available.len());
                    buf.put_slice(&available[..len]);
                    reader.consume(len);
                    return Poll::Ready(Ok(()));
                }
                Ok(_) => {
                    // Empty buffer, need to read more
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // No data available yet
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        if this.is_read_eof {
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

        // No data in session buffer, read from TCP and decrypt
        // Split borrows manually to avoid borrow checker issues

        loop {
            let bytes_read = {
                let mut adapter = SyncReadAdapter {
                    io: &mut this.io,
                    cx,
                };
                match this.session.read_tls(&mut adapter) {
                    Ok(n) => n,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        return Poll::Pending;
                    }
                    Err(e) => return Poll::Ready(Err(e)),
                }
            };

            if bytes_read == 0 {
                // EOF
                this.is_read_eof = true;
                return Poll::Ready(Ok(()));
            }

            // Process encrypted data - try to send alerts on error
            let io_state = match this.session.process_new_packets() {
                Ok(state) => state,
                Err(e) => {
                    // Try last-gasp write to send any pending TLS alerts (tokio-rustls pattern)
                    // Make best-effort attempt to drain all pending writes without blocking.
                    // This increases the chance that the peer receives an alert explaining
                    // the protocol error. We ignore write failures to ensure the primary
                    // TLS protocol error (e) is always returned.
                    while this.session.wants_write() {
                        let mut adapter = SyncWriteAdapter {
                            io: &mut this.io,
                            cx,
                        };
                        match this.session.write_tls(&mut adapter) {
                            Ok(_) => {} // Continue draining
                            Err(ref write_err) if write_err.kind() == io::ErrorKind::WouldBlock => {
                                break
                            }
                            Err(_) => break, // Give up on write error
                        }
                    }
                    return Poll::Ready(Err(e));
                }
            };

            if io_state.plaintext_bytes_to_read() == 0 {
                // No plaintext yet, need more data
                continue;
            }

            // Extract plaintext from session
            let mut reader = this.session.reader();
            match reader.fill_buf() {
                Ok(available) => {
                    if available.is_empty() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "Read zero bytes when plaintext is available",
                        )));
                    }
                    let len = buf.remaining().min(available.len());
                    buf.put_slice(&available[..len]);
                    reader.consume(len);
                    return Poll::Ready(Ok(()));
                }
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }
        }
    }
}

impl<IO> AsyncWrite for CryptoTlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
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
                    Poll::Ready(Ok(0)) | Poll::Pending => {
                        would_block = true;
                        break;
                    }
                    Poll::Ready(Ok(_)) => (),
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
        // Drain all pending TLS writes
        match self.drain_all_writes(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        // Flush underlying stream
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Send close notification
        self.session.send_close_notify();

        // Drain all pending writes
        match self.drain_all_writes(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        // Shutdown underlying stream - ignore NotConnected errors (tokio-rustls pattern)
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

// Implement AsyncPing for CryptoTlsStream
impl<IO> crate::async_stream::AsyncPing for CryptoTlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn supports_ping(&self) -> bool {
        false // TLS doesn't have a built-in ping mechanism
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

// Implement AsyncStream blanket trait
impl<IO> crate::async_stream::AsyncStream for CryptoTlsStream<IO> where
    IO: AsyncRead + AsyncWrite + Unpin + Send
{
}
