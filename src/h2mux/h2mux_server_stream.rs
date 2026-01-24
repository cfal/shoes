//! H2MUX Server Stream
//!
//! Wraps H2MuxStream with sing-mux server protocol handling:
//! - Status response is prepended to first write (like sing-mux serverConn)

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};
use crate::util::write_all;

use super::h2mux_protocol::{StreamResponse, STATUS_SUCCESS};
use super::h2mux_stream::H2MuxStream;

/// Server stream wrapper that prepends status response to first write.
///
/// This matches sing-mux's serverConn behavior where the status byte
/// is sent with the first data write rather than immediately.
pub struct H2MuxServerStream {
    inner: H2MuxStream,
    /// Whether we've written the status response
    response_written: bool,
}

impl H2MuxServerStream {
    /// Create a new server stream wrapper.
    pub fn new(inner: H2MuxStream) -> Self {
        Self {
            inner,
            response_written: false,
        }
    }

    /// Get reference to inner stream.
    #[allow(dead_code)]
    pub fn inner_mut(&mut self) -> &mut H2MuxStream {
        &mut self.inner
    }

    /// Send an error response to the client before closing.
    ///
    /// This should be called when rejecting a stream (e.g., UDP disabled).
    /// After calling this, the stream should be shut down.
    /// Returns error if response was already written.
    pub async fn write_error_response(&mut self, message: &str) -> io::Result<()> {
        if self.response_written {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Response already written",
            ));
        }

        let response = StreamResponse::error(message);
        let encoded = response.encode();
        write_all(&mut self.inner, &encoded).await?;
        self.response_written = true;
        Ok(())
    }
}

impl AsyncRead for H2MuxServerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for H2MuxServerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // First write prepends the status response
        if !self.response_written {
            // Create combined buffer: status + data
            let mut combined = BytesMut::with_capacity(1 + buf.len());
            combined.put_u8(STATUS_SUCCESS);
            combined.put_slice(buf);

            match Pin::new(&mut self.inner).poll_write(cx, &combined) {
                Poll::Ready(Ok(written)) => {
                    self.response_written = true;
                    // Return amount of user data written (subtract status byte)
                    if written >= 1 {
                        Poll::Ready(Ok((written - 1).min(buf.len())))
                    } else {
                        Poll::Ready(Ok(0))
                    }
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncPing for H2MuxServerStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl Unpin for H2MuxServerStream {}

impl AsyncStream for H2MuxServerStream {}
