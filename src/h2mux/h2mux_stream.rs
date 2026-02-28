//! H2MuxStream - Async stream wrapper for h2 send/recv streams
//!
//! Provides an AsyncRead/AsyncWrite interface over HTTP/2 streams.
//! Used by the server side where both send and recv streams are available immediately.
//! The client side uses H2MuxClientStream directly which handles lazy response resolution.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};

/// H2 stream for multiplexed connections (server side).
///
/// Wraps h2's SendStream and RecvStream to provide AsyncRead/AsyncWrite.
/// Used on the server side where both streams are available immediately.
pub struct H2MuxStream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    /// Buffered received data
    recv_buf: Bytes,
    /// Whether we've sent END_STREAM
    shutdown_sent: bool,
}

impl H2MuxStream {
    pub fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
        Self {
            send,
            recv,
            recv_buf: Bytes::new(),
            shutdown_sent: false,
        }
    }
}

impl AsyncRead for H2MuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Return buffered data first
        if !self.recv_buf.is_empty() {
            let to_copy = self.recv_buf.len().min(buf.remaining());
            buf.put_slice(&self.recv_buf[..to_copy]);
            self.recv_buf = self.recv_buf.slice(to_copy..);
            log::trace!("H2MuxStream: returning {} buffered bytes", to_copy);
            return Poll::Ready(Ok(()));
        }

        // Poll for more data
        match Pin::new(&mut self.recv).poll_data(cx) {
            Poll::Ready(Some(Ok(data))) => {
                // Release capacity so the sender can send more
                let len = data.len();
                let _ = self.recv.flow_control().release_capacity(len);

                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);

                if to_copy < data.len() {
                    self.recv_buf = data.slice(to_copy..);
                }

                log::trace!("H2MuxStream: poll_data returned {} bytes", len);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => {
                log::trace!("H2MuxStream: poll_data error: {}", e);
                Poll::Ready(Err(io::Error::other(format!("H2 recv error: {e}"))))
            }
            Poll::Ready(None) => {
                log::trace!("H2MuxStream: poll_data returned EOF");
                Poll::Ready(Ok(()))
            }
            Poll::Pending => {
                log::trace!("H2MuxStream: poll_data pending");
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for H2MuxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Reserve capacity if current capacity is insufficient for the write
        let current_capacity = self.send.capacity();
        if current_capacity < buf.len() {
            self.send.reserve_capacity(buf.len());
        }

        // Poll for capacity
        match self.send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) => {
                let to_send = buf.len().min(capacity);
                self.send
                    .send_data(Bytes::copy_from_slice(&buf[..to_send]), false)
                    .map_err(|e| io::Error::other(format!("H2 send_data failed: {e}")))?;
                Poll::Ready(Ok(to_send))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::other(format!(
                "H2 poll_capacity error: {e}"
            )))),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "H2 stream closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // h2 doesn't have a per-stream flush
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Send END_STREAM if we haven't already
        if !self.shutdown_sent {
            match self.send.send_data(Bytes::new(), true) {
                Ok(()) => self.shutdown_sent = true,
                Err(e) => {
                    return Poll::Ready(Err(io::Error::other(format!(
                        "H2 send END_STREAM failed: {e}"
                    ))));
                }
            }
        }

        // Check for immediate reset
        match self.send.poll_reset(cx) {
            Poll::Ready(Ok(_)) | Poll::Ready(Err(_)) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Ready(Ok(())),
        }
    }
}

impl AsyncPing for H2MuxStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl Unpin for H2MuxStream {}

impl AsyncStream for H2MuxStream {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_h2mux_stream_is_async_stream() {
        fn assert_async_stream<T: AsyncStream>() {}
        assert_async_stream::<H2MuxStream>();
    }

    #[test]
    fn test_h2mux_stream_is_unpin() {
        fn assert_unpin<T: Unpin>() {}
        assert_unpin::<H2MuxStream>();
    }

    #[test]
    fn test_h2mux_stream_is_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<H2MuxStream>();
        assert_sync::<H2MuxStream>();
    }
}
