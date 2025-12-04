//! H2MultiStream - H2 stream for multiplexed connections

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};

/// H2 stream for multiplexed connections.
/// The connection driver is managed by NaiveServerSession and stays alive
/// as long as any stream is active.
pub struct H2MultiStream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    /// Buffered received data
    recv_buf: Bytes,
    /// Whether we've sent END_STREAM
    shutdown_sent: bool,
}

impl H2MultiStream {
    pub fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
        Self {
            send,
            recv,
            recv_buf: Bytes::new(),
            shutdown_sent: false,
        }
    }
}

impl AsyncRead for H2MultiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.recv_buf.is_empty() {
            let to_copy = self.recv_buf.len().min(buf.remaining());
            buf.put_slice(&self.recv_buf[..to_copy]);
            self.recv_buf = self.recv_buf.slice(to_copy..);
            return Poll::Ready(Ok(()));
        }

        match Pin::new(&mut self.recv).poll_data(cx) {
            Poll::Ready(Some(Ok(data))) => {
                // Release capacity so sender can continue
                let _ = self.recv.flow_control().release_capacity(data.len());

                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);

                if to_copy < data.len() {
                    self.recv_buf = data.slice(to_copy..);
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::other(e))),
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for H2MultiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Only reserve capacity when needed to avoid resetting h2's internal state on re-polls
        if self.send.capacity() == 0 {
            self.send.reserve_capacity(buf.len());
        }

        match self.send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) => {
                let to_send = buf.len().min(capacity);
                self.send
                    .send_data(Bytes::copy_from_slice(&buf[..to_send]), false)
                    .map_err(io::Error::other)?;
                Poll::Ready(Ok(to_send))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::other(e))),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "H2 stream closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // h2 has no per-stream flush; the connection driver handles transmission
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.shutdown_sent {
            match self.send.send_data(Bytes::new(), true) {
                Ok(()) => self.shutdown_sent = true,
                Err(e) => return Poll::Ready(Err(io::Error::other(e))),
            }
        }

        // Don't wait for peer ACK; the connection driver transmits END_STREAM reliably
        match self.send.poll_reset(cx) {
            Poll::Ready(_) | Poll::Pending => Poll::Ready(Ok(())),
        }
    }
}

impl AsyncPing for H2MultiStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl Unpin for H2MultiStream {}

impl AsyncStream for H2MultiStream {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_h2_multi_stream_is_async_stream() {
        fn assert_async_stream<T: AsyncStream>() {}
        assert_async_stream::<H2MultiStream>();
    }

    #[test]
    fn test_h2_multi_stream_is_unpin() {
        fn assert_unpin<T: Unpin>() {}
        assert_unpin::<H2MultiStream>();
    }

    #[test]
    fn test_h2_multi_stream_is_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<H2MultiStream>();
        assert_sync::<H2MultiStream>();
    }
}
