use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A stream wrapper that prepends initial data to reads.
///
/// Used when the protocol detection leaves some data buffered that needs
/// to be read first before continuing with the underlying stream.
pub struct PrependStream<S> {
    inner: S,
    initial_data: Option<Box<[u8]>>,
    offset: usize,
}

impl<S> PrependStream<S> {
    pub fn new(inner: S, initial_data: Option<Box<[u8]>>) -> Self {
        Self {
            inner,
            initial_data,
            offset: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrependStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // First, drain any initial data
        if let Some(data) = this.initial_data.take() {
            let remaining = &data[this.offset..];
            if !remaining.is_empty() {
                let to_copy = std::cmp::min(remaining.len(), buf.remaining());
                buf.put_slice(&remaining[..to_copy]);
                this.offset += to_copy;
                // Put back if not fully consumed
                if this.offset < data.len() {
                    this.initial_data = Some(data);
                } else {
                    this.offset = 0;
                }
                return Poll::Ready(Ok(()));
            }
            this.offset = 0;
        }
        // Read from inner stream
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrependStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
