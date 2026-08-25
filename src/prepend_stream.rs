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

impl<S: crate::async_stream::AsyncPing + Unpin> crate::async_stream::AsyncPing
    for PrependStream<S>
{
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Pin::new(&mut self.inner).poll_write_ping(cx)
    }
}

impl<S: crate::async_stream::AsyncStream> crate::async_stream::AsyncStream for PrependStream<S> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_stream::AsyncStream;
    use crate::async_stream::testing::TestStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    /// The prefix comes first, then whatever the stream itself carries.
    #[tokio::test]
    async fn the_prefix_is_read_before_the_stream() {
        let (near, mut far) = duplex(1024);
        far.write_all(b"world").await.unwrap();

        let mut stream = PrependStream::new(TestStream(near), Some(b"hello ".to_vec().into()));

        let mut got = vec![0u8; 11];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello world");
    }

    /// The point of the move: a handler can hand this to an inner handler.
    #[tokio::test]
    async fn a_prepend_stream_is_an_async_stream() {
        let (near, _far) = duplex(1024);
        let boxed: Box<dyn AsyncStream> = Box::new(PrependStream::new(
            TestStream(near),
            Some(b"x".to_vec().into()),
        ));
        assert!(!boxed.supports_ping());
    }
}
