use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};

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

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncPing + Unpin> AsyncPing for PrependStream<S> {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Pin::new(&mut self.get_mut().inner).poll_write_ping(cx)
    }
}

impl<S: AsyncStream> AsyncStream for PrependStream<S> {
    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.peer_addr()
    }
    fn preferred_write_size(&self) -> Option<std::num::NonZeroUsize> {
        self.inner.preferred_write_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn fragmented_prefix_reads_preserve_bytes_across_pending_and_eof() {
        timeout(Duration::from_secs(5), async {
            for chunk_size in [1, 2, 7] {
                let (inner, mut peer) = tokio::io::duplex(8);
                let mut stream = PrependStream::new(inner, Some(Box::from(&b"prefix"[..])));
                let mut output = Vec::new();
                let mut chunk = vec![0; chunk_size];
                assert_eq!(stream.read(&mut []).await.unwrap(), 0);
                while output.len() < 6 {
                    let count = stream.read(&mut chunk).await.unwrap();
                    assert!(count > 0);
                    output.extend_from_slice(&chunk[..count]);
                }
                assert_eq!(output, b"prefix");
                std::future::poll_fn(|cx| {
                    let mut buffer = ReadBuf::new(&mut chunk);
                    assert!(
                        Pin::new(&mut stream)
                            .poll_read(cx, &mut buffer)
                            .is_pending()
                    );
                    Poll::Ready(())
                })
                .await;
                peer.write_all(b"tail").await.unwrap();
                peer.shutdown().await.unwrap();
                stream.read_to_end(&mut output).await.unwrap();
                assert_eq!(output, b"prefixtail");
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn absent_and_empty_prefixes_delegate_without_false_eof() {
        timeout(Duration::from_secs(5), async {
            for prefix in [None, Some(Box::from(&b""[..]))] {
                let (inner, mut peer) = tokio::io::duplex(8);
                let mut stream = PrependStream::new(inner, prefix);
                let mut byte = [0; 1];
                std::future::poll_fn(|cx| {
                    let mut buffer = ReadBuf::new(&mut byte);
                    assert!(
                        Pin::new(&mut stream)
                            .poll_read(cx, &mut buffer)
                            .is_pending()
                    );
                    Poll::Ready(())
                })
                .await;
                peer.write_all(b"data").await.unwrap();
                peer.shutdown().await.unwrap();
                let mut output = Vec::new();
                stream.read_to_end(&mut output).await.unwrap();
                assert_eq!(output, b"data");
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn write_half_close_keeps_unread_prefix_and_reverse_traffic() {
        timeout(Duration::from_secs(5), async {
            let (inner, mut peer) = tokio::io::duplex(8);
            let mut stream = PrependStream::new(inner, Some(Box::from(&b"prefix"[..])));
            stream.write_all(b"upload").await.unwrap();
            stream.flush().await.unwrap();
            stream.shutdown().await.unwrap();
            let mut upload = Vec::new();
            peer.read_to_end(&mut upload).await.unwrap();
            assert_eq!(upload, b"upload");
            peer.write_all(b"reply").await.unwrap();
            peer.shutdown().await.unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"prefixreply");
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn buffered_prefix_precedes_underlying_read_error() {
        struct FailedReader;

        impl AsyncRead for FailedReader {
            fn poll_read(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
            }
        }

        let mut stream = PrependStream::new(FailedReader, Some(Box::from(&b"prefix"[..])));
        let mut output = Vec::new();
        let error = stream.read_to_end(&mut output).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(output, b"prefix");
    }
}
