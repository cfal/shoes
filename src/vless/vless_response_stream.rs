use std::pin::Pin;
use std::task::{Context, Poll};

use futures::ready;
use log::debug;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};

/// A wrapper stream that reads VLESS response header on first read, similar
/// to vmess and shadowsocks.
pub struct VlessResponseStream<IO> {
    inner: IO,
    response_pending: bool,
    response_buffer: Vec<u8>,
}

impl<IO> VlessResponseStream<IO>
where
    IO: AsyncStream,
{
    pub fn new(inner: IO) -> Self {
        Self {
            inner,
            response_pending: true,
            response_buffer: Vec::new(),
        }
    }

    fn poll_read_response(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Need to read at least 2 bytes for the response header
        while self.response_buffer.len() < 2 {
            let mut buf = [0u8; 2];
            let mut read_buf = ReadBuf::new(&mut buf);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read_buf))?;

            let filled = read_buf.filled();
            if filled.is_empty() {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Connection closed while reading VLESS response",
                )));
            }
            self.response_buffer.extend_from_slice(filled);
        }

        // Validate version
        let version = self.response_buffer[0];
        if version != 0 {
            return Poll::Ready(Err(std::io::Error::other(format!(
                "invalid server protocol version, expected 0, got {version}"
            ))));
        }

        // Check if we need to read addons
        let addon_length = self.response_buffer[1] as usize;
        let total_response_len = 2 + addon_length;

        // Read addon data if needed
        while self.response_buffer.len() < total_response_len {
            let remaining = total_response_len - self.response_buffer.len();
            let mut buf = vec![0u8; remaining];
            let mut read_buf = ReadBuf::new(&mut buf);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read_buf))?;

            let filled = read_buf.filled();
            if filled.is_empty() {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Connection closed while reading VLESS response addons",
                )));
            }
            self.response_buffer.extend_from_slice(filled);
        }

        debug!(
            "VLESS: Successfully read and consumed {} byte response header (version={}, addon_length={})",
            total_response_len, version, addon_length
        );

        Poll::Ready(Ok(()))
    }
}

impl<IO> AsyncRead for VlessResponseStream<IO>
where
    IO: AsyncStream,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Read VLESS response header on first read
        if self.response_pending {
            match self.poll_read_response(cx) {
                Poll::Ready(Ok(())) => {
                    self.response_pending = false;
                    // Response is consumed, now read actual data
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Pass through to inner stream
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<IO> AsyncWrite for VlessResponseStream<IO>
where
    IO: AsyncStream,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<IO> AsyncPing for VlessResponseStream<IO>
where
    IO: AsyncStream,
{
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.inner).poll_write_ping(cx)
    }
}

impl<IO> AsyncStream for VlessResponseStream<IO> where IO: AsyncStream {}
