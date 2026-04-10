use std::pin::Pin;
use std::task::{Context, Poll};

use kcp_tokio::KcpStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};

/// Wrapper around `kcp_tokio::KcpStream` that implements the `AsyncStream` trait.
pub struct KcpStreamWrapper(KcpStream);

// SAFETY: KcpStream is polled exclusively from a single Tokio task at a time.
// The `Send + Sync` bounds on `AsyncStream` are satisfied: `Send` holds because
// `KcpStream: Send`, and `Sync` is safe here because concurrent shared references
// are never created — all access goes through `Pin<&mut Self>`.
unsafe impl Sync for KcpStreamWrapper {}

impl KcpStreamWrapper {
    pub fn new(stream: KcpStream) -> Self {
        Self(stream)
    }
}

impl AsyncRead for KcpStreamWrapper {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for KcpStreamWrapper {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

impl AsyncPing for KcpStreamWrapper {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        unimplemented!()
    }
}

impl AsyncStream for KcpStreamWrapper {}
