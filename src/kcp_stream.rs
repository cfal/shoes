use std::pin::Pin;
use std::task::{Context, Poll};

use kcp_tokio::KcpStream;
use log::debug;
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

impl Drop for KcpStreamWrapper {
    fn drop(&mut self) {
        debug!("[KcpStream] KcpStreamWrapper dropped");
    }
}

impl AsyncRead for KcpStreamWrapper {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.get_mut().0).poll_read(cx, buf);
        match &result {
            Poll::Ready(Ok(())) => {
                let filled = buf.filled().len() - before;
                if filled == 0 {
                    debug!("[KcpStream] poll_read → EOF (data_rx channel closed)");
                }
            }
            Poll::Ready(Err(e)) => debug!("[KcpStream] poll_read → error: {e}"),
            Poll::Pending => {}
        }
        result
    }
}

impl AsyncWrite for KcpStreamWrapper {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.get_mut().0).poll_write(cx, buf);
        if let Poll::Ready(Err(ref e)) = result {
            debug!("[KcpStream] poll_write → error: {e}");
        }
        result
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let result = Pin::new(&mut self.get_mut().0).poll_flush(cx);
        if let Poll::Ready(Err(ref e)) = result {
            debug!("[KcpStream] poll_flush → error: {e}");
        }
        result
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        // KCP does not support half-close: calling KcpStream::close() (which poll_shutdown
        // does internally) sets closed=true and drops data_tx, causing any concurrent
        // poll_read to immediately return 0 bytes (EOF). This breaks Vision VLESS where
        // copy_bidirectional calls shutdown on the write side while the read side still
        // needs to receive the server VLESS response or remaining payload.
        //
        // Fix: only flush pending writes. The KCP connection is fully closed when
        // KcpStreamWrapper is dropped, which happens naturally once both directions are done.
        // This preserves proper half-close semantics for TCP and QUIC (those transports'
        // poll_shutdown implementations are not changed).
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
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
