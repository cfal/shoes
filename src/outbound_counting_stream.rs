//! Counting adapters that credit an outbound for what passes through it.
//!
//! The direction convention here is the INVERSE of
//! `crate::tun::traffic::TrafficCountingStream`. That one sits on the device
//! side, where a read is bytes travelling device to proxy -- upload. These sit
//! at the outbound, where a read is bytes arriving from the server --
//! download. Reusing that type would silently transpose the two figures, and
//! no test that only checks totals would notice.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::ReadBuf;

use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};
use crate::outbound_stats::OutboundCounters;

pin_project_lite::pin_project! {
    /// Counts application payload bytes to and from one outbound, and holds
    /// a live-connection slot for as long as it exists.
    pub struct OutboundCountingStream<S> {
        #[pin]
        inner: S,
        counters: Arc<OutboundCounters>,
    }

    impl<S> PinnedDrop for OutboundCountingStream<S> {
        fn drop(this: Pin<&mut Self>) {
            this.project().counters.connection_closed();
        }
    }
}

impl<S> OutboundCountingStream<S> {
    pub fn new(inner: S, counters: Arc<OutboundCounters>) -> Self {
        counters.connection_opened();
        Self { inner, counters }
    }

    /// Credit bytes that never travelled through this stream: `early_data`
    /// the final hop read while completing its own handshake. Dropping it
    /// would lose the first bytes of every such connection -- a small number,
    /// but a systematically biased one.
    pub fn count_early_data(&self, len: usize) {
        self.counters.add_download(len as u64);
    }
}

impl<S: tokio::io::AsyncRead> tokio::io::AsyncRead for OutboundCountingStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let this = self.project();
        let result = this.inner.poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let n = buf.filled().len() - before;
            if n > 0 {
                this.counters.add_download(n as u64);
            }
        }
        result
    }
}

impl<S: tokio::io::AsyncWrite> tokio::io::AsyncWrite for OutboundCountingStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();
        let result = this.inner.poll_write(cx, buf);
        if let Poll::Ready(Ok(n @ 1..)) = &result {
            this.counters.add_upload(*n as u64);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

impl<S: AsyncPing + Unpin> AsyncPing for OutboundCountingStream<S> {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        self.project().inner.poll_write_ping(cx)
    }
}

impl<S> AsyncStream for OutboundCountingStream<S> where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + AsyncPing + Unpin + Send + Sync
{
}

pin_project_lite::pin_project! {
    /// The datagram equivalent, counting payload lengths as the UDP router
    /// already sees them.
    ///
    /// Deliberately does NOT touch `active_connections`: that figure counts
    /// TCP connections today, and folding datagram sessions in would silently
    /// change what an existing host is reading.
    pub struct OutboundCountingMessageStream<S> {
        #[pin]
        inner: S,
        counters: Arc<OutboundCounters>,
    }
}

impl<S> OutboundCountingMessageStream<S> {
    pub fn new(inner: S, counters: Arc<OutboundCounters>) -> Self {
        Self { inner, counters }
    }
}

impl<S: AsyncReadMessage> AsyncReadMessage for OutboundCountingMessageStream<S> {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let this = self.project();
        let result = this.inner.poll_read_message(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let n = buf.filled().len() - before;
            if n > 0 {
                this.counters.add_download(n as u64);
            }
        }
        result
    }
}

impl<S: AsyncWriteMessage> AsyncWriteMessage for OutboundCountingMessageStream<S> {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();
        let result = this.inner.poll_write_message(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            this.counters.add_upload(buf.len() as u64);
        }
        result
    }
}

impl<S: AsyncFlushMessage> AsyncFlushMessage for OutboundCountingMessageStream<S> {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush_message(cx)
    }
}

impl<S: AsyncShutdownMessage> AsyncShutdownMessage for OutboundCountingMessageStream<S> {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown_message(cx)
    }
}

impl<S: AsyncPing + Unpin> AsyncPing for OutboundCountingMessageStream<S> {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        self.project().inner.poll_write_ping(cx)
    }
}

impl<S> AsyncMessageStream for OutboundCountingMessageStream<S> where
    S: AsyncReadMessage
        + AsyncWriteMessage
        + AsyncFlushMessage
        + AsyncShutdownMessage
        + AsyncPing
        + Unpin
        + Send
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound_stats::{REGISTRY_TEST_LOCK, reset_for_test, snapshot_all};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Install one outbound and hand back its counters. Every test here goes
    /// through install: it is the only writer, so a test that wants a real
    /// counter has to declare it the way a running config would.
    fn installed(
        name: &str,
        address: &str,
    ) -> std::sync::Arc<crate::outbound_stats::OutboundCounters> {
        let mut set = crate::outbound_stats::OutboundSet::default();
        set.insert(name, address).unwrap();
        crate::outbound_stats::install(&set);
        crate::outbound_stats::lookup(name)
    }

    /// At the outbound a read is DOWNLOAD and a write is UPLOAD — the inverse
    /// of tun::traffic, whose stream sits on the device side. The two byte
    /// counts are deliberately different, because equal ones would pass with
    /// the directions transposed.
    #[tokio::test]
    async fn a_read_is_download_and_a_write_is_upload() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();
        let counters = installed("Frankfurt", "fra1.example:443");

        let (mut peer, local) = tokio::io::duplex(4096);
        peer.write_all(&[0u8; 9]).await.unwrap();

        let mut counting = OutboundCountingStream::new(local, counters);
        let mut buf = [0u8; 9];
        counting.read_exact(&mut buf).await.unwrap();
        counting.write_all(&[0u8; 3]).await.unwrap();
        counting.flush().await.unwrap();

        let all = snapshot_all();
        assert_eq!(all[0].download_bytes, 9, "a read must count as download");
        assert_eq!(all[0].upload_bytes, 3, "a write must count as upload");
    }

    #[tokio::test]
    async fn a_connection_is_counted_for_its_lifetime() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();
        let counters = installed("Frankfurt", "fra1.example:443");

        let (_peer, local) = tokio::io::duplex(64);
        let counting = OutboundCountingStream::new(local, counters);
        assert_eq!(snapshot_all()[0].active_connections, 1);

        drop(counting);
        assert_eq!(snapshot_all()[0].active_connections, 0);
    }

    #[tokio::test]
    async fn early_data_is_credited_as_download() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();
        let counters = installed("Frankfurt", "fra1.example:443");

        let (_peer, local) = tokio::io::duplex(64);
        let counting = OutboundCountingStream::new(local, counters);
        counting.count_early_data(17);

        assert_eq!(snapshot_all()[0].download_bytes, 17);
    }

    /// A datagram session is not a connection: active_connections counts TCP
    /// today, and folding datagrams in would change what a host is reading.
    #[tokio::test]
    async fn a_message_stream_does_not_hold_a_connection_slot() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();
        let counters = installed("Frankfurt", "fra1.example:443");

        let (_peer, local) = tokio::io::duplex(64);
        let counting = OutboundCountingMessageStream::new(local, counters);
        assert_eq!(snapshot_all()[0].active_connections, 0);
        drop(counting);
    }
}
