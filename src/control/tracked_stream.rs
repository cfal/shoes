use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::WaitForCancellationFutureOwned;

use super::flows::{FlowEntry, FlowGuard};
use crate::async_stream::*;

pub struct TrackedStream {
    inner: Box<dyn AsyncStream>,
    guard: FlowGuard,
    cancelled: Pin<Box<WaitForCancellationFutureOwned>>,
}

impl TrackedStream {
    pub fn new(inner: Box<dyn AsyncStream>, guard: FlowGuard) -> Self {
        let cancelled = Box::pin(guard.entry.cancel.clone().cancelled_owned());
        Self {
            inner,
            guard,
            cancelled,
        }
    }

    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.cancelled.as_mut().poll(cx).is_ready() {
            Err(cancelled())
        } else {
            Ok(())
        }
    }
}

pub fn cancelled() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "flow cancelled")
}

pub async fn wait_cancel(flow: Option<&FlowEntry>) {
    match flow {
        Some(flow) => flow.cancel.cancelled().await,
        None => std::future::pending().await,
    }
}

pub async fn during_flow<T>(
    flow: Option<&FlowEntry>,
    future: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    tokio::select! {
        biased;
        _ = wait_cancel(flow) => Err(cancelled()),
        result = future => result,
    }
}

pub async fn finish_shutdown(
    a: Option<&FlowEntry>,
    b: Option<&FlowEntry>,
    shutdown: impl Future<Output = ()>,
) {
    tokio::pin!(shutdown);
    let cancelled = async {
        tokio::select! {
            _ = wait_cancel(a) => {},
            _ = wait_cancel(b) => {},
        }
    };
    tokio::select! {
        _ = &mut shutdown => {},
        _ = cancelled => {
            // Protocol FINs can flush queued data; cancellation cannot wait for backpressure.
            let _ = tokio::time::timeout(std::time::Duration::from_millis(250), shutdown).await;
        }
    }
}

pub async fn during_flows<T>(
    a: Option<&FlowEntry>,
    b: Option<&FlowEntry>,
    future: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    if a.is_none() && b.is_none() {
        return future.await;
    }
    // Unlike setup writes, relay completion and cancellation retain unbiased tie-breaking.
    tokio::select! {
        result = future => result,
        _ = wait_cancel(a) => Err(cancelled()),
        _ = wait_cancel(b) => Err(cancelled()),
    }
}

impl AsyncRead for TrackedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.check(cx)?;
        let before = buf.filled().len();
        let result = Pin::new(&mut *self.inner).poll_read(cx, buf);
        self.guard
            .entry
            .counters
            .download(buf.filled().len() - before);
        result
    }
}

impl AsyncWrite for TrackedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check(cx)?;
        let result = Pin::new(&mut *self.inner).poll_write(cx, bytes);
        if let Poll::Ready(Ok(count)) = result {
            self.guard.entry.counters.upload(count);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check(cx)?;
        Pin::new(&mut *self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The forwarding owner still allows a bounded FIN after cancellation.
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

impl AsyncPing for TrackedStream {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }
    fn poll_write_ping(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        self.check(cx)?;
        Pin::new(&mut *self.inner).poll_write_ping(cx)
    }
}

impl AsyncStream for TrackedStream {
    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.peer_addr()
    }
    fn flow(&self) -> Option<&Arc<FlowEntry>> {
        Some(&self.guard.entry)
    }
    #[cfg(target_os = "linux")]
    fn plain_tcp(&self) -> Option<&tokio::net::TcpStream> {
        self.inner.plain_tcp()
    }
    fn preferred_write_size(&self) -> Option<std::num::NonZeroUsize> {
        self.inner.preferred_write_size()
    }
}

pub struct TrackedMessageStream {
    inner: Box<dyn AsyncMessageStream>,
    guard: FlowGuard,
    cancelled: Pin<Box<WaitForCancellationFutureOwned>>,
}

impl TrackedMessageStream {
    pub fn new(inner: Box<dyn AsyncMessageStream>, guard: FlowGuard) -> Self {
        let cancelled = Box::pin(guard.entry.cancel.clone().cancelled_owned());
        Self {
            inner,
            guard,
            cancelled,
        }
    }
    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.cancelled.as_mut().poll(cx).is_ready() {
            Err(cancelled())
        } else {
            Ok(())
        }
    }
}

impl AsyncReadMessage for TrackedMessageStream {
    fn read_message_eof_on_empty(&self) -> bool {
        self.inner.read_message_eof_on_empty()
    }
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.check(cx)?;
        let before = buf.filled().len();
        let result = Pin::new(&mut *self.inner).poll_read_message(cx, buf);
        self.guard
            .entry
            .counters
            .download(buf.filled().len() - before);
        result
    }
}

impl AsyncWriteMessage for TrackedMessageStream {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<()>> {
        self.check(cx)?;
        let result = Pin::new(&mut *self.inner).poll_write_message(cx, bytes);
        if let Poll::Ready(Ok(())) = result {
            self.guard.entry.counters.upload(bytes.len());
        }
        result
    }
}

impl AsyncFlushMessage for TrackedMessageStream {
    fn poll_flush_message(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check(cx)?;
        Pin::new(&mut *self.inner).poll_flush_message(cx)
    }
}

impl AsyncShutdownMessage for TrackedMessageStream {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown_message(cx)
    }
}

impl AsyncPing for TrackedMessageStream {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }
    fn poll_write_ping(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        self.check(cx)?;
        Pin::new(&mut *self.inner).poll_write_ping(cx)
    }
}

impl AsyncMessageStream for TrackedMessageStream {
    fn flow(&self) -> Option<&Arc<FlowEntry>> {
        Some(&self.guard.entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct StalledShutdown;
    impl AsyncRead for StalledShutdown {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }
    impl AsyncWrite for StalledShutdown {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }
    impl AsyncPing for StalledShutdown {
        fn supports_ping(&self) -> bool {
            false
        }
        fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }
    impl AsyncStream for StalledShutdown {}

    #[tokio::test(start_paused = true)]
    async fn tcp_shutdown_observes_cancellation_before_and_during_cleanup() {
        use futures::FutureExt;
        for cancel_before in [true, false] {
            let guard = super::super::flows::test_guard();
            let entry = guard.entry.clone();
            let mut outbound = TrackedStream::new(Box::new(StalledShutdown), guard);
            let mut inbound = StalledShutdown;
            if cancel_before {
                entry.cancel.cancel();
            }
            let cleanup = crate::util::shutdown_stream_pair(&mut inbound, &mut outbound);
            tokio::pin!(cleanup);
            assert!(cleanup.as_mut().now_or_never().is_none());
            if !cancel_before {
                tokio::time::advance(Duration::from_secs(1)).await;
                entry.cancel.cancel();
            }
            let start = tokio::time::Instant::now();
            cleanup.await;
            assert_eq!(start.elapsed(), Duration::from_millis(250));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_interrupts_initial_inbound_writes() {
        use futures::FutureExt;
        let guard = super::super::flows::test_guard();
        let mut inbound = StalledShutdown;
        let setup = during_flow(Some(&guard.entry), inbound.write_all(b"early data"));
        tokio::pin!(setup);
        assert!(setup.as_mut().now_or_never().is_none());
        guard.entry.cancel.cancel();
        let start = tokio::time::Instant::now();
        assert_eq!(
            setup.await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    struct BackpressuredMessages {
        payload: Option<Vec<u8>>,
        blocked: Arc<tokio::sync::Notify>,
        fail_read: bool,
    }
    impl AsyncReadMessage for BackpressuredMessages {
        fn poll_read_message(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.fail_read {
                return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
            }
            match self.payload.take() {
                Some(payload) => {
                    buf.put_slice(&payload);
                    Poll::Ready(Ok(()))
                }
                None => Poll::Pending,
            }
        }
    }
    impl AsyncWriteMessage for BackpressuredMessages {
        fn poll_write_message(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<()>> {
            self.blocked.notify_one();
            Poll::Pending
        }
    }
    impl AsyncFlushMessage for BackpressuredMessages {
        fn poll_flush_message(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncShutdownMessage for BackpressuredMessages {
        fn poll_shutdown_message(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            self.blocked.notify_one();
            Poll::Pending
        }
    }
    impl AsyncPing for BackpressuredMessages {
        fn supports_ping(&self) -> bool {
            false
        }
        fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }
    impl AsyncMessageStream for BackpressuredMessages {}

    #[tokio::test]
    async fn fixed_udp_cancellation_interrupts_a_blocked_inbound_writer() {
        let guard = super::super::flows::test_guard();
        let entry = guard.entry.clone();
        let blocked = Arc::new(tokio::sync::Notify::new());
        let inbound = Box::new(BackpressuredMessages {
            payload: None,
            blocked: blocked.clone(),
            fail_read: false,
        });
        let outbound = Box::new(TrackedMessageStream::new(
            Box::new(BackpressuredMessages {
                payload: Some(b"payload".to_vec()),
                blocked: blocked.clone(),
                fail_read: false,
            }),
            guard,
        ));
        let relay = tokio::spawn(crate::tcp::tcp_server::run_udp_copy(
            inbound, outbound, false, false,
        ));
        tokio::time::timeout(Duration::from_secs(1), blocked.notified())
            .await
            .unwrap();
        assert_eq!(entry.counters.totals(), (0, 7));
        entry.cancel.cancel();
        let error = tokio::time::timeout(Duration::from_secs(1), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    }

    #[tokio::test]
    async fn fixed_udp_cancellation_interrupts_shutdown_already_in_progress() {
        let guard = super::super::flows::test_guard();
        let entry = guard.entry.clone();
        let shutdown_started = Arc::new(tokio::sync::Notify::new());
        let inbound = Box::new(BackpressuredMessages {
            payload: None,
            blocked: shutdown_started.clone(),
            fail_read: true,
        });
        let outbound = Box::new(TrackedMessageStream::new(
            Box::new(BackpressuredMessages {
                payload: None,
                blocked: shutdown_started.clone(),
                fail_read: false,
            }),
            guard,
        ));
        let relay = tokio::spawn(crate::tcp::tcp_server::run_udp_copy(
            inbound, outbound, false, false,
        ));
        tokio::time::timeout(Duration::from_secs(1), shutdown_started.notified())
            .await
            .unwrap();
        entry.cancel.cancel();
        let error = tokio::time::timeout(Duration::from_secs(1), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    }

    #[tokio::test]
    async fn buffered_counts_partial_io_and_wakes_idle_cancellation() {
        let guard = super::super::flows::test_guard();
        let entry = guard.entry.clone();
        let (outbound, mut remote) = tokio::io::duplex(4);
        let mut tracked = TrackedStream::new(Box::new(outbound), guard);
        let (mut inbound, mut client) = tokio::io::duplex(4);
        let relay = tokio::spawn(async move {
            crate::copy_bidirectional::copy_bidirectional(&mut inbound, &mut tracked, false, false)
                .await
        });
        let exchange = async {
            let send = async {
                client.write_all(b"upload-payload").await.unwrap();
            };
            let receive = async {
                let mut bytes = [0; 14];
                remote.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"upload-payload");
            };
            tokio::join!(send, receive);
            let send = async {
                remote.write_all(b"reply-payload").await.unwrap();
            };
            let receive = async {
                let mut bytes = [0; 13];
                client.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"reply-payload");
            };
            tokio::join!(send, receive);
        };
        tokio::time::timeout(Duration::from_secs(2), exchange)
            .await
            .unwrap();
        assert_eq!(entry.counters.totals(), (14, 13));
        entry.cancel.cancel();
        let error = tokio::time::timeout(Duration::from_secs(1), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn raw_splice_keeps_live_payload_counts_and_cancellation() {
        crate::splice::TEST_SPLICED_BYTES.set(0);
        async fn pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
            let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let (client, accepted) = tokio::join!(
                tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)),
                listener.accept()
            );
            (client.unwrap(), accepted.unwrap().0)
        }
        let (mut client, mut inbound) = pair().await;
        let (outbound, mut remote) = pair().await;
        let guard = super::super::flows::test_guard();
        let entry = guard.entry.clone();
        let mut tracked = TrackedStream::new(Box::new(outbound), guard);
        assert!(tracked.plain_tcp().is_some());
        let relay = tokio::spawn(async move {
            crate::copy_bidirectional::copy_bidirectional(&mut inbound, &mut tracked, false, false)
                .await
        });
        let payload = vec![37; 1024 * 1024];
        let exchange = async {
            let send = async {
                client.write_all(&payload).await.unwrap();
            };
            let receive = async {
                let mut bytes = vec![0; payload.len()];
                remote.read_exact(&mut bytes).await.unwrap();
                assert_eq!(bytes, payload);
            };
            tokio::join!(send, receive);
            remote.write_all(b"reply").await.unwrap();
            let mut reply = [0; 5];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"reply");
        };
        tokio::time::timeout(Duration::from_secs(5), exchange)
            .await
            .unwrap();
        assert_eq!(entry.counters.totals(), (payload.len() as u64, 5));
        assert!(crate::splice::TEST_SPLICED_BYTES.get() > 0);
        entry.cancel.cancel();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), relay)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::ConnectionAborted
        );
    }
}
