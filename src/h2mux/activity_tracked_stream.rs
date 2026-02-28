//! Activity-tracking stream wrapper for connection-level idle timeout detection.
//!
//! Wraps an AsyncRead+AsyncWrite stream and records activity on any successful
//! read or write. This ensures that HTTP/2 control frames (PING, SETTINGS, etc.)
//! are counted as activity, not just data frames.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::activity_tracker::ActivityTracker;

/// Stream wrapper that records activity on any successful read/write.
///
/// This is used to wrap the underlying connection before passing it to the
/// h2 server handshake, ensuring that all HTTP/2 frames (including PING)
/// reset the idle timeout.
pub struct ActivityTrackedStream<S> {
    inner: S,
    activity: ActivityTracker,
}

impl<S> ActivityTrackedStream<S> {
    pub fn new(inner: S, activity: ActivityTracker) -> Self {
        Self { inner, activity }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ActivityTrackedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let filled_before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);

        // Record activity on successful read with data
        if let Poll::Ready(Ok(())) = &result
            && buf.filled().len() > filled_before
        {
            self.activity.record_activity();
        }

        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ActivityTrackedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);

        // Record activity on successful write
        if let Poll::Ready(Ok(n)) = &result
            && *n > 0
        {
            self.activity.record_activity();
        }

        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
