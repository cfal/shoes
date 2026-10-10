use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

#[derive(Clone, Default)]
pub(super) struct H2Writes {
    bytes: Arc<Mutex<Vec<u8>>>,
    changed: Arc<Notify>,
}

impl H2Writes {
    pub(super) fn wrap<S>(&self, inner: S) -> RecordedStream<S> {
        RecordedStream {
            inner,
            writes: self.clone(),
        }
    }

    pub(super) async fn wait_for_goaway(&self) {
        while !self.has_graceful_goaway() {
            self.changed.notified().await;
        }
    }

    pub(super) fn assert_graceful_goaway(&self) {
        assert!(self.has_graceful_goaway(), "server never wrote GOAWAY");
    }

    fn has_graceful_goaway(&self) -> bool {
        let bytes = self.bytes.lock().unwrap();
        let mut remaining = bytes.as_slice();
        let mut found = false;
        while !remaining.is_empty() {
            if remaining.len() < 9 {
                break;
            }
            let length = u32::from_be_bytes([0, remaining[0], remaining[1], remaining[2]]) as usize;
            if remaining.len() < 9 + length {
                break;
            }
            if remaining[3] == 7 {
                assert!(length >= 8, "truncated GOAWAY");
                assert_eq!(&remaining[5..9], &[0; 4], "GOAWAY stream ID");
                assert_eq!(&remaining[13..17], &[0; 4], "GOAWAY must be NO_ERROR");
                found = true;
            }
            remaining = &remaining[9 + length..];
        }
        found
    }
}

pub(super) struct RecordedStream<S> {
    inner: S,
    writes: H2Writes,
}

impl<S: AsyncRead + Unpin> AsyncRead for RecordedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RecordedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(length)) = result {
            self.writes
                .bytes
                .lock()
                .unwrap()
                .extend_from_slice(&buf[..length]);
            self.writes.changed.notify_one();
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
