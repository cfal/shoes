//! AnyTLS Stream implementation
//!
//! A Stream represents a single multiplexed connection within an AnyTLS Session.
//! It implements AsyncRead and AsyncWrite for transparent integration.
//!
//! ## Shutdown Behavior
//!
//! Unlike many async stream implementations, `poll_shutdown` properly blocks until
//! the FIN frame is queued for transmission. This matches the Go reference
//! implementation which blocks on `streamClosed()` until the FIN is written.
//!
//! This is important because:
//! 1. The peer needs to receive the FIN to know the stream is done
//! 2. `copy_bidirectional` expects shutdown to complete before marking direction as done
//! 3. Best-effort FIN could be silently dropped if the channel is full

use super::anytls_client_session::{AnyTlsClientSession, OutgoingMessage};
use crate::async_stream::{AsyncPing, AsyncStream};
use bytes::Bytes;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::PollSender;

/// Buffer size for bounded channels (number of messages, not bytes)
/// Each message is typically a frame's worth of data (up to 64KB)
/// 16 messages = up to ~1MB buffered per direction per stream
pub const STREAM_CHANNEL_BUFFER: usize = 16;

/// Maximum data payload per frame (u16::MAX = 65535)
/// Writes larger than this must be chunked into multiple frames
const MAX_FRAME_DATA_SIZE: usize = 65535;

enum WriteChannel {
    Server(PollSender<(u32, Bytes)>),
    Client {
        sender: PollSender<OutgoingMessage>,
        flush: Option<oneshot::Receiver<()>>,
    },
}

impl WriteChannel {
    fn poll_pending_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if matches!(self, Self::Client { flush: Some(_), .. }) {
            self.poll_flush(cx)
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn poll_reserve(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ()>> {
        match self {
            Self::Server(sender) => sender.poll_reserve(cx).map_err(|_| ()),
            Self::Client { sender, .. } => sender.poll_reserve(cx).map_err(|_| ()),
        }
    }

    fn send_item(&mut self, (stream_id, data): (u32, Bytes)) -> Result<(), ()> {
        match self {
            Self::Server(sender) => sender.send_item((stream_id, data)).map_err(|_| ()),
            Self::Client { sender, .. } => {
                let message = if data.is_empty() {
                    OutgoingMessage::Fin { stream_id }
                } else {
                    OutgoingMessage::Data { stream_id, data }
                };
                sender.send_item(message).map_err(|_| ())
            }
        }
    }

    fn try_send_fin(&mut self, stream_id: u32) -> Result<(), ()> {
        match self {
            Self::Server(sender) => sender
                .get_ref()
                .ok_or(())?
                .try_send((stream_id, Bytes::new()))
                .map_err(|_| ()),
            Self::Client { sender, .. } => sender
                .get_ref()
                .ok_or(())?
                .try_send(OutgoingMessage::Fin { stream_id })
                .map_err(|_| ()),
        }
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Self::Client { sender, flush } = self else {
            return Poll::Ready(Ok(()));
        };
        if flush.is_none() {
            std::task::ready!(sender.poll_reserve(cx)).map_err(|_| io::ErrorKind::BrokenPipe)?;
            let (done, rx) = oneshot::channel();
            sender
                .send_item(OutgoingMessage::Flush { done })
                .map_err(|_| io::ErrorKind::BrokenPipe)?;
            *flush = Some(rx);
        }
        let result = std::task::ready!(Pin::new(flush.as_mut().unwrap()).poll(cx));
        *flush = None;
        Poll::Ready(result.map_err(|_| io::ErrorKind::BrokenPipe.into()))
    }
}

/// AnyTlsStream represents a multiplexed stream within an AnyTLS session
///
/// Reads come from data pushed by the session's recv loop.
/// Writes are sent to the session for framing and transmission.
///
/// Uses bounded channels with backpressure to prevent OOM during
/// speed-mismatched transfers.
pub struct AnyTlsStream {
    /// Stream ID (unique within session)
    id: u32,

    /// Receiver for incoming data from session (bounded for backpressure)
    /// The session's recv loop pushes PSH frame data here
    data_rx: mpsc::Receiver<Bytes>,

    /// Buffer for partial reads - uses Bytes for O(1) advance without memmove
    read_buffer: Bytes,

    /// Offset into read_buffer for partial consumption
    read_offset: usize,

    /// Poll-based sender for outgoing data to session (bounded with backpressure)
    /// Data sent here will be framed as PSH and written to the connection.
    /// PollSender provides poll_reserve() for non-blocking backpressure.
    data_tx: WriteChannel,

    /// Shared flag indicating session closure
    session_closed: Arc<AtomicBool>,

    /// Local stream closed flag (set once shutdown completes or stream is dropped)
    stream_closed: bool,

    /// Flag indicating shutdown is in progress (FIN being sent)
    /// This tracks the multi-poll cycle of poll_reserve -> send_item
    shutdown_in_progress: bool,
    fin_sent: bool,

    /// Flag to track if we've received EOF
    eof: bool,

    /// Keepalive reference to the session (client-side only)
    /// This ensures the session stays alive as long as any stream exists
    _session_keepalive: Option<Arc<AnyTlsClientSession>>,
}

impl AnyTlsStream {
    /// Create a new AnyTlsStream
    ///
    /// # Arguments
    /// * `id` - Stream ID
    /// * `data_rx` - Receiver for incoming data from session (bounded)
    /// * `data_tx` - Sender for outgoing data to session (bounded, wrapped in PollSender)
    /// * `session_closed` - Shared flag for session closure
    pub fn new(
        id: u32,
        data_rx: mpsc::Receiver<Bytes>,
        data_tx: mpsc::Sender<(u32, Bytes)>,
        session_closed: Arc<AtomicBool>,
    ) -> Self {
        Self {
            id,
            data_rx,
            read_buffer: Bytes::new(),
            read_offset: 0,
            data_tx: WriteChannel::Server(PollSender::new(data_tx)),
            session_closed,
            stream_closed: false,
            shutdown_in_progress: false,
            fin_sent: false,
            eof: false,
            _session_keepalive: None,
        }
    }

    /// Create a new AnyTlsStream with a session keepalive reference
    ///
    /// This variant holds an Arc reference to the session, ensuring it stays
    /// alive as long as the stream exists. Used by client-side streams.
    pub(super) fn with_keepalive(
        id: u32,
        data_rx: mpsc::Receiver<Bytes>,
        data_tx: mpsc::Sender<OutgoingMessage>,
        session_closed: Arc<AtomicBool>,
        session: Arc<AnyTlsClientSession>,
    ) -> Self {
        Self {
            id,
            data_rx,
            read_buffer: Bytes::new(),
            read_offset: 0,
            data_tx: WriteChannel::Client {
                sender: PollSender::new(data_tx),
                flush: None,
            },
            session_closed,
            stream_closed: false,
            shutdown_in_progress: false,
            fin_sent: false,
            eof: false,
            _session_keepalive: Some(session),
        }
    }

    /// Get the stream ID
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Best-effort FIN send for Drop (cannot block in Drop)
    ///
    /// This is only used when the stream is dropped without being properly shutdown.
    /// It uses try_send which may fail if the channel is full, but that's acceptable
    /// for the Drop path since we can't block there.
    ///
    /// For proper shutdown semantics, use `poll_shutdown` which blocks until FIN is sent.
    fn send_fin_best_effort(&mut self) {
        // Don't abort pending data - just try to send FIN if there's room
        if self.data_tx.try_send_fin(self.id).is_err()
            && let Some(session) = &self._session_keepalive
        {
            session.close();
        }
    }
}

impl AsyncRead for AnyTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // Check EOF with empty buffer
        let remaining_in_buffer = self.read_buffer.len() - self.read_offset;
        if self.eof && remaining_in_buffer == 0 {
            return Poll::Ready(Ok(()));
        }

        // First, drain any buffered data (O(1) advance, no memmove)
        if remaining_in_buffer > 0 {
            let n = std::cmp::min(remaining_in_buffer, buf.remaining());
            buf.put_slice(&self.read_buffer[self.read_offset..self.read_offset + n]);
            self.read_offset += n;

            // Release buffer when fully consumed (allows memory to be freed)
            if self.read_offset >= self.read_buffer.len() {
                self.read_buffer = Bytes::new();
                self.read_offset = 0;
            }

            return Poll::Ready(Ok(()));
        }

        // Try to receive more data from the session
        match Pin::new(&mut self.data_rx).poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                if data.is_empty() {
                    // Empty data signals EOF
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }

                let n = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..n]);

                // Buffer remaining data (O(1) - just keep the Bytes reference)
                if n < data.len() {
                    self.read_buffer = data;
                    self.read_offset = n;
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                // Channel closed - EOF
                self.eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for AnyTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.stream_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream closed",
            )));
        }

        if self.shutdown_in_progress {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream is shutting down",
            )));
        }

        if self.session_closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "session closed",
            )));
        }

        std::task::ready!(self.data_tx.poll_pending_flush(cx))?;
        // Use poll_reserve for backpressure - this will return Pending if channel is full
        match self.data_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                // Limit write size to max frame payload (u16::MAX = 65535)
                // This prevents protocol corruption from length field truncation
                let write_len = buf.len().min(MAX_FRAME_DATA_SIZE);
                let data = Bytes::copy_from_slice(&buf[..write_len]);
                let id = self.id;
                match self.data_tx.send_item((id, data)) {
                    Ok(()) => Poll::Ready(Ok(write_len)),
                    Err(_) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "session channel closed",
                    ))),
                }
            }
            Poll::Ready(Err(_)) => {
                // Channel closed
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "session channel closed",
                )))
            }
            Poll::Pending => {
                // Channel full - backpressure! Return Pending to slow down the writer
                Poll::Pending
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.data_tx.poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.stream_closed {
            return Poll::Ready(Ok(()));
        }
        if self.session_closed.load(Ordering::Relaxed) {
            self.data_rx.close();
            self.stream_closed = true;
            return Poll::Ready(Ok(()));
        }
        self.shutdown_in_progress = true;
        if !self.fin_sent {
            std::task::ready!(self.data_tx.poll_pending_flush(cx))?;
            std::task::ready!(self.data_tx.poll_reserve(cx))
                .map_err(|_| io::ErrorKind::BrokenPipe)?;
            let id = self.id;
            self.data_tx
                .send_item((id, Bytes::new()))
                .map_err(|_| io::ErrorKind::BrokenPipe)?;
            self.fin_sent = true;
        }
        std::task::ready!(self.data_tx.poll_flush(cx))?;
        self.data_rx.close();
        self.stream_closed = true;
        Poll::Ready(Ok(()))
    }
}

impl Drop for AnyTlsStream {
    fn drop(&mut self) {
        // If stream wasn't properly shutdown, try best-effort FIN
        // This handles cases where the stream is dropped without calling shutdown()
        if !self.stream_closed && !self.fin_sent {
            self.stream_closed = true;
            self.send_fin_best_effort();
        }
        if let Some(session) = &self._session_keepalive {
            session.remove_stream(self.id);
        }
    }
}

impl AsyncPing for AnyTlsStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        // AnyTLS doesn't have a ping mechanism at the stream level
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for AnyTlsStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn shutdown_keeps_buffered_and_queued_response_bytes_readable() {
        let (outgoing, _outgoing_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let (incoming, incoming_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let mut stream =
            AnyTlsStream::new(1, incoming_rx, outgoing, Arc::new(AtomicBool::new(false)));
        incoming.send(Bytes::from_static(b"first")).await.unwrap();
        incoming.send(Bytes::from_static(b"second")).await.unwrap();
        let mut first = [0; 1];
        stream.read_exact(&mut first).await.unwrap();
        stream.shutdown().await.unwrap();
        assert!(stream.write_all(b"closed").await.is_err());
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        assert_eq!(first, *b"f");
        assert_eq!(rest, b"irstsecond");
    }

    #[tokio::test]
    async fn test_stream_write() {
        let (data_tx, mut data_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let (_incoming_tx, incoming_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let session_closed = Arc::new(AtomicBool::new(false));

        let mut stream = AnyTlsStream::new(1, incoming_rx, data_tx, session_closed);

        // Write data
        stream.write_all(b"hello").await.unwrap();

        // Verify data was sent to channel
        let (stream_id, data) = data_rx.recv().await.unwrap();
        assert_eq!(stream_id, 1);
        assert_eq!(data.as_ref(), b"hello");
    }

    #[tokio::test]
    async fn test_stream_read() {
        let (data_tx, _data_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let (incoming_tx, incoming_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let session_closed = Arc::new(AtomicBool::new(false));

        let mut stream = AnyTlsStream::new(1, incoming_rx, data_tx, session_closed);

        // Send data to stream
        incoming_tx.send(Bytes::from("world")).await.unwrap();

        // Read data
        let mut buf = vec![0u8; 10];
        let n = stream.read(&mut buf).await.unwrap();

        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"world");
    }

    #[tokio::test]
    async fn test_stream_read_buffering() {
        let (data_tx, _data_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let (incoming_tx, incoming_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let session_closed = Arc::new(AtomicBool::new(false));

        let mut stream = AnyTlsStream::new(1, incoming_rx, data_tx, session_closed);

        // Send larger data
        incoming_tx.send(Bytes::from("hello world")).await.unwrap();

        // Read in small chunks
        let mut buf = vec![0u8; 5];

        let n1 = stream.read(&mut buf).await.unwrap();
        assert_eq!(n1, 5);
        assert_eq!(&buf[..n1], b"hello");

        let n2 = stream.read(&mut buf).await.unwrap();
        assert_eq!(n2, 5);
        assert_eq!(&buf[..n2], b" worl");

        let n3 = stream.read(&mut buf).await.unwrap();
        assert_eq!(n3, 1);
        assert_eq!(&buf[..n3], b"d");
    }

    #[tokio::test]
    async fn test_stream_eof() {
        let (data_tx, _data_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let (incoming_tx, incoming_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let session_closed = Arc::new(AtomicBool::new(false));

        let mut stream = AnyTlsStream::new(1, incoming_rx, data_tx, session_closed);

        // Close the channel
        drop(incoming_tx);

        // Read should return 0 (EOF)
        let mut buf = vec![0u8; 10];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn test_stream_shutdown_sends_fin() {
        let (data_tx, mut data_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let (_incoming_tx, incoming_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let session_closed = Arc::new(AtomicBool::new(false));

        let mut stream = AnyTlsStream::new(42, incoming_rx, data_tx, session_closed);

        // Shutdown the stream
        stream.shutdown().await.unwrap();

        // Should receive empty bytes (FIN signal)
        let (stream_id, data) = data_rx.recv().await.unwrap();
        assert_eq!(stream_id, 42);
        assert!(data.is_empty());
    }

    #[tokio::test]
    async fn test_stream_backpressure() {
        // Create a channel with very small buffer
        let (data_tx, mut data_rx) = mpsc::channel(2);
        let (_incoming_tx, incoming_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let session_closed = Arc::new(AtomicBool::new(false));

        let mut stream = AnyTlsStream::new(1, incoming_rx, data_tx, session_closed);

        // Fill the channel
        stream.write_all(b"msg1").await.unwrap();
        stream.write_all(b"msg2").await.unwrap();

        // Third write should succeed after we drain one
        let write_future = stream.write_all(b"msg3");

        // Drain one message to make room
        let _ = data_rx.recv().await.unwrap();

        // Now the write should complete
        write_future.await.unwrap();

        // Verify remaining messages
        let (_, data) = data_rx.recv().await.unwrap();
        assert_eq!(data.as_ref(), b"msg2");
        let (_, data) = data_rx.recv().await.unwrap();
        assert_eq!(data.as_ref(), b"msg3");
    }

    #[tokio::test]
    async fn test_shutdown_blocks_when_channel_full() {
        // Create a channel with very small buffer (2 slots)
        let (data_tx, mut data_rx) = mpsc::channel(2);
        let (_incoming_tx, incoming_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let session_closed = Arc::new(AtomicBool::new(false));

        let mut stream = AnyTlsStream::new(1, incoming_rx, data_tx, session_closed);

        // Fill the channel with data
        stream.write_all(b"msg1").await.unwrap();
        stream.write_all(b"msg2").await.unwrap();

        // Channel is now full - shutdown should block
        let shutdown_future = stream.shutdown();

        // Drain one message to make room for FIN
        let (_, data1) = data_rx.recv().await.unwrap();
        assert_eq!(data1.as_ref(), b"msg1");

        // Now shutdown should complete
        shutdown_future.await.unwrap();

        // Verify data was received before FIN
        let (_, data2) = data_rx.recv().await.unwrap();
        assert_eq!(data2.as_ref(), b"msg2");

        // FIN should be last (empty bytes)
        let (stream_id, fin) = data_rx.recv().await.unwrap();
        assert_eq!(stream_id, 1);
        assert!(fin.is_empty(), "FIN should be empty bytes");
    }

    #[tokio::test]
    async fn test_shutdown_preserves_data_order() {
        // Verify that data written before shutdown is sent before FIN
        let (data_tx, mut data_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let (_incoming_tx, incoming_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let session_closed = Arc::new(AtomicBool::new(false));

        let mut stream = AnyTlsStream::new(1, incoming_rx, data_tx, session_closed);

        // Write some data
        stream.write_all(b"data1").await.unwrap();
        stream.write_all(b"data2").await.unwrap();
        stream.write_all(b"data3").await.unwrap();

        // Then shutdown
        stream.shutdown().await.unwrap();

        // Verify order: data1, data2, data3, FIN
        let (_, d1) = data_rx.recv().await.unwrap();
        assert_eq!(d1.as_ref(), b"data1");

        let (_, d2) = data_rx.recv().await.unwrap();
        assert_eq!(d2.as_ref(), b"data2");

        let (_, d3) = data_rx.recv().await.unwrap();
        assert_eq!(d3.as_ref(), b"data3");

        let (_, fin) = data_rx.recv().await.unwrap();
        assert!(fin.is_empty(), "FIN should be last and empty");
    }

    #[tokio::test]
    async fn test_write_after_shutdown_fails() {
        let (data_tx, _data_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let (_incoming_tx, incoming_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let session_closed = Arc::new(AtomicBool::new(false));

        let mut stream = AnyTlsStream::new(1, incoming_rx, data_tx, session_closed);

        // Shutdown the stream
        stream.shutdown().await.unwrap();

        // Write after shutdown should fail
        let result = stream.write_all(b"should fail").await;
        assert!(result.is_err());
    }
}
