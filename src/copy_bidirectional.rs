// Forked from tokio's copy.rs and copy_bidirectional.rs.
//
// Changes:
// - Customizable buffer size
// - Read and write whenever there's a space
// - Circular buffer
// - Cooperative yielding via tokio's coop budget to prevent task starvation

use futures::ready;
use tokio::io::ReadBuf;

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::async_stream::AsyncStream;
use crate::util::allocate_vec;

const DEFAULT_BUF_SIZE: usize = 16384;
pub(crate) const MAX_COPY_BYTES_PER_POLL: usize = 1024 * 1024;

#[derive(Debug)]
struct CopyBuffer {
    read_done: bool,
    need_flush: bool,
    need_write_ping: bool,
    start_index: usize,
    cache_length: usize,
    size: usize,
    buf: Box<[u8]>,
}

impl CopyBuffer {
    #[cfg(target_os = "linux")]
    fn can_handoff(&self) -> bool {
        !self.read_done && self.cache_length == 0 && !self.need_flush && !self.need_write_ping
    }

    pub fn new(size: usize, need_initial_flush: bool) -> Self {
        let buf = allocate_vec(size);
        Self {
            read_done: false,
            need_flush: need_initial_flush,
            need_write_ping: false,
            start_index: 0,
            cache_length: 0,
            size,
            buf: buf.into_boxed_slice(),
        }
    }

    pub fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncStream + ?Sized,
        W: AsyncStream + ?Sized,
    {
        let coop = ready!(tokio::task::coop::poll_proceed(cx));
        // Initial output and an unfinished flush remain barriers across polls.
        if self.need_flush {
            ready!(writer.as_mut().poll_flush(cx))?;
            self.need_flush = false;
            coop.made_progress();
        }
        let mut copied = 0;

        loop {
            let mut read_pending = false;
            let mut write_pending = false;

            // Read as much as possible before writing. Some AsyncStream implementations
            // packetize each poll_write call individually, so this reduces the overhead.
            while !self.read_done && self.cache_length < self.size {
                let unused_start_index = (self.start_index + self.cache_length) % self.size;
                let unused_end_index_exclusive = if unused_start_index < self.start_index {
                    self.start_index
                } else {
                    self.size
                };

                let me = &mut *self;
                let mut buf =
                    ReadBuf::new(&mut me.buf[unused_start_index..unused_end_index_exclusive]);
                match reader.as_mut().poll_read(cx, &mut buf) {
                    Poll::Ready(val) => {
                        val?;
                        let n = buf.filled().len();
                        if n == 0 {
                            self.read_done = true;
                        } else {
                            self.cache_length += n;
                            coop.made_progress();
                        }
                    }
                    Poll::Pending => {
                        read_pending = true;
                        break;
                    }
                }
            }

            if self.need_write_ping {
                // if we just read data and we are going to write anyway, no need for a ping
                if self.cache_length == 0 {
                    match writer.as_mut().poll_write_ping(cx) {
                        Poll::Ready(val) => {
                            let written = val?;
                            self.need_write_ping = false;
                            if written {
                                self.need_flush = true;
                                coop.made_progress();
                            }
                        }
                        Poll::Pending => {
                            write_pending = true;
                        }
                    }
                } else {
                    self.need_write_ping = false;
                }
            }

            // If our buffer has some data, let's write it out!
            // Loop and try to write out as much as possible to minimize forwarding
            // latency, and so that we increase the chance we have an optimal read
            // with start_index at zero.
            while self.cache_length > 0 {
                let used_start_index = self.start_index;
                let used_end_index_exclusive =
                    (self.start_index + self.cache_length).min(self.size);

                let me = &mut *self;
                match writer
                    .as_mut()
                    .poll_write(cx, &me.buf[used_start_index..used_end_index_exclusive])
                {
                    Poll::Ready(val) => {
                        let written = val?;
                        if written == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "write zero byte into writer",
                            )));
                        } else {
                            copied += written;
                            self.cache_length -= written;
                            if self.cache_length == 0 {
                                self.start_index = 0;
                            } else {
                                self.start_index = (self.start_index + written) % self.size;
                            }
                            self.need_flush = true;
                            coop.made_progress();
                        }
                    }
                    Poll::Pending => {
                        write_pending = true;
                        break;
                    }
                }
            }

            // Complete the current chunk rather than splitting a protocol-sized record.
            let quota_reached = copied >= MAX_COPY_BYTES_PER_POLL;
            if self.need_flush && (read_pending || write_pending || self.read_done || quota_reached)
            {
                ready!(writer.as_mut().poll_flush(cx))?;
                self.need_flush = false;
                coop.made_progress();
            }

            // If we've written all the data and we've seen EOF, finish the transfer.
            if self.read_done && self.cache_length == 0 {
                return Poll::Ready(Ok(()));
            }

            // Return Pending to prevent task starvation
            if read_pending || write_pending {
                return Poll::Pending;
            }
            if quota_reached {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
    }
}

enum TransferState {
    Running,
    ShuttingDown(Pin<Box<tokio::time::Sleep>>),
    Done,
}

enum CopyOutcome {
    Complete,
    #[cfg(target_os = "linux")]
    Splice,
}

struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_buf: CopyBuffer,
    b_buf: CopyBuffer,
    a_to_b: TransferState,
    b_to_a: TransferState,
    sleep_future: Option<Pin<Box<tokio::time::Sleep>>>,
    #[cfg(target_os = "linux")]
    allow_splice: bool,
}

impl<'a, A: AsyncStream + ?Sized, B: AsyncStream + ?Sized> CopyBidirectional<'a, A, B> {
    fn new(
        a: &'a mut A,
        b: &'a mut B,
        a_need_initial_flush: bool,
        b_need_initial_flush: bool,
        a_to_b_buf_size: usize,
        b_to_a_buf_size: usize,
    ) -> Self {
        let sleep_future = if a.supports_ping() || b.supports_ping() {
            Some(Box::pin(tokio::time::sleep(
                std::time::Duration::from_secs(60),
            )))
        } else {
            None
        };

        let a_to_b_buf_size = copy_buffer_size(a_to_b_buf_size, b);
        let b_to_a_buf_size = copy_buffer_size(b_to_a_buf_size, a);
        Self {
            a,
            b,
            // Each buffer's flush obligation belongs to its writer, not its reader.
            a_buf: CopyBuffer::new(a_to_b_buf_size, b_need_initial_flush),
            b_buf: CopyBuffer::new(b_to_a_buf_size, a_need_initial_flush),
            a_to_b: TransferState::Running,
            b_to_a: TransferState::Running,
            sleep_future,
            #[cfg(target_os = "linux")]
            allow_splice: false,
        }
    }
}

fn transfer_one_direction<A, B>(
    cx: &mut Context<'_>,
    state: &mut TransferState,
    buf: &mut CopyBuffer,
    r: &mut A,
    w: &mut B,
) -> Poll<io::Result<()>>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    let mut r = Pin::new(r);
    let mut w = Pin::new(w);

    loop {
        match state {
            TransferState::Running => {
                ready!(buf.poll_copy(cx, r.as_mut(), w.as_mut()))?;
                *state = TransferState::ShuttingDown(Box::pin(tokio::time::sleep(
                    crate::util::SHUTDOWN_TIMEOUT,
                )));
            }
            TransferState::ShuttingDown(deadline) => match w.as_mut().poll_shutdown(cx) {
                Poll::Ready(result) => {
                    result?;
                    *state = TransferState::Done;
                }
                Poll::Pending => {
                    ready!(deadline.as_mut().poll(cx));
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "stream shutdown timed out",
                    )));
                }
            },
            TransferState::Done => return Poll::Ready(Ok(())),
        }
    }
}

impl<A, B> Future for CopyBidirectional<'_, A, B>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    type Output = io::Result<CopyOutcome>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let CopyBidirectional {
            a,
            b,
            a_buf,
            b_buf,
            a_to_b,
            b_to_a,
            sleep_future,
            #[cfg(target_os = "linux")]
            allow_splice,
        } = &mut *self;

        if let Some(sleep) = sleep_future {
            let ping_fired = sleep.as_mut().poll(cx).is_ready();
            if ping_fired {
                // a_buf writes to b - so we need to check if b supports ping, and similarly
                // for b_buf.
                a_buf.need_write_ping = b.supports_ping();
                b_buf.need_write_ping = a.supports_ping();
                sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + std::time::Duration::from_secs(60));
            }
        }

        let a_result = transfer_one_direction(cx, a_to_b, &mut *a_buf, &mut *a, &mut *b);
        let b_result = transfer_one_direction(cx, b_to_a, &mut *b_buf, &mut *b, &mut *a);

        match (a_result, b_result) {
            (Poll::Ready(Err(e)), _) | (_, Poll::Ready(Err(e))) => return Poll::Ready(Err(e)),
            (Poll::Ready(Ok(())), Poll::Ready(Ok(()))) => {
                return Poll::Ready(Ok(CopyOutcome::Complete));
            }
            _ => {}
        }

        // A final transition read/flush can return Pending without another
        // packet to wake us. Recheck after both directions have been polled.
        #[cfg(target_os = "linux")]
        if *allow_splice
            && matches!(a_to_b, TransferState::Running)
            && matches!(b_to_a, TransferState::Running)
            && a_buf.can_handoff()
            && b_buf.can_handoff()
            && !a.supports_ping()
            && !b.supports_ping()
            && a.plain_tcp().is_some()
            && b.plain_tcp().is_some()
        {
            return Poll::Ready(Ok(CopyOutcome::Splice));
        }
        Poll::Pending
    }
}

/// Copies data in both directions between `a` and `b`.
///
/// This function returns a future that will read from both streams,
/// writing any data read to the opposing stream.
/// This happens in both directions concurrently.
///
/// If an EOF is observed on one stream, [`shutdown()`] will be invoked on
/// the other, and reading from that stream will stop. Copying of data in
/// the other direction will continue.
///
/// The future will complete successfully once both directions of communication has been shut down.
/// A direction is shut down when the reader reports EOF,
/// at which point [`shutdown()`] is called on the corresponding writer.
/// Each shutdown has a five-second deadline; an active read direction has no lifetime limit.
///
/// [`shutdown()`]: tokio::io::AsyncWriteExt::shutdown
///
/// # Errors
///
/// The future will immediately return an error if any IO operation on `a`
/// or `b` returns an error. Some data read from either stream may be lost (not
/// written to the other stream) in this case.
///
pub async fn copy_bidirectional<A, B>(
    a: &mut A,
    b: &mut B,
    a_need_initial_flush: bool,
    b_need_initial_flush: bool,
) -> io::Result<()>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    #[cfg(target_os = "linux")]
    if let (Some(a), Some(b)) = (a.plain_tcp(), b.plain_tcp()) {
        // Raw Tokio sockets have no userspace output to flush.
        return crate::splice::copy_bidirectional(a, b).await;
    }

    let copy = CopyBidirectional::new(
        a,
        b,
        a_need_initial_flush,
        b_need_initial_flush,
        DEFAULT_BUF_SIZE,
        DEFAULT_BUF_SIZE,
    );
    #[cfg(target_os = "linux")]
    let copy = CopyBidirectional {
        allow_splice: true,
        ..copy
    };
    match copy.await? {
        CopyOutcome::Complete => Ok(()),
        #[cfg(target_os = "linux")]
        CopyOutcome::Splice => {
            // The buffered stage may have exhausted its byte quota in this poll.
            tokio::task::yield_now().await;
            crate::splice::copy_bidirectional(
                a.plain_tcp().expect("raw stream after handoff"),
                b.plain_tcp().expect("raw stream after handoff"),
            )
            .await
        }
    }
}

/// Copies data in both directions between `a` and `b` using buffers of the specified size.
///
/// This method is the same as the [`copy_bidirectional()`], except that it allows you to set the
/// size of the internal buffers used when copying data.
/// This path always uses buffered copying, including after protocol transitions.
pub async fn copy_bidirectional_with_sizes<A, B>(
    a: &mut A,
    b: &mut B,
    a_need_initial_flush: bool,
    b_need_initial_flush: bool,
    a_to_b_buf_size: usize,
    b_to_a_buf_size: usize,
) -> io::Result<()>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    CopyBidirectional::new(
        a,
        b,
        a_need_initial_flush,
        b_need_initial_flush,
        a_to_b_buf_size,
        b_to_a_buf_size,
    )
    .await
    .map(|_| ())
}

fn copy_buffer_size(requested: usize, writer: &(impl AsyncStream + ?Sized)) -> usize {
    match writer.preferred_write_size() {
        Some(preferred) => requested.min(preferred.get()),
        None => requested,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::async_stream::AsyncPing;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    #[cfg(target_os = "linux")]
    #[test]
    fn handoff_requires_empty_open_buffers_without_flush_or_ping_debt() {
        let mut buffer = CopyBuffer::new(16, true);
        assert!(!buffer.can_handoff());
        buffer.need_flush = false;
        assert!(buffer.can_handoff());
        buffer.cache_length = 1;
        assert!(!buffer.can_handoff());
        buffer.cache_length = 0;
        buffer.need_write_ping = true;
        assert!(!buffer.can_handoff());
        buffer.need_write_ping = false;
        buffer.read_done = true;
        assert!(!buffer.can_handoff());
    }

    #[derive(Default)]
    pub(crate) struct Capture {
        pub(crate) data: Vec<u8>,
        pub(crate) first_write_offer: Vec<u8>,
        pub(crate) bytes_before_shutdown: usize,
        writes: Vec<usize>,
        flushes: usize,
        write_release: Option<tokio::sync::oneshot::Receiver<()>>,
        flush_release: Option<tokio::sync::oneshot::Receiver<()>>,
    }

    #[derive(Default)]
    struct MemoryStream {
        input: std::io::Cursor<Vec<u8>>,
        output: Arc<Mutex<Capture>>,
        block_flush: bool,
        pending_at_eof: bool,
        write_limit: Option<usize>,
        write_flush_release: Option<tokio::sync::oneshot::Receiver<()>>,
    }

    impl AsyncRead for MemoryStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.pending_at_eof && self.input.position() as usize == self.input.get_ref().len() {
                return Poll::Pending;
            }
            Pin::new(&mut self.input).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for MemoryStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            let already_written = !self.output.lock().unwrap().data.is_empty();
            if already_written && let Some(release) = &mut self.write_flush_release {
                ready!(Pin::new(release).poll(cx)).unwrap();
                self.write_flush_release = None;
            }
            let mut output = self.output.lock().unwrap();
            if already_written && let Some(release) = &mut output.write_release {
                ready!(Pin::new(release).poll(cx)).unwrap();
                output.write_release = None;
            }
            if output.first_write_offer.is_empty() {
                output.first_write_offer.extend_from_slice(data);
            }
            let data = &data[..data.len().min(self.write_limit.unwrap_or(usize::MAX))];
            output.data.extend_from_slice(data);
            output.writes.push(data.len());
            Poll::Ready(Ok(data.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if let Some(release) = &mut self.write_flush_release {
                ready!(Pin::new(release).poll(cx)).unwrap();
                self.write_flush_release = None;
            }
            if self.block_flush {
                return Poll::Pending;
            }
            let mut output = self.output.lock().unwrap();
            if let Some(release) = &mut output.flush_release {
                ready!(Pin::new(release).poll(cx)).unwrap();
                output.flush_release = None;
            }
            output.flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for MemoryStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for MemoryStream {}

    struct WakeCount(AtomicUsize);

    impl std::task::Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn quota_test_payload() -> Vec<u8> {
        let quota = MAX_COPY_BYTES_PER_POLL;
        let payload: Vec<u8> = (0..2 * quota + 37)
            .map(|i| (i ^ (i >> 8) ^ (i >> 16)) as u8)
            .collect();
        assert!(payload[..quota] != payload[quota..2 * quota]);
        payload
    }

    pub(crate) async fn copy_response_with_flush_pressure<W, F>(
        make_writer: impl FnOnce(Box<dyn AsyncStream>) -> F,
        payload: &[u8],
    ) -> Capture
    where
        W: AsyncStream,
        F: Future<Output = W>,
    {
        let (write_release, blocked_write) = tokio::sync::oneshot::channel();
        let sink = MemoryStream {
            write_limit: Some(7),
            ..Default::default()
        };
        let capture = sink.output.clone();
        capture.lock().unwrap().write_release = Some(blocked_write);
        let mut writer = make_writer(Box::new(sink)).await;
        let mut reader = MemoryStream {
            pending_at_eof: true,
            ..Default::default()
        };
        let mut buffer = CopyBuffer::new(copy_buffer_size(DEFAULT_BUF_SIZE, &writer), true);
        let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = std::task::Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);

        // Models an outer TLS handshake flush before any response body is available.
        let (initial_release, blocked_initial_flush) = tokio::sync::oneshot::channel();
        capture.lock().unwrap().flush_release = Some(blocked_initial_flush);
        for _ in 0..2 {
            assert!(
                buffer
                    .poll_copy(&mut cx, Pin::new(&mut reader), Pin::new(&mut writer))
                    .is_pending()
            );
            assert!(capture.lock().unwrap().data.is_empty());
        }
        assert_eq!(wakes.0.load(Ordering::Relaxed), 0);
        initial_release.send(()).unwrap();
        assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
        assert!(
            buffer
                .poll_copy(&mut cx, Pin::new(&mut reader), Pin::new(&mut writer))
                .is_pending()
        );
        assert!(!buffer.need_flush);
        for _ in 0..2 {
            writer.flush().await.unwrap();
            assert!(capture.lock().unwrap().data.is_empty());
        }

        reader.input = std::io::Cursor::new(payload.to_vec());
        if !payload.is_empty() {
            assert!(
                buffer
                    .poll_copy(&mut cx, Pin::new(&mut reader), Pin::new(&mut writer))
                    .is_pending()
            );
            assert_eq!(capture.lock().unwrap().data.len(), 7);
            assert!(buffer.need_flush);
            let position = reader.input.position();

            let (flush_release, blocked_flush) = tokio::sync::oneshot::channel();
            capture.lock().unwrap().flush_release = Some(blocked_flush);
            write_release.send(()).unwrap();
            for _ in 0..2 {
                assert!(
                    buffer
                        .poll_copy(&mut cx, Pin::new(&mut reader), Pin::new(&mut writer))
                        .is_pending()
                );
                assert_eq!(reader.input.position(), position);
                assert!(buffer.need_flush);
            }
            // Only poll_flush can register this wake; the write gate is already open.
            wakes.0.store(0, Ordering::Relaxed);
            flush_release.send(()).unwrap();
            assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
        } else {
            write_release.send(()).unwrap();
        }
        let mut quota_yields = 0;
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            std::future::poll_fn(|cx| {
                let result = buffer.poll_copy(cx, Pin::new(&mut reader), Pin::new(&mut writer));
                assert!(result.is_pending(), "copy did not suspend: {result:?}");
                if buffer.cache_length > 0 || buffer.need_flush {
                    return Poll::Pending;
                }
                if reader.input.position() as usize == payload.len() {
                    return Poll::Ready(());
                }
                quota_yields += 1;
                Poll::Pending
            }),
        )
        .await
        .expect("copier did not resume after quota or flush pressure");
        if payload.len() > 2 * MAX_COPY_BYTES_PER_POLL {
            assert!(quota_yields > 0);
        }

        {
            let mut output = capture.lock().unwrap();
            output.bytes_before_shutdown = output.data.len();
        }
        reader.pending_at_eof = false;
        let mut state = TransferState::Running;
        std::future::poll_fn(|cx| {
            transfer_one_direction(cx, &mut state, &mut buffer, &mut reader, &mut writer)
        })
        .await
        .unwrap();
        let wire_len = capture.lock().unwrap().data.len();
        writer.flush().await.unwrap();
        assert_eq!(capture.lock().unwrap().data.len(), wire_len);
        std::mem::take(&mut *capture.lock().unwrap())
    }

    #[tokio::test]
    async fn ready_copy_batches_flushes_and_yields_at_a_byte_quota() {
        let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = std::task::Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        let payload = vec![42; MAX_COPY_BYTES_PER_POLL * 4];
        let mut reader = MemoryStream {
            input: std::io::Cursor::new(payload.clone()),
            ..Default::default()
        };
        let mut writer = MemoryStream {
            write_limit: Some(1023),
            ..Default::default()
        };
        let mut buffer = CopyBuffer::new(DEFAULT_BUF_SIZE, false);
        assert!(
            buffer
                .poll_copy(&mut cx, Pin::new(&mut reader), Pin::new(&mut writer))
                .is_pending()
        );
        assert_eq!(
            writer.output.lock().unwrap().data.len(),
            MAX_COPY_BYTES_PER_POLL
        );
        assert_eq!(writer.output.lock().unwrap().flushes, 1);
        assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
        std::future::poll_fn(|cx| {
            buffer.poll_copy(cx, Pin::new(&mut reader), Pin::new(&mut writer))
        })
        .await
        .unwrap();
        let output = writer.output.lock().unwrap();
        assert_eq!(output.data, payload);
        assert_eq!(output.flushes, 4);
    }

    #[tokio::test]
    async fn write_pressure_resumes_after_a_pending_flush_wakes() {
        let payload: Vec<u8> = (0..128).collect();
        let mut reader = MemoryStream {
            input: std::io::Cursor::new(payload.clone()),
            ..Default::default()
        };
        let (release, blocked) = tokio::sync::oneshot::channel();
        let mut writer = MemoryStream {
            write_limit: Some(7),
            write_flush_release: Some(blocked),
            ..Default::default()
        };
        let mut buffer = CopyBuffer::new(32, false);
        let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = std::task::Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        for _ in 0..2 {
            assert!(
                buffer
                    .poll_copy(&mut cx, Pin::new(&mut reader), Pin::new(&mut writer))
                    .is_pending()
            );
            assert_eq!(reader.input.position(), 32);
            assert_eq!(writer.output.lock().unwrap().data, payload[..7]);
            assert!(buffer.need_flush);
        }
        assert_eq!(wakes.0.load(Ordering::Relaxed), 0);
        release.send(()).unwrap();
        assert_eq!(wakes.0.load(Ordering::Relaxed), 1);

        std::future::poll_fn(|cx| {
            buffer.poll_copy(cx, Pin::new(&mut reader), Pin::new(&mut writer))
        })
        .await
        .unwrap();
        let output = writer.output.lock().unwrap();
        assert_eq!(output.data, payload);
        assert_eq!(output.flushes, 2);
        assert!(!buffer.need_flush);
    }

    #[test]
    fn initial_and_pending_flushes_are_write_barriers() {
        let mut reader = MemoryStream {
            input: std::io::Cursor::new(vec![1; MAX_COPY_BYTES_PER_POLL * 2]),
            ..Default::default()
        };
        let mut writer = MemoryStream {
            block_flush: true,
            ..Default::default()
        };
        let mut buffer = CopyBuffer::new(DEFAULT_BUF_SIZE, true);
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(
            buffer
                .poll_copy(&mut cx, Pin::new(&mut reader), Pin::new(&mut writer))
                .is_pending()
        );
        assert_eq!(reader.input.position(), 0);
        writer.block_flush = false;
        assert!(
            buffer
                .poll_copy(&mut cx, Pin::new(&mut reader), Pin::new(&mut writer))
                .is_pending()
        );
        assert_eq!(reader.input.position() as usize, MAX_COPY_BYTES_PER_POLL);
        writer.block_flush = true;
        assert!(
            buffer
                .poll_copy(&mut cx, Pin::new(&mut reader), Pin::new(&mut writer))
                .is_pending()
        );
        let position = reader.input.position();
        assert!(
            buffer
                .poll_copy(&mut cx, Pin::new(&mut reader), Pin::new(&mut writer))
                .is_pending()
        );
        assert_eq!(reader.input.position(), position);
        writer.block_flush = false;
        assert!(matches!(
            buffer.poll_copy(&mut cx, Pin::new(&mut reader), Pin::new(&mut writer)),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(
            writer.output.lock().unwrap().data.len(),
            MAX_COPY_BYTES_PER_POLL * 2
        );
    }

    #[test]
    fn sparse_input_is_flushed_without_waiting_for_a_full_batch() {
        let mut reader = MemoryStream {
            input: std::io::Cursor::new(b"interactive".to_vec()),
            pending_at_eof: true,
            ..Default::default()
        };
        let mut writer = MemoryStream::default();
        let mut buffer = CopyBuffer::new(DEFAULT_BUF_SIZE, false);
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(
            buffer
                .poll_copy(&mut cx, Pin::new(&mut reader), Pin::new(&mut writer))
                .is_pending()
        );
        let output = writer.output.lock().unwrap();
        assert_eq!(output.data, b"interactive");
        assert_eq!(output.flushes, 1);
    }

    #[tokio::test]
    async fn legacy_shadowsocks_copy_avoids_one_byte_records() {
        use crate::shadowsocks::{
            DefaultKey, ShadowsocksKey, ShadowsocksStream, ShadowsocksStreamType,
        };

        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(DefaultKey::new("test", 32)));
        let encrypted = |stream: MemoryStream| {
            ShadowsocksStream::new(
                Box::new(stream),
                ShadowsocksStreamType::Aead,
                &aws_lc_rs::aead::AES_256_GCM,
                32,
                key.clone(),
                None,
            )
        };
        let payload: Vec<u8> = (0..1024 * 1024).map(|i| (i ^ (i >> 8)) as u8).collect();
        let sink = MemoryStream::default();
        let capture = sink.output.clone();
        let mut writer: Box<dyn AsyncStream> = Box::new(encrypted(sink));
        writer.write_all(b"warm").await.unwrap();
        writer.flush().await.unwrap();
        capture.lock().unwrap().writes.clear();
        let mut writer = crate::prepend_stream::PrependStream::new(&mut writer, None);
        assert_eq!(copy_buffer_size(16384, &writer), 16383);
        assert_eq!(copy_buffer_size(1024, &writer), 1024);
        assert_eq!(copy_buffer_size(16384, &MemoryStream::default()), 16384);

        let mut source = MemoryStream {
            input: std::io::Cursor::new(payload.clone()),
            ..Default::default()
        };
        copy_bidirectional(&mut source, &mut writer, false, false)
            .await
            .unwrap();
        let wire = {
            let captured = capture.lock().unwrap();
            assert_eq!(captured.writes.len(), 65);
            assert!(!captured.writes.contains(&35));
            captured.data.clone()
        };
        let mut reader = encrypted(MemoryStream {
            input: std::io::Cursor::new(wire),
            ..Default::default()
        });
        let mut decoded = Vec::new();
        reader.read_to_end(&mut decoded).await.unwrap();
        assert_eq!(&decoded[..4], b"warm");
        assert_eq!(&decoded[4..], payload);
    }

    struct StalledShutdown;

    impl AsyncRead for StalledShutdown {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for StalledShutdown {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(data.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
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
    async fn stalled_shutdown_and_error_cleanup_have_deadlines() {
        let start = tokio::time::Instant::now();
        let error = copy_bidirectional(&mut StalledShutdown, &mut StalledShutdown, false, false)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(start.elapsed(), crate::util::SHUTDOWN_TIMEOUT);
        let start = tokio::time::Instant::now();
        crate::util::shutdown_stream(&mut StalledShutdown).await;
        assert_eq!(start.elapsed(), crate::util::SHUTDOWN_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn half_close_does_not_limit_response_lifetime() {
        let (mut client, mut downstream) = tokio::io::duplex(64);
        let (mut upstream, mut server) = tokio::io::duplex(64);
        let copy = tokio::spawn(async move {
            copy_bidirectional(&mut downstream, &mut upstream, false, false).await
        });
        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();
        let mut request = Vec::new();
        server.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");
        tokio::time::advance(std::time::Duration::from_secs(300)).await;
        assert!(!copy.is_finished());
        server.write_all(b"response").await.unwrap();
        server.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"response");
        copy.await.unwrap().unwrap();
    }
}
