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
    let a_flow = a.flow().cloned();
    let b_flow = b.flow().cloned();
    crate::control::tracked_stream::during_flows(
        a_flow.as_deref(),
        b_flow.as_deref(),
        copy_bidirectional_inner(a, b, a_need_initial_flush, b_need_initial_flush),
    )
    .await
}

async fn copy_bidirectional_inner<A: AsyncStream + ?Sized, B: AsyncStream + ?Sized>(
    a: &mut A,
    b: &mut B,
    a_need_initial_flush: bool,
    b_need_initial_flush: bool,
) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    if let (Some(a_tcp), Some(b_tcp)) = (a.plain_tcp(), b.plain_tcp()) {
        // Raw Tokio sockets have no userspace output to flush.
        return crate::splice::copy_bidirectional_tracked(
            a_tcp,
            b_tcp,
            a.flow().map(AsRef::as_ref),
            b.flow().map(AsRef::as_ref),
        )
        .await;
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
            crate::splice::copy_bidirectional_tracked(
                a.plain_tcp().expect("raw stream after handoff"),
                b.plain_tcp().expect("raw stream after handoff"),
                a.flow().map(AsRef::as_ref),
                b.flow().map(AsRef::as_ref),
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
    let a_flow = a.flow().cloned();
    let b_flow = b.flow().cloned();
    let copy = CopyBidirectional::new(
        a,
        b,
        a_need_initial_flush,
        b_need_initial_flush,
        a_to_b_buf_size,
        b_to_a_buf_size,
    );
    crate::control::tracked_stream::during_flows(a_flow.as_deref(), b_flow.as_deref(), copy)
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
pub(crate) mod tests;
