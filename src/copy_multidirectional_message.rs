use futures::ready;
use tokio::io::ReadBuf;

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use crate::address::NetLocation;
use crate::async_stream::{AsyncSourcedMessageStream, AsyncTargetedMessageStream};

// Informed by https://stackoverflow.com/questions/14856639/udp-hole-punching-timeout
pub const DEFAULT_ASSOCIATION_TIMEOUT_SECS: u32 = 200;

#[derive(Debug)]
struct CopyProxyBuffer {
    read_done: bool,
    need_flush: bool,
    need_write_ping: bool,
    cache_length: usize,
    buf: [u8; 65535],
    target: NetLocation,
    read_count: usize,
    write_count: usize,
}

impl CopyProxyBuffer {
    pub fn new(need_flush: bool) -> Self {
        Self {
            read_done: false,
            need_flush,
            need_write_ping: false,
            cache_length: 0,
            buf: [0u8; 65535],
            target: NetLocation::UNSPECIFIED,
            read_count: 0,
            write_count: 0,
        }
    }

    pub fn poll_copy_targeted_messages<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncTargetedMessageStream + ?Sized,
        W: AsyncSourcedMessageStream + ?Sized,
    {
        loop {
            // Make sure we flush any existing messages first.
            // We don't want to read fast else bandwidth estimators will think we are able
            // to handle all the messages and start sending even better quality.
            //if self.need_flush {
            //ready!(writer.as_mut().poll_flush_message(cx))?;
            //self.need_flush = false;
            //}

            let mut did_read = false;
            let mut did_write = false;
            let mut read_pending = false;
            let mut write_pending = false;

            if !self.read_done && self.cache_length == 0 {
                let me = &mut *self;
                let mut buf = ReadBuf::new(&mut me.buf);
                match reader.as_mut().poll_read_targeted_message(cx, &mut buf) {
                    Poll::Ready(val) => {
                        let target = val?;
                        let n = buf.filled().len();
                        if n == 0 {
                            self.read_done = true;
                        } else {
                            self.target = target;
                            self.cache_length = n;
                            did_read = true;
                            self.read_count = self.read_count.wrapping_add(n);
                        }
                    }
                    Poll::Pending => {
                        read_pending = true;
                    }
                }
            }

            if self.cache_length > 0 {
                let me = &mut *self;
                match writer.as_mut().poll_write_targeted_message(
                    cx,
                    &me.buf[0..me.cache_length],
                    &me.target,
                ) {
                    Poll::Ready(val) => {
                        // TODO: check that n == cache length
                        val?;
                        self.write_count = self.write_count.wrapping_add(1);
                        self.cache_length = 0;
                        self.need_flush = true;
                        // Don't bother writing ping, since we just wrote.
                        self.need_write_ping = false;
                        did_write = true;
                    }
                    Poll::Pending => {
                        write_pending = true;
                    }
                }
            }

            if !write_pending && self.need_write_ping {
                match writer.as_mut().poll_write_ping(cx) {
                    Poll::Ready(val) => {
                        let written = val?;
                        self.need_write_ping = false;
                        if written {
                            self.need_flush = true;
                        }
                    }
                    Poll::Pending => {
                        write_pending = true;
                    }
                }
            }

            if did_read && did_write && !read_pending && !write_pending {
                continue;
            }

            if self.need_flush {
                ready!(writer.as_mut().poll_flush_message(cx))?;
                self.need_flush = false;
                continue;
            }

            // If we've written all the data and we've seen EOF, finish the transfer.
            if self.read_done && self.cache_length == 0 {
                return Poll::Ready(Ok(()));
            }

            // Previously we kept going until both read and write were pending, but
            // this might starve other tasks.
            if read_pending || write_pending {
                // If we got here,
                // 1) we hit read_pending on the current iteration.
                // 2) all data has been written successfully
                // 3) there is no data left to write and we need to read more.
                return Poll::Pending;
            }
        }
    }
}

#[derive(Debug)]
struct CopyManyBuffer {
    read_done: bool,
    need_flush: bool,
    need_write_ping: bool,
    cache_length: usize,
    buf: [u8; 65535],
    source: SocketAddr,
    read_count: usize,
    write_count: usize,
}

impl CopyManyBuffer {
    pub fn new(need_flush: bool) -> Self {
        Self {
            read_done: false,
            need_flush,
            need_write_ping: false,
            cache_length: 0,
            buf: [0u8; 65535],
            source: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            read_count: 0,
            write_count: 0,
        }
    }

    pub fn poll_copy_sourced_messages<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncSourcedMessageStream + ?Sized,
        W: AsyncTargetedMessageStream + ?Sized,
    {
        loop {
            // Make sure we flush any existing messages first.
            // We don't want to read fast else bandwidth estimators will think we are able
            // to handle all the messages and start sending even better quality.
            //if self.need_flush {
            //ready!(writer.as_mut().poll_flush_message(cx))?;
            //self.need_flush = false;
            //}

            let mut did_read = false;
            let mut did_write = false;
            let mut read_pending = false;
            let mut write_pending = false;

            if !self.read_done && self.cache_length == 0 {
                let me = &mut *self;
                let mut buf = ReadBuf::new(&mut me.buf);
                match reader.as_mut().poll_read_sourced_message(cx, &mut buf) {
                    Poll::Ready(val) => {
                        let source = val?;
                        let n = buf.filled().len();
                        if n == 0 {
                            self.read_done = true;
                        } else {
                            self.source = source;
                            self.cache_length = n;
                            did_read = true;
                            self.read_count = self.read_count.wrapping_add(n);
                        }
                    }
                    Poll::Pending => {
                        read_pending = true;
                    }
                }
            }

            if self.cache_length > 0 {
                let me = &mut *self;
                match writer.as_mut().poll_write_sourced_message(
                    cx,
                    &me.buf[0..me.cache_length],
                    &me.source,
                ) {
                    Poll::Ready(val) => {
                        val?;
                        self.write_count = self.write_count.wrapping_add(1);
                        self.cache_length = 0;
                        self.need_flush = true;
                        // Don't bother writing ping, since we just wrote.
                        self.need_write_ping = false;
                        did_write = true;
                    }
                    Poll::Pending => {
                        write_pending = true;
                    }
                }
            }

            if !write_pending && self.need_write_ping {
                match writer.as_mut().poll_write_ping(cx) {
                    Poll::Ready(val) => {
                        let written = val?;
                        self.need_write_ping = false;
                        if written {
                            self.need_flush = true;
                        }
                    }
                    Poll::Pending => {
                        write_pending = true;
                    }
                }
            }

            if did_read && did_write && !read_pending && !write_pending {
                continue;
            }

            if self.need_flush {
                ready!(writer.as_mut().poll_flush_message(cx))?;
                self.need_flush = false;
                continue;
            }

            // If we've written all the data and we've seen EOF, finish the transfer.
            if self.read_done && self.cache_length == 0 {
                return Poll::Ready(Ok(()));
            }

            // Previously we kept going until both read and write were pending, but
            // this might starve other tasks.
            if read_pending || write_pending {
                // If we got here,
                // 1) we hit read_pending on the current iteration.
                // 2) all data has been written successfully
                // 3) there is no data left to write and we need to read more.
                return Poll::Pending;
            }
        }
    }
}

enum TransferState {
    Running,
    ShuttingDown,
    Done,
}

struct CopyMultidirectional<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_buf: CopyProxyBuffer,
    b_buf: CopyManyBuffer,
    a_to_b: TransferState,
    b_to_a: TransferState,
    sleep_future: Pin<Box<tokio::time::Sleep>>,
    a_last_active: Instant,
    b_last_active: Instant,
}

fn transfer_targeted_messages<A, B>(
    cx: &mut Context<'_>,
    state: &mut TransferState,
    buf: &mut CopyProxyBuffer,
    r: &mut A,
    w: &mut B,
) -> Poll<io::Result<()>>
where
    A: AsyncTargetedMessageStream + ?Sized,
    B: AsyncSourcedMessageStream + ?Sized,
{
    let mut r = Pin::new(r);
    let mut w = Pin::new(w);

    loop {
        match state {
            TransferState::Running => {
                ready!(buf.poll_copy_targeted_messages(cx, r.as_mut(), w.as_mut()))?;
                *state = TransferState::ShuttingDown;
            }
            TransferState::ShuttingDown => {
                ready!(w.as_mut().poll_shutdown_message(cx))?;
                *state = TransferState::Done;
            }
            TransferState::Done => return Poll::Ready(Ok(())),
        }
    }
}

fn transfer_sourced_messages<A, B>(
    cx: &mut Context<'_>,
    state: &mut TransferState,
    buf: &mut CopyManyBuffer,
    r: &mut A,
    w: &mut B,
) -> Poll<io::Result<()>>
where
    A: AsyncSourcedMessageStream + ?Sized,
    B: AsyncTargetedMessageStream + ?Sized,
{
    let mut r = Pin::new(r);
    let mut w = Pin::new(w);

    loop {
        match state {
            TransferState::Running => {
                ready!(buf.poll_copy_sourced_messages(cx, r.as_mut(), w.as_mut()))?;
                *state = TransferState::ShuttingDown;
            }
            TransferState::ShuttingDown => {
                ready!(w.as_mut().poll_shutdown_message(cx))?;
                *state = TransferState::Done;
            }
            TransferState::Done => return Poll::Ready(Ok(())),
        }
    }
}

impl<'a, A, B> Future for CopyMultidirectional<'a, A, B>
where
    A: AsyncTargetedMessageStream + ?Sized,
    B: AsyncSourcedMessageStream + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Unpack self into mut refs to each field to avoid borrow check issues.
        let CopyMultidirectional {
            a,
            b,
            a_buf,
            b_buf,
            a_to_b,
            b_to_a,
            sleep_future,
            a_last_active,
            b_last_active,
        } = &mut *self;

        let ping_fired = sleep_future.as_mut().poll(cx).is_ready();
        if ping_fired {
            // a_buf writes to b - so we need to check if b supports ping, and similarly
            // for b_buf.
            a_buf.need_write_ping = b.supports_ping();
            b_buf.need_write_ping = a.supports_ping();
            sleep_future
                .as_mut()
                .reset(tokio::time::Instant::now() + std::time::Duration::from_secs(60));
        }

        let a_read_count = a_buf.read_count;
        let a_write_count = a_buf.write_count;
        let b_read_count = b_buf.read_count;
        let b_write_count = b_buf.write_count;

        let a_to_b = transfer_targeted_messages(cx, a_to_b, &mut *a_buf, &mut *a, &mut *b);
        let b_to_a = transfer_sourced_messages(cx, b_to_a, &mut *b_buf, &mut *b, &mut *a);

        if a_buf.read_count != a_read_count || a_buf.write_count != a_write_count {
            *a_last_active = Instant::now();
        } else if a_last_active.elapsed().as_secs() >= DEFAULT_ASSOCIATION_TIMEOUT_SECS.into() {
            return Poll::Ready(Ok(()));
        }

        if b_buf.read_count != b_read_count || b_buf.write_count != b_write_count {
            *b_last_active = Instant::now();
        } else if b_last_active.elapsed().as_secs() >= DEFAULT_ASSOCIATION_TIMEOUT_SECS.into() {
            return Poll::Ready(Ok(()));
        }

        if a_to_b.is_ready() {
            return a_to_b;
        } else if b_to_a.is_ready() {
            return b_to_a;
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
/// at which point [`shutdown()`] is called on the corresponding writer. When finished,
/// it will return a tuple of the number of bytes copied from a to b
/// and the number of bytes copied from b to a, in that order.
///
/// [`shutdown()`]: crate::io::AsyncWriteExt::shutdown
///
/// # Errors
///
/// The future will immediately return an error if any IO operation on `a`
/// or `b` returns an error. Some data read from either stream may be lost (not
/// written to the other stream) in this case.
///
/// # Return value
///
/// Returns a tuple of bytes copied `a` to `b` and bytes copied `b` to `a`.
pub async fn copy_multidirectional_message<A, B>(
    a: &mut A,
    b: &mut B,
    a_initial_flush: bool,
    b_initial_flush: bool,
) -> Result<(), std::io::Error>
where
    A: AsyncTargetedMessageStream + ?Sized,
    B: AsyncSourcedMessageStream + ?Sized,
{
    // Unlike tcp copy_bidirectional, we always run a sleep future so that we can expire
    // connections.
    let sleep_future = Box::pin(tokio::time::sleep(std::time::Duration::from_secs(60)));

    CopyMultidirectional {
        a,
        b,
        // this is correctly reversed - CopyBuffer will copy from a (reader) to b (writer) using
        // a_buf, which means that the need_flush signal is for the writer (b), and vice versa for
        // b_buf.
        a_buf: CopyProxyBuffer::new(b_initial_flush),
        b_buf: CopyManyBuffer::new(a_initial_flush),
        a_to_b: TransferState::Running,
        b_to_a: TransferState::Running,
        sleep_future,
        a_last_active: Instant::now(),
        b_last_active: Instant::now(),
    }
    .await
}
