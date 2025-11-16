use futures::ready;
use tokio::io::ReadBuf;

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use crate::async_stream::AsyncSessionMessageStream;

// Informed by https://stackoverflow.com/questions/14856639/udp-hole-punching-timeout
pub const DEFAULT_ASSOCIATION_TIMEOUT_SECS: u32 = 200;

/// Buffer for copying messages from one session stream to another
#[derive(Debug)]
struct CopySessionToSessionBuffer {
    read_done: bool,
    need_flush: bool,
    need_write_ping: bool,
    cache_length: usize,
    buf: [u8; 65535],
    session_id: u16,
    source_addr: SocketAddr,
    read_count: usize,
    write_count: usize,
}

impl CopySessionToSessionBuffer {
    pub fn new(need_flush: bool) -> Self {
        Self {
            read_done: false,
            need_flush,
            need_write_ping: false,
            cache_length: 0,
            buf: [0u8; 65535],
            session_id: 0,
            source_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            read_count: 0,
            write_count: 0,
        }
    }

    pub fn poll_copy_session_to_session<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncSessionMessageStream + ?Sized,
        W: AsyncSessionMessageStream + ?Sized,
    {
        loop {
            let mut did_read = false;
            let mut did_write = false;
            let mut read_pending = false;
            let mut write_pending = false;

            // Read from session stream
            if !self.read_done && self.cache_length == 0 {
                let me = &mut *self;
                let mut buf = ReadBuf::new(&mut me.buf);
                match reader.as_mut().poll_read_session_message(cx, &mut buf) {
                    Poll::Ready(val) => {
                        let (session_id, source_addr) = val?;
                        let n = buf.filled().len();
                        if n == 0 {
                            self.read_done = true;
                        } else {
                            self.session_id = session_id;
                            self.source_addr = source_addr;
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

            // Write to session stream
            if self.cache_length > 0 {
                let me = &mut *self;
                match writer.as_mut().poll_write_session_message(
                    cx,
                    me.session_id,
                    &me.buf[0..me.cache_length],
                    &me.source_addr,
                ) {
                    Poll::Ready(val) => {
                        val?;
                        self.write_count = self.write_count.wrapping_add(1);
                        self.cache_length = 0;
                        self.need_flush = true;
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

            if self.read_done && self.cache_length == 0 {
                return Poll::Ready(Ok(()));
            }

            if read_pending || write_pending {
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

struct CopySessionMessages<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_buf: CopySessionToSessionBuffer,
    b_buf: CopySessionToSessionBuffer,
    a_to_b: TransferState,
    b_to_a: TransferState,
    sleep_future: Pin<Box<tokio::time::Sleep>>,
    a_last_active: Instant,
    b_last_active: Instant,
}

fn transfer_session_to_session<A, B>(
    cx: &mut Context<'_>,
    state: &mut TransferState,
    buf: &mut CopySessionToSessionBuffer,
    r: &mut A,
    w: &mut B,
) -> Poll<io::Result<()>>
where
    A: AsyncSessionMessageStream + ?Sized,
    B: AsyncSessionMessageStream + ?Sized,
{
    let mut r = Pin::new(r);
    let mut w = Pin::new(w);

    loop {
        match state {
            TransferState::Running => {
                ready!(buf.poll_copy_session_to_session(cx, r.as_mut(), w.as_mut()))?;
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

impl<A, B> Future for CopySessionMessages<'_, A, B>
where
    A: AsyncSessionMessageStream + ?Sized,
    B: AsyncSessionMessageStream + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let CopySessionMessages {
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

        let a_to_b = transfer_session_to_session(cx, a_to_b, &mut *a_buf, &mut *a, &mut *b);
        let b_to_a = transfer_session_to_session(cx, b_to_a, &mut *b_buf, &mut *b, &mut *a);

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

/// Copies data in both directions between two session-based streams.
///
/// This is used for session-based protocols like XUDP where:
/// - `a` is the protocol stream (e.g., VlessXudpMessageStream) that reads/writes XUDP frames with session IDs
/// - `b` is the UDP manager (e.g., SessionUdpManager) that manages dedicated UDP sockets per session
///
/// The function returns a future that will:
/// - Read from `a` (XUDP frames with session IDs) and write to `b` (create/use UDP sockets for each session)
/// - Read from `b` (UDP socket responses with session IDs) and write to `a` (encode as XUDP frames)
///
/// This happens in both directions concurrently with timeout handling.
pub async fn copy_session_messages<A, B>(
    a: &mut A,
    b: &mut B,
    a_initial_flush: bool,
    b_initial_flush: bool,
) -> Result<(), std::io::Error>
where
    A: AsyncSessionMessageStream + ?Sized,
    B: AsyncSessionMessageStream + ?Sized,
{
    let sleep_future = Box::pin(tokio::time::sleep(std::time::Duration::from_secs(60)));

    CopySessionMessages {
        a,
        b,
        // a_buf copies from a (XUDP reader) to b (UDP manager writer), so need_flush is for b
        a_buf: CopySessionToSessionBuffer::new(b_initial_flush),
        // b_buf copies from b (UDP manager reader) to a (XUDP writer), so need_flush is for a
        b_buf: CopySessionToSessionBuffer::new(a_initial_flush),
        a_to_b: TransferState::Running,
        b_to_a: TransferState::Running,
        sleep_future,
        a_last_active: Instant::now(),
        b_last_active: Instant::now(),
    }
    .await
}
