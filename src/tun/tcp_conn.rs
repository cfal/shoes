//! TCP Connection for async read/write.
//!
//! This module provides a TCP connection that implements tokio's AsyncRead
//! and AsyncWrite traits, bridging between the smoltcp stack thread and
//! async Rust code.
//!
//! Based on the proven pattern from shadowsocks-rust.

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    thread::Thread,
};

use parking_lot::Mutex;
use smoltcp::storage::RingBuffer;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Internal state for TCP connection control.
///
/// Shared between the async connection handle and the stack thread.
pub struct TcpConnectionControl {
    inner: Mutex<TcpConnectionInner>,
}

struct TcpConnectionInner {
    /// Buffer for data to send
    send_buffer: RingBuffer<'static, u8>,
    /// Waker to notify when send buffer has space
    send_waker: Option<Waker>,
    /// Buffer for received data
    recv_buffer: RingBuffer<'static, u8>,
    /// Waker to notify when recv buffer has data
    recv_waker: Option<Waker>,
    /// Whether receive side is closed
    recv_closed: bool,
    /// Whether send side is closed
    send_closed: bool,
    /// Whether close has been requested
    close_requested: bool,
}

impl TcpConnectionControl {
    /// Create new connection control with specified buffer sizes.
    pub fn new(send_buffer_size: usize, recv_buffer_size: usize) -> Self {
        Self {
            inner: Mutex::new(TcpConnectionInner {
                send_buffer: RingBuffer::new(vec![0u8; send_buffer_size]),
                send_waker: None,
                recv_buffer: RingBuffer::new(vec![0u8; recv_buffer_size]),
                recv_waker: None,
                recv_closed: false,
                send_closed: false,
                close_requested: false,
            }),
        }
    }

    // --- Methods called by stack thread ---

    /// Check if recv buffer is full.
    pub fn recv_buffer_full(&self) -> bool {
        self.inner.lock().recv_buffer.is_full()
    }

    /// Enqueue data into recv buffer. Returns bytes written.
    pub fn enqueue_recv_data(&self, data: &[u8]) -> usize {
        self.inner.lock().recv_buffer.enqueue_slice(data)
    }

    /// Check if send buffer is empty.
    pub fn send_buffer_empty(&self) -> bool {
        self.inner.lock().send_buffer.is_empty()
    }

    /// Dequeue data from send buffer. Returns bytes read.
    pub fn dequeue_send_data(&self, buf: &mut [u8]) -> usize {
        self.inner.lock().send_buffer.dequeue_slice(buf)
    }

    /// Wake the receiver (data available or closed).
    pub fn wake_receiver(&self) {
        let waker = self.inner.lock().recv_waker.take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Wake the sender (buffer space available or closed).
    pub fn wake_sender(&self) {
        let waker = self.inner.lock().send_waker.take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Mark connection as fully closed.
    pub fn set_closed(&self) {
        let mut inner = self.inner.lock();
        inner.recv_closed = true;
        inner.send_closed = true;

        let recv_waker = inner.recv_waker.take();
        let send_waker = inner.send_waker.take();
        drop(inner);

        if let Some(w) = recv_waker {
            w.wake();
        }
        if let Some(w) = send_waker {
            w.wake();
        }
    }

    /// Mark receive side as closed. Returns true if state changed.
    pub fn set_recv_closed(&self) -> bool {
        let mut inner = self.inner.lock();
        if !inner.recv_closed {
            inner.recv_closed = true;
            true
        } else {
            false
        }
    }

    /// Mark send side as closed.
    pub fn set_send_closed(&self) {
        self.inner.lock().send_closed = true;
    }

    /// Check if close has been requested.
    pub fn should_close_send(&self) -> bool {
        self.inner.lock().close_requested
    }

    /// Check if send side is already closed.
    pub fn is_send_closed(&self) -> bool {
        self.inner.lock().send_closed
    }
}

/// Async TCP connection.
///
/// Implements AsyncRead and AsyncWrite for use with tokio.
pub struct TcpConnection {
    control: Arc<TcpConnectionControl>,
    thread: Thread,
}

impl TcpConnection {
    /// Create a new TCP connection.
    pub fn new(control: Arc<TcpConnectionControl>, thread: Thread) -> Self {
        Self { control, thread }
    }

    /// Wake up the stack thread.
    fn notify(&self) {
        self.thread.unpark();
    }
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        // Request close when connection is dropped
        let mut inner = self.control.inner.lock();
        if !inner.send_closed {
            inner.close_requested = true;
        }
        if !inner.recv_closed {
            inner.recv_closed = true;
        }
        drop(inner);
        self.notify();
    }
}

impl AsyncRead for TcpConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut inner = self.control.inner.lock();

        if !inner.recv_buffer.is_empty() {
            let unfilled = buf.initialize_unfilled();
            let n = inner.recv_buffer.dequeue_slice(unfilled);
            buf.advance(n);

            // Notify stack that we freed buffer space (can receive more data)
            if n > 0 {
                drop(inner);
                self.notify();
            }
            return Poll::Ready(Ok(()));
        }

        if inner.recv_closed {
            return Poll::Ready(Ok(())); // EOF
        }

        // Register waker and wait
        let new_waker = cx.waker();
        if let Some(ref old_waker) = inner.recv_waker {
            if !old_waker.will_wake(new_waker) {
                inner.recv_waker = Some(new_waker.clone());
            }
        } else {
            inner.recv_waker = Some(new_waker.clone());
        }

        Poll::Pending
    }
}

impl AsyncWrite for TcpConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut inner = self.control.inner.lock();

        if inner.send_closed || inner.close_requested {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }

        if !inner.send_buffer.is_full() {
            let n = inner.send_buffer.enqueue_slice(buf);

            // Notify stack that we have data to send
            if n > 0 {
                drop(inner);
                self.notify();
            }
            return Poll::Ready(Ok(n));
        }

        // Buffer full - register waker and wait
        let new_waker = cx.waker();
        if let Some(ref old_waker) = inner.send_waker {
            if !old_waker.will_wake(new_waker) {
                inner.send_waker = Some(new_waker.clone());
            }
        } else {
            inner.send_waker = Some(new_waker.clone());
        }

        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Don't notify - stack polls regularly
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.control.inner.lock();

        if inner.send_closed {
            return Poll::Ready(Ok(()));
        }

        inner.close_requested = true;

        // We must wait for the stack thread to actually call socket.close()
        // and set send_closed=true. This ensures the FIN packet is sent.

        // Register waker to be notified when send_closed becomes true
        let new_waker = cx.waker();
        if let Some(ref old_waker) = inner.send_waker {
            if !old_waker.will_wake(new_waker) {
                inner.send_waker = Some(new_waker.clone());
            }
        } else {
            inner.send_waker = Some(new_waker.clone());
        }

        drop(inner);
        self.notify();

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_basic() {
        let control = TcpConnectionControl::new(1024, 1024);

        // Test enqueue/dequeue
        let data = b"hello world";
        let n = control.enqueue_recv_data(data);
        assert_eq!(n, data.len());

        let mut buf = [0u8; 32];
        let n = control.inner.lock().recv_buffer.dequeue_slice(&mut buf);
        assert_eq!(n, data.len());
        assert_eq!(&buf[..n], data);
    }
}
