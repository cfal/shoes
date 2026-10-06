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
};

use parking_lot::Mutex;
use smoltcp::storage::RingBuffer;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::wake::Wake;

/// TCP socket state machine.
///
/// Follows shadowsocks-rust patterns for proper connection lifecycle management.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpSocketState {
    /// Active connection
    Normal,
    /// Close requested by application
    Close,
    /// socket.close() called, waiting for FIN-ACK
    Closing,
    /// Fully closed
    Closed,
}

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
    /// Receive side state
    recv_state: TcpSocketState,
    /// Send side state
    send_state: TcpSocketState,
    abandoned: bool,
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
                recv_state: TcpSocketState::Normal,
                send_state: TcpSocketState::Normal,
                abandoned: false,
            }),
        }
    }

    // --- Methods called by stack thread ---

    pub fn is_abandoned(&self) -> bool {
        self.inner.lock().abandoned
    }

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

    /// Get current send state.
    pub fn send_state(&self) -> TcpSocketState {
        self.inner.lock().send_state
    }

    /// Get current recv state.
    pub fn recv_state(&self) -> TcpSocketState {
        self.inner.lock().recv_state
    }

    /// Set send state. Returns true if state changed.
    pub fn set_send_state(&self, state: TcpSocketState) -> bool {
        let mut inner = self.inner.lock();
        if inner.send_state != state {
            inner.send_state = state;
            true
        } else {
            false
        }
    }

    /// Set recv state. Returns true if state changed.
    pub fn set_recv_state(&self, state: TcpSocketState) -> bool {
        let mut inner = self.inner.lock();
        if inner.recv_state != state {
            inner.recv_state = state;
            true
        } else {
            false
        }
    }

    /// Mark connection as fully closed (both directions).
    pub fn set_closed(&self) {
        let mut inner = self.inner.lock();
        inner.recv_state = TcpSocketState::Closed;
        inner.send_state = TcpSocketState::Closed;

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
}

/// Async TCP connection.
///
/// Implements AsyncRead and AsyncWrite for use with tokio.
pub struct TcpConnection {
    control: Arc<TcpConnectionControl>,
    wake: Wake,
}

impl TcpConnection {
    /// Create a new TCP connection.
    pub fn new(control: Arc<TcpConnectionControl>, wake: Wake) -> Self {
        Self { control, wake }
    }

    /// Wake up the stack thread.
    fn notify(&self) {
        self.wake.notify();
    }
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        let mut inner = self.control.inner.lock();
        inner.abandoned = true;
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

        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        // Try to read from buffer first
        if !inner.recv_buffer.is_empty() {
            let unfilled = buf.initialize_unfilled();
            let n = inner.recv_buffer.dequeue_slice(unfilled);
            buf.advance(n);

            if n > 0 {
                drop(inner);
                self.notify();
            }
            return Poll::Ready(Ok(()));
        }

        // If recv is closed, return EOF
        if matches!(inner.recv_state, TcpSocketState::Closed) {
            return Poll::Ready(Ok(()));
        }

        // Register waker and wait
        if let Some(ref old_waker) = inner.recv_waker {
            if !old_waker.will_wake(cx.waker()) {
                inner.recv_waker = Some(cx.waker().clone());
            }
        } else {
            inner.recv_waker = Some(cx.waker().clone());
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

        // If send state is not Normal, connection is closing/closed
        if !matches!(inner.send_state, TcpSocketState::Normal) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }

        if !inner.send_buffer.is_full() {
            let n = inner.send_buffer.enqueue_slice(buf);
            if n > 0 {
                drop(inner);
                self.notify();
            }
            return Poll::Ready(Ok(n));
        }

        // Buffer full - register waker
        if let Some(ref old_waker) = inner.send_waker {
            if !old_waker.will_wake(cx.waker()) {
                inner.send_waker = Some(cx.waker().clone());
            }
        } else {
            inner.send_waker = Some(cx.waker().clone());
        }

        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.control.inner.lock();

        // Already fully closed
        if matches!(inner.send_state, TcpSocketState::Closed) {
            return Poll::Ready(Ok(()));
        }

        // Request close (Normal -> Close)
        if matches!(inner.send_state, TcpSocketState::Normal) {
            inner.send_state = TcpSocketState::Close;
        }

        // Register waker to be notified when Closed
        if let Some(ref old_waker) = inner.send_waker {
            if !old_waker.will_wake(cx.waker()) {
                inner.send_waker = Some(cx.waker().clone());
            }
        } else {
            inner.send_waker = Some(cx.waker().clone());
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
    fn async_buffer_and_lifecycle_changes_notify_the_wait_fd() {
        use std::os::{fd::AsRawFd, unix::net::UnixStream};
        use std::time::Duration;

        let (_peer, tun) = UnixStream::pair().unwrap();
        let (wake, mut receiver) = Wake::new().unwrap();
        let control = Arc::new(TcpConnectionControl::new(32, 32));
        let mut connection = TcpConnection::new(control.clone(), wake);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(
            Pin::new(&mut connection)
                .poll_write(&mut cx, b"request")
                .is_ready()
        );
        assert!(
            receiver
                .wait(tun.as_raw_fd(), Some(Duration::ZERO))
                .unwrap()
        );
        receiver.drain().unwrap();
        control.enqueue_recv_data(b"reply");
        assert!(
            Pin::new(&mut connection)
                .poll_read(&mut cx, &mut ReadBuf::new(&mut [0; 32]))
                .is_ready()
        );
        assert!(
            receiver
                .wait(tun.as_raw_fd(), Some(Duration::ZERO))
                .unwrap()
        );
        receiver.drain().unwrap();
        assert!(
            Pin::new(&mut connection)
                .poll_shutdown(&mut cx)
                .is_pending()
        );
        assert!(
            receiver
                .wait(tun.as_raw_fd(), Some(Duration::ZERO))
                .unwrap()
        );
        receiver.drain().unwrap();
        drop(connection);
        assert!(
            receiver
                .wait(tun.as_raw_fd(), Some(Duration::ZERO))
                .unwrap()
        );
    }

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

    #[test]
    fn test_state_transitions() {
        let control = TcpConnectionControl::new(1024, 1024);

        assert_eq!(control.send_state(), TcpSocketState::Normal);
        assert_eq!(control.recv_state(), TcpSocketState::Normal);

        assert!(control.set_send_state(TcpSocketState::Close));
        assert_eq!(control.send_state(), TcpSocketState::Close);

        // Setting same state returns false
        assert!(!control.set_send_state(TcpSocketState::Close));

        assert!(control.set_send_state(TcpSocketState::Closing));
        assert_eq!(control.send_state(), TcpSocketState::Closing);

        control.set_closed();
        assert_eq!(control.send_state(), TcpSocketState::Closed);
        assert_eq!(control.recv_state(), TcpSocketState::Closed);
    }
}
