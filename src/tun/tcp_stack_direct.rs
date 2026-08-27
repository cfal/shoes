//! The Unix TUN backend: a file descriptor read with `libc::read`, written
//! with `libc::write`, and waited on with `poll()`.
//!
//! The smoltcp loop and the manager surface live in `stack_common.rs`; this
//! file supplies the descriptor-shaped [`StackDevice`] and the wake pipe that
//! gets an idle thread out of `poll()` at shutdown.

use std::{cell::RefCell, io, os::unix::io::RawFd};

use log::{error, trace, warn};
use smoltcp::{
    phy::{Device, DeviceCapabilities, TxToken},
    time::{Duration as SmolDuration, Instant as SmolInstant},
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use super::stack_common::{
    MAX_POLL_WAIT_MILLIS, NewTcpConnection, PacketBuffer, PooledBuffer, PooledRxToken, StackDevice,
    StackHandle, StackWaker, TcpStackOptions, ip_capabilities,
};

/// Direct TCP Stack Manager.
///
/// Manages the smoltcp interface with direct fd access for efficient I/O.
pub struct TcpStackDirect {
    handle: StackHandle,
    /// TUN file descriptor.
    tun_fd: RawFd,
    /// Whether `tun_fd` belongs to us. False when the platform owns it — on
    /// mobile the app opens the device and closing its descriptor here would
    /// be a double close once the app closes it too, which on a busy process
    /// means closing whatever unrelated socket has since taken the number.
    close_fd_on_drop: bool,
    /// Write end of the pipe that wakes the stack thread out of `poll()`.
    wake_tx: RawFd,
    /// Read end, closed here once the thread that reads it has exited.
    wake_rx: RawFd,
}

impl Drop for TcpStackDirect {
    fn drop(&mut self) {
        self.handle.signal_stop();

        // The thread spends its idle time blocked in poll(), which unpark does
        // not interrupt. Without this byte it would not look at `running` again
        // until the next packet arrived, so shutting down a quiet tunnel — a
        // phone with the screen off, most of the time — would block here until
        // something happened to arrive. The join below is what guarantees the
        // TUN descriptor has been let go, so it cannot simply be skipped.
        let wake = [0u8; 1];
        unsafe {
            libc::write(self.wake_tx, wake.as_ptr() as *const libc::c_void, 1);
        }

        self.handle.join();

        unsafe {
            libc::close(self.wake_tx);
            libc::close(self.wake_rx);
        }

        if self.close_fd_on_drop {
            unsafe {
                libc::close(self.tun_fd);
            }
        }
    }
}

impl TcpStackDirect {
    /// Create a new direct TCP stack.
    ///
    /// # Arguments
    /// * `fd` - Raw file descriptor for the TUN device
    /// * `options` - MTU, per-connection buffer size, connection cap, and
    ///   whether the descriptor is ours to close
    ///
    /// This spawns a dedicated OS thread for running the smoltcp interface.
    /// The thread uses `poll()` on the fd for efficient event-driven I/O.
    pub fn new(fd: RawFd, options: TcpStackOptions) -> Self {
        // A shutdown that the stack thread can see while it is asleep. Both
        // ends stay open for the life of the stack; the thread only ever reads,
        // and Drop only ever writes.
        let (wake_rx, wake_tx) = match new_wake_pipe() {
            Ok(pipe) => pipe,
            Err(e) => {
                // -1 reads as "no wake fd" in the poll below, which costs a
                // shutdown that waits for the next packet rather than one that
                // returns immediately. Not worth refusing to start over.
                error!("Failed to create the stack wake pipe: {e}");
                (-1, -1)
            }
        };

        let handle = StackHandle::spawn("shoes-smoltcp-direct", options, move || {
            // Sets fd to non-blocking mode once at startup for performance.
            set_nonblocking(fd)
                .map_err(|e| io::Error::other(format!("set TUN fd non-blocking: {e}")))?;
            Ok(FdDevice::new(fd, wake_rx, options.mtu))
        });

        Self {
            handle,
            tun_fd: fd,
            close_fd_on_drop: options.close_fd_on_drop,
            wake_tx,
            wake_rx,
        }
    }

    /// Take the receiver for UDP packets (filtered from TUN by the stack).
    pub fn take_udp_rx(&mut self) -> Option<UnboundedReceiver<PacketBuffer>> {
        self.handle.take_udp_rx()
    }

    /// Set the channel for UDP responses to write back to TUN.
    pub fn set_udp_response_tx(&mut self, rx: UnboundedReceiver<PacketBuffer>) {
        self.handle.set_udp_response_tx(rx)
    }

    /// Set the channel for notifying about new TCP connections.
    pub fn set_new_conn_tx(&mut self, tx: UnboundedSender<NewTcpConnection>) {
        self.handle.set_new_conn_tx(tx)
    }

    /// Check if the stack thread is still running.
    pub fn is_running(&self) -> bool {
        self.handle.is_running()
    }

    /// A waker for the UDP response path: one byte down the wake pipe gets
    /// the stack thread out of `poll()` to drain the response channel.
    ///
    /// The descriptor is duplicated so the waker cannot write to a reused
    /// descriptor number after Drop closes the pipe — the waker lives in
    /// tokio tasks whose teardown races the stack's own.
    pub fn udp_waker(&self) -> StackWaker {
        if self.wake_tx < 0 {
            // The pipe could not be created at startup; responses fall back
            // to being drained on the wait timeout.
            return std::sync::Arc::new(|| {});
        }
        // SAFETY: wake_tx is a live pipe descriptor owned by this stack.
        let duped = unsafe { libc::dup(self.wake_tx) };
        if duped < 0 {
            return std::sync::Arc::new(|| {});
        }
        // SAFETY: `duped` was just returned by dup() and nothing else owns it.
        let owned = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(duped) };
        std::sync::Arc::new(move || {
            use std::os::fd::AsRawFd;
            let byte = [1u8];
            // SAFETY: `owned` keeps the descriptor alive for the closure's
            // lifetime. A failed write (pipe full) is fine — a full pipe is
            // already waking the poll.
            unsafe {
                libc::write(owned.as_raw_fd(), byte.as_ptr() as *const libc::c_void, 1);
            }
        })
    }
}

/// Direct TUN device that reads/writes directly to fd.
struct FdDevice {
    fd: RawFd,
    /// Read end of the wake pipe; -1 when the pipe could not be created.
    wake_fd: RawFd,
    mtu: usize,
    pending_rx: Option<PooledBuffer>,
}

impl FdDevice {
    fn new(fd: RawFd, wake_fd: RawFd, mtu: usize) -> Self {
        Self {
            fd,
            wake_fd,
            mtu,
            pending_rx: None,
        }
    }
}

impl StackDevice for FdDevice {
    /// Try to read a packet (non-blocking) using pooled buffer.
    /// Returns:
    /// - Ok(Some(packet)) if a packet was read
    /// - Ok(None) if no packet was available (WouldBlock)
    /// - Err(e) if a fatal error occurred (including EOF)
    fn try_recv(&mut self) -> io::Result<Option<PooledBuffer>> {
        if let Some(pkt) = self.pending_rx.take() {
            return Ok(Some(pkt));
        }

        // Get a buffer from the pool
        let mut buffer = PooledBuffer::with_capacity(self.mtu + 4);
        buffer.resize(self.mtu + 4, 0);

        match read_nonblocking(self.fd, &mut buffer) {
            Ok(n) if n > 0 => {
                buffer.truncate(n);
                Ok(Some(buffer))
            }
            Ok(_) => {
                // n == 0 means EOF
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TUN device closed (EOF)",
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // Buffer is returned to pool when dropped
                Ok(None)
            }
            Err(e) => {
                // Fatal error
                Err(e)
            }
        }
    }

    /// Store a packet for later processing by smoltcp.
    fn store_packet(&mut self, pkt: PooledBuffer) {
        self.pending_rx = Some(pkt);
    }

    fn has_pending(&self) -> bool {
        self.pending_rx.is_some()
    }

    /// Write a packet to TUN.
    fn write_packet(&self, data: &[u8]) -> io::Result<()> {
        write_all(self.fd, data)
    }

    fn wait(&self, duration: Option<SmolDuration>) -> io::Result<()> {
        wait_readable(self.fd, self.wake_fd, duration)
    }
}

impl Device for FdDevice {
    type RxToken<'a> = PooledRxToken;
    type TxToken<'a> = DirectTxToken;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(buffer) = self.pending_rx.take() {
            let rx = PooledRxToken { buffer };
            let tx = DirectTxToken { fd: self.fd };
            Some((rx, tx))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(DirectTxToken { fd: self.fd })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        ip_capabilities(self.mtu)
    }
}

struct DirectTxToken {
    fd: RawFd,
}

thread_local! {
    /// Scratch for the packet currently being written to the TUN.
    ///
    /// Every segment and every ACK the stack sends passes through here, so a
    /// fresh `vec![0u8; len]` per packet was an allocation per packet on the
    /// busiest path in the process. The token is consumed synchronously on the
    /// stack thread and the buffer does not outlive the call, so one buffer per
    /// thread is enough.
    static TX_SCRATCH: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

impl TxToken for DirectTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let fd = self.fd;
        let write = |buffer: &mut Vec<u8>| {
            buffer.clear();
            buffer.resize(len, 0);
            let result = f(buffer);

            if let Err(e) = write_all(fd, buffer) {
                warn!("Failed to write to TUN: {}", e);
            }

            result
        };

        TX_SCRATCH.with(|scratch| match scratch.try_borrow_mut() {
            Ok(mut buffer) => write(&mut buffer),
            // Unreachable as smoltcp uses it — a token is consumed before the
            // next one is handed out — but borrowing rather than assuming keeps
            // a future caller from turning a nested consume into a panic.
            Err(_) => write(&mut Vec::new()),
        })
    }
}

/// Create the shutdown wake pipe, returning (read end, write end).
fn new_wake_pipe() -> io::Result<(RawFd, RawFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a two-element array, which is what pipe() writes.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }

    for fd in fds {
        // Nonblocking so that neither end can stall: a wake write must not
        // block Drop, and the read that drains it must not block the loop.
        // SAFETY: both descriptors were just returned by pipe().
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL, 0);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }

    Ok((fds[0], fds[1]))
}

/// Sleep until the TUN device is readable, the wake pipe fires, or `duration`
/// elapses. `None` waits [`MAX_POLL_WAIT_MILLIS`]; a negative `wake_fd` is
/// ignored.
///
/// poll() rather than select(): select's `fd_set` cannot hold a descriptor
/// numbered above `FD_SETSIZE`, and a VPN process with a thousand connections
/// open reaches those numbers.
fn wait_readable(fd: RawFd, wake_fd: RawFd, duration: Option<SmolDuration>) -> io::Result<()> {
    let mut fds = [
        libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: wake_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    let count = if wake_fd >= 0 { 2 } else { 1 };
    let timeout = duration
        .map(|d| d.total_millis())
        .unwrap_or(MAX_POLL_WAIT_MILLIS)
        .min(MAX_POLL_WAIT_MILLIS) as libc::c_int;

    // SAFETY: `fds` holds `count` initialised pollfds for the call's duration.
    let result = unsafe { libc::poll(fds.as_mut_ptr(), count, timeout) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    // POLLNVAL means the descriptor is closed, which poll reports without
    // setting errno. Turned into an error so the backstop counter sees it
    // rather than spinning on an instant return.
    if fds[0].revents & libc::POLLNVAL != 0 {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }

    // Drain the wake pipe, or every byte the UDP waker ever wrote would keep
    // it readable and turn this wait into a busy loop. The shutdown byte is
    // drained along with the rest, which is fine: shutdown is decided by the
    // `running` flag the loop checks after every wait, not by the byte.
    if count == 2 && fds[1].revents & libc::POLLIN != 0 {
        let mut sink = [0u8; 64];
        // Non-blocking by construction (new_wake_pipe sets O_NONBLOCK), so
        // this ends with EAGAIN rather than blocking.
        while unsafe { libc::read(wake_fd, sink.as_mut_ptr() as *mut libc::c_void, sink.len()) } > 0
        {
        }
    }

    Ok(())
}

/// Set a file descriptor to non-blocking mode (call once at startup).
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if (flags & libc::O_NONBLOCK) == 0
        && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Non-blocking read from a file descriptor (fd must already be non-blocking).
/// Returns Err(WouldBlock) when no data is available, so callers can
/// distinguish it from Ok(0) which indicates EOF.
fn read_nonblocking(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// Write all data to a file descriptor.
fn write_all(fd: RawFd, buf: &[u8]) -> io::Result<()> {
    let mut written = 0;
    while written < buf.len() {
        let n = unsafe {
            libc::write(
                fd,
                buf[written..].as_ptr() as *const libc::c_void,
                buf.len() - written,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOBUFS) || err.kind() == io::ErrorKind::WouldBlock
            {
                trace!("TUN write {}, packet dropped", err);
                return Ok(());
            }
            return Err(err);
        }
        written += n as usize;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::stack_common::{clear_buffer_pool, test_util::syn_packet};
    use super::*;
    use std::os::unix::io::IntoRawFd;
    use std::os::unix::net::UnixStream;
    use std::thread;
    use std::time::Duration;

    /// Stack options for a test that hands its descriptor over to the stack.
    fn owning_options() -> TcpStackOptions {
        TcpStackOptions {
            mtu: 1500,
            tcp_buffer_size: 32 * 1024,
            max_connections: 16,
            close_fd_on_drop: true,
        }
    }

    #[test]
    fn test_stack_shutdown_on_eof() {
        let (server, client) = UnixStream::pair().expect("Failed to create socket pair");
        let client_fd = client.into_raw_fd();

        let stack = TcpStackDirect::new(client_fd, owning_options());

        thread::sleep(Duration::from_millis(100));
        assert!(stack.is_running(), "Stack thread should be running");

        // Closing the writer end triggers EOF on the reader.
        drop(server);

        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(2);

        while stack.is_running() {
            if start.elapsed() > timeout {
                panic!("Stack thread did not exit after EOF on FD");
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn test_stack_shutdown_on_closed_fd() {
        let (server, client) = UnixStream::pair().expect("Failed to create socket pair");
        let client_fd = client.into_raw_fd();

        // Borrowed, not owned: this test closes the descriptor itself below,
        // and a stack that closed it again would be a double close.
        let stack = TcpStackDirect::new(
            client_fd,
            TcpStackOptions {
                close_fd_on_drop: false,
                ..owning_options()
            },
        );

        thread::sleep(Duration::from_millis(100));
        assert!(stack.is_running(), "Stack thread should be running");

        // Externally close the fd to produce EBADF on both read and select.
        unsafe { libc::close(client_fd) };
        // Also drop the writer so there's no other holder.
        drop(server);

        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(5);

        while stack.is_running() {
            if start.elapsed() > timeout {
                panic!("Stack thread did not exit after closed FD");
            }
            thread::sleep(Duration::from_millis(50));
        }

        // Safe to drop only because the stack was told the descriptor is not
        // its own. Closing it twice would let a concurrent test's OwnedFd take
        // the freed number in between and then lose it, which aborts the whole
        // test binary ("IO Safety violation: owned file descriptor already
        // closed") rather than failing one test.
        drop(stack);
    }

    /// Resident bytes this process is using, from `ps`.
    fn resident_bytes() -> u64 {
        let pid = std::process::id();
        let out = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &pid.to_string()])
            .output()
            .expect("ps");
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse::<u64>()
            .expect("rss")
            * 1024
    }

    /// What a connection actually costs in resident memory, and whether the
    /// stack gives it back.
    ///
    /// Ignored by default: resident size is a measurement, not something to
    /// assert on across machines and allocators. Run it with
    /// `cargo test measure_memory_per_connection -- --ignored --nocapture`
    /// when changing buffer sizing.
    #[test]
    #[ignore = "measurement; run with --ignored --nocapture"]
    fn measure_memory_per_connection() {
        use std::io::Write;

        const CONNECTIONS: usize = 200;
        let buffer_size = 32 * 1024;

        let (mut server, client) = UnixStream::pair().expect("socket pair");
        let client_fd = client.into_raw_fd();

        let before = resident_bytes();
        let stack = TcpStackDirect::new(
            client_fd,
            TcpStackOptions {
                mtu: 1500,
                tcp_buffer_size: buffer_size,
                max_connections: CONNECTIONS * 2,
                close_fd_on_drop: true,
            },
        );
        thread::sleep(Duration::from_millis(100));

        for i in 0..CONNECTIONS {
            server
                .write_all(&syn_packet(20000 + i as u16))
                .expect("write SYN");
            // The stack reads in batches of 64; give it room to keep up rather
            // than filling the socket buffer and blocking this side.
            if i % 32 == 0 {
                thread::sleep(Duration::from_millis(20));
            }
        }
        thread::sleep(Duration::from_millis(500));
        let occupied = resident_bytes();

        drop(stack);
        drop(server);
        clear_buffer_pool();
        thread::sleep(Duration::from_millis(200));
        let after_free = resident_bytes();

        crate::memory::release_to_os();
        thread::sleep(Duration::from_millis(200));
        let after = resident_bytes();

        let per_connection = (occupied.saturating_sub(before)) as f64 / CONNECTIONS as f64;
        println!(
            "buffers {} KiB/direction, {} connections\n  \
             before          {:>7} KiB\n  \
             occupied        {:>7} KiB  ({:.0} KiB per connection, \
             {:.0}% of the four buffers it allocated)\n  \
             after free      {:>7} KiB  ({:+} KiB vs before)\n  \
             after purge     {:>7} KiB  ({:+} KiB vs before)",
            buffer_size / 1024,
            CONNECTIONS,
            before / 1024,
            occupied / 1024,
            per_connection / 1024.0,
            100.0 * per_connection / (4.0 * buffer_size as f64),
            after_free / 1024,
            (after_free as i64 - before as i64) / 1024,
            after / 1024,
            (after as i64 - before as i64) / 1024,
        );
    }

    #[test]
    fn stack_leaves_a_borrowed_fd_open() {
        // The mobile case: the app owns the descriptor and closes it itself.
        // Closing it here as well would be a double close in a process that is
        // opening sockets constantly, which means closing whichever socket has
        // taken the number in the meantime.
        let (server, client) = UnixStream::pair().expect("Failed to create socket pair");
        let client_fd = client.into_raw_fd();

        let stack = TcpStackDirect::new(
            client_fd,
            TcpStackOptions {
                close_fd_on_drop: false,
                ..owning_options()
            },
        );
        thread::sleep(Duration::from_millis(100));
        drop(stack);

        let still_open = unsafe { libc::fcntl(client_fd, libc::F_GETFD) } != -1;
        // Closed here, not by the stack, which is the whole point.
        unsafe { libc::close(client_fd) };
        drop(server);

        assert!(still_open, "the stack closed a descriptor it does not own");
    }

    #[test]
    fn test_stack_exits_promptly() {
        // Verifies the stack exits within 1 second of EOF, catching
        // regressions that would cause CPU spin on a dead fd.
        let (server, client) = UnixStream::pair().expect("Failed to create socket pair");
        let client_fd = client.into_raw_fd();

        let stack = TcpStackDirect::new(client_fd, owning_options());

        thread::sleep(Duration::from_millis(100));
        assert!(stack.is_running());

        drop(server);

        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(1);

        while stack.is_running() {
            if start.elapsed() > timeout {
                panic!("Stack thread took >1s to exit after EOF (possible spin)");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// A tunnel that stops with connections still open must not leave them
    /// counted. The count is process-global, so a leak here compounds across
    /// every start and stop for the life of the process: reconnect after
    /// browsing with thirty sockets open and the GUI starts from thirty.
    #[cfg(feature = "control-stats")]
    #[test]
    fn test_the_connection_count_does_not_survive_the_stack() {
        // Shared with control::stats' tests: the counter is process-global and
        // cargo runs these in parallel, so without this they read each other's
        // increments.
        let _guard = super::super::traffic::COUNTER_TEST_LOCK.lock().unwrap();
        super::super::traffic::reset_active_connections();

        let (server, client) = UnixStream::pair().expect("Failed to create socket pair");
        let client_fd = client.into_raw_fd();

        let stack = TcpStackDirect::new(client_fd, owning_options());
        thread::sleep(Duration::from_millis(100));
        assert!(stack.is_running());

        // Stand in for connections the stack is holding when it is told to
        // stop -- the sweep that decrements only runs inside its loop.
        super::super::traffic::connection_opened();
        super::super::traffic::connection_opened();
        assert_eq!(super::super::traffic::active_connections(), 2);

        drop(server);

        let start = std::time::Instant::now();
        while stack.is_running() {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "stack thread never exited"
            );
            thread::sleep(Duration::from_millis(10));
        }

        assert_eq!(
            super::super::traffic::active_connections(),
            0,
            "connections stayed counted after the stack thread exited"
        );
    }

    /// A UDP response queued while the stack is idle must be written as soon
    /// as the waker fires, not when the idle wait next times out — the
    /// difference between DNS answered in microseconds and DNS answered in
    /// half a second, measured on the Windows live run and just as real here.
    #[test]
    fn a_udp_response_is_written_promptly_when_woken() {
        use std::io::Read;

        let (mut server, client) = UnixStream::pair().expect("socket pair");
        let client_fd = client.into_raw_fd();

        let mut stack = TcpStackDirect::new(client_fd, owning_options());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        stack.set_udp_response_tx(rx);
        let waker = stack.udp_waker();

        // Let the loop reach its idle wait, so the timeout path cannot be
        // what delivers the packet.
        thread::sleep(Duration::from_millis(150));

        let start = std::time::Instant::now();
        tx.send(vec![0xAB; 32]).unwrap();
        waker();

        // Well under the loop's 1-second idle wait: if the wake is broken,
        // this read times out rather than the assertion below flaking.
        server
            .set_read_timeout(Some(Duration::from_millis(800)))
            .unwrap();
        let mut buf = [0u8; 64];
        let n = server.read(&mut buf).expect("the response never arrived");
        assert_eq!(&buf[..n], &[0xAB; 32][..]);
        assert!(
            start.elapsed() < Duration::from_millis(800),
            "the response took {:?}; the waker did not interrupt the idle wait",
            start.elapsed()
        );

        drop(stack);
    }

    #[test]
    fn test_write_all_eagain() {
        // Fill a non-blocking socket's write buffer, then verify write_all
        // treats EAGAIN the same as ENOBUFS (drops the packet, returns Ok).
        let (reader, writer) = UnixStream::pair().expect("Failed to create socket pair");
        let writer_fd = writer.into_raw_fd();

        set_nonblocking(writer_fd).expect("set_nonblocking");

        // Fill the write buffer until WouldBlock
        let big_buf = vec![0u8; 65536];
        loop {
            let n = unsafe {
                libc::write(
                    writer_fd,
                    big_buf.as_ptr() as *const libc::c_void,
                    big_buf.len(),
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                assert_eq!(
                    err.kind(),
                    io::ErrorKind::WouldBlock,
                    "unexpected error: {}",
                    err
                );
                break;
            }
        }

        // Now write_all should drop the packet gracefully
        let result = write_all(writer_fd, &[1, 2, 3]);
        assert!(
            result.is_ok(),
            "write_all should return Ok on EAGAIN, got {:?}",
            result
        );

        unsafe { libc::close(writer_fd) };
        drop(reader);
    }
}
