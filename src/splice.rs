use std::io;
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use tokio::io::Interest;
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, SemaphorePermit};

use crate::copy_bidirectional::MAX_COPY_BYTES_PER_POLL;

// Bound only optimization resources; saturation falls back to ordinary copying.
static PIPE_BUDGET: Semaphore = Semaphore::const_new(128);
const BUFFER_SIZE: usize = 16 * 1024;

#[cfg(test)]
thread_local! {
    pub(crate) static TEST_SPLICED_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

struct Pipe {
    read: OwnedFd,
    write: OwnedFd,
    _permit: SemaphorePermit<'static>,
}

impl Pipe {
    fn new() -> io::Result<Self> {
        let permit = PIPE_BUDGET
            .try_acquire()
            .map_err(|_| io::ErrorKind::WouldBlock)?;
        let mut fds = [-1; 2];
        // Both ends become owned only after pipe2 succeeds.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            read: unsafe { OwnedFd::from_raw_fd(fds[0]) },
            write: unsafe { OwnedFd::from_raw_fd(fds[1]) },
            _permit: permit,
        })
    }
}

trait Operations: Sync {
    fn pipe(&self) -> io::Result<Pipe> {
        Pipe::new()
    }

    fn splice(&self, from: RawFd, to: RawFd, len: usize) -> io::Result<usize> {
        syscall_result(unsafe {
            libc::splice(
                from,
                std::ptr::null_mut(),
                to,
                std::ptr::null_mut(),
                len,
                libc::SPLICE_F_NONBLOCK,
            )
        })
    }
}

struct Native;
impl Operations for Native {}

fn syscall_result(result: isize) -> io::Result<usize> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

fn retry_interrupted<T>(mut operation: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    loop {
        match operation() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

fn can_fallback(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(
            libc::EINVAL
                | libc::ENOSYS
                | libc::EOPNOTSUPP
                | libc::EPERM
                | libc::EACCES
                | libc::ENOMEM
        )
    )
}

#[derive(Clone, Copy, Default)]
struct Accounting<'a> {
    source: Option<&'a crate::control::flows::FlowEntry>,
    destination: Option<&'a crate::control::flows::FlowEntry>,
}

impl Accounting<'_> {
    fn read(self, bytes: usize) {
        if let Some(flow) = self.source {
            flow.counters.download(bytes);
        }
    }
    fn wrote(self, bytes: usize) {
        if let Some(flow) = self.destination {
            flow.counters.upload(bytes);
        }
    }
}

async fn write_all(
    socket: &TcpStream,
    mut data: &[u8],
    accounting: Accounting<'_>,
) -> io::Result<()> {
    while !data.is_empty() {
        socket.writable().await?;
        match socket.try_write(data) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                accounting.wrote(n);
                data = &data[n..];
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

async fn account(copied: &mut usize, bytes: usize) {
    *copied += bytes;
    if *copied >= MAX_COPY_BYTES_PER_POLL {
        tokio::task::yield_now().await;
        *copied = 0;
    }
}

async fn copy_buffered(
    source: &TcpStream,
    destination: &TcpStream,
    mut copied: usize,
    mut buffer: Vec<u8>,
    accounting: Accounting<'_>,
) -> io::Result<()> {
    loop {
        source.readable().await?;
        let length = buffer.len().min(MAX_COPY_BYTES_PER_POLL - copied);
        match source.try_read(&mut buffer[..length]) {
            Ok(0) => return shutdown_write(destination),
            Ok(n) => {
                accounting.read(n);
                write_all(destination, &buffer[..n], accounting).await?;
                account(&mut copied, n).await;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

async fn drain_buffered(
    pipe: &Pipe,
    destination: &TcpStream,
    mut pending: usize,
    copied: &mut usize,
    buffer: &mut [u8],
    accounting: Accounting<'_>,
) -> io::Result<()> {
    while pending != 0 {
        let len = pending
            .min(buffer.len())
            .min(MAX_COPY_BYTES_PER_POLL - *copied);
        let n = retry_interrupted(|| {
            syscall_result(unsafe {
                libc::read(pipe.read.as_raw_fd(), buffer.as_mut_ptr().cast(), len)
            })
        })?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        write_all(destination, &buffer[..n], accounting).await?;
        pending -= n;
        account(copied, n).await;
    }
    Ok(())
}

async fn copy_direction_tracked(
    source: &TcpStream,
    destination: &TcpStream,
    operations: &impl Operations,
    accounting: Accounting<'_>,
) -> io::Result<()> {
    let mut copied = 0;
    let mut buffer = vec![0; BUFFER_SIZE];
    'bursts: loop {
        source.readable().await?;
        // Small bursts are cheaper to copy than allocating and releasing a pipe.
        let length = buffer.len().min(MAX_COPY_BYTES_PER_POLL - copied);
        let n = match source.try_read(&mut buffer[..length]) {
            Ok(0) => return shutdown_write(destination),
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        accounting.read(n);
        write_all(destination, &buffer[..n], accounting).await?;
        account(&mut copied, n).await;
        if n < buffer.len() {
            continue;
        }
        // Idle directions retain no pipe descriptors or pages. Allocation failure
        // changes the copy strategy, not connection admission.
        let pipe = match operations.pipe() {
            Ok(pipe) => pipe,
            Err(_) => break 'bursts,
        };
        loop {
            let result = source.try_io(Interest::READABLE, || {
                let result = retry_interrupted(|| {
                    operations.splice(
                        source.as_raw_fd(),
                        pipe.write.as_raw_fd(),
                        MAX_COPY_BYTES_PER_POLL - copied,
                    )
                });
                // splice cannot cross a TCP urgent mark. Detect it before
                // try_io clears readiness or zero is mistaken for stream EOF.
                if (matches!(result, Ok(0))
                    || matches!(&result, Err(e) if e.kind() == io::ErrorKind::WouldBlock))
                    && at_urgent_mark(source.as_raw_fd())?
                {
                    return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
                }
                result
            });
            let mut pending = match result {
                Ok(0) => return shutdown_write(destination),
                Ok(n) => n,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if can_fallback(&error) => break 'bursts,
                Err(error) => return Err(error),
            };
            accounting.read(pending);
            while pending != 0 {
                destination.writable().await?;
                match destination.try_io(Interest::WRITABLE, || {
                    retry_interrupted(|| {
                        operations.splice(pipe.read.as_raw_fd(), destination.as_raw_fd(), pending)
                    })
                }) {
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(n) => {
                        accounting.wrote(n);
                        #[cfg(test)]
                        TEST_SPLICED_BYTES.update(|bytes| bytes + n);
                        pending -= n;
                        account(&mut copied, n).await;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(error) if can_fallback(&error) => {
                        // The source already consumed these bytes. Recover them
                        // before switching this direction permanently to copying.
                        drain_buffered(
                            &pipe,
                            destination,
                            pending,
                            &mut copied,
                            &mut buffer,
                            accounting,
                        )
                        .await?;
                        break 'bursts;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    }
    copy_buffered(source, destination, copied, buffer, accounting).await
}

fn shutdown_write(socket: &TcpStream) -> io::Result<()> {
    match socket2::SockRef::from(socket).shutdown(Shutdown::Write) {
        // Match raw CryptoTlsStream shutdown when the peer is already gone.
        Err(error) if error.kind() == io::ErrorKind::NotConnected => Ok(()),
        result => result,
    }
}

fn at_urgent_mark(fd: RawFd) -> io::Result<bool> {
    // libc does not expose this POSIX wrapper on Linux; the ioctl varies by architecture.
    unsafe extern "C" {
        fn sockatmark(fd: libc::c_int) -> libc::c_int;
    }
    retry_interrupted(|| syscall_result(unsafe { sockatmark(fd) } as isize))
        .map(|marked| marked != 0)
}

#[cfg(test)]
pub(crate) async fn copy_bidirectional(a: &TcpStream, b: &TcpStream) -> io::Result<()> {
    copy_bidirectional_tracked(a, b, None, None).await
}

pub(crate) async fn copy_bidirectional_tracked(
    a: &TcpStream,
    b: &TcpStream,
    a_flow: Option<&crate::control::flows::FlowEntry>,
    b_flow: Option<&crate::control::flows::FlowEntry>,
) -> io::Result<()> {
    tokio::try_join!(
        copy_direction_tracked(
            a,
            b,
            &Native,
            Accounting {
                source: a_flow,
                destination: b_flow
            }
        ),
        copy_direction_tracked(
            b,
            a,
            &Native,
            Accounting {
                source: b_flow,
                destination: a_flow
            }
        ),
    )?;
    Ok(())
}

#[cfg(test)]
async fn copy_direction(
    source: &TcpStream,
    destination: &TcpStream,
    operations: &impl Operations,
) -> io::Result<()> {
    copy_direction_tracked(source, destination, operations, Accounting::default()).await
}

#[cfg(test)]
mod tests;
