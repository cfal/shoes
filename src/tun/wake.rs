use std::{
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, RawFd},
        unix::net::UnixStream,
    },
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(Clone)]
pub(super) struct Wake(Arc<WakeInner>);

struct WakeInner {
    writer: UnixStream,
    pending: AtomicBool,
}

pub(super) struct WakeReceiver {
    reader: UnixStream,
    wake: Wake,
    #[cfg(test)]
    pub before_clear: Option<super::test_gate::TestGate>,
    #[cfg(test)]
    pub before_wait: Option<super::test_gate::TestGate>,
}

impl Wake {
    pub fn new() -> io::Result<(Self, WakeReceiver)> {
        let (reader, writer) = UnixStream::pair()?;
        reader.set_nonblocking(true)?;
        writer.set_nonblocking(true)?;
        let wake = Self(Arc::new(WakeInner {
            writer,
            pending: AtomicBool::new(false),
        }));
        let receiver = WakeReceiver {
            reader,
            wake: wake.clone(),
            #[cfg(test)]
            before_clear: None,
            #[cfg(test)]
            before_wait: None,
        };
        Ok((wake, receiver))
    }

    pub fn notify(&self) {
        if self.0.pending.swap(true, Ordering::AcqRel) {
            return;
        }
        loop {
            match (&self.0.writer).write(&[1]) {
                Ok(_) => return,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                // A full socket is already readable. Producers may outlive the receiver.
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::BrokenPipe
                    ) =>
                {
                    return;
                }
                Err(error) => {
                    log::warn!("Failed to wake TUN stack: {error}");
                    return;
                }
            }
        }
    }
}

impl WakeReceiver {
    /// Acknowledges notifications before the caller consumes shared work, never before waiting.
    pub fn drain(&mut self) -> io::Result<()> {
        let mut bytes = [0; 128];
        loop {
            match self.reader.read(&mut bytes) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        #[cfg(test)]
        if let Some(gate) = self.before_clear.take() {
            gate.pause();
        }
        self.wake.0.pending.swap(false, Ordering::AcqRel);
        Ok(())
    }

    pub fn wait(&self, tun_fd: RawFd, delay: Option<Duration>) -> io::Result<bool> {
        let mut fds = [
            libc::pollfd {
                fd: tun_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: self.reader.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let timeout = delay.map_or(-1, |delay| {
            delay
                .as_nanos()
                .div_ceil(1_000_000)
                .min(libc::c_int::MAX as u128) as libc::c_int
        });
        let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        for fd in fds {
            if fd.revents & libc::POLLNVAL != 0 {
                return Err(io::Error::from_raw_os_error(libc::EBADF));
            }
            if fd.revents & libc::POLLERR != 0 {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            if fd.revents & libc::POLLHUP != 0 && fd.revents & libc::POLLIN == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
        Ok(result > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc, thread};

    #[test]
    fn notifications_coalesce_and_survive_before_wait() {
        let (_peer, tun) = UnixStream::pair().unwrap();
        let (wake, mut receiver) = Wake::new().unwrap();
        for _ in 0..10_000 {
            wake.notify();
        }
        assert!(
            receiver
                .wait(tun.as_raw_fd(), Some(Duration::ZERO))
                .unwrap()
        );
        let mut bytes = [0; 128];
        assert_eq!(receiver.reader.read(&mut bytes).unwrap(), 1);
        receiver.drain().unwrap();
        assert!(
            !receiver
                .wait(tun.as_raw_fd(), Some(Duration::ZERO))
                .unwrap()
        );
        wake.notify();
        assert!(
            receiver
                .wait(tun.as_raw_fd(), Some(Duration::ZERO))
                .unwrap()
        );
    }

    #[test]
    fn notification_interrupts_an_indefinite_wait() {
        let (mut peer, tun) = UnixStream::pair().unwrap();
        let (wake, receiver) = Wake::new().unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let waiter = thread::spawn(move || {
            ready_tx.send(()).unwrap();
            let result = receiver.wait(tun.as_raw_fd(), None);
            done_tx.send(result).unwrap();
        });
        ready_rx.recv().unwrap();
        wake.notify();
        let result = done_rx.recv_timeout(Duration::from_secs(1));
        if result.is_err() {
            let _ = peer.write(&[1]);
        }
        waiter.join().unwrap();
        assert!(result.unwrap().unwrap());
    }

    #[test]
    fn full_wake_socket_is_already_a_notification() {
        let (_peer, tun) = UnixStream::pair().unwrap();
        let (wake, mut receiver) = Wake::new().unwrap();
        let bytes = [0; 4096];
        loop {
            match (&wake.0.writer).write(&bytes) {
                Ok(written) => assert!(written > 0),
                Err(error) => {
                    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                    break;
                }
            }
        }
        wake.notify();
        assert!(
            receiver
                .wait(tun.as_raw_fd(), Some(Duration::ZERO))
                .unwrap()
        );
        receiver.drain().unwrap();
        assert!(
            !receiver
                .wait(tun.as_raw_fd(), Some(Duration::ZERO))
                .unwrap()
        );
        wake.notify();
        assert!(
            receiver
                .wait(tun.as_raw_fd(), Some(Duration::ZERO))
                .unwrap()
        );
    }

    #[test]
    fn late_producer_does_not_raise_sigpipe() {
        let (wake, receiver) = Wake::new().unwrap();
        drop(receiver);
        wake.notify();
        wake.notify();
    }

    #[test]
    fn notification_during_acknowledgment_is_observed_as_shared_work() {
        let (wake, mut receiver) = Wake::new().unwrap();
        let (tx, rx) = mpsc::channel();
        let (gate, control) = super::super::test_gate::TestGate::new();
        receiver.before_clear = Some(gate);
        wake.notify();
        let consumer = thread::spawn(move || {
            receiver.drain().unwrap();
            assert_eq!(rx.try_recv().unwrap(), 42);
            receiver
        });
        control.wait();
        tx.send(42).unwrap();
        wake.notify();
        drop(control);
        let mut receiver = consumer.join().unwrap();
        assert_eq!(
            receiver.reader.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        wake.notify();
        assert_eq!(receiver.reader.read(&mut [0]).unwrap(), 1);
    }

    #[test]
    fn invalid_descriptor_is_not_reported_as_readiness() {
        let (_, receiver) = Wake::new().unwrap();
        assert_eq!(
            receiver
                .wait(libc::c_int::MAX, Some(Duration::ZERO))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EBADF)
        );
    }
}
