//! The Windows TUN backend: a wintun ring-buffer session read with
//! `try_receive`, written with `allocate_send_packet`/`send_packet`, and
//! waited on with `WaitForMultipleObjects` over the session's event handles.
//!
//! The smoltcp loop and the manager surface live in `stack_common.rs`; this
//! file supplies the session-shaped [`StackDevice`]. Where the Unix backend
//! wakes an idle thread through a pipe, this one uses the session's own
//! shutdown event — the same mechanism wireguard-go uses
//! (`tun/tun_windows.go`: shutdown sets the read-wait event and the reader
//! observes the closed flag).

use std::{io, sync::Arc};

use log::{trace, warn};
use smoltcp::{
    phy::{Device, DeviceCapabilities, TxToken},
    time::{Duration as SmolDuration, Instant as SmolInstant},
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BUFFER_OVERFLOW, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent, WaitForMultipleObjects};
use wintun_bindings::Session;

use super::stack_common::{
    MAX_POLL_WAIT_MILLIS, NewTcpConnection, PacketBuffer, PooledBuffer, PooledRxToken, StackDevice,
    StackHandle, StackWaker, TcpStackOptions, ip_capabilities,
};
use super::wintun_device::OpenedWintun;

/// An auto-reset event the UDP waker sets to get the stack thread out of its
/// idle wait — this backend's equivalent of a byte down the Unix wake pipe.
/// Auto-reset, so one `SetEvent` is one wakeup with nothing to drain.
struct WakeEvent(HANDLE);

// SAFETY: an event handle is a thread-safe kernel object; SetEvent and
// waiting may happen from any thread concurrently.
unsafe impl Send for WakeEvent {}
unsafe impl Sync for WakeEvent {}

impl Drop for WakeEvent {
    fn drop(&mut self) {
        // SAFETY: the handle was returned by CreateEventW and is only closed
        // here, when the last Arc — stack thread or waker — lets go.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

impl WakeEvent {
    /// Create the event, or None if the system refuses — in which case UDP
    /// responses fall back to being drained on the wait timeout.
    fn new() -> Option<Arc<Self>> {
        // SAFETY: null attributes and name are documented as valid;
        // bManualReset=0 makes it auto-reset, bInitialState=0 unsignalled.
        let handle = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
        if handle.is_null() {
            log::warn!("CreateEventW failed; UDP responses will ride the wait timeout");
            None
        } else {
            Some(Arc::new(Self(handle)))
        }
    }
}

/// Whether an `allocate_send_packet` failure is the send ring being full —
/// ERROR_BUFFER_OVERFLOW, per wintun.h — as opposed to a session that is
/// gone (ERROR_HANDLE_EOF while the adapter terminates). The two must not be
/// conflated: a full ring is backpressure and the packet is dropped the way
/// a full socket buffer drops it, while a dead session deserves the same
/// loud surfacing the Unix backend gives a failed `write()`.
fn is_ring_full(e: &wintun_bindings::Error) -> bool {
    matches!(e, wintun_bindings::Error::Io(io_err)
        if io_err.raw_os_error() == Some(ERROR_BUFFER_OVERFLOW as i32))
}

/// Windows TCP stack manager over a wintun session.
///
/// Presents the same surface as the Unix `TcpStackDirect`, so
/// `run_tun_server` differs only where the stack is constructed.
pub struct TcpStackWintun {
    handle: StackHandle,
    /// The session, held here so Drop can signal shutdown; the adapter and
    /// library handles ride along inside and outlive the stack thread.
    tun: Arc<OpenedWintun>,
    /// Wake event shared with the device's wait; None if creation failed.
    wake_event: Option<Arc<WakeEvent>>,
}

impl Drop for TcpStackWintun {
    fn drop(&mut self) {
        self.handle.signal_stop();

        // The thread spends its idle time blocked in WaitForMultipleObjects,
        // which unpark does not interrupt. Session::shutdown sets the
        // session's shutdown event — one of the two handles the wait sleeps
        // on — so an idle stack wakes now rather than at the next packet.
        // The join below is what guarantees the session is no longer being
        // read when the adapter is torn down.
        let _ = self.tun.session.shutdown();

        self.handle.join();
    }
}

impl TcpStackWintun {
    /// Create a new wintun-backed TCP stack.
    ///
    /// This spawns a dedicated OS thread for running the smoltcp interface,
    /// waiting on the session's read event for event-driven I/O.
    pub fn new(tun: OpenedWintun, options: TcpStackOptions) -> Self {
        let tun = Arc::new(tun);
        let wake_event = WakeEvent::new();

        let session = tun.session.clone();
        let device_wake = wake_event.clone();
        // The session event handles are fetched inside the closure, on the
        // stack thread itself: raw HANDLEs are not Send, and nothing outside
        // that thread needs them. The wake event travels as an Arc, whose
        // Send is the deliberate exception WakeEvent exists to declare.
        let handle = StackHandle::spawn("shoes-smoltcp-wintun", options, move || {
            WintunDevice::new(session, device_wake, options.mtu)
        });

        Self {
            handle,
            tun,
            wake_event,
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

    /// A waker for the UDP response path: sets the wake event so the stack
    /// thread leaves `WaitForMultipleObjects` and drains the response
    /// channel now rather than on the wait timeout.
    pub fn udp_waker(&self) -> StackWaker {
        match &self.wake_event {
            Some(event) => {
                let event = event.clone();
                Arc::new(move || {
                    // SAFETY: the Arc keeps the handle alive for the
                    // closure's lifetime; SetEvent is thread-safe.
                    unsafe {
                        SetEvent(event.0);
                    }
                })
            }
            None => Arc::new(|| {}),
        }
    }
}

/// TUN device over a wintun session.
struct WintunDevice {
    session: Arc<Session>,
    /// Signalled by the driver while the receive ring is non-empty.
    read_wait: HANDLE,
    /// Set by `Session::shutdown()`; with the wake event below, this
    /// backend's wake pipe.
    shutdown_event: HANDLE,
    /// Set by the UDP waker; auto-reset, so waking consumes the signal.
    wake_event: Option<Arc<WakeEvent>>,
    mtu: usize,
    pending_rx: Option<PooledBuffer>,
}

impl WintunDevice {
    fn new(
        session: Arc<Session>,
        wake_event: Option<Arc<WakeEvent>>,
        mtu: usize,
    ) -> io::Result<Self> {
        let read_wait = session
            .get_read_wait_event()
            .map_err(|e| io::Error::other(format!("wintun read event unavailable: {e}")))?
            .0;
        let shutdown_event = session.get_shutdown_event().0;

        Ok(Self {
            session,
            read_wait,
            shutdown_event,
            wake_event,
            mtu,
            pending_rx: None,
        })
    }
}

impl StackDevice for WintunDevice {
    /// Non-blocking read of one packet out of the receive ring.
    ///
    /// The copy into the pooled buffer is the same single copy the Unix
    /// `read()` performs, and returning the ring slot immediately keeps the
    /// driver's ring from filling while smoltcp works.
    fn try_recv(&mut self) -> io::Result<Option<PooledBuffer>> {
        if let Some(pkt) = self.pending_rx.take() {
            return Ok(Some(pkt));
        }

        loop {
            match self.session.try_receive() {
                Ok(Some(packet)) => {
                    let data = packet.bytes();
                    // The ring can hand over packets up to 64 KiB whatever
                    // MTU the adapter was given (an admin can raise it later
                    // via netsh). Growing the pooled buffer for them would
                    // quietly raise the pool's retained memory past its
                    // documented budget, so oversize is dropped instead —
                    // the Unix backend's fixed-size read truncates the same
                    // packets into unparseable fragments and drops them too.
                    if data.len() > self.mtu + 4 {
                        trace!(
                            "dropping a {}-byte packet from a {}-MTU adapter",
                            data.len(),
                            self.mtu
                        );
                        continue;
                    }
                    let mut buffer = PooledBuffer::with_capacity(self.mtu + 4);
                    buffer.extend_from_slice(data);
                    return Ok(Some(buffer));
                }
                Ok(None) => return Ok(None),
                // Shutdown or a dead session; either way the loop must stop,
                // the way a Unix EOF stops it.
                Err(e) => return Err(io::Error::other(format!("wintun receive failed: {e}"))),
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

    /// Write a packet to the send ring.
    fn write_packet(&self, data: &[u8]) -> io::Result<()> {
        let Ok(len) = u16::try_from(data.len()) else {
            // An IP packet over 64 KiB cannot exist on this path; reject
            // rather than truncate.
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet exceeds the wintun frame limit",
            ));
        };

        match self.session.allocate_send_packet(len) {
            Ok(mut packet) => {
                packet.bytes_mut().copy_from_slice(data);
                self.session.send_packet(packet);
                Ok(())
            }
            // A full send ring is what a full socket buffer is on Unix: the
            // packet is dropped and the tunnel carries on.
            Err(e) if is_ring_full(&e) => {
                trace!("wintun send ring full, packet dropped");
                Ok(())
            }
            // Anything else is the session dying under us; surface it so the
            // loop's caller warns, as the Unix write path would.
            Err(e) => Err(io::Error::other(format!("wintun send failed: {e}"))),
        }
    }

    fn wait(&self, duration: Option<SmolDuration>) -> io::Result<()> {
        let mut handles = [self.read_wait, self.shutdown_event, std::ptr::null_mut()];
        let count = match &self.wake_event {
            Some(event) => {
                handles[2] = event.0;
                3
            }
            None => 2,
        };
        let timeout = duration
            .map(|d| d.total_millis())
            .unwrap_or(MAX_POLL_WAIT_MILLIS)
            .min(MAX_POLL_WAIT_MILLIS) as u32;

        // SAFETY: the session handles live as long as the session and the
        // wake event as long as its Arc, both of which `self` holds for the
        // duration of the call.
        let result = unsafe { WaitForMultipleObjects(count, handles.as_ptr(), 0, timeout) };

        if result == WAIT_FAILED {
            return Err(io::Error::last_os_error());
        }

        // Readable, shutdown, woken and timed out all return Ok: the loop
        // re-checks `running`, drains the response channel and calls
        // try_recv either way, which is how the Unix poll() path behaves.
        debug_assert!(
            (WAIT_OBJECT_0..WAIT_OBJECT_0 + count).contains(&result) || result == WAIT_TIMEOUT,
            "unexpected WaitForMultipleObjects result: {result}"
        );

        Ok(())
    }
}

impl Device for WintunDevice {
    type RxToken<'a> = PooledRxToken;
    type TxToken<'a> = WintunTxToken;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(buffer) = self.pending_rx.take() {
            let rx = PooledRxToken { buffer };
            let tx = WintunTxToken {
                session: self.session.clone(),
            };
            Some((rx, tx))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(WintunTxToken {
            session: self.session.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        ip_capabilities(self.mtu)
    }
}

struct WintunTxToken {
    session: Arc<Session>,
}

impl TxToken for WintunTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // The happy path emits straight into the ring slot: no scratch copy.
        if let Ok(len16) = u16::try_from(len) {
            match self.session.allocate_send_packet(len16) {
                Ok(mut packet) => {
                    let result = f(packet.bytes_mut());
                    self.session.send_packet(packet);
                    return result;
                }
                Err(e) if is_ring_full(&e) => {
                    trace!("wintun send ring full, dropping a {len}-byte segment");
                }
                // The session dying under a TX token cannot propagate an
                // error, so it is surfaced the way the Unix token surfaces
                // a failed write().
                Err(e) => warn!("Failed to write to TUN: {e}"),
            }
        } else {
            warn!("Failed to write to TUN: {len}-byte segment exceeds the frame limit");
        }

        // smoltcp's contract is that `consume` runs the closure, so the
        // segment is built and dropped. This path is rare and lossy by
        // definition, so a plain allocation is fine here — unlike the Unix
        // token's scratch, which every packet passes through.
        f(&mut vec![0u8; len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun::wintun_device::open_wintun;

    /// The real thing: load wintun.dll, create an adapter, run the stack on
    /// a session, and tear it all down promptly.
    ///
    /// Ignored by default because it needs what CI does not have —
    /// Administrator and wintun.dll. Run it by hand from an elevated shell:
    /// `cargo test adapter_lifecycle -- --ignored --nocapture`
    #[test]
    #[ignore = "needs Administrator and wintun.dll; run from an elevated shell with --ignored"]
    fn adapter_lifecycle_round_trip() {
        let tun = open_wintun(
            "shoes-test0",
            "10.199.0.2".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
            1500,
        )
        .expect("open_wintun failed - is this shell elevated, with wintun.dll present?");

        let mut stack = TcpStackWintun::new(
            tun,
            TcpStackOptions {
                mtu: 1500,
                tcp_buffer_size: 32 * 1024,
                max_connections: 16,
                close_fd_on_drop: false,
            },
        );
        let _udp_rx = stack.take_udp_rx();

        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(stack.is_running(), "stack thread died right after start");

        // Drop must come back promptly: the session's shutdown event is what
        // gets an idle stack out of WaitForMultipleObjects, and a hang here
        // is exactly the bug it exists to prevent.
        let start = std::time::Instant::now();
        drop(stack);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "dropping the stack took {:?}; the shutdown event is not waking the wait",
            start.elapsed()
        );
    }
}
