//! How much memory a virtual TCP/IP stack may spend per connection.
//!
//! Two stacks in this crate run smoltcp over a byte pipe and allocate their
//! buffers up front, when a connection is opened rather than when it carries
//! anything: the TUN stack in `src/tun/tcp_stack_direct.rs`, and the AmneziaWG
//! virtual stack in `src/amneziawg/netstack.rs`. On a mobile VPN both are in
//! series — a browser connection is accepted by the first and initiated through
//! the second — so a number chosen in one of them is only half the bill.
//!
//! They do not, however, want the same number, and that difference is the whole
//! reason this module exists.
//!
//! # A local buffer versus a receive window
//!
//! Most of these buffers sit between two halves of this process: the TUN stack
//! faces an application on the same device, and both stacks keep ring buffers
//! between their smoltcp half and their async half. Nothing there spans a
//! network round trip. When such a buffer fills, the reader is a scheduling
//! quantum away, so it only has to cover jitter — a few tens of kilobytes is
//! generous, and more is memory spent on nothing.
//!
//! The AmneziaWG stack's *socket* buffers are a different thing wearing the
//! same shape. That smoltcp socket is the endpoint of a TCP connection whose
//! far end is a server on the internet, reached through the tunnel, so its
//! receive buffer is that connection's receive window and its send buffer holds
//! what is in flight and unacknowledged. Both are bandwidth-delay products, and
//! a window below one caps throughput at `window / RTT` however fast the link.
//!
//! That is not a theoretical distinction. Measured against a real AmneziaWG
//! peer at about 40 ms RTT, 50 MiB per transfer, five rounds each:
//!
//! | socket buffer | throughput | CPU per transfer |
//! |---|---|---|
//! | 256 KiB | 6.2 MB/s | 0.6-1.6 s |
//! | 64 KiB | 2.1 MB/s | 1.1-2.5 s |
//! | 32 KiB | 1.05 MB/s | 1.7-3.6 s |
//!
//! Throughput is linear in the window, which is what a window limit looks like,
//! and the smaller windows cost *more* CPU rather than less, because the same
//! bytes take five times as long to move. So the window keeps its size and the
//! local buffers get cut instead.
//!
//! # What a connection costs
//!
//! Through both stacks on mobile: four local buffers in the TUN stack, and two
//! window buffers plus two local buffers in the AmneziaWG stack — 128 KiB plus
//! 576 KiB, about 704 KiB. Against [`default_max_connections`] that is a
//! ceiling near 176 MiB, and roughly a third of that resident, since these are
//! zero pages the kernel faults in only as they are written.

/// Bytes of buffering per direction for a buffer that does not span a network
/// round trip: the TUN stack's socket buffers, and both stacks' ring buffers.
pub const fn default_local_buffer_size() -> usize {
    if cfg!(any(target_os = "ios", target_os = "android")) {
        32 * 1024
    } else {
        64 * 1024
    }
}

/// Bytes of receive window, and of unacknowledged send data, for a connection
/// whose far end is across the internet.
///
/// Not platform-dependent: a phone's round trip is longer than a server's, not
/// shorter, so there is nothing here to save by being on a phone. 256 KiB
/// carries about 6 MB/s at 40 ms and about 2.5 MB/s at 100 ms.
pub const fn default_remote_window_size() -> usize {
    256 * 1024
}

/// Connections a virtual TCP stack accepts before it refuses more.
pub const fn default_max_connections() -> usize {
    if cfg!(any(target_os = "ios", target_os = "android")) {
        256
    } else {
        1024
    }
}
