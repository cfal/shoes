//! How much memory a virtual TCP/IP stack may spend per connection.
//!
//! Two stacks in this crate run smoltcp over a byte pipe and allocate their
//! buffers up front, when a connection is accepted rather than when it carries
//! anything: the TUN stack in `src/tun/tcp_stack_direct.rs`, and the AmneziaWG
//! virtual stack in `src/amneziawg/netstack.rs`. On a mobile VPN both are in
//! series — a browser connection is accepted by the first and initiated through
//! the second — so a number chosen in one of them is only half the bill.
//!
//! They share their defaults here so that the total stays something anyone can
//! work out. Per connection it is eight buffers of [`default_tcp_buffer_size`]:
//! 512 KiB on mobile, 1 MiB elsewhere. Against
//! [`default_max_connections`] that is a ceiling of 128 MiB and 1 GiB
//! respectively.
//!
//! The mobile figure is set by an iOS `NEPacketTunnelProvider`, which is killed
//! rather than warned when the extension crosses roughly 50 MB — so the point
//! is not that the ceiling is comfortable but that reaching it takes hundreds
//! of simultaneous connections rather than the thirty-five the previous
//! constants allowed.
//!
//! Note what these buffers are not: neither spans a network round trip. Both
//! sit between two halves of this process, so their size buys tolerance for a
//! burst that arrives while the other half is not scheduled, not throughput.
//! That is why a number sized for a desktop 10 GbE path — the 320 KiB and
//! 256 KiB these replaced — bought nothing on a phone except a jetsam kill.

/// Bytes of buffering per direction, per connection, in a virtual TCP stack.
pub const fn default_tcp_buffer_size() -> usize {
    if cfg!(any(target_os = "ios", target_os = "android")) {
        32 * 1024
    } else {
        64 * 1024
    }
}

/// Connections a virtual TCP stack accepts before it refuses more.
pub const fn default_max_connections() -> usize {
    if cfg!(any(target_os = "ios", target_os = "android")) {
        256
    } else {
        1024
    }
}
