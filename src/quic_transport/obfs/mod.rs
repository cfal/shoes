//! QUIC packet obfuscation.

mod salamander;
mod socket;

pub use salamander::Salamander;
pub use socket::ObfuscatedUdpSocket;

use std::fmt::Debug;

/// A symmetric packet obfuscator applied to every UDP datagram of a QUIC
/// connection, on both ends.
///
/// Implementations are used from many threads at once and must not require
/// exclusive access.
pub trait Obfuscator: Send + Sync + Debug {
    /// Transform `input` into `out`, returning the number of bytes written.
    ///
    /// Returns None when `out` is too small, which the caller treats as a
    /// dropped packet rather than an error.
    fn obfuscate(&self, input: &[u8], out: &mut [u8]) -> Option<usize>;

    /// Reverse `obfuscate`, in place, returning the length of the recovered
    /// payload. Returns None for a packet that cannot be a valid obfuscated
    /// datagram.
    ///
    /// In place rather than into a second buffer because this runs on every
    /// received packet: the recovered bytes only ever move toward the front of
    /// the buffer, so nothing is lost by overwriting as we go, and the receive
    /// path stays free of a per-packet allocation.
    fn deobfuscate_in_place(&self, buf: &mut [u8]) -> Option<usize>;

    /// Bytes added to every packet. Subtracted from the QUIC MTU.
    fn overhead(&self) -> usize;
}
