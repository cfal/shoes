//! The mieru proxy protocol, client side.
//!
//! Wire format verified against enfein/mieru at b9bbc41; see
//! docs/superpowers/specs/2026-08-20-mieru-client-outbound-design.md for the
//! citation table.

pub mod crypto;
pub mod frame;
pub mod metadata;
pub mod padding;
pub mod stream;
#[cfg(test)]
pub mod testing;

/// Nonce size of XChaCha20-Poly1305. `pkg/cipher/api.go:31`.
pub const NONCE_LEN: usize = 24;

/// AEAD tag size. `pkg/cipher/api.go:32`.
pub const TAG_LEN: usize = 16;

/// Fixed metadata size. `docs/protocol.md`, "Metadata Format".
pub const METADATA_LEN: usize = 32;

/// Largest application fragment in one segment. `docs/protocol.md`,
/// "TCP Segment Rules".
pub const MAX_FRAGMENT_LEN: usize = 32768;

/// Largest padding at any position over TCP. `pkg/protocol/padding.go:95`
/// returns 255 for StreamTransport.
pub const MAX_PADDING_LEN: usize = 255;

#[cfg(test)]
mod tests {
    use super::*;

    /// The overhead of a segment carrying a payload: metadata plus its tag,
    /// plus the payload's tag. `pkg/protocol/underlay_stream.go:41` defines
    /// streamOverhead as MetadataLength + DefaultOverhead*2.
    #[test]
    fn test_stream_overhead_matches_upstream() {
        assert_eq!(METADATA_LEN + TAG_LEN * 2, 64);
    }
}
