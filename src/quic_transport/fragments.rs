//! Reassembly of fragmented UDP payloads.
//!
//! Hysteria2 and TUIC both split a UDP payload that does not fit one QUIC
//! datagram into numbered fragments under a shared packet id, and both put the
//! pieces back together the same way. Only the framing differs, so the callers
//! parse their own headers and hand the results here.
//!
//! It lives beside the other QUIC-protocol machinery because those two are its
//! only users; nothing about the table itself is QUIC-specific.

use lru::LruCache;
use std::num::NonZeroUsize;

/// Packets a single session will hold while waiting for their missing pieces.
///
/// This is a bound on memory, not a tuning knob. Without one the table grows
/// with every packet id whose fragments never all arrive, and a peer that sends
/// one fragment of each id and completes none makes it grow until the process
/// dies. Both servers already cap this at 256 under the same name; matching
/// them keeps one answer to the question rather than two.
///
/// It is also generous for the legitimate case: fragments of a packet arrive
/// back to back, so more than a handful are in flight only when the path is
/// reordering heavily.
pub const MAX_PENDING_PACKETS: usize = 256;

/// Fragments waiting for their siblings, keyed by packet id.
///
/// A packet whose fragments never all arrive is dropped once its id is reused
/// or it falls out of the cache, which is the protocol's own rule: a lost
/// fragment loses the whole packet, and UDP was never going to guarantee
/// otherwise.
pub struct FragmentTable {
    packets: LruCache<u16, Vec<Option<Vec<u8>>>>,
}

impl Default for FragmentTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FragmentTable {
    pub fn new() -> Self {
        Self {
            packets: LruCache::new(
                NonZeroUsize::new(MAX_PENDING_PACKETS).expect("the capacity is a non-zero literal"),
            ),
        }
    }

    /// Feed one fragment; returns the whole payload when the last piece lands.
    ///
    /// Returns None both for a fragment that merely completes nothing and for
    /// one that cannot be valid. The caller cannot act differently on the two,
    /// and a malformed fragment is a dropped packet either way.
    pub fn push(
        &mut self,
        packet_id: u16,
        fragment_id: u8,
        fragment_count: u8,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        if fragment_count == 0 || fragment_id >= fragment_count {
            return None;
        }
        // The overwhelmingly common case: nothing is stored, so an unfragmented
        // packet cannot be made to occupy the table at all.
        if fragment_count == 1 {
            return Some(payload.to_vec());
        }

        let slots = self
            .packets
            .get_or_insert_mut(packet_id, || vec![None; fragment_count as usize]);
        if slots.len() != fragment_count as usize {
            // The id was reused with a different fragment count, so the older
            // packet can never complete. Start over rather than mixing them.
            *slots = vec![None; fragment_count as usize];
        }
        slots[fragment_id as usize] = Some(payload.to_vec());

        if slots.iter().all(|slot| slot.is_some()) {
            let slots = self.packets.pop(&packet_id)?;
            Some(slots.into_iter().flatten().flatten().collect())
        } else {
            None
        }
    }

    /// Packets currently held incomplete.
    #[cfg(test)]
    fn pending(&self) -> usize {
        self.packets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_an_unfragmented_packet_passes_straight_through() {
        let mut table = FragmentTable::new();
        assert_eq!(table.push(1, 0, 1, b"payload").unwrap(), b"payload");
        assert_eq!(table.pending(), 0, "nothing should have been stored");
    }

    #[test]
    fn test_fragments_reassemble_in_order() {
        let mut table = FragmentTable::new();
        assert!(table.push(7, 0, 3, b"one ").is_none());
        assert!(table.push(7, 1, 3, b"two ").is_none());
        assert_eq!(table.push(7, 2, 3, b"three").unwrap(), b"one two three");
        assert_eq!(table.pending(), 0, "a completed packet must be released");
    }

    #[test]
    fn test_fragments_reassemble_out_of_order() {
        let mut table = FragmentTable::new();
        assert!(table.push(7, 2, 3, b"three").is_none());
        assert!(table.push(7, 0, 3, b"one ").is_none());
        assert_eq!(table.push(7, 1, 3, b"two ").unwrap(), b"one two three");
    }

    #[test]
    fn test_two_packets_reassemble_independently() {
        let mut table = FragmentTable::new();
        assert!(table.push(1, 0, 2, b"a").is_none());
        assert!(table.push(2, 0, 2, b"c").is_none());
        assert_eq!(table.push(2, 1, 2, b"d").unwrap(), b"cd");
        assert_eq!(table.push(1, 1, 2, b"b").unwrap(), b"ab");
    }

    #[test]
    fn test_a_reused_id_with_a_new_count_starts_over() {
        let mut table = FragmentTable::new();
        assert!(table.push(1, 0, 3, b"stale").is_none());
        // Same id, different count: the earlier fragment cannot belong to it.
        assert!(table.push(1, 0, 2, b"a").is_none());
        assert_eq!(table.push(1, 1, 2, b"b").unwrap(), b"ab");
    }

    #[test]
    fn test_invalid_fragment_headers_are_refused() {
        let mut table = FragmentTable::new();
        assert!(table.push(1, 0, 0, b"count of zero").is_none());
        assert!(table.push(1, 3, 3, b"id equal to count").is_none());
        assert!(table.push(1, 9, 3, b"id past the count").is_none());
        assert_eq!(table.pending(), 0, "nothing invalid should be stored");
    }

    /// The reason this type exists.
    ///
    /// Both clients used to hold these in a plain HashMap that was only ever
    /// emptied by a packet completing, so a server sending one fragment of
    /// every id and completing none grew the client's memory without limit.
    #[test]
    fn test_incomplete_packets_cannot_grow_without_bound() {
        let mut table = FragmentTable::new();

        // Every u16 id, one fragment each, none of them ever completing.
        for packet_id in 0..=u16::MAX {
            assert!(table.push(packet_id, 0, 2, b"first half").is_none());
        }

        assert_eq!(
            table.pending(),
            MAX_PENDING_PACKETS,
            "the table must stop at its capacity"
        );
    }

    /// Eviction must not corrupt a packet that is still being assembled: the
    /// survivors of a flood still complete correctly.
    #[test]
    fn test_a_packet_still_completes_after_eviction_pressure() {
        let mut table = FragmentTable::new();
        assert!(table.push(1000, 0, 2, b"kept ").is_none());

        // Push the tracked packet out with more than a cache's worth of others.
        for packet_id in 0..MAX_PENDING_PACKETS as u16 {
            assert!(table.push(packet_id, 0, 2, b"noise").is_none());
        }

        // Its first half is gone, so the second half alone completes nothing.
        assert!(table.push(1000, 1, 2, b"half").is_none());
        // And it is now tracked afresh rather than left corrupt.
        assert_eq!(table.push(1000, 0, 2, b"other ").unwrap(), b"other half");
    }

    /// Touching a packet must keep it alive - otherwise a steady trickle of
    /// noise would evict a packet whose fragments are still arriving.
    #[test]
    fn test_a_packet_being_filled_survives_less_recent_ones() {
        let mut table = FragmentTable::new();
        assert!(table.push(9999, 0, 3, b"a").is_none());

        for packet_id in 0..(MAX_PENDING_PACKETS as u16 - 1) {
            assert!(table.push(packet_id, 0, 2, b"noise").is_none());
            // Keep the tracked packet at the recent end of the cache.
            assert!(table.push(9999, 1, 3, b"b").is_none());
        }

        assert_eq!(table.push(9999, 2, 3, b"c").unwrap(), b"abc");
    }
}
