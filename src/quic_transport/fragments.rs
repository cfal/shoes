//! Reassembly of fragmented UDP payloads.
//!
//! Hysteria2 and TUIC both split a UDP payload that does not fit one QUIC
//! datagram into numbered fragments under a shared packet id. The callers parse
//! their own framing and hand the results here.
//!
//! The two protocols do not agree on how much may be in flight, so there are
//! two reassemblers. [`Defragmenter`] holds one packet id, which is Hysteria2's
//! rule and its memory bound. [`FragmentTable`] holds a bounded table of them,
//! which is what TUIC uses.
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

/// TUIC's reassembler: a bounded table of packets waiting for their pieces.
///
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

/// Reassembly for a protocol that keeps one packet id in flight at a time.
///
/// Hysteria2's rule, on both of its ends: `frag.Defragger` tracks a single
/// packet id and throws away what it held the moment a different one arrives
/// (`core/internal/frag/frag.go:40-43`). A lost fragment costs one packet and
/// nothing else.
///
/// That rule is the memory bound. A session can be made to hold one packet -
/// at most 255 fragments of a QUIC datagram, about 300 KB - where a table
/// keyed by packet id holds as many as its capacity, which a peer fills by
/// sending every fragment of every id but one.
///
/// [`FragmentTable`] is the other answer to the same question and TUIC keeps
/// it. Whether TUIC's reference also holds one packet at a time has not been
/// read, and Hysteria's source is not evidence about TUIC's.
pub struct Defragmenter {
    in_flight: Option<InFlight>,
}

struct InFlight {
    packet_id: u16,
    slots: Vec<Option<Vec<u8>>>,
    /// Slots filled. Counted rather than rescanned, and incremented only when
    /// an empty slot is filled, so a duplicate cannot complete a packet that
    /// still has a hole.
    received: usize,
    /// Bytes held, so the finished packet is allocated once at its real size.
    len: usize,
}

impl Default for Defragmenter {
    fn default() -> Self {
        Self::new()
    }
}

impl Defragmenter {
    pub fn new() -> Self {
        Self { in_flight: None }
    }

    /// The packet id being assembled, or None between packets.
    ///
    /// For a caller that keeps something of its own beside the packet - the
    /// Hysteria2 server keeps the remote address the first fragment carried -
    /// this is how it learns that a new packet has started.
    pub fn in_flight_packet_id(&self) -> Option<u16> {
        self.in_flight.as_ref().map(|p| p.packet_id)
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

        // The common case, and it must not touch the state: upstream returns
        // the message for `FragCount <= 1` before it looks at the id
        // (`frag.go:31-33`), so an unfragmented packet arriving between the
        // fragments of a larger one cannot discard it.
        if fragment_count == 1 {
            return Some(payload.to_vec());
        }

        let continues_current = self
            .in_flight
            .as_ref()
            .is_some_and(|p| p.packet_id == packet_id && p.slots.len() == fragment_count as usize);
        if !continues_current {
            // A different id, or the same id with a different count: whatever
            // was held can never complete, so it goes rather than accumulating.
            self.in_flight = Some(InFlight {
                packet_id,
                slots: vec![None; fragment_count as usize],
                received: 0,
                len: 0,
            });
        }

        let in_flight = self
            .in_flight
            .as_mut()
            .expect("in_flight was just set if it was not already the current packet");

        let slot = &mut in_flight.slots[fragment_id as usize];
        if slot.is_some() {
            return None;
        }
        *slot = Some(payload.to_vec());
        in_flight.received += 1;
        in_flight.len += payload.len();

        if in_flight.received < in_flight.slots.len() {
            return None;
        }

        let done = self.in_flight.take()?;
        let mut packet = Vec::with_capacity(done.len);
        for fragment in done.slots.into_iter().flatten() {
            packet.extend_from_slice(&fragment);
        }
        Some(packet)
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

    #[test]
    fn test_defragmenter_passes_an_unfragmented_packet_straight_through() {
        let mut frag = Defragmenter::new();
        assert_eq!(frag.push(1, 0, 1, b"payload").unwrap(), b"payload");
        assert_eq!(
            frag.in_flight_packet_id(),
            None,
            "nothing should have been stored"
        );
    }

    #[test]
    fn test_defragmenter_reassembles_in_order() {
        let mut frag = Defragmenter::new();
        assert!(frag.push(7, 0, 3, b"one ").is_none());
        assert!(frag.push(7, 1, 3, b"two ").is_none());
        assert_eq!(frag.push(7, 2, 3, b"three").unwrap(), b"one two three");
        assert_eq!(
            frag.in_flight_packet_id(),
            None,
            "a completed packet must be released"
        );
    }

    #[test]
    fn test_defragmenter_reassembles_out_of_order() {
        let mut frag = Defragmenter::new();
        assert!(frag.push(7, 2, 3, b"three").is_none());
        assert!(frag.push(7, 0, 3, b"one ").is_none());
        assert_eq!(frag.push(7, 1, 3, b"two ").unwrap(), b"one two three");
    }

    /// The rule that bounds the memory: upstream keeps one packet id and drops
    /// what it held the moment another arrives (`frag.go:40-43`). The older
    /// packet is not merely deprioritised - it is gone, and its remaining
    /// fragments complete nothing.
    #[test]
    fn test_defragmenter_a_new_packet_id_discards_the_previous_one() {
        let mut frag = Defragmenter::new();
        assert!(frag.push(1, 0, 2, b"first half").is_none());

        assert!(frag.push(2, 0, 2, b"other ").is_none());
        assert_eq!(frag.in_flight_packet_id(), Some(2));

        // Packet 1's second half now completes nothing: its first half is gone.
        assert!(frag.push(1, 1, 2, b"second half").is_none());
        // And packet 2 is what is being tracked, uncorrupted by the visit.
        assert_eq!(
            frag.in_flight_packet_id(),
            Some(1),
            "the stray restarted it"
        );
    }

    /// An unfragmented packet arriving mid-reassembly must not disturb it:
    /// upstream returns early for `FragCount <= 1` before touching any state.
    #[test]
    fn test_defragmenter_an_unfragmented_packet_does_not_disturb_reassembly() {
        let mut frag = Defragmenter::new();
        assert!(frag.push(7, 0, 2, b"one ").is_none());
        assert_eq!(frag.push(9, 0, 1, b"unrelated").unwrap(), b"unrelated");
        assert_eq!(frag.push(7, 1, 2, b"two").unwrap(), b"one two");
    }

    #[test]
    fn test_defragmenter_a_reused_id_with_a_new_count_starts_over() {
        let mut frag = Defragmenter::new();
        assert!(frag.push(1, 0, 3, b"stale").is_none());
        // Same id, different count: the earlier fragment cannot belong to it.
        assert!(frag.push(1, 0, 2, b"a").is_none());
        assert_eq!(frag.push(1, 1, 2, b"b").unwrap(), b"ab");
    }

    /// A repeated fragment must not be counted twice, or a packet with a hole
    /// in it would be released as complete.
    #[test]
    fn test_defragmenter_a_duplicate_fragment_completes_nothing() {
        let mut frag = Defragmenter::new();
        assert!(frag.push(1, 0, 3, b"a").is_none());
        assert!(frag.push(1, 0, 3, b"a").is_none());
        assert!(frag.push(1, 1, 3, b"b").is_none());
        assert_eq!(
            frag.in_flight_packet_id(),
            Some(1),
            "two of three slots are filled, so nothing may have been released"
        );
        assert_eq!(frag.push(1, 2, 3, b"c").unwrap(), b"abc");
    }

    #[test]
    fn test_defragmenter_refuses_invalid_fragment_headers() {
        let mut frag = Defragmenter::new();
        assert!(frag.push(1, 0, 0, b"count of zero").is_none());
        assert!(frag.push(1, 3, 3, b"id equal to count").is_none());
        assert!(frag.push(1, 9, 3, b"id past the count").is_none());
        assert_eq!(
            frag.in_flight_packet_id(),
            None,
            "nothing invalid should be stored"
        );
    }

    /// The reason this type exists beside `FragmentTable`.
    ///
    /// A peer sending 254 of every packet's 255 fragments and completing none
    /// makes a 256-entry table hold about 78 MB. Holding one packet id caps the
    /// same attack at one packet, and every id after the first costs nothing
    /// extra because it evicts the one before it.
    #[test]
    fn test_defragmenter_holds_one_packet_however_many_ids_arrive() {
        let mut frag = Defragmenter::new();

        for packet_id in 0..=u16::MAX {
            assert!(frag.push(packet_id, 0, 255, b"first fragment").is_none());
            assert_eq!(
                frag.in_flight_packet_id(),
                Some(packet_id),
                "only the newest id may be held"
            );
        }
    }
}
