# Hysteria2 Conformance, Phase 2 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Take the three robustness defects in the Hysteria2 UDP path — a
reassembly table a peer can grow to about 78 MB per session, a session removal
that leaks its socket and task, and an `assert!` plus a truncating cast on a
path reachable from network input — and close them the way the reference
implementation does.

**Architecture:** Three independent repairs. Reassembly moves to a new
`Defragmenter` that holds one packet id at a time, mirroring upstream's
`frag.Defragger`, and both Hysteria2 ends use it. Session removal becomes
structurally safe by cancelling in `Drop`, so no future removal path can forget.
The idle sweep moves onto a timer instead of running only when a datagram
happens to arrive. And the reply path's size arithmetic becomes one pure
function that returns errors where it used to panic and truncate.

**Tech Stack:** Rust, quinn 0.11, tokio. Reference: HyNetworks/hysteria at
`619a6f8`. Clone it to `/tmp/hysteria` if you need to read it:
`git clone https://github.com/HyNetworks/hysteria /tmp/hysteria && git -C /tmp/hysteria checkout 619a6f8`

**Spec:** [docs/superpowers/specs/2026-08-24-hysteria2-conformance-design.md](../specs/2026-08-24-hysteria2-conformance-design.md), phase 2

## Global Constraints

- **Nothing here changes the wire format.** Phase 2 is memory, lifetime and
  panic-safety. A peer that worked before must work identically after, and the
  bytes on the wire must not move. Phase 3 owns every deliberate wire change.
- **No `assert!`, `unwrap()`, `expect()` or `panic!` on a value that came from
  the network.** That is the whole of item 2.3, and it applies to the code the
  other tasks touch as well.
- **`cargo fmt --all -- --check` must pass before every commit.** It is the
  first job in `.github/workflows/lint.yml` and it blocks CI. Running it only at
  the end has cost this repository a red build before.
- Clippy runs with `-D warnings` across four feature combinations — see Task 7.
  A warning is a failure.
- **TUIC is out of scope.** `FragmentTable` stays exactly as it is for TUIC's
  use. Hysteria's source says nothing about what TUIC's reference does, and
  changing TUIC's reassembly on the strength of it would be precisely the
  unchecked assumption this conformance effort exists to remove.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `src/quic_transport/fragments.rs` | Gains `Defragmenter`, the one-packet-in-flight reassembler. Keeps `FragmentTable` for TUIC, with its doc corrected to say so. |
| `src/hysteria2/server.rs` | Reassembles with `Defragmenter`; cancels a session in `Drop`; sweeps on a timer; replaces the reply path's `assert!` and `as u8` with one checked function |
| `src/hysteria2/udp.rs` | The client session reassembles with `Defragmenter` too — upstream's client uses the same `frag` package |
| `CHANGELOG.md` | The record |

Task 1 produces the type Tasks 2 and 3 consume. Task 6 is independent of
everything. Tasks 4 and 5 are independent of Tasks 1–3 and 6, but **Task 5's
tests use the `detached_session` helper that Task 4 introduces**, so do 4 first
or move the helper into 5.

The recommended order is 1 → 2 → 3 → 4 → 5 → 6 → 7, and it is the order the
tasks are written in: it is the only order in which every task's test compiles
against the tree as the previous task left it.

---

### Task 1: One packet id in flight

**Files:**
- Modify: `src/quic_transport/fragments.rs` (add `Defragmenter` beside `FragmentTable`; correct `FragmentTable`'s module and type docs)
- Test: `src/quic_transport/fragments.rs` — the existing `#[cfg(test)] mod tests` at the bottom of the file

**Interfaces:**
- Consumes: nothing.
- Produces:
  ```rust
  pub struct Defragmenter { /* private */ }
  impl Default for Defragmenter { fn default() -> Self }
  impl Defragmenter {
      pub fn new() -> Self;
      /// Feed one fragment; returns the whole payload when the last piece lands.
      pub fn push(
          &mut self,
          packet_id: u16,
          fragment_id: u8,
          fragment_count: u8,
          payload: &[u8],
      ) -> Option<Vec<u8>>;
      /// The packet id currently being assembled, or None between packets.
      pub fn in_flight_packet_id(&self) -> Option<u16>;
  }
  ```

**Why this shape.** Upstream's `frag.Defragger` (`core/internal/frag/frag.go:20-60`)
holds exactly one packet id. A fragment carrying a different id throws away
whatever was held and starts over, and an unfragmented message is returned
before the id is even looked at. That is the entire memory bound: one packet,
at most 255 fragments of a QUIC datagram, about 300 KB — against
`MAX_FRAGMENT_CACHE_SIZE = 256` packets of the same shape, which a peer can
fill to roughly 78 MB per session by sending 254 of every packet's 255
fragments and completing none.

`in_flight_packet_id` exists for one caller: the Hysteria2 server keeps the
remote address from the fragment that started a packet, and needs to know when a
packet has started. It is a small window into the state rather than a generic
metadata slot, because the client (Task 3) has a fixed address per session and
would carry a type parameter for nothing.

- [x] **Step 1: Write the failing tests**

Add to the existing `mod tests` at the bottom of
`src/quic_transport/fragments.rs`. Note the `Defragmenter::` prefix: these live
beside `FragmentTable`'s tests, which stay untouched.

```rust
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
        assert_eq!(frag.in_flight_packet_id(), Some(1), "the stray restarted it");
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
```

- [x] **Step 2: Run the tests to verify they fail**

```bash
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"
cargo test --lib quic_transport::fragments
```

Expected: FAIL to compile, `cannot find type Defragmenter in this scope` (E0433
/ E0412) at every one of the new tests. A compile failure is the correct red
here — the type does not exist yet.

- [x] **Step 3: Write the implementation**

Add above the `#[cfg(test)] mod tests` block in
`src/quic_transport/fragments.rs`:

```rust
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
```

The `slots[fragment_id as usize]` index cannot panic: `fragment_id <
fragment_count` was checked at the top, and `slots.len() == fragment_count` is
either freshly constructed above or was the condition for reusing the existing
one.

- [x] **Step 4: Correct `FragmentTable`'s docs**

The module doc at the top of the file says Hysteria2 and TUIC both use the
table. After Task 3 only TUIC does. Replace the module doc's second paragraph
and add a line to `FragmentTable`'s own doc:

Module doc — replace:

```rust
//! Hysteria2 and TUIC both split a UDP payload that does not fit one QUIC
//! datagram into numbered fragments under a shared packet id, and both put the
//! pieces back together the same way. Only the framing differs, so the callers
//! parse their own headers and hand the results here.
```

with:

```rust
//! Hysteria2 and TUIC both split a UDP payload that does not fit one QUIC
//! datagram into numbered fragments under a shared packet id. The callers parse
//! their own framing and hand the results here.
//!
//! The two protocols do not agree on how much may be in flight, so there are
//! two reassemblers. [`Defragmenter`] holds one packet id, which is Hysteria2's
//! rule and its memory bound. [`FragmentTable`] holds a bounded table of them,
//! which is what TUIC uses.
```

`FragmentTable`'s type doc — add as its first line:

```rust
/// TUIC's reassembler: a bounded table of packets waiting for their pieces.
///
```

- [x] **Step 5: Run the tests to verify they pass**

```bash
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"
cargo test --lib quic_transport::fragments
```

Expected: PASS, including every pre-existing `FragmentTable` test — this task
adds a type and must not have changed one.

- [x] **Step 6: Format, lint and commit**

```bash
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --locked --lib --tests -- -D warnings
git add src/quic_transport/fragments.rs
git commit -m "quic_transport: a reassembler that holds one packet id"
```

---

### Task 2: The Hysteria2 server reassembles with it

**Files:**
- Modify: `src/hysteria2/server.rs` — delete `MAX_FRAGMENT_CACHE_SIZE` (`:32-34`) and `struct FragmentedPacket` (`:302-308`), change `UdpSession` (`:288-300`), replace the reassembly block in `run_udp_local_to_remote_loop` (`:684-750`)
- Test: `src/hysteria2/client.rs` — the existing in-process client↔server tests cover this end to end

**Interfaces:**
- Consumes: `Defragmenter::{new, push, in_flight_packet_id}` from Task 1.
- Produces: nothing new. `UdpSession` is private to `server.rs`.

**What changes and what must not.** This is a swap of one reassembler for
another. The server's own header validation stays exactly where it is — the
`fragment_count == 0` and `fragment_id >= fragment_count` guards log at `error!`
with the session id, and that diagnosis is worth keeping even though
`Defragmenter` would refuse the same fragments silently.

- [x] **Step 1: Confirm the existing coverage passes first**

```bash
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"
cargo test --lib hysteria2::client::tests::test_large_udp_payload_is_fragmented_and_reassembled
cargo test --lib hysteria2::
```

Expected: PASS. This is the baseline the refactor has to preserve; a failure
here is a pre-existing flake, not something this task caused, and it needs
chasing before continuing.

- [x] **Step 2: Change the imports and the session struct**

At the top of `src/hysteria2/server.rs`, remove:

```rust
use lru::LruCache;
```

and

```rust
use std::num::NonZeroUsize;
```

Check first that nothing else in the file uses them:

```bash
grep -n "LruCache\|NonZeroUsize" src/hysteria2/server.rs
```

Only the fragment cache should appear. Add to the crate imports beside the
other `crate::quic_transport` use:

```rust
use crate::quic_transport::fragments::Defragmenter;
```

Delete the constant:

```rust
/// Maximum number of fragmented packets to track per session.
/// Old entries are automatically evicted when this limit is reached.
const MAX_FRAGMENT_CACHE_SIZE: usize = 256;
```

Delete `struct FragmentedPacket` entirely:

```rust
struct FragmentedPacket {
    fragment_count: u8,
    fragment_received: u8,
    packet_len: usize,
    received: Vec<Option<Bytes>>,
    remote_location: NetLocation,
}
```

In `struct UdpSession`, replace the `fragments` field and add the location the
packet arrived with:

```rust
struct UdpSession {
    fragments: Defragmenter,
    /// The address the fragment that started the in-flight packet carried.
    ///
    /// The protocol repeats the address in every fragment, but only the first
    /// one decides where the reassembled packet goes - upstream reads it off
    /// the message that opened the packet (`core/server/udp.go:137`). Kept
    /// beside the reassembler rather than inside it because the client end has
    /// one fixed address per session and would carry this for nothing.
    pending_location: Option<NetLocation>,
    send_socket: Arc<UdpSocket>,
    // we cache the last location in case of mid-session address changes, and
    // don't want to have to call ClientProxySelector::judge on every packet.
    last_location: NetLocation,
    last_socket_addr: SocketAddr,
    override_remote_write_address: Option<SocketAddr>,
    // Shared with the spawned remote-to-local task so that reply traffic counts as
    // activity too; otherwise a download-only session would be reaped mid-transfer.
    last_activity: Arc<AtomicU64>,
    cancel_token: CancellationToken,
}
```

In `UdpSession::start`, replace the initialiser's first line:

```rust
        let session = UdpSession {
            fragments: Defragmenter::new(),
            pending_location: None,
            send_socket: client_socket.clone(),
```

- [x] **Step 3: Replace the reassembly block**

In `run_udp_local_to_remote_loop`, replace the whole
`let (complete_payload, remote_location) = if fragment_count == 0 { ... };`
expression — from the `if fragment_count == 0` line down to the closing `};`
before `let socket_addr = match session.override_remote_write_address` — with:

```rust
        let (complete_payload, remote_location) = if fragment_count == 0 {
            error!("Ignoring empty UDP fragment for session {session_id}");
            continue;
        } else if fragment_id >= fragment_count {
            error!("Ignoring out-of-range UDP fragment for session {session_id}");
            continue;
        } else if fragment_count == 1 {
            (payload_fragment, remote_location)
        } else {
            // A packet id we are not already assembling starts a new packet,
            // and the address it carries is the one the whole packet goes to.
            if session.fragments.in_flight_packet_id() != Some(packet_id) {
                session.pending_location = Some(remote_location.clone());
            }
            match session.fragments.push(
                packet_id,
                fragment_id,
                fragment_count,
                &payload_fragment,
            ) {
                Some(packet) => {
                    let location = session.pending_location.take().unwrap_or(remote_location);
                    (Bytes::from(packet), location)
                }
                None => continue,
            }
        };
```

Two things about this that are easy to get wrong:

- The `fragment_count == 1` arm returns before the reassembler is touched, so an
  unfragmented packet cannot clear `pending_location` out from under a
  fragmented one that is still arriving.
- `pending_location.take()` empties it on completion, so the next fragment of a
  new packet is always seen as starting one.

- [x] **Step 4: Run the tests to verify they pass**

```bash
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"
cargo test --lib hysteria2::
```

Expected: PASS, and in particular
`test_large_udp_payload_is_fragmented_and_reassembled`, which sends 4000 bytes
through the client and the server — larger than one QUIC datagram, so the
client fragments it and this code is what puts it back together.

- [x] **Step 5: Confirm the old table is gone**

```bash
grep -n "LruCache\|FragmentedPacket\|MAX_FRAGMENT_CACHE_SIZE" src/hysteria2/server.rs
```

Expected: no output. Non-empty output means a leftover, and `cargo build` would
have warned about an unused import rather than failed.

- [x] **Step 6: Format, lint and commit**

```bash
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --locked --lib --tests -- -D warnings
git add src/hysteria2/server.rs
git commit -m "hysteria2: hold one packet id per UDP session, as upstream does"
```

---

### Task 3: The Hysteria2 client reassembles with it too

**Files:**
- Modify: `src/hysteria2/udp.rs:14` (import), `:41` (field), `:74` (initialiser)
- Test: `src/hysteria2/udp.rs` — the existing `mod tests` at `:199`

**Interfaces:**
- Consumes: `Defragmenter::{new, push}` from Task 1.
- Produces: nothing.

**Why the client too.** Upstream's client uses the same `frag` package as its
server (`core/client/udp.go`), so one packet in flight is the protocol's rule
rather than a server-side hardening measure. The client's exposure is the same
shape and it is the end that runs on a phone, where the 78 MB matters most.

- [x] **Step 1: Read the existing tests**

```bash
sed -n '199,273p' src/hysteria2/udp.rs
```

They drive reassembly through `push_wire`, which parses a real datagram and
feeds the table. They are the coverage for this change; note which of them
assume more than one packet may be in flight, because such a test is now
asserting the old rule and must be rewritten rather than deleted.

- [x] **Step 2: Swap the type**

`src/hysteria2/udp.rs:14`:

```rust
use crate::quic_transport::fragments::Defragmenter;
```

`:41`:

```rust
    fragments: Defragmenter,
```

`:74`:

```rust
            fragments: Defragmenter::new(),
```

And `push_wire`'s signature at `:206`:

```rust
    fn push_wire(table: &mut Defragmenter, datagram: &[u8]) -> Option<Vec<u8>> {
```

with every `FragmentTable::new()` in that test module becoming
`Defragmenter::new()`.

- [x] **Step 3: Run the tests**

```bash
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"
cargo test --lib hysteria2::udp
```

Expected: PASS. If a test fails because it interleaves two packet ids and
expects both to complete, it was asserting the unbounded rule. Rewrite it to
assert the new one — the older id is discarded — and say in the test's doc
comment that this is upstream's behaviour, citing `frag.go:40-43`. Do not
delete it.

- [x] **Step 4: Run the whole Hysteria2 suite**

```bash
cargo test --lib hysteria2::
```

Expected: PASS. `test_large_udp_payload_is_fragmented_and_reassembled` now
exercises `Defragmenter` on both ends at once.

- [x] **Step 5: Format, lint and commit**

```bash
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --locked --lib --tests -- -D warnings
git add src/hysteria2/udp.rs
git commit -m "hysteria2: the client holds one packet id too"
```

---

### Task 4: A removed session cannot leave its task running

**Files:**
- Modify: `src/hysteria2/server.rs` — add `impl Drop for UdpSession`, simplify the sweep at `:533-540`, fix the send-failure removal at `:803-810`
- Test: `src/hysteria2/server.rs` — the `#[cfg(test)] mod tests` at `:1057`

**Interfaces:**
- Consumes: `UdpSession`. Only its `cancel_token` field matters here, so this
  task does not depend on Tasks 1–3 — but the `detached_session` helper below
  builds a `UdpSession` field by field, so **its field list must match whichever
  version of the struct is in the tree.** As written it matches the struct after
  Task 2. If Task 2 has not been done, replace `fragments: Defragmenter::new(),
  pending_location: None,` with
  `fragments: LruCache::new(NonZeroUsize::new(MAX_FRAGMENT_CACHE_SIZE).unwrap()),`.
- Produces: `detached_session`, which Task 5's tests also use.

**The defect.** `sessions.remove(&session_id)` on a send failure
(`server.rs:809`) drops the session without cancelling its token, so
`run_udp_remote_to_local_loop` stays parked on `socket.recv_from` holding its
UDP socket until the whole connection ends. The idle sweep at `:536` does cancel
first. Two removal paths, one correct.

**The fix, and why it is `Drop`.** Cancelling in `Drop` makes the two paths
identical by construction: every way a `UdpSession` can leave the map — an
explicit `remove`, a `retain` returning false, the map itself dropping when the
loop exits — runs the same cancel. A helper function would fix today's bug and
leave tomorrow's third removal path free to forget again.

- [x] **Step 1: Write the failing tests**

Add to `mod tests` in `src/hysteria2/server.rs`. The session is built field by
field rather than through `UdpSession::start`, because `start` spawns a task
that needs a live `quinn::Connection` and this test is about the struct's own
lifetime behaviour.

```rust
    /// Build a session with no connection behind it. `UdpSession::start` needs
    /// a live quinn connection to spawn its reply loop; nothing here does.
    async fn detached_session(parent: &CancellationToken, idle_since_secs: u64) -> UdpSession {
        let socket = crate::socket_util::new_udp_socket(true, None).unwrap();
        let location = NetLocation::from_str("127.0.0.1:9", None).unwrap();
        UdpSession {
            fragments: Defragmenter::new(),
            pending_location: None,
            send_socket: Arc::new(socket),
            last_location: location.clone(),
            last_socket_addr: "127.0.0.1:9".parse().unwrap(),
            override_remote_write_address: None,
            last_activity: Arc::new(AtomicU64::new(idle_since_secs)),
            cancel_token: parent.child_token(),
        }
    }

    /// The reply loop holds a UDP socket and parks on `recv_from` forever; the
    /// only thing that ends it is its token. Dropping the session is therefore
    /// the last moment anything can cancel it, so that is where the cancel
    /// goes - not in each of the callers that happen to remove a session today.
    #[tokio::test]
    async fn test_dropping_a_session_cancels_its_reply_loop() {
        let parent = CancellationToken::new();
        let session = detached_session(&parent, 0).await;
        let token = session.cancel_token.clone();

        assert!(!token.is_cancelled());
        drop(session);
        assert!(
            token.is_cancelled(),
            "a dropped session must not leave its task parked on a socket"
        );
    }

    /// The path that had the bug: a failed `send_to` removes the session from
    /// the map, and that removal must end the task like every other one.
    #[tokio::test]
    async fn test_removing_a_session_from_the_map_cancels_it() {
        let parent = CancellationToken::new();
        let mut sessions: FxHashMap<u32, UdpSession> = FxHashMap::default();
        sessions.insert(1, detached_session(&parent, 0).await);
        let token = sessions.get(&1).unwrap().cancel_token.clone();

        sessions.remove(&1);

        assert!(
            token.is_cancelled(),
            "removal is how the send-failure path drops a session"
        );
    }
```

- [x] **Step 2: Run the tests to verify they fail**

```bash
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"
cargo test --lib hysteria2::server::tests::test_dropping_a_session_cancels_its_reply_loop
cargo test --lib hysteria2::server::tests::test_removing_a_session_from_the_map_cancels_it
```

Expected: both FAIL on the final assertion —
`a dropped session must not leave its task parked on a socket`.

`NetLocation::from_str` here is the inherent two-argument method the receive
loop already calls (`NetLocation::from_str(addr_str, None)`), not the `FromStr`
trait — do not add a `use std::str::FromStr;` to make it compile, that would
bring the one-argument trait method into scope and change which is called.

- [x] **Step 3: Write the implementation**

Add directly after `struct UdpSession { ... }` in `src/hysteria2/server.rs`:

```rust
impl Drop for UdpSession {
    /// Cancelling here rather than at each removal is what keeps the removal
    /// paths from diverging. There are three of them - the idle sweep, a failed
    /// `send_to`, and the map dropping when the connection ends - and one of
    /// them used to forget, leaving the reply loop parked on its socket for the
    /// life of the connection.
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}
```

Then remove the now-redundant explicit cancel in the sweep — `retain`'s closure
returning `false` drops the session, which cancels it:

```rust
            sessions.retain(|session_id, session| {
                let idle = now_secs.saturating_sub(session.last_activity.load(Ordering::Relaxed));
                if idle > idle_timeout_secs {
                    // Dropping the session cancels its reply loop; see `Drop`.
                    debug!("Removing inactive UDP session {session_id}");
                    false
                } else {
                    true
                }
            });
```

The send-failure site at the bottom of the loop needs no change at all — that
is the point of doing it this way — but add the comment so the next reader does
not re-add a cancel beside it:

```rust
        if let Err(e) = session
            .send_socket
            .send_to(&complete_payload, socket_addr)
            .await
        {
            error!("Failed to forward UDP payload for session {session_id}: {e}");
            // Removing it drops it, and dropping it cancels its reply loop.
            sessions.remove(&session_id);
        }
```

- [x] **Step 4: Run the tests to verify they pass**

```bash
cargo test --lib hysteria2::server
cargo test --lib hysteria2::
```

Expected: PASS. Watch for a new failure in the client↔server UDP tests: if a
session is now being cancelled somewhere it was not before, it will show up as a
UDP round trip that stops working, not as a subtle regression.

- [x] **Step 5: Format, lint and commit**

```bash
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --locked --lib --tests -- -D warnings
git add src/hysteria2/server.rs
git commit -m "hysteria2: end a UDP session's reply loop when the session goes"
```

---

### Task 5: The idle sweep runs on a timer, not on traffic

**Files:**
- Modify: `src/hysteria2/server.rs` — extract the sweep out of `run_udp_local_to_remote_loop` (`:526-545`) and drive it from a `tokio::time::interval`
- Test: `src/hysteria2/server.rs` — `mod tests`

**Interfaces:**
- Consumes: `UdpSession`, and `Drop for UdpSession` from Task 4 if that is
  already done. If Task 5 is done first, keep the explicit
  `session.cancel_token.cancel()` inside the extracted function and let Task 4
  remove it.
- Produces:
  ```rust
  fn sweep_idle_sessions(
      sessions: &mut FxHashMap<u32, UdpSession>,
      now_secs: u64,
      idle_timeout_secs: u64,
  );
  ```

**The defect.** The sweep only runs at the top of the loop body, and the loop
body only runs when `connection.read_datagram()` returns. A connection whose
client goes quiet keeps every session it ever opened, with its socket and its
task, until the connection itself ends. Upstream sweeps on a 1s ticker that owes
nothing to traffic (`core/server/udp.go:277-288`).

- [x] **Step 1: Write the failing test**

```rust
    /// Extracted from the receive loop so it can be tested at all: while it
    /// lived inside `run_udp_local_to_remote_loop` the only way to reach it was
    /// a live quinn connection, which is why it went years without one.
    #[tokio::test]
    async fn test_the_sweep_removes_only_the_idle_session() {
        let parent = CancellationToken::new();
        let mut sessions: FxHashMap<u32, UdpSession> = FxHashMap::default();
        // now = 1000, timeout = 60: session 1 last spoke at 900, session 2 at 990.
        sessions.insert(1, detached_session(&parent, 900).await);
        sessions.insert(2, detached_session(&parent, 990).await);
        let idle_token = sessions.get(&1).unwrap().cancel_token.clone();
        let live_token = sessions.get(&2).unwrap().cancel_token.clone();

        sweep_idle_sessions(&mut sessions, 1000, 60);

        assert!(!sessions.contains_key(&1), "100s idle is past the timeout");
        assert!(sessions.contains_key(&2), "10s idle is well inside it");
        assert!(idle_token.is_cancelled(), "the reaped session must be ended");
        assert!(!live_token.is_cancelled(), "the live one must be untouched");
    }

    /// A clock that has not yet passed the timeout must not reap anything - the
    /// subtraction runs on a monotonic epoch and saturates rather than wrapping.
    #[tokio::test]
    async fn test_the_sweep_keeps_a_session_whose_activity_is_in_the_future() {
        let parent = CancellationToken::new();
        let mut sessions: FxHashMap<u32, UdpSession> = FxHashMap::default();
        sessions.insert(1, detached_session(&parent, 5000).await);

        sweep_idle_sessions(&mut sessions, 1000, 60);

        assert!(sessions.contains_key(&1));
    }
```

- [x] **Step 2: Run the test to verify it fails**

```bash
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"
cargo test --lib hysteria2::server::tests::test_the_sweep
```

Expected: FAIL to compile, `cannot find function sweep_idle_sessions in this
scope`.

- [x] **Step 3: Extract the function**

Add above `run_udp_local_to_remote_loop` in `src/hysteria2/server.rs`:

```rust
/// How often idle sessions are looked for, whether or not traffic is arriving.
///
/// Upstream runs a 1s ticker independent of the receive path
/// (`core/server/udp.go:277-288`). Ours used to sweep only at the top of the
/// receive loop, so a client that fell silent kept every session it had opened,
/// each with a socket and a parked task, until the connection ended.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(1);

/// How long a session may go without traffic in either direction.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Drop every session that has been silent longer than `idle_timeout_secs`.
///
/// `now_secs` and the sessions' stored activity are both counts of whole
/// seconds since `ACTIVITY_EPOCH`, and the subtraction saturates: a stored
/// value ahead of `now_secs` reads as zero idle time rather than as an
/// enormous one.
fn sweep_idle_sessions(
    sessions: &mut FxHashMap<u32, UdpSession>,
    now_secs: u64,
    idle_timeout_secs: u64,
) {
    sessions.retain(|session_id, session| {
        let idle = now_secs.saturating_sub(session.last_activity.load(Ordering::Relaxed));
        if idle > idle_timeout_secs {
            // Dropping the session cancels its reply loop; see `Drop`.
            debug!("Removing inactive UDP session {session_id}");
            false
        } else {
            true
        }
    });
}
```

If Task 4 has not been done yet, put `session.cancel_token.cancel();` back above
the `debug!` and change the comment to say so; Task 4 removes it.

- [x] **Step 4: Drive it from a timer**

In `run_udp_local_to_remote_loop`, delete the two `const` declarations that were
inside it and the `let mut last_cleanup = std::time::Instant::now();` line, and
replace the top-of-loop sweep with a `select!`:

```rust
async fn run_udp_local_to_remote_loop(
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let mut resolver_cache = ResolverCache::new(resolver.clone());
    let mut sessions: FxHashMap<u32, UdpSession> = FxHashMap::default();

    let mut cleanup = tokio::time::interval(CLEANUP_INTERVAL);
    // The first tick of an interval completes immediately, and a sweep of an
    // empty map is not worth a branch to skip.
    cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let data = tokio::select! {
            _ = cleanup.tick() => {
                sweep_idle_sessions(&mut sessions, activity_secs(), IDLE_TIMEOUT.as_secs());
                continue;
            }
            // Cancel-safe: `ReadDatagram::poll` takes a datagram out of quinn's
            // queue only on the poll that returns Ready, and it checks that
            // queue before it registers for a notification
            // (`quinn-0.11.11/src/connection.rs:803-828`). Dropping the future
            // to serve a tick therefore cannot lose a datagram or a wakeup.
            data = connection.read_datagram() => {
                data.map_err(|err| {
                    std::io::Error::other(format!("failed to read datagram: {err}"))
                })?
            }
        };

        // ... the rest of the body is unchanged, starting at:
        // Per official hysteria reference (server.go:332-353), parse errors are ignored
```

Leave the rest of the loop body exactly as it is. Note that the loop's exit
condition does not change: it still ends when `read_datagram` returns an error,
and `cancel_token` is still not selected on, because the connection's token is
cancelled after `try_join!` returns rather than before.

- [x] **Step 5: Run the tests to verify they pass**

```bash
cargo test --lib hysteria2::server
cargo test --lib hysteria2::
```

Expected: PASS.

The `select!` wiring itself has no test, and saying so is more useful than
pretending otherwise: reaching it needs a live connection, a client that falls
silent and a 60-second wait. What is tested is the reaping decision, which is
where the arithmetic and the cancellation live. The wiring is three lines and
gets a reviewer instead.

- [x] **Step 6: Check the timer against the whole suite**

```bash
cargo test --lib
```

Expected: PASS. A 1s ticker inside a `select!` is the kind of change that turns
a slow test into a flaky one; if anything in `hysteria2::client::tests` starts
failing intermittently, run it twenty times before concluding it is unrelated:

```bash
for i in $(seq 1 20); do cargo test --lib hysteria2:: || break; done
```

- [x] **Step 7: Format, lint and commit**

```bash
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --locked --lib --tests -- -D warnings
git add src/hysteria2/server.rs
git commit -m "hysteria2: sweep idle UDP sessions on a timer, not on traffic"
```

---

### Task 6: No assert and no truncating cast on the reply path

**Files:**
- Modify: `src/hysteria2/server.rs` — `run_udp_remote_to_local_loop`, the `assert!` at `:471-474` and the fragment loop at `:476-509`
- Test: `src/hysteria2/server.rs` — `mod tests`

**Interfaces:**
- Consumes: nothing from the other tasks.
- Produces:
  ```rust
  /// (payload bytes per fragment, number of fragments)
  fn fragment_plan(
      max_datagram_size: usize,
      header_overhead: usize,
      payload_len: usize,
  ) -> std::io::Result<(usize, u8)>;
  ```

**The defects, both on the same six lines.**

`assert!(max_datagram_size > header_overhead, ...)` panics on a size derived
from an address the *client* chose — the reply address can be up to
`MAX_ADDRESS_LEN` — against a datagram size the *client* advertised. Both
operands come from the peer. Upstream returns nil rather than asserting
(`core/internal/frag/frag.go:13-15`).

`payload_len.div_ceil(available_payload) as u8` truncates. A peer advertising a
small `max_datagram_frame_size` makes `available_payload` small enough that a
64 KB UDP reply needs more than 255 fragments, and `as u8` wraps that count to
something small — so the receiver is told to expect a handful of fragments and
gets a stream of them with ids past the count it was given.

**Why a function rather than two inline checks.** The arithmetic is the whole
of both bugs and it is the only part of this loop that can be tested without a
connection. `frame::build_datagrams` computes the same thing correctly for the
client, and unifying the two encoders is the spec's phase 3 structural item —
keeping this one arithmetic-only, with no framing in it, is what makes that
merge a deletion later rather than a rewrite.

- [x] **Step 1: Write the failing tests**

```rust
    /// Both operands come from the peer: the datagram size it advertised, and
    /// the length of the address it asked us to reply from. A peer must not be
    /// able to choose a pair of them that aborts the process.
    #[test]
    fn test_a_header_that_does_not_fit_the_datagram_is_an_error_not_a_panic() {
        let err = fragment_plan(64, 64, 100).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("64"), "both sizes belong in it: {message}");

        let err = fragment_plan(64, 200, 100).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
    }

    /// The protocol counts fragments in one byte. A payload needing more than
    /// 255 of them cannot be sent, and must not be sent as a wrapped count -
    /// which would tell the receiver to expect a few and then hand it fragment
    /// ids past the number it was given.
    #[test]
    fn test_a_payload_needing_more_than_255_fragments_is_refused() {
        // 10 bytes of payload per fragment, 65535 bytes to send: 6554 fragments.
        let err = fragment_plan(60, 50, 65535).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("6554"), "say how many it needed: {message}");
        assert!(message.contains("255"), "and what the limit is: {message}");
    }

    #[test]
    fn test_a_payload_that_fits_one_datagram_is_one_fragment() {
        assert_eq!(fragment_plan(1200, 200, 500).unwrap(), (1000, 1));
        // Exactly filling it is still one fragment.
        assert_eq!(fragment_plan(1200, 200, 1000).unwrap(), (1000, 1));
        // One byte over is two.
        assert_eq!(fragment_plan(1200, 200, 1001).unwrap(), (1000, 2));
    }

    /// A zero-length UDP packet is a packet. `div_ceil` gives zero fragments
    /// for it, which would drop it silently, so the count floors at one.
    #[test]
    fn test_an_empty_payload_still_takes_one_fragment() {
        assert_eq!(fragment_plan(1200, 200, 0).unwrap(), (1000, 1));
    }

    #[test]
    fn test_the_largest_sendable_payload_is_accepted() {
        // 255 fragments of 1000 bytes is exactly the limit.
        assert_eq!(fragment_plan(1200, 200, 255_000).unwrap(), (1000, 255));
        assert!(fragment_plan(1200, 200, 255_001).is_err());
    }
```

- [x] **Step 2: Run the tests to verify they fail**

```bash
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"
cargo test --lib hysteria2::server::tests::test_a_header
cargo test --lib hysteria2::server::tests::test_a_payload
cargo test --lib hysteria2::server::tests::test_an_empty_payload
cargo test --lib hysteria2::server::tests::test_the_largest
```

Expected: FAIL to compile, `cannot find function fragment_plan in this scope`.

- [x] **Step 3: Write the function**

Add above `run_udp_remote_to_local_loop` in `src/hysteria2/server.rs`:

```rust
/// How a reply payload is split across datagrams.
///
/// Returns the payload bytes each fragment may carry and how many fragments
/// there will be. Both inputs are the peer's: `max_datagram_size` is what it
/// advertised, and `header_overhead` includes the reply address it chose, up to
/// `MAX_ADDRESS_LEN`. Neither may be able to panic us, which is what an
/// `assert!` here used to allow, and neither may silently produce a fragment
/// count that does not fit the byte the protocol gives it.
///
/// `frame::build_datagrams` does the same arithmetic for the client. Merging
/// the two encoders is the spec's phase 3 item; this one deliberately holds no
/// framing so that the merge is a deletion.
fn fragment_plan(
    max_datagram_size: usize,
    header_overhead: usize,
    payload_len: usize,
) -> std::io::Result<(usize, u8)> {
    let available_payload = max_datagram_size
        .checked_sub(header_overhead)
        .filter(|available| *available > 0)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "a datagram of {max_datagram_size} bytes has no room for a payload after a \
                     {header_overhead} byte header"
                ),
            )
        })?;

    // An empty UDP packet is still a packet, and `div_ceil` gives zero for it.
    let fragment_count = payload_len.div_ceil(available_payload).max(1);
    if fragment_count > u8::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "a reply of {payload_len} bytes needs {fragment_count} fragments, over the 255 \
                 the protocol allows"
            ),
        ));
    }

    Ok((available_payload, fragment_count as u8))
}
```

- [x] **Step 4: Use it, and delete the duplicated single-datagram branch**

In `run_udp_remote_to_local_loop`, replace everything from the `assert!` down to
the end of the `else` block — that is the `assert!`, the
`if header_overhead + payload_len <= max_datagram_size { ... }` arm and its
`else { ... }` arm — with:

```rust
        let (available_payload, fragment_count) =
            fragment_plan(max_datagram_size, header_overhead, payload_len)?;

        for fragment_id in 0..fragment_count {
            let start = (fragment_id as usize) * available_payload;
            let end = std::cmp::min(start + available_payload, payload_len);
            let mut datagram = BytesMut::with_capacity(header_overhead + (end - start));
            datagram.extend_from_slice(&session_id.to_be_bytes());
            datagram.extend_from_slice(&packet_id.to_be_bytes());
            datagram.extend_from_slice(&[fragment_id, fragment_count]);
            datagram.extend_from_slice(&address_len_bytes);
            datagram.extend_from_slice(&address_bytes);
            datagram.extend_from_slice(&buf[start..end]);

            connection.send_datagram(datagram.freeze()).map_err(|e| {
                std::io::Error::other(format!("Failed to send datagram fragment {fragment_id}: {e}"))
            })?;
        }
```

The single-datagram branch is gone because it was this loop with
`fragment_count == 1` written out a second time: it wrote the same
`[0, 1]` fragment id and count, the same header and the same payload slice.
Two copies of one encoder is how the divergences in this spec came to exist.

- [x] **Step 5: Run the tests to verify they pass**

```bash
cargo test --lib hysteria2::server
cargo test --lib hysteria2::
```

Expected: PASS, including `test_udp_round_trip` and
`test_large_udp_payload_is_fragmented_and_reassembled` — the first goes down the
former single-datagram branch and the second down the fragment loop, so between
them they cover the branch that was deleted and the one that absorbed it.

- [x] **Step 6: Confirm nothing can panic there any more**

```bash
grep -n "assert!\|unwrap()\|expect(\|as u8" src/hysteria2/server.rs | sed -n '1,20p'
```

Every remaining hit must be either inside `mod tests` or on a value that did not
come from the network. Read each one; do not assume.

- [x] **Step 7: Format, lint and commit**

```bash
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --locked --lib --tests -- -D warnings
git add src/hysteria2/server.rs
git commit -m "hysteria2: refuse an unsendable reply instead of panicking on it"
```

---

### Task 7: The gate, and the record

**Files:**
- Modify: `CHANGELOG.md`, `docs/superpowers/specs/2026-08-24-hysteria2-conformance-design.md`

- [x] **Step 1: Full gate**

```bash
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"
cargo fmt --all -- --check
cargo clippy --locked --lib --bins --tests -- -D warnings
cargo clippy --locked --features ffi --lib --tests -- -D warnings
cargo clippy --locked --features ffi --bins -- -D warnings
cargo clippy --locked --features desktop --lib --tests -- -D warnings
cargo test --lib
cargo test --bins
cargo test --test '*'
```

Every one must pass. `cargo fmt --all -- --check` is first because it is the
first job in CI and the cheapest to fail.

- [x] **Step 2: Run the UDP path repeatedly**

Task 5 puts a timer inside the receive loop's `select!`. That is the change most
likely to show up as an intermittent failure rather than a deterministic one.

```bash
for i in $(seq 1 20); do cargo test --lib hysteria2:: || { echo "FAILED on run $i"; break; }; done
```

Expected: twenty passes. If one fails, do not re-run until it goes green —
find it. This repository has twice shipped a test that failed roughly one run in
fifty.

- [x] **Step 3: Record it**

Add to the `Unreleased` section of `CHANGELOG.md`, under the existing
`### Hysteria2 conformance with the reference implementation` heading, a short
subsection covering what a user or operator sees:

- A UDP session can no longer be made to hold about 78 MB of half-finished
  packets: one packet id is in flight at a time, which is what upstream does and
  what caps the memory at roughly 300 KB. Both ends of ours changed, and the end
  that matters most is the phone.
- A session whose send fails no longer leaves its socket and its reply task
  alive for the rest of the connection.
- Idle sessions are reaped on a timer rather than only when another datagram
  happens to arrive, so a client that goes quiet stops holding what it opened.
- A reply that cannot be framed — a peer's advertised datagram size too small
  for the address it chose, or a payload needing more than the 255 fragments the
  protocol counts — is now an error naming the sizes, where one case aborted the
  process and the other silently sent a wrapped fragment count.

Say plainly that none of this changes the wire format.

- [x] **Step 4: Mark phase 2 done in the spec**

In `docs/superpowers/specs/2026-08-24-hysteria2-conformance-design.md`, change
the `## Phase 2 — robustness` heading to `## Phase 2 — robustness — done` and
add a sentence under it stating the date, the commit range, and the one place
the plan deviated from the spec: the fix landed in a new shared `Defragmenter`
used by both Hysteria2 ends rather than only in the server's own table, and
TUIC's `FragmentTable` was deliberately left alone because Hysteria's reference
says nothing about TUIC's.

- [x] **Step 5: Commit**

```bash
git add CHANGELOG.md docs/superpowers/specs/2026-08-24-hysteria2-conformance-design.md
git commit -m "docs: record the Hysteria2 phase 2 robustness fixes"
```

---

## Live verification

Phase 1's lesson, in the spec's own words: *building the official client from
source and pointing it at our server is the cheapest way to check anything on
this list and should be the first move next time, not the last.*

Phase 2 needs less of it than phase 1 did, because none of these are shared
misreadings — they are behaviours, and behaviours are testable in process. But
two of them are worth one run against the official client, because both are
about what happens over time rather than in a single exchange:

- **A large UDP payload still round-trips.** The reassembler changed on both
  ends; a 4 KB payload through the official client and back is the check.
- **A quiet connection releases its sessions.** Open a UDP session, let it sit
  for more than 60 seconds, confirm the server logged
  `Removing inactive UDP session` without the client having sent anything to
  provoke the sweep. That is the one behaviour that was impossible before this
  change and cannot be observed from a test.

---

## Not in this phase

For the reader who goes looking and finds these still open:

- **A cap on the number of sessions per connection.** The spec calls it a
  separate question, and it is: the reassembly change takes the per-session
  bound from 78 MB to about 300 KB, but a peer may still open sessions without
  limit and each one holds a UDP socket.
- **TUIC's `FragmentTable`,** which has the same 256-packet exposure. Fixing it
  means reading TUIC's reference first.
- **The two encoders,** `frame::build_datagrams` and the server's inline one.
  Task 6 removes the duplicated branch inside the server's and makes its
  arithmetic a function, but the framing is still written twice. Phase 3.
- **Everything in phase 3,** which is fingerprint decisions and needs the
  user's answer to one question before it can be planned: are we imitating the
  Go client, or merely interoperating with it?

---

## What execution found

Done 2026-08-25. Every task landed as written; three things the plan did not
anticipate are worth carrying forward.

**The clippy gate cannot pass on macOS, and never could.** `cargo clippy -- -D
warnings` reports five errors on a pristine tree here: two `unused variable:
interface` in `src/socket_util.rs` (the interface binding is Linux-only) and
three `nonminimal_bool` in `src/config/types/dns.rs`'s tests, under this
machine's clippy 1.94. CI is Linux and is green, so the workable local gate is
*no new diagnostics in the files being touched*, checked with:

```bash
cargo clippy --locked --lib --tests 2>&1 -- -D warnings \
  | grep -E "^ +--> src/(quic_transport|quic_outbound|hysteria2)/"
```

Anyone writing the next plan for this repository should state the gate that way
rather than as an unqualified pass.

**A test-harness race had to be fixed before the 20-run gate could mean
anything.** `hysteria2::client::tests::test_udp_round_trip` failed once, on a run
that took 10.08s against a usual 2.3s — exactly `udp_exchange`'s ten-second
timeout. `reserve_udp_port` closes its probe socket before returning the
address, so two servers can be handed one port; and because they bind with
`SO_REUSEPORT` (`quic_transport::build_server_endpoint` passes `true`) they both
bind successfully and the kernel splits datagrams between them. No bind error is
raised, because `SO_REUSEPORT` is what suppresses it. Ports issued in a process
are now remembered and never reused (`e88486c`). This was the third latent flake
in this harness; the previous two were found the same way, by chasing a single
failure rather than re-running until green.

**The reply path's single-datagram branch was dead weight.** Task 6 predicted
this and it held: with `fragment_count == 1` the fragment loop writes the same
`[0, 1]` header, the same address and the same payload slice, so the branch was
the loop written out a second time. It went with the `assert!`.

Gate as run: fmt clean; 1326 lib + 1315 bin + 8 integration tests passing;
clippy clean in the touched modules across four feature combinations;
`hysteria2::` 20/20 clean and the full lib suite 10/10 clean.

Live verification is still outstanding — see the section above.
