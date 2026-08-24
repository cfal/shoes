# Hysteria2: conformance with the reference implementation

Written 2026-08-24 against `mobile` at `254144b`, and against
[HyNetworks/hysteria](https://github.com/HyNetworks/hysteria) at `619a6f8`.

## Why

A review that read the Go source found fifteen divergences across 5500 lines of
Hysteria2 code. Five of them mean a real Hysteria2 peer does not work with us;
the rest are fingerprint, robustness or structure.

The pattern behind most of them is the one this codebase has now hit three
times: **our encoder and our decoder share a misreading, so every test passes.**
The IPv6 address case is the sharpest example — the parser was fixed two days
ago and the encoder has the mirror-image bug, undetected because the two agree.

Scope: everything the review found, in three phases. Phase 1 is the five that
make "we support Hysteria2" untrue.

## Sources

Every claim below is cited to the upstream clone. Where a decision rests on
what quinn can do, it is cited to the quinn source in the local registry.

| What | Where |
| --- | --- |
| TCP request/response and datagram codec | `core/internal/protocol/proxy.go` |
| Auth exchange and padding | `core/internal/protocol/http.go`, `padding.go` |
| Server behaviour, masquerade, UDP sessions | `core/server/server.go`, `core/server/udp.go` |
| Client transport parameters | `core/client/client.go`, `core/client/config.go` |
| Fragment reassembly | `core/internal/frag/frag.go` |
| Datagram size, and why one fix is not a config change | `quinn-proto-0.11.17/src/connection/datagrams.rs:70-84` |

## Phase 1 — a real peer does not work with us

### 1.1 The server claims success before it dials

`handle_tcp_header` (`server.rs:841-861`) writes status 0 with an empty message
unconditionally, then `process_tcp_stream` dials and, on failure, shuts the
stream down. Upstream dials first and answers
`WriteTCPResponse(stream, false, err.Error())` or
`WriteTCPResponse(stream, true, "Connected")` (`core/server/server.go:310-324`).

A client asking for an unresolvable host is told the connection succeeded and
then sees EOF with no diagnosis. Our own client's error path and its test
(`frame.rs:188`, `frame.rs:394`) are dead against our own server.

**Decision:** dial first, then answer. Success carries the message `Connected`,
as upstream does — the field exists and we send it empty today.

### 1.2 Concurrent UDP sessions steal each other's datagrams

Each `Hysteria2UdpSession` spawns a task calling `read_datagram()` on the
shared `quinn::Connection` and drops what is not its own session id
(`udp.rs:51-68`). `LiveConnection::get` hands every caller a clone of the same
connection, and `connect_udp_bidirectional` makes a session per association —
called from the UDP router, the QUIC server, the TUN manager and AnyTLS.

quinn pops from one queue, so with N sessions each reader wins about 1/N of the
datagrams. Two concurrent DNS lookups lose about half their replies. The
comment at `udp.rs:48-50` states the precondition that makes this safe;
nothing enforces it and it is false.

Upstream runs one demultiplexer per connection that routes by session id into
per-session channels (`core/client/udp.go:126-142`).

**Decision:** the same shape. One reader task per `LiveConnection`, owning the
`read_datagram` loop, dispatching into per-session channels. Sessions register
and deregister; a datagram for an unknown session is dropped there, once.

### 1.3 Our server cannot send UDP to a client that omits the datagram size

**Corrected 2026-08-24 after a live run. The original claim — "every official
client omits `max_datagram_frame_size`" — is wrong, and this finding is far
narrower than it was written.**

`core/client/client.go:92-93` does set `OmitMaxDatagramFrameSize: true`, but
`ChromeParrot` — on unless `disableChromeParrot` is set — overrides it back to
false, because Chrome always advertises the parameter and omitting it would
leave the client one parameter short of Chrome's set
(`apernet/quic-go config.go:107-114`, and its own test at `config_test.go:239`).
So the **stock official client advertises the parameter and its UDP works
against us**; only a client with parroting deliberately disabled does not.

Verified both ways against our server with the official client built from
`619a6f8`: default config carries UDP, and `disableChromeParrot: true` gives
exactly one-way UDP with our named warning in the log.

`run_udp_remote_to_local_loop` requires `connection.max_datagram_size()`
(`server.rs:357`), and upstream's server compensates for such a peer with
`AssumePeerMaxDatagramFrameSize` (`core/server/server.go:64`).

**quinn has no equivalent.** `Datagrams::max_size` returns `None` through `?` on
`peer_params.max_datagram_frame_size`
(`quinn-proto-0.11.17/src/connection/datagrams.rs:79`), and there is no config
knob to assume a value. So such a client gets one-way UDP: queries leave,
answers never come back, and nothing surfaces client-side.

**There is no fix inside quinn.** `Datagrams::send` calls `max_size()` itself
and returns `SendDatagramError::UnsupportedByPeer` when the peer omitted the
parameter (`quinn-proto-0.11.17/src/connection/datagrams.rs:32-34`), so
bypassing our own check and letting quinn size the datagram does not help: the
send call is where it refuses.

That leaves three options. With the finding corrected, the third is no longer a
headline feature broken for the peer that matters most — it is a documented
limitation for a peer that has deliberately turned off its own camouflage:

1. **Carry a patched quinn**, adding the equivalent of upstream's
   `AssumePeerMaxDatagramFrameSize`. A small patch — the value would be used at
   `datagrams.rs:79` in place of the `?` — but it means a fork to maintain, and
   this tree deliberately pins released dependencies.
2. **Upstream the knob to quinn** and wait. Correct, and slow.
3. **Document the limitation**: our Hysteria2 server does not carry UDP to a
   peer that omits `max_datagram_frame_size`, which an official client does only
   with `disableChromeParrot: true`.

**Recommended: 3.** A fork or an upstream wait is a large cost for a
configuration a user has to opt into, and which costs them their Chrome
fingerprint anyway.

Either way the implementable part is the same: name the cause, so a client
seeing one-way UDP leaves something in the operator's log
(`server.rs:341,357-359`).

### 1.4 IPv6 addresses go on the wire unbracketed

`client.rs:181` uses `target.location().to_string()`, and `NetLocation`'s
`Display` (`address.rs:183`) prints the address bare and appends `:{port}`, so
`2001:db8::1` port 443 becomes `2001:db8::1:443`. Go's `net.SplitHostPort`
rejects that. Our own parser accepts it because it splits at the last colon.

The same string is used for the UDP session address (`client.rs:214`) and for
the server's reply source when an override is active (`server.rs:363`).

**Decision:** one function that formats a `NetLocation` for the wire,
bracketing an IPv6 literal, used by all three sites. `Display` is not changed:
it is used in logs and error messages throughout the tree, and changing it
would be a wide behavioural change for a narrow reason.

### 1.5 The server answers `Hysteria-CC-RX: 0`, which means something else

`server.rs:239` hardcodes `0`. PROTOCOL.md defines `0` as "no bandwidth limit;
the client MAY transmit at any rate" and `auto` as "the server chooses not to
specify a rate; the client MUST use a congestion control algorithm". Upstream
sends `auto` exactly when the server ignores the client's bandwidth
(`core/server/server.go:172,206`).

We never read the client's `Hysteria-CC-RX` and never install Brutal, so we
*are* that case. An official client configured with `up: 200 mbps` reads our
`0`, falls through to `congestion.UseBrutal` (`core/client/client.go:156-162`)
and transmits at a fixed rate ignoring loss, against a server running ordinary
congestion control.

**Decision:** send `auto`.

## Phase 2 — robustness

### 2.1 Fragment cache and session map are unbounded in the ways that matter

Each session holds up to 256 incomplete packets of up to 255 slices each
(`server.rs:35`, `695`), about 78 MB per session; the session map has no cap
(`server.rs:482`) and its eviction only runs when a datagram arrives, every 10s
(`server.rs:486,491`). Upstream tracks **one** packet id at a time and discards
previous state when a new id arrives (`core/internal/frag/frag.go:40-43`), and
sweeps on a 1s ticker independent of traffic (`core/server/udp.go:277-288`).

**Decision:** match upstream — one packet id in flight per session, and a
timer-driven sweep. A session cap is a separate question and is not part of
this; the reassembly change alone takes the per-session bound from 78 MB to
about 300 KB.

### 2.2 A send failure leaks the session's socket and task

`server.rs:770-772` removes the session without cancelling its token, so the
remote-to-local task stays parked holding its socket until the connection ends.
The idle sweep does it correctly (`server.rs:494-504`).

**Decision:** cancel before removing, in both places. Better, make removal the
only way to drop a session so the two cannot diverge again.

### 2.3 An assert and a truncating cast on the reply path

`server.rs:433` asserts on a size derived from the client's chosen address, and
`server.rs:453` truncates the fragment count with `as u8`. `frame.rs:291`
already guards the same case and returns an error. Upstream returns nil rather
than asserting (`core/internal/frag/frag.go:13-15`).

**Decision:** return an error. No `assert!` on a path reachable from network
input.

## Phase 3 — fingerprint and structure

These are decisions rather than repairs, and each changes what we look like on
the wire. They are listed with their upstream values so the choice is informed.

| What we do | What upstream does | Where |
| --- | --- | --- |
| Auth padding 1-79 | 256-2047 | `padding.go:27-28` |
| TCP request padding 0-64, response 0-63 | 64-511 and 128-1023 | `padding.go:29-30` |
| `max_datagram_frame_size` advertised | omitted | `client.go:92-93` |
| bidi 0 / uni 1024 | Chrome's 100 / 103 | `client.go:95` |
| 8-byte connection IDs | zero-length | `client.go:102` |
| Masquerade: empty 404, connection killed after 3s | real 404 body, connection kept | `server.go:350-356` |

Also structural: the server keeps a second datagram encoder (`server.rs:439`)
and a second reassembly table beside `frame.rs` and
`quic_transport/fragments.rs`. Two encoders for one wire format is the
arrangement that lets a shared misreading ship green — which is how most of
this list came to exist.

**Decision:** phase 3 gets its own spec. The fingerprint items in particular
need a decision about whether we are imitating the Go client or merely
interoperating with it, and that decision belongs with the user.

## What this does not cover

- The `effective_mtu` truncation (`quic_transport/mod.rs:50`) and its test that
  passes by accident. Latent: no shipped obfuscator claims 65536 bytes of
  overhead. Recorded, not scheduled.
- Empty UDP payloads, which upstream rejects (`proxy.go:216-219`) and we send.
  It needs a decision — refuse, or document the divergence — and it belongs
  with the phase 3 fingerprint questions.

## Testing

Every phase 1 item gets a test that fails before the fix. Two of them need a
peer that is not ours, because the whole class of defect here is our two ends
agreeing:

- **1.4** is testable directly: assert the exact bytes on the wire for an IPv6
  target, against the string Go would accept, not against our own parser.
- **1.1, 1.2, 1.5** are testable in process against our own server, because the
  defect is a behaviour, not a shared misreading.
- **1.3** cannot be tested against our own client, which advertises the
  parameter. A test can still pin the *diagnosis*: a client that omits it must
  make the server log a named error rather than a silent task death.

A live run against a real Hysteria2 server, as the port-hopping work had, is
what would catch the next one of these. That is worth doing once phase 1 lands.
