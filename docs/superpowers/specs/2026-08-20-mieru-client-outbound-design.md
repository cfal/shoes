# mieru client outbound

Design for speaking the mieru proxy protocol from shoes, as a client outbound
over TCP, with a server implementation kept for testing.

## Sources

Everything about the wire format below was read from
[enfein/mieru](https://github.com/enfein/mieru) at `b9bbc41` (2026-08-20), not
recalled. Each claim cites where it came from:

| Claim | Source |
| --- | --- |
| Segment layout, metadata formats, UDP encapsulation | `docs/protocol.md` |
| PBKDF2 parameters, time salt, three-salt window | `pkg/cipher/keygen.go` |
| Password hashing | `pkg/cipher/api.go:149` |
| Implicit nonce, its increment, user hint | `pkg/cipher/cipher.go:100-189, 359-396` |
| Nonce and overhead sizes | `pkg/cipher/api.go:31-35` |
| Stream overhead | `pkg/protocol/underlay_stream.go:41` |
| Padding strategies and limits | `pkg/protocol/padding.go:30-31, 95-135` |
| Strategy seeding | `pkg/rng/rng.go:110-132` |
| No ARQ over TCP | `pkg/protocol/session.go:1042-1051, 1144-1148` |
| socks5 inside the session | `apis/client/client.go:120-154` |

## Problem

mieru is a censorship-resistant proxy protocol. shoes speaks fifteen protocols
but not this one, so a user with a mieru deployment cannot route through it.

## Scope

**In scope:** a client outbound over mieru's TCP transport, and a server
implementation sufficient to test the client against in process.

**Out of scope, and rejected loudly in config validation rather than ignored:**

| Feature | Why it is out |
| --- | --- |
| mieru's UDP transport | It carries a full ARQ stack — CUBIC, RTT estimation, retransmission, windows — which is a small TCP in userspace. Upstream's own `docs/protocol.md` says "In most cases, we recommend using TCP protocol." |
| Low entropy encoding | Four modes with mask rotation, needed only against DPI that measures entropy. The client selects it, so a server accepts a client without it. |
| Session multiplexing | `MULTIPLEXING_OFF` is a legal client setting, so one session per connection interoperates. |
| Traffic pattern profiles | mieru's configurable padding-bound layer. Its absence changes padding limits, not correctness. |

UDP application traffic is **in scope** and works without mieru's UDP
transport: mieru carries socks5 UDP-associate inside the TCP session.

## Protocol summary

### Key derivation

1. `hashedPassword = SHA-256(password ‖ 0x00 ‖ username)`
2. `timeSalt = SHA-256(be64(unixSeconds rounded to 2 minutes))`
3. `key = PBKDF2-HMAC-SHA256(hashedPassword, timeSalt, iterations = 64, len = 32)`

The rounding is Go's `Time.Round`, which rounds half away from zero. A server
tries three salts — the rounded time, one interval before, one after
(`saltFromTime`, `pkg/cipher/keygen.go:55`). `docs/protocol.md` states the
resulting requirement as: the client-server time difference must not exceed
4 minutes, and the server tries at most 3 salts.

The AEAD is XChaCha20-Poly1305: 24-byte nonce, 16-byte tag. The last 4 bytes of
each nonce are overwritten with the first 4 bytes of
`SHA-256(username ‖ nonce[0..16])`, letting a server find the user without
trying every one.

### Segments

```
[padding 0][nonce?][encrypted metadata][tag][padding 1][encrypted payload][tag][padding 2]
     ?       0|24         32            16       ?         0..32768        16      ?
```

Over TCP the nonce appears **once per direction**, in the first segment. After
that both ends increment their own copy on every encryption — big-endian
increment from the last byte, `pkg/cipher/cipher.go:359`. Metadata is one
encryption; a payload, when present, is a second. A missed or extra increment
desynchronises the stream permanently and silently, because decryption simply
stops matching.

Maximum fragment: 32768 bytes.

### Metadata

32 bytes, big-endian, two formats in scope:

**Session metadata** — protocol types `openSessionRequest` = 2,
`openSessionResponse` = 3, `closeSessionRequest` = 4, `closeSessionResponse` = 5:

| protocol | unused | timestamp | session ID | sequence | status | payload len | suffix len | unused |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 1 | 4 | 4 | 4 | 1 | 2 | 1 | 14 |

**Data metadata** — types `dataClientToServer` = 6, `dataServerToClient` = 7,
`ackClientToServer` = 8, `ackServerToClient` = 9:

| protocol | unused | timestamp | session ID | sequence | unack seq | window | fragment | prefix len | payload len | suffix len | unused |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 1 | 4 | 4 | 4 | 4 | 2 | 1 | 1 | 2 | 1 | 7 |

`timestamp` is minutes since the epoch. Types 10 and 11 are the low-entropy
extension: recognised and rejected, never produced.

**Over TCP there is no ARQ.** `inputAck` returns immediately for
`StreamTransport` and `inputData` inserts straight into the receive queue —
TCP already provides ordering and retransmission. `sequence`, `unack` and
`window` are carried because the format requires them, not acted upon.

### Padding

Two strategies, chosen per connection:

- **ASCII:** length is uniform in `[minConsecutiveASCII, maxLen]`, filled with
  random bytes, then a run of `minConsecutiveASCII` bytes starting at a random
  offset is forced into printable ASCII.
- **Entropy:** length is computed so the rarer bit reaches a target probability
  of 0.325 across the segment.

Over TCP `maxLen` is 255 for every padding position.

## Architecture

### Where it plugs in

mieru over TCP is a protocol over a stream, like VMess and Trojan — not a
transport owner like Hysteria2 and TUIC. It is therefore a `TcpClientHandler`,
not a `TerminalConnector`, which means it composes with the existing chain
model for free: mieru over TLS, over WebSocket, or as a later hop behind
another proxy. `supports_udp_over_tcp()` and `setup_client_udp_bidirectional`
already describe exactly what mieru does with socks5 UDP-associate.

### Modules

`src/mieru/`, each with one purpose and its own tests:

| Module | Responsibility | Depends on |
| --- | --- | --- |
| `crypto.rs` | Key derivation, `DirectionCipher` owning one implicit nonce, user hint | `aws-lc-rs` |
| `metadata.rs` | The 32-byte metadata formats: encode, parse, reject low-entropy types | — |
| `padding.rs` | Both padding strategies and their length bounds | — |
| `frame.rs` | Segment codec: assemble and parse the byte layout | the three above |
| `stream.rs` | `MieruStream: AsyncStream` — session state machine, fragmentation, `poll_read`/`poll_write` | `frame.rs` |
| `client.rs`, `server.rs` | The handlers, socks5 inside the session, UDP encapsulation | `stream.rs` |

`frame.rs` does no I/O, so it is testable on vectors. `stream.rs` knows nothing
about socks5. `client.rs` knows nothing about padding.

### Session layer as a stream wrapper

`MieruStream` frames inline in `poll_read`/`poll_write`, following
`VmessStream` and `ShadowsocksStream`. Over TCP the session has no ARQ, no ACK
processing and no timers, so it is framing plus a small open/close state
machine. An actor with channels — the shape our TUIC UDP sessions use — would
add a task and queues per connection for no benefit here.

### Cipher state

The nonce is implicit and direction-scoped, so `MieruStream` holds two
`DirectionCipher` values, send and receive, each owning its nonce. Nothing is
shared between tasks, so no mutex is needed; Go has one only because its cipher
object is shared.

## Data flow

**TCP:** the chain hands us a stream → derive the key → send
`openSessionRequest`, the only segment carrying our nonce → await
`openSessionResponse` → socks5 CONNECT inside the session → application data is
split into `dataClientToServer` segments, each padded independently.

**UDP:** the same session with socks5 UDP-associate, each datagram wrapped as
`[0x00][u16 len][data][0xff]` — the UDP-over-TCP pattern shoes already uses for
Shadowsocks.

## Traffic-pattern parity

For a censorship-resistant protocol, speaking correctly and looking correct are
different goals: a server accepts any valid padding, while a censor compares
traffic statistics against the real Go client.

Upstream ties two padding decisions to values shoes cannot honestly reproduce:

- The strategy choice is `FixedIntV(2, username)`, seeded with
  `SHA-256(username ‖ " " ‖ mieruAppVersion)` — so it depends on **the Go
  application's version string** and can flip between mieru releases.
- `recommendedConsecutiveASCIILen` is `24 + FixedIntVH(17)`, seeded from **the
  hostname**.

Byte-for-byte parity with "the" Go client is therefore not a thing that exists;
it varies by version and host even among Go clients.

**Decision: distributional parity with independent seeding.** Both strategies
and their length distributions are reproduced exactly. The per-user strategy
choice is seeded from the username alone, without borrowing another project's
version string, and the ASCII run length is drawn from the same
`24 + [0, 17)` range. The result is statistically indistinguishable from the
Go client population without pinning shoes to someone else's release cadence.

## Error handling

Nothing on the data path panics; anything derived from a peer's bytes returns
`io::Error`.

- **Clock.** The key comes from time rounded to 2 minutes, so a device whose
  clock has not synchronised cannot authenticate at all. The error says so
  directly rather than reporting a generic decryption failure.
- **Nonce desynchronisation** is silent by construction. The stream
  distinguishes "wrong password" (the very first segment failed) from "the
  stream diverged" (earlier segments succeeded) by counting segments decrypted
  so far, and says which.
- **No secrets leak.** The password, the derived key and the username never
  reach a log line or an error message — only that authentication failed. The
  config password is wrapped in `Redacted<T>`.
- **Config rejections are loud.** `transport: udp`, a multiplexing setting
  other than off, and a non-zero low-entropy mode are rejected in
  `config/validate.rs` naming what is unimplemented.

## Testing

Three tiers, matching how the QUIC outbounds are tested:

1. **Codec vectors** in `frame.rs`, `metadata.rs`, `crypto.rs`: field offsets,
   the nonce increment including the carry across a `0xff` byte, key derivation
   against a value computed from the documented steps, and the low-entropy
   example from `docs/protocol.md` used as a rejection test.
2. **In-process interoperability**: the client against this repository's own
   mieru server over a loopback socket, for TCP round trips, a UDP round trip
   through the socks5 encapsulation, a payload larger than one fragment, and a
   wrong password.
3. **Padding distribution**: lengths stay inside their bounds, ASCII padding
   really contains its printable run, entropy padding moves the bit
   distribution toward the target, and both strategies are reachable.

Every new test is mutation-checked: the defect it describes is reintroduced and
exactly that test must go red.

## Deliberately not decided here

The implementation plan decides file-by-file ordering and step granularity.
This document fixes the wire format, the module boundaries, the parity policy
and the rejection list.
