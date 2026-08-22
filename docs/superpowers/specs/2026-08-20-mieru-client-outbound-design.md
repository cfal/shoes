# mieru client outbound

Design for speaking the mieru proxy protocol from shoes, as a client outbound
over TCP. Client only: shoes dials mieru servers and does not become one.

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
| UDP encapsulation, byte for byte | `apis/common/packet_over_stream.go:39-84` |

A second reference exists and is worth reading before changing this code:
[enfein/mbox](https://github.com/enfein/mbox) is the author's own integration
of mieru into sing-box — the same task this document describes, solved for a
different host. `protocol/mieru/outbound.go` there dials TCP through the
client API and wraps UDP in `PacketOverStreamTunnel`, which is the same
division of labour used here.

## Problem

mieru is a censorship-resistant proxy protocol. shoes speaks fifteen protocols
but not this one, so a user with a mieru deployment cannot route through it.

## Scope

**In scope:** a client outbound over mieru's TCP transport.

**A mieru server is out of scope.** shoes implements servers for most of the
protocols it speaks, and for Hysteria2 and TUIC that server is what the client
is tested against in process. Here the client is the whole deliverable; a
server would be roughly a third more work for a listener nobody has asked for.
The cost lands on testing, and is paid as described under Testing: a scripted
peer supplies the bytes a server would send, and interoperability with a real
mieru deployment stays unverified until someone runs it.

**Out of scope, and rejected loudly in config validation rather than ignored:**

| Feature | Why it is out |
| --- | --- |
| mieru's UDP transport | It carries a full ARQ stack — CUBIC, RTT estimation, retransmission, windows — which is a small TCP in userspace. Upstream's own `docs/protocol.md` says "In most cases, we recommend using TCP protocol." |
| Low entropy encoding | Four modes with mask rotation, needed only against DPI that measures entropy. The client selects it, so a server accepts a client without it. |
| Session multiplexing | `MULTIPLEXING_OFF` is a legal client setting, so one session per connection interoperates. |
| Traffic pattern profiles | mieru's configurable padding-bound layer. Its absence changes padding limits, not correctness. |

UDP application traffic is **in scope** and works without mieru's UDP
transport: mieru carries socks5 UDP-associate inside the TCP session.

## Feature parity with the Go client

Read from `pkg/appctl/proto/clientcfg.proto`, `pkg/appctl/proto/base.proto` and
`pkg/protocol/mux.go` at `b9bbc41`. "Planned" means this design covers it.

### Core protocol

| Capability | Go client | This design |
| --- | --- | --- |
| TCP transport | yes | planned |
| UDP transport | yes | **no** — needs the ARQ stack; rejected in validation |
| XChaCha20-Poly1305 with time-derived key | yes | planned |
| Three-salt window on the receiving side | yes | planned — the client keeps one key per attempt and re-derives on rotation |
| Implicit nonce per direction | yes | planned |
| User hint in the nonce | yes | planned |
| Session open/close handshake | yes | planned |
| Fragmentation to 32768 bytes | yes | planned |
| socks5 CONNECT inside the session | yes | planned |
| socks5 UDP-associate inside the session | yes | planned |
| ACK / window / sequence fields over TCP | carried, not acted on | same — carried, not acted on |

### Obfuscation

| Capability | Go client | This design |
| --- | --- | --- |
| ASCII padding strategy | yes | planned |
| Entropy padding strategy | yes | planned |
| Per-user stable strategy choice | seeded from username + app version | planned, seeded from username only — see Traffic-pattern parity |
| Low entropy encoding (4 modes, mask rotation) | yes | **no** — rejected in validation |
| `trafficPattern.padding` limits | yes | **no** — internal defaults only |
| `trafficPattern.nonce` (4 nonce types, custom prefixes) | yes | **no** |
| `trafficPattern.tcpFragment` (extra fragmentation with sleeps) | yes | **no** |
| `trafficPattern.seed` / `unlockAll` | yes | **no** |

### Connection management

| Capability | Go client | This design |
| --- | --- | --- |
| Multiple server endpoints | yes, picked at random per dial | shoes' own chain and pool selection covers this |
| Port ranges per endpoint (`portRange`) | yes | **no** — a single port per endpoint |
| Session multiplexing (4 levels) | yes | **no** — one session per connection, `MULTIPLEXING_OFF` equivalent |
| Underlay reuse | yes | not applicable without multiplexing |
| `handshakeMode` 0-RTT (send payload with the request) | yes | **no** — standard 1-RTT only |
| Configurable MTU | yes | not applicable to the TCP transport |
| Dialer proxy (`ClientDialer`) | yes | shoes' chain model covers this, and more generally |

For a second opinion on which of these a host integration actually needs,
`option/mieru.go` in mbox is the minimum the author himself exposed when
putting mieru into sing-box: `server`, `server_ports`, `transport`,
`username`, `password`, `multiplexing`, `traffic_pattern`. Ours matches on
username, password and server, and refuses the rest — the same three fields
carry a working connection in both.

### Deliberately not our problem

mieru bundles a client application; several of its settings have broader shoes
equivalents, and copying them would be a regression rather than a gain:

| mieru | shoes |
| --- | --- |
| `socks5Port`, `httpProxyPort`, `socks5ListenLAN` | server types in their own right, usable in front of any outbound |
| `socks5Authentication` | the `socks5` server's own auth |
| `rpcPort`, `activeProfile`, profile management | configuration is a file |
| `loggingLevel`, `metricsLoggingInterval` | shoes' logging and counters |
| `noCheckUpdate` | shoes does not phone home |

### What parity means here

The unimplemented rows fall into two groups, and they carry different risk.

**Reachability:** only the UDP transport and `portRange` can make a server
unreachable, and both are server-side deployment choices a user controls.
Everything else in the "no" column is a client-side option — a server accepts a
client that does not use it.

**Detectability:** the `trafficPattern` rows are the ones that matter for the
protocol's actual purpose. A Go client with a configured traffic pattern and a
shoes client without one produce different traffic. This design targets the
*default* Go client's behaviour, which is what the population of deployments
mostly runs; matching a customised pattern would need the whole
`trafficPattern` surface and is the natural second iteration.

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
| `client.rs` | `TcpClientHandler`, socks5 inside the session, UDP encapsulation | `stream.rs` |

The codec modules encode **and** decode. The client only needs to decode what a
server sends, but the reverse direction is what makes the codec testable
without a server, and it is the same code path a server would use if one is
ever written.

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
- **Config rejections are loud.** Every row marked "no" in the parity table
  that a user could plausibly write into a shoes config is rejected in
  `config/validate.rs`, naming what is unimplemented rather than silently
  ignoring it: `transport: udp`, a multiplexing level other than off, a
  non-zero low-entropy mode, a port range, 0-RTT handshake mode, and any
  traffic-pattern field. A user who asks for a traffic pattern and silently
  gets shoes' defaults believes something false about how their traffic looks,
  which for this protocol is the whole point.

## Testing

Without a server to dial, the usual second tier — run the real thing in
process — is replaced by a scripted peer. Three tiers:

1. **Codec vectors** in `frame.rs`, `metadata.rs`, `crypto.rs`: field offsets,
   the nonce increment including the carry across a `0xff` byte, key derivation
   against a value computed from the documented steps, and the low-entropy
   example from `docs/protocol.md` used as a rejection test.
2. **Scripted peer** over a loopback socket: a test double that encodes, with
   this crate's own codec, the exact bytes a mieru server would send — the
   `openSessionResponse`, the socks5 reply, then data segments — and records
   what the client sends back. It is a byte generator, not a server: no user
   table, no salt window, no quota. This is the same shape as the scripted
   server-side stream used by `routing/udp_router.rs`, and it covers the
   session state machine, fragment reassembly, the UDP encapsulation, and
   nonce desynchronisation.
3. **Padding distribution**: lengths stay inside their bounds, ASCII padding
   really contains its printable run, entropy padding moves the bit
   distribution toward the target, and both strategies are reachable.

Every new test is mutation-checked: the defect it describes is reintroduced and
exactly that test must go red.

### Verified against a real server

A scripted peer built from our own codec cannot detect a shared
misunderstanding of the specification: if we encode a field wrongly, we decode
it wrongly to match, and every test passes. Only a real mieru server settles
that, and one has now been run against.

The deployment was routebox on a VPS: TCP transport, one user, traffic pattern
off, no user hint required. What passed, on 2026-08-22:

| | |
| --- | --- |
| TCP connect and egress | the reply carried the server's own address |
| HTTPS through the proxy | 200, 75 ms |
| Three sequential connections | 200 each, about 150 ms |
| 1 MB download | 1048576 bytes over the multi-segment path |
| DNS over socks5 UDP associate | answered, three times running |
| TCP after UDP on the same config | works |
| Wrong password | server closes the connection, client says so |

The megabyte download and the UDP round trip matter most: those are the paths
where the code review found the read-buffer bound and the missing socks5 UDP
header. They are now confirmed on a live peer rather than only in tests.

One component has independent confirmation of a different kind. The UDP
encapsulation was compared line by line against
`apis/common/packet_over_stream.go` — the `0x00` prefix, the big-endian 16-bit
length, the 65535 ceiling, the `0xff` suffix and the rejection of a wrong
marker at either end all match.

### What is still not guaranteed

A single manual run is not a regression test. The next change to the codec is
unguarded, so `ROADMAP.md` keeps a `mita`-in-CI entry as the next step, with a
mieru server here as the more thorough alternative.

The run also covered one server configuration. A deployment using mieru's UDP
transport, a configured traffic pattern, session multiplexing, port ranges or
the low entropy encoding is refused by our validation rather than mishandled —
but it is refused, not supported.

## Deliberately not decided here

The implementation plan decides file-by-file ordering and step granularity.
This document fixes the wire format, the module boundaries, the parity policy
and the rejection list.
