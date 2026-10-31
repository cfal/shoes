---
title: VLESS Encryption
description: Native VLESS encryption, Vision composition, and resumption limits.
---

Generate matching client `encryption` and server `decryption` strings:

```sh
shoes generate-vless-encryption
shoes generate-vless-encryption --auth x25519 --auth mlkem768 --mode random
shoes generate-vless-encryption --auth x25519 --rtt 1rtt --lifetime 0s
```

The default uses ML-KEM-768 authentication, `native` appearance, and resumable
sessions with a maximum 600-second ticket lifetime. Repeated `--auth` options
form an ordered key chain; preserve that order on both ends. Private credentials
are printed only by the generator and should be treated as passwords.

Put the generated settings on the VLESS protocol itself. Native Vision uses
`vision: true` at that same level. When wrapping native VLESS in TLS or REALITY,
leave the **outer** `vision` flag false. Native DIRECT removes only the native
record encryption; it never bypasses an outer TLS, REALITY, WebSocket, XHTTP, or
QUIC transport. Existing encryption-disabled Vision configurations keep their
outer TLS/REALITY flag unchanged. See [the native example](/examples/vless_encryption/).

The appearances `native`, `xorpub`, and `random` share the same encrypted protocol.
`xorpub` masks the key-exchange relay; `random` additionally masks record headers,
including application TLS headers after Vision DIRECT. Random mode cannot use
TCP splice. Fresh exchanges combine ephemeral ML-KEM-768 and X25519; Vision
DIRECT subsequently relies on the application's own TLS, which is not necessarily
post-quantum. Native encryption works with pinned Xray and Mihomo peers, not
sing-box. Empty settings and `none` preserve unencrypted VLESS.
Server `encryption` and client `decryption` are rejected; use the setting for the
correct side rather than swapping the generated strings.

Native decryption rejects VLESS fallback. Native Vision rejects H2MUX; encrypted
VLESS without Vision supports H2MUX. Command-2 UDP uses an empty flow, while
XUDP may use Vision. No failed encrypted connection is silently retried as
plaintext or automatically replayed to a destination.

Server `encryption_limits` defaults are `max_sessions: 4096`,
`max_replays: 262144`, and `max_replays_per_session: 65536`. All must be positive.
Size replay limits for the expected resumption rate times the maximum ticket
lifetime plus the 120-second retention grace.
At 75% session/replay occupancy, new connections receive zero-lifetime tickets
and remain usable through fresh handshakes. At the hard replay limit, the whole
requesting ticket is invalidated; that resumption fails, and the next independent
connection performs a fresh handshake. New resumable tickets are issued only
once both session and replay occupancy fall below 75%. Duplicate resumes never
repeat destination I/O.
Ticket state is shared across addresses of one logical listener, not across
different protocol targets. Reloads reset ticket state; existing streams retain
their cryptographic state. TLS/REALITY/QUIC resumption is independent.

Rollback requires rolling back configuration as well as the binary: older Shoes
versions silently ignore native encryption fields. Conversely, a previously
ignored VLESS-level `vision: true` without native encryption now produces a
migration error instead of silently disabling Vision.
