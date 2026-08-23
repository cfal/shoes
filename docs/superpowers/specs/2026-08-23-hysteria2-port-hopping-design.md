# Hysteria2 port hopping, client side

Written 2026-08-23 against `mobile` at `ff7e969`, and against
[HyNetworks/hysteria](https://github.com/HyNetworks/hysteria) at `master`.

## Why

A Hysteria2 server is often published as a port *range* rather than a single
port, and the deployment then firewalls everything except that range. A client
that dials one fixed port either cannot reach such a server at all, or reaches
it on a port a censor can block once and for good.

The mechanism is not a performance feature. Rotating the port changes the
connection's 4-tuple on a timer, so a middlebox tracking the flow loses it.
That is the whole point, and it is why the *local* port has to change too — see
"What the reference actually does".

Scope: **the Hysteria2 client outbound only.** Our own Hysteria2 server keeps
its single listening port. TUIC does not get this: its protocol has no such
mechanism, and offering the option would be offering something no real TUIC
server understands.

## Sources

| What | Where |
| --- | --- |
| Hop connection, socket lifecycle, address rewriting | `extras/transport/udphop/conn.go` |
| Address and port-union type | `extras/transport/udphop/addr.go` |
| User-facing syntax, defaults, server requirements | <https://v2.hysteria.network/docs/advanced/Port-Hopping/> |
| Our QUIC outbound and its socket seam | `src/quic_outbound/mod.rs:119`, `src/quic_transport/obfs/socket.rs:87` |
| Protected socket construction | `src/socket_util.rs:20` |
| Port-union parsing we already have | `src/address.rs:310` |

## What the reference actually does

Read before designing, because half of it is counter-intuitive.

- **A new socket is bound on every hop.** `ListenUDPFunc` defaults to
  `net.ListenUDP("udp", nil)`, so the local port changes as well as the
  destination. This is deliberate: if only the destination moved, the flow
  would still be trivially linkable by its unchanged source port.
- **Two sockets are alive at a time.** On a hop, the previous socket is closed,
  the current becomes the previous, and the new one becomes current. The
  previous keeps receiving until the hop after next, which covers the packets
  the server already sent to the old port.
- **The destination is chosen at random**, `rand.Intn(len(Addrs))`, not round
  robin.
- **The QUIC layer is lied to.** `ReadFrom` reports every packet as coming from
  one canonical address, and `WriteTo` ignores the address it is given and
  sends to the currently chosen one. Without this, QUIC would see a path change
  on every hop.
- **Timing**: default 30s, minimum 5s, optionally a random value in a
  `[min, max]` range. Upstream spells these `hopInterval`, `minHopInterval`
  and `maxHopInterval`.
- **Syntax**: `example.com:1234,5000-6000,7044,8000-9000` — individual ports,
  ranges, and mixtures, comma separated.

Note for anyone extending this later: upstream's *server* does support
`listen: :20000-50000` natively on Linux, programming nftables or iptables
itself. External DNAT rules are an alternative, not the only route. We are
deliberately not doing either.

## Architecture

A new module, `src/quic_transport/hop.rs`, sitting beside `obfs/`. It is the
same kind of thing — a wrapper implementing `quinn::AsyncUdpSocket` — and
belongs next to its sibling. Placement grants nothing: the feature is reachable
only through a config field that exists on `Hysteria2ClientConfig` alone.

### Components

**`PortSet`** — the parsed union of candidate ports, drawn from at random. The
parsing rules are the ones `NetLocationPortRange::from_str` already implements
(`src/address.rs:310`); that loop is extracted into a shared function rather
than copied, so the two cannot drift.

**`HopSchedule`** — either a fixed interval or a `[min, max]` pair yielding a
fresh random duration per hop.

**`HoppingUdpSocket`** — implements `AsyncUdpSocket`. Holds the socket factory,
the current socket, the previous socket, the currently chosen destination, a
generation counter, and an `AtomicWaker`.

**`HoppingPoller`** — implements `quinn::UdpPoller`. quinn asks for a poller
once and holds it for the connection's life, while the socket underneath
changes; this one records the generation it was built for and rebuilds its
inner poller when the generation moves.

### The socket factory

The factory is the only way a socket comes into existence in this module.
There are no direct binds. It closes over
`new_udp_socket(is_ipv6, bind_interface)` (`src/socket_util.rs:20`), which
calls `protect_outbound`.

This is not a stylistic choice. Sockets are created at runtime, on a timer, for
the life of the connection; a socket that skipped the protector would be routed
back into the VPN tunnel it is meant to carry. That is the class of leak
MOBILE.md §2 records as fixed, and the only durable fix is making the mistake
unrepresentable rather than remembered.

The factory also applies obfuscation when configured, returning an
`Arc<dyn AsyncUdpSocket>` that is already wrapped. Hopping therefore knows
nothing about Salamander, and Salamander knows nothing about hopping. This is
sound because Salamander carries no state between packets, so each new socket
can be obfuscated independently.

The existing non-hopping paths in `build_endpoint` are left exactly as they
are. The factory is used only when hopping is configured, so the default path
keeps its current shape and cannot regress.

## Data flow

**Send.** `try_send` discards `transmit.destination` and substitutes the
currently chosen address, clears `src_ip` (the socket quinn believes it is
using is not the one that will carry the datagram), and delegates to the
current socket.

**Receive.** Poll the current socket; if it is `Pending`, poll the previous
one. Rewrite `RecvMeta.addr` on every datagram to the canonical server address,
so quinn never observes a path change. Wakers are registered on both sockets.

**Hop.** A task on a timer: build a socket through the factory, drop the old
previous socket, move current to previous, install the new socket as current,
bump the generation, pick a new destination port at random, and wake the
`AtomicWaker`.

That wake matters. Without it quinn stays parked on the socket it was polling
and learns about the new one only if something happens to arrive — which, on a
connection that is idle in one direction, may be never.

## Configuration

```yaml
- address: example.com:443
  protocol:
    type: hysteria2
    password: ...
    port_hopping:
      ports: "20000-50000"       # or "1234,5000-6000,7044"
      interval_ms: 30000         # or min_interval_ms / max_interval_ms, not both
```

Milliseconds in the field name, following `heartbeat_ms` on the TUIC client
(`src/config/types/client.rs:282`). This tree has no `30s`-style duration
strings: the only string-valued timings are AmneziaWG's `a-b` ranges in
seconds, which are a different thing. Inventing a third format here would be a
format nobody else in the file uses.

`PortHoppingConfig` carries `#[serde(deny_unknown_fields)]`, as every other
config struct in that file does, so a misspelled key is an error rather than a
setting silently doing nothing.

**When `ports` is set it replaces the port in `address` entirely.** In the
example above, 443 is never dialled. This is upstream's semantics and it is
what the `hysteria2://` sharing link expresses, where the multi-port parameter
supersedes the host's port. It is stated here, in the field's documentation
comment, and in CONFIG.md, because it is the one thing about this feature that
will surprise someone.

Rejected at config load rather than ignored, following the convention the rest
of this tree uses:

| Rejected | Why |
| --- | --- |
| `ports` empty or unparsable | There is nothing to hop between |
| `interval_ms` below 5000 | Upstream's floor; below it the hop rate itself becomes a signature |
| `min_interval_ms` greater than `max_interval_ms` | Not an interval |
| `interval_ms` together with `min_interval_ms` or `max_interval_ms` | Two answers to one question; picking one silently would be a guess |

## Error handling

**A failed hop must never kill a live connection.** If the factory fails — file
descriptors exhausted, the protector refusing — the current socket stays in
place, a warning is logged, and the next tick tries again. The alternative
turns an anti-blocking feature into a source of outages, which is worse than
not having it.

`try_send` refuses a transmit carrying `segment_size`, exactly as the
obfuscated socket does: we report `max_transmit_segments() == 1`, and silently
scrambling a coalesced batch would corrupt every packet in it. For the same
reason `enable_segmentation_offload` is set false in the transport parameters
when hopping is on, mirroring what obfuscation already does.

Errors on the previous socket are swallowed. It is scheduled to die; noise
about it would train the reader to ignore the log.

`local_addr()` reports the current socket's address. The MTU calculation is
untouched — hopping costs no bytes per datagram, unlike Salamander.

## Testing

**Port union parsing.** Single port, comma list, range, mixture; rejection of a
reversed range, of a value beyond `u16`, and of an empty string. These run
against the extracted shared function, so they cover the existing listen-range
path too.

**Schedule.** A fixed interval returns that interval; a range stays within its
bounds.

**The socket wrapper**, over loopback sockets with no QUIC involved:

- a send goes to the *chosen* destination, not the one quinn asked for
- every received datagram is reported with the canonical server address
- after a hop, a datagram sent to the previous socket still arrives
- after two hops, the socket from two hops ago is closed
- a factory failure during a hop leaves the current socket working
- the waker fires on a hop

**Integration — the iptables mimicry.** A bank of UDP relays on a range of
ports forwards to the single port of our own Hysteria2 server, all in process.
This is what an iptables REDIRECT does, in userspace and without root, and it
runs in CI on every commit. A transfer longer than three hop intervals must
satisfy three assertions:

1. the payload arrives intact
2. the relay bank saw traffic on at least two distinct ports
3. the client used at least two distinct local ports

The last two are not decoration. Without them the test passes with hopping
switched off entirely, which is precisely the kind of green test that let
seventeen defects through in the mieru work.

The test runs with an interval of roughly 200ms. **The 5000ms floor is a
config-validation rule, not an invariant of the mechanism** — recorded here so
that nobody later "fixes" the test by raising it and turns a fast check into a
minute of waiting.

**Mutation check.** With the hop timer stubbed to never fire, assertions 2 and
3 must fail. If they do not, they are measuring nothing.

**Live.** Against a real Hysteria2 server published on a port range, if one is
raised. Manual, once, recorded in ROADMAP.md the way the mieru run was.

## What this does not do

- No server-side support. Our Hysteria2 server still listens on one port.
- No TUIC. The config surface does not exist there.
- No `hysteria2://` link import. That is the next sub-project, and it will
  consume the config surface defined here rather than inventing its own.
