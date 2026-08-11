# Hysteria2 and TUIC client outbounds

Dial Hysteria2 and TUIC v5 servers. Both protocols are already served by this
repository and neither can be used as an upstream, which is the last open item
in Tier 1.

Written 2026-08-11 against `mobile` at `5aea5ad`. Roadmap item: Tier 1 #3.

## Table of Contents

- [Problem](#problem)
- [Scope](#scope)
- [What sing-box does](#what-sing-box-does)
- [Why the existing chain model does not fit](#why-the-existing-chain-model-does-not-fit)
- [The terminal connector](#the-terminal-connector)
- [Connection lifetime](#connection-lifetime)
- [Hysteria2 on the wire](#hysteria2-on-the-wire)
- [TUIC v5 on the wire](#tuic-v5-on-the-wire)
- [Obfuscation](#obfuscation)
- [QUIC transport parameters and fingerprinting](#quic-transport-parameters-and-fingerprinting)
- [File structure](#file-structure)
- [Configuration](#configuration)
- [Validation](#validation)
- [Error handling](#error-handling)
- [Adjacent defect: a pool of tunnels panics](#adjacent-defect-a-pool-of-tunnels-panics)
- [Testing](#testing)
- [Dependencies](#dependencies)
- [Order of work](#order-of-work)
- [Deliberately out of scope](#deliberately-out-of-scope)
- [Sources](#sources)

## Problem

`src/hysteria2_server.rs` and `src/tuic_server.rs` implement both protocols in
full: authentication, framing, address encoding, UDP relay with fragment
reassembly. Neither appears in `ClientProxyConfig` (`src/config/types/client.rs:442`),
so shoes can serve Hysteria2 and cannot dial it.

Every frame the client needs to write is already parsed by the server in this
tree, and every frame it needs to read is already written by it. The work is
not protocol research; it is that the client-side plumbing has nowhere to
attach.

Hysteria2 in particular is now one of the most widely deployed protocols in the
commercial market, so this is the largest gain in real-world-server coverage
per line written that remains.

## Scope

In:

- Hysteria2 client outbound: HTTP/3 authentication, TCP streams, UDP relay over
  QUIC datagrams with fragmentation.
- TUIC v5 client outbound: `Authenticate`, `Connect`, `Packet` in both relay
  modes, `Dissociate`, `Heartbeat`.
- Salamander obfuscation, on the client **and** the server, so the pair can be
  tested end to end.
- One long-lived QUIC connection per configured outbound, re-established lazily.
- Both protocols as the single hop of a chain.

Out, and why: see [Deliberately out of scope](#deliberately-out-of-scope).

## What sing-box does

sing-box exposes both as ordinary outbounds with their own transport; neither
is composed out of a socket layer and a stream-wrapping layer. Its Hysteria2
outbound surface is worth reading in full because it marks where this feature
grows next.

Findings from the changelog and the current option reference:

- **`gecko` obfuscation exists and is official.** It lives upstream in
  `apernet/hysteria` (`extras/obfs/gecko.go`, `gecko_frame.go`), is marked
  experimental, and is supported by sing-box on both the inbound and the
  outbound since 1.14.0-alpha.26. It *builds on* Salamander: the same
  scrambling, plus fragmentation of QUIC handshake packets into randomly sized,
  randomly padded chunks (`min_packet_size` 512, `max_packet_size` 1200).
  Salamander is therefore a prerequisite for it rather than an alternative to
  it, and the obfuscation layer here is specified as a trait with one
  implementation rather than as a single concrete type.
- **Chrome QUIC fingerprint parroting is on by default.** It originated
  upstream in `apernet/hysteria` 2.11.0, where `quic.disableChromeParrot` turns
  it off; sing-box followed in 1.14.0-beta.7 with `disable_chrome_parrot`. It is
  a client-side property: a server accepts a parroting and a non-parroting
  client alike. Its consequence for us is covered under
  [QUIC transport parameters and fingerprinting](#quic-transport-parameters-and-fingerprinting).
- **Bandwidth is optional and its absence is meaningful.** With `up_mbps` and
  `down_mbps` unset, the server instructs the client to use BBR rather than
  Hysteria's own congestion control. That is exactly what our server already
  does — it sends `Hysteria-CC-RX: 0` unconditionally — so declining to
  implement Brutal costs interoperability nothing.
- **Port hopping** (`server_ports`, `hop_interval`, `hop_interval_max`) and the
  **Realm** rendezvous service for NAT traversal (1.14.0-alpha.22) are separate
  features layered on the same client.
- The 1.13.0 deprecation of `recv_window_conn`, `recv_window`,
  `recv_window_client`, `max_conn_client` and `disable_mtu_discovery`, with
  removal planned for 1.16.0, concerns Hysteria v1 tuning fields. There is no
  Hysteria v1 here, so it does not apply.

One operational detail worth carrying into the documentation: a Hysteria2
password is a single opaque string. Servers that use username/password
authentication expect `<username>:<password>` in that one field. Our server
compares the whole `hysteria-auth` header value against the configured
password, so we are already compatible — but a user with such a server will
otherwise spend an afternoon guessing.

## Why the existing chain model does not fit

A chain is built from two traits. `SocketConnector` produces a
`Box<dyn AsyncStream>` at hop 0; `ProxyConnector` wraps an existing stream at
every hop. QUIC is already available as a socket transport
(`src/tcp/socket_connector_impl.rs:258`), so at first glance Hysteria2 could be
a `ProxyConnector` over a QUIC `SocketConnector`.

It cannot, for three reasons.

**Authentication is per connection, not per stream.** Hysteria2 authenticates
once with an HTTP/3 request; TUIC authenticates once with an `Authenticate`
command on a unidirectional stream, using a token derived from the TLS session.
`SocketConnectorImpl::connect` calls `endpoint.connect(...)` on every
invocation, so each proxied TCP connection would get a fresh QUIC connection
and a fresh authentication — a full handshake plus an authentication round trip
per connection, for a protocol whose entire point is that you pay for that once.

**UDP is connection-scoped.** Both protocols multiplex UDP sessions inside one
QUIC connection, keyed by a session or associate ID, with fragments reassembled
against that key. A model that creates a connection per stream has nowhere to
put a session table.

**The same wall has already been hit here once.** `H2MuxClientHandler` carries a
TODO at `src/h2mux/h2mux_client_handler.rs:6` recording that its session pooling
does not work, for precisely this reason: the caller supplies the transport
stream, so the handler cannot own connections. That is not a coincidence to
route around a second time.

## The terminal connector

The escape hatch already exists. `ClientProxyChainKind::VirtualNetwork` holds a
`VirtualNetworkConnector` (`src/tcp/virtual_network_connector.rs:24`) for
AmneziaWG, which likewise owns its transport. Its signature is what a Hysteria2
client needs, method for method:

```rust
async fn connect_tcp(&self, resolver, target) -> io::Result<TcpClientSetupResult>;
async fn connect_udp_bidirectional(&self, resolver, target) -> io::Result<Box<dyn AsyncMessageStream>>;
fn supports_udp(&self) -> bool;
```

The trait is generalised rather than duplicated:

- `VirtualNetworkConnector` → `TerminalConnector`, with documentation that says
  "owns its transport" instead of "virtual network tunnel".
- `ClientProxyChainKind::VirtualNetwork` → `Terminal`;
  `ClientProxyChain::new_virtual` → `new_terminal`.
- `ClientProxyConfig::is_virtual_network()` → `owns_transport()`, returning true
  for `Wireguard`, `AmneziaWg`, `Hysteria2` and `Tuic`.

WireGuard and AmneziaWG keep working unchanged; they are simply no longer the
only implementations. The dispatch branch in `chain_builder.rs:58` is widened,
not rewritten.

`supports_udp()` is synchronous and is consulted by `ClientProxyChain::new`
while the chain is being built, long before any authentication happens. It
therefore reports the value from the client's own configuration. A server that
later declines UDP is handled at [error handling](#error-handling) time, not
here.

The single-hop restriction that applies to AmneziaWG applies here for the same
reason: QUIC needs a UDP socket, and there is no way to raise one over another
proxy's TCP stream.

## Connection lifetime

One QUIC connection per configured outbound, held in a `LiveConnection`:

```rust
struct LiveConnection {
    inner: tokio::sync::Mutex<Option<quinn::Connection>>,
    /* endpoint, server address, auth material */
}
```

`get()` takes the mutex, and returns a clone of the held connection when
`close_reason()` is `None`. Otherwise it performs the QUIC handshake and the
protocol's authentication **while still holding the mutex**, so that concurrent
requests arriving during a reconnect wait for one result instead of starting
ten handshakes against a server that has just gone away. `quinn::Connection` is
cheap to clone and internally shared, so holding the mutex only across
establishment costs nothing on the hot path.

A failed establishment is not cached. The next request tries again.

The endpoint itself is created once, when the connector is built, and outlives
individual connections.

Rationale for one connection rather than a pool: a pool multiplies
authentications and UDP session tables by N for no benefit that QUIC does not
already provide — streams within one connection are independent, so there is no
head-of-line blocking to spread. Rationale for lazy rather than eager
re-establishment: a background task that keeps a connection warm is a wakeup
source on a device that is asleep, and this branch exists to run on phones.

## Hysteria2 on the wire

All constants below are taken from `src/hysteria2_server.rs`, which parses
exactly these frames today; the client is its mirror image.

**Connection.** QUIC with ALPN `h3`. Authentication runs over an HTTP/3
connection on that QUIC connection (`h3` + `h3-quinn`, both already
dependencies).

**Authentication.** `POST https://hysteria/auth` with:

| Header | Value |
| --- | --- |
| `Hysteria-Auth` | the password, verbatim |
| `Hysteria-CC-RX` | `0` — bandwidth unknown, use BBR |
| `Hysteria-Padding` | 1–79 random alphanumeric characters |

A successful response has status **233** and carries `Hysteria-UDP`,
`Hysteria-CC-RX` and `Hysteria-Padding`. Anything else — notably the 404 our
server returns for a request it does not recognise — is an authentication
failure. `Hysteria-UDP: false` is recorded on the connection and turns every
subsequent UDP attempt into an error naming the reason.

**TCP.** Open a bidirectional stream and write:

```
[varint] 0x401          frame type
[varint] address length
[bytes]  address        "host:port", UTF-8, at most 2048 bytes
[varint] padding length at most 4096
[bytes]  padding
```

Then read the response:

```
[uint8]  status         0x00 = OK, 0x01 = error
[varint] message length
[bytes]  message
[varint] padding length
[bytes]  padding
```

`0x401` is a QUIC varint. It is 1025, so the one-byte form cannot hold it and
the two-byte form `[0x44, 0x01]` is what goes out. A reader must accept every
encoding, which the shared varint decoder already does — our server has a
comment saying exactly that at `src/hysteria2_server.rs:777`.

Anything read past the end of the response belongs to the target's response
stream and is returned as `TcpClientSetupResult::early_data`, whose documented
meaning — "application data received during handshake (from final destination)"
(`src/tcp/tcp_handler.rs:99`) — is exactly this case.

**UDP.** QUIC datagrams:

```
[u32be]  session id
[u16be]  packet id
[u8]     fragment id
[u8]     fragment count
[varint] address length     at most 2048, never 0
[bytes]  address            "host:port", UTF-8
[bytes]  payload fragment
```

The client allocates the session ID. A payload that does not fit the connection's
current datagram limit is split across fragments sharing one packet ID; more
than 255 fragments is an error rather than a silent truncation.

## TUIC v5 on the wire

Verified against the upstream specification, not only against our server.

Every command is `[u8 version = 0x05][u8 type][type-specific data]`. Types:
`0x00` Authenticate, `0x01` Connect, `0x02` Packet, `0x03` Dissociate, `0x04`
Heartbeat.

Addresses are `[u8 type][address][u16be port]` with type `0xff` none, `0x00`
domain name prefixed by a one-byte length, `0x01` IPv4, `0x02` IPv6. Type
`0xff` appears in `Packet` commands that are not the first fragment.

**Authentication.** A unidirectional stream carrying `Authenticate`: the
16-byte UUID followed by a 32-byte token. The token comes from the TLS keying
material exporter on the live session, with the **UUID as the label and the raw
password as the context** — `quinn::Connection::export_keying_material(&mut out,
uuid, password)`, the same call our server makes to compute what it expects
(`src/tuic_server.rs:198`).

**TCP.** A bidirectional stream carrying `Connect` with the target address.
There is no response — the specification is explicit that the server never
answers — so payload follows the header immediately and `early_data` is always
`None`. A failure is signalled by the server closing the stream.

**UDP.** `Packet` commands with `[u16be assoc_id][u16be pkt_id][u8 frag_total]
[u8 frag_id][u16be size][address]`, sent either over QUIC datagrams (relay mode
`native`) or over unidirectional streams (relay mode `quic`). The server replies
in whichever mode the session's first packet used. The client allocates the
associate ID and sends `Dissociate` on a unidirectional stream when the session
ends.

**Heartbeat.** A datagram carrying `Heartbeat`, sent periodically **only while
a relaying task is in flight**. An idle connection sends nothing; quinn's own
keep-alive covers that case.

## Obfuscation

Salamander, verified against `apernet/hysteria`
(`extras/obfs/salamander.go`) rather than from memory:

```
smPSKMinLen = 4
smSaltLen   = 8
smKeyLen    = blake2b.Size256   // 32
```

Obfuscate: draw 8 random bytes of salt, derive `key = BLAKE2b-256(PSK ‖ salt)`,
then write `salt` followed by `payload[i] ^ key[i % 32]`. Deobfuscate reverses
it, rejecting anything 8 bytes or shorter. The transform is symmetric, so one
implementation serves both ends.

It is expressed as a trait so that `gecko` becomes an added file rather than a
rewrite:

```rust
pub trait Obfuscator: Send + Sync + Debug {
    /// Returns the number of bytes written to `out`, or None if it does not fit.
    fn obfuscate(&self, input: &[u8], out: &mut [u8]) -> Option<usize>;
    fn deobfuscate(&self, input: &[u8], out: &mut [u8]) -> Option<usize>;
    /// Bytes of overhead added to every packet.
    fn overhead(&self) -> usize;
}
```

It is applied by wrapping `quinn::AsyncUdpSocket`, transforming each datagram on
the way out and back. Two consequences that are easy to miss and expensive to
debug:

- **Segmentation offload must be off.** With GSO a single `sendmsg` carries
  several QUIC packets, and obfuscating the buffer as one unit produces
  something the peer cannot split apart. When an obfuscator is configured the
  connector sets `enable_segmentation_offload(false)` and caps the socket at one
  segment per send.
- **The usable MTU drops by `overhead()`.** The salt occupies room in the
  datagram, so `initial_mtu` and `min_mtu` are reduced by 8 when Salamander is
  on. Without this, packets that are exactly at the floor start disappearing on
  paths that honour it.

The server side takes the same `obfs` block and the same wrapper, which is what
makes the end-to-end tests possible at all.

## QUIC transport parameters and fingerprinting

This is not a feature; it is a property of the stack, recorded so the choice is
made deliberately.

Hysteria has parroted Chrome's QUIC handshake by default since upstream 2.11.0,
and sing-box followed. We cannot match that — it is the QUIC equivalent of uTLS,
a project rather than a backport, and the same conclusion applies as in the
ROADMAP's TLS fingerprinting section. The population of clients moving toward a
Chrome-like shape makes a default quinn client *more* distinctive than it was,
not less.

What is free, and what this spec requires: the sing-box documentation notes that
enabling parroting **overrides `idle_timeout` to 30s and the receive window
values**. Transport parameters are part of the fingerprint. So the connector
does not invent "reasonable" numbers; it uses the values our own Hysteria2 and
TUIC servers already use (`src/hysteria2_server.rs:993`,
`src/tuic_server.rs:1414`), which were themselves taken from the reference
implementations. Picking arbitrary windows would buy nothing and cost a unique
signature.

## File structure

The two servers are 1054 and 1474 line flat files, and the frame codecs the
client needs — varints, `serialize_address`/`read_address`, datagram layout —
are buried inside them. Copying a varint codec into a third file is not
acceptable, so each becomes a module:

```
src/hysteria2/
    mod.rs        re-exports; shared constants
    server.rs     today's hysteria2_server.rs, minus what moved to frame.rs
    client.rs     Hysteria2Connector: TerminalConnector
    auth.rs       the HTTP/3 authentication exchange
    frame.rs      varints, TCP request/response, datagram header
    udp.rs        a UDP session as AsyncMessageStream

src/tuic/
    mod.rs
    server.rs     today's tuic_server.rs, minus what moved to frame.rs
    client.rs     TuicConnector: TerminalConnector
    frame.rs      commands, addresses, packet headers
    udp.rs

src/quic_outbound/
    mod.rs        endpoint construction from ClientQuicConfig
    connection.rs LiveConnection
    obfs/
        mod.rs        the Obfuscator trait and the AsyncUdpSocket wrapper
        salamander.rs
```

The server moves are mechanical: cut the codec functions into `frame.rs`, fix
imports, let the compiler find the rest. `src/main.rs` declares its own module
tree independently of `src/lib.rs`, so both need the new modules.

## Configuration

Hysteria2:

```yaml
client_chains:
  - hops:
      - address: server.example.com:443
        protocol:
          type: hysteria2
          password: secret
          udp_enabled: true       # default true
          obfs:                   # optional
            type: salamander
            password: obfspass
        quic_settings:
          sni_hostname: server.example.com
          verify: true
```

TUIC:

```yaml
        protocol:
          type: tuic
          uuid: "00000000-0000-0000-0000-000000000000"
          password: secret
          udp_enabled: true             # default true
          udp_relay_mode: native        # native = datagrams, quic = uni streams
          zero_rtt_handshake: false
          heartbeat_ms: 10000
```

The obfuscation block is internally tagged with per-type fields alongside, which
is byte-for-byte the shape sing-box uses, so a `gecko` entry with
`min_packet_size` and `max_packet_size` slots in without a schema change.

`quic_settings` is reused rather than replaced: it already carries `verify`,
`server_fingerprints`, `sni_hostname`, `alpn_protocols`, `key` and `cert`, all
of which mean the same thing here. `alpn_protocols` defaults to `["h3"]` for
both protocols.

The server gains the same `obfs` block on `ServerProxyConfig::Hysteria2`.

## Validation

Mirroring the rules already applied to virtual-network protocols
(`src/config/validate.rs:975`), with one deliberate difference:

| Field | Rule |
| --- | --- |
| `transport` | Rejected. The transport is QUIC and is not chosen. |
| `tcp_settings` | Rejected. There is no TCP socket. |
| `quic_settings` | **Allowed**, unlike WireGuard/AmneziaWG. |
| `obfs.password` | At least 4 bytes, matching `smPSKMinLen` upstream. |
| `uuid` | Must parse as a UUID. |
| `udp_relay_mode` | One of `native`, `quic`. |
| chain position | Only hop, and cannot share a pool with other protocols. |

## Error handling

| Situation | Behaviour |
| --- | --- |
| Hysteria2 authentication rejected (status is not 233) | Permanent error naming the status; the connection is closed and not retried within the request |
| TUIC authentication rejected | The server closes the connection; surfaced as a connect error |
| Connection died between authentication and opening a stream | One retry on a freshly established connection, then an error |
| Hysteria2 TCP response with `status != 0` | Error carrying the server's message when it is non-empty |
| TUIC `Connect` stream closed without data | Error; the specification defines no response, so a closed stream is the only failure signal |
| UDP requested while the server declined it | Error naming the reason, rather than a timeout |
| Payload needs more than 255 fragments | Rejected rather than truncated |
| Obfuscated datagram shorter than the salt | Dropped, counted at debug level |

## Adjacent defect: a pool of tunnels panics

Independent of this feature, and fixed first as its own commit.

`validate.rs:1679` explicitly permits a pool of several virtual-network configs
in one hop — it checks that they are *all* tunnels and accepts that. But
`chain_builder.rs:58` only takes the virtual branch when the hop holds exactly
one config, so a pool of two AmneziaWG configs falls through to the ordinary
path, reaches `tcp_client_handler_factory.rs:366` and panics. A configuration
the validator blesses kills the process at startup.

The fix belongs to the same dispatch this work touches, and the widened branch
should accept a pool of terminal connectors for every protocol that owns its
transport, not just for the two being added.

## Testing

End-to-end, against our own server on `127.0.0.1` with a generated certificate,
which is what makes implementing Salamander on both ends worth it:

- Hysteria2: TCP round trip; UDP round trip; both again with obfuscation on.
- Hysteria2: fragmented UDP payload larger than the datagram limit.
- TUIC: TCP round trip; UDP round trip in `native` and in `quic` mode.
- Reconnect: kill the connection from the server side, assert the next request
  establishes a new one and succeeds.
- Wrong password on each protocol produces a clear error, not a timeout.
- Server with UDP disabled produces the documented error rather than hanging.

Unit level:

- Frame codecs: varints at each width boundary, the multi-byte encoding of
  `0x401`, address encodings including a 255-byte hostname, oversized address
  and padding lengths rejected.
- Salamander: round trip through obfuscate/deobfuscate; a packet at or below 8
  bytes rejected; a fixed vector so a future refactor cannot silently change the
  transform.
- Config: every documented field parses, unknown fields are rejected, a
  misspelled `obfs.type` names the valid options, and each validation rule above
  has a test.

## Dependencies

One new crate: `blake2`, for BLAKE2b-256 in Salamander. Pure Rust, built on the
`digest` crate that is already a dependency. Nothing else is added — `quinn`,
`h3`, `h3-quinn`, `http`, `rand` and `rustls` are all present because the
servers use them.

## Order of work

1. Fix the tunnel-pool panic, with its own test and its own commit.
2. Rename `VirtualNetworkConnector` to `TerminalConnector` and
   `is_virtual_network` to `owns_transport`.
3. Move both servers into modules and lift the frame codecs into `frame.rs`.
4. `src/quic_outbound/`: endpoint construction and `LiveConnection`.
5. Salamander: the trait, the implementation, the socket wrapper, and the server
   config field.
6. Hysteria2 client: authentication, then TCP, then UDP.
7. TUIC client: authentication, then TCP, then UDP.
8. Configuration, validation, `examples/`, CONFIG.md, README, ROADMAP, and a
   dry-run entry in the CI smoke test.

## Deliberately out of scope

- **Brutal congestion control.** Hysteria's bandwidth-driven controller.
  Requires a `quinn` congestion controller implementation. Costs nothing in
  interoperability: our server sends `Hysteria-CC-RX: 0`, and sing-box treats
  absent bandwidth as an instruction to use BBR. Without it, throughput on a
  lossy path will be lower than the official client's, which is the whole reason
  people choose Hysteria2 — so this is the first thing to add next.
- **`gecko` obfuscation.** Experimental upstream. Its scrambling is Salamander,
  which this spec implements; what it adds is a handshake-packet fragmentation
  layer that deserves its own work.
- **Port hopping** (`server_ports`, `hop_interval`, `hop_interval_max`).
- **Hysteria Realm**: rendezvous, STUN discovery and UDP hole punching.
- **Chrome QUIC handshake parroting.** See
  [QUIC transport parameters and fingerprinting](#quic-transport-parameters-and-fingerprinting).
  Recorded as a known exposure, not planned.
- **Multi-hop chains.** Both protocols must be the only hop, for the same reason
  AmneziaWG must be.
- **Hysteria v1.** Not implemented on either side, and being retired upstream.

## Sources

- `apernet/hysteria`, `extras/obfs/salamander.go` — obfuscation constants and
  transform, read directly.
- `EAimTY/tuic`, `SPEC.md` — TUIC v5 command layout, token derivation, relay
  modes, heartbeat rule, read directly.
- sing-box changelog and the Hysteria2 inbound/outbound option references —
  `gecko`, Chrome parroting, bandwidth semantics, port hopping, Realm.
- `src/hysteria2_server.rs` and `src/tuic_server.rs` in this repository — the
  authoritative encoders and decoders for everything the client must mirror.
