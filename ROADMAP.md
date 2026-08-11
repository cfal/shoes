# Roadmap

Where this fork stands against sing-box and Xray-core, and what is worth building
next. Written 2026-08-09 against `mobile` at `7ed9f0b`; the Hysteria section was
added 2026-08-11 against `apernet/hysteria` at `app/v2.12.1`.

The audience is anyone deciding what to work on. Every gap below is stated with
the file it lands in, so the estimate is checkable rather than a guess.

## Table of Contents

- [Where we already compete](#where-we-already-compete)
- [Where we do not](#where-we-do-not)
- [Tier 1 — closes most of the gap](#tier-1--closes-most-of-the-gap)
- [Tier 2 — worth doing after Tier 1](#tier-2--worth-doing-after-tier-1)
- [Tier 3 — real, but not urgent](#tier-3--not-urgent)
- [Hysteria: the rest of the surface](#hysteria-the-rest-of-the-surface)
- [Explicitly not planned](#explicitly-not-planned)
- [Open risk: TLS fingerprinting](#open-risk-tls-fingerprinting)

## Where we already compete

The protocol surface is close to parity with sing-box.

Server: HTTP, SOCKS5, Mixed, Shadowsocks (including 2022-blake3), VMess AEAD,
VLESS, Trojan, Snell v3, Hysteria2, TUIC v5, AnyTLS, NaiveProxy, port-forward,
TLS, WebSocket.

Client: Direct, HTTP, SOCKS5, Shadowsocks, Snell, VMess, VLESS, Trojan, AnyTLS,
NaiveProxy, WireGuard, AmneziaWG 2.0/3.0, plus TLS, Reality, ShadowTLS and
WebSocket as wrapping layers.

Transports and obfuscation: TCP and QUIC for every protocol, XTLS Reality (a
hand-written TLS 1.3 stack, `src/reality/`), XTLS Vision, ShadowTLS v3, H2MUX,
SagerNet UDP-over-TCP, XUDP.

TUN mode with a Fake IP pool, on Linux, Android and iOS.

## Where we do not

The gap is not in protocols. It is in everything around them.

| Capability | shoes | sing-box |
| --- | --- | --- |
| Routing rule matchers | CIDR and `*.domain` masks | 43 fields |
| Domain/IP lists (geosite, geoip) | `.srs` rule-sets, local files | `.srs` rule-sets, remote, auto-updating |
| Protocol sniffing (SNI, Host, QUIC, DNS) | SNI and Host, TCP only | yes |
| Per-app routing on Android | none | `package_name` |
| Outbound selection | round-robin, no health check | `urltest` by latency, `selector` |
| Per-connection statistics | global counters only | Clash API |
| Extra transports | WebSocket, H2MUX | + gRPC, HTTPUpgrade, HTTP/2 |
| Hysteria2 / TUIC as a *client* | yes | yes |

## Tier 1 — closes most of the gap

Ordered by value per unit of work. All three built on code already in the tree,
and all three are now done.

### 1. Rule-sets — done

Shipped. Spec: [docs/specs/2026-08-09-rule-sets.md](./docs/specs/2026-08-09-rule-sets.md).
Plan: [docs/plans/2026-08-09-rule-sets.md](./docs/plans/2026-08-09-rule-sets.md).

`masks` was a literal list. A rule as ordinary as "Russian domains direct,
everything else through the tunnel" needed tens of thousands of YAML lines, so
in practice nobody wrote it.

sing-box `.srs` files are now read directly, so the existing ecosystem of
compiled lists — geosite, geoip, antifilter, Loyalsoldier — works as-is, with no
list-building pipeline of our own. `src/rule_set/` decodes the container and
holds the succinct trie in its on-disk shape; `ConnectRule` consults a rule's
sets when its masks miss.

Local files only. Remote rule-sets with `update_interval` are deliberately
deferred — see the spec's scope section — as are `source_ip_cidr`, inline rules
and `type: logical`.

### 2. Protocol sniffing — done

Shipped. Spec: [docs/specs/2026-08-10-protocol-sniffing.md](./docs/specs/2026-08-10-protocol-sniffing.md).
Plan: [docs/plans/2026-08-10-protocol-sniffing.md](./docs/plans/2026-08-10-protocol-sniffing.md).

A destination domain used to be known only when Fake IP assigned it. An app with
a hardcoded DoH resolver, or one that dials a literal IP, defeats that — and
every domain rule silently degraded to IP matching, which hit the rule-sets from
item 1 hardest, since geosite lists are domains only.

`src/sniff/` now reads the TLS ClientHello and the HTTP/1.x request line from
the first bytes of a connection. The recovered name goes into
`ResolvedLocation.location` with the original address in `resolved_addr`, so
domain rules and rule-sets match the name while CIDR masks still match the real
address and a direct connection dials it without a DNS lookup. Opt-in per
listener with `sniff: true`, on both TCP inbounds and the TUN.

A QUIC sniffer, DNS sniffing, protocol-only sniffers (`bittorrent`, `ssh`,
`stun` and friends) and the `protocol` rule matcher they would serve are
deliberately deferred — see the spec's scope section. Overriding the destination
for direct connections is not planned: Xray had to bolt an exclusion list onto
it and sing-box has deprecated it.

### 3. Hysteria2 and TUIC client outbounds — done

Shipped. Spec: [docs/specs/2026-08-11-quic-client-outbounds.md](./docs/specs/2026-08-11-quic-client-outbounds.md).
Plan: [docs/plans/2026-08-11-quic-client-outbounds.md](./docs/plans/2026-08-11-quic-client-outbounds.md).

shoes could serve Hysteria2 and could not dial it. The framing and crypto were
already in the server modules, so the gap was the client-side plumbing, and
Hysteria2 in particular is now one of the most widely deployed protocols in the
commercial market.

Neither protocol fits the chain model, which builds an outbound from a socket
connector that yields a stream and proxy connectors that wrap one: both
authenticate once per QUIC connection and key their UDP sessions to it. They
are `TerminalConnector`s instead — the escape hatch AmneziaWG already used —
and are therefore always the only hop in a chain. `src/quic_outbound/` holds
what they share: endpoint construction from `quic_settings`, one connection per
outbound re-established lazily, and the obfuscation layer.

Both speak TCP and UDP. Salamander obfuscation works on the client and the
server. Every protocol path is tested against this repository's own server
running in-process, and the Hysteria2 client has been checked by hand against a
third-party sing-box server for TCP and UDP alike.

Two options are refused at config load rather than silently ignored, because a
user who asks for them and does not get them should be told: TUIC's
`zero_rtt_handshake`, and its `udp_relay_mode: quic`. The latter is blocked by
a defect on our own server side — see below. What else is missing is in
[Hysteria: the rest of the surface](#hysteria-the-rest-of-the-surface).

**Known defect, server side.** In TUIC's `quic` UDP relay mode our server
writes reply packets onto one unidirectional stream without the version and
command bytes that make a `Packet` a command, so what it sends is something its
own receiving side would reject. Fixing it means one stream per reply packet
with a full command header, which changes `UdpSession::start_with_send_stream`
and its caller. Until then the client refuses the mode by name.

## Tier 2 — worth doing after Tier 1

### 4. `urltest`: latency-based selection with health checks

A pool is plain round-robin with no liveness probe, so a dead node keeps taking
every Nth connection. Needs a background prober, shared state, and a new variant
in `src/config/types/selection.rs`. A mobile UI gets something to display as a
side effect.

### 5. Per-app routing on Android

`src/tun/traffic.rs` aside, there is no notion of which app a flow belongs to.
sing-box resolves uid to package name and matches on it.

This is entangled with a defect already recorded in
[MOBILE.md](./MOBILE.md): `protect_socket` has exactly one caller,
`src/amneziawg/tunnel.rs:82`. The general outbound path —
`socket_util::new_tcp_socket` and `new_udp_socket` — never consults the
protector, so any non-AmneziaWG `client_chain` opens its upstream socket inside
the tunnel it is meant to feed. A working Android setup today depends on
`Builder.addDisallowedApplication`, an app-side workaround this repository
neither requires nor documents. The leak needs fixing regardless; per-app routing
is its natural continuation.

### 6. Per-connection statistics

`src/tun/traffic.rs` keeps two global atomics and a callback. A client UI needs a
connection list: destination, protocol, the rule that matched, and bytes each
way. Either expose it over FFI, or implement a subset of the Clash API and
inherit the existing dashboards (yacd, metacubexd) for free.

### 7. HTTPUpgrade transport

WebSocket without the framing, and `src/websocket/` is already there. Small, and
required by a good share of CDN-fronted server configs.

### 8. DNS rules

`DnsConfigGroup` exists (`src/config/types/dns.rs:166`) but nothing selects a
group per rule, so split DNS cannot be expressed. Half the mechanism is built.

## Tier 3 — not urgent

- **Network-change handling.** A Wi-Fi to cellular switch leaves the AmneziaWG
  endpoint socket bound to a dead local address with no error path. Recorded in
  MOBILE.md. Closer to a bug than a feature, but it needs an interface-watch
  design to fix properly.
- **Cache file.** Fake IP mappings, rule-set downloads and the selected outbound
  do not survive a restart. On mobile, where the process is killed routinely,
  this is felt more than the effort suggests.
- **Multiplex interop** with sing-box's smux/yamux. H2MUX covers our own
  deployments; this is purely about talking to other implementations.

## Hysteria: the rest of the surface

Written against [apernet/hysteria](https://github.com/apernet/hysteria) at
`app/v2.12.1` (2026-08-09), read from `PROTOCOL.md` and the `serverConfig` and
`clientConfig` structs in `app/cmd/`.

Speaking the protocol is not the same as matching the implementation. This
section is the difference, so that "we support Hysteria2" is never claimed
wider than it is true.

### Interoperability — a server we cannot talk to

| Gap | Effect |
| --- | --- |
| **Gecko obfuscation** (`obfs.type: gecko`, upstream 2.9.2) | A server with it configured is unreachable. Experimental upstream, and it builds on Salamander's scrambling rather than replacing it, so it is an added framing layer rather than a second cipher. |
| **Port hopping** (`transport.udp.hopInterval`, `minHopInterval`, `maxHopInterval`) | Servers published as a port range expect the client to migrate between ports on a timer. Without it, only the single configured port works — and some deployments firewall all but the range. |
| **`Hysteria-CC-RX: "auto"`** | The protocol allows the literal string as well as an integer. A parser that assumes a number must not choke on it. Our client ignores the header entirely, which is compliant, but the ignoring has to be deliberate. |
| **Multiple users on our server** (`auth.type: userpass`, `http`, `command`) | `ServerProxyConfig::Hysteria2` takes one password. Upstream supports a user map, an HTTP callback and an external command. A client authenticating as `user:pass` works against us today only because we compare the whole string. |

### Performance — the reason people pick Hysteria

| Gap | Effect |
| --- | --- |
| **Brutal congestion control** and the bandwidth negotiation behind it (`bandwidth.up`/`down`, `Hysteria-CC-RX` in both directions) | This is the headline feature. Brutal sends at a declared rate instead of backing off on loss, which is why Hysteria is fast on lossy intercontinental paths. We send `Hysteria-CC-RX: 0` in both directions, which is the protocol's "use ordinary congestion control" signal, so throughput on a lossy path will be visibly below the official client's. Needs a `quinn` congestion controller. |
| **BBR profile** (`congestion.bbrProfile`: conservative/standard/aggressive) | Tuning knob on top of the fallback controller. |
| **`bandwidth.disableLossCompensation`** (upstream 2.10.0) | Only meaningful once Brutal exists. |
| **QUIC stateless resets** (upstream 2.12.1) | Server side. Without them a client holding a connection that died while the device slept waits out its idle timeout before reconnecting. Upstream called this out as most noticeable on mobile, which is this branch's entire audience. |
| **QUIC window and timeout tuning** (`quic.*`) | We hard-code the values the reference implementation uses. Exposing them is easy; whether it is worth the configuration surface is a separate question. |

### Detectability

| Gap | Effect |
| --- | --- |
| **Chrome QUIC fingerprint parroting** | Upstream since 2.11.0 and **on by default** there, with `quic.disableChromeParrot` to turn it off; sing-box followed. So the population a censor sees is moving to a Chrome-shaped handshake, and a default `quinn` client stands out more each release. This is the QUIC twin of the uTLS gap below, and closing it properly is a project rather than a backport. |
| **Masquerade** (`masquerade.type`: file/proxy/string) | Server side. The protocol requires a Hysteria server to behave like an ordinary HTTP/3 web server for anything that is not an auth request. Ours answers a bare 404 to everything, which is a constant response pattern — exactly what the specification warns active probers look for. |
| **ECH** (upstream 2.10.0) | Encrypts the ClientHello's SNI. Already listed under "explicitly not planned" for the TLS stack generally. |
| **mimic** (upstream 2.12.0) | Disguises the connection as TCP for networks that block UDP outright. Linux only, needs an XDP program and a separately installed binary. |

### Operational, server side

Not protocol, but part of what a Hysteria server is expected to do: **ACME**
certificate issuance, **SNI guard** (`tls.sniGuard`), **`speedTest`**, and
**Hysteria Realms** — the STUN and hole-punching rendezvous (upstream 2.9.0,
with UPnP/NAT-PMP in 2.9.3) that lets a server run behind NAT with no public
address.

### Deliberately not our problem

Upstream bundles a whole proxy application. Several of its configuration
sections have shoes equivalents that are broader, and copying them would be a
regression rather than a gain:

| Upstream | Ours |
| --- | --- |
| `acl` and `outbounds` | `rules`, `client_chains` and rule-sets |
| `sniff` | the `sniff` block, on every inbound and the TUN |
| `resolver` | the `dns` configuration |
| `socks5`, `http`, `tcpForwarding`, `udpForwarding`, `tcpTProxy`, `tcpRedirect`, `tun` on the client | server types in their own right, usable in front of any outbound |
| `trafficStats` | global counters today; per-connection statistics is Tier 2 item 6 |

One genuinely missing convenience: shoes cannot import a `hysteria2://` sharing
link. Every client in the ecosystem can, and it is how servers are distributed
in practice.

## Explicitly not planned

- **gRPC transport** — considerable work, and less used in practice than
  WebSocket.
- **ECH** — no demand behind it yet.
- **mKCP** — effectively dead.

## Open risk: TLS fingerprinting

Not a missing feature; a property of the stack.

Xray and sing-box both use uTLS to imitate a Chrome ClientHello. shoes goes
through rustls, whose handshake is fixed and quite recognisable. Where a DPI
classifies by TLS fingerprint, Reality protects us and a plain TLS client does
not.

There is no mature uTLS equivalent in Rust. Closing this would mean writing one,
which is a project rather than a backport, and it should be decided as such.

The same exposure now exists over QUIC, and it is getting worse rather than
staying still. Hysteria has parroted Chrome's QUIC handshake by default since
its 2.11.0, sing-box followed, and both pin transport parameters — idle timeout
and receive windows — as part of the imitation. Every release moves more of the
observable population toward one shape, which makes a default `quinn` client
easier to pick out by standing still. Our QUIC outbounds at least take their
transport parameters from the reference implementations rather than inventing
plausible-looking numbers, so we do not pay for a unique signature we never
chose; the handshake itself remains ours.
