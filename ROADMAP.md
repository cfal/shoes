# Roadmap

Where this fork stands against sing-box and Xray-core, and what is worth building
next. Written 2026-08-09 against `mobile` at `7ed9f0b`.

The audience is anyone deciding what to work on. Every gap below is stated with
the file it lands in, so the estimate is checkable rather than a guess.

## Table of Contents

- [Where we already compete](#where-we-already-compete)
- [Where we do not](#where-we-do-not)
- [Tier 1 — closes most of the gap](#tier-1--closes-most-of-the-gap)
- [Tier 2 — worth doing after Tier 1](#tier-2--worth-doing-after-tier-1)
- [Tier 3 — real, but not urgent](#tier-3--not-urgent)
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
| Hysteria2 / TUIC as a *client* | **absent** | yes |

That last row is the odd one. `src/hysteria2_server.rs` and `src/tuic_server.rs`
both exist, but neither protocol appears in `ClientProxyConfig`
(`src/config/types/client.rs:441`). shoes can serve Hysteria2 and cannot dial it.

## Tier 1 — closes most of the gap

Ordered by value per unit of work. All three build on code already in the tree.
Items 1 and 2 are done; 3 is open.

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

### 3. Hysteria2 and TUIC client outbounds

The framing and crypto exist in the server modules. Adding the two variants to
`ClientProxyConfig` and their client handlers is the largest gain in
real-world-server coverage per line written, and Hysteria2 in particular is now
one of the most widely deployed protocols in the commercial market.

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
