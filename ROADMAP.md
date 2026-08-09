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
| Domain/IP lists (geosite, geoip) | none | `.srs` rule-sets, remote, auto-updating |
| Protocol sniffing (SNI, Host, QUIC, DNS) | none | yes |
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

### 1. Rule-sets

`masks` is a literal list. A rule as ordinary as "Russian domains direct,
everything else through the tunnel" needs tens of thousands of YAML lines, so in
practice nobody writes it. This single gap is what makes the routing engine
unusable for a real client, and it blocks the value of everything else here.

sing-box's `.srs` container is documented and binary. Reading it directly means
the existing ecosystem of compiled lists — geosite, geoip, antifilter,
Loyalsoldier — works on day one, with no list-building pipeline of our own.

Lands in `src/client_proxy_selector.rs`: `ConnectRule` (line 114) gains a matcher
variant beyond `Vec<NetLocationMask>`, and `judge` (line 283) consults it. The
`RoutingCache` LRU already in that file absorbs the per-connection cost.

### 2. Protocol sniffing

Today a destination domain is known only when Fake IP assigned it. An app with a
hardcoded DoH resolver, or one that dials a literal IP, defeats that — and every
domain rule silently degrades to IP matching. Sniffing the TLS ClientHello and
the HTTP request line recovers the name on the connection itself.

Most of this is written. `read_client_hello`
(`src/shadow_tls/shadow_tls_server_handler.rs:360`) already returns
`requested_server_name` and already backs SNI routing for inbound TLS. The work
is wiring it into the TUN and outbound paths, not writing a parser.

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
