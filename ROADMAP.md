# Roadmap

Where this fork stands against sing-box and Xray-core, and what is worth building
next. Written 2026-08-09 against `mobile` at `7ed9f0b`; the Hysteria section was
added 2026-08-11 against `apernet/hysteria` at `app/v2.12.1`. Refreshed
2026-08-23 against `mobile` at `c83ce5f`, 128 commits later: the protocol lists
and the mieru section were re-checked against the tree, and every Tier 2 and
Tier 3 item was confirmed still open. Refreshed again 2026-08-24 against
`mobile` at `a27b666`, when the desktop control API landed and earned a section
of its own. Refreshed again 2026-08-25 against `mobile` at `30346aa`, when the
first two phases of Hysteria2 conformance landed — which corrected two claims in
the Hysteria section that had been wrong rather than merely stale.

The audience is anyone deciding what to work on. Every gap below is stated with
the file it lands in, so the estimate is checkable rather than a guess.

## Table of Contents

- [Where we already compete](#where-we-already-compete)
- [Where we do not](#where-we-do-not)
- [Tier 1 — closes most of the gap](#tier-1--closes-most-of-the-gap)
- [Tier 2 — worth doing after Tier 1](#tier-2--worth-doing-after-tier-1)
- [Tier 3 — real, but not urgent](#tier-3--not-urgent)
- [Desktop clients](#desktop-clients)
- [Hysteria: the rest of the surface](#hysteria-the-rest-of-the-surface)
- [mieru: what is left](#mieru-what-is-left)
- [Explicitly not planned](#explicitly-not-planned)
- [Open risk: TLS fingerprinting](#open-risk-tls-fingerprinting)

## Where we already compete

The protocol surface is close to parity with sing-box.

Server: HTTP, SOCKS5, Mixed, Shadowsocks (including 2022-blake3), VMess AEAD,
VLESS, Trojan, Snell v3, Hysteria2, TUIC v5, AnyTLS, NaiveProxy, port-forward,
TLS, WebSocket.

Client: Direct, HTTP, SOCKS5, Shadowsocks, Snell, VMess, VLESS, Trojan, AnyTLS,
NaiveProxy, Hysteria2, TUIC v5, mieru, WireGuard, AmneziaWG 2.0/3.0/3.1,
port-forward, plus TLS, Reality, ShadowTLS and WebSocket as wrapping layers.

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
| Per-connection statistics | global counters, plus a live connection count | Clash API |
| Extra transports | WebSocket, H2MUX | + gRPC, HTTPUpgrade, HTTP/2 |
| Hysteria2 / TUIC as a *client* | yes | yes |
| Desktop client | control API only, no GUI | full GUI on three platforms |

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

TUIC carries UDP in both relay modes. `native` uses QUIC datagrams; `quic` uses
one unidirectional stream per packet, which is what the reference implementation
does and what our server now does — it used to hold a single stream open for the
association and write bare packet bodies onto it, without the version and
command bytes that make a `Packet` a command, so what it sent was something its
own receiving side would have rejected.

One option is refused at config load rather than silently ignored, because a
user who asks for it and does not get it should be told: TUIC's
`zero_rtt_handshake`. What else is missing is in
[Hysteria: the rest of the surface](#hysteria-the-rest-of-the-surface).

## Tier 2 — worth doing after Tier 1

### 4. `urltest`: latency-based selection with health checks

A pool is plain round-robin with no liveness probe, so a dead node keeps taking
every Nth connection. Needs a background prober, shared state, and a new variant
in `src/config/types/selection.rs`. A mobile UI gets something to display as a
side effect.

### 5. Per-app routing on Android

`src/tun/traffic.rs` aside, there is no notion of which app a flow belongs to.
sing-box resolves uid to package name and matches on it.

The leak this used to be entangled with is fixed: every outbound socket is now
excluded from the VPN route, because `socket_util`'s constructors consult the
protector rather than each caller remembering to. See
[MOBILE.md](./MOBILE.md) §2. Per-app routing is the remaining half.

### 6. Per-connection statistics — partly done

`src/tun/traffic.rs` keeps two global atomics and a callback, and now a live
connection count beside them, readable through
`shoes::control::stats::snapshot()` behind the `control-stats` feature.

The rest is blocked on something small and unglamorous: **outbounds have no
names**. A client UI wants bytes per configured server, and the only key
available today is an address, which is neither stable across config edits nor
meaningful to show a user — client configs in `src/config/types/client.rs`
carry no label field. Adding one is a config schema change that reaches mobile,
so it wants its own spec, and everything else here waits behind it.

Beyond that: a connection list with destination, protocol, the rule that
matched, and bytes each way. Either over FFI, or as a subset of the Clash API,
which inherits the existing dashboards (yacd, metacubexd) for free.

### 7. HTTPUpgrade transport

WebSocket without the framing, and `src/websocket/` is already there. Small, and
required by a good share of CDN-fronted server configs.

### 8. DNS rules

`DnsConfigGroup` exists (`src/config/types/dns.rs:166`) but nothing selects a
group per rule, so split DNS cannot be expressed. Half the mechanism is built.

## Tier 3 — not urgent

- **Network-change handling — done.** A Wi-Fi to cellular switch used to leave
  the AmneziaWG endpoint socket bound to a dead local address with no error
  path: it went quiet rather than failing, and the only recovery was a
  stop-and-start that tore down the TUN interface. The endpoint socket is
  replaceable now (`src/amneziawg/endpoint.rs`), swapped under the tunnel tasks
  through a `watch` channel. Two things trigger a rebind: the app, through the
  `notify_network_change()` FFI call meant for `ConnectivityManager` and
  `NWPathMonitor`, and a send that fails with a route-is-gone error, so an app
  that never wires up the callback still recovers one failed send later. No new
  handshake is needed — WireGuard peers roam. See [MOBILE.md](./MOBILE.md) §3.
- **Address-family fallback, everywhere else.** A dual-stack host can publish
  an IPv6 address whose UDP replies never come back while its IPv4 works. The
  QUIC outbound used to take the first resolved address and stay there, which
  made the outbound look permanently dead with no error; it now walks the whole
  list (`src/quic_outbound/connection.rs`). Two things are left.

  The AmneziaWG endpoint has the same shape and the same silence:
  `src/amneziawg/connector.rs:142` resolves the tunnel's UDP peer to one
  address and never reconsiders.

  And pre-resolution quietly defeats the fallback that does exist.
  `SocketConnectorImpl` walks every address only when handed an *unresolved*
  location (`src/tcp/socket_connector_impl.rs:218`), so each caller that
  resolves to a literal first — `src/http_handler.rs:417`,
  `src/routing/udp_router.rs:1043`, `src/tuic/server.rs:535` and `:1000`,
  `src/anytls/anytls_server_handler.rs:202`,
  `src/vless/vless_server_handler.rs:84` — collapses the list to one behind its
  back. That is the more interesting half: the mechanism is there and is being
  switched off by accident.

  None of this is happy eyeballs. RFC 8305 racing would also remove the three
  seconds the QUIC fallback now spends discovering that the first address is a
  black hole, and that is a larger change than walking a list.
- **Cache file.** The Fake IP pool is a `Mutex<PoolState>` and nothing else
  (`src/dns/fake_ip/pool.rs`), so every mapping is lost on restart. On mobile,
  where the process is killed routinely, this is felt more than the effort
  suggests. Rule-set downloads and a remembered outbound selection would belong
  in the same file, but neither exists yet — see Tier 1 item 1 and Tier 2
  item 4.
- **Multiplex interop** with sing-box's smux/yamux. `MuxProtocol` names both
  (`src/h2mux/mod.rs:60`), but they are identifiers only: no framing behind
  them. H2MUX covers our own deployments; this is purely about talking to other
  implementations.

## Desktop clients

Linux, macOS and Windows, with one Tauri GUI across all three and native
platform integration underneath. Design in
`docs/specs/2026-08-24-desktop-control-api.md`, task breakdown in
`docs/plans/2026-08-24-desktop-control-api.md`.

Seven sub-projects. The first is merged; the other six are open, and the order
below is roughly the order they unblock each other.

### 1. Control API — done

`shoes::control` is the lifecycle that used to be locked inside
`src/ffi/common.rs`, compiled out on every non-mobile target. A privileged host
now gets `prepare_from_config` with a `DevicePolicy`, `start`, `status`,
`stats::snapshot`, a subscribable log sink, and a `stop` that reports whether
the device was released. Verified by building an external crate against it, not
by inspection.

Two facts worth carrying forward. `Status` has no `Starting` variant, because
nothing can produce one: `start` returns as soon as the task is spawned and the
stack offers no readiness signal, so a GUI that shows "connected" at that moment
is lying. Adding one is a change to `run_tun_from_config`, and it should land
before a tray icon does. And `ServiceHandle` must not be stopped or dropped from
async code — it owns a `Runtime`, and dropping a runtime inside another panics.

### 2. Windows TUN backend

The largest piece left, and the only one that makes a platform unusable by its
absence. `src/lib.rs` gates the TUN module on `cfg(unix)`, so on Windows
`run_prepared` returns `ErrorKind::Unsupported`: a Windows GUI would build,
start, show a tray icon and fail the moment someone clicks Connect. The library
itself does build on Windows — CI checks it now — so this is a backend, not a
port of the whole crate.

`src/tun/tcp_stack_direct.rs` runs smoltcp on a dedicated thread and waits on
the descriptor. Wintun has no descriptor; it is a ring-buffer session API, so
the work is a second backend behind the same interface, attaching at
`DevicePolicy::Owned`.

Upstream PR cfal/shoes#102 implements Windows TUN and is **not** worth adopting.
It converts the stack to `AsyncDevice` and `.await`, which deletes the
dedicated-thread design that `MOBILE.md`'s buffer and connection tuning rests
on, and it removes the `phy_wait_error_count` / `MAX_PHY_WAIT_ERRORS` guard at
`src/tun/tcp_stack_direct.rs:620` that stops a dead descriptor busy-looping a
core. It has been conflicting against upstream master since January, and our
`tun/` has diverged further than master has. Worth reading for which wintun
knobs matter; not worth cherry-picking.

### 3. macOS Network Extension provider

No new Rust. An NE provider on macOS is handed its descriptor by `packetFlow`
exactly as on iOS, and `TunServerConfig::raw_fd` plus the `macos` arm in
`src/tun/mod.rs:470` already consume it. All ten `shoes_*` symbols export on
`aarch64-apple-darwin`, and CI compares that list against `include/shoes.h`.

What remains is Swift and packaging: a provider target, the
`com.apple.developer.networking.networkextension` entitlement, and
post-processing the `.app` to embed the extension, which Tauri's bundler does
not do.

### 4. Privileged helper and IPC contract

One protocol, three genuinely different mechanisms — `SMAppService` on macOS, a
service running as SYSTEM on Windows, systemd with polkit on Linux. The GUI must
have no platform branches, which means it asks the helper what it can do rather
than inferring it from the OS.

This is where **host network configuration** lives, and shoes deliberately does
not do it: nothing in `src/` touches routes, `resolv.conf`, systemd-resolved or
`netsh`. shoes moves packets; the host owns the network. On Linux that is the
awkward part — systemd-resolved, resolvconf, NetworkManager and a bare
`/etc/resolv.conf` are four different mechanisms, and without one of them a TUN
device exists that no traffic is routed into.

### 5. The Tauri GUI

Tray, popover, dashboard, config editor. Can be built against a mocked helper in
parallel with #2 and #4. Config validation needs none of that plumbing:
`shoes::config::load_config_str` and `create_server_configs` are public and give
the editor real parse and semantic errors from the same code that will run the
connection.

Known rough edge on Linux: the tray goes through StatusNotifierItem, which works
on KDE and needs a user-installed extension on stock GNOME.

### 6. Packaging, signing, notarization, updater

Signed DMG, MSI and NSIS, deb and AppImage, plus a signed updater feed.

### 7. Share-link import

`vless://`, `ss://`, `hysteria2://` and friends. Nothing in `src/` parses one
today — the only mention in the tree is a doc comment at
`src/config/types/client.rs:238`. A parser per protocol, mapping query
parameters onto the config types. Belongs in the GUI repository rather than
here: no mobile caller wants it, and it would cost mobile bytes for no mobile
benefit.

## Hysteria: the rest of the surface

Written against [apernet/hysteria](https://github.com/apernet/hysteria) at
`app/v2.12.1` (2026-08-09), read from `PROTOCOL.md` and the `serverConfig` and
`clientConfig` structs in `app/cmd/`.

Speaking the protocol is not the same as matching the implementation. This
section is the difference, so that "we support Hysteria2" is never claimed
wider than it is true.

### Conformance with the reference — phases 1 and 2 done

A review that read the Go source of
[HyNetworks/hysteria](https://github.com/HyNetworks/hysteria) at `619a6f8`
found fifteen divergences across 5500 lines of our Hysteria2 code. Design:
[docs/superpowers/specs/2026-08-24-hysteria2-conformance-design.md](./docs/superpowers/specs/2026-08-24-hysteria2-conformance-design.md).

**Phase 1 — the ones that made a real peer fail — done.** An IPv6 target went
on the wire unbracketed, so `2001:db8::1` port 443 became `2001:db8::1:443` and
Go's `net.SplitHostPort` refused it outright. Concurrent UDP sessions each ran
their own reader on the shared connection and dropped what was not theirs, so
with two sessions each won about half the datagrams; one demultiplexer per
connection routes by session id now. The server answered success before it
dialled, so a refused target reached the client as a connection that succeeded
and immediately closed with no diagnosis. And it sent `Hysteria-CC-RX: 0`,
which the protocol defines as "no limit, transmit at any rate" — not the
"run your own congestion control" signal it was taken for — so an official
client configured with `up: 200 mbps` switched to fixed-rate Brutal against a
server running ordinary congestion control.

One of the five has no fix available here and is documented rather than closed:
our server cannot carry UDP to a peer that omits `max_datagram_frame_size`,
because quinn refuses to send a datagram to such a peer and has no equivalent of
upstream's `AssumePeerMaxDatagramFrameSize`. An official client does this only
with `disableChromeParrot: true`, so a stock client is unaffected. It names the
cause in the operator's log now instead of silently never replying.

**Phase 2 — robustness — done.** A UDP session tracked up to 256 incomplete
packets of up to 255 fragments each — about 78 MB — and opening sessions cost a
peer nothing; holding one packet id in flight, as upstream does, caps it at
roughly 300 KB. A session whose send failed was dropped from the map without its
reply task being cancelled, leaving a socket and a parked task for the life of
the connection. Idle sessions were swept only when another datagram happened to
arrive, so a client that went quiet kept everything it had opened. And an
`assert!` on two peer-chosen values sat on the reply path beside a fragment
count that truncated to a byte.

**Phase 3 is a decision, not a repair, and it is open.** Auth and request
padding sizes, connection ID length, stream limits and the masquerade body are
all places where we differ from the Go client — some deliberately, some not —
and choosing means answering one question first: *are we imitating that client,
or merely interoperating with it?* The tables below are what phase 3 would draw
from. Structural work waits behind the same decision: the server keeps a second
datagram encoder beside `frame.rs`, and two encoders for one wire format is
exactly the arrangement that produced this list.

Which is the part worth carrying away. In almost every case **our encoder and
our decoder shared a misreading, so every test passed** — the same shape that
produced nine defects in mieru and then eight more. Reading the reference found
each one. A live run against the official client then disproved one of the
findings as written, which no test of ours could have done, because the claim
was about a peer we do not control.

### Interoperability — a server we cannot talk to

| Gap | Effect |
| --- | --- |
| **Gecko obfuscation** (`obfs.type: gecko`, upstream 2.9.2) | A server with it configured is unreachable. Experimental upstream, and it builds on Salamander's scrambling rather than replacing it, so it is an added framing layer rather than a second cipher. |
| **`Hysteria-CC-RX: "auto"`, on the client** | The protocol allows the literal string as well as an integer. Our *server* sends `auto` now — see the conformance section above — but our client still ignores the header it receives. That is compliant only for as long as we install no congestion controller of our own, and becomes a real gap the day Brutal lands. |
| **Multiple users on our server** (`auth.type: userpass`, `http`, `command`) | `ServerProxyConfig::Hysteria2` takes one password. Upstream supports a user map, an HTTP callback and an external command. A client authenticating as `user:pass` works against us today only because we compare the whole string. |

**Port hopping — done, client side.** A server published as a port range is
reachable now. `src/quic_transport/hop.rs` binds a fresh UDP socket on a timer
and rotates the destination across the configured union, reporting one constant
address to QUIC so the connection never sees a path change. The local port
moves with it, which is the half that stops the 4-tuple being a handle for a
middlebox — rotating only the destination would have looked like the feature
while leaving the flow linkable. Spec:
[docs/superpowers/specs/2026-08-23-hysteria2-port-hopping-design.md](./docs/superpowers/specs/2026-08-23-hysteria2-port-hopping-design.md).

It is covered by an in-process bank of UDP relays standing in for an iptables
REDIRECT, which asserts that more than one port was used at each end rather
than only that the transfer succeeded.

It has also been run by hand against a real third-party Hysteria2 server on a
VPS, over the internet, with Salamander obfuscation. A local relay bank
supplied the port range, so what this proves is the client half: across a
90-second stream the client used all six destination ports and forty-two
distinct local ports, twenty consecutive requests returned 200, a 20 MB
download hashed identically to the same file fetched directly, DNS went
through the socks5 UDP associate, and no hop failed. What it does not prove is
a server natively published on a range: upstream supports
`listen: :20000-50000` on Linux and programs the firewall rules itself, ours
still listens on a single port, and the server in that run saw one port and
several source addresses rather than a range.

That run also turned up something unrelated to hopping: the same server
reached by hostname hung, because the name resolved to an IPv6 address whose
UDP replies never came back and the outbound never tried the working IPv4 one.
That is fixed, and what is left of it is the Tier 3 entry on address-family
fallback.

### Performance — the reason people pick Hysteria

| Gap | Effect |
| --- | --- |
| **Brutal congestion control** and the bandwidth negotiation behind it (`bandwidth.up`/`down`, `Hysteria-CC-RX` in both directions) | This is the headline feature. Brutal sends at a declared rate instead of backing off on loss, which is why Hysteria is fast on lossy intercontinental paths. Our server answers `auto` (`server.rs:176`), the value for a server that declines to set a rate, and our client declares `0` (`auth.rs:35`), meaning it does not know its own receive rate. Neither end installs Brutal either way, so throughput on a lossy path stays visibly below the official client's. Needs a `quinn` congestion controller. This row said we sent `0` in both directions and called `0` the "use ordinary congestion control" signal; both halves were wrong, and the second was the defect phase 1 fixed. |
| **BBR profile** (`congestion.bbrProfile`: conservative/standard/aggressive) | Tuning knob on top of the fallback controller. |
| **`bandwidth.disableLossCompensation`** (upstream 2.10.0) | Only meaningful once Brutal exists. |
| **QUIC stateless resets** (upstream 2.12.1) | Server side. Without them a client holding a connection that died while the device slept waits out its idle timeout before reconnecting. Upstream called this out as most noticeable on mobile, which is this branch's entire audience. |
| **QUIC window and timeout tuning** (`quic.*`) | We hard-code the values the reference implementation uses. Exposing them is easy; whether it is worth the configuration surface is a separate question. |
| **Salamander's overhead is not deducted from the MTU** | `quic_transport::effective_mtu` subtracts the obfuscator's 8 bytes, but `quinn` clamps both `initial_mtu` and `min_mtu` with `.max(1200)` — 1200 being QUIC's own floor — so the subtraction has no effect. An obfuscated packet is therefore 1208 bytes on the wire, and a path that honours exactly 1200 will drop or fragment it. `quinn` exposes no way to send QUIC packets under the floor, so closing this means shrinking the payload some other way or carrying a patched transport. The code says this where the subtraction happens. |

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

## mieru: what is left

The client outbound is verified against a real mieru server — a routebox
deployment on a VPS, TCP transport, one user, traffic pattern off. Two runs,
the second after the review fixes below:

- **Bulk, both directions.** 10 MB down and 20 MB up, at 6–10 MB/s. The
  10 MB download hashes byte for byte against the same file fetched
  directly, so the multi-segment path neither drops nor reorders.
- **Concurrency.** Eight simultaneous sessions, 4 MB in total, in 0.35 s.
- **A long session.** A server-sent-events stream held for 185 s: 8.7 MB,
  5656 events, no break, the last event intact.
- **Idle.** A keep-alive connection reused after 45 s and after 90 s of
  silence. mieru has no keepalive of its own over TCP, so this is the case
  that would fail first.
- **UDP.** DNS through the socks5 UDP associate, ten queries down one
  association, each reply matching its transaction id; and TCP on a fresh
  connection immediately after.
- **Address families.** An IPv6 destination through the tunnel, and the
  server reached over both its IPv4 and its IPv6 address.

A wrong password is reported as `the mieru server closed the connection
before answering the session request` — but only after about 44 seconds.
That is the server, not us: probed with random bytes it holds the
connection open, silent, for roughly 42 s before closing, which is mieru's
defence against active probing. A client-side timeout shorter than that
turns a clear refusal into what looks like a hang.

Those runs are what the tests could not give. They exercise the client against
a scripted peer built from this repository's own codec, and that construction
cannot detect a shared misreading of the specification — encode a field
wrongly, decode it wrongly to match, and every test passes. A code review
that read the Go implementation found nine defects while all of them were
green, four of which broke the protocol outright. A second review, after the
first live run, found eight more: the entropy padding was filling with the wrong
bit and so emitted a near-constant byte run, the segment encoders fell back
to a zero timestamp that a peer rejects, the handshake accepted a response
for someone else's session, and a UDP datagram spanning segments was refused
outright. Reading the reference is what found each of those; the live run is
the check that neither tests nor review can substitute for.

What is still worth doing, in order:

- **A `mita` run in CI.** The verification above was manual and is not
  repeated on any commit, so the next protocol change is unguarded. This
  needs a Go toolchain in the workflow and a server process to manage.
- **A mieru server here.** It would turn the scripted peer into a real
  interoperability test, the way the Hysteria2 and TUIC servers do for their
  clients, and cost roughly a third more work than the client did.
- **Read the reference for the remaining codecs.** Only the UDP encapsulation
  has been compared line by line against upstream
  (`apis/common/packet_over_stream.go`). The segment codec, the metadata
  offsets and the key derivation now have a working handshake behind them,
  which is strong evidence but not the same thing.

Unimplemented, and refused in configuration rather than ignored: mieru's UDP
transport, session multiplexing, the low entropy encoding, port ranges, the
0-RTT handshake mode, and configurable traffic patterns. Only the first two
can make a server unreachable, and both are deployment choices. The
traffic-pattern options are the ones that matter for the protocol's purpose:
this client reproduces the default Go client's padding behaviour, so a
deployment using a customised pattern would look different on the wire.

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
