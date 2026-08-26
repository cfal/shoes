# Changelog

## Unreleased

### Named outbounds

An outbound can carry a `name`, and with the `control-stats` feature
`control::stats::snapshot()` reports upload, download and active-connection
counts against it. An outbound without a name is keyed by its address, so
existing configs get the same figures under a less friendly label; a `direct`
outbound is keyed `direct`, since its address is unspecified and would
otherwise collide with every other direct outbound.

Bytes are credited to the **exit** hop of a chain rather than to the relay the
socket actually opens, because the exit is the server a person means. Two
outbounds sharing a name but not an address are rejected at config load, on
every build, and `direct` is reserved.

A ShadowTLS remote handshake chain and a REALITY `dest_client_chain` are now
expanded during validation like every other chain. They were not, which meant
a group reference in either one panicked when the server started; now it
resolves, and their outbounds are counted rather than silently dropped.

### Hysteria2 port hopping

The client can rotate its UDP port across a published range, which is what a
Hysteria2 server behind an `iptables REDIRECT` range expects. Configured as
`port_hopping: { ports, interval_ms }`; the local port moves with the remote
one, so the whole 4-tuple changes rather than half of it.

Verified against a real deployment behind an `iptables REDIRECT` rule: over
seven hops the server saw eight distinct client source ports and traffic to
every published port, with no request lost. A UDP association survives a hop
too, though a datagram sent as one happens can be lost — QUIC datagrams are not
retransmitted, and the new path has to be validated before the peer will use it.

A QUIC outbound also walks every resolved address instead of only the first. A
dual-stack host whose IPv6 is published but whose return UDP never arrives used
to look permanently dead; each address now gets a bounded attempt before the
next is tried, with the last one left unbounded so a single-address outbound
behaves exactly as it did.

### Hysteria2 conformance with the reference implementation

Four divergences that made a real Hysteria2 peer fail against us, found by
reading the Go source rather than by any test — in every case our encoder and
our decoder shared the misreading, so both ends agreed and nothing failed.

- **An IPv6 target now works.** We put `2001:db8::1:443` on the wire, which Go's
  `net.SplitHostPort` rejects outright. Addresses leaving the process are now
  bracketed per RFC 3986. `Display` is unchanged: it is what logs and errors use
  throughout the tree.
- **Concurrent UDP sessions no longer lose each other's traffic.** Every session
  ran its own datagram reader on the shared connection and discarded what was
  not its own; with two sessions the second could receive nothing at all. One
  demultiplexer per connection now routes by session id, as upstream does.
- **A failed dial now says why.** The server answered "OK" before it had dialled
  anything, so a refused target reached the client as a connection that
  succeeded and immediately closed with no diagnosis. The response now waits for
  the dial and carries the outcome, with `Connected` on success.
- **`Hysteria-CC-RX: auto` instead of `0`.** `0` means "no limit, send as fast as
  you like", which made an official client switch to fixed-rate Brutal
  congestion control against a server running ordinary congestion control.

One known limitation remains: our server cannot send UDP to a peer that omits
`max_datagram_frame_size`, because quinn refuses to send datagrams to such a
peer and has no equivalent of upstream's `AssumePeerMaxDatagramFrameSize`. An
official Hysteria2 client does this only with `disableChromeParrot: true` — its
Chrome parroting otherwise forces the parameter to be advertised — so a stock
client's UDP works. Such a peer now produces a log line naming the cause instead
of a session that silently never answers.

All four fixes were verified against a real Hysteria2 server, and the two
server-side ones against the official client built from upstream: an IPv6 target
that the reference implementation used to dial as port 0, two simultaneous UDP
associations that previously lost most of their answers, a failed dial whose
reason now reaches the official client, and a client that honours `auto` by
ignoring its own configured bandwidth.

Four robustness fixes in the same UDP path followed, none of which changes
anything on the wire.

- **A UDP session can no longer be made to hold about 78 MB.** It tracked up to
  256 incomplete packets of up to 255 fragments each, and a peer that sends
  every fragment of every packet but one fills that. Upstream keeps one packet
  id in flight and discards it the moment another arrives, which caps the same
  attack at roughly 300 KB. Both of our ends changed, and the one that matters
  most is the phone.
- **A session whose send fails no longer leaks its socket and its task.**
  Removing it from the map left its reply loop parked on `recv_from` for the
  rest of the connection; the idle sweep did it correctly, so there were two
  removal paths and one of them was wrong. Cancelling when the session is
  dropped makes them the same by construction.
- **Idle sessions are reaped on a timer.** The sweep ran only when another
  datagram happened to arrive, so a client that went quiet kept every session it
  had opened — each with a socket and a task — until the connection ended.
- **An unsendable reply is now an error rather than a panic or a corrupt one.**
  The size check was an `assert!` on two values the peer chooses, so a peer
  could abort the process; and a payload needing more than the 255 fragments the
  protocol counts had its count truncated, telling the receiver to expect a
  handful and then sending it fragment ids past that count. Both now return an
  error naming the sizes.

TUIC shares the same connection machinery and has the same one-reader-per-
session defect. It is untouched here and remains to be fixed.

### HTTPUpgrade transport

WebSocket's HTTP handshake without WebSocket's framing, on the server and the
client, compatible with sing-box's `httpupgrade`. A `GET` carrying
`Connection: Upgrade`, a `101`, and raw bytes after that -- no masking and no
frame header on every write, which is what a proxy pays WebSocket for and gets
nothing back for. Configured as `type: httpupgrade` on either side; see
CONFIG.md.

Read from the reference implementation rather than from its documentation,
which is where the two rules that decide interoperability live. A real
WebSocket handshake is *refused* rather than served: our client never sends
`Sec-WebSocket-Key` and our server answers `404` to a request carrying one,
because a framed peer would read the unframed bytes that follow as garbage. And
bytes arriving in the same packet as the header block are the tunnel's first
payload; there is no stream wrapper here to hold them, so they go in front of
the connection instead. Both rules are pinned by tests watched failing with the
fix removed.

One deviation, deliberate: sing-box answers `400` for a Host mismatch and `404`
for everything else, while `Host` here is an ordinary entry in
`matching_headers` and indistinguishable at the point of refusal, so every
mismatch is `404`. No client can tell -- sing-box's own inspects nothing but the
`101` and the two headers.

Not implemented: Xray's `ed` early data, which hands back a stream before its
response has been read and so does not fit `setup_client_tcp_stream`'s
contract, and Xray's browser-shaped default headers.

Verified against a real sing-box, release 1.13.19, in both directions with
VMess inside the tunnel. Our client through their server and their client
through our server each fetched a page and then 10 MB in each direction — a
download and a `POST` body — with every transfer hashing byte for byte against
the same content fetched directly, so nothing was dropped, duplicated or
reordered across segment boundaries.

The two refusal cases were checked against that client rather than against our
own: sing-box asking for a path we do not serve got `unexpected status: 404 Not
Found` while our log named the path that missed, and sing-box configured with
`type: ws` — a genuine WebSocket handshake — was refused with the same `404`,
our log reading `real websocket request received`. That is the rule the whole
design turns on, and it now holds against a peer we do not control.

Not covered by that run: TLS in front of the transport, a CDN between the ends,
and a `Host` mismatch, since sing-box only enforces `host` when its own
configuration names one.

### AmneziaWG 3.1 carries traffic

The awgtun pin moves to the fixes it made after v0.9.0. Three of them are on a
path shoes uses, and all three were found against a live AmneziaWG 3.1 server:

- **A data packet is no longer misparsed as a handshake.** 3.1 relaxes the three
  handshake size tests from `==` to `>`, since a random trailer makes the
  datagram longer than the message, and those tests ran before the transport
  one. All that separated a full-size data packet from a handshake was a type
  field read over ciphertext, so uniformly random: with the ranges Amnezia's own
  generator emits, ~3.5% of received packets were dropped. Classification now
  tries transport first.
- **We stop sending packets a 3.1 peer will drop for the same reason.** Its
  receive path is not ours to fix, but the value it reads is masked by a
  keystream derived from our S4 prefix, so the prefix is redrawn until all three
  candidates miss. Upstream measured 0.17 MB/s to 12.55 MB/s on the affected
  direction.
- **A real `I1` chain is accepted.** The `<r>` length cap was an invented 1000
  bytes; production chains pad the initiation to the size of a TLS record and
  were rejected at config load, so the tunnel never sent a packet. The bound is
  now the largest UDP datagram, which is the only one amneziawg-go has.

Nothing in shoes changes; the pin move is the whole diff. A 2.0 tunnel is
untouched, and a 3.0 one keeps its wire format: the relaxed size tests apply
only with random trailers on, so a 3.0 sender redraws its prefix only for the
much rarer case of a transport datagram whose length equals a handshake
message's — a collision the reference classifier would have misparsed too, and
one the prefix being random already made arbitrary.

## v0.2.12

### Synced with upstream

`cfal/shoes` moved seven commits ahead; this branch is rebased onto them. Most
land on the server side and change nothing a mobile client does, but two touch
code this branch had also rewritten, and those needed a decision rather than a
merge:

- **The resolver cache holds a list, not an address.** Upstream bounded both
  resolver caches and reduced `ResolverCache` to a single pending lookup; this
  branch had separately made `CachingNativeResolver` cache every resolved
  address, so a cache hit still feeds the per-address connect fallback. Both
  changes are kept: the cache is bounded *and* holds the full list.
- **Sniffing survives multiple bind addresses.** Upstream let a server config
  bind several addresses, sharing one protocol handler per IP; this branch had
  threaded the sniff settings into `run_tcp_server`. The sniff settings are now
  cloned per spawned listener inside the new per-address loop.

Also arriving from upstream: a bound on the REALITY client handshake plaintext,
pending ciphertext counted against the REALITY outgoing limit, and a `WriteZero`
error instead of a silent success on a zero-byte TLS direct write. The AGP 9.0
Android migration that landed upstream as #136 is this fork's own change coming
back the other way.

### mieru client outbound

A new protocol, client side only. XChaCha20-Poly1305 with a 24-byte nonce; the
key derived from the password, the username and the current time rounded to two
minutes; an implicit nonce sent once per direction and then incremented; three
metadata formats; both of upstream's padding strategies. socks5 rides inside
the session, and UDP is framed inside that.

No ARQ: over the TCP transport upstream makes ACK handling a no-op, because TCP
already orders and retransmits.

Verified against a real mieru server over the internet — bulk transfer in both
directions with a byte-exact hash against a direct fetch, eight concurrent
sessions, a three-minute stream, idle keep-alive reuse, DNS through the socks5
UDP associate, and both address families. That run mattered: the tests exercise
the client against a scripted peer built from this repository's own codec, and
two reviews reading the Go implementation found seventeen defects while every
one of those tests was green.

Refused at config load rather than silently ignored: mieru's UDP transport,
session multiplexing, the low-entropy encoding, port ranges, the 0-RTT
handshake mode, and configurable traffic patterns.

### Fixes

- **Bracketed IPv6 addresses are parsed.** `[2001:db8::1]:443` — the form RFC
  3986 defines and the form HTTP clients send — was classified as a hostname
  and handed to the resolver, which answered "Name or service not known". An
  IPv6 outbound was unreachable and the message said nothing about why. The
  same defect made the HTTP inbound refuse `CONNECT [2001:db8::1]:443`, since
  it split the authority on the first colon.
- **`set_log_level` says when a level is compiled out.** Release builds compile
  out `debug!` and `trace!`, so raising the level through the mobile FFI did
  nothing and said nothing. The host cannot see stderr, so the warning now goes
  through the log pipeline it is already reading.

## Earlier work that was never written up

This file starts at v0.2.5 and describes v0.2.9 onward in detail, but a body of
work that landed before v0.2.9 never got an entry. Listed here so the omission
is visible rather than silent. [ROADMAP.md](./ROADMAP.md) carries the detail
and the scope decisions for each.

- **Rule-sets.** sing-box `.srs` files are read directly — the succinct trie in
  its on-disk shape, IP range sets, headless matching — so the existing
  ecosystem of compiled lists works as-is. Before this, a rule as ordinary as
  "Russian domains direct, everything else tunnelled" needed tens of thousands
  of YAML lines. Local files only.
- **Protocol sniffing.** The TLS ClientHello and the HTTP/1.x request line are
  read from the first bytes of a connection, so domain rules keep working for
  an app with a hardcoded DoH resolver or one that dials a literal IP. Opt-in
  per listener.
- **Hysteria2 and TUIC v5 client outbounds.** The servers existed; dialling
  somebody else's did not. Both own their transport and are therefore terminal
  in a chain. Both carry TCP and UDP, TUIC in both relay modes.
- **Salamander obfuscation**, on the client and on our Hysteria2 server.
- **Vanilla WireGuard and AmneziaWG 2.0 and 3.0**, with the tunnel runtime and
  its virtual network stack. 3.1 arrived later and is described under v0.2.11.
- **Fake IP** in TUN mode.
- **The iOS and Android FFI**: start, stop, traffic statistics and last-error
  reporting, made to behave on a phone rather than only in tests.

## v0.2.11

### AmneziaWG 3.1

The two parameters awgtun gained in v0.9.0 are configurable now. Both default
to off, so a 2.0 or 3.0 tunnel is byte-identical on the wire to what it was
before this change, and each generation stays opt-in on top of the last — a
2.0 config may adopt a 3.1 parameter without adopting anything from 3.0.

- `random_trailers` appends a random number of bytes to each datagram, so a
  message with a fixed size stops having one. **Both peers must enable it.** A
  receiver only tolerates bytes past the end of a handshake message when it is
  on, so one-sided it breaks the handshake in the direction that grew — and
  breaks it the same silent way every other wire-shaping mismatch does. Pinned
  by a test that feeds a trailered initiation to a 3.0 peer.
- **A one-sided `random_trailers` recovers by itself.** The setting is not on
  the wire and a disagreeing peer does not answer, so there is nothing to ask:
  a tunnel that was given packets to send and has still not handshaked after
  15 seconds rebuilds with the setting flipped, and alternates until one works.
  Whichever setting handshakes is the one it keeps — a `Tunn` that has
  handshaked is never flipped, so an established tunnel that later goes idle is
  never disturbed. Each flip is logged at warning level and names the setting
  to correct. A misconfiguration costs a delay instead of an outage.
- `disable_cookies` withholds the cookie reply. The rate limiter still decides
  a cookie is warranted, so a peer under load gets silence rather than a retry
  hint. This changes only what we send, so the two ends need not agree.
- A trailer's length is drawn from a high-water mark of datagram sizes seen on
  the path, which stops describing anything once the path changes. The endpoint
  rebind — the mobile network-change recovery — now resets it, the way
  upstream's `Device` does on a peer roam. awgtun leaves this to the caller
  because `Tunn` has no endpoint of its own.

## v0.2.10

Security and packaging. No protocol changes; a server deployment is affected
only by the REALITY logging fix.

### Security

- REALITY logged key material at debug level: the TLS traffic secret and the
  key and IV derived from it on every derivation, the authentication key on
  every client handshake, and the peer's short_id on the server — which also
  appeared in the rejection error text. Debug logging is switchable at runtime
  and MOBILE.md tells users a log file is safe to hand to support; with these
  lines it was a transcript-decryption kit. All of it is gone. What remains
  logged is lengths, cipher-suite parameters and outcomes, and a rejected
  short_id is no longer echoed anywhere — it may be a valid credential for a
  different deployment.
- The crate's only `unsafe` block is gone. `allocate_vec` handed out
  uninitialized memory as initialized bytes — formally undefined behaviour.
  Buffers are zeroed now, which costs nothing that matters: large allocations
  arrive as lazy zero pages, the same mechanism the resident-memory numbers
  already relied on.

### The tunnel library is now awgtun

- The boringtun fork became its own project. shoes follows it through v0.8.0
  — AmneziaWG 3.1 in the library (random trailers, cookie suppression), not
  yet exposed in shoes configuration — to v0.9.0, which split the C/JNI
  exports into a separate crate at shoes' request: Rust consumers no longer
  build artifacts they discard, and nothing foreign lands in the Android AAR
  to begin with. The delete step and the CI check on the AAR remain as guards.
- The dependency is pinned to a release tag now rather than a moving branch.

### Packaging

- The Android AAR carries an `x86_64` slice, so the stock emulator can load
  the library at all; previously `System.loadLibrary` failed at startup on any
  non-ARM image. Verified in CI by the AAR content check.
- Intel macOS binaries are no longer published; nothing deploys there.

### Dependencies

- Everything on the latest released versions as of this release, and
  `cargo audit` is clean: 333 crates against 1225 advisories, nothing flagged.
- `digest` is pinned to its major (`"0.11"`). The wildcard requirement let a
  routine re-resolution flip it to 0.10, whose `XofReader` trait does not match
  the one `shake` implements — caught when it broke this release's build.

Note for the app side: `shoes_get_version()` and `ShoesNative.getVersion()`
now report 0.2.10.


## v0.2.9

Mobile integration work. Everything below is on the client side; a server
deployment is unaffected except for the dependency update.

### Fixes

#### The TUN stack and the app's file descriptor
- The stack closed the TUN descriptor even when told not to. `close_fd_on_drop`
  was only honoured on the path that creates the device, so every Android and
  iOS start had the library closing a descriptor the app owns — a double close
  once the app closed its own, which in a process opening sockets constantly
  means closing whichever socket has taken the number since.
- Shutting down a quiet tunnel could block indefinitely. The stack thread sleeps
  in a syscall that `unpark` does not interrupt, so `stop` waited for a packet
  that might never arrive. There is a wake pipe now, and the sleep is bounded.
- The wait uses `poll()` rather than `select()`, whose `fd_set` cannot hold a
  descriptor numbered above `FD_SETSIZE`.

#### AmneziaWG across a network change
- The endpoint socket is rebindable. A UDP socket bound to an address that no
  longer exists does not report an error — it goes silent — so leaving Wi-Fi
  used to mean stopping and starting the whole tunnel.
- `networkChanged()` / `shoes_network_changed()` let the app report the change
  from `ConnectivityManager.NetworkCallback` or `NWPathMonitor`. A send that
  fails with a route error also triggers a rebind on its own, so an app that
  never wires the callback still recovers.

#### FFI
- `start` validates the config on the calling thread, so a `-1` is a real
  verdict with `getLastError()` behind it rather than a failure the app has to
  discover by polling `isRunning()`.
- `stop` no longer blocks on dropping the runtime, and polls at 5 ms rather than
  100 ms. It still waits for the stack thread to release the TUN descriptor,
  which is what makes it safe for the app to close its own copy afterwards.
- `stop` clears the socket protector, which on Android held a JNI global
  reference keeping a destroyed `VpnService` and its `Context` alive.
- `setLogLevel()` / `shoes_set_log_level()` change the level of a running
  library, so debug logs no longer need an app restart.
- The traffic callback reports once per session start and then only when a
  counter moved, instead of crossing into the JVM or Swift once a second on an
  idle tunnel.

### Memory

- Per-connection buffering is configurable (`tcp_buffer_size`,
  `max_connections`) and sized by platform. A connection through the TUN and
  AmneziaWG stacks costs 704 KiB rather than 2.3 MB.
- Buffers that face the network keep their size. Cutting the AmneziaWG socket
  buffers to the size of a local buffer measured as a 6x throughput loss, since
  those are a receive window rather than local buffering; `src/buffer_sizing.rs`
  documents the distinction and the measurement.
- The AmneziaWG data path and the TUN write path no longer allocate per packet.
- Stopping a tunnel drops the read path's buffer pool and asks the allocator to
  release what it is holding.

### Security

- `h2` updated to 0.4.16 for RUSTSEC-2026-0258 (unbounded empty DATA frames).

## v0.2.7

### Improvements

#### H2MUX Stability
- Added connection-level activity tracking that counts HTTP/2 control frames (PING, SETTINGS) as activity, ensuring keepalives properly reset idle detection
- Removed application-level idle timeout in favor of PING-based dead connection detection, matching sing-mux behavior for better compatibility
- Added drain timeout for graceful session shutdown
- Updated window sizes to match Go http2 defaults (256KB per stream, 1MB per connection)

#### AnyTLS Memory Leak Fixes
- Stream handler tasks are now tracked and aborted when session closes, preventing memory leaks from orphaned tasks
- Added 5-minute stream handler timeout to prevent hung streams (slow DNS, stuck connections) from leaking memory
- Reduced allocations in padding frame generation

#### TUN Connection Tracking
- Refactored TCP connection state machine with explicit states (Normal, Close, Closing, Closed) for proper lifecycle management
- Improved connection teardown handling following shadowsocks-rust patterns

## v0.2.6

### New Features

#### H2MUX (sing-box Compatible HTTP/2 Multiplexing)

H2MUX multiplexes multiple proxy streams over a single HTTP/2 connection, reducing connection overhead and improving performance for many concurrent streams. This is compatible with sing-box's h2mux implementation.

**Client configuration (VMess, VLESS, Trojan):**
```yaml
client_chain:
  address: "example.com:443"
  protocol:
    type: tls
    protocol:
      type: vmess
      cipher: aes-128-gcm
      user_id: "uuid"
      h2mux:
        max_connections: 4    # Maximum connections to maintain
        min_streams: 4        # Min streams before opening new connection
        max_streams: 0        # Max streams per connection (0 = unlimited)
        padding: true         # Enable padding for traffic obfuscation
```

**Server support:** H2MUX is auto-detected on the server side for VMess, VLESS, Trojan, Shadowsocks, and Snell protocols. No server configuration changes are needed.

#### H2MUX Client Compatibility

The Go H2MUX library contained a bug that prevents data upload from finishing successfully, see [https://github.com/SagerNet/sing-mux/pull/8](https://github.com/SagerNet/sing-mux/pull/8)

sing-box now contains this fix, but other clients (eg mihomo) that depend on sing-mux without this change can have issues.

#### DNS Resolution Timeout

DNS servers now support a configurable timeout to prevent hanging on unresponsive DNS servers.

```yaml
- dns_group: my-dns
  servers:
    - url: "tls://dns.example.com"
      timeout_secs: 10      # Default: 5. Set to 0 to disable.
```

### Improvements

- **DNS connection timeout**: DNS-over-TLS/HTTPS connections now respect a 5-second connection timeout, preventing hangs when DNS servers are unreachable
- **Reality server**: Improved shutdown handling with proper flush after every forward operation

## v0.2.5

### New Features

#### AnyTLS Protocol

**Server:**
```yaml
protocol:
  type: tls
  tls_targets:
    "example.com":
      cert: cert.pem
      key: key.pem
      protocol:
        type: anytls
        users:
          - name: user1
            password: secret123
        udp_enabled: true
        padding_scheme: ["stop=8", "0=30-30"]  # Optional custom padding
        fallback: "127.0.0.1:80"               # Optional fallback
```

**Client:**
```yaml
client_chain:
  address: "example.com:443"
  protocol:
    type: tls
    protocol:
      type: anytls
      password: secret123
```

#### NaiveProxy Protocol

**Server:**
```yaml
protocol:
  type: tls
  tls_targets:
    "example.com":
      cert: cert.pem
      key: key.pem
      alpn_protocols: ["h2"]
      protocol:
        type: naiveproxy
        users:
          - username: user1
            password: secret123
        padding: true
        fallback: "/var/www/html"  # Optional static file fallback
```

**Client:**
```yaml
client_chain:
  address: "example.com:443"
  protocol:
    type: tls
    alpn_protocols: ["h2"]
    protocol:
      type: naiveproxy
      username: user1
      password: secret123
```

#### Mixed Port (HTTP + SOCKS5)
Auto-detects HTTP or SOCKS5 protocol.

```yaml
- address: "0.0.0.0:7890"
  protocol:
    type: mixed
    username: user
    password: pass
    udp_enabled: true  # Enable SOCKS5 UDP ASSOCIATE
```

#### TUN/VPN Support
Layer 3 VPN mode using TUN devices for transparent proxying. Supports Linux, Android, and iOS.

```yaml
- device_name: "tun0"
  address: "10.0.0.1"
  netmask: "255.255.255.0"
  mtu: 1500
  tcp_enabled: true
  udp_enabled: true
  icmp_enabled: true
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        address: "proxy.example.com:443"
        protocol:
          type: vless
          user_id: "uuid"
```

**Platform support:**
- Linux: Creates TUN device with specified name/address (requires root)
- Android: Use `device_fd` from `VpnService.Builder.establish()`
- iOS: Use `device_fd` from `NEPacketTunnelProvider.packetFlow`

#### SOCKS5 UDP ASSOCIATE
Full UDP support for SOCKS5 servers including UDP ASSOCIATE command. Enable with `udp_enabled: true` (default).

```yaml
protocol:
  type: socks
  udp_enabled: true  # Default: true
```

#### VLESS Fallback
Route failed authentication attempts to a fallback destination instead of rejecting them.

```yaml
protocol:
  type: vless
  user_id: "uuid"
  fallback: "127.0.0.1:80"  # Serve web content for invalid clients
```

#### Reality `dest_client_chain`
Route Reality fallback (dest) connections through a proxy chain.

```yaml
reality_targets:
  "www.example.com":
    private_key: "..."
    dest: "www.example.com:443"
    dest_client_chain:
      address: "proxy.example.com:1080"
      protocol:
        type: socks
    protocol:
      type: vless
      user_id: "uuid"
```

### Improvements

- **UDP routing**: Comprehensive rewrite of UDP session routing with better multiplexing support
- **Reality**: Improved active probing resistance with TLS 1.3 verification
- **Performance**: Optimized buffer handling and reduced allocations
- **QUIC**: Better buffer sizing based on quic-go recommendations

### Mobile Support

- **iOS FFI**: Added iOS bindings via `NEPacketTunnelProvider` integration
- **Android FFI**: Added Android bindings via `VpnService` integration
- Library now builds as `rlib`, `cdylib`, and `staticlib` for mobile embedding

---

## v0.2.1

## New Features

### Client Chaining (`client_chains`)
Multi-hop proxy chains with load balancing support. Traffic can now be routed through multiple proxies in sequence.

- **Multi-hop chains**: Route traffic through multiple proxies sequentially (e.g., `proxy1 -> proxy2 -> target`)
- **Round-robin chains**: Specify multiple chains and rotate between them for load distribution
- **Pool-based load balancing**: At each hop, use a pool of proxies for load balancing
- New config fields: `client_chain` (singular) and `client_chains` (multiple)
- See `examples/multi_hop_chain.yaml` for usage examples

### TUIC v5 Zero-RTT Handshake
New `zero_rtt_handshake` option for TUIC v5 servers enables 0-RTT (0.5-RTT for server) handshakes for faster connection establishment.

```yaml
protocol:
  type: tuic
  uuid: "..."
  password: "..."
  zero_rtt_handshake: true  # Default: false
```

Note: 0-RTT is vulnerable to replay attacks. Only enable if the latency benefit outweighs security concerns.

### Reality Cipher Suites
Both Reality server and client now support specifying TLS 1.3 cipher suites.

```yaml
# Server
reality_targets:
  "example.com":
    cipher_suites: ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]
    ...

# Client
protocol:
  type: reality
  cipher_suites: ["TLS_AES_256_GCM_SHA384"]
  ...
```

Valid values: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`

### Reality Client Version Control
Server-side Reality configuration can now restrict client versions:

```yaml
reality_targets:
  "example.com":
    min_client_version: [1, 8, 0]  # [major, minor, patch]
    max_client_version: [2, 0, 0]
    ...
```

## Deprecations

### `client_proxy` / `client_proxies` in Rules
The `client_proxy` and `client_proxies` fields in rule configurations are deprecated in favor of `client_chain` and `client_chains`.

**Migration**: Replace `client_proxy:` with `client_chain:` in your configuration files. The old fields still work but will emit a warning and may be removed in a future version.

Before:
```yaml
rules:
  - masks: "0.0.0.0/0"
    action: allow
    client_proxy: my-proxy-group
```

After:
```yaml
rules:
  - masks: "0.0.0.0/0"
    action: allow
    client_chain: my-proxy-group
```

### VMess `force_aead` / `aead` Fields
The `force_aead` and `aead` fields in VMess configuration are deprecated. AEAD mode is now always enabled, and non-AEAD (legacy) mode is no longer supported.

**Migration**: Remove `force_aead` and `aead` fields from your VMess configurations. They have no effect and will be ignored.

## Removed / Breaking Changes

### VMess Non-AEAD Mode Removed
VMess non-AEAD (legacy) mode is no longer supported. All VMess connections now use AEAD encryption exclusively. This improves security but breaks compatibility with very old VMess clients that don't support AEAD.

## Other Changes

- Hysteria2 and TUIC servers now have authentication timeouts (3 seconds by default) to prevent connection hogging
- Improved fragment packet handling with LRU cache eviction
- TUIC server now sends heartbeat packets to maintain connection liveness
