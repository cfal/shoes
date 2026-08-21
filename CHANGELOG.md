# Changelog

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
