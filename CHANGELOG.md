# Changelog

## Unreleased

- Breaking: file-backed inbound TLS/QUIC identities, including legacy `cert`/`key` paths and file-backed named PEMs, now rotate live and require currently valid, leaf-to-issuer certificate chains. Expired or misordered bundles can fail startup after upgrade, and expired sources stop serving new handshakes even to clients using fingerprint pinning or disabled verification. Renew certificates, remove expired cross-signs and certificates outside that chain, and synchronize the system clock before starting Shoes. Child-to-issuer signatures must use TLS-provider-supported algorithms (no SHA-1; RSA issuer keys of at least 2048 bits); reissue certificates with unsupported signatures. Inline-only pairs retain their previous behavior. See [certificate sources](CONFIG.md#certificate-sources).

## v0.3.4

- Added an opt-in Clash API controller over authenticated TCP or Unix sockets, with manual proxy selectors, optional persistent choices, connection inspection/cancellation, traffic/log streams, and delay probes. Existing groups remain round-robin; selection changes affect new flows only. Every controller requires a nonempty secret. TCP listeners serve plain HTTP; bind to loopback or terminate TLS in front. Controller settings require a restart. Browser origins require an explicit allowlist; `cors_origins: ["*"]` permits any origin without disabling authentication. No dashboard hosting or full Mihomo API parity is included; controller/cache entries are not supported through FFI.
- Added multiarchitecture Docker images at `ghcr.io/cfal/shoes` for `linux/amd64` and `linux/arm64`. Use `v0.3.4` for this release, `latest` for the latest stable release, or `master` for current development builds.
- Fixed payload loss after fragmented VLESS response headers, WebSocket framing after nonempty Ping frames, and preread-byte loss in ShadowTLS authentication fallback.
- Fixed WebSocket handling of 125-byte control frames, false EOF with partly filled read buffers, and flushing buffered frames on shutdown. The shared TLS ClientHello parser now reassembles handshakes across records, and message-stream shutdown after EOF is bounded.
- Replaced REALITY's custom TLS state machine and record crypto with a pinned `cfal/rustls` fork. Authentication, ML-DSA policy, transparent forwarding and Vision remain in Shoes. Outbound ClientHello now uses rustls's native fingerprint, not Chrome/uTLS emulation; clients still fail closed on non-REALITY certificates.
- REALITY servers preserve admitted target ServerHello bytes except the key share and follow the target's cipher within the configured allowlist. Every synthetic handshake record must fit its target length. Unsupported layouts, cipher conflicts and insufficient capacity forward transparently before synthetic output; targets that previously worked only because Shoes enlarged records may now fail outbound REALITY authentication. Combined flights with observed trailing records or partial data are not synthesized; separate flights require capacity for rustls's server-name acknowledgement.
- REALITY now reports TCP EOF without TLS `close_notify` as `UnexpectedEof`, matching ordinary rustls TLS connections rather than treating truncation as a clean close.
- Fixed Naive HTTP/2 writes stalling on already available flow-control credit after a pending write is cancelled and retried with a smaller buffer.
- Fixed TUN startup resets for queued TCP connections, rejected SYN admission, and stale passive listeners after handshake resets. TUN and WireGuard now defer inbound routing and hostname sniffing until TCP establishment; half-open TUN connections expire after 30 seconds instead of retaining the established-connection timeout.
- Propagated TUN worker startup and runtime failures, including hard write errors, to the service owner. The daemon now stops with an error rather than silently continuing without TUN. Temporary Linux link-down and Apple utun queue backpressure drop packets without stopping the service. Invalid supplied descriptors are rejected before taking ownership.
- Kept reply-only TUN UDP sessions alive while destination traffic continues.
- Bound each iOS service's socket-protection callback to its own protector so stopping an older service cannot clear a replacement callback.
- Released Fake DNS snapshot locks explicitly on owner teardown so concurrently starting subprocesses cannot delay reopening the state file.
- Updated Rust dependencies, including GotaTun 0.10.2, Tokio 1.54.1, LRU 0.19.0, and ML-KEM 0.3.3, which removes secret-dependent table lookups. Tokio 1.54.1 fixes an `Interval` timer race on multithreaded runtimes that could cause crashes or use-after-free ([GHSA-5wjr-9356-4wc8](https://github.com/advisories/GHSA-5wjr-9356-4wc8)).
- Refreshed the BLAKE3 fork with upstream buffer-alignment and AVX-512 soundness fixes while retaining the binary-context key derivation API.
- Removed the standalone Android Kotlin/Gradle wrapper, AAR and iOS XCFramework packaging, and mobile SDK release artifacts from this repository. Mobile embedding remains supported through the Rust JNI/C interfaces; Android and iOS cross-compilation checks remain in CI. Existing SDK users must build the native libraries and supply their own `com.shoesproxy.ShoesNative` declarations on Android or link `libshoes.a` using `include/shoes.h` on iOS; see the README's Mobile Embedding section.
- Updated Web PKI dependencies for the [eMudhra intermediate CA compromise](https://emudhra.we-have-a-problem.com/) (CVE-2026-111943): removed `emSign ECC Root CA - G3` from bundled roots and blocked the eight compromised intermediate keys, including cross-signed chains, during certificate verification. Affected deployments need certificates with an unaffected CA chain. Existing binaries must be rebuilt or upgraded to receive this protection.
- Added opt-in native VLESS Encryption with X25519 and ML-KEM key chains, session resumption, native Vision, and the `generate-vless-encryption` command. A VLESS-level `vision: true` without native encryption, previously ignored, now fails validation; move it to the TLS/REALITY layer for legacy Vision. Older versions silently ignore native encryption settings, so roll back configuration together with the binary. Native encryption interoperates with supported Xray and Mihomo peers, not sing-box; see the README for configuration and transport limitations.
- Added standard HTTP/2 CONNECT support to HTTP and mixed listeners and opt-in HTTP proxy clients (`http_version: h2`), including concurrent tunnels on eligible shared connections. HTTP/1 remains the client default; explicit H2 over TLS requires matching `h2` ALPN.
- Fixed Vision DIRECT decisions under backpressure and tightened TLS ServerHello parsing.
- Fixed bracketed IPv6 literals in destinations and DNS upstream URLs being treated as hostnames.
- Fixed TCP loss recovery in TUN and WireGuard through a pinned smoltcp fork.
- Fixed XHTTP shutdown handling for complete HTTP/2 responses. Added server `matching_headers` for exact required-header matching, with single values or lists of allowed values for rotation. Requests must send exactly one value per required header. Header/path mismatches return plain 404s on all HTTP versions without affecting H2/H3 sibling streams, subject to request-admission limits. All XHTTP error responses now omit XHTTP padding, caching, and CORS headers; successful responses are unchanged. The development-only `close_on_http1_error` option is not supported and configurations containing it fail to load.
- XHTTP client `headers` now reject names that differ only in case, which previously sent every value and failed exact server matching, and values with leading or trailing whitespace, which receivers strip or reject.
- XHTTP aggregate/session admission and byte caps are now opt-in, and the per-connection request limit defaults to 250 instead of 128. Uncapped workloads can use more memory under overload. Setting only an aggregate byte or request cap derives the previous per-session safeguard (at most 4 MiB or 128 requests); explicit session caps override it. To restore all v0.3.3 XHTTP limits, set `max_sessions: 1024`, `max_pending_sessions: 256`, `max_requests: 4096`, `max_requests_per_session: 128`, `max_requests_per_connection: 128`, `max_buffered_bytes: 67108864`, and `max_session_buffered_bytes: 4194304` under `limits`. Packet sizes, reorder windows, transport windows and timeouts are unchanged.
- Added ordered destination predicates and shared domain/IP indexes, with local SRS, sing-box JSON, Mihomo YAML/text/MRS and Xray GeoSite/GeoIP DAT rule sets. Sources compile before listener replacement and participate in config-file watching; invalid candidates retain the running configuration. IP rules resolve only when needed and pin the judged address; DNS failures stop routing.
- Rule migration: legacy `*.example.com` and `.example.com` masks now reject at startup; use typed `domain_pattern` or `subdomains`. Supplied hostnames must be valid ASCII A-label names, even with catch-all-only rules. Non-`/0` IPv6 masks no longer implicitly match IPv4 addresses through mapped representation; mapped-only legacy prefixes migrate with a warning. Legacy `/0` remains universal; typed CIDRs are family-specific.
- Added opt-in `dns.fake_ip` with shared DNS-group mappings, TCP/UDP port-53 interception, hostname restoration, and optional persistent state. Other DNS records use the configured real upstreams; Android/iOS require explicit `dns.servers` rather than VPN system discovery.
- Added opt-in `sniff: true` for route-only TLS SNI and cleartext HTTP/1 Host matching on logical TCP streams. The sniffed hostname takes precedence over Fake-DNS-restored names for hostname rules without replacing the connection target; explicitly supplied hostnames are not sniffed. Routing is fixed after initial inspection, including across later HTTP requests. HTTP/2 headers and QUIC datagram sniffing are not included.
- Preserved original UDP reply identities across Fake DNS restoration and fixed early-data delivery in AnyTLS, H2MUX, and Naive TCP adapters.
- Added userspace WireGuard client and server protocols using GotaTun 0.10.2. They support inbound TCP/UDP forwarding, outbound proxy chains, IPv4/IPv6, multiple server peers, PSKs, keepalives, and authenticated roaming on Unix. Identical client configurations share devices automatically; conflicting settings for the same endpoint and key pair reject.
- WireGuard clients are supported only at the first chain hop. TCP DNS transports can use them; unsupported UDP/H3 DNS routes and tunnel-dependent bootstrap configurations are rejected instead of bypassing the tunnel.
- Added protocol `peer_client_chain` for proxies before WireGuard, including nested WireGuard clients and optional inner proxy suffixes. Detours use fixed peer destinations, require a UDP-capable final carrier hop, and never fall back to direct UDP. Proxied servers omit their listen address and initiate peer associations using keepalive. Detours do not accept unsolicited public peers or support arbitrary peer roaming.
- WireGuard reloads disconnect existing flows and explicitly release endpoint sockets before rebinding. Initial limitations include no IP fragmentation/reassembly, ICMP forwarding, or OS route management.
- Shared TUN and WireGuard TCP streams complete write-half shutdown after queuing FIN, without waiting for the remote read half to close. Dropping a drained stream allows the FIN exchange to finish, bounded by a 60-second orphan deadline.
- SOCKS5 outbounds now wait for each server reply during negotiation instead of sending the CONNECT request ahead, fixing timeouts with servers that drop early data, such as Cloudflare WARP's local proxy. Setup through a SOCKS5 upstream takes one more round trip, or two with username/password. Servers that select an authentication method the client did not offer are rejected.
- SOCKS5, mixed, and WebSocket inbounds flush each handshake reply, and ShadowTLS sends records without waiting for a flush, so clients that wait for each reply, such as sing-box and now Shoes, no longer stall when these inbounds run inside ShadowTLS. Upgrade Shoes servers running SOCKS or mixed inbounds inside ShadowTLS before or together with clients; updated clients stall against older servers.

This release is distributed through GitHub Releases and GHCR, not crates.io. Crates.io publishing remains disabled while fork patches are required; `cargo install shoes` still installs the previously published release. Building from source requires Rust 1.95 or newer. The six Linux/macOS release tarballs contain `THIRD_PARTY_NOTICES.md` and `licenses/` beside the binary; distributors must retain these notices and corresponding source information. Android AAR and iOS XCFramework archives are no longer provided.

## v0.3.3

- Added XHTTP/SplitHTTP client and server transports with packet-up, stream-up, and stream-one modes over HTTP/1.1, HTTP/2, and HTTP/3. See the README for supported configurations and interoperability limitations.
- Added ordered `key_exchange_groups` allowlists for TLS and QUIC (`quic_settings`), including native hybrid key exchange. Omitting the field preserves current defaults.
- REALITY clients now offer `X25519MLKEM768` first, with X25519 fallback. Servers accept both groups and follow the camouflage target's choice. Upgrade Xray servers to v25.5.16 or newer: v25.4.30 and earlier reject hybrid-selected target handshakes, so hybrid-first clients fail when the target selects that group.
- Added optional pinned ML-DSA-65 REALITY authentication through `mldsa65_seed` (server), `mldsa65_verify` (client), and `generate-reality-mldsa65-keypair`. Configured clients reject missing or invalid signatures; signing requires enough room in the camouflage target's certificate flight.
- Hardened malformed protocol framing, credential comparisons, replay rejection, and secret-safe diagnostics.
- Preserved handshake early data and response ordering in TCP, TUN, Hysteria2, and TUIC forwarding; bounded initial writes and flushes.
- Added `check` and `version` aliases, nonzero validation failures, last-good configuration preparation, and explicit signal handling. SIGHUP reloads even with `--no-reload`; orderly signal shutdown exits with status 0.
- Corrected Snell salts to 16 bytes for all ciphers. ChaCha20 and AES-256 connections to older Shoes versions using 32-byte salts are not wire-compatible; upgrade both ends together.
- Hysteria2 now reports actual connection outcomes, emits bracketed IPv6 addresses, and advertises `Hysteria-CC-RX: auto`. Compatible clients select automatic congestion control (BBR in sing-box), even when a client bandwidth is configured.
- Unsupported VMess cipher names, including `auto`, are rejected during validation instead of panicking at startup. Use `any` for automatic cipher selection.
- Stricter server validation rejects empty authentication passwords, invalid SOCKS/mixed credential lengths, wrong-length Shadowsocks 2022 keys, Vision with non-VLESS inner protocols, and misplaced Hysteria2/TUIC/NaiveProxy layers (including NaiveProxy inside ShadowTLS). Some configurations accepted by v0.3.2 now fail `check` or startup.
- Improved QUIC socket portability, SOCKS UDP compatibility with NAT clients, and synchronous mobile lifecycle safety.
- Fixed h2mux data loss under backpressure.
- Fixed premature HTTP/3 body EOF on empty DATA frames through a pinned h3 fork, preserving XHTTP idle streams and covering direct and transitive h3 dependencies.
- Reduced Linux TCP relay overhead with splice, including drained Vision DIRECT connections, and added TCPv4 segmentation offload for created Linux TUN devices. Offload is automatic when available; set `segmentation_offload: false` to disable it.
- Reduced TCP and UDP relay copies, allocations, and polling overhead.

This release is available on GitHub only. Crates.io publishing remains disabled while the h3 fork patches are required; `cargo install shoes` still installs the previously published release.

## v0.3.2

### Fixes

- Fixed TLS record ownership across Vision handshakes and mode transitions, preserving fragmented records and buffered data. This resolves the Vision TLS handoff limitation documented in v0.3.1.
- Improved TLS closure, output backpressure, and transport keepalive handling, and preserved REALITY preread bytes during fallback forwarding.
- Fixed a TUN TCP handler setup race that could reset a valid connection.

### Performance

- Replaced the TUN stack's 10 ms polling fallback with coalesced wakeups for TCP and UDP work, reducing latency and idle wakeups.
- Reduced TUN packet-processing overhead with bounded ingress batches and TCP egress sweeps.
- Reduced UDP packet copies and allocations by carrying owned buffers through forwarding queues and reusing transmit storage, while preserving configured queue limits and packet-atomic writes.

## v0.3.1

### Fixes

- Restored unlimited connection, stream, UDP destination, and QUIC memory admission by default. Limits are now opt-in, while transport buffers and connection cleanup remain bounded.
- Made TUN connection, memory, session, destination, and queued-byte admission limits opt-in through the existing `resource_limits` configuration.
- Preserved outstanding resource reservations when limits change during configuration reloads.
- Preserved QUIC protocol control streams when small application stream limits are configured.

### Configuration Migration

Resource-related `SHOES_*` environment variables are no longer used. Configure process-wide limits with a single top-level `global_limits` YAML entry across all loaded configuration files:

```yaml
- global_limits:
    max_connections: 1024
    max_streams: 2048
    reload_grace_secs: 300
```

Omitted or `null` admission caps are unlimited; transport buffer sizes remain finite. `SHOES_RELOAD_GRACE_SECS` is replaced by `global_limits.reload_grace_secs`. Existing TUN `resource_limits` values remain supported; omitted admission caps are now unlimited.

Resource budgets limit admitted work and modeled buffers, not total process memory. DNS-over-HTTP/3 reservations remain approximate.

Known limitation: Vision TLS handoff can still fail when a TCP read ends partway through a TLS record.

## v0.3.0

### New Features

- Added configurable connection, stream, UDP destination, and QUIC buffer budgets through `SHOES_*` environment variables.
- Added support for multiple bind addresses in server configurations.
- Added file logging with `--log-file` and version reporting with `--version`.
- Added Android AAR and iOS XCFramework release artifacts for mobile embedding.

### Improvements

- Bounded protocol queues and setup/shutdown deadlines, with more reliable task, socket, and session cleanup during disconnects and configuration reloads.
- Improved H2MUX and NaiveProxy draining, AnyTLS session ownership, QUIC listener startup cleanup, and TUN connection teardown.
- Improved UDP/XUDP session isolation, destination admission, cancellation, and routing overrides.
- Bounded DNS caches and pending lookups, preserved upstream connection pooling, and improved resolver refresh and destination-address failover.
- Improved REALITY compatibility and buffering, and fixed Vision handling of already-decrypted data after the END command.
- Hardened protocol parsing and authentication, and fixed mobile stop/restart socket-protection cleanup.

Resource budgets limit admitted work and modeled buffers, not total process memory. DNS-over-HTTP/3 reservations remain approximate.

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
