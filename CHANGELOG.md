# Changelog

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
