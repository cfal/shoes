# Configuration Reference

shoes uses YAML configuration files. Multiple configuration types can be combined in a single file or split across multiple files.

## Table of Contents
- [Configuration Structure](#configuration-structure)
- [Server Config](#server-config)
- [Server Protocols](#server-protocols)
- [TUN Config](#tun-config)
- [Client Config](#client-config)
- [Client Protocols](#client-protocols)
- [Rules System](#rules-system)
  - [Rule-sets](#rule-sets)
  - [Protocol sniffing](#protocol-sniffing)
- [Named Groups](#named-groups)
- [Named PEMs](#named-pems)
- [Advanced Features](#advanced-features)
- [Command Line](#command-line)

## Configuration Structure

A configuration file is a YAML array containing one or more configuration entries. Each entry can be:

- **Server Config** - Defines a proxy server instance
- **TUN Config** - Defines a TUN/VPN device for transparent proxying
- **Client Config Group** - Defines reusable upstream proxy configurations
- **Rule Config Group** - Defines reusable routing rules
- **Named PEM** - Defines reusable certificate/key data

```yaml
# Server configs have 'address' or 'path'
- address: "0.0.0.0:8080"
  protocol: ...

# TUN configs have 'device_name' or 'device_fd'
- device_name: "tun0"
  address: "10.0.0.1"
  ...

# Client config groups have 'client_group'
- client_group: my-upstream
  client_proxy: ...

# Rule config groups have 'rule_group'
- rule_group: my-rules
  rules: ...

# Named PEMs have 'pem'
- pem: my-cert
  path: /path/to/cert.pem
```

## Server Config

```yaml
# Bind to IP address and port
address: "0.0.0.0:8080"        # IPv4
address: "[::]:8080"           # IPv6
address: "0.0.0.0:443-445"     # Port range

# OR bind to multiple addresses and port ranges (`address` is also accepted)
addresses:
  - "127.0.0.1:22223"
  - "172.17.0.1:22223-22225"

# OR bind to Unix socket (TCP only)
path: "/tmp/shoes.sock"

# Protocol configuration (required)
protocol: ServerProxyConfig

# Transport layer (default: tcp)
transport: tcp | quic

# TCP settings (only when transport: tcp)
tcp_settings:
  no_delay: true               # Default: true

# QUIC settings (required when transport: quic)
quic_settings:
  cert: string                 # TLS certificate (path or named PEM)
  key: string                  # TLS private key (path or named PEM)
  alpn_protocols: [string]     # Optional ALPN protocols
  client_ca_certs: [string]    # Optional client CA certificates
  client_fingerprints: [string] # Optional client certificate fingerprints
  num_endpoints: int           # Optional, 0 = auto (based on thread count)

# Routing rules (default: allow-all-direct)
rules: string | [RuleConfig]
```

## Server Protocols

### HTTP
```yaml
protocol:
  type: http
  username: string?            # Optional authentication
  password: string?
```

### SOCKS5
```yaml
protocol:
  type: socks                  # Aliases: socks5
  username: string?
  password: string?
  udp_enabled: true            # Default: true (enables UDP ASSOCIATE)
```

### Mixed (HTTP + SOCKS5)
```yaml
protocol:
  type: mixed                  # Aliases: http+socks, socks+http
  username: string?
  password: string?
  udp_enabled: true            # Default: true (enables UDP ASSOCIATE for SOCKS5)
```

Auto-detects HTTP or SOCKS5 protocol from the first byte of the connection.

### Shadowsocks
```yaml
protocol:
  type: shadowsocks            # Aliases: ss
  cipher: string               # See supported ciphers below
  password: string

# Supported ciphers:
# - aes-128-gcm
# - aes-256-gcm
# - chacha20-ietf-poly1305
# - 2022-blake3-aes-128-gcm
# - 2022-blake3-aes-256-gcm
# - 2022-blake3-chacha20-ietf-poly1305
```

### VMess
```yaml
protocol:
  type: vmess
  cipher: string               # aes-128-gcm, chacha20-poly1305, none
  user_id: string              # UUID
  udp_enabled: true            # Default: true (enables XUDP)
```

**Note:** VMess AEAD mode is always enabled. The legacy `force_aead` field is deprecated and non-AEAD mode is no longer supported.

### VLESS
```yaml
protocol:
  type: vless
  user_id: string              # UUID
  udp_enabled: true            # Default: true (enables XUDP)
  fallback: string?            # Optional fallback destination for failed auth (e.g., "127.0.0.1:80")
```

### Trojan
```yaml
protocol:
  type: trojan
  password: string
  shadowsocks:                 # Optional encryption layer
    cipher: string
    password: string
```

### Snell v3
```yaml
protocol:
  type: snell
  cipher: string               # aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305
  password: string
  udp_enabled: true            # Default: true
  udp_num_sockets: 1           # Default: 1, sockets per UDP session
```

### TLS Server
```yaml
protocol:
  type: tls

  # Standard TLS targets (by SNI)
  tls_targets:                 # Aliases: sni_targets, targets
    "example.com":
      cert: string             # Certificate (path or named PEM)
      key: string              # Private key (path or named PEM)
      alpn_protocols: [string] # Optional ALPN
      client_ca_certs: [string] # Optional client CA certs
      client_fingerprints: [string] # Optional client cert fingerprints
      vision: false            # Enable Vision (requires VLESS inner protocol)
      protocol: ServerProxyConfig
      override_rules: [RuleConfig] # Optional rule override

  # Default TLS target (for unmatched/no SNI)
  default_tls_target:          # Aliases: default_target
    cert: string
    key: string
    # ... same fields as tls_targets

  # Reality targets (by SNI)
  reality_targets:
    "www.cloudflare.com":
      private_key: string      # X25519 private key (base64url)
      short_ids: [string]      # Valid client IDs (hex, 0-16 chars)
      dest: string             # Fallback destination (e.g., "example.com:443")
      dest_client_chain: ClientChain?  # Optional proxy chain for reaching dest
      max_time_diff: 60000     # Max timestamp diff in ms (default: 60000)
      min_client_version: [1, 8, 0]  # Optional [major, minor, patch]
      max_client_version: [2, 0, 0]  # Optional [major, minor, patch]
      cipher_suites: [string]  # Optional TLS 1.3 cipher suites (see below)
      vision: false            # Enable Vision (requires VLESS inner protocol)
      protocol: ServerProxyConfig
      override_rules: [RuleConfig]

  # ShadowTLS v3 targets (by SNI)
  shadowtls_targets:
    "example.com":
      password: string
      handshake:
        # Local handshake (with own certificate):
        cert: string
        key: string
        alpn_protocols: [string]
        client_ca_certs: [string]
        client_fingerprints: [string]
        # OR Remote handshake (proxy to real server):
        address: string        # e.g., "google.com:443"
        client_proxies: [ClientConfig] # Optional proxies for handshake
      protocol: ServerProxyConfig
      override_rules: [RuleConfig]

  # Buffer size for TLS (optional, min 16384)
  tls_buffer_size: int
```

### WebSocket
```yaml
protocol:
  type: websocket              # Aliases: ws
  targets:
    - matching_path: string?   # Optional path filter (e.g., "/ws")
      matching_headers:        # Optional header filters
        X-Custom-Header: "value"
      protocol: ServerProxyConfig
      ping_type: ping-frame    # disabled | ping-frame | empty-frame
      override_rules: [RuleConfig]
```

### HTTPUpgrade
```yaml
protocol:
  type: httpupgrade            # Aliases: http-upgrade, http_upgrade
  targets:
    - matching_path: string?   # Optional path filter (e.g., "/download")
      matching_headers:        # Optional header filters, including Host
        X-Custom-Header: "value"
      protocol: ServerProxyConfig
      override_rules: [RuleConfig]
```

WebSocket's handshake without its framing, compatible with sing-box's
`httpupgrade`. There is no `ping_type`: without frames there is nothing to ping
with. A request carrying `Sec-WebSocket-Key` is refused with `404`, as the
reference does -- a real WebSocket client would misread the unframed bytes that
follow. Anything else that does not match is refused with `404` too.

### Port Forward
```yaml
protocol:
  type: forward                # Aliases: port_forward, portforward
  targets: string | [string]   # Target address(es)
```

### Hysteria2
```yaml
protocol:
  type: hysteria2
  password: string
  udp_enabled: true            # Default: true
  obfs:                        # Optional. Both ends must agree.
    type: salamander
    password: string           # At least 4 bytes
```

Obfuscation scrambles every QUIC packet, including the handshake, so a client
that does not use the same type and password cannot reach this server at all.
There is no error for a mismatch — neither side can decode the other, so it
looks exactly like an unreachable server.

### TUIC v5
```yaml
protocol:
  type: tuic                   # Aliases: tuicv5
  uuid: string                 # UUID
  password: string
  zero_rtt_handshake: false    # Default: false (enables 0-RTT for lower latency)
```

### AnyTLS
```yaml
protocol:
  type: anytls
  users:                       # One or more users
    - name: string?            # Optional display name
      password: string         # User password
  udp_enabled: true            # Default: true (enables UDP over TCP)
  padding_scheme: [string]?    # Optional custom padding (e.g., ["stop=8", "0=30-30"])
  fallback: string?            # Optional fallback destination for failed auth
```

AnyTLS is a TLS-based multiplexing proxy protocol with traffic obfuscation. Should be used within TLS or Reality.

### NaiveProxy
```yaml
protocol:
  type: naiveproxy             # Aliases: naive
  users:                       # One or more users
    - name: string?            # Optional display name
      username: string         # Basic Auth username
      password: string         # Basic Auth password
  padding: true                # Default: true (enables padding protocol)
  udp_enabled: true            # Default: true (enables UDP over TCP)
  fallback: string?            # Optional path to serve static files for probe resistance
```

NaiveProxy implements HTTP/2 CONNECT with padding for censorship resistance. Should be used within TLS with `alpn_protocols: ["h2"]`.

## TUN Config

TUN (network TUNnel) devices operate at the IP layer (Layer 3), allowing shoes to act as a transparent VPN.

```yaml
# Linux: Create TUN device by name
device_name: string            # Device name (e.g., "tun0")
address: string                # Device IP address (e.g., "10.0.0.1")
netmask: string?               # Netmask (e.g., "255.255.255.0")
destination: string?           # Gateway/destination (Linux only)

# iOS/Android: Use existing file descriptor
device_fd: int                 # FD from VpnService (Android) or NEPacketTunnelProvider (iOS)

# Common settings
mtu: 1500                      # Default: 1500 (Linux), 9000 (Android), 4064 (iOS)
tcp_enabled: true              # Default: true
udp_enabled: true              # Default: true
icmp_enabled: true             # Default: true

# TCP stack sizing (see "Memory" below)
tcp_buffer_size: int?          # Bytes per direction per connection.
                               # Default: 32768 (mobile), 65536 (elsewhere)
max_connections: int?          # Concurrent TCP connections before SYNs are dropped.
                               # Default: 256 (mobile), 1024 (elsewhere)

# Fake IP (optional, off by default)
fake_ip:
  network: string              # IPv4 CIDR, prefix 8-30. Default: "198.18.0.0/16"
  max_entries: int             # Live mapping ceiling. Default: 8192
  bypass_domains: [string]     # Globs that must resolve for real. Default: none

# Routing rules
rules: [RuleConfig]
```

### Memory

The stack allocates four buffers of `tcp_buffer_size` when it accepts a
connection — two smoltcp socket buffers and two ring buffers — so the ceiling is
`tcp_buffer_size * 4 * max_connections`: 32 MiB on the mobile defaults, 256 MiB
elsewhere. The logged line `TCP stack: buffer=... max_connections=...` reports it
at startup.

A connection through an AmneziaWG outbound pays again on the far side, where the
tunnel's own virtual stack keeps two ring buffers of the same size plus two
256 KiB socket buffers. That larger number is deliberate and not configurable
here: those two are the receive window and in-flight send data of a connection
whose far end is across the internet, and shrinking them to the size of a local
buffer measured as a 6x throughput loss. `tcp_buffer_size` covers the device
side only, where there is no round trip to cover.

Note also that these are allocation ceilings: the buffers are zero-filled pages,
so a connection's resident cost is roughly a third of what it allocates until it
fills them.

The mobile defaults are chosen for an iOS `NEPacketTunnelProvider`, which is
killed rather than warned when it crosses roughly 50 MB. Neither buffer spans a
network round trip — both sit between the device and a proxy connection in the
same process — so raising them buys burst tolerance rather than throughput. A
value below two MTUs is raised to two MTUs, since a buffer that cannot hold a
segment plus what arrives behind it stalls rather than slows.

### Fake IP

DNS queries arriving over the TUN are answered from `network` instead of being
resolved, and the address is turned back into the domain when the connection
arrives — so the name is resolved at the far end of the proxy, not on the
device.

Queries are intercepted by destination **port**, not destination address, so an
app that hardcodes a public resolver is caught along with one that follows the
system settings.

| Query type | Behaviour |
|---|---|
| `A` | Answered with an address from `network`, TTL 1 |
| `AAAA` | NODATA (`NOERROR`, no answers), so the client falls back to `A` |
| `HTTPS`/`SVCB`, `SRV`, `TXT`, `MX`, everything else | Forwarded, so it gets a real answer |
| Any type for a `bypass_domains` match | Forwarded |

Notes:

- Requires `udp_enabled: true`; DNS arrives over UDP.
- `network` must be a range that is not routed for real. The default sits in
  `198.18.0.0/15`, reserved for benchmarking by RFC 2544.
- Past `max_entries` the least recently used mapping is recycled. The 1-second
  answer TTL keeps active domains being refreshed, so they are not recycled
  while in use.
- `bypass_domains` patterns are globs matched case-insensitively, where `*`
  spans dots: `*.local`, `captive.apple.com`, `time.*.apple.com`. Use it for
  anything that must reach a host outside the tunnel — captive-portal probes,
  NTP, STUN, and names the tunnel does not carry.
- Restoration happens before routing rules are evaluated, so hostname rules
  match TUN traffic.

**Platform notes:**
- **Linux**: Requires root or `CAP_NET_ADMIN`. Creates device with specified name/address.
- **Android**: Use `device_fd` from `VpnService.Builder.establish()`. Routes configured via VpnService.
- **iOS**: Use `device_fd` from `NEPacketTunnelProvider.packetFlow`.

**Example (Linux):**
```yaml
- device_name: "tun0"
  address: "10.0.0.1"
  netmask: "255.255.255.0"
  mtu: 1500
  tcp_enabled: true
  udp_enabled: true
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        address: "proxy.example.com:443"
        protocol:
          type: tls
          protocol:
            type: vless
            user_id: "uuid"
```

**Example (Fake IP):** see `examples/tun_fake_ip.yaml`.

## Client Config

Used in rules to specify upstream proxies.

```yaml
address: string                # Proxy server address (e.g., "proxy.example.com:1080")
protocol: ClientProxyConfig
transport: tcp | quic          # Default: tcp
bind_interface: string         # Optional, Linux/Android/Fuchsia only

tcp_settings:
  no_delay: true

quic_settings:
  verify: true                 # Default: true
  server_fingerprints: [string]
  sni_hostname: string
  alpn_protocols: [string]
  cert: string                 # Client certificate for mTLS
  key: string                  # Client key for mTLS
```

## Client Protocols

### Direct
```yaml
protocol:
  type: direct
```

### HTTP
```yaml
protocol:
  type: http
  username: string?
  password: string?
```

### SOCKS5
```yaml
protocol:
  type: socks
  username: string?
  password: string?
```

### Shadowsocks
```yaml
protocol:
  type: shadowsocks
  cipher: string
  password: string
```

### Snell
```yaml
protocol:
  type: snell
  cipher: string
  password: string
```

### VMess
```yaml
protocol:
  type: vmess
  cipher: string
  user_id: string
  h2mux:                         # Optional h2mux multiplexing (see below)
    max_connections: 4
    min_streams: 4
    max_streams: 0
    padding: false
```

**Note:** VMess AEAD mode is always enabled. The legacy `aead` field is deprecated.

### VLESS
```yaml
protocol:
  type: vless
  user_id: string
  h2mux:                         # Optional h2mux multiplexing (see below)
    max_connections: 4
    min_streams: 4
    max_streams: 0
    padding: false
```

### Trojan
```yaml
protocol:
  type: trojan
  password: string
  shadowsocks:                 # Optional
    cipher: string
    password: string
  h2mux:                         # Optional h2mux multiplexing (see below)
    max_connections: 4
    min_streams: 4
    max_streams: 0
    padding: false
```

### H2MUX Multiplexing

H2MUX multiplexes multiple proxy streams over a single HTTP/2 connection, reducing connection overhead. Compatible with sing-box. Available for VMess, VLESS, and Trojan client protocols.

```yaml
h2mux:
  max_connections: 4           # Maximum connections to maintain (default: 4)
  min_streams: 4               # Min streams before opening new connection (default: 4)
  max_streams: 0               # Max streams per connection, 0 = unlimited (default: 0)
  padding: false               # Enable padding for traffic obfuscation (default: false)
```

**Server support:** H2MUX is auto-detected on servers. No configuration needed.

### TLS Client
```yaml
protocol:
  type: tls
  verify: true                 # Default: true
  server_fingerprints: [string]
  sni_hostname: string
  alpn_protocols: [string]
  tls_buffer_size: int
  cert: string                 # Client certificate for mTLS
  key: string                  # Client key for mTLS
  vision: false                # Enable Vision (requires VLESS inner protocol)
  protocol: ClientProxyConfig
```

### Reality Client
```yaml
protocol:
  type: reality
  public_key: string           # Server's X25519 public key (base64url)
  short_id: string             # Your client ID (hex, 0-16 chars)
  sni_hostname: string         # SNI to send (must match server's reality_targets key)
  cipher_suites: [string]      # Optional TLS 1.3 cipher suites (see below)
  vision: false                # Enable Vision (requires VLESS inner protocol)
  protocol: ClientProxyConfig  # Inner protocol (typically VLESS)
```

**Reality cipher suites:** Valid values are `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`. If not specified, all three are offered/supported.

### ShadowTLS Client
```yaml
protocol:
  type: shadowtls
  password: string
  sni_hostname: string?        # Optional SNI override
  protocol: ClientProxyConfig
```

### WebSocket Client
```yaml
protocol:
  type: websocket
  matching_path: string?
  matching_headers:
    header_name: string
  ping_type: ping-frame        # disabled | ping-frame | empty-frame
  protocol: ClientProxyConfig
```

### HTTPUpgrade Client
```yaml
protocol:
  type: httpupgrade
  host: string?                # Sent as the Host header
  matching_path: string?
  matching_headers:
    header_name: string
  protocol: ClientProxyConfig
```

Set `host` whenever a CDN, or a sing-box server with its own `host` configured,
sits in front: left unset the request goes out without a `Host` header, which a
bare sing-box server accepts and a CDN does not. `Host`, `Connection` and
`Upgrade` in `matching_headers` are ignored -- the transport owns all three.

### Port Forward (No-op)
```yaml
protocol:
  type: portforward            # Aliases: noop
```

Passes through the raw connection without protocol wrapping. Useful for testing or transparent proxying.

### AnyTLS Client
```yaml
protocol:
  type: anytls
  password: string             # User password
  udp_enabled: true            # Default: true (enables UDP over TCP)
  padding_scheme: [string]?    # Optional custom padding scheme
```

### NaiveProxy Client
```yaml
protocol:
  type: naiveproxy             # Aliases: naive
  username: string             # Basic Auth username
  password: string             # Basic Auth password
  padding: true                # Default: true (enables padding protocol)
```

### Hysteria2 Client
```yaml
protocol:
  type: hysteria2              # Aliases: hy2
  password: string
  udp_enabled: true            # Default: true
  obfs:                        # Optional. Both ends must agree.
    type: salamander
    password: string           # At least 4 bytes
  port_hopping:                # Optional. See below.
    ports: "20000-50000"
    interval_ms: 30000
```

The password is one opaque string. A server that authenticates by username and
password expects them joined: `"<username>:<password>"`.

A mismatched `obfs` password produces no error. Neither side can decode the
other's packets, so the connection simply never establishes and looks exactly
like an unreachable server. Check it first when a Hysteria2 outbound times out.

#### Port hopping

A Hysteria2 server is often published as a port range. `port_hopping` rotates
the client's UDP port across that range on a timer, which is also what keeps
the connection from holding one 4-tuple for its whole life.

```yaml
- address: 203.0.113.10:443
  protocol:
    type: hysteria2
    password: ...
    port_hopping:
      ports: "20000-50000"       # or "1234,5000-6000,7044"
      interval_ms: 30000         # default 30000, minimum 5000
      # or, instead of interval_ms:
      # min_interval_ms: 15000
      # max_interval_ms: 45000
```

**`ports` replaces the port in `address`.** In the example above, 443 is never
dialled. This matches the reference client, and it is what a `hysteria2://`
link's multi-port parameter means.

`address` must be a literal IP when port hopping is on. The peer address is
fixed for the connection's life - that is what stops QUIC from seeing a path
change on every hop - so a hostname has nowhere to re-resolve to, and the
combination is refused at config load.

Both the local and the destination port move on each hop. Rotating only the
destination would leave the flow linkable by its unchanged source port, which
is the thing port hopping exists to prevent.

### TUIC Client
```yaml
protocol:
  type: tuic                   # Aliases: tuic_v5, tuicv5
  uuid: string                 # UUID
  password: string
  udp_enabled: true            # Default: true
  udp_relay_mode: native       # Default: native. Either 'native' or 'quic'.
  heartbeat_ms: 10000          # Default: 10000
```

`udp_relay_mode: native` carries UDP over QUIC datagrams, and `quic` carries
them over unidirectional streams. Datagrams are cheaper; streams are the way
through a path that drops or mangles QUIC datagrams, and they carry a packet
larger than the datagram limit without fragmenting it. The server replies in
whichever mode the association's first packet used.

`zero_rtt_handshake` is a server-side option only. The client rejects it rather
than accepting it and performing an ordinary handshake.

### mieru Client
```yaml
protocol:
  type: mieru
  username: string             # Part of the key derivation, not just a label
  password: string
```

A client for the [mieru](https://github.com/enfein/mieru) protocol, over
mieru's TCP transport. Both fields must match the server exactly: the
encryption key is derived from the password, the username, and the current
time rounded to two minutes.

That last part is worth knowing before debugging a failure. A client and
server whose clocks differ by more than about four minutes cannot agree on a
key, and a device that has not synchronised its clock cannot connect at all.
The error says so rather than reporting a generic authentication failure.

UDP destinations work: mieru carries socks5 UDP-associate inside the same TCP
session, so no separate transport is involved.

Not implemented, and refused rather than ignored if configured: mieru's UDP
transport, session multiplexing, the low entropy encoding, port ranges and the
0-RTT handshake mode. `transport` must be `tcp` — mieru defines exactly two
transports and carrying its TCP framing over QUIC produces bytes no mieru
server understands.

### QUIC-native outbounds

Hysteria2 and TUIC own their transport rather than running over one, which
changes three things about how they are configured:

- **They must be the only hop in a chain.** QUIC needs a UDP socket, and there
  is no way to raise one over another proxy's TCP stream.
- **`transport` and `tcp_settings` are rejected.** The transport is QUIC and is
  not chosen.
- **`quic_settings` is where the TLS options go** — `verify`,
  `server_fingerprints`, `sni_hostname`, `alpn_protocols`, `key` and `cert` all
  mean the same thing here as they do for a QUIC transport. Unlike WireGuard
  and AmneziaWG, these protocols accept the block without a `transport: quic`
  line, because their transport is implied by the protocol.

```yaml
client_chain:
  - address: "example.com:443"
    protocol:
      type: hysteria2
      password: "a strong password"
    quic_settings:
      sni_hostname: "example.com"
      verify: true
```

Not implemented on the client side, and rejected rather than ignored where a
configuration can ask for them: Brutal congestion control and bandwidth
negotiation, `gecko` obfuscation, port hopping, and TUIC's `zero_rtt_handshake`.
See [ROADMAP.md](./ROADMAP.md) for what each costs.

## Rules System

Rules determine how incoming connections are routed.

### Rule Config
```yaml
rules:
  - masks: string | [string]   # IP/CIDR or hostname masks
    action: allow | block
    # For action: allow
    override_address: string?  # Optional address override
    client_chain: ClientChain | [ClientChain]  # Proxy chain(s) for routing
```

### Client Chains

Client chains define how traffic is routed through upstream proxies. Each chain is a sequence of "hops" - proxies that traffic passes through in order.

```yaml
# Single proxy (simplest form)
client_chain: my-proxy-group           # Reference a named group
client_chain:                          # Or inline config
  address: "proxy.example.com:1080"
  protocol:
    type: socks

# Multi-hop chain (traffic goes: client -> hop1 -> hop2 -> target)
client_chain:
  chain:
    - first-proxy-group
    - second-proxy-group

# Multiple chains (round-robin selection)
client_chains:
  - us-proxy-group                     # Chain 1: single hop
  - chain: [proxy1, proxy2]            # Chain 2: multi-hop

# Load balancing at a hop (pool)
client_chain:
  chain:
    - pool: [us-proxies, eu-proxies]   # Round-robin between pool members
    - final-proxy
```

**Migration note:** The `client_proxy` / `client_proxies` fields still work but are deprecated. Please migrate to `client_chain` / `client_chains`.

### Mask Syntax
```yaml
# IP/CIDR masks
masks: "0.0.0.0/0"             # All IPv4
masks: "::/0"                  # All IPv6
masks: "192.168.0.0/16"        # Subnet
masks: "10.0.0.1:80"           # Specific IP and port

# Hostname masks
masks: "*.google.com"          # Wildcard subdomain
masks: "example.com"           # Exact match

# Multiple masks
masks:
  - "192.168.0.0/16"
  - "10.0.0.0/8"
  - "*.internal.com"
```

### Built-in Rule Groups
- `allow-all-direct` - Allow all connections, direct routing
- `block-all` - Block all connections

### Rule-sets

A rule-set is a compiled list of domains or IP ranges in sing-box's `.srs`
format. Declare it once at the top level and reference it by name:

```yaml
- rule_set: geosite-ru
  path: /etc/shoes/geosite-ru.srs

- rule_set: geoip-ru
  path: /etc/shoes/geoip-ru.srs
```

Relative paths resolve against the directory of the config file that declared
them, so a config directory can be moved intact.

Reference rule-sets from a rule with `rule_sets`. A rule matches if **any** of
its masks matches **or** any of its rule-sets does, so `masks` may be omitted
when a rule matches purely through a rule-set:

```yaml
rules:
  - rule_sets: [geosite-ru, geoip-ru]
    action: allow
    client_chain:
      protocol:
        type: direct

  - masks: "0.0.0.0/0"
    action: allow
    client_chain: my-proxy
```

Compiled lists are published at
[SagerNet/sing-geosite](https://github.com/SagerNet/sing-geosite) and
[SagerNet/sing-geoip](https://github.com/SagerNet/sing-geoip), on their
`rule-set` branches:

```bash
curl -O https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-google.srs
curl -O https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs
```

**Supported matchers:** `domain`, `domain_suffix`, `domain_keyword`,
`domain_regex` and `ip_cidr`. Anything else a `.srs` file can carry --
`process_name`, `package_name`, port matchers, the network and Wi-Fi families,
AdGuard matchers, `source_ip_cidr`, and `type: logical` rules -- is refused at
startup with a message naming the field. A rule-set that loads is one that
matches exactly what it says.

Files are read and checked while the config is validated, so `--dry-run` catches
a bad path or a corrupt file. Editing a `.srs` triggers the same reload a config
edit does.

Domain matching lowercases the destination and ignores a trailing dot. `ip_cidr`
is compared against a resolved address only when the server resolves rule
hostnames; otherwise a hostname destination is matched on its name alone.

### Protocol sniffing

A domain rule needs a domain. When a client hands over a bare address -- an app
with its own DoH resolver, one that dials a literal IP, or a client configured
for `socks5` rather than `socks5h` -- every domain rule and every rule-set
silently stops matching.

Sniffing recovers the name from the first bytes of the connection: the
`server_name` extension of a TLS ClientHello, or the request line and `Host`
header of an HTTP/1.x request. It is off by default and enabled per listener,
on a server or on the TUN.

```yaml
- address: 0.0.0.0:1080
  protocol:
    type: socks
  sniff: true
```

The long form spells out the defaults:

```yaml
  sniff:
    enabled: true
    protocols: [tls, http]
    timeout_ms: 300
```

| Field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` inside a `sniff:` block | Whether to sniff at all |
| `protocols` | `[tls, http]` | Which sniffers to run. A single name may be written without a list. An empty list with `enabled: true` is a config error |
| `timeout_ms` | `300` | How long to wait for the client's first bytes |

`timeout_ms: 0` is valid and means "sniff whatever has already been buffered and
wait for nothing". Use it when no added latency is acceptable.

The recovered name is used **for routing only**. A direct connection still
dials the original address and performs no DNS lookup; a connection routed
through a proxy sends the name upstream, so the exit node resolves it -- which
is what a client using `socks5h` is asking for. CIDR masks keep matching the
real address either way.

Some connections are never sniffed:

- a destination that is already a hostname, because there is nothing to
  recover;
- ports 25, 465, 587, 143, 993, 110 and 995 -- SMTP, IMAP and POP3, where the
  server speaks first, so waiting would stall the connection for the whole
  timeout and learn nothing.

Sniffing can never itself fail a connection. If nothing is recognised, if the
protocol carries no name, or if the client says nothing before the deadline,
the connection is routed by address exactly as it would have been. Successful
sniffs are logged at `debug`.

One consequence worth stating plainly: with `sniff` enabled the proxy reads the
first bytes of application payload before deciding where to route it. Those
bytes are not stored, are not logged above `debug`, live only in a
per-connection buffer capped at 16 KiB, and reach the remote unchanged. This is
why the feature is off unless you turn it on.

Note also that with sniffing enabled, protocols that send a success response --
SOCKS5 and HTTP `CONNECT` -- send it **before** the upstream connection is
attempted, because the client will not send anything to sniff until it has one.
A client therefore sees the connection open and then close, rather than an
error code, when the upstream is unreachable.

### Example Rules
```yaml
rules:
  # Direct connection for local networks
  - masks: ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
    action: allow
    client_chain:
      protocol:
        type: direct

  # Block specific domains
  - masks: ["*.ads.example.com", "tracking.example.com"]
    action: block

  # Route through upstream proxy
  - masks: "0.0.0.0/0"
    action: allow
    client_chain:
      address: "proxy.example.com:1080"
      protocol:
        type: socks
```

## Named Groups

### Client Proxy Group
```yaml
- client_group: my-upstream
  client_proxies:              # Define proxies in this group
    - address: "proxy1.example.com:1080"
      protocol:
        type: socks
    - address: "proxy2.example.com:1080"
      protocol:
        type: socks

# Reference in rules
- address: "0.0.0.0:8080"
  protocol:
    type: http
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain: my-upstream  # Reference by name
```

### Rule Group
```yaml
- rule_group: standard-rules
  rules:
    - masks: ["192.168.0.0/16"]
      action: allow
      client_chain:
        protocol:
          type: direct
    - masks: "0.0.0.0/0"
      action: allow
      client_chain: my-upstream

# Reference in server config
- address: "0.0.0.0:8080"
  protocol:
    type: http
  rules: standard-rules        # Reference by name
```

## Named PEMs

Define certificates once and reference throughout configuration.

```yaml
# From file
- pem: my-cert
  path: /path/to/certificate.pem

# Inline data
- pem: my-key
  data: |
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----

# Reference in config
- address: "0.0.0.0:443"
  protocol:
    type: tls
    tls_targets:
      "example.com":
        cert: my-cert          # Reference by name
        key: my-key
        protocol:
          type: http
```

## Advanced Features

### Vision (XTLS-Vision)

Vision optimizes TLS-in-TLS scenarios by detecting inner TLS traffic and switching to direct mode for zero-copy performance.

**Requirements:**
- Inner protocol MUST be VLESS
- Works with both TLS and Reality

```yaml
# TLS + Vision
protocol:
  type: tls
  tls_targets:
    "example.com":
      cert: cert.pem
      key: key.pem
      vision: true
      alpn_protocols: ["http/1.1"]
      protocol:
        type: vless
        user_id: "uuid"

# Reality + Vision
protocol:
  type: tls
  reality_targets:
    "www.google.com":
      private_key: "..."
      short_ids: ["..."]
      dest: "www.google.com:443"
      vision: true
      protocol:
        type: vless
        user_id: "uuid"
```

### XUDP Multiplexing

Automatically enabled for VMess and VLESS when `udp_enabled: true`. Multiplexes UDP traffic over a single connection.

### Proxy Chaining

**Protocol nesting** (wrap one protocol in another):

```yaml
client_chain:
  address: "proxy.example.com:443"
  protocol:
    type: tls
    protocol:
      type: vmess
      cipher: aes-128-gcm
      user_id: "uuid"
```

**Multi-hop chains** (route through multiple proxies sequentially):

```yaml
client_chain:
  chain:
    - address: "proxy1.example.com:1080"
      protocol:
        type: socks
    - address: "proxy2.example.com:443"
      protocol:
        type: tls
        protocol:
          type: vless
          user_id: "uuid"
```

### Hot Reloading

Configuration changes are automatically detected and applied without restarting. Disable with `--no-reload` flag.

### mTLS (Mutual TLS)

Require client certificates for authentication:

```yaml
# Server side
protocol:
  type: tls
  tls_targets:
    "example.com":
      cert: server.crt
      key: server.key
      client_ca_certs: [ca.crt]  # Required CA
      client_fingerprints: ["sha256:..."]  # Optional specific certs
      protocol: ...

# Client side
client_chain:
  address: "example.com:443"
  protocol:
    type: tls
    cert: client.crt
    key: client.key
    protocol: ...
```

## Command Line

```bash
shoes [OPTIONS] <config.yaml> [config.yaml...]

OPTIONS:
  -t, --threads NUM    Worker threads (default: CPU count)
  -d, --dry-run        Parse config and exit
  --no-reload          Disable hot-reloading

COMMANDS:
  generate-reality-keypair                       Generate Reality X25519 keypair
  generate-shadowsocks-2022-password <cipher>    Generate Shadowsocks 2022 password
```

## Tips

### Generate Keys

**Reality keypair:**
```bash
shoes generate-reality-keypair
```

**Shadowsocks 2022 password:**
```bash
shoes generate-shadowsocks-2022-password 2022-blake3-aes-256-gcm
```

**UUID:**
```bash
uuidgen
```

**TLS certificate fingerprint:**
```bash
openssl x509 -in cert.pem -noout -fingerprint -sha256
```

### Security Best Practices

- Use strong, random passwords
- Keep private keys secure
- Use `127.0.0.1` instead of `0.0.0.0` for local-only access
- Use firewall rules to restrict access
- Enable client certificate authentication for sensitive services
- Use Vision with Reality for maximum privacy

### Performance Tips

- Enable `vision: true` for TLS-in-TLS scenarios
- Use `tcp_settings.no_delay: true` for low latency
- Set `quic_settings.num_endpoints` to match worker threads
- Use QUIC transport for high-latency or lossy networks

### Common Issues

- **"Address already in use"**: Change port or stop conflicting service
- **"Permission denied"**: Ports < 1024 require root/admin
- **Reality connection fails**: Verify keys match, UUID matches, SNI matches server's reality_targets key
- **Vision not working**: Ensure inner protocol is VLESS
- **Config validation fails**: Run with `--dry-run` for detailed errors
