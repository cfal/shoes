# Configuration Reference

shoes uses YAML configuration files. Multiple configuration types can be combined in a single file or split across multiple files.

## Table of Contents
- [Configuration Structure](#configuration-structure)
- [Server Config](#server-config)
- [Server Protocols](#server-protocols)
- [TUN Config](#tun-config)
- [WireGuard Endpoints](#wireguard-endpoints)
- [Client Config](#client-config)
- [Client Protocols](#client-protocols)
- [Rules System](#rules-system)
- [Named Groups](#named-groups)
- [Named PEMs](#named-pems)
- [Advanced Features](#advanced-features)
- [Command Line](#command-line)

## WireGuard Endpoints

WireGuard is a named top-level endpoint, not a TCP server protocol or a stream
wrapper. Each configuration generation owns one GotaTun device and one smoltcp
stack per endpoint name. All references share that endpoint. Unix builds
support this mode; Windows rejects WireGuard configuration.

See [server](examples/wireguard_server.yaml) and
[client](examples/wireguard_client.yaml) examples. Their demonstration keys
must be replaced before deployment. Generate a private key with `wg genkey`
and derive its public key with `wg pubkey`. Never share the private key.

| Field | Meaning |
| --- | --- |
| `wireguard` | Unique, nonempty endpoint name |
| `private_key` | Base64-encoded 32-byte private key |
| `addresses` | Nonempty local tunnel CIDRs; at most one address per family |
| `listen` | Optional literal UDP socket address in direct mode; omission chooses an ephemeral dual-stack wildcard, with IPv4 fallback when IPv6 is unavailable |
| `bind_interface` | Optional outer UDP interface, supported on Linux/Android |
| `outer_client_chain` | Optional client chain carrying encrypted UDP to the peers; conflicts with `listen` and endpoint `bind_interface` |
| `mtu` | Inner IP MTU, default 1408; supported range 1280-1420 |
| `peers` | Nonempty static peer list |
| `inbound` | Optional forwarding policy; omitted disables unsolicited inbound flows |
| `resource_limits` | Same fields as TUN, with bounded WireGuard defaults |

Each peer requires `public_key` and nonempty `allowed_ips`. Optional fields
are `pre_shared_key`, `endpoint: "host:port"`, and
`persistent_keepalive` in seconds (zero disables it). Omit `endpoint` for a
peer that initiates toward this server. Hostnames are resolved through native
bootstrap DNS during preparation and refreshed on reload. Direct mode selects
the first resolved address compatible with the bound socket at startup.
Authenticated WireGuard roaming can update the active peer address without a reload in direct mode.
Overlapping allowed prefixes between different peers, duplicate keys, and
self-peering are rejected. Assign each client distinct tunnel addresses.

`0.0.0.0:51820` listens only on IPv4; `[::]:51820` uses a dual-stack socket
where supported. Outer sockets retain mobile socket protection and interface
binding. No OS interface, route, firewall rule, or NAT rule is created.

An explicit `inbound` requires nonempty `rules` and may specify `dns`.
Rules use the normal destination masks, overrides, and client chains. There
is no implicit allow-all fallback for an empty inbound block. Outbound socket
replies remain enabled when `inbound` is omitted. Per-peer authorization
beyond cryptokey source validation is not supplied by destination rules.
Authenticated peers can reach the gateway's local services unless rules block
them. The server example blocks loopback and link-local destinations; restrict
private networks too when peers should not access the gateway's LAN.

Reference an endpoint from the first hop:

```yaml
client_chain:
  - protocol: {type: wireguard, endpoint: wg-out}
  - address: "10.77.0.10:1080"
    protocol: {type: socks}
```

The second hop is optional. A WireGuard reference must not specify `address`,
`bind_interface`, QUIC, or TCP/QUIC socket settings. WireGuard cannot appear
inside TLS/WebSocket or at later hops. A missing route, address family, failed
endpoint, or unavailable peer never causes direct fallback.

To put proxies **before** WireGuard, configure `outer_client_chain` on the endpoint:

```yaml
outer_client_chain:
  - address: "relay.example:443"
    protocol:
      type: tls
      protocol:
        type: vless
        user_id: "b85798ef-e9dc-46a4-9a87-8da4499d36d0"
        udp_enabled: true
```

The effective path is `Shoes -> outer proxy chain -> WireGuard peer -> optional
inner proxy chain -> destination`. The routing rule still references WireGuard
at hop zero. See [the complete detour example](examples/wireguard_outer_chain.yaml).

Outer chains use the normal inline, named-group and pool syntax. Their final hop
must support UDP; earlier hops may be TCP-only. VLESS, VMess and compatible
Shadowsocks/AnyTLS UDP-over-TCP configurations work. Shoes' SOCKS outbound only
implements CONNECT, and Trojan outbound UDP is not implemented, so neither can
be the final UDP hop. Pools select UDP-capable final members. Selection remains
fixed for the life of an association; reconnection may select another member.

Every detoured peer must specify `endpoint`. One persistent association is shared
by all inner flows to each resolved peer destination; peers with the same resolved
destination share an association. No native WireGuard UDP listener is opened.
Configure physical interface binding on the first outer client, not the endpoint.
`inbound.rules` still handles authenticated connections received over established
associations, but cannot accept unsolicited public peers through a proxy detour.
Inbound-only detours require a nonzero `persistent_keepalive` on every peer:
Shoes must initiate a handshake to establish the proxy's UDP return mapping.
Without keepalive, an outbound inner flow must initiate that handshake first.

Detoured destinations are fixed for the configuration generation. Their message
streams do not expose source addresses, so arbitrary peer address roaming is not
supported. Peer hostname changes require reload. Peer and outer-proxy bootstrap
use native DNS independently of routed DNS and `inbound.dns`. Ensure host DNS and
host routes do not themselves require the tunnel being established.

Outer connect and blocked-write attempts time out after 10 seconds. Failed streams
retry with backoff from 250 ms to 10 seconds, never falling back to direct UDP.
Offline/overflow packets are dropped rather than indefinitely buffered; WireGuard
and inner TCP perform their normal retries. Use `persistent_keepalive` to maintain
idle proxy UDP mappings. Silent blackholes without stream errors remain UDP loss.
Queues hold at most 64 packets per destination and 64 aggregate received packets,
with a 2048-byte outer datagram limit, above the supported inner MTU plus WireGuard
overhead. Shutdown waits for workers to release their associations.

An outer chain can itself start with another named WireGuard endpoint. Dependencies
start first, regardless of declaration order; self-dependencies and indirect cycles
(including pool alternatives) are rejected. A direct WireGuard-in-WireGuard carrier
requires `round_up(inner_mtu, 16) + 80 <= carrier_mtu`, conservatively accounting for
IPv6, UDP and WireGuard overhead. For example, inner MTU 1280 fits carrier MTU 1408.
A TCP proxy after the carrier segments packets instead. External path MTU still
needs operator tuning; UDP-over-TCP can introduce head-of-line blocking.

DNS remains independently configured. Merely defining a WireGuard endpoint
does not tunnel the application's default native DNS. Explicit TCP DNS,
DoT, and DoH client chains may use WireGuard with a literal upstream IP.
Use `server_name` for TLS authentication where needed. UDP DNS, HTTP/3 DNS,
hostname upstreams on WireGuard chains, and bootstrap dependencies on
WireGuard-routed DNS groups are rejected. Endpoint bootstrap itself is native
DNS, not DNS through the not-yet-active tunnel.

This is TCP/UDP proxying, not arbitrary IP routing. Remote destinations see
the gateway's outgoing proxy connection, not the original client's source
address. A non-Shoes gateway must provide the required routes and forwarding
or NAT for destinations behind it. ICMP forwarding, IP fragment reassembly,
peer-to-peer IP forwarding, WARP reserved bytes, and
wg-quick import are not implemented.

Fragmented input and unsupported IPv6 extension chains are dropped before
transport parsing. TCP advertises an MSS derived from the MTU. Outbound UDP
writes larger than MTU minus 28 bytes (IPv4) or 48 bytes (IPv6) are dropped and
counted without closing the flow; they are never truncated. UDP queue-budget
exhaustion also drops individual writes. At MTU 1408 the payload limits are 1380 and 1360
bytes. Oversized UDP responses on inbound forwarding are dropped. Large DNS
replies should use TCP-based transports. Reduce MTU for constrained underlays;
automatic path-MTU discovery is not provided.
Packets received from a peer above the local MTU are also dropped. Configure
matching MTUs on both sides, including peers whose default is 1420 rather than
Shoes' 1408; TCP MSS negotiation does not protect UDP traffic.

Default admission limits are 256 TCP connections, 32 KiB TCP buffers, a
32 MiB TCP buffer budget, 1024 UDP sessions, 4096 UDP destinations, 64
destinations per inbound UDP session, and 8 MiB queued UDP payloads.
UDP forwarding and outbound associations have separate bounded pools.
Missing or null limit fields use WireGuard defaults rather than the unlimited
TUN defaults. Packet and command queues are bounded at 64. These budgets
cover modeled Shoes-owned state, not total process RSS or all GotaTun state.

The TCP buffers bound the advertised receive window and in-flight data across
the tunnel. A 32 KiB window limits a single flow to roughly 5 Mbit/s at 50 ms RTT
or 2.6 Mbit/s at 100 ms RTT, before other bottlenecks. For higher-bandwidth,
higher-latency links, set `resource_limits.tcp_buffer_size` to, for example,
262144 (256 KiB). Four buffers are budgeted per flow, so retaining 256 connections
at that size also requires `tcp_memory_bytes: 268435456` (256 MiB); the default
32 MiB budget would admit only 32 connections. Tune against measured RTT,
throughput, and available memory rather than increasing buffers unconditionally.

Periodic logs report endpoint flow/drop counts and each peer's public key,
handshake age, and byte counters. Private keys and PSKs are redacted.

Preparation failures retain the old configuration. Successful reloads
disconnect existing tunnel flows and rebuild endpoints; sessions are not
migrated. Bind failures during activation can still terminate the process
after the old generation has stopped. Shutdown waits for buffered UDP tasks
to release their sockets before rebind. No host route cleanup is necessary.

## Configuration Structure

A configuration file is a YAML array containing one or more configuration entries. Each entry can be:

- **Server Config** - Defines a proxy server instance
- **TUN Config** - Defines a TUN/VPN device for transparent proxying
- **WireGuard Endpoint** - Defines a shared userspace WireGuard server/client
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
  key_exchange_groups: [X25519MLKEM768] # Optional; see TLS Key Exchange below

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

Accepts HTTP/1.0 and HTTP/1.1 CONNECT and absolute-form forwarding, plus
multiplexed TCP CONNECT over HTTP/2. H2 is detected from its connection preface;
cleartext H2 requires prior knowledge, not HTTP Upgrade. Authentication applies
independently to every H2 stream. A successful CONNECT response is sent only
after the destination connects.

H2 connections with no active tunnels close after 60 seconds; PINGs and rejected
authentication attempts do not extend that interval. Missing credentials receive
a 407 challenge. Incorrect credentials also begin connection shutdown, preventing
repeated password guesses on one carrier.

For HTTPS proxying, wrap HTTP in a TLS server and explicitly configure
`alpn_protocols: [h2, http/1.1]` on its TLS target. HTTP does not change the
parent layer's ALPN defaults. H2 GET/POST forwarding, extended CONNECT,
CONNECT-UDP, and HTTP/3 are not supported. This is standard HTTP proxying, not
NaiveProxy or XHTTP.

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

Auto-detects HTTP (including H2 CONNECT) or SOCKS5.

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

Replay protection uses a process-wide cache of at most 65,536 Auth-IDs, shared across credentials, listeners, and reloads. Entries remain protected through their timestamp's 120-second validity window; future-dated IDs can occupy a slot for about four minutes. A full cache rejects new authentication rather than evicting live entries. Heavy traffic from one credential can therefore exhaust capacity for other VMess users in the same process. A backward system-clock step also pauses authentication until the clock catches up.

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
      key_exchange_groups: [X25519MLKEM768] # Optional; see TLS Key Exchange below
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
      mldsa65_seed: string?     # Optional 32-byte ML-DSA-65 seed (unpadded base64url)
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
```

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

# Routing rules
rules: [RuleConfig]
```

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
  key_exchange_groups: [X25519MLKEM768] # Optional; see TLS Key Exchange below
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
  http_version: h1             # h1 (default) or h2
  resolve_hostname: false      # Resolve destinations locally before CONNECT
```

Both versions establish TCP CONNECT tunnels. When the H2 proxy is the first and
only hop, eligible routes reuse a connection for multiple concurrent tunnels.
Chained H2 hops use the carrier established through the selected prefix rather
than sharing tunnels across routes. H1 retains its existing one-tunnel-per-connection behavior.
There is no automatic version fallback or replay after a failed CONNECT.

For H2 over TLS, set `http_version: h2` here and `alpn_protocols: [h2]` on
the enclosing TLS client. The handshake must negotiate `h2`. Omitted or explicit
`http_version: h1` preserves legacy behavior: it sends HTTP/1.1 without checking
the negotiated ALPN. Set `alpn_protocols: [http/1.1]` on the enclosing TLS client
when the peer requires ALPN to match the HTTP version. Cleartext H2 uses prior
knowledge. See [examples/http2-proxy.yaml](examples/http2-proxy.yaml).

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
  key_exchange_groups: [X25519MLKEM768] # Optional; see TLS Key Exchange below
  protocol: ClientProxyConfig
```

### TLS Key Exchange

`key_exchange_groups` is an optional, ordered allowlist for ordinary TLS clients,
TLS server targets (including `default_tls_target`), and client/server
`quic_settings`. It applies to that TLS layer, regardless of the inner proxy
protocol. Supported names are case-sensitive:

- `X25519MLKEM768`: native rustls X25519 + ML-KEM-768 hybrid.
- `SecP256r1MLKEM768`: native rustls P-256 + ML-KEM-768 hybrid.
- `X25519`, `SecP256r1`, `SecP384r1`: classical groups.

Omitting the field preserves rustls defaults: currently X25519+ML-KEM-768 is
preferred, with classical fallback. An explicit list replaces those defaults;
the first client group normally supplies the initial key share. Empty lists, duplicates,
null, unknown names, standalone ML-KEM, and `SecP384r1MLKEM1024` are rejected.
No custom cryptographic implementations are used.

Client QUIC allowlists require a non-direct client at the first chain hop
(hop 0), where Shoes creates the QUIC transport. Explicit allowlists on direct
clients or later hops are rejected, including entries resolved from groups or
pools. Use ordinary TLS in a later hop's `protocol` when that hop needs its own
hybrid-protected tunnel.

To require hybrid exchange without classical fallback:

```yaml
key_exchange_groups: [X25519MLKEM768, SecP256r1MLKEM768]
```

Hybrid-only lists force TLS 1.3 and disable early application data. TLS 1.3
resumption remains enabled and still performs a fresh exchange using an allowed
hybrid group. Peers offering only classical groups or TLS 1.2 cannot connect.
For opportunistic hybrid exchange with explicit classical fallback, use a mixed
list such as `[X25519MLKEM768, X25519, SecP256r1]`.

Hybrid-only lists cannot be combined with `vision: true` on the same TLS layer:
Vision direct copy bypasses that layer's encryption. They also cannot be
combined with TUIC `zero_rtt_handshake: true`. Ordinary outer TLS or QUIC can
still protect a separate inner Vision connection. The setting does not apply to
REALITY, VLESS encryption, or ShadowTLS camouflage handshakes; it is rejected on
ShadowTLS configurations and with deprecated `shadowtls_password`.

Hybrid key exchange protects session-key establishment, not certificate
signatures. Certificate verification, fingerprints, and mTLS work as before.
`verify: false` without a trusted fingerprint still permits active impersonation.

### Reality Client
```yaml
protocol:
  type: reality
  public_key: string           # Server's X25519 public key (base64url)
  mldsa65_verify: string?      # Optional pinned 1952-byte ML-DSA-65 key (unpadded base64url)
  short_id: string             # Your client ID (hex, 0-16 chars)
  sni_hostname: string         # SNI to send (must match server's reality_targets key)
  cipher_suites: [string]      # Optional TLS 1.3 cipher suites (see below)
  vision: false                # Enable Vision (requires VLESS inner protocol)
  protocol: ClientProxyConfig  # Inner protocol (typically VLESS)
```

**Reality cipher suites:** Valid values are `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`. If not specified, all three are offered/supported.

Reality offers `X25519MLKEM768` first, with X25519 fallback. Servers follow the camouflage target's selected group; choose a PQ-preferring TLS 1.3 target to negotiate hybrid key exchange. Legacy X25519 clients remain supported. Debug logs report the authenticated connection's `negotiated_group`.

For Xray servers, use v25.5.16 or newer. Xray v25.4.30 and earlier cannot synthesize a hybrid-selected target handshake: when a PQ-capable target selects `X25519MLKEM768`, those servers forward to the real target and Shoes rejects its certificate. X25519 fallback does not prevent this failure because the target has already selected the hybrid group.

`mldsa65_seed` enables optional server signing. Clients with `mldsa65_verify` require a matching signature and reject unsigned or incorrectly signed connections. These fields correspond to Xray's `mldsa65Seed` and `mldsa65Verify`; neither replaces the existing X25519 key. Omit the fields to disable this extra authentication; empty or incorrectly sized values are invalid.

Enable server signing before distributing verification keys. The camouflage certificate flight must have room for the extra 3309-byte signature and DER overhead; insufficient capacity falls back to the real target instead of silently removing the signature. Removing signing later requires coordinating clients that already pin its key. Vision's direct mode relies on the inner TLS connection for payload encryption, not the outer Reality hybrid exchange.

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

NaiveProxy retains its own HTTP/2 client transport policies, independent of
`http_version: h2` on standard HTTP proxies: 256 KiB stream and connection
receive windows, the H2 library's 16 MiB response-header decoding limit, and no periodic
HTTP/2 PING watchdog. Peer stream limits and timeouts still apply. In particular,
Caddy v2.11.7 defaults to a one-minute request-body idle timeout, which can end a
quiet CONNECT tunnel; connection-level PINGs do not reset that timeout.

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

Configuration changes are automatically detected. `--no-reload` disables file watching; on Unix, SIGHUP still requests a reload.

On Linux, if directory permissions prevent watching a readable configuration's parent, startup falls back to direct file watches and logs a warning. In-place edits remain detectable, but atomic replacements may be missed; use SIGHUP or grant directory read permission when replacing files.

Replacement configurations, certificates, and DNS resolvers are prepared while the current listeners continue serving. A preparation failure leaves the current configuration running. Once preparation succeeds, listeners are replaced. A failure to activate replacements exits with status 1; there is no rollback after listeners are retired. Existing TCP connections may drain for `global_limits.reload_grace_secs` during successful reloads; QUIC connections are closed.

QUIC listener sockets must finish closing before replacements bind. Closing endpoints get up to one second for best-effort close delivery, then their drivers are stopped locally so peer-controlled timers cannot delay reloads. A five-second socket-release guard remains; exceeding it indicates a local cleanup failure and exits with an error rather than announcing a partially ready generation.

Candidate QUIC buffer sizes are used during DNS preparation, but `global_limits` admission caps change only at activation. DNS bootstrap over HTTP/3 or QUIC proxy chains therefore needs headroom under the live cap. A cap-increasing reload may require a restart if preparation cannot fit. Lowering a cap does not revoke existing reservations, including those made during preparation; new admissions are blocked until usage falls sufficiently. At cold startup, preparation uses the initial unlimited admission caps.

On macOS, edit the configured file path or use SIGHUP when writing through a hard-link alias in another directory. Automatic detection of such alias writes is backend-dependent. System-volume directory symlinks are resolved without watching their immutable links.

SIGINT/SIGTERM (or Ctrl-C on Windows) stop listeners and exit with status 0. Process shutdown does not wait for the TCP reload grace period.

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
  -d, --dry-run        Validate config and certificates without starting listeners
  --no-reload          Disable automatic reloads on file changes

COMMANDS:
  check <config.yaml>                           Alias for --dry-run
  version                                      Alias for --version
  generate-reality-keypair                       Generate Reality X25519 keypair
  generate-reality-mldsa65-keypair                Generate optional Reality ML-DSA-65 keys
  generate-shadowsocks-2022-password <cipher>    Generate Shadowsocks 2022 password
```

`check` and `--dry-run` exit with status 0 for valid configuration and 1 for errors. They do not open listeners, create a file watcher, or perform DNS bootstrap networking. Runtime failures such as unavailable bind addresses remain possible after a successful check.

## Tips

### Generate Keys

**Reality keypair:**
```bash
shoes generate-reality-keypair
```

**Optional Reality post-quantum authentication keys:**
```bash
shoes generate-reality-mldsa65-keypair
```
Keep `mldsa65_seed` on the server; distribute only `mldsa65_verify` to clients.

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
