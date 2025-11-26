# Configuration Reference

shoes uses YAML configuration files. Multiple configuration types can be combined in a single file or split across multiple files.

## Table of Contents
- [Configuration Structure](#configuration-structure)
- [Server Config](#server-config)
- [Server Protocols](#server-protocols)
- [Client Config](#client-config)
- [Client Protocols](#client-protocols)
- [Rules System](#rules-system)
- [Named Groups](#named-groups)
- [Named PEMs](#named-pems)
- [Advanced Features](#advanced-features)
- [Command Line](#command-line)

## Configuration Structure

A configuration file is a YAML array containing one or more configuration entries. Each entry can be:

- **Server Config** - Defines a proxy server instance
- **Client Config Group** - Defines reusable upstream proxy configurations
- **Rule Config Group** - Defines reusable routing rules
- **Named PEM** - Defines reusable certificate/key data

```yaml
# Server configs have 'address' or 'path'
- address: "0.0.0.0:8080"
  protocol: ...

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
```

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
```

**Note:** VMess AEAD mode is always enabled. The legacy `aead` field is deprecated.

### VLESS
```yaml
protocol:
  type: vless
  user_id: string
```

### Trojan
```yaml
protocol:
  type: trojan
  password: string
  shadowsocks:                 # Optional
    cipher: string
    password: string
```

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

### Port Forward (No-op)
```yaml
protocol:
  type: portforward            # Aliases: noop
```

Passes through the raw connection without protocol wrapping. Useful for testing or transparent proxying.

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
