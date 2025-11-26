# shoes

shoes is a high-performance multi-protocol proxy server written in Rust.

## Supported Protocols

### Proxy Protocols
- **HTTP/HTTPS**
- **SOCKS5**
- **VMess AEAD**
- **VLESS**
- **Shadowsocks**
- **Trojan**
- **Snell v3**
- **Hysteria2**
- **TUIC v5**

### Transport Protocols
All server protocols plus:
- **SagerNet UDP over TCP** (for Shadowsocks and SOCKS5)
- **ShadowTLS v3**
- **TLS**
- **WebSocket** (Shadowsocks SIP003)
- **XTLS Reality**
- **XTLS Vision** (for VLESS)

### Supported Ciphers
- **VMess**: `aes-128-gcm`, `chacha20-poly1305`, `none`
- **Shadowsocks**: `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-ietf-poly1305`
- **Snell v3**: `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`

## Features

- **Multi-transport**: TCP or QUIC for all protocols
- **TLS with SNI routing**: Route by Server Name Indication
- **Upstream proxy chaining**: Multi-hop chains with load balancing
- **Rule-based routing**: Route by IP/CIDR or hostname masks
- **Named PEM certificates**: Define once, reference everywhere
- **TLS fingerprint authentication**: Certificate pinning for TLS/QUIC
- **Hot reloading**: Apply config changes without restart
- **Unix socket support**: Bind to Unix domain sockets

For advanced access control (IP allowlist/blocklists), see [tobaru](https://github.com/cfal/tobaru).

## Installation

Precompiled binaries for x86_64 and Apple aarch64 are available on [Github Releases](https://github.com/cfal/shoes/releases).

Or install with cargo:

```bash
cargo install shoes
```

## Usage

```
shoes [OPTIONS] <config.yaml> [config.yaml...]

OPTIONS:
    -t, --threads NUM    Set the number of worker threads (default: CPU count)
    -d, --dry-run        Parse the config and exit
    --no-reload          Disable automatic config reloading on file changes

COMMANDS:
    generate-reality-keypair                  Generate a new Reality X25519 keypair
    generate-shadowsocks-2022-password <cipher>    Generate a Shadowsocks password
```

### Examples
```bash
# Run with a single config file
shoes config.yaml

# Run with multiple config files
shoes server1.yaml server2.yaml rules.yaml

# Run with custom thread count
shoes --threads 8 config.yaml

# Validate configuration without starting
shoes --dry-run config.yaml

# Run without hot-reloading
shoes --no-reload config.yaml

# Generate Reality keypair
shoes generate-reality-keypair

# Generate Shadowsocks 2022 cipher password
shoes generate-shadowsocks-2022-password 2022-blake3-aes-256-gcm
```

## Configuration

See [CONFIG.md](./CONFIG.md) for the complete YAML configuration reference.

## Examples

See the [examples](./examples) directory for all examples.

### Basic VMess Server
```yaml
- address: 0.0.0.0:16823
  protocol:
    type: vmess
    cipher: chacha20-poly1305
    user_id: b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4
    udp_enabled: true
```

### VLESS with Vision over TLS
```yaml
- address: 0.0.0.0:443
  protocol:
    type: tls
    tls_targets:
      "vless.example.com":
        cert: cert.pem
        key: key.pem
        vision: true
        alpn_protocols: ["http/1.1"]
        protocol:
          type: vless
          user_id: b85798ef-e9dc-46a4-9a87-8da4499d36d0
          udp_enabled: true
```

### Reality Server
```yaml
- address: 0.0.0.0:443
  protocol:
    type: tls
    reality_targets:
      "www.example.com":
        private_key: "YOUR_BASE64URL_PRIVATE_KEY"
        short_ids: ["0123456789abcdef", ""]
        dest: "www.example.com:443"
        protocol:
          type: vless
          user_id: b85798ef-e9dc-46a4-9a87-8da4499d36d0
          udp_enabled: true
```

### Reality Client
```yaml
- address: 127.0.0.1:1080
  protocol:
    type: socks
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        address: "server.example.com:443"
        protocol:
          type: reality
          public_key: "SERVER_PUBLIC_KEY"
          short_id: "0123456789abcdef"
          sni_hostname: "www.example.com"
          protocol:
            type: vless
            user_id: b85798ef-e9dc-46a4-9a87-8da4499d36d0
```

### Hysteria2 Server
```yaml
- address: 0.0.0.0:443
  transport: quic
  quic_settings:
    cert: cert.pem
    key: key.pem
    alpn_protocols: ["h3"]
  protocol:
    type: hysteria2
    password: supersecret
    udp_enabled: true
```

### TUIC v5 Server
```yaml
- address: 0.0.0.0:443
  transport: quic
  quic_settings:
    cert: cert.pem
    key: key.pem
  protocol:
    type: tuic
    uuid: d685aef3-b3c4-4932-9a9d-d0c2f6727dfa
    password: supersecret
```

## Similar Projects

- [apernet/hysteria](https://github.com/apernet/hysteria)
- [ihciah/shadow-tls](https://github.com/ihciah/shadow-tls)
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- [shadowsocks/shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)
- [EAimTY/tuic](https://github.com/EAimTY/tuic)
- [v2fly/v2ray-core](https://github.com/v2fly/v2ray-core)
- [XTLS/Xray-core](https://github.com/XTLS/Xray-core)
