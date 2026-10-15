# shoes

shoes is a high-performance multi-protocol proxy server written in Rust.

## Supported Protocols

### Proxy Protocols
- **HTTP/HTTPS**
- **SOCKS5** (with UDP ASSOCIATE)
- **Mixed** (auto-detect HTTP/SOCKS5)
- **VMess AEAD**
- **VLESS** (with fallback support)
- **Shadowsocks**
- **Trojan**
- **Snell v3**
- **Hysteria2**
- **TUIC v5**
- **AnyTLS**
- **NaiveProxy**
- **H2MUX** (supported with VMess, VLESS, Trojan, Shadowsocks, Snell)

### Transport Protocols
All server protocols plus:
- **SagerNet UDP over TCP** (for Shadowsocks, SOCKS5, AnyTLS, NaiveProxy)
- **ShadowTLS v3**
- **TLS**
- **WebSocket** (Shadowsocks SIP003)
- **XHTTP / SplitHTTP** (packet-up, stream-up, stream-one over HTTP/1.1, HTTP/2, HTTP/3)
- **XTLS Reality**
  - Hybrid-first X25519MLKEM768 key exchange and optional ML-DSA-65 server authentication
- **XTLS Vision** (for VLESS)

### TUN/VPN Mode
- **TUN device support** - Layer 3 VPN for transparent proxying
- Supported platforms: Linux, Android, iOS

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
    -d, --dry-run        Validate the config and certificates, then exit
    --no-reload          Disable automatic config reloading on file changes

COMMANDS:
    check <config.yaml>                       Alias for --dry-run
    version                                  Alias for --version
    generate-reality-keypair                  Generate a new Reality X25519 keypair
    generate-reality-mldsa65-keypair           Generate optional Reality ML-DSA-65 keys
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

### Mixed HTTP/SOCKS5 Server
```yaml
- address: 0.0.0.0:7890
  protocol:
    type: mixed
    username: myuser
    password: mypassword
```

### AnyTLS Server
```yaml
- address: 0.0.0.0:443
  protocol:
    type: tls
    tls_targets:
      "anytls.example.com":
        cert: cert.pem
        key: key.pem
        protocol:
          type: anytls
          users:
            - name: user1
              password: secret123
          udp_enabled: true
```

### NaiveProxy Server
```yaml
- address: 0.0.0.0:443
  protocol:
    type: tls
    tls_targets:
      "naive.example.com":
        cert: cert.pem
        key: key.pem
        alpn_protocols: ["h2"]
        protocol:
          type: naiveproxy
          users:
            - username: user1
              password: secret123
          padding: true
```

### TUN VPN
```yaml
- device_name: tun0
  address: 10.0.0.1
  netmask: 255.255.255.0
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
            user_id: b85798ef-e9dc-46a4-9a87-8da4499d36d0
```

On created Linux devices, TCPv4 transmit segmentation offload is selected
automatically when available. IPv6 continues using ordinary MTU-sized packets;
the configured MTU and TCP buffer sizes are unchanged. Set
`segmentation_offload: false` to disable it, or `true` to require it at startup.
Explicit enablement is not supported with `device_fd`, packet-information
headers, or non-Linux devices. Automatic setup falls back to ordinary packets
if offload initialization fails.

### XHTTP / SplitHTTP

See [examples/xhttp.yaml](examples/xhttp.yaml) for client/server configurations
covering all three modes and HTTP versions. `type: splithttp` is an alias for
`type: xhttp`; the inner `protocol` still handles authentication and destinations.

- `http_version: auto`: H1 for plaintext TCP, H2 for TLS/REALITY, H3 for QUIC.
  An explicit TLS ALPN of `http/1.1` selects H1. Explicit plaintext H2 uses h2c
  prior knowledge, not HTTP Upgrade.
- Client `mode: auto`: packet-up normally, stream-one under REALITY. Servers
  default to accepting all modes. Stream-one uses one request; stream-up uses
  separate streaming upload/download requests; packet-up uses bounded POSTs.
- Packet-up cannot transmit upload EOF. Use a streaming mode when the target
  must receive EOF before responding. After upload shutdown and packet acknowledgements,
  the client allows a one-second download tail before closing the session.
  Streaming bodies require unbuffered proxies. H1 stream-one closes the whole HTTP
  connection when its response ends; use H2/H3 or stream-up for remote-first half-close.
- H1/H2 preserve selected upstream proxy chains. H3 must be the first proxy hop;
  it reuses the existing QUIC/H3 dependencies, not Hysteria2 framing.
- `host` overrides HTTP authority independently of TLS SNI. Default Referer
  padding, path/query handling, packet sizing/pacing, and stream-up keepalives
  follow modern Xray. `limits` bounds sessions, buffered bytes, requests and
  setup/header/packet deadlines; `pool` bounds connections and idle retention.
  Split legs may use different carriers on the same selected route. H2/H3 admission
  respects peer stream capacity; draining carriers retain their connection slots.
  A full pool refuses new sessions rather than exceeding its configured cap.
- The server bounds the initial TCP HTTP header/preface to four seconds after
  transport setup (or the shorter configured setup timeout). H1 keep-alive idle
  periods and subsequent partial headers have no deadline. For exposed listeners,
  set `global_limits.max_connections` and `global_limits.max_connections_per_ip`.
- Xray 26.10.10's H1 packet-up uploader can lose pipelined requests when Go GC
  discards pooled connections with unread responses. Sustained uploads to slow
  destinations can therefore fail despite bounded server backpressure. Prefer
  H2/H3 or a streaming mode for these clients; disabling GC is not a production fix.
- Advanced placement/padding obfuscation, custom session IDs, separate downloads,
  full XMUX policy, and Vision over XHTTP are not supported. Unsupported options
  are rejected rather than silently ignored. Public CDN compatibility is not implied.
- Modern Xray clients work with Shoes REALITY servers. The existing Shoes REALITY
  client does not yet offer X25519MLKEM768, which Xray 26.10.10 requires; use ordinary
  TLS for Shoes-to-Xray XHTTP until that separate REALITY limitation is resolved.

## Similar Projects

- [apernet/hysteria](https://github.com/apernet/hysteria)
- [ihciah/shadow-tls](https://github.com/ihciah/shadow-tls)
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- [shadowsocks/shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)
- [EAimTY/tuic](https://github.com/EAimTY/tuic)
- [v2fly/v2ray-core](https://github.com/v2fly/v2ray-core)
- [XTLS/Xray-core](https://github.com/XTLS/Xray-core)
