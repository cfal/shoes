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
- **mieru** (client only, over mieru's TCP transport; not yet verified against a real server)
- **H2MUX** (supported with VMess, VLESS, Trojan, Shadowsocks, Snell)

### Outbound Tunnel Protocols
- **WireGuard** (outbound L3 tunnel over UDP)
- **AmneziaWG 2.0 / 3.0 / 3.1** (WireGuard with traffic obfuscation; 3.0 adds header protection, content padding and randomized timings, 3.1 adds random trailers and cookie suppression)

### QUIC-native Outbounds
Own their transport, so they are always the only hop in a chain:
- **Hysteria2** (TCP and UDP, with optional Salamander obfuscation)
- **TUIC v5** (TCP, and UDP over QUIC datagrams)

### Transport Protocols
All server protocols plus:
- **SagerNet UDP over TCP** (for Shadowsocks, SOCKS5, AnyTLS, NaiveProxy)
- **ShadowTLS v3**
- **TLS**
- **WebSocket** (Shadowsocks SIP003)
- **XTLS Reality**
- **XTLS Vision** (for VLESS)

### TUN/VPN Mode
- **TUN device support** - Layer 3 VPN for transparent proxying
- **Fake IP** - answers DNS locally from a private pool, so nothing resolves on the device
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
- **Rule-sets**: Match against sing-box `.srs` domain and IP lists (geosite, geoip)
- **Protocol sniffing**: Recover the destination hostname from the TLS ClientHello or the HTTP `Host` header, so domain rules keep working on connections opened straight to an IP address
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

### TUN VPN with Fake IP

A DNS query arriving over the TUN is answered from a private address pool instead of being resolved. The client connects to that address, and the TUN restores the original domain before routing, so the name is resolved at the far end of the proxy rather than on the device.

```yaml
- device_name: tun0
  address: 10.0.0.1
  netmask: 255.255.255.0
  mtu: 1500
  tcp_enabled: true
  udp_enabled: true      # required: DNS arrives over UDP
  fake_ip:
    network: "198.18.0.0/16"
    max_entries: 8192
    bypass_domains:
      - "*.local"
      - "captive.apple.com"
      - "*.pool.ntp.org"
      - "time.*.apple.com"
  rules:
    # Fake IP restores the domain before rules run, so hostname rules match
    # even though the client connected to 198.18.x.x.
    - masks: "example.com"
      action: allow
      client_chain:
        address: "proxy.example.com:443"
        protocol:
          type: socks
```

What it buys you:

- **No DNS leak.** Interception matches on destination *port*, not destination address, so an app that hardcodes `8.8.8.8` is caught the same as one that follows the system resolver. Queries that are not answered locally still travel through the tunnel rather than to a local resolver.
- **One less round trip.** The client never waits for a real resolution before it can connect.
- **Hostname routing for TUN traffic.** Rules see the domain rather than an address.

Details worth knowing:

- Only `A` is answered with a fake address. `AAAA` gets NODATA so the client falls back to `A` — handing out a fake IPv6 would be worse, since the client would prefer it and the tunnel may not carry IPv6. `HTTPS`/`SVCB`, `SRV`, `TXT`, `MX` and the rest are forwarded so they get real answers; blackholing them would cost ECH, ALPN hints and service discovery.
- `network` must be a range you do not route for real. `198.18.0.0/15` is reserved for benchmarking (RFC 2544), which is why it is the default.
- Past `max_entries` the pool recycles the least recently used mapping. Answers carry a 1-second TTL so an active domain keeps being refreshed and is not recycled while in use.
- `bypass_domains` exists because a fake address is useless to anything that must reach the host outside the tunnel: captive-portal probes, NTP, STUN, and `.local`/`.lan` names.

### Hysteria2 Client
```yaml
- address: 127.0.0.1:1080
  protocol:
    type: socks
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - address: "example.com:443"
          protocol:
            type: hysteria2
            password: "a strong password"
            # Optional. Both ends must agree.
            obfs:
              type: salamander
              password: "an obfuscation password"
          quic_settings:
            sni_hostname: "example.com"
```

The password is one opaque string; a server using username and password
authentication expects them joined as `"<username>:<password>"`. A mismatched
`obfs` password produces no error — neither end can decode the other, so it
looks exactly like an unreachable server.

### TUIC Client
```yaml
- address: 127.0.0.1:1080
  protocol:
    type: socks
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - address: "example.com:443"
          protocol:
            type: tuic
            uuid: "b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4"
            password: "a strong password"
          quic_settings:
            sni_hostname: "example.com"
```

Both protocols own their transport, so they are always the only hop in a chain,
and their TLS options live in `quic_settings` without a `transport: quic` line.

### WireGuard Client
```yaml
- address: 127.0.0.1:1080
  protocol:
    type: socks
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        address: "wg.example.com:51820"
        protocol:
          type: wireguard
          private_key: "CLIENT_PRIVATE_KEY_BASE64"
          peer_public_key: "SERVER_PUBLIC_KEY_BASE64"
          preshared_key: "OPTIONAL_PRESHARED_KEY_BASE64"
          local_addresses: "10.0.0.2/32"
          allowed_ips:
            - "0.0.0.0/0"
          persistent_keepalive: 25
```

### AmneziaWG Client (SOCKS5 inbound)
```yaml
- address: 127.0.0.1:1080
  protocol:
    type: socks
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        address: "awg.example.com:51820"
        protocol:
          type: amneziawg
          private_key: "CLIENT_PRIVATE_KEY_BASE64"
          peer_public_key: "SERVER_PUBLIC_KEY_BASE64"
          preshared_key: "OPTIONAL_PRESHARED_KEY_BASE64"
          local_addresses:
            - "10.8.0.2/32"
          allowed_ips:
            - "0.0.0.0/0"
            - "::/0"
          persistent_keepalive: 25
          mtu: 1280
          awg:
            jc: 4
            jmin: 64
            jmax: 256
            s1: 32
            s2: 32
            s3: 16
            s4: 16
            h1: "1000000-1000999"
            h2: "1001000-1001999"
            h3: "1002000-1002999"
            h4: "1003000-1003999"
```

### AmneziaWG Client (TUN VPN)
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
        address: "awg.example.com:51820"
        protocol:
          type: amneziawg
          private_key: "CLIENT_PRIVATE_KEY_BASE64"
          peer_public_key: "SERVER_PUBLIC_KEY_BASE64"
          local_addresses: "10.8.0.2/32"
          allowed_ips: "0.0.0.0/0"
          persistent_keepalive: 25
          mtu: 1280
          awg:
            h1: "1000000-1000999"
            h2: "1001000-1001999"
            h3: "1002000-1002999"
            h4: "1003000-1003999"
```

### AmneziaWG 3.0 Client

AmneziaWG 3.0 adds three things on top of the 2.0 parameters above, all in the same `awg` block. Set any of them and the tunnel runs as 3.0; omit them all and it stays 2.0.

```yaml
          awg:
            # 2.0 parameters as usual. Header protection reads its nonce from
            # the padding prefix, so s1-s4 must each be at least 12.
            jc: 4
            jmin: 64
            jmax: 256
            s1: 32
            s2: 32
            s3: 16
            s4: 16
            h1: "1000000-1000999"
            h2: "1001000-1001999"
            h3: "1002000-1002999"
            h4: "1003000-1003999"

            # 3.0: ChaCha20 over the message header. Base64 as an AmneziaWG
            # .conf writes it, or 64 hex characters as UAPI does.
            header_protection_key: "HEADER_PROTECTION_KEY_BASE64"
            # 3.0: extra random padding inside the AEAD envelope, in bytes.
            content_padding_addition: "0-64"
            # 3.0: randomized WireGuard timings, in seconds. Each is optional;
            # unset keeps the standard WireGuard constant.
            rekey_after_time: "110-130"
            rekey_timeout: "5"
            reject_after_time: "170-190"
            keepalive_timeout: "8-12"
            max_handshake_attempts: "18-20"
            persistent_keepalive_interval: "20-30"
```

Every value that shapes the wire format has to match the server exactly — `h1`-`h4`, `s1`-`s4`, the junk parameters, the header protection key and the content padding. A mismatch is not reported by either end; the peer simply cannot recognise the packets as WireGuard, and the handshake never completes. The timing ranges are local: they only shape when this peer acts, so the two ends may differ.

`h1`-`h4` may be omitted entirely, in which case the standard WireGuard message types (1, 2, 3, 4) are used — useful for a tunnel that wants only the 3.0 features.

### AmneziaWG 3.1 Client

3.1 adds two booleans, both off unless you set them. They are independent of the 3.0 parameters: a 2.0 tunnel may turn them on without adopting anything else, and a tunnel that sets neither behaves exactly as it did before 3.1 existed.

```yaml
          awg:
            # 2.0 and/or 3.0 parameters as usual.
            jc: 4
            jmin: 64
            jmax: 256

            # 3.1: append a random number of bytes to each datagram, so a
            # message with a fixed size stops having one. MUST match the
            # server — see below.
            random_trailers: true
            # 3.1: never answer with a cookie reply. Local to this peer.
            disable_cookies: true
```

`random_trailers` has to be enabled on **both** peers or on neither. A receiver only tolerates bytes past the end of a handshake message when it is on, so with it on at one end only the handshake fails in the direction that grew. Handshake messages carry the extra bytes after the message, outside the MAC; transport packets get no trailer at all and widen their content padding instead, and only when `content_padding_addition` is unset — an explicit value wins.

Unlike every other wire-shaping mismatch, this one does not leave you with a dead tunnel. A peer's setting is not on the wire and a peer that disagrees does not answer, so there is nothing to negotiate — instead, a tunnel that has been given packets to send and has still not completed a handshake after 15 seconds rebuilds itself with the setting flipped, and keeps alternating until one of them works. Whichever setting completes the handshake is the one it stays on. The flip is logged at warning level and names the setting to fix, so a config that disagrees with the server costs a delay rather than an outage.

`disable_cookies` withholds the cookie reply. The rate limiter still decides a cookie is warranted, so a peer under load gets silence instead of a retry hint. It changes only what this peer sends, so the two ends need not agree.

> **Note:** WireGuard and AmneziaWG work as client/outbound only — each creates a UDP-backed L3 tunnel to the server. Neither supports multi-hop chains yet; they must be the sole hop. All three modes share one code path: plain WireGuard is AmneziaWG with every obfuscation parameter left at its default.

## Similar Projects

- [apernet/hysteria](https://github.com/apernet/hysteria)
- [ihciah/shadow-tls](https://github.com/ihciah/shadow-tls)
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- [shadowsocks/shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)
- [EAimTY/tuic](https://github.com/EAimTY/tuic)
- [v2fly/v2ray-core](https://github.com/v2fly/v2ray-core)
- [XTLS/Xray-core](https://github.com/XTLS/Xray-core)
