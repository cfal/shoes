---
title: "Server Config"
description: shoes server config configuration.
---

WireGuard servers require one literal UDP address with a nonzero port, or omit
the bind location when `peer_client_chain` is configured. They do not support
port ranges, multiple bind addresses, or Unix socket paths. See [WireGuard](/protocols/wireguard/).

This is a field sketch, not one runnable listener: choose one bind form and a
concrete [server protocol](/protocols/socks5/). `name` optionally gives the
listener a stable dashboard identity. Omitted `rules` allow direct forwarding;
use [routing rules](/routing/rules/) to restrict destinations or select upstreams.
Optional `dns` selects the listener's resolver (see [DNS](/dns/configuration/) and
[Fake DNS](/dns/fake/)); `sniff: true` enables [TCP hostname sniffing](/routing/rules/#tcp-hostname-sniffing).

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
name: string?                 # Optional dashboard identity
sniff: false                  # TCP hostname sniffing, default false
dns: {servers: system}        # Optional resolver configuration

# Transport layer (default: tcp)
transport: tcp | quic          # WireGuard only: udp (default, required)

# TCP settings (only when transport: tcp)
tcp_settings:
  no_delay: true               # Default: true

# QUIC settings (required when transport: quic)
quic_settings:
  cert: string                 # TLS certificate (path or named PEM)
  key: string                  # TLS private key (path or named PEM)
  certificate_source: string   # Alternative managed certificate source
  alpn_protocols: [string]     # Optional ALPN protocols
  client_ca_certs: [string]    # Optional client CA certificates
  client_fingerprints: [string] # Optional client certificate fingerprints
  num_endpoints: int           # Optional, 0 = auto (based on thread count)
  key_exchange_groups: [X25519MLKEM768] # Optional; see TLS key exchange

# Routing rules (default: allow-all-direct; WireGuard requires explicit nonempty rules)
rules: string | [RuleConfig]
```

Use either `certificate_source` or `cert`/`key`, not both; see
[certificate sources](/security/certificates/). For supported hybrid and
classical groups, see [TLS key exchange](/security/tls-key-exchange/).
