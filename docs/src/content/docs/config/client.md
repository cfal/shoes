---
title: "Client Config"
description: shoes client config configuration.
---

Used in rules to specify upstream proxies.

This is a field sketch, not a complete config. Set `address` to the proxy
endpoint and choose a [client protocol](/protocols/socks5/); reference the
client from a [chain or named group](/routing/chains/). Optional `name`
identifies an inline group member in the controller. `tcp_settings` applies to
TCP; `quic_settings` applies to QUIC. See [TLS key exchange](/security/tls-key-exchange/)
for supported groups and [certificates](/security/certificates/) for identity sources.

```yaml
address: string                # Proxy server address (e.g., "proxy.example.com:1080")
protocol: ClientProxyConfig
name: string?                 # Optional named group member
transport: tcp | quic          # Default: tcp; WireGuard only: udp (default, required)
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
  key_exchange_groups: [X25519MLKEM768] # Optional; see TLS key exchange
```

WireGuard clients use `address` for their peer endpoint and reject TCP/QUIC
socket settings. See [WireGuard](/protocols/wireguard/) for their protocol fields.

For QUIC, an omitted `sni_hostname` sends SNI for a hostname address; explicit
`null` suppresses wire SNI. Certificate verification still uses the proxy
address when no SNI is sent, including literal IPv4 and IPv6 addresses. An
explicit hostname override is used for both SNI and verification.
