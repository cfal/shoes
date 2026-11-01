---
title: "TLS"
description: TLS listeners, client wrappers, and SNI-based targets.
---

**Complete example:** [https.yaml](/examples/https/). Adapt addresses and secrets before deployment.

REALITY and ShadowTLS server targets are configured inside this TLS listener;
their outbound settings are on the [REALITY](/protocols/reality/) and
[ShadowTLS](/protocols/shadowtls/) pages. See [TLS key exchange](/security/tls-key-exchange/)
for supported groups.

The field sketches below contain placeholders, not runnable values. Use a complete example when configuring a deployment.

## Server

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
      key_exchange_groups: [X25519MLKEM768] # Optional; see TLS key exchange
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
      cipher_suites: [string]  # Optional TLS 1.3 cipher suites
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


## Client

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
  key_exchange_groups: [X25519MLKEM768] # Optional; see TLS key exchange
  protocol: ClientProxyConfig
```
