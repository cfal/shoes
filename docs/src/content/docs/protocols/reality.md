---
title: "Reality"
description: Shoes reality configuration.
---

**Complete example:** [reality_basic.yaml](/examples/reality_basic/). Adapt addresses and secrets before deployment.

The field sketches below contain placeholders, not runnable values. Use a complete example when configuring a deployment.

## Server

Configure a `type: tls` server with `reality_targets`. See the
[TLS server reference](/protocols/tls/#server) for target selection, credentials,
and inner protocol settings.

## Client

See the [basic client](/examples/reality_client/) and
[Vision client](/examples/reality_vision_client/) examples for complete files.

```yaml
protocol:
  type: reality
  public_key: string           # Server's X25519 public key (base64url)
  mldsa65_verify: string?      # Optional pinned 1952-byte ML-DSA-65 key (unpadded base64url)
  short_id: string             # Your client ID (hex, 0-16 chars)
  sni_hostname: string         # SNI to send (must match server's reality_targets key)
  cipher_suites: [string]      # Optional TLS 1.3 cipher suites
  vision: false                # Enable Vision (requires VLESS inner protocol)
  protocol: ClientProxyConfig  # Inner protocol (typically VLESS)
```

**Reality cipher suites:** Valid values are `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`. If not specified, all three are offered/supported.

Reality offers `X25519MLKEM768` first, with X25519 fallback. Servers follow the camouflage target's selected group; choose a PQ-preferring TLS 1.3 target to negotiate hybrid key exchange. Legacy X25519 clients remain supported. Debug logs report the authenticated connection's `negotiated_group`.

For Xray servers, use v25.5.16 or newer. Xray v25.4.30 and earlier cannot synthesize a hybrid-selected target handshake: when a PQ-capable target selects `X25519MLKEM768`, those servers forward to the real target and Shoes rejects its certificate. X25519 fallback does not prevent this failure because the target has already selected the hybrid group.

`mldsa65_seed` enables optional server signing. Clients with `mldsa65_verify` require a matching signature and reject unsigned or incorrectly signed connections. These fields correspond to Xray's `mldsa65Seed` and `mldsa65Verify`; neither replaces the existing X25519 key. Omit the fields to disable this extra authentication; empty or incorrectly sized values are invalid.

Enable server signing before distributing verification keys. The camouflage certificate flight must have room for the extra 3309-byte signature and DER overhead; insufficient capacity falls back to the real target instead of silently removing the signature. Removing signing later requires coordinating clients that already pin its key. Vision's direct mode relies on the inner TLS connection for payload encryption, not the outer Reality hybrid exchange.
