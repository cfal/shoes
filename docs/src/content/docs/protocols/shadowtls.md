---
title: "ShadowTLS"
description: Shoes shadowtls configuration.
---

**Complete example:** [shadowtls_v3_local_handshake.yaml](/examples/shadowtls_v3_local_handshake/). Adapt addresses and secrets before deployment.

The field sketches below contain placeholders, not runnable values. Use a complete example when configuring a deployment.

## Server

Configure a `type: tls` server with `shadowtls_targets`. See the
[TLS server reference](/protocols/tls/#server) for handshake targets, passwords,
and inner protocol settings.

## Client

```yaml
protocol:
  type: shadowtls
  password: string
  sni_hostname: string?        # Optional SNI override
  protocol: ClientProxyConfig
```
