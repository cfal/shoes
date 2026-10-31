---
title: "VLESS"
description: Shoes vless configuration.
---

**Complete example:** [vless_over_tls.yaml](/examples/vless_over_tls/). Adapt addresses and secrets before deployment.

The field sketches below contain placeholders, not runnable values. Use a complete example when configuring a deployment.

## Server

```yaml
protocol:
  type: vless
  user_id: string              # UUID
  udp_enabled: true            # Default: true (enables XUDP)
  fallback: string?            # Optional fallback destination for failed auth (e.g., "127.0.0.1:80")
```


## Client

```yaml
protocol:
  type: vless
  user_id: string
  h2mux:                         # Optional multiplexing
    max_connections: 4
    min_streams: 4
    max_streams: 0
    padding: false
```

## Related settings

- [H2MUX](/protocols/h2mux/) describes client connection pooling and multiplexing fields.
- [Vision](/protocols/vision/) describes encryption-disabled VLESS over TLS or REALITY.
- [VLESS Encryption](/protocols/vless-encryption/) describes native client `encryption`, server `decryption`, protocol-level `vision`, and server `encryption_limits`.
