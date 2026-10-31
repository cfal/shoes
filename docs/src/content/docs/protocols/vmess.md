---
title: "VMess"
description: Shoes vmess configuration.
---

**Complete example:** [vmess.yaml](/examples/vmess/). Adapt addresses and secrets before deployment.

The field sketches below contain placeholders, not runnable values. Use a complete example when configuring a deployment.

## Server

```yaml
protocol:
  type: vmess
  cipher: string               # any, aes-128-gcm, chacha20-poly1305, none
  user_id: string              # UUID
  udp_enabled: true            # Default: true (enables XUDP)
```

**Note:** VMess AEAD mode is always enabled. The legacy `force_aead` field is deprecated and non-AEAD mode is no longer supported.

Replay protection uses a process-wide cache of at most 65,536 Auth-IDs, shared across credentials, listeners, and reloads. Entries remain protected through their timestamp's 120-second validity window; future-dated IDs can occupy a slot for about four minutes. A full cache rejects new authentication rather than evicting live entries. Heavy traffic from one credential can therefore exhaust capacity for other VMess users in the same process. A backward system-clock step also pauses authentication until the clock catches up.


## Client

```yaml
protocol:
  type: vmess
  cipher: string
  user_id: string
  h2mux:                         # Optional multiplexing; see H2MUX
    max_connections: 4
    min_streams: 4
    max_streams: 0
    padding: false
```

**Note:** VMess AEAD mode is always enabled. The legacy `aead` field is deprecated.
