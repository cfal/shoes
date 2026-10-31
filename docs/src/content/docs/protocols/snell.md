---
title: "Snell v3"
description: Shoes snell v3 configuration.
---

**Complete example:** [snell.yaml](/examples/snell/). Adapt addresses and secrets before deployment.

The field sketches below contain placeholders, not runnable values. Use a complete example when configuring a deployment.

## Server

```yaml
protocol:
  type: snell
  cipher: string               # aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305
  password: string
  udp_enabled: true            # Default: true
```


## Client

```yaml
protocol:
  type: snell
  cipher: string
  password: string
```
