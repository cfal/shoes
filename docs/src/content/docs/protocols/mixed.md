---
title: "Mixed (HTTP + SOCKS5)"
description: Shoes mixed (http + socks5) configuration.
---

**Complete example:** [mixed.yaml](/examples/mixed/). Adapt addresses and secrets before deployment.

The field sketches below contain placeholders, not runnable values. Use a complete example when configuring a deployment.

## Server

```yaml
protocol:
  type: mixed                  # Aliases: http+socks, socks+http
  username: string?
  password: string?
  udp_enabled: true            # Default: true (enables UDP ASSOCIATE for SOCKS5)
```

Auto-detects HTTP (including H2 CONNECT) or SOCKS5.
