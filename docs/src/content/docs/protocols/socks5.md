---
title: "SOCKS5"
description: Shoes socks5 configuration.
---

**Complete example:** [socks_basic.yaml](/examples/socks_basic/). Adapt addresses and secrets before deployment.

The field sketches below contain placeholders, not runnable values. Use a complete example when configuring a deployment.

## Server

```yaml
protocol:
  type: socks                  # Aliases: socks5
  username: string?
  password: string?
  udp_enabled: true            # Default: true (enables UDP ASSOCIATE)
```


## Client

```yaml
protocol:
  type: socks
  username: string?
  password: string?
```
