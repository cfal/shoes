---
title: "Trojan"
description: shoes trojan configuration.
---

**Complete example:** [trojan_basic.yaml](/examples/trojan_basic/). Adapt addresses and secrets before deployment.

The field sketches below contain placeholders, not runnable values. Use a complete example when configuring a deployment.

## Server

```yaml
protocol:
  type: trojan
  password: string
  shadowsocks:                 # Optional encryption layer
    cipher: string
    password: string
```


## Client

```yaml
protocol:
  type: trojan
  password: string
  shadowsocks:                 # Optional
    cipher: string
    password: string
  h2mux:                         # Optional multiplexing; see H2MUX
    max_connections: 4
    min_streams: 4
    max_streams: 0
    padding: false
```
