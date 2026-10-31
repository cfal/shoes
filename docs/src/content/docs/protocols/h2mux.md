---
title: "H2MUX"
description: Shoes h2mux configuration.
---

**Complete example:** [h2mux_client.yaml](/examples/h2mux_client/). Adapt addresses and secrets before deployment.

## Client


H2MUX multiplexes multiple proxy streams over a single HTTP/2 connection, reducing connection overhead. Compatible with sing-box. Available for VMess, VLESS, and Trojan client protocols.

```yaml
h2mux:
  max_connections: 4           # Maximum connections to maintain (default: 4)
  min_streams: 4               # Min streams before opening new connection (default: 4)
  max_streams: 0               # Max streams per connection, 0 = unlimited (default: 0)
  padding: false               # Enable padding for traffic obfuscation (default: false)
```

**Server support:** H2MUX is auto-detected on servers. No configuration needed.
