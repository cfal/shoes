---
title: "NaiveProxy"
description: shoes naiveproxy configuration.
---

**Complete example:** [naiveproxy.yaml](/examples/naiveproxy/). Adapt addresses and secrets before deployment.

The field sketches below contain placeholders, not runnable values. Use a complete example when configuring a deployment.

## Server

```yaml
protocol:
  type: naiveproxy             # Aliases: naive
  users:                       # One or more users
    - name: string?            # Optional display name
      username: string         # Basic Auth username
      password: string         # Basic Auth password
  padding: true                # Default: true (enables padding protocol)
  udp_enabled: true            # Default: true (enables UDP over TCP)
  fallback: string?            # Optional path to serve static files for probe resistance
```

NaiveProxy implements HTTP/2 CONNECT with padding for censorship resistance. Should be used within TLS with `alpn_protocols: ["h2"]`.


## Client

```yaml
protocol:
  type: naiveproxy             # Aliases: naive
  username: string             # Basic Auth username
  password: string             # Basic Auth password
  padding: true                # Default: true (enables padding protocol)
```

NaiveProxy retains its own HTTP/2 client transport policies, independent of
`http_version: h2` on standard HTTP proxies: 256 KiB stream and connection
receive windows, the H2 library's 16 MiB response-header decoding limit, and no periodic
HTTP/2 PING watchdog. Peer stream limits and timeouts still apply. In particular,
Caddy v2.11.7 defaults to a one-minute request-body idle timeout, which can end a
quiet CONNECT tunnel; connection-level PINGs do not reset that timeout.

Session reuse is scoped to the selected proxy prefix. Each NaiveProxy handler
retains one reusable session; changing the prefix replaces it without closing
active tunnels. Alternating prefixes therefore opens new sessions, while warm
connections through the same prefix share a session. Concurrent cold connections
may establish separate sessions.
