---
title: "Hysteria2"
description: shoes hysteria2 configuration.
---

**Complete example:** [hysteria2.yaml](/examples/hysteria2/). Adapt addresses and secrets before deployment.

The field sketches below contain placeholders, not runnable values. Use a complete example when configuring a deployment.

## Server

```yaml
protocol:
  type: hysteria2
  password: string
  udp_enabled: true            # Default: true
```

## Client

**Complete client example:** [quic_clients.yaml](/examples/quic_clients/).

```yaml
address: proxy.example.com:443
quic_settings:
  sni_hostname: proxy.example.com
  verify: true
protocol:
  type: hysteria2 # alias: hy2
  password: your-password
  udp_enabled: true
```

Transport defaults to QUIC and ALPN to `h3`. TLS verification, certificate
fingerprints, client certificates, and key-exchange groups use `quic_settings`.
The protocol must be outermost at chain hop 0. It can carry subsequent
stream-based proxies, but cannot follow another proxy or run inside TLS,
WebSocket, or another stream wrapper.

TCP streams and UDP associations share an authenticated connection. Connection
replacement never migrates existing flows or replays application bytes. UDP
queues and fragmented-packet reassembly are bounded; overload drops packets.
UDP requires permission from the server. TCP target errors surface when reading
the response, allowing application writes before the server's success response.
HTTP/3 authentication headers are limited to 16 KiB decoded. The H3 dependency
rejects buffered frames larger than 1 MiB from their declared length and
discards unknown-frame payloads incrementally, without a lifetime byte budget.
These limits do not apply to proxied TCP or UDP traffic.

Congestion control is adaptive (Quinn's default CUBIC), with unknown receive
bandwidth advertised as zero. Brutal and fixed-bandwidth negotiation are not
implemented; `up_mbps`, `down_mbps`, and 0-RTT options are rejected.

Optional `obfs: {type: salamander, password: your-obfs-password}` wraps QUIC
datagrams with Salamander obfuscation (minimum four password bytes). The peer
must use the same setting. It adds eight bytes per wire datagram; the minimum
path UDP payload is therefore 1208 bytes. shoes' Hysteria2 server does not yet
implement this option.

Optional port hopping uses a dedicated connection-owned endpoint:

```yaml
protocol:
  type: hysteria2
  password: your-password
  hopping:
    ports: '443,20000-30000' # Inclusive ranges, nonzero ports
    interval_secs: 30       # Minimum 5; default 30
    # Alternatively: min_interval_secs: 5, max_interval_secs: 30
```

All listed ports must reach the same server connection state (usually through
server-side UDP port redirection). A hostname is resolved once per connection;
hops retain that IP and randomly choose a destination port. Each hop creates a
fresh protected, interface-bound socket and retains the preceding socket for
late replies until the next hop. Hopping can be combined with Salamander.
