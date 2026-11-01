---
title: "TUIC v5"
description: shoes tuic v5 configuration.
---

**Complete example:** [tuic_v5.yaml](/examples/tuic_v5/). Adapt addresses and secrets before deployment.

The field sketches below contain placeholders, not runnable values. Use a complete example when configuring a deployment.

## Server

```yaml
protocol:
  type: tuic                   # Aliases: tuicv5
  uuid: string                 # UUID
  password: string
  zero_rtt_handshake: false    # Default: false (enables 0-RTT for lower latency)
```

## Client

**Complete client example:** [quic_clients.yaml](/examples/quic_clients/).

```yaml
address: proxy.example.com:443
quic_settings:
  sni_hostname: proxy.example.com
  verify: true
protocol:
  type: tuic # alias: tuicv5; version 5 only
  uuid: 01234567-89ab-4def-8123-456789abcdef
  password: your-password
  udp_enabled: true
  udp_relay_mode: native # native QUIC datagrams or quic unidirectional streams
  heartbeat_interval_secs: 10 # 1..30
```

Transport defaults to QUIC, ALPN to `h3`. Placement and TLS settings follow the
[Hysteria2 client rules](/protocols/hysteria2/#client). QUIC datagrams are required for heartbeats even
with stream-mode UDP. Authentication uses the current TLS session exporter;
TUIC has no authentication acknowledgement or TCP success response. Wrong
credentials surface when the peer closes the connection, not necessarily during
stream setup. Client 0-RTT is not supported.

UDP associations share a bounded, connection-owned receiver. Association IDs
are never reused within a connection; exhaustion creates a new connection while
existing flows retain the old one. Explicit shutdown sends DISSOCIATE with a
deadline; dropping an association queues a bounded best-effort notification.
Up to 64 command writers run concurrently. Admission has a five-second deadline;
once admitted, a write completes even if its caller is cancelled, or fails when
the connection closes. This prevents partial commands from disrupting other flows.
The default incoming uni-stream credit is 1024 (reduced by an explicit
`max_streams_per_connection`), with at most 64 concurrent command readers.
Very small stream limits can make external servers reject bursty stream-mode
UDP replies; prefer native mode when strict stream limits are required.
