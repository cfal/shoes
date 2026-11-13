---
title: ShadowQuic
---

ShadowQuic inbound authenticates users in the JLS QUIC/TLS handshake. It uses the
same `quinn-jls` 0.4 transport as the ShadowQuic reference implementation, alongside
Shoes' existing routing, DNS, proxy chains, sniffing, and TCP/UDP forwarding.

```yaml
- address: 0.0.0.0:443
  transport: quic
  protocol:
    type: shadowquic
    users:
      - username: alice
        password: replace-with-a-long-random-password
    server_name: example.com
    jls_upstream: example.com:443
    zero_rtt: true
    udp_enabled: true
  rules:
    - allow-all-direct
```

Configure the reference client's `username`, `password`, and `server_name` to
match. Its `addr` points to Shoes; ALPN is `h3`. The camouflage upstream must
support QUIC on the configured UDP port. Shoes generates the internal certificate;
omit `quic_settings`. This protocol requires a top-level `transport: quic` listener.

TCP CONNECT (`0x01`), UDP association over datagrams (`0x03`), UDP association over
unidirectional streams (`0x04`), and connection statistics (`0xff`, connection
opcode 1, subopcode 0) follow the reference framing. Both UDP modes support
multiple destinations and associations on one connection. Context IDs in each
direction are independent; out-of-order packets are buffered within fixed limits.

`zero_rtt` and `udp_enabled` default to `true`. Shoes waits for JLS authentication
before dispatching requests, including resumed connections. Disable `zero_rtt` to
reject replayable early data. Setting `udp_enabled: false` rejects UDP associations.

TCP BIND and SunnyQuic application authentication are unsupported, as in the
ShadowQuic inbound's supported proxy workflow. Remote user-management operations
return an extension error; manage users through Shoes configuration and reload.
User statistics and dynamic user management are not implemented by this adapter.
