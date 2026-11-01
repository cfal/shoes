---
title: Global settings
description: Default DNS, admission limits, remote-rule cache, QUIC buffers, and reload grace periods.
---

Use at most one `global_settings` entry across all configuration files. Omitted
admission caps are unlimited; transport windows and buffers have finite defaults.
An omitted, null, or empty `global_settings` entry uses those defaults.

This is a configuration fragment, not a listener:

```yaml
- global_settings:
    max_connections: 1024
    max_streams_per_connection: 128
    reload_grace_secs: 300
    rule_cache_dir: ./rule-cache
```

`rule_cache_dir` is optional. Omit it or set it to `null` to retain remote rules
only in memory. One configured directory serves all remote sources; per-source
cache directories and standalone `rule_cache_dir` entries are not accepted.
Its path is relative to the declaring configuration file. See
[remote rule sources](/routing/remote-sources/) for ownership, permissions,
bootstrap, and restart requirements.

`global_limits` remains a compatibility alias, but logs a warning and will be
deprecated. Rename it to `global_settings`. Both names count toward the same
single-entry limit, even for empty entries. Serialization always uses
`global_settings`.

## Default DNS

`default_dns` accepts the same object as a listener's `dns`: a `servers` group
reference or inline upstreams, and optional `fake_ip` settings.

```yaml
- global_settings:
    default_dns:
      servers: secure-dns
```

Listeners, TUN entries, and WireGuard inbounds with omitted or null `dns` inherit
this default. An explicit `dns` object replaces it completely, without merging
fields. In any explicit object, omitted or empty `servers` uses the underlying
system resolver; it never inherits the default again. `dns: {}` therefore opts
out, and `dns: {servers: system}` selects explicit system DNS without application
memoization. See [native DNS](/dns/native/).

An inline default creates one shared resolver group. If it enables fake IPs,
all inheriting inbounds share one mapping pool and state file. Explicit per-inbound
overrides retain their own existing ownership rules.

Without `default_dns`, existing system defaults are unchanged. Independent DNS
bootstrap, rule downloads, ACME, WireGuard peer preparation, and controller probes
do not inherit this setting. See [DNS configuration](/dns/configuration/) for
upstream options and bootstrap requirements.

## Admission caps

Each cap accepts a positive integer, or omission/null for unlimited. Zero is
rejected. `max_streams_per_connection` additionally cannot exceed 65,535.

| Field | Applies to |
| --- | --- |
| `max_connections` | Admitted connections across the process |
| `max_connections_per_ip` | Admitted connections per peer IP |
| `max_streams` | Admitted logical streams across the process |
| `max_streams_per_connection` | Logical streams within one connection |
| `max_udp_destinations` | Admitted UDP destinations |
| `quic_memory_bytes` | QUIC memory admission budget, in bytes |

Admission budgets are not measurements of total process RSS. Lowering a cap
does not revoke existing reservations; new work is blocked until usage permits
it. See [reload behavior](/operations/reload/).

## Buffers and reload

Sizes below are integer bytes, not strings such as `2MiB`.

| Field | Default | Accepted range |
| --- | --- | --- |
| `quic_receive_window` | 2,097,152 | 65,536-67,108,864 |
| `quic_send_window` | 2,097,152 | 65,536-67,108,864 |
| `quic_stream_window` | 262,144 | 16,384-67,108,864 |
| `quic_dns_memory_bytes` | 16,777,216 | 1,048,576-1,073,741,824 |
| `quic_socket_buffer` | 8,388,608 | 65,536-16,777,216 |
| `reload_grace_secs` | 300 seconds | 0-86,400 seconds |

`quic_dns_memory_bytes` is an admission estimate for the DNS library's private
HTTP/3 transport, not a hard buffer limit. `quic_socket_buffer` requests OS socket
buffer sizes; the OS can grant less. See [QUIC socket buffers](/config/quic-sockets/).

Unknown fields and duplicate global-settings entries are rejected. Per-protocol
limits, including [XHTTP](/protocols/xhttp/), [TUN](/config/tun/#resource-limits-and-device-framing), and
[WireGuard](/protocols/wireguard/), remain separate settings.
