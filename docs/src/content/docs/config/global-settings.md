---
title: Global settings
description: Default DNS, opt-in NTP, admission limits, remote-rule cache, QUIC buffers, and reload grace periods.
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
A `default_dns` object with omitted or empty `servers` uses the underlying
system resolver, including when it specifies only fake-IP settings.

```yaml
- global_settings:
    default_dns:
      servers: secure-dns
```

Listeners, TUN entries, and WireGuard inbounds with omitted or null `dns` inherit
this default. An explicit `dns` object replaces it completely, without merging
fields. In any explicit object, omitted or empty `servers` uses the underlying
system resolver; it never inherits the default again. `dns: {}` therefore opts
out. See [native DNS](/dns/native/) for system resolver caching.

An inline default creates one shared resolver group. If it enables fake IPs,
all inheriting inbounds share one mapping pool and state file, owned by
`global_settings` independently of listener identities.

Independent DNS bootstrap, NTP, rule downloads, ACME, WireGuard peer preparation,
and controller probes do not inherit this setting. See
[DNS configuration](/dns/configuration/) for upstream options and bootstrap requirements.

## NTP

Optional application-local clock correction, useful when shoes cannot change the
host clock. Omit `ntp` or set it to `null` to disable it. Providing the object opts
in; there is no `enabled` field. Disabled instances send no NTP requests.

```yaml
- global_settings:
    ntp:
      server: time.cloudflare.com:123
      interval_secs: 1800
      timeout_secs: 5
```

| Field | Default | Accepted values |
| --- | --- | --- |
| `server` | Required | Nonempty hostname or IP with explicit UDP port, normally `123`; IPv6 uses `[address]:port` |
| `interval_secs` | 1800 | Integer seconds, 60-86,400 |
| `timeout_secs` | 5 | Integer seconds, 1-30 |

The application clock is **system time + the last measured signed offset**.
NTP measurements always use uncorrected system time. shoes never writes the OS
clock or requires permission to set it. REALITY, VMess, Shadowsocks 2022, and
rustls certificate validation (including TLS-based DNS and QUIC) use the corrected
clock. Logs and other protocols retain their existing clocks. Certificate-source
validity checks (loading, accepting issued certificates, and selecting certificates
to serve) and renewal scheduling still use the OS clock. An incorrect OS clock can
therefore reject or suppress a certificate even after NTP synchronization.
REALITY's `max_time_diff` default and null behavior are unchanged.

One bounded synchronization attempt completes before runtime listeners,
WireGuard, and TUN start. Its timeout covers DNS and UDP exchange. Failure is
nonfatal: startup continues with zero offset, or the previous correction after
an NTP settings change. Refresh failures retain the last offset and retry after
`interval_secs`. As a conservative policy, `DENY`, `RSTR`, and `RATE` Kiss-of-Death
responses stop polling until NTP settings change or the service restarts. Other
stratum-zero responses, such as `INIT` or `STEP`, are discarded without stopping
address failover or periodic retries. Only plain 48-byte NTP replies are accepted;
extensions and authentication trailers are not supported.

Traffic goes directly through shoes' protected/policy-aware UDP sockets, not
proxy chains. Hostnames use native DNS, or managed-TUN bootstrap DNS, independently
of `default_dns`. Active/retained fake-IP ranges, protected TUN endpoints, and
managed TUN subnets cannot be NTP destinations. Prefer an IP literal on embedded
VPN hosts to avoid depending on DNS routed through the VPN itself.

**Limitations and trust:**

- This is unauthenticated UDP NTP, not NTS. The server or an on-path attacker can
  shift protocol time and TLS certificate validity checks. Use a trusted,
  reachable server and network.
- Preparation-time encrypted DNS bootstrap, HTTPS rule downloads, and certificate
  preparation occur before initial synchronization. An IP-literal NTP server
  avoids its own DNS dependency, but does not repair these earlier failures.
  `check` and `--dry-run` validate NTP settings without resolving or querying it.
- An OS clock step changes application time immediately; the offset is not a
  replacement clock. Correction waits until the next successful refresh. Avoid
  combining this feature with another service that steps the OS clock.
- Backward corrections, including disabling NTP or rollback, can pause VMess
  inbound authentication until its previous high-water time is reached. The pause
  can last the entire backward delta, not just the protocol's timestamp window.
  The replay cache is never reset, even by FFI stop/start in the same process.
- Shadowsocks 2022's salt cache expires on monotonic time. A sufficiently large
  backward correction can make an old handshake's timestamp valid again after
  its cached salt expires. OS clock rollback has the same limitation. Timestamp
  window widths are unchanged; NTP does not eliminate replay risks from clock steps.
- Ordinary skew and the 2036 NTP rollover are supported, not arbitrary broken-clock
  recovery. Raw dates before 1970 fail synchronization; offsets beyond about
  68 years can be ambiguous. Offsets are not persisted across process restarts.

See [reload behavior](/operations/reload/) and the complete
[`ntp.yaml` example](/examples/ntp/).

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
