---
title: "AnyTLS"
description: Shoes anytls configuration.
---

**Complete example:** [anytls.yaml](/examples/anytls/). Adapt addresses and secrets before deployment.

The field sketches below contain placeholders, not runnable values. Use a complete example when configuring a deployment.

## Server

```yaml
protocol:
  type: anytls
  users:                       # One or more users
    - name: string?            # Optional display name
      password: string         # User password
  udp_enabled: true            # Default: true (enables UDP over TCP)
  padding_scheme: [string]?    # Optional custom padding (e.g., ["stop=8", "0=30-30"])
  fallback: string?            # Optional fallback destination for failed auth
```

AnyTLS is a TLS-based multiplexing proxy protocol with traffic obfuscation. Should be used within TLS or Reality.


## Client

```yaml
protocol:
  type: anytls
  password: string             # User password
  udp_enabled: true            # Default: true (enables UDP over TCP)
  padding_scheme: [string]?    # Optional custom padding scheme
  idle_session_check_interval_secs: 30
  idle_session_timeout_secs: 30
  min_idle_session: 0
  disable_reuse: false
```

TCP and UDP-over-TCP share an idle-session pool. Each request exclusively checks
out the most recently returned session for its selected proxy route; concurrent
requests create additional sessions when none are idle. Warm reuse avoids new
socket and transport handshakes, including in proxy chains and wrapped transports.

Idle checks expire the oldest sessions beyond `min_idle_session`. This minimum is
a retention floor across the client's routes, not prewarming or a connection cap.
Both interval settings use integer seconds; values at or below 5 select the
default of 30 seconds. `disable_reuse` closes sessions after each flow.
Active flows are not expired and can drain after configuration reload; idle
sessions close when their owning client is retired. Valid server padding updates
apply to the client's current and future sessions without restarting padding counters.

A clean peer FIN stops forwarding uploads for that stream. Late upload bytes are
discarded so the relay can finish draining buffered response data without affecting
the next session lease. Local shutdown and rejected stream opens still reject writes.
