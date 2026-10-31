---
title: "QUIC Socket Buffers"
description: Shoes quic socket buffers configuration.
---

`global_settings.quic_socket_buffer` requests the UDP receive and send buffer size
for each QUIC listener, outbound QUIC proxy endpoint and DNS-over-HTTP/3 socket.
It defaults to **8388608 bytes (8 MiB)**; allowed values are 65536 through
16777216 bytes. This is per socket, not per QUIC connection, and is separate
from QUIC flow-control windows and userspace buffer admission limits. Ordinary
UDP forwarding sockets keep their existing buffer sizes.

```yaml
- global_settings:
    quic_socket_buffer: 8388608
```

Requests are best-effort: if the OS clamps or rejects the size, startup continues
with the available buffers. Shoes checks the resulting sizes and warns at most
once per receive/send direction per process when the request is not satisfied
or cannot be verified. Smaller buffers can limit throughput during bursts.

On Linux, administrators can allow the default request with
`net.core.rmem_max=8388608` and `net.core.wmem_max=8388608`; Shoes does not change
sysctls or require elevated privileges for buffer tuning. Linux reports double
the requested buffer size for accounting overhead; Shoes normalizes this when
checking the result. The limits do not preallocate their maximum memory, but
queued traffic consumes memory across all endpoints. Raising kernel ceilings
does not resize existing sockets. Configuration reloads recreate QUIC listeners
and can disconnect their active sessions; see [Hot Reloading](/operations/reload/).
