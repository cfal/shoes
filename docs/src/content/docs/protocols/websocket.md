---
title: "WebSocket"
description: shoes websocket configuration.
---

**Complete example:** [wss_vmess.yaml](/examples/wss_vmess/). Adapt addresses and secrets before deployment.

The field sketches below contain placeholders, not runnable values. Use a complete example when configuring a deployment.

## Server
```yaml
protocol:
  type: websocket              # Aliases: ws
  targets:
    - matching_path: string?   # Optional path filter (e.g., "/ws")
      matching_headers:        # Optional header filters
        X-Custom-Header: "value"
      max_early_data: 0        # 0: automatic standard-header reception, up to 2048 bytes
      early_data_header_name: string? # With positive max: empty/omitted selects path suffix
      protocol: ServerProxyConfig
      ping_type: ping-frame    # disabled | ping-frame | empty-frame
      override_rules: [RuleConfig]
```

WebSocket early data carries an initial byte prefix in the HTTP Upgrade request,
not in a WebSocket frame and not as TLS 0-RTT. Clients send it only when explicitly
enabled. Servers with omitted or zero `max_early_data` automatically accept it
from `Sec-WebSocket-Protocol`, up to 2048 decoded bytes. A positive server limit
selects explicit mode and only the configured carrier is read; there is no
automatic fallback to the standard header. To change the automatic cap, set both
a positive `max_early_data` and `early_data_header_name: Sec-WebSocket-Protocol`.

A target with a static `Sec-WebSocket-Protocol` filter in `matching_headers`
suppresses automatic reception: its token remains a selector, with no prefix
or subprotocol echo. Otherwise an unclaimed nonempty subprotocol token is treated
as early data, not ordinary subprotocol negotiation. A valid base64url token
such as `chat` injects decoded bytes; an invalid token is rejected. There is no
general server-side off switch. Missing or uniquely empty headers remain plain
WebSocket upgrades; duplicated carrier headers are rejected in automatic mode,
even when the final value is empty.

Support is not negotiated: a successful upgrade, including an absent subprotocol
echo, does not prove the server accepted the prefix. Automatic reception prevents
the standard-header/default-server mismatch, but mismatched custom headers or
path suffixes reaching a target without `matching_path` can still silently lose
the prefix, particularly with raw port forwarding. Explicit path/custom-header
targets also do not read the standard header. Configure matching carriers;
no replay can recover a mismatched prefix safely.

Explicit targets accept at most `max_early_data` decoded bytes.
Malformed, noncanonical or oversized base64url is rejected before the upgrade.
Missing or empty early data is allowed. Decoded bytes precede all framed payload.

With `early_data_header_name: Sec-WebSocket-Protocol`, shoes interoperates with
Xray's `/ws?ed=2048` client configuration and sing-box's named-header mode. shoes
uses explicit fields; do not put `?ed=` in its `matching_path`. Other nonreserved
HTTP header names are supported for sing-box peers. Names are case-insensitive;
an explicit carrier cannot also appear in `matching_headers`.
Use sing-box 1.14.3 or newer for client-side early data: older clients can discard
the first response bytes when they arrive together with the HTTP upgrade.

With a positive limit and no header name, encoded bytes are appended directly to
`matching_path`, as in sing-box's path mode. This requires an explicit, query-free
server path. Requests matching multiple targets are rejected if any candidate
has a positive limit or the first matching target would automatically receive
data (including a duplicated carrier). Otherwise legacy first-match routing
remains, including when the first target has a static subprotocol selector.
A generic automatic target before a matching static-selector target is ambiguous
for a nonempty token; target order is not changed to prefer selectors. Use
disjoint paths/header filters rather than overlapping prefix paths or catch-all
targets on the same listener.

Limits must fit the HTTP budget: each request/header line is less than
4096 bytes, the header block at most 32768 bytes, and fewer than 40 nonempty
lines. Configuration validation includes base64 expansion and rejects limits
that cannot fit. The aggregate 32768-byte cap also applies to plain WebSocket
upgrades. Clients reject malformed status codes, missing or invalid
`Upgrade: websocket` and `Connection: upgrade` response tokens, and duplicate
accept/subprotocol response headers in both modes. Early data is visible to HTTP
intermediaries and their logs; use TLS when confidentiality is required.


## Client
```yaml
protocol:
  type: websocket
  matching_path: string?
  matching_headers:
    header_name: string
  max_early_data: 0            # Decoded-byte limit; 0 keeps eager upgrades
  early_data_header_name: string? # Empty/omitted: path suffix
  ping_type: ping-frame        # disabled | ping-frame | empty-frame
  protocol: ClientProxyConfig
```

Example for Xray or sing-box protocol-header mode:

```yaml
protocol:
  type: websocket
  matching_path: /ws
  matching_headers:
    Host: proxy.example.com
  max_early_data: 2048
  early_data_header_name: Sec-WebSocket-Protocol
  protocol:
    type: vless
    user_id: "11111111-1111-4111-8111-111111111111"
```

Early-enabled clients require an explicit `matching_headers.Host` identifying
the proxy, not the tunneled destination. Omit `early_data_header_name` for
sing-box path-suffix mode; that mode does not support query strings.
Sending remains off by default. Default shoes servers accept standard-header
early data up to 2048 bytes without additional server configuration; path and
custom-header carriers require explicit server configuration.

The first nonempty write contributes up to the configured limit; remaining
bytes use ordinary WebSocket frames. For vectored writes, only the first nonempty
slice contributes to the early prefix. Inner protocol headers normally make up
this first write, not the application's first payload. A read, flush, shutdown
or enabled ping before the first write performs an ordinary upgrade instead.
Empty reads/writes do not initiate it. Upgrade failures are terminal and never
replay the accepted prefix. Deferred upgrades retain the 60-second setup timeout.
