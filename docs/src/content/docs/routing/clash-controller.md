---
title: "Clash Controller"
description: shoes clash controller configuration.
---

The CLI can expose a documented subset of the Clash API. The controller is
disabled unless a listener is configured. It does not change existing groups'
round-robin behavior.

```yaml
- clash_api_address: "0.0.0.0:9090"
  secret: "replace-with-a-strong-secret"
  cors_origins: ["https://dashboard.example.com"]

- clash_api_path: "/run/shoes/clash.sock"
  secret: "replace-with-a-local-secret"

- cache_file_path: "./cache.db"
```

`clash_api_address` accepts one address or a list, using the ordinary server
address syntax. Use either `clash_api_address` or `clash_api_path` per entry.
Multiple entries share selectors, connections, counters, and resource budgets;
they are not separate tenants. Each has its own secret and browser origins.
Listener definitions and `cache_file_path` require a restart to change.

Every listener requires a nonempty secret. HTTP uses `Authorization: Bearer
<secret>`; supported WebSocket upgrades also accept `?token=`. Browser origins
must exactly match `cors_origins`, unless `cors_origins: ["*"]` explicitly allows
any origin, including opaque (`null`) origins. This applies to HTTP and WebSocket
requests and does not disable authentication. Prefer exact origins when possible.
With `*`, any website can attempt authenticated requests; use a long random secret.
The default empty list permits authenticated clients without an Origin header
but rejects requests carrying one. Only a standalone `*` acts as a wildcard;
literal `null` entries are not accepted. Optional `allow_private_network: true`
enables private-network preflight responses for allowed origins, not mixed-content
bypass. Protect TCP with a firewall and external TLS termination. Unix sockets
require an absolute path in an existing owner-only directory and are created
with mode `0600`. Browsers need an HTTP reverse proxy to use a Unix socket.

Opt into manual selection explicitly:

```yaml
- client_group: outbound
  type: selector
  default: east
  client_chains:
    - chain:
        - name: east
          address: "east.example.com:1080"
          protocol: {type: socks}
    - chain:
        - name: west
          address: "west.example.com:1080"
          protocol: {type: socks}
```

Rules continue to use `client_chain: outbound`. A selector chooses an immediate
named member or referenced group; inline selector clients and multi-hop paths
require `name`. See [whole-path groups](/routing/groups/#client-group) for naming,
`Relay` nodes, and alternatives with different hop counts.
The group discriminant is `type`: `round-robin` (the default), `selector`,
or `url-test`. The removed `strategy` field and unknown types are errors. Nested round-robin weights,
duplicate membership, and existing UDP filtering are preserved. A selected
branch without UDP support fails new UDP flows instead of silently falling back.
Selection changes affect new flows only; existing streams, UDP destinations,
DNS connections, and WireGuard associations remain pinned until reopened.
Optional client and server/TUN `name` fields provide stable dashboard identities.
Generated anonymous names are stable only for unchanged definition sites.

Automatic selection does not require a controller listener or a cache file:
see the [URL-test example](/examples/url_test/) for a complete file.

```yaml
- client_group: fastest
  type: url-test
  url: "https://probe.example.com/generate_204"
  interval: 300       # seconds, 1..86400
  timeout: 5000       # milliseconds, 1..60000, no longer than interval
  tolerance: 50       # milliseconds, 0..65535
  lazy: true
  client_chains:
    - chain:
        - name: east
          address: "east.example.com:1080"
          protocol: {type: socks}
    - chain:
        - name: west
          address: "west.example.com:1080"
          protocol: {type: socks}
```

Only `url` is required for `url-test`; the values above are the other defaults.
Literal URL addresses denied by probe policy (including loopback, link-local,
multicast, unspecified, and synthetic benchmark addresses) are configuration errors.
Locally resolved hostnames are subject to the same destination policy at probe time.
Literal URLs overlapping configured or retained fake-IP ranges are also rejected.
`default` is selector-only. `url`, `interval`, `timeout`, `tolerance`, and `lazy`
are url-test-only. Members must be nonempty and distinct; references to nested
groups are supported. Explicit names are recommended for automatic inline members.

Selection uses the fastest fresh healthy result for the configured URL, among
members eligible for that hop and transport. A healthy incumbent stays selected
unless another member improves its delay by more than `tolerance`. TCP and UDP
have separate incumbents; an automatic group can choose a UDP-capable alternative
even when its fastest TCP member does not support UDP. Nested manual selectors
still restrict eligibility, and intermediate chain hops only need TCP support.
Changing selection affects new connections, not established streams or associations.

There is one initial check after activation, including for lazy groups. Thereafter
`lazy: true` normally checks only groups used by new forwarding connections during
the last interval. Every effective manual selector change also makes all URL-test
groups due for a check, including idle lazy groups unrelated to that selector.
An active round finishes before the new check starts.
Probes, dashboard reads, and WireGuard carrier maintenance never count as use.
New outbound connections through a WireGuard endpoint wake its carrier groups,
including nested carriers, without changing their existing associations. Inbound-only
endpoints and long-lived flows need `lazy: false` for continuous checks. `lazy: false` checks idle
groups too. Samples older than `2 * interval + timeout` are stale and cannot win
on delay. Without fresh healthy results (startup, all dead, stale, or locally
unavailable probes), retain the eligible incumbent, or choose the first eligible
member in configuration order. This is best-effort routing, not fail-closed routing.

Unambiguous remote connection errors request a rate-limited recheck (at most once
per second); they do not mark the configured URL dead based on a different user
destination. Local overload and unsupported operations do not penalize health.
HTTP/2 adapters preserve matching transport-error causes for this classification.
This is best effort when a protocol replaces a failure with a generic cancellation:
for example, XHTTP upload cancellation can lose the original cause and count as a
remote failure.
User payloads are never retried across candidates. Probes use HTTP HEAD and accept
any HTTP response status, without redirects; HTTPS certificates are verified.
Checks use the generation's guarded system probe resolver and each member's
declared chain, not a caller's surrounding route or DNS bootstrap.
Background results update only the group performing the check. API probes with
the same normalized URL and wildcard/default expected status also update matching
groups. Other URLs and explicit status expectations cannot overwrite selection
samples. Nested automatic groups use their shared group state.

Periodic and API probes share a 16-probe limit. Each automatic member check gets
its full timeout after admission; waiting for capacity does not consume that
timeout or change health. An admitted check that times out records a failure.
Due groups start in catalog order, and each round checks members in configuration
order. Rounds have no overall deadline and can exceed the configured interval
under load. Under sustained saturation, reduce group size or adjust
timeouts/intervals, or expect unprobed/stale members. Scheduling has one-second
granularity and does not overlap rounds within a group; other groups can run while
a slow round is in flight. Activation/reload cancels old work and rejects obsolete
results; an interrupted round is immediately eligible when its generation resumes.
New committed generations start with unprobed health.

Manual API group probes retain a request-wide deadline, including queue time.
Expiry after queued admission is inconclusive and preserves prior health.
API batches prioritize members with no full-budget API attempt, then the oldest
such attempts; automatic rounds do not track or use these priorities.
Long automatic rounds can keep capacity busy across multiple member timeouts,
causing single-node API probes to report busy or API group probes to time out.

The controller reports `type: URLTest`, group TCP `now`, optional `udpNow`,
`testUrl`, and selected-member `health` (`unprobed`, `healthy`, `dead`, or `stale`).
Its `alive` is true only for fresh healthy results. Manual selection PUTs for
automatic groups are rejected; automatic choices are neither pinned nor persisted.
Leaf histories remain bounded to ten samples per URL and eight URLs. Automatic
selection retains its configured-URL samples independently of API eviction.
API full-budget attempt timestamps for configured URLs also survive eviction;
other attempt URLs are capped at eight per member for each of filtered and
unfiltered probes.
All occurrences of a URL-test group share its samples and TCP/UDP incumbents.
There are no route contexts, per-occurrence probe rounds, or contextual samplers.
Forwarding and dashboard selection consult the same group state, subject to each
caller's transport eligibility. Any effective manual selector change clears all
URL-test samples and incumbents and fences in-flight results, even for unrelated
groups. Selecting the same effective choice preserves samples. Groups become due
again, after any active round finishes; no selector dependency graph is maintained.
Surrounding route choices do not create additional health identities. Complete
chains declared as members are probed end to end. External caller prefixes and
suffixes are not tested. URL-test groups are not supported by FFI.
Probe connectors have separate round-robin counters, so probes never advance
forwarding counters.

## Persistence

Only one `cache_file_path` is allowed across all input files. Its absence disables
persistence; relative paths resolve against the process working directory.
The file is shoes-specific versioned JSON, not a sing-box/Mihomo database. Parent
directories must exist, and Unix cache/lock files must be private. Explicit API
choices take precedence over `default`, then the first member. Startup/reload
never save defaults or rewrite YAML. Every accepted selection PUT saves before
publishing the new choice. Failed saves leave routing unchanged. An error after
atomic replacement can leave an unacknowledged choice on disk; logs report this
durability uncertainty. Saved entries for removed groups are retained. Both reads
and writes are limited to 1 MiB; remove obsolete entries only while shoes is stopped.

## API behavior

Supported endpoints: `/version`, read-only `/configs`, `/proxies`, `/group`,
selector PUTs, node/group `/delay`, read-only `/rules`, `/connections` snapshots
and DELETE cancellation, plus WebSocket/NDJSON `/traffic`, `/memory`, and `/logs`.
Provider collections return `{"providers":{}}`. Traffic counters measure outbound
application payload, not headers, padding, or retransmissions. Probes, internal
DNS/carrier traffic, and unauthenticated camouflage/fallback forwarding are excluded;
synthetic fake-DNS answers and ICMP are not represented as connections.
Connection speeds are derived by the dashboard from successive byte counters.
Process/GeoIP data is not fabricated.

Optional `connection_notes: true` on a Clash API entry (`clash_api_address` or
`clash_api_path`) adds setup notes to active `/connections` objects, over HTTP and
WebSocket. It defaults to false; changing it requires a restart.
If any controller enables it, all controllers expose notes. In zashboard, open a
connection's details and select **Raw** to inspect `notes` (`elapsedUs`, `phase`,
`text`), alongside its existing generation, destination, selected chain, and rule
metadata.

Notes describe preparation, routing choices, inbound-resolver calls, and outbound
setup. They are best-effort: rejected/failed setup and closed connections have no
retained history or separate debug endpoint. A dashboard may retain previously
sampled connections, but short-lived connections can be missed. DNS notes cover
existing routing/dial call boundaries, not resolver cache/upstream internals or
remote DNS. Initial UDP prechecks and local-DNS handling are not observed.
Notes contain hostnames and addresses, never payloads, credentials, or error
messages; errors use only their kind.
They may reveal outbound proxy server hostnames and IP addresses not otherwise
exposed by the API.

At most 256 connections (including pending setup) collect notes at once. Each
buffer holds 32 events with at most 128 UTF-8 bytes of text each, plus an overflow
summary when read. New connections skip notes while all slots are occupied.
Buffers reserve at most 8 KiB each, 2 MiB in aggregate, excluding allocator/RSS
overhead and snapshot copies/JSON. Closing or abandoning a connection releases
its buffer when its last reader finishes. The budget is shared across reloads.
With notes disabled, no note buffers or resolver wrappers are allocated.
When enabled, notes add setup work and snapshot copying/serialization: the
controller samples every second even without subscribers; HTTP requests and
custom-interval WebSocket subscriptions can request additional snapshots.

Delay tests send HTTP HEAD through actual outbounds, verify HTTPS certificates,
and never follow redirects. A leaf test is standalone, not a test of every chain
containing that leaf. Unused WireGuard nodes remain inactive and cannot be probed
until referenced by a forwarding or DNS rule. Direct probe destinations cannot be
loopback, link-local, unspecified, multicast, or synthetic fake-IP addresses.
Remote proxies may resolve names differently: this is authenticated administrative
network access, not an API for untrusted users.

The compatibility target is zashboard revision
`6225aac84439425ae4f4493437b110a314753436`, not full Mihomo parity. Only rule mode
is offered, with no synthetic `GLOBAL`. Use `disableUpgradeCore=1` in the dashboard
backend settings. Unsupported controls can still be visible: config editing,
API reload/restart, upgrades, provider updates, rule disabling, DNS/cache
maintenance, and dashboard storage sync return explicit errors, never fake success.
No UI download/hosting is included. Controller/cache entries are rejected by FFI.

See [the complete example](/examples/clash_api/). Controller connections share
a limit of 64, subscriptions 16, probes 16, and bound sockets 16. Request heads
must finish within 15 seconds of accept or the preceding response; ordinary
request bodies have a 10-second deadline and 64 KiB limit. Established subscriptions
are exempt from header idle expiry and have bounded queues/write deadlines.
Responses are limited to 32 MiB. An oversized connection snapshot closes its
WebSocket with code 1009 and reason `response exceeds 32 MiB`; tracking continues
without truncating the connection list.
Configuring a controller, `cache_file_path`, or any selector/url-test group enables the
catalog and its 16,384-node limit. Names must be nonempty, unique, at most 256
bytes, and contain no control characters. `DIRECT`, `REJECT`, and
`GLOBAL` are reserved. Configuration preparation rejects `/rules` or base
`/proxies` responses larger than 32 MiB. Group delay requests support at most
1,024 immediate members.
