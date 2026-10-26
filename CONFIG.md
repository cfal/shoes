# Configuration Reference

shoes uses YAML configuration files. Multiple configuration types can be combined in a single file or split across multiple files.

## Table of Contents
- [Configuration Structure](#configuration-structure)
- [Server Config](#server-config)
- [Server Protocols](#server-protocols)
- [TUN Config](#tun-config)
- [WireGuard](#wireguard)
- [Client Config](#client-config)
- [Client Protocols](#client-protocols)
- [Native DNS Freshness](#native-dns-freshness)
- [Fake DNS](#fake-dns)
- [Rules System](#rules-system)
- [Named Groups](#named-groups)
- [Named PEMs](#named-pems)
- [Certificate Sources](#certificate-sources)
- [Advanced Features](#advanced-features)
- [Command Line](#command-line)

## WireGuard

WireGuard uses `protocol: {type: wireguard}` in ordinary client and server
configs. It carries TCP/UDP flows over a userspace GotaTun device and smoltcp
stack, not a TCP stream wrapper. Unix builds support WireGuard; Windows rejects it.

See [server](examples/wireguard_server.yaml) and
[client](examples/wireguard_client.yaml) examples. Their demonstration keys
must be replaced before deployment. Generate a private key with `wg genkey`
and derive its public key with `wg pubkey`. Never share the private key.

| Field | Meaning |
| --- | --- |
| `private_key` | Base64-encoded 32-byte private key |
| `addresses` | Nonempty local tunnel CIDRs; at most one address per family |
| `peer_client_chain` | Optional client chain carrying encrypted UDP packets to peers; accepts normal group, inline, and pool syntax |
| `mtu` | Inner IP MTU, default 1408; supported range 1280-1420 |
| `resource_limits` | Same fields as TUN, with bounded WireGuard defaults |

These fields live inside `protocol`. WireGuard implies UDP; `transport: udp`
is optional. TCP/QUIC transports and their socket settings are rejected.

A client has one remote peer. Its ordinary `address` identifies that peer;
`public_key`, optional `pre_shared_key`, `allowed_ips`, and
`persistent_keepalive` belong directly in `protocol`, not a `peers` list:

```yaml
- client_group: vpn
  client_proxies:
    - address: "vpn.example:51820"
      protocol:
        type: wireguard
        private_key: "<client-private-key>"
        public_key: "<server-public-key>"
        addresses: ["10.77.0.2/32"]
        allowed_ips: ["0.0.0.0/0"]
        persistent_keepalive: 25
```

Omitted client `allowed_ips` defaults to `["0.0.0.0/0", "::/0"]`; an explicit
empty list rejects. `addresses` remains required. Routes for an address family
without a local tunnel address fail closed. These settings do not install host
routes. For multiple upstreams, configure separate clients or a group pool.

A server has a nonempty `protocol.peers` list. Each peer requires `public_key`
and explicit nonempty `allowed_ips`. Optional fields are `pre_shared_key`,
`endpoint: "host:port"`, and `persistent_keepalive` in seconds (zero disables it).
Omit `endpoint` for a peer that initiates toward a directly listening server:

```yaml
- address: "0.0.0.0:51820"
  protocol:
    type: wireguard
    wireguard_name: gateway
    private_key: "<server-private-key>"
    addresses: ["10.77.0.1/32"]
    peers:
      - public_key: "<client-public-key>"
        allowed_ips: ["10.77.0.2/32"]
  rules:
    - masks: ["192.168.10.0/24"]
      action: allow
```

Peer hostnames are resolved through native
bootstrap DNS during preparation and refreshed on reload. Direct mode selects
the first resolved address compatible with the bound socket at startup.
Authenticated WireGuard roaming can update the active peer address without a reload in direct mode.
Overlapping allowed prefixes between different peers, duplicate keys, and
self-peering are rejected. Assign each client distinct tunnel addresses.

The server `address` must be one literal UDP socket address with a nonzero port,
not a hostname, port range, or Unix socket path. `0.0.0.0:51820` listens only on IPv4;
`[::]:51820` uses a dual-stack socket where supported. Direct clients bind an
ephemeral dual-stack wildcard, with IPv4 fallback when IPv6 is unavailable.
Outer sockets retain mobile socket protection and interface binding. Optional
`bind_interface` belongs at the client-config level for clients and inside
`protocol` for servers; Linux/Android/Fuchsia support it. No OS interface,
route, firewall rule, or NAT rule is created.

Servers require explicit nonempty top-level `rules` and may specify top-level
`dns` and `sniff`. Missing, null, or empty rules reject; `rules: block-all` is valid.
`protocol.wireguard_name` gives a server a stable, case-sensitive identity. When
omitted, null, or empty, the server's public key supplies its identity instead.
Duplicate names or duplicate unnamed public-key identities reject configuration,
even with different listen addresses. Name-based and key-based identities are separate.
Client deduplication is unchanged. Reordering servers or adding clients does not
change server identity or private Fake DNS ownership. Use an explicit name to
preserve that ownership across key rotation; changing the effective identity
creates a different context and existing state files reject the new owner.
Rules use the normal destination masks, overrides, and client chains. Clients
accept replies to their outgoing flows, not unsolicited inbound flows. Per-peer authorization
beyond cryptokey source validation is not supplied by destination rules.
Authenticated peers can reach the gateway's local services unless rules block
them. The server example blocks loopback and link-local destinations; restrict
private networks too when peers should not access the gateway's LAN.

Use the client group from the first hop, or put the full client config inline:

```yaml
client_chain:
  - vpn
  - address: "10.77.0.10:1080"
    protocol: {type: socks}
```

The second hop is optional. WireGuard cannot appear
inside TLS/WebSocket or at later hops. A missing route, address family, failed
endpoint, or unavailable peer never causes direct fallback.

To put proxies **before** WireGuard, configure `peer_client_chain` inside its protocol:

```yaml
peer_client_chain:
  - address: "relay.example:443"
    protocol:
      type: tls
      protocol:
        type: vless
        user_id: "b85798ef-e9dc-46a4-9a87-8da4499d36d0"
        udp_enabled: true
```

The effective path is `Shoes -> peer client chain -> WireGuard peer -> optional
inner proxy chain -> destination`. The routing rule still selects WireGuard
at hop zero. See [the complete detour example](examples/wireguard_outer_chain.yaml).

Peer chains use the normal inline, named-group and pool syntax. Their final hop
must support UDP; earlier hops may be TCP-only. VLESS, VMess and compatible
Shadowsocks/AnyTLS UDP-over-TCP configurations work. Shoes' SOCKS outbound only
implements CONNECT, and Trojan outbound UDP is not implemented, so neither can
be the final UDP hop. Pools select UDP-capable final members. Selection remains
fixed for the life of an association; reconnection may select another member.

One persistent association is shared
by all inner flows to each resolved peer destination; peers with the same resolved
destination share an association. No native WireGuard UDP listener is opened.
Configure physical interface binding on the first carrier client, not the
WireGuard socket. A proxied server must omit its top-level listen `address` and
specify `endpoint` and nonzero `persistent_keepalive` on every peer. It initiates
handshakes to establish return mappings, then its ordinary `rules` handle
incoming tunnel flows. It cannot accept arbitrary public peers through the
proxy. See [the proxied server example](examples/wireguard_proxied_server.yaml).
`peer_client_chain` conflicts with a server listen address or WireGuard socket
interface binding. Clients without keepalive initiate a handshake when an
outbound inner flow needs one.

Detoured destinations are fixed for the configuration generation. Their message
streams do not expose source addresses, so arbitrary peer address roaming is not
supported. Peer hostname changes require reload. Peer and outer-proxy bootstrap
use native DNS independently of routed DNS and the server's `dns`. Ensure host DNS and
host routes do not themselves require the tunnel being established.

Outer connect and blocked-write attempts time out after 10 seconds. Failed streams
retry with backoff from 250 ms to 10 seconds, never falling back to direct UDP.
Offline/overflow packets are dropped rather than indefinitely buffered; WireGuard
and inner TCP perform their normal retries. Use `persistent_keepalive` to maintain
idle proxy UDP mappings. Silent blackholes without stream errors remain UDP loss.
Queues hold at most 64 packets per destination and 64 aggregate received packets,
with a 2048-byte outer datagram limit, above the supported inner MTU plus WireGuard
overhead. Shutdown waits for workers to release their associations.

The peer chain can itself start with another WireGuard client. Dependencies
start first, regardless of declaration order; self-dependencies and indirect cycles
(including pool alternatives) are rejected. A direct WireGuard-in-WireGuard carrier
requires `round_up(inner_mtu, 16) + 80 <= carrier_mtu`, conservatively accounting for
IPv6, UDP and WireGuard overhead. For example, inner MTU 1280 fits carrier MTU 1408.
A TCP proxy after the carrier segments packets instead. External path MTU still
needs operator tuning; UDP-over-TCP can introduce head-of-line blocking.

Identical clients share one device per configuration generation, even when copied
between different groups or inline locations. Identity is the configured peer
address, derived client public key, and server public key, not a resolved or
roaming address. WireGuard defaults and equivalent key/address/route encodings,
plus carrier interface and TCP socket defaults, are normalized before comparison.
Local address prefixes are canonicalized to host prefixes; routing prefixes retain
their meaning. Other carrier protocol settings are compared as configured.
Conflicting addresses, routes, PSKs, MTUs, limits, interfaces, or peer
chains for the same identity reject rather than silently merging. Different
identities and servers remain separate. Unused client groups open no sockets.
Unreferenced WireGuard-routed DNS groups are validated but not prepared; selecting
the group through a server or TUN `dns` field activates its devices.

DNS remains independently configured. Merely defining a WireGuard client
does not tunnel the application's default native DNS. Explicit TCP DNS,
DoT, and DoH client chains may use WireGuard with a literal upstream IP.
Use `server_name` for TLS authentication where needed. UDP DNS, HTTP/3 DNS,
hostname upstreams on WireGuard chains, and bootstrap dependencies on
WireGuard-routed DNS groups are rejected. Endpoint bootstrap itself is native
DNS, not DNS through the not-yet-active tunnel.

This is TCP/UDP proxying, not arbitrary IP routing. Remote destinations see
the gateway's outgoing proxy connection, not the original client's source
address. A non-Shoes gateway must provide the required routes and forwarding
or NAT for destinations behind it. ICMP forwarding, IP fragment reassembly,
peer-to-peer IP forwarding, WARP reserved bytes, and
wg-quick import are not implemented.

Fragmented input and unsupported IPv6 extension chains are dropped before
transport parsing. TCP advertises an MSS derived from the MTU. Outbound UDP
writes larger than MTU minus 28 bytes (IPv4) or 48 bytes (IPv6) are dropped and
counted without closing the flow; they are never truncated. UDP queue-budget
exhaustion also drops individual writes. At MTU 1408 the payload limits are 1380 and 1360
bytes. Oversized UDP responses on inbound forwarding are dropped. Large DNS
replies should use TCP-based transports. Reduce MTU for constrained underlays;
automatic path-MTU discovery is not provided.
Packets received from a peer above the local MTU are also dropped. Configure
matching MTUs on both sides, including peers whose default is 1420 rather than
Shoes' 1408; TCP MSS negotiation does not protect UDP traffic.

Default admission limits are 256 TCP connections, 32 KiB TCP buffers, a
32 MiB TCP buffer budget, 1024 UDP sessions, 4096 UDP destinations, 64
destinations per inbound UDP session, and 8 MiB queued UDP payloads.
UDP forwarding and outbound associations have separate bounded pools.
Missing or null limit fields use WireGuard defaults rather than the unlimited
TUN defaults. Packet and command queues are bounded at 64. These budgets
cover modeled Shoes-owned state, not total process RSS or all GotaTun state.

The TCP buffers bound the advertised receive window and in-flight data across
the tunnel. A 32 KiB window limits a single flow to roughly 5 Mbit/s at 50 ms RTT
or 2.6 Mbit/s at 100 ms RTT, before other bottlenecks. For higher-bandwidth,
higher-latency links, set `resource_limits.tcp_buffer_size` to, for example,
262144 (256 KiB). Four buffers are budgeted per flow, so retaining 256 connections
at that size also requires `tcp_memory_bytes: 268435456` (256 MiB); the default
32 MiB budget would admit only 32 connections. Tune against measured RTT,
throughput, and available memory rather than increasing buffers unconditionally.

Periodic logs report endpoint flow/drop counts and each peer's public key,
handshake age, and byte counters. Private keys and PSKs are redacted.

Preparation failures retain the old configuration. Reload activation stops
existing tunnel flows and rebuilds endpoints; sessions are not migrated.
Bind failures during activation trigger rollback to the previous configuration,
but disconnected tunnel sessions are not restored. If rollback fails, Shoes
exits with status 1. Shutdown waits for buffered UDP tasks to release their
sockets before rebind. No host route cleanup is necessary.

## Configuration Structure

A configuration file is a YAML array containing one or more configuration entries. Each entry can be:

- **Server Config** - Defines a proxy server instance
- **TUN Config** - Defines a TUN/VPN device for transparent proxying
- **Client Config Group** - Defines reusable upstream proxy configurations
- **Rule Config Group** - Defines reusable routing rules
- **Named PEM** - Defines reusable certificate/key data

```yaml
# Server configs have 'address' or 'path', except proxied WireGuard servers
- address: "0.0.0.0:8080"
  protocol: ...

# TUN configs have 'device_name' or 'device_fd'
- device_name: "tun0"
  address: "10.0.0.1"
  ...

# Client config groups have 'client_group'
- client_group: my-upstream
  client_proxy: ...

# Rule config groups have 'rule_group'
- rule_group: my-rules
  rules: ...

# Named PEMs have 'pem'
- pem: my-cert
  path: /path/to/cert.pem
```

## Ordered Healthy Fallback

The CLI supports opt-in ordered fallback without a Clash API listener:

```yaml
- client_group: outbound
  type: fallback
  health_check:
    url: "https://probe.example.com/generate_204"
    interval_secs: 30
    timeout_ms: 5000
    expected_status: 204
  client_proxies:
    - name: primary
      address: "primary.example.com:1080"
      protocol: {type: socks}
    - name: backup
      address: "backup.example.com:1080"
      protocol: {type: socks}
```

Rules use `client_chain: outbound`. `health_check` is required only for fallback
and rejected on other group types. The removed `strategy` field is not accepted.
The URL must be HTTP(S), at most 2048 bytes,
without credentials or fragments. `interval_secs` is required, 1..86400;
`timeout_ms` defaults to 5000, 1..32767; `expected_status` defaults to 204,
100..599. Unknown fields, empty groups, duplicate immediate members and
selector-only `default` are rejected. Anonymous inline members are supported.

For each new flow, explicit nested selector choices and final-hop UDP capability
are applied first. Fallback chooses the first member with a healthy eligible
concrete path. If none is healthy, never-sampled paths may be tried in order.
Failed and stale paths are excluded; all-down returns an error, never implicit
DIRECT. A sample becomes stale after three intervals plus the probe timeout.
Probes skip paths excluded by manual selector choices, rechecking those choices
after admission. Reselecting a skipped path schedules a check without waiting
another interval, still subject to shared admission and transport deadlines.
Previously sampled paths that became stale while unselected remain excluded
until a new check succeeds; reselection does not make an old sample Unknown.
New flows can therefore fail closed while rechecks are pending or locally blocked.
Manual choices are never rewritten or persisted by health checking.
Resolver-chain selector changes trigger rechecks without erasing
existing samples: DNS caches and retained connections are not concrete-path
identity. Relevant selector changes fence in-flight probe results, including
A-to-B-to-A changes; unrelated selectors and inactive nested branches do not.
Fixed outer path choices do not erase samples. DNS-chain checks use the same
configured bootstrap resolver as forwarding.
A fallback-checked chain cannot contain WireGuard whose `peer_client_chain` has
more than one member at any hop, including recursively nested WireGuard carriers.
All configured alternatives count, even branches that cannot carry UDP. It also
cannot contain NaiveProxy (including wrapped NaiveProxy) after a hop with multiple
members: its retained H2 session is not scoped to the selected prefix. These
combinations are rejected, not probed approximately. Fixed WireGuard carriers,
NaiveProxy at hop 0 or behind a single fixed prefix, and ordinary chains without
fallback remain supported. The restrictions also cover DNS chains and unused
groups available to controller/URL-test probes; resolver-only dependencies do
not count as the fallback chain's transport path.
A fallback containing a selector may choose its next member, but
never another branch inside
that selector. Fallback member and healthy-before-unknown priorities are resolved
across complete eligible paths before URL-test latency and round-robin pool
choices. Paths outside each fallback branch remain eligible, so an unrelated
round-robin branch is not globally overridden by health.

Checks send HEAD through the complete configured TCP chain, require the expected
status, verify HTTPS certificates, and do not follow redirects. They share the
controller and URL-test probe engine and its 16 concurrent permits. The total deadline includes
admission, DNS, connect, TLS and response headers. Admission exhaustion or local
resource shortages do not mark a path failed; expiry after queued admission
preserves the previous sample without refreshing its timestamp. Successful and failed checks both
wait the configured interval, jittered by +/-10%, before retrying. Unused groups
do not start transports; checks start when a runtime chain is instantiated.
Controller delay requests and URL-test targets can instantiate additional fallback
chains. Their checks last while the cached probe connector lives (normally the
generation) and obey that target's selectors, not selectors enclosing it in
routing rules. They share the same check and concurrency limits.

Health is generation-local and keyed by canonical full-path configuration, resolver
identity, selector constraints and probe settings, not names or member positions.
Equivalent checks share one sample; different prefixes/endpoints do not. Each
chain is limited to 256 concrete paths and each generation to 1024 active checks. Large pool products are
rejected instead of spawning unbounded probes. Due checks are admitted oldest-first
so repeated checks cannot indefinitely overtake waiting paths. Saturation can make samples stale;
choose intervals/timeouts that fit the shared budget. Reload cancels and joins old
checks before starting the new generation. Draining sessions keep the old
generation's health snapshot at cancellation, without further probes or aging;
rollback/resume restores normal freshness checks. Samples are not persisted.
Pause time counts toward sample age after resume, so a long rejected activation
can require successful rechecks before the resumed fallback accepts new flows.

Checks use the existing probe destination restrictions (including loopback,
link-local and synthetic Fake-IP protection). Forbidden literal URLs, including
configured or retained Fake-IP ranges, are rejected during validation.
Proxy-side DNS remains subject to
the remote proxy's policy. A TCP sample does not prove UDP reachability, nor does
one probe endpoint measure all destinations. Application errors never update
health, and application bytes are never replayed. Existing TCP streams, UDP
associations and pooled transports keep their selected member until reopened.
There is no latency scoring, passive cooldown, hysteresis, affinity, or all-down
last-resort mode. FFI rejects fallback because it does not own this scheduler.

Controller delay history remains separate from fallback samples. `Fallback`
catalog entries expose members and capabilities; there is no single global `now`
member because selection depends on the concrete chain and transport.

## Clash Controller

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
  client_proxies:
    - name: east
      address: "east.example.com:1080"
      protocol: {type: socks}
    - name: west
      address: "west.example.com:1080"
      protocol: {type: socks}
```

Rules continue to use `client_chain: outbound`. A selector chooses an immediate
named member or referenced group; inline selector members require `name`.
The group discriminant is `type`: `round-robin` (the default), `selector`,
`url-test`, or `fallback`. The removed `strategy` field and unknown types are errors. Nested round-robin weights,
duplicate membership, and existing UDP filtering are preserved. A selected
branch without UDP support fails new UDP flows instead of silently falling back.
Selection changes affect new flows only; existing streams, UDP destinations,
DNS connections, and WireGuard associations remain pinned until reopened.
Optional client and server/TUN `name` fields provide stable dashboard identities.
Generated anonymous names are stable only for unchanged definition sites.

Automatic selection does not require a controller listener or a cache file:

```yaml
- client_group: fastest
  type: url-test
  url: "https://probe.example.com/generate_204"
  interval: 300       # seconds, 1..86400
  timeout: 5000       # milliseconds, 1..60000, no longer than interval
  tolerance: 50       # milliseconds, 0..65535
  lazy: true
  client_proxies:
    - name: east
      address: "east.example.com:1080"
      protocol: {type: socks}
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
`lazy: true` checks only groups used by new forwarding connections during the last
interval. Probes, dashboard reads, and WireGuard carrier maintenance never count as use.
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
Local probe lookups use guarded system DNS, not a server's configured DNS group.
API probes with the same normalized URL and wildcard/default expected status also
update selection. Other URLs and explicit status expectations cannot overwrite it.

Periodic and API probes share a 16-probe limit. Each periodic round's timeout
includes admission/queue time; members not admitted before the deadline retain
their previous health. A deadline expiry after queueing is inconclusive and also
preserves prior health; successful probes and explicit remote errors still update it.
Members with no full-budget attempt, then the oldest full-budget attempts, lead each
round, independently of health. Local failures cannot monopolize these slots, and
queued attempts can receive a full budget on a later round. Tied members rotate on admission.
Due groups with the oldest unqueued admission get priority, with stable catalog order
breaking ties.
Under sustained saturation, reduce group size, increase
timeout/interval, or expect unprobed/stale members. Scheduling has one-second
granularity and does not overlap rounds within a group; other groups can run while
a slow round is in flight. Activation/reload cancels old work and rejects obsolete
results; an interrupted round is immediately eligible when its generation resumes.
New committed generations start with unprobed health.

The controller reports `type: URLTest`, effective TCP `now`, optional `udpNow`,
`testUrl`, and selected-member `health` (`unprobed`, `healthy`, `dead`, or `stale`).
Its `alive` is true only for fresh healthy results. Manual selection PUTs for
automatic groups are rejected; automatic choices are neither pinned nor persisted.
Leaf histories remain bounded to ten samples per URL and eight URLs. Automatic
selection retains its configured-URL samples and full-budget attempt timestamps
independently of API eviction; other attempt URLs are capped at eight per member
for each of filtered and unfiltered probes.
Automatic checks test each immediate member as a standalone outbound, not every
surrounding chain or destination. URL-test groups are not supported by FFI.

Only one `cache_file_path` is allowed across all input files. Its absence disables
persistence; relative paths resolve against the process working directory.
The file is Shoes-specific versioned JSON, not a sing-box/Mihomo database. Parent
directories must exist, and Unix cache/lock files must be private. Explicit API
choices take precedence over `default`, then the first member. Startup/reload
never save defaults or rewrite YAML. Every accepted selection PUT saves before
publishing the new choice. Failed saves leave routing unchanged. An error after
atomic replacement can leave an unacknowledged choice on disk; logs report this
durability uncertainty. Saved entries for removed groups are retained. Both reads
and writes are limited to 1 MiB; remove obsolete entries only while Shoes is stopped.

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

See [the complete example](examples/clash_api.yaml). Controller connections share
a limit of 64, subscriptions 16, probes 16, and bound sockets 16. Request heads
must finish within 15 seconds of accept or the preceding response; ordinary
request bodies have a 10-second deadline and 64 KiB limit. Established subscriptions
are exempt from header idle expiry and have bounded queues/write deadlines.
Responses are limited to 32 MiB. An oversized connection snapshot closes its
WebSocket with code 1009 and reason `response exceeds 32 MiB`; tracking continues
without truncating the connection list.
Configuring a controller, `cache_file_path`, or any selector/url-test/fallback group enables the
catalog and its 16,384-node limit. Names must be nonempty, unique, at most 256
bytes, and contain no control characters. `DIRECT`, `REJECT`, and
`GLOBAL` are reserved. Configuration preparation rejects `/rules` or base
`/proxies` responses larger than 32 MiB. Group delay requests support at most
1,024 immediate members.

## Server Config

WireGuard servers require one literal UDP address with a nonzero port, or omit
the bind location when `peer_client_chain` is configured. They do not support
port ranges, multiple bind addresses, or Unix socket paths. See [WireGuard](#wireguard).

```yaml
# Bind to IP address and port
address: "0.0.0.0:8080"        # IPv4
address: "[::]:8080"           # IPv6
address: "0.0.0.0:443-445"     # Port range

# OR bind to multiple addresses and port ranges (`address` is also accepted)
addresses:
  - "127.0.0.1:22223"
  - "172.17.0.1:22223-22225"

# OR bind to Unix socket (TCP only)
path: "/tmp/shoes.sock"

# Protocol configuration (required)
protocol: ServerProxyConfig

# Transport layer (default: tcp)
transport: tcp | quic          # WireGuard only: udp (default, required)

# TCP settings (only when transport: tcp)
tcp_settings:
  no_delay: true               # Default: true

# QUIC settings (required when transport: quic)
quic_settings:
  cert: string                 # TLS certificate (path or named PEM)
  key: string                  # TLS private key (path or named PEM)
  alpn_protocols: [string]     # Optional ALPN protocols
  client_ca_certs: [string]    # Optional client CA certificates
  client_fingerprints: [string] # Optional client certificate fingerprints
  num_endpoints: int           # Optional, 0 = auto (based on thread count)
  key_exchange_groups: [X25519MLKEM768] # Optional; see TLS Key Exchange below

# Routing rules (default: allow-all-direct; WireGuard requires explicit nonempty rules)
rules: string | [RuleConfig]
```

## Server Protocols

### HTTP
```yaml
protocol:
  type: http
  username: string?            # Optional authentication
  password: string?
```

Accepts HTTP/1.0 and HTTP/1.1 CONNECT and absolute-form forwarding, plus
multiplexed TCP CONNECT over HTTP/2. H2 is detected from its connection preface;
cleartext H2 requires prior knowledge, not HTTP Upgrade. Authentication applies
independently to every H2 stream. A successful CONNECT response is sent only
after the destination connects.

H2 connections with no active tunnels close after 60 seconds; PINGs and rejected
authentication attempts do not extend that interval. Missing credentials receive
a 407 challenge. Incorrect credentials also begin connection shutdown, preventing
repeated password guesses on one carrier.

For HTTPS proxying, wrap HTTP in a TLS server and explicitly configure
`alpn_protocols: [h2, http/1.1]` on its TLS target. HTTP does not change the
parent layer's ALPN defaults. H2 GET/POST forwarding, extended CONNECT,
CONNECT-UDP, and HTTP/3 are not supported. This is standard HTTP proxying, not
NaiveProxy or XHTTP.

### SOCKS5
```yaml
protocol:
  type: socks                  # Aliases: socks5
  username: string?
  password: string?
  udp_enabled: true            # Default: true (enables UDP ASSOCIATE)
```

### Mixed (HTTP + SOCKS5)
```yaml
protocol:
  type: mixed                  # Aliases: http+socks, socks+http
  username: string?
  password: string?
  udp_enabled: true            # Default: true (enables UDP ASSOCIATE for SOCKS5)
```

Auto-detects HTTP (including H2 CONNECT) or SOCKS5.

### Shadowsocks
```yaml
protocol:
  type: shadowsocks            # Aliases: ss
  cipher: string               # See supported ciphers below
  password: string

# Supported ciphers:
# - aes-128-gcm
# - aes-256-gcm
# - chacha20-ietf-poly1305
# - 2022-blake3-aes-128-gcm
# - 2022-blake3-aes-256-gcm
# - 2022-blake3-chacha20-ietf-poly1305
```

### VMess
```yaml
protocol:
  type: vmess
  cipher: string               # aes-128-gcm, chacha20-poly1305, none
  user_id: string              # UUID
  udp_enabled: true            # Default: true (enables XUDP)
```

**Note:** VMess AEAD mode is always enabled. The legacy `force_aead` field is deprecated and non-AEAD mode is no longer supported.

Replay protection uses a process-wide cache of at most 65,536 Auth-IDs, shared across credentials, listeners, and reloads. Entries remain protected through their timestamp's 120-second validity window; future-dated IDs can occupy a slot for about four minutes. A full cache rejects new authentication rather than evicting live entries. Heavy traffic from one credential can therefore exhaust capacity for other VMess users in the same process. A backward system-clock step also pauses authentication until the clock catches up.

### VLESS
```yaml
protocol:
  type: vless
  user_id: string              # UUID
  udp_enabled: true            # Default: true (enables XUDP)
  fallback: string?            # Optional fallback destination for failed auth (e.g., "127.0.0.1:80")
```

### Trojan
```yaml
protocol:
  type: trojan
  password: string
  shadowsocks:                 # Optional encryption layer
    cipher: string
    password: string
```

### Snell v3
```yaml
protocol:
  type: snell
  cipher: string               # aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305
  password: string
  udp_enabled: true            # Default: true
  udp_num_sockets: 1           # Default: 1, sockets per UDP session
```

### TLS Server
```yaml
protocol:
  type: tls

  # Standard TLS targets (by SNI)
  tls_targets:                 # Aliases: sni_targets, targets
    "example.com":
      cert: string             # Certificate (path or named PEM)
      key: string              # Private key (path or named PEM)
      alpn_protocols: [string] # Optional ALPN
      client_ca_certs: [string] # Optional client CA certs
      client_fingerprints: [string] # Optional client cert fingerprints
      vision: false            # Enable Vision (requires VLESS inner protocol)
      key_exchange_groups: [X25519MLKEM768] # Optional; see TLS Key Exchange below
      protocol: ServerProxyConfig
      override_rules: [RuleConfig] # Optional rule override

  # Default TLS target (for unmatched/no SNI)
  default_tls_target:          # Aliases: default_target
    cert: string
    key: string
    # ... same fields as tls_targets

  # Reality targets (by SNI)
  reality_targets:
    "www.cloudflare.com":
      private_key: string      # X25519 private key (base64url)
      mldsa65_seed: string?     # Optional 32-byte ML-DSA-65 seed (unpadded base64url)
      short_ids: [string]      # Valid client IDs (hex, 0-16 chars)
      dest: string             # Fallback destination (e.g., "example.com:443")
      dest_client_chain: ClientChain?  # Optional proxy chain for reaching dest
      max_time_diff: 60000     # Max timestamp diff in ms (default: 60000)
      min_client_version: [1, 8, 0]  # Optional [major, minor, patch]
      max_client_version: [2, 0, 0]  # Optional [major, minor, patch]
      cipher_suites: [string]  # Optional TLS 1.3 cipher suites (see below)
      vision: false            # Enable Vision (requires VLESS inner protocol)
      protocol: ServerProxyConfig
      override_rules: [RuleConfig]

  # ShadowTLS v3 targets (by SNI)
  shadowtls_targets:
    "example.com":
      password: string
      handshake:
        # Local handshake (with own certificate):
        cert: string
        key: string
        alpn_protocols: [string]
        client_ca_certs: [string]
        client_fingerprints: [string]
        # OR Remote handshake (proxy to real server):
        address: string        # e.g., "google.com:443"
        client_proxies: [ClientConfig] # Optional proxies for handshake
      protocol: ServerProxyConfig
      override_rules: [RuleConfig]

  # Buffer size for TLS (optional, min 16384)
  tls_buffer_size: int
```

### WebSocket
```yaml
protocol:
  type: websocket              # Aliases: ws
  targets:
    - matching_path: string?   # Optional path filter (e.g., "/ws")
      matching_headers:        # Optional header filters
        X-Custom-Header: "value"
      protocol: ServerProxyConfig
      ping_type: ping-frame    # disabled | ping-frame | empty-frame
      override_rules: [RuleConfig]
```

### Port Forward
```yaml
protocol:
  type: forward                # Aliases: port_forward, portforward
  targets: string | [string]   # Target address(es)
```

### Hysteria2
```yaml
protocol:
  type: hysteria2
  password: string
  udp_enabled: true            # Default: true
```

### TUIC v5
```yaml
protocol:
  type: tuic                   # Aliases: tuicv5
  uuid: string                 # UUID
  password: string
  zero_rtt_handshake: false    # Default: false (enables 0-RTT for lower latency)
```

### AnyTLS
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

### NaiveProxy
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

## TUN Config

TUN (network TUNnel) devices operate at the IP layer (Layer 3), allowing shoes to act as a transparent VPN.

```yaml
# Linux: Create TUN device by name
device_name: string            # Device name (e.g., "tun0")
address: string                # Device IP address (e.g., "10.0.0.1")
netmask: string?               # Netmask (e.g., "255.255.255.0")
destination: string?           # Gateway/destination (Linux only)

# iOS/Android: Use existing file descriptor
device_fd: int                 # FD from VpnService (Android) or NEPacketTunnelProvider (iOS)

# Common settings
mtu: 1500                      # Default: 1500 (Linux), 9000 (Android), 4064 (iOS)
tcp_enabled: true              # Default: true
udp_enabled: true              # Default: true
icmp_enabled: true             # Default: true

# Routing rules
rules: [RuleConfig]
```

**Platform notes:**
- **Linux**: Requires root or `CAP_NET_ADMIN`. Creates device with specified name/address.
- **Android**: Use `device_fd` from `VpnService.Builder.establish()`. Routes configured via VpnService.
- **iOS**: Use `device_fd` from `NEPacketTunnelProvider.packetFlow`.

**Example (Linux):**
```yaml
- device_name: "tun0"
  address: "10.0.0.1"
  netmask: "255.255.255.0"
  mtu: 1500
  tcp_enabled: true
  udp_enabled: true
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        address: "proxy.example.com:443"
        protocol:
          type: tls
          protocol:
            type: vless
            user_id: "uuid"
```

## Client Config

Used in rules to specify upstream proxies.

```yaml
address: string                # Proxy server address (e.g., "proxy.example.com:1080")
protocol: ClientProxyConfig
transport: tcp | quic          # Default: tcp; WireGuard only: udp (default, required)
bind_interface: string         # Optional, Linux/Android/Fuchsia only

tcp_settings:
  no_delay: true

quic_settings:
  verify: true                 # Default: true
  server_fingerprints: [string]
  sni_hostname: string
  alpn_protocols: [string]
  cert: string                 # Client certificate for mTLS
  key: string                  # Client key for mTLS
  key_exchange_groups: [X25519MLKEM768] # Optional; see TLS Key Exchange below
```

WireGuard clients use `address` for their peer endpoint and reject TCP/QUIC
socket settings. See [WireGuard](#wireguard) for their protocol fields.

## Client Protocols

### Direct
```yaml
protocol:
  type: direct
```

### HTTP
```yaml
protocol:
  type: http
  username: string?
  password: string?
  http_version: h1             # h1 (default) or h2
  resolve_hostname: false      # Resolve destinations locally before CONNECT
```

Both versions establish TCP CONNECT tunnels. When the H2 proxy is the first and
only hop, eligible routes reuse a connection for multiple concurrent tunnels.
Chained H2 hops use the carrier established through the selected prefix rather
than sharing tunnels across routes. H1 retains its existing one-tunnel-per-connection behavior.
There is no automatic version fallback or replay after a failed CONNECT.

For H2 over TLS, set `http_version: h2` here and `alpn_protocols: [h2]` on
the enclosing TLS client. The handshake must negotiate `h2`. Omitted or explicit
`http_version: h1` preserves legacy behavior: it sends HTTP/1.1 without checking
the negotiated ALPN. Set `alpn_protocols: [http/1.1]` on the enclosing TLS client
when the peer requires ALPN to match the HTTP version. Cleartext H2 uses prior
knowledge. See [examples/http2-proxy.yaml](examples/http2-proxy.yaml).

### SOCKS5
```yaml
protocol:
  type: socks
  username: string?
  password: string?
```

### Shadowsocks
```yaml
protocol:
  type: shadowsocks
  cipher: string
  password: string
```

For `2022-blake3-aes-128-gcm` and `2022-blake3-aes-256-gcm`, a client can connect
to a multi-user server using `password: "server-key:user-key"`. Each component is
independently base64-encoded and must decode to 16 bytes for AES-128 or 32 bytes
for AES-256. For identity relays, use
`password: "relay-key:server-key:user-key"`, with identity keys in connection order
and the user key last. These are SS2022 extensible identity headers (EIH), not
separate entries in `client_chain`.

Single-key SS2022 configurations are unchanged. Identity chains are client-only
and are not supported by `2022-blake3-chacha20-poly1305`. Legacy Shadowsocks
passwords may still contain literal colons. Shoes does not accept multi-user
identity chains in server configurations.

`udp_enabled: true` on the client uses the same identity handshake for SagerNet
UDP-over-TCP and requires a UoT-capable upstream. It does not enable native
SS2022 UDP. See [examples/shadowsocks-2022-client.yaml](examples/shadowsocks-2022-client.yaml).

### Snell
```yaml
protocol:
  type: snell
  cipher: string
  password: string
```

### VMess
```yaml
protocol:
  type: vmess
  cipher: string
  user_id: string
  h2mux:                         # Optional h2mux multiplexing (see below)
    max_connections: 4
    min_streams: 4
    max_streams: 0
    padding: false
```

**Note:** VMess AEAD mode is always enabled. The legacy `aead` field is deprecated.

### VLESS
```yaml
protocol:
  type: vless
  user_id: string
  h2mux:                         # Optional h2mux multiplexing (see below)
    max_connections: 4
    min_streams: 4
    max_streams: 0
    padding: false
```

### Trojan
```yaml
protocol:
  type: trojan
  password: string
  shadowsocks:                 # Optional
    cipher: string
    password: string
  h2mux:                         # Optional h2mux multiplexing (see below)
    max_connections: 4
    min_streams: 4
    max_streams: 0
    padding: false
```

### H2MUX Multiplexing

H2MUX multiplexes multiple proxy streams over a single HTTP/2 connection, reducing connection overhead. Compatible with sing-box. Available for VMess, VLESS, and Trojan client protocols.

```yaml
h2mux:
  max_connections: 4           # Maximum connections to maintain (default: 4)
  min_streams: 4               # Min streams before opening new connection (default: 4)
  max_streams: 0               # Max streams per connection, 0 = unlimited (default: 0)
  padding: false               # Enable padding for traffic obfuscation (default: false)
```

**Server support:** H2MUX is auto-detected on servers. No configuration needed.

### TLS Client
```yaml
protocol:
  type: tls
  verify: true                 # Default: true
  server_fingerprints: [string]
  sni_hostname: string
  alpn_protocols: [string]
  tls_buffer_size: int
  cert: string                 # Client certificate for mTLS
  key: string                  # Client key for mTLS
  vision: false                # Enable Vision (requires VLESS inner protocol)
  key_exchange_groups: [X25519MLKEM768] # Optional; see TLS Key Exchange below
  protocol: ClientProxyConfig
```

### TLS Key Exchange

`key_exchange_groups` is an optional, ordered allowlist for ordinary TLS clients,
TLS server targets (including `default_tls_target`), and client/server
`quic_settings`. It applies to that TLS layer, regardless of the inner proxy
protocol. Supported names are case-sensitive:

- `X25519MLKEM768`: native rustls X25519 + ML-KEM-768 hybrid.
- `SecP256r1MLKEM768`: native rustls P-256 + ML-KEM-768 hybrid.
- `X25519`, `SecP256r1`, `SecP384r1`: classical groups.

Omitting the field preserves rustls defaults: currently X25519+ML-KEM-768 is
preferred, with classical fallback. An explicit list replaces those defaults;
the first client group normally supplies the initial key share. Empty lists, duplicates,
null, unknown names, standalone ML-KEM, and `SecP384r1MLKEM1024` are rejected.
No custom cryptographic implementations are used.

Client QUIC allowlists require a non-direct client at the first chain hop
(hop 0), where Shoes creates the QUIC transport. Explicit allowlists on direct
clients or later hops are rejected, including entries resolved from groups or
pools. Use ordinary TLS in a later hop's `protocol` when that hop needs its own
hybrid-protected tunnel.

To require hybrid exchange without classical fallback:

```yaml
key_exchange_groups: [X25519MLKEM768, SecP256r1MLKEM768]
```

Hybrid-only lists force TLS 1.3 and disable early application data. TLS 1.3
resumption remains enabled and still performs a fresh exchange using an allowed
hybrid group. Peers offering only classical groups or TLS 1.2 cannot connect.
For opportunistic hybrid exchange with explicit classical fallback, use a mixed
list such as `[X25519MLKEM768, X25519, SecP256r1]`.

Hybrid-only lists cannot be combined with `vision: true` on the same TLS layer:
Vision direct copy bypasses that layer's encryption. They also cannot be
combined with TUIC `zero_rtt_handshake: true`. Ordinary outer TLS or QUIC can
still protect a separate inner Vision connection. The setting does not apply to
REALITY, VLESS encryption, or ShadowTLS camouflage handshakes; it is rejected on
ShadowTLS configurations and with deprecated `shadowtls_password`.

Hybrid key exchange protects session-key establishment, not certificate
signatures. Certificate verification, fingerprints, and mTLS work as before.
`verify: false` without a trusted fingerprint still permits active impersonation.

### Reality Client
```yaml
protocol:
  type: reality
  public_key: string           # Server's X25519 public key (base64url)
  mldsa65_verify: string?      # Optional pinned 1952-byte ML-DSA-65 key (unpadded base64url)
  short_id: string             # Your client ID (hex, 0-16 chars)
  sni_hostname: string         # SNI to send (must match server's reality_targets key)
  cipher_suites: [string]      # Optional TLS 1.3 cipher suites (see below)
  vision: false                # Enable Vision (requires VLESS inner protocol)
  protocol: ClientProxyConfig  # Inner protocol (typically VLESS)
```

**Reality cipher suites:** Valid values are `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`. If not specified, all three are offered/supported.

Reality offers `X25519MLKEM768` first, with X25519 fallback. Servers follow the camouflage target's selected group; choose a PQ-preferring TLS 1.3 target to negotiate hybrid key exchange. Legacy X25519 clients remain supported. Debug logs report the authenticated connection's `negotiated_group`.

For Xray servers, use v25.5.16 or newer. Xray v25.4.30 and earlier cannot synthesize a hybrid-selected target handshake: when a PQ-capable target selects `X25519MLKEM768`, those servers forward to the real target and Shoes rejects its certificate. X25519 fallback does not prevent this failure because the target has already selected the hybrid group.

`mldsa65_seed` enables optional server signing. Clients with `mldsa65_verify` require a matching signature and reject unsigned or incorrectly signed connections. These fields correspond to Xray's `mldsa65Seed` and `mldsa65Verify`; neither replaces the existing X25519 key. Omit the fields to disable this extra authentication; empty or incorrectly sized values are invalid.

Enable server signing before distributing verification keys. The camouflage certificate flight must have room for the extra 3309-byte signature and DER overhead; insufficient capacity falls back to the real target instead of silently removing the signature. Removing signing later requires coordinating clients that already pin its key. Vision's direct mode relies on the inner TLS connection for payload encryption, not the outer Reality hybrid exchange.

### ShadowTLS Client
```yaml
protocol:
  type: shadowtls
  password: string
  sni_hostname: string?        # Optional SNI override
  protocol: ClientProxyConfig
```

### WebSocket Client
```yaml
protocol:
  type: websocket
  matching_path: string?
  matching_headers:
    header_name: string
  ping_type: ping-frame        # disabled | ping-frame | empty-frame
  protocol: ClientProxyConfig
```

### Port Forward (No-op)
```yaml
protocol:
  type: portforward            # Aliases: noop
```

Passes through the raw connection without protocol wrapping. Useful for testing or transparent proxying.

### AnyTLS Client
```yaml
protocol:
  type: anytls
  password: string             # User password
  udp_enabled: true            # Default: true (enables UDP over TCP)
  padding_scheme: [string]?    # Optional custom padding scheme
```

### NaiveProxy Client
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

## Native DNS Freshness

Omitting a listener's `dns` or leaving `dns.servers` empty uses native OS/NSS
hostname resolution with a **60-second application memoization window**. The
same default resolver serves controller probes. The window starts when a
successful lookup finishes; an entry expires at the window boundary. All returned
usable addresses and their original order are retained.
Errors and empty results are not cached, and expired answers are not served on
failure. Each cache has a lazy, bounded 10,000-entry LRU keyed by exact hostname;
results are shared across ports, with each caller receiving its requested port.
Eviction can cause earlier refresh. Concurrent misses share a lookup, up to
1,024 participating callers per resolver. Excess callers look up independently;
this is not an OS lookup concurrency cap. Cancelling the owner makes surviving
callers retry within their remaining deadlines. No background refresh is added,
and already-running OS calls cannot be stopped.

Explicit `dns: {servers: system}` continues to use OS/NSS lookup **without
application memoization or concurrent lookup sharing**. To select a different
fixed window, use a system server options object, inline or in a named DNS group:

```yaml
dns:
  servers:
    url: system
    native_cache_secs: 15
```

`native_cache_secs` accepts an integer from 0 to 4294967295 seconds. Omitted or
`0` disables memoization for this explicit system entry. It is rejected on
non-system upstreams, including when set to `0`; unknown options and invalid
values are rejected. The option belongs to the server options object, not the
outer `dns` object. Existing `timeout_secs` remains a lookup deadline, not cache
freshness; `connect_timeout_secs` and `attempts` do not control native caching.

This is a load/freshness trade-off, **not DNS TTL compliance**: the OS lookup API
does not provide record TTLs. Shorter windows increase OS lookups; disabling the
Shoes cache cannot bypass caches in the OS, NSS modules, or upstream resolvers.
Native hosts-file/NSS behavior is preserved. New flows can see updated answers
after expiry; established flows retain their pinned destination. This setting
controls native hostname lookup caching, not every DNS-related cache. Hickory
caches and Fake-IP mappings/TTLs are unchanged.

See [the DNS tuning example](examples/dns_tuning.yaml).

## Fake DNS

Fake DNS is opt-in on a server (including WireGuard) or TUN configuration:

```yaml
dns:
  servers: "tls://1.1.1.1"
  fake_ip: true
```

It intercepts logical TCP and UDP destinations on port 53 after inbound
authentication/admission, before destination rules. It does not open a DNS
listener or intercept encrypted DNS. Intercepted DNS is answered locally or
forwarded through `dns.servers`, never to the application's requested resolver.
An explicit rule override to port 53 is ordinary forwarding, not interception.

A/AAAA synthesis creates scoped mappings. Later connections to those addresses
restore the hostname before routing or hostname sniffing. A restored hostname is
resolved normally when a rule or direct connection needs a real IP; a proxy can
receive the hostname instead. With `sniff: true`, visible TLS SNI or HTTP Host
takes precedence for hostname rules only; the restored name remains the
connection target and is what IP rules resolve. Both hints are client-controlled,
so a different sniffed name can bypass a hostname deny rule on the restored name.
Unmapped addresses inside the receiving context's ranges fail closed. Addresses
from another context's non-overlapping range are not recognized and are routed
as ordinary IPs. Overlapping ranges may map to an unrelated hostname in the
receiving context. Use one shared named DNS group for inbounds serving the same clients.
Established flows keep their chosen target.

`false` disables the feature. An options object enables it with these defaults:

```yaml
fake_ip:
  ipv4_range: "198.18.0.0/15"
  ipv6_range: null
  max_entries: 65536
  bypass_domains: []
  missing_family: forward
  https_records: forward
  state_file: null
```

- Pools must be CIDRs with usable addresses; reserve non-conflicting ranges
  and route them through the same ingress. The base and base+1 addresses are
  reserved, as is IPv4 broadcast. Real upstream, bootstrap, proxy, configured
  forwarding/fallback targets, and literal rule-override addresses cannot be
  inside any active or retained fake range. These checks apply even to inbounds
  without Fake DNS or with it explicitly disabled.
- TUN interface and gateway addresses cannot overlap any active or retained
  pool, except its reserved base+1 address. An address inside overlapping pools
  must be reserved in every one of them, regardless of the TUN's DNS context.
- `max_entries` bounds retained domain mappings, not the allocation range.
  Least-recently-used domains are evicted; sequential allocation traverses the
  entire range before reuse. Synthetic answers have a 60-second TTL. This is
  not a guarantee that a mapping remains valid for 60 seconds under pressure.
- `bypass_domains` uses the normal hostname-mask suffix matching, including
  subdomains. Excluded names and IP-shaped questions are forwarded.
- `missing_family: forward` forwards queries for a disabled family;
  `nodata` returns an empty successful answer instead.
- `https_records: forward` preserves HTTPS/SVCB answers; `suppress` returns
  empty successful answers for both types. Forwarded address hints and ECH can
  bypass hostname-based routing; suppression trades away those capabilities.
- Other record types use real upstream exchange. Valid negative/error answers
  are retained. Multi-question queries receive FORMERR; TSIG/SIG(0), zone
  transfers, and non-query operations are refused. Synthesized answers are
  unsigned and do not claim DNSSEC authentication.

Named DNS groups share one pool across every referencing inbound:

```yaml
- dns_group: shared-fake
  dns_servers: ["tls://1.1.1.1"]
  fake_ip: true
- address: "0.0.0.0:1080"
  protocol: {type: socks}
  dns: {servers: shared-fake}
```

Inline `fake_ip` creates a private context, even when `servers` references a
named group. Omit the inline override to share the group's mappings. Combining
fake-enabled groups requires an explicit policy on the composed group.

Private context identity uses the server transport and configured listen addresses
(including their order), or the Unix socket path. TUN contexts use `device_name`
(`default` when omitted); WireGuard contexts use the name/public-key identity
described above. Changing these inputs changes private pool and snapshot ownership.
Use a named `dns_group` when ownership must survive listener changes or address
reordering. An existing state file with a different owner is rejected.

Compatible reloads retain mappings, including explicit disable/re-enable under
the same group/inline identity. Pool ranges, capacity, or state-file ownership
changes require restart. Without `state_file`, restart loses the mappings.
Previously active synthetic ranges and endpoints remain excluded from real DNS,
carrier resolution, and configured forwarding/override targets until restart,
including after a context is removed.
With a state file, snapshots are private, atomically replaced, locked against
multiple writers, and checked for pool and context identity compatibility. Create its parent directory
before startup; protect it because the file records queried domains. State filenames
must not end in `.lock` (case-insensitive); that suffix is reserved for ownership locks. Cursor
reservations are persisted before issuance; a crash can lose recent mappings,
which then fail closed rather than restoring an obsolete owner. Back up or
explicitly remove incompatible state before changing its pool configuration.
Persistent families need at least two allocatable addresses, and persistent pools
are limited to 383,473 entries to fit the snapshot read limit; unusually long
context names reduce the available snapshot capacity. Reservations may
skip unused addresses after restart; Windows power-loss durability and state-file
ACLs require platform-specific verification.

Omitted `servers` uses system DNS. Desktop discovery is a periodically refreshed
endpoint snapshot, not the OS's complete split/scoped DNS policy. Keep discovered
resolvers and any loopback stub's own upstream traffic outside TUN capture to
avoid recursive interception. Android/iOS hosts must supply underlying real
`dns.servers` explicitly; automatic VPN system discovery is not supported.
Host-local TUN deployments should configure explicit real upstreams: native
hostname lookups can otherwise re-enter the host's intercepted resolver.
Fake-enabled system configurations fail startup if no usable endpoints can be
discovered. Later upstream failures produce DNS failure, not a public-provider fallback.
UDP and HTTP/3 upstreams remain direct-only; TCP/TLS/HTTPS can use client chains.
UDP truncation retries TCP only when that transport is explicitly configured.
Groups with mixed upstream settings try their remaining configured resolvers for
a complete successful or negative reply before returning a truncated answer.
The retained truncated reply is returned if fallback fails or reaches the
forwarding deadline; it still passes the real-address guards.
Local UDP DNS peers process one query at a time with bounded backpressure; a
forwarded query can delay subsequent synthetic answers until its deadline.

SOCKS, UoT, H2MUX, XUDP, Hysteria2, and TUIC preserve the original logical reply
address. Snell's reply format supports only IP addresses: hostname-addressed
DNS requires a real lookup for its reply identity and fails if that lookup
fails. Literal-address DNS interception remains fully local on Snell.

See [the shared-pool example](examples/fake_dns.yaml).

## Rules System

Rules determine how incoming connections are routed.

<a id="tls-sni-routing"></a>

### TCP Hostname Sniffing

Set `sniff: true` on a server (including WireGuard) or TUN configuration to use
visible TLS ClientHello SNI or cleartext HTTP/1.0 and HTTP/1.1 Host for hostname
rules. The default is `false`. The option applies to logical TCP streams,
including multiplexed and QUIC-carried TCP, not UDP/QUIC Initial packets,
HTTP/2 or HTTP/3 application headers, or the outer TLS carrier handshake.
Nested `override_rules` inherit the setting.

Sniffing applies to literal IP targets, including restored Fake DNS mappings,
when hostname rules exist. Explicitly supplied hostnames are not sniffed. The
sniffed hostname takes precedence over the restored DNS name for hostname rules
only. IP/CIDR masks and the outbound destination still use the original real IP or restored
DNS hostname, including through proxy chains. IP rules resolve the restored
hostname when needed, never the sniffed name. An explicit rule `override_address`
can still change the destination.

Capture is best-effort, limited to 300 ms and 64 KiB of wire data. Unknown,
malformed, oversized, or incomplete TLS or HTTP falls back to ordinary routing
using the original IP or restored DNS hostname; captured bytes are replayed
unchanged.
Transport errors still terminate the connection.
Server-first applications can incur the full delay. When more client bytes are
needed, response-gated protocols send success before routing/dialing; a later
failure closes or resets the stream rather than sending another status.

HTTP inspection accepts origin-form requests (`GET /path HTTP/1.1`) and
`OPTIONS *`, on any destination port. It requires a complete CRLF-delimited
header section with exactly one valid Host and at most 128 fields. Host names
are matched case-insensitively with an optional terminal DNS dot; a numeric port
is validated but never changes the destination or rule-matching port. IP-literal
Host values, duplicate Host fields, absolute-form requests, and CONNECT requests
produce no hint. Request bodies are not parsed or awaited.

The probe sees application bytes after proxy setup: the outer CONNECT headers
are not sniffed. A plaintext request inside a tunnel exposes Host; an inner
HTTPS connection still exposes only visible TLS SNI. Normal HTTP forward-proxy
requests are rewritten to origin-form before reaching the probe.

Routing happens once per logical TCP stream. Later keep-alive or pipelined
requests with different Host values, and traffic after an HTTP Upgrade, remain
on the first route without another hostname check. Existing `sniff: true`
configurations now also use HTTP Host; omitted or false settings are unchanged.
See [the HTTP Host example](examples/http_host_sniffing.yaml).

SNI and Host are client-controlled, not authenticated identity or a domain
firewall. Put mandatory IP deny rules before hostname allows. With ECH, only the
visible outer name is available, not the encrypted inner hostname.
For Fake DNS flows, that outer name takes precedence over the restored hostname
for hostname rules. Disable `sniff` when routing must follow the restored name,
or configure rules for the ECH public names.

### Rule Config
```yaml
rules:
  - masks: Mask | [Mask]      # Strings, typed predicates, file sources, or group references
    no_resolve: boolean?      # Default false; known IPs still participate
    action: allow | block     # Default allow
    # For action: allow
    override_address: string?  # Optional address override
    client_chain: ClientChain | [ClientChain]  # Proxy chain(s) for routing
```

### Client Chains

Client chains define how traffic is routed through upstream proxies. Each chain is a sequence of "hops" - proxies that traffic passes through in order.

```yaml
# Single proxy (simplest form)
client_chain: my-proxy-group           # Reference a named group
client_chain:                          # Or inline config
  address: "proxy.example.com:1080"
  protocol:
    type: socks

# Multi-hop chain (traffic goes: client -> hop1 -> hop2 -> target)
client_chain:
  chain:
    - first-proxy-group
    - second-proxy-group

# Multiple chains (round-robin selection)
client_chains:
  - us-proxy-group                     # Chain 1: single hop
  - chain: [proxy1, proxy2]            # Chain 2: multi-hop

# Load balancing at a hop (pool)
client_chain:
  chain:
    - pool: [us-proxies, eu-proxies]   # Round-robin between pool members
    - final-proxy
```

**Migration note:** The `client_proxy` / `client_proxies` fields still work but are deprecated. Please migrate to `client_chain` / `client_chains`.

### Mask Syntax
```yaml
# IP/CIDR masks
masks: "0.0.0.0/0"             # Any destination, including hostnames and IPv6
masks: "::/0"                  # Same legacy universal predicate
masks: "192.168.0.0/16"        # Subnet
masks: "10.0.0.1:80"           # Specific IP and port

# Hostname masks
masks: { subdomains: [google.com] } # Descendants, excluding the apex
masks: "example.com"           # Name and all descendants

# Multiple masks
masks:
  - "192.168.0.0/16"
  - "10.0.0.0/8"
  - "internal.com"
```

### Built-in Rule Groups
- `allow-all-direct` - Allow all connections, direct routing
- `block-all` - Block all connections

### Typed Destination Predicates

`masks` accepts legacy strings, typed predicates, file sources, and action-free
group references. A list combines its entries with OR. Predicate objects contain
one operator: `all`, `any`, `not`, or a leaf. The same forms work recursively inside
`all`/`any`/`not`; strings always remain legacy masks, never group names or paths.
Lists inside a typed leaf are alternatives.

Keep mixed legacy masks and imported groups in one OR list: splitting them into
separate policies can change ordered DNS evaluation.

```yaml
rules:
  - masks:
      all:
        - domain_suffix: [example.com]
        - destination_port: [443]
    action: allow
  - masks: { any_destination: true }
    action: block
```

Leaves: `domain` (exact), `domain_suffix` (apex and descendants), `subdomains`
(descendants only), `domain_pattern` (`*` matches one label), `domain_keyword`,
`domain_regex`, `ip_cidr`, `destination_port`, `destination_port_range`
(inclusive `"8000:9000"`), and `any_destination: true`. Native domain literals
and keywords are case-insensitive. Regexes are unanchored and case-sensitive
unless they enable case folding; backreferences, lookaround and non-ASCII
patterns are unsupported. Typed ports are 1-65535. Empty sets match nothing;
empty `all`/`any` nodes are rejected.

Policies still use first-match order. Inside one policy, a known OR match or AND
miss can avoid DNS, regardless of predicate order. An earlier unresolved policy
cannot be bypassed by a later domain rule. IP predicates use the selected local
DNS answer, pinning it for direct dialing; lookup failure aborts routing. Direct
multi-address fallback is disabled after this pinning. Hostname-forwarding proxy
protocols may still resolve independently at the exit.

`no_resolve: true` on a rule prohibits initiating DNS, but consumes an address
already supplied/resolved. Without an address, IP predicates remain unknown,
including under `not`; an undecidable policy falls through even when its action
is `block`. Domain predicates without a hostname are false, including for
literal-IP connections without a sniff hint. No reverse DNS is performed.

Migration: legacy `*.x` and `.x` masks are rejected at startup and reload; replace
them explicitly with `subdomains` or `domain_pattern`. Bare masks still include
the apex and descendants. Legacy `/0` masks remain universal without DNS, but
typed `ip_cidr: ["::/0"]` is IPv6-only and requires an IP. Other legacy IPv6 masks
no longer match IPv4 through numeric overlap; mapped-only legacy masks normalize
to IPv4 with a warning. Explicit typed mapped IPv6 predicates must use IPv4
spelling. Invalid supplied hostnames (including non-ASCII, whitespace, empty
labels and excessive length) are now rejected even with catch-all-only rules;
use A-label/punycode names. Invalid sniff hints are ignored. Matching strips one
root dot and lowercases ASCII without changing the dial target.

### Local Rule Sources

Declare an action-free `rule_group` containing file paths, or load a file inline
under `masks`. Sources are read and compiled during validation, including `--dry-run`,
before a reload stops existing listeners. Invalid sources reject the candidate.
Automatic reload watches imported files as well as configs. A parseable rejected
candidate keeps its source paths watched, so creating or repairing a missing file
can recover without another config edit. Active sources remain watched until a
replacement activates. `--no-reload` disables automatic full reloads; SIGHUP
still reloads, and live server-certificate rotation remains enabled.
Established connections retain their original rules until they drain. New routing
caches belong to the new configuration; Fake DNS pools are preserved separately.

```yaml
- rule_group: blocked
  rules:
    - lists/domains.srs
    - path: lists/addresses.json
      format: singbox_json

- address: "0.0.0.0:1080"
  protocol: {type: socks}
  rules:
    - masks: {rule_group: blocked}
      action: block
    - masks: {path: lists/extra.srs}
      action: block
    - masks:
        - "192.168.0.0/16"
        - "internal.example"
        - path: lists/direct.txt
          behavior: domain
      action: allow
```

Sources and groups also compose with typed predicates:

```yaml
rules:
  - masks:
      all:
        - rule_group: blocked
        - destination_port: [443]
        - not: {path: lists/exceptions.srs}
    action: block
```

File groups OR their sources together. A source is a path string inside a group's
`rules`, or an object with `path` and optional `format`, `behavior`, `code`, and
`attributes`. Inline sources under `masks` require the object form; a mask string
is always an IP/CIDR/hostname. For example, `masks: blocked` matches that hostname,
not the group above. No filesystem or name-existence heuristic changes this.

Actions and routing options belong to the referencing policy, not the sources.
Omitting `action` still means `allow`; an action-free group does not imply block.
Source objects reject action fields and cannot be mixed with predicate operators.
Sources with the same canonical path and decoding options share one compiled
set, including across named groups and inline uses. DAT codes and attribute
names are case-insensitive; attribute order and duplicates do not affect sharing.
For MRS, omitted and explicitly supplied `behavior` values use separate cache
entries. Each generation accepts at most 1,024 distinct sources.

Explicit `format` overrides detection. Otherwise SRS and
Zstd signatures select the SRS and MRS decoders, followed by case-insensitive
`.srs`, `.mrs`, `.json`, `.yaml`/`.yml`, and `.txt` suffixes. Zstd data must still
contain a valid MRS payload. Unknown formats require an explicit `format`; DAT
always requires `geosite_dat` or `geoip_dat`. YAML/text still require `behavior`.

Source paths are relative to the declaring config file, including inline sources
inside nested predicates and protocol overrides, even when multiple configs are
combined. FFI string configs require absolute source paths. Existing
PEM `cert`/`key` paths remain relative to the working directory; absolute paths
avoid mixing these conventions.

SRS versions 1-5 and sing-box source versions 1-5 support destination domain,
suffix, keyword, regex, IP, port, inversion and nested logical rules. Unsupported
fields, tags and versions fail validation, including inside inverted expressions.
Source address alternatives form an OR; destination ports constrain that OR.
An empty top-level set matches nothing. Empty individual rules are invalid.
sing-box literal spelling is preserved: uppercase domain/suffix/keyword entries
cannot match normalized lowercase queries and produce a warning. Regex patterns
retain their own case flags; only the bounded ASCII Rust regex subset is accepted.

Files are limited to 64 MiB, inflated payloads to 256 MiB, and compilation has a
512 MiB conservative allocation budget. Each source is limited to 2 million
entries. Temporary decode/build charges are released between sources; retained
indexes count toward the generation budget. These are safety ceilings, not a mobile
memory guarantee. Runtime regex caches are separate per worker and generation;
capture tracking is disabled and each lazy-DFA cache is capped at 256 KiB.
Regex groups accept at most 512 KiB of pattern text, with syntax-proportional
compilation reserves. Remote URLs and GeoIP `.db` (MMDB) files are not supported;
use country SRS files from sing-geoip instead.

Mihomo providers use `format: mihomo_yaml` (a `payload` string list),
`format: mihomo_text` (one entry per line, blank lines and `#`/`//` comments ignored;
one leading UTF-8 BOM is accepted),
or `format: mrs`. YAML/text require `behavior: domain`, `ipcidr`, or `classical`.
MRS supports domain/IP only; an optional configured behavior must match its header.
MRS accepts one zstd frame with at most an 8 MiB window.
YAML supports block and flow sequences in one mapping containing only `payload`;
tags, anchors, aliases and multiple documents are rejected. Parser read-ahead
between events is limited to 128 KiB, including comments and whitespace.

Domain providers distinguish bare exact names, `+.example.com` (apex and all
descendants), `.example.com` (descendants only), and `*` as one whole nonempty
label. Literal labels are case-insensitive. Classical providers accept `DOMAIN`,
`DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `DOMAIN-REGEX`, `IP-CIDR`, `IP-CIDR6`, and
`DST-PORT`. Entries are alternatives, not paired independent lists. IP entries
may end with `,no-resolve`; destination ports accept `80/443/8000-9000`.
Other operators/options fail validation. Classical keywords and regexes are
case-insensitive, with inline regex case overrides preserved. Unlike some Mihomo
classical paths, Shoes normalizes incoming query names to lowercase.

Xray geodata uses explicit `format: geosite_dat` or `format: geoip_dat`, with a
required case-insensitive `code: CN` category selector. GeoSite optionally accepts
`attributes: [ads]`: every listed attribute must have a true boolean value on the
domain. Unlike Xray's key-presence filters, false, integer and key-only attributes
do not satisfy this filter. Inline `@` selectors and other selection syntax are
rejected. GeoIP supports `reverse_match` and separate IPv4/IPv6 membership.
The loader scans protobuf framing without decoding unselected category bodies;
selected entries reject unknown fields/enums and unsupported regex syntax.
DAT has no relation to the MMDB `.db` files in sing-geoip releases.

### Example Rules
```yaml
rules:
  # Direct connection for local networks
  - masks: ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
    action: allow
    client_chain:
      protocol:
        type: direct

  # Block specific domains
  - masks:
      any:
        - subdomains: [ads.example.com]
        - domain_suffix: [tracking.example.com]
    action: block

  # Route through upstream proxy
  - masks: "0.0.0.0/0"
    action: allow
    client_chain:
      address: "proxy.example.com:1080"
      protocol:
        type: socks
```

## Named Groups

### Client Proxy Group
```yaml
- client_group: my-upstream
  client_proxies:              # Define proxies in this group
    - address: "proxy1.example.com:1080"
      protocol:
        type: socks
    - address: "proxy2.example.com:1080"
      protocol:
        type: socks

# Reference in rules
- address: "0.0.0.0:8080"
  protocol:
    type: http
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain: my-upstream  # Reference by name
```

### Rule Group

A group contains either ordered policies or action-free file sources. Member shape
determines its kind: objects with `masks` are policies, even when `action` is
omitted; paths and `{path: ...}` objects are sources. Empty groups and mixed kinds
are rejected. Both kinds share one namespace, including built-in names. `rule` is
an alias for `rules`; either accepts one item directly or a nonempty list.

Policy groups are referenced from `rules` or `override_rules`, preserving order,
actions, and routing options. Source groups are referenced only with
`masks: {rule_group: name}`, with the caller's action. Cross-kind references are
errors: actions are never discarded or invented. Group nesting is not supported.

```yaml
- rule_group: standard-rules
  rules:
    - masks: ["192.168.0.0/16"]
      action: allow
      client_chain:
        protocol:
          type: direct
    - masks: "0.0.0.0/0"
      action: allow
      client_chain: my-upstream

# Reference in server config
- address: "0.0.0.0:8080"
  protocol:
    type: http
  rules: standard-rules        # Reference by name
```

## Named PEMs

Define certificates once and reference throughout configuration.

```yaml
# From file
- pem: my-cert
  path: /path/to/certificate.pem

# Inline data
- pem: my-key
  data: |
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----

# Reference in config
- address: "0.0.0.0:443"
  protocol:
    type: tls
    tls_targets:
      "example.com":
        cert: my-cert          # Reference by name
        key: my-key
        protocol:
          type: http
```

## Certificate Sources

Ordinary TLS targets and QUIC listeners can share a named certificate source.
Use `certificate_source` instead of `cert` and `key`; combining them is an error.
Existing inline certificates, file paths, and named PEMs remain supported.

```yaml
- certificate_source: public
  type: files
  cert: /etc/shoes/certs/fullchain.pem
  key: /etc/shoes/certs/privkey.pem

- address: "0.0.0.0:443"
  protocol:
    type: tls
    tls_targets:
      proxy.example.com:
        certificate_source: public
        protocol: {type: trojan, password: change-me}

- address: "0.0.0.0:443"
  transport: quic
  quic_settings:
    certificate_source: public
  protocol: {type: hysteria2, password: change-me}
```

There is one runtime worker per source, not per listener. File sources use the
same filesystem watcher machinery as configuration files, with a 250 ms quiet
period after the last relevant event. They support atomic rename and symlink
replacement. Both the full certificate chain and its matching private key must
validate before publication. Separate file writes, missing files, malformed
data, key mismatches, and invalid validity
periods leave the last good pair in place. Failed updates retry every second;
a 60-second internal reconciliation also recovers missed events or unavailable
watches. Neither interval is a configuration setting. Errors are rate-limited
and never include private material. An expired source fails new handshakes
rather than serving a substitute certificate. Existing connections continue
uninterrupted.

Initial file-source loading (including legacy paths) rejects expired or not-yet-valid
chains, malformed or misordered chains, and PEM files larger than 1 MiB. A rejected
configuration reload leaves the current listeners running and watches the candidate's
file paths so repairing the pair retries the reload. After activation, identity-only
changes use live rotation, not a full reload.

**Upgrade warning:** These checks also apply to existing `cert`/`key` file paths
and file-backed named PEMs, even without a configuration change. Previously accepted
expired or not-yet-valid certificates and misordered bundles now reject at startup;
running file sources stop serving at expiry, including when clients disable
verification or pin a fingerprint. Renew expired certificates, put bundles in
leaf-to-issuer order, remove expired cross-signs and certificates outside that chain,
and synchronize the system clock before starting Shoes. Child-to-issuer signatures
must use algorithms supported by the TLS provider: no SHA-1, and RSA issuer keys
must be at least 2048 bits. Reissue certificates with unsupported signatures.
Inline-only pairs retain their previous static behavior.

Legacy `cert`/`key` paths, including paths referenced through named PEMs, also
rotate live through these watches. Inline-only pairs stay static. This applies
to ordinary inbound TLS and QUIC, including Hysteria2, TUIC and XHTTP. Outbound
client certificates, trust roots, and local ShadowTLS handshake certificates
instead trigger a full CLI configuration reload when their referenced files
change, including named PEM references. If a file serves both roles, a full
reload is still necessary. REALITY's handshake behavior is unchanged.

New handshakes use the current certificate without replacing TCP listeners or
QUIC endpoints. TLS session state is scoped to the certificate generation and
the listener's security policy: sessions resume within a generation, but not
across rotation or expiration. Existing TCP and QUIC sessions are not retired.

### Built-in ACME

ACME uses `instant-acme` and explicitly configured domains. Start with your CA's
staging directory. No certificate is issued during `--dry-run`.

```yaml
- certificate_source: public
  type: acme
  domains: [proxy.example.com]
  directory_url: https://acme-staging-v02.api.letsencrypt.org/directory
  state_dir: /var/lib/shoes/acme/public
  contacts: [mailto:operator@example.com]
  # Read the CA's terms, then set this to its exact meta.termsOfService URL.
  terms_of_service: https://example.invalid/replace-with-accepted-ca-terms-url
  challenge:
    type: http01
    listen: ["0.0.0.0:8080"]
```

Reference `public` from TLS or QUIC as in the file-source example. Domains must
be unique lowercase ASCII DNS names (use punycode for internationalized names).
Every named TLS target using an ACME source must be covered by its domains.
There is no issuance based on incoming SNI.

`terms_of_service` is explicit acceptance of that exact URL, not blanket
acceptance of future terms. Shoes checks the directory's `meta.termsOfService`
before account operations and refuses a changed URL. Review new terms and
update the configuration to accept them. If a private CA publishes no terms,
omit this field; a subsequently advertised terms URL still requires explicit
acceptance. Accounts requiring external account
binding are not supported in this version.

HTTP-01 requirements:

- The CA must reach public TCP port 80 for every domain, forwarded to one of the
  explicit `listen` addresses. Shoes never implicitly binds port 80.
- The challenge listener is independent of proxy listeners, so UDP-only QUIC
  deployments can use HTTP-01. A reverse proxy/CDN must forward the exact
  `/.well-known/acme-challenge/` path and original Host header.
- Listen addresses must not overlap another HTTP-01 source or a TCP proxy
  listener. Use a single multi-domain source when sharing the challenge address.
  Dry-run checks literal addresses and port ranges; a hostname-bound TCP
  listener on the same port is conservatively treated as a conflict.
- Only exact, pending, unexpired GET challenges are answered. Unknown tokens
  return 404. Headers are limited to 8 KiB / 32 fields, with at most 64 concurrent
  connections per address and a 10-second request lifetime.

For TLS-ALPN-01, replace the `challenge` mapping with:

```yaml
  challenge: {type: tls_alpn01}
```

The CA must reach public TCP port 443, forwarded to an existing outermost Shoes
TLS listener covering every configured domain. This is not QUIC, ShadowTLS or
REALITY validation. An intermediate TLS terminator must pass the handshake
through, including SNI and ALPN. Shoes only answers the sole offered protocol
`acme-tls/1` for a pending configured SNI. The short-lived challenge response
uses the RFC 8737 critical `acmeIdentifier` extension and never enters the proxy
handler or replaces the ordinary certificate. Normal ALPN, client authentication,
fallback routing and QUIC policy are unchanged.

At first start, proxy and challenge listeners bind before issuance begins.
Normal handshakes for a source without a certificate fail until issuance
succeeds; `Servers ready` means listeners are bound, not that ACME has finished.
A valid cached certificate allows immediate startup during a CA outage.

Shoes persists the account key before registration, account credentials,
in-progress orders and CSR keys, and the certificate/key pair in one atomically
replaced, synced state file. Do not edit it or share it between sources. On Unix,
the state directory must be owned by the running user with mode 0700, and files
use 0600. Other platforms use their inherited filesystem access controls; place
the directory in private application storage. An exclusive OS file lock prevents
multiple processes or embedded lifecycles from owning the same directory.
Back up the whole directory securely. Changing the CA or domain list requires a
distinct state directory; staging and production must never share one.

Renewal normally begins with one third of the certificate's lifetime remaining.
ARI is checked while idle and can request earlier renewal when the CA and
certificate support it. Its Retry-After applies only to ARI; optional checks,
including account setup, cannot delay due renewal. The source worker alone
schedules requests and durable deadlines. Pending orders use a five-second
polling interval unless the CA requests a longer wait. Transient
failures preserve valid material and use jittered exponential backoff from 60
seconds to 6 hours, honoring longer CA Retry-After values. Retry-After waits over
100 years or outside the platform clock range are rejected. Each worker step is
bounded to 10 minutes. Pending and processing orders are polled until the CA
completes, invalidates, or removes them. A completed pair is persisted before
it becomes live. Storage errors do not publish an unpersisted replacement.
Order retry deadlines, including successful finalization and resumed orders,
survive restart; startup logs an inherited delay rather than bypassing it.
The failure backoff resets after installation or healthy idle, not after a
deferred wake or a successful intermediate order step. Its exponent is kept
in memory; the selected deadline survives restart.
ARI retry deadlines also survive restart, including failed ARI responses.
Missing or invalid orders are discarded so a later attempt can create a new one.
Certificate failures and inherited retry delays are visible with the default
error-only logging; successful issuance and rotation use the info level.
During deferred polling, pending challenge responses remain
available until their 10-minute lease expires, the order leaves the pending
state, or the source is stopped.

CA traffic goes directly through the OS resolver and Shoes' protected TCP socket
helper, not through proxy rules or the certificate being issued. HTTPS verifies
the CA hostname and public roots. Optional `ca_cert: /path/to/test-ca.crt`
replaces those roots for a private CA. Requests have a 30-second total timeout,
32 KiB response header limit and 1 MiB response body limit; redirects are not
followed. Plain HTTP directories/endpoints are accepted only on numeric loopback
addresses for local testing. Never disable verification for a public CA.

Configuration reload reuses unchanged sources and their workers, accounts and
pending challenges. Changed sources hand off storage and challenge listeners
when a validated reload commits. Retired challenge ports are released before
new proxy listeners bind; failed preparation does not mutate live sources.
When an existing proxy address moves to HTTP-01, its challenge bind is deferred
until the old proxy has stopped. Narrowing a proxy wildcard within the same IP
family is also supported. Other challenge addresses are still bound during
preparation: widening bindings, changing IP families, or replacing a challenge
wildcard binding may require a restart or two separate reloads to avoid conflicts.
Removed sources are canceled. CLI and mobile/FFI use the same
manager, with no process-global certificate registry. Mobile deployments still
need externally reachable challenge ports and persistent application storage.

`--dry-run` validates configuration, references, domain coverage, challenge
compatibility, certificate material and declared address conflicts without
contacting a CA, binding ports, or creating ACME state. An unissued ACME source
is a valid configuration, not a self-signed placeholder. Existing readable state
is checked for CA/domain identity mismatches without locking or modifying it;
the check need not run as the service user.
Actual OS port conflicts,
storage ownership and permissions are checked during runtime preparation.

There is no built-in DNS-01, wildcard ACME issuance, DNS vendor API, shell hook,
Tailscale provider, or Cloudflare Origin CA provider. For wildcard certificates
or DNS-01, run an external client such as acme.sh, lego or Certbot and use a file
source. Manually supplied wildcard certificates remain supported.

Examples: [file rotation and reuse](examples/certificates_files.yaml) and
[ACME with shared TCP/QUIC consumers](examples/certificates_acme.yaml).

## Advanced Features

### Vision (XTLS-Vision)

Vision optimizes TLS-in-TLS scenarios by detecting inner TLS traffic and switching to direct mode for zero-copy performance.

**Requirements:**
- Inner protocol MUST be VLESS
- Works with both TLS and Reality

```yaml
# TLS + Vision
protocol:
  type: tls
  tls_targets:
    "example.com":
      cert: cert.pem
      key: key.pem
      vision: true
      alpn_protocols: ["http/1.1"]
      protocol:
        type: vless
        user_id: "uuid"

# Reality + Vision
protocol:
  type: tls
  reality_targets:
    "www.google.com":
      private_key: "..."
      short_ids: ["..."]
      dest: "www.google.com:443"
      vision: true
      protocol:
        type: vless
        user_id: "uuid"
```

### XUDP Multiplexing

Automatically enabled for VMess and VLESS when `udp_enabled: true`. Multiplexes UDP traffic over a single connection.

### Proxy Chaining

**Protocol nesting** (wrap one protocol in another):

```yaml
client_chain:
  address: "proxy.example.com:443"
  protocol:
    type: tls
    protocol:
      type: vmess
      cipher: aes-128-gcm
      user_id: "uuid"
```

**Multi-hop chains** (route through multiple proxies sequentially):

```yaml
client_chain:
  chain:
    - address: "proxy1.example.com:1080"
      protocol:
        type: socks
    - address: "proxy2.example.com:443"
      protocol:
        type: tls
        protocol:
          type: vless
          user_id: "uuid"
```

### Hot Reloading

Configuration changes are automatically detected. The CLI also watches referenced
outbound TLS/QUIC client certificates and keys, client-auth CA bundles, local
ShadowTLS certificates/keys, and ACME custom `ca_cert` files. Changing ACME trust
roots replaces the affected renewal worker after successful preparation, while
retaining its account and issued certificate.

Automatic full reloads wait for **5 seconds of quiet after the last relevant
filesystem event**. Writes to config, rule, or reload-only PEM dependencies share
that debounce window. Separate certificate/key writes are coalesced; an invalid
or incomplete candidate is rejected without retiring the running listeners.
Active and parseable candidate dependencies remain watched, so repairing or
creating a missing PEM file retries the reload without another config edit.
Unix SIGHUP bypasses debounce; shutdown also interrupts it immediately.

`--no-reload` disables automatic full-reload watches, not live server-certificate
rotation or ACME renewal. On Unix, SIGHUP still requests a reload. Embedded/FFI
instances use the same live server-certificate watcher, but have no full config
reload loop: reload-only PEM changes require restarting the embedded instance.

On Linux, if directory permissions prevent watching a readable configuration's parent, startup falls back to direct file watches and logs a warning. In-place edits remain detectable, but atomic replacements may be missed; use SIGHUP or grant directory read permission when replacing files.

Replacement configurations, certificates, and DNS resolvers are prepared while
the current listeners continue serving. A preparation failure leaves the current
configuration running. Unchanged fixed TCP listen addresses retain their sockets
across generations. New-generation TCP and Unix listeners accept queued
connections only after activation completes; connections may wait in the kernel
backlog during that interval.

If activation fails, Shoes stops the candidate services and restores the previous
configuration, including control state, resource limits, DNS ownership, and
certificate workers. A successful rollback keeps the process running; if rollback
also fails, Shoes exits with status 1 rather than serving a partial generation.
Existing TCP connections begin draining when their old listeners retire, for up
to `global_limits.reload_grace_secs`. That deadline still applies after rollback.
TUN, WireGuard, and QUIC services are stopped and restarted; their existing
sessions are not migrated or restored by rollback.

Certificate-source file changes and ACME renewal do not trigger this full reload.
They rotate live without replacing listeners or closing QUIC connections; see
[Certificate Sources](#certificate-sources).

QUIC listener sockets must finish closing before replacements bind. Closing endpoints get up to one second for best-effort close delivery, then their drivers are stopped locally so peer-controlled timers cannot delay reloads. If the previous generation's sockets do not retire within the five-second socket-release guard, Shoes exits with an error rather than announcing a partially ready generation.

Candidate QUIC buffer sizes are used during DNS preparation, but `global_limits` admission caps change only at activation. DNS bootstrap over HTTP/3 or QUIC proxy chains therefore needs headroom under the live cap. A cap-increasing reload may require a restart if preparation cannot fit. Lowering a cap does not revoke existing reservations, including those made during preparation; new admissions are blocked until usage falls sufficiently. At cold startup, preparation uses the initial unlimited admission caps.

On macOS, edit the configured file path or use SIGHUP when writing through a hard-link alias in another directory. Automatic detection of such alias writes is backend-dependent. System-volume directory symlinks are resolved without watching their immutable links.

SIGINT/SIGTERM (or Ctrl-C on Windows) stop listeners and exit with status 0. Process shutdown does not wait for the TCP reload grace period.

### mTLS (Mutual TLS)

Require client certificates for authentication:

```yaml
# Server side
protocol:
  type: tls
  tls_targets:
    "example.com":
      cert: server.crt
      key: server.key
      client_ca_certs: [ca.crt]  # Required CA
      client_fingerprints: ["sha256:..."]  # Optional specific certs
      protocol: ...

# Client side
client_chain:
  address: "example.com:443"
  protocol:
    type: tls
    cert: client.crt
    key: client.key
    protocol: ...
```

## Command Line

```bash
shoes [OPTIONS] <config.yaml> [config.yaml...]

OPTIONS:
  -t, --threads NUM    Worker threads (default: CPU count)
  -d, --dry-run        Validate config and certificates without starting listeners
  --no-reload          Disable automatic reloads on file changes

COMMANDS:
  check <config.yaml>                           Alias for --dry-run
  version                                      Alias for --version
  generate-reality-keypair                       Generate Reality X25519 keypair
  generate-reality-mldsa65-keypair                Generate optional Reality ML-DSA-65 keys
  generate-shadowsocks-2022-password <cipher>    Generate Shadowsocks 2022 password
```

`check` and `--dry-run` exit with status 0 for valid configuration and 1 for errors. They do not open listeners, create a file watcher, or perform DNS bootstrap networking. Runtime failures such as unavailable bind addresses remain possible after a successful check.

### Configuration Diagnostics

Check the same set of files that will be used at startup:

```bash
shoes check groups.yaml listeners.yaml
```

Configuration decoding failures identify the input file and the entry's
zero-based `config[N]` index. Rule-group decoding also identifies `rules[N]`
(or `rules` for a single object). For example, an unsupported field in the second
rule source of the third entry reports `config[2]`, `rules[1]`, and the unknown
field. YAML syntax and duplicate-key errors retain the parser's original
diagnostic and line/column information when available, rather than adding an
entry prefix. For `config[N]` decoding errors, a trailing line/column (if any)
marks the start of the file's top-level list, not entry N or the failing field;
use the `config[N]` and `rules[N]` paths for that context.

Errors during certificate loading and semantic validation name the input file
set, not an inferred single culprit: group references can span files. Checks use
the native validation path, including graph and transport-composition checks.
Named PEM entries accept only `pem` and exactly one of `path` or `data`; unknown
fields are rejected rather than ignored. TCP settings likewise reject unknown
fields; their only current field is `no_delay` (default `true`).

Diagnostics do not include full YAML excerpts. They are not a redacted config
export: user-defined names, paths, and some invalid values can appear in errors.
Review diagnostics before sharing them. No normalized-config output is provided.

Offline regression coverage fully validates the representative
[SOCKS](examples/socks_basic.yaml), [HTTP-through-SOCKS](examples/http_through_socks.yaml),
[multi-hop](examples/multi_hop_chain.yaml), [controller](examples/clash_api.yaml),
and [local rule-source](examples/rule_sources.yaml) examples. Other examples may
need deployment-specific certificates, keys, files, or platform support; parsing
an example alone does not establish runtime validity.

Optional reference generation, editor schema support, and strict subset conversion
are described in [Configuration Tooling Follow-Ups](CONFIG_TOOLING_FOLLOWUP.md).

## Tips

### Generate Keys

**Reality keypair:**
```bash
shoes generate-reality-keypair
```

**Optional Reality post-quantum authentication keys:**
```bash
shoes generate-reality-mldsa65-keypair
```
Keep `mldsa65_seed` on the server; distribute only `mldsa65_verify` to clients.

**Shadowsocks 2022 password:**
```bash
shoes generate-shadowsocks-2022-password 2022-blake3-aes-256-gcm
```

**UUID:**
```bash
uuidgen
```

**TLS certificate fingerprint:**
```bash
openssl x509 -in cert.pem -noout -fingerprint -sha256
```

### Security Best Practices

- Use strong, random passwords
- Keep private keys secure
- Use `127.0.0.1` instead of `0.0.0.0` for local-only access
- Use firewall rules to restrict access
- Enable client certificate authentication for sensitive services
- Use Vision with Reality for maximum privacy

### Performance Tips

- Enable `vision: true` for TLS-in-TLS scenarios
- Use `tcp_settings.no_delay: true` for low latency
- Set `quic_settings.num_endpoints` to match worker threads
- Use QUIC transport for high-latency or lossy networks

### Common Issues

- **"Address already in use"**: Change port or stop conflicting service
- **"Permission denied"**: Ports < 1024 require root/admin
- **Reality connection fails**: Verify keys match, UUID matches, SNI matches server's reality_targets key
- **Vision not working**: Ensure inner protocol is VLESS
- **Config validation fails**: Run with `--dry-run` for detailed errors
