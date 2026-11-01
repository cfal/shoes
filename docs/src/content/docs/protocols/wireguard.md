---
title: "WireGuard"
description: Shoes wireguard configuration.
---

**Complete example:** [wireguard_server.yaml](/examples/wireguard_server/). Adapt addresses and secrets before deployment.

WireGuard uses `protocol: {type: wireguard}` in ordinary client and server
configs. It carries TCP/UDP flows over a userspace GotaTun device and smoltcp
stack, not a TCP stream wrapper. Unix builds support WireGuard; Windows rejects it.

See [server](/examples/wireguard_server/) and
[client](/examples/wireguard_client/) examples. Their demonstration keys
must be replaced before deployment. Generate a private key with `wg genkey`
and derive its public key with `wg pubkey`. Never share the private key.

| Field | Meaning |
| --- | --- |
| `private_key` | Base64-encoded 32-byte private key |
| `addresses` | Nonempty local tunnel CIDRs; at most one address per family |
| `peer_client_chain` | Optional client chain carrying encrypted UDP packets to peers; accepts normal group, inline, and pool syntax |
| `mtu` | Inner IP MTU, default 1408; supported range 1280-1420 |
| `resource_limits` | [Same fields as TUN](/config/tun/#resource-limits-and-device-framing), with bounded WireGuard defaults |

WireGuard defaults to a 32 MiB TCP memory budget, 256 TCP connections, 1,024
UDP sessions, 4,096 UDP destinations, 64 destinations per session, and an 8 MiB
UDP queue. Its TCP buffer size remains 32 KiB. Explicit values override those
defaults; the TUN limit constraints still apply.

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
at hop zero. See [the complete detour example](/examples/wireguard_outer_chain/).

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
proxy. See [the proxied server example](/examples/wireguard_proxied_server/).
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
