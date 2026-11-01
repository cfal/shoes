---
title: "TUN Config"
description: Shoes tun config configuration.
---

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
dns_hijack: true               # Optional: intercept TCP/UDP port 53 independently of fake-IP

# Routing rules
rules: [RuleConfig]
```

**Platform notes:**
- **Linux**: Requires root or `CAP_NET_ADMIN`. Creates device with specified name/address.
- **Android**: Use `device_fd` from `VpnService.Builder.establish()`. Routes configured via VpnService.
- **iOS**: Use `device_fd` from `NEPacketTunnelProvider.packetFlow`.

## Resource limits and device framing

`resource_limits` is an optional object on the TUN entry. Omitted admission
limits are unlimited; a specified admission limit must be positive.

| Field | Default | Constraint |
| --- | --- | --- |
| `tcp_buffer_size` | 32,768 bytes | 1,024-16,777,216 bytes |
| `tcp_memory_bytes` | Unlimited | At least four times `tcp_buffer_size` |
| `max_tcp_connections` | Unlimited | Positive integer |
| `max_udp_sessions` | Unlimited | Positive integer |
| `max_udp_destinations` | Unlimited | Positive integer |
| `max_udp_destinations_per_session` | Unlimited | Positive integer |
| `max_udp_queued_bytes` | Unlimited | At least 65,535 bytes |

When both TCP memory and connection caps are set, the lower effective
connection count applies. These limits are separate from
[process-wide admission](/config/global-settings/#admission-caps).

`segmentation_offload` controls TCPv4 transmit offload on a created Linux
device. Omission tries it automatically and falls back to ordinary packets if
initialization fails; `false` disables it and `true` requires it at startup.
Explicit enablement is rejected with `device_fd`, packet-information headers,
or non-Linux devices. IPv6 continues using ordinary MTU-sized packets.

Devices Shoes creates on iOS and macOS always use four-byte packet-information
headers; this cannot be disabled. For a supplied `device_fd`,
`packet_information` defaults to `true` on iOS/macOS and `false` elsewhere.
If an iOS or macOS app supplies a header-less FD, including one bridged from
the packet-flow API, explicitly set `packet_information: false`. This setting
does not configure routes in the host VPN service.

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

### Managed Linux Desktop Capture

`auto_route: true` gives the Shoes process ownership of one nonpersistent TUN,
private routing table, policy rules, nftables table, and optional per-link DNS
configuration. It captures host-originated TCP/UDP using conntrack-aware output
marking. Both protocols use the existing TUN engine unless `auto_redirect: true`
selects kernel TCP REDIRECT. The system `nft` executable runs only for control-plane
changes and reconciliation, not per packet or connection.

See [the desktop example](/examples/tun_desktop/) and
[the systemd unit on master](https://github.com/cfal/shoes/blob/master/examples/shoes-desktop.service).
These are manual deployment examples, not files installed by the release archive.
The unit expects the binary at `/usr/local/bin/shoes` and configuration at
`/etc/shoes/desktop.yaml`; install it as
`/etc/systemd/system/shoes-desktop.service` to run under systemd. The
configuration example forwards DIRECT; replace its `rules` with the desired
proxy policy before using it as a proxy.

```yaml
- device_name: shoes0
  auto_route: true
  auto_redirect: true
  addresses: [10.233.0.1/30, 'fd73:686f:6573::1/126']
  bootstrap_dns: ['1.1.1.1:53', '9.9.9.9:53']
  auto_dns: true
  dns_hijack: true
  dns:
    servers: ['udp://1.1.1.1', 'tcp://1.1.1.1']
  rules: allow-all-direct
```

| Field | Managed Behavior |
|---|---|
| `auto_route` | Enables process-owned Linux capture; default `false` |
| `auto_redirect` | Uses kernel TCP REDIRECT; requires `auto_route`; default `false` |
| `addresses` | One local CIDR per family; cannot combine with manual `address`, `netmask`, `destination`, or supplied FDs |
| `route_address` | Captured destination CIDRs; default `[0.0.0.0/0, '::/0']` |
| `route_exclude_address` | Explicit destination exclusions, including DNS; default empty |
| `bootstrap_dns` | Required literal real DNS socket addresses, never a loopback stub or TUN subnet |
| `auto_dns` | Attempts to publish transient systemd-resolved settings on the owned link; default `true` |
| `dns_hijack` | Intercepts TCP/UDP port 53; defaults `true` when managed, otherwise follows fake-IP policy |
| `linux.table` | Private route table; default `12000` |
| `linux.rule_priority` | Policy rule priority; default `12000` |
| `linux.capture_mark` | Capture bit; default `536870912` (`0x20000000`) |
| `linux.bypass_mark` | Shoes socket bypass bit; default `1073741824` (`0x40000000`) |
| `linux.mark_mask` | Combined reserved bits; default `1610612736` (`0x60000000`) |

Requirements: Linux, `/dev/net/tun`, trusted system `nft` with JSON support, and
network-administration privileges. Automatic DNS additionally requires a running
systemd-resolved, `busctl` with JSON support, and authorization to
configure the owned link. Automatic DNS setup and cleanup are best-effort, with
bounded helper calls. Missing services, failed namespace checks, and configuration
errors produce warnings rather than stopping capture. Failed setup may leave
partial per-link settings until cleanup; system DNS routing through Shoes is not
guaranteed in that case. Resolver settings are not continuously monitored or
restored after external changes, and resolver restarts do not stop the proxy.
Namespace checks assume a standard local system bus whose
listener and daemon share a PID namespace, with procfs mounted for that namespace;
resolved must share Shoes' network namespace. Custom bus arrangements should use
`auto_dns: false`. Restart Shoes to reapply automatic DNS after restarting the
resolver or system bus. The supplied
service runs as root with a bounded
capability set. File capabilities on Shoes alone do not grant privileges to
`nft` children or authorize resolved changes.

Use `auto_dns: false` for externally managed DNS. Shoes never rewrites
`/etc/resolv.conf`. Bootstrap and native resolution use protected Shoes sockets
while managed mode is active; listener bind addresses must be literal IPs.
Real DNS does not require fake-IP. Automatic DNS requires interception and room
after each interface address for its adjacent virtual DNS endpoint. Settings are
published after ingress workers start, without a separate DNS readiness probe.
The owned link disables DNS-over-TLS, DNSSEC validation, LLMNR, and mDNS;
upstream encryption and DNS policy belong in Shoes' `dns` configuration.
Cleanup attempts to revert per-link settings on the owned interface, even if
another manager changed them while Shoes was running. Removing the owned TUN also
discards its transient resolver settings. Other links are not changed.
The managed TUN subnet is reserved for ingress:
forwarding a connection back to that subnet is rejected, except local DNS handling.

The initial route must exist before OUTPUT capture, so every configured family
requires an underlying main-table default route without source or TOS constraints.
For explicitly IPv4-only capture, configure only an IPv4 address and
`route_address: [0.0.0.0/0]`; IPv6
then remains native. This is not an IPv6 blocking policy.

Loopback, local destinations, multicast, broadcast, link-local destinations,
and connected networks remain native. DNS to connected networks is intercepted
unless explicitly excluded. Replies to inbound services remain native. Existing
tracked native flows remain native, including unreplied UDP; captured flows retain
their selection. Traffic excluded from conntrack by foreign NOTRACK rules remains
native.
New TCP capture starts only with connection establishment. Invalid conntrack
packets selected for capture are dropped. UDP flows created
before conntrack was enabled cannot be identified reliably and may reset.
Applications explicitly bound to a physical device remain native in both modes;
address-bound TCP/UDP clients are supported. REDIRECT requires an unused adjacent
virtual peer in each TUN subnet. Its private routes use that peer as their next
hop, and only traffic routed through that peer is redirected. Traffic to the peer
itself, including virtual DNS, stays on the TUN engine.
Foreign-marked traffic is left to existing policy. Unsupported protocols remain
native; ICMP handling is the existing synthetic echo behavior, not remote ICMP
forwarding. This is host capture, not gateway or container forwarding.

Conflicting tables, priorities, mark reservations, or preceding nonlocal policy
rules cause startup rejection. Other VPNs and firewall managers require explicit
coexistence validation; Shoes does not override foreign firewall decisions.
REDIRECT also rejects native routes using its virtual peer as a gateway and
opaque nexthop-object routes. Captured replies carry the capture mark before
mark-aware reverse-path filtering.
No universal VPN, firewall, resolver-manager, or distribution compatibility is
promised.

Reload retains the interface, capture, and redirect listener identities. Network
topology changes require restart and are rejected before retiring live workers.
Ordinary worker reloads can reset existing connections and briefly interrupt
traffic, but do not disable capture. Failed candidates roll back on the same
network lease. Unexpected owned routing changes or a missing private firewall
table cause orderly shutdown. Resolver-setting changes do not.

Shoes exclusively owns its token-named `inet` nftables table, including all of its
contents. Do not add rules, chains, or sets to that table: external changes inside
it are neither audited nor preserved. Cleanup removes the exact owned table even
if its contents have changed; other tables are left untouched. Connected-network
sets are updated atomically through nftables and cached in memory, not journaled
as firewall snapshots.

Shutdown removes capture and attempts DNS cleanup before retiring ingress.
SIGKILL cannot run cleanup: the service's `ExecStopPost` invokes
`shoes cleanup-tun`, and the next managed startup also reconciles stale state.
Recovery uses a private namespace-scoped journal under `/run/shoes` to track
cleanup identity and pending operations, not firewall policies. Interface and
routing ownership checks remain strict; conflicting changes are refused, with
errors reported. Temporary outages and lost connections are possible. Cached fake
addresses may outlive shutdown. There is
no kill switch, no automatic DIRECT fallback on upstream failure, and no
uninterrupted fail-open guarantee.
Outstanding helper processes retain the namespace lock, so recovery fails rather
than racing a helper that could still commit. The service terminates remaining
helpers before `ExecStopPost`; standalone operators must let them finish or stop
them before retrying cleanup.
The service retries without a start-rate limit, including while a configured
family is waiting for its underlying default route. Read failures during
reconciliation currently trigger cleanup and a supervised restart, not in-place
repair. Cleanup errors retain the journal for retry. Until the owned table is
removed, stale TCP REDIRECT rules can continue to reject connections.
