---
title: "Fake DNS"
description: shoes fake dns configuration.
---

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
(`default` when omitted); WireGuard contexts use the
[name/public-key identity](/protocols/wireguard/). Changing these inputs changes
private pool and snapshot ownership.
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
DNS client chains use the configured bootstrap resolver. Downstream proxy
hostnames remain unresolved when passed through a proxy that supports remote
name resolution; shoes cannot inspect addresses resolved by that remote proxy.
Rule downloads instead pre-resolve downstream proxies through their guarded
bootstrap resolver.
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

See [the shared-pool example](/examples/fake_dns/).
