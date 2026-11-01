---
title: DNS configuration
description: Choose resolvers, reusable groups, bootstrap, and proxy routing.
---

A server, WireGuard listener, or TUN entry can select an inline resolver or a
named `dns_group`. Omitted or null `dns` inherits `global_settings.default_dns`
when set, otherwise it uses the native system resolver; see
[native DNS freshness](/dns/native/) for its cache behavior. Use
[Fake DNS](/dns/fake/) only when synthetic address mapping is needed.

The global default has the same shape as `dns`. An explicit per-inbound `dns`
object replaces it completely: `dns: {}` uses system DNS, even with a global
default. A default with omitted `servers` also uses system DNS, not itself.
Inline fake-IP defaults share one pool across inheriting inbounds. Independent
bootstrap resolvers keep their own configuration. See
[global settings](/config/global-settings/#default-dns).

**Complete example:** [dns_tuning.yaml](/examples/dns_tuning/). Its proxy
addresses and credentials need deployment-specific values.

```yaml
- dns_group: secure-dns
  dns_servers:
    - url: tls://1.1.1.1
      server_name: cloudflare-dns.com
      timeout_secs: 5

- address: "127.0.0.1:1080"
  protocol: {type: socks}
  dns: {servers: secure-dns}
```

`dns.servers` and a group's `dns_servers` each accept one server or a list.
`dns.server` and `dns_server` are singular aliases. A plain string is either a
named group reference or a resolver URL. Resolver URLs support `system`,
`udp://`, `tcp://`, `tls://` (DNS-over-TLS), `https://` (DNS-over-HTTPS), and
`h3://` (DNS-over-HTTP/3). Default ports are 53, 53, 853, 443, and 443,
respectively. A URL object accepts these options:

| Field | Default | Meaning |
| --- | --- | --- |
| `url` | Required | Resolver endpoint or `system` |
| `server_name` | URL hostname | TLS name override for TLS/HTTPS/H3 |
| `bootstrap_url` | System resolver | IP-literal DNS URL, `system`, or named DNS group for resolving endpoint/proxy hostnames |
| `client_chain` / `client_chains` | Direct | Proxy chain(s) used to reach this DNS upstream |
| `ip_strategy` | `ipv4_then_ipv6` | Address-family query order |
| `timeout_secs` | 5 | Whole lookup timeout; `0` disables it |
| `connect_timeout_secs` | 5 | Connection setup timeout |
| `attempts` | 1 | Query retry attempts |
| `native_cache_secs` | 0 | System-only application memoization window; see [native DNS](/dns/native/) |

`ip_strategy` also accepts `ipv4_only`, `ipv6_only`, `ipv4_and_ipv6`, and
`ipv6_then_ipv4`. Option objects reject unknown fields. A non-system upstream
cannot set `native_cache_secs`, even to zero. `bootstrap_url` must not itself
contain a hostname; named groups may be used for multi-step bootstrap, but
cycles are rejected.

TCP, TLS, and HTTPS upstreams can use proxy chains. UDP and H3 upstreams are
direct-only, except a direct chain can set an interface binding; `system` does
not support a client chain. WireGuard-routed DNS requires a literal upstream
IP and no `bootstrap_url`. See [remote rule sources](/routing/remote-sources/)
for their stricter startup-bootstrap rules.

`client_chain` and `client_chains` are exact aliases and use the
[routing chain syntax](/routing/rules/#client-chains): `[a, b]` means sequential
hops, while `[{chain: [a]}, {chain: [b]}]` means alternatives. Named client groups
retain their whole-path choices and selection policies.

**Migration:** DNS previously interpreted a bare list as alternatives. It now
uses sequential hops, without a compatibility mode or warning. Use explicit
chain wrappers or a named group to preserve alternative routes.
