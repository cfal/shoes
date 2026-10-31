---
title: "Rules System"
description: shoes rules system configuration.
---

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
See the [HTTP Host](/examples/http_host_sniffing/) and
[TLS SNI](/examples/sni_sniffing/) examples.

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

In rules, client groups, and DNS server options, `client_chain` and `client_chains`
are exact aliases. The value, not the field's plurality, determines the structure:
`[a, b]` and `{chain: [a, b]}` both mean sequential hops. For alternative paths,
use `[{chain: [a]}, {chain: [b]}]`. Nested lists (`[[a], [b]]`) also specify
alternative chains; explicit wrappers are recommended for clarity.

DNS previously treated a bare list as alternatives. It now interprets `[a, b]`
as a sequence, matching routing, without a compatibility mode or warning.
DNS alternatives require explicit chain wrappers (or a named group).
System DNS still rejects client chains; UDP/H3 DNS still requires direct-only paths.

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
  - chain: [us-proxy-group]            # Chain 1: single hop
  - chain: [proxy1, proxy2]            # Chain 2: multi-hop

# Load balancing at a hop (pool)
client_chain:
  chain:
    - pool: [us-proxies, eu-proxies]   # Round-robin between pool members
    - final-proxy
```

### Legacy Proxy Fields

`client_proxy` and `client_proxies` still work in rules, client groups, and
ShadowTLS remote handshakes, with a deprecation warning. Existing behavior is
preserved: a legacy list contains alternatives, not sequential hops.
Use `RUST_LOG=warn` or a more verbose log level to display these warnings.

A single `client_proxy: upstream` can become `client_chain: upstream`.
For a list, changing only the field name changes behavior. The following
fragments assume groups `a` and `b` are defined elsewhere:

```yaml
# Old rule: client_proxies: [a, b]
# Equivalent rule, retaining one-hop round-robin alternatives:
client_chain:
  chain:
    - pool: [a, b]

# Old group: client_proxies: [a, b]
# Equivalent group, retaining separate policy members:
client_group: outbound
client_chains:
  - chain: [a]
  - chain: [b]
```

For ShadowTLS remote handshakes, use `client_chain: [{pool: [a, b]}]` to replace
a legacy proxy list. Do not specify legacy and new fields together.

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

Declare an action-free `rule_source_group` containing matching expressions and file
paths, or load a file inline under `masks` or alongside `action`. Sources are read
and compiled during validation, including `--dry-run`,
before a reload stops existing listeners. Invalid sources reject the candidate.
Automatic reload watches imported files as well as configs. A parseable rejected
candidate keeps its source paths watched, so creating or repairing a missing file
can recover without another config edit. Active sources remain watched until a
replacement activates. `--no-reload` disables automatic full reloads; SIGHUP
still reloads, and live server-certificate rotation remains enabled.
Established connections retain their original rules until they drain. New routing
caches belong to the new configuration; Fake DNS pools are preserved separately.

```yaml
- rule_source_group: blocked
  rules:
    - lists/domains.srs
    - path: lists/addresses.json
      format: singbox_json
    - domain_suffix: [ads.example, tracking.example]
    - all:
        - domain_suffix: [restricted.example]
        - destination_port: [443]

- address: "0.0.0.0:1080"
  protocol: {type: socks}
  rules:
    - masks: {rule_source_group: blocked}
      action: block
    - masks: {path: lists/extra.srs}
      action: block
    - path: lists/another.srs
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
        - rule_source_group: blocked
        - destination_port: [443]
        - not: {path: lists/exceptions.srs}
    action: block
```

Source groups OR their entries together, including native predicates, `all`,
`any`, `not`, source-group references, and file sources. A source is a path string inside a group's
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
indexes count toward the generation budget, including remote indexes retained
before cache, download, or local-source decoding. Refresh candidates exclude the
replaced source's old index. The budget excludes old/new generation overlap and
does not cap process RSS. Reference-expanded predicate visits also have a
conservative 2 million compilation budget, counting repeated group
references and caller compositions. These are safety ceilings, not a mobile
memory guarantee. Runtime regex caches are separate per worker and generation;
capture tracking is disabled and each lazy-DFA cache is capped at 256 KiB.
Regex groups accept at most 512 KiB of pattern text, with syntax-proportional
compilation reserves. GeoIP `.db` (MMDB) files are not supported;
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
classical paths, shoes normalizes incoming query names to lowercase.

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
