---
title: "Named Groups"
description: shoes named groups configuration.
---

### Client Group

**Complete example:** [chain_groups.yaml](/examples/chain_groups/) demonstrates
whole-path alternatives and manual selection. Adapt its addresses and credentials
before deployment.

`client_chain` and `client_chains` accept the same sequence and alternative-path
syntax as routing. A bare `[a, b]` defines one sequential path; a list of explicit
chain wrappers defines separate alternatives selected by the group's policy.
Group references inside a path contribute their entire selected path, so
alternatives may have different hop counts. Stages accept group references,
inline clients, and `{pool: [...]}`. Unknown group chain-wrapper fields are rejected.
Legacy group `client_proxy` / `client_proxies` lists retain their alternative-member
behavior with a deprecation warning; see [migration examples](/routing/rules/#legacy-proxy-fields).

The following fragments reference groups defined elsewhere:

```yaml
- client_group: a1-selected-nl
  client_chains:
    - chain: [a1-selected, nl-hop]

- client_group: geo-reddit-selected
  type: selector
  default: a1-selected-nl
  client_chains:
    - {chain: [a1-selected]}
    - {chain: [a1-selected-nl]}
    - name: via-us
      chain: [a1-selected, us-hop]
    - {chain: [direct]}
```

An unnamed one-hop wrapper retains its referenced group or inline client's identity.
Inline selector clients and multi-hop paths require explicit names. Other policies generate
definition-site labels for unnamed paths; use explicit names for stable controller
identities. Labels do not introduce another routing-reference namespace.
The controller exposes named paths as `Relay` nodes, with whole-path delay probes
and final-hop UDP capability.

Round-robin selects immediate alternatives before their descendants, with independent
TCP and UDP counters per occurrence, including nonterminal choices.
Duplicate round-robin entries provide extra tickets;
selector and URL-test members must be distinct. A nested group with ten
members has the same outer weight as one inline client, not ten times its weight.
Each new flow snapshots manual choices once and pins the complete selected path.
Selecting a TCP-only path for UDP fails rather than choosing another selector member.
Existing streams, UDP associations and carrier redials retain their pinned paths.

The same composition works in routing, DNS, WireGuard peer chains, ShadowTLS
handshake chains and REALITY destination chains. Direct, WireGuard and XHTTP H3
clients are valid only at physical hop zero. UDP/H3 DNS still requires a direct-only
route. Resolution rejects cycles, more than 16,384 expanded nodes, more than 64
nested choices, or paths longer than 64 hops. Fixed one-hop round-robin aliases
do not add choice depth. Health state is bounded by declared groups and members,
not the number of route combinations.

```yaml
- client_group: my-upstream
  client_chains:              # Define alternatives in this group
    - chain:
        - address: "proxy1.example.com:1080"
          protocol:
            type: socks
    - chain:
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

A `rule_group` contains ordered policies; omitted `action` still means `allow`.
A `rule_source_group` contains action-free matching expressions and local or
remote sources. The declaration determines the kind, never the presence of an
action. Empty groups are rejected. Both kinds share one namespace, including
built-in names. `rule` is an alias for `rules`; either accepts one item directly
or a nonempty list.

Policy groups are referenced from `rules` or `override_rules`, preserving order,
actions, and routing options. Source groups are referenced only with
`masks: {rule_source_group: name}`, with the caller's action. Cross-kind references are
errors: actions are never discarded or invented. Source groups can reference
other source groups; cycles and excessive nesting are rejected. Policy groups
cannot reference other policy groups.

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

### Rule source group

Source groups are referenced inside a policy's `masks`, so the policy supplies
the action. They may reference other source groups, but not policy groups.
See [local rule sources](/routing/rules/#local-rule-sources) and
[remote rule sources](/routing/remote-sources/) for formats, refresh, and caching.
