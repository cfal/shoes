---
title: "Named Groups"
description: shoes named groups configuration.
---

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
