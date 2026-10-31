---
title: "Configuration model"
description: How Shoes organizes YAML configuration entries.
---

The field-shape snippets in the reference use placeholders such as `string` and
`...`; they are not complete runnable configurations. Use [complete
examples](/start/examples/) for files to copy and adapt.

A configuration file is a YAML array containing one or more configuration entries. Each entry can be:

- [Server](/config/server/): a proxy listener and its protocol stack.
- [TUN](/config/tun/): an IP packet device for transparent proxying.
- [Client group](/routing/groups/#client-proxy-group): reusable upstream configurations.
- [Rule group](/routing/groups/#rule-group): reusable routing rules.
- [Rule source group](/routing/groups/#rule-source-group): reusable action-free matching expressions and local or remote sources.
- [DNS group](/dns/configuration/): a named DNS configuration shared by consumers.
- [Named PEM](/security/named-pems/): reusable certificate or key data.
- [Certificate source](/security/certificates/): file-backed or managed certificates.
- [Global settings](/config/global-settings/): process-wide admission, remote-rule cache, and QUIC buffer settings.
- [Clash controller](/routing/clash-controller/): controller listener settings.
- [Cache file](/routing/clash-controller/#persistence): persistent controller state.

Entries are identified by their configuration keys, not a common top-level
`type`. The `type` inside `protocol` selects a protocol. Multiple files are
loaded together, so named groups can be referenced across files.

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

# Action-free source groups have 'rule_source_group'
- rule_source_group: my-sources
  rules: ...

# Named PEMs have 'pem'
- pem: my-cert
  path: /path/to/cert.pem
```
