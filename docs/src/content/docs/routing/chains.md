---
title: "Proxy Chaining"
description: shoes proxy chaining configuration.
---

**Complete examples:** [multi-hop chains](/examples/multi_hop_chain/) and
[whole-path client groups](/examples/chain_groups/). Adapt addresses and
credentials before deployment. The fragments below are illustrative.

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

For `client_chains`, group references, and `pool:` hops, see
[routing rules](/routing/rules/#client-chains). Define named groups under
[client groups](/routing/groups/#client-group); see the
[controller and selectors](/routing/clash-controller/) page for `selector` and
`url-test` selection.
