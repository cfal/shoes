---
title: "Proxy Chaining"
description: shoes proxy chaining configuration.
---

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
[client proxy groups](/routing/groups/#client-proxy-group); see the
[controller and selectors](/routing/clash-controller/) page for `selector` and
`url-test` selection.
