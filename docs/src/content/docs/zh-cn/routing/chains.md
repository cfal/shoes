---
title: "代理链"
description: "shoes 代理链接配置。"
---

**完整示例：** [多跳链](/zh-cn/examples/multi_hop_chain/)和[完整路径客户端组](/zh-cn/examples/chain_groups/)。部署前请调整地址和凭据。以下片段仅作说明。

**协议嵌套**（将一个协议包装在另一个协议中）：

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

**多跳链**（顺序通过多个代理路由）：

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

对于`client_chains`、组引用和`pool:`跳数，请参见[路由规则](/zh-cn/routing/rules/#client-chains)。在[客户端组](/zh-cn/routing/groups/#client-group)下定义命名组； `selector` 和 `url-test` 的选择请参见[控制器和选择器](/zh-cn/routing/clash-controller/)页面。
