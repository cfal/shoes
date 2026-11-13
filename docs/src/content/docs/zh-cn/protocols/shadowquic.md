---
title: ShadowQuic
---

ShadowQuic 入站通过 JLS QUIC/TLS 握手认证，使用与参考实现相同的
`quinn-jls` 0.4 传输层，复用 Shoes 的路由、DNS、代理链、嗅探及 TCP/UDP 转发。

```yaml
- address: 0.0.0.0:443
  transport: quic
  protocol:
    type: shadowquic
    users:
      - username: alice
        password: replace-with-a-long-random-password
    server_name: example.com
    jls_upstream: example.com:443
    zero_rtt: true
    udp_enabled: true
  rules:
    - allow-all-direct
```

参考客户端的 `username`、`password` 和 `server_name` 必须与入站匹配，
`addr` 指向 Shoes，ALPN 使用 `h3`。伪装上游需要支持指定 UDP 端口的 QUIC。
内部证书由 JLS 生成，请勿设置 `quic_settings`。只能作为顶层 QUIC 入站使用。

支持 TCP CONNECT（`0x01`）、UDP 数据报关联（`0x03`）、UDP 流关联
（`0x04`）及连接统计扩展（`0xff`，主操作码 1、子操作码 0）。UDP 支持
同一连接上的多个目标及关联；每个方向独立分配上下文 ID，并在固定上限内缓冲乱序数据。

`zero_rtt` 和 `udp_enabled` 默认开启。包括恢复连接在内，Shoes 均在 JLS
认证完成后分发请求。关闭 `zero_rtt` 可拒绝可重放的早期数据；关闭
`udp_enabled` 会拒绝 UDP 关联。

不支持 TCP BIND、SunnyQuic 应用层认证，以及远程用户管理和用户统计。
用户管理扩展返回协议错误；通过修改 Shoes 配置并重载来管理用户。
