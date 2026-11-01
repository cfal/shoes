---
title: "TUIC v5"
description: "shoes tuic v5 配置。"
---

**完整示例：** [tuic_v5.yaml](/zh-cn/examples/tuic_v5/)。在部署之前调整地址和机密。

下面的字段草图包含占位符，而不是可运行的值。配置部署时使用完整的示例。

<a id="server"></a>
## 服务端

```yaml
protocol:
  type: tuic                   # Aliases: tuicv5
  uuid: string                 # UUID
  password: string
  zero_rtt_handshake: false    # Default: false (enables 0-RTT for lower latency)
```

<a id="client"></a>
## 客户端

**完整的客户端示例：** [quic_clients.yaml](/zh-cn/examples/quic_clients/)。

```yaml
address: proxy.example.com:443
quic_settings:
  sni_hostname: proxy.example.com
  verify: true
protocol:
  type: tuic # alias: tuicv5; version 5 only
  uuid: 01234567-89ab-4def-8123-456789abcdef
  password: your-password
  udp_enabled: true
  udp_relay_mode: native # native QUIC datagrams or quic unidirectional streams
  heartbeat_interval_secs: 10 # 1..30
```

传输默认为 QUIC，ALPN 为 `h3`。放置和 TLS 设置遵循 [Hysteria2 客户端规则](/zh-cn/protocols/hysteria2/#client)。即使使用流模式 UDP，心跳也需要 QUIC 数据报。认证使用当前的TLS会话导出器； TUIC没有认证确认或TCP成功响应。当对等方关闭连接时（不一定是在流设置期间），错误的凭据就会出现。不支持客户端 0-RTT。

UDP 关联共享一个有界的、连接拥有的接收器。关联 ID 永远不会在连接中重复使用；耗尽会创建一个新连接，而现有流会保留旧连接。显式关闭会发送带有截止日期的 DISSOCIATE；删除关联会将有限的尽力而为通知排队。最多 64 个命令编写器同时运行。录取有五秒钟的截止日期；一旦被承认，即使调用者被取消，写入也会完成，或者在连接关闭时失败。这可以防止部分命令中断其他流程。默认传入单流信用为 1024（通过显式 `max_streams_per_connection` 减少），最多有 64 个并发命令读取器。非常小的流限制可以使外部服务器拒绝突发流模式 UDP 回复；当需要严格的流限制时，首选本机模式。
