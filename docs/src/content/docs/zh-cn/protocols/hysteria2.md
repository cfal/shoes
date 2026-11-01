---
title: "Hysteria2"
description: "shoes hysteria2 配置。"
---

**完整示例：** [hysteria2.yaml](/zh-cn/examples/hysteria2/)。在部署之前调整地址和机密。

下面的字段草图包含占位符，而不是可运行的值。配置部署时使用完整的示例。

<a id="server"></a>
## 服务端

```yaml
protocol:
  type: hysteria2
  password: string
  udp_enabled: true            # Default: true
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
  type: hysteria2 # alias: hy2
  password: your-password
  udp_enabled: true
```

传输默认为 QUIC，ALPN 默认为 `h3`。 TLS 验证、证书指纹、客户端证书和密钥交换组使用 `quic_settings`。该协议必须位于链跳 0 的最外层。它可以承载后续基于流的代理，但不能遵循另一个代理或在 TLS、WebSocket 或另一个流包装器内部运行。

TCP 流和 UDP 关联共享经过身份验证的连接。连接替换永远不会迁移现有流或重播应用程序字节。 UDP 队列和分段数据包重组是有界的；过载丢包。 UDP需要服务器的许可。读取响应时出现 TCP 目标错误，允许应用程序在服务器成功响应之前写入。 HTTP/3 身份验证标头限制为 16 KiB 解码。 H3 依赖项会拒绝声明长度大于 1 MiB 的缓冲帧，并逐步丢弃未知帧有效负载，而没有生命周期字节预算。这些限制不适用于代理 TCP 或 UDP 流量。

拥塞控制是自适应的（Quinn 的默认 CUBIC），未知的接收带宽被通告为零。没有进行残酷的固定带宽协商； `up_mbps`、`down_mbps` 和 0-RTT 选项被拒绝。

可选的 `obfs: {type: salamander, password: your-obfs-password}` 使用 Salamander 混淆包装 QUIC 数据报（至少四个密码字节）。对等方必须使用相同的设置。它为每个线路数据报添加了 8 个字节；因此，最小路径 UDP 有效负载为 1208 字节。 shoes' Hysteria2 服务器尚未实现此选项。

可选端口跳跃使用专用的连接拥有的端点：

```yaml
protocol:
  type: hysteria2
  password: your-password
  hopping:
    ports: '443,20000-30000' # Inclusive ranges, nonzero ports
    interval_secs: 30       # Minimum 5; default 30
    # Alternatively: min_interval_secs: 5, max_interval_secs: 30
```

所有列出的端口必须达到相同的服务器连接状态（通常通过服务器端 UDP 端口重定向）。每个连接都会解析一次主机名； hops 保留 IP 并随机选择一个目标端口。每个跃点都会创建一个新的受保护的、接口绑定的套接字，并保留前面的套接字以供后期回复，直到下一跃点为止。跳跃可以与Salamander结合使用。
