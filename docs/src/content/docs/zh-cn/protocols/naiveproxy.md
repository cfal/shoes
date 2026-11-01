---
title: "NaiveProxy"
description: "shoes naiveproxy 配置。"
---

**完整示例：** [naiveproxy.yaml](/zh-cn/examples/naiveproxy/)。在部署之前调整地址和机密。

下面的字段草图包含占位符，而不是可运行的值。配置部署时使用完整的示例。

<a id="server"></a>
## 服务端

```yaml
protocol:
  type: naiveproxy             # Aliases: naive
  users:                       # One or more users
    - name: string?            # Optional display name
      username: string         # Basic Auth username
      password: string         # Basic Auth password
  padding: true                # Default: true (enables padding protocol)
  udp_enabled: true            # Default: true (enables UDP over TCP)
  fallback: string?            # Optional path to serve static files for probe resistance
```

NaiveProxy 实现 HTTP/2 CONNECT，并带有填充以抵抗审查。应在 TLS 内与 `alpn_protocols: ["h2"]` 一起使用。


<a id="client"></a>
## 客户端

```yaml
protocol:
  type: naiveproxy             # Aliases: naive
  username: string             # Basic Auth username
  password: string             # Basic Auth password
  padding: true                # Default: true (enables padding protocol)
```

NaiveProxy 保留其自己的 HTTP/2 客户端传输策略，独立于标准 HTTP 代理上的 `http_version: h2`：256 KiB 流和连接接收窗口、H2 库的 16 MiB 响应标头解码限制，并且无定期 HTTP/2 PING 看门狗。对等流限制和超时仍然适用。特别是，Caddy v2.11.7 默认设置一分钟的 request-body 空闲超时，这可以结束安静的 CONNECT 隧道；连接级 PING 不会重置该超时。

会话复用以选定的前置代理路径为范围。每个 NaiveProxy 处理器最多保留 16 个可复用会话，每条选定的前置路径对应一个。插入会话时先清除已关闭的会话；如果缓存仍满，再淘汰最久未使用的条目。淘汰不会关闭活动隧道。在已缓存的前置路径之间切换会复用各自的会话；这是缓存容量限制，不是活动连接数限制。并发冷连接仍可能建立各自的会话。
