---
title: "WebSocket"
description: "shoes websocket 配置。"
---

**完整示例：** [wss_vmess.yaml](/zh-cn/examples/wss_vmess/)。在部署之前调整地址和机密。

下面的字段草图包含占位符，而不是可运行的值。配置部署时使用完整的示例。

<a id="server"></a>
## 服务端
```yaml
protocol:
  type: websocket              # Aliases: ws
  targets:
    - matching_path: string?   # Optional path filter (e.g., "/ws")
      matching_headers:        # Optional header filters
        X-Custom-Header: "value"
      max_early_data: 0        # 0: automatic standard-header reception, up to 2048 bytes
      early_data_header_name: string? # With positive max: empty/omitted selects path suffix
      protocol: ServerProxyConfig
      ping_type: ping-frame    # disabled | ping-frame | empty-frame
      override_rules: [RuleConfig]
```

WebSocket 早期数据在 HTTP 升级请求中携带初始字节前缀，而不是在 WebSocket 帧中，也不作为 TLS 0-RTT。客户端仅在明确启用时才发送它。省略或零 `max_early_data` 的服务器自动从 `Sec-WebSocket-Protocol` 接受它，最多 2048 个解码字节。正服务器限制选择显式模式，仅读取配置的承载层；没有自动回退到标准标头。要更改自动上限，请设置正 `max_early_data` 和 `early_data_header_name: Sec-WebSocket-Protocol`。

在 `matching_headers` 中具有静态 `Sec-WebSocket-Protocol` 过滤器的目标会抑制自动接收：其令牌仍然是选择器，没有前缀或子协议回显。否则，无人认领的非空子协议令牌将被视为早期数据，而不是普通的子协议协商。有效的 base64url 令牌（例如 `chat`）会注入解码后的字节；无效令牌被拒绝。没有通用的服务器端关闭开关。丢失或唯一空的标头仍然是普通的 WebSocket 升级；即使最终值为空，重复的承载层标头也会在自动模式下被拒绝。

未协商支持：成功升级（包括缺少子协议回显）并不能证明服务器接受了前缀。自动接收可以防止标准标头/默认服务器不匹配，但不匹配的自定义标头或路径后缀在没有 `matching_path` 的情况下到达目标时仍然可能会默默地丢失前缀，特别是在原始端口转发时。显式路径/自定义标头目标也不读取标准标头。配置匹配承载层；没有重放可以安全地恢复不匹配的前缀。

显式目标最多接受 `max_early_data` 解码字节。格式错误、不规范或过大的 base64url 在升级前会被拒绝。允许早期数据缺失或为空。解码字节先于所有成帧的有效负载。

通过 `early_data_header_name: Sec-WebSocket-Protocol`，shoes 可以与 Xray 的 `/ws?ed=2048` 客户端配置和 sing-box 的命名标头模式进行互操作。 shoes 使用显式字段；不要将 `?ed=` 放入其 `matching_path` 中。单盒对等点支持其他非保留的 HTTP 标头名称。名称不区分大小写；显式承载层也不能出现在 `matching_headers` 中。对客户端早期数据使用 sing-box 1.14.3 或更高版本：较旧的客户端在随 HTTP 升级一起到达时可以丢弃第一个响应字节。

在正限制且没有标头名称的情况下，编码字节将直接附加到 `matching_path`，就像在 sing-box 的路径模式中一样。这需要一个显式的、免查询的服务器路径。如果任何候选者具有正限制，或者第一个匹配目标将自动接收数据（包括重复的承载层），则匹配多个目标的请求将被拒绝。否则，传统的第一匹配路由仍然存在，包括当第一个目标具有静态子协议选择器时。匹配静态选择器目标之前的通用自动目标对于非空标记来说是不明确的；目标顺序不会更改为首选选择器。使用不相交的路径/标头过滤器，而不是在同一监听器上重叠前缀路径或捕获所有目标。

限制必须符合 HTTP 预算：每个请求/标头行小于 4096 字节，标头块最多 32768 字节，并且非空行少于 40 个。配置验证包括 base64 扩展并拒绝不适合的限制。总计 32768 字节上限也适用于普通 WebSocket 升级。客户端在两种模式下拒绝格式错误的状态代码、丢失或无效的 `Upgrade: websocket` 和 `Connection: upgrade` 响应令牌以及重复的接受/子协议响应标头。早期数据对HTTP中介及其日志可见；需要保密时使用TLS。


<a id="client"></a>
## 客户端
```yaml
protocol:
  type: websocket
  matching_path: string?
  matching_headers:
    header_name: string
  max_early_data: 0            # Decoded-byte limit; 0 keeps eager upgrades
  early_data_header_name: string? # Empty/omitted: path suffix
  ping_type: ping-frame        # disabled | ping-frame | empty-frame
  protocol: ClientProxyConfig
```

Xray 或单盒协议头模式示例：

```yaml
protocol:
  type: websocket
  matching_path: /ws
  matching_headers:
    Host: proxy.example.com
  max_early_data: 2048
  early_data_header_name: Sec-WebSocket-Protocol
  protocol:
    type: vless
    user_id: "11111111-1111-4111-8111-111111111111"
```

早期启用的客户端需要明确的 `matching_headers.Host` 来标识代理，而不是隧道目的地。对于单盒路径后缀模式，省略 `early_data_header_name`；该模式不支持查询字符串。默认情况下，发送保持关闭状态。默认 shoes 服务器接受最多 2048 字节的标准标头早期数据，无需额外的服务器配置；路径和自定义标头载体需要显式服务器配置。

第一次非空写入贡献达到配置的限制；其余字节使用普通 WebSocket 帧。对于向量写入，只有第一个非空切片有助于早期前缀。内部协议标头通常构成第一次写入，而不是应用程序的第一个有效负载。第一次写入之前的读取、刷新、关闭或启用 ping 会执行普通升级。空读/写不会启动它。升级失败是最终失败，并且永远不会重播接受的前缀。延迟升级保留 60 秒的设置超时。
