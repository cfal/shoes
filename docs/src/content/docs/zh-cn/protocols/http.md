---
title: "HTTP"
description: "shoes http 配置。"
---

**完整示例：** [http_proxy_basic.yaml](/zh-cn/examples/http_proxy_basic/)。在部署之前调整地址和机密。

下面的字段草图包含占位符，而不是可运行的值。配置部署时使用完整的示例。

<a id="server"></a>
## 服务端

```yaml
protocol:
  type: http
  username: string?            # Optional authentication
  password: string?
```

接受 HTTP/1.0 和 HTTP/1.1 CONNECT 和绝对形式转发，以及通过 HTTP/2 的复用 TCP CONNECT。 H2从其连接序言中检测到；明文 H2 需要先验知识，而不是 HTTP 升级。身份验证独立应用于每个 H2 流。仅在目标连接后才会发送成功的 CONNECT 响应。

没有活动隧道的 H2 连接将在 60 秒后关闭； PING 和拒绝的身份验证尝试不会延长该间隔。缺少凭据会收到 407 质询。不正确的凭据还会导致连接关闭，从而防止在一家承载层上重复猜测密码。

对于 HTTPS 代理，将 HTTP 包装在 TLS 服务器中，并在其 TLS 目标上显式配置 `alpn_protocols: [h2, http/1.1]`。 HTTP 不会更改父层的 ALPN 默认值。不支持 H2 GET/POST 转发、扩展 CONNECT、CONNECT-UDP 和 HTTP/3。这是标准 HTTP 代理，而不是 NaiveProxy 或 XHTTP。


<a id="client"></a>
## 客户端

```yaml
protocol:
  type: http
  username: string?
  password: string?
  http_version: h1             # h1 (default) or h2
  resolve_hostname: false      # Resolve destinations locally before CONNECT
```

两个版本都建立 TCP CONNECT 隧道。当 H2 代理是第一也是唯一的跃点时，符合条件的路由将重用多个并发隧道的连接。链式 H2 跃点使用通过所选前缀建立的承载层，而不是跨路由共享隧道。 H1 保留其现有的每个连接一个隧道的行为。 CONNECT 失败后不会自动版本回退或重播。

对于 TLS 上的 H2，请在此处设置 `http_version: h2`，并在封闭的 TLS 客户端上设置 `alpn_protocols: [h2]`。握手必须协商`h2`。省略或显式的 `http_version: h1` 保留传统行为：它发送 HTTP/1.1 而不检查协商的 ALPN。当对等方要求 ALPN 匹配 HTTP 版本时，在封闭的 TLS 客户端上设置 `alpn_protocols: [http/1.1]`。 Cleartext H2 使用先验知识。请参阅[示例/http2-proxy.yaml](/zh-cn/examples/http2-proxy/)。
