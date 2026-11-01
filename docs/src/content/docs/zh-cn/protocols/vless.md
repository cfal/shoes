---
title: "VLESS"
description: "shoes vless 配置。"
---

**完整示例：** [vless_over_tls.yaml](/zh-cn/examples/vless_over_tls/)。在部署之前调整地址和机密。

下面的字段草图包含占位符，而不是可运行的值。配置部署时使用完整的示例。

<a id="server"></a>
## 服务端

```yaml
protocol:
  type: vless
  user_id: string              # UUID
  udp_enabled: true            # Default: true (enables XUDP)
  fallback: string?            # Optional fallback destination for failed auth (e.g., "127.0.0.1:80")
```


<a id="client"></a>
## 客户端

```yaml
protocol:
  type: vless
  user_id: string
  h2mux:                         # Optional multiplexing
    max_connections: 4
    min_streams: 4
    max_streams: 0
    padding: false
```

## 相关设置

- [H2MUX](/zh-cn/protocols/h2mux/) 描述客户端连接池和多路复用字段。
- [Vision](/zh-cn/protocols/vision/) 描述了 TLS 或 REALITY 上禁用加密的 VLESS。
- [VLESS加密](/zh-cn/protocols/vless-encryption/)描述了本机客户端`encryption`、服务器`decryption`、协议级`vision`和服务器`encryption_limits`。
