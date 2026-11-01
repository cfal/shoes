---
title: "H2MUX"
description: "shoes h2mux 配置。"
---

**完整示例：** [h2mux_client.yaml](/zh-cn/examples/h2mux_client/)。在部署之前调整地址和机密。

<a id="client"></a>
## 客户端


H2MUX 通过单个 HTTP/2 连接复用多个代理流，从而减少连接开销。与歌唱盒兼容。适用于 VMess、VLESS 和 Trojan 客户端协议。

```yaml
h2mux:
  max_connections: 4           # Maximum connections to maintain (default: 4)
  min_streams: 4               # Min streams before opening new connection (default: 4)
  max_streams: 0               # Max streams per connection, 0 = unlimited (default: 0)
  padding: false               # Enable padding for traffic obfuscation (default: false)
```

**服务器支持：** H2MUX 在服务器上自动检测。无需配置。
