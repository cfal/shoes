---
title: "Snell v3"
description: "shoes snell v3 配置。"
---

**完整示例：** [snell.yaml](/zh-cn/examples/snell/)。在部署之前调整地址和机密。

下面的字段草图包含占位符，而不是可运行的值。配置部署时使用完整的示例。

<a id="server"></a>
## 服务端

```yaml
protocol:
  type: snell
  cipher: string               # aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305
  password: string
  udp_enabled: true            # Default: true
```


<a id="client"></a>
## 客户端

```yaml
protocol:
  type: snell
  cipher: string
  password: string
```
