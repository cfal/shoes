---
title: "ShadowTLS"
description: "shoes shadowtls 配置。"
---

**完整示例：** [shadowtls_v3_local_handshake.yaml](/zh-cn/examples/shadowtls_v3_local_handshake/)。在部署之前调整地址和机密。

下面的字段草图包含占位符，而不是可运行的值。配置部署时使用完整的示例。

<a id="server"></a>
## 服务端

使用 `shadowtls_targets` 配置 `type: tls` 服务器。有关握手目标、密码和内部协议设置，请参阅[TLS 服务器参考](/zh-cn/protocols/tls/#server)。

<a id="client"></a>
## 客户端

```yaml
protocol:
  type: shadowtls
  password: string
  sni_hostname: string?        # Optional SNI override
  protocol: ClientProxyConfig
```
