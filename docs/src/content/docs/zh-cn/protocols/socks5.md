---
title: "SOCKS5"
description: "shoes socks5 配置。"
---

**完整示例：** [socks_basic.yaml](/zh-cn/examples/socks_basic/)。在部署之前调整地址和机密。

下面的字段草图包含占位符，而不是可运行的值。配置部署时使用完整的示例。

<a id="server"></a>
## 服务端

```yaml
protocol:
  type: socks                  # Aliases: socks5
  username: string?
  password: string?
  udp_enabled: true            # Default: true (enables UDP ASSOCIATE)
```


<a id="client"></a>
## 客户端

```yaml
protocol:
  type: socks
  username: string?
  password: string?
```
