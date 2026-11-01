---
title: "混合（HTTP + SOCKS5）"
description: "shoes混合（http + socks5）配置。"
---

**完整示例：** [mixed.yaml](/zh-cn/examples/mixed/)。在部署之前调整地址和机密。

下面的字段草图包含占位符，而不是可运行的值。配置部署时使用完整的示例。

<a id="server"></a>
## 服务端

```yaml
protocol:
  type: mixed                  # Aliases: http+socks, socks+http
  username: string?
  password: string?
  udp_enabled: true            # Default: true (enables UDP ASSOCIATE for SOCKS5)
```

自动检测HTTP（包括H2 CONNECT）或SOCKS5。
