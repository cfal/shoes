---
title: "端口转发"
description: "shoes端口转发配置。"
---

下面的字段草图包含占位符，而不是可运行的值。配置部署时使用完整的示例。

<a id="server"></a>
## 服务端

```yaml
protocol:
  type: portforward            # Alias: forward
  targets: string | [string]   # Target address(es)
```


<a id="client"></a>
## 客户端

```yaml
protocol:
  type: portforward            # Aliases: noop
```

通过原始连接而不进行协议包装。对于测试或透明代理很有用。
