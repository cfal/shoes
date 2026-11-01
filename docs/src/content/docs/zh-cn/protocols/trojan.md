---
title: "Trojan"
description: "shoes trojan 配置。"
---

**完整示例：** [trojan_basic.yaml](/zh-cn/examples/trojan_basic/)。在部署之前调整地址和机密。

下面的字段草图包含占位符，而不是可运行的值。配置部署时使用完整的示例。

<a id="server"></a>
## 服务端

```yaml
protocol:
  type: trojan
  password: string
  shadowsocks:                 # Optional encryption layer
    cipher: string
    password: string
```


<a id="client"></a>
## 客户端

```yaml
protocol:
  type: trojan
  password: string
  shadowsocks:                 # Optional
    cipher: string
    password: string
  h2mux:                         # Optional multiplexing; see H2MUX
    max_connections: 4
    min_streams: 4
    max_streams: 0
    padding: false
```
