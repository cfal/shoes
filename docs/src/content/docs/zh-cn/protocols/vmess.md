---
title: "VMess"
description: "shoes vmess 配置。"
---

**完整示例：** [vmess.yaml](/zh-cn/examples/vmess/)。在部署之前调整地址和机密。

下面的字段草图包含占位符，而不是可运行的值。配置部署时使用完整的示例。

<a id="server"></a>
## 服务端

```yaml
protocol:
  type: vmess
  cipher: string               # any, aes-128-gcm, chacha20-poly1305, none
  user_id: string              # UUID
  udp_enabled: true            # Default: true (enables XUDP)
```

**注意：** VMess AEAD 模式始终启用。旧版 `force_aead` 字段已弃用，并且不再支持非 AEAD 模式。

重放保护使用最多 65,536 个 Auth-ID 的进程范围缓存，在凭据、监听器和重新加载之间共享。条目在其时间戳的 120 秒有效期内仍然受到保护；未来的 ID 可以占用一个槽约四分钟。完整的缓存会拒绝新的身份验证，而不是逐出活动条目。因此，来自一个凭证的大量流量可能会耗尽同一进程中其他 VMess 用户的容量。向后的系统时钟步骤也会暂停身份验证，直到时钟赶上。


<a id="client"></a>
## 客户端

```yaml
protocol:
  type: vmess
  cipher: string
  user_id: string
  h2mux:                         # Optional multiplexing; see H2MUX
    max_connections: 4
    min_streams: 4
    max_streams: 0
    padding: false
```

**注意：** VMess AEAD 模式始终启用。旧版 `aead` 字段已弃用。
