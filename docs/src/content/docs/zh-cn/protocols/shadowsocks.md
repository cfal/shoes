---
title: "Shadowsocks"
description: "shoes shadowsocks 配置。"
---

**完整示例：** [shadowsocks_basic.yaml](/zh-cn/examples/shadowsocks_basic/)。在部署之前调整地址和机密。

下面的字段草图包含占位符，而不是可运行的值。配置部署时使用完整的示例。

<a id="server"></a>
## 服务端

```yaml
protocol:
  type: shadowsocks            # Aliases: ss
  cipher: string               # See supported ciphers below
  password: string

# Supported ciphers:
# - aes-128-gcm
# - aes-256-gcm
# - chacha20-ietf-poly1305
# - 2022-blake3-aes-128-gcm
# - 2022-blake3-aes-256-gcm
# - 2022-blake3-chacha20-ietf-poly1305
```


<a id="client"></a>
## 客户端

```yaml
protocol:
  type: shadowsocks
  cipher: string
  password: string
```

对于 `2022-blake3-aes-128-gcm` 和 `2022-blake3-aes-256-gcm`，客户端可以使用 `password: "server-key:user-key"` 连接到多用户服务器。每个组件都是独立的 Base64 编码，并且必须解码为 AES-128 的 16 字节或 AES-256 的 32 字节。对于身份中继，请使用 `password: "relay-key:server-key:user-key"`，身份密钥按连接顺序排列，用户密钥放在最后。这些是 SS2022 可扩展身份标头 (EIH)，而不是 `client_chain` 中的单独条目。

单键 SS2022 配置不变。身份链仅供客户端使用，`2022-blake3-chacha20-poly1305` 不支持。旧版 Shadowsocks 密码可能仍包含文字冒号。 shoes 不接受服务器配置中的多用户身份链。

客户端上的 `udp_enabled: true` 使用与 SagerNet UDP-over-TCP 相同的身份握手，并且需要支持 UoT 的上游。它不启用本机 SS2022 UDP。请参阅[示例/shadowsocks-2022-client.yaml](/zh-cn/examples/shadowsocks-2022-client/)。
