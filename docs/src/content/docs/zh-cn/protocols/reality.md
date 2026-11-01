---
title: "Reality"
description: "shoes reality 配置。"
---

**完整示例：** [reality_basic.yaml](/zh-cn/examples/reality_basic/)。在部署之前调整地址和机密。

下面的字段草图包含占位符，而不是可运行的值。配置部署时使用完整的示例。

<a id="server"></a>
## 服务端

使用 `reality_targets` 配置 `type: tls` 服务器。有关目标选择、凭据和内部协议设置，请参阅 [TLS 服务器参考](/zh-cn/protocols/tls/#server)。

<a id="client"></a>
## 客户端

有关完整文件，请参阅[基本客户端](/zh-cn/examples/reality_client/) 和 [Vision 客户端](/zh-cn/examples/reality_vision_client/) 示例。

```yaml
protocol:
  type: reality
  public_key: string           # Server's X25519 public key (base64url)
  mldsa65_verify: string?      # Optional pinned 1952-byte ML-DSA-65 key (unpadded base64url)
  short_id: string             # Your client ID (hex, 0-16 chars)
  sni_hostname: string         # SNI to send (must match server's reality_targets key)
  cipher_suites: [string]      # Optional TLS 1.3 cipher suites
  vision: false                # Enable Vision (requires VLESS inner protocol)
  protocol: ClientProxyConfig  # Inner protocol (typically VLESS)
```

**Reality 密码套件：** 有效值为 `TLS_AES_128_GCM_SHA256`、`TLS_AES_256_GCM_SHA384`、`TLS_CHACHA20_POLY1305_SHA256`。如果未指定，则提供/支持所有三个。

Reality 首先提供 `X25519MLKEM768`，并提供 X25519 后备。服务器跟随伪装目标选择的组；选择 PQ-preferring TLS 1.3 目标来协商混合密钥交换。旧版 X25519 客户端仍受支持。调试日志报告经过身份验证的连接的 `negotiated_group`。

对于 Xray 服务器，请使用 v25.5.16 或更高版本。 Xray v25.4.30 及更早版本无法合成混合选择的目标握手：当支持 PQ 的目标选择 `X25519MLKEM768` 时，这些服务器转发到真实目标，而 shoes 拒绝其证书。 X25519 回退不会阻止此故障，因为目标已选择混合组。

`mldsa65_seed` 启用可选的服务器签名。具有 `mldsa65_verify` 的客户端需要匹配的签名并拒绝未签名或错误签名的连接。这些字段对应Xray的`mldsa65Seed`和`mldsa65Verify`；两者都不会取代现有的 X25519 密钥。省略字段以禁用此额外身份验证；空值或大小不正确的值无效。

应在分发验证密钥之前启用服务端签名。伪装目标的证书消息序列必须能容纳额外的 3309 字节签名和 DER 开销；容量不足时会回退到真实目标，而不是静默省略签名。之后若移除签名，需要与已固定验证密钥的客户端协调。Vision 的直连模式依赖内部 TLS 连接加密负载，而不是依赖外层 REALITY 混合密钥交换。
